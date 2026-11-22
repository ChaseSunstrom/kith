//! Scale to zero (T-1210): a Service with `spec.scaleToZero` lets the Workloads behind it sleep.
//!
//! Each node says in its own Node's status which Services it met a connection to (`seen`: unix
//! seconds, now while one is open) and which it holds one for (`wake`: now). The node that leads
//! reads them ([`decide`]) and writes `status.asleep` on each Workload: true once no node has seen
//! a connection for `idle`, false once a node holds one. The controller runs a sleeping Workload
//! with no replicas (`template_of`) and keeps its `spec.replicas`, so the sleep is state, not a spec
//! edit. A connection to a sleeping Service waits in [`hold`] until a replica is ready, up to `start`.
//
// ponytail: TCP only (a datagram wakes nothing), nodes' clocks are taken to agree, and a Service
// counts as seen to within `TICK`. A Workload with a Service that has no `scaleToZero` never sleeps.

use super::{Proxy, Table, behind, v4};
use kith_api::Resource;
use kith_api::kinds::{Protocol, ServiceSpec, every};
use kith_api::store::Store;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Notify, watch};

/// Connections held at once for one Service: the rest are closed with the reason.
const HELD: usize = 256;
/// How often a node says what it met, and so how much later than `idle` the leader acts.
const TICK: u64 = 10;
/// How far a node's clock may be from the leader's: ahead, its word is believed up to this far;
/// behind, its `wake` is believed for this long more.
const SKEW: u64 = 60;
/// A `wake` this old, or older, by the node's clock, is a connection that ended or a node that is
/// gone (it is said every `TICK` while held: this is the `SKEW` the docs promise, and some more).
const FRESH: u64 = SKEW + 30;
/// How often a held connection looks for a replica.
const POLL: Duration = Duration::from_millis(250);

/// Unix seconds.
pub(super) fn unix() -> u64 {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    now.map_or(0, |now| now.as_secs())
}

/// What a port of a Service that may sleep is: the Service (its key), its `start`, and the Workloads
/// behind it, each with the port a connection goes to.
pub(super) type Ports = BTreeMap<(IpAddr, u16), (String, Duration, Vec<(String, u16)>)>;

/// May a connection from the kithd of `node` reach one of `behind` (where a NetworkPolicy keeps
/// it out, it neither wakes the Workload nor keeps it awake)? The same check the node that has
/// the replica makes ([`super::admits`]).
pub(super) fn admitted(store: &Store, prefix: Ipv6Addr, node: &str, behind: &[(String, u16)]) -> bool {
    let from = IpAddr::from(kith_mesh::node_address(prefix, node));
    behind
        .iter()
        .any(|(workload, port)| super::admits(store, workload, Some(node), from, *port))
}

/// The ports of `table` that are a TCP port of a Service with `scaleToZero`, with the Service
/// (its key) and its `start`: where a connection may find the Workload asleep.
pub(super) fn ports(store: &Store, prefix: Ipv6Addr, table: &Table) -> Ports {
    let mut found = BTreeMap::new();
    for service in store.list(Some("Service")) {
        let Ok(spec) = serde_json::from_value::<ServiceSpec>(service.spec.clone()) else {
            continue;
        };
        let Some(start) = spec.scale_to_zero.as_ref().and_then(|zero| every(&zero.start)) else {
            continue;
        };
        let workloads = behind(store, service, &spec);
        let address = IpAddr::from(kith_mesh::service_address(
            prefix,
            &super::namespace(service),
            &service.metadata.name,
        ));
        let addresses = [Some(address), v4::address_of(service).map(IpAddr::from)];
        for (at, port) in addresses
            .into_iter()
            .flatten()
            .flat_map(|at| spec.ports.iter().map(move |p| (at, p)))
        {
            let key = (at, port.port);
            if port.protocol != Some(Protocol::Udp) && table.contains_key(&key) {
                let targets = workloads
                    .iter()
                    .filter_map(|workload| Some((workload.key(), super::target_of(port, workload)?)));
                found.insert(key, (service.key(), Duration::from_secs(start), targets.collect()));
            }
        }
    }
    found
}

/// What a node says of `seen` or `wake`: null, or the Services (their keys) by unix seconds.
pub(crate) fn shape(said: &Value) -> Result<(), &'static str> {
    let fits = match said {
        Value::Null => true,
        Value::Object(services) => {
            services.len() <= 256 && services.iter().all(|(name, at)| name.len() <= 320 && at.is_u64())
        }
        _ => false,
    };
    fits.then_some(())
        .ok_or("is null or at most 256 Services by unix seconds")
}

#[derive(Default)]
struct Service {
    /// Unix seconds of the last connection to end (or begin).
    seen: u64,
    open: usize,
    held: usize,
}

#[derive(Default)]
struct Inner {
    /// What each address and port of a Service with `scaleToZero` is: the Service, and its `start`.
    ports: Ports,
    services: BTreeMap<String, Service>,
}

/// What this node met of the Services that may sleep.
#[derive(Default)]
pub(super) struct Naps {
    inner: Mutex<Inner>,
    /// Told when a first connection is held: the node says so at once.
    asked: Notify,
}

/// A connection to a Service that may sleep, while it lasts.
pub(super) struct Met<'a> {
    naps: &'a Naps,
    service: String,
    start: Duration,
}

impl Drop for Met<'_> {
    fn drop(&mut self) {
        let mut inner = self.naps.inner.lock().expect("nothing panics holding the naps");
        if let Some(met) = inner.services.get_mut(&self.service) {
            met.open = met.open.saturating_sub(1);
            met.seen = unix();
        }
    }
}

/// Why a held connection is closed.
#[derive(Debug, PartialEq)]
pub(super) enum Closed {
    Full(String),
    Late(String, Duration),
    /// The client hung up while it waited.
    Gone,
}

impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Closed::Full(service) => write!(f, "{HELD} connections already wait for {service} to start"),
            Closed::Late(service, start) => write!(f, "{service} did not start within {}s", start.as_secs()),
            Closed::Gone => write!(f, "the client hung up"),
        }
    }
}

/// A place among the held connections of a Service, while it lasts.
struct Held<'a>(&'a Naps, &'a str);

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let mut inner = self.0.inner.lock().expect("nothing panics holding the naps");
        if let Some(held) = inner.services.get_mut(self.1) {
            held.held = held.held.saturating_sub(1);
        }
    }
}

impl Naps {
    /// What the Services that may sleep are now; the others are forgotten.
    pub(super) fn set(&self, ports: Ports) {
        let mut inner = self.inner.lock().expect("nothing panics holding the naps");
        inner
            .services
            .retain(|name, _| ports.values().any(|(of, ..)| of == name));
        inner.ports = ports;
    }

    /// Is `key` a port of a Service that may sleep?
    pub(super) fn has(&self, key: &(IpAddr, u16)) -> bool {
        self.inner
            .lock()
            .expect("nothing panics holding the naps")
            .ports
            .contains_key(key)
    }

    /// A connection to `key` at `now`: `Some` if its Service may sleep and `admits` the
    /// Workloads behind it ([`admitted`]): one that is refused is not met, so it counts for nothing.
    pub(super) fn meet(
        &self,
        key: (IpAddr, u16),
        now: u64,
        admits: impl Fn(&[(String, u16)]) -> bool,
    ) -> Option<Met<'_>> {
        let mut inner = self.inner.lock().expect("nothing panics holding the naps");
        let (service, start, behind) = inner.ports.get(&key)?.clone();
        if !admits(&behind) {
            return None;
        }
        let met = inner.services.entry(service.clone()).or_default();
        (met.open, met.seen) = (met.open + 1, now);
        Some(Met {
            naps: self,
            service,
            start,
        })
    }

    /// Hold a place for one more connection of `service`, if fewer than [`HELD`] wait.
    fn hold<'a>(&'a self, service: &'a str) -> Option<Held<'a>> {
        let mut inner = self.inner.lock().expect("nothing panics holding the naps");
        let held = inner.services.get_mut(service).filter(|held| held.held < HELD)?;
        held.held += 1;
        if held.held == 1 {
            self.asked.notify_one();
        }
        Some(Held(self, service))
    }

    /// What this node says now: `seen` (now for a Service with a connection open) and `wake`.
    pub(super) fn say(&self, now: u64) -> (Map<String, Value>, Map<String, Value>) {
        let inner = self.inner.lock().expect("nothing panics holding the naps");
        let seen = inner.services.iter().map(|(name, met)| {
            let at = if met.open > 0 { now } else { met.seen };
            (name.clone(), json!(at))
        });
        let wake = inner.services.iter().filter(|(_, met)| met.held > 0);
        (
            seen.collect(),
            wake.map(|(name, _)| (name.clone(), json!(now))).collect(),
        )
    }
}

/// Wait for `view` to say a replica is there, for the time the Service allows: the connection
/// `met` is held while a replica starts, or until `gone` is done (the client hung up: its place, and
/// the Workload's wake, are let go at once). Waiting is polled (a replica takes seconds to start).
pub(super) async fn hold(met: &Met<'_>, view: impl Fn() -> bool, gone: impl Future<Output = ()>) -> Result<(), Closed> {
    let Some(_place) = met.naps.hold(&met.service) else {
        return Err(Closed::Full(met.service.clone()));
    };
    let deadline = tokio::time::Instant::now() + met.start;
    let wait = async {
        while !view() {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Err(Closed::Late(met.service.clone(), met.start));
            }
            tokio::time::sleep(POLL.min(left)).await;
        }
        Ok(())
    };
    tokio::select! {
        held = wait => held,
        () = gone => Err(Closed::Gone),
    }
}

/// Done once `client` has hung up (or failed). What it says while it waits stays unread for [`serve`](super::Proxy).
pub(super) async fn hung_up(client: &tokio::net::TcpStream) {
    loop {
        if client.readable().await.is_err() {
            return;
        }
        if !matches!(client.peek(&mut [0]).await, Ok(1..)) {
            return;
        }
        // (It said something: it is waiting still, and `readable` would be ready at once.)
        tokio::time::sleep(POLL).await;
    }
}

/// Say why a held connection is closed (it may be heard or not).
pub(super) async fn close(client: &mut tokio::net::TcpStream, why: &Closed) {
    let line = format!("kith: {why}\r\n");
    drop(tokio::time::timeout(Duration::from_secs(1), client.write_all(line.as_bytes())).await);
}

/// What the node that leads the store writes: `asleep` on each Workload whose state is not
/// what its Services' connections say. `since` is when this node first saw each Workload awake (or
/// woke it): a Workload sleeps `idle` after the later of that and the last connection to its
/// Services, and `TICK` more, for what a node has not said yet.
///
/// A node's word of a Service counts only where its kithd could have connected to the Workloads
/// behind it ([`admitted`]): a node a NetworkPolicy keeps out cannot keep one awake or wake it, and a
/// key that is no Service behind a Workload is never read.
pub(super) fn decide(
    store: &Store,
    prefix: Ipv6Addr,
    now: u64,
    since: &mut BTreeMap<String, u64>,
) -> Vec<(String, Map<String, Value>)> {
    let mut services: BTreeMap<String, Vec<(String, Option<u64>)>> = BTreeMap::new();
    // Each Service's Workloads with the ports a connection goes to.
    let mut targets: BTreeMap<String, Vec<(String, u16)>> = BTreeMap::new();
    if store.list(Some("Service")).any(|s| s.spec.get("scaleToZero").is_some()) {
        for service in store.list(Some("Service")) {
            let Ok(spec) = serde_json::from_value::<ServiceSpec>(service.spec.clone()) else {
                continue;
            };
            let idle = spec.scale_to_zero.as_ref().and_then(|zero| every(&zero.idle));
            let named = (service.key(), idle);
            let workloads = behind(store, service, &spec);
            let mut reached = Vec::new();
            for workload in &workloads {
                services.entry(workload.key()).or_default().push(named.clone());
                let targets = spec.ports.iter().filter_map(|port| super::target_of(port, workload));
                reached.extend(targets.map(|target| (workload.key(), target)));
            }
            targets.insert(service.key(), reached);
        }
    }
    let nodes: Vec<&Resource> = store.list(Some("Node")).collect();
    let said = |field: &str, service: &str| {
        let ats = nodes.iter().filter_map(|node| {
            let at = node.status.as_ref()?[field][service]
                .as_u64()
                .filter(|at| *at <= now + SKEW)?;
            admitted(store, prefix, &node.metadata.name, targets.get(service)?).then_some(at)
        });
        ats.collect::<Vec<_>>()
    };
    let mut writes = Vec::new();
    for workload in store.list(Some("Workload")) {
        let key = workload.key();
        let asleep = workload.status.as_ref().is_some_and(|status| status["asleep"] == true);
        let behind = services.get(&key).map(Vec::as_slice).unwrap_or_default();
        // (One Service with no `scaleToZero` keeps it awake: a connection to that one is not met.)
        let sleeps = !behind.is_empty()
            && behind.iter().all(|(_, idle)| idle.is_some())
            && workload.spec["replicas"].as_u64() != Some(0);
        let want = sleeps && {
            let wake = behind
                .iter()
                .any(|(name, _)| said("wake", name).iter().any(|at| now.saturating_sub(*at) <= FRESH));
            let last = behind.iter().flat_map(|(name, _)| said("seen", name)).max();
            let idle = behind.iter().filter_map(|(_, idle)| *idle).max().unwrap_or(0);
            let from = last.unwrap_or(0).max(since.get(&key).copied().unwrap_or(now));
            let quiet = now > from.saturating_add(idle).saturating_add(TICK);
            !wake && (asleep || quiet)
        };
        match want {
            true => drop(since.remove(&key)),
            // (Counted from the wake, so it does not sleep again at once.)
            false if asleep => drop(since.insert(key.clone(), now)),
            false => drop(since.entry(key.clone()).or_insert(now)),
        }
        if want != asleep {
            writes.push((key, Map::from_iter([("asleep".to_string(), json!(want))])));
        }
    }
    since.retain(|key, _| store.get(key).is_some());
    writes
}

/// Say what this node met, and, on the node that leads the store, put to sleep and wake the
/// Workloads, until stopped.
pub(super) async fn run(proxy: Arc<Proxy>, mut stopping: watch::Receiver<bool>) {
    let shared = &proxy.shared;
    let Some(cluster) = &shared.cluster else { return };
    let node = format!("Node/{}", cluster.me.name);
    let (mut told, mut since) = ((Map::new(), Map::new()), BTreeMap::new());
    let mut generation = shared.generation.subscribe();
    loop {
        let now = unix();
        let said = proxy.naps.say(now);
        if said != told {
            let fields = Map::from_iter([
                ("seen".to_string(), Value::Object(said.0.clone())),
                ("wake".to_string(), Value::Object(said.1.clone())),
            ]);
            match shared
                .submit(kith_store::Command::Patch {
                    statuses: vec![(node.clone(), fields)],
                })
                .await
            {
                Ok(_) => told = said,
                Err(e) => eprintln!("kithd: services: telling the cluster what this node met: {e}"),
            }
        }
        let leads = {
            let metrics = shared.raft.metrics().borrow().clone();
            metrics.current_leader == Some(metrics.id)
        };
        if leads {
            let writes = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                decide(&state.store, proxy.prefix, now, &mut since)
            };
            if !writes.is_empty()
                && let Err(e) = shared.write_here(kith_store::Command::Patch { statuses: writes }).await
            {
                eprintln!("kithd: services: waking or sleeping a Workload: {e}");
            }
        }
        // (Coalesces what the store changes while this was written.)
        tokio::time::sleep(Duration::from_millis(500)).await;
        tokio::select! {
            _ = generation.changed() => {}
            () = proxy.naps.asked.notified() => {}
            () = tokio::time::sleep(Duration::from_secs(TICK)) => {}
            _ = stopping.changed() => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_api::Resource;
    use std::sync::atomic::{AtomicBool, Ordering};

    const WEB: &str = "
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: web, labels: { app: web } }
spec:
  replicas: 2
  template:
    containers: [{ name: main, image: example.org/web, ports: [{ port: 8080 }] }]
";

    /// A Store with the Workload `web` and a Service for it, `zero` its `scaleToZero` (or none).
    fn store(zero: &str) -> Store {
        let service = format!(
            "apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: web }}\n\
             spec: {{ selector: {{ app: web }}, ports: [{{ port: 80, targetPort: 8080 }}]{zero} }}\n"
        );
        let node = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: { name: n1 }\nspec: {}\n";
        let mut store = Store::default();
        for source in [WEB, service.as_str(), node, &node.replace("n1", "n2")] {
            for resource in Resource::from_source(source).unwrap() {
                store.apply(resource.unwrap()).unwrap();
            }
        }
        store
    }

    const ZERO: &str = ", scaleToZero: { idle: 5m, start: 30s }";

    /// Nodes say what they met: `[(node, field, service, unix seconds)]`.
    fn said(store: &mut Store, says: &[(&str, &str, u64)]) {
        for node in ["n1", "n2"] {
            let mut status = Map::new();
            for field in ["seen", "wake"] {
                let mine = says.iter().filter(|(who, f, _)| *who == node && *f == field);
                let found = mine.map(|(_, _, at)| ("Service/default/web".to_string(), json!(at)));
                status.insert(field.into(), Value::Object(found.collect()));
            }
            store
                .set_status(&format!("Node/{node}"), Some(Value::Object(status)))
                .unwrap();
        }
    }

    fn asleep(store: &mut Store, asleep: bool) {
        store
            .set_status("Workload/default/web", Some(json!({ "asleep": asleep })))
            .unwrap();
    }

    fn writes(store: &Store, now: u64, since: &mut BTreeMap<String, u64>) -> Vec<(String, bool)> {
        let writes = decide(store, prefix(), now, since);
        writes
            .into_iter()
            .map(|(key, fields)| (key, fields["asleep"] == true))
            .collect()
    }

    const WEB_KEY: &str = "Workload/default/web";

    fn prefix() -> Ipv6Addr {
        kith_mesh::prefix(b"test")
    }

    #[test]
    fn scale_to_zero_sleeps_once_no_node_has_seen_a_connection_for_idle() {
        let mut store = store(ZERO);
        said(&mut store, &[("n1", "seen", 1000), ("n2", "seen", 1100)]);
        let mut since = BTreeMap::from([(WEB_KEY.to_string(), 0)]);
        // The latest of the nodes counts, and the leader allows `TICK` more for what is not said yet.
        assert_eq!(writes(&store, 1100 + 300 + TICK, &mut since), []);
        assert_eq!(
            writes(&store, 1100 + 300 + TICK + 1, &mut since),
            [(WEB_KEY.into(), true)]
        );
    }

    #[test]
    fn scale_to_zero_counts_a_workload_first_seen_awake_from_then() {
        let store = store(ZERO);
        let mut since = BTreeMap::new();
        // Never met a connection: asleep `idle` after the leader first saw it, not at once.
        assert_eq!(writes(&store, 5000, &mut since), []);
        assert_eq!(writes(&store, 5000 + 300 + TICK, &mut since), []);
        assert_eq!(
            writes(&store, 5000 + 300 + TICK + 1, &mut since),
            [(WEB_KEY.into(), true)]
        );
    }

    #[test]
    fn scale_to_zero_wakes_when_a_node_holds_a_connection_and_not_otherwise() {
        let mut store = store(ZERO);
        asleep(&mut store, true);
        said(&mut store, &[("n1", "seen", 1000)]);
        let mut since = BTreeMap::new();
        // Asleep it stays, however long since a connection.
        assert_eq!(writes(&store, 9000, &mut since), []);
        said(&mut store, &[("n2", "wake", 9000)]);
        assert_eq!(writes(&store, 9001, &mut since), [(WEB_KEY.into(), false)]);
        // A wake nobody refreshed is a connection that ended, or a node that is gone.
        said(&mut store, &[("n2", "wake", 9000)]);
        assert_eq!(writes(&store, 9000 + FRESH + 1, &mut since), []);
    }

    #[test]
    fn scale_to_zero_does_not_flap_after_a_wake() {
        let mut store = store(ZERO);
        said(&mut store, &[("n1", "seen", 100)]);
        asleep(&mut store, true);
        let mut since = BTreeMap::new();
        said(&mut store, &[("n1", "seen", 100), ("n1", "wake", 9000)]);
        assert_eq!(writes(&store, 9000, &mut since), [(WEB_KEY.into(), false)]);
        // Awake, with the old `seen` still the latest word: not asleep again until `idle` from the wake.
        asleep(&mut store, false);
        said(&mut store, &[("n1", "seen", 100)]);
        assert_eq!(writes(&store, 9000 + 300, &mut since), []);
        assert_eq!(
            writes(&store, 9000 + 300 + TICK + 1, &mut since),
            [(WEB_KEY.into(), true)]
        );
    }

    #[test]
    fn scale_to_zero_does_not_count_a_node_that_stopped_saying() {
        let mut store = store(ZERO);
        // n2 met a connection long ago and has not said since (it is down): n1's word decides.
        said(
            &mut store,
            &[("n1", "seen", 8000), ("n2", "seen", 100), ("n2", "wake", 100)],
        );
        let mut since = BTreeMap::from([(WEB_KEY.to_string(), 0)]);
        assert_eq!(
            writes(&store, 8000 + 300 + TICK + 1, &mut since),
            [(WEB_KEY.into(), true)]
        );
        // And a node's word from far ahead of the clock holds nothing awake or asleep.
        said(
            &mut store,
            &[("n1", "seen", 8000), ("n2", "seen", 8000 + 300 + TICK + 1 + SKEW + 1)],
        );
        let mut since = BTreeMap::from([(WEB_KEY.to_string(), 0)]);
        assert_eq!(
            writes(&store, 8000 + 300 + TICK + 1, &mut since),
            [(WEB_KEY.into(), true)]
        );
    }

    #[test]
    fn scale_to_zero_off_changes_nothing() {
        // No `scaleToZero`: never asleep, and one left asleep (it was taken off) is woken.
        let mut store = store("");
        said(&mut store, &[("n1", "seen", 1)]);
        let mut since = BTreeMap::new();
        assert_eq!(writes(&store, 99_999, &mut since), []);
        asleep(&mut store, true);
        assert_eq!(writes(&store, 99_999, &mut since), [(WEB_KEY.into(), false)]);
        // A Workload another Service with no `scaleToZero` also names does not sleep.
        let mut store = self::store(ZERO);
        let other = "apiVersion: kith.dev/v1\nkind: Service\nmetadata: { name: all }\n\
                     spec: { selector: { app: web }, ports: [{ port: 81, targetPort: 8080 }] }\n";
        store
            .apply(Resource::from_source(other).unwrap().remove(0).unwrap())
            .unwrap();
        assert_eq!(writes(&store, 99_999, &mut since), []);
        assert_eq!(writes(&store, 999_999, &mut since), []);
    }

    #[test]
    fn scale_to_zero_keeps_the_spec_and_runs_no_replica_while_asleep() {
        let mut store = store(ZERO);
        let replicas = |store: &Store| crate::controller::template_of(store.get(WEB_KEY).unwrap()).unwrap().1;
        assert_eq!(replicas(&store), 2);
        asleep(&mut store, true);
        assert_eq!(replicas(&store), 0);
        assert_eq!(store.get(WEB_KEY).unwrap().spec["replicas"], 2);
        asleep(&mut store, false);
        assert_eq!(replicas(&store), 2);
    }

    #[test]
    fn scale_to_zero_wakes_only_through_a_service_that_names_the_workload() {
        let mut store = store(ZERO);
        asleep(&mut store, true);
        let mut status = Map::new();
        status.insert("wake".into(), json!({ "Service/default/other": 9000 }));
        store.set_status("Node/n1", Some(Value::Object(status))).unwrap();
        assert_eq!(writes(&store, 9000, &mut BTreeMap::new()), []);
    }

    /// The Workload `web` lets in only the kithd of `n2`.
    fn guarded() -> Store {
        let mut store = store(ZERO);
        let policy = "apiVersion: kith.dev/v1\nkind: NetworkPolicy\nmetadata: { name: p }\nspec:\n  \
                      selector: { app: web }\n  ingress: [{ action: allow, peers: [{ node: n2 }] }]\n  egress: []\n";
        store
            .apply(Resource::from_source(policy).unwrap().remove(0).unwrap())
            .unwrap();
        store
    }

    #[test]
    fn scale_to_zero_a_client_the_policy_refuses_neither_wakes_nor_counts() {
        let (store, prefix) = (guarded(), prefix());
        let store = &store;
        let key = (IpAddr::from(kith_mesh::service_address(prefix, "default", "web")), 80);
        let naps = Naps::default();
        naps.set(ports(store, prefix, &Table::from([(key, Vec::new())])));
        let from = |node: &'static str| move |behind: &[(String, u16)]| admitted(store, prefix, node, behind);
        // On n1, whose connections the policy refuses: not met, so not seen, not held, not woken.
        assert!(naps.meet(key, 1000, from("n1")).is_none());
        let (seen, wake) = naps.say(2000);
        assert!(seen.is_empty() && wake.is_empty(), "{seen:?} {wake:?}");
        // On n2, it is met.
        let met = naps.meet(key, 1000, from("n2"));
        assert!(met.is_some());
        assert_eq!(naps.say(2000).0["Service/default/web"], 2000);
    }

    #[test]
    fn scale_to_zero_counts_a_nodes_word_only_where_the_policy_lets_its_kithd_connect() {
        let mut store = guarded();
        asleep(&mut store, true);
        // n1 (kept out) says it holds a connection: nothing wakes. n2 (let in) says it: it wakes.
        said(&mut store, &[("n1", "wake", 9000), ("n1", "seen", 9000)]);
        assert_eq!(writes(&store, 9000, &mut BTreeMap::new()), []);
        said(&mut store, &[("n2", "wake", 9000)]);
        assert_eq!(writes(&store, 9000, &mut BTreeMap::new()), [(WEB_KEY.into(), false)]);
        // Awake, n1 keeps saying it met connections: it does not keep the Workload awake.
        let mut store = guarded();
        said(&mut store, &[("n1", "seen", 8000 + 299)]);
        let mut since = BTreeMap::from([(WEB_KEY.to_string(), 1000)]);
        assert_eq!(
            writes(&store, 8000 + 300 + TICK + 1, &mut since),
            [(WEB_KEY.into(), true)]
        );
        said(&mut store, &[("n2", "seen", 8000 + 299)]);
        assert_eq!(writes(&store, 8000 + 300 + TICK + 1, &mut since), []);
    }

    #[test]
    fn scale_to_zero_an_idle_that_overflows_never_sleeps_the_workload() {
        // (The API refuses one now: it is written as an older version left it.)
        let mut store = store(ZERO);
        let mut service = store.get("Service/default/web").unwrap().clone();
        service.spec["scaleToZero"]["idle"] = json!("213503982334601d");
        store.put(service);
        assert_eq!(writes(&store, 100_000, &mut BTreeMap::new()), []);
    }

    /// A client connected to a listener here, and the listener's side of it.
    async fn connected() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
        let (client, served) = tokio::join!(client, listener.accept());
        (client.unwrap(), served.unwrap().0)
    }

    #[tokio::test]
    async fn held_connection_is_let_go_when_the_client_hangs_up() {
        let (client, served) = connected().await;
        let (naps, key) = naps();
        let met = naps.meet(key, 1000, |_| true).unwrap();
        let waiting = hold(&met, || false, hung_up(&served));
        let hangs_up = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(naps.say(2000).1["Service/default/web"], 2000, "held while it waits");
            drop(client);
        };
        let (held, ()) = tokio::join!(tokio::time::timeout(Duration::from_secs(5), waiting), hangs_up);
        // (Not the 30 s of `start`: the place and the wake are gone with the client.)
        assert_eq!(held.expect("not waiting out `start`"), Err(Closed::Gone));
        assert!(naps.say(2000).1.is_empty());
    }

    #[tokio::test]
    async fn held_connection_that_says_something_is_waiting_still() {
        let (mut client, served) = connected().await;
        client.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
        let waiting = tokio::time::timeout(Duration::from_millis(600), hung_up(&served));
        assert!(waiting.await.is_err(), "what it said is not a hang up");
    }

    fn naps() -> (Naps, (IpAddr, u16)) {
        let key = (IpAddr::from([127, 0, 0, 1]), 80);
        let naps = Naps::default();
        let start = Duration::from_secs(30);
        naps.set(BTreeMap::from([(
            key,
            (
                "Service/default/web".to_string(),
                start,
                vec![(WEB_KEY.to_string(), 8080)],
            ),
        )]));
        (naps, key)
    }

    #[tokio::test(start_paused = true)]
    async fn held_connection_goes_on_once_a_replica_is_ready() {
        let (naps, key) = naps();
        let ready = AtomicBool::new(false);
        let met = naps.meet(key, 1000, |_| true).unwrap();
        let waiting = hold(&met, || ready.load(Ordering::Relaxed), std::future::pending());
        let started = async {
            tokio::time::sleep(Duration::from_secs(12)).await;
            // While it waits the node says it holds one (for the leader to wake the Workload).
            let (seen, wake) = naps.say(2000);
            assert_eq!(wake["Service/default/web"], 2000);
            assert_eq!(seen["Service/default/web"], 2000, "open: seen now");
            ready.store(true, Ordering::Relaxed);
        };
        let (held, ()) = tokio::join!(waiting, started);
        assert_eq!(held, Ok(()));
        assert!(naps.say(2000).1.is_empty(), "no longer held");
    }

    #[tokio::test(start_paused = true)]
    async fn held_connection_gives_up_past_the_start_deadline_and_says_why() {
        let (naps, key) = naps();
        let met = naps.meet(key, 1000, |_| true).unwrap();
        let before = tokio::time::Instant::now();
        let closed = hold(&met, || false, std::future::pending()).await.unwrap_err();
        assert_eq!(before.elapsed(), Duration::from_secs(30));
        assert_eq!(closed.to_string(), "Service/default/web did not start within 30s");
        assert!(naps.say(2000).1.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn held_connection_is_at_most_256_per_service() {
        let (naps, key) = naps();
        let (ready, met) = (
            AtomicBool::new(false),
            (0..HELD + 1)
                .map(|_| naps.meet(key, 1, |_| true).unwrap())
                .collect::<Vec<_>>(),
        );
        let held = met
            .iter()
            .take(HELD)
            .map(|met| hold(met, || ready.load(Ordering::Relaxed), std::future::pending()));
        let held = futures_util::future::join_all(held);
        let over = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            // The 257th is closed at once, with the reason; the others wait.
            let closed = hold(&met[HELD], || false, std::future::pending()).await.unwrap_err();
            assert_eq!(closed, Closed::Full("Service/default/web".into()));
            assert!(closed.to_string().starts_with("256 connections"));
            ready.store(true, Ordering::Relaxed);
        };
        let (held, ()) = tokio::join!(held, over);
        assert!(held.iter().all(Result::is_ok));
        // The places are given back: one more is held again.
        assert_eq!(hold(&met[HELD], || true, std::future::pending()).await, Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn held_connection_is_met_only_at_a_service_that_may_sleep() {
        let (naps, key) = naps();
        assert!(naps.meet((key.0, 81), 1, |_| true).is_none());
        let met = naps.meet(key, 7, |_| true);
        assert!(met.is_some() && naps.has(&key));
        drop(met);
        // Ended: seen no longer moves with the clock.
        assert_ne!(naps.say(1).0["Service/default/web"], 1);
        naps.set(BTreeMap::new());
        assert!(!naps.has(&key) && naps.say(1).0.is_empty());
    }

    #[test]
    fn held_connection_shape_is_null_or_a_few_services_by_seconds() {
        assert!(shape(&json!(null)).is_ok() && shape(&json!({ "default/web": 1 })).is_ok());
        for bad in [
            json!([]),
            json!({ "default/web": "1" }),
            json!({ "default/web": -1 }),
            json!(1),
        ] {
            assert!(shape(&bad).is_err());
        }
    }

    #[test]
    fn scale_to_zero_ports_are_the_listened_ones_of_the_services_that_may_sleep() {
        let prefix = Ipv6Addr::new(0xfd00, 1, 2, 0, 0, 0, 0, 0);
        let store = store(ZERO);
        let service = store.get("Service/default/web").unwrap();
        let at = IpAddr::from(kith_mesh::service_address(prefix, "default", "web"));
        let mut table = Table::new();
        assert!(ports(&store, prefix, &table).is_empty());
        table.insert((at, 80), Vec::new());
        table.insert((at, 81), Vec::new());
        let found = ports(&store, prefix, &table);
        assert_eq!(found.keys().collect::<Vec<_>>(), [&(at, 80)]);
        let behind = vec![(WEB_KEY.to_string(), 8080)];
        assert_eq!(found[&(at, 80)], (service.key(), Duration::from_secs(30), behind));
        // Off: no port.
        assert!(ports(&self::store(""), prefix, &table).is_empty());
    }
}
