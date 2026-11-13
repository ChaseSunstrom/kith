//! Services, on a node of the mesh: every Service has an address every node holds
//! (`kith_mesh::service_address`), and a TCP connection to one of its ports there is
//! passed to a ready replica of a Workload its selector matches, one after the other in
//! turn. A replica on this node is reached on the machine itself (so it may listen on
//! 127.0.0.1 only); one on another node through that node's kithd, which listens on its
//! mesh address for exactly this and connects to the replica there.
//
// ponytail: kithd copies every byte (a restart of kithd cuts the connections), TCP only,
// and replicas of one node share its ports until workloads have addresses of their own.
// The kernel takes this over (nftables or eBPF) behind the same addresses.

use crate::Shared;
use kith_api::Resource;
use kith_api::kinds::{NetworkPolicySpec, Peer, PolicyAction, PortRef, Protocol, ServiceSpec, WorkloadSpec};
use kith_api::store::Store;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

/// Where a connection may go: a node's name, a port on it, and the Workload it is of.
type Backend = (String, u16, String);
/// For every address and port a Service listens on: its backends.
type Table = BTreeMap<(Ipv6Addr, u16), Vec<Backend>>;

const CONNECT: Duration = Duration::from_secs(3);

fn namespace(resource: &Resource) -> String {
    resource.key().split('/').nth(1).unwrap_or_default().to_string()
}

/// The address of every Service in the store.
pub fn addresses(store: &Store, prefix: Ipv6Addr) -> BTreeMap<String, Ipv6Addr> {
    let address = |service: &Resource| kith_mesh::service_address(prefix, &namespace(service), &service.metadata.name);
    let services = store.list(Some("Service"));
    services.map(|service| (service.key(), address(service))).collect()
}

/// The nodes that run a replica of `workload` with every unit ready.
fn ready_on(workload: &Resource) -> Vec<String> {
    let mut replicas: BTreeMap<(u64, &str), bool> = BTreeMap::new();
    let units = workload
        .status
        .as_ref()
        .and_then(|status| status["containers"].as_array());
    for unit in units.into_iter().flatten() {
        let (Some(replica), Some(node)) = (unit["replica"].as_u64(), unit["node"].as_str()) else {
            continue;
        };
        *replicas.entry((replica, node)).or_insert(true) &= unit["ready"] == true;
    }
    let ready = replicas.into_iter().filter(|(_, ready)| *ready);
    ready.map(|((_, node), _)| node.to_string()).collect()
}

/// What every Service listens on, and where its connections go.
fn table(store: &Store, prefix: Ipv6Addr) -> Table {
    let mut table = Table::new();
    for service in store.list(Some("Service")) {
        let Ok(spec) = serde_json::from_value::<ServiceSpec>(service.spec.clone()) else {
            continue;
        };
        let address = kith_mesh::service_address(prefix, &namespace(service), &service.metadata.name);
        // (A selector that asks for nothing would take in every workload: it takes none.)
        let behind = |workload: &&Resource| {
            let has = |(label, value): (&String, &String)| workload.metadata.labels.get(label) == Some(value);
            namespace(workload) == namespace(service) && !spec.selector.is_empty() && spec.selector.iter().all(has)
        };
        let workloads: Vec<&Resource> = store.list(Some("Workload")).filter(behind).collect();
        for port in &spec.ports {
            if port.protocol == Some(Protocol::Udp) {
                continue;
            }
            let backends = table.entry((address, port.port)).or_default();
            for workload in &workloads {
                let target = match &port.target_port {
                    None => Some(port.port),
                    Some(PortRef::Number(number)) => Some(*number),
                    // A port by name: the container port of that name.
                    Some(PortRef::Name(name)) => {
                        let spec = serde_json::from_value::<WorkloadSpec>(workload.spec.clone()).ok();
                        let containers = spec.into_iter().flat_map(|spec| spec.template.containers);
                        let mut ports = containers.flat_map(|container| container.ports);
                        ports
                            .find(|port| port.name.as_ref() == Some(name))
                            .map(|port| port.port)
                    }
                };
                let nodes = ready_on(workload).into_iter();
                backends.extend(
                    target
                        .into_iter()
                        .flat_map(|target| nodes.clone().map(move |node| (node, target, workload.key()))),
                );
            }
        }
    }
    table
}

/// Is `address` in `cidr` (`10.0.0.0/8`, `fd00::/8`)? One that cannot be read holds nothing.
fn within_cidr(cidr: &str, address: IpAddr) -> bool {
    let bits = |ip: IpAddr| -> (u128, u32) {
        match ip {
            IpAddr::V4(ip) => (u128::from(u32::from(ip)), 32),
            IpAddr::V6(ip) => (u128::from(ip), 128),
        }
    };
    let Some((net, length)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(net), Ok(length)) = (net.parse::<IpAddr>(), length.parse::<u32>()) else {
        return false;
    };
    let ((net, size), (address, same)) = (bits(net), bits(address));
    let shift = size.checked_sub(length);
    size == same && shift.is_some_and(|shift| net.checked_shr(shift) == address.checked_shr(shift))
}

/// Can a rule's peer be told from where a connection comes from? Workloads share their
/// node's addresses for now, so one named by namespace or labels cannot.
fn told_apart(peer: &Peer) -> bool {
    peer.namespace.is_none() && peer.selector.is_empty()
}

/// May a connection from `from` (the node `node`, if it is one) reach the Workload
/// `workload` on `port`? Yes when no NetworkPolicy is for the Workload; otherwise the
/// first ingress rule that fits says, and when none fits, no. Where a rule names peers
/// that cannot be told apart yet, it errs on the side of no: an allow rule lets nobody
/// in for them, a deny rule keeps everybody out.
pub fn admits(store: &Store, workload: &str, node: Option<&str>, from: IpAddr, port: u16) -> bool {
    let Some(target) = store.get(workload) else {
        return false;
    };
    let mut chosen = false;
    for policy in store.list(Some("NetworkPolicy")) {
        let Ok(spec) = serde_json::from_value::<NetworkPolicySpec>(policy.spec.clone()) else {
            continue;
        };
        let has = |(label, value): (&String, &String)| target.metadata.labels.get(label) == Some(value);
        if namespace(policy) != namespace(target) || !spec.selector.iter().all(has) {
            continue;
        }
        chosen = true;
        for rule in &spec.ingress {
            let allow = rule.action == PolicyAction::Allow;
            let fits = |peer: &Peer| {
                let here = peer.node.as_deref().is_none_or(|name| Some(name) == node);
                let there = peer.cidr.as_deref().is_none_or(|cidr| within_cidr(cidr, from));
                here && there && (told_apart(peer) || !allow)
            };
            let port_fits = rule.ports.is_empty() || rule.ports.contains(&port);
            if port_fits && (rule.peers.is_empty() || rule.peers.iter().any(fits)) {
                return allow;
            }
        }
    }
    !chosen
}

/// What a NetworkPolicy's status is to be told, if it is not already.
fn policy_unsaid(policy: &Resource) -> Option<serde_json::Map<String, Value>> {
    let report = policy_report(policy);
    if policy.status.as_ref() == Some(&report) {
        return None;
    }
    let Value::Object(fields) = report else {
        unreachable!("an object")
    };
    Some(fields)
}

/// What a NetworkPolicy's status says: whether all of it is enforced.
fn policy_report(policy: &Resource) -> Value {
    let Ok(spec) = serde_json::from_value::<NetworkPolicySpec>(policy.spec.clone()) else {
        return json!({ "state": "error", "message": "cannot read this NetworkPolicy" });
    };
    let mut gaps = Vec::new();
    if !spec.egress.is_empty() {
        gaps.push("egress rules are not enforced yet");
    }
    if spec
        .ingress
        .iter()
        .flat_map(|rule| &rule.peers)
        .any(|peer| !told_apart(peer))
    {
        gaps.push(
            "peers by namespace or selector cannot be told apart yet: \
             an allow rule lets none of them in, a deny rule keeps everybody out",
        );
    }
    match gaps.is_empty() {
        // (A message from before has to go: fields that are not written stay.)
        true => json!({ "state": "enforced", "message": null }),
        false => json!({ "state": "partial", "message": gaps.join("; ") }),
    }
}

/// Counts the connections of each Service port, so each goes to the next backend of its
/// own Service (one busy Service does not move the others' turns).
#[derive(Default)]
struct Turns(Mutex<BTreeMap<(Ipv6Addr, u16), usize>>);

impl Turns {
    fn next(&self, key: (Ipv6Addr, u16)) -> usize {
        let mut turns = self.0.lock().expect("nothing panics holding the turns");
        let turn = turns.entry(key).or_default();
        *turn = turn.wrapping_add(1);
        *turn - 1
    }

    /// Forget the ports that are gone.
    fn keep(&self, table: &Table) {
        self.0
            .lock()
            .expect("nothing panics holding the turns")
            .retain(|key, _| table.contains_key(key));
    }
}

struct Proxy {
    shared: Arc<Shared>,
    prefix: Ipv6Addr,
    table: Mutex<Table>,
    turns: Turns,
}

impl Proxy {
    fn me(&self) -> &str {
        self.shared.members.me()
    }

    /// A connection to the replica behind `backend`: on this machine, or through the
    /// kithd of the node it is on.
    async fn reach(&self, (node, port, workload): &Backend) -> std::io::Result<TcpStream> {
        if node == self.me() {
            // (Whoever connects to a Service's address is on this node: only it has it.)
            if !self.admits(workload, kith_mesh::node_address(self.prefix, node), *port) {
                return Err(std::io::Error::other("a NetworkPolicy says no"));
            }
            return local(*port).await;
        }
        let relay = {
            let state = self.shared.store.lock().expect("nothing panics holding the store");
            let status = state
                .store
                .get(&format!("Node/{node}"))
                .and_then(|node| node.status.as_ref());
            status.and_then(|status| u16::try_from(status["mesh"]["port"].as_u64()?).ok())
        };
        let relay = relay.ok_or_else(|| std::io::Error::other(format!("node {node} is not on the mesh")))?;
        let there = SocketAddr::new(kith_mesh::node_address(self.prefix, node).into(), relay);
        let mut stream = within(TcpStream::connect(there)).await?;
        stream.write_all(format!("{port} {workload}\n").as_bytes()).await?;
        // It says so (one byte) when it has the replica; if it hangs up instead (a
        // policy, a replica just gone), the next backend is tried.
        within(stream.read_u8()).await?;
        Ok(stream)
    }

    /// Someone connected to a Service: pass the connection to its next backend that
    /// takes it.
    async fn serve(&self, key: (Ipv6Addr, u16), mut client: TcpStream) {
        let backends = {
            let table = self.table.lock().expect("nothing panics holding the table");
            table.get(&key).cloned().unwrap_or_default()
        };
        // (No turn is taken, or kept, for what has nothing behind it.)
        let first = if backends.is_empty() { 0 } else { self.turns.next(key) };
        for at in 0..backends.len() {
            if let Ok(mut backend) = self.reach(&backends[(first + at) % backends.len()]).await {
                let _ = tokio::io::copy_bidirectional(&mut client, &mut backend).await;
                return;
            }
        }
        // (Nothing behind it, or nothing that answers: the client sees the connection close.)
    }

    /// May a connection from the mesh address `from` reach `workload` on `port`?
    fn admits(&self, workload: &str, from: Ipv6Addr, port: u16) -> bool {
        let state = self.shared.store.lock().expect("nothing panics holding the store");
        let is = |node: &&Resource| kith_mesh::node_address(self.prefix, &node.metadata.name) == from;
        let node = state.store.list(Some("Node")).find(is);
        let node = node.map(|node| node.metadata.name.as_str());
        admits(&state.store, workload, node, from.into(), port)
    }

    /// Another node passes on a connection for a replica here: the port and the Workload
    /// come first, on a line. Only for what a Service has a backend for on this node,
    /// and only from where the Workload's NetworkPolicies let it.
    async fn take(&self, mut from: TcpStream) -> Option<()> {
        let IpAddr::V6(caller) = from.peer_addr().ok()?.ip() else {
            return None;
        };
        let mut line = Vec::new();
        while line.last() != Some(&b'\n') {
            line.push(within(from.read_u8()).await.ok()?);
            if line.len() > 300 {
                return None;
            }
        }
        let line = std::str::from_utf8(&line).ok()?.trim();
        let (port, workload) = line.split_once(' ')?;
        let port: u16 = port.parse().ok()?;
        let asked_for = {
            let table = self.table.lock().expect("nothing panics holding the table");
            let mut backends = table.values().flatten();
            backends.any(|(node, backend, of)| node == self.me() && *backend == port && of == workload)
        };
        if !asked_for || !self.admits(workload, caller, port) {
            return None;
        }
        let mut replica = local(port).await.ok()?;
        from.write_all(b"+").await.ok()?;
        tokio::io::copy_bidirectional(&mut from, &mut replica)
            .await
            .ok()
            .map(drop)
    }

    /// Accept on `listener` for good, each connection from the mesh handled by `with`.
    async fn accept<F, Fut>(self: Arc<Self>, listener: TcpListener, with: F)
    where
        F: Fn(Arc<Proxy>, TcpStream) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        loop {
            let Ok((stream, from)) = listener.accept().await else {
                // (Out of file descriptors, say: not in a tight loop.)
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            // Whoever routes one of our addresses to this machine from outside is not on the mesh.
            if matches!(from.ip(), IpAddr::V6(ip) if kith_mesh::in_mesh(self.prefix, ip)) {
                tokio::spawn(with(self.clone(), stream));
            }
        }
    }
}

async fn within<T>(doing: impl Future<Output = std::io::Result<T>>) -> std::io::Result<T> {
    tokio::time::timeout(CONNECT, doing)
        .await
        .map_err(std::io::Error::other)?
}

/// A replica on this machine, wherever it listens.
async fn local(port: u16) -> std::io::Result<TcpStream> {
    match within(TcpStream::connect(("127.0.0.1", port))).await {
        Ok(stream) => Ok(stream),
        Err(_) => within(TcpStream::connect(("::1", port))).await,
    }
}

/// Listen for every Service on this node's mesh interface, until stopped. `port` is the
/// TCP port other nodes pass connections on to (the mesh's own, which is UDP).
///
/// With `strays` (a node with the ingress), ports 443 and 80 of the Services' addresses
/// are not listened on here: the ingress has those ports, and sends what is ours on.
pub async fn run(
    shared: Arc<Shared>,
    port: u16,
    mut strays: Option<mpsc::UnboundedReceiver<TcpStream>>,
    mut stopping: watch::Receiver<bool>,
) {
    let Some(cluster) = &shared.cluster else { return };
    let prefix = crate::mesh::prefix(&cluster.me.ca);
    let proxy = Arc::new(Proxy {
        shared: shared.clone(),
        prefix,
        table: Mutex::default(),
        turns: Turns::default(),
    });
    let me = kith_mesh::node_address(prefix, proxy.me());
    // (False again if the ingress gives up: then the ports are ours after all.)
    let elsewhere = Arc::new(AtomicBool::new(strays.is_some()));
    let stray = strays.take().map(|mut strays| {
        let (proxy, elsewhere) = (proxy.clone(), elsewhere.clone());
        tokio::spawn(async move {
            while let Some(stream) = strays.recv().await {
                let (Ok(SocketAddr::V6(at)), Ok(SocketAddr::V6(from))) = (stream.local_addr(), stream.peer_addr())
                else {
                    continue;
                };
                if kith_mesh::in_mesh(prefix, *from.ip()) {
                    let proxy = proxy.clone();
                    tokio::spawn(async move { proxy.serve((*at.ip(), at.port()), stream).await });
                }
            }
            elsewhere.store(false, Ordering::Relaxed);
        })
    });
    let mut listening: BTreeMap<(Ipv6Addr, u16), tokio::task::JoinHandle<()>> = BTreeMap::new();
    let mut generation = shared.generation.subscribe();
    loop {
        let (wanted, reports) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let table = table(&state.store, prefix);
            // (A Service that was refused its host says so, in `expose`; the others say nothing.)
            let refused = crate::ingress::exposed(&state.store, prefix).1;
            // What `kith get service` shows; written by the node that leads the store.
            let stale = |(key, address): (String, Ipv6Addr)| {
                let backends = table.iter().filter(|((at, _), _)| *at == address);
                let backends: BTreeSet<&Backend> = backends.flat_map(|(_, backends)| backends).collect();
                let expose = refused
                    .get(&key)
                    .map(|message| json!({ "state": "refused", "message": message }));
                let report = json!({
                    "address": address.to_string(), "backends": backends.len(), "expose": expose,
                });
                let live = state.store.get(&key).and_then(|service| service.status.as_ref());
                let Value::Object(fields) = report else {
                    unreachable!("an object")
                };
                // (Only these fields: the ingress writes others.)
                let same = |(field, value): (&String, &Value)| live.is_some_and(|live| &live[field] == value);
                (!fields.iter().all(same)).then_some((key, fields))
            };
            let mut reports: Vec<_> = addresses(&state.store, prefix).into_iter().filter_map(stale).collect();
            for policy in state.store.list(Some("NetworkPolicy")) {
                reports.extend(policy_unsaid(policy).map(|fields| (policy.key(), fields)));
            }
            (table, reports)
        };
        let metrics = shared.raft.metrics().borrow().clone();
        if metrics.current_leader == Some(metrics.id) && !reports.is_empty() {
            let reported = shared.submit(kith_store::Command::Patch { statuses: reports }).await;
            if let Err(e) = reported {
                eprintln!("kithd: services: writing their status: {e}");
            }
        }
        // The relay, and one listener for each Service port; one whose address is not on
        // the interface yet (the mesh puts it there) is tried again shortly.
        let mut keys: BTreeSet<(Ipv6Addr, u16)> = wanted.keys().copied().collect();
        let elsewhere = elsewhere.load(Ordering::Relaxed);
        keys.retain(|(_, port)| !(elsewhere && [443, 80].contains(port)));
        keys.insert((me, port));
        proxy.turns.keep(&wanted);
        *proxy.table.lock().expect("nothing panics holding the table") = wanted;
        listening.retain(|key, task| {
            let keep = keys.contains(key) && !task.is_finished();
            if !keep {
                task.abort();
            }
            keep
        });
        let mut waiting = false;
        for key in keys {
            if listening.contains_key(&key) {
                continue;
            }
            let Ok(listener) = TcpListener::bind(SocketAddr::new(key.0.into(), key.1)).await else {
                waiting = true;
                continue;
            };
            let task = if key == (me, port) {
                let take = |proxy: Arc<Proxy>, stream| async move {
                    let _ = proxy.take(stream).await;
                };
                tokio::spawn(proxy.clone().accept(listener, take))
            } else {
                let serve = move |proxy: Arc<Proxy>, stream| async move { proxy.serve(key, stream).await };
                tokio::spawn(proxy.clone().accept(listener, serve))
            };
            listening.insert(key, task);
        }
        let again = Duration::from_millis(if waiting { 500 } else { 5000 });
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(again) => {}
            _ = stopping.changed() => break,
        }
    }
    listening
        .values()
        .chain(&stray)
        .for_each(tokio::task::JoinHandle::abort);
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: web, labels: { app: web } }
spec:
  replicas: 3
  template:
    containers: [{ name: main, image: example.org/web, ports: [{ name: http, port: 8080 }] }]
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: other, labels: { app: other } }
spec:
  template:
    exec: [{ name: run, command: [sleep, inf] }]
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: web }
spec:
  selector: { app: web }
  ports:
    - { port: 80, targetPort: http }
    - { port: 9000 }
    - { port: 53, protocol: udp }
";

    #[test]
    fn connections_go_to_ready_replicas() {
        let mut store = Store::default();
        for resource in Resource::from_source(HOME).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let unit = |replica: u32, node: &str, ready: bool| json!({ "name": "main", "replica": replica, "node": node, "ready": ready });
        let web = json!({ "containers": [unit(0, "a", true), unit(1, "b", true), unit(2, "b", false)] });
        store.set_status("Workload/default/web", Some(web)).unwrap();
        let other = json!({ "containers": [unit(0, "c", true)] });
        store.set_status("Workload/default/other", Some(other)).unwrap();

        let prefix = kith_mesh::prefix(b"test");
        let address = addresses(&store, prefix)["Service/default/web"];
        assert_eq!(address, kith_mesh::service_address(prefix, "default", "web"));
        let table = table(&store, prefix);
        // The named port is the container's; a port with no target is itself; UDP is left out.
        let of = "Workload/default/web".to_string();
        let to = |port: u16| vec![("a".to_string(), port, of.clone()), ("b".to_string(), port, of.clone())];
        let wanted = Table::from([((address, 80), to(8080)), ((address, 9000), to(9000))]);
        assert_eq!(table, wanted);

        // The Service's name, where the cluster's names are asked.
        let (zones, _) = crate::dns::zones_of(&store, Some(prefix));
        let found = zones
            .lookup("10.0.0.1".parse().unwrap(), "web.default.kith", 28)
            .unwrap();
        assert_eq!(found.answers[0].data, kith_dns::Rdata::Aaaa(address));
    }

    #[test]
    fn ingress_proxy_turns_are_each_services_own() {
        let turns = Turns::default();
        let (a, b) = ((Ipv6Addr::LOCALHOST, 80), (Ipv6Addr::LOCALHOST, 81));
        assert_eq!([turns.next(a), turns.next(a), turns.next(a)], [0, 1, 2]);
        assert_eq!([turns.next(b), turns.next(b)], [0, 1]);
        // A port that is gone starts over if it comes back.
        turns.keep(&Table::from([(b, vec![])]));
        assert_eq!([turns.next(a), turns.next(b)], [0, 2]);
    }

    #[test]
    fn ingress_proxy_policy_status_settles_from_partial_to_enforced() {
        let policy = |ingress: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: NetworkPolicy\nmetadata: {{ name: p }}\n\
                 spec:\n  selector: {{ app: web }}\n  ingress: {ingress}\n"
            )
        };
        let mut store = Store::default();
        let key = "NetworkPolicy/default/p";
        // What the leader does: write what is not said yet, merged into the status as a Patch does.
        let settle = |store: &mut Store| -> Option<Value> {
            let fields = policy_unsaid(store.get(key).unwrap())?;
            let mut status = match store.get(key).unwrap().status.clone() {
                Some(Value::Object(status)) => status,
                _ => serde_json::Map::new(),
            };
            status.extend(fields);
            store.set_status(key, Some(status.into())).unwrap();
            store.get(key).unwrap().status.clone()
        };
        let apply = |store: &mut Store, source: &str| {
            for resource in Resource::from_source(source).unwrap() {
                store.apply(resource.unwrap()).unwrap();
            }
        };
        apply(
            &mut store,
            &policy("[{ action: allow, peers: [{ selector: { app: other } }] }]"),
        );
        assert_eq!(settle(&mut store).unwrap()["state"], "partial");
        assert!(settle(&mut store).is_none());

        // The rules change to ones that can all be enforced: the status says so once, with
        // no message left over, and then nothing more is written.
        apply(&mut store, &policy("[{ action: allow, peers: [{ node: a }] }]"));
        let settled = settle(&mut store).unwrap();
        assert_eq!(settled, json!({ "state": "enforced", "message": null }));
        assert!(settle(&mut store).is_none());
    }

    #[test]
    fn policies_say_who_gets_in() {
        let mut store = Store::default();
        let policy = |name: &str, rules: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: NetworkPolicy\nmetadata: {{ name: {name} }}\n\
                 spec:\n  selector: {{ app: web }}\n  ingress: {rules}\n"
            )
        };
        let apply = |store: &mut Store, source: &str| {
            for resource in Resource::from_source(source).unwrap() {
                store.apply(resource.unwrap()).unwrap();
            }
        };
        apply(&mut store, HOME);
        let (web, other) = ("Workload/default/web", "Workload/default/other");
        let from: IpAddr = "fd00::1".parse().unwrap();
        let asks =
            |store: &Store, workload: &str, node: &str, port: u16| admits(store, workload, Some(node), from, port);
        // No policy: everyone. A workload that is not there: no one.
        assert!(asks(&store, web, "a", 8080) && !asks(&store, "Workload/default/gone", "a", 80));

        // The first rule that fits says; with a policy and no rule that fits, no.
        let rules = "[{ action: deny, peers: [{ node: c }] }, { action: allow, peers: [{ node: a }, { cidr: 'fd00::/64' }], ports: [8080] }]";
        apply(&mut store, &policy("web", rules));
        assert!(asks(&store, web, "a", 8080) && asks(&store, web, "b", 8080));
        assert!(!asks(&store, web, "c", 8080) && !asks(&store, web, "a", 9000));
        assert!(!admits(&store, web, Some("b"), "fd01::1".parse().unwrap(), 9000));
        // Not for other workloads.
        assert!(asks(&store, other, "c", 1));
        let report = policy_report(store.get("NetworkPolicy/default/web").unwrap());
        assert_eq!(report, json!({ "state": "enforced", "message": null }));

        // Peers by label cannot be told apart yet: allowing them lets nobody in, denying
        // them keeps everybody out, and the status says so.
        let mut labels = Store::default();
        apply(&mut labels, HOME);
        apply(
            &mut labels,
            &policy("web", "[{ action: allow, peers: [{ selector: { app: other } }] }]"),
        );
        assert!(!asks(&labels, web, "a", 8080));
        let report = policy_report(labels.get("NetworkPolicy/default/web").unwrap());
        assert_eq!(report["state"], "partial");
        let rules = "[{ action: deny, peers: [{ namespace: other }] }, { action: allow }]";
        let mut denied = Store::default();
        apply(&mut denied, HOME);
        apply(&mut denied, &policy("web", rules));
        assert!(!asks(&denied, web, "a", 8080));

        assert!(within_cidr("10.0.0.0/8", "10.9.9.9".parse().unwrap()));
        assert!(!within_cidr("10.0.0.0/8", "11.0.0.1".parse().unwrap()));
        assert!(within_cidr("0.0.0.0/0", "11.0.0.1".parse().unwrap()));
        assert!(!within_cidr("0.0.0.0/0", from) && !within_cidr("10.0.0.0/40", "10.0.0.1".parse().unwrap()));
        assert!(!within_cidr("nonsense", from));
    }
}
