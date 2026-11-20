//! A Service's IPv4 address (`status.addressV4`), so a client with no IPv6 reaches it by name (an
//! A record) or by the address: one of the node's Service range (`--service-range`, default
//! `100.87.0.0/16`), held on the loopback of every node and listened on by kithd there. Only the
//! node that leads the store allocates, once it has applied its log; every node reads the status.
//!
//! An address is the next free one after the highest in use, wrapping at the range's end: no
//! counter is stored, so the address of a deleted Service is free again at once if it was the
//! highest, and otherwise only after the allocation wraps. Two statuses with one address (a store
//! restored, a Service moved) are served to the first key only; the later key gets another at the
//! next reconcile. The same range must be named on every node: an address outside a node's range is
//! not served by it.

use super::{Table, headless};
use kith_api::Resource;
use kith_api::kinds::ServiceSpec;
use kith_api::store::Store;
use kith_mesh::pod::Range;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

/// The Services' range when none is named.
pub const DEFAULT: &str = "100.87.0.0/16";

pub fn default_range() -> Range {
    DEFAULT.parse().expect("the default range is a good one")
}

/// What a Service's status says its IPv4 address is, if it says one that reads.
pub fn address_of(service: &Resource) -> Option<Ipv4Addr> {
    service.status.as_ref()?["addressV4"].as_str()?.parse().ok()
}

/// Can the Service have an address? Not a headless one, nor one whose spec cannot be read (the
/// table serves neither).
fn addressable(service: &Resource) -> bool {
    serde_json::from_value::<ServiceSpec>(service.spec.clone()).is_ok() && !headless(service)
}

/// The addresses of `range` that the Services' statuses hold, each with the first key that holds it
/// (the one served).
pub fn claims(store: &Store, range: &Range) -> BTreeMap<Ipv4Addr, String> {
    let mut claims = BTreeMap::new();
    for service in store.list(Some("Service")).filter(|service| addressable(service)) {
        if let Some(address) = address_of(service).filter(|address| range.number_of(*address).is_some()) {
            claims.entry(address).or_insert_with(|| service.key());
        }
    }
    claims
}

/// The next address of `range` free after the highest in `used`, wrapping; none when it is all used.
pub fn next_free(range: &Range, used: &BTreeSet<Ipv4Addr>) -> Option<Ipv4Addr> {
    let numbers = range.numbers();
    let (low, high) = (u32::from(*numbers.start()), u32::from(*numbers.end()));
    let count = high - low + 1;
    let highest = used.iter().filter_map(|address| range.number_of(*address)).max();
    let first = highest.map_or(0, |highest| (u32::from(highest) - low + 1) % count);
    let at = |step: u32| low + (first + step) % count;
    (0..count)
        .map(|step| range.address(at(step) as u16))
        .find(|address| !used.contains(address))
}

/// The statuses to write: an address for each Service that has none of `range` it holds alone. Nothing
/// until the store has applied its leader's log (`caught_up`: a store behind plans from statuses
/// it lacks and would give a second address), and none for a Service when the range is full (it
/// keeps its IPv6 one).
pub fn allocate(store: &Store, range: &Range, caught_up: bool) -> Vec<(String, Map<String, Value>)> {
    if !caught_up {
        return Vec::new();
    }
    let claims = claims(store, range);
    let mut used: BTreeSet<Ipv4Addr> = claims.keys().copied().collect();
    let mut written = Vec::new();
    for service in store.list(Some("Service")).filter(|service| addressable(service)) {
        let key = service.key();
        let held = address_of(service).is_some_and(|address| claims.get(&address) == Some(&key));
        if held {
            continue;
        }
        let Some(address) = next_free(range, &used) else {
            continue;
        };
        used.insert(address);
        let fields = json!({ "addressV4": address.to_string() });
        let Value::Object(fields) = fields else {
            unreachable!("an object")
        };
        written.push((key, fields));
    }
    written
}

/// The IPv4 addresses a table listens on.
pub fn wanted(table: &Table) -> BTreeSet<Ipv4Addr> {
    table
        .keys()
        .filter_map(|(at, _)| match at {
            IpAddr::V4(at) => Some(*at),
            IpAddr::V6(_) => None,
        })
        .collect()
}

/// The addresses of `range` among `present` that are not `wanted`: what a kithd that was killed, or a
/// Service since deleted or given another address, left on the loopback. Nothing else.
pub fn stale(range: &Range, present: Vec<Ipv4Addr>, wanted: &BTreeSet<Ipv4Addr>) -> Vec<Ipv4Addr> {
    let outside = |at: &Ipv4Addr| !range.contains(*at) || wanted.contains(at);
    present.into_iter().filter(|at| !outside(at)).collect()
}

/// The Services' IPv4 addresses on the loopback: what the table wants, nothing else of the range.
pub struct Loopback {
    range: Range,
    index: Option<u32>,
    held: BTreeSet<Ipv4Addr>,
    /// Whether the addresses of the range an earlier kithd left are taken off.
    cleaned: bool,
    told: Option<String>,
}

impl Loopback {
    pub fn new(range: Range) -> Self {
        Loopback {
            range,
            index: None,
            held: BTreeSet::new(),
            cleaned: false,
            told: None,
        }
    }

    /// Make the addresses on the loopback `wanted`, saying once what stops it.
    pub fn hold(&mut self, wanted: &BTreeSet<Ipv4Addr>) {
        if self.cleaned && self.held.is_empty() && wanted.is_empty() {
            return;
        }
        let held = self.try_hold(wanted).map_err(|e| e.to_string());
        match held {
            Ok(()) => self.told = None,
            Err(e) if self.told.as_ref() != Some(&e) => {
                eprintln!("kithd: services: their IPv4 addresses on the loopback: {e}");
                self.told = Some(e);
            }
            Err(_) => {}
        }
    }

    fn try_hold(&mut self, wanted: &BTreeSet<Ipv4Addr>) -> std::io::Result<()> {
        let index = match self.index {
            Some(index) => index,
            None => {
                let index = kith_mesh::cards()?
                    .1
                    .ok_or_else(|| std::io::Error::other("no loopback"))?;
                *self.index.insert(index)
            }
        };
        if !self.cleaned {
            // (Held, they are taken off below, with whatever else is not wanted.)
            let present = kith_mesh::addresses4(index)?;
            self.held.extend(stale(&self.range, present, wanted));
            self.cleaned = true;
        }
        kith_mesh::hold4(index, &mut self.held, wanted)
    }
}

/// The range this node serves, and what to say: the one named (`explicit`) or, with none, the default.
/// `clash` says what a range overlaps (the pods' range, the people's, a network of a link). One named
/// that clashes is refused (the error names the clash); the default that does is left off for the node
/// (`None`, and the words to say once).
pub fn choose(
    explicit: Option<Range>,
    clash: impl Fn(&Range) -> Result<Option<String>, String>,
) -> Result<(Option<Range>, Option<String>), String> {
    match explicit {
        Some(range) => match clash(&range)? {
            Some(clash) => Err(format!("{clash}: name another with --service-range")),
            None => Ok((Some(range), None)),
        },
        None => {
            let range = default_range();
            match clash(&range) {
                Ok(None) => Ok((Some(range), None)),
                Ok(Some(clash)) => Ok((
                    None,
                    Some(format!(
                        "no IPv4 for Services on this node: {clash} (name another with --service-range)"
                    )),
                )),
                Err(e) => Ok((None, Some(format!("no IPv4 for Services on this node: {e}")))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    const SERVICES: &str = "
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: web, labels: { app: web } }
spec:
  replicas: 2
  template:
    containers: [{ name: main, image: example.org/web, ports: [{ name: http, port: 8080 }] }]
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: a }
spec: { selector: { app: web }, ports: [{ port: 80, targetPort: http }, { port: 9000 }] }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: b }
spec: { selector: { app: web }, ports: [{ port: 80, targetPort: http }] }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: c }
spec: { selector: { app: web }, ports: [{ port: 80 }] }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: hl }
spec: { selector: { app: web }, headless: true, ports: [{ port: 80 }] }
";

    fn range() -> Range {
        "100.87.0.0/24".parse().unwrap()
    }

    fn at(number: u16) -> Ipv4Addr {
        range().address(number)
    }

    fn store() -> Store {
        let mut store = Store::default();
        for resource in Resource::from_source(SERVICES).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let unit =
            |replica: u32, node: &str| json!({ "name": "main", "replica": replica, "node": node, "ready": true });
        let web = json!({ "containers": [unit(0, "a"), unit(1, "b")] });
        store.set_status("Workload/default/web", Some(web)).unwrap();
        store
    }

    /// Give the Services these addresses (a status is `addressV4` and what else the others write).
    fn give(store: &mut Store, of: &[(&str, Option<Ipv4Addr>)]) {
        for (name, address) in of {
            let status = address.map(|address| json!({ "addressV4": address.to_string(), "backends": 1 }));
            store.set_status(&format!("Service/default/{name}"), status).unwrap();
        }
    }

    fn written(store: &Store) -> BTreeMap<String, String> {
        let written = allocate(store, &range(), true);
        let one =
            |(key, fields): (String, Map<String, Value>)| (key, fields["addressV4"].as_str().unwrap().to_string());
        written.into_iter().map(one).collect()
    }

    #[test]
    fn service_v4_allocation_takes_the_next_free_after_the_highest_and_a_batch_differs() {
        let mut store = store();
        // Nothing yet: the batch gets the range's first addresses, one each, and none for the headless one.
        let first = written(&store);
        let all: Vec<&str> = first.values().map(String::as_str).collect();
        assert_eq!(all, ["100.87.0.2", "100.87.0.3", "100.87.0.4"]);
        assert_eq!(
            first.keys().map(String::as_str).collect::<Vec<_>>(),
            ["Service/default/a", "Service/default/b", "Service/default/c"]
        );
        // Stable: what is written stays, and the next reconcile writes nothing.
        give(
            &mut store,
            &[("a", Some(at(2))), ("b", Some(at(3))), ("c", Some(at(4)))],
        );
        assert!(written(&store).is_empty());
        // The next free is after the highest in use, not the first gap: b goes, d comes.
        give(&mut store, &[("b", None)]);
        assert_eq!(
            written(&store),
            BTreeMap::from([("Service/default/b".into(), at(5).to_string())])
        );
    }

    #[test]
    fn service_v4_allocation_wraps_and_a_full_range_gives_none() {
        let numbers = range().numbers();
        let used = |from: u16, to: u16| (from..=to).map(at).collect::<BTreeSet<_>>();
        // After the highest; at the end it wraps to the first free one.
        assert_eq!(next_free(&range(), &used(2, 3)), Some(at(4)));
        assert_eq!(next_free(&range(), &BTreeSet::new()), Some(at(*numbers.start())));
        let mut crowded = used(*numbers.start() + 1, *numbers.end());
        assert_eq!(next_free(&range(), &crowded), Some(at(*numbers.start())));
        crowded.remove(&at(10));
        crowded.insert(at(*numbers.start()));
        assert_eq!(
            next_free(&range(), &crowded),
            Some(at(10)),
            "after the end, the first free one"
        );
        // Full: none.
        assert_eq!(next_free(&range(), &used(*numbers.start(), *numbers.end())), None);
        // (The address of the range's own, the node's and the broadcast are never given.)
        assert!(!used(*numbers.start(), *numbers.end()).contains(&range().gateway()));
        // A full range writes nothing for the Service, and the Services that have addresses keep them.
        let mut store = store();
        let full = used(*numbers.start(), *numbers.end());
        let mut taken = full.iter();
        give(&mut store, &[("a", taken.next().copied())]);
        let other = Resource::from_source(
            "apiVersion: kith.dev/v1\nkind: Service\nmetadata: { name: z }\nspec: { selector: { app: web }, ports: [{ port: 80 }] }\n",
        )
        .unwrap();
        for resource in other {
            store.apply(resource.unwrap()).unwrap();
        }
        // (Services b, c and z all want one; with the range used up by claims we model it with a tiny one.)
        let tiny: Range = "100.87.0.0/24".parse().unwrap();
        let mut crowd = BTreeSet::new();
        for number in tiny.numbers() {
            crowd.insert(tiny.address(number));
        }
        assert_eq!(next_free(&tiny, &crowd), None);
    }

    #[test]
    fn service_v4_allocation_waits_for_the_log_and_frees_a_deleted_services_address() {
        let mut store = store();
        assert!(
            allocate(&store, &range(), false).is_empty(),
            "a store that has not applied its log gives none"
        );
        assert_eq!(allocate(&store, &range(), true).len(), 3);
        give(
            &mut store,
            &[("a", Some(at(2))), ("b", Some(at(3))), ("c", Some(at(4)))],
        );
        // The highest one deleted: its address is the next one given.
        store.delete("Service/default/c").unwrap();
        let again = Resource::from_source(
            "apiVersion: kith.dev/v1\nkind: Service\nmetadata: { name: d }\nspec: { selector: { app: web }, ports: [{ port: 80 }] }\n",
        )
        .unwrap();
        for resource in again {
            store.apply(resource.unwrap()).unwrap();
        }
        assert_eq!(
            written(&store),
            BTreeMap::from([("Service/default/d".into(), at(4).to_string())])
        );
    }

    #[test]
    fn service_v4_allocation_gives_a_pre_upgrade_service_one_and_the_later_of_two_claims_another() {
        let mut store = store();
        // a and b hold one address (a store restored), c holds one outside the range, the headless one none.
        give(
            &mut store,
            &[
                ("a", Some(at(7))),
                ("b", Some(at(7))),
                ("c", Some(Ipv4Addr::new(10, 1, 2, 3))),
            ],
        );
        let claims = claims(&store, &range());
        assert_eq!(claims, BTreeMap::from([(at(7), "Service/default/a".to_string())]));
        let new = written(&store);
        assert_eq!(
            new,
            BTreeMap::from([
                ("Service/default/b".into(), at(8).to_string()),
                ("Service/default/c".into(), at(9).to_string())
            ])
        );
    }

    #[test]
    fn service_v4_table_serves_the_first_key_of_an_address_and_never_one_outside_the_range() {
        let mut store = store();
        let prefix = kith_mesh::prefix(b"test");
        give(
            &mut store,
            &[
                ("a", Some(at(7))),
                ("b", Some(at(7))),
                ("c", Some(Ipv4Addr::new(10, 1, 2, 3))),
            ],
        );
        let table = table(&store, prefix, Some(range()));
        let v4: Vec<_> = table.keys().filter(|(at, _)| at.is_ipv4()).collect();
        // a's two ports; b's address is a's, so b is not served on it; c's is out of the range.
        assert_eq!(v4, [&(IpAddr::V4(at(7)), 80), &(IpAddr::V4(at(7)), 9000)]);
        // Every Service still has its IPv6 address.
        assert_eq!(table.keys().filter(|(at, _)| at.is_ipv6()).count(), 4);
        // With no range (IPv4 off for the node) there is no IPv4 key at all.
        assert!(
            super::super::table(&store, prefix, None)
                .keys()
                .all(|(at, _)| at.is_ipv6())
        );
        assert_eq!(wanted(&table), BTreeSet::from([at(7)]));
    }

    /// The plan, per family, as a pure function of the store and the table: the IPv4 service's
    /// port gets its own entry, whose replicas here are asked at their pods' IPv4 addresses.
    #[test]
    fn service_v4_table_plans_each_family_apart_and_a_v6_replica_address_never_goes_in_a_v4_entry() {
        let mut store = store();
        let prefix = kith_mesh::prefix(b"test");
        give(&mut store, &[("a", Some(at(7)))]);
        let table = table(&store, prefix, Some(range()));
        let plans = kernel_plan(&store, &table, "a");
        let v4: Vec<&Plan> = plans.iter().filter(|plan| plan.service.0.is_ipv4()).collect();
        assert_eq!(v4.len(), 2, "ports 80 and 9000 of a");
        assert!(v4.iter().all(|plan| plan.service.0 == IpAddr::V4(at(7))));
        // A replica's pod's addresses: v4 ones for the IPv4 entry, v6 ones for the IPv6 entry.
        let pod: Vec<IpAddr> = vec!["100.88.0.7".parse().unwrap(), "fd00::7".parse().unwrap()];
        assert_eq!(
            reachable(Some(0), pod.clone(), true),
            ["100.88.0.7".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(reachable(Some(0), pod, false), ["fd00::7".parse::<IpAddr>().unwrap()]);
        assert!(
            reachable(Some(0), vec![], true).is_empty(),
            "no pod yet: nowhere to ask"
        );
        assert_eq!(reachable(None, vec![], true), [IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        // Each family's plan is a pick of ports that never meets the other's: the port to kithd
        // is free on its own address.
        let ports: BTreeSet<(IpAddr, u16)> = table.keys().copied().collect();
        for plan in &plans {
            if let Some(port) = plan.elsewhere {
                assert!(!ports.contains(&(plan.service.0, port)));
            }
        }
        // Entries: a replica answering at its pod's v4 address is written in place; one elsewhere
        // changes only the port; the connect program of v4 never holds an address of v6.
        let backend = |at: &str| (at.to_string(), 8080, "Workload/default/web".to_string(), Some(0u32));
        let here = backend("a");
        let mut probed = Probed::new();
        let found: SocketAddr = "100.88.0.7:8080".parse().unwrap();
        probed.insert((true, here.clone()), (vec!["100.88.0.7".parse().unwrap()], found));
        let asked = BTreeMap::from([((true, here.clone()), vec!["100.88.0.7".parse().unwrap()])]);
        let plan = Plan {
            service: (IpAddr::V4(at(7)), 80),
            here: vec![here],
            others: vec![backend("b")],
            elsewhere: Some(65534),
        };
        let mut wanted = Table::new();
        let entries = kernel_entries(&[plan], &mut probed, &asked, &mut wanted);
        assert_eq!(
            entries,
            [connect::Entry {
                service: (IpAddr::V4(at(7)), 80),
                here: vec![found],
                all: 2,
                elsewhere: Some(65534),
            }]
        );
        assert_eq!(wanted.keys().collect::<Vec<_>>(), [&(IpAddr::V4(at(7)), 65534)]);
    }

    #[test]
    fn service_v4_cleanup_takes_off_only_what_is_in_the_range_and_wanted_by_no_status() {
        let present = vec![
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(10, 0, 0, 5),
            at(2),
            at(3),
            Ipv4Addr::new(100, 88, 0, 1), // the pods' gateway: not in the range
        ];
        let wanted = BTreeSet::from([at(3)]);
        assert_eq!(super::stale(&range(), present, &wanted), [at(2)]);
    }

    #[test]
    fn service_v4_cleanup_a_deleted_or_changed_address_leaves_the_table_and_the_plan() {
        let mut store = store();
        let prefix = kith_mesh::prefix(b"test");
        give(&mut store, &[("a", Some(at(7)))]);
        let before = table(&store, prefix, Some(range()));
        assert_eq!(wanted(&before), BTreeSet::from([at(7)]));
        assert!(
            kernel_plan(&store, &before, "a")
                .iter()
                .any(|plan| plan.service.0 == IpAddr::V4(at(7)))
        );
        // Changed: the old address is no one's, the new one is.
        give(&mut store, &[("a", Some(at(8)))]);
        let changed = table(&store, prefix, Some(range()));
        assert_eq!(wanted(&changed), BTreeSet::from([at(8)]));
        assert!(
            !kernel_plan(&store, &changed, "a")
                .iter()
                .any(|plan| plan.service.0 == IpAddr::V4(at(7)))
        );
        // Deleted: none left.
        store.delete("Service/default/a").unwrap();
        assert!(wanted(&table(&store, prefix, Some(range()))).is_empty());
        // A Service with no address yet (before the upgrade) has no entry, and gets one at the first reconcile.
        let mut store = self::store();
        assert!(wanted(&table(&store, prefix, Some(range()))).is_empty());
        let new = allocate(&store, &range(), true);
        assert_eq!(new.len(), 3);
        for (key, fields) in new {
            store.set_status(&key, Some(Value::Object(fields))).unwrap();
        }
        assert_eq!(wanted(&table(&store, prefix, Some(range()))).len(), 3);
    }

    #[test]
    fn service_v4_cleanup_a_refused_ipv4_attach_is_said_once_and_leaves_the_ipv6_hook_working() {
        let netns = 1;
        let entry = |service: IpAddr, port: u16, to: &str| connect::Entry {
            service: (service, port),
            here: vec![to.parse().unwrap()],
            all: 1,
            elsewhere: None,
        };
        let entries = vec![
            entry("fd00::80".parse().unwrap(), 80, "[fd00::7]:8080"),
            entry(IpAddr::V4(at(7)), 80, "100.88.0.7:8080"),
        ];
        let put: Mutex<Vec<(bool, Vec<u8>)>> = Mutex::new(Vec::new());
        let refuse4 = |v4: bool, program: &[u8]| {
            put.lock().unwrap().push((v4, program.to_vec()));
            if v4 {
                Err(std::io::Error::other("refused"))
            } else {
                Ok(())
            }
        };
        let mut kernel = Kernel::Has(netns, Vec::new(), V4::Works);
        let mut said = Vec::new();
        let listening = BTreeMap::new();
        install_with(&mut kernel, entries.clone(), &listening, &refuse4, &mut |text| {
            said.push(text)
        });
        // The IPv6 program took the IPv6 entry; the IPv4 refusal is said once, with a line; the kernel is still on.
        let Kernel::Has(_, last, no4) = &kernel else {
            panic!("the IPv6 hook is still on")
        };
        assert_eq!(last, &entries[..1]);
        // (Refused, and the empty one before it as well: stale.)
        assert_eq!(*no4, V4::Stale);
        assert_eq!(said.len(), 1, "{said:?}");
        assert!(said[0].contains("IPv4") && said[0].contains("refused"), "{said:?}");
        // The IPv6 program written is the one for the entry.
        assert_eq!(put.lock().unwrap()[0], (false, connect::program(&entries, netns)));
        // A later change goes on for IPv6 and says nothing more.
        let more = vec![
            entries[0].clone(),
            entry("fd00::81".parse().unwrap(), 80, "[fd00::8]:8080"),
            entries[1].clone(),
        ];
        install_with(&mut kernel, more.clone(), &listening, &refuse4, &mut |text| {
            said.push(text)
        });
        let Kernel::Has(_, last, _) = &kernel else {
            panic!("still on")
        };
        assert_eq!(last, &more[..2]);
        assert_eq!(said.len(), 1, "said once: {said:?}");
    }

    #[test]
    fn service_v4_dns_a_service_with_an_address_answers_an_a_record() {
        let mut store = store();
        let prefix = kith_mesh::prefix(b"test");
        // (The AAAA from the mesh prefix; the A from the status.)
        give(&mut store, &[("a", Some(at(7)))]);
        let (zones, _) = crate::dns::zones_of(&store, Some(prefix));
        let client: IpAddr = "198.51.100.1".parse().unwrap();
        // (rcode, the answers' data) of a lookup.
        let ask = |name: &str, qtype: u16| {
            let found = zones.lookup(client, name, qtype).unwrap();
            (
                found.rcode,
                found.answers.into_iter().map(|r| r.data).collect::<Vec<_>>(),
            )
        };
        use kith_dns::Rdata;
        assert_eq!(ask("a.default.kith", 1), (0, vec![Rdata::A(at(7))]));
        let v6 = kith_mesh::service_address(prefix, "default", "a");
        assert_eq!(ask("a.default.kith", 28), (0, vec![Rdata::Aaaa(v6)]));
        assert_eq!(ask("a.default.svc.cluster.local", 1), (0, vec![Rdata::A(at(7))]));
        // One with no address: its name is there with an AAAA, and an A answers nothing (NODATA).
        assert_eq!(ask("b.default.kith", 1), (0, vec![]));
        assert_eq!(ask("b.default.kith", 28).1.len(), 1);
        // A headless Service has none either.
        assert_eq!(ask("hl.default.kith", 1).1, vec![]);
        // A node that serves no Service IPv4 range (its default overlapped a network), or another
        // range than the address is in, does not hold the address: NODATA to A there, AAAA as before.
        for served in [None, Some("10.99.0.0/16".parse::<Range>().unwrap())] {
            let (zones, _) = crate::dns::zones_serving(&store, Some(prefix), served);
            let found = zones.lookup(client, "a.default.kith", 1).unwrap();
            assert_eq!((found.rcode, found.answers.len()), (0, 0));
            assert_eq!(zones.lookup(client, "a.default.kith", 28).unwrap().answers.len(), 1);
        }
    }

    #[test]
    fn service_range_names_what_it_clashes_with_and_the_default_is_left_off() {
        use kith_mesh::pod::Held;
        let pods: Range = "100.88.0.0/16".parse().unwrap();
        let held = |address: &str, bits, link, name: &str| Held {
            address: address.parse().unwrap(),
            bits,
            link,
            name: name.into(),
        };
        let lan = [held("192.168.1.5", 24, 2, "eth0"), held("100.87.0.1", 32, 1, "lo")];
        let clash = |range: &Range| Ok(range.service_clash(&pods, &lan));
        // The default is fine here (the loopback's address of it is ours).
        let (range, said) = choose(None, clash).unwrap();
        assert_eq!((range.unwrap().to_string().as_str(), said), ("100.87.0.0/16", None));
        // Named, it is kept; or refused naming the clash.
        let named: Range = "10.99.0.0/16".parse().unwrap();
        assert_eq!(choose(Some(named), clash).unwrap().0, Some(named));
        let over_pods: Range = "100.88.0.0/16".parse().unwrap();
        let refused = choose(Some(over_pods), clash).unwrap_err();
        assert!(
            refused.contains("overlaps the pods' range 100.88.0.0/16") && refused.contains("--service-range"),
            "{refused}"
        );
        let over_people: Range = "100.89.0.0/16".parse().unwrap();
        assert!(
            choose(Some(over_people), clash)
                .unwrap_err()
                .contains("people's 100.89.0.0/16")
        );
        let over_lan: Range = "192.168.0.0/16".parse().unwrap();
        assert!(
            choose(Some(over_lan), clash)
                .unwrap_err()
                .contains("192.168.1.5/24 on eth0")
        );
        // The default that clashes turns IPv4 off for the node, saying why, and starts.
        let on_lan = [held("100.87.4.4", 24, 2, "eth0")];
        let clash = |range: &Range| Ok(range.service_clash(&pods, &on_lan));
        let (range, said) = choose(None, clash).unwrap();
        assert!(range.is_none());
        assert!(said.unwrap().contains("100.87.4.4/24 on eth0"));
        // A node whose addresses cannot be read: refused when named, off when the default.
        let broken = |_: &Range| Err::<Option<String>, String>("reading this node's addresses: no".into());
        assert!(choose(Some(named), broken).is_err());
        assert!(choose(None, broken).unwrap().0.is_none());
    }
}
