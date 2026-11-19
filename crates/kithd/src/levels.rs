//! The people's levels held on the node started with `--people` (docs/adr-people.md, "Built:
//! slice E1"): the store's AccessLevels and RemotePeers become kith-mesh's table of level chains,
//! the routing rules 9010 to 9012, and the peers of kwg0, in that order, and a removed or narrowed
//! peer is cut within seconds. [`wanted`] says what the store asks for; [`Tend`] makes the kernel so.
//
// ponytail: a pass is one netlink round of each kind, every 10 s or on a change of what the store
// asks for; the kernel is read again each time rather than trusted from the last pass, so a rule or
// a table taken away by hand is put back.

use crate::Shared;
use kith_api::Resource;
use kith_api::kinds::{AccessLevelSpec, Protocol, RemotePeerSpec, ServiceSpec};
use kith_api::store::Store;
use kith_mesh::people::{Internet, Level, Person};
use kith_mesh::{Key, Peer};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Is kwg0 made, behind its table and the rules that send nowhere? Set by `people::up`; the tend
/// loop puts nothing on the device before.
pub static DEVICE_UP: AtomicBool = AtomicBool::new(false);

/// How often the kernel is looked at again with nothing changed in the store.
const EVERY: Duration = Duration::from_secs(10);

/// What the flags give: the mesh's link, the networks a level may name, the API's port.
pub struct Config {
    pub interface: String,
    pub networks: Vec<(IpAddr, u8)>,
    pub api: u16,
    /// The pods' IPv4 range (`--pod-range`): no level's network lies over it, nor over the people's.
    pub pods: (Ipv4Addr, u8),
}

/// `--people-networks`: `ADDRESS/LENGTH`, IPv4 or IPv6, never `/0` (that is the internet's).
pub fn network(text: &str) -> Result<(IpAddr, u8), String> {
    let (address, length) = text.split_once('/').ok_or("as ADDRESS/LENGTH")?;
    let address: IpAddr = address.parse().map_err(|_| "an IPv4 or IPv6 address before the /")?;
    let length: u8 = length.parse().map_err(|_| "a length after the /")?;
    let most = if address.is_ipv4() { 32 } else { 128 };
    if length == 0 || length > most {
        return Err(format!(
            "a length from 1 to {most} (`/0` is the internet, which a level says itself)"
        ));
    }
    Ok((address, length))
}

/// Is `inner` in `outer`, the same family?
fn within(outer: (IpAddr, u8), inner: (IpAddr, u8)) -> bool {
    let bits = |address: IpAddr| match address {
        IpAddr::V4(a) => u128::from(u32::from(a)) << 96,
        IpAddr::V6(a) => u128::from(a),
    };
    let mask = |length: u8| u128::MAX.checked_shl(128 - u32::from(length)).unwrap_or(0);
    outer.0.is_ipv4() == inner.0.is_ipv4()
        && outer.1 <= inner.1
        && bits(outer.0) & mask(outer.1) == bits(inner.0) & mask(outer.1)
}

/// What the store asks of the kernel for this node.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Wanted {
    levels: Vec<(String, Level)>,
    people: Vec<(Person, Peer)>,
    /// The IPv4 addresses of the peers whose level has the home's internet (rule 9011).
    internet: BTreeSet<Ipv4Addr>,
    /// The node's own networks, which a level's `-out` never reaches.
    links: Vec<(IpAddr, u8)>,
    /// What was left out, and why.
    notes: Vec<String>,
}

/// What each peer reaches: its Services' addresses and TCP ports (none is all of them).
pub type Reach = BTreeMap<IpAddr, Arc<Vec<(Ipv6Addr, Vec<u16>)>>>;

/// The Services each of this node's peers reaches, by the peer's address (both of them): what the
/// Service listener lets a person's connection through to (docs/adr-people.md, slice E2b).
pub fn reach(store: &Store, prefixes: (Ipv6Addr, Ipv6Addr), node: &str) -> Reach {
    // (No networks: only the levels' Services are asked of it.)
    let config = Config {
        interface: String::new(),
        networks: Vec::new(),
        api: 0,
        pods: (Ipv4Addr::UNSPECIFIED, 32),
    };
    let asked = wanted(store, prefixes, node, &config, Vec::new());
    let mut reach = BTreeMap::new();
    for (person, _) in &asked.people {
        let Some((_, level)) = asked.levels.iter().find(|(name, _)| *name == person.level) else {
            continue;
        };
        let services = Arc::new(level.services.clone());
        reach.extend(person.v4.map(|v4| (IpAddr::V4(v4), services.clone())));
        reach.extend(person.v6.map(|v6| (IpAddr::V6(v6), services.clone())));
    }
    reach
}

fn status_text(resource: &Resource, field: &str) -> Option<String> {
    let said = resource.status.as_ref()?.get(field)?.as_str()?;
    (!said.is_empty()).then(|| said.to_string())
}

/// The TCP ports of a Service: none for one with UDP only, which the people's table cannot name
/// (a level's Service with no ports is every port).
fn tcp_ports(service: &Resource) -> Vec<u16> {
    let Ok(spec) = serde_json::from_value::<ServiceSpec>(service.spec.clone()) else {
        return Vec::new();
    };
    let ports: BTreeSet<u16> = spec
        .ports
        .iter()
        .filter(|port| port.protocol != Some(Protocol::Udp))
        .map(|port| port.port)
        .collect();
    ports.into_iter().collect()
}

/// One AccessLevel as the table has it, with what was left out of it: its `internet` too.
fn level_of(
    store: &Store,
    spec: &AccessLevelSpec,
    name: &str,
    (mesh, people64): (Ipv6Addr, Ipv6Addr),
    config: &Config,
) -> (Level, bool, Vec<String>) {
    let mut notes = Vec::new();
    let addresses = crate::services::addresses(store, mesh);
    let mut services: BTreeMap<Ipv6Addr, Vec<u16>> = BTreeMap::new();
    for named in &spec.services {
        let keys: Vec<String> = if named == "*" {
            addresses.keys().cloned().collect()
        } else {
            vec![format!("Service/{named}")]
        };
        for key in keys {
            let Some(address) = addresses.get(&key) else {
                notes.push(format!("level {name}: Service {named} is not there, or is headless"));
                continue;
            };
            let ports = store.get(&key).map(tcp_ports).unwrap_or_default();
            if ports.is_empty() {
                if named != "*" {
                    notes.push(format!("level {name}: Service {named} has no TCP port"));
                }
                continue;
            }
            services.entry(*address).or_default().extend(ports);
        }
    }
    let services = services
        .into_iter()
        .map(|(address, ports)| {
            (
                address,
                ports.into_iter().collect::<BTreeSet<_>>().into_iter().collect(),
            )
        })
        .collect();
    let mut networks = Vec::new();
    for net in &spec.networks {
        let Ok(parsed) = network(net) else {
            notes.push(format!("level {name}: network `{net}` is not ADDRESS/LENGTH"));
            continue;
        };
        // (The store refuses these IPv4 ranges at the Apply; a status or a stored level of an older
        // kithd is not trusted to have been through that.)
        let taken = [
            (Ipv4Addr::new(100, 89, 0, 0), 16),
            (Ipv4Addr::new(100, 88, 0, 0), 16),
            config.pods,
        ]
        .into_iter()
        .map(|(address, bits)| (IpAddr::V4(address), bits))
        .find(|taken| within(*taken, parsed) || within(parsed, *taken));
        if let Some(why) = crate::people::over(net, mesh, people64) {
            notes.push(format!("level {name}: {why}"));
        } else if let Some((range, bits)) = taken {
            notes.push(format!(
                "level {name}: network `{net}` overlaps the pods' or the people's range {range}/{bits}"
            ));
        } else if !config.networks.iter().any(|outer| within(*outer, parsed)) {
            notes.push(format!(
                "level {name}: network `{net}` is not in this node's --people-networks"
            ));
        } else {
            networks.push(parsed);
        }
    }
    let resolver = spec.dns.as_deref().and_then(|dns| {
        let parsed = dns.parse::<IpAddr>().ok();
        if parsed.is_none() {
            notes.push(format!("level {name}: dns `{dns}` is not an address"));
        }
        parsed
    });
    let mut home = false;
    let internet = if let Some(exit) = &spec.exit {
        notes.push(format!(
            "level {name}: exit {exit} is not held yet (docs/adr-people.md, slice E2): no internet"
        ));
        Internet::None
    } else if spec.internet == Some(true) {
        home = true;
        Internet::Home
    } else {
        Internet::None
    };
    let level = Level {
        networks,
        services,
        api: (spec.api == Some(true)).then_some(config.api),
        resolver,
        internet,
    };
    (level, home, notes)
}

/// A RemotePeer of this node that has its addresses, as far as it can be put on the device.
struct Candidate {
    name: String,
    level: String,
    person: Person,
    peer: Peer,
}

fn candidate(resource: &Resource, node: &str, people64: Ipv6Addr, notes: &mut Vec<String>) -> Option<Candidate> {
    use base64::Engine as _;
    let spec = serde_json::from_value::<RemotePeerSpec>(resource.spec.clone()).ok()?;
    let name = resource.metadata.name.clone();
    if spec.node != node {
        return None;
    }
    if let Some(why) = status_text(resource, "refused") {
        notes.push(format!("peer {name}: refused: {why}"));
        return None;
    }
    // (No addresses yet: the leader gives them in a moment.)
    let (v4, v6) = crate::people::held(resource)?;
    let [100, 89, high, low] = v4.octets() else {
        notes.push(format!("peer {name}: {v4} is not in 100.89.0.0/16"));
        return None;
    };
    let offset = u16::from_be_bytes([high, low]);
    let six = u128::from(v6);
    // (Not the first two addresses of the range, nor its last: docs/adr-people.md, Review 5.)
    if !(2..0xffff).contains(&offset)
        || six >> 64 != u128::from(people64) >> 64
        || (six as u64) < 2
        || six as u64 == u64::MAX
    {
        notes.push(format!("peer {name}: {v4} and {v6} are not the people's to give"));
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&spec.public_key)
        .ok()?;
    let Ok(key) = Key::try_from(bytes) else {
        notes.push(format!("peer {name}: its public key is not 32 bytes"));
        return None;
    };
    Some(Candidate {
        name,
        level: spec.level.clone(),
        person: Person {
            level: spec.level,
            offset,
            v4: Some(v4),
            v6: Some(v6),
        },
        peer: Peer {
            key,
            endpoint: None,
            allowed: vec![(IpAddr::V4(v4), 32), (IpAddr::V6(v6), 128)],
            keepalive: 0,
        },
    })
}

/// What the store asks of this node (`node`): the levels its peers are in, and its peers with
/// theirs, and `notes` of what it left out. A peer is left out when its address or key is another's
/// (neither has it: docs/adr-people.md, Review 5), when it is refused, or when its level is not there.
pub fn wanted(
    store: &Store,
    (mesh, people64): (Ipv6Addr, Ipv6Addr),
    node: &str,
    config: &Config,
    links: Vec<(IpAddr, u8)>,
) -> Wanted {
    let mut notes = Vec::new();
    let all: Vec<Candidate> = store
        .list(Some("RemotePeer"))
        .filter_map(|resource| candidate(resource, node, people64, &mut notes))
        .collect();
    let clash = |one: &Candidate| {
        all.iter().any(|other| {
            other.name != one.name
                && (other.person.offset == one.person.offset
                    || other.person.v6 == one.person.v6
                    || other.peer.key == one.peer.key)
        })
    };
    let mut specs: BTreeMap<String, Option<AccessLevelSpec>> = BTreeMap::new();
    let mut out = Wanted {
        links,
        ..Wanted::default()
    };
    for one in &all {
        if clash(one) {
            notes.push(format!(
                "peer {}: its address or key is another peer's: left out",
                one.name
            ));
            continue;
        }
        let level = specs.entry(one.level.clone()).or_insert_with(|| {
            let resource = store.get(&format!("AccessLevel/{}", one.level))?;
            serde_json::from_value(resource.spec.clone()).ok()
        });
        let Some(spec) = level else {
            notes.push(format!("peer {}: level {} is not there: left out", one.name, one.level));
            continue;
        };
        if !out.levels.iter().any(|(name, _)| *name == one.level) {
            let (level, _, said) = level_of(store, spec, &one.level, (mesh, people64), config);
            notes.extend(said);
            out.levels.push((one.level.clone(), level));
        }
        let home = out
            .levels
            .iter()
            .any(|(name, l)| *name == one.level && l.internet == Internet::Home);
        if let (true, Some(v4)) = (home, one.person.v4) {
            out.internet.insert(v4);
        }
        out.people.push((one.person.clone(), one.peer.clone()));
    }
    out.levels.sort_by(|a, b| a.0.cmp(&b.0));
    out.people.sort_by_key(|(person, _)| person.offset);
    out.notes = notes;
    out
}

/// The node's own IPv4 networks, but not the people's device's: what a level's `-out` never reaches.
pub fn own_links() -> Vec<(IpAddr, u8)> {
    let Ok(all) = nix::ifaddrs::getifaddrs() else {
        return Vec::new();
    };
    let found = |card: nix::ifaddrs::InterfaceAddress| {
        if card.interface_name == "lo" || card.interface_name == kith_mesh::people::DEVICE {
            return None;
        }
        let address = u32::from(card.address?.as_sockaddr_in()?.ip());
        let mask = u32::from(card.netmask?.as_sockaddr_in()?.ip());
        Some((Ipv4Addr::from(address & mask), mask.count_ones() as u8))
    };
    let nets: BTreeSet<(Ipv4Addr, u8)> = all.filter_map(found).collect();
    nets.into_iter()
        .map(|(address, bits)| (IpAddr::V4(address), bits))
        .collect()
}

type Table = fn(Ipv6Addr, &[Person], &[(String, Level)], &str, &[(IpAddr, u8)]) -> io::Result<()>;

type Rules = io::Result<Vec<(u32, bool, Option<Ipv4Addr>)>>;
type Sent = (Vec<Person>, Vec<(String, Level)>, Vec<(IpAddr, u8)>);

/// What a pass asks of the kernel, as plain functions, so a test can make one fail.
pub struct Kernel {
    pub table: Table,
    pub present: fn() -> io::Result<bool>,
    pub rules: fn() -> Rules,
    pub hold: fn() -> io::Result<()>,
    pub internet: fn(Ipv4Addr, bool) -> io::Result<()>,
    pub set_peers: fn(&[Peer]) -> io::Result<()>,
    pub forget: fn(u32) -> io::Result<()>,
}

impl Kernel {
    pub fn real() -> Kernel {
        Kernel {
            table: kith_mesh::people::send,
            present: kith_mesh::people::table_present,
            rules: kith_mesh::exit::people_rules,
            hold: kith_mesh::exit::people_hold,
            internet: kith_mesh::exit::people_internet,
            set_peers: kith_mesh::people::set_peers,
            forget: kith_mesh::exit::forget_marked,
        }
    }
}

/// What is set in the kernel, and the steps of each pass.
pub struct Tend {
    pub kernel: Kernel,
    people64: Ipv6Addr,
    interface: String,
    /// What the table was last written from: its persons, levels and the node's links.
    sent: Option<Sent>,
    /// What is on the device, by offset (as last set).
    device: BTreeMap<u16, Peer>,
    /// The peers taken off the device whose connections are not flushed yet.
    flush: BTreeSet<u16>,
    /// The kernel calls of the passes since the last clear, in order (the tests read them).
    pub steps: Vec<String>,
}

impl Tend {
    pub fn new(kernel: Kernel, people64: Ipv6Addr, interface: String) -> Tend {
        Tend {
            kernel,
            people64,
            interface,
            sent: None,
            device: BTreeMap::new(),
            flush: BTreeSet::new(),
            steps: Vec::new(),
        }
    }

    /// Make the kernel what `w` asks, in the order of docs/adr-people.md: a peer leaves the device
    /// first, then its rules and the table go, then its connections are flushed; a peer comes on
    /// the device last, after its table and its rules. A step that fails leaves the device with
    /// no peers at all. Says what it could not do.
    pub fn pass(&mut self, w: &Wanted) -> Vec<String> {
        let mut notes = w.notes.clone();
        let step = |steps: &mut Vec<String>, text: String| steps.push(text);

        // 1. Off the device: a peer no longer wanted as it is.
        let wanted: BTreeMap<u16, &Peer> = w.people.iter().map(|(person, peer)| (person.offset, peer)).collect();
        let gone: Vec<u16> = self
            .device
            .iter()
            .filter(|(offset, peer)| wanted.get(offset) != Some(peer))
            .map(|(offset, _)| *offset)
            .collect();
        if !gone.is_empty() {
            step(&mut self.steps, "off the device".into());
            let stays: Vec<Peer> = self
                .device
                .iter()
                .filter(|(offset, _)| !gone.contains(offset))
                .map(|(_, peer)| peer.clone())
                .collect();
            match (self.kernel.set_peers)(&stays) {
                Ok(()) => {
                    for offset in &gone {
                        self.device.remove(offset);
                    }
                    self.flush.extend(&gone);
                }
                // (The table below cuts them as well, and the next pass asks again. Their
                // connections are flushed only once they are off: one still on would connect again.)
                Err(e) => notes.push(format!("taking peers off {}: {e}", kith_mesh::people::DEVICE)),
            }
        }

        // 2. The table and the rules.
        if let Err(why) = self.table_and_rules(w) {
            notes.push(why);
            self.sent = None;
            step(&mut self.steps, "peers emptied".into());
            match (self.kernel.set_peers)(&[]) {
                // (Every peer that was on it left: the next pass flushes their connections.)
                Ok(()) => {
                    self.flush.extend(self.device.keys());
                    self.device.clear();
                }
                Err(e) => notes.push(format!("emptying {}: {e}", kith_mesh::people::DEVICE)),
            }
            return notes;
        }

        // 3. Onto the device, behind all of it. What the kernel has is what was last set without
        // an error: after a failure the next pass asks again (and a peer still wrongly on it goes).
        let all: Vec<Peer> = w.people.iter().map(|(_, peer)| peer.clone()).collect();
        let there: Vec<&Peer> = self.device.values().collect();
        if all.iter().collect::<Vec<_>>() != there {
            step(&mut self.steps, "peers".into());
            match (self.kernel.set_peers)(&all) {
                Ok(()) => {
                    // (Those that could not be taken off in step 1 are off now.)
                    self.flush.extend(
                        self.device
                            .iter()
                            .filter(|(offset, peer)| wanted.get(offset) != Some(peer))
                            .map(|(offset, _)| *offset),
                    );
                    self.device = w
                        .people
                        .iter()
                        .map(|(person, peer)| (person.offset, peer.clone()))
                        .collect();
                }
                Err(e) => notes.push(format!("setting peers on {}: {e}", kith_mesh::people::DEVICE)),
            }
        }

        // 4. The connections of those off the device, once nothing lets them through.
        for offset in self.flush.clone() {
            let mark = 0x6b79_0000 | u32::from(offset);
            step(&mut self.steps, format!("flush {mark:#x}"));
            match (self.kernel.forget)(mark) {
                Ok(()) => {
                    self.flush.remove(&offset);
                }
                Err(e) => notes.push(format!("flushing the connections of peer {offset:#06x}: {e}")),
            }
        }
        notes
    }

    /// The table written when what it is made of changed (or it is not there), the rules that send
    /// nowhere put back when they are missing, rule 9011 for each home-internet peer and for no one else.
    fn table_and_rules(&mut self, w: &Wanted) -> Result<(), String> {
        let persons: Vec<Person> = w.people.iter().map(|(person, _)| person.clone()).collect();
        let made = (persons, w.levels.clone(), w.links.clone());
        let present = (self.kernel.present)().unwrap_or(false);
        if self.sent.as_ref() != Some(&made) || !present {
            self.steps.push("table".into());
            (self.kernel.table)(self.people64, &made.0, &made.1, &self.interface, &made.2)
                .map_err(|e| format!("the people's table: {e}"))?;
            self.sent = Some(made);
        }
        let mut rules = (self.kernel.rules)().map_err(|e| format!("reading the routing rules: {e}"))?;
        let base = |v6: bool| {
            [9010, 9012].iter().all(|&priority| {
                rules
                    .iter()
                    .any(|&(p, six, from)| (p, six, from) == (priority, v6, None))
            })
        };
        if !base(false) || !base(true) {
            self.steps.push("rules".into());
            (self.kernel.hold)().map_err(|e| format!("routing rules 9010 and 9012: {e}"))?;
            rules.clear();
        }
        let have: BTreeSet<Ipv4Addr> = rules
            .iter()
            .filter_map(|&(priority, six, from)| if priority == 9011 && !six { from } else { None })
            .collect();
        for address in w.internet.difference(&have) {
            self.steps.push(format!("rule 9011 + {address}"));
            (self.kernel.internet)(*address, true).map_err(|e| format!("routing rule 9011 for {address}: {e}"))?;
        }
        for address in have.difference(&w.internet) {
            self.steps.push(format!("rule 9011 - {address}"));
            (self.kernel.internet)(*address, false).map_err(|e| format!("taking away rule 9011 for {address}: {e}"))?;
        }
        Ok(())
    }
}

/// Held by a pass while it works the kernel, and by the device's teardown while it takes the
/// device away: a pass in flight finishes first, and one after sees `DEVICE_UP` unset.
pub static TENDING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// One pass, but none once the device is being (or has been) taken away: that would make the table
/// and the rules again. `None` then.
pub fn tend_once(tend: &mut Tend, w: &Wanted) -> Option<Vec<String>> {
    let _tending = TENDING.lock().unwrap_or_else(|e| e.into_inner());
    DEVICE_UP.load(Ordering::Acquire).then(|| tend.pass(w))
}

/// The notes as the Node's status has them: a few short lines, or null.
fn said_notes(notes: &[String]) -> Value {
    if notes.is_empty() {
        return Value::Null;
    }
    Value::Array(
        notes
            .iter()
            .take(16)
            .map(|note| Value::from(note.chars().take(200).collect::<String>()))
            .collect(),
    )
}

/// Hold the levels as the store says, on a node started with `--people` (`config`), until stopped;
/// a node without the flag takes back what an earlier start said.
pub async fn run(shared: Arc<Shared>, config: Option<Config>, mut stopping: watch::Receiver<bool>) {
    let Some(config) = config else {
        return crate::mesh::left(shared, "peopleNotes", stopping).await;
    };
    let Some(cluster) = &shared.cluster else { return };
    let prefixes = (
        crate::mesh::prefix(&cluster.me.ca),
        crate::people::prefix(&cluster.me.ca),
    );
    let node = format!("Node/{}", cluster.me.name);
    let mut tend = Tend::new(Kernel::real(), prefixes.1, config.interface.clone());
    let mut generation = shared.generation.subscribe();
    let mut last: Option<(Wanted, Instant)> = None;
    loop {
        let up = DEVICE_UP.load(Ordering::Acquire);
        if up {
            let links = own_links();
            let (asked, said) = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                let asked = wanted(&state.store, prefixes, &cluster.me.name, &config, links);
                let said = state.store.get(&node).map(|own| {
                    own.status
                        .as_ref()
                        .and_then(|s| s.get("peopleNotes"))
                        .cloned()
                        .unwrap_or(Value::Null)
                });
                (asked, said)
            };
            let due = last
                .as_ref()
                .is_none_or(|(before, at)| *before != asked || at.elapsed() >= EVERY);
            if due {
                // (Netlink, the nft batch and conntrack block: not on the runtime's threads.)
                let work = tokio::task::spawn_blocking(move || {
                    let notes = tend_once(&mut tend, &asked);
                    (tend, asked, notes)
                })
                .await;
                let Ok((back, asked, Some(notes))) = work else {
                    // (Torn down, or a pass that panicked and took its state: nothing more to do until stopped.)
                    let _ = stopping.changed().await;
                    break;
                };
                tend = back;
                for note in &notes {
                    eprintln!("kithd: people: {note}");
                }
                let now = said_notes(&notes);
                if said.is_some_and(|said| said != now)
                    && let Err(e) = crate::mesh::say(&shared, &node, "peopleNotes", now).await
                {
                    eprintln!("kithd: people: telling the cluster what was left out: {e}");
                }
                last = Some((asked, Instant::now()));
            }
        }
        let wait = if up { EVERY } else { Duration::from_secs(1) };
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(wait) => {}
            _ = stopping.changed() => break,
        }
    }
    // (The device and the table go with the people's own loop.)
    if let Err(e) = crate::mesh::say(&shared, &node, "peopleNotes", Value::Null).await {
        eprintln!("kithd: people: taking back what this node said was left out: {e}");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::Engine as _;
    use kith_store::Command;

    fn ids() -> (Ipv6Addr, Ipv6Addr) {
        (kith_mesh::prefix(b"a cluster"), crate::people::prefix("a cluster"))
    }

    fn apply(store: &mut Store, source: &str) {
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
    }

    fn key(n: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([n; 32])
    }

    fn peer_yaml(name: &str, node: &str, level: &str, n: u8) -> String {
        format!(
            "apiVersion: kith.dev/v1\nkind: RemotePeer\nmetadata: {{ name: {name} }}\nspec: {{ node: {node}, level: {level}, publicKey: '{}' }}\n",
            key(n)
        )
    }

    fn service_yaml(name: &str, ports: &str) -> String {
        format!(
            "apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ namespace: default, name: {name} }}\nspec: {{ selector: {{ app: web }}, ports: {ports} }}\n"
        )
    }

    fn level_yaml(name: &str, spec: &str) -> String {
        format!("apiVersion: kith.dev/v1\nkind: AccessLevel\nmetadata: {{ name: {name} }}\nspec: {spec}\n")
    }

    /// The addresses the leader gives, as a leader that has applied its log gives them.
    fn settle(store: &mut Store) {
        let (mesh, people64) = ids();
        let statuses = crate::people::statuses(store, mesh, people64, true);
        kith_store::run(store, Command::Patch { statuses }).unwrap();
    }

    fn config(networks: &[&str]) -> Config {
        Config {
            interface: "kith0".into(),
            networks: networks.iter().map(|net| network(net).unwrap()).collect(),
            api: 7443,
            pods: (Ipv4Addr::new(172, 20, 0, 0), 16),
        }
    }

    /// Review 5: the range's last address is never given, nor the first two.
    #[test]
    fn people_levels_range_ends() {
        let (mesh, people64) = ids();
        let mut store = Store::default();
        apply(&mut store, &level_yaml("family", "{ services: ['*'] }"));
        for (name, n) in [
            ("first", 1),
            ("second", 2),
            ("last", 3),
            ("one-before", 4),
            ("top-six", 5),
        ] {
            apply(&mut store, &peer_yaml(name, "n1", "family", n));
        }
        let with = |name: &str, offset: u16, six_id: u64| {
            let four = Ipv4Addr::new(100, 89, (offset >> 8) as u8, offset as u8);
            let six = Ipv6Addr::from(u128::from(people64) | u128::from(six_id));
            let fields = serde_json::Map::from_iter([(
                "addresses".to_string(),
                serde_json::json!({"ipv4": four.to_string(), "ipv6": six.to_string()}),
            )]);
            (format!("RemotePeer/{name}"), fields)
        };
        let at = |name: &str, offset: u16| with(name, offset, u64::from(offset));
        let statuses = vec![
            at("first", 1),
            at("second", 2),
            at("last", 0xffff),
            at("one-before", 0xfffe),
            // A fine IPv4 offset, but the /64's last address (all ones in the low 64 bits).
            with("top-six", 5, u64::MAX),
        ];
        kith_store::run(&mut store, Command::Patch { statuses }).unwrap();
        let asked = wanted(&store, (mesh, people64), "n1", &config(&[]), Vec::new());
        let mut offsets: Vec<u16> = asked.people.iter().map(|(person, _)| person.offset).collect();
        offsets.sort();
        assert_eq!(offsets, [2, 0xfffe], "{:?}", asked.notes);
        let said = asked.notes.join("\n");
        for name in ["first", "last", "top-six"] {
            assert!(
                said.contains(&format!("peer {name}: ")) && said.contains("not the people's to give"),
                "{said}"
            );
        }
    }

    /// A level naming the people's range, the pods' or 100.64.0.0/10 over them is left out at
    /// `level_of` (the store's Apply refuses it too, but a stored level is not trusted to have been through it).
    #[test]
    fn people_levels_overlap() {
        let (mesh, people64) = ids();
        let store = Store::default();
        let flag = config(&["172.16.0.0/12", "100.64.0.0/10", "192.168.0.0/16"]);
        let spec: AccessLevelSpec = serde_json::from_value(serde_json::json!({
            "networks": [
                "100.64.0.0/10", "100.89.4.0/24", "100.88.0.0/17", "100.89.0.0/16",
                "172.20.0.0/16", "172.20.9.0/24", "172.16.0.0/12", "192.168.4.0/24", "100.96.0.0/16"
            ]
        }))
        .unwrap();
        let (level, _, notes) = level_of(&store, &spec, "family", (mesh, people64), &flag);
        assert_eq!(
            level.networks,
            vec![network("192.168.4.0/24").unwrap(), network("100.96.0.0/16").unwrap()],
            "{notes:?}"
        );
        // (172.16.0.0/12 holds the pods' /16: left out as well.)
        let said = notes.join("\n");
        for net in [
            "100.64.0.0/10",
            "100.89.4.0/24",
            "100.88.0.0/17",
            "100.89.0.0/16",
            "172.20.0.0/16",
            "172.20.9.0/24",
            "172.16.0.0/12",
        ] {
            assert!(said.contains(&format!("`{net}` overlaps")), "{net}: {said}");
        }
    }

    #[test]
    fn people_levels() {
        let (mesh, people64) = ids();
        let mut store = Store::default();
        let over = format!("{mesh}/48");
        apply(
            &mut store,
            &level_yaml(
                "family",
                &format!(
                    "{{ services: ['*'], api: true, dns: '192.0.2.53', internet: true, networks: ['192.168.4.0/24', '10.0.0.0/8', '{over}'] }}"
                ),
            ),
        );
        apply(
            &mut store,
            &level_yaml("away", "{ dns: '192.0.2.53', exit: somewhere }"),
        );
        apply(
            &mut store,
            &level_yaml("named", "{ services: ['default/web', 'default/dns', 'default/gone'] }"),
        );
        apply(
            &mut store,
            &service_yaml("web", "[{ port: 80 }, { port: 8080 }, { port: 80 }]"),
        );
        apply(&mut store, &service_yaml("dns", "[{ port: 53, protocol: udp }]"));
        for (name, node, level, n) in [
            ("phone-1", "n1", "family", 1),
            ("phone-2", "n1", "away", 2),
            ("phone-3", "n1", "nowhere", 3),
            ("phone-4", "n2", "family", 4),
            ("phone-5", "n1", "named", 5),
            ("phone-6", "n1", "family", 6),
            ("phone-8", "n1", "family", 8),
            ("same-key", "n1", "family", 1),
        ] {
            apply(&mut store, &peer_yaml(name, node, level, n));
        }
        settle(&mut store);
        // (phone-6 refused, and phone-8 given phone-1's addresses, as a hand could write a status.)
        let patch = |name: &str, field: &str, value: Value| {
            let fields = serde_json::Map::from_iter([(field.to_string(), value)]);
            (format!("RemotePeer/{name}"), fields)
        };
        let theirs = store.get("RemotePeer/phone-1").unwrap().status.as_ref().unwrap()["addresses"].clone();
        let statuses = vec![
            patch("phone-6", "refused", Value::from("name it otherwise")),
            patch("phone-8", "addresses", theirs),
        ];
        kith_store::run(&mut store, Command::Patch { statuses }).unwrap();
        // (One that has no addresses yet.)
        apply(&mut store, &peer_yaml("phone-7", "n1", "family", 7));

        let asked = wanted(&store, (mesh, people64), "n1", &config(&["192.168.0.0/16"]), Vec::new());
        let names: Vec<&str> = asked.levels.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["away", "named"], "{:?}", asked.notes);

        // phone-1 and phone-8 share an address: both are left out; same-key and phone-6 are
        // refused, phone-3 has no level, phone-4 is another node's, phone-7 has no address.
        let offsets = asked.people.len();
        assert_eq!(
            offsets,
            2,
            "{:?}",
            asked.people.iter().map(|(p, _)| &p.level).collect::<Vec<_>>()
        );
        let said = asked.notes.join("\n");
        for part in [
            "peer same-key: refused: publicKey: the same as phone-1's",
            "peer phone-6: refused: name it otherwise",
            "peer phone-3: level nowhere is not there",
            "peer phone-1: its address or key is another peer's",
            "peer phone-8: its address or key is another peer's",
        ] {
            assert!(said.contains(part), "{part}: {said}");
        }
        assert!(!said.contains("phone-4") && !said.contains("phone-7"), "{said}");

        // Without the clash: phone-1 is held, with the whole level.
        let mut store = store;
        store.delete("RemotePeer/phone-8").unwrap();
        let asked = wanted(&store, (mesh, people64), "n1", &config(&["192.168.0.0/16"]), vec![]);
        let family = &asked
            .levels
            .iter()
            .find(|(name, _)| name == "family")
            .expect("family")
            .1;
        let web = kith_mesh::service_address(mesh, "default", "web");
        assert_eq!(
            family.services,
            vec![(web, vec![80, 8080])],
            "the UDP-only Service is not there"
        );
        assert_eq!(family.api, Some(7443));
        assert_eq!(family.resolver, Some("192.0.2.53".parse().unwrap()));
        assert_eq!(family.internet, Internet::Home);
        assert_eq!(
            family.networks,
            vec![network("192.168.4.0/24").unwrap()],
            "only what the flag has, and not the mesh's /48"
        );
        let said = asked.notes.join("\n");
        for part in ["10.0.0.0/8", "--people-networks", "overlaps the mesh's /48"] {
            assert!(said.contains(part), "{part}: {said}");
        }
        let (phone, peer) = asked.people.iter().find(|(p, _)| p.level == "family").expect("phone-1");
        assert_eq!(asked.internet, BTreeSet::from([phone.v4.unwrap()]));
        assert_eq!(peer.key, [1; 32]);
        assert_eq!(
            peer.allowed,
            vec![
                (IpAddr::V4(phone.v4.unwrap()), 32),
                (IpAddr::V6(phone.v6.unwrap()), 128)
            ]
        );
        assert_eq!(u32::from(phone.v4.unwrap()) & 0xffff, u32::from(phone.offset));

        // An exit's level has no internet, and says why; Services named are looked up one by one.
        let away = &asked.levels.iter().find(|(name, _)| name == "away").expect("away").1;
        assert_eq!(away.internet, Internet::None);
        assert!(said.contains("exit somewhere is not held yet"), "{said}");
        let named = &asked.levels.iter().find(|(name, _)| name == "named").expect("named").1;
        assert_eq!(named.services, vec![(web, vec![80, 8080])]);
        assert!(
            said.contains("default/dns has no TCP port") && said.contains("default/gone is not there"),
            "{said}"
        );

        // With no --people-networks, a level's networks are all left out: Services only.
        let none = wanted(&store, (mesh, people64), "n1", &config(&[]), vec![]);
        assert!(none.levels.iter().all(|(_, level)| level.networks.is_empty()));
    }

    #[test]
    fn the_networks_flag() {
        assert!(network("192.168.0.0/16").is_ok() && network("fd00::/8").is_ok());
        for bad in [
            "192.168.0.0",
            "0.0.0.0/0",
            "::/0",
            "192.168.0.0/33",
            "fd00::/129",
            "x/8",
            "10.0.0.0/x",
        ] {
            assert!(network(bad).is_err(), "{bad}");
        }
        assert!(within(network("10.0.0.0/8").unwrap(), network("10.4.0.0/16").unwrap()));
        assert!(!within(network("10.4.0.0/16").unwrap(), network("10.0.0.0/8").unwrap()));
        assert!(!within(network("10.0.0.0/8").unwrap(), network("fd00::/16").unwrap()));
        assert!(within(network("fd00::/8").unwrap(), network("fd12::/32").unwrap()));
    }

    // The tests below set up kwg0 in a network namespace of their own (`KITH_E2E=1 unshare -Urn`),
    // one at a time.
    // (`people::tests::people_device` takes it too: it is in the same namespace.)
    pub(crate) static KERNEL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A namespace of its own, with nothing of the people's left in it; else the test is skipped.
    fn alone() -> Option<(std::sync::MutexGuard<'static, ()>, std::path::PathBuf)> {
        if std::env::var_os("KITH_E2E").is_none() {
            eprintln!("skipped: set KITH_E2E=1 under unshare -Urn");
            return None;
        }
        let alone = std::fs::read_to_string("/proc/net/dev")
            .is_ok_and(|dev| dev.lines().skip(2).all(|line| line.trim_start().starts_with("lo:")));
        if !alone {
            eprintln!("skipped: not in a network namespace of its own");
            return None;
        }
        let guard = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
        kith_mesh::people::remove().unwrap();
        let state = std::env::temp_dir().join(format!("kithd-levels-{}", std::process::id()));
        std::fs::create_dir_all(state.join("pki")).unwrap();
        Some((guard, state))
    }

    /// This namespace's kernel has no masquerade: the table is written without.
    fn tend() -> Tend {
        let mut kernel = Kernel::real();
        kernel.table = kith_mesh::people::send_without_masquerade;
        Tend::new(kernel, ids().1, "kith0".into())
    }

    /// `people::up`, as the tests have it: the table, the rules, the device, no peers.
    fn start(state: &std::path::Path) {
        let people64 = ids().1;
        crate::people::up_with(state, 51821, people64, || {
            kith_mesh::people::send_without_masquerade(people64, &[], &[], "kith0", &[])
        })
        .expect("the device comes up");
    }

    fn person(offset: u16, level: &str) -> (Person, Peer) {
        let (v4, v6) = (
            Ipv4Addr::new(100, 89, 0, offset as u8),
            Ipv6Addr::from(u128::from(ids().1) | u128::from(offset)),
        );
        let person = Person {
            level: level.into(),
            offset,
            v4: Some(v4),
            v6: Some(v6),
        };
        let peer = Peer {
            key: [offset as u8; 32],
            endpoint: None,
            allowed: vec![(IpAddr::V4(v4), 32), (IpAddr::V6(v6), 128)],
            keepalive: 0,
        };
        (person, peer)
    }

    fn level(networks: Vec<(IpAddr, u8)>, internet: Internet) -> Level {
        Level {
            networks,
            services: Vec::new(),
            api: None,
            resolver: None,
            internet,
        }
    }

    fn asks(offsets: &[u16], networks: Vec<(IpAddr, u8)>) -> Wanted {
        Wanted {
            levels: vec![("family".into(), level(networks, Internet::Home))],
            people: offsets.iter().map(|&offset| person(offset, "family")).collect(),
            internet: offsets
                .iter()
                .map(|&offset| Ipv4Addr::new(100, 89, 0, offset as u8))
                .collect(),
            ..Wanted::default()
        }
    }

    fn peers_on_device() -> usize {
        kith_mesh::people::device_found().unwrap().expect("kwg0 is up").peers
    }

    fn sources() -> Vec<Ipv4Addr> {
        let rules = kith_mesh::exit::people_rules().unwrap();
        rules
            .into_iter()
            .filter_map(|(priority, _, from)| if priority == 9011 { from } else { None })
            .collect()
    }

    fn failing<T>() -> io::Result<T> {
        Err(io::Error::other("refused here"))
    }

    /// The start order of docs/adr-people.md: the table with its drops, the rules that send
    /// nowhere, the device with no peers; then the level chains, the jumps and rule 9011; then the
    /// peers. A step that cannot be done leaves kwg0 without peers, and says why.
    #[test]
    fn people_order() {
        let Some((_guard, state)) = alone() else { return };
        start(&state);
        assert!(kith_mesh::people::table_present().unwrap());
        let rules = kith_mesh::exit::people_rules().unwrap();
        for six in [false, true] {
            for priority in [9010, 9012] {
                assert!(
                    rules.contains(&(priority, six, None)),
                    "rule {priority} (v6 {six}): {rules:?}"
                );
            }
        }
        assert_eq!(peers_on_device(), 0, "no peers behind the rules alone");

        let mut tend = tend();
        let notes = tend.pass(&asks(&[2], Vec::new()));
        assert_eq!(notes, Vec::<String>::new());
        assert_eq!(tend.steps, ["table", "rule 9011 + 100.89.0.2", "peers"]);
        assert_eq!(sources(), [Ipv4Addr::new(100, 89, 0, 2)]);
        assert_eq!(peers_on_device(), 1);
        tend.steps.clear();
        assert!(tend.pass(&asks(&[2], Vec::new())).is_empty());
        assert!(tend.steps.is_empty(), "nothing changed: {:?}", tend.steps);

        // A rule taken away by hand is put back, with no peer's connection let through without it.
        kith_mesh::exit::people_release().unwrap();
        tend.pass(&asks(&[2], Vec::new()));
        assert_eq!(tend.steps, ["rules", "rule 9011 + 100.89.0.2"]);
        assert_eq!(peers_on_device(), 1);
        tend.steps.clear();

        // A rule that cannot be written: no peers at all, the table made again, and the reason.
        let mut failed = tend;
        failed.kernel.internet = |_, _| failing();
        let notes = failed.pass(&asks(&[2, 3], Vec::new()));
        assert_eq!(failed.steps, ["table", "rule 9011 + 100.89.0.3", "peers emptied"]);
        assert_eq!(peers_on_device(), 0);
        assert!(
            notes
                .iter()
                .any(|note| note.contains("routing rule 9011") && note.contains("refused here")),
            "{notes:?}"
        );
        failed.steps.clear();
        failed.kernel.table = |_, _, _, _, _| failing();
        let notes = failed.pass(&asks(&[2, 3], Vec::new()));
        assert_eq!(failed.steps, ["table", "peers emptied"]);
        assert!(
            notes.iter().any(|note| note.contains("the people's table")),
            "{notes:?}"
        );
        assert_eq!(peers_on_device(), 0);

        // Mended, they come back.
        failed.kernel = Kernel::real();
        failed.kernel.table = kith_mesh::people::send_without_masquerade;
        failed.steps.clear();
        assert!(failed.pass(&asks(&[2, 3], Vec::new())).is_empty());
        // (Peer 2 left the device when it was emptied: its connections are flushed now, once.)
        assert_eq!(&failed.steps[failed.steps.len() - 2..], ["peers", "flush 0x6b790002"]);
        assert_eq!(peers_on_device(), 2);

        kith_mesh::people::remove().unwrap();
        let _ = std::fs::remove_dir_all(&state);
    }

    /// A peer deleted goes off the device, then its rule goes, then its connections are flushed by
    /// its mark; a level narrowed has the table written again; each on the pass after the change.
    #[test]
    fn people_removed() {
        let Some((_guard, state)) = alone() else { return };
        start(&state);
        let mut tend = tend();
        let wide = vec![network("192.168.0.0/16").unwrap()];
        assert!(tend.pass(&asks(&[2, 3], wide.clone())).is_empty());
        assert_eq!(peers_on_device(), 2);
        tend.steps.clear();

        // Nothing changed: nothing is written.
        tend.pass(&asks(&[2, 3], wide.clone()));
        assert!(tend.steps.is_empty(), "{:?}", tend.steps);

        // A level narrowed: the table written again, and the peers stay.
        let narrow = vec![network("192.168.4.0/24").unwrap()];
        tend.pass(&asks(&[2, 3], narrow.clone()));
        assert_eq!(tend.steps, ["table"]);
        assert_eq!(peers_on_device(), 2);
        tend.steps.clear();

        // A peer deleted.
        let notes = tend.pass(&asks(&[3], narrow));
        assert_eq!(
            tend.steps,
            ["off the device", "table", "rule 9011 - 100.89.0.2", "flush 0x6b790002"],
            "{notes:?}"
        );
        assert_eq!(peers_on_device(), 1);
        assert_eq!(sources(), [Ipv4Addr::new(100, 89, 0, 3)]);
        tend.steps.clear();
        tend.pass(&asks(&[3], vec![network("192.168.4.0/24").unwrap()]));
        assert!(tend.steps.is_empty(), "{:?}", tend.steps);

        // The last one, and the store with none.
        tend.pass(&asks(&[], Vec::new()));
        assert_eq!(peers_on_device(), 0);
        assert!(sources().is_empty());

        kith_mesh::people::remove().unwrap();
        let _ = std::fs::remove_dir_all(&state);
    }

    /// A device that will not take the peers off keeps them in the pass's memory too: nothing is
    /// flushed (they would connect again), and the next pass asks again, then flushes.
    #[test]
    fn people_removed_when_the_device_will_not_change() {
        let Some((_guard, state)) = alone() else { return };
        start(&state);
        let mut tend = tend();
        assert!(tend.pass(&asks(&[2, 3], Vec::new())).is_empty());
        tend.steps.clear();

        tend.kernel.set_peers = |_| failing();
        let notes = tend.pass(&asks(&[3], Vec::new()));
        assert_eq!(
            tend.steps,
            ["off the device", "table", "rule 9011 - 100.89.0.2", "peers"]
        );
        let said = notes.join("\n");
        assert!(
            said.contains("taking peers off") && said.contains("setting peers"),
            "{said}"
        );
        assert_eq!(peers_on_device(), 2, "still there");
        assert_eq!(tend.device.len(), 2, "and remembered as there");

        tend.kernel.set_peers = kith_mesh::people::set_peers;
        tend.steps.clear();
        assert!(tend.pass(&asks(&[3], Vec::new())).is_empty());
        assert_eq!(tend.steps, ["off the device", "flush 0x6b790002"]);
        assert_eq!(peers_on_device(), 1);
        tend.steps.clear();
        assert!(tend.pass(&asks(&[3], Vec::new())).is_empty() && tend.steps.is_empty());

        // The fail-closed emptying that fails flushes nothing either.
        tend.kernel.set_peers = |_| failing();
        tend.kernel.internet = |_, _| failing();
        tend.steps.clear();
        let notes = tend.pass(&asks(&[], Vec::new()));
        assert_eq!(
            tend.steps,
            ["off the device", "table", "rule 9011 - 100.89.0.3", "peers emptied"]
        );
        assert!(notes.iter().any(|note| note.contains("emptying")), "{notes:?}");
        assert_eq!(peers_on_device(), 1);
        tend.kernel = Kernel::real();
        tend.kernel.table = kith_mesh::people::send_without_masquerade;
        tend.steps.clear();
        assert!(tend.pass(&asks(&[], Vec::new())).is_empty());
        assert_eq!(
            tend.steps,
            ["off the device", "table", "rule 9011 - 100.89.0.3", "flush 0x6b790003"]
        );
        assert_eq!(peers_on_device(), 0);

        kith_mesh::people::remove().unwrap();
        let _ = std::fs::remove_dir_all(&state);
    }

    /// Review 2.2: a pass that could not take a peer off the device, then fails in the table or the
    /// rules and empties the device with success: every peer that was on it left, so each one's
    /// connections are owed a flush (the next pass makes it); none is forgotten.
    #[test]
    fn people_removed_when_a_failed_pass_then_empties_the_device() {
        let Some((_guard, state)) = alone() else { return };
        start(&state);
        let mut tend = tend();
        assert!(tend.pass(&asks(&[2, 3], Vec::new())).is_empty());
        tend.steps.clear();

        // The device takes no peers but the empty list; the rules cannot be made.
        tend.kernel.set_peers = |peers| {
            if peers.is_empty() {
                kith_mesh::people::set_peers(peers)
            } else {
                failing()
            }
        };
        tend.kernel.internet = |_, _| failing();
        let notes = tend.pass(&asks(&[3], Vec::new()));
        assert_eq!(tend.steps.first().map(String::as_str), Some("off the device"));
        assert_eq!(tend.steps.last().map(String::as_str), Some("peers emptied"));
        assert!(notes.iter().any(|note| note.contains("taking peers off")), "{notes:?}");
        assert_eq!(peers_on_device(), 0, "emptied");
        assert!(tend.device.is_empty());
        assert_eq!(tend.flush, BTreeSet::from([2, 3]), "both left the device");

        tend.kernel = Kernel::real();
        tend.kernel.table = kith_mesh::people::send_without_masquerade;
        tend.steps.clear();
        assert!(tend.pass(&asks(&[3], Vec::new())).is_empty());
        assert!(
            tend.steps
                .ends_with(&["flush 0x6b790002".into(), "flush 0x6b790003".into()]),
            "{:?}",
            tend.steps
        );
        assert!(tend.flush.is_empty());
        assert_eq!(peers_on_device(), 1);

        kith_mesh::people::remove().unwrap();
        let _ = std::fs::remove_dir_all(&state);
    }

    /// A start that fails takes away what an earlier start left (its peers and rules): the device is
    /// not left with last run's peers and nothing tending them.
    #[test]
    fn people_order_a_failed_start_takes_the_old_device_away() {
        let Some((_guard, state)) = alone() else { return };
        start(&state);
        let mut tend = tend();
        assert!(tend.pass(&asks(&[2], Vec::new())).is_empty());
        assert_eq!(peers_on_device(), 1);

        let people64 = ids().1;
        let failed = crate::people::up_with(&state, 51821, people64, failing);
        assert!(failed.is_err());
        assert!(kith_mesh::people::device_found().unwrap().is_none(), "no kwg0");
        assert!(!kith_mesh::people::table_present().unwrap());
        assert!(kith_mesh::exit::people_rules().unwrap().is_empty());
        assert!(!DEVICE_UP.load(Ordering::Acquire));

        let _ = std::fs::remove_dir_all(&state);
    }

    /// Once the device is taken away, no pass makes its table and rules again; a start allows them.
    #[test]
    fn people_order_no_pass_after_the_teardown() {
        let Some((_guard, state)) = alone() else { return };
        start(&state);
        let mut tend = tend();
        assert_eq!(tend_once(&mut tend, &asks(&[2], Vec::new())), Some(Vec::new()));
        assert_eq!(peers_on_device(), 1);

        crate::people::take_away();
        assert_eq!(tend_once(&mut tend, &asks(&[2], Vec::new())), None);
        assert!(!kith_mesh::people::table_present().unwrap(), "no table made again");
        assert!(
            kith_mesh::exit::people_rules().unwrap().is_empty(),
            "no rules made again"
        );
        assert!(kith_mesh::people::device_found().unwrap().is_none());

        let _ = std::fs::remove_dir_all(&state);
    }
}
