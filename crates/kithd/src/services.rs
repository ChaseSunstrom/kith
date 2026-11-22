//! Services, on a node (of the mesh or not: without `--mesh` the Services' addresses are on the
//! loopback, and only this node's replicas are reached): every Service has an address every node
//! holds (`kith_mesh::service_address`), and a TCP connection to one of its ports there is
//! passed to a ready replica of a Workload its selector matches, one after the other in
//! turn. A replica on this node is reached on the machine itself (so it may listen on
//! 127.0.0.1 only); one on another node through that node's kithd, which listens on its
//! mesh address for exactly this and connects to the replica there. Two nodes keep the
//! connections between them for a while and pass on one client's after another on each
//! ([`carry`]): a new connection to a Service is then no new one between the nodes. A node that
//! says it takes links (`status.mesh.link`) is reached on one link, a stream for each client
//! ([`Proxy::linked`]).
//
// The kernel passes a connection made on the node's own network to a replica here with
// no NetworkPolicy straight to it ([`connect`]); kithd then never sees it.
//
// ponytail: kithd copies every other byte (a restart of kithd cuts those connections),
// TCP only, and replicas of one node share its ports until workloads have addresses of
// their own. A pod's client, or one with a NetworkPolicy, is the kernel's next. Tried
// (T-0318): a socket map whose verdict program redirects each side's bytes to the
// other lost no byte, and was slower on small turns (kernel 6.18 passes each
// redirected segment through a worker): 74k kept requests a second where this has 81k.

mod connect;
// (A Service's IPv4 address: its allocation, its loopback address and what the DNS answers.)
pub mod v4;
// (One link to each node that takes them, opened by `Proxy::linked`; its receiving end is `receive`.)
mod link;
mod receive;
// (A Service that may sleep, and the connection held while it wakes: T-1210.)
pub(crate) mod wake;

/// KITH_NO_LINK in the environment (ci/vm.sh --test services sets it on one node): this node
/// says no `status.mesh.link` and opens no link, as a node of before does, so that a cluster of
/// both is tried with one binary. Not a setting: nothing else reads or documents it.
pub(crate) fn links_off() -> bool {
    static OFF: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OFF.get_or_init(|| std::env::var_os("KITH_NO_LINK").is_some())
}

use crate::Shared;
use crate::ingress::{Idle, Limits, Place};
use crate::levels::Reach;
use futures_util::FutureExt;
use kith_api::Resource;
use kith_api::kinds::{
    NetworkPolicySpec, Peer, PolicyAction, PolicyRule, PortRef, Protocol, ServiceSpec, WorkloadSpec, parse_cidr,
};
use kith_api::store::Store;
use kith_mesh::pod::{Egress, Range};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

/// Where a connection may go: a node's name, a port on it, the Workload it is of, and
/// which replica where each is a pod with ports of its own.
type Backend = (String, u16, String, Option<u32>);
/// For every address (its IPv6 one, and its IPv4 one where it has one) and port a Service
/// listens on: its backends.
type Table = BTreeMap<(IpAddr, u16), Vec<Backend>>;

const CONNECT: Duration = Duration::from_secs(3);
/// A connection to a Service with no byte either way for this long is closed (a client
/// that is gone without a word, a backend that stopped answering).
const IDLE: Duration = Duration::from_secs(3600);
/// A connection to another node's kithd, which passes on one client's connection after
/// another on it.
struct Relay {
    from: BufReader<OwnedReadHalf>,
    to: OwnedWriteHalf,
}

impl Relay {
    fn new(stream: TcpStream) -> Relay {
        // (Each frame is to go when it is written: nothing waits for the one before.)
        let _ = stream.set_nodelay(true);
        let (from, to) = stream.into_split();
        Relay {
            from: BufReader::new(from),
            to,
        }
    }
}
/// How long a connection between two nodes is kept with nothing passed on: by the node
/// that made it and, longer (so it is not hung up on just as it is used), by the other.
const KEPT: Duration = Duration::from_secs(30);
const KEPT_THERE: Duration = Duration::from_secs(60);
/// How many of them a node keeps to each other node while none of its clients needs them.
const KEEP: usize = 16;
/// The most bytes in one frame of [`carry`].
const CHUNK: usize = 8192;
/// How long a replica here has to take a connection another node asks for: less than
/// that node waits for the answer ([`CONNECT`]), so that it hears a no and tries the next
/// replica, where no answer would cost a client that had spoken its connection.
const FOUND: Duration = Duration::from_secs(2);
/// How many connections to Services this node passes on at a time, from its own side; one
/// over is hung up on.
const SERVING: usize = 4096;
/// How many connections from the other nodes this node relays to its replicas at a time, all
/// of them together (so no node can take them all); one over is said no to, if it is kept,
/// from a spare ([`SPARE`]), and hung up on past those ([`admit`]).
const RELAYING: usize = 4096;
/// How many of the relayed ones one other node may hold.
const RELAYING_PER_NODE: usize = 1024;
/// The sockets a node over its relaying limit keeps open to say no with, in all and for one
/// other node: the most it holds for a node that keeps asking, and past those its asks are
/// hung up on at once ([`admit`]).
const SPARE: usize = 256;
const SPARE_PER_NODE: usize = 64;
/// The most threads the connections to Services are on, one to a core. Each connection
/// still takes the store's lock and the table's for a moment as it starts: past a few
/// threads those moments queue, and the rest of kithd keeps a core of its own.
const THREADS: usize = 4;

pub fn namespace(resource: &Resource) -> String {
    resource.key().split('/').nth(1).unwrap_or_default().to_string()
}

/// Is this Service headless? One that cannot be read is not.
pub fn headless(service: &Resource) -> bool {
    serde_json::from_value::<ServiceSpec>(service.spec.clone()).is_ok_and(|spec| spec.headless == Some(true))
}

/// The address of every Service in the store that has one: a headless Service has none.
pub fn addresses(store: &Store, prefix: Ipv6Addr) -> BTreeMap<String, Ipv6Addr> {
    let address = |service: &Resource| kith_mesh::service_address(prefix, &namespace(service), &service.metadata.name);
    let services = store.list(Some("Service")).filter(|service| !headless(service));
    services.map(|service| (service.key(), address(service))).collect()
}

/// Refuse an Apply with a Service whose mesh address another Service has, stored or in the
/// same Apply: two names can hash to one address (48 bits), and then their connections go to
/// one another's backends. (Not said whose: a namespace learns nothing of another's by it.)
pub fn unclaimed(store: &Store, prefix: Ipv6Addr, resources: &[Resource]) -> Result<(), String> {
    unclaimed_with(store, resources, |namespace, name| {
        kith_mesh::service_address(prefix, namespace, name)
    })
}

/// [`unclaimed`] with the address of a Service given by `address`, so a test can make two
/// collide.
fn unclaimed_with(
    store: &Store,
    resources: &[Resource],
    address: impl Fn(&str, &str) -> Ipv6Addr,
) -> Result<(), String> {
    let batch: Vec<&Resource> = resources.iter().filter(|resource| resource.kind == "Service").collect();
    if batch.is_empty() {
        return Ok(());
    }
    let of = |service: &Resource| address(&namespace(service), &service.metadata.name);
    let claims: Vec<(String, Ipv6Addr)> = store
        .list(Some("Service"))
        .chain(batch.iter().copied())
        .map(|service| (service.key(), of(service)))
        .collect();
    for service in &batch {
        let (key, mine) = (service.key(), of(service));
        if claims.iter().any(|(other, theirs)| *other != key && *theirs == mine) {
            return Err(format!(
                "Service {key} would have the mesh address another Service has (an address comes from a Service's namespace and name): pick another name"
            ));
        }
    }
    Ok(())
}

/// The Workloads a Service's selector picks: of its namespace, with every label it asks for. A
/// selector that asks for nothing picks none (it would take in every workload).
pub fn behind<'a>(store: &'a Store, service: &Resource, spec: &ServiceSpec) -> Vec<&'a Resource> {
    let ns = namespace(service);
    let picks = |workload: &&Resource| {
        let has = |(label, value): (&String, &String)| workload.metadata.labels.get(label) == Some(value);
        namespace(workload) == ns && !spec.selector.is_empty() && spec.selector.iter().all(has)
    };
    store.list(Some("Workload")).filter(picks).collect()
}

/// The mesh address of each ready replica of `workload`, by replica number. (A unit with no
/// address, or one that is not on the mesh, names nothing.)
pub fn ready_addresses(workload: &Resource) -> BTreeMap<u32, Ipv6Addr> {
    let ready: BTreeSet<u32> = ready_on(workload).into_iter().map(|(_, replica)| replica).collect();
    let units = workload
        .status
        .as_ref()
        .and_then(|status| status["containers"].as_array());
    let mut addresses = BTreeMap::new();
    for unit in units.into_iter().flatten() {
        let replica = unit["replica"].as_u64().and_then(|replica| u32::try_from(replica).ok());
        let address = unit["address"]
            .as_str()
            .and_then(|address| address.parse::<Ipv6Addr>().ok());
        if let (Some(replica), Some(address)) = (replica, address)
            && ready.contains(&replica)
        {
            addresses.entry(replica).or_insert(address);
        }
    }
    addresses
}

/// The replicas of `workload` with every unit ready, and the node each runs on.
fn ready_on(workload: &Resource) -> Vec<(String, u32)> {
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
    ready
        .map(|((replica, node), _)| (node.to_string(), replica as u32))
        .collect()
}

/// The (address, port) pairs kithd really listens on for the Services, IPv4 and IPv6 (not the relay's
/// port): all a pod may reach of the node's addresses over TCP, besides the resolver. A pair whose bind
/// failed (a host listener on the wildcard holds that port: a Service made to name it) is not among them,
/// so the pod's connection there is not let through to that listener.
fn open_keys(
    listening: &BTreeMap<(IpAddr, u16), Vec<tokio::task::JoinHandle<()>>>,
    relay: Option<(IpAddr, u16)>,
) -> Vec<(IpAddr, u16)> {
    listening.keys().copied().filter(|key| Some(*key) != relay).collect()
}

/// The port of `workload` a connection to the Service port `port` goes to.
fn target_of(port: &kith_api::kinds::ServicePort, workload: &Resource) -> Option<u16> {
    match &port.target_port {
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
    }
}

/// What every Service listens on, and where its connections go: on its IPv6 address, and on its
/// IPv4 one (`status.addressV4`) where `services` (this node's range for them) holds it and no
/// Service before it (by key) has it.
fn table(store: &Store, prefix: Ipv6Addr, services: Option<Range>) -> Table {
    let mut table = Table::new();
    let claims = services.map(|range| v4::claims(store, &range)).unwrap_or_default();
    for service in store.list(Some("Service")) {
        let Ok(spec) = serde_json::from_value::<ServiceSpec>(service.spec.clone()) else {
            continue;
        };
        // (A headless Service has no address to listen on: its name answers the replicas.)
        if spec.headless == Some(true) {
            continue;
        }
        let address = IpAddr::from(kith_mesh::service_address(
            prefix,
            &namespace(service),
            &service.metadata.name,
        ));
        let address4 = v4::address_of(service)
            .filter(|at| claims.get(at) == Some(&service.key()))
            .map(IpAddr::from);
        let workloads = behind(store, service, &spec);
        for port in &spec.ports {
            if port.protocol == Some(Protocol::Udp) {
                continue;
            }
            let mut found = Vec::new();
            for workload in &workloads {
                let target = target_of(port, workload);
                let pod = workload.spec["template"]["pod"] == true;
                let nodes = ready_on(workload).into_iter();
                found.extend(target.into_iter().flat_map(|target| {
                    let backend = move |(node, replica)| (node, target, workload.key(), pod.then_some(replica));
                    nodes.clone().map(backend)
                }));
            }
            for at in address4.into_iter().chain([address]) {
                table.entry((at, port.port)).or_default().extend(found.iter().cloned());
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
/// node's addresses, so one named by namespace or labels cannot.
fn told_apart(peer: &Peer) -> bool {
    peer.namespace.is_none() && peer.selector.is_empty()
}

/// May a connection from `from` (the node `node`, if it is one) reach the Workload
/// `workload` on `port`? Yes when no NetworkPolicy is for the Workload; otherwise the
/// first ingress rule that fits says, and when none fits, no. Where a rule names peers
/// that cannot be told apart yet, it errs on the side of no: an allow rule lets nobody
/// in for them, a deny rule keeps everybody out; so does a deny peer whose cidr cannot be read
/// or is IPv4 (`from` is a mesh address, IPv6: see `unreadable`).
pub fn admits(store: &Store, workload: &str, node: Option<&str>, from: IpAddr, port: u16) -> bool {
    let Some(target) = store.get(workload) else {
        return false;
    };
    let mut chosen = false;
    for spec in policies(store, target) {
        chosen = true;
        for rule in &spec.ingress {
            let allow = rule.action == PolicyAction::Allow;
            let fits = |peer: &Peer| {
                if !allow && unreadable(peer, true) {
                    return true;
                }
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

/// What a pod of `workload` may reach: the egress rules of the NetworkPolicies for it, in the
/// order the store lists them and each is written; `None` when none has an egress rule (the
/// pod is not held). `prefix`: the mesh's, where there is one: a peer by `node` is that node's
/// address on it (nothing without a mesh). The peers of a rule are the networks it fits: a
/// `cidr` is one, `node` and `cidr` together are the node's address if it is within the
/// cidr, and neither is everything (both families). One that cannot be told apart by
/// `namespace` or `selector` fits nothing in an allow (as for ingress) and, but for what its
/// `node` or `cidr` say, everything in a deny; so does a deny peer whose `cidr` cannot be read
/// (one stored before the API refused it): a deny never fails open. A rule whose peers hold no
/// network is left out (it would fit anything): so is a deny of a `node` where there is no
/// mesh prefix, as that is only without a cluster, where no node has an address to keep out. Nothing is let through that no rule allows: the node's resolver
/// too (DNS to the gateway), so a policy that holds a pod must name it.
pub fn egress_of(store: &Store, workload: &str, prefix: Option<Ipv6Addr>) -> Option<Vec<Egress>> {
    let target = store.get(workload)?;
    let specs: Vec<NetworkPolicySpec> = policies(store, target).filter(|spec| !spec.egress.is_empty()).collect();
    if specs.is_empty() {
        return None;
    }
    let rules = specs.iter().flat_map(|spec| &spec.egress);
    Some(rules.filter_map(|rule| egress_rule(rule, prefix)).collect())
}

/// The mesh's prefix where this node is in a cluster: the one `egress_of` is asked with, by
/// every caller (so the rules a pod is made with are the ones it is kept in step with).
pub fn mesh_prefix(shared: &Shared) -> Option<Ipv6Addr> {
    shared
        .cluster
        .as_ref()
        .map(|cluster| crate::mesh::prefix(&cluster.me.ca))
}

/// Both families whole: what a deny that must keep everything out names.
const EVERYTHING: [(IpAddr, u8); 2] = [
    (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
];

/// Does the peer name a `cidr` that cannot be read, or that nothing is matched by: IPv4 on
/// `ingress` (a caller comes from an IPv6 mesh address)? The API refuses one; this is one stored
/// before it did. In a deny it fits everything (it must never fail open), in an allow nothing.
fn unreadable(peer: &Peer, ingress: bool) -> bool {
    let unmatched = |cidr: &str| parse_cidr(cidr).is_none_or(|(address, _)| ingress && address.is_ipv4());
    peer.cidr.as_deref().is_some_and(unmatched)
}

fn egress_rule(rule: &PolicyRule, prefix: Option<Ipv6Addr>) -> Option<Egress> {
    let allow = rule.action == PolicyAction::Allow;
    let mut to = Vec::new();
    for peer in &rule.peers {
        if allow && !told_apart(peer) {
            continue;
        }
        if !allow && unreadable(peer, false) {
            to.extend(EVERYTHING);
            continue;
        }
        match (&peer.node, &peer.cidr) {
            // (A node's address is a network of one, if the cidr has it.)
            (Some(name), cidr) => {
                let Some(prefix) = prefix else { continue };
                let address = IpAddr::from(kith_mesh::node_address(prefix, name));
                if cidr.as_deref().is_none_or(|cidr| within_cidr(cidr, address)) {
                    to.push((address, 128));
                }
            }
            (None, Some(cidr)) => to.extend(parse_cidr(cidr)),
            (None, None) => to.extend(EVERYTHING),
        }
    }
    (rule.peers.is_empty() || !to.is_empty()).then(|| Egress {
        allow,
        to,
        ports: rule.ports.clone(),
    })
}

/// The NetworkPolicies for `target`: of its namespace, with a selector its labels fit.
fn policies<'a>(store: &'a Store, target: &'a Resource) -> impl Iterator<Item = NetworkPolicySpec> + 'a {
    store.list(Some("NetworkPolicy")).filter_map(move |policy| {
        let spec = serde_json::from_value::<NetworkPolicySpec>(policy.spec.clone()).ok()?;
        let has = |(label, value): (&String, &String)| target.metadata.labels.get(label) == Some(value);
        (namespace(policy) == namespace(target) && spec.selector.iter().all(has)).then_some(spec)
    })
}

/// What a NetworkPolicy's status is to be told, if it is not already.
fn policy_unsaid(policy: &Resource, unsent: bool) -> Option<serde_json::Map<String, Value>> {
    let report = policy_report(policy, unsent);
    if policy.status.as_ref() == Some(&report) {
        return None;
    }
    let Value::Object(fields) = report else {
        unreachable!("an object")
    };
    Some(fields)
}

/// What a NetworkPolicy's status says: whether all of it is enforced. `unsent`: this node's
/// pods' tables could not be made again for a change of rules (`Pods::unsent`): a policy with
/// egress rules is then not enforced for them yet.
fn policy_report(policy: &Resource, unsent: bool) -> Value {
    // (`policies` skips one that cannot be read: the pods it was meant for are not held by it.)
    let Ok(spec) = serde_json::from_value::<NetworkPolicySpec>(policy.spec.clone()) else {
        return json!({ "state": "error", "message": "cannot read this NetworkPolicy: it holds no pod" });
    };
    let mut gaps = Vec::new();
    if unsent && !spec.egress.is_empty() {
        gaps.push("egress not enforced yet: this node could not write its pods' rules (tried again)");
    }
    // (Egress is enforced for a Workload's pods, by `egress_of`'s rules: a pod it holds
    // reaches only what they allow, its DNS included.)
    if spec
        .ingress
        .iter()
        .chain(&spec.egress)
        .flat_map(|rule| &rule.peers)
        .any(|peer| !told_apart(peer))
    {
        gaps.push(
            "peers by namespace or selector cannot be told apart yet: \
             an allow rule lets none of them in, a deny rule keeps everybody out",
        );
    }
    let cannot = |rules: &[PolicyRule], ingress| {
        rules
            .iter()
            .flat_map(|rule| &rule.peers)
            .any(|p| unreadable(p, ingress))
    };
    if cannot(&spec.ingress, true) || cannot(&spec.egress, false) {
        gaps.push("a cidr cannot be read: a deny rule keeps everybody out, an allow rule lets nobody in");
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
struct Turns(Mutex<BTreeMap<(IpAddr, u16), usize>>);

impl Turns {
    fn next(&self, key: (IpAddr, u16)) -> usize {
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

/// The people's connections to Services on a node started with `--people`: from a peer, to the
/// Services of its level. (The kernel's table says so first; this is its second look, and what
/// holds each peer to a few of the places.)
struct People {
    /// The people's /64, and its IPv4 range, are the sources that are theirs.
    people64: Ipv6Addr,
    /// Places apart from the mesh's, counted by the peer's address whole (never its /64: a
    /// peer's address is one of the /64's, which many peers share).
    limits: Limits,
    reach: Mutex<Reach>,
}

/// How many of its places one peer holds at a time.
const PEOPLE_EACH: usize = 8;

impl People {
    fn new(people64: Ipv6Addr, room: usize) -> People {
        People {
            people64,
            limits: Limits::new(room, PEOPLE_EACH).per_address(),
            reach: Mutex::default(),
        }
    }

    /// The peers and what they reach, as the store says now.
    fn hold(&self, reach: Reach) {
        *self.reach.lock().expect("nothing panics holding the reach") = reach;
    }

    /// Is `from` in the people's ranges?
    fn holds(&self, from: IpAddr) -> bool {
        crate::people::holds(self.people64, from)
    }

    /// A place for a connection from the peer `from` to the Service at `(address, port)`: none
    /// for another level's, nor for a source that is no peer's (it is not counted either), nor
    /// for a port the level does not list (a Service listing none is reached on none: fail closed).
    fn place(&self, from: IpAddr, (address, port): (Ipv6Addr, u16)) -> Option<Place> {
        let from = from.to_canonical();
        let allowed = {
            let reach = self.reach.lock().expect("nothing panics holding the reach");
            let services = reach.get(&from)?;
            services
                .iter()
                .any(|(at, ports)| *at == address && ports.contains(&port))
        };
        allowed.then(|| self.limits.take(from)).flatten()
    }
}

struct Proxy {
    shared: Arc<Shared>,
    prefix: Ipv6Addr,
    table: Mutex<Table>,
    turns: Turns,
    /// Places for the connections of this node's own clients.
    serving: Limits,
    /// The people's, with `--people`.
    people: Option<People>,
    /// Places for the connections another node passes on to a replica here.
    relaying: Limits,
    /// Spares for the over-limit connections of other nodes, to be said no to ([`admit`]).
    spares: Limits,
    /// The connections to each other node's kithd that no client's is on now, and since when.
    /// (As the kernel's, on no thread's runtime: the next client's may be on another.)
    kept: Mutex<BTreeMap<String, Vec<(std::net::TcpStream, Instant)>>>,
    /// What a link from another node may hold ([`receive`]).
    links: receive::Bounds,
    /// The one link this node keeps to each other node that takes links, dialled by the first
    /// client that needs it ([`Proxy::link_to`]); one that is down is dialled again. With
    /// when a stream was last open on it, as far as [`Proxy::forget`] has looked.
    // ponytail: one link, so one task (a core) frames and writes everything to a node; a second
    // link per node when a profile of a busy one shows that core full.
    linked: Mutex<BTreeMap<String, (link::Link, Instant)>>,
    /// The Services that may sleep: what this node met of them, and the connections it holds.
    naps: wake::Naps,
    /// Where every other node is dialled, in the tests (a node's mesh address is not on the machine).
    #[cfg(test)]
    dial_to: Option<SocketAddr>,
}

/// What [`Proxy::reach`] reached.
enum Reached {
    /// A connection that is this client's alone: to a replica here, or through a node of
    /// before, which keeps none.
    Whole(TcpStream),
    /// A stream on the link to a node that takes links ([`link`]): this client's alone, and
    /// the node has the replica.
    Linked(link::Stream),
    /// One to that node's kithd, which has the replica: kept after, if it ends well.
    Kept(String, Relay),
    /// That node was sent the client's first bytes with the asking and gave no answer in
    /// time: it may yet pass them to a replica, so they go to no other.
    Lost,
}

impl Proxy {
    fn me(&self) -> &str {
        self.shared.members.me()
    }

    /// A connection to the replica behind `backend`: on this machine, or through the
    /// kithd of the node it is on.
    async fn reach(&self, (node, port, workload, replica): &Backend, early: &[u8]) -> std::io::Result<Reached> {
        if node == self.me() {
            // (Whoever connects to a Service's address is on this node: only it has it.)
            if !self.admits(workload, kith_mesh::node_address(self.prefix, node), *port) {
                return Err(std::io::Error::other("a NetworkPolicy says no"));
            }
            return self.local(workload, *replica, *port).await.map(Reached::Whole);
        }
        let relay = {
            let state = self.shared.store.lock().expect("nothing panics holding the store");
            let status = state
                .store
                .get(&format!("Node/{node}"))
                .and_then(|node| node.status.as_ref());
            status.and_then(|status| {
                let port = u16::try_from(status["mesh"]["port"].as_u64()?).ok()?;
                Some((port, status["mesh"]["kept"] == true, status["mesh"]["link"] == true))
            })
        };
        let (relay, keeps, links) =
            relay.ok_or_else(|| std::io::Error::other(format!("node {node} is not on the mesh")))?;
        let there = SocketAddr::new(kith_mesh::node_address(self.prefix, node).into(), relay);
        let replica = replica.map(|replica| format!(" {replica}")).unwrap_or_default();
        if links && !links_off() {
            let line = format!("{port} {workload}{replica}\n");
            // (None: the node would not take the link, or this one holds as many streams as the
            // node takes; the connection kept to it is used instead, as it says it keeps them.)
            if let Some(reached) = self.linked(node, there, &line, early).await? {
                return Ok(reached);
            }
        }
        if !keeps {
            // A node of before: a connection for this client alone, as it knows them. It
            // says so (one byte) when it has the replica; if it hangs up instead (a
            // policy, a replica just gone), the next backend is tried.
            let mut stream = within(self.dial(there)).await?;
            stream
                .write_all(format!("{port} {workload}{replica}\n").as_bytes())
                .await?;
            within(stream.read_u8()).await?;
            return Ok(Reached::Whole(stream));
        }
        let line = format!("kept {port} {workload}{replica}\n");
        // One kept from before, if there is one; hung up on since, perhaps: then a new one.
        let mut before = self.kept_to(node);
        loop {
            let (was_kept, mut relay) = match before.take() {
                Some(relay) => (true, relay),
                None => (false, Relay::new(within(self.dial(there)).await?)),
            };
            let asked = ask(&mut relay, &line, early).await;
            if was_kept && asked.is_err() {
                // (The others kept with it are as old: a node that is gone is waited for once.)
                self.kept.lock().expect("nothing panics holding the kept").remove(node);
            }
            match asked {
                Ok(true) => return Ok(Reached::Kept(node.clone(), relay)),
                Ok(false) => {
                    self.keep(node, relay);
                    return Err(std::io::Error::other("that node does not pass it on"));
                }
                Err(e) => match unanswered(e, was_kept, !early.is_empty()) {
                    Unanswered::Lost => return Ok(Reached::Lost),
                    Unanswered::Next(e) => return Err(e),
                    Unanswered::Again => {}
                },
            }
        }
    }

    async fn dial(&self, there: SocketAddr) -> std::io::Result<TcpStream> {
        #[cfg(test)]
        let there = self.dial_to.unwrap_or(there);
        TcpStream::connect(there).await
    }

    /// A stream on the link to `node`, which takes links, asked for the replica `line` names
    /// with `early` (what the client has said so far) behind it, in one frame: the node says
    /// `+` when it has it, and resets the stream when it has not. A link that is down is
    /// dialled again, once: with the client's bytes on the link that went down they may be
    /// with a replica ([`Reached::Lost`]), and with none said the same asking is made on the new one.
    /// A node that gives no answer in time has the link taken down (it is as good as gone), so
    /// that the next client dials a new one rather than waiting as long. None, with nothing
    /// sent: the node took no link, or this one holds the streams the node takes at most.
    async fn linked(
        &self,
        node: &str,
        there: SocketAddr,
        line: &str,
        early: &[u8],
    ) -> std::io::Result<Option<Reached>> {
        let asking = [line.as_bytes(), early].concat();
        for attempt in 0..2 {
            let Some(link) = self.link_to(node, there).await? else {
                return Ok(None);
            };
            // (The node resets what is past its cap, which reads as its no: the kept way is for those.)
            if link.streams() >= receive::STREAMS {
                return Ok(None);
            }
            let Ok(mut stream) = link.open() else { continue };
            if stream.tx.write(&asking).await.is_err() {
                continue;
            }
            let e = match within(stream.rx.read()).await {
                Ok(Some(said)) if said == b"+" => return Ok(Some(Reached::Linked(stream))),
                Ok(_) => return Err(std::io::Error::other("that node does not pass it on")),
                Err(e) => e,
            };
            // (A reset with the link up is the node's no: before its `+` it resets for nothing else.)
            if !link.is_down() && e.kind() == std::io::ErrorKind::ConnectionReset {
                return Err(e);
            }
            if e.kind() == std::io::ErrorKind::TimedOut {
                link.close();
            }
            match unanswered(e, link.is_down() && attempt == 0, !early.is_empty()) {
                Unanswered::Lost => return Ok(Some(Reached::Lost)),
                Unanswered::Next(e) => return Err(e),
                Unanswered::Again => {}
            }
        }
        Err(std::io::Error::other("the link is down"))
    }

    /// The link to `node`: the one there is, or a new one (`link` said first, as a node
    /// that takes links wants it, and answers `+` to) that takes its place. None when the
    /// node says no (`-`) or hangs up instead, before anything of a client's was sent.
    async fn link_to(&self, node: &str, there: SocketAddr) -> std::io::Result<Option<link::Link>> {
        let live = |links: &BTreeMap<String, (link::Link, Instant)>| {
            links
                .get(node)
                .filter(|(link, _)| !link.is_down())
                .map(|(link, _)| link.clone())
        };
        let hit = live(&self.linked.lock().expect("nothing panics holding the links"));
        if let Some(link) = hit {
            return Ok(Some(link));
        }
        let mut relay = Relay::new(within(self.dial(there)).await?);
        within(relay.to.write_all(b"link\n")).await?;
        match within(relay.from.read_u8()).await {
            Ok(b'+') => {}
            // (Silent: a node that is slow or gone, and the kept way would wait as long.)
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Err(e),
            _ => return Ok(None),
        }
        let (link, _) = link::link(relay, true);
        let mut links = self.linked.lock().expect("nothing panics holding the links");
        // (Another client dialled meanwhile: one link to a node, so ours goes.)
        if let Some(other) = live(&links) {
            link.close();
            return Ok(Some(other));
        }
        links.insert(node.to_string(), (link.clone(), Instant::now()));
        Ok(Some(link))
    }

    /// A connection to `node`'s kithd from before, if one is kept and not for too long.
    fn kept_to(&self, node: &str) -> Option<Relay> {
        let mut kept = self.kept.lock().expect("nothing panics holding the kept");
        let (relay, since) = kept.get_mut(node)?.pop()?;
        if since.elapsed() < KEPT {
            // (A runtime that cannot take it: a new one is made, as for a node that hung up.)
            return TcpStream::from_std(relay).ok().map(Relay::new);
        }
        // (The others were kept before it: for too long as well.)
        kept.remove(node);
        None
    }

    /// Keep `relay`, on which a client's connection ended well, for the next one to `node`.
    fn keep(&self, node: &str, relay: Relay) {
        // (Bytes read and not yet used would be lost with the buffer: not kept, then.)
        if !relay.from.buffer().is_empty() {
            return;
        }
        let Some(relay) = relay
            .from
            .into_inner()
            .reunite(relay.to)
            .ok()
            .and_then(|relay| relay.into_std().ok())
        else {
            return;
        };
        let mut kept = self.kept.lock().expect("nothing panics holding the kept");
        let kept = kept.entry(node.to_string()).or_default();
        if kept.len() < KEEP {
            kept.push((relay, Instant::now()));
        }
    }

    /// Hang up on the connections between nodes that were kept for too long.
    fn forget(&self) {
        let mut kept = self.kept.lock().expect("nothing panics holding the kept");
        kept.retain(|_, kept| {
            kept.retain(|(_, since)| since.elapsed() < KEPT);
            !kept.is_empty()
        });
        // (A link that is down is dialled again by the next client that needs it. One with no
        // stream open for as long as a connection is kept is closed, as the node closes it.)
        let mut links = self.linked.lock().expect("nothing panics holding the links");
        links.retain(|_, (link, since)| {
            if link.streams() > 0 {
                *since = Instant::now();
            } else if since.elapsed() > KEPT {
                link.close();
            }
            !link.is_down()
        });
    }

    /// The place for a connection from `from` to the Service `key`: a person's (of the people's
    /// ranges, `--people`) from the people's places, and only for its level's Services; anyone
    /// else's from the mesh's. (A Service's IPv4 address is no level's: a person gets none there.)
    fn place(&self, from: IpAddr, key: (IpAddr, u16)) -> Option<Place> {
        match &self.people {
            Some(people) if people.holds(from) => match key {
                (IpAddr::V6(address), port) => people.place(from, (address, port)),
                (IpAddr::V4(_), _) => None,
            },
            _ => self.serving.take(from),
        }
    }

    /// Does a listener take a connection from `from` at all? The mesh's, and with `people` (the
    /// listeners of the Services only) a person's. Whoever routes one of our addresses to this
    /// machine from outside is neither.
    fn takes(&self, from: IpAddr, people: bool) -> bool {
        self.is_ours(from) || (people && self.people.as_ref().is_some_and(|people| people.holds(from)))
    }

    /// Someone connected to a Service: pass the connection to its next backend that
    /// takes it.
    async fn serve(&self, key: (IpAddr, u16), mut client: TcpStream) {
        // (The place is held while the connection lasts.)
        let Ok(from) = client.peer_addr().map(|from| from.ip()) else {
            return;
        };
        let Some(_place) = self.place(from, key) else {
            return;
        };
        let backends_of = || {
            let table = self.table.lock().expect("nothing panics holding the table");
            table.get(&key).cloned().unwrap_or_default()
        };
        let mut backends = backends_of();
        // A Service that may sleep (T-1210) counts the connection, and holds one that finds no
        // replica while the Workload wakes: until one is ready, or the Service's `start` is up.
        // (Only a client the Workload's NetworkPolicies let in: the others are not activity.)
        // (Asked before the store's lock: most Services never sleep.)
        let met = if self.naps.has(&key) {
            let state = self.shared.store.lock().expect("nothing panics holding the store");
            let admits = |behind: &[_]| wake::admitted(&state.store, self.prefix, self.me(), behind);
            self.naps.meet(key, wake::unix(), admits)
        } else {
            None
        };
        if let Some(met) = met.as_ref().filter(|_| backends.is_empty()) {
            match wake::hold(met, || !backends_of().is_empty(), wake::hung_up(&client)).await {
                Ok(()) => {}
                Err(wake::Closed::Gone) => return,
                Err(closed) => return wake::close(&mut client, &closed).await,
            }
            backends = backends_of();
        }
        // (No turn is taken, or kept, for what has nothing behind it.)
        let first = if backends.is_empty() { 0 } else { self.turns.next(key) };
        // What the client has said by now goes with the asking where another node is
        // asked: one round trip between the nodes before its answer, not two. (Looked
        // for after the others here had a turn: a client's first bytes are a moment
        // behind its connection. One that says nothing first is not waited for.)
        tokio::task::yield_now().await;
        let mut early = vec![0; CHUNK];
        let said = client.read(&mut early).now_or_never().and_then(Result::ok);
        early.truncate(said.unwrap_or(0));
        for at in 0..backends.len() {
            match self.reach(&backends[(first + at) % backends.len()], &early).await {
                Ok(Reached::Whole(mut backend)) => {
                    if backend.write_all(&early).await.is_ok() {
                        drop(early);
                        let _ = pass(client, backend, IDLE).await;
                    }
                    return;
                }
                Ok(Reached::Kept(node, mut relay)) => {
                    drop(early);
                    if carry(client, &mut relay, IDLE).await.is_ok() {
                        self.keep(&node, relay);
                    }
                    return;
                }
                Ok(Reached::Linked(stream)) => {
                    // (What the client said went with the asking.)
                    drop(early);
                    let _ = client.set_nodelay(true);
                    stream.join(Idle::new(client, IDLE, None)).await;
                    return;
                }
                Ok(Reached::Lost) => return,
                Err(_) => {}
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

    /// Another node's kithd connected, to pass on its clients' connections for replicas
    /// here ([`taken`]): only for what a Service has a backend for on this node, and only
    /// from where the Workload's NetworkPolicies let it, asked for each of them.
    async fn take(&self, from: TcpStream) -> Option<()> {
        let IpAddr::V6(caller) = from.peer_addr().ok()?.ip() else {
            return None;
        };
        // (Each asking, of a connection or of a stream of a link, is found for by itself.)
        let find = move |port, workload, replica| self.find(caller, port, workload, replica);
        let link = move |io, relaying, caller: IpAddr| receive::serve(io, relaying, caller, self.links, find);
        admit_or_link(&self.relaying, &self.spares, caller.into(), from, find, link).await
    }

    /// The replica `caller` asks for, if this node's table asks for it and the Workload's
    /// NetworkPolicies let `caller` in: a connection to it.
    async fn find(&self, caller: Ipv6Addr, port: u16, workload: String, replica: Option<u32>) -> Option<TcpStream> {
        let asked_for = {
            let table = self.table.lock().expect("nothing panics holding the table");
            let mut backends = table.values().flatten();
            let asked = (self.me(), port, workload.as_str(), replica);
            backends.any(|(node, port, of, which)| (node.as_str(), *port, of.as_str(), *which) == asked)
        };
        if !asked_for || !self.admits(&workload, caller, port) {
            return None;
        }
        self.local(&workload, replica, port).await.ok()
    }

    /// A replica on this machine, wherever it listens: on the machine's own loopback, or
    /// in its pod.
    async fn local(&self, workload: &str, replica: Option<u32>, port: u16) -> std::io::Result<TcpStream> {
        let pod = replica.map(|replica| {
            let pod = crate::controller::pod_of(workload, replica);
            let pods = self.shared.pods.lock().expect("nothing panics holding the pods");
            pods.live_id(&pod).to_string()
        });
        let pod = pod.as_deref().map(|pod| (&*self.shared, pod));
        within(crate::pods::connect(pod, port)).await
    }

    /// Is `from` on the mesh, or, of IPv4 (a Service's IPv4 address, which only this machine and its
    /// pods are sent to), this machine (the loopback, or a Service address held on it: what a
    /// process here dials from) or one of its pods? Not any address of the pods' or Services'
    /// ranges: whoever routes one of those to this machine from a link that is not a pod's
    /// would pass.
    fn is_ours(&self, from: IpAddr) -> bool {
        match from {
            IpAddr::V6(ip) => kith_mesh::in_mesh(self.prefix, ip),
            IpAddr::V4(ip) => {
                ip.is_loopback()
                    || self
                        .shared
                        .pods
                        .lock()
                        .expect("nothing panics holding the pods")
                        .serves4(ip)
                    || {
                        let table = self.table.lock().expect("nothing panics holding the table");
                        table.keys().any(|(address, _)| *address == IpAddr::V4(ip))
                    }
            }
        }
    }

    /// Accept on `listener` for good, each connection from the mesh handled by `with`; with
    /// `people`, those of the people's ranges too (handled by `with` as well: `serve`).
    async fn accept<F, Fut>(self: Arc<Self>, listener: TcpListener, people: bool, with: F)
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
            if self.takes(from.ip(), people) {
                tokio::spawn(with(self.clone(), stream));
            }
        }
    }
}

/// Bytes both ways between a client and a backend, until either ends or `idle` goes by
/// with no byte moved on one of them.
///
/// The bytes move in the kernel, by splice(2) through a pipe each way, not through a buffer
/// here; a way that splice or a pipe is refused for (or that is past [`PIPES_MAX`]) goes on by
/// the copy. (Plain TCP only: a TLS stream is bytes to be decrypted, so the ingress's, which
/// end in TLS, keep `copy_bidirectional`.)
async fn pass(client: TcpStream, backend: TcpStream, idle: Duration) -> std::io::Result<(u64, u64)> {
    let (begun, moved) = (tokio::time::Instant::now(), AtomicU64::new(0));
    let ((from_client, to_client), (from_backend, to_backend)) = (client.into_split(), backend.into_split());
    let both = async {
        tokio::try_join!(
            pump(from_client, to_backend, begun, &moved),
            pump(from_backend, to_client, begun, &moved)
        )
    };
    // (The time since a byte last moved either way, asked when it may be up.)
    let quiet = async {
        loop {
            let until = begun + Duration::from_millis(moved.load(Ordering::Relaxed)) + idle;
            if tokio::time::Instant::now() >= until {
                return Err::<(u64, u64), _>(std::io::ErrorKind::TimedOut.into());
            }
            tokio::time::sleep_until(until).await;
        }
    };
    tokio::select! { out = both => out, out = quiet => out }
}

/// A pipe: what splice moves bytes through, of the kernel's default 64 KiB. (Made once for a
/// way of a connection.)
struct Pipe(std::os::fd::OwnedFd, std::os::fd::OwnedFd);

/// What a splice may move at once: the pipe's size.
const PIPE: usize = 64 << 10;

/// The most pipes open at once, all connections' ways: two files each, so 4096 of the 65536
/// kithd has (`NOFILE_WANTED`); a way past it goes by the copy, as one a pipe is refused for.
const PIPES_MAX: usize = 2048;

/// Pipes open now, to keep within [`PIPES_MAX`].
static PIPES_OPEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Takes a place of `max` in `open`, if there is one.
fn take_place(open: &std::sync::atomic::AtomicUsize, max: usize) -> bool {
    open.try_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < max).then_some(n + 1))
        .is_ok()
}

impl Pipe {
    /// None when there is no room for one, or no pipe (out of files, say): the copy then.
    fn new() -> Option<Pipe> {
        #[cfg(test)]
        if NO_PIPE.get() {
            return None;
        }
        if !take_place(&PIPES_OPEN, PIPES_MAX) {
            return None;
        }
        let made = nix::unistd::pipe2(nix::fcntl::OFlag::O_NONBLOCK | nix::fcntl::OFlag::O_CLOEXEC);
        let Ok((read, write)) = made else {
            PIPES_OPEN.fetch_sub(1, Ordering::AcqRel);
            return None;
        };
        #[cfg(test)]
        PIPES.set(PIPES.get() + 1);
        Some(Pipe(read, write))
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        PIPES_OPEN.fetch_sub(1, Ordering::AcqRel);
        #[cfg(test)]
        PIPES.set(PIPES.get() - 1);
    }
}

/// Splices that moved bytes on this thread (for another module's test).
#[cfg(test)]
pub(crate) fn splices() -> u64 {
    SPLICES.get()
}

#[cfg(test)]
thread_local! {
    /// For the tests of the thread: splices that moved bytes, pipes open, splice refused, and
    /// no pipe to be had.
    static SPLICES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static PIPES: std::cell::Cell<i64> = const { std::cell::Cell::new(0) };
    static REFUSE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static NO_PIPE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Splices that a filter or an old kernel gives these for do not come again: the copy.
fn refused(error: &std::io::Error) -> bool {
    use nix::errno::Errno::{EACCES, EINVAL, ENOSYS, EOPNOTSUPP, EPERM};
    let errno = error.raw_os_error();
    [EINVAL, ENOSYS, EPERM, EACCES, EOPNOTSUPP]
        .iter()
        .any(|e| errno == Some(*e as i32))
}

/// One way of [`pass`]: what `from` reads goes to `to`, until `from` ends (then `to` is
/// shut for writing: it is dropped), counting the bytes, and each that moves is noted in
/// `moved` for the idle cut.
async fn pump(
    mut from: OwnedReadHalf,
    mut to: OwnedWriteHalf,
    begun: tokio::time::Instant,
    moved: &AtomicU64,
) -> std::io::Result<u64> {
    use nix::fcntl::{SpliceFFlags, splice};
    use std::io::{Error, ErrorKind::WouldBlock};
    use tokio::io::Interest;
    let note = || moved.store(begun.elapsed().as_millis() as u64, Ordering::Relaxed);
    let mut total = 0u64;
    if let Some(pipe) = Pipe::new() {
        let (src, dst) = (from.as_ref(), to.as_ref());
        let flags = SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_NONBLOCK;
        loop {
            src.readable().await?;
            let pulled = src.try_io(Interest::READABLE, || {
                #[cfg(test)]
                if REFUSE.get() {
                    return Err(Error::from_raw_os_error(nix::errno::Errno::EINVAL as i32));
                }
                splice(src, None, &pipe.1, None, PIPE, flags).map_err(Error::from)
            });
            let mut left = match pulled {
                Ok(0) => return Ok(total),
                Ok(n) => n,
                Err(e) if e.kind() == WouldBlock => continue,
                // (Nothing is in the pipe when it is asked: the copy has all of it still.)
                Err(e) if refused(&e) => break,
                Err(e) => return Err(e),
            };
            #[cfg(test)]
            SPLICES.set(SPLICES.get() + 1);
            note();
            total += left as u64;
            while left > 0 {
                dst.writable().await?;
                match dst.try_io(Interest::WRITABLE, || {
                    splice(&pipe.0, None, dst, None, left, flags).map_err(Error::from)
                }) {
                    Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
                    Ok(n) => {
                        left -= n;
                        note();
                    }
                    Err(e) if e.kind() == WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
        }
    }
    let mut chunk = vec![0; 16 << 10];
    loop {
        let read = from.read(&mut chunk).await?;
        if read == 0 {
            return Ok(total);
        }
        note();
        to.write_all(&chunk[..read]).await?;
        note();
        total += read as u64;
    }
}

/// What an asking that got no answer means for its client.
enum Unanswered {
    /// Its bytes may be with a replica: it is not asked for anywhere else.
    Lost,
    /// The next backend is tried.
    Next(std::io::Error),
    /// Asked again of the same node, on a new connection.
    Again,
}

/// An asking failed with `e`, on a connection that `was_kept` or was new, with what the
/// client had said (`spoke`) or with nothing. What the client said went with the asking,
/// and a node that hangs up or goes quiet may have passed it on to a replica first (it
/// was stopped between that and its answer): said to no second replica, so that client's
/// connection is closed. With nothing said: no answer in the time (or the kernel gave the
/// connection up, which reads the same) is a node that is slow or gone, and a new
/// connection to it would be waited for as long; a kept connection hung up on is one
/// that was kept too long there, asked again on a new one.
fn unanswered(e: std::io::Error, was_kept: bool, spoke: bool) -> Unanswered {
    match (spoke, was_kept && e.kind() != std::io::ErrorKind::TimedOut) {
        (true, _) => Unanswered::Lost,
        (false, true) => Unanswered::Again,
        (false, false) => Unanswered::Next(e),
    }
}

/// Ask the kithd on `relay` for the replica `line` names, and send `early` (what the
/// client has said so far, a frame of [`carry`] at most) with the asking: whether it has
/// the replica. What it does not pass on it says too; it is then told where the client's
/// bytes end, and the connection is as good as before.
async fn ask(relay: &mut Relay, line: &str, early: &[u8]) -> std::io::Result<bool> {
    let mut asking = line.as_bytes().to_vec();
    if !early.is_empty() {
        asking.extend_from_slice(&(early.len() as u16).to_be_bytes());
        asking.extend_from_slice(early);
    }
    relay.to.write_all(&asking).await?;
    match within(relay.from.read_u8()).await? {
        b'+' => Ok(true),
        b'-' => relay.to.write_all(&[0, 0]).await.map(|()| false),
        _ => Err(std::io::Error::other("not an answer")),
    }
}

/// What another node's kithd asks for on `from`, one line for each client of its own: the
/// port, the Workload and (where each is a pod) which replica, which `find` connects to if
/// that node may have it. After `kept ` it asks for a connection that is used again, and
/// the client's bytes follow in frames ([`carry`]) without waiting: `+` and the replica's
/// in frames, or `-` (and then the client's are nobody's, to where it says they end), and
/// then the next line. A node of before asks with no such word, once: `+` and the bytes
/// as they are, or it is hung up on. Over the limit (no place for it at this asking) nothing
/// is looked for: each kept asking is said no to in the same way, and a node of before is
/// hung up on. Each asking looks for a place again ([`Hold::room`]).
///
/// A first line of `link` alone makes the connection a link between the two kithds
/// instead: what `link` does with it ([`receive::serve`]), which holds the place the
/// connection has for as long as the link lasts. Its streams each ask for a replica by
/// themselves and take places of their own.
async fn taken<F, Fut, L, LFut>(from: TcpStream, mut hold: Hold<'_>, find: F, link: L) -> Option<()>
where
    F: Fn(u16, String, Option<u32>) -> Fut,
    Fut: Future<Output = Option<TcpStream>>,
    L: FnOnce(Relay, Limits, IpAddr) -> LFut,
    LFut: Future<Output = Option<()>>,
{
    let mut relay = Relay::new(from);
    let mut wait = CONNECT;
    loop {
        // A connection that is kept may say nothing for a while. A line that has begun
        // has all of it in the time, not each byte: one that drips holds no place.
        let begun = tokio::time::timeout(wait, relay.from.fill_buf()).await.ok()?.ok()?;
        if begun.is_empty() {
            return None;
        }
        let mut line = Vec::new();
        within((&mut relay.from).take(300).read_until(b'\n', &mut line))
            .await
            .ok()?;
        let line = std::str::from_utf8(&line).ok()?.strip_suffix('\n')?;
        if line == "link" && wait == CONNECT {
            // (A node with no place to relay for gets no link: it is told `-` and hung up on. A
            // link is begun with `+`, which the node that asks for it waits for before it sends.)
            if !hold.room() {
                let _ = relay.to.write_all(b"-").await;
                return None;
            }
            relay.to.write_all(b"+").await.ok()?;
            return link(relay, hold.relaying.clone(), hold.caller).await;
        }
        let mut words = line.split(' ').peekable();
        let kept = words.next_if_eq(&"kept").is_some();
        let (port, workload) = (words.next()?.parse::<u16>().ok()?, words.next()?);
        let replica = match words.next() {
            Some(replica) => Some(replica.parse::<u32>().ok()?),
            None => None,
        };
        let replica = match hold.room() {
            true => tokio::time::timeout(FOUND, find(port, workload.to_string(), replica))
                .await
                .ok()
                .flatten(),
            false => None,
        };
        if !kept {
            let (mut from, replica) = (relay.from.into_inner().reunite(relay.to).ok()?, replica?);
            from.write_all(b"+").await.ok()?;
            return pass(from, replica, IDLE).await.ok().map(drop);
        }
        match replica {
            Some(replica) => {
                relay.to.write_all(b"+").await.ok()?;
                carry(replica, &mut relay, IDLE).await.ok()?;
            }
            None => {
                relay.to.write_all(b"-").await.ok()?;
                let skipped = async {
                    loop {
                        let size = relay.from.read_u16().await?;
                        if size == 0 {
                            return Ok(());
                        }
                        if usize::from(size) > CHUNK {
                            return Err(std::io::Error::other("a frame too long"));
                        }
                        tokio::io::copy(&mut (&mut relay.from).take(u64::from(size)), &mut tokio::io::sink()).await?;
                    }
                };
                within(skipped).await.ok()?;
            }
        }
        wait = KEPT_THERE;
    }
}

/// What a connection from another node holds while it is kept: a place to relay (room for
/// replicas), or else a spare ([`SPARE`]), which only says no. Each asking looks for a place
/// again; the first to get one keeps it for the rest of the connection, and the spare goes.
struct Hold<'a> {
    relaying: &'a Limits,
    caller: IpAddr,
    place: Option<Place>,
    spare: Option<Place>,
}

impl Hold<'_> {
    /// Whether this asking may look for a replica: a place held, or one got now.
    fn room(&mut self) -> bool {
        if self.place.is_none() {
            self.place = self.relaying.take(self.caller);
            match self.place {
                Some(_) => self.spare = None,
                None => over_limit(self.caller),
            }
        }
        self.place.is_some()
    }
}

/// A node that is over its limit of relayed connections says so in its log, and no more often
/// than once a minute: whether it is said at `now` (seconds), `last` being when it last was.
fn said_now(last: &AtomicU64, now: u64) -> bool {
    let was = last.load(Ordering::Relaxed);
    // (Two at once: one of them says it.)
    now >= was + 60
        && last
            .compare_exchange(was, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

/// Says that `caller` was told no for want of a place ([`said_now`]).
fn over_limit(caller: IpAddr) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    static BEGUN: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    // (From 60 on, so that the first is said.)
    let now = 60 + BEGUN.get_or_init(Instant::now).elapsed().as_secs();
    if said_now(&LAST, now) {
        eprintln!(
            "kithd: services: over the limit of connections relayed for other nodes: {caller} is told no \
             (said once a minute at most)"
        );
    }
}

/// [`taken`] for a connection from node `caller`, with a place for relaying if one is free,
/// else a spare ([`SPARE`]) to say no with. Past the spares, the connection is dropped at once:
/// nothing is read from it, and no answer is given.
#[cfg(test)]
async fn admit<F, Fut>(relaying: &Limits, spares: &Limits, caller: IpAddr, from: TcpStream, find: F) -> Option<()>
where
    F: Fn(u16, String, Option<u32>) -> Fut,
    Fut: Future<Output = Option<TcpStream>>,
{
    // (A node with no links: one that says `link` is hung up on, as a line it does not know.)
    let link = |_, _, _| async { None };
    admit_or_link(relaying, spares, caller, from, find, link).await
}

/// [`admit`] for a node that takes links too ([`taken`]).
async fn admit_or_link<F, Fut, L, LFut>(
    relaying: &Limits,
    spares: &Limits,
    caller: IpAddr,
    from: TcpStream,
    find: F,
    link: L,
) -> Option<()>
where
    F: Fn(u16, String, Option<u32>) -> Fut,
    Fut: Future<Output = Option<TcpStream>>,
    L: FnOnce(Relay, Limits, IpAddr) -> LFut,
    LFut: Future<Output = Option<()>>,
{
    let place = relaying.take(caller);
    let spare = match place.is_some() {
        true => None,
        false => {
            over_limit(caller);
            Some(spares.take(caller)?)
        }
    };
    taken(
        from,
        Hold {
            relaying,
            caller,
            place,
            spare,
        },
        find,
        link,
    )
    .await
}

/// Bytes both ways between `local` (a client here, or a replica) and the other node's
/// kithd on `relay`, each way in frames: two bytes of length and as many bytes, and a
/// length of none where that side says no more. So `relay` outlasts the connection: Ok
/// when both ways ended as a connection's do, and then (only then) another may be passed
/// on it. As in [`pass`], `idle` with no byte moved ends it.
async fn carry(mut local: TcpStream, relay: &mut Relay, idle: Duration) -> std::io::Result<()> {
    let (mut from, mut to) = local.split();
    let (theirs, ours) = (&mut relay.from, &mut relay.to);
    // When a byte last moved, in ms since it began: asked once in `idle`, not set a
    // timer for each time.
    let (begun, moved) = (Instant::now(), AtomicU64::new(0));
    let moves = || moved.store(begun.elapsed().as_millis() as u64, Ordering::Relaxed);
    let out = async {
        let (mut chunk, mut frames) = (vec![0; CHUNK], Vec::new());
        loop {
            if frames.len() >= CHUNK {
                ours.write_all(&frames).await?;
                frames.clear();
            }
            // What is there now goes in one write (an answer and its end, say), so in as
            // few packets; only when nothing more is, is it sent and waited for.
            let read = match from.read(&mut chunk).now_or_never() {
                Some(read) => read?,
                None => {
                    ours.write_all(&frames).await?;
                    frames.clear();
                    from.read(&mut chunk).await?
                }
            };
            moves();
            frames.extend_from_slice(&(read as u16).to_be_bytes());
            frames.extend_from_slice(&chunk[..read]);
            if read == 0 {
                return ours.write_all(&frames).await;
            }
        }
    };
    let back = async {
        loop {
            let mut left = usize::from(theirs.read_u16().await?);
            if left > CHUNK {
                return Err(std::io::Error::other("a frame too long"));
            }
            if left == 0 {
                // (Whether or not it is still there to be told.)
                let _ = to.shutdown().await;
                return Ok(());
            }
            while left > 0 {
                let has = theirs.fill_buf().await?;
                let some = has.len().min(left);
                if some == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                to.write_all(&has[..some]).await?;
                theirs.consume(some);
                left -= some;
                moves();
            }
        }
    };
    let silent = async {
        loop {
            let until = begun + Duration::from_millis(moved.load(Ordering::Relaxed)) + idle;
            if Instant::now() >= until {
                return std::io::Error::from(std::io::ErrorKind::TimedOut);
            }
            tokio::time::sleep_until(until.into()).await;
        }
    };
    tokio::select! {
        passed = async { tokio::try_join!(out, back) } => passed.map(drop),
        timed = silent => Err(timed),
    }
}

async fn within<T>(doing: impl Future<Output = std::io::Result<T>>) -> std::io::Result<T> {
    tokio::time::timeout(CONNECT, doing)
        .await
        .map_err(|_| std::io::ErrorKind::TimedOut)?
}

/// Listen for every Service on this node's mesh interface (the loopback with no mesh), until
/// stopped. `shared.mesh_port` is the TCP port other nodes pass connections on to (the mesh's
/// own, which is UDP); none with no mesh, where there is no relay either. It may change while
/// this runs (`mesh::follow`): the listeners are then made again.
///
/// With `strays` (a node with the ingress), ports 443 and 80 of the Services' addresses
/// are not listened on here: the ingress has those ports, and sends what is ours on.
pub async fn run(
    shared: Arc<Shared>,
    people: bool,
    mut strays: Option<mpsc::UnboundedReceiver<TcpStream>>,
    mut stopping: watch::Receiver<bool>,
) {
    let Some(cluster) = &shared.cluster else { return };
    let prefix = crate::mesh::prefix(&cluster.me.ca);
    let people64 = crate::people::prefix(&cluster.me.ca);
    let proxy = Arc::new(Proxy {
        shared: shared.clone(),
        prefix,
        table: Mutex::default(),
        turns: Turns::default(),
        serving: Limits::new(SERVING, SERVING),
        people: people.then(|| People::new(people64, SERVING)),
        relaying: Limits::new(RELAYING, RELAYING_PER_NODE).per_node(),
        spares: Limits::new(SPARE, SPARE_PER_NODE).per_node(),
        kept: Mutex::default(),
        links: receive::BOUNDS,
        linked: Mutex::default(),
        naps: wake::Naps::default(),
        #[cfg(test)]
        dial_to: None,
    });
    tokio::spawn(wake::run(proxy.clone(), stopping.clone()));
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
                    tokio::spawn(async move { proxy.serve((IpAddr::V6(*at.ip()), at.port()), stream).await });
                }
            }
            elsewhere.store(false, Ordering::Relaxed);
        })
    });
    // On each thread a listener of each port, the kernel spreading the connections between them.
    let mut listening: BTreeMap<(IpAddr, u16), Vec<tokio::task::JoinHandle<()>>> = BTreeMap::new();
    let mut threads = Vec::new();
    let mut generation = shared.generation.subscribe();
    // (A cgroup that was not there has no program an earlier kithd left.)
    let left = std::path::Path::new(connect::CGROUP).exists();
    let attached = kith_dm_sys::netns_cookie().map(|netns| {
        let attached = connect::attach(&[], netns);
        (netns, attached.v6.and(Ok(attached.v4)))
    });
    let mut kernel = match attached {
        Ok((netns, Ok(four))) => {
            eprintln!("kithd: services: the kernel passes connections to a replica here");
            // (Its IPv4 hook refused: the IPv6 one works, and the Services' IPv4 addresses are kithd's.)
            // (With a program an earlier kithd left, if there is one, it may still pass: tried to empty each round.)
            let no4 = match (&four, left) {
                (Ok(()), _) => V4::Works,
                (Err(_), true) => V4::Stale,
                (Err(_), false) => V4::Refused,
            };
            if let Err(e) = four {
                eprintln!(
                    "kithd: services: the kernel's IPv4 program: {e}: kithd passes the connections to a Service's IPv4 address itself"
                );
            }
            Kernel::Has(netns, Vec::new(), no4)
        }
        Ok((netns, Err(e))) if left => {
            eprintln!(
                "kithd: services: kithd passes every connection itself: {e}; the kernel's program an earlier \
                 kithd left may still pass connections to a replica here, until it is emptied (tried again each round)"
            );
            Kernel::Stuck(netns)
        }
        Ok((_, Err(e))) | Err(e) => {
            eprintln!("kithd: services: kithd passes every connection itself: {e}");
            Kernel::Off
        }
    };
    // Making or letting go of a pod wakes a round: the address of one let go may be given
    // to the next.
    let moved = shared
        .pods
        .lock()
        .expect("nothing panics holding the pods")
        .moved
        .clone();
    let mut probed = BTreeMap::new();
    // (With no mesh: the Services' addresses on the loopback; and the listeners that could not bind, said once.)
    let mut on_loopback = Loopback::new(prefix);
    // (The Services' IPv4 addresses are on the loopback with a mesh too: the mesh holds none.)
    let services = crate::pods::service_range();
    let mut on_loopback4 = services.map(v4::Loopback::new);
    let mut unbound = BTreeSet::new();
    let mut mesh_port = shared.mesh_port.subscribe();
    let mut port = *mesh_port.borrow_and_update();
    loop {
        // (The mesh came, or went, since the last round: the listeners were made for the other
        // kind of address, so they are made again; the loopback's addresses go with the mesh's.)
        let now = *mesh_port.borrow_and_update();
        if now != port {
            port = now;
            listening.values().flatten().for_each(tokio::task::JoinHandle::abort);
            listening.clear();
            unbound.clear();
            if port.is_some() {
                on_loopback.hold(&BTreeSet::new());
            }
        }
        let relay = port.map(|port| (IpAddr::V6(me), port));
        // (Asked before the store's lock: never both at once. The rules themselves are kept in
        // step by `pods::keep_held`, which needs no cluster.)
        let unsent = shared.pods.lock().expect("nothing panics holding the pods").unsent();
        // (The node that leads the store gives the Services their IPv4 addresses, once its store has
        // applied its log.)
        let leads = {
            let metrics = shared.raft.metrics().borrow().clone();
            let applied = metrics.last_applied.map(|log| log.index);
            metrics.current_leader == Some(metrics.id) && crate::people::caught_up(metrics.last_log_index, applied)
        };
        let (mut wanted, reports, plans) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let table = table(&state.store, prefix, services);
            if let Some(people) = &proxy.people {
                people.hold(crate::levels::reach(&state.store, (prefix, people64), proxy.me()));
            }
            // (A Service that was refused its host says so, in `expose`; the others say nothing.)
            let refused = crate::ingress::exposed(&state.store, prefix).1;
            // What `kith get service` shows; written by the node that leads the store.
            let stale = |(key, address): (String, Ipv6Addr)| {
                let backends = table.iter().filter(|((at, _), _)| *at == IpAddr::V6(address));
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
            for (key, fields) in services
                .into_iter()
                .flat_map(|range| v4::allocate(&state.store, &range, leads))
            {
                match reports.iter_mut().find(|(other, _)| *other == key) {
                    Some((_, report)) => report.extend(fields),
                    None => reports.push((key, fields)),
                }
            }
            for policy in state.store.list(Some("NetworkPolicy")) {
                reports.extend(policy_unsaid(policy, unsent).map(|fields| (policy.key(), fields)));
            }
            // (Without a cluster nothing tells the Workload to sleep or wake: none is held.)
            let ports = if shared.cluster.is_some() {
                wake::ports(&state.store, prefix, &table)
            } else {
                Default::default()
            };
            proxy.naps.set(ports);
            let mut plans = match kernel {
                Kernel::Has(..) => kernel_plan(&state.store, &table, proxy.me()),
                Kernel::Off | Kernel::Stuck(_) => Vec::new(),
            };
            // (The kernel passes a connection past kithd, which would not meet it: a Service
            // that may sleep is kithd's.)
            plans.retain(|plan| !proxy.naps.has(&plan.service));
            (table, reports, plans)
        };
        // Where each replica here the kernel may pass to is asked; then, before anything that
        // waits, what may no longer be passed (a NetworkPolicy, a replica gone, a pod made
        // again) is taken from the kernel, and only then are the new ones asked. (Taken only:
        // what is added waits for this round's table, with the ports to kithd in it.)
        let asked = where_asked(&shared, &plans);
        let mut kept = kernel_entries(&plans, &mut probed, &asked, &mut Table::new());
        kept.retain(|entry| matches!(&kernel, Kernel::Has(_, last, _) if last.contains(entry)));
        install(&mut kernel, kept, &listening);
        let metrics = shared.raft.metrics().borrow().clone();
        if metrics.current_leader == Some(metrics.id) && !reports.is_empty() {
            // (Never passed on to a new leader: the addresses were planned from this node's view.)
            let reported = shared
                .write_here(kith_store::Command::Patch { statuses: reports })
                .await;
            if let Err(e) = reported {
                eprintln!("kithd: services: writing their status: {e}");
            }
        }
        if matches!(kernel, Kernel::Has(..)) {
            ask_where(&asked, &mut probed).await;
        }
        // The pods asked again, with nothing that waits from here to the program: a pod let
        // go while its replica was asked, its address maybe another's now, is not passed to.
        let entries = kernel_entries(&plans, &mut probed, &where_asked(&shared, &plans), &mut wanted);
        // The relay, and one listener for each Service port; one whose address is not on
        // the interface yet (the mesh puts it there) is tried again shortly.
        let mut keys: BTreeSet<(IpAddr, u16)> = wanted.keys().copied().collect();
        let wanted_at: BTreeSet<Ipv6Addr> = keys
            .iter()
            .filter_map(|(at, _)| match at {
                IpAddr::V6(at) => Some(*at),
                IpAddr::V4(_) => None,
            })
            .collect();
        let elsewhere = elsewhere.load(Ordering::Relaxed);
        // (The ingress has these ports of the IPv6 addresses only.)
        keys.retain(|(at, port)| !(elsewhere && at.is_ipv6() && [443, 80].contains(port)));
        // (No thread, and no listener, before there is a Service: a node that has none
        // has nothing to pass on, and nothing on it waits.)
        if threads.is_empty() && !wanted.is_empty() {
            threads = start();
        }
        if let (false, Some(relay)) = (threads.is_empty(), relay) {
            keys.insert(relay);
        }
        // With no mesh to carry them, the Services' addresses are on the loopback: a pod's
        // connection to one arrives there, and kithd listens on it (T-0723).
        if port.is_none() {
            on_loopback.hold(&wanted_at);
        }
        if let Some(on_loopback4) = &mut on_loopback4 {
            on_loopback4.hold(&v4::wanted(&wanted));
        }
        proxy.turns.keep(&wanted);
        proxy.forget();
        *proxy.table.lock().expect("nothing panics holding the table") = wanted;
        listening.retain(|key, tasks| {
            let keep = keys.contains(key) && !tasks.iter().any(tokio::task::JoinHandle::is_finished);
            if !keep {
                tasks.iter().for_each(tokio::task::JoinHandle::abort);
            }
            keep
        });
        let mut waiting = false;
        for key in keys {
            if listening.contains_key(&key) {
                continue;
            }
            // (Until the last thread's handle on the one bound before is dropped, tried again.)
            let listeners = match listen(SocketAddr::new(key.0, key.1), threads.len()) {
                Ok(listeners) => {
                    unbound.remove(&key);
                    listeners
                }
                Err(e) => {
                    // (With a mesh, its address not being there yet is usual; without, it is ours.)
                    // (An IPv4 address is on the loopback before this, or we said so.)
                    if (port.is_none() || key.0.is_ipv4()) && unbound.insert(key) {
                        eprintln!("kithd: services: listening on {}:{}: {e}", key.0, key.1);
                    }
                    waiting = true;
                    continue;
                }
            };
            let tasks = threads.iter().zip(listeners).map(|(thread, listener)| {
                let proxy = proxy.clone();
                thread.spawn(async move {
                    // (Taken by this thread's runtime, which then wakes it.)
                    let Ok(listener) = TcpListener::from_std(listener) else {
                        return;
                    };
                    if Some(key) == relay {
                        let take = |proxy: Arc<Proxy>, stream| async move {
                            let _ = proxy.take(stream).await;
                        };
                        // (The relay is for the other nodes: never for a person.)
                        proxy.accept(listener, false, take).await;
                    } else {
                        let serve = move |proxy: Arc<Proxy>, stream| async move { proxy.serve(key, stream).await };
                        proxy.accept(listener, true, serve).await;
                    }
                })
            });
            listening.insert(key, tasks.collect());
        }
        // (Only what is listened on is open to the pods, the tables made again when that changes.)
        crate::pods::open_to(&shared, open_keys(&listening, relay));
        install(&mut kernel, entries, &listening);
        let again = Duration::from_millis(if waiting { 500 } else { 5000 });
        tokio::select! {
            _ = generation.changed() => {}
            () = moved.notified() => {}
            _ = mesh_port.changed() => {}
            () = tokio::time::sleep(again) => {}
            _ = stopping.changed() => break,
        }
    }
    // (A kithd that is gone sends nothing the kernel's way: started again, it begins empty.)
    if let Kernel::Has(netns, ..) | Kernel::Stuck(netns) = kernel {
        let _ = connect::attach(&[], netns);
    }
    if port.is_none() {
        on_loopback.hold(&BTreeSet::new());
    }
    if let Some(on_loopback4) = &mut on_loopback4 {
        on_loopback4.hold(&BTreeSet::new());
    }
    listening
        .values()
        .flatten()
        .chain(&stray)
        .for_each(tokio::task::JoinHandle::abort);
}

/// With no mesh, the Services' addresses on the loopback (what the mesh's interface holds
/// where there is one): the node's own, as a pod's connection to one is sent here, and kithd
/// listens on it.
struct Loopback {
    prefix: Ipv6Addr,
    /// The loopback's index, asked for once.
    index: Option<u32>,
    /// What this kithd put there.
    held: BTreeSet<Ipv6Addr>,
    /// Whether the Services' addresses an earlier kithd left (one killed) are taken off.
    cleaned: bool,
    /// What was last said of a failure, said again only when it changes.
    told: Option<String>,
}

/// The Services' addresses of `prefix` among `present` that are not `wanted`: what a kithd
/// that was killed left on the loopback.
fn stale(prefix: Ipv6Addr, present: Vec<Ipv6Addr>, wanted: &BTreeSet<Ipv6Addr>) -> impl Iterator<Item = Ipv6Addr> {
    let wanted = wanted.clone();
    present
        .into_iter()
        .filter(move |at| kith_mesh::is_service_address(prefix, *at) && !wanted.contains(at))
}

impl Loopback {
    fn new(prefix: Ipv6Addr) -> Self {
        Loopback {
            prefix,
            index: None,
            held: BTreeSet::new(),
            cleaned: false,
            told: None,
        }
    }

    /// Make the Services' addresses on the loopback `wanted`, saying once what stops it.
    /// With none wanted and none held (and the stale ones gone) it asks the kernel nothing.
    fn hold(&mut self, wanted: &BTreeSet<Ipv6Addr>) {
        if self.cleaned && self.held.is_empty() && wanted.is_empty() {
            return;
        }
        let held = self.try_hold(wanted).map_err(|e| e.to_string());
        match held {
            Ok(()) => self.told = None,
            Err(e) if self.told.as_ref() != Some(&e) => {
                eprintln!("kithd: services: their addresses on the loopback: {e}");
                self.told = Some(e);
            }
            Err(_) => {}
        }
    }

    fn try_hold(&mut self, wanted: &BTreeSet<Ipv6Addr>) -> std::io::Result<()> {
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
            let present = kith_mesh::addresses6(index)?;
            self.held.extend(stale(self.prefix, present, wanted));
            self.cleaned = true;
        }
        kith_mesh::hold(index, &mut self.held, wanted)
    }
}

/// The kernel's IPv4 program, apart from the IPv6 one.
#[derive(Clone, Copy, Debug, PartialEq)]
enum V4 {
    Works,
    /// Refused (said once): it has none of IPv4 entries, put again at each round with one, and kithd
    /// passes the connections to the Services' IPv4 addresses itself.
    Refused,
    /// Refused, and the one before could not be emptied: it may pass to a replica that is gone, so
    /// emptying it is tried again at each round.
    Stale,
}

/// The kernel's program on the containers' cgroup, for the network namespace (`u64`, its
/// cookie) it passes connections of.
enum Kernel {
    /// None: kithd passes every connection itself.
    Off,
    /// What it has, and what of its IPv4 program ([`V4`]).
    Has(u64, Vec<connect::Entry>, V4),
    /// One kithd could not empty: it may pass what kithd no longer knows of.
    Stuck(u64),
}

/// The kernel's program, made again when what it passes changes: never sending a share to
/// a port of kithd's that is not listened on yet. Refused, it is emptied, and kithd passes
/// every connection itself from then on; one that could not be emptied either is tried
/// again at each call until it is (said once, and once more when it is).
///
/// What it may still pass after it should not, and for how long: a replica gone, until the
/// round the store's change wakes takes it out (one store read and one program load); a
/// pod let go, whose address the next pod made on this node (of any namespace) may be
/// given, until the round making or letting go of a pod wakes takes it out: at most the
/// rest of the round in progress (its probes, together at most `CONNECT`, 3 s, and on the
/// node that leads the store its status write, as long as that takes to commit), then one
/// program load. The pods are asked again just before each load, with nothing that waits
/// in between.
///
/// The IPv4 program is put apart from the IPv6 one: one refused (said once) leaves the IPv6 one
/// working, and the Services' IPv4 addresses are then kithd's alone.
fn install(
    kernel: &mut Kernel,
    entries: Vec<connect::Entry>,
    listening: &BTreeMap<(IpAddr, u16), Vec<tokio::task::JoinHandle<()>>>,
) {
    install_with(kernel, entries, listening, &connect::put, &mut |text| {
        eprintln!("{text}")
    });
}

/// [`install`] with `put` to put each program (`true` for the IPv4 one) and `say` to say what it
/// says, so a test can have one refused.
fn install_with(
    kernel: &mut Kernel,
    mut entries: Vec<connect::Entry>,
    listening: &BTreeMap<(IpAddr, u16), Vec<tokio::task::JoinHandle<()>>>,
    put: &impl Fn(bool, &[u8]) -> std::io::Result<()>,
    say: &mut impl FnMut(String),
) {
    let (netns, last, v4) = match kernel {
        Kernel::Off => return,
        Kernel::Stuck(netns) => {
            if connect::attach_with(&[], *netns, put).all().is_ok() {
                say(
                    "kithd: services: the kernel's program is emptied at last: kithd passes every connection itself"
                        .into(),
                );
                *kernel = Kernel::Off;
            }
            return;
        }
        Kernel::Has(netns, last, v4) => (netns, last, v4),
    };
    if *v4 == V4::Stale && put(true, &connect::program4(&[], *netns)).is_ok() {
        say("kithd: services: the kernel's IPv4 program is emptied at last".into());
        *v4 = V4::Refused;
    }
    entries.retain(|entry| {
        entry
            .elsewhere
            .is_none_or(|port| listening.contains_key(&(entry.service.0, port)))
    });
    if entries == *last {
        return;
    }
    let said_v4 = *v4 != V4::Works;
    let attached = connect::attach_with(&entries, *netns, put);
    if let Err(e) = attached.v6 {
        *kernel = match connect::attach_with(&[], *netns, put).all() {
            Ok(()) => {
                say(format!(
                    "kithd: services: kithd passes every connection itself: the kernel's program: {e}"
                ));
                Kernel::Off
            }
            Err(left) => {
                say(format!(
                    "kithd: services: the kernel's program: {e}; nor could it be emptied ({left}): \
                     the one before may still pass connections to a replica here, until it is (tried again each round)"
                ));
                Kernel::Stuck(*netns)
            }
        };
        return;
    }
    // (One refused is put again at each round that has an IPv4 entry, as `last` then lacks them:
    // the next that is accepted lifts it, and a refusal after that is said again.)
    if attached.v4.is_ok() {
        *v4 = V4::Works;
    }
    if let Err(e) = attached.v4 {
        if !said_v4 {
            // (Emptied if it can be: the one before may still pass to a replica that is gone.)
            let emptied = put(true, &connect::program4(&[], *netns));
            *v4 = if emptied.is_ok() { V4::Refused } else { V4::Stale };
            let then = match emptied {
                Ok(()) => String::new(),
                Err(left) => format!(
                    "; nor could it be emptied ({left}): the one before may still pass connections to a replica here"
                ),
            };
            say(format!(
                "kithd: services: the kernel's IPv4 program: {e}{then}: kithd passes the connections to a Service's IPv4 address itself, and those of IPv6 are still the kernel's"
            ));
        }
        entries.retain(|entry| entry.service.0.is_ipv6());
    }
    *last = entries;
}

/// A Service port the kernel may pass on ([`connect`]): its backends here, which it
/// connects to itself, and the others, whose share goes to kithd's listener on port
/// `elsewhere` of the same address (with only them behind it).
#[derive(Debug, PartialEq)]
struct Plan {
    service: (IpAddr, u16),
    here: Vec<Backend>,
    others: Vec<Backend>,
    elsewhere: Option<u16>,
}

/// The most replicas here of one Service port the kernel's program picks between (each
/// is a few instructions, and a jump over them has to fit).
const MOST_HERE: usize = 256;

/// What the kernel may pass on, for `me`: each Service port with a replica here, and no
/// NetworkPolicy for any of their Workloads (kithd asks those at each connection). The
/// port to kithd for the others is the highest free one of the address, never 80 or 443
/// (the ingress may have those).
fn kernel_plan(store: &Store, table: &Table, me: &str) -> Vec<Plan> {
    let guarded = |(_, _, workload, _): &Backend| {
        store
            .get(workload)
            .is_none_or(|workload| policies(store, workload).next().is_some())
    };
    let mut taken: BTreeSet<(IpAddr, u16)> = table.keys().copied().collect();
    let mut plans = Vec::new();
    for (&service, backends) in table {
        let (here, others): (Vec<Backend>, Vec<Backend>) =
            backends.iter().cloned().partition(|backend| backend.0 == me);
        if here.is_empty() || here.len() > MOST_HERE || here.iter().any(guarded) {
            continue;
        }
        let mut elsewhere = None;
        if !others.is_empty() {
            let free = (1..=u16::MAX)
                .rev()
                .find(|port| ![80, 443].contains(port) && !taken.contains(&(service.0, *port)));
            let Some(port) = free else { continue };
            taken.insert((service.0, port));
            elsewhere = Some(port);
        }
        plans.push(Plan {
            service,
            here,
            others,
            elsewhere,
        });
    }
    plans
}

/// Each replica here the kernel may pass to (`true` first for one of an IPv4 Service address), where
/// it answered, and the addresses it was asked at ([`reachable`] then): kept while those stay what it
/// would be asked at.
type Probed = BTreeMap<(bool, Backend), (Vec<IpAddr>, SocketAddr)>;

/// Where a replica here is asked, of the family of the Service address it is behind (`v4`): its
/// pod's addresses of that family, of `pod` (none before its pod is made: never the machine's
/// loopback, where something else may listen), or with no pod the machine's loopback of that family.
/// Never the other family's: a socket made of one could not reach it once the kernel wrote it in, so
/// a replica with a pod address of that family only is left to kithd.
fn reachable(replica: Option<u32>, pod: Vec<IpAddr>, v4: bool) -> Vec<IpAddr> {
    match replica {
        None if v4 => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        None => vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
        Some(_) => pod.into_iter().filter(|ip| ip.is_ipv4() == v4).collect(),
    }
}

/// Where a replica answers on `port`: the first of `at` that does.
async fn probe(at: Vec<IpAddr>, port: u16) -> Option<SocketAddr> {
    for ip in at {
        if within(TcpStream::connect((ip, port))).await.is_ok() {
            return Some(SocketAddr::new(ip, port));
        }
    }
    None
}

/// Where each replica here of `plans` is asked now ([`reachable`]), by its pod, for the family of the
/// plan's Service address.
fn where_asked(shared: &Shared, plans: &[Plan]) -> BTreeMap<(bool, Backend), Vec<IpAddr>> {
    let pods = shared.pods.lock().expect("nothing panics holding the pods");
    let at = |(_, _, workload, replica): &Backend, v4: bool| {
        let pod = replica.map_or_else(Vec::new, |replica| {
            let pod = crate::controller::pod_of(workload, replica);
            pods.addresses(pods.live_id(&pod))
        });
        reachable(*replica, pod, v4)
    };
    let mut asked = BTreeMap::new();
    for plan in plans {
        let v4 = plan.service.0.is_ipv4();
        asked.extend(plan.here.iter().map(|backend| ((v4, backend.clone()), at(backend, v4))));
    }
    asked
}

/// Ask each replica of `asked` not in `probed` where it answers; keep what does. One with
/// nowhere to ask, or that does not answer, is asked again next time.
async fn ask_where(asked: &BTreeMap<(bool, Backend), Vec<IpAddr>>, probed: &mut Probed) {
    let new: Vec<(&(bool, Backend), &Vec<IpAddr>)> = asked
        .iter()
        .filter(|(backend, at)| !at.is_empty() && !probed.contains_key(*backend))
        .collect();
    let found = futures_util::future::join_all(new.iter().map(|(backend, at)| probe(at.to_vec(), backend.1.1))).await;
    for ((backend, at), found) in new.into_iter().zip(found) {
        if let Some(found) = found {
            probed.insert(backend.clone(), (at.clone(), found));
        }
    }
}

/// The program's entries for `plans`, each replica here where it answered (`probed`); a
/// port with one that has not is left to kithd. The ports to kithd for the others go into
/// `wanted`. First each replica `probed` is forgotten that is not to be asked at the same
/// addresses now (`asked`): gone from the plans, or its pod let go or made again elsewhere.
fn kernel_entries(
    plans: &[Plan],
    probed: &mut Probed,
    asked: &BTreeMap<(bool, Backend), Vec<IpAddr>>,
    wanted: &mut Table,
) -> Vec<connect::Entry> {
    probed.retain(|backend, (at, _)| asked.get(backend) == Some(at));
    let mut entries = Vec::new();
    for plan in plans {
        let v4 = plan.service.0.is_ipv4();
        let here = plan
            .here
            .iter()
            .map(|backend| probed.get(&(v4, backend.clone())).map(|(_, at)| *at));
        let Some(here) = here.collect() else {
            continue;
        };
        if let Some(port) = plan.elsewhere {
            wanted.insert((plan.service.0, port), plan.others.clone());
        }
        let all = (plan.here.len() + plan.others.len()) as u32;
        entries.push(connect::Entry {
            service: plan.service,
            here,
            all,
            elsewhere: plan.elsewhere,
        });
    }
    entries
}

/// `threads` handles on one listener on `at`, one for each thread: one accept queue,
/// which whichever thread is free takes from, and a port no other socket may share.
fn listen(at: SocketAddr, threads: usize) -> std::io::Result<Vec<std::net::TcpListener>> {
    let socket = if at.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(at)?;
    // (Not blocking, as a runtime needs: and so are its clones, which share that.)
    let listener = socket.listen(1024)?.into_std()?;
    let mut all = (1..threads)
        .map(|_| listener.try_clone())
        .collect::<std::io::Result<Vec<_>>>()?;
    all.push(listener);
    Ok(all)
}

/// The threads the connections to Services are on, each with a runtime of its own: the
/// requests a second rise with the cores, and kithd's API never waits behind a busy
/// Service. Where none can be started, they are on kithd's own, as they were.
fn start() -> Vec<tokio::runtime::Handle> {
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let mut threads = Vec::new();
    for at in 0..cores.min(THREADS) {
        match thread(format!("kith-proxy-{at}")) {
            Ok(handle) => threads.push(handle),
            Err(e) => {
                eprintln!("kithd: services: starting a thread: {e}");
                break;
            }
        }
    }
    if threads.is_empty() {
        threads.push(tokio::runtime::Handle::current());
    }
    threads
}

/// A thread called `name` with a runtime of its own, for as long as kithd runs (what is
/// on it is stopped, not the thread).
pub fn thread(name: String) -> std::io::Result<tokio::runtime::Handle> {
    thread_by(name, |name, run| {
        std::thread::Builder::new().name(name).spawn(run).map(drop)
    })
}

/// [`thread`] with the spawn given. The runtime is built on the new thread, never on the caller:
/// a failed spawn would drop it on the async thread, where tokio panics.
fn thread_by(
    name: String,
    spawn: impl FnOnce(String, Box<dyn FnOnce() + Send>) -> std::io::Result<()>,
) -> std::io::Result<tokio::runtime::Handle> {
    let (tx, rx) = std::sync::mpsc::channel();
    let run = move || match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => {
            let _ = tx.send(Ok(runtime.handle().clone()));
            runtime.block_on(std::future::pending::<()>());
        }
        Err(e) => {
            let _ = tx.send(Err(e));
        }
    };
    spawn(name, Box::new(run))?;
    rx.recv().map_err(std::io::Error::other)?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A spawn that fails (EAGAIN at a thread limit) on the async thread: an error back, and no
    /// runtime to drop there (tokio panics on that).
    #[tokio::test]
    async fn a_thread_that_cannot_be_spawned_is_an_error_not_a_panic() {
        let refused = |_: String, _: Box<dyn FnOnce() + Send>| {
            Err(std::io::Error::from_raw_os_error(nix::errno::Errno::EAGAIN as i32))
        };
        let e = thread_by("refused".into(), refused).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(nix::errno::Errno::EAGAIN as i32));
    }

    #[tokio::test]
    async fn a_thread_gives_a_handle_that_runs_tasks() {
        let handle = thread("runs-tasks".into()).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        handle.spawn(async move {
            let _ = tx.send(std::thread::current().name().map(str::to_owned));
        });
        assert_eq!(rx.await.unwrap().as_deref(), Some("runs-tasks"));
    }

    /// What a killed kithd left on the loopback goes: the Services' addresses of this cluster that
    /// are not wanted; the wanted ones, a node's, another cluster's and ::1 stay.
    #[test]
    fn a_stale_service_address_on_the_loopback_is_taken_off_and_nothing_else() {
        let prefix = kith_mesh::prefix(b"a cluster");
        let service = |name| kith_mesh::service_address(prefix, "default", name);
        let (kept, left) = (service("kept"), service("left"));
        let present = vec![
            Ipv6Addr::LOCALHOST,
            kept,
            left,
            kith_mesh::node_address(prefix, "alpha"),
            kith_mesh::service_address(kith_mesh::prefix(b"another"), "default", "web"),
        ];
        let gone: Vec<_> = stale(prefix, present, &BTreeSet::from([kept])).collect();
        assert_eq!(gone, [left]);
    }

    fn people_of(reach: &[(&str, &[(Ipv6Addr, u16)])]) -> (People, Ipv6Addr) {
        let people64: Ipv6Addr = "fd12:3456:789a:1::".parse().unwrap();
        let people = People::new(people64, SERVING);
        people.hold(
            reach
                .iter()
                .map(|(from, services)| {
                    let services = services.iter().map(|(address, port)| (*address, vec![*port])).collect();
                    (from.parse().unwrap(), Arc::new(services))
                })
                .collect(),
        );
        (people, people64)
    }

    /// A peer reaches the Services of its own level on the people node, and no other's; a
    /// source that is not a peer of the people's ranges is not served at all.
    #[test]
    fn people_serving_a_peer_reaches_its_own_levels_services_only() {
        let prefix = kith_mesh::prefix(b"a cluster");
        let (web, db) = (
            kith_mesh::service_address(prefix, "default", "web"),
            kith_mesh::service_address(prefix, "default", "db"),
        );
        let (people, _) = people_of(&[
            ("100.89.0.5", &[(web, 443)]),
            ("fd12:3456:789a:1::5", &[(web, 443)]),
            ("100.89.0.6", &[(db, 5432)]),
        ]);
        let ip = |text: &str| -> IpAddr { text.parse().unwrap() };
        for peer in ["100.89.0.5", "fd12:3456:789a:1::5"] {
            assert!(
                people.place(ip(peer), (web, 443)).is_some(),
                "{peer} reaches its level's Service"
            );
            assert!(
                people.place(ip(peer), (db, 5432)).is_none(),
                "{peer}: another level's Service"
            );
            assert!(
                people.place(ip(peer), (web, 80)).is_none(),
                "{peer}: a port its level lacks"
            );
        }
        assert!(people.place(ip("100.89.0.6"), (web, 443)).is_none());
        assert!(people.place(ip("100.89.0.6"), (db, 5432)).is_some());
        // Not the people's: outside both ranges, or in a range and no peer's.
        for from in [
            "203.0.113.9",
            "fd00:1:2:3::1",
            "fd12:3456:789a:2::5",
            "::1",
            "127.0.0.1",
        ] {
            assert!(!people.holds(ip(from)), "{from} is not in the people's ranges");
            assert!(people.place(ip(from), (web, 443)).is_none(), "{from} is refused");
        }
        for from in ["100.89.0.77", "fd12:3456:789a:1::77", "::ffff:100.89.0.77"] {
            assert!(people.holds(ip(from)), "{from} is in the people's ranges");
            assert!(
                people.place(ip(from), (web, 443)).is_none(),
                "{from}: no peer's address"
            );
        }
        assert!(
            people.holds(ip("::ffff:100.89.0.5")),
            "a v4 peer as the dual-stack socket shows it"
        );
        assert!(people.place(ip("::ffff:100.89.0.5"), (web, 443)).is_some());
        assert!(
            people.limits.sources.lock().unwrap().len() <= 3,
            "only a peer is counted"
        );
    }

    /// A peer holds 8 of the 4096 places, by its own address; two IPv6 peers of one /64 are two.
    #[test]
    fn people_serving_a_peer_holds_a_few_places_of_the_many() {
        let web = kith_mesh::service_address(kith_mesh::prefix(b"a cluster"), "default", "web");
        let (people, _) = people_of(&[
            ("fd12:3456:789a:1::5", &[(web, 443)]),
            ("fd12:3456:789a:1::6", &[(web, 443)]),
            ("100.89.0.5", &[(web, 443)]),
        ]);
        let ip = |text: &str| -> IpAddr { text.parse().unwrap() };
        let mut all = Vec::new();
        for peer in ["fd12:3456:789a:1::5", "fd12:3456:789a:1::6", "100.89.0.5"] {
            let held: Vec<_> = (0..8).map(|_| people.place(ip(peer), (web, 443))).collect();
            assert!(held.iter().all(Option::is_some), "{peer} holds 8");
            assert!(
                people.place(ip(peer), (web, 443)).is_none(),
                "{peer}: the 9th is refused"
            );
            all.extend(held);
        }
        assert_eq!(people.limits.room.available_permits(), SERVING - 24, "of 4096 places");
    }

    /// A level's Service with no port listed is reached on no port (fail closed), not on all.
    #[test]
    fn people_serving_an_empty_port_list_reaches_nothing() {
        let web = kith_mesh::service_address(kith_mesh::prefix(b"a cluster"), "default", "web");
        let people = People::new("fd12:3456:789a:1::".parse().unwrap(), SERVING);
        people.hold(BTreeMap::from([(
            "100.89.0.5".parse().unwrap(),
            Arc::new(vec![(web, Vec::new())]),
        )]));
        let from: IpAddr = "100.89.0.5".parse().unwrap();
        for port in [0, 80, 443] {
            assert!(people.place(from, (web, port)).is_none(), "port {port}");
        }
        assert!(people.limits.sources.lock().unwrap().is_empty());
    }

    /// What `serve` and `accept` do with a source, on a Proxy as `run` makes one: a person is
    /// taken by the listeners of the Services only, and placed as a peer of its level; the mesh
    /// keeps the mesh's places; a source in neither is not taken.
    #[tokio::test]
    async fn people_serving_admits_by_source_and_listener() {
        let mut proxy = proxy_of(state_with_web("people-admit").await, 8080, "Workload/default/web", None);
        let web = kith_mesh::service_address(proxy.prefix, "default", "web");
        let (people, _) = people_of(&[("100.89.0.5", &[(web, 443)]), ("fd12:3456:789a:1::5", &[(web, 443)])]);
        let ip = |text: &str| -> IpAddr { text.parse().unwrap() };
        let (mesh, person, v6_person) = (
            IpAddr::V6(kith_mesh::node_address(proxy.prefix, "b")),
            ip("100.89.0.5"),
            ip("fd12:3456:789a:1::5"),
        );
        // Without --people nobody of the ranges is taken, and none is placed as a person.
        for from in [person, v6_person, ip("203.0.113.9"), ip("fd00:9::1")] {
            assert!(!proxy.takes(from, true) && !proxy.takes(from, false), "{from}");
        }
        assert!(proxy.takes(mesh, true) && proxy.takes(mesh, false));
        proxy.people = Some(people);
        for from in [person, v6_person] {
            assert!(proxy.takes(from, true), "{from}: the Service listeners take a person");
            assert!(!proxy.takes(from, false), "{from}: the relay and the strays do not");
            assert!(
                proxy.place(from, (web.into(), 443)).is_some(),
                "{from}: its level's Service"
            );
            assert!(
                proxy.place(from, (web.into(), 80)).is_none(),
                "{from}: not a port its level lists"
            );
        }
        assert!(!proxy.takes(ip("203.0.113.9"), true));
        assert!(
            proxy.takes(ip("100.89.0.77"), true),
            "a source of the range is taken, then refused a place"
        );
        assert!(proxy.place(ip("100.89.0.77"), (web.into(), 443)).is_none());
        // A Service's IPv4 address is no level's: a person of a level that lists the port gets none.
        let from = ip("100.89.0.2");
        assert!(proxy.place(from, (ip("10.96.0.5"), 443)).is_none());
        // The mesh is placed from the mesh's places, whatever its port; a person from the people's.
        let (kept_mesh, kept_person) = (
            proxy.place(mesh, (web.into(), 80)),
            proxy.place(person, (web.into(), 443)),
        );
        assert!(kept_mesh.is_some() && kept_person.is_some());
        assert_eq!(proxy.serving.room.available_permits(), SERVING - 1);
        assert_eq!(
            proxy.people.as_ref().unwrap().limits.room.available_permits(),
            SERVING - 1
        );
    }

    #[test]
    fn over_the_limit_is_said_once_a_minute() {
        let last = AtomicU64::new(0);
        let said: Vec<bool> = [60, 61, 119, 120, 121, 500].map(|now| said_now(&last, now)).to_vec();
        assert_eq!(said, [true, false, false, true, false, true]);
    }

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
        let table = table(&store, prefix, None);
        let address = IpAddr::from(address);
        // The named port is the container's; a port with no target is itself; UDP is left out.
        let of = "Workload/default/web".to_string();
        let to = |port: u16| {
            vec![
                ("a".to_string(), port, of.clone(), None),
                ("b".to_string(), port, of.clone(), None),
            ]
        };
        let wanted = Table::from([((address, 80), to(8080)), ((address, 9000), to(9000))]);
        assert_eq!(table, wanted);

        // The Service's name, where the cluster's names are asked.
        let (zones, _) = crate::dns::zones_of(&store, Some(prefix));
        let found = zones
            .lookup("10.0.0.1".parse().unwrap(), "web.default.kith", 28)
            .unwrap();
        assert_eq!(
            found.answers[0].data,
            kith_dns::Rdata::Aaaa(kith_mesh::service_address(prefix, "default", "web"))
        );
    }

    #[test]
    fn ingress_proxy_turns_are_each_services_own() {
        let turns = Turns::default();
        let (a, b) = (
            (IpAddr::V6(Ipv6Addr::LOCALHOST), 80),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), 81),
        );
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
            let fields = policy_unsaid(store.get(key).unwrap(), false)?;
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

    /// A policy whose peer cidr cannot be read: the API refuses one now, so it is written into
    /// the store as an older version left it. A deny with such a peer keeps everything out (ingress
    /// and egress both), so the allow after it opens nothing; an allow with one lets nothing in.
    #[test]
    fn a_deny_with_a_peer_that_cannot_be_read_keeps_everything_out() {
        let stored = stored_policy;
        let web = "Workload/default/web";
        let prefix = kith_mesh::prefix(b"test");
        let from: IpAddr = "10.1.2.3".parse().unwrap();
        let deny = "{ action: deny, peers: [{ cidr: 'nonsense' }] }";
        let nodes = "{ action: deny, peers: [{ node: b, cidr: 'nonsense' }] }";
        let (all, none) = ("{ action: allow }", "[]");
        for deny in [deny, nodes] {
            let store = stored(&format!("[{deny}, {all}]"), &format!("[{deny}, {all}]"));
            for node in [None, Some("a"), Some("b")] {
                assert!(!admits(&store, web, node, from, 80), "{deny}, {node:?}");
                assert!(
                    !admits(&store, web, node, "fd00::1".parse().unwrap(), 80),
                    "{deny}, {node:?}"
                );
            }
            let net = |cidr: &str| {
                let (address, bits) = cidr.split_once('/').unwrap();
                (address.parse::<IpAddr>().unwrap(), bits.parse::<u8>().unwrap())
            };
            let got = egress_of(&store, web, Some(prefix)).unwrap();
            assert_eq!(got.len(), 2, "{deny}");
            assert_eq!(got[0].to, vec![net("0.0.0.0/0"), net("::/0")], "{deny}");
            assert!(!got[0].allow && got[1].allow, "{deny}");
        }
        // An allow with one lets nobody in, and holds nothing out of its egress.
        let store = stored("[{ action: allow, peers: [{ cidr: 'nonsense' }] }]", none);
        assert!(!admits(&store, web, Some("a"), from, 80));
        let store = stored(
            "[{ action: allow }]",
            "[{ action: allow, peers: [{ cidr: 'nonsense' }] }]",
        );
        assert_eq!(egress_of(&store, web, Some(prefix)).unwrap(), vec![]);
        // The status says so (not `enforced`).
        let store = stored(
            "[{ action: deny, peers: [{ cidr: 'nonsense' }] }, { action: allow }]",
            none,
        );
        let report = policy_report(store.get("NetworkPolicy/default/p").unwrap(), false);
        assert_eq!(report["state"], "partial");
        assert!(
            report["message"].as_str().unwrap().contains("cannot be read"),
            "{report}"
        );
    }

    /// A policy as an older version left it, which the store holds as it is (`put`), as a log
    /// replayed does: the API refuses these now.
    fn stored_policy(ingress: &str, egress: &str) -> Store {
        let mut store = Store::default();
        for source in [
            HOME.to_string(),
            format!(
                "apiVersion: kith.dev/v1\nkind: NetworkPolicy\nmetadata: {{ name: p }}\n\
                 spec:\n  selector: {{ app: web }}\n  ingress: {ingress}\n  egress: {egress}\n"
            ),
        ] {
            for resource in Resource::from_source(&source).unwrap() {
                store.put(resource.unwrap());
            }
        }
        store
    }

    /// A cidr that reads but that nothing is matched by is as one that cannot be read: an IPv4
    /// address written as IPv6 (a pod's IPv4 packets never meet it) in egress, and any IPv4 cidr in
    /// ingress (a caller comes from an IPv6 mesh address). A deny keeps everything out, an allow
    /// lets nothing through.
    #[test]
    fn a_deny_with_a_peer_that_cannot_be_read_by_what_asks_keeps_everything_out() {
        let web = "Workload/default/web";
        let prefix = kith_mesh::prefix(b"test");
        let mesh: IpAddr = kith_mesh::node_address(prefix, "a").into();
        let all = [
            (IpAddr::from(Ipv4Addr::UNSPECIFIED), 0),
            (IpAddr::from(Ipv6Addr::UNSPECIFIED), 0),
        ];
        let (denied, open) = (
            "{ action: deny, peers: [{ cidr: '::ffff:10.0.0.0/104' }] }",
            "{ action: allow }",
        );
        let store = stored_policy("[]", &format!("[{denied}, {open}]"));
        let got = egress_of(&store, web, Some(prefix)).unwrap();
        assert_eq!(got[0].to, all.to_vec(), "IPv4 as IPv6, in a deny");
        let store = stored_policy(
            "[]",
            "[{ action: allow, peers: [{ cidr: '::ffff:10.0.0.0/104' }] }, { action: allow, peers: [{ cidr: '10.0.0.0/8' }] }]",
        );
        let got = egress_of(&store, web, Some(prefix)).unwrap();
        assert_eq!((got.len(), got[0].to.len()), (1, 1), "an allow of it holds nothing");
        for cidr in ["0.0.0.0/0", "10.0.0.0/8", "::ffff:10.0.0.0/104"] {
            let store = stored_policy(
                &format!("[{{ action: deny, peers: [{{ cidr: '{cidr}' }}] }}, {open}]"),
                "[]",
            );
            assert!(!admits(&store, web, Some("a"), mesh, 80), "{cidr}");
            let store = stored_policy(&format!("[{{ action: allow, peers: [{{ cidr: '{cidr}' }}] }}]"), "[]");
            assert!(!admits(&store, web, Some("a"), mesh, 80), "{cidr}");
        }
        // A deny of a network an IPv6 caller is in still says so, as before.
        let store = stored_policy(
            "[{ action: deny, peers: [{ cidr: 'fd00::/8' }] }, { action: allow }]",
            "[]",
        );
        assert!(!admits(&store, web, None, "fd00::1".parse().unwrap(), 80));
        assert!(admits(&store, web, None, "fe80::1".parse().unwrap(), 80));
    }

    /// A deny of a node, on a node with no mesh prefix, is left out: `mesh_prefix` is `None`
    /// only where there is no cluster, so there is no node address to keep out.
    #[test]
    fn a_deny_of_a_node_without_a_mesh_is_left_out() {
        let mut store = Store::default();
        let policy = "apiVersion: kith.dev/v1\nkind: NetworkPolicy\nmetadata: { name: p }\n\
             spec:\n  selector: { app: web }\n  egress: [{ action: deny, peers: [{ node: b }] }, { action: allow }]\n";
        for source in [HOME, policy] {
            for resource in Resource::from_source(source).unwrap() {
                store.apply(resource.unwrap()).unwrap();
            }
        }
        let got = egress_of(&store, "Workload/default/web", None).unwrap();
        assert_eq!(got.len(), 1, "the deny has no address to hold out");
        assert!(got[0].allow && got[0].to.is_empty());
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
        let report = policy_report(store.get("NetworkPolicy/default/web").unwrap(), false);
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
        let report = policy_report(labels.get("NetworkPolicy/default/web").unwrap(), false);
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

    /// What a pod of a Workload may reach is its policies' egress rules, in the order they are
    /// stored and written: a peer by node is the node's address on the mesh, by cidr the
    /// network, and one that cannot be told apart matches nothing in an allow and everything in
    /// a deny. A Workload with no egress rule in any policy is not held; the status says enforced.
    #[test]
    fn egress_rules_of_a_workload_come_from_its_policies() {
        use kith_mesh::pod::Egress;
        let mut store = Store::default();
        let apply = |store: &mut Store, source: &str| {
            for resource in Resource::from_source(source).unwrap() {
                store.apply(resource.unwrap()).unwrap();
            }
        };
        let (web, other) = ("Workload/default/web", "Workload/default/other");
        let prefix = kith_mesh::prefix(b"test");
        apply(&mut store, HOME);
        assert_eq!(egress_of(&store, web, Some(prefix)), None, "no policy");
        let policy = |name: &str, selector: &str, rules: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: NetworkPolicy\nmetadata: {{ name: {name} }}\n\
                 spec:\n  selector: {selector}\n  ingress: [{{ action: allow }}]\n  egress: {rules}\n"
            )
        };
        let rules = "[{ action: deny, peers: [{ cidr: '10.1.0.0/16' }], ports: [22] }, \
                     { action: allow, peers: [{ node: b }, { cidr: '10.0.0.0/8' }, { selector: { app: x } }], ports: [443, 80] }, \
                     { action: allow, peers: [{ node: b, cidr: 'fd00::/8' }] }, { action: deny }]";
        apply(&mut store, &policy("p", "{ app: web }", rules));
        let b = IpAddr::from(kith_mesh::node_address(prefix, "b"));
        let got = egress_of(&store, web, Some(prefix)).unwrap();
        let net = |cidr: &str| {
            let (address, bits) = cidr.split_once('/').unwrap();
            (address.parse().unwrap(), bits.parse().unwrap())
        };
        assert_eq!(
            got,
            vec![
                Egress {
                    allow: false,
                    to: vec![net("10.1.0.0/16")],
                    ports: vec![22]
                },
                // (The peer by selector holds nothing in an allow; the other two are the rule's.)
                Egress {
                    allow: true,
                    to: vec![(b, 128), net("10.0.0.0/8")],
                    ports: vec![443, 80]
                },
                // (The node's address is within fd00::/8 only if the mesh's prefix is: it is.)
                Egress {
                    allow: true,
                    to: vec![(b, 128)],
                    ports: vec![]
                },
                Egress {
                    allow: false,
                    to: vec![],
                    ports: vec![]
                },
            ]
        );
        // With no mesh a node has no address: its peer holds nothing.
        let alone = egress_of(&store, web, None).unwrap();
        assert_eq!(alone[1].to, vec![net("10.0.0.0/8")]);
        assert_eq!(
            alone.len(),
            3,
            "a rule whose peers hold nothing is no rule: it would be any"
        );
        // Others are not held, nor is a Workload whose policies have ingress rules only.
        assert_eq!(egress_of(&store, other, Some(prefix)), None);
        let mut ingress = Store::default();
        apply(&mut ingress, HOME);
        let only = "apiVersion: kith.dev/v1\nkind: NetworkPolicy\nmetadata: { name: i }\n\
                    spec:\n  selector: { app: web }\n  ingress: [{ action: allow }]\n";
        apply(&mut ingress, only);
        assert_eq!(egress_of(&ingress, web, Some(prefix)), None);
        // A deny of peers that cannot be told apart keeps everybody out, in both families.
        let mut denied = Store::default();
        apply(&mut denied, HOME);
        apply(
            &mut denied,
            &policy("d", "{ app: web }", "[{ action: deny, peers: [{ namespace: x }] }]"),
        );
        let all = egress_of(&denied, web, Some(prefix)).unwrap();
        assert_eq!(all[0].to, vec![net("0.0.0.0/0"), net("::/0")]);
        // The status says egress is enforced.
        let report = policy_report(store.get("NetworkPolicy/default/p").unwrap(), false);
        assert_eq!(report["state"], "partial", "(the selector peer)");
        assert!(
            !report["message"]
                .as_str()
                .unwrap()
                .contains("egress rules are not enforced")
        );
        let report = policy_report(denied.get("NetworkPolicy/default/d").unwrap(), false);
        assert!(report["message"].as_str().unwrap().contains("cannot be told apart"));
        let mut plain = Store::default();
        apply(&mut plain, HOME);
        apply(
            &mut plain,
            &policy(
                "e",
                "{ app: web }",
                "[{ action: allow, peers: [{ cidr: '10.0.0.0/8' }] }]",
            ),
        );
        let report = policy_report(plain.get("NetworkPolicy/default/e").unwrap(), false);
        assert_eq!(report, json!({ "state": "enforced", "message": null }));
        // While this node's pods' tables could not be made again for it, egress is not enforced:
        // the status says so (a policy with no egress rule is not held back by it).
        let report = policy_report(plain.get("NetworkPolicy/default/e").unwrap(), true);
        assert_eq!(report["state"], "partial");
        assert!(report["message"].as_str().unwrap().contains("egress not enforced yet"));
        let report = policy_report(ingress.get("NetworkPolicy/default/i").unwrap(), true);
        assert_eq!(report, json!({ "state": "enforced", "message": null }));
        // A policy that cannot be read holds no pod (`policies` skips it): the status is not enforced.
        // (The store refuses one, so this is one it holds from another version of the spec.)
        let spec = json!({ "selector": { "app": "web" }, "egress": "nonsense" });
        let written = json!({
            "apiVersion": "kith.dev/v1", "kind": "NetworkPolicy", "metadata": { "name": "x" }, "spec": spec,
        });
        let report = policy_report(&serde_json::from_value(written).unwrap(), false);
        assert_eq!(report["state"], "error");
        assert!(report["message"].as_str().unwrap().contains("holds no pod"));
    }

    #[tokio::test]
    async fn services_are_on_a_thread_a_core_taking_from_one_listener() {
        let named = || {
            let tasks = std::fs::read_dir("/proc/self/task").unwrap().flatten();
            let comm = |task: std::fs::DirEntry| std::fs::read_to_string(task.path().join("comm")).unwrap_or_default();
            tasks.map(comm).filter(|comm| comm.starts_with("kith-proxy")).count()
        };
        let before = named();
        let threads = start();
        let cores = std::thread::available_parallelism().unwrap().get();
        assert_eq!(threads.len(), cores.min(THREADS));
        // (Each thread names itself as it starts.)
        for _ in 0..100 {
            if named() - before == cores.min(THREADS) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(named() - before, cores.min(THREADS));
        // Every thread takes from the one listener of a port; each connection is taken once.
        let listeners = listen("127.0.0.1:0".parse().unwrap(), threads.len()).unwrap();
        let at = listeners[0].local_addr().unwrap();
        let taken = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let on = |listener: std::net::TcpListener, thread: &tokio::runtime::Handle| {
            let taken = taken.clone();
            thread.spawn(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                while let Ok((stream, _)) = listener.accept().await {
                    taken.fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                }
            })
        };
        let tasks: Vec<_> = listeners
            .into_iter()
            .zip(&threads)
            .map(|(l, thread)| on(l, thread))
            .collect();
        for _ in 0..200 {
            TcpStream::connect(at).await.unwrap();
        }
        let all = async {
            while taken.load(Ordering::Relaxed) < 200 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        assert!(tokio::time::timeout(Duration::from_secs(5), all).await.is_ok());
        assert_eq!(taken.load(Ordering::Relaxed), 200);
        tasks.iter().for_each(tokio::task::JoinHandle::abort);
    }

    /// A Service's port is kithd's alone: another socket asking to share it (as one of the
    /// same user may) is refused, and takes none of its connections before they are admitted.
    #[tokio::test]
    async fn no_other_socket_shares_a_services_port() {
        let ours = listen("127.0.0.1:0".parse().unwrap(), 2).unwrap();
        let at = ours[0].local_addr().unwrap();
        let other = tokio::net::TcpSocket::new_v4().unwrap();
        other.set_reuseport(true).unwrap();
        other.set_reuseaddr(true).unwrap();
        let bound = other.bind(at).and_then(|()| other.listen(1).map(drop));
        assert_eq!(bound.map_err(|e| e.kind()), Err(std::io::ErrorKind::AddrInUse));
    }

    /// Two connected loopback sockets: (the one a client holds, the one the proxy holds).
    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ours = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        (ours, listener.accept().await.unwrap().0)
    }

    /// A replica: it answers what each connection says (all of it, to its end) with `a:`
    /// before it, then hangs up. Where it listens, and how many connections it has had.
    pub(super) async fn replica() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use tokio::io::AsyncReadExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (at, had) = (
            listener.local_addr().unwrap(),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        );
        let count = had.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut said = b"a:".to_vec();
                    if stream.read_to_end(&mut said).await.is_ok() {
                        let _ = stream.write_all(&said).await;
                    }
                });
            }
        });
        (at, had)
    }

    /// Another node's kithd for the tests: what it is asked ([`taken`]) it passes to
    /// `replica`, except for the Workload `shut`. Where it listens, how many connections
    /// it has had, and every replica it was asked for.
    async fn other_node(
        replica: SocketAddr,
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (at, had) = (
            listener.local_addr().unwrap(),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        );
        let asked = Arc::new(Mutex::new(Vec::new()));
        let (count, lines) = (had.clone(), asked.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                let lines = lines.clone();
                tokio::spawn(async move {
                    let (relaying, spares) = (Limits::new(1, 1), Limits::new(1, 1));
                    let local = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
                    admit(
                        &relaying,
                        &spares,
                        local,
                        stream,
                        move |port, workload: String, which| {
                            lines.lock().unwrap().push(format!("{port} {workload} {which:?}"));
                            async move {
                                match workload.as_str() {
                                    "shut" => None,
                                    "slow" => std::future::pending().await,
                                    _ => TcpStream::connect(replica).await.ok(),
                                }
                            }
                        },
                    )
                    .await
                });
            }
        });
        (at, had, asked)
    }

    /// One client's connection through `relay`: it says `says` and no more, and what it hears.
    async fn through(relay: &mut Relay, says: &str) -> (std::io::Result<()>, String) {
        use tokio::io::AsyncReadExt;
        let (mut client, held) = pair().await;
        let asking = async {
            client.write_all(says.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();
            let mut heard = String::new();
            let _ = client.read_to_string(&mut heard).await;
            heard
        };
        tokio::join!(carry(held, relay, Duration::from_secs(60)), asking)
    }

    /// A client's connection to [`Proxy::take`] from loopback, as an IPv4-mapped V6 address:
    /// (the client's end, the one held). Not `[::1]`: where loopback has no IPv6 that bind
    /// fails, and the whole workspace gate with it. The mapped address is still a V6 caller to
    /// `take`, and `Limits` canonicalizes it to the V4 key. (Needs `net.ipv6.bindv6only=0`, the
    /// kernel's default, so `[::]` takes V4 connections.)
    pub(super) async fn pair_from_ipv6() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("[::]:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let ours = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();
        (ours, listener.accept().await.unwrap().0)
    }

    /// Applies the resources of `source` to `shared`'s store.
    pub(super) fn apply(shared: &Shared, source: &str) {
        let mut state = shared.store.lock().unwrap();
        for resource in Resource::from_source(source).unwrap() {
            state.store.apply(resource.unwrap()).unwrap();
        }
    }

    const WEB: &str = "
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: web, labels: { app: web } }
spec:
  template:
    containers: [{ name: main, image: example.org/web, ports: [{ name: http, port: 8080 }] }]
";

    /// A node `a` whose store has the Workload `web` in it, and nothing else.
    pub(super) async fn state_with_web(tag: &str) -> Arc<Shared> {
        let ca = crate::pki::Ca::create().unwrap();
        let shared =
            crate::cluster::pinned_peer::shared_with(tag, crate::cluster::pinned_peer::node(&ca, "a"), &[]).await;
        apply(&shared, WEB);
        shared
    }

    /// A Proxy as [`run`] makes one on `shared`, its table one backend: this node's Workload `of`
    /// on `port`, and `replica` of it where it is a pod's.
    pub(super) fn proxy_of(shared: Arc<Shared>, port: u16, of: &str, replica: Option<u32>) -> Proxy {
        let cluster = shared.cluster.as_ref().expect("a cluster");
        let backend = (shared.members.me().to_string(), port, of.to_string(), replica);
        Proxy {
            prefix: crate::mesh::prefix(&cluster.me.ca),
            table: Mutex::new(BTreeMap::from([((IpAddr::V6(Ipv6Addr::LOCALHOST), 80), vec![backend])])),
            turns: Turns::default(),
            serving: Limits::new(SERVING, SERVING),
            people: None,
            relaying: Limits::new(RELAYING, RELAYING_PER_NODE).per_node(),
            spares: Limits::new(SPARE, SPARE_PER_NODE).per_node(),
            kept: Mutex::default(),
            links: receive::BOUNDS,
            linked: Mutex::default(),
            naps: wake::Naps::default(),
            dial_to: None,
            shared,
        }
    }

    /// An IPv4 source is ours when it is the loopback, a Service address held here or a pod made
    /// here; an address of the pods' or Services' range that is none of those (a source made up on
    /// another link) is refused.
    #[tokio::test]
    async fn an_ipv4_source_in_the_ranges_is_ours_only_when_held_or_a_pod() {
        let proxy = proxy_of(state_with_web("is-ours-v4").await, 8080, "Workload/default/web", None);
        let held = Ipv4Addr::new(100, 87, 0, 5);
        let backend = proxy.table.lock().unwrap().values().next().unwrap().clone();
        proxy.table.lock().unwrap().insert((IpAddr::V4(held), 80), backend);
        let ip = |ip: Ipv4Addr| IpAddr::V4(ip);
        assert!(proxy.is_ours(ip(Ipv4Addr::LOCALHOST)));
        assert!(proxy.is_ours(ip(held)));
        assert!(
            !proxy.is_ours(ip(Ipv4Addr::new(100, 87, 0, 6))),
            "a Service address nobody holds"
        );
        assert!(
            !proxy.is_ours(ip(crate::pods::range().address(9))),
            "a pod address no pod has"
        );
        assert!(!proxy.is_ours(ip(Ipv4Addr::new(192, 0, 2, 1))));
    }

    /// Says `says` to `proxy`'s take over loopback: what take passed on, and what the client heard.
    async fn take_says(proxy: &Proxy, says: &str) -> (Option<()>, Vec<u8>) {
        let (mut client, held) = pair_from_ipv6().await;
        let asking = async {
            client.write_all(says.as_bytes()).await.unwrap();
            // Said all: a replica it reaches answers once the client's side ends.
            client.shutdown().await.unwrap();
            let mut heard = Vec::new();
            client.read_to_end(&mut heard).await.unwrap();
            heard
        };
        // A take that never closes must fail the test, not hang it.
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(proxy.take(held), asking)
        })
        .await
        .expect("take ends")
    }

    /// What the table asks for over loopback (this node's `web` on `port`, no replica) reaches the
    /// replica, which answers `a:`; the place it holds is held while the connection lasts and
    /// given back when it ends.
    #[tokio::test]
    async fn take_passes_on_what_the_table_asks_for_to_the_replica() {
        let (replica, replicas) = replica().await;
        let port = replica.port();
        let mut proxy = proxy_of(state_with_web("take-asked").await, port, "Workload/default/web", None);
        // One place, so that a second one can be seen to be held.
        proxy.relaying = Limits::new(1, 1).per_node();
        let caller = IpAddr::V6(std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        let (mut client, held) = pair_from_ipv6().await;
        let asking = async {
            client
                .write_all(format!("{port} Workload/default/web\n").as_bytes())
                .await
                .unwrap();
            assert_eq!(client.read_u8().await.unwrap(), b'+');
            assert!(proxy.relaying.take(caller).is_none(), "held while the connection lasts");
            client.write_all(b"q").await.unwrap();
            client.shutdown().await.unwrap();
            let mut heard = String::new();
            client.read_to_string(&mut heard).await.unwrap();
            heard
        };
        let (passed, heard) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(proxy.take(held), asking)
        })
        .await
        .expect("take ends");
        assert_eq!((passed, heard.as_str()), (Some(()), "a:q"));
        assert!(proxy.relaying.take(caller).is_some(), "given back when it ends");
        assert_eq!(replicas.load(Ordering::Relaxed), 1);
    }

    /// What the table does not ask for is closed with no byte, and no replica is connected: the
    /// same Workload on the same port, but a replica the table has none of.
    #[tokio::test]
    async fn take_closes_what_the_table_does_not_ask_for_with_no_byte() {
        let (replica, replicas) = replica().await;
        let port = replica.port();
        let proxy = proxy_of(state_with_web("take-unasked").await, port, "Workload/default/web", None);
        let said = take_says(&proxy, &format!("{port} Workload/default/web 0\n")).await;
        assert_eq!(said, (None, Vec::new()));
        assert_eq!(replicas.load(Ordering::Relaxed), 0);
    }

    /// A NetworkPolicy that does not let loopback in closes what the table asks for the same way:
    /// no byte, and no replica is connected. The same policy naming the caller's own address
    /// lets it through, so it is the cidr that refuses, not a policy that never matches.
    #[tokio::test]
    async fn take_closes_what_a_network_policy_refuses_with_no_byte() {
        let policy = |cidr: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: NetworkPolicy\nmetadata: {{ name: web }}\n\
                 spec:\n  selector: {{ app: web }}\n  ingress: [{{ action: allow, peers: [{{ cidr: '{cidr}' }}] }}]\n"
            )
        };
        for (cidr, passes) in [("fd00::/64", false), ("::ffff:127.0.0.1/128", true)] {
            let (replica, replicas) = replica().await;
            let port = replica.port();
            let shared = state_with_web(if passes { "take-let-in" } else { "take-refused" }).await;
            apply(&shared, &policy(cidr));
            let proxy = proxy_of(shared, port, "Workload/default/web", None);
            let (passed, heard) = take_says(&proxy, &format!("{port} Workload/default/web\n")).await;
            assert_eq!(passed.is_some(), passes, "{cidr}");
            assert_eq!(heard.is_empty(), !passes, "{cidr}: no byte when refused");
            assert_eq!(replicas.load(Ordering::Relaxed), usize::from(passes), "{cidr}");
        }
    }

    /// One connection between two nodes passes on one client's connection after another,
    /// each to a replica that was asked for (and so admitted) by itself; what is not
    /// passed on is said, and costs no connection.
    #[tokio::test]
    async fn a_connection_between_nodes_is_used_again_and_each_client_is_asked_for() {
        let (replica, replicas) = replica().await;
        let (node, connections, asked) = other_node(replica).await;
        let mut relay = Relay::new(TcpStream::connect(node).await.unwrap());
        for turn in 0..3 {
            assert!(ask(&mut relay, "kept 8080 web 1\n", b"").await.unwrap());
            let (carried, heard) = through(&mut relay, &format!("q{turn}")).await;
            carried.unwrap();
            assert_eq!(heard, format!("a:q{turn}"));
        }
        // What a client said before the answer goes with the asking: to the replica if
        // there is one for it, and to nobody (not the next client's replica) if not.
        assert!(!ask(&mut relay, "kept 8080 shut\n", b"for nobody").await.unwrap());
        assert!(ask(&mut relay, "kept 8081 web\n", b"first, ").await.unwrap());
        assert_eq!(through(&mut relay, "more").await.1, "a:first, more");
        assert_eq!(
            (connections.load(Ordering::Relaxed), replicas.load(Ordering::Relaxed)),
            (1, 4)
        );
        let asked = asked.lock().unwrap().join(", ");
        assert_eq!(
            asked,
            "8080 web Some(1), 8080 web Some(1), 8080 web Some(1), 8080 shut None, 8081 web None"
        );
    }

    /// A node of before asks as it always did, a connection for each client's: it is answered so.
    #[tokio::test]
    async fn a_node_of_before_is_still_passed_on_for() {
        use tokio::io::AsyncReadExt;
        let (node, _, asked) = other_node(replica().await.0).await;
        let mut relay = TcpStream::connect(node).await.unwrap();
        relay.write_all(b"8080 web 2\n").await.unwrap();
        assert_eq!(relay.read_u8().await.unwrap(), b'+');
        relay.write_all(b"q").await.unwrap();
        relay.shutdown().await.unwrap();
        let mut heard = String::new();
        relay.read_to_string(&mut heard).await.unwrap();
        assert_eq!(heard, "a:q");
        assert_eq!(asked.lock().unwrap().join(", "), "8080 web Some(2)");
        // And what it may not have is hung up on, with no word.
        let mut relay = TcpStream::connect(node).await.unwrap();
        relay.write_all(b"8080 shut\n").await.unwrap();
        assert_eq!(relay.read_to_string(&mut heard).await.unwrap(), 0);
    }

    /// A node over its relaying limit says no to what a kept connection asks, with what the
    /// client said in it: the connection between the two is used again, the next asking on
    /// it is read past and said no to too, and no replica is asked for. A node of before
    /// has no no: it is hung up on, as it was.
    #[tokio::test]
    async fn over_its_limit_says_no() {
        use tokio::io::AsyncReadExt;
        let (replica, replicas) = replica().await;
        let local = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let full = Limits::new(1, 1);
        let _held = full.take(local).unwrap();
        assert!(full.take(local).is_none());
        let spares = Limits::new(2, 2);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let lines = asked.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let lines = lines.clone();
                let (relaying, spare) = (full.clone(), spares.clone());
                tokio::spawn(async move {
                    admit(
                        &relaying,
                        &spare,
                        local,
                        stream,
                        move |port, workload: String, which| {
                            lines.lock().unwrap().push(format!("{port} {workload} {which:?}"));
                            async move { TcpStream::connect(replica).await.ok() }
                        },
                    )
                    .await
                });
            }
        });
        let mut relay = Relay::new(TcpStream::connect(at).await.unwrap());
        assert!(!ask(&mut relay, "kept 8080 web 1\n", b"said").await.unwrap());
        assert!(!ask(&mut relay, "kept 8080 web 1\n", b"").await.unwrap());
        assert!(!ask(&mut relay, "kept 8081 web 1\n", b"more").await.unwrap());
        assert!(asked.lock().unwrap().is_empty());
        assert_eq!(replicas.load(Ordering::Relaxed), 0);
        // A node of before asks with no kept word, and is hung up on with no answer.
        let mut old = TcpStream::connect(at).await.unwrap();
        old.write_all(b"8080 web 2\n").await.unwrap();
        let mut heard = Vec::new();
        assert_eq!(old.read_to_end(&mut heard).await.unwrap(), 0);
    }

    /// Past the spares, for the node or in all, a connection is dropped at once: nothing is
    /// read from it or waited for, so a silent one is ended before the time to wait for a line.
    #[tokio::test]
    async fn over_its_limit_and_past_the_spare_is_hung_up_on() {
        use tokio::io::AsyncReadExt;
        let (replica, replicas) = replica().await;
        let local = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        // One spare held: with one in all, and with room in all but none for this node.
        for (total, per_node) in [(1, 1), (4, 1)] {
            let full = Limits::new(1, 1);
            let _held = full.take(local).unwrap();
            let spares = Limits::new(total, per_node);
            let _spare = spares.take(local).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = listener.local_addr().unwrap();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let (relaying, spare) = (full.clone(), spares.clone());
                    tokio::spawn(async move {
                        admit(&relaying, &spare, local, stream, move |_, _: String, _| async move {
                            TcpStream::connect(replica).await.ok()
                        })
                        .await
                    });
                }
            });
            let mut relay = TcpStream::connect(at).await.unwrap();
            let mut heard = Vec::new();
            let ended = tokio::time::timeout(std::time::Duration::from_secs(1), relay.read_to_end(&mut heard)).await;
            assert_eq!(ended.expect("hung up on at once").unwrap(), 0);
        }
        assert_eq!(replicas.load(Ordering::Relaxed), 0);
    }

    /// A kept connection admitted with no room is said no to; once the node has room again, the
    /// next asking on that same connection gets a place and reaches the replica.
    #[tokio::test]
    async fn over_its_limit_has_room_again() {
        let (replica, replicas) = replica().await;
        let local = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let full = Limits::new(1, 1);
        let held = full.take(local).unwrap();
        let spares = Limits::new(2, 2);
        let spare = spares.clone();
        let finds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = finds.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (relaying, spare, counted) = (full.clone(), spares.clone(), counted.clone());
                tokio::spawn(async move {
                    admit(&relaying, &spare, local, stream, move |_, _: String, _| {
                        counted.fetch_add(1, Ordering::Relaxed);
                        async move { TcpStream::connect(replica).await.ok() }
                    })
                    .await
                });
            }
        });
        let mut relay = Relay::new(TcpStream::connect(at).await.unwrap());
        assert!(!ask(&mut relay, "kept 8080 web 1\n", b"said").await.unwrap());
        drop(held);
        assert!(ask(&mut relay, "kept 8080 web 1\n", b"more").await.unwrap());
        // (The spare it said no from is given back once it has a place.)
        let both = (spare.take(local), spare.take(local));
        assert!(both.0.is_some() && both.1.is_some(), "the spare was kept");
        assert_eq!(finds.load(Ordering::Relaxed), 1);
        assert_eq!(replicas.load(Ordering::Relaxed), 1);
    }

    /// A frame longer than a chunk, sent where a refused asking's early bytes go, hangs the
    /// connection up at once: it is not waited for.
    #[tokio::test]
    async fn a_frame_too_long_after_a_refused_asking_is_hung_up_on() {
        use tokio::io::AsyncReadExt;
        let local = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let full = Limits::new(1, 1);
        let _held = full.take(local).unwrap();
        let spares = Limits::new(2, 2);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (relaying, spare) = (full.clone(), spares.clone());
                tokio::spawn(
                    async move { admit(&relaying, &spare, local, stream, |_, _: String, _| async { None }).await },
                );
            }
        });
        let mut relay = TcpStream::connect(at).await.unwrap();
        relay.write_all(b"kept 8080 web 1\n").await.unwrap();
        assert_eq!(relay.read_u8().await.unwrap(), b'-');
        relay.write_all(&u16::MAX.to_be_bytes()).await.unwrap();
        let mut heard = Vec::new();
        let ended = tokio::time::timeout(std::time::Duration::from_secs(1), relay.read_to_end(&mut heard)).await;
        assert_eq!(ended.expect("hung up on at once").unwrap(), 0);
    }

    /// A client's connection that ends as none does (here: silent for the idle time) takes
    /// the connection between the nodes with it: nothing else is passed on that one, and
    /// the replica sees its end.
    #[tokio::test]
    async fn a_connection_between_nodes_that_was_cut_is_not_used_again() {
        use tokio::io::AsyncReadExt;
        let (node, _, _) = other_node(replica().await.0).await;
        let mut relay = Relay::new(TcpStream::connect(node).await.unwrap());
        assert!(ask(&mut relay, "kept 8080 web\n", b"").await.unwrap());
        let (mut client, held) = pair().await;
        client.write_all(b"half a question").await.unwrap();
        let cut = carry(held, &mut relay, Duration::from_secs(1)).await;
        assert_eq!(cut.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert!(client.read_u8().await.is_err());
        // (The replica answers what it heard, once its connection ends: to nobody.)
        drop(relay);
        // A frame longer than any that is sent is no frame: the other node hangs up.
        let mut relay = Relay::new(TcpStream::connect(node).await.unwrap());
        assert!(ask(&mut relay, "kept 8080 web\n", b"").await.unwrap());
        relay.to.write_all(&[0xff, 0xff]).await.unwrap();
        assert!(relay.from.read_u8().await.is_err());
    }

    /// A node that takes an asking and what the client said with it, and hangs up with no
    /// answer (it was stopped, perhaps after it passed the bytes on): the client is asked
    /// for nowhere else, whether the connection was kept or new, so that what it said
    /// reaches no second replica. One that had said nothing is tried elsewhere, or asked
    /// again where the connection was only kept too long.
    #[tokio::test]
    async fn what_a_client_said_goes_to_no_second_replica_when_a_node_hangs_up() {
        use tokio::io::AsyncReadExt;
        let stopped = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = stopped.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut asker, _) = stopped.accept().await.unwrap();
                let _ = asker.read(&mut [0; 64]).await;
            }
        });
        let said = |spoke: bool, was_kept| async move {
            let mut relay = Relay::new(TcpStream::connect(at).await.unwrap());
            let early: &[u8] = if spoke { b"POST /pay" } else { b"" };
            let hung_up = ask(&mut relay, "kept 8080 web\n", early).await.unwrap_err();
            assert_ne!(hung_up.kind(), std::io::ErrorKind::TimedOut);
            unanswered(hung_up, was_kept, spoke)
        };
        assert!(matches!(said(true, false).await, Unanswered::Lost));
        assert!(matches!(said(true, true).await, Unanswered::Lost));
        assert!(matches!(said(false, false).await, Unanswered::Next(_)));
        assert!(matches!(said(false, true).await, Unanswered::Again));
        // No answer in the time: lost with something said, the next backend without.
        let late = || std::io::Error::from(std::io::ErrorKind::TimedOut);
        assert!(matches!(unanswered(late(), true, true), Unanswered::Lost));
        assert!(matches!(unanswered(late(), true, false), Unanswered::Next(_)));
    }

    /// A replica that does not take its node's connection is said no to before the asking
    /// node gives up waiting: that one tries the next replica, and the connection between
    /// the two is as good as before. A node that says nothing at all is waited for
    /// [`CONNECT`], and that reads as time gone by, which [`Proxy::reach`] tells from a
    /// connection that was hung up on.
    #[tokio::test]
    async fn a_replica_that_does_not_answer_is_said_no_to_in_time() {
        let (node, connections, _) = other_node(replica().await.0).await;
        let mut relay = Relay::new(TcpStream::connect(node).await.unwrap());
        let begun = std::time::Instant::now();
        assert!(!ask(&mut relay, "kept 8080 slow\n", b"said").await.unwrap());
        assert!(begun.elapsed() >= FOUND);
        assert!(ask(&mut relay, "kept 8080 web\n", b"").await.unwrap());
        assert_eq!(through(&mut relay, "q").await.1, "a:q");
        assert_eq!(connections.load(Ordering::Relaxed), 1);

        let mute = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut relay = Relay::new(TcpStream::connect(mute.local_addr().unwrap()).await.unwrap());
        let none = ask(&mut relay, "kept 8080 web\n", b"said").await;
        assert_eq!(none.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }

    /// What ends a passed-on connection is silence, not time: one way alone, bytes now and
    /// then keep it for longer than the idle time; and with one side's end said, silence
    /// still ends it.
    #[tokio::test]
    async fn bytes_one_way_keep_a_passed_on_connection_and_silence_after_an_end_ends_it() {
        use tokio::io::AsyncReadExt;
        let dripping = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = dripping.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = dripping.accept().await {
                tokio::spawn(async move {
                    // Twelve bytes a quarter second apart (three seconds), then (its client's end
                    // heard) its own.
                    for _ in 0..12 {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        stream.write_all(b".").await.unwrap();
                    }
                    let _ = stream.read_to_end(&mut Vec::new()).await;
                });
            }
        });
        let (node, _, _) = other_node(at).await;
        let mut relay = Relay::new(TcpStream::connect(node).await.unwrap());
        assert!(ask(&mut relay, "kept 8080 web\n", b"").await.unwrap());
        let (mut client, held) = pair().await;
        let hearing = async {
            let mut heard = [0; 12];
            client.read_exact(&mut heard).await.unwrap();
            client.shutdown().await.unwrap();
            client.read_to_end(&mut Vec::new()).await.unwrap()
        };
        let begun = std::time::Instant::now();
        let (carried, more) = tokio::join!(carry(held, &mut relay, Duration::from_secs(2)), hearing);
        carried.unwrap();
        assert!(more == 0 && begun.elapsed() >= Duration::from_secs(2));

        // The client's end said and passed on, and then nothing from the replica.
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (node, _, _) = other_node(silent.local_addr().unwrap()).await;
        let mut relay = Relay::new(TcpStream::connect(node).await.unwrap());
        assert!(ask(&mut relay, "kept 8080 web\n", b"").await.unwrap());
        let (mut client, held) = pair().await;
        client.shutdown().await.unwrap();
        let begun = std::time::Instant::now();
        let cut = carry(held, &mut relay, Duration::from_secs(2)).await;
        assert_eq!(cut.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert!(begun.elapsed() >= Duration::from_secs(2) && begun.elapsed() < Duration::from_secs(10));
    }

    /// A replica that speaks first and ends first: its bytes and its end reach the client,
    /// and when the client ends too the connection between the nodes is as good as new.
    #[tokio::test]
    async fn a_replica_that_ends_first_leaves_the_connection_between_nodes_whole() {
        use tokio::io::AsyncReadExt;
        let greeter = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = greeter.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = greeter.accept().await {
                let _ = stream.write_all(b"hello").await;
            }
        });
        let (node, connections, _) = other_node(at).await;
        let mut relay = Relay::new(TcpStream::connect(node).await.unwrap());
        for _ in 0..2 {
            assert!(ask(&mut relay, "kept 25 mail\n", b"").await.unwrap());
            let (mut client, held) = pair().await;
            let hearing = async {
                let mut heard = String::new();
                client.read_to_string(&mut heard).await.unwrap();
                drop(client);
                heard
            };
            let (carried, heard) = tokio::join!(carry(held, &mut relay, Duration::from_secs(60)), hearing);
            carried.unwrap();
            assert_eq!(heard, "hello");
        }
        assert_eq!(connections.load(Ordering::Relaxed), 1);
    }

    /// Not a check: how many small questions and answers a second twenty kept connections
    /// get through two kithds, as a node of before passes them on and in frames.
    #[tokio::test]
    #[ignore = "a measurement, for whoever changes carry"]
    async fn how_fast_bytes_pass_between_nodes() {
        use tokio::io::AsyncReadExt;
        const TURNS: usize = 20_000;
        let answering = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = answering.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut replica, _)) = answering.accept().await {
                tokio::spawn(async move {
                    let mut asked = [0; 80];
                    while replica.read_exact(&mut asked).await.is_ok() && replica.write_all(&[7; 200]).await.is_ok() {}
                });
            }
        });
        let (node, _, _) = other_node(at).await;
        for kept in [false, true] {
            let begun = std::time::Instant::now();
            let clients = (0..20).map(|_| async move {
                let (mut client, held) = pair().await;
                let asking = async {
                    let mut answer = [0; 200];
                    for _ in 0..TURNS {
                        client.write_all(&[1; 80]).await.unwrap();
                        client.read_exact(&mut answer).await.unwrap();
                    }
                    drop(client);
                };
                let passing = async {
                    if kept {
                        let mut there = Relay::new(TcpStream::connect(node).await.unwrap());
                        assert!(ask(&mut there, "kept 8080 web\n", b"").await.unwrap());
                        return carry(held, &mut there, Duration::from_secs(60)).await;
                    }
                    let mut there = TcpStream::connect(node).await.unwrap();
                    there.write_all(b"8080 web\n").await.unwrap();
                    there.read_u8().await.unwrap();
                    pass(held, there, Duration::from_secs(60)).await.map(drop)
                };
                tokio::join!(passing, asking).0.unwrap();
            });
            futures_util::future::join_all(clients).await;
            let each = (20 * TURNS) as f64 / begun.elapsed().as_secs_f64();
            eprintln!("in frames {kept}: {each:.0} questions answered a second");
        }
    }

    /// Not a check: how many clients a second, each with a connection of its own, one
    /// question and one answer, get through two kithds: with a connection between the
    /// two for each as a node of before has it, and with ones that are kept (`cargo test
    /// --release -p kithd --bin kithd how_fast -- --ignored --nocapture`).
    #[tokio::test]
    #[ignore = "a measurement, for whoever changes carry or taken"]
    async fn how_fast_clients_pass_between_nodes() {
        use tokio::io::AsyncReadExt;
        const TURNS: usize = 2_000;
        let (node, _, _) = other_node(replica().await.0).await;
        for kept in [false, true] {
            let begun = std::time::Instant::now();
            let clients = (0..20).map(|_| async move {
                let mut relay = None;
                for _ in 0..TURNS {
                    let (mut client, held) = pair().await;
                    let asking = async {
                        client.write_all(&[1; 80]).await.unwrap();
                        client.shutdown().await.unwrap();
                        client.read_to_end(&mut Vec::new()).await.unwrap()
                    };
                    let passing = async {
                        if !kept {
                            let mut there = TcpStream::connect(node).await.unwrap();
                            there.write_all(b"8080 web\n").await.unwrap();
                            there.read_u8().await.unwrap();
                            return pass(held, there, Duration::from_secs(60)).await.map(drop);
                        }
                        let mut there = match relay.take() {
                            Some(there) => there,
                            None => Relay::new(TcpStream::connect(node).await.unwrap()),
                        };
                        assert!(ask(&mut there, "kept 8080 web\n", b"").await.unwrap());
                        carry(held, &mut there, Duration::from_secs(60)).await?;
                        relay = Some(there);
                        Ok(())
                    };
                    let (passed, heard) = tokio::join!(passing, asking);
                    passed.unwrap();
                    assert_eq!(heard, 82);
                }
            });
            futures_util::future::join_all(clients).await;
            let each = (20 * TURNS) as f64 / begun.elapsed().as_secs_f64();
            eprintln!("kept {kept}: {each:.0} clients a second");
        }
    }

    /// Not a check: how many small questions and answers a second twenty connections get
    /// through [`pass`] here, to try a change to it (`cargo test --release -p kithd --bin
    /// kithd how_fast -- --ignored --nocapture`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "a measurement, for whoever changes pass"]
    async fn how_fast_bytes_pass() {
        use tokio::io::AsyncReadExt;
        const TURNS: usize = 20_000;
        let mut clients = Vec::new();
        for _ in 0..20 {
            let ((mut client, held), (backend, mut replica)) = (pair().await, pair().await);
            tokio::spawn(pass(held, backend, Duration::from_secs(60)));
            tokio::spawn(async move {
                let mut asked = [0; 80];
                while replica.read_exact(&mut asked).await.is_ok() && replica.write_all(&[7; 200]).await.is_ok() {}
            });
            clients.push(tokio::spawn(async move {
                let mut answer = [0; 200];
                for _ in 0..TURNS {
                    client.write_all(&[1; 80]).await.unwrap();
                    client.read_exact(&mut answer).await.unwrap();
                }
            }));
        }
        let begun = std::time::Instant::now();
        for client in clients {
            client.await.unwrap();
        }
        let each = (20 * TURNS) as f64 / begun.elapsed().as_secs_f64();
        eprintln!("pass: {each:.0} questions answered a second");
    }

    /// What [`pass`] did on this thread: (splices that moved bytes, pipes still open).
    fn spliced() -> (u64, i64) {
        (SPLICES.get(), PIPES.get())
    }

    #[tokio::test]
    async fn splice_moves_bytes_both_ways_and_ends_each_way_on_eof() {
        use tokio::io::AsyncReadExt;
        let ((mut client, held), (backend, mut replica)) = (pair().await, pair().await);
        let passing = tokio::spawn(pass(held, backend, Duration::from_secs(60)));
        client.write_all(b"question").await.unwrap();
        let mut got = [0; 8];
        replica.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"question");
        replica.write_all(b"answer").await.unwrap();
        let mut got = [0; 6];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"answer");
        // The client ends its way: the replica sees the end, and can still be heard.
        client.shutdown().await.unwrap();
        assert_eq!(replica.read(&mut got).await.unwrap(), 0);
        replica.write_all(b"late").await.unwrap();
        replica.shutdown().await.unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"late");
        assert_eq!(passing.await.unwrap().unwrap(), (8, 10));
        // (The thread of this test did the splicing, none of it on the copy.)
        assert!(spliced().0 >= 3);
    }

    /// A transfer far past a pipe's size, the replica slow to take it: all of it arrives, in order.
    #[tokio::test]
    async fn splice_moves_a_large_transfer_whole_against_a_slow_reader() {
        use tokio::io::AsyncReadExt;
        const SIZE: usize = 8 << 20;
        let ((mut client, held), (backend, mut replica)) = (pair().await, pair().await);
        let passing = tokio::spawn(pass(held, backend, Duration::from_secs(60)));
        let sending = tokio::spawn(async move {
            let block: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
            for _ in 0..SIZE / block.len() {
                client.write_all(&block).await.unwrap();
            }
            client
        });
        let mut got = vec![0; SIZE];
        for part in got.chunks_mut(1 << 20) {
            tokio::time::sleep(Duration::from_millis(5)).await;
            replica.read_exact(part).await.unwrap();
        }
        assert!(
            got.chunks(65536)
                .all(|c| c.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8))
        );
        drop((sending.await.unwrap(), replica));
        assert_eq!(passing.await.unwrap().unwrap().0, SIZE as u64);
    }

    #[tokio::test]
    async fn splice_leaks_no_pipe_when_a_connection_ends_either_way() {
        use tokio::io::AsyncReadExt;
        let before = spliced().1;
        for round in 0..20 {
            let ((mut client, held), (backend, mut replica)) = (pair().await, pair().await);
            let passing = tokio::spawn(pass(held, backend, Duration::from_secs(60)));
            client.write_all(b"x").await.unwrap();
            assert_eq!(replica.read_u8().await.unwrap(), b'x');
            // Some end by the client going, some by the replica, some in a reset.
            // (A way that ends leaves the other to end by itself: both go, one first.)
            match round % 3 {
                0 => drop((client, replica)),
                1 => drop((replica, client)),
                _ => {
                    client.set_zero_linger().unwrap();
                    drop(client);
                }
            }
            let _ = tokio::time::timeout(Duration::from_secs(10), passing).await.unwrap();
        }
        assert_eq!(spliced().1, before);
        assert!(before >= 0 && SPLICES.get() > 0);
    }

    #[tokio::test]
    async fn splice_keeps_the_idle_cut() {
        use tokio::io::AsyncReadExt;
        let ((mut client, held), (backend, mut replica)) = (pair().await, pair().await);
        let passing = tokio::spawn(pass(held, backend, Duration::from_secs(2)));
        // Bytes one way only keep it going past the idle time, too...
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(700)).await;
            client.write_all(b"q").await.unwrap();
            assert_eq!(replica.read_u8().await.unwrap(), b'q');
            assert!(!passing.is_finished());
        }
        // ...and then silence ends it, and both ends see the hang-up.
        let ended = tokio::time::timeout(Duration::from_secs(10), passing).await;
        assert_eq!(
            ended.unwrap().unwrap().unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert!(client.read_u8().await.is_err());
        assert!(replica.read_u8().await.is_err());
        assert!(spliced().0 > 0);
    }

    /// A kernel (or a filter) that refuses splice: the bytes go on by the copy, both ways.
    #[tokio::test]
    async fn splice_refused_falls_back_to_the_copy() {
        use tokio::io::AsyncReadExt;
        REFUSE.set(true);
        let before = spliced().0;
        let ((mut client, held), (backend, mut replica)) = (pair().await, pair().await);
        let passing = tokio::spawn(pass(held, backend, Duration::from_secs(60)));
        client.write_all(b"question").await.unwrap();
        let mut got = [0; 8];
        replica.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"question");
        replica.write_all(b"answer").await.unwrap();
        let mut got = [0; 6];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"answer");
        drop(client);
        assert_eq!(replica.read(&mut got).await.unwrap(), 0);
        drop(replica);
        assert_eq!(passing.await.unwrap().unwrap(), (8, 6));
        assert_eq!(spliced().0, before);
        REFUSE.set(false);
    }

    /// No pipe to be had (out of files, or past the cap): the connection is not refused, the
    /// bytes go by the copy.
    #[tokio::test]
    async fn splice_without_a_pipe_falls_back_to_the_copy() {
        use tokio::io::AsyncReadExt;
        NO_PIPE.set(true);
        let before = spliced().0;
        let ((mut client, held), (backend, mut replica)) = (pair().await, pair().await);
        let passing = tokio::spawn(pass(held, backend, Duration::from_secs(60)));
        client.write_all(b"question").await.unwrap();
        let mut got = [0; 8];
        replica.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"question");
        replica.write_all(b"answer").await.unwrap();
        let mut got = [0; 6];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"answer");
        drop((client, replica));
        assert_eq!(passing.await.unwrap().unwrap(), (8, 6));
        assert_eq!((spliced().0, spliced().1), (before, 0));
        NO_PIPE.set(false);
    }

    /// The count of pipes holds at its cap, and a place freed can be taken again.
    #[test]
    fn pipes_stop_at_the_cap() {
        let open = std::sync::atomic::AtomicUsize::new(0);
        assert!(take_place(&open, 2) && take_place(&open, 2));
        assert!(!take_place(&open, 2));
        open.fetch_sub(1, Ordering::AcqRel);
        assert!(take_place(&open, 2));
        assert_eq!(open.load(Ordering::Acquire), 2);
    }

    /// Not a check: the same proxy path by splice and by the copy, on loopback, for what the
    /// kept-connection rows (small questions and answers) and a bulk transfer ask of it
    /// (`cargo test --release -p kithd --bin kithd splice_not_slower_than_copy -- --ignored
    /// --nocapture`). Splice may not be slower than 0.9 of the copy on either.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "a measurement, for whoever changes pass"]
    async fn splice_not_slower_than_copy() {
        use tokio::io::AsyncReadExt;
        async fn copy(client: TcpStream, backend: TcpStream, idle: Duration) -> std::io::Result<(u64, u64)> {
            let (mut client, mut backend) = (Idle::new(client, idle, None), Idle::new(backend, idle, None));
            tokio::io::copy_bidirectional(&mut client, &mut backend).await
        }
        type Way = fn(
            TcpStream,
            TcpStream,
            Duration,
        ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<(u64, u64)>> + Send>>;
        // Small: 20 kept connections of 1000 question and answer pairs each, 20000 in all.
        async fn small(way: Way) -> f64 {
            let mut clients = Vec::new();
            for _ in 0..20 {
                let ((mut client, held), (backend, mut replica)) = (pair().await, pair().await);
                tokio::spawn(way(held, backend, Duration::from_secs(60)));
                tokio::spawn(async move {
                    let mut asked = [0; 80];
                    while replica.read_exact(&mut asked).await.is_ok() && replica.write_all(&[7; 200]).await.is_ok() {}
                });
                clients.push(tokio::spawn(async move {
                    let mut answer = [0; 200];
                    for _ in 0..1000 {
                        client.write_all(&[1; 80]).await.unwrap();
                        client.read_exact(&mut answer).await.unwrap();
                    }
                }));
            }
            let begun = std::time::Instant::now();
            for client in clients {
                client.await.unwrap();
            }
            20_000.0 / begun.elapsed().as_secs_f64()
        }
        // Bulk: 1 GiB over 4 connections, in MiB a second.
        async fn bulk(way: Way) -> f64 {
            let mut clients = Vec::new();
            for _ in 0..4 {
                let ((mut client, held), (backend, mut replica)) = (pair().await, pair().await);
                tokio::spawn(way(held, backend, Duration::from_secs(60)));
                tokio::spawn(async move {
                    let mut sink = vec![0; 1 << 20];
                    while replica.read(&mut sink).await.is_ok_and(|n| n > 0) {}
                });
                clients.push(tokio::spawn(async move {
                    let block = vec![5u8; 1 << 20];
                    for _ in 0..256 {
                        client.write_all(&block).await.unwrap();
                    }
                    client.shutdown().await.unwrap();
                    let mut end = [0; 1];
                    let _ = client.read(&mut end).await;
                }));
            }
            let begun = std::time::Instant::now();
            for client in clients {
                client.await.unwrap();
            }
            1024.0 / begun.elapsed().as_secs_f64()
        }
        let (spliced, copied): (Way, Way) = (|a, b, i| Box::pin(pass(a, b, i)), |a, b, i| Box::pin(copy(a, b, i)));
        // (Each way twice, alternating, the better of the two: a loaded host swings.)
        let (mut small_rates, mut bulk_rates) = ([0f64; 2], [0f64; 2]);
        for _ in 0..2 {
            for (i, way) in [spliced, copied].into_iter().enumerate() {
                small_rates[i] = small_rates[i].max(small(way).await);
                bulk_rates[i] = bulk_rates[i].max(bulk(way).await);
            }
        }
        eprintln!(
            "small: splice {:.0}/s, copy {:.0}/s ({:.2})",
            small_rates[0],
            small_rates[1],
            small_rates[0] / small_rates[1]
        );
        eprintln!(
            "bulk: splice {:.0} MiB/s, copy {:.0} MiB/s ({:.2})",
            bulk_rates[0],
            bulk_rates[1],
            bulk_rates[0] / bulk_rates[1]
        );
        assert!(
            small_rates[0] >= 0.9 * small_rates[1],
            "small requests slower by splice"
        );
        assert!(bulk_rates[0] >= 0.9 * bulk_rates[1], "bulk slower by splice");
    }

    #[tokio::test]
    async fn an_idle_connection_between_a_client_and_a_service_ends() {
        use tokio::io::AsyncReadExt;
        let ((mut client, held), (backend, mut replica)) = (pair().await, pair().await);
        let passing = tokio::spawn(pass(held, backend, Duration::from_secs(2)));
        // Bytes both ways keep it going past the idle time...
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            client.write_all(b"q").await.unwrap();
            assert_eq!(replica.read_u8().await.unwrap(), b'q');
            replica.write_all(b"a").await.unwrap();
            assert_eq!(client.read_u8().await.unwrap(), b'a');
            assert!(!passing.is_finished());
        }
        // ...and then silence ends it, and both ends see the hang-up.
        let ended = tokio::time::timeout(Duration::from_secs(10), passing).await;
        assert_eq!(
            ended.unwrap().unwrap().unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert!(client.read_u8().await.is_err());
        assert!(replica.read_u8().await.is_err());
    }

    #[test]
    fn the_kernel_passes_what_no_policy_guards_and_sends_the_rest_on() {
        let mut store = Store::default();
        let apply = |store: &mut Store, source: &str| {
            for resource in Resource::from_source(source).unwrap() {
                store.apply(resource.unwrap()).unwrap();
            }
        };
        apply(&mut store, HOME);
        let unit =
            |replica: u32, node: &str| json!({ "name": "main", "replica": replica, "node": node, "ready": true });
        let web = json!({ "containers": [unit(0, "a"), unit(1, "b")] });
        store.set_status("Workload/default/web", Some(web)).unwrap();
        let prefix = kith_mesh::prefix(b"test");
        let address = kith_mesh::service_address(prefix, "default", "web");
        let address = IpAddr::from(address);
        let mut table = table(&store, prefix, None);
        // (A Service port as high as they go: the one to kithd is another.)
        table.insert((address, 65535), vec![]);
        let at = |node: &str, port| (node.to_string(), port, "Workload/default/web".to_string(), None);
        // Of two replicas, the one here is the kernel's to pass on; the other's share goes to
        // a port of kithd's own on the same address, with only the other node's behind it.
        let plan = |port, target, elsewhere| Plan {
            service: (address, port),
            here: vec![at("a", target)],
            others: vec![at("b", target)],
            elsewhere,
        };
        let planned = kernel_plan(&store, &table, "a");
        assert_eq!(planned, [plan(80, 8080, Some(65534)), plan(9000, 9000, Some(65533))]);
        // On a node with no replica of it there is nothing to pass on; with all of them
        // here, nothing goes to kithd.
        assert_eq!(kernel_plan(&store, &table, "c"), []);
        let here = json!({ "containers": [unit(0, "a"), unit(1, "a")] });
        store.set_status("Workload/default/web", Some(here)).unwrap();
        let all_here = kernel_plan(&store, &super::table(&store, prefix, None), "a");
        assert!(
            all_here
                .iter()
                .all(|plan| plan.others.is_empty() && plan.elsewhere.is_none() && plan.here.len() == 2)
        );
        assert_eq!(all_here.len(), 2);
        // A NetworkPolicy for the Workload is asked by kithd at each connection: the kernel
        // passes none of them, from the rebuild that sees it.
        apply(
            &mut store,
            "apiVersion: kith.dev/v1\nkind: NetworkPolicy\nmetadata: { name: p }\n\
             spec:\n  selector: { app: web }\n  ingress: [{ action: allow }]\n",
        );
        assert_eq!(kernel_plan(&store, &super::table(&store, prefix, None), "a"), []);
    }

    #[tokio::test]
    async fn the_kernel_sends_a_connection_only_where_a_replica_answers_on_ipv6() {
        // Where a replica here is asked: its pod's IPv6 addresses (a socket made IPv6-only
        // reaches no IPv4 one the kernel writes in), none before its pod is made (never the
        // machine's loopback, where something else may listen), and with no pod that loopback.
        let mesh: Ipv6Addr = "fd00::7".parse().unwrap();
        let v4 = std::net::Ipv4Addr::new(100, 88, 0, 7);
        assert_eq!(
            reachable(Some(0), vec![mesh.into(), v4.into()], false),
            [IpAddr::from(mesh)]
        );
        assert!(reachable(Some(0), vec![v4.into()], false).is_empty());
        assert!(reachable(Some(0), vec![], false).is_empty());
        assert_eq!(reachable(None, vec![], false), [IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        // A replica that listens on IPv4 only is left to kithd.
        let only_v4 = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = only_v4.local_addr().unwrap().port();
        assert_eq!(probe(vec![Ipv6Addr::LOCALHOST.into()], port).await, None);
        // (A replica's address here is the IPv4 loopback's mapped one: what runs the tests
        // may have no IPv6 loopback.)
        let replica = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = replica.local_addr().unwrap().port();
        let loopback = IpAddr::V6(std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        let backend = ("a".to_string(), port, "Workload/default/web".to_string(), Some(0));
        let plans = [Plan {
            service: (IpAddr::V6("fd00::80".parse().unwrap()), 80),
            here: vec![backend.clone()],
            others: vec![],
            elsewhere: None,
        }];
        let entry = |ip| connect::Entry {
            service: plans[0].service,
            here: vec![SocketAddr::new(ip, port)],
            all: 1,
            elsewhere: None,
        };
        let key = (false, backend.clone());
        let mut probed = Probed::new();
        // Its pod not made yet: the port stays kithd's this round, and nothing is kept.
        let mut asked = BTreeMap::from([(key.clone(), vec![])]);
        ask_where(&asked, &mut probed).await;
        assert_eq!(kernel_entries(&plans, &mut probed, &asked, &mut Table::new()), []);
        assert!(probed.is_empty());
        // Made: asked, kept, and the kernel's.
        asked.insert(key.clone(), vec![loopback]);
        ask_where(&asked, &mut probed).await;
        assert_eq!(
            kernel_entries(&plans, &mut probed, &asked, &mut Table::new()),
            [entry(loopback)]
        );
        // What was kept of a pod made before under the same name, at other addresses (its
        // number given again), is forgotten, and the pod there now asked.
        let old = SocketAddr::new(mesh.into(), port);
        probed.insert(key.clone(), (vec![mesh.into()], old));
        assert_eq!(kernel_entries(&plans, &mut probed, &asked, &mut Table::new()), []);
        ask_where(&asked, &mut probed).await;
        assert_eq!(
            kernel_entries(&plans, &mut probed, &asked, &mut Table::new()),
            [entry(loopback)]
        );
        // Nothing listening: none, and kithd passes that Service port's connections itself.
        drop(replica);
        assert_eq!(probe(vec![loopback], port).await, None);
    }

    /// The same for a Service's IPv4 address: asked at the pod's IPv4 addresses, written into the
    /// program for it as IPv4 (T-0664).
    #[tokio::test]
    async fn service_v4_table_the_kernel_sends_a_connection_to_a_replicas_ipv4_address() {
        let mesh: Ipv6Addr = "fd00::7".parse().unwrap();
        let v4 = std::net::Ipv4Addr::new(100, 88, 0, 7);
        assert_eq!(
            reachable(Some(0), vec![mesh.into(), v4.into()], true),
            [IpAddr::from(v4)]
        );
        assert!(reachable(Some(0), vec![mesh.into()], true).is_empty());
        assert_eq!(
            reachable(None, vec![], true),
            [IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]
        );
        let replica = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = replica.local_addr().unwrap().port();
        let backend = ("a".to_string(), port, "Workload/default/web".to_string(), Some(0));
        let service = (IpAddr::V4(std::net::Ipv4Addr::new(100, 87, 0, 2)), 80);
        let plans = [Plan {
            service,
            here: vec![backend.clone()],
            others: vec![],
            elsewhere: None,
        }];
        let asked = BTreeMap::from([((true, backend), vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)])]);
        let mut probed = Probed::new();
        ask_where(&asked, &mut probed).await;
        let entries = kernel_entries(&plans, &mut probed, &asked, &mut Table::new());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].service, service);
        assert_eq!(
            entries[0].here,
            [SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), port)]
        );
    }

    #[test]
    fn a_replica_whose_pod_address_moved_while_it_was_asked_is_not_given_to_the_kernel() {
        let backend = ("a".to_string(), 8080, "Workload/default/web".to_string(), Some(0));
        let plans = [Plan {
            service: (IpAddr::V6("fd00::80".parse().unwrap()), 80),
            here: vec![backend.clone()],
            others: vec![("b".to_string(), 8080, "Workload/default/web".to_string(), Some(1))],
            elsewhere: Some(65535),
        }];
        let was: IpAddr = "fd00::7".parse().unwrap();
        let key = (false, backend.clone());
        let answered = |probed: &mut Probed| {
            probed.insert(key.clone(), (vec![was], SocketAddr::new(was, 8080)));
        };
        let mut probed = Probed::new();
        // Its pod still at the address it answered on: the kernel's.
        answered(&mut probed);
        let still = BTreeMap::from([(key.clone(), vec![was])]);
        assert_eq!(kernel_entries(&plans, &mut probed, &still, &mut Table::new()).len(), 1);
        // Released while it was asked, and its number given to another namespace's pod (or
        // to none yet): what the pods say just before the program is made has the last word.
        for now in [vec![], vec!["fd00::9".parse().unwrap()]] {
            answered(&mut probed);
            let mut wanted = Table::new();
            let now = BTreeMap::from([(key.clone(), now)]);
            assert_eq!(kernel_entries(&plans, &mut probed, &now, &mut wanted), []);
            assert!(probed.is_empty() && wanted.is_empty());
        }
    }

    /// T-0326, step 1: a measurement, not a test of kithd. Twenty clients that each wait
    /// for their answer reach an echoing replica through two "nodes", each on a thread of
    /// its own. With a connection between the nodes for each client (as [`carry`] has it)
    /// every request is a write of its own. With one link and one writer that takes
    /// whatever frames wait: how many requests share a write, and so a segment, and so one
    /// encrypted packet on the mesh? Prints both; asserts nothing about times.
    #[test]
    #[ignore = "a measurement: cargo test -p kithd --bin kithd link_trial -- --ignored --nocapture"]
    fn link_trial_requests_that_share_a_write() {
        use std::sync::atomic::AtomicUsize;
        const CLIENTS: usize = 20;
        const REQUEST: usize = 100;
        const FOR: Duration = Duration::from_secs(3);

        /// Requests answered in [`FOR`] by `CLIENTS` clients through two nodes, `shared`
        /// (one link, of [`link`](super::link)'s streams: the frames and writes of both
        /// its ends are in `links`) or with a connection between the nodes for each.
        fn run(shared: bool, links: &Arc<Mutex<Vec<link::Link>>>) -> usize {
            let on = |name: &str| thread(format!("trial-{name}")).unwrap();
            let (near, far, replicas, clients) = (on("near"), on("far"), on("replica"), on("clients"));
            let bound = |on: &tokio::runtime::Handle| {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                listener.set_nonblocking(true).unwrap();
                let at = listener.local_addr().unwrap();
                let _in = on.enter();
                (TcpListener::from_std(listener).unwrap(), at)
            };
            let (replica, replica_at) = bound(&replicas);
            let (there, there_at) = bound(&far);
            let (here, here_at) = bound(&near);
            replicas.spawn(async move {
                while let Ok((mut client, _)) = replica.accept().await {
                    client.set_nodelay(true).unwrap();
                    tokio::spawn(async move {
                        let (mut read, mut write) = client.split();
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    });
                }
            });
            let to_replica = move || async move {
                let replica = TcpStream::connect(replica_at).await.unwrap();
                replica.set_nodelay(true).unwrap();
                replica
            };
            let far_links = links.clone();
            far.spawn(async move {
                if shared {
                    let (from, _) = there.accept().await.unwrap();
                    from.set_nodelay(true).unwrap();
                    let (link, mut incoming) = link::link(from, false);
                    far_links.lock().unwrap().push(link);
                    while let Some(stream) = incoming.accept().await {
                        tokio::spawn(async move { stream.join(to_replica().await).await });
                    }
                } else {
                    while let Ok((mut from, _)) = there.accept().await {
                        from.set_nodelay(true).unwrap();
                        tokio::spawn(async move {
                            let _ = tokio::io::copy_bidirectional(&mut from, &mut to_replica().await).await;
                        });
                    }
                }
            });
            let near_links = links.clone();
            near.spawn(async move {
                let mut all = Vec::new();
                for _ in 0..CLIENTS {
                    all.push(here.accept().await.unwrap().0);
                }
                if shared {
                    let to = TcpStream::connect(there_at).await.unwrap();
                    to.set_nodelay(true).unwrap();
                    let (link, _) = link::link(to, true);
                    near_links.lock().unwrap().push(link.clone());
                    for client in all {
                        let stream = link.open().unwrap();
                        tokio::spawn(stream.join(client));
                    }
                } else {
                    for mut client in all {
                        client.set_nodelay(true).unwrap();
                        tokio::spawn(async move {
                            let mut to = TcpStream::connect(there_at).await.unwrap();
                            to.set_nodelay(true).unwrap();
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut to).await;
                        });
                    }
                }
            });
            let answered = Arc::new(AtomicUsize::new(0));
            let (done, wait) = std::sync::mpsc::channel();
            for _ in 0..CLIENTS {
                let (answered, done) = (answered.clone(), done.clone());
                clients.spawn(async move {
                    let mut to = TcpStream::connect(here_at).await.unwrap();
                    to.set_nodelay(true).unwrap();
                    let (until, mut bytes) = (Instant::now() + FOR, [7; REQUEST]);
                    while Instant::now() < until {
                        to.write_all(&bytes).await.unwrap();
                        to.read_exact(&mut bytes).await.unwrap();
                        answered.fetch_add(1, Ordering::Relaxed);
                    }
                    done.send(()).unwrap();
                });
            }
            for _ in 0..CLIENTS {
                wait.recv_timeout(FOR * 10).expect("a client that got no answer");
            }
            answered.load(Ordering::Relaxed)
        }

        let each = run(false, &Arc::default());
        let links = Arc::default();
        let shared = run(true, &links);
        // (Both ends of the link write: a request and its answer are a frame each, and
        // the credit that gives their window back, and an open and an end for each client.)
        let (frames, writes) = links
            .lock()
            .unwrap()
            .iter()
            .map(link::Link::counts)
            .fold((0, 0), |(f, w), (frames, writes)| (f + frames, w + writes));
        let secs = FOR.as_secs() as usize;
        println!(
            "a connection for each client: {} requests a second, one write for each request each way",
            each / secs
        );
        println!(
            "one link, one writer: {} requests a second, {frames} frames in {writes} writes: {:.2} to a write",
            shared / secs,
            frames as f64 / writes.max(1) as f64
        );
        assert!(each > 0 && shared > 0 && frames >= 2 * shared as u64);
        assert!(
            frames * 2 >= writes * 3,
            "fewer than 1.5 frames to a write: {frames} in {writes}"
        );
    }

    // ---- T-0326, slice B: the sending end of a link ----

    /// Another node's kithd that takes links as well as connections ([`other_node`] takes only
    /// connections): every replica but the Workload `shut` is the one at `replica`. Where it
    /// listens, and how many connections it has had.
    async fn linking_node(replica: SocketAddr, places: usize) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (at, had) = (
            listener.local_addr().unwrap(),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        );
        let count = had.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let (relaying, spares) = (Limits::new(places, places), Limits::new(1, 1));
                    let local = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
                    let find = move |_: u16, workload: String, _: Option<u32>| async move {
                        match workload.as_str() {
                            "shut" => None,
                            _ => TcpStream::connect(replica).await.ok(),
                        }
                    };
                    let link = |io, relaying, caller| receive::serve(io, relaying, caller, receive::BOUNDS, &find);
                    admit_or_link(&relaying, &spares, local, stream, &find, link).await
                });
            }
        });
        (at, had)
    }

    /// A node that takes each link (`link\n`, answered `+`), reads `reads` bytes more of it and
    /// hangs up; or, with none, reads what it is sent and says nothing, as a peer that is half-open
    /// does. Where it listens, and how many connections it has had.
    async fn hanging_node(reads: Option<usize>) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use tokio::io::AsyncReadExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (at, had) = (
            listener.local_addr().unwrap(),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        );
        let count = had.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let _ = stream.read_exact(&mut [0; 5]).await;
                    let _ = stream.write_all(b"+").await;
                    match reads {
                        Some(reads) => drop(stream.read_exact(&mut vec![0; reads]).await),
                        None => while stream.read(&mut [0; 4096]).await.is_ok_and(|read| read > 0) {},
                    }
                });
            }
        });
        (at, had)
    }

    const AT_B: &str = "Workload/default/web";

    /// A Proxy of node `a` that knows Node `b` as saying `mesh`, and dials it at `at`.
    async fn proxy_to_b(tag: &str, mesh: Value, at: SocketAddr) -> Proxy {
        let shared = state_with_web(tag).await;
        {
            let mut state = shared.store.lock().unwrap();
            let node = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: { name: b }\nspec: {}\n";
            state
                .store
                .apply(Resource::from_source(node).unwrap().remove(0).unwrap())
                .unwrap();
            state.store.set_status("Node/b", Some(json!({ "mesh": mesh }))).unwrap();
        }
        let mut proxy = proxy_of(shared, 8080, AT_B, None);
        proxy.dial_to = Some(at);
        proxy
    }

    /// The link `proxy` has to Node b.
    fn link_of(proxy: &Proxy) -> link::Link {
        proxy.linked.lock().unwrap().get("b").unwrap().0.clone()
    }

    fn on_b(workload: &str) -> Backend {
        ("b".into(), 8080, workload.into(), None)
    }

    /// A client that says `says` through `stream`: what it hears.
    async fn say_on(stream: link::Stream, says: &str) -> String {
        use tokio::io::AsyncReadExt;
        let (mut client, held) = pair().await;
        let asking = async {
            client.write_all(says.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();
            let mut heard = String::new();
            client.read_to_string(&mut heard).await.unwrap();
            heard
        };
        let (_, heard) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(stream.join(held), asking)
        })
        .await
        .expect("the stream ends");
        heard
    }

    /// A node that says it takes links is reached by a stream on one link, however many clients
    /// there are, with what a client said first going with the opening; one that says `kept`
    /// only is reached on a kept connection, and a node of before on a connection of its own.
    #[tokio::test]
    async fn reach_uses_a_stream_of_the_link_where_the_node_takes_links_and_the_old_paths_where_not() {
        let (replica, replicas) = replica().await;
        let (node, connections) = linking_node(replica, 8).await;
        let proxy = proxy_to_b("reach-link", json!({ "port": 1, "kept": true, "link": true }), node).await;
        for turn in 0..3 {
            let Ok(Reached::Linked(stream)) = proxy.reach(&on_b(AT_B), b"").await else {
                panic!("not a stream of a link");
            };
            assert_eq!(say_on(stream, &format!("q{turn}")).await, format!("a:q{turn}"));
        }
        let Ok(Reached::Linked(stream)) = proxy.reach(&on_b(AT_B), b"first, ").await else {
            panic!("not a stream of a link");
        };
        assert_eq!(say_on(stream, "more").await, "a:first, more");
        // What the node has no replica for is said no to on its stream; the link carries on.
        assert!(proxy.reach(&on_b("shut"), b"for nobody").await.is_err());
        assert!(matches!(proxy.reach(&on_b(AT_B), b"").await, Ok(Reached::Linked(_))));
        assert_eq!(connections.load(Ordering::Relaxed), 1, "one connection to the node");
        assert_eq!(replicas.load(Ordering::Relaxed), 5);
        assert!(proxy.kept.lock().unwrap().is_empty());

        // Only `kept`: a kept connection, and no link.
        let (node, connections, _) = other_node(replica).await;
        let proxy = proxy_to_b("reach-kept", json!({ "port": 1, "kept": true }), node).await;
        assert!(matches!(proxy.reach(&on_b(AT_B), b"").await, Ok(Reached::Kept(..))));
        assert!(proxy.linked.lock().unwrap().is_empty());
        // A node of before says neither: a connection of its own.
        let proxy = proxy_to_b("reach-whole", json!({ "port": 1 }), node).await;
        assert!(matches!(proxy.reach(&on_b(AT_B), b"").await, Ok(Reached::Whole(_))));
        assert!(proxy.linked.lock().unwrap().is_empty());
        assert_eq!(connections.load(Ordering::Relaxed), 2);
    }

    /// A link that went down while no client used it is dialled again, once, before the next
    /// client is asked for: the client does not notice.
    #[tokio::test]
    async fn a_link_that_went_down_idle_is_redialled_for_the_next_client() {
        let (node, connections) = linking_node(replica().await.0, 8).await;
        let proxy = proxy_to_b("link-redial", json!({ "port": 1, "kept": true, "link": true }), node).await;
        let Ok(Reached::Linked(stream)) = proxy.reach(&on_b(AT_B), b"").await else {
            panic!("not a stream of a link");
        };
        assert_eq!(say_on(stream, "one").await, "a:one");
        link_of(&proxy).close();
        let Ok(Reached::Linked(stream)) = proxy.reach(&on_b(AT_B), b"spoken").await else {
            panic!("not a stream of a link");
        };
        assert_eq!(say_on(stream, " and two").await, "a:spoken and two");
        assert_eq!(connections.load(Ordering::Relaxed), 2);
        assert!(!link_of(&proxy).is_down());
    }

    /// A link that goes down with a client's bytes on it ends that client's connection as a
    /// kept connection's does ([`Reached::Lost`]: they may be with a replica, and go to no other); with
    /// nothing said it is dialled for once more, and then the next backend is tried.
    #[tokio::test]
    async fn a_link_that_dies_ends_its_streams_as_lost_and_is_dialled_once_more_for_a_client_that_said_nothing() {
        let line = format!("8080 {AT_B}\n");
        // (After the node's `+`: the opening, and the data frame with the asking.)
        let (node, connections) = hanging_node(Some(7 + 7 + line.len() + 6)).await;
        let proxy = proxy_to_b("link-lost", json!({ "port": 1, "kept": true, "link": true }), node).await;
        assert!(matches!(proxy.reach(&on_b(AT_B), b"spoken").await, Ok(Reached::Lost)));
        assert_eq!(
            connections.load(Ordering::Relaxed),
            1,
            "what was said is asked for nowhere else"
        );

        let (node, connections) = hanging_node(Some(7 + 7 + line.len())).await;
        let proxy = proxy_to_b("link-twice", json!({ "port": 1, "kept": true, "link": true }), node).await;
        assert!(proxy.reach(&on_b(AT_B), b"").await.is_err());
        assert_eq!(connections.load(Ordering::Relaxed), 2, "dialled once more, not again");
    }

    /// A stream open when its link goes down ends, and the client's connection with it.
    #[tokio::test]
    async fn a_stream_open_on_a_link_that_goes_down_closes_its_client() {
        use tokio::io::AsyncReadExt;
        let (node, _) = linking_node(replica().await.0, 8).await;
        let proxy = proxy_to_b("link-open", json!({ "port": 1, "kept": true, "link": true }), node).await;
        let Ok(Reached::Linked(stream)) = proxy.reach(&on_b(AT_B), b"").await else {
            panic!("not a stream of a link");
        };
        let (mut client, held) = pair().await;
        let joined = tokio::spawn(stream.join(held));
        link_of(&proxy).close();
        tokio::time::timeout(Duration::from_secs(10), joined)
            .await
            .expect("the stream ends")
            .unwrap();
        let mut heard = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut heard)).await;
        assert!(
            matches!(read, Ok(Ok(0)) | Ok(Err(_))),
            "the client's connection is closed"
        );
    }

    /// The node holds as many streams of a link as [`receive::STREAMS`] and resets the rest: the
    /// clients past that many reach it on a kept connection, and all of them reach the replica.
    #[tokio::test]
    async fn clients_past_the_streams_a_link_holds_take_the_kept_path() {
        let (replica, replicas) = replica().await;
        let (node, connections) = linking_node(replica, receive::STREAMS + 8).await;
        let proxy = proxy_to_b("link-cap", json!({ "port": 1, "kept": true, "link": true }), node).await;
        let (mut held, mut kept) = (Vec::new(), Vec::new());
        for _ in 0..receive::STREAMS + 4 {
            match proxy.reach(&on_b(AT_B), b"").await {
                Ok(Reached::Linked(stream)) => held.push(stream),
                Ok(Reached::Kept(_, relay)) => kept.push(relay),
                _ => panic!("a client did not reach the replica"),
            }
        }
        assert_eq!((held.len(), kept.len()), (receive::STREAMS, 4));
        assert_eq!(say_on(held.pop().unwrap(), "linked").await, "a:linked");
        for relay in &mut kept {
            let (carried, heard) = through(relay, "kept").await;
            assert!(carried.is_ok());
            assert_eq!(heard, "a:kept");
        }
        assert_eq!(replicas.load(Ordering::Relaxed), receive::STREAMS + 4);
        assert_eq!(
            connections.load(Ordering::Relaxed),
            1 + 4,
            "the link, and a connection to each"
        );
    }

    /// A node that takes the link and answers nothing on a stream is not waited for by each
    /// client: the first one's wait ends the link, and the next client dials a new one.
    #[tokio::test]
    async fn a_node_that_answers_nothing_on_a_stream_loses_its_link() {
        let (node, connections) = hanging_node(None).await;
        let proxy = proxy_to_b("link-silent", json!({ "port": 1, "kept": true, "link": true }), node).await;
        assert!(proxy.reach(&on_b(AT_B), b"").await.is_err());
        assert!(link_of(&proxy).is_down());
        assert_eq!(connections.load(Ordering::Relaxed), 1);
        assert!(proxy.reach(&on_b(AT_B), b"").await.is_err());
        assert_eq!(connections.load(Ordering::Relaxed), 2, "the next client dialled again");
    }

    /// The node answers `link\n` with `+` or `-`: a no (or a hang-up, as a node of before does)
    /// before any stream is opened sends the client the kept way, with nothing lost.
    #[tokio::test]
    async fn a_node_that_does_not_take_the_link_is_reached_on_a_kept_connection() {
        let (replica, _) = replica().await;
        // No place to relay in: the link is said no to, and so is the kept connection.
        let (node, connections) = linking_node(replica, 0).await;
        let proxy = proxy_to_b("link-no", json!({ "port": 1, "kept": true, "link": true }), node).await;
        assert!(proxy.reach(&on_b(AT_B), b"spoken").await.is_err());
        assert!(proxy.linked.lock().unwrap().is_empty());
        assert_eq!(connections.load(Ordering::Relaxed), 2, "the link's, and the kept one's");

        // A hang-up before any answer: the kept way is tried (and is hung up on as well here).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (node, connections) = (
            listener.local_addr().unwrap(),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        );
        let count = connections.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                drop(stream);
            }
        });
        let proxy = proxy_to_b("link-hung-up", json!({ "port": 1, "kept": true, "link": true }), node).await;
        // (Not Lost: nothing was sent on the link.)
        assert!(proxy.reach(&on_b(AT_B), b"").await.is_err());
        assert!(proxy.linked.lock().unwrap().is_empty());
        assert_eq!(connections.load(Ordering::Relaxed), 2);
    }

    /// A link with no open stream for longer than a kept connection lasts is closed by
    /// [`Proxy::forget`] (the node closes one that is empty), and one with a stream open is not.
    #[tokio::test]
    async fn a_link_no_stream_has_used_for_long_is_closed() {
        let (node, connections) = linking_node(replica().await.0, 8).await;
        let proxy = proxy_to_b("link-idle", json!({ "port": 1, "kept": true, "link": true }), node).await;
        let Ok(Reached::Linked(open)) = proxy.reach(&on_b(AT_B), b"").await else {
            panic!("not a stream of a link");
        };
        let long_ago = |proxy: &Proxy| {
            let ago = Instant::now().checked_sub(KEPT + Duration::from_secs(1)).unwrap();
            proxy.linked.lock().unwrap().get_mut("b").unwrap().1 = ago;
        };
        long_ago(&proxy);
        proxy.forget();
        assert!(!link_of(&proxy).is_down(), "a stream is open on it");
        let Ok(Reached::Linked(over)) = proxy.reach(&on_b(AT_B), b"").await else {
            panic!("not a stream of a link");
        };
        assert_eq!(say_on(over, "two").await, "a:two");
        drop(open);
        for _ in 0..100 {
            if link_of(&proxy).streams() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(link_of(&proxy).streams(), 0);
        long_ago(&proxy);
        let link = link_of(&proxy);
        proxy.forget();
        assert!(link.is_down() && proxy.linked.lock().unwrap().is_empty());
        assert_eq!(connections.load(Ordering::Relaxed), 1);
    }
}

/// A Service made to name a port a host listener holds on the wildcard (7443, 22) gets no listener
/// of kithd's there, as the bind fails; the pair is then not open to the pods, which would else reach
/// the host's listener at the Service's address.
#[tokio::test]
async fn a_port_a_host_wildcard_listener_holds_is_not_open_to_pods() {
    let host = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let taken = host.local_addr().unwrap().port();
    let free = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let at = |port| (IpAddr::from([127, 0, 0, 1]), port);
    let relay = at(free + 1);
    let mut listening = BTreeMap::new();
    for key in [at(taken), at(free), relay] {
        if listen(SocketAddr::new(key.0, key.1), 1).is_ok() {
            listening.insert(key, Vec::new());
        }
    }
    assert!(
        !listening.contains_key(&at(taken)),
        "the bind next to a wildcard listener fails"
    );
    assert_eq!(
        open_keys(&listening, Some(relay)),
        vec![at(free)],
        "not the held port, nor the relay's"
    );
}

/// An IPv4 program the kernel refused is put again at the next round, and said once.
#[test]
fn a_refused_ipv4_program_is_put_again_and_said_once() {
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    let entry = |address: IpAddr| connect::Entry {
        service: (address, 80),
        here: vec![SocketAddr::new(address, 8080)],
        all: 1,
        elsewhere: None,
    };
    let entries = vec![entry("100.87.0.1".parse().unwrap()), entry("fd00::1".parse().unwrap())];
    let no_listeners = BTreeMap::new();
    let refuse4 = AtomicBool::new(true);
    let put = |v4: bool, _: &[u8]| -> std::io::Result<()> {
        if v4 && refuse4.load(Relaxed) {
            Err(std::io::Error::other("no hook"))
        } else {
            Ok(())
        }
    };
    let mut said = Vec::new();
    let mut kernel = Kernel::Has(1, Vec::new(), V4::Works);
    install_with(&mut kernel, entries.clone(), &no_listeners, &put, &mut |t| said.push(t));
    install_with(&mut kernel, entries.clone(), &no_listeners, &put, &mut |t| said.push(t));
    assert_eq!(said.len(), 1, "said once: {said:?}");
    let Kernel::Has(_, last, no4) = &kernel else {
        panic!("kernel gone")
    };
    assert!(
        *no4 == V4::Stale && last.len() == 1 && last[0].service.0.is_ipv6(),
        "only IPv6 passed"
    );
    // The hook takes it at a later round: both are passed, and a refusal after is said again.
    refuse4.store(false, Relaxed);
    install_with(&mut kernel, entries.clone(), &no_listeners, &put, &mut |t| said.push(t));
    let Kernel::Has(_, last, no4) = &kernel else {
        panic!("kernel gone")
    };
    assert!(*no4 == V4::Works && *last == entries, "IPv4 passed again");
    refuse4.store(true, Relaxed);
    let mut other = entries.clone();
    other[0].all = 2;
    install_with(&mut kernel, other, &no_listeners, &put, &mut |t| said.push(t));
    // (The refusal, the one before emptied at last, and the refusal after it worked.)
    assert_eq!(said.len(), 3, "said again after it worked: {said:?}");
}

/// An IPv4 program refused, whose one before could not be emptied either, is emptied again at each
/// round, with nothing else changed, until it is.
#[test]
fn an_ipv4_program_that_could_not_be_emptied_is_emptied_again() {
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    let address: IpAddr = "fd00::1".parse().unwrap();
    let entries = vec![connect::Entry {
        service: (address, 80),
        here: vec![SocketAddr::new(address, 8080)],
        all: 1,
        elsewhere: None,
    }];
    let refuse4 = AtomicBool::new(true);
    let put = |v4: bool, _: &[u8]| -> std::io::Result<()> {
        if v4 && refuse4.load(Relaxed) {
            Err(std::io::Error::other("no hook"))
        } else {
            Ok(())
        }
    };
    let no_listeners = BTreeMap::new();
    let mut said = Vec::new();
    let mut kernel = Kernel::Has(1, Vec::new(), V4::Works);
    install_with(&mut kernel, entries.clone(), &no_listeners, &put, &mut |t| said.push(t));
    assert!(matches!(kernel, Kernel::Has(_, _, V4::Stale)), "not emptied: stale");
    // Nothing changed, and the put still fails: still stale, nothing said again.
    install_with(&mut kernel, entries.clone(), &no_listeners, &put, &mut |t| said.push(t));
    assert!(matches!(kernel, Kernel::Has(_, _, V4::Stale)));
    assert_eq!(said.len(), 1, "{said:?}");
    refuse4.store(false, Relaxed);
    install_with(&mut kernel, entries, &no_listeners, &put, &mut |t| said.push(t));
    assert!(matches!(kernel, Kernel::Has(_, _, V4::Refused)), "emptied at last");
    assert_eq!(said.len(), 2, "said: {said:?}");
}

/// A Service `name` in `namespace`, as an Apply has it.
#[cfg(test)]
fn service(namespace: &str, name: &str) -> Resource {
    let text = format!(
        "apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ namespace: {namespace}, name: {name} }}\nspec: {{ selector: {{ app: web }}, ports: [{{ port: 80 }}] }}"
    );
    Resource::from_source(&text)
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
        .unwrap()
}

/// An Apply of a Workload and no Service.
#[cfg(test)]
fn no_service() -> Vec<Resource> {
    let text = "apiVersion: kith.dev/v1\nkind: Workload\nmetadata: { name: web }\nspec:\n  template:\n    containers: [{ name: main, image: example.org/web }]";
    Resource::from_source(text)
        .unwrap()
        .into_iter()
        .map(Result::unwrap)
        .collect()
}

// (Here, not in `tests`: the criteria name them `services::<name>`.)
#[test]
fn a_service_whose_address_is_anothers_is_refused() {
    // (Every name gets the one address here, so any two Services clash.)
    let one = |_: &str, _: &str| Ipv6Addr::LOCALHOST;
    let mut store = Store::default();
    store.apply(service("tenant-x", "vault")).unwrap();
    // One stored, one in the Apply.
    let refused = unclaimed_with(&store, &[service("media", "web")], one).unwrap_err();
    assert!(
        refused.contains("would have the mesh address another Service has"),
        "{refused}"
    );
    assert!(refused.starts_with("Service Service/media/web would"), "{refused}");
    assert!(!refused.contains("tenant-x") && !refused.contains("vault"), "{refused}");
    // Two in one Apply.
    let both = [service("tenant-x", "vault"), service("media", "web")];
    let refused = unclaimed_with(&Store::default(), &both, one).unwrap_err();
    assert!(refused.starts_with("Service Service/tenant-x/vault would"), "{refused}");
    assert!(!refused.contains("media") && !refused.contains("web"), "{refused}");
}

#[test]
fn a_service_applied_again_under_its_own_key_is_no_clash() {
    let one = |_: &str, _: &str| Ipv6Addr::LOCALHOST;
    let mut store = Store::default();
    store.apply(service("media", "web")).unwrap();
    unclaimed_with(&store, &[service("media", "web")], one).unwrap();
    // With the real addresses too, and an Apply with no Service at all.
    let prefix = kith_mesh::prefix(b"test");
    unclaimed(&store, prefix, &[service("media", "web")]).unwrap();
    unclaimed(&store, prefix, &no_service()).unwrap();
}

#[test]
fn a_batch_with_no_service_is_never_asked() {
    let asked = |_: &str, _: &str| -> Ipv6Addr { panic!("an address was asked for") };
    let mut store = Store::default();
    store.apply(service("media", "web")).unwrap();
    unclaimed_with(&store, &no_service(), asked).unwrap();
}
