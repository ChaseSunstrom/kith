//! Services, on a node of the mesh: every Service has an address every node holds
//! (`kith_mesh::service_address`), and a TCP connection to one of its ports there is
//! passed to a ready replica of a Workload its selector matches, one after the other in
//! turn. A replica on this node is reached on the machine itself (so it may listen on
//! 127.0.0.1 only); one on another node through that node's kithd, which listens on its
//! mesh address for exactly this and connects to the replica there. Two nodes keep the
//! connections between them for a while and pass on one client's after another on each
//! ([`carry`]): a new connection to a Service is then no new one between the nodes.
//
// ponytail: kithd copies every byte (a restart of kithd cuts the connections), TCP only,
// and replicas of one node share its ports until workloads have addresses of their own.
// The kernel takes this over (nftables or eBPF) behind the same addresses.

mod connect;

use crate::Shared;
use crate::ingress::{Idle, Limits};
use futures_util::FutureExt;
use kith_api::Resource;
use kith_api::kinds::{NetworkPolicySpec, Peer, PolicyAction, PortRef, Protocol, ServiceSpec, WorkloadSpec};
use kith_api::store::Store;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
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
/// For every address and port a Service listens on: its backends.
type Table = BTreeMap<(Ipv6Addr, u16), Vec<Backend>>;

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
/// How many connections to Services this node passes on at a time, from its own side and
/// (for the other nodes together, so no node can take them all) from the mesh; one
/// over is hung up on.
const SERVING: usize = 4096;
const RELAYING: usize = 4096;
/// How many of the relayed ones one other node may hold.
const RELAYING_PER_NODE: usize = 1024;
/// The most threads the connections to Services are on, one to a core. Each connection
/// still takes the store's lock and the table's for a moment as it starts: past a few
/// threads those moments queue, and the rest of kithd keeps a core of its own.
const THREADS: usize = 4;

fn namespace(resource: &Resource) -> String {
    resource.key().split('/').nth(1).unwrap_or_default().to_string()
}

/// The address of every Service in the store.
pub fn addresses(store: &Store, prefix: Ipv6Addr) -> BTreeMap<String, Ipv6Addr> {
    let address = |service: &Resource| kith_mesh::service_address(prefix, &namespace(service), &service.metadata.name);
    let services = store.list(Some("Service"));
    services.map(|service| (service.key(), address(service))).collect()
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
                let pod = workload.spec["template"]["pod"] == true;
                let nodes = ready_on(workload).into_iter();
                backends.extend(target.into_iter().flat_map(|target| {
                    let backend = move |(node, replica)| (node, target, workload.key(), pod.then_some(replica));
                    nodes.clone().map(backend)
                }));
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
    /// Places for the connections of this node's own clients, and for those another node
    /// passes on to a replica here.
    serving: Limits,
    relaying: Limits,
    /// The connections to each other node's kithd that no client's is on now, and since when.
    /// (As the kernel's, on no thread's runtime: the next client's may be on another.)
    kept: Mutex<BTreeMap<String, Vec<(std::net::TcpStream, Instant)>>>,
}

/// What [`Proxy::reach`] reached.
enum Reached {
    /// A connection that is this client's alone: to a replica here, or through a node of
    /// before, which keeps none.
    Whole(TcpStream),
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
                Some((port, status["mesh"]["kept"] == true))
            })
        };
        let (relay, keeps) = relay.ok_or_else(|| std::io::Error::other(format!("node {node} is not on the mesh")))?;
        let there = SocketAddr::new(kith_mesh::node_address(self.prefix, node).into(), relay);
        let replica = replica.map(|replica| format!(" {replica}")).unwrap_or_default();
        if !keeps {
            // A node of before: a connection for this client alone, as it knows them. It
            // says so (one byte) when it has the replica; if it hangs up instead (a
            // policy, a replica just gone), the next backend is tried.
            let mut stream = within(TcpStream::connect(there)).await?;
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
                None => (false, Relay::new(within(TcpStream::connect(there)).await?)),
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
    }

    /// Someone connected to a Service: pass the connection to its next backend that
    /// takes it.
    async fn serve(&self, key: (Ipv6Addr, u16), mut client: TcpStream) {
        // (The place is held while the connection lasts.)
        let Some(_place) = client.peer_addr().ok().and_then(|from| self.serving.take(from.ip())) else {
            return;
        };
        let backends = {
            let table = self.table.lock().expect("nothing panics holding the table");
            table.get(&key).cloned().unwrap_or_default()
        };
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
        // (The place is held while the connection between the nodes lasts.)
        let _place = self.relaying.take(caller.into())?;
        let find = |port, workload: String, replica| async move {
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
        };
        taken(from, find).await
    }

    /// A replica on this machine, wherever it listens: on the machine's own loopback, or
    /// in its pod.
    async fn local(&self, workload: &str, replica: Option<u32>, port: u16) -> std::io::Result<TcpStream> {
        let pod = replica.map(|replica| crate::controller::pod_of(workload, replica));
        let pod = pod.as_deref().map(|pod| (&*self.shared, pod));
        within(crate::pods::connect(pod, port)).await
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

/// Bytes both ways between a client and a backend, until either ends or `idle` goes by
/// with no byte moved on one of them.
async fn pass(client: TcpStream, backend: TcpStream, idle: Duration) -> std::io::Result<(u64, u64)> {
    let (mut client, mut backend) = (Idle::new(client, idle, None), Idle::new(backend, idle, None));
    tokio::io::copy_bidirectional(&mut client, &mut backend).await
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
/// as they are, or it is hung up on.
async fn taken<F, Fut>(from: TcpStream, find: F) -> Option<()>
where
    F: Fn(u16, String, Option<u32>) -> Fut,
    Fut: Future<Output = Option<TcpStream>>,
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
        let mut words = line.split(' ').peekable();
        let kept = words.next_if_eq(&"kept").is_some();
        let (port, workload) = (words.next()?.parse::<u16>().ok()?, words.next()?);
        let replica = match words.next() {
            Some(replica) => Some(replica.parse::<u32>().ok()?),
            None => None,
        };
        let replica = tokio::time::timeout(FOUND, find(port, workload.to_string(), replica)).await;
        let replica = replica.ok().flatten();
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
                        let size = u64::from(relay.from.read_u16().await?);
                        if size == 0 {
                            return Ok(());
                        }
                        tokio::io::copy(&mut (&mut relay.from).take(size), &mut tokio::io::sink()).await?;
                    }
                };
                within(skipped).await.ok()?;
            }
        }
        wait = KEPT_THERE;
    }
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
        serving: Limits::new(SERVING, SERVING),
        relaying: Limits::new(RELAYING, RELAYING_PER_NODE).per_node(),
        kept: Mutex::default(),
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
    // On each thread a listener of each port, the kernel spreading the connections between them.
    let mut listening: BTreeMap<(Ipv6Addr, u16), Vec<tokio::task::JoinHandle<()>>> = BTreeMap::new();
    let mut threads = Vec::new();
    let mut generation = shared.generation.subscribe();
    let mut kernel = kith_dm_sys::netns_cookie()
        .and_then(|netns| connect::attach(&[], netns).map(|()| netns))
        .inspect(|_| eprintln!("kithd: services: the kernel passes connections to a replica here"))
        .inspect_err(|e| eprintln!("kithd: services: kithd passes every connection itself: {e}"))
        .ok()
        .map(|netns| (netns, Vec::new()));
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
        // (No thread, and no listener, before there is a Service: a node that has none
        // has nothing to pass on, and nothing on it waits.)
        if threads.is_empty() && !wanted.is_empty() {
            threads = start();
        }
        if !threads.is_empty() {
            keys.insert((me, port));
        }
        if let Some((netns, last)) = &mut kernel {
            let entries = kernel_entries(&wanted, proxy.me()).await;
            if entries != *last {
                match connect::attach(&entries, *netns) {
                    Ok(()) => *last = entries,
                    Err(e) => eprintln!("kithd: services: the kernel's program: {e}"),
                }
            }
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
            let Ok(listeners) = listen(SocketAddr::new(key.0.into(), key.1), threads.len()) else {
                waiting = true;
                continue;
            };
            let tasks = threads.iter().zip(listeners).map(|(thread, listener)| {
                let proxy = proxy.clone();
                thread.spawn(async move {
                    // (Taken by this thread's runtime, which then wakes it.)
                    let Ok(listener) = TcpListener::from_std(listener) else {
                        return;
                    };
                    if key == (me, port) {
                        let take = |proxy: Arc<Proxy>, stream| async move {
                            let _ = proxy.take(stream).await;
                        };
                        proxy.accept(listener, take).await;
                    } else {
                        let serve = move |proxy: Arc<Proxy>, stream| async move { proxy.serve(key, stream).await };
                        proxy.accept(listener, serve).await;
                    }
                })
            });
            listening.insert(key, tasks.collect());
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
        .flatten()
        .chain(&stray)
        .for_each(tokio::task::JoinHandle::abort);
}

/// What the kernel passes itself: (spike) a Service port whose every backend is a
/// container on this node's network, which answers on its loopback.
async fn kernel_entries(table: &Table, me: &str) -> Vec<connect::Entry> {
    let mut entries = Vec::new();
    for (&service, backends) in table {
        let Some((_, port, _, _)) = backends.first() else { continue };
        if !backends.iter().all(|(node, at, _, replica)| node == me && at == port && replica.is_none()) {
            continue;
        }
        let v4 = within(TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, *port))).await.is_ok();
        let ip = if v4 { std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped() } else { Ipv6Addr::LOCALHOST };
        if v4 || within(TcpStream::connect((Ipv6Addr::LOCALHOST, *port))).await.is_ok() {
            let here = vec![std::net::SocketAddrV6::new(ip, *port, 0, 0)];
            entries.push(connect::Entry { service, here, all: 1, elsewhere: None });
        }
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
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let handle = runtime.handle().clone();
    let run = move || runtime.block_on(std::future::pending::<()>());
    std::thread::Builder::new().name(name).spawn(run)?;
    Ok(handle)
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
    async fn replica() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
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
                tokio::spawn(taken(stream, move |port, workload: String, which| {
                    lines.lock().unwrap().push(format!("{port} {workload} {which:?}"));
                    async move {
                        match workload.as_str() {
                            "shut" => None,
                            "slow" => std::future::pending().await,
                            _ => TcpStream::connect(replica).await.ok(),
                        }
                    }
                }));
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
                    // Five bytes over two seconds, then (its client's end heard) its own.
                    for _ in 0..5 {
                        tokio::time::sleep(Duration::from_millis(400)).await;
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
            let mut heard = [0; 5];
            client.read_exact(&mut heard).await.unwrap();
            client.shutdown().await.unwrap();
            client.read_to_end(&mut Vec::new()).await.unwrap()
        };
        let begun = std::time::Instant::now();
        let (carried, more) = tokio::join!(carry(held, &mut relay, Duration::from_secs(1)), hearing);
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
        let cut = carry(held, &mut relay, Duration::from_secs(1)).await;
        assert_eq!(cut.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert!(begun.elapsed() >= Duration::from_secs(1) && begun.elapsed() < Duration::from_secs(3));
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
}
