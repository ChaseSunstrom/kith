//! Pods: a replica whose template says `pod: true` runs as Kubernetes runs one. Its
//! containers share a network namespace of their own (kith-mesh's `pod`: an address on
//! the mesh, in its node's /80, and one only the node knows for what goes elsewhere), are
//! told where to ask for names (this node's DNS, with the search list Kubernetes gives),
//! and a connection of a Service or a probe is made inside the namespace, to the pod's
//! own loopback.
//!
//! Only where kithd is root. Elsewhere a pod shares the node's network like any replica.
//
// ponytail: a pod's numbers are kept in memory: kithd starts with no containers (it
// removes what an earlier one left), so with no pods. Names of the pods themselves (a
// StatefulSet's `web-0.web`) are not served yet.

use crate::Shared;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{Notify, watch};

struct Pod {
    number: u16,
    /// The tunnel it leaves by, if it is one of an exit's.
    exit: Option<u16>,
    namespace: OwnedFd,
    address: IpAddr,
    dir: PathBuf,
}

/// What a container of a pod is given.
pub struct Given {
    /// The pod's network namespace, by a path any process of this machine can open.
    pub netns: PathBuf,
    pub hostname: String,
    /// The pod's `resolv.conf` and `hosts`, for the container's `/etc`.
    pub files: [PathBuf; 2],
}

#[derive(Default)]
pub struct Pods {
    made: BTreeMap<String, Pod>,
    /// Told once the node is ready for pods: its DNS for them starts then.
    up: Arc<Notify>,
    /// Told when a pod is made or let go (its address may be given to the next): the
    /// Services' round, which keeps the kernel from passing to a pod gone, wakes.
    pub moved: Arc<Notify>,
    /// The mesh's link: an exit's pods pass on to the mesh by it, and by no other link of the node's.
    pub mesh: String,
}

/// Where the node keeps that it guards what it passes on, until it restarts.
const GUARDED: &str = "/run/kith-pods";

/// The range this node's pods get their addresses from (`--pod-range`), set once at start.
static RANGE: std::sync::OnceLock<kith_mesh::pod::Range> = std::sync::OnceLock::new();

pub fn set_range(range: kith_mesh::pod::Range) {
    let _ = RANGE.set(range);
}

pub fn range() -> kith_mesh::pod::Range {
    RANGE.get().copied().unwrap_or_default()
}

impl Pods {
    /// The pod `id` (of `namespace`, called `hostname`), made if it is not there yet.
    /// `net`: this node's /80 of the mesh, where there is a cluster. `exit`: the tunnel it
    /// leaves by, and where it asks for names (through it), for one of an exit's.
    pub fn given(
        &mut self,
        state: &Path,
        id: &str,
        namespace: &str,
        hostname: &str,
        net: Option<Ipv6Addr>,
        exit: Option<(u16, &[Ipv4Addr])>,
    ) -> Result<Given, String> {
        let failed = |e: std::io::Error| format!("the pod's network: {e}");
        let range = range();
        if self.made.is_empty() {
            let guarded = kith_mesh::pod::node(range, Path::new(GUARDED).exists(), &self.mesh).map_err(failed)?;
            if guarded {
                let _ = std::fs::write(GUARDED, "");
            }
            self.up.notify_one();
        }
        if let Some(pod) = self.made.get(id)
            && pod.exit != exit.map(|(tunnel, _)| tunnel)
        {
            return Err("the pod was made to leave another way: it is made again once its containers stop".into());
        }
        if !self.made.contains_key(id) {
            let taken: Vec<u16> = self.made.values().map(|pod| pod.number).collect();
            let number = range.numbers().find(|number| !taken.contains(number));
            let number = number.ok_or("this node has no number left for another pod")?;
            let (v4, v6) = kith_mesh::pod::addresses(range, net, number);
            let address = v6.map_or(IpAddr::V4(v4), IpAddr::V6);
            let dir = state.join("pods").join(id);
            let gateway = range.gateway();
            let resolv = match exit {
                // (Asked through the tunnel, of its own DNS: never this node's, nor its cache.)
                Some((_, dns)) => dns.iter().map(|server| format!("nameserver {server}\n")).collect(),
                None => format!(
                    "nameserver {gateway}\nsearch {namespace}.svc.cluster.local svc.cluster.local cluster.local\noptions ndots:5\n"
                ),
            };
            let hosts = format!("127.0.0.1 localhost\n::1 localhost\n{address} {hostname}\n");
            let written = std::fs::create_dir_all(&dir)
                .and_then(|()| std::fs::write(dir.join("resolv.conf"), resolv))
                .and_then(|()| std::fs::write(dir.join("hosts"), hosts));
            written.map_err(|e| format!("{}: {e}", dir.display()))?;
            let tunnel = exit.map(|(tunnel, _)| tunnel);
            let namespace = kith_mesh::pod::make(range, number, v6, tunnel).map_err(failed)?;
            let pod = Pod {
                number,
                exit: tunnel,
                namespace,
                address,
                dir,
            };
            self.made.insert(id.into(), pod);
            self.moved.notify_one();
        }
        let pod = &self.made[id];
        let netns = format!("/proc/{}/fd/{}", std::process::id(), pod.namespace.as_raw_fd());
        Ok(Given {
            netns: netns.into(),
            hostname: hostname.into(),
            files: [pod.dir.join("resolv.conf"), pod.dir.join("hosts")],
        })
    }

    /// Let go of every pod `wanted` does not name: its namespace goes with its last process.
    pub fn keep(&mut self, wanted: impl Fn(&str) -> bool) {
        let before = self.made.len();
        self.made.retain(|id, pod| {
            let kept = wanted(id);
            if !kept {
                let _ = std::fs::remove_dir_all(&pod.dir);
                // (What of it lingers still goes nowhere: `release` leaves that rule.)
                if pod.exit.is_some()
                    && let Err(e) = kith_mesh::exit::release(&kith_mesh::exit::link(pod.number))
                {
                    eprintln!("kithd: pod {id}: taking its exit's rules away: {e}");
                }
            }
            kept
        });
        if self.made.len() < before {
            self.moved.notify_one();
        }
    }

    pub fn address(&self, id: &str) -> Option<IpAddr> {
        self.made.get(id).map(|pod| pod.address)
    }

    /// The pod's addresses: on the mesh where there is one, and its IPv4 one.
    pub fn addresses(&self, id: &str) -> Vec<IpAddr> {
        let Some(pod) = self.made.get(id) else {
            return Vec::new();
        };
        let v4 = IpAddr::V4(kith_mesh::pod::addresses(range(), None, pod.number).0);
        if pod.address == v4 {
            vec![v4]
        } else {
            vec![pod.address, v4]
        }
    }
}

/// A connection to `port` of a pod, or (`None`, or a pod with no network of its own) of
/// this machine: on the loopback either way, so what listens only there is reached.
//
// ponytail: a thread is started and ended for every connection into a pod (the socket has
// to be made inside its namespace). Sockets made ahead, or the kernel passing the
// connection on (services.rs's own note), when a node's Services are that busy.
pub async fn connect(pod: Option<(&Shared, &str)>, port: u16) -> std::io::Result<TcpStream> {
    let socket = |v4: bool| -> std::io::Result<TcpSocket> {
        let make = || if v4 { TcpSocket::new_v4() } else { TcpSocket::new_v6() };
        let Some((shared, id)) = pod else { return make() };
        let pods = shared.pods.lock().expect("nothing panics holding the pods");
        match pods.made.get(id) {
            Some(pod) => kith_mesh::pod::within(&pod.namespace, make)?,
            None => make(),
        }
    };
    match socket(true)?.connect((Ipv4Addr::LOCALHOST, port).into()).await {
        Ok(stream) => Ok(stream),
        Err(_) => socket(false)?.connect((Ipv6Addr::LOCALHOST, port).into()).await,
    }
}

/// Make the node's tables for its pods again where they are gone while pods run (`nft flush
/// ruleset`, say): else an exit's pods would reach the node itself, kithd's API among it.
pub fn guard_again(shared: &Shared) {
    let pods = shared.pods.lock().expect("nothing panics holding the pods");
    if pods.made.is_empty() || kith_mesh::pod::tables().unwrap_or(true) {
        return;
    }
    eprintln!("kithd: the tables of this node's pods are gone: made again");
    if let Err(e) = kith_mesh::pod::node(range(), Path::new(GUARDED).exists(), &pods.mesh) {
        eprintln!("kithd: making the tables of this node's pods again: {e}");
    }
}

/// A socket made in pod `id`'s namespace, and never the node's: a pod gone is an error.
fn inside<T: Send>(shared: &Shared, id: &str, make: impl FnOnce() -> std::io::Result<T> + Send) -> std::io::Result<T> {
    let pods = shared.pods.lock().expect("nothing panics holding the pods");
    let pod = pods
        .made
        .get(id)
        .ok_or_else(|| std::io::Error::other("the pod is not on this node"))?;
    kith_mesh::pod::within(&pod.namespace, make)?
}

/// The ports pods publish (`publish: true`), each at the same port of every IPv4 address
/// of this node: kithd listens there, and passes each connection, or each datagram, on to
/// the pod's own IPv4 address (the app sees it, not the LAN client's), until the pod goes or
/// stops publishing it. No rule of the kernel's is made for it (nothing is passed on that
/// kithd did not take). Never one of kithd's own ports here (`own`), nor one below 1024.
//
// ponytail: a pod of this node that asks for a port another has waits for that one to go,
// and says nothing of it but kithd's log.
pub async fn publish(shared: Arc<Shared>, own: Vec<(u16, &'static str)>, mut stopping: watch::Receiver<bool>) {
    let mut generation = shared.generation.subscribe();
    // (Each port's pod, and its relay.)
    type Relay = (Asker, tokio::task::JoinHandle<()>);
    let mut open: BTreeMap<(bool, u16), Relay> = BTreeMap::new();
    let mut said = std::collections::BTreeSet::new();
    loop {
        let mut asked = published(&shared);
        let mut refused = refuse_own(&mut asked, &own);
        let held = open.iter().map(|(port, (pod, _))| (*port, pod.clone())).collect();
        let wanted = chosen(asked, &held, &mut refused);
        for refused in refused {
            if said.insert(refused.clone()) {
                eprintln!("{refused}");
            }
        }
        // (A pod made again with another number is another address: its relay is made again.)
        open.retain(|port, (pod, task)| {
            let kept = wanted.get(port) == Some(pod);
            if !kept {
                task.abort();
            }
            kept
        });
        for (port, pod) in wanted {
            open.entry(port).or_insert_with(|| {
                let (id, number, _) = pod.clone();
                (pod, tokio::spawn(relay(shared.clone(), (id, number), port)))
            });
        }
        tokio::select! {
            _ = generation.changed() => {}
            // (A pod is made, or goes, with nothing written: looked at again soon.)
            () = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
            _ = stopping.changed() => break,
        }
    }
    open.values().for_each(|(_, task)| task.abort());
}

/// Take out of `wanted` the ports below 1024 and those kithd serves on itself here (`own`:
/// either protocol), each with why, for the log. (The apply refuses them too, but only
/// kithd's defaults, and a Workload stored by an older kithd was not asked.)
fn refuse_own(wanted: &mut BTreeMap<(bool, u16), Vec<Asker>>, own: &[(u16, &str)]) -> Vec<String> {
    let mut refused = Vec::new();
    wanted.retain(|&(_, port), pods| {
        let why = match own.iter().find(|(served, _)| *served == port) {
            Some((_, what)) => format!("kithd serves its {what} on it at this node"),
            None if port < 1024 => "those below 1024 are the node's".to_string(),
            None => return true,
        };
        for (id, _, _) in pods.iter() {
            refused.push(format!("kithd: pod {id}: port {port} is not published: {why}"));
        }
        false
    });
    refused
}

/// At most this many ports of a node published at once: each is a listener of kithd's.
const PORTS: usize = 64;

/// A pod asking for a published port: its id, its number, and its namespace.
type Asker = (String, u16, String);

/// Which of the pods asking for each port (`asked`, in the store's order) has it: the one
/// that had it (`held`) while it asks still, else the first of the namespace that had it,
/// else the first where all that ask are of one namespace; and at most [`PORTS`] ports,
/// those held first. Why each other is not published goes to `refused`. (A pod that came
/// later, or of a namespace whose name sorts first, takes no port; and where pods of two
/// namespaces ask for a port none had, after a restart say, none has it: the apply refuses
/// that, but not a Release's or a Source's writing.)
fn chosen(
    asked: BTreeMap<(bool, u16), Vec<Asker>>,
    held: &BTreeMap<(bool, u16), Asker>,
    refused: &mut Vec<String>,
) -> BTreeMap<(bool, u16), Asker> {
    let (old, new): (Vec<_>, Vec<_>) = asked.into_iter().partition(|(port, _)| held.contains_key(port));
    let mut wanted = BTreeMap::new();
    for ((udp, port), pods) in old.into_iter().chain(new) {
        let had = held.get(&(udp, port));
        let namespace = match (had, pods.first()) {
            (Some(had), _) if pods.iter().any(|pod| pod.2 == had.2) => Some(&had.2),
            (_, Some(first)) if pods.iter().all(|pod| pod.2 == first.2) => Some(&first.2),
            _ => None,
        };
        let Some(namespace) = namespace else {
            for (id, _, _) in &pods {
                let why = "pods of more than one namespace ask for it";
                refused.push(format!("kithd: pod {id}: port {port} is not published: {why}"));
            }
            continue;
        };
        let ours = pods.iter().filter(|pod| pod.2 == *namespace);
        let still = ours.clone().find(|pod| had.is_some_and(|had| had.0 == pod.0));
        let Some(has) = still.or_else(|| ours.clone().next()).cloned() else {
            continue;
        };
        for (id, _, _) in pods.iter().filter(|pod| pod.0 != has.0) {
            refused.push(format!(
                "kithd: pod {id}: port {port} is not published: pod {} of this node has it",
                has.0
            ));
        }
        if wanted.len() == PORTS {
            let at_most = format!("this node publishes {PORTS} ports at most");
            refused.push(format!("kithd: pod {}: port {port} is not published: {at_most}", has.0));
            continue;
        }
        wanted.insert((udp, port), has);
    }
    wanted
}

/// The ports (UDP, and the number) a Workload's or Job's pods publish.
fn ports_of(resource: &kith_api::Resource) -> Vec<(bool, u16)> {
    let Ok((template, _)) = crate::controller::template_of(resource) else {
        return Vec::new();
    };
    let ports = template.containers().flat_map(|c| &c.ports);
    let udp = |p: &kith_api::kinds::Port| p.protocol == Some(kith_api::kinds::Protocol::Udp);
    ports
        .filter(|p| p.publish == Some(true))
        .map(|p| (udp(p), p.port))
        .collect()
}

/// Refuse a Workload or Job of `resources` that publishes a port another namespace's does:
/// on whichever node they meet, one namespace never has another's port. (Within one, the
/// node's pod that has it keeps it.)
pub fn unshared(store: &kith_api::store::Store, resources: &[kith_api::Resource]) -> Result<(), String> {
    let namespace = |resource: &kith_api::Resource| resource.metadata.namespace.clone().unwrap_or_default();
    let publishing = |resource: &kith_api::Resource| ["Workload", "Job"].contains(&resource.kind.as_str());
    let asking: Vec<_> = resources
        .iter()
        .filter(|r| publishing(r))
        .map(|r| (r, ports_of(r)))
        .collect();
    if asking.iter().all(|(_, ports)| ports.is_empty()) {
        return Ok(());
    }
    let keys: Vec<String> = resources.iter().map(kith_api::Resource::key).collect();
    let stored = ["Workload", "Job"].into_iter().flat_map(|kind| store.list(Some(kind)));
    let others: Vec<_> = stored
        .filter(|other| !keys.contains(&other.key()))
        .chain(resources.iter().filter(|r| publishing(r)))
        .map(|other| (namespace(other), ports_of(other)))
        .collect();
    for (resource, ports) in asking {
        for (udp, port) in ports {
            // (Not said whose: a namespace learns nothing of another's by it.)
            let taken = others
                .iter()
                .any(|(of, theirs)| *of != namespace(resource) && theirs.contains(&(udp, port)));
            if taken {
                let protocol = if udp { "UDP" } else { "TCP" };
                return Err(format!("{}: {protocol} port {port} is not available", resource.key()));
            }
        }
    }
    Ok(())
}

/// The pods of this node that ask for each published port (UDP, and the number), in the
/// store's order.
fn published(shared: &Shared) -> BTreeMap<(bool, u16), Vec<Asker>> {
    let mut asked = Vec::new();
    {
        let state = shared.store.lock().expect("nothing panics holding the store");
        for resource in ["Workload", "Job"]
            .into_iter()
            .flat_map(|kind| state.store.list(Some(kind)))
        {
            let Ok((template, replicas)) = crate::controller::template_of(resource) else {
                continue;
            };
            let ports = template
                .containers()
                .flat_map(|c| &c.ports)
                .filter(|p| p.publish == Some(true));
            let udp = |p: &kith_api::kinds::Port| p.protocol == Some(kith_api::kinds::Protocol::Udp);
            let ports: Vec<(bool, u16)> = ports.map(|p| (udp(p), p.port)).collect();
            if template.pod == Some(true) && !ports.is_empty() {
                let key = resource.key();
                let namespace = resource.metadata.namespace.clone().unwrap_or_default();
                let ids = (0..replicas).map(|replica| crate::controller::pod_of(&key, replica));
                asked.extend(ids.map(|id| (id, namespace.clone(), ports.clone())));
            }
        }
    }
    let pods = shared.pods.lock().expect("nothing panics holding the pods");
    let mut wanted: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for (id, namespace, ports) in asked {
        let Some(pod) = pods.made.get(&id) else { continue };
        for port in ports {
            wanted
                .entry(port)
                .or_default()
                .push((id.clone(), pod.number, namespace.clone()));
        }
    }
    wanted
}

/// Pass what comes to `port` of this node on to the pod `id` (of `number`), until told to stop.
async fn relay(shared: Arc<Shared>, (id, number): (String, u16), (udp, port): (bool, u16)) {
    let at = std::net::SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    // To the pod's own address, never its loopback: what it lets in from 127.0.0.1 alone
    // (as only its own) is not let in from the LAN. (From inside the pod, by its
    // loopback link: no rule of an exit's is passed.)
    let own = kith_mesh::pod::addresses(range(), None, number).0;
    let mut said = false;
    loop {
        let done = match udp {
            true => {
                let (shared, id) = (shared.clone(), id.clone());
                let to_pod = move || {
                    inside(&shared, &id, || {
                        let socket = std::net::UdpSocket::bind((own, 0))?;
                        socket.connect((own, port))?;
                        Ok(socket)
                    })
                };
                datagrams(at, &RELAYED, to_pod).await
            }
            false => {
                let (shared, id) = (shared.clone(), id.clone());
                let to_pod = move || inside(&shared, &id, TcpSocket::new_v4);
                connections(at, (own, port).into(), (FIRST, IDLE), &RELAYED, to_pod).await
            }
        };
        if let Err(e) = done
            && !std::mem::replace(&mut said, true)
        {
            eprintln!("kithd: pod {id}: publishing port {port}: {e}; tried again every two seconds");
        }
        // (The port's last relay, stopped a moment ago, may hold it yet; or something not
        // kithd's does.)
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// The connections, or senders, each published port has of its own: however many another
/// port's clients hold, these are its.
const OWN: usize = 2;

/// The connections and senders all of a node's published ports share, past their own: a
/// connection holds two files, a sender one, so with [`PORTS`] listeners and their own the
/// relays hold 448 files at most. kithd never raises RLIMIT_NOFILE (1024), and its
/// listeners, these relays, its API and ingress all take of it.
static RELAYED: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(64);

/// A connection's or a sender's room: of its port's own, or of the node's.
type Room = Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::SemaphorePermit<'static>>;

/// Room of the port's `own` first, else of the `node`'s; none, if neither has any.
fn room_of(own: &Arc<tokio::sync::Semaphore>, node: &'static tokio::sync::Semaphore) -> Option<Room> {
    let own = own.clone().try_acquire_owned().map(Ok);
    own.or_else(|_| node.try_acquire().map(Err)).ok()
}

/// How long a connection of a published port is given to reach the pod, and then for the
/// first bytes either way, before [`IDLE`] applies: one that says nothing holds no room long.
const FIRST: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a connection of a published port is kept with nothing passed either way.
const IDLE: std::time::Duration = std::time::Duration::from_secs(600);

/// Pass each connection to `at` on to `to` through a socket `to_pod` makes, each given
/// `first`, then `idle` (see [`FIRST`]), and room of `node`'s past the port's own.
async fn connections(
    at: std::net::SocketAddr,
    to: std::net::SocketAddr,
    (first, idle): (std::time::Duration, std::time::Duration),
    node: &'static tokio::sync::Semaphore,
    to_pod: impl Fn() -> std::io::Result<TcpSocket> + Clone + Send + 'static,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(at).await?;
    let own = Arc::new(tokio::sync::Semaphore::new(OWN));
    // (Each connection's task is this one's: ended with it, as the port is unpublished.)
    let mut passing = tokio::task::JoinSet::new();
    loop {
        while passing.try_join_next().is_some() {}
        let Ok((from, _)) = listener.accept().await else {
            // (Out of files for now, say: a moment later.)
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        };
        // (No room, of the port's own or the node's: this one is ended at once, and none
        // waits on another port's clients.)
        let Some(room) = room_of(&own, node) else { continue };
        let to_pod = to_pod.clone();
        passing.spawn(async move {
            let _room = room;
            // (Made in the pod's namespace, by a thread of its own: not this task's.)
            let socket = tokio::task::spawn_blocking(to_pod).await;
            if let Ok(Ok(socket)) = socket
                && let Ok(Ok(to)) = tokio::time::timeout(first, socket.connect(to)).await
            {
                pass(from, to, first, idle).await;
            }
        });
    }
}

/// Pass bytes both ways between `a` and `b`, and each one's end to the other, until both
/// have ended, one fails, or nothing has passed for `first` (before any byte has), then `idle`.
async fn pass(mut a: TcpStream, mut b: TcpStream, first: std::time::Duration, idle: std::time::Duration) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut a_read, mut a_write) = a.split();
    let (mut b_read, mut b_write) = b.split();
    let (mut a_open, mut b_open) = (true, true);
    let (mut of_a, mut of_b) = (vec![0; 16 << 10], vec![0; 16 << 10]);
    let mut quiet = first;
    while a_open || b_open {
        let read = tokio::time::timeout(quiet, async {
            tokio::select! {
                read = a_read.read(&mut of_a), if a_open => (true, read),
                read = b_read.read(&mut of_b), if b_open => (false, read),
            }
        });
        let Ok((from_a, read)) = read.await else {
            return;
        };
        let (buffer, write, open) = match from_a {
            true => (&of_a, &mut b_write, &mut a_open),
            false => (&of_b, &mut a_write, &mut b_open),
        };
        let passed = match read {
            Ok(0) => {
                *open = false;
                write.shutdown().await
            }
            Ok(length) => {
                quiet = idle;
                tokio::time::timeout(idle, write.write_all(&buffer[..length]))
                    .await
                    .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))
            }
            Err(e) => Err(e),
        };
        if passed.is_err() {
            return;
        }
    }
}

/// Pass each datagram to `at` on through a socket `to_pod` makes, one per sender (as many
/// as the port has room for, of its own and of `node`'s), and its answers back.
async fn datagrams(
    at: std::net::SocketAddr,
    node: &'static tokio::sync::Semaphore,
    to_pod: impl Fn() -> std::io::Result<std::net::UdpSocket> + Clone + Send + 'static,
) -> std::io::Result<()> {
    let outside = Arc::new(tokio::net::UdpSocket::bind(at).await?);
    let own = Arc::new(tokio::sync::Semaphore::new(OWN));
    // Per sender, a socket of the pod's own, which takes the answers back to it, when it was
    // last heard from, and its room. (Its task is this one's: stopped with it, which lets
    // go of the port at once.)
    type Sender = (Arc<tokio::net::UdpSocket>, tokio::task::AbortHandle, u64, Room);
    let mut senders: BTreeMap<std::net::SocketAddr, Sender> = BTreeMap::new();
    let mut answering = tokio::task::JoinSet::new();
    let mut buffer = vec![0; 65_536];
    for heard in 0_u64..=u64::MAX {
        let Ok((length, from)) = outside.recv_from(&mut buffer).await else {
            // (The socket's error: not asked again at once.)
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            continue;
        };
        while answering.try_join_next().is_some() {}
        senders.retain(|_, (_, answers, _, _)| !answers.is_finished());
        let inner = match senders.get_mut(&from) {
            Some((inner, _, last, _)) => {
                *last = heard;
                inner.clone()
            }
            None => {
                // (No room, of the port's own or the node's: the sender of this port heard
                // from longest ago is forgotten, not this one.)
                let room = loop {
                    if let Some(room) = room_of(&own, node) {
                        break Some(room);
                    }
                    let oldest = senders.iter().min_by_key(|(_, sender)| sender.2).map(|(at, _)| *at);
                    match oldest.and_then(|oldest| senders.remove(&oldest)) {
                        Some((_, answers, _, _)) => answers.abort(),
                        None => break None,
                    }
                };
                let Some(room) = room else { continue };
                // (Made in the pod's namespace, by a thread of its own: not this task's.)
                let made = tokio::task::spawn_blocking(to_pod.clone()).await;
                let made = made.map_err(std::io::Error::other).and_then(|made| made);
                let made = made.and_then(|socket| socket.set_nonblocking(true).map(|()| socket));
                let Ok(inner) = made.and_then(tokio::net::UdpSocket::from_std) else {
                    continue;
                };
                let inner = Arc::new(inner);
                let (back, outside) = (inner.clone(), outside.clone());
                // (A sender heard nothing from for a minute is forgotten.)
                let answers = answering.spawn(async move {
                    let mut buffer = vec![0; 65_536];
                    let quiet = std::time::Duration::from_secs(60);
                    while let Ok(Ok(length)) = tokio::time::timeout(quiet, back.recv(&mut buffer)).await {
                        let _ = outside.send_to(&buffer[..length], from).await;
                    }
                });
                senders.insert(from, (inner.clone(), answers, heard, room));
                inner
            }
        };
        let _ = inner.send(&buffer[..length]).await;
    }
    Ok(())
}

/// This node's DNS for its pods, from the first pod on: at the address every pod is told.
pub async fn names(
    shared: Arc<Shared>,
    upstreams: watch::Receiver<Vec<std::net::SocketAddr>>,
    mut stopping: watch::Receiver<bool>,
) {
    let up = shared.pods.lock().expect("nothing panics holding the pods").up.clone();
    tokio::select! {
        () = up.notified() => {}
        _ = stopping.changed() => return,
    }
    match crate::dns::bind((range().gateway(), 53).into()).await {
        Ok(sockets) => crate::dns::run(shared, sockets, upstreams, stopping).await,
        // (A `--dns` on every address has this one too.)
        Err(e) => eprintln!("kithd: no DNS of the pods' own: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A port kithd serves on itself on this node is not published, whichever pod asks,
    /// and the log says which and why.
    #[test]
    fn a_port_kithd_serves_on_is_not_published() {
        let pod = |id: &str, number| (id.to_string(), number, "n".to_string());
        let mut wanted = BTreeMap::from([
            ((false, 8443), vec![pod("a", 2)]),
            ((true, 6881), vec![pod("b", 3)]),
            ((true, 1023), vec![pod("c", 4)]),
        ]);
        let refused = refuse_own(&mut wanted, &[(8443, "API"), (5353, "DNS")]);
        assert_eq!(wanted.into_keys().collect::<Vec<_>>(), [(true, 6881)]);
        assert_eq!(refused.len(), 2);
        assert!(
            refused[0].contains("pod a: port 8443") && refused[0].contains("API"),
            "{}",
            refused[0]
        );
        assert!(
            refused[1].contains("pod c: port 1023") && refused[1].contains("below 1024"),
            "{}",
            refused[1]
        );
    }

    /// A port a pod has stays its own while it asks, whichever pod comes to ask for it too
    /// (another namespace's, sorted first, among them); one made again with another number
    /// keeps it, at its new address; and a node publishes [`PORTS`] at most, those it has first.
    #[test]
    fn a_published_port_stays_with_the_pod_that_has_it() {
        let pod = |id: &str, number| (id.to_string(), number, id[..1].to_string());
        let mut refused = Vec::new();
        let asked = BTreeMap::from([((false, 8080), vec![pod("a/x-0", 2), pod("b/y-0", 3)])]);
        let held = BTreeMap::from([((false, 8080), pod("b/y-0", 3))]);
        let wanted = chosen(asked, &held, &mut refused);
        assert_eq!(wanted[&(false, 8080)], pod("b/y-0", 3));
        assert!(refused[0].contains("pod a/x-0: port 8080") && refused[0].contains("pod b/y-0"));
        // (Made again, as number 5: the same pod, at its new address.)
        let asked = BTreeMap::from([((false, 8080), vec![pod("a/x-0", 2), pod("b/y-0", 5)])]);
        assert_eq!(chosen(asked, &held, &mut refused)[&(false, 8080)], pod("b/y-0", 5));
        // (Gone: the next asks for it has it.)
        let asked = BTreeMap::from([((false, 8080), vec![pod("a/x-0", 2)])]);
        assert_eq!(chosen(asked, &held, &mut refused)[&(false, 8080)], pod("a/x-0", 2));
        // At most PORTS: the one held is kept over one before it.
        let mut asked: BTreeMap<_, _> = (0..=PORTS as u16)
            .map(|n| ((false, 2000 + n), vec![pod("p", 2)]))
            .collect();
        asked.insert((true, 9000), vec![pod("q", 3)]);
        let held = BTreeMap::from([((true, 9000), pod("q", 3))]);
        refused.clear();
        let wanted = chosen(asked, &held, &mut refused);
        assert_eq!(wanted.len(), PORTS);
        assert!(wanted.contains_key(&(true, 9000)));
        assert_eq!(refused.len(), 2, "{refused:?}");
        assert!(refused.iter().all(|why| why.contains("ports at most")), "{refused:?}");
    }

    /// A port no pod has (kithd started again, say) is published for none where pods of two
    /// namespaces ask for it, whatever wrote them; a namespace whose pod had it keeps it for
    /// another pod of its own, over another namespace's.
    #[test]
    fn a_port_two_namespaces_ask_for_is_kept_or_none_has_it() {
        let pod = |id: &str, number| (id.to_string(), number, id[..1].to_string());
        let mut refused = Vec::new();
        let asked = || BTreeMap::from([((false, 8080), vec![pod("a/x-0", 2), pod("b/y-0", 3)])]);
        assert!(chosen(asked(), &BTreeMap::new(), &mut refused).is_empty());
        assert_eq!(refused.len(), 2, "{refused:?}");
        assert!(
            refused.iter().all(|why| why.contains("more than one namespace")),
            "{refused:?}"
        );
        // (Its pod gone, another of its namespace has it.)
        let held = BTreeMap::from([((false, 8080), pod("b/z-0", 4))]);
        assert_eq!(chosen(asked(), &held, &mut refused)[&(false, 8080)], pod("b/y-0", 3));
    }

    /// A port another namespace's Workload or Job publishes is refused at apply; one of the
    /// same namespace, or the other protocol's, is not.
    #[test]
    fn a_port_of_another_namespace_is_refused() {
        let workload = |namespace: &str, name: &str, port: serde_json::Value| -> kith_api::Resource {
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kith.dev/v1", "kind": "Workload", "metadata": {"name": name, "namespace": namespace},
                "spec": {"template": {"pod": true, "containers": [{"name": "c", "image": "x", "ports": [port]}]}},
            }))
            .unwrap()
        };
        let tcp = serde_json::json!({"port": 8080, "publish": true});
        let udp = serde_json::json!({"port": 8080, "protocol": "udp", "publish": true});
        let mut store = kith_api::store::Store::default();
        store.apply(workload("media", "web", tcp.clone())).unwrap();
        let refused = unshared(&store, &[workload("other", "web", tcp.clone())]).unwrap_err();
        assert!(refused.ends_with("TCP port 8080 is not available"), "{refused}");
        unshared(&store, &[workload("media", "second", tcp.clone())]).unwrap();
        unshared(&store, &[workload("other", "web", udp)]).unwrap();
        // (In one apply too; and the stored one changed by it is not counted.)
        let both = [workload("a", "x", tcp.clone()), workload("b", "x", tcp.clone())];
        assert!(unshared(&kith_api::store::Store::default(), &both).is_err());
        let moved = serde_json::json!({"port": 8081, "publish": true});
        unshared(
            &store,
            &[workload("media", "web", moved), workload("other", "web", tcp)],
        )
        .unwrap();
    }

    /// A node's room of its own for its tests' relays, of `room` connections or senders.
    fn node(room: usize) -> &'static tokio::sync::Semaphore {
        Box::leak(Box::new(tokio::sync::Semaphore::new(room)))
    }

    /// An echo server standing for a pod's UDP port, and a relay of it at a free port, with
    /// room of `node`'s past its own.
    fn udp_relay(
        node: &'static tokio::sync::Semaphore,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<std::io::Result<()>>) {
        let pod = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let pod_at = pod.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buffer = [0; 64];
            while let Ok((length, from)) = pod.recv_from(&mut buffer) {
                let _ = pod.send_to(&buffer[..length], from);
            }
        });
        let at = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap();
        let to_pod = move || {
            let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
            socket.connect(pod_at).map(|()| socket)
        };
        (at, tokio::spawn(datagrams(at, node, to_pod)))
    }

    /// Whether `sender`'s datagrams to `at` are answered, asked again for up to two seconds.
    async fn answered(sender: &tokio::net::UdpSocket, at: std::net::SocketAddr) -> bool {
        let mut buffer = [0; 64];
        let asking = async {
            loop {
                sender.send_to(b"hello", at).await.unwrap();
                let wait = std::time::Duration::from_millis(200);
                if let Ok(Ok(length)) = tokio::time::timeout(wait, sender.recv(&mut buffer)).await {
                    return length;
                }
            }
        };
        let length = tokio::time::timeout(std::time::Duration::from_secs(2), asking).await;
        length.is_ok_and(|length| &buffer[..length] == b"hello")
    }

    /// With the table of senders full, a new one is answered: the one heard from longest ago
    /// is forgotten for it (else a few spoofed senders would shut the port to everyone).
    #[tokio::test]
    async fn a_new_udp_sender_takes_the_place_of_the_oldest() {
        let (at, relay) = udp_relay(node(0));
        let mut senders = Vec::new();
        for _ in 0..=OWN {
            let sender = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            assert!(answered(&sender, at).await, "sender {} is answered", senders.len());
            senders.push(sender);
        }
        relay.abort();
    }

    /// A TCP echo server standing for a pod's port, and a relay of it at a free port whose
    /// connections end after `first`, then `idle`, with nothing passed, with room of `node`'s.
    async fn tcp_relay(
        first: std::time::Duration,
        idle: std::time::Duration,
        node: &'static tokio::sync::Semaphore,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<std::io::Result<()>>) {
        let pod = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let pod_at = pod.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = pod.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let at = listener.local_addr().unwrap();
        drop(listener);
        let times = (first, idle);
        (
            at,
            tokio::spawn(connections(at, pod_at, times, node, TcpSocket::new_v4)),
        )
    }

    /// Connect to `at`, tried again while the relay starts.
    async fn connected(at: std::net::SocketAddr) -> TcpStream {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match TcpStream::connect(at).await {
                Ok(stream) => return stream,
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(e) => panic!("{at}: {e}"),
            }
        }
    }

    /// Connect to `at` and see one line echoed.
    async fn echoed(at: std::net::SocketAddr) -> TcpStream {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = connected(at).await;
        stream.write_all(b"hello").await.unwrap();
        let mut buffer = [0; 5];
        stream.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"hello");
        stream
    }

    /// Whether `stream` is ended by the other side within two seconds.
    async fn ended(stream: &mut TcpStream) -> bool {
        use tokio::io::AsyncReadExt;
        let mut buffer = [0; 8];
        let read = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buffer)).await;
        matches!(read, Ok(Ok(0) | Err(_)))
    }

    /// A port unpublished (its relay stopped) ends the connections it passed on, too.
    #[tokio::test]
    async fn a_connection_ends_when_its_port_is_unpublished() {
        let (at, relay) = tcp_relay(FIRST, IDLE, node(1)).await;
        let mut stream = echoed(at).await;
        relay.abort();
        let _ = relay.await;
        assert!(ended(&mut stream).await, "the connection outlived its relay");
    }

    /// A connection nothing passes on for its idle time is ended (and its room given back).
    #[tokio::test]
    async fn an_idle_connection_ends() {
        let (at, relay) = tcp_relay(FIRST, std::time::Duration::from_millis(300), node(1)).await;
        let mut stream = echoed(at).await;
        assert!(ended(&mut stream).await, "the idle connection was kept");
        relay.abort();
    }

    /// A connection that says nothing, nor its pod, is ended after the short time it is
    /// given, not the long one of one that has.
    #[tokio::test]
    async fn a_silent_connection_ends_soon() {
        let (at, relay) = tcp_relay(std::time::Duration::from_millis(300), IDLE, node(1)).await;
        let mut stream = connected(at).await;
        assert!(ended(&mut stream).await, "the silent connection was kept");
        // (One that has said something is kept past it.)
        let mut stream = echoed(at).await;
        assert!(
            !ended(&mut stream).await,
            "a connection was ended as silent after its first bytes"
        );
        relay.abort();
    }

    /// Clients that fill one published port, its own room and all the node's, leave another
    /// port its own: it still answers, and the next client of the full one is ended at once.
    #[tokio::test]
    async fn a_full_port_leaves_another_its_own() {
        let node = node(1);
        let (full, full_relay) = tcp_relay(FIRST, IDLE, node).await;
        let (other, other_relay) = tcp_relay(FIRST, IDLE, node).await;
        let mut held = Vec::new();
        for _ in 0..=OWN {
            held.push(echoed(full).await);
        }
        let mut turned_away = connected(full).await;
        assert!(ended(&mut turned_away).await, "a connection past all the room was kept");
        echoed(other).await;
        full_relay.abort();
        other_relay.abort();
    }

    /// A published UDP port stopped (its pod gone) is free at once for the pod made again,
    /// though a sender's answers were still awaited.
    #[tokio::test]
    async fn a_udp_port_stopped_is_free_at_once() {
        let (at, relay) = udp_relay(node(1));
        let sender = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        assert!(answered(&sender, at).await);
        relay.abort();
        let _ = relay.await;
        tokio::net::UdpSocket::bind(at)
            .await
            .expect("the port is free once its relay is stopped");
    }
}
