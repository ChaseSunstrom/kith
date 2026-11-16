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
// ponytail: the first pod of this node to publish a port has it; another that asks for it
// waits for that one to go, and says nothing of it but kithd's log.
pub async fn publish(shared: Arc<Shared>, own: Vec<(u16, &'static str)>, mut stopping: watch::Receiver<bool>) {
    let mut generation = shared.generation.subscribe();
    let mut open: BTreeMap<(bool, u16), (String, tokio::task::JoinHandle<()>)> = BTreeMap::new();
    let mut said = std::collections::BTreeSet::new();
    loop {
        let mut wanted = published(&shared);
        for refused in refuse_own(&mut wanted, &own) {
            if said.insert(refused.clone()) {
                eprintln!("{refused}");
            }
        }
        open.retain(|port, (id, task)| {
            let kept = wanted.get(port) == Some(id);
            if !kept {
                task.abort();
            }
            kept
        });
        for (port, id) in wanted {
            open.entry(port)
                .or_insert_with(|| (id.clone(), tokio::spawn(relay(shared.clone(), id, port))));
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
fn refuse_own(wanted: &mut BTreeMap<(bool, u16), String>, own: &[(u16, &str)]) -> Vec<String> {
    let mut refused = Vec::new();
    wanted.retain(|&(_, port), id| {
        let why = match own.iter().find(|(served, _)| *served == port) {
            Some((_, what)) => format!("kithd serves its {what} on it at this node"),
            None if port < 1024 => "those below 1024 are the node's".to_string(),
            None => return true,
        };
        refused.push(format!("kithd: pod {id}: port {port} is not published: {why}"));
        false
    });
    refused
}

/// Which pod of this node each published port (UDP, and the number) goes to.
fn published(shared: &Shared) -> BTreeMap<(bool, u16), String> {
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
                let ids = (0..replicas).map(|replica| crate::controller::pod_of(&key, replica));
                asked.extend(ids.map(|id| (id, ports.clone())));
            }
        }
    }
    let pods = shared.pods.lock().expect("nothing panics holding the pods");
    let mut wanted = BTreeMap::new();
    for (id, ports) in asked.into_iter().filter(|(id, _)| pods.made.contains_key(id)) {
        for port in ports {
            wanted.entry(port).or_insert_with(|| id.clone());
        }
    }
    wanted
}

/// Pass what comes to `port` of this node on to the pod `id`, until told to stop.
async fn relay(shared: Arc<Shared>, id: String, (udp, port): (bool, u16)) {
    let at = std::net::SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    let mut said = false;
    loop {
        // To the pod's own address, never its loopback: what it lets in from 127.0.0.1 alone
        // (as only its own) is not let in from the LAN. (From inside the pod, by its
        // loopback link: no rule of an exit's is passed.)
        let own = {
            let pods = shared.pods.lock().expect("nothing panics holding the pods");
            pods.made
                .get(&id)
                .map(|pod| kith_mesh::pod::addresses(range(), None, pod.number).0)
        };
        let done = match (own, udp) {
            (None, _) => Err(std::io::Error::other("the pod is not on this node")),
            (Some(own), true) => {
                let to_pod = || {
                    inside(&shared, &id, || {
                        let socket = std::net::UdpSocket::bind((own, 0))?;
                        socket.connect((own, port))?;
                        Ok(socket)
                    })
                };
                datagrams(at, AT_ONCE, to_pod).await
            }
            (Some(own), false) => {
                let to_pod = || inside(&shared, &id, TcpSocket::new_v4);
                connections(at, (own, port).into(), IDLE, to_pod).await
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

/// At most this many connections, or senders, a published port at once.
const AT_ONCE: usize = 512;

/// How long a connection of a published port is kept with nothing passed either way.
const IDLE: std::time::Duration = std::time::Duration::from_secs(600);

/// Pass each connection to `at` on to `to` through a socket `to_pod` makes.
async fn connections(
    at: std::net::SocketAddr,
    to: std::net::SocketAddr,
    idle: std::time::Duration,
    to_pod: impl Fn() -> std::io::Result<TcpSocket>,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(at).await?;
    let room = Arc::new(tokio::sync::Semaphore::new(AT_ONCE));
    // (Each connection's task is this one's: ended with it, as the port is unpublished.)
    let mut passing = tokio::task::JoinSet::new();
    loop {
        while passing.try_join_next().is_some() {}
        let Ok(held) = room.clone().acquire_owned().await else {
            return Ok(());
        };
        let Ok((from, _)) = listener.accept().await else {
            // (Out of files for now, say: a moment later.)
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        };
        let socket = to_pod();
        passing.spawn(async move {
            let _held = held;
            if let Ok(socket) = socket
                && let Ok(Ok(to)) = tokio::time::timeout(idle, socket.connect(to)).await
            {
                pass(from, to, idle).await;
            }
        });
    }
}

/// Pass bytes both ways between `a` and `b`, and each one's end to the other, until both
/// have ended, one fails, or nothing has passed for `idle`.
async fn pass(mut a: TcpStream, mut b: TcpStream, idle: std::time::Duration) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut a_read, mut a_write) = a.split();
    let (mut b_read, mut b_write) = b.split();
    let (mut a_open, mut b_open) = (true, true);
    let (mut of_a, mut of_b) = (vec![0; 16 << 10], vec![0; 16 << 10]);
    while a_open || b_open {
        let read = tokio::time::timeout(idle, async {
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
            Ok(length) => tokio::time::timeout(idle, write.write_all(&buffer[..length]))
                .await
                .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into())),
            Err(e) => Err(e),
        };
        if passed.is_err() {
            return;
        }
    }
}

/// Pass each datagram to `at` on through a socket `to_pod` makes, one per sender (at most
/// `room`), and its answers back.
async fn datagrams(
    at: std::net::SocketAddr,
    room: usize,
    to_pod: impl Fn() -> std::io::Result<std::net::UdpSocket>,
) -> std::io::Result<()> {
    let outside = Arc::new(tokio::net::UdpSocket::bind(at).await?);
    // Per sender, a socket of the pod's own, which takes the answers back to it, and when it
    // was last heard from. (Its task is this one's: stopped with it, which lets go of the
    // port at once.)
    type Sender = (Arc<tokio::net::UdpSocket>, tokio::task::AbortHandle, u64);
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
        senders.retain(|_, (_, answers, _)| !answers.is_finished());
        let inner = match senders.get_mut(&from) {
            Some((inner, _, last)) => {
                *last = heard;
                inner.clone()
            }
            None => {
                // (Full: the sender heard from longest ago is forgotten, not this one.)
                if senders.len() >= room
                    && let Some(oldest) = senders.iter().min_by_key(|(_, sender)| sender.2).map(|(at, _)| *at)
                    && let Some((_, answers, _)) = senders.remove(&oldest)
                {
                    answers.abort();
                }
                let made = to_pod().and_then(|socket| socket.set_nonblocking(true).map(|()| socket));
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
                senders.insert(from, (inner.clone(), answers, heard));
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
        let mut wanted = BTreeMap::from([
            ((false, 8443), "a".to_string()),
            ((true, 6881), "b".to_string()),
            ((true, 1023), "c".to_string()),
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

    /// An echo server standing for a pod's UDP port, and a relay of it at a free port.
    fn udp_relay(room: usize) -> (std::net::SocketAddr, tokio::task::JoinHandle<std::io::Result<()>>) {
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
        (at, tokio::spawn(datagrams(at, room, to_pod)))
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
        let (at, relay) = udp_relay(2);
        let mut senders = Vec::new();
        for _ in 0..3 {
            let sender = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            assert!(answered(&sender, at).await, "sender {} is answered", senders.len());
            senders.push(sender);
        }
        relay.abort();
    }

    /// A TCP echo server standing for a pod's port, and a relay of it at a free port whose
    /// connections end after `idle` with nothing passed.
    async fn tcp_relay(
        idle: std::time::Duration,
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
        (at, tokio::spawn(connections(at, pod_at, idle, TcpSocket::new_v4)))
    }

    /// Connect to `at` (tried again while the relay starts) and see one line echoed.
    async fn echoed(at: std::net::SocketAddr) -> TcpStream {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut stream = loop {
            match TcpStream::connect(at).await {
                Ok(stream) => break stream,
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(e) => panic!("{at}: {e}"),
            }
        };
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
        let (at, relay) = tcp_relay(std::time::Duration::from_secs(600)).await;
        let mut stream = echoed(at).await;
        relay.abort();
        let _ = relay.await;
        assert!(ended(&mut stream).await, "the connection outlived its relay");
    }

    /// A connection nothing passes on for its idle time is ended (and its room given back).
    #[tokio::test]
    async fn an_idle_connection_ends() {
        let (at, relay) = tcp_relay(std::time::Duration::from_millis(300)).await;
        let mut stream = echoed(at).await;
        assert!(ended(&mut stream).await, "the idle connection was kept");
        relay.abort();
    }

    /// A published UDP port stopped (its pod gone) is free at once for the pod made again,
    /// though a sender's answers were still awaited.
    #[tokio::test]
    async fn a_udp_port_stopped_is_free_at_once() {
        let (at, relay) = udp_relay(AT_ONCE);
        let sender = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        assert!(answered(&sender, at).await);
        relay.abort();
        let _ = relay.await;
        tokio::net::UdpSocket::bind(at)
            .await
            .expect("the port is free once its relay is stopped");
    }
}
