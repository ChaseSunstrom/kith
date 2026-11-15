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
        if self.made.is_empty() {
            let guarded = kith_mesh::pod::node(Path::new(GUARDED).exists(), &self.mesh).map_err(failed)?;
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
            let numbers = match exit {
                Some(_) => kith_mesh::exit::PODS,
                None => kith_mesh::pod::NUMBERS,
            };
            let number = numbers.into_iter().find(|number| !taken.contains(number));
            let number = number.ok_or("this node has no number left for another pod")?;
            let (v4, v6) = kith_mesh::pod::addresses(net, number);
            let address = v6.map_or(IpAddr::V4(v4), IpAddr::V6);
            let dir = state.join("pods").join(id);
            let gateway = kith_mesh::pod::GATEWAY;
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
            let namespace = kith_mesh::pod::make(number, v6, tunnel).map_err(failed)?;
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
        let v4 = IpAddr::V4(kith_mesh::pod::addresses(None, pod.number).0);
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
/// the pod's own loopback, until the pod goes or stops publishing it. No rule of the
/// kernel's is made for it (nothing is passed on that kithd did not take).
//
// ponytail: the first pod of this node to publish a port has it; another that asks for it
// waits for that one to go, and says nothing of it but kithd's log.
pub async fn publish(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let mut generation = shared.generation.subscribe();
    let mut open: BTreeMap<(bool, u16), (String, tokio::task::JoinHandle<()>)> = BTreeMap::new();
    loop {
        let wanted = published(&shared);
        open.retain(|port, (id, task)| {
            let kept = wanted.get(port) == Some(id);
            if !kept {
                task.abort();
            }
            kept
        });
        for (port, id) in wanted {
            open.entry(port).or_insert_with(|| (id.clone(), tokio::spawn(relay(shared.clone(), id, port))));
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
    let done = match udp {
        true => datagrams(&shared, &id, at).await,
        false => connections(&shared, &id, at).await,
    };
    if let Err(e) = done {
        eprintln!("kithd: pod {id}: publishing port {port}: {e}");
    }
    // (Not tried again until the pod, or what it publishes, changes.)
    std::future::pending::<()>().await
}

/// At most this many connections, or senders, a published port at once.
const AT_ONCE: usize = 512;

async fn connections(shared: &Arc<Shared>, id: &str, at: std::net::SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(at).await?;
    let room = Arc::new(tokio::sync::Semaphore::new(AT_ONCE));
    loop {
        let Ok(held) = room.clone().acquire_owned().await else {
            return Ok(());
        };
        let Ok((mut from, _)) = listener.accept().await else {
            // (Out of files for now, say: a moment later.)
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        };
        let (shared, id, port) = (shared.clone(), id.to_string(), at.port());
        tokio::spawn(async move {
            let to = match inside(&shared, &id, TcpSocket::new_v4) {
                Ok(socket) => socket.connect((Ipv4Addr::LOCALHOST, port).into()).await,
                Err(e) => Err(e),
            };
            if let Ok(mut to) = to {
                let _ = tokio::io::copy_bidirectional(&mut from, &mut to).await;
            }
            drop(held);
        });
    }
}

async fn datagrams(shared: &Arc<Shared>, id: &str, at: std::net::SocketAddr) -> std::io::Result<()> {
    let outside = Arc::new(tokio::net::UdpSocket::bind(at).await?);
    // Per sender, a socket of the pod's own, which takes the answers back to it.
    let mut senders: BTreeMap<std::net::SocketAddr, (Arc<tokio::net::UdpSocket>, tokio::task::JoinHandle<()>)> =
        BTreeMap::new();
    let mut buffer = vec![0; 65_536];
    loop {
        let Ok((length, from)) = outside.recv_from(&mut buffer).await else {
            continue;
        };
        senders.retain(|_, (_, answers)| !answers.is_finished());
        let inner = match senders.get(&from) {
            Some((inner, _)) => inner.clone(),
            None if senders.len() >= AT_ONCE => continue,
            None => {
                let made = inside(shared, id, || {
                    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
                    socket.connect((Ipv4Addr::LOCALHOST, at.port()))?;
                    socket.set_nonblocking(true).map(|()| socket)
                });
                let Ok(inner) = made.and_then(tokio::net::UdpSocket::from_std) else {
                    continue;
                };
                let inner = Arc::new(inner);
                let (back, outside) = (inner.clone(), outside.clone());
                // (A sender heard nothing from for a minute is forgotten.)
                let answers = tokio::spawn(async move {
                    let mut buffer = vec![0; 65_536];
                    let quiet = std::time::Duration::from_secs(60);
                    while let Ok(Ok(length)) = tokio::time::timeout(quiet, back.recv(&mut buffer)).await {
                        let _ = outside.send_to(&buffer[..length], from).await;
                    }
                });
                senders.insert(from, (inner.clone(), answers));
                inner
            }
        };
        let _ = inner.send(&buffer[..length]).await;
    }
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
    match crate::dns::bind((kith_mesh::pod::GATEWAY, 53).into()).await {
        Ok(sockets) => crate::dns::run(shared, sockets, upstreams, stopping).await,
        // (A `--dns` on every address has this one too.)
        Err(e) => eprintln!("kithd: no DNS of the pods' own: {e}"),
    }
}
