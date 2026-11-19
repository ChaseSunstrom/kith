//! What the root part is asked (docs/adr-privilege.md, "The requests"): one typed list, so
//! that what the serving part may have the root part do is this list and nothing else.
//! [`Root`] is the seam: [`Direct`] does a request in this process, as kithd has always done;
//! the root part as a second process takes the same [`Request`]s over a socket pair, with
//! [`decode`] reading each one. Here are the Listeners family (`Bind`), the Pods family (`Pod`,
//! `Sockets`, [`Root::create`] and [`Root::start`]) and, through the last, what Services and
//! probes connect into a pod by, and the Mesh family (`MeshUp`, `Mesh`, `MeshSeen`, `MeshDown`:
//! the WireGuard interface, its addresses and its peers) and the Images family (`Unpack`, with
//! the layers as files beside the request, and `Drop`: both name a digest, and the path is
//! derived from it here).
//!
//! A request is refused for what it is, never for who asked ([`check`], [`check_create`]): a
//! mount outside the state directory, a device no claim of this node's granted, a network
//! namespace this part did not make, a unit the node's policy has none of.
//!
//! [`Book`] counts what crosses ([`Kind`]): the ADR's table of what a hot path costs is
//! asserted against it (the `crossings` tests).
//
// ponytail: Create and Start take what only this process has (an Image, a Handle): they are
// not in [`Request`], and cross no wire until the root part is a process (T-0810). Said here
// so that they are not taken for a gap in `check`.

use crate::pods::{Given, Pods};
use crate::policy::Policy;
use kith_runtime::{Handle, Image, ImageStore, Mount, Runtime, Unit};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The most a request may be, in bytes (a datagram of the socket pair; bigger things travel
/// as file handles beside it).
pub const MAX_REQUEST: usize = 256 * 1024;

/// The ports kithd serves on itself: its API, the registry and the mesh's WireGuard. The
/// root part refuses to bind them for the serving part, which would otherwise have it take
/// over what it serves.
const OWN_PORTS: [u16; 3] = [7443, 5000, 51820];

/// The most sockets one request for them is for.
const MOST_SOCKETS: u8 = 16;
/// The most name servers a pod's `resolv.conf` is given (the C library reads three).
const MOST_NAMESERVERS: usize = 8;
/// The most layers an image is unpacked from.
const MOST_LAYERS: usize = 256;

/// What a socket is for: only these two, so a request for any other protocol does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

/// One thing the serving part asks of the root part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Request {
    /// A socket bound to `address` and `port`; a tcp one is listening.
    Bind { address: IpAddr, port: u16, proto: Proto },
    /// The pod `id` (of `namespace`, called `hostname`), made if it is not there yet: its
    /// network namespace and its `resolv.conf` and `hosts` (see `Pods::given`).
    Pod {
        id: String,
        namespace: String,
        hostname: String,
        net: Option<std::net::Ipv6Addr>,
        exit: Option<(u16, Vec<Ipv4Addr>)>,
        /// The key of the resource it is a replica of, and what its policies let it reach
        /// (`None`: all), as for `Pods::given`.
        owner: String,
        egress: Option<Vec<kith_mesh::pod::Egress>>,
    },
    /// `count` stream sockets made inside the pod `pod`'s namespace, for connections to its
    /// loopback: one thread and one `setns` for all of them.
    Sockets { pod: String, v6: bool, count: u8 },
    /// The mesh's interface up (made if it is not there), with the node's own `address`: its
    /// private key, port and key file are the root part's own (the Book), and its public key
    /// comes back.
    MeshUp { interface: String, address: Ipv6Addr },
    /// The interface as the serving part wants it: these `peers` and these further `addresses`
    /// (the services'), and no others.
    Mesh {
        interface: String,
        peers: Vec<kith_mesh::Peer>,
        addresses: BTreeSet<Ipv6Addr>,
    },
    /// When each peer last shook hands (a read: it changes nothing).
    MeshSeen { interface: String },
    /// The interface taken away.
    MeshDown { interface: String },
    /// The image `image` (a digest) unpacked, its `manifest` (the text the digest is of) saying
    /// what it is made of; the layer files come beside the request, one for each layer the
    /// manifest names, in order. The store and the path are the root part's: it derives them
    /// (the digest names the one, the state directory the other), takes each layer's digest,
    /// media type and size from the manifest, and hashes each layer as it reads it, which must
    /// be the digest the manifest gives it.
    Unpack { image: String, manifest: String },
    /// The unpacked image `image` (a digest) removed, if it was last used no later than `before`
    /// (seconds since the epoch), no pull holds the store and no container's bundle names it.
    Drop { image: String, before: u64 },
}

/// What a request gives back.
#[derive(Debug)]
pub enum Reply {
    /// The bytes an image's removal freed, or `None` when it stayed.
    Freed(Option<u64>),
    Socket(OwnedFd),
    Sockets(Vec<OwnedFd>),
    Pod(Given),
    /// The public key of the mesh's interface.
    Key(kith_mesh::Key),
    Seen(Vec<kith_mesh::Seen>),
    /// Done, and there is nothing to give back.
    Done,
}

/// A container to make, as the serving part has it made: the unit, what its image is, and
/// where its output goes.
pub struct Create<'a> {
    pub id: &'a str,
    pub image: &'a Image,
    pub unit: &'a Unit,
    pub out: File,
    pub err: File,
}

/// Read one request off the wire: at most [`MAX_REQUEST`] bytes, JSON, no field or variant
/// this build does not know.
// (Nothing reads a wire yet: the root part is not a second process. The tests do.)
#[allow(dead_code)]
pub fn decode(bytes: &[u8]) -> Result<Request, String> {
    if bytes.len() > MAX_REQUEST {
        return Err(format!("request of {} bytes: at most {MAX_REQUEST}", bytes.len()));
    }
    serde_json::from_slice(bytes).map_err(|e| format!("request: {e}"))
}

/// A name that is safe to put in a file's name and a line of a file: letters, digits, `.`,
/// `-` and `_`, not starting with `-` or `.`, no `..`, at most a file name's length.
fn label(what: &str, text: &str) -> Result<(), String> {
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_');
    let whole = !text.is_empty() && text.len() <= 255 && !text.starts_with(['-', '.']) && !text.contains("..");
    match whole && text.chars().all(plain) {
        true => Ok(()),
        false => Err(format!(
            "{what} `{}` is not a name (letters, digits, `.`, `-` and `_`)",
            text.escape_debug()
        )),
    }
}

/// Why a request is refused, or `Ok` when the root part may do it. It looks at what is
/// asked and never at who asks.
pub fn check(request: &Request) -> Result<(), String> {
    match request {
        Request::Bind { address, port, .. } => {
            if OWN_PORTS.contains(port) {
                return Err(format!("port {port} is one kithd serves on itself"));
            }
            if address.is_multicast() {
                return Err(format!("{address} is a multicast address: not an address to listen on"));
            }
            Ok(())
        }
        // (The names go into files, `search` and `hosts` lines among them: a name with a line
        // break would be another line.)
        Request::Pod {
            id,
            namespace,
            hostname,
            exit,
            ..
        } => {
            label("pod id", id)?;
            label("namespace", namespace)?;
            label("hostname", hostname)?;
            match exit {
                Some((_, dns)) if dns.len() > MOST_NAMESERVERS => {
                    Err(format!("{} name servers: at most {MOST_NAMESERVERS}", dns.len()))
                }
                _ => Ok(()),
            }
        }
        Request::Sockets { pod, count, .. } => {
            label("pod id", pod)?;
            match *count {
                1..=MOST_SOCKETS => Ok(()),
                count => Err(format!("{count} sockets: from 1 to {MOST_SOCKETS}")),
            }
        }
        // (Against what the root part was told of the mesh, which is not in the request: [`check_mesh`].)
        Request::MeshUp { .. } | Request::Mesh { .. } | Request::MeshSeen { .. } | Request::MeshDown { .. } => Ok(()),
        // (Digests, and nothing else, become the names of files.)
        Request::Unpack { image, .. } | Request::Drop { image, .. } => digest(image),
    }
}

fn digest(text: &str) -> Result<(), String> {
    kith_runtime::sha256_hex(text).map(drop).map_err(|e| e.to_string())
}

/// What the root part was told of the mesh, once: where its interface is kept, which cluster's
/// it is and what this node is called (so which address is its own, and which /80 is not a
/// peer's). `up` is whether the interface is up with that address, as far as the root part knows.
#[derive(Clone)]
struct MeshTold {
    interface: String,
    port: u16,
    key: PathBuf,
    name: String,
    prefix: Option<Ipv6Addr>,
    up: bool,
}

/// Whether a peer is called where the root part would not have it called: this machine,
/// nowhere, the mesh itself (its packets would be the node's own, or go round the mesh), or no
/// port. Everything else of an endpoint, and the keepalive, is the serving part's to say.
fn endpoint_refused(prefix: Ipv6Addr, endpoint: SocketAddr) -> bool {
    // (An IPv4 address in IPv6's clothes is the IPv4 one.)
    let ip = endpoint.ip().to_canonical();
    endpoint.port() == 0
        || ip.is_loopback()
        || ip.is_unspecified()
        || matches!(ip, IpAddr::V6(a) if kith_mesh::in_mesh(prefix, a))
}

/// Why a mesh request is refused, or `Ok`: what the root part would not have made itself. The
/// interface is the one kith made, the addresses are the cluster's range: this node's alone as
/// its own, services' as addresses, and peers may be allowed the /80s of other nodes and no
/// other address (so no peer gets this node's traffic, or the host's, or another cluster's).
/// One peer that is not right refuses the whole request: nothing is set of it.
fn check_mesh(request: &Request, told: &Option<MeshTold>) -> Result<(), String> {
    let interface = match request {
        Request::MeshUp { interface, .. }
        | Request::Mesh { interface, .. }
        | Request::MeshSeen { interface }
        | Request::MeshDown { interface } => interface,
        _ => return Ok(()),
    };
    let told = told.as_ref().ok_or("this root part was told no mesh")?;
    if *interface != told.interface {
        return Err(format!("{}: not the mesh's interface", interface.escape_debug()));
    }
    let prefix = told
        .prefix
        .ok_or("this root part was told no cluster's range for the mesh")?;
    // (The node's own, from the name it was told: not from what an up said, which is the
    // serving part's to say.)
    let own = kith_mesh::node_address(prefix, &told.name);
    match request {
        Request::MeshUp { address, .. } if *address == own => Ok(()),
        Request::MeshUp { address, .. } => Err(format!(
            "{address}: not this node's address of the mesh {prefix}/{}",
            kith_mesh::MESH_BITS
        )),
        Request::Mesh { peers, addresses, .. } => {
            if !told.up {
                return Err("the mesh is not up".into());
            }
            let mut keys = BTreeSet::new();
            for peer in peers {
                if peer.key == [0; 32] {
                    return Err("a peer's key is not a key".into());
                }
                if !keys.insert(peer.key) {
                    return Err("a peer's key twice: one key is one peer".into());
                }
                if let Some(endpoint) = peer.endpoint.filter(|e| endpoint_refused(prefix, *e)) {
                    return Err(format!("{endpoint}: not an endpoint outside the mesh"));
                }
                for (address, bits) in &peer.allowed {
                    let ok = match address {
                        IpAddr::V6(a) => {
                            *bits == kith_mesh::NODE_BITS
                                && kith_mesh::in_mesh(prefix, *a)
                                && !kith_mesh::is_service_address(prefix, *a)
                                && a.octets()[10..] == [0; 6]
                                && a.octets()[..10] != own.octets()[..10]
                        }
                        IpAddr::V4(_) => false,
                    };
                    if !ok {
                        return Err(format!("{address}/{bits}: not another node's /80 of the mesh"));
                    }
                }
            }
            match addresses.iter().find(|a| !kith_mesh::is_service_address(prefix, **a)) {
                Some(a) => Err(format!("{a}: not a service's address of the mesh")),
                None => Ok(()),
            }
        }
        _ => Ok(()),
    }
}

/// What the root part knows for itself, against which a container to create is checked: not
/// what the serving part says of it.
pub struct Ground {
    /// The state directory the serving part was started with.
    pub state: Option<PathBuf>,
    /// The directory in memory for kithd (`files::memory_dir`).
    pub memory: Option<PathBuf>,
    /// The device nodes the node's claims came to ([`Book::claim`]).
    pub devices: BTreeSet<PathBuf>,
    pub policy: Policy,
    /// Whether this process is root: a pod's network is made only then.
    pub root: bool,
}

/// How many ids a container's user namespace has where kithd is root
/// (`kith_runtime`'s `RANGE`): a user past them is one the runtime refuses.
const RANGE: u32 = 65536;

/// Whether a unit `container` of the pod `pod` is made a mount of `host` (a path as it is,
/// links followed), by what the controller mounts: `Some(true)` of what it gives the unit's
/// user (it made it for the unit, or a volume the unit's workload asks for), `Some(false)` of
/// what the unit only reads, `None` of all else. The state and memory directories hold more
/// than that (the node's keys, other pods' files): none of it is the unit's to mount, and
/// neither is a directory that holds only what is.
///
/// `pod` is the unit's pod (its network's, where `resolv.conf` and `hosts` are) and `replica` the
/// replica's, which keeps its files, scratch and identity: the same but in a rolling update's
/// second generation, whose pod is the replica's with a `b` (`controller::pod_id`) and which
/// mounts what the first does.
fn source(host: &Path, ground: &Ground, pod: &str, replica: &str, container: &str) -> Option<bool> {
    let parts = |base: &Option<PathBuf>| -> Option<Vec<String>> {
        let rest = host.strip_prefix(base.as_ref()?.canonicalize().ok()?).ok()?;
        Some(
            rest.components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect(),
        )
    };
    // (The pod's own, in either directory: a file of a map and a scratch; and in memory its
    // identity's files. The pod's directory itself, in memory, holds its key.)
    let own = |rest: &[&str], identity: bool| match rest {
        ["replicas", p, "files", c, _, ..] => (p, c) == (&replica, &container),
        ["replicas", p, "identity", c, ..] => identity && (p, c) == (&replica, &container),
        ["replicas", p, "scratch", _, ..] => *p == replica,
        _ => false,
    };
    if let Some(rest) = parts(&ground.state) {
        let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
        return match rest[..] {
            ["volumes", _, _, ..] | ["remote", _, _, _, ..] | ["seats", _, ..] => Some(true),
            ["pods", p, "resolv.conf" | "hosts"] if p == pod => Some(false),
            _ => own(&rest, false).then_some(true),
        };
    }
    let rest = parts(&ground.memory)?;
    let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
    own(&rest, true).then_some(true)
}

fn check_mount(mount: &Mount, ground: &Ground, id: &str) -> Result<(), String> {
    let (host, at) = (&mount.host, &mount.container);
    if !at.starts_with('/') || at.contains('\0') || at.split('/').any(|part| part == "..") {
        return Err(format!("mount at `{}`: not a path in the container", at.escape_debug()));
    }
    let hostpaths = ground.policy.allows("hostPaths");
    let refused = |why: &str| {
        Err(format!(
            "mount of {}: {why} (the state directory is {}; hostPaths is {})",
            host.display(),
            ground
                .state
                .as_ref()
                .map_or("none set".into(), |dir| dir.display().to_string()),
            if hostpaths { "on" } else { "off" }
        ))
    };
    if !host.is_absolute() {
        return refused("not a directory a unit's mounts are made from: it is no absolute path");
    }
    // (Not judged by its text: a path that is not there is made of nothing the root part saw.)
    let Ok(real) = host.canonicalize() else {
        return refused("a path that does not resolve");
    };
    let (pod, container) = id.rsplit_once('_').unwrap_or((id, ""));
    let replica = pod.strip_suffix('b').unwrap_or(pod);
    let given = "not a directory the node gives to a container's user: it may not be given";
    match (source(&real, ground, pod, replica, container), mount.give) {
        (Some(true), _) => Ok(()),
        // (The pod's resolv.conf and hosts are the node's, written for every container in it: one
        // that could write them would answer for the others' names.)
        (Some(false), false) if mount.read_only => Ok(()),
        (Some(false), false) => refused("the pod's own file, mounted read-only or not at all"),
        // (Where the node's policy lets the store name a path, it does: a directory of the host's
        // that an admin named is theirs, and given to no one.)
        (None, false) if hostpaths => Ok(()),
        (Some(false), true) => refused(given),
        (None, true) if hostpaths => refused(given),
        (None, _) => refused("not a directory a unit's mounts are made from"),
    }
}

/// Why a container is not created, or `Ok`: what the root part would not have made itself.
/// `owns`: whether a path is the namespace of a pod this node made.
pub fn check_create(create: &Create, ground: &Ground, owns: &dyn Fn(&Path) -> bool) -> Result<(), String> {
    let (unit, policy) = (create.unit, &ground.policy);
    label("unit id", create.id)?;
    for mount in &unit.mounts {
        check_mount(mount, ground, create.id)?;
    }
    // What is given a user is chowned to it, tree and all, before the runtime looks at the
    // user: where there are ranges (kithd is root, and the runtime shifts this unit: one of its
    // own network, not the host's users, no device), a user past the range is refused here.
    if ground.root
        && unit.netns.is_some()
        && !unit.host_users
        && unit.devices.is_empty()
        && let Some(user) = unit.user.filter(|user| *user >= RANGE)
        && unit.mounts.iter().any(|mount| mount.give)
    {
        return Err(format!(
            "user {user} is past the {RANGE} ids a container's range has: nothing is given it"
        ));
    }
    for device in &unit.devices {
        if !ground.devices.contains(device) {
            return Err(format!(
                "{}: no claim of this node's granted this device",
                device.display()
            ));
        }
    }
    match &unit.netns {
        Some(path) if !owns(path) => {
            return Err(format!("{}: not the network of a pod this node made", path.display()));
        }
        Some(_) => {}
        // (A pod where kithd is not root shares the node's network; where it is, it has its own.)
        None if !unit.as_image || ground.root => {
            if let Some(refusal) = policy.refusal("nodeNetwork") {
                return Err(refusal);
            }
        }
        None => {}
    }
    if let Some(hostname) = &unit.hostname {
        label("hostname", hostname)?;
    }
    if !unit.no_node_root
        && let Some(refusal) = policy.refusal("rootContainers")
    {
        return Err(refusal);
    }
    if (unit.unconfined || !unit.allow.is_empty())
        && let Some(refusal) = policy.refusal("unconfined")
    {
        return Err(refusal);
    }
    Ok(())
}

/// What crossed from the serving part to the root part, and what the root part holds that it
/// was told once: the state directory, and the device nodes the node's claims came to.
pub struct Book {
    state: Mutex<Option<PathBuf>>,
    devices: Mutex<BTreeSet<PathBuf>>,
    mesh: Mutex<Option<MeshTold>>,
    /// Held by a mesh request from its check to its end: one at a time.
    meshing: Mutex<()>,
    crossed: [AtomicUsize; 9],
}

/// What a request is, for counting.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Bind,
    Pod,
    Sockets,
    Create,
    Start,
    /// The mesh's interface, peers and addresses: what changes it (`MeshUp`, `Mesh`, `MeshDown`).
    Mesh,
    /// A read of when the peers shook hands (`MeshSeen`): every pass of the mesh's loop.
    Seen,
    /// An image unpacked (`Unpack`): once per image, and none for one that is here.
    Unpack,
    /// An image removed (`Drop`): the pruning job's.
    Drop,
}

impl Book {
    pub const fn new() -> Book {
        Book {
            state: Mutex::new(None),
            devices: Mutex::new(BTreeSet::new()),
            mesh: Mutex::new(None),
            meshing: Mutex::new(()),
            crossed: [const { AtomicUsize::new(0) }; 9],
        }
    }

    /// The mesh's interface, its WireGuard port, where its private key is kept and this node's
    /// name, as the node was started with them: told once. The same again is nothing; a second
    /// telling that differs is refused (the first is the node's).
    //
    // ponytail: told by the serving part, in this process. When the root part is a process of its
    // own (T-0810) it is given these by its own arguments, which the serving part cannot change.
    pub fn set_mesh(&self, interface: String, port: u16, key: PathBuf, name: String) -> Result<(), String> {
        let mut told = self.mesh.lock().expect("nothing panics holding the book");
        match told.as_ref() {
            Some(had) if (&had.interface, had.port, &had.key, &had.name) != (&interface, port, &key, &name) => {
                Err(format!(
                    "the mesh was told as {} of {} on port {}: not told again as another",
                    had.interface, had.name, had.port
                ))
            }
            Some(_) => Ok(()),
            None => {
                *told = Some(MeshTold {
                    interface,
                    port,
                    key,
                    name,
                    prefix: None,
                    up: false,
                });
                Ok(())
            }
        }
    }

    /// The cluster's /48 (`kith_mesh::prefix` of its CA): the range every address of the mesh is
    /// in. The first told is the cluster's; another is refused.
    //
    // ponytail: told by the serving part, as above. The root part is to work it out of the CA
    // itself (T-0810).
    pub fn set_prefix(&self, prefix: Ipv6Addr) -> Result<(), String> {
        let mut told = self.mesh.lock().expect("nothing panics holding the book");
        let told = told.as_mut().ok_or("this root part was told no mesh")?;
        match told.prefix {
            Some(had) if had != prefix => Err(format!("the mesh is of the cluster {had}/{}", kith_mesh::MESH_BITS)),
            _ => {
                told.prefix = Some(prefix);
                Ok(())
            }
        }
    }

    /// The state directory, as the node was started with it: the one place a mount may be.
    pub fn set_state(&self, dir: PathBuf) {
        *self.state.lock().expect("nothing panics holding the book") = Some(dir);
    }

    /// The device nodes this node's claims come to now: a container is given these and no others.
    pub fn claim(&self, devices: impl IntoIterator<Item = PathBuf>) {
        *self.devices.lock().expect("nothing panics holding the book") = devices.into_iter().collect();
    }

    /// How many requests of `kind` crossed (refused ones too).
    #[cfg(test)]
    pub fn crossed(&self, kind: Kind) -> usize {
        self.crossed[kind as usize].load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn total(&self) -> usize {
        self.crossed.iter().map(|n| n.load(Ordering::Relaxed)).sum()
    }

    fn count(&self, kind: Kind) {
        self.crossed[kind as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn state(&self) -> Option<PathBuf> {
        self.state.lock().expect("nothing panics holding the book").clone()
    }
}

/// This process's book: what kithd's root part holds, one for the node.
static BOOK: Book = Book::new();

pub fn set_state(dir: PathBuf) {
    BOOK.set_state(dir);
}

pub fn claim(devices: impl IntoIterator<Item = PathBuf>) {
    BOOK.claim(devices);
}

pub fn set_mesh(interface: String, port: u16, key: PathBuf, name: String) -> Result<(), String> {
    BOOK.set_mesh(interface, port, key, name)
}

pub fn set_prefix(prefix: Ipv6Addr) -> Result<(), String> {
    BOOK.set_prefix(prefix)
}

/// This process's mesh interface, once it is up: one per node.
static DEVICE: Mutex<Option<kith_mesh::Device>> = Mutex::new(None);

fn device<T>(then: impl FnOnce(&mut kith_mesh::Device) -> std::io::Result<T>) -> Result<T, String> {
    let mut held = DEVICE.lock().expect("nothing panics holding the device");
    let device = held.as_mut().ok_or("the mesh is not up")?;
    then(device).map_err(|e| e.to_string())
}

/// What the root part does with the machine, for [`Direct`] to ask after it has checked: here
/// the code kithd always had, there (in a test) a stand-in.
pub trait Hands {
    /// What a created container is, until it is started.
    type Made;
    #[allow(clippy::too_many_arguments)]
    fn pod(
        &self,
        state: &Path,
        id: &str,
        namespace: &str,
        hostname: &str,
        net: Option<std::net::Ipv6Addr>,
        exit: Option<(u16, &[Ipv4Addr])>,
        owner: &str,
        egress: Option<Vec<kith_mesh::pod::Egress>>,
    ) -> Result<Given, String>;
    fn sockets(&self, pod: &str, v6: bool, count: usize) -> Result<Vec<OwnedFd>, String>;
    /// Whether `path` is the network namespace of a pod this root part made.
    fn owns_netns(&self, path: &Path) -> bool;
    fn create(&self, create: Create) -> Result<Self::Made, String>;
    /// Written down, then started: it comes back with what refused it, to be deleted.
    fn start(&self, made: Self::Made, id: &str, mark: &str) -> Result<Self::Made, (Self::Made, String)>;

    // The mesh: the node's one WireGuard interface, which is the machine's whatever else these
    // hands are (so these are what they are by default, and a test says another).
    /// The interface `interface` up with the key in `key` (made if there is none) on `port`,
    /// and `address`: its public key.
    fn mesh_up(&self, interface: &str, key: &Path, port: u16, address: Ipv6Addr) -> Result<kith_mesh::Key, String> {
        let private = crate::mesh::private_key(key).map_err(|e| e.to_string())?;
        let mut device = kith_mesh::Device::ensure(interface, &private, port, address).map_err(|e| e.to_string())?;
        let public = device.public_key().map_err(|e| e.to_string())?;
        *DEVICE.lock().expect("nothing panics holding the device") = Some(device);
        Ok(public)
    }
    /// The interface with these peers and these further addresses. Both are tried, and what
    /// failed is said.
    fn mesh(&self, peers: &[kith_mesh::Peer], addresses: &BTreeSet<Ipv6Addr>) -> Result<(), String> {
        let addresses =
            device(|device| device.set_addresses(addresses)).map_err(|e| format!("the services' addresses: {e}"));
        let peers = device(|device| device.set_peers(peers)).map_err(|e| format!("setting the peers: {e}"));
        match (addresses, peers) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(a), Ok(())) | (Ok(()), Err(a)) => Err(a),
            (Err(a), Err(b)) => Err(format!("{a}; {b}")),
        }
    }
    fn mesh_seen(&self) -> Result<Vec<kith_mesh::Seen>, String> {
        device(|device| device.peers())
    }
    fn mesh_down(&self) -> Result<(), String> {
        let device = DEVICE.lock().expect("nothing panics holding the device").take();
        device.ok_or("the mesh is not up")?.remove().map_err(|e| e.to_string())
    }
}

/// The root part, as the serving part sees it.
pub trait Root {
    type Made;
    /// Do `request` if [`check`] allows it.
    fn request(&self, request: Request) -> Result<Reply, String>;
    /// [`Root::request`] with the files that come beside it (the layers of an `Unpack`).
    fn request_with(&self, request: Request, files: Vec<File>) -> Result<Reply, String> {
        match files.is_empty() {
            true => self.request(request),
            false => Err("this root part takes no files beside a request".into()),
        }
    }
    /// Create the container if [`check_create`] allows it.
    fn create(&self, create: Create) -> Result<Self::Made, String>;
    /// Start what [`Root::create`] made; `mark` is what it is started as (`Runtime::record`).
    fn start(&self, made: Self::Made, id: &str, mark: &str) -> Result<Self::Made, (Self::Made, String)>;
}

/// The root part inside this process: today's code, called directly.
pub struct Direct<'a, H: Hands = Nobody> {
    hands: H,
    book: &'a Book,
    /// The node's own policy, unless a test says another.
    policy: Option<Policy>,
}

/// Hands for a Direct that is asked for sockets to listen on, for the mesh and for images, and nothing else.
pub struct Nobody;

impl Hands for Nobody {
    type Made = ();
    fn pod(
        &self,
        _: &Path,
        _: &str,
        _: &str,
        _: &str,
        _: Option<std::net::Ipv6Addr>,
        _: Option<(u16, &[Ipv4Addr])>,
        _: &str,
        _: Option<Vec<kith_mesh::pod::Egress>>,
    ) -> Result<Given, String> {
        Err("this root part makes no pods".into())
    }
    fn sockets(&self, _: &str, _: bool, _: usize) -> Result<Vec<OwnedFd>, String> {
        Err("this root part makes no pods".into())
    }
    fn owns_netns(&self, _: &Path) -> bool {
        false
    }
    fn create(&self, _: Create) -> Result<(), String> {
        Err("this root part makes no containers".into())
    }
    fn start(&self, made: (), _: &str, _: &str) -> Result<(), ((), String)> {
        Err((made, "this root part starts no containers".into()))
    }
}

/// The pods and the runtime of this node.
pub struct Today<'a> {
    pods: &'a Mutex<Pods>,
    runtime: Option<&'a Runtime>,
}

impl Hands for Today<'_> {
    type Made = Handle;

    fn pod(
        &self,
        state: &Path,
        id: &str,
        namespace: &str,
        hostname: &str,
        net: Option<std::net::Ipv6Addr>,
        exit: Option<(u16, &[Ipv4Addr])>,
        owner: &str,
        egress: Option<Vec<kith_mesh::pod::Egress>>,
    ) -> Result<Given, String> {
        let mut pods = self.pods.lock().expect("nothing panics holding the pods");
        pods.given(state, id, namespace, hostname, net, exit, owner, egress)
    }

    fn sockets(&self, pod: &str, v6: bool, count: usize) -> Result<Vec<OwnedFd>, String> {
        let pods = self.pods.lock().expect("nothing panics holding the pods");
        pods.sockets(pod, v6, count)
    }

    fn owns_netns(&self, path: &Path) -> bool {
        self.pods
            .lock()
            .expect("nothing panics holding the pods")
            .owns_netns(path)
    }

    fn create(&self, create: Create) -> Result<Handle, String> {
        let runtime = self.runtime.ok_or("this root part has no runtime")?;
        let Create {
            id,
            image,
            unit,
            out,
            err,
        } = create;
        runtime.create(id, image, unit, out, err).map_err(|e| e.to_string())
    }

    fn start(&self, mut made: Handle, id: &str, mark: &str) -> Result<Handle, (Handle, String)> {
        let Some(runtime) = self.runtime else {
            return Err((made, "this root part has no runtime".into()));
        };
        // Written down before it runs: a unit may end kithd at once, and one that ran with no
        // record would be run again by the next.
        runtime.record(id, &made, mark);
        match made.start() {
            Ok(()) => Ok(made),
            Err(e) => Err((made, e.to_string())),
        }
    }
}

impl Direct<'static, Nobody> {
    /// For the Listeners family alone.
    pub fn new() -> Self {
        Direct {
            hands: Nobody,
            book: &BOOK,
            policy: None,
        }
    }
}

impl<'a> Direct<'a, Today<'a>> {
    /// The root part of this node: its pods, and its runtime if containers are made.
    pub fn today(pods: &'a Mutex<Pods>, runtime: Option<&'a Runtime>) -> Self {
        Direct::with(Today { pods, runtime }, &BOOK)
    }
}

impl<'a, H: Hands> Direct<'a, H> {
    pub fn with(hands: H, book: &'a Book) -> Self {
        Direct {
            hands,
            book,
            policy: None,
        }
    }

    /// Check against `policy` and not the node's own: for a test, which cannot set it.
    #[cfg(test)]
    fn under(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Whether the interface is up with the node's address, as far as the root part knows.
    fn up(&self, up: bool) {
        if let Some(told) = self.book.mesh.lock().expect("nothing panics holding the book").as_mut() {
            told.up = up;
        }
    }

    /// A request of the Mesh family: one at a time from its check to its act, so what was
    /// checked is what is acted on (two ups are not both checked against a node that is not up,
    /// and a set is not checked against an interface that a down is taking away).
    fn mesh_request(&self, request: Request) -> Result<Reply, String> {
        let _one = self.book.meshing.lock().unwrap_or_else(|e| e.into_inner());
        let told = self.book.mesh.lock().expect("nothing panics holding the book").clone();
        check_mesh(&request, &told)?;
        // (The mesh was told, or `check_mesh` would have refused.)
        let told = told.ok_or("this root part was told no mesh")?;
        match request {
            Request::MeshUp { interface, address } => {
                // Up before it is made, undone if it was not: what a request that looks in
                // between sees is a node that is up. A second up that fails leaves the first one's
                // interface, which is there still.
                self.up(true);
                match self.hands.mesh_up(&interface, &told.key, told.port, address) {
                    Ok(key) => Ok(Reply::Key(key)),
                    Err(e) => {
                        self.up(told.up);
                        Err(e)
                    }
                }
            }
            Request::Mesh { peers, addresses, .. } => self.hands.mesh(&peers, &addresses).map(|()| Reply::Done),
            Request::MeshSeen { .. } => self.hands.mesh_seen().map(Reply::Seen),
            Request::MeshDown { .. } => {
                // Only a down that worked is a node that is not up: one that failed leaves the
                // link, and it is still the node's.
                self.hands.mesh_down()?;
                self.up(false);
                Ok(Reply::Done)
            }
            _ => Err("not a request of the mesh".into()),
        }
    }

    /// What the root part holds, to check a container against.
    fn ground(&self) -> Ground {
        Ground {
            state: self.book.state(),
            memory: crate::files::memory_dir(),
            devices: self
                .book
                .devices
                .lock()
                .expect("nothing panics holding the book")
                .clone(),
            policy: self.policy.clone().unwrap_or_else(crate::policy::get),
            root: nix::unistd::getuid().is_root(),
        }
    }
}

impl<H: Hands> Root for Direct<'_, H> {
    type Made = H::Made;

    fn request(&self, request: Request) -> Result<Reply, String> {
        self.act(request, Vec::new())
    }

    fn request_with(&self, request: Request, files: Vec<File>) -> Result<Reply, String> {
        self.act(request, files)
    }

    fn create(&self, create: Create) -> Result<H::Made, String> {
        self.book.count(Kind::Create);
        check_create(&create, &self.ground(), &|path| self.hands.owns_netns(path))?;
        self.hands.create(create)
    }

    fn start(&self, made: H::Made, id: &str, mark: &str) -> Result<H::Made, (H::Made, String)> {
        self.book.count(Kind::Start);
        let plain = !mark.is_empty() && mark.len() <= 256 && mark.chars().all(|c| c.is_ascii_alphanumeric());
        let refused =
            label("unit id", id).and_then(|()| plain.then_some(()).ok_or("the mark is not hexadecimal text".into()));
        match refused {
            Ok(()) => self.hands.start(made, id, mark),
            Err(why) => Err((made, why)),
        }
    }
}

impl<H: Hands> Direct<'_, H> {
    /// A request of the Images family: the store is exactly `<state>/runtime` (the state
    /// directory as the node was started with it, which is already canonical), and nothing
    /// the asker says names it; the path of an image is derived from its digest.
    fn images_request(&self, request: Request, files: Vec<File>) -> Result<Reply, String> {
        let root = self
            .book
            .state()
            .ok_or("this root part has no state directory")?
            .join("runtime");
        // (A store that is a link to somewhere else is not the node's.)
        if root.canonicalize().ok().as_deref() != Some(&root) {
            return Err("the image store is not the node's own".into());
        }
        let store = ImageStore::at(root);
        match request {
            Request::Unpack { image, manifest } => {
                if files.len() > MOST_LAYERS {
                    return Err(format!("{} layer files: at most {MOST_LAYERS}", files.len()));
                }
                store
                    .unpack(&image, &manifest, files)
                    .map(|()| Reply::Done)
                    .map_err(|e| e.to_string())
            }
            Request::Drop { image, before } => {
                // (Seconds that are no time at all are refused, not added.)
                let before = std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_secs(before))
                    .ok_or("a time that is not a time")?;
                store
                    .remove_image(&image, before)
                    .map(Reply::Freed)
                    .map_err(|e| e.to_string())
            }
            _ => Err("not a request of the images".into()),
        }
    }

    fn act(&self, request: Request, files: Vec<File>) -> Result<Reply, String> {
        self.book.count(match request {
            Request::Bind { .. } => Kind::Bind,
            Request::Pod { .. } => Kind::Pod,
            Request::Sockets { .. } => Kind::Sockets,
            Request::MeshUp { .. } | Request::Mesh { .. } | Request::MeshDown { .. } => Kind::Mesh,
            Request::MeshSeen { .. } => Kind::Seen,
            Request::Unpack { .. } => Kind::Unpack,
            Request::Drop { .. } => Kind::Drop,
        });
        check(&request)?;
        if !files.is_empty() && !matches!(request, Request::Unpack { .. }) {
            return Err("only an unpack comes with files".into());
        }
        match request {
            images @ (Request::Unpack { .. } | Request::Drop { .. }) => self.images_request(images, files),
            mesh @ (Request::MeshUp { .. }
            | Request::Mesh { .. }
            | Request::MeshSeen { .. }
            | Request::MeshDown { .. }) => self.mesh_request(mesh),
            Request::Bind { address, port, proto } => {
                let at = SocketAddr::new(address, port);
                let made = match proto {
                    Proto::Tcp => TcpListener::bind(at).map(OwnedFd::from),
                    Proto::Udp => UdpSocket::bind(at).map(OwnedFd::from),
                };
                made.map(Reply::Socket)
                    .map_err(|e| format!("binding {address} port {port}: {e}"))
            }
            Request::Pod {
                id,
                namespace,
                hostname,
                net,
                exit,
                owner,
                egress,
            } => {
                // (The directory is the root part's own, never the asker's.)
                let state = self.book.state().ok_or("this root part has no state directory")?;
                let exit = exit.as_ref().map(|(tunnel, dns)| (*tunnel, dns.as_slice()));
                self.hands
                    .pod(&state, &id, &namespace, &hostname, net, exit, &owner, egress)
                    .map(Reply::Pod)
            }
            Request::Sockets { pod, v6, count } => self.hands.sockets(&pod, v6, usize::from(count)).map(Reply::Sockets),
        }
    }
}

/// An image unpacked from its `manifest` and the layer `files`, as the root part of this node
/// does it: asked of it, with the files beside the request.
pub fn unpack(image: String, manifest: String, files: Vec<File>) -> Result<(), String> {
    match Direct::new().request_with(Request::Unpack { image, manifest }, files)? {
        Reply::Done => Ok(()),
        _ => Err("the root part answered an unpack with another reply".into()),
    }
}

/// The image `image` removed, if last used no later than `before`: what it freed, or `None`.
pub fn drop_image(image: &str, before: std::time::SystemTime) -> Result<Option<u64>, String> {
    let before = before.duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    match Direct::new().request(Request::Drop {
        image: image.into(),
        before,
    })? {
        Reply::Freed(freed) => Ok(freed),
        _ => Err("the root part answered a drop with another reply".into()),
    }
}

/// The pod `ask` (a [`Request::Pod`]) as a container of it is given it: asked of the root part
/// for the first container of a pod, and not for the next (what was told is kept, until the pod
/// goes). The lock on the pods is not held while the root part is asked.
pub fn pod<R: Root>(root: &R, pods: &Mutex<Pods>, ask: Request) -> Result<Given, String> {
    let Request::Pod { id, hostname, exit, .. } = &ask else {
        return Err("not a request for a pod".into());
    };
    let tunnel = exit.as_ref().map(|(tunnel, _)| *tunnel);
    let (id, hostname) = (id.clone(), hostname.clone());
    if let Some(told) = pods
        .lock()
        .expect("nothing panics holding the pods")
        .told(&id, &hostname, tunnel)
    {
        return Ok(told);
    }
    let Reply::Pod(given) = root.request(ask)? else {
        return Err("the root part answered a request for a pod with something else".into());
    };
    pods.lock()
        .expect("nothing panics holding the pods")
        .remember(&id, tunnel, &given);
    Ok(given)
}

/// What the mesh was last told, for [`mesh`]: the peers (by key) and the services' addresses.
pub type Told = (Vec<kith_mesh::Peer>, BTreeSet<Ipv6Addr>);

/// The mesh's interface as wanted: asked of the root part when it is not what was told last
/// (`told`, which is kept), and not otherwise, so a mesh that has not changed crosses nothing.
/// Whether it crossed. A refused or failed one is not taken for told: it is asked again.
pub fn mesh<R: Root>(
    root: &R,
    told: &mut Option<Told>,
    interface: &str,
    mut peers: Vec<kith_mesh::Peer>,
    addresses: BTreeSet<Ipv6Addr>,
) -> Result<bool, String> {
    peers.sort_by_key(|peer| peer.key);
    if told.as_ref().is_some_and(|(had, at)| *had == peers && *at == addresses) {
        return Ok(false);
    }
    let ask = Request::Mesh {
        interface: interface.into(),
        peers: peers.clone(),
        addresses: addresses.clone(),
    };
    match root.request(ask)? {
        Reply::Done => {
            *told = Some((peers, addresses));
            Ok(true)
        }
        _ => Err("the root part answered a request for the mesh with something else".into()),
    }
}

/// The mesh's interface up with the node's `address`: its public key.
pub fn mesh_key<R: Root>(root: &R, interface: &str, address: Ipv6Addr) -> Result<kith_mesh::Key, String> {
    match root.request(Request::MeshUp {
        interface: interface.into(),
        address,
    })? {
        Reply::Key(key) => Ok(key),
        _ => Err("the root part answered a request for the mesh with something else".into()),
    }
}

/// When each peer of the mesh last shook hands.
pub fn mesh_seen<R: Root>(root: &R, interface: &str) -> Result<Vec<kith_mesh::Seen>, String> {
    match root.request(Request::MeshSeen {
        interface: interface.into(),
    })? {
        Reply::Seen(seen) => Ok(seen),
        _ => Err("the root part answered a request for the mesh with something else".into()),
    }
}

/// The mesh's interface taken away.
pub fn mesh_down<R: Root>(root: &R, interface: &str) -> Result<(), String> {
    match root.request(Request::MeshDown {
        interface: interface.into(),
    })? {
        Reply::Done => Ok(()),
        _ => Err("the root part answered a request for the mesh with something else".into()),
    }
}

/// A stream socket, not yet connected, to be made over into a `TcpSocket`.
pub fn stream_socket(v6: bool) -> std::io::Result<OwnedFd> {
    let family = if v6 { AddressFamily::Inet6 } else { AddressFamily::Inet };
    let flags = SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC;
    Ok(socket(family, SockType::Stream, flags, None)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn ask(address: &str, port: u16, proto: Proto) -> Request {
        Request::Bind {
            address: address.parse().unwrap(),
            port,
            proto,
        }
    }

    fn socket_of(reply: Result<Reply, String>) -> OwnedFd {
        match reply.unwrap() {
            Reply::Socket(fd) => fd,
            other => panic!("not a socket: {other:?}"),
        }
    }

    #[test]
    fn wire() {
        // A good Bind reads back, and what is sent is what is read.
        let good = br#"{"Bind":{"address":"::1","port":2049,"proto":"tcp"}}"#;
        assert_eq!(decode(good).unwrap(), ask("::1", 2049, Proto::Tcp));
        let sent = serde_json::to_vec(&ask("127.0.0.1", 53, Proto::Udp)).unwrap();
        assert_eq!(decode(&sent).unwrap(), ask("127.0.0.1", 53, Proto::Udp));
        // So do the pods' requests.
        for request in [
            Request::Sockets {
                pod: "w_a_b_0".into(),
                v6: true,
                count: 16,
            },
            pod_ask("w_a_b_0", "a", "b-0", None),
        ] {
            let sent = serde_json::to_vec(&request).unwrap();
            assert_eq!(decode(&sent).unwrap(), request);
        }
        // Over 256 KiB is refused unread, even where it would otherwise be a good request.
        let mut big = good.to_vec();
        big.resize(MAX_REQUEST + 1, b' ');
        assert!(decode(&big).unwrap_err().contains("at most"));
        big.truncate(MAX_REQUEST);
        assert!(decode(&big).is_ok(), "exactly the limit is taken");
        // An unknown field, an unknown variant, an unknown protocol, a port out of range,
        // a name for an address, and noise are refused.
        for bad in [
            &br#"{"Bind":{"address":"::1","port":2049,"proto":"tcp","path":"/etc"}}"#[..],
            br#"{"Exec":{"argv":["sh"]}}"#,
            br#"{"Bind":{"address":"::1","port":2049,"proto":"sctp"}}"#,
            br#"{"Bind":{"address":"::1","port":70000,"proto":"tcp"}}"#,
            br#"{"Bind":{"address":"localhost","port":2049,"proto":"tcp"}}"#,
            br#"{"Bind":{"address":"::1","port":2049}}"#,
            br#"{"Sockets":{"pod":"a","v6":false,"count":300}}"#,
            br#"{"Sockets":{"pod":"a","v6":false,"count":1,"netns":"/proc/1/ns/net"}}"#,
            b"not json",
            b"",
        ] {
            assert!(decode(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn bind() {
        let root = Direct::new();
        // Whatever the asker says, a port kithd serves on is refused, on either family.
        for port in OWN_PORTS {
            for address in ["127.0.0.1", "::1", "0.0.0.0", "::"] {
                for proto in [Proto::Tcp, Proto::Udp] {
                    let why = root.request(ask(address, port, proto)).unwrap_err();
                    assert!(why.contains("serves on itself"), "{address} {port}: {why}");
                }
            }
        }
        // A multicast address is not one to listen on.
        assert!(check(&ask("224.0.0.1", 9000, Proto::Udp)).is_err());
        assert!(check(&ask("ff02::1", 9000, Proto::Udp)).is_err());
        // An allowed one gives a socket: a tcp one listening, a udp one bound.
        let tcp = TcpListener::from(socket_of(root.request(ask("127.0.0.1", 0, Proto::Tcp))));
        assert!(tcp.local_addr().unwrap().ip().is_loopback());
        let udp = root.request(ask("::1", 0, Proto::Udp));
        // (A container with no IPv6 loopback cannot bind it: that is the system's refusal.)
        if let Ok(udp) = udp {
            let Reply::Socket(udp) = udp else {
                panic!("not a socket")
            };
            assert!(UdpSocket::from(udp).local_addr().unwrap().is_ipv6());
        }
        let udp = socket_of(root.request(ask("127.0.0.1", 0, Proto::Udp)));
        assert!(UdpSocket::from(udp).local_addr().is_ok());
        // A port taken is the system's refusal, said with the address.
        let taken = tcp.local_addr().unwrap().port();
        let why = root.request(ask("127.0.0.1", taken, Proto::Tcp)).unwrap_err();
        assert!(why.contains("binding 127.0.0.1"), "{why}");
    }

    // What stands in for the machine: nothing it is asked of is done, and each is said.
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<&'static str>>,
        /// The calls that fail, by name (`mesh_up`, `mesh_down`).
        failing: Mutex<Vec<&'static str>>,
        /// How many of the mesh's calls are inside one at once, and the most there were.
        inside: AtomicUsize,
        most: AtomicUsize,
    }

    const NETNS: &str = "/proc/1/fd/3";

    impl Fake {
        fn said(&self, what: &'static str) {
            self.calls.lock().unwrap().push(what);
        }

        fn fail(&self, what: &'static str, fails: bool) {
            let mut failing = self.failing.lock().unwrap();
            failing.retain(|w| *w != what);
            if fails {
                failing.push(what);
            }
        }

        /// A mesh call that takes a while, and says whether it is to fail.
        fn slow(&self, what: &'static str) -> Result<(), String> {
            self.said(what);
            let now = self.inside.fetch_add(1, Ordering::SeqCst) + 1;
            self.most.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(30));
            self.inside.fetch_sub(1, Ordering::SeqCst);
            match self.failing.lock().unwrap().contains(&what) {
                true => Err(format!("{what} failed")),
                false => Ok(()),
            }
        }

        fn reached(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Hands for Fake {
        type Made = String;

        fn pod(
            &self,
            state: &Path,
            id: &str,
            _: &str,
            hostname: &str,
            _: Option<std::net::Ipv6Addr>,
            _: Option<(u16, &[Ipv4Addr])>,
            _: &str,
            _: Option<Vec<kith_mesh::pod::Egress>>,
        ) -> Result<Given, String> {
            self.said("pod");
            let dir = state.join("pods").join(id);
            Ok(Given {
                netns: NETNS.into(),
                hostname: hostname.into(),
                files: [dir.join("resolv.conf"), dir.join("hosts")],
                address: "10.0.0.2".parse().unwrap(),
            })
        }

        fn sockets(&self, _: &str, v6: bool, count: usize) -> Result<Vec<OwnedFd>, String> {
            self.said("sockets");
            (0..count)
                .map(|_| stream_socket(v6).map_err(|e| e.to_string()))
                .collect()
        }

        fn owns_netns(&self, path: &Path) -> bool {
            path == Path::new(NETNS)
        }

        fn create(&self, create: Create) -> Result<String, String> {
            self.said("create");
            Ok(create.id.into())
        }

        fn start(&self, made: String, _: &str, _: &str) -> Result<String, (String, String)> {
            self.said("start");
            Ok(made)
        }

        fn mesh_up(&self, _: &str, _: &Path, _: u16, _: Ipv6Addr) -> Result<kith_mesh::Key, String> {
            self.slow("mesh_up").map(|()| [7; 32])
        }

        fn mesh(&self, _: &[kith_mesh::Peer], _: &BTreeSet<Ipv6Addr>) -> Result<(), String> {
            self.said("mesh");
            Ok(())
        }

        fn mesh_seen(&self) -> Result<Vec<kith_mesh::Seen>, String> {
            self.said("mesh_seen");
            Ok(Vec::new())
        }

        fn mesh_down(&self) -> Result<(), String> {
            self.slow("mesh_down")
        }
    }

    fn pod_ask(id: &str, namespace: &str, hostname: &str, tunnel: Option<u16>) -> Request {
        Request::Pod {
            id: id.into(),
            namespace: namespace.into(),
            hostname: hostname.into(),
            net: None,
            exit: tunnel.map(|tunnel| (tunnel, vec!["10.9.0.1".parse().unwrap()])),
            owner: "Workload/a/b".into(),
            egress: None,
        }
    }

    /// A state directory of its own, and a book that has it.
    fn book(name: &str) -> (Book, PathBuf) {
        let dir = std::env::temp_dir().join(format!("kith-root-part-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.canonicalize().unwrap();
        let book = Book::new();
        book.set_state(dir.clone());
        (book, dir)
    }

    fn policy(words: &str) -> Policy {
        words.parse().unwrap()
    }

    fn ground(state: &Path, words: &str) -> Ground {
        Ground {
            state: Some(state.to_path_buf()),
            memory: None,
            devices: BTreeSet::from([PathBuf::from("/dev/dri/renderD128")]),
            policy: policy(words),
            root: true,
        }
    }

    fn mount(host: &Path, container: &str) -> Mount {
        Mount {
            host: host.to_path_buf(),
            container: container.into(),
            read_only: false,
            give: false,
            part: None,
        }
    }

    fn null() -> File {
        File::open("/dev/null").unwrap()
    }

    /// Why `unit` is refused (or `None`: it is made) under the ground.
    fn refused(unit: &Unit, ground: &Ground) -> Option<String> {
        refused_as("w_a_b_0_c", unit, ground)
    }

    /// [`refused`], of the unit `id`.
    fn refused_as(id: &str, unit: &Unit, ground: &Ground) -> Option<String> {
        let image = Image::default();
        let create = Create {
            id,
            image: &image,
            unit,
            out: null(),
            err: null(),
        };
        check_create(&create, ground, &|path| path == Path::new(NETNS)).err()
    }

    /// A unit as the controller makes one of a plain container, whose policy has nothing off.
    fn plain() -> Unit {
        Unit {
            no_node_root: false,
            ..Unit::default()
        }
    }

    #[test]
    fn a_pod_asked_for_with_a_name_a_file_would_read_as_more_is_refused() {
        let (book, _) = book("pod-names");
        let root = Direct::with(Fake::default(), &book);
        let long = "a".repeat(300);
        for (id, namespace, hostname) in [
            ("../../etc", "a", "b-0"),
            ("w_a_b_0", "a\nnameserver 6.6.6.6", "b-0"),
            ("w_a_b_0", "a", "b-0\n6.6.6.6 bank.example"),
            ("w_a_b_0", "a/b", "b-0"),
            ("w_a_b_0", "", "b-0"),
            ("w_a_b_0", "a", ""),
            ("-w", "a", "b-0"),
            (".hidden", "a", "b-0"),
            ("w a", "a", "b-0"),
            (&long, "a", "b-0"),
        ] {
            let why = root.request(pod_ask(id, namespace, hostname, None)).unwrap_err();
            assert!(why.contains("not a name"), "{id:?} {namespace:?} {hostname:?}: {why}");
        }
        let many = Request::Pod {
            id: "w_a_b_0".into(),
            namespace: "a".into(),
            hostname: "b-0".into(),
            net: None,
            exit: Some((7, vec![Ipv4Addr::LOCALHOST; 9])),
            owner: "Workload/a/b".into(),
            egress: None,
        };
        assert!(root.request(many).unwrap_err().contains("name servers"));
        assert_eq!(
            root.hands.reached(),
            Vec::<&str>::new(),
            "a refused request reached the machine"
        );
        // A good one does, and the files are the root part's own state directory's.
        let Reply::Pod(given) = root.request(pod_ask("w_a_b_0", "a", "b-0", None)).unwrap() else {
            panic!("not a pod")
        };
        assert!(given.files[0].starts_with(book.state().unwrap()));
        assert_eq!(root.hands.reached(), ["pod"]);
    }

    #[test]
    fn a_pod_is_refused_where_the_root_part_has_no_state_directory() {
        let book = Book::new();
        let root = Direct::with(Fake::default(), &book);
        let why = root.request(pod_ask("w_a_b_0", "a", "b-0", None)).unwrap_err();
        assert!(why.contains("no state directory"), "{why}");
        assert!(root.hands.reached().is_empty());
    }

    #[test]
    fn sockets_are_asked_for_in_a_pod_by_a_name_and_a_count_the_root_part_takes() {
        let (book, _) = book("sockets");
        let root = Direct::with(Fake::default(), &book);
        for (pod, count) in [("w_a_b_0", 0), ("w_a_b_0", 17), ("w_a_b_0", 255), ("../w", 1), ("", 1)] {
            let why = root
                .request(Request::Sockets {
                    pod: pod.into(),
                    v6: false,
                    count,
                })
                .unwrap_err();
            assert!(
                why.contains("sockets: from 1 to") || why.contains("not a name"),
                "{pod:?} {count}: {why}"
            );
        }
        assert!(root.hands.reached().is_empty());
        // A pod this node did not make has no sockets to make in: never the node's own.
        let why = Pods::default().sockets("w_a_b_0", false, 1).unwrap_err();
        assert!(why.contains("not on this node"), "{why}");
    }

    #[test]
    fn a_mount_outside_the_state_directory_is_refused_whatever_the_caller_says() {
        let (_, state) = book("mounts");
        let off = ground(&state, "no-host-paths");
        let inside = state.join("volumes").join("ns").join("data");
        std::fs::create_dir_all(&inside).unwrap();
        let with = |host: &Path, at: &str| Unit {
            mounts: vec![mount(host, at)],
            ..plain()
        };
        // Under the state directory: made.
        assert_eq!(refused(&with(&inside, "/data"), &off), None);
        // Outside it, in each way a path gets there.
        let link = state.join("escape");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        let dotdot = state.join("..").join("etc");
        for host in [
            Path::new("/etc"),
            Path::new("/"),
            Path::new("/root/.ssh"),
            Path::new("relative/dir"),
            &dotdot,
            &link,
            &state.join("escape").join("passwd"),
            Path::new("/proc/1/root"),
        ] {
            let why = refused(&with(host, "/data"), &off).unwrap_or_else(|| panic!("{} was mounted", host.display()));
            assert!(
                why.contains("not a directory a unit's mounts") || why.contains("does not resolve"),
                "{}: {why}",
                host.display()
            );
        }
        // A path in the container that is no path in it.
        for at in ["data", "/a/../../b", ""] {
            assert!(refused(&with(&inside, at), &off).is_some(), "{at:?}");
        }
        // Where the node's policy lets the store name a path, it does.
        let on = ground(&state, "");
        assert_eq!(refused(&with(Path::new("/etc"), "/data"), &on), None);
        // And where no state directory is known, nothing is under it.
        let none = Ground {
            state: None,
            ..ground(&state, "no-host-paths")
        };
        assert!(refused(&with(&inside, "/data"), &none).is_some());
    }

    /// Make `path` a directory (or, with a file name that has a dot, a file) and say it.
    fn on_disk(path: PathBuf) -> PathBuf {
        match path.extension().is_some() {
            true => {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, "x").unwrap();
            }
            false => std::fs::create_dir_all(&path).unwrap(),
        }
        path
    }

    #[test]
    fn a_unit_mounts_only_what_its_mounts_are_made_from_and_is_given_only_what_it_owns() {
        let (_, state) = book("mount-kinds");
        let (_, memory) = book("mount-kinds-memory");
        let g = Ground {
            memory: Some(memory.clone()),
            ..ground(&state, "no-host-paths")
        };
        let (s, m) = (
            |rest: &str| on_disk(state.join(rest)),
            |rest: &str| on_disk(memory.join(rest)),
        );
        let with = |host: &Path, give: bool| Unit {
            mounts: vec![Mount {
                give,
                ..mount(host, "/data")
            }],
            ..plain()
        };
        // What the controller mounts a unit of the pod `w_a_b_0` from: each made, and each given.
        let mine = [
            s("volumes/ns/vol"),
            s("volumes/ns/vol/deeper"),
            s("remote/node/ns/vol"),
            s("replicas/w_a_b_0/files/c/0"),
            s("replicas/w_a_b_0/scratch/tmp"),
            s("seats/one"),
            m("replicas/w_a_b_0/files/c/0"),
            m("replicas/w_a_b_0/scratch/tmp"),
            m("replicas/w_a_b_0/identity/c"),
        ];
        for host in &mine {
            assert_eq!(refused(&with(host, true), &g), None, "{}", host.display());
        }
        // A rolling update's second generation (`w_a_b_0b`, a pod of its own) mounts what the
        // replica keeps, under the first's name, as the first does.
        for host in &mine {
            assert_eq!(
                refused_as("w_a_b_0b_c", &with(host, true), &g),
                None,
                "{}",
                host.display()
            );
        }
        // The pod's own two files: read, never given, and never written.
        let read = |host: &Path| Unit {
            mounts: vec![Mount {
                read_only: true,
                ..mount(host, "/etc/hosts")
            }],
            ..plain()
        };
        let resolv = s("pods/w_a_b_0/resolv.conf");
        assert_eq!(refused(&read(&resolv), &g), None);
        assert!(refused(&with(&resolv, false), &g).unwrap().contains("read-only"));
        assert!(refused(&with(&resolv, true), &g).unwrap().contains("given"));
        // Each generation's are its own pod's.
        let second = s("pods/w_a_b_0b/hosts");
        assert_eq!(refused_as("w_a_b_0b_c", &read(&second), &g), None);
        assert!(refused_as("w_a_b_0b_c", &read(&resolv), &g).is_some());
        assert!(refused(&read(&second), &g).is_some());
        // What the node keeps for itself is in the state and memory directories too, and no
        // mount of it is made whoever asks: the directories themselves, and their keys.
        let keys = s("pki/ca.key");
        std::fs::write(&keys, "x").unwrap();
        let theirs = [
            state.clone(),
            memory.clone(),
            s("pki"),
            keys,
            s("volumes"),
            s("volumes/ns"),
            s("remote/node/ns"),
            s("replicas"),
            s("replicas/w_a_b_0"),
            s("seats"),
            s("pods"),
            s("pods/w_a_b_0"),
            s("pods/w_a_b_1/resolv.conf"),
            // Another pod's, though of the kind a unit may mount.
            s("replicas/w_a_b_1/files/c/0"),
            m("replicas/w_a_b_1/scratch/tmp"),
            m("replicas/w_a_b_1/identity/c"),
            // The pod's directory in memory holds its key.
            m("replicas/w_a_b_0"),
            m("replicas/w_a_b_0/identity.key"),
            m("replicas"),
            // A kind of the state directory's own that the memory directory has none of.
            m("volumes/ns/vol"),
        ];
        for host in &theirs {
            for give in [false, true] {
                let why = refused(&with(host, give), &g).unwrap_or_else(|| panic!("{} was mounted", host.display()));
                assert!(
                    why.contains("not a directory a unit's mounts"),
                    "{}: {why}",
                    host.display()
                );
            }
        }
        // A path that does not resolve is judged by nothing but its text, so it is refused.
        let gone = state.join("volumes/ns/gone");
        let open = ground(&state, "");
        for ground in [&g, &open] {
            let why = refused(&with(&gone, false), ground).unwrap();
            assert!(why.contains("does not resolve"), "{why}");
        }
        // Where hostPaths is on, a path anywhere is mounted, and given to no one.
        assert_eq!(refused(&with(Path::new("/etc"), false), &open), None);
        assert!(
            refused(&with(Path::new("/etc"), true), &open)
                .unwrap()
                .contains("given")
        );
        assert!(refused(&with(&state, true), &open).unwrap().contains("given"));
        // A user the unit's range does not have is given nothing: the runtime would refuse the
        // user, but not the chown of what is to be given it.
        let user = |user: u32, give: bool| Unit {
            user: Some(user),
            netns: Some(PathBuf::from(NETNS)),
            ..with(&mine[0], give)
        };
        assert_eq!(refused(&user(65535, true), &g), None);
        assert!(refused(&user(65536, true), &g).unwrap().contains("range"));
        assert!(refused(&user(u32::MAX - 1, true), &g).unwrap().contains("range"));
        assert_eq!(refused(&user(65536, false), &g), None);
        // Only where the runtime shifts ids: not for the host's users, or a unit with no pod,
        // whose user is the host's own.
        let unshifted = [
            Unit {
                host_users: true,
                ..user(65536, true)
            },
            Unit {
                netns: None,
                ..user(65536, true)
            },
        ];
        for unit in &unshifted {
            assert_eq!(refused(unit, &g), None);
        }
    }

    #[test]
    fn a_device_no_claim_granted_is_refused_whatever_the_caller_says() {
        let (_, state) = book("devices");
        let g = ground(&state, "no-host-paths");
        let with = |paths: &[&str]| Unit {
            devices: paths.iter().map(PathBuf::from).collect(),
            ..plain()
        };
        assert_eq!(refused(&with(&["/dev/dri/renderD128"]), &g), None);
        for paths in [
            &["/dev/mem"][..],
            &["/dev/dri/renderD129"],
            &["/dev/dri/renderD128", "/dev/kmsg"],
            &["/dev/dri/../mem"],
        ] {
            let why = refused(&with(paths), &g).unwrap_or_else(|| panic!("{paths:?} was given"));
            assert!(why.contains("no claim"), "{paths:?}: {why}");
        }
    }

    #[test]
    fn a_container_the_policy_has_none_of_is_refused_whatever_the_caller_says() {
        let (_, state) = book("policy");
        let g = ground(&state, "no-root-containers,no-unconfined,no-node-network");
        // Left as the policy has it: made, in a pod's network.
        let pod = Unit {
            no_node_root: true,
            netns: Some(NETNS.into()),
            hostname: Some("b-0".into()),
            ..plain()
        };
        assert_eq!(refused(&pod, &g), None);
        // Each thing the caller may leave off or turn on to have more than the node gives.
        let more = [
            (
                Unit {
                    no_node_root: false,
                    ..pod.clone()
                },
                "containers that are the node's root",
            ),
            (
                Unit {
                    unconfined: true,
                    ..pod.clone()
                },
                "no system call filter",
            ),
            (
                Unit {
                    allow: vec!["mount".into()],
                    ..pod.clone()
                },
                "no system call filter",
            ),
            (
                Unit {
                    netns: None,
                    as_image: false,
                    ..pod.clone()
                },
                "the node's own network",
            ),
            // (As a pod, where kithd is root, with no network of its own: the node's.)
            (
                Unit {
                    netns: None,
                    as_image: true,
                    ..pod.clone()
                },
                "the node's own network",
            ),
            // A namespace this root part did not make: the node's own, or another process's.
            (
                Unit {
                    netns: Some("/proc/1/ns/net".into()),
                    ..pod.clone()
                },
                "not the network of a pod",
            ),
            (
                Unit {
                    hostname: Some("b\n0".into()),
                    ..pod.clone()
                },
                "not a name",
            ),
        ];
        for (unit, said) in more {
            let why = refused(&unit, &g).unwrap_or_else(|| panic!("{said} was made"));
            assert!(why.contains(said), "{said}: {why}");
        }
        // Where kithd is not root a pod has no network of its own, and shares the node's.
        let shared = Ground {
            root: false,
            ..ground(&state, "no-node-network")
        };
        let sharing = Unit {
            netns: None,
            as_image: true,
            ..plain()
        };
        assert_eq!(refused(&sharing, &shared), None);
        assert!(
            refused(
                &Unit {
                    as_image: false,
                    ..sharing
                },
                &shared
            )
            .is_some()
        );
        // A node with nothing off is asked for nothing.
        let open = ground(&state, "");
        let all = Unit {
            unconfined: true,
            netns: None,
            ..plain()
        };
        assert_eq!(refused(&all, &open), None);
        // And a name that is no unit's is refused first.
        let image = Image::default();
        let unit = plain();
        let create = Create {
            id: "../w",
            image: &image,
            unit: &unit,
            out: null(),
            err: null(),
        };
        assert!(check_create(&create, &open, &|_| true).is_err());
    }

    #[test]
    fn a_container_refused_never_reaches_the_machine() {
        let (book, state) = book("through");
        book.claim([PathBuf::from("/dev/dri/renderD128")]);
        let root = Direct::with(Fake::default(), &book).under(policy("no-host-paths,no-root-containers"));
        let image = Image::default();
        let made = |unit: &Unit, id: &str| {
            root.create(Create {
                id,
                image: &image,
                unit,
                out: null(),
                err: null(),
            })
        };
        let good = Unit {
            no_node_root: true,
            ..plain()
        };
        let other = Unit {
            mounts: vec![mount(Path::new("/etc"), "/etc")],
            ..good.clone()
        };
        let device = Unit {
            devices: vec!["/dev/mem".into()],
            ..good.clone()
        };
        let root_of_node = Unit {
            no_node_root: false,
            ..good.clone()
        };
        for unit in [&other, &device, &root_of_node] {
            assert!(made(unit, "w_a_b_0_c").is_err());
        }
        assert!(made(&good, "../w").is_err());
        assert!(root.hands.reached().is_empty(), "{:?}", root.hands.reached());
        let granted = Unit {
            devices: vec!["/dev/dri/renderD128".into()],
            mounts: vec![mount(&on_disk(state.join("volumes/ns/data")), "/data")],
            ..good
        };
        assert_eq!(made(&granted, "w_a_b_0_c").unwrap(), "w_a_b_0_c");
        assert_eq!(root.hands.reached(), ["create"]);
        // A start is refused for a unit id or a mark that is no name or no hash.
        for (id, mark) in [
            ("../w", "ab12"),
            ("w_a_b_0_c", ""),
            ("w_a_b_0_c", "ab 12\n"),
            ("w_a_b_0_c", &"a".repeat(257)),
        ] {
            let (back, why) = root.start("made".into(), id, mark).unwrap_err();
            assert_eq!(back, "made");
            assert!(why.contains("not a name") || why.contains("not hexadecimal"), "{why}");
        }
        assert_eq!(root.hands.reached(), ["create"]);
        assert!(root.start("made".into(), "w_a_b_0_c", "ab12").is_ok());
    }

    // The ADR's table of a hot path's cost (docs/adr-privilege.md): counted at the crossing.

    /// What the serving part does to start the container `c` of the pod `id`, as the
    /// controller does: ask for the pod (told once), create, start.
    fn start_one(root: &Direct<Fake>, pods: &Mutex<Pods>, state: &Path, id: &str, c: &str) {
        let given = pod(root, pods, pod_ask(id, "a", "b-0", None)).unwrap();
        let unit = Unit {
            no_node_root: false,
            netns: Some(given.netns),
            hostname: Some(given.hostname),
            mounts: vec![
                Mount {
                    read_only: true,
                    ..mount(&on_disk(given.files[0].clone()), "/etc/resolv.conf")
                },
                mount(&on_disk(state.join("volumes/ns/data")), "/data"),
            ],
            ..Unit::default()
        };
        let image = Image::default();
        let unit_id = format!("{id}_{c}");
        let create = Create {
            id: &unit_id,
            image: &image,
            unit: &unit,
            out: null(),
            err: null(),
        };
        let made = root.create(create).unwrap();
        root.start(made, &unit_id, "ab12").unwrap();
    }

    #[test]
    fn crossings_of_a_container_start_are_at_most_three() {
        let (book, state) = book("start");
        let root = Direct::with(Fake::default(), &book).under(policy("no-host-paths"));
        let pods = Mutex::new(Pods::default());
        pods.lock().unwrap().pretend("w_a_b_0", &state);
        // The first container of a pod: its pod, its creation, its start.
        start_one(&root, &pods, &state, "w_a_b_0", "first");
        assert_eq!(book.total(), 3);
        assert_eq!(
            (
                book.crossed(Kind::Pod),
                book.crossed(Kind::Create),
                book.crossed(Kind::Start)
            ),
            (1, 1, 1)
        );
        // The pod was told once: the next container of it is a creation and a start.
        start_one(&root, &pods, &state, "w_a_b_0", "second");
        assert_eq!(book.total(), 5);
        assert_eq!(book.crossed(Kind::Pod), 1);
        assert_eq!(book.crossed(Kind::Sockets) + book.crossed(Kind::Bind), 0);
        // A pod let go is asked for again, and so is one told another hostname.
        pods.lock().unwrap().keep(|_| false);
        pods.lock().unwrap().pretend("w_a_b_0", &state);
        start_one(&root, &pods, &state, "w_a_b_0", "third");
        assert_eq!(book.crossed(Kind::Pod), 2);
    }

    #[test]
    fn crossings_of_a_pod_told_once_are_not_asked_again() {
        let (book, state) = book("told");
        let root = Direct::with(Fake::default(), &book);
        let pods = Mutex::new(Pods::default());
        pods.lock().unwrap().pretend("w_a_b_0", &state);
        let first = pod(&root, &pods, pod_ask("w_a_b_0", "a", "b-0", None)).unwrap();
        let again = pod(&root, &pods, pod_ask("w_a_b_0", "a", "b-0", None)).unwrap();
        assert_eq!((first.netns, first.address), (again.netns, again.address));
        assert_eq!(book.crossed(Kind::Pod), 1);
        // Another hostname, or another exit's tunnel, is not what was told: asked again.
        pod(&root, &pods, pod_ask("w_a_b_0", "a", "other-0", None)).unwrap();
        assert_eq!(book.crossed(Kind::Pod), 2);
        pod(&root, &pods, pod_ask("w_a_b_0", "a", "other-0", Some(3))).unwrap();
        assert_eq!(book.crossed(Kind::Pod), 3);
        // What is not a request for a pod is not answered as one.
        let bind = Request::Bind {
            address: "::1".parse().unwrap(),
            port: 9,
            proto: Proto::Tcp,
        };
        assert!(pod(&root, &pods, bind).is_err());
        assert_eq!(book.crossed(Kind::Bind), 0);
    }

    const WG: &str = "kith0";

    /// A book of a node on the mesh of the cluster `seed`, interface `kith0`, with its interface up
    /// as the node `a`; the mesh's address of a node `name`.
    fn meshed(seed: &str) -> (Book, Ipv6Addr) {
        let book = Book::new();
        book.set_mesh(WG.into(), 51820, PathBuf::from("/nowhere/mesh.key"), "a".into())
            .unwrap();
        let prefix = kith_mesh::prefix(seed.as_bytes());
        book.set_prefix(prefix).unwrap();
        (book, prefix)
    }

    fn up(root: &Direct<Fake>, prefix: Ipv6Addr) -> Result<Reply, String> {
        let address = kith_mesh::node_address(prefix, "a");
        root.request(Request::MeshUp {
            interface: WG.into(),
            address,
        })
    }

    fn peer(key: u8, allowed: Vec<(IpAddr, u8)>) -> kith_mesh::Peer {
        kith_mesh::Peer {
            key: [key; 32],
            endpoint: Some("203.0.113.2:51820".parse().unwrap()),
            allowed,
            keepalive: 25,
        }
    }

    fn mesh_ask(interface: &str, peers: Vec<kith_mesh::Peer>, addresses: &[Ipv6Addr]) -> Request {
        Request::Mesh {
            interface: interface.into(),
            peers,
            addresses: addresses.iter().copied().collect(),
        }
    }

    #[test]
    fn a_mesh_request_outside_what_the_root_part_would_make_is_refused() {
        let (book, prefix) = meshed("a cluster");
        let root = Direct::with(Fake::default(), &book);
        let other = kith_mesh::prefix(b"another cluster");
        let net = |name: &str| (IpAddr::V6(kith_mesh::node_net(prefix, name)), kith_mesh::NODE_BITS);
        let service = kith_mesh::service_address(prefix, "default", "web");
        // Nothing is made until the interface is up with an address of the cluster's: not an
        // interface that is not kith's, not another cluster's address, not a service's or a
        // node's other address.
        let said = |interface: &str, address: Ipv6Addr| {
            root.request(Request::MeshUp {
                interface: interface.into(),
                address,
            })
            .unwrap_err()
        };
        let mine = kith_mesh::node_address(prefix, "a");
        for interface in ["eth0", "lo", "", "kith0\n", "KITH0", "kith00"] {
            assert!(
                said(interface, mine).contains("not the mesh's interface"),
                "{interface:?}"
            );
        }
        for address in [
            kith_mesh::node_address(other, "a"),
            "fe80::1".parse().unwrap(),
            Ipv6Addr::UNSPECIFIED,
            service,
            kith_mesh::node_net(prefix, "a"),
            "fd00::1".parse().unwrap(),
            // (Another node's of this very cluster: the first of its /80 is not this node's.)
            kith_mesh::node_address(prefix, "b"),
            kith_mesh::node_address(prefix, "A"),
        ] {
            assert!(said(WG, address).contains("not this node's address"), "{address}");
        }
        assert!(
            root.request(mesh_ask(WG, Vec::new(), &[]))
                .unwrap_err()
                .contains("not up"),
            "a set before an up"
        );
        assert!(root.hands.reached().is_empty(), "{:?}", root.hands.reached());
        // A root part that was told no mesh makes none, and none with no cluster's range.
        let none = Book::new();
        let nobody = Direct::with(Fake::default(), &none);
        assert!(up(&nobody, prefix).unwrap_err().contains("no mesh"));
        none.set_mesh(WG.into(), 51820, PathBuf::from("/nowhere/mesh.key"), "a".into())
            .unwrap();
        assert!(up(&nobody, prefix).unwrap_err().contains("range"));
        assert!(nobody.hands.reached().is_empty());
        // The first cluster told is the one: another is refused.
        assert!(book.set_prefix(other).is_err());
        book.set_prefix(prefix).unwrap();
        // Up: the key comes back, and it is the node's address that is its own from now on.
        assert!(matches!(up(&root, prefix).unwrap(), Reply::Key(key) if key == [7; 32]));
        assert_eq!(root.hands.reached(), ["mesh_up"]);
        let refused = |request: Request| root.request(request).unwrap_err();
        let bad = [
            // Not the interface kith made.
            mesh_ask("eth0", vec![peer(1, vec![net("b")])], &[]),
            // Allowed addresses outside the cluster's mesh, or the whole of it, or a part of it
            // that is no node's /80 (a service's, a node's own, one with its address in it).
            mesh_ask(
                WG,
                vec![peer(1, vec![(IpAddr::V6(kith_mesh::node_net(other, "b")), 80)])],
                &[],
            ),
            mesh_ask(
                WG,
                vec![peer(1, vec![(IpAddr::V6("fe80::".parse().unwrap()), 80)])],
                &[],
            ),
            mesh_ask(WG, vec![peer(1, vec![("10.0.0.0".parse().unwrap(), 24)])], &[]),
            mesh_ask(WG, vec![peer(1, vec![(IpAddr::V6(prefix), 48)])], &[]),
            mesh_ask(WG, vec![peer(1, vec![(IpAddr::V6(prefix), 0)])], &[]),
            mesh_ask(
                WG,
                vec![peer(1, vec![(IpAddr::V6(kith_mesh::node_net(prefix, "b")), 64)])],
                &[],
            ),
            mesh_ask(
                WG,
                vec![peer(1, vec![(IpAddr::V6(kith_mesh::node_net(prefix, "b")), 200)])],
                &[],
            ),
            mesh_ask(WG, vec![peer(1, vec![net("a")])], &[]),
            mesh_ask(WG, vec![peer(1, vec![(IpAddr::V6(mine), 128)])], &[]),
            mesh_ask(WG, vec![peer(1, vec![(IpAddr::V6(service), 80)])], &[]),
            mesh_ask(WG, vec![peer(1, vec![(IpAddr::V6(service), 128)])], &[]),
            // (One bad allowed address among good ones refuses all.)
            mesh_ask(WG, vec![peer(1, vec![net("b")]), peer(2, vec![net("a")])], &[]),
            mesh_ask(WG, vec![peer(0, vec![net("b")])], &[]),
            // A key twice is one peer's allowed addresses taken from another's.
            mesh_ask(WG, vec![peer(1, vec![net("b")]), peer(1, vec![net("c")])], &[]),
            // An IPv4 address in IPv6's clothes is no node's /80.
            mesh_ask(
                WG,
                vec![peer(1, vec![(IpAddr::V6("::ffff:10.0.0.1".parse().unwrap()), 80)])],
                &[],
            ),
            mesh_ask(
                WG,
                vec![peer(1, vec![(IpAddr::V6("::ffff:10.0.0.0".parse().unwrap()), 128)])],
                &[],
            ),
            // Addresses of services only, in the cluster's, and never the node's own.
            mesh_ask(WG, Vec::new(), &[mine]),
            mesh_ask(WG, Vec::new(), &[kith_mesh::node_address(prefix, "b")]),
            mesh_ask(WG, Vec::new(), &[kith_mesh::service_address(other, "default", "web")]),
            mesh_ask(WG, Vec::new(), &[service, "fe80::1".parse().unwrap()]),
        ];
        // Where a peer is called: not this machine, not nowhere, not into the mesh itself (a
        // peer's packets would go to the node's own traffic, or round the mesh), not port 0.
        let node_b = kith_mesh::node_address(prefix, "b");
        let mut bad = bad.to_vec();
        for endpoint in [
            "127.0.0.1:51820".to_string(),
            "127.5.5.5:51820".into(),
            "[::1]:51820".into(),
            "0.0.0.0:51820".into(),
            "[::]:51820".into(),
            "[::ffff:127.0.0.1]:51820".into(),
            "[::ffff:0.0.0.0]:51820".into(),
            format!("[{node_b}]:51820"),
            format!("[{mine}]:51820"),
            format!("[{service}]:51820"),
            "203.0.113.2:0".into(),
        ] {
            let endpoint: SocketAddr = endpoint.parse().unwrap();
            let called = kith_mesh::Peer {
                endpoint: Some(endpoint),
                ..peer(1, vec![net("b")])
            };
            bad.push(mesh_ask(WG, vec![called], &[]));
        }
        for request in bad {
            let why = refused(request.clone());
            assert!(
                why.contains("mesh") || why.contains("interface") || why.contains("key"),
                "{request:?}: {why}"
            );
        }
        assert_eq!(
            root.hands.reached(),
            ["mesh_up"],
            "a refused request reached the machine"
        );
        // What is right does: peers' /80s of the cluster (several: a relay's), services' addresses.
        // (A peer with no endpoint, and one at an IPv6 one, are right too.)
        let roaming = kith_mesh::Peer {
            endpoint: None,
            ..peer(3, vec![net("d")])
        };
        let v6 = kith_mesh::Peer {
            endpoint: Some("[2001:db8::1]:51820".parse().unwrap()),
            ..peer(4, vec![net("e")])
        };
        let good = mesh_ask(
            WG,
            vec![peer(1, vec![net("b"), net("c")]), peer(2, Vec::new()), roaming, v6],
            &[service],
        );
        assert!(matches!(root.request(good).unwrap(), Reply::Done));
        assert_eq!(root.hands.reached(), ["mesh_up", "mesh"]);
        assert!(matches!(
            root.request(Request::MeshSeen { interface: WG.into() }),
            Ok(Reply::Seen(_))
        ));
        assert!(
            root.request(Request::MeshSeen {
                interface: "eth0".into()
            })
            .is_err()
        );
        assert!(
            root.request(Request::MeshDown {
                interface: "eth0".into()
            })
            .is_err()
        );
        assert!(matches!(
            root.request(Request::MeshDown { interface: WG.into() }),
            Ok(Reply::Done)
        ));
        assert_eq!(root.hands.reached(), ["mesh_up", "mesh", "mesh_seen", "mesh_down"]);
        // The wire reads it as it is sent, and no other field.
        let sent = serde_json::to_vec(&mesh_ask(WG, vec![peer(1, vec![net("b")])], &[service])).unwrap();
        assert_eq!(
            decode(&sent).unwrap(),
            mesh_ask(WG, vec![peer(1, vec![net("b")])], &[service])
        );
        assert!(decode(br#"{"MeshSeen":{"interface":"kith0","path":"/x"}}"#).is_err());
    }

    #[test]
    fn a_mesh_request_is_on_the_wire_as_it_is_pinned() {
        // (The wire is the second process's one day: a field renamed here is a change to both.)
        let ask = mesh_ask(
            WG,
            vec![peer(1, vec![("fd12:3456:789a:bcde:f012::".parse().unwrap(), 80)])],
            &["fd12:3456:789a:ffff::1".parse().unwrap()],
        );
        let key = ["1"; 32].join(",");
        let literal = format!(
            r#"{{"Mesh":{{"interface":"kith0","peers":[{{"key":[{key}],"endpoint":"203.0.113.2:51820","allowed":[["fd12:3456:789a:bcde:f012::",80]],"keepalive":25}}],"addresses":["fd12:3456:789a:ffff::1"]}}}}"#
        );
        assert_eq!(serde_json::to_string(&ask).unwrap(), literal);
        assert_eq!(decode(literal.as_bytes()).unwrap(), ask);
        let up = Request::MeshUp {
            interface: WG.into(),
            address: "fd12:3456:789a:bcde:f012::1".parse().unwrap(),
        };
        let literal = r#"{"MeshUp":{"interface":"kith0","address":"fd12:3456:789a:bcde:f012::1"}}"#;
        assert_eq!(serde_json::to_string(&up).unwrap(), literal);
        assert_eq!(decode(literal.as_bytes()).unwrap(), up);
    }

    #[test]
    fn the_mesh_is_told_once_and_a_second_telling_that_differs_is_refused() {
        let book = Book::new();
        let key = || PathBuf::from("/nowhere/mesh.key");
        book.set_mesh(WG.into(), 51820, key(), "a".into()).unwrap();
        // The same again is heeded as nothing; another interface, port, key file or name is refused.
        book.set_mesh(WG.into(), 51820, key(), "a".into()).unwrap();
        for (interface, port, path, name) in [
            ("eth0", 51820, key(), "a"),
            (WG, 51821, key(), "a"),
            (WG, 51820, PathBuf::from("/elsewhere/mesh.key"), "a"),
            (WG, 51820, key(), "b"),
        ] {
            let why = book.set_mesh(interface.into(), port, path, name.into()).unwrap_err();
            assert!(why.contains("told"), "{why}");
        }
        // (What was told first still is: a prefix goes with it, and the up is for that name.)
        let prefix = kith_mesh::prefix(b"a cluster");
        book.set_prefix(prefix).unwrap();
        let root = Direct::with(Fake::default(), &book);
        let ask = |name: &str| Request::MeshUp {
            interface: WG.into(),
            address: kith_mesh::node_address(prefix, name),
        };
        assert!(root.request(ask("b")).is_err());
        assert!(root.request(ask("a")).is_ok());
    }

    #[test]
    fn a_node_is_up_as_the_name_it_was_told_and_never_as_another() {
        let (book, prefix) = meshed("a cluster");
        let root = Direct::with(Fake::default(), &book);
        let ask = |name: &str| Request::MeshUp {
            interface: WG.into(),
            address: kith_mesh::node_address(prefix, name),
        };
        let down = || Request::MeshDown { interface: WG.into() };
        let net = |name: &str| (IpAddr::V6(kith_mesh::node_net(prefix, name)), kith_mesh::NODE_BITS);
        // Another node's address is not this node's, before it is up and after.
        assert!(root.request(ask("b")).unwrap_err().contains("not this node's address"));
        root.request(ask("a")).unwrap();
        assert!(root.request(ask("b")).unwrap_err().contains("not this node's address"));
        // Down is not a way to a different one: it was told, not learned from the first up.
        root.request(down()).unwrap();
        assert!(root.request(ask("b")).unwrap_err().contains("not this node's address"));
        // Nor does b's /80 become the node's own to be left out: it is still a peer's.
        root.request(ask("a")).unwrap();
        assert!(root.request(mesh_ask(WG, vec![peer(1, vec![net("a")])], &[])).is_err());
        assert!(root.request(mesh_ask(WG, vec![peer(1, vec![net("b")])], &[])).is_ok());
        assert_eq!(root.hands.reached(), ["mesh_up", "mesh_down", "mesh_up", "mesh"]);
    }

    #[test]
    fn what_fails_leaves_the_node_as_it_was() {
        let (book, prefix) = meshed("a cluster");
        let root = Direct::with(Fake::default(), &book);
        let net = |name: &str| (IpAddr::V6(kith_mesh::node_net(prefix, name)), kith_mesh::NODE_BITS);
        let set = || root.request(mesh_ask(WG, vec![peer(1, vec![net("b")])], &[]));
        let down = || root.request(Request::MeshDown { interface: WG.into() });
        let up_now = || book.mesh.lock().unwrap().as_ref().unwrap().up;
        // An up that failed is no up: the interface is not there, and none is set on it.
        root.hands.fail("mesh_up", true);
        assert!(up(&root, prefix).is_err());
        assert!(!up_now());
        assert!(set().unwrap_err().contains("not up"));
        // One that did not: the node is up.
        root.hands.fail("mesh_up", false);
        up(&root, prefix).unwrap();
        assert!(up_now());
        // A second up that fails leaves the first as it is: the link stays.
        root.hands.fail("mesh_up", true);
        assert!(up(&root, prefix).is_err());
        assert!(up_now());
        assert!(set().is_ok(), "the interface is still up");
        // A down that fails leaves the node as it was, with the link: it is still up.
        root.hands.fail("mesh_down", true);
        assert!(down().is_err());
        assert!(up_now());
        assert!(
            root.request(mesh_ask(WG, vec![peer(1, vec![net("a")])], &[])).is_err(),
            "the node's own /80 is still not a peer's"
        );
        // One that worked: it is not up.
        root.hands.fail("mesh_down", false);
        down().unwrap();
        assert!(!up_now());
        assert!(set().unwrap_err().contains("not up"));
    }

    #[test]
    fn mesh_requests_are_one_at_a_time_from_the_check_to_the_act() {
        let (book, prefix) = meshed("a cluster");
        let root = Direct::with(Fake::default(), &book);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| up(&root, prefix).unwrap());
            }
            for _ in 0..4 {
                scope.spawn(|| root.request(Request::MeshDown { interface: WG.into() }).ok());
            }
        });
        assert_eq!(
            root.hands.most.load(Ordering::SeqCst),
            1,
            "two were in the machine at once"
        );
        assert_eq!(root.hands.reached().len(), 12);
    }

    #[test]
    fn crossings_of_an_unchanged_mesh_are_none() {
        let (book, prefix) = meshed("a cluster");
        let root = Direct::with(Fake::default(), &book);
        up(&root, prefix).unwrap();
        let net = |name: &str| (IpAddr::V6(kith_mesh::node_net(prefix, name)), kith_mesh::NODE_BITS);
        let service = kith_mesh::service_address(prefix, "default", "web");
        let mut told = None;
        let mut set = |peers: Vec<kith_mesh::Peer>, addresses: &[Ipv6Addr]| {
            mesh(&root, &mut told, WG, peers, addresses.iter().copied().collect())
        };
        // The first is a crossing; the same every ten seconds after it is none.
        let b = || vec![peer(1, vec![net("b")])];
        assert!(set(b(), &[service]).unwrap());
        for _ in 0..50 {
            assert!(!set(b(), &[service]).unwrap());
        }
        assert_eq!(book.crossed(Kind::Mesh), 2, "the interface up and the first set");
        // A peer that changed (its endpoint, or one more) or an address is one crossing each.
        let moved = vec![kith_mesh::Peer {
            endpoint: None,
            ..peer(1, vec![net("b")])
        }];
        assert!(set(moved.clone(), &[service]).unwrap());
        assert!(set(moved.clone(), &[]).unwrap());
        assert!(!set(moved.clone(), &[]).unwrap());
        assert_eq!(book.crossed(Kind::Mesh), 4);
        // One refused is not taken for told: asked again next time, and counted.
        let bad = || vec![peer(1, vec![net("a")])];
        assert!(set(bad(), &[]).is_err());
        assert!(set(bad(), &[]).is_err());
        assert_eq!(book.crossed(Kind::Mesh), 6);
        assert!(!set(moved, &[]).unwrap(), "what was told last is still what is told");
        // Reading the handshakes is a crossing of its own kind and changes nothing.
        root.request(Request::MeshSeen { interface: WG.into() }).unwrap();
        assert_eq!((book.crossed(Kind::Mesh), book.crossed(Kind::Seen)), (6, 1));
        assert_eq!(
            book.crossed(Kind::Pod) + book.crossed(Kind::Create) + book.crossed(Kind::Start),
            0
        );
    }

    /// `n` connections into the pod `id`, through sockets made ahead, to a real listener.
    async fn connect_n(book: &Book, n: usize, v6_listener: bool) -> usize {
        let listener = match v6_listener {
            true => std::net::TcpListener::bind("[::1]:0"),
            false => std::net::TcpListener::bind("127.0.0.1:0"),
        };
        let Ok(listener) = listener else { return 0 };
        let port = listener.local_addr().unwrap().port();
        // (Answers each, or a backlog of 128 would hold back the 129th.)
        std::thread::spawn(move || {
            let kept: Vec<_> = listener.incoming().flatten().collect();
            drop(kept);
        });
        let root = Direct::with(Fake::default(), book);
        let pods = Mutex::new(Pods::default());
        let mut held = Vec::new();
        for at in 0..n {
            let one = crate::pods::through(&root, &pods, "w_a_b_0", port).await;
            held.push(one.unwrap_or_else(|e| panic!("connection {at} of {n}: {e}")));
        }
        assert_eq!(held.len(), n);
        book.crossed(Kind::Sockets)
    }

    #[tokio::test]
    async fn crossings_of_n_connections_into_a_pod_are_at_most_n_over_8_and_one() {
        for n in [1, 2, 8, 9, 10, 16, 17, 31, 100, 200] {
            let book = Book::new();
            let crossed = connect_n(&book, n, false).await;
            assert!(crossed <= n / 8 + 1, "{n} connections: {crossed} requests");
            assert!(crossed >= 1);
            // Nothing else crossed for them: no pod, no creation, no thread of the serving part's.
            assert_eq!(book.total(), crossed, "{n}");
        }
    }

    #[tokio::test]
    async fn crossings_of_connections_to_what_listens_on_ipv6_alone_are_the_same() {
        // (A machine with no IPv6 loopback has nothing to listen on: nothing to assert.)
        let book = Book::new();
        let crossed = connect_n(&book, 40, true).await;
        if crossed > 0 {
            // The family that last worked goes first: the v4 sockets tried once.
            assert!(crossed <= 40 / 8 + 2, "{crossed}");
        }
    }

    #[tokio::test]
    async fn crossings_of_connections_ask_nothing_while_sockets_are_spare_and_closed_with_the_pod() {
        let book = Book::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let root = Direct::with(Fake::default(), &book);
        let pods = Mutex::new(Pods::default());
        crate::pods::through(&root, &pods, "w_a_b_0", port).await.unwrap();
        // 16 made, one taken: seven more are taken from them with nothing asked.
        for _ in 0..7 {
            crate::pods::through(&root, &pods, "w_a_b_0", port).await.unwrap();
        }
        assert_eq!(book.crossed(Kind::Sockets), 1);
        // The pod is let go (it was never made: `keep` wants none): its spares are closed.
        pods.lock().unwrap().keep(|_| false);
        crate::pods::through(&root, &pods, "w_a_b_0", port).await.unwrap();
        assert_eq!(book.crossed(Kind::Sockets), 2);
        // A refused refill is the connection's error, with nothing spare.
        let (broken, _) = (Book::new(), ());
        let none = Direct::with(Nobody, &broken);
        let pods = Mutex::new(Pods::default());
        assert!(crate::pods::through(&none, &pods, "w_a_b_0", port).await.is_err());
        assert_eq!(broken.crossed(Kind::Sockets), 1);
    }

    // The Images family: Unpack and Drop name a digest; the path is the root part's own.

    const TAR: &str = "application/vnd.oci.image.layer.v1.tar";

    fn sha(bytes: &[u8]) -> String {
        format!(
            "sha256:{}",
            crate::pki::hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
        )
    }

    /// An image manifest of layers (the bytes of each, and the size it says it is): its text, and
    /// the digest of that.
    fn made_with(layers: &[(&[u8], usize)]) -> (String, String) {
        let layers: Vec<_> = layers
            .iter()
            .map(|(bytes, size)| serde_json::json!({"mediaType": TAR, "digest": sha(bytes), "size": size}))
            .collect();
        let text = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": sha(b"{}"), "size": 2},
            "layers": layers,
        })
        .to_string();
        (sha(text.as_bytes()), text)
    }

    fn made(layers: &[&[u8]]) -> (String, String) {
        made_with(&layers.iter().map(|bytes| (*bytes, bytes.len())).collect::<Vec<_>>())
    }

    /// A layer of one file, as the tar's bytes.
    fn layer(name: &str, body: &[u8]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, body).unwrap();
        tar.into_inner().unwrap()
    }

    /// `bytes` in a file of `dir`, opened.
    fn held(dir: &Path, bytes: &[u8]) -> File {
        let path = dir.join(sha(bytes).replace(':', "-"));
        std::fs::write(&path, bytes).unwrap();
        File::open(path).unwrap()
    }

    /// A root part whose images are in `state/runtime`, as kithd's are.
    fn imaged(name: &str) -> (Book, PathBuf, kith_runtime::ImageStore) {
        let (book, state) = book(name);
        let store = kith_runtime::ImageStore::new(state.join("runtime")).unwrap();
        (book, state, store)
    }

    fn unpack_ask(image: &str, manifest: &str) -> Request {
        Request::Unpack {
            image: image.into(),
            manifest: manifest.into(),
        }
    }

    /// Whether anything of an image is in the store (an unpacked one, or one on its way in).
    fn nothing_in(store: &kith_runtime::ImageStore) -> bool {
        std::fs::read_dir(store.root().join("images"))
            .unwrap()
            .flatten()
            .all(|e| e.file_name() == ".lock")
    }

    #[test]
    fn an_unpack_naming_a_path_or_no_digest_is_refused_whatever_the_caller_says() {
        let (book, state, store) = imaged("unpack-names");
        let root = Direct::with(Nobody, &book);
        let bytes = layer("a", b"one");
        let (good, manifest) = made(&[&bytes]);
        // The image is a digest: nothing else becomes a path.
        for bad in [
            "../../etc",
            "/etc/passwd",
            "sha256:../x",
            &good.to_uppercase(),
            "",
            "sha512:ab",
        ] {
            let ask = unpack_ask(bad, &manifest);
            assert!(check(&ask).is_err(), "{bad}");
            assert!(root.request_with(ask, vec![held(&state, &bytes)]).is_err(), "{bad}");
        }
        // A manifest that is not the image's, or no manifest: refused, and so is a file too many
        // or too few for its layers.
        let ask = unpack_ask(&sha(b"another"), &manifest);
        assert!(
            root.request_with(ask, vec![held(&state, &bytes)])
                .unwrap_err()
                .contains("manifest")
        );
        assert!(
            root.request_with(unpack_ask(&sha(b""), ""), vec![held(&state, &bytes)])
                .is_err()
        );
        let ask = unpack_ask(&good, &manifest);
        assert!(root.request_with(ask.clone(), vec![]).unwrap_err().contains("layer"));
        let two = vec![held(&state, &bytes), held(&state, &bytes)];
        assert!(root.request_with(ask.clone(), two).is_err());
        let many = (0..=MOST_LAYERS).map(|_| held(&state, &bytes)).collect();
        assert!(root.request_with(ask, many).unwrap_err().contains("at most"));
        // Nothing of it is in the store, and the wire reads it as pinned.
        assert!(nothing_in(&store));
        let wire = format!(
            r#"{{"Unpack":{{"image":"{good}","manifest":{}}}}}"#,
            serde_json::json!(manifest)
        );
        assert_eq!(decode(wire.as_bytes()).unwrap(), unpack_ask(&good, &manifest));
        assert!(decode(wire.replace("image", "path").as_bytes()).is_err());
        assert!(decode(wire.replace("manifest", "layers").as_bytes()).is_err());
    }

    #[test]
    fn an_unpack_is_into_the_nodes_own_store_whatever_the_state_holds() {
        let (book, state) = book("unpack-outside");
        let bytes = layer("a", b"one");
        let (image, manifest) = made(&[&bytes]);
        let root = Direct::with(Nobody, &book);
        let ask = unpack_ask(&image, &manifest);
        // No store where the node's is: not one to make.
        let why = root.request_with(ask.clone(), vec![held(&state, &bytes)]).unwrap_err();
        assert!(why.contains("not the node's own"), "{why}");
        assert!(!state.join("runtime").exists());
        // `state/runtime` a link to another store: that is not the node's.
        let (_, other, _) = imaged("unpack-elsewhere");
        std::os::unix::fs::symlink(other.join("runtime"), state.join("runtime")).unwrap();
        let why = root.request_with(ask, vec![held(&state, &bytes)]).unwrap_err();
        assert!(why.contains("not the node's own"), "{why}");
        let drop = Request::Drop {
            image: image.clone(),
            before: 1 << 40,
        };
        assert!(root.request(drop).unwrap_err().contains("not the node's own"));
        assert!(!other.join("runtime/images").join(&image["sha256:".len()..]).exists());
    }

    #[test]
    fn a_layer_that_is_not_the_digest_the_manifest_gives_it_is_refused_and_nothing_is_published() {
        let (book, state, store) = imaged("unpack-hash");
        let root = Direct::with(Nobody, &book);
        let (one, other) = (layer("a", b"one"), layer("a", b"another"));
        let (image, manifest) = made(&[&one]);
        let hex = &image["sha256:".len()..];
        let published = || store.root().join("images").join(hex).join("config.json").exists();
        let leftovers = || {
            std::fs::read_dir(store.root().join("images"))
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().contains("unpacking"))
                .count()
        };
        // The bytes are another layer's: a good tar, and not the manifest's.
        let ask = unpack_ask(&image, &manifest);
        let why = root.request_with(ask.clone(), vec![held(&state, &other)]).unwrap_err();
        assert!(why.contains("digest"), "{why}");
        assert!(!published() && leftovers() == 0);
        // The tar is the digest's, with more after its end (read, then hashed): refused all the same.
        let mut padded = one.clone();
        padded.extend_from_slice(b"junk after the end");
        assert!(root.request_with(ask.clone(), vec![held(&state, &padded)]).is_err());
        assert!(!published() && leftovers() == 0);
        // The second of two is the one that is wrong: the first's files are not published either.
        let (two, two_manifest) = made(&[&one, &one]);
        let ask2 = unpack_ask(&two, &two_manifest);
        let wrong = vec![held(&state, &one), held(&state, &other)];
        assert!(root.request_with(ask2.clone(), wrong).is_err());
        assert!(
            !store
                .root()
                .join("images")
                .join(&two["sha256:".len()..])
                .join("config.json")
                .exists()
        );
        assert_eq!(leftovers(), 0);
        // A layer that is not a file (a directory) is no layer.
        assert!(
            root.request_with(ask.clone(), vec![File::open(&state).unwrap()])
                .is_err()
        );
        assert!(!published());
        // Right layers in the wrong order are not the manifest's.
        let (both, both_manifest) = made(&[&one, &other]);
        let ask_both = unpack_ask(&both, &both_manifest);
        let swapped = vec![held(&state, &other), held(&state, &one)];
        assert!(root.request_with(ask_both.clone(), swapped).is_err());
        assert!(!store.root().join("images").join(&both["sha256:".len()..]).exists());
        // What is the digest it is given is unpacked, at the path the digest gives.
        let files = vec![held(&state, &one), held(&state, &other)];
        assert!(matches!(root.request_with(ask_both.clone(), files), Ok(Reply::Done)));
        let there = store.root().join("images").join(&both["sha256:".len()..]);
        assert_eq!(std::fs::read(there.join("rootfs/a")).unwrap(), b"another");
        // Asked again, it is there: nothing is made over.
        let again = vec![held(&state, &one), held(&state, &other)];
        assert!(matches!(root.request_with(ask_both, again), Ok(Reply::Done)));
        assert_eq!(book.crossed(Kind::Unpack), 7);
    }

    #[test]
    fn what_follows_a_layers_tar_is_part_of_its_digest() {
        let (book, state, store) = imaged("unpack-drain");
        let root = Direct::with(Nobody, &book);
        let mut padded = layer("a", b"one");
        padded.extend_from_slice(b"junk after the end");
        // The manifest names the digest of the tar and its junk: whole, it is what it names, and it
        // is accepted only because what the tar's end leaves is read and hashed too.
        let (image, manifest) = made(&[&padded]);
        let ask = unpack_ask(&image, &manifest);
        assert!(matches!(
            root.request_with(ask, vec![held(&state, &padded)]),
            Ok(Reply::Done)
        ));
        let there = store.root().join("images").join(&image["sha256:".len()..]);
        assert_eq!(std::fs::read(there.join("rootfs/a")).unwrap(), b"one");
    }

    #[test]
    fn a_layer_larger_than_the_manifest_says_is_refused_before_it_is_read() {
        let (book, state, store) = imaged("unpack-size");
        let root = Direct::with(Nobody, &book);
        let bytes = layer("a", b"one");
        // The digest is right; the size the manifest gives is less than the file's.
        let (image, manifest) = made_with(&[(&bytes, bytes.len() - 1)]);
        let ask = unpack_ask(&image, &manifest);
        let why = root.request_with(ask, vec![held(&state, &bytes)]).unwrap_err();
        assert!(why.contains("larger"), "{why}");
        assert!(nothing_in(&store));
        // (A size of nothing leaves no room for the file.)
        let (image, manifest) = made_with(&[(&bytes, 0)]);
        let ask = unpack_ask(&image, &manifest);
        assert!(root.request_with(ask, vec![held(&state, &bytes)]).is_err());
        assert!(nothing_in(&store));
    }

    #[test]
    fn a_drop_names_a_digest_and_frees_the_image_it_names() {
        let (book, state, store) = imaged("drop");
        let root = Direct::with(Nobody, &book);
        let bytes = layer("a", b"one");
        let (image, manifest) = made(&[&bytes]);
        let ask = unpack_ask(&image, &manifest);
        root.request_with(ask, vec![held(&state, &bytes)]).unwrap();
        for bad in ["../x", "sha256:", "/"] {
            assert!(
                root.request(Request::Drop {
                    image: bad.into(),
                    before: 1 << 40
                })
                .is_err()
            );
        }
        // (Used no later than `before`: an image used since stays.)
        let used = |before| Request::Drop {
            image: image.clone(),
            before,
        };
        assert!(matches!(root.request(used(0)), Ok(Reply::Freed(None))));
        let Ok(Reply::Freed(Some(freed))) = root.request(used(1 << 40)) else {
            panic!("not freed")
        };
        assert!(freed > 0);
        assert!(!store.root().join("images").join(&image["sha256:".len()..]).exists());
        assert_eq!((book.crossed(Kind::Drop), book.crossed(Kind::Unpack)), (5, 1));
    }

    #[test]
    fn a_drop_before_the_end_of_time_is_refused_and_does_not_panic() {
        let (book, _, _) = imaged("drop-forever");
        let root = Direct::with(Nobody, &book);
        let image = sha(b"the manifest");
        for before in [u64::MAX, u64::MAX - 1] {
            let why = root
                .request(Request::Drop {
                    image: image.clone(),
                    before,
                })
                .unwrap_err();
            assert!(why.contains("not a time"), "{why}");
        }
    }

    #[test]
    fn a_drop_of_an_image_a_container_bundle_names_is_refused_whatever_the_time() {
        let (book, state, store) = imaged("drop-in-use");
        let root = Direct::with(Nobody, &book);
        let bytes = layer("a", b"one");
        let (image, manifest) = made(&[&bytes]);
        root.request_with(unpack_ask(&image, &manifest), vec![held(&state, &bytes)])
            .unwrap();
        let hex = &image["sha256:".len()..];
        let bundle = store.root().join("containers/c1");
        std::fs::create_dir_all(&bundle).unwrap();
        let named = format!(
            r#"{{"root":{{"path":"{}/images/{hex}/rootfs"}}}}"#,
            store.root().display()
        );
        std::fs::write(bundle.join("config.json"), named).unwrap();
        let far = Request::Drop {
            image: image.clone(),
            before: 1 << 40,
        };
        assert!(matches!(root.request(far), Ok(Reply::Freed(None))));
        assert!(store.root().join("images").join(hex).join("config.json").exists());
        // The container gone, the image goes.
        std::fs::remove_dir_all(&bundle).unwrap();
        let far = Request::Drop { image, before: 1 << 40 };
        assert!(matches!(root.request(far), Ok(Reply::Freed(Some(_)))));
    }

    #[test]
    fn crossings_of_a_start_through_the_root_part_are_three_with_no_unpack_or_drop() {
        // (That a cached image is not unpacked is the pull's: `cached_image_is_asked_for_again_after_it_is_deleted`.)
        let (book, state, _) = imaged("unpack-cached");
        let root = Direct::with(Fake::default(), &book).under(policy("no-host-paths"));
        let pods = Mutex::new(Pods::default());
        pods.lock().unwrap().pretend("w_a_b_0", &state);
        // The ADR's three, and no more.
        start_one(&root, &pods, &state, "w_a_b_0", "first");
        assert_eq!(book.total(), 3);
        assert_eq!((book.crossed(Kind::Unpack), book.crossed(Kind::Drop)), (0, 0));
    }
}
