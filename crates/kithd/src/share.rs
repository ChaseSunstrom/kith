//! Shared volumes: a node serves its `shared: true` Volumes to the cluster's other nodes over
//! NFS 4.2, on its mesh address only, and a node that runs a replica mounting one from another
//! node mounts it under `<state>/remote/` and binds that into the container.
//!
//! The kernel does the serving and the mounting; kithd is the only helper. There is no mountd,
//! exportfs, rpcbind or mount.nfs: kithd starts the kernel's server through `/proc/fs/nfsd`
//! (versions, a listening socket it bound itself, threads) and answers the three questions the
//! kernel asks on its cache channels, as mountd would: who an address is (`auth.unix.ip`), what
//! a path is served as to them (`nfsd.export`), and what path a file handle names (`nfsd.fh`).
//! The answers are text made by [`Table`], from the store.
//!
//! Who gets what: only the mesh addresses of the cluster's own nodes are anybody (a container
//! has an address of its own, and is nobody); they are all one client, `kith`. That client sees
//! `<state>/volumes` as the root, read-only and showing nothing but the directories on the way
//! to a served volume, and each served volume's directory read-write.
//
// ponytail: a node that mounts is trusted as root on what it mounts (AUTH_SYS, no squashing),
// as every node is trusted today; and a file handle is not tied to its volume's directory (no
// subtree check), so a node could reach the rest of that file system by guessing handles.
// Kerberos or per-volume file systems would close both.
// ponytail: an answer is good for two minutes, so a volume that stops being shared is served
// that long; nothing stops the kernel's server once started; four server threads; leases and
// the grace period after a restart are 30 seconds, with no record of clients kept across one.

use crate::root_part::{Direct, Proto, Reply, Request, Root};
use crate::volumes::Dir;
use kith_api::kinds::ShareSpec;
use kith_api::store::Store;
use nix::mount::{MntFlags, MsFlags};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// NFS's port, on the mesh address.
pub const PORT: u16 = 2049;
/// The one client the kernel is told of: any node of the cluster.
const CLIENT: &str = "kith";
/// What the client of machines that are not nodes starts with: then the Shares that name it.
const LAN: &str = "share:";
/// How long the kernel may keep an answer, in seconds.
const GOOD_FOR: u64 = 120;
/// Who a Share's clients are on its files unless it says.
const NOBODY: u32 = 65534;
/// How often what is served is worked out again.
const ROUND: Duration = Duration::from_secs(3);
/// Says the kernel's server on this machine is the one kithd started (gone at a reboot, as it is).
const OURS: &str = "/run/kith-nfsd";

// The kernel's export flags (include/uapi/linux/nfsd/export.h).
const READONLY: u32 = 0x1;
const ROOTSQUASH: u32 = 0x4;
const ALLSQUASH: u32 = 0x8;
/// From any port of the client: what is not Linux (macOS, Windows) mounts from a high one.
const ANYPORT: u32 = 0x2;
const NOSUBTREECHECK: u32 = 0x400;
const FSID: u32 = 0x2000;
const V4ROOT: u32 = 0x10000;

/// What this node serves, and to whom.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Table {
    /// `<state>/volumes`: what a client sees as `/`.
    pub root: PathBuf,
    /// The served volumes' directories, as the kernel names them (no links, no `..`).
    pub served: BTreeSet<PathBuf>,
    /// The mesh addresses of the cluster's nodes.
    pub clients: BTreeSet<Ipv6Addr>,
    /// The Shares (`NAMESPACE/NAME`) of volumes on this node that name NFS clients.
    pub shares: BTreeMap<String, Lan>,
    /// The IPv4 addresses of this node and of the cluster's other nodes: never a Share's
    /// client, whatever range a Share names (a container has its node's address).
    pub nodes: BTreeSet<Ipv4Addr>,
}

/// A Share's volume as this node serves it to machines that are not nodes.
#[derive(Debug, Clone, PartialEq)]
pub struct Lan {
    pub dir: PathBuf,
    /// IPv4 networks and their prefix lengths.
    pub clients: Vec<(Ipv4Addr, u32)>,
    pub read_only: bool,
    /// Who every client is on the volume's files, whoever it says it is.
    pub owner: (u32, u32),
}

impl Lan {
    fn has(&self, address: Ipv4Addr) -> bool {
        let within = |(net, length): &(Ipv4Addr, u32)| {
            let shift = 32 - length.min(&32);
            u32::from(*net).checked_shr(shift) == u32::from(address).checked_shr(shift)
        };
        self.clients.iter().any(within)
    }
}

/// A field as the kernel writes and reads one: `\ooo` for a space, tab, newline or backslash.
fn quote(field: &str) -> String {
    let mut quoted = String::new();
    for c in field.chars() {
        match c {
            ' ' | '\t' | '\n' | '\\' => quoted.push_str(&format!("\\{:03o}", c as u8)),
            c => quoted.push(c),
        }
    }
    quoted
}

fn unquote(field: &str) -> Option<String> {
    let (mut bytes, mut rest) = (Vec::new(), field.as_bytes());
    while let Some((&first, after)) = rest.split_first() {
        if first == b'\\' {
            let octal = std::str::from_utf8(after.get(..3)?).ok()?;
            bytes.push(u8::from_str_radix(octal, 8).ok()?);
            rest = &after[3..];
        } else {
            bytes.push(first);
            rest = after;
        }
    }
    String::from_utf8(bytes).ok()
}

/// Bytes written `\x0a1b…`, as the kernel writes a file handle's key.
fn unhex(field: &str) -> Option<Vec<u8>> {
    let digits = field.strip_prefix("\\x")?;
    let byte = |at: usize| u8::from_str_radix(digits.get(at..at + 2)?, 16).ok();
    (digits.len() % 2 == 0).then(|| (0..digits.len()).step_by(2).map(byte).collect())?
}

impl Table {
    /// The 16 bytes a directory under the root is known by in file handles: the same after a
    /// restart, and on a volume made again at the same place.
    fn id(&self, path: &Path) -> [u8; 16] {
        let under = path.strip_prefix(&self.root).unwrap_or(path);
        let named = [b"kith shared volume\0", under.as_os_str().as_encoded_bytes()].concat();
        let digest = ring::digest::digest(&ring::digest::SHA256, &named);
        digest.as_ref()[..16].try_into().expect("a SHA-256 is 32 bytes")
    }

    /// What `client` is served: every shared volume if it is the cluster's nodes, the volumes
    /// of the Shares it is named for if it is `share:…`, nothing otherwise.
    fn dirs(&self, client: &str) -> Vec<&Path> {
        let shares = client.strip_prefix(LAN).into_iter().flat_map(|names| names.split(','));
        let shares = shares.filter_map(|name| Some(self.shares.get(name)?.dir.as_path()));
        let nodes = self.served.iter().map(PathBuf::as_path);
        nodes.filter(|_| client == CLIENT).chain(shares).collect()
    }

    /// The directories strictly between the root and a volume served to `client`: shown, and
    /// nothing in them.
    fn on_the_way(&self, client: &str) -> BTreeSet<&Path> {
        let mut found = BTreeSet::new();
        for dir in self.dirs(client) {
            let above = dir.ancestors().skip(1);
            found.extend(above.take_while(|up| *up != self.root && up.starts_with(&self.root)));
        }
        found
    }

    /// `auth.unix.ip` asks `CLASS ADDRESS`: a node's mesh address is the client `kith`, an
    /// IPv4 address some Shares name is the client `share:` and those Shares, and anything
    /// else is nobody.
    fn who(&self, asked: &str, until: u64) -> Option<String> {
        let (class, address) = asked.split_once(' ')?;
        let parsed = address.parse::<IpAddr>().ok().filter(|_| class == "nfsd");
        let client = match parsed {
            Some(IpAddr::V6(address)) if self.clients.contains(&address) => format!(" {CLIENT}"),
            Some(address) => {
                let address = match address {
                    IpAddr::V4(address) => Some(address),
                    IpAddr::V6(address) => address.to_ipv4_mapped(),
                };
                let address = address.filter(|address| !address.is_loopback() && !self.nodes.contains(address));
                let named = |(_, lan): &(&String, &Lan)| address.is_some_and(|address| lan.has(address));
                let names: Vec<&str> = self
                    .shares
                    .iter()
                    .filter(named)
                    .map(|(name, _)| name.as_str())
                    .collect();
                if names.is_empty() {
                    String::new()
                } else {
                    format!(" {LAN}{}", names.join(","))
                }
            }
            None => String::new(),
        };
        Some(format!("{class} {address} {until}{client}"))
    }

    /// `nfsd.export` asks `CLIENT PATH`: the root and the directories on the way to a served
    /// volume are read-only and show only what leads on; a served volume is read-write; anything
    /// else, or any other client, is not served.
    fn export(&self, asked: &str, until: u64) -> Option<String> {
        let (client, quoted) = asked.split_once(' ')?;
        let path = PathBuf::from(unquote(quoted)?);
        let any = if client.starts_with(LAN) { ANYPORT } else { 0 };
        let way = READONLY | ROOTSQUASH | NOSUBTREECHECK | V4ROOT | any;
        let id = || format!("uuid \\x{}", crate::pki::hex(&self.id(&path)));
        let dirs = self.dirs(client);
        // A Share's volume: every client is the Share's one user, and (the kernel checking
        // that a file handle names something under the volume) reaches nothing beside it.
        let shares = client.strip_prefix(LAN).into_iter().flat_map(|names| names.split(','));
        let lan = shares
            .filter_map(|name| self.shares.get(name))
            .find(|lan| lan.dir == path);
        let served = if dirs.is_empty() {
            String::new()
        } else if path == self.root {
            format!(" {} 65534 65534 0", way | FSID)
        } else if let Some(lan) = lan {
            let flags = ALLSQUASH | ANYPORT | if lan.read_only { READONLY } else { 0 };
            format!(" {flags} {} {} 0 {}", lan.owner.0, lan.owner.1, id())
        } else if dirs.contains(&path.as_path()) {
            format!(" {NOSUBTREECHECK} 65534 65534 0 {}", id())
        } else if self.on_the_way(client).contains(path.as_path()) {
            format!(" {way} 65534 65534 0 {}", id())
        } else {
            String::new()
        };
        Some(format!("{client} {quoted} {until}{served}"))
    }

    /// `nfsd.fh` asks `CLIENT TYPE \xKEY`, the start of a file handle: the root's is the number
    /// 0 (type 1); any other's ends in the 16 bytes of [`Table::id`] (types 6 and 7).
    fn handle(&self, asked: &str, until: u64) -> Option<String> {
        let mut fields = asked.split(' ');
        let (client, kind, key) = (fields.next()?, fields.next()?, fields.next()?);
        let bytes = unhex(key)?;
        let known = || {
            let id = bytes.get(bytes.len().checked_sub(16)?..)?;
            let all = self.dirs(client).into_iter().chain(self.on_the_way(client));
            all.into_iter().find(|path| self.id(path) == id)
        };
        let path = match kind {
            _ if self.dirs(client).is_empty() => None,
            "1" if bytes == [0; 4] => Some(self.root.as_path()),
            "6" | "7" => known(),
            _ => None,
        };
        let path = path.and_then(Path::to_str).map(|path| format!(" {}", quote(path)));
        Some(format!("{client} {kind} {key} {until}{}", path.unwrap_or_default()))
    }
}

/// What a node mounts a volume of `server` from, and with what: NFS 4.2 over TCP to the
/// server's mesh address, from this node's (`me`), waiting for a server that is away.
fn source(server: Ipv6Addr, me: Ipv6Addr, dir: &Dir) -> (String, String) {
    (
        format!("[{server}]:/{}/{}/{}", dir.namespace, dir.name, dir.path),
        format!("vers=4.2,proto=tcp6,port={PORT},addr={server},clientaddr={me},sec=sys,hard"),
    )
}

/// What is mounted at or under `under`, from `/proc/self/mountinfo`: where, and from what (both
/// as that file writes them: [`quote`]d).
fn mounted<'a>(mountinfo: &'a str, under: &str) -> Vec<(&'a str, &'a str)> {
    let read = |line: &'a str| {
        let (before, after) = line.split_once(" - ")?;
        let (at, from) = (before.split(' ').nth(4)?, after.split(' ').nth(1)?);
        let inside = at
            .strip_prefix(under)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
        inside.then_some((at, from))
    };
    mountinfo.lines().filter_map(read).collect()
}

/// Where on this node a volume of another node is mounted.
fn target(state: &Path, dir: &Dir) -> Result<PathBuf, String> {
    let mut target = state.join("remote");
    for part in [&dir.node, &dir.namespace, &dir.name] {
        // (A Volume names its node as it likes; nothing is mounted outside `remote` for that.)
        if part.is_empty() || part.contains(['/', '\0']) || matches!(part.as_str(), "." | "..") {
            return Err(format!("`{part}` cannot be part of where it is mounted"));
        }
        target.push(part);
    }
    Ok(target)
}

/// Mount a shared volume of another node here (unless it is already), and say where.
/// `prefix` is the cluster's mesh; `me` this node's name.
pub async fn mount(state: &Path, dir: &Dir, prefix: Ipv6Addr, me: &str) -> Result<PathBuf, String> {
    let state = state.canonicalize().map_err(|e| format!("{}: {e}", state.display()))?;
    let target = target(&state, dir)?;
    let server = kith_mesh::node_address(prefix, &dir.node);
    let (from, options) = source(server, kith_mesh::node_address(prefix, me), dir);
    let at = quote(target.to_str().ok_or("its mount point is not text")?);
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    // (What is mounted there itself, and the newest if something is mounted over it.)
    match mounted(&mountinfo, &at).iter().rfind(|(found, _)| *found == at) {
        Some((_, found)) if *found == quote(&from) => return Ok(target),
        // (Its Volume was given another path: what is mounted is not it any more.)
        Some(_) => detach(target.clone())
            .await
            .map_err(|e| format!("unmounting what was there: {e}"))?,
        None => {}
    }
    std::fs::create_dir_all(&target).map_err(|e| format!("cannot make {}: {e}", target.display()))?;
    // The mount itself waits minutes for a server that is not there, and nothing here may:
    // ask first, briefly, and once for the node whatever number of units start (a node that
    // does not answer costs the two seconds once a round, not once a unit).
    let away = || {
        format!(
            "node {} does not serve it (no answer on its mesh address, port {PORT}): is it up, and is the volume `shared`?",
            dir.node
        )
    };
    let up = match PROBES.recall(server, Instant::now()) {
        Some(up) => up,
        None => {
            let asked =
                tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect((server, PORT))).await;
            let up = matches!(asked, Ok(Ok(_)));
            PROBES.note(server, Instant::now(), up);
            up
        }
    };
    if !up {
        return Err(away());
    }
    let mounting = {
        let target = target.clone();
        move || {
            nix::mount::mount(
                Some(from.as_str()),
                &target,
                Some("nfs4"),
                // A set-uid file or a device node another node's workload wrote is not honoured on this node (a container's own bind is nosuid and nodev already); no noexec: containers run programs from their volumes.
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                Some(options.as_str()),
            )
        }
    };
    let done = tokio::task::spawn_blocking(mounting).await.map_err(|e| e.to_string())?;
    done.map_err(|e| format!("mounting it from node {}: {e}", dir.node))?;
    eprintln!(
        "kithd: mounted volume {}/{} from node {}",
        dir.namespace, dir.name, dir.node
    );
    Ok(target)
}

/// Unmount the other nodes' volumes that nothing here mounts any more: every mount under
/// `<state>/remote` that is not for one of `used`. (What still has files open in one keeps it
/// until it is done; nothing waits for a server that is away.)
pub async fn release(state: &Path, used: &[&Dir]) {
    let Ok(state) = state.canonicalize() else { return };
    let (remote, mountinfo) = (state.join("remote"), std::fs::read_to_string("/proc/self/mountinfo"));
    let (true, Some(under), Ok(mountinfo)) = (remote.exists(), remote.to_str(), mountinfo) else {
        return;
    };
    let used: Vec<String> = used
        .iter()
        .filter_map(|dir| Some(quote(target(&state, dir).ok()?.to_str()?)))
        .collect();
    for (at, _) in mounted(&mountinfo, &quote(under)) {
        if let (false, Some(path)) = (used.iter().any(|used| used == at), unquote(at)) {
            match detach(PathBuf::from(&path)).await {
                Ok(()) => eprintln!("kithd: unmounted {path}: nothing here mounts it"),
                Err(e) => eprintln!("kithd: cannot unmount {path}: {e}"),
            }
        }
    }
}

/// Lazily unmount `path`, off the async thread: the call can wait on the kernel for as long as
/// the file system's server is away.
async fn detach(path: PathBuf) -> Result<(), String> {
    off_thread(move || nix::mount::umount2(&path, MntFlags::MNT_DETACH).map_err(|e| e.to_string())).await
}

/// Run `work` on a thread tokio keeps for what may block, and wait for it.
async fn off_thread<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work)
        .await
        .expect("work that blocks does not panic")
}

/// How long what a probe of a node found is believed: a bit under a scheduler round, so each
/// round asks once for each node and the next asks again.
const PROBED_FOR: Duration = Duration::from_secs(5);

/// Which nodes answered the last probe of their NFS port, and when.
struct Probes(Mutex<BTreeMap<Ipv6Addr, (Instant, bool)>>);

static PROBES: Probes = Probes(Mutex::new(BTreeMap::new()));

impl Probes {
    /// What the probe of `server` found, if one was made within [`PROBED_FOR`] of `now`.
    fn recall(&self, server: Ipv6Addr, now: Instant) -> Option<bool> {
        let found = self.0.lock().expect("nothing panics holding the probes");
        let (at, up) = found.get(&server)?;
        (now.saturating_duration_since(*at) < PROBED_FOR).then_some(*up)
    }

    fn note(&self, server: Ipv6Addr, now: Instant, up: bool) {
        let mut found = self.0.lock().expect("nothing panics holding the probes");
        // (Those too old to be believed are forgotten: nodes come and go.)
        found.retain(|_, (at, _)| now.saturating_duration_since(*at) < PROBED_FOR);
        found.insert(server, (now, up));
    }
}

/// Whether the kernel's NFS server here already runs as kithd started it; an error if it runs
/// and is somebody else's (theirs to answer for, not kithd's).
fn running() -> Result<bool, String> {
    let control = Path::new("/proc/fs/nfsd");
    if !control.join("threads").exists() {
        let mounted = nix::mount::mount(Some("nfsd"), control, Some("nfsd"), MsFlags::empty(), None::<&str>);
        mounted.map_err(|e| format!("this kernel has no NFS server kithd may start ({e})"))?;
    }
    let threads = std::fs::read_to_string(control.join("threads")).unwrap_or_default();
    match (threads.trim() != "0", Path::new(OURS).exists()) {
        (true, false) => Err("this machine already runs an NFS server that is not kithd's".into()),
        (running, _) => Ok(running),
    }
}

/// Start the kernel's NFS server: 4.2 only (so no rpcbind and no lock manager), listening on
/// `address` alone: the socket is bound here and handed over, where a port alone would listen
/// on every address.
fn start(address: Ipv6Addr) -> Result<(), String> {
    let control = Path::new("/proc/fs/nfsd");
    let tell = |name: &str, text: &str| std::fs::write(control.join(name), text).map_err(|e| format!("{name}: {e}"));
    let listening = std::fs::read_to_string(control.join("portlist")).unwrap_or_default();
    // (All but the threads cannot be said twice: an earlier try may have got that far. The
    // kernel lists a listener as `tcp 2049`, whatever its address: any line is one.)
    if listening.trim().is_empty() {
        tell("versions", "-3 +4 -4.0 -4.1 +4.2\n")?;
        tell("nfsv4leasetime", "30\n")?;
        tell("nfsv4gracetime", "30\n")?;
        listen(IpAddr::V6(address))?;
    }
    std::fs::write(OURS, "").map_err(|e| format!("{OURS}: {e}"))?;
    tell("threads", "4\n")
}

/// Have the kernel's server listen on `address` too (a socket bound here and handed over).
fn listen(address: IpAddr) -> Result<(), String> {
    let given = listen_at(address, PORT, |listener| {
        std::fs::write("/proc/fs/nfsd/portlist", format!("{}\n", listener.as_raw_fd()))
            .map_err(|e| format!("portlist: {e}"))
    });
    // (Where the port is held, and the server is the one kithd started, the port is held by
    // that server: kithd's last start made this listener, and a restart does not unmake it.)
    let held = std::fs::read_to_string("/proc/fs/nfsd/portlist").is_ok_and(|ports| !ports.trim().is_empty());
    match given {
        Err(e) if held && in_use(&e) => Ok(()),
        given => given,
    }
}

/// Whether a bind's error is EADDRINUSE (98 on Linux), whatever the C library calls it
/// (musl says "Address in use", glibc "Address already in use").
fn in_use(error: &str) -> bool {
    error.contains("(os error 98)")
}

/// Bind `address` and `port` and hand the socket to `give`. The socket is closed when `give`
/// returns (the kernel has its own hold on one it was given), so a bind after that finds
/// nothing of this process's holding the port.
fn listen_at(
    address: IpAddr,
    port: u16,
    give: impl FnOnce(std::os::fd::OwnedFd) -> Result<(), String>,
) -> Result<(), String> {
    let listener = Direct::new().request(Request::Bind {
        address,
        port,
        proto: Proto::Tcp,
    })?;
    let Reply::Socket(listener) = listener else {
        return Err("the root part answered a bind with something else".into());
    };
    give(listener)
}

/// Where a node says it is reached, as IPv4 addresses: its LAN one (`status.lan`, once the leader
/// has moved `status.address` onto the mesh) and its `status.address` if that is one too.
fn reached(node: &kith_api::Resource) -> Vec<Ipv4Addr> {
    let at = node.node_addresses();
    let at = at.filter_map(|address| address.parse::<std::net::SocketAddr>().ok());
    at.filter_map(|address| match address.ip() {
        IpAddr::V4(address) => Some(address),
        IpAddr::V6(address) => address.to_ipv4_mapped(),
    })
    .collect()
}

/// The Shares of volumes on `me` that name NFS clients: each one's name, its volume, and what
/// [`Table`] has of it but for where the volume's directory is on this node.
fn lans(store: &Store, me: &str) -> Vec<(String, Dir, Lan)> {
    let mut found: Vec<(String, Dir, Lan)> = Vec::new();
    for share in store.list(Some("Share")) {
        let Ok(spec) = serde_json::from_value::<ShareSpec>(share.spec.clone()) else {
            continue;
        };
        let namespace = share.metadata.namespace.as_deref().unwrap_or("default");
        let clients = spec.nfs.iter().flat_map(|nfs| &nfs.clients);
        let clients: Vec<_> = clients
            .filter_map(|client| kith_api::kinds::share_client(client))
            .collect();
        let dir = crate::volumes::dir(store, namespace, &spec.volume).filter(|dir| dir.node == me);
        // (One in `kith-system` is anywhere on the host, not under what is served: not given.)
        let dir = dir.filter(|dir| dir.namespace != crate::volumes::SYSTEM && !clients.is_empty());
        // (One Share gives a volume over NFS: the first by name; a second says so in its status.)
        let dir = dir.filter(|dir| !found.iter().any(|(_, given, _)| given == dir));
        if let Some(dir) = dir {
            let lan = Lan {
                dir: PathBuf::new(),
                clients,
                read_only: spec.read_only == Some(true),
                owner: (spec.uid.unwrap_or(NOBODY), spec.gid.unwrap_or(NOBODY)),
            };
            found.push((format!("{namespace}/{}", share.metadata.name), dir, lan));
        }
    }
    found
}

/// The leader's part: what each Share's status should say, where it says otherwise. Where
/// its volume is (`node`, and `path` as an NFS client names it), or why it is given to nobody.
pub fn writes(store: &Store) -> Vec<(String, Option<Value>)> {
    let mut writes = Vec::new();
    // Which Share gives each volume over NFS: the first by name.
    let mut nfs: BTreeMap<Dir, String> = BTreeMap::new();
    for share in store.list(Some("Share")) {
        let Ok(spec) = serde_json::from_value::<ShareSpec>(share.spec.clone()) else {
            continue;
        };
        let namespace = share.metadata.namespace.as_deref().unwrap_or("default");
        let unknown = |user: &&String| store.get(&format!("Identity/{user}")).is_none();
        let names = spec.nfs.as_ref().is_some_and(|nfs| !nfs.clients.is_empty());
        if let (true, Some(dir)) = (names, crate::volumes::dir(store, namespace, &spec.volume)) {
            nfs.entry(dir).or_insert_with(|| share.metadata.name.clone());
        }
        let status = match (
            crate::volumes::dir(store, namespace, &spec.volume),
            spec.users.iter().find(unknown),
        ) {
            (None, _) => json!({ "message": format!("there is no Volume {} it can give", spec.volume) }),
            (Some(dir), _) if dir.namespace == crate::volumes::SYSTEM => {
                json!({ "message": format!("a Volume in {} cannot be given", crate::volumes::SYSTEM) })
            }
            (Some(_), Some(user)) => json!({ "message": format!("there is no Identity {user}") }),
            (Some(dir), None) if names && nfs.get(&dir).is_some_and(|first| *first != share.metadata.name) => {
                json!({ "message": format!("the Share {} gives that volume over NFS already: one does", nfs[&dir]) })
            }
            (Some(_), None) if spec.users.is_empty() && spec.nfs.is_none_or(|nfs| nfs.clients.is_empty()) => {
                json!({ "message": "it is given to nobody: name `nfs.clients` or `users`" })
            }
            (Some(dir), None) => {
                let mut said =
                    json!({ "node": dir.node, "path": format!("/{}/{}/{}", dir.namespace, dir.name, dir.path) });
                // Whether that node serves it over NFS, as the node itself says (`status.shares`
                // of its Node; false until it has said so, as when it is down).
                if names {
                    let name = format!("{namespace}/{}", share.metadata.name);
                    let node = store.get(&format!("Node/{}", dir.node));
                    let serving = node.and_then(|node| node.status.as_ref()?["shares"].as_array());
                    said["served"] = json!(serving.is_some_and(|names| names.iter().any(|served| *served == name)));
                }
                said
            }
        };
        if share.status.as_ref() != Some(&status) {
            writes.push((share.key(), Some(status)));
        }
    }
    writes
}

/// Answer the kernel's questions from `table`, for as long as this process lives.
fn answer(table: Arc<Mutex<Table>>) -> Result<(), String> {
    type Answer = fn(&Table, &str, u64) -> Option<String>;
    let channels: [(&str, Answer); 3] = [
        ("auth.unix.ip", Table::who),
        ("nfsd.export", Table::export),
        ("nfsd.fh", Table::handle),
    ];
    let mut open = Vec::new();
    for (name, answer) in channels {
        let path = format!("/proc/net/rpc/{name}/channel");
        let channel = std::fs::OpenOptions::new().read(true).write(true).open(&path);
        open.push((channel.map_err(|e| format!("{path}: {e}"))?, answer));
    }
    let serve = move || {
        loop {
            let mut waiting: Vec<_> = open
                .iter()
                .map(|(file, _)| nix::poll::PollFd::new(file.as_fd(), nix::poll::PollFlags::POLLIN))
                .collect();
            if let Err(e) = nix::poll::poll(&mut waiting, nix::poll::PollTimeout::NONE) {
                // (An interrupted wait is tried again at once; anything else, not in a spin.)
                if e != nix::errno::Errno::EINTR {
                    eprintln!("kithd: shared volumes: waiting for the kernel's questions: {e}");
                    std::thread::sleep(Duration::from_secs(1));
                }
                continue;
            }
            let asked: Vec<bool> = waiting.iter().map(|fd| fd.any().unwrap_or(false)).collect();
            for ((mut file, answer), _) in open
                .iter()
                .map(|(file, answer)| (file, answer))
                .zip(asked)
                .filter(|(_, asked)| *asked)
            {
                // One question a read, one answer a write; a question that makes no sense is
                // left for the kernel to give up on.
                let mut question = [0; 8192];
                let Ok(size) = file.read(&mut question) else { continue };
                let question = std::str::from_utf8(&question[..size])
                    .unwrap_or_default()
                    .trim_end_matches('\n');
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let table = table.lock().expect("nothing panics holding the table").clone();
                if let Some(reply) = answer(&table, question, now + GOOD_FOR)
                    && let Err(e) = file.write(format!("{reply}\n").as_bytes())
                {
                    eprintln!("kithd: shared volumes: the kernel did not take `{reply}`: {e}");
                }
            }
        }
    };
    let spawned = std::thread::Builder::new().name("nfs-answers".into()).spawn(serve);
    spawned.map(drop).map_err(|e| e.to_string())
}

/// What a node says in its own Node's status of the Shares it serves over NFS: their names
/// (`NAMESPACE/NAME`), or null for none.
fn shares_said(names: &[String]) -> Value {
    match names.is_empty() {
        true => Value::Null,
        false => json!(names),
    }
}

/// Say in this node's own Node what it serves (`status.shares`), where that is not what the
/// Node says already. The leader tells a Share's reader from it. `told` is what was last
/// sent that the store did not show yet (or refused): not sent again until what is served
/// changes.
async fn report(shared: &Arc<crate::Shared>, me: &str, names: &[String], told: &mut Option<Vec<String>>) {
    let (key, want) = (format!("Node/{me}"), shares_said(names));
    let differs = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let said = |node: &kith_api::Resource| node.status.as_ref().map_or(Value::Null, |s| s["shares"].clone());
        state.store.get(&key).map(|node| said(node) != want)
    };
    if differs != Some(true) {
        *told = None;
        return;
    }
    if told.as_deref() == Some(names) {
        return;
    }
    *told = Some(names.to_vec());
    let statuses = vec![(key, serde_json::Map::from_iter([("shares".to_string(), want)]))];
    if let Err(e) = shared.submit(kith_store::Command::Patch { statuses }).await {
        eprintln!("kithd: shared volumes: saying which Shares this node serves: {e}");
        // (Refused or no leader yet, or an old leader: tried again next round.)
        *told = None;
    }
}

/// Serve this node's shared volumes to the cluster's other nodes, until stopped: nothing is
/// started while it has none.
pub async fn run(shared: Arc<crate::Shared>, state: PathBuf, mut stopping: tokio::sync::watch::Receiver<bool>) {
    let Some(cluster) = &shared.cluster else { return };
    let (me, prefix) = (cluster.me.name.as_str(), crate::mesh::prefix(&cluster.me.ca));
    let table = Arc::new(Mutex::new(Table::default()));
    let (mut answering, mut said) = (false, String::new());
    // Whether the kernel's server was handed a socket for every IPv4 address (once is enough:
    // it keeps it), and what this node last told its Node it serves.
    let (mut v4, mut told): (bool, Option<Vec<String>>) = (false, None);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(ROUND) => {}
            _ = stopping.changed() => return,
        }
        let (dirs, clients, shares, mut nodes) = {
            let file_store = shared.store.lock().expect("a handler panicked holding the store");
            let store = &file_store.store;
            let address = |node: &kith_api::Resource| kith_mesh::node_address(prefix, &node.metadata.name);
            (
                crate::volumes::served(store, me),
                store.list(Some("Node")).map(address).collect(),
                lans(store, me),
                store
                    .list(Some("Node"))
                    .flat_map(reached)
                    .collect::<BTreeSet<Ipv4Addr>>(),
            )
        };
        // And every address this node has itself: what a container here comes from.
        let own = nix::ifaddrs::getifaddrs().into_iter().flatten();
        let own = own.filter_map(|card| Some(card.address?.as_sockaddr_in()?.ip()));
        nodes.extend(own);
        if dirs.is_empty() && shares.is_empty() && !answering {
            report(&shared, me, &[], &mut told).await;
            continue;
        }
        let serve = || -> Result<(String, Vec<String>), String> {
            let root = state.canonicalize().map_err(|e| e.to_string())?.join("volumes");
            std::fs::create_dir_all(&root).map_err(|e| format!("{}: {e}", root.display()))?;
            // (One volume whose directory cannot be made does not take the others with it.)
            let (mut served, mut not) = (BTreeSet::new(), String::new());
            for dir in &dirs {
                match crate::volumes::host_dir(&state, dir) {
                    Ok(made) => drop(served.insert(made)),
                    Err(e) => not.push_str(&format!("; {}/{} is not served: {e}", dir.namespace, dir.name)),
                }
            }
            let mut given = BTreeMap::new();
            for (name, dir, lan) in shares.clone() {
                match crate::volumes::host_dir(&state, &dir) {
                    Ok(made) => drop(given.insert(name, Lan { dir: made, ..lan })),
                    Err(e) => not.push_str(&format!("; the Share {name} is not served: {e}")),
                }
            }
            let (count, shares, given) = (served.len(), given.clone(), given.len());
            let names: Vec<String> = shares.keys().cloned().collect();
            *table.lock().expect("nothing panics holding the table") = Table {
                root,
                served,
                clients,
                shares,
                nodes: nodes.clone(),
            };
            let up = running()?;
            // (Listening for the questions before there is anybody to ask them.)
            if !answering {
                answer(table.clone())?;
                answering = true;
            }
            if !up {
                start(kith_mesh::node_address(prefix, me))?;
            }
            // ponytail: once a Share here names NFS clients the server listens on every IPv4
            // address of this node until it restarts, answering only whom a Share names;
            // IPv6 clients that are not nodes are not served. Listen per address, and stop,
            // when a node has networks a Share should not be heard on.
            // (Once: the kernel's server keeps the socket it was given, and the same address
            // bound again is in use. The kernel's list of listeners does not say which are IPv4.)
            if given > 0 && !v4 {
                listen(IpAddr::V4(Ipv4Addr::UNSPECIFIED))?;
                v4 = true;
            }
            let lan = if given > 0 {
                format!("; {given} Share(s) to the addresses they name")
            } else {
                String::new()
            };
            let saying =
                format!("serving {count} shared volume(s) to the cluster's nodes (NFS 4.2, mesh only){lan}{not}");
            Ok((saying, names))
        };
        let (saying, serving) = match serve() {
            Ok(done) => done,
            // (What did not start serves nobody, and the Node says so.)
            Err(e) => (format!("shared volumes are not served: {e}"), Vec::new()),
        };
        report(&shared, me, &serving, &mut told).await;
        if saying != said {
            eprintln!("kithd: {saying}");
            said = saying;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node moved onto the mesh (its `address` an IPv6 one) is still one of the IPv4 addresses
    /// a container here may come from: its LAN address, kept in `status.lan`.
    #[test]
    fn a_moved_nodes_lan_address_is_still_a_node_address() {
        let node = |status: serde_json::Value| {
            let text = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: { name: b }\nspec: {}\n";
            let mut node = kith_api::Resource::from_source(text).unwrap().remove(0).unwrap();
            node.status = Some(status);
            node
        };
        let lan: Ipv4Addr = "10.9.0.2".parse().unwrap();
        assert_eq!(reached(&node(serde_json::json!({ "address": "10.9.0.2:7443" }))), [lan]);
        let moved = serde_json::json!({ "address": "[fd00:1:2::5]:7443", "lan": "10.9.0.2:7443" });
        assert_eq!(reached(&node(moved)), [lan]);
        assert_eq!(
            reached(&node(serde_json::json!({ "address": "[::ffff:10.9.0.2]:7443" }))),
            [lan]
        );
        assert!(reached(&node(serde_json::json!({ "address": "[fd00:1:2::5]:7443" }))).is_empty());
    }

    fn table() -> Table {
        Table {
            root: "/var/lib/kith/volumes".into(),
            served: [
                "/var/lib/kith/volumes/default/media/films",
                "/var/lib/kith/volumes/shop/my data/x",
            ]
            .map(PathBuf::from)
            .into(),
            clients: ["fd00:1::1", "fd00:1::2"].map(|a| a.parse().unwrap()).into(),
            shares: BTreeMap::new(),
            nodes: BTreeSet::new(),
        }
    }

    /// The table with one Share on it: the films, to one LAN and one more machine, as uid 1000.
    fn given(read_only: bool) -> Table {
        let lan = Lan {
            dir: "/var/lib/kith/volumes/default/media/films".into(),
            clients: vec![("192.168.1.0".parse().unwrap(), 24), ("10.0.2.2".parse().unwrap(), 32)],
            read_only,
            owner: (1000, 100),
        };
        Table {
            shares: [("default/films".to_string(), lan)].into(),
            ..table()
        }
    }

    /// A machine a Share names is the client of that Share, whichever way the kernel writes
    /// its address; its neighbours, and anybody when no Share names them, are nobody.
    #[test]
    fn a_share_is_served_to_the_addresses_it_names_only() {
        let table = given(false);
        for named in ["192.168.1.20", "192.168.1.255", "10.0.2.2", "::ffff:192.168.1.20"] {
            assert_eq!(
                table.who(&format!("nfsd {named}"), 99).unwrap(),
                format!("nfsd {named} 99 share:default/films"),
            );
        }
        for other in ["192.168.2.20", "10.0.2.3", "2001:db8::1", "::ffff:192.168.2.20"] {
            assert_eq!(
                table.who(&format!("nfsd {other}"), 99).unwrap(),
                format!("nfsd {other} 99")
            );
        }
        // A node's own address is never a Share's client, though a Share's range has it: a
        // container there, which has that address, is not a machine the Share named.
        let among = Table {
            nodes: ["192.168.1.20".parse().unwrap()].into(),
            ..given(false)
        };
        assert_eq!(among.who("nfsd 192.168.1.20", 99).unwrap(), "nfsd 192.168.1.20 99");
        assert!(
            among
                .who("nfsd 192.168.1.21", 99)
                .unwrap()
                .ends_with(" share:default/films")
        );
        assert_eq!(table.who("nfsd 127.0.0.1", 99).unwrap(), "nfsd 127.0.0.1 99");
        // A node is still a node, and gets what nodes get.
        assert!(table.who("nfsd fd00:1::2", 99).unwrap().ends_with(" kith"));
        assert_eq!(
            self::table().who("nfsd 192.168.1.20", 99).unwrap(),
            "nfsd 192.168.1.20 99"
        );
    }

    /// A Share's client sees the way to its volume and the volume: as the Share's one user
    /// whoever it says it is and from any port (0xa), read-only when the Share says (0xb), and with the kernel
    /// checking each file handle is under the volume (no 0x400). Not the nodes' other volume,
    /// and not as a Share that does not name it or is gone.
    #[test]
    fn a_shares_client_gets_its_volume_as_the_shares_user_and_nothing_else() {
        let (table, client) = (given(false), "share:default/films");
        let export = |table: &Table, client: &str, path: &str| {
            let said = table.export(&format!("{client} {path}"), 99).unwrap();
            said.strip_prefix(&format!("{client} {path} 99")).unwrap().to_string()
        };
        let films = "/var/lib/kith/volumes/default/media/films";
        assert!(export(&table, client, films).starts_with(" 10 1000 100 0 uuid \\x"));
        assert!(export(&given(true), client, films).starts_with(" 11 1000 100 0 uuid \\x"));
        assert_eq!(
            export(&table, client, "/var/lib/kith/volumes"),
            format!(" {} 65534 65534 0", 0x12407)
        );
        assert!(export(&table, client, "/var/lib/kith/volumes/default/media").starts_with(&format!(" {} ", 0x10407)));
        for not in [
            "/var/lib/kith/volumes/shop",
            "/var/lib/kith/volumes/shop/my\\040data/x",
            "/var/lib/kith",
            "/",
        ] {
            assert_eq!(export(&table, client, not), "", "{not}");
        }
        for nobody in ["share:default/other", "share:", "lan", ""] {
            assert_eq!(export(&table, nobody, films), "", "{nobody}");
            assert_eq!(export(&table, nobody, "/var/lib/kith/volumes"), "", "{nobody}");
        }
        // The nodes get it as they did: theirs is the volume being `shared`, not the Share.
        assert!(export(&table, CLIENT, films).starts_with(&format!(" {NOSUBTREECHECK} 65534 65534 0 uuid")));
        // A file handle of the nodes' other volume names nothing to a Share's client.
        let id = crate::pki::hex(&table.id(Path::new("/var/lib/kith/volumes/shop/my data/x")));
        let asked = format!("{client} 6 \\x{id}");
        assert_eq!(table.handle(&asked, 99).unwrap(), format!("{asked} 99"));
        let id = crate::pki::hex(&table.id(Path::new(films)));
        let asked = format!("{client} 6 \\x{id}");
        assert_eq!(table.handle(&asked, 99).unwrap(), format!("{asked} 99 {films}"));
    }

    /// A Share is served by the node its volume is on, to the clients it names; its status
    /// says where a client finds it, or why nobody does.
    #[test]
    fn a_share_is_its_volumes_nodes_to_serve_and_says_where_it_is() {
        let mut store = Store::default();
        let text = "
apiVersion: kith.dev/v1
kind: Volume
metadata: {name: media}
spec: {node: a, path: films}
---
apiVersion: kith.dev/v1
kind: Identity
metadata: {name: ada}
spec: {}
---
apiVersion: kith.dev/v1
kind: Share
metadata: {name: films}
spec: {volume: media, readOnly: true, uid: 1000, nfs: {clients: [192.168.1.0/24]}, users: [ada]}
---
apiVersion: kith.dev/v1
kind: Share
metadata: {name: smb-only}
spec: {volume: media, users: [ada, bob]}
---
apiVersion: kith.dev/v1
kind: Share
metadata: {name: second}
spec: {volume: media, nfs: {clients: [192.168.1.0/24]}}
---
apiVersion: kith.dev/v1
kind: Share
metadata: {name: nobodys}
spec: {volume: media}
---
apiVersion: kith.dev/v1
kind: Share
metadata: {name: lost}
spec: {volume: gone, nfs: {clients: [192.168.1.9]}}
";
        for resource in kith_api::Resource::from_source(text).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let mine = lans(&store, "a");
        assert_eq!(mine.len(), 1, "only the one with NFS clients and a volume");
        let (name, dir, lan) = &mine[0];
        assert_eq!((name.as_str(), dir.path.as_str()), ("default/films", "films"));
        assert_eq!((lan.read_only, lan.owner), (true, (1000, NOBODY)));
        assert!(lan.has("192.168.1.7".parse().unwrap()) && !lan.has("192.168.2.7".parse().unwrap()));
        assert!(lans(&store, "b").is_empty(), "not the node its volume is on");
        // (`second` gives the same volume over NFS: the first by name does, and it says so.)
        let again = writes(&store)
            .into_iter()
            .find(|(key, _)| key == "Share/default/second");
        let again = again.unwrap().1.unwrap();
        assert!(
            again["message"]
                .as_str()
                .unwrap()
                .contains("the Share films gives that volume"),
            "{again}"
        );

        let said: BTreeMap<String, Value> = writes(&store)
            .into_iter()
            .map(|(key, status)| (key, status.unwrap()))
            .collect();
        assert_eq!(
            said["Share/default/films"],
            json!({ "node": "a", "path": "/default/media/films", "served": false })
        );
        assert_eq!(
            said["Share/default/smb-only"],
            json!({ "message": "there is no Identity bob" })
        );
        assert!(
            said["Share/default/nobodys"]["message"]
                .as_str()
                .unwrap()
                .contains("given to nobody")
        );
        assert_eq!(
            said["Share/default/lost"],
            json!({ "message": "there is no Volume gone it can give" })
        );
        // Said once.
        let statuses = writes(&store);
        kith_store::run(&mut store, kith_store::Command::Status { statuses }).unwrap();
        assert!(writes(&store).is_empty());
    }

    /// A Share's status says whether the node that has its volume serves it: from what that node
    /// says in its own Node (`status.shares`), for a Share that names NFS clients.
    #[test]
    fn a_shares_status_says_whether_its_node_serves_it() {
        let mut store = Store::default();
        let text = "
apiVersion: kith.dev/v1
kind: Node
metadata: {name: a}
spec: {}
---
apiVersion: kith.dev/v1
kind: Identity
metadata: {name: ada}
spec: {}
---
apiVersion: kith.dev/v1
kind: Volume
metadata: {name: media}
spec: {node: a, path: films}
---
apiVersion: kith.dev/v1
kind: Share
metadata: {name: films}
spec: {volume: media, nfs: {clients: [192.168.1.0/24]}}
---
apiVersion: kith.dev/v1
kind: Share
metadata: {name: smb-only}
spec: {volume: media, users: [ada]}
";
        for resource in kith_api::Resource::from_source(text).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let status = |store: &Store, key: &str| {
            let found = writes(store).into_iter().find(|(share, _)| share == key);
            found.map(|(_, status)| status.unwrap())
        };
        // The node has said nothing yet: where it is, and not served.
        assert_eq!(
            status(&store, "Share/default/films").unwrap(),
            json!({ "node": "a", "path": "/default/media/films", "served": false })
        );
        // (Served over NFS is what a Share that names clients is; one for SMB users has no `served`.)
        assert_eq!(
            status(&store, "Share/default/smb-only").unwrap(),
            json!({ "node": "a", "path": "/default/media/films" })
        );
        // The node says it serves it.
        let said = |store: &mut Store, shares: Value| {
            store.set_status("Node/a", Some(json!({ "shares": shares }))).unwrap();
        };
        said(&mut store, json!(["default/films"]));
        assert_eq!(status(&store, "Share/default/films").unwrap()["served"], true);
        // Said once: the status is written, and not again.
        let statuses = writes(&store);
        kith_store::run(&mut store, kith_store::Command::Status { statuses }).unwrap();
        assert!(writes(&store).is_empty());
        // It serves others, or none: this one is not served any more, and the status says so.
        said(&mut store, json!(["default/other"]));
        assert_eq!(status(&store, "Share/default/films").unwrap()["served"], false);
        said(&mut store, Value::Null);
        assert_eq!(status(&store, "Share/default/films").unwrap()["served"], false);
        // What a node says is of its own Node: null when it serves none.
        assert_eq!(shares_said(&[]), Value::Null);
        assert_eq!(shares_said(&["default/films".to_string()]), json!(["default/films"]));
    }

    /// A node is probed once for the units that start in a round: what was found is kept for
    /// [`PROBED_FOR`], and asked again after.
    #[test]
    fn a_nodes_probe_is_kept_for_the_round() {
        let probes = Probes(Mutex::new(BTreeMap::new()));
        let (a, b): (Ipv6Addr, Ipv6Addr) = ("fd00:1::1".parse().unwrap(), "fd00:1::2".parse().unwrap());
        let start = Instant::now();
        assert_eq!(probes.recall(a, start), None, "not probed yet");
        probes.note(a, start, false);
        // The units that start after it in the round use it, down or up.
        assert_eq!(probes.recall(a, start + Duration::from_secs(1)), Some(false));
        assert_eq!(
            probes.recall(a, start + PROBED_FOR - Duration::from_millis(1)),
            Some(false)
        );
        assert_eq!(probes.recall(b, start), None, "each node has its own");
        // The next round asks again, and the old answer is forgotten.
        assert_eq!(probes.recall(a, start + PROBED_FOR), None);
        probes.note(b, start + PROBED_FOR, true);
        assert_eq!(probes.recall(b, start + PROBED_FOR), Some(true));
        assert_eq!(probes.0.lock().unwrap().len(), 1, "a is forgotten");
    }

    /// A lazy unmount can wait on the kernel for as long as a server is away: it is called from
    /// a thread kept for what blocks, never the one the async tasks run on.
    #[tokio::test]
    async fn an_unmount_runs_off_the_async_thread() {
        let here = std::thread::current().id();
        let there = off_thread(|| std::thread::current().id()).await;
        assert_ne!(here, there);
        // The unmount itself goes that way: nothing is mounted at this path, so it is refused,
        // and the refusal comes back as text.
        let nothing = std::env::temp_dir().join(format!("kith-share-nothing-{}", std::process::id()));
        assert!(detach(nothing).await.is_err());
    }

    /// The listener is bound again where nothing holds the old one (the kernel's server keeps
    /// what it was given, and this process lets go of its own at once): twice on one address
    /// and port; and while one is held, the bind is refused as in use, and so is told apart.
    #[test]
    fn the_listener_is_bound_again_once_the_old_is_dropped() {
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let let_go = |listener| {
            drop(listener);
            Ok(())
        };
        for _ in 0..2 {
            assert_eq!(listen_at(address, port, let_go), Ok(()));
        }
        let mut held = Vec::new();
        let hold = |listener| {
            held.push(listener);
            Ok(())
        };
        assert_eq!(listen_at(address, port, hold), Ok(()));
        let refused = listen_at(address, port, |_| Ok(())).unwrap_err();
        assert!(in_use(&refused), "{refused}");
        drop(held);
        assert_eq!(listen_at(address, port, let_go), Ok(()));
    }

    /// Only a node's mesh address is a client: any other address of the mesh's /48 (a
    /// container's), an address outside it and an IPv4 one are answered as nobody.
    #[test]
    fn a_shared_volume_is_served_to_the_nodes_mesh_addresses_only() {
        let table = table();
        // (The kernel writes an address out in full.)
        let node = "fd00:0001:0000:0000:0000:0000:0000:0002";
        assert_eq!(
            table.who(&format!("nfsd {node}"), 99).unwrap(),
            format!("nfsd {node} 99 kith")
        );
        for other in [
            "fd00:0001:0000:0000:0000:0000:0001:0002",
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "10.0.0.1",
        ] {
            assert_eq!(
                table.who(&format!("nfsd {other}"), 99).unwrap(),
                format!("nfsd {other} 99")
            );
        }
        assert_eq!(table.who(&format!("nlm {node}"), 99).unwrap(), format!("nlm {node} 99"));
        assert_eq!(table.who("nonsense", 99), None);
    }

    /// The root and the directories on the way are read-only and show only what leads to a
    /// volume (0x10405, and the root is number 0: 0x12405); a volume is read-write (0x400);
    /// nothing else under the root, nothing outside it and no other client gets anything.
    #[test]
    fn only_shared_volumes_directories_are_exported() {
        let table = table();
        let export = |path: &str| table.export(&format!("kith {path}"), 7).unwrap();
        let id = |path: &str| crate::pki::hex(&table.id(Path::new(path)));
        assert_eq!(
            export("/var/lib/kith/volumes"),
            "kith /var/lib/kith/volumes 7 74757 65534 65534 0"
        );
        let way = "/var/lib/kith/volumes/default/media";
        assert_eq!(
            export(way),
            format!("kith {way} 7 66565 65534 65534 0 uuid \\x{}", id(way))
        );
        let films = "/var/lib/kith/volumes/default/media/films";
        assert_eq!(
            export(films),
            format!("kith {films} 7 1024 65534 65534 0 uuid \\x{}", id(films))
        );
        // A path with a space comes, and goes back, with the space written `\040`.
        let spaced = "/var/lib/kith/volumes/shop/my\\040data/x";
        let answer = export(spaced);
        assert!(answer.starts_with(&format!("kith {spaced} 7 1024 ")), "{answer}");
        for not in [
            "/var/lib/kith/volumes/default/private",
            "/var/lib/kith/volumes/default/media/films/inside",
            "/var/lib/kith",
            "/",
            "/var/lib/kith/volumes/../store",
        ] {
            assert_eq!(export(not), format!("kith {not} 7"), "{not}");
        }
        assert_eq!(
            table.export(&format!("other {films}"), 7).unwrap(),
            format!("other {films} 7")
        );
        assert_eq!(id(films).len(), 32);
        assert_ne!(id(films), id(way));
    }

    /// A file handle's key leads back to the directory it was made for, and to nothing else.
    #[test]
    fn a_shared_volumes_file_handle_names_its_directory() {
        let table = table();
        let handle = |kind: &str, key: &str| table.handle(&format!("kith {kind} \\x{key}"), 7).unwrap();
        assert_eq!(handle("1", "00000000"), "kith 1 \\x00000000 7 /var/lib/kith/volumes");
        let films = Path::new("/var/lib/kith/volumes/default/media/films");
        let id = crate::pki::hex(&table.id(films));
        // (Type 7 has the directory's inode number before the 16 bytes; type 6 has them alone.)
        let key = format!("0102030405060708{id}");
        assert_eq!(handle("7", &key), format!("kith 7 \\x{key} 7 {}", films.display()));
        assert_eq!(handle("6", &id), format!("kith 6 \\x{id} 7 {}", films.display()));
        let spaced = crate::pki::hex(&table.id(Path::new("/var/lib/kith/volumes/shop/my data/x")));
        assert!(handle("6", &spaced).ends_with(" 7 /var/lib/kith/volumes/shop/my\\040data/x"));
        let unknown = "ff".repeat(16);
        assert_eq!(handle("6", &unknown), format!("kith 6 \\x{unknown} 7"));
        assert_eq!(handle("1", "01000000"), "kith 1 \\x01000000 7");
        assert_eq!(handle("0", "0000000000000000"), "kith 0 \\x0000000000000000 7");
        assert_eq!(
            table.handle(&format!("other 6 \\x{id}"), 7).unwrap(),
            format!("other 6 \\x{id} 7")
        );
        assert_eq!(table.handle("kith 6 nothex", 7), None);
    }

    /// What a node mounts a shared volume with, and where: only ever under `remote`.
    #[test]
    fn a_shared_volume_is_mounted_from_its_nodes_mesh_address() {
        let dir = |node: &str| Dir {
            namespace: "default".into(),
            name: "media".into(),
            path: "films/all of them".into(),
            node: node.into(),
            encrypted: false,
        };
        let (server, me) = ("fd00:1::1".parse().unwrap(), "fd00:1::2".parse().unwrap());
        let (from, options) = source(server, me, &dir("a"));
        assert_eq!(from, "[fd00:1::1]:/default/media/films/all of them");
        assert_eq!(
            options,
            "vers=4.2,proto=tcp6,port=2049,addr=fd00:1::1,clientaddr=fd00:1::2,sec=sys,hard"
        );
        let state = Path::new("/var/lib/kith");
        assert_eq!(
            target(state, &dir("a")).unwrap(),
            Path::new("/var/lib/kith/remote/a/default/media")
        );
        for bad in ["..", ".", "", "a/b"] {
            assert!(target(state, &dir(bad)).is_err(), "{bad:?}");
        }
        // What is mounted under there, read from the kernel's list (which writes a space `\040`).
        let mountinfo = "\
22 1 0:21 / / rw - ext4 /dev/vda7 rw
40 22 0:44 / /var/lib/kith/remote/a/default/media rw,relatime - nfs4 [fd00:1::1]:/default/media/films/all\\040of\\040them rw,vers=4.2
41 22 0:45 / /var/lib/kith/remote-not/x rw - nfs4 [fd00:1::1]:/x rw
42 22 0:46 / /var/lib/kith/remote/b/shop/my\\040data rw shared:1 - nfs4 [fd00:1::3]:/shop/d/p rw
";
        let found = mounted(mountinfo, "/var/lib/kith/remote");
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[0],
            ("/var/lib/kith/remote/a/default/media", quote(&from).as_str())
        );
        assert_eq!(unquote(found[1].0).unwrap(), "/var/lib/kith/remote/b/shop/my data");
    }
}
