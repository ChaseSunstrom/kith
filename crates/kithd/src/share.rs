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

use crate::volumes::Dir;
use nix::mount::{MntFlags, MsFlags};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::Ipv6Addr;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// NFS's port, on the mesh address.
pub const PORT: u16 = 2049;
/// The one client the kernel is told of: any node of the cluster.
const CLIENT: &str = "kith";
/// How long the kernel may keep an answer, in seconds.
const GOOD_FOR: u64 = 120;
/// How often what is served is worked out again.
const ROUND: Duration = Duration::from_secs(3);
/// Says the kernel's server on this machine is the one kithd started (gone at a reboot, as it is).
const OURS: &str = "/run/kith-nfsd";

// The kernel's export flags (include/uapi/linux/nfsd/export.h).
const READONLY: u32 = 0x1;
const ROOTSQUASH: u32 = 0x4;
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

    /// The directories strictly between the root and a served volume: shown, and nothing in them.
    fn on_the_way(&self) -> BTreeSet<&Path> {
        let mut found = BTreeSet::new();
        for dir in &self.served {
            let above = dir.ancestors().skip(1);
            found.extend(above.take_while(|up| *up != self.root && up.starts_with(&self.root)));
        }
        found
    }

    /// `auth.unix.ip` asks `CLASS ADDRESS`: a node's mesh address is the client `kith`, and
    /// anything else is nobody.
    fn who(&self, asked: &str, until: u64) -> Option<String> {
        let (class, address) = asked.split_once(' ')?;
        let node = class == "nfsd"
            && address
                .parse()
                .is_ok_and(|address: Ipv6Addr| self.clients.contains(&address));
        let client = if node { format!(" {CLIENT}") } else { String::new() };
        Some(format!("{class} {address} {until}{client}"))
    }

    /// `nfsd.export` asks `CLIENT PATH`: the root and the directories on the way to a served
    /// volume are read-only and show only what leads on; a served volume is read-write; anything
    /// else, or any other client, is not served.
    fn export(&self, asked: &str, until: u64) -> Option<String> {
        let (client, quoted) = asked.split_once(' ')?;
        let path = PathBuf::from(unquote(quoted)?);
        let way = READONLY | ROOTSQUASH | NOSUBTREECHECK | V4ROOT;
        let id = || format!("uuid \\x{}", crate::pki::hex(&self.id(&path)));
        let served = if client != CLIENT {
            String::new()
        } else if path == self.root {
            format!(" {} 65534 65534 0", way | FSID)
        } else if self.served.contains(&path) {
            format!(" {NOSUBTREECHECK} 65534 65534 0 {}", id())
        } else if self.on_the_way().contains(path.as_path()) {
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
            let all = self.served.iter().map(PathBuf::as_path).chain(self.on_the_way());
            all.into_iter().find(|path| self.id(path) == id)
        };
        let path = match kind {
            _ if client != CLIENT => None,
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
        Some(_) => {
            nix::mount::umount2(&target, MntFlags::MNT_DETACH).map_err(|e| format!("unmounting what was there: {e}"))?
        }
        None => {}
    }
    std::fs::create_dir_all(&target).map_err(|e| format!("cannot make {}: {e}", target.display()))?;
    // The mount itself waits minutes for a server that is not there, and nothing here may:
    // ask first, briefly.
    let away = || {
        format!(
            "node {} does not serve it (no answer on its mesh address, port {PORT}): is it up, and is the volume `shared`?",
            dir.node
        )
    };
    let asked = tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect((server, PORT))).await;
    asked.map_err(|_| away())?.map_err(|_| away())?;
    let mounting = {
        let target = target.clone();
        move || {
            nix::mount::mount(
                Some(from.as_str()),
                &target,
                Some("nfs4"),
                MsFlags::empty(),
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
pub fn release(state: &Path, used: &[&Dir]) {
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
            match nix::mount::umount2(path.as_str(), MntFlags::MNT_DETACH) {
                Ok(()) => eprintln!("kithd: unmounted {path}: nothing here mounts it"),
                Err(e) => eprintln!("kithd: cannot unmount {path}: {e}"),
            }
        }
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
    // (All but the threads cannot be said twice: an earlier try may have got that far.)
    if !listening.lines().any(|line| line.ends_with(&format!(" {PORT}"))) {
        tell("versions", "-3 +4 -4.0 -4.1 +4.2\n")?;
        tell("nfsv4leasetime", "30\n")?;
        tell("nfsv4gracetime", "30\n")?;
        let listener = std::net::TcpListener::bind((address, PORT))
            .map_err(|e| format!("listening on [{address}]:{PORT}: {e}"))?;
        tell("portlist", &format!("{}\n", listener.as_raw_fd()))?;
    }
    std::fs::write(OURS, "").map_err(|e| format!("{OURS}: {e}"))?;
    tell("threads", "4\n")
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

/// Serve this node's shared volumes to the cluster's other nodes, until stopped: nothing is
/// started while it has none.
pub async fn run(shared: Arc<crate::Shared>, state: PathBuf, mut stopping: tokio::sync::watch::Receiver<bool>) {
    let Some(cluster) = &shared.cluster else { return };
    let (me, prefix) = (cluster.me.name.as_str(), crate::mesh::prefix(&cluster.me.ca));
    let table = Arc::new(Mutex::new(Table::default()));
    let (mut answering, mut said) = (false, String::new());
    loop {
        tokio::select! {
            _ = tokio::time::sleep(ROUND) => {}
            _ = stopping.changed() => return,
        }
        let (dirs, clients) = {
            let file_store = shared.store.lock().expect("a handler panicked holding the store");
            let store = &file_store.store;
            let address = |node: &kith_api::Resource| kith_mesh::node_address(prefix, &node.metadata.name);
            (
                crate::volumes::served(store, me),
                store.list(Some("Node")).map(address).collect(),
            )
        };
        if dirs.is_empty() && !answering {
            continue;
        }
        let serve = || -> Result<String, String> {
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
            let count = served.len();
            *table.lock().expect("nothing panics holding the table") = Table { root, served, clients };
            let up = running()?;
            // (Listening for the questions before there is anybody to ask them.)
            if !answering {
                answer(table.clone())?;
                answering = true;
            }
            if !up {
                start(kith_mesh::node_address(prefix, me))?;
            }
            Ok(format!(
                "serving {count} shared volume(s) to the cluster's nodes (NFS 4.2, mesh only){not}"
            ))
        };
        let saying = serve().unwrap_or_else(|e| format!("shared volumes are not served: {e}"));
        if saying != said {
            eprintln!("kithd: {saying}");
            said = saying;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        }
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
