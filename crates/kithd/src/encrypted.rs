//! A Volume with `encrypted: true`: a file on its node under dm-crypt, its key held by the
//! cluster's other nodes.
//!
//! The volume is a file as big as its `size`, under the node's state (`encrypted/NS/NAME`).
//! It is given a block device (a loop device), opened under aes-xts with a 512-bit key (what
//! [`crate::crypt`] does for a node's whole state) and mounted where the volume's directory
//! would be: `volumes/NS/NAME`. Its file system starts as the small ext4 one kith OS carries
//! ([`SEED`]: a node has no mkfs) and is grown to the file's size where it is mounted.
//!
//! The key is made by the volume's node and never written there. Every other node keeps it,
//! in a file of its own state (`volume-keys/NS/NAME`), and hands it to the volume's node
//! alone, over the cluster's mutual TLS, each time that node has to open the volume. A disk
//! taken from the node has the volume's file and no key; `kith node lock` has the others
//! refuse. A key is made only while the volume has no file, and another node has it before
//! anything is written under it; a key a node keeps is never written over.
//
// ponytail: the other nodes keep the key as it is, so two disks (the volume's node's and
// another's) open the volume unless that other node's state is encrypted (`encrypt: true`
// when it is installed); a cluster of one node has nobody to keep a key and no encrypted
// volume. What a Backup, an Image or a Share makes of the volume is not encrypted by this.
// Why a volume is not open is in its node's log and in what a workload that mounts it says,
// not in the Volume's status. The file system keeps the seed's journal (4 MiB) and its one
// inode for 32 KiB however big it grows, and a volume is as big as it was made: `size` is
// read once. A key stays on the other nodes after its Volume is deleted (as the file does
// on its node). While a volume is open its key is in kithd's memory on its node (as it is
// in the kernel's), for the nodes that join later. Each has its own day; the first is a key sealed to each holder's TPM.

use crate::Shared;
use crate::cluster::Peer;
use crate::volumes::Dir;
use axum::extract::{ConnectInfo, Path as Named, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kith_api::store::Store;
use ring::rand::SecureRandom;
use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// The file system every encrypted volume starts as: ext4, 8 MiB, made when kith OS is
/// built (os/build.sh).
pub const SEED: &str = "/usr/share/kith/volume.ext4";
const ROUND: Duration = Duration::from_secs(10);
/// Every so many rounds the nodes there are now are given the key: one that joined since
/// the volume was made keeps it too, and the volume outlives the nodes that had it first.
const SPREAD: u32 = 30;
/// How long a node has to answer about a key.
const QUIET: Duration = Duration::from_secs(5);
const KEY: usize = 64;

/// Where the volume's file is on its node.
fn backing(state: &Path, namespace: &str, name: &str) -> PathBuf {
    state.join("encrypted").join(namespace).join(name)
}

/// Whether the volume was made encrypted on this node: its file is there.
pub fn made(state: &Path, namespace: &str, name: &str) -> bool {
    backing(state, namespace, name).exists()
}

/// Where the volume is mounted on its node: its directory, as of any volume.
fn root(state: &Path, namespace: &str, name: &str) -> PathBuf {
    state.join("volumes").join(namespace).join(name)
}

/// Where another node keeps the volume's key: under the name of the node the volume is on,
/// so a Volume that is made to name another node is not that node's way to this key.
fn kept(state: &Path, dir: &Dir) -> PathBuf {
    let of = state.join("volume-keys").join(&dir.node);
    of.join(&dir.namespace).join(&dir.name)
}

/// The name of the volume's dm-crypt mapping (a mapping's name is short and has no `/`).
fn mapping(namespace: &str, name: &str) -> String {
    let hash = blake3::hash(format!("{namespace}/{name}").as_bytes()).to_hex();
    format!("kith-vol-{}", &hash[..16])
}

/// Whether the volume whose directory is `root` is open: a file system is mounted there.
pub fn open(root: &Path) -> bool {
    let on = |path: &Path| std::fs::metadata(path).map(|found| found.dev());
    matches!((on(root), root.parent().map(on)), (Ok(here), Some(Ok(above))) if here != above)
}

// ---- On the other nodes: keeping the key ----

/// The encrypted Volume `namespace`/`name`, if `node` is the node it is on and may have its
/// key now.
fn asked(store: &Store, namespace: &str, name: &str, node: &str) -> Result<Dir, String> {
    let dir = crate::volumes::dir(store, namespace, name).filter(|dir| dir.encrypted && dir.node == node);
    let dir = dir.ok_or("no encrypted volume of the node that asks is named so")?;
    // (A node that was deleted, its disk lost say, is no node of this cluster's any more.)
    if store.get(&format!("Node/{node}")).is_none() {
        return Err(format!("{node} is no node of this cluster"));
    }
    // (`kith node lock`: the cluster opens nothing of that node's, and a wiped one is gone.)
    let locked = |key: &kith_api::Resource| key.spec["locked"] == true || key.spec["wiped"] == true;
    if store.get(&format!("NodeKey/{node}")).is_some_and(locked) {
        return Err(format!("{node} is locked: nothing of its is opened"));
    }
    Ok(dir)
}

/// Keep `key` as the volume's. One that is kept already stays: the same is fine, another is
/// refused.
fn keep(state: &Path, dir: &Dir, key: &[u8]) -> Result<(), String> {
    let path = kept(state, dir);
    let failed = |e: std::io::Error| format!("keeping the key: {e}");
    let parent = path.parent().unwrap_or(state);
    let mut made = std::fs::DirBuilder::new();
    made.recursive(true).mode(0o700).create(parent).map_err(failed)?;
    // Whole under another name first, then given its name only if nothing has it: a key is
    // there entirely or not at all, and never in place of another.
    let new = parent.join(format!(".{}.new", dir.name));
    let _ = std::fs::remove_file(&new);
    let written = File::options().write(true).create_new(true).mode(0o600).open(&new);
    let written = written.and_then(|mut file| {
        std::io::Write::write_all(&mut file, key)?;
        file.sync_all()
    });
    let named = written.and_then(|()| std::fs::hard_link(&new, &path));
    let _ = std::fs::remove_file(&new);
    match named {
        // (On the disk before the volume's node hears that it is kept.)
        Ok(()) => File::open(parent).and_then(|parent| parent.sync_all()).map_err(failed),
        Err(_) if std::fs::read(&path).is_ok_and(|held| held == key) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err("this node keeps another key for a volume of that name".into())
        }
        Err(e) => Err(failed(e)),
    }
}

/// The key this node keeps for the volume.
fn held(state: &Path, dir: &Dir) -> Option<Vec<u8>> {
    let key = std::fs::read(kept(state, dir)).ok();
    key.filter(|key| key.len() == KEY)
}

/// The node at the other end and the volume it names, if it may have that volume's key.
fn theirs(shared: &Shared, peer: &Peer, namespace: &str, name: &str) -> Result<Dir, String> {
    let Some(crate::pki::Subject::Node(node)) = &peer.subject else {
        return Err("this is for the cluster's nodes".into());
    };
    let state = shared.store.lock().expect("a handler panicked holding the store");
    asked(&state.store, namespace, name, node)
}

/// `GET /v1/volume-key/NS/NAME` (members only): the key, for the volume's node alone. 204
/// when this node may be asked and keeps none.
pub async fn get(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    Named((namespace, name)): Named<(String, String)>,
) -> Response {
    match (theirs(&shared, &peer, &namespace, &name), shared.logs.parent()) {
        (Err(why), _) => (StatusCode::FORBIDDEN, why).into_response(),
        (Ok(dir), Some(state)) => match held(state, &dir) {
            Some(key) => {
                eprintln!("kithd: handed {} the key of its volume {namespace}/{name}", dir.node);
                key.into_response()
            }
            None => StatusCode::NO_CONTENT.into_response(),
        },
        (Ok(_), None) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `PUT /v1/volume-key/NS/NAME` (members only): keep this key, from the volume's node alone.
pub async fn put(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    Named((namespace, name)): Named<(String, String)>,
    key: axum::body::Bytes,
) -> Response {
    let dir = match theirs(&shared, &peer, &namespace, &name) {
        Ok(dir) if key.len() == KEY => dir,
        Ok(_) => return (StatusCode::BAD_REQUEST, "a key is 64 bytes").into_response(),
        Err(why) => return (StatusCode::FORBIDDEN, why).into_response(),
    };
    match shared.logs.parent().map(|state| keep(state, &dir, &key)) {
        Some(Ok(())) => StatusCode::OK.into_response(),
        Some(Err(why)) => (StatusCode::CONFLICT, why).into_response(),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// ---- On the volume's node: opening it ----

/// What a node that was asked for the key said: the key, that it keeps none, or nothing
/// (no answer, or a refusal).
#[derive(Debug, Clone, PartialEq)]
enum Said {
    Key(Vec<u8>),
    None,
    Nothing,
}

/// What to do about a volume that is not open.
#[derive(Debug, PartialEq)]
enum Plan {
    /// Open it with one of these keys (more than one only after a volume of the same name).
    Open(Vec<Vec<u8>>),
    /// Make a key and the volume.
    Make,
    Wait(&'static str),
}

/// A key is made only for a volume with no file yet, and only when a node that could keep
/// it said it keeps none: never because nobody answered, and never over a file that is there.
fn plan(exists: bool, said: &[Said]) -> Plan {
    let key = |said: &Said| match said {
        Said::Key(key) => Some(key.clone()),
        _ => None,
    };
    let mut keys: Vec<_> = said.iter().filter_map(key).collect();
    keys.sort();
    keys.dedup();
    match (keys.is_empty(), exists, said.contains(&Said::None)) {
        (false, ..) => Plan::Open(keys),
        (true, false, true) => Plan::Make,
        (true, true, _) => Plan::Wait("no node that answers keeps its key"),
        (true, false, false) => Plan::Wait("its key is for the cluster's other nodes to keep, and none answers"),
    }
}

fn url(address: &str, dir: &Dir) -> String {
    format!("https://{address}/v1/volume-key/{}/{}", dir.namespace, dir.name)
}

async fn ask(client: &reqwest::Client, address: &str, dir: &Dir) -> Said {
    let Ok(Ok(answer)) = tokio::time::timeout(QUIET, client.get(url(address, dir)).send()).await else {
        return Said::Nothing;
    };
    match answer.status() {
        StatusCode::OK => match tokio::time::timeout(QUIET, answer.bytes()).await {
            Ok(Ok(key)) if key.len() == KEY => Said::Key(key.to_vec()),
            _ => Said::Nothing,
        },
        StatusCode::NO_CONTENT => Said::None,
        _ => Said::Nothing,
    }
}

/// Whether the node at `address` keeps `key` now.
async fn give(client: &reqwest::Client, address: &str, dir: &Dir, key: &[u8]) -> bool {
    let sent = client.put(url(address, dir)).body(key.to_vec()).send();
    matches!(tokio::time::timeout(QUIET, sent).await, Ok(Ok(answer)) if answer.status().is_success())
}

/// The file at `path` as a device under `key`: a loop device, and the mapping `name` over it.
fn map(path: &Path, name: &str, key: &[u8]) -> Result<PathBuf, String> {
    let said = |e: std::io::Error| format!("{}: {e}", path.display());
    let file = File::options().read(true).write(true).open(path).map_err(said)?;
    let sectors = file.metadata().map_err(said)?.len() / 512;
    // (One left by a start that got no further. One in use stays, and making it fails.)
    let _ = kith_dm_sys::remove(name);
    let (held, device) = kith_dm_sys::attach(&file).map_err(|e| format!("a loop device for it: {e}"))?;
    let mapped = kith_dm_sys::crypt(name, &device, 0, sectors, key).map_err(|e| format!("dm-crypt: {e}"));
    // (The mapping has the loop device open now, which goes when the mapping does.)
    drop(held);
    mapped
}

/// Make the volume's file: `size` bytes, and the seed file system written through `key`.
fn make(state: &Path, dir: &Dir, key: &[u8], size: u64) -> Result<(), String> {
    let path = backing(state, &dir.namespace, &dir.name);
    let said = |e: std::io::Error| format!("making it: {e}");
    // (Mounted over, they would be hidden and still in the clear.)
    let before = std::fs::read_dir(root(state, &dir.namespace, &dir.name));
    if before.is_ok_and(|mut found| found.next().is_some()) {
        return Err("its directory has files from before it was encrypted: move them away first".into());
    }
    let seed = File::open(SEED);
    let mut seed = seed.map_err(|e| format!("{SEED}: {e}: the file system it starts as comes with kith OS"))?;
    let parent = path.parent().unwrap_or(state);
    let mut made = std::fs::DirBuilder::new();
    made.recursive(true).mode(0o700).create(parent).map_err(said)?;
    // Under another name until the file system is in it: a file with the volume's name is
    // one that has been written under its key, and is never made again.
    let new = parent.join(format!(".{}.new", dir.name));
    let mut written = || {
        let file = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&new)
            .map_err(said)?;
        // All of it now: a volume has its size, and a state that fills up later takes nothing
        // from under the file system in it.
        let whole = nix::fcntl::fallocate(
            file.as_raw_fd(),
            nix::fcntl::FallocateFlags::empty(),
            0,
            (size & !4095) as i64,
        );
        whole.map_err(|e| format!("room for its {size} bytes: {e}"))?;
        let name = mapping(&dir.namespace, &dir.name);
        let device = map(&new, &name, key)?;
        let wrote = File::options().write(true).open(&device).and_then(|mut through| {
            std::io::copy(&mut seed, &mut through)?;
            through.sync_all()
        });
        let closed = kith_dm_sys::remove(&name);
        wrote.and(closed).map_err(said)?;
        // (Its name on the disk too: what a workload then has written through it is under
        // a file that is still there after a power cut.)
        std::fs::rename(&new, &path).map_err(said)?;
        File::open(parent).and_then(|parent| parent.sync_all()).map_err(said)
    };
    written().inspect_err(|_| drop(std::fs::remove_file(&new)))
}

/// Open the volume's file under `key`, mount it, and grow its file system to the file.
fn mount(state: &Path, dir: &Dir, key: &[u8]) -> Result<(), String> {
    use nix::mount::MsFlags;
    let (name, root) = (
        mapping(&dir.namespace, &dir.name),
        root(state, &dir.namespace, &dir.name),
    );
    let path = backing(state, &dir.namespace, &dir.name);
    let size = std::fs::metadata(&path).map_or(0, |file| file.len());
    let device = map(&path, &name, key)?;
    std::fs::create_dir_all(&root).map_err(|e| format!("{}: {e}", root.display()))?;
    let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOATIME;
    if let Err(e) = nix::mount::mount(Some(&device), &root, Some("ext4"), flags, None::<&str>) {
        let _ = kith_dm_sys::remove(&name);
        // (Under a key that is not its own there is no file system to find.)
        return Err(format!("mounting it: {e}"));
    }
    // (Asked each time: the kernel does nothing when it is that big already. Not grown, it
    // is closed again and tried at the next round: never open at less than its size.)
    let block = nix::sys::statvfs::statvfs(&root).map_or(4096, |stat| stat.fragment_size().max(512));
    kith_dm_sys::grow(&root, size / block).map_err(|e| {
        let _ = nix::mount::umount(&root);
        let _ = kith_dm_sys::remove(&name);
        format!("growing its file system to its size: {e}")
    })
}

/// Close every encrypted volume this node has open: before its state is unmounted.
pub fn close(state: &Path) {
    let inside = |path: PathBuf| std::fs::read_dir(path).into_iter().flatten().flatten();
    for namespace in inside(state.join("encrypted")) {
        for volume in inside(namespace.path()) {
            let (namespace, name) = (namespace.file_name(), volume.file_name());
            let (Some(namespace), Some(name)) = (namespace.to_str(), name.to_str()) else {
                continue;
            };
            if nix::mount::umount(&root(state, namespace, name)).is_ok() {
                let _ = kith_dm_sys::remove(&mapping(namespace, name));
            }
        }
    }
}

/// See to one volume of this node: open it if it is not, and every so often give its key
/// to the nodes there are. What was done, if anything was.
async fn tend(
    client: Option<&reqwest::Client>,
    peers: &[String],
    state: &Path,
    (dir, size): (&Dir, u64),
    key: &mut Option<Vec<u8>>,
    spread: bool,
) -> Result<Option<&'static str>, String> {
    let is_open = open(&root(state, &dir.namespace, &dir.name));
    if is_open && !spread {
        return Ok(None);
    }
    let mut said = Vec::new();
    for peer in peers {
        // ponytail: one node after another, each given `QUIET` to answer; all at once when
        // a cluster is big enough for that to be felt.
        match (client, &*key) {
            (Some(client), Some(key)) if is_open => drop(give(client, peer, dir, key).await),
            (Some(client), _) => said.push(ask(client, peer, dir).await),
            (None, _) => {}
        }
    }
    if is_open {
        // (kithd started again under a volume that stayed open: the key is learned again.)
        let learned = said.into_iter().find_map(|said| match said {
            Said::Key(key) => Some(key),
            _ => None,
        });
        *key = key.take().or(learned);
        return Ok(None);
    }
    let exists = backing(state, &dir.namespace, &dir.name).exists();
    let blocking = |work: Box<dyn FnOnce() -> Result<(), String> + Send>| async {
        let done = tokio::task::spawn_blocking(work).await;
        done.map_err(|e| e.to_string()).and_then(|done| done)
    };
    let (state, dir) = (state.to_path_buf(), dir.clone());
    let (keys, what) = match plan(exists, &said) {
        Plan::Wait(why) => return Err(why.into()),
        Plan::Open(keys) => (keys, "opened"),
        Plan::Make => {
            let mut new = vec![0; KEY];
            let filled = ring::rand::SystemRandom::new().fill(&mut new);
            filled.expect("the kernel gives random bytes");
            let mut keepers = 0;
            for peer in peers {
                keepers += usize::from(give(client.expect("a node answered"), peer, &dir, &new).await);
            }
            if keepers == 0 {
                return Err("no other node took its key to keep".into());
            }
            (vec![new], "made")
        }
    };
    if !exists {
        let (at, of, with) = (state.clone(), dir.clone(), keys[0].clone());
        blocking(Box::new(move || make(&at, &of, &with, size))).await?;
    }
    let mut failed = String::new();
    for tried in keys {
        let (at, of, with) = (state.clone(), dir.clone(), tried.clone());
        match blocking(Box::new(move || mount(&at, &of, &with))).await {
            Ok(()) => {
                *key = Some(tried);
                return Ok(Some(what));
            }
            Err(e) => failed = e,
        }
    }
    Err(format!("the key the cluster keeps does not open it: {failed}"))
}

/// Keeps this node's encrypted volumes open.
pub async fn run(shared: Arc<Shared>, state: PathBuf, mut stopping: watch::Receiver<bool>) {
    let me = shared.members.me().to_string();
    // The keys of the volumes that are open (for the nodes that join later), and what was
    // last said of each that is not, so that it is said once.
    let mut keys: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    let mut said: BTreeMap<String, String> = BTreeMap::new();
    let mut round = 0u32;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(ROUND) => {}
            _ = stopping.changed() => return,
        }
        let (mine, peers) = {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            let address = |node: &kith_api::Resource| Some(node.status.as_ref()?["address"].as_str()?.to_string());
            let others = state.store.list(Some("Node")).filter(|node| node.metadata.name != me);
            (
                crate::volumes::encrypted(&state.store, &me),
                others.filter_map(address).collect::<Vec<_>>(),
            )
        };
        round += 1;
        let client = shared.cluster.as_ref().map(|cluster| &cluster.client);
        for (dir, size) in mine {
            let name = format!("{}/{}", dir.namespace, dir.name);
            let key = keys.entry(name.clone()).or_default();
            match tend(client, &peers, &state, (&dir, size), key, round.is_multiple_of(SPREAD)).await {
                Ok(None) => {}
                Ok(Some(what)) => {
                    said.remove(&name);
                    eprintln!(
                        "kithd: {what} the encrypted volume {name}: its key is kept by the cluster's other nodes"
                    );
                }
                Err(why) if said.get(&name) != Some(&why) => {
                    eprintln!("kithd: the encrypted volume {name} is not open: {why}");
                    said.insert(name, why);
                }
                Err(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn state(name: &str) -> PathBuf {
        let state = std::env::temp_dir().join(format!("kith-encrypted-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        std::fs::create_dir_all(&state).unwrap();
        state.canonicalize().unwrap()
    }

    const CLUSTER: &str = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: b }
spec: {}
---
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: vault }
spec: { node: a, path: data, size: 1Gi, encrypted: true }
---
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: plain }
spec: { node: a, path: data }
---
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: anywhere, namespace: kith-system }
spec: { node: a, path: /srv/data, size: 1Gi, encrypted: true }
";

    fn store(extra: &str) -> Store {
        let mut store = Store::default();
        for resource in kith_api::Resource::from_source(&format!("{CLUSTER}{extra}")).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        store
    }

    /// Another node keeps the key for the volume's node and nobody else, keeps the first
    /// one it was given whatever comes later, and gives nothing to a node that is locked.
    #[test]
    fn encrypted_volume_keys_are_kept_for_its_node_alone_and_never_written_over() {
        let plain = store("");
        let dir = asked(&plain, "default", "vault", "a").unwrap();
        assert!((dir.encrypted, dir.node.as_str()) == (true, "a"));
        for (namespace, name, node) in [
            ("default", "vault", "b"),
            ("default", "plain", "a"),
            ("default", "nothing", "a"),
            ("other", "vault", "a"),
            ("kith-system", "anywhere", "a"),
            ("default", "../vault", "a"),
        ] {
            assert!(
                asked(&plain, namespace, name, node).is_err(),
                "{namespace}/{name} for {node}"
            );
        }
        let key = |spec: &str| {
            format!("---\napiVersion: kith.dev/v1\nkind: NodeKey\nmetadata: {{ name: a }}\nspec: {spec}\n")
        };
        assert!(asked(&store(&key("{ id: aa, wrapped: '01' }")), "default", "vault", "a").is_ok());
        let locked = asked(
            &store(&key("{ id: aa, wrapped: '01', locked: true }")),
            "default",
            "vault",
            "a",
        );
        assert!(locked.unwrap_err().contains("a is locked"));
        assert!(asked(&store(&key("{ id: aa, wiped: true }")), "default", "vault", "a").is_err());
        // A volume of a node that is no node any more (deleted: its disk was lost) is nobody's
        // to ask for, and one made to name another node has another place for its key.
        let gone = "---\napiVersion: kith.dev/v1\nkind: Volume\nmetadata: { name: left }\nspec: { node: c, path: d, size: 1Gi, encrypted: true }\n";
        assert!(
            asked(&store(gone), "default", "left", "c")
                .unwrap_err()
                .contains("no node of this cluster")
        );
        let moved = Dir {
            node: "b".into(),
            ..dir.clone()
        };
        assert_ne!(kept(Path::new("/s"), &dir), kept(Path::new("/s"), &moved));

        let state = state("keep");
        let (first, other) = ([7u8; KEY], [9u8; KEY]);
        assert_eq!(held(&state, &dir), None);
        keep(&state, &dir, &first).unwrap();
        assert_eq!(held(&state, &dir).as_deref(), Some(&first[..]));
        // The same again is kept already; another is refused, and the first stays.
        keep(&state, &dir, &first).unwrap();
        assert!(keep(&state, &dir, &other).unwrap_err().contains("keeps another key"));
        assert_eq!(held(&state, &dir).as_deref(), Some(&first[..]));
        // For this node's kithd alone to read, and nothing left beside it.
        let file = state.join("volume-keys/a/default/vault");
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_dir(file.parent().unwrap()).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&state);
    }

    /// The volume's node makes a key only for a volume that has no file, and only once a node
    /// that could keep it says it keeps none; with a file there it waits for the key.
    #[test]
    fn encrypted_volume_is_made_only_where_there_was_none_and_a_node_can_keep_its_key() {
        let (one, two) = (Said::Key(vec![1; KEY]), Said::Key(vec![2; KEY]));
        assert_eq!(plan(false, &[Said::None, Said::Nothing]), Plan::Make);
        // Alone, or with nobody answering: no key is made that nobody keeps.
        assert!(matches!(plan(false, &[]), Plan::Wait(why) if why.contains("none answers")));
        assert!(matches!(plan(false, &[Said::Nothing, Said::Nothing]), Plan::Wait(_)));
        // A file is there: never a new key, whoever says they keep none.
        assert!(matches!(plan(true, &[Said::None, Said::Nothing]), Plan::Wait(why) if why.contains("keeps its key")));
        assert!(matches!(plan(true, &[]), Plan::Wait(_)));
        // A key that is kept is the key, file or none (a start that ended before the file was whole).
        assert_eq!(
            plan(true, &[Said::None, one.clone(), one.clone()]),
            Plan::Open(vec![vec![1; KEY]])
        );
        assert_eq!(
            plan(false, &[one.clone(), Said::Nothing]),
            Plan::Open(vec![vec![1; KEY]])
        );
        assert_eq!(plan(true, &[two, one]), Plan::Open(vec![vec![1; KEY], vec![2; KEY]]));
    }

    /// Closed, an encrypted volume has no directory for a workload: nothing is made there in
    /// the clear, and nothing of this node's keeps a key for its own volume.
    #[test]
    fn encrypted_volume_is_no_directory_while_it_is_closed() {
        let state = state("closed");
        let dir = asked(&store(""), "default", "vault", "a").unwrap();
        assert!(!open(&state.join("volumes/default/vault")));
        let refused = crate::volumes::host_dir(&state, &dir).unwrap_err();
        assert!(refused.contains("encrypted and not open"), "{refused}");
        assert!(!state.join("volumes").exists() && !state.join("volume-keys").exists());
        // (What is mounted is told from what is not by the device it is on.)
        assert!(open(Path::new("/proc")) && !open(&state));
        let plain = Dir {
            encrypted: false,
            ..dir
        };
        assert!(
            crate::volumes::host_dir(&state, &plain)
                .unwrap()
                .ends_with("volumes/default/vault/data")
        );
        // With its file there, a volume that stopped saying `encrypted` is no empty directory
        // in the file's place.
        std::fs::create_dir_all(state.join("encrypted/default")).unwrap();
        std::fs::write(state.join("encrypted/default/vault"), b"").unwrap();
        let refused = crate::volumes::host_dir(&state, &plain).unwrap_err();
        assert!(refused.contains("was made encrypted"), "{refused}");
        let _ = std::fs::remove_dir_all(&state);
    }
}
