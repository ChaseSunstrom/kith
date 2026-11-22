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
// Why a volume is not open is in the Volume's status (`reason`) and its node's log. The file
// system keeps the seed's journal (4 MiB) and its one inode for 32 KiB however big it grows,
// and a volume is as big as it was made: `size` is read once. A Volume that has been gone
// from the store for a day (`GONE`, seen by each node on its own, only while it sees a leader,
// and counted again after a restart) has its key copies erased where they are held (zeros,
// then unlinked) and its file unlinked (not shredded: the blocks are the disk's), closed first
// if it is open (unmounted, then its mapping removed: a mount in use is left, and tried again at
// the next round); a Volume of the name in the store keeps both, whatever it says. A node keeps
// the copy it holds for another's volume until that node's Node says (`status.encrypted`, a list,
// `[]` for none) it holds no file of it, and a day more: a Node that has said no list is not
// known to hold none, and its copies stay. While a volume is open its key is in kithd's memory on its node (as it is
// in the kernel's), for the nodes that join later. Each is left for later; the first to
// come is a key sealed to each holder's TPM.

use crate::Shared;
use crate::cluster::Peer;
use crate::view::Upstream;
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

/// The newest format of a kept key file this build reads. Format 1 is the bare key (`KEY` bytes),
/// which is what this build writes too: a stamp ahead of the key would make a kithd of a release
/// before it find no key where there is one. A later format begins `kith-volume-key format N\n`.
const KEY_FORMAT: u32 = 1;

/// The key this node keeps for the volume. A file of a format newer than this build reads is
/// refused, not taken for no key (T-0219).
fn held(state: &Path, dir: &Dir) -> Result<Option<Vec<u8>>, String> {
    let path = kept(state, dir);
    let Ok(key) = std::fs::read(&path) else {
        return Ok(None);
    };
    const STAMP: &[u8] = b"kith-volume-key format ";
    if let Some(rest) = key.strip_prefix(STAMP) {
        let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        let format = std::str::from_utf8(&rest[..digits])
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(u32::MAX);
        kith_store::refuse_newer(&path, format, KEY_FORMAT)?;
    }
    Ok(Some(key).filter(|key| key.len() == KEY))
}

/// The node at the other end and the volume it names, if it may have that volume's key.
fn theirs(shared: &Shared, peer: &Peer, namespace: &str, name: &str) -> Result<Dir, String> {
    let Some(crate::pki::Subject::Node(node, ..)) = &peer.subject else {
        return Err("this is for the cluster's nodes".into());
    };
    let state = shared.store.lock().expect("a handler panicked holding the store");
    // (Refused, not "keeps none": a node that asks a worker has heard nothing of the key.)
    if crate::access::is_worker(&state.store, shared.members.me()) {
        return Err("this node is a worker: it keeps no volume's key".into());
    }
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
            Ok(Some(key)) => {
                eprintln!("kithd: handed {} the key of its volume {namespace}/{name}", dir.node);
                key.into_response()
            }
            Ok(None) => StatusCode::NO_CONTENT.into_response(),
            // (The state's path is this node's: said here, not to the peer.)
            Err(why) => {
                eprintln!("kithd: the key of {namespace}/{name} is not read: {why}");
                (StatusCode::INTERNAL_SERVER_ERROR, "format newer than this kithd reads").into_response()
            }
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
    // (No path in what it says: it is shown in the Volume's status, which namespace readers see; the log names the volume.)
    let said = |e: std::io::Error| format!("its file: {e}");
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
    std::fs::create_dir_all(&root).map_err(|e| format!("its directory: {e}"))?;
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
    cluster: Option<&crate::cluster::Cluster>,
    peers: &[Upstream],
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
        // (Each is the node it is, and not another at its address: a key is for that node's volume.)
        let Some(cluster) = cluster else { continue };
        let client = match cluster.to(peer) {
            Ok(client) => client,
            Err(why) => {
                eprintln!(
                    "kithd: no call to node {} for the key of {}/{}: {why}",
                    peer.name, dir.namespace, dir.name
                );
                continue;
            }
        };
        match &*key {
            Some(key) if is_open => drop(give(&client, &peer.address, dir, key).await),
            _ => said.push(ask(&client, &peer.address, dir).await),
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
                let client = cluster.expect("a node answered").to(peer)?;
                keepers += usize::from(give(&client, &peer.address, &dir, &new).await);
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

/// The nodes that keep the keys of `me`'s volumes, as they are called: the other control
/// nodes. A worker is given none and asked for none.
fn keepers(store: &Store, me: &str) -> Vec<Upstream> {
    let others = store
        .list(Some("Node"))
        .filter(|node| node.metadata.name != me && node.spec["trust"] != "worker");
    others.filter_map(Upstream::of).collect()
}

/// What to write in the Volume's status so that it says `why` it is not open (`None`: it is
/// open, and says nothing): the Patch for its key, if the status does not say that already.
fn reason_write(
    store: &Store,
    dir: &Dir,
    why: Option<&str>,
) -> Option<(String, serde_json::Map<String, serde_json::Value>)> {
    let key = format!("Volume/{}/{}", dir.namespace, dir.name);
    let volume = store.get(&key)?;
    let said = volume.status.as_ref().and_then(|status| status["reason"].as_str());
    // (At most 1 KiB, cut on a character: a worker's write of it is refused above that.)
    let end = why.map(|why| {
        (0..=why.len().min(1024))
            .rev()
            .find(|&i| why.is_char_boundary(i))
            .unwrap_or(0)
    });
    let why = why.zip(end).map(|(why, end)| &why[..end]);
    (said != why).then(|| (key, [("reason".to_string(), why.into())].into_iter().collect()))
}

/// How long a Volume has to be gone from the store before what its node and the others keep
/// of it is erased: the window in which applying it again brings back its file and its key.
const GONE: u64 = 86_400;

/// What is in `path` as (name, path). What starts with a `.` is the file of a start that got no
/// further (`keep` and a volume's file are each made under such a name first): left out unless
/// `strays` asks for it.
fn inside(path: &Path, strays: bool) -> Vec<(String, PathBuf)> {
    let found = std::fs::read_dir(path).into_iter().flatten().flatten();
    let named = found.filter_map(|entry| Some((entry.file_name().into_string().ok()?, entry.path())));
    named.filter(|(name, _)| strays || !name.starts_with('.')).collect()
}

/// The regular files in `path` (a link is none).
fn files(path: &Path, strays: bool) -> Vec<(String, PathBuf)> {
    let regular = |(_, path): &(String, PathBuf)| std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file());
    inside(path, strays).into_iter().filter(regular).collect()
}

/// The folders in `path` (a link is none).
fn folders(path: &Path) -> Vec<(String, PathBuf)> {
    let real = |(_, path): &(String, PathBuf)| std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir());
    inside(path, false).into_iter().filter(real).collect()
}

/// How many files a node says it holds: what its Node's write of them is refused above.
pub(crate) const HELD: usize = 1024;

/// The Volumes (`NAMESPACE/NAME`) whose files this node holds, in order: a Volume that is gone
/// from the store and not open has its file erased after [`GONE`], and the node's keepers keep
/// their copies of its key until it says it does not hold the file.
fn files_held(state: &Path) -> Vec<String> {
    let mut names = Vec::new();
    for (namespace, folder) in folders(&state.join("encrypted")) {
        names.extend(
            files(&folder, false)
                .into_iter()
                .map(|(name, _)| format!("{namespace}/{name}")),
        );
    }
    names.sort();
    // (A node with more says no more: the copies of the rest are erased as they would be.)
    names.truncate(HELD);
    names
}

/// What to write in `me`'s own Node so that it says which files it holds (`status.encrypted`:
/// `[]` for none, which is not the same as saying nothing), if it does not say that already.
fn held_write(
    store: &Store,
    me: &str,
    files: &[String],
) -> Option<(String, serde_json::Map<String, serde_json::Value>)> {
    let key = format!("Node/{me}");
    let said = store
        .get(&key)?
        .status
        .as_ref()
        .map_or(serde_json::Value::Null, |s| s["encrypted"].clone());
    let want = serde_json::Value::from(files);
    (said != want).then(|| (key, [("encrypted".to_string(), want)].into_iter().collect()))
}

/// Whether `what` (what went wrong with `at`) is news: it is not what was said of `at` last.
/// `None` (it went right) is not, and what goes wrong after it is.
fn news(said: &mut BTreeMap<String, String>, at: &str, what: Option<&str>) -> bool {
    let Some(what) = what else {
        said.remove(at);
        return false;
    };
    let new = said.get(at).is_none_or(|last| last != what);
    if new {
        said.insert(at.to_string(), what.to_string());
    }
    new
}

/// A file this node keeps for a Volume, as it is found on the disk.
struct Found {
    namespace: String,
    name: String,
    path: PathBuf,
    /// The node a key copy is for: none for a volume's own file.
    owner: Option<String>,
}

/// What [`due`] looks at: the keys this node holds for other nodes' volumes
/// (`volume-keys/NODE/NS/NAME`, and the `.NAME.new` of a `keep` that was cut short, which holds
/// one too) and the files of its own (`encrypted/NS/NAME`). It reads the disk and nothing else:
/// not under the store's lock.
fn found(state: &Path) -> Vec<Found> {
    let mut all = Vec::new();
    for (owner, node) in folders(&state.join("volume-keys")) {
        for (namespace, folder) in folders(&node) {
            for (file, path) in files(&folder, true) {
                // (Another name that starts with a `.` is none of ours.)
                let name = match file.strip_prefix('.') {
                    Some(rest) => rest.strip_suffix(".new").map(str::to_string),
                    None => Some(file.clone()),
                };
                let owner = Some(owner.clone());
                all.extend(name.map(|name| Found {
                    namespace: namespace.clone(),
                    name,
                    path,
                    owner,
                }));
            }
        }
    }
    for (namespace, folder) in folders(&state.join("encrypted")) {
        let own = files(&folder, false).into_iter();
        all.extend(own.map(|(name, path)| Found {
            namespace: namespace.clone(),
            name,
            path,
            owner: None,
        }));
    }
    all
}

/// The files of `found` that are for Volumes that have been gone from `store` for [`GONE`]
/// seconds (`now` and `seen` are in seconds: when each was first seen gone), by what the store
/// says and nothing on the disk. A Volume of the name that is in the store, whatever it says or
/// where it is, keeps them: this is only for what nothing names any more. One of this node's own
/// files that is open is listed too: [`forget`] closes it.
fn due(store: &Store, found: Vec<Found>, seen: &mut BTreeMap<PathBuf, u64>, now: u64) -> Vec<PathBuf> {
    // Whether the node a key copy is for may hold the Volume's file: it may be running it. One
    // that says nothing of it (it never said, say, or has not yet) is not known to hold none.
    let held = |owner: &str, volume: &str| match store.get(&format!("Node/{owner}")) {
        // (A node that is not in the store holds nothing.)
        None => false,
        Some(node) => match node.status.as_ref().and_then(|status| status["encrypted"].as_array()) {
            Some(files) => files.iter().any(|file| file == volume),
            None => true,
        },
    };
    let mut gone = Vec::new();
    for Found {
        namespace,
        name,
        path,
        owner,
    } in found
    {
        let there = store.get(&format!("Volume/{namespace}/{name}")).is_some();
        let kept = owner.is_some_and(|owner| held(&owner, &format!("{namespace}/{name}")));
        if !there && !kept {
            gone.push(path);
        }
    }
    seen.retain(|path, _| gone.contains(path));
    gone.retain(|path| now.saturating_sub(*seen.entry(path.clone()).or_insert(now)) >= GONE);
    gone
}

/// Erase a key kept in `path`: written over with zeros, then unlinked. One that is not there
/// is erased.
fn erase(path: &Path) -> std::io::Result<()> {
    let zeros = || {
        let flags = nix::fcntl::OFlag::O_NOFOLLOW.bits();
        let mut file = File::options().write(true).custom_flags(flags).open(path)?;
        let len = file.metadata()?.len();
        // (A key is 64 bytes; a stray file here is not read whole.)
        std::io::Write::write_all(&mut file, &vec![0; len.min(1 << 20) as usize])?;
        file.sync_all()
    };
    match zeros().and_then(|()| std::fs::remove_file(path)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        done => done,
    }
}

/// Erase what [`due`] listed: a key kept under `state`'s `volume-keys` is written over and
/// unlinked; a volume's file (as big as the volume) is only unlinked, after it is closed: its
/// root unmounted if that is mounted, and its mapping removed if there is one (whether or not
/// the root is mounted: an unmount that went through and a removal that did not leave a mapping
/// over the file). One still in use stays open and is an error, to be tried again at the next
/// round, and the file stays. One that is not there is erased.
fn forget(state: &Path, path: &Path) -> std::io::Result<()> {
    let umount = |at: &Path| nix::mount::umount(at).map_err(std::io::Error::from);
    forget_with(state, path, &umount, &kith_dm_sys::remove)
}

/// [`forget`], with `umount` (a volume's root) and `unmap` (its mapping's name) to close it. A
/// mapping that is not there (no such device, or no device mapper at all) is closed.
fn forget_with(
    state: &Path,
    path: &Path,
    umount: &dyn Fn(&Path) -> std::io::Result<()>,
    unmap: &dyn Fn(&str) -> std::io::Result<()>,
) -> std::io::Result<()> {
    if path.starts_with(state.join("volume-keys")) {
        return erase(path);
    }
    let named = |path: &Path| path.file_name()?.to_str().map(str::to_string);
    if let (Some(name), Some(namespace)) = (named(path), path.parent().and_then(named)) {
        let at = root(state, &namespace, &name);
        if open(&at) {
            umount(&at)?;
        }
        match unmap(&mapping(&namespace, &name)) {
            Err(e)
                if matches!(
                    e.raw_os_error().map(nix::errno::Errno::from_raw),
                    Some(nix::errno::Errno::ENXIO | nix::errno::Errno::ENOENT)
                ) => {}
            done => done?,
        }
    }
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        done => done,
    }
}

/// Keeps this node's encrypted volumes open.
pub async fn run(shared: Arc<Shared>, state: PathBuf, mut stopping: watch::Receiver<bool>) {
    let me = shared.members.me().to_string();
    // The keys of the volumes that are open (for the nodes that join later), and what was
    // last said of each that is not, so that it is said once.
    let mut keys: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    let mut said: BTreeMap<String, String> = BTreeMap::new();
    // What failed to be erased or written, by path or key, said once like `said`.
    let mut unsaid: BTreeMap<String, String> = BTreeMap::new();
    let mut round = 0u32;
    // When each file of a Volume that is not in the store was first seen so, in seconds since
    // kithd started: a start again counts from nothing, and so does a time with no leader (a
    // store that is not current says a Volume is gone that is not).
    let (mut seen, started) = (BTreeMap::new(), std::time::Instant::now());
    loop {
        tokio::select! {
            _ = tokio::time::sleep(ROUND) => {}
            _ = stopping.changed() => return,
        }
        let led = shared.raft.metrics().borrow().current_leader.is_some();
        // (What is on the disk is read before the store is, and not while it is locked.)
        let on_disk = match led {
            true => {
                let at = state.clone();
                tokio::task::spawn_blocking(move || found(&at))
                    .await
                    .unwrap_or_default()
            }
            false => Vec::new(),
        };
        let (mine, peers, forgot) = {
            let held = shared.store.lock().expect("a handler panicked holding the store");
            // A worker that was a control node before deletes what it kept then.
            if crate::access::is_worker(&held.store, &me) {
                let kept = state.join("volume-keys");
                if kept.exists() && std::fs::remove_dir_all(&kept).is_ok() {
                    eprintln!("kithd: this node is a worker: the volume keys it kept are deleted");
                }
            }
            let forgot = match led {
                true => due(&held.store, on_disk, &mut seen, started.elapsed().as_secs()),
                false => {
                    seen.clear();
                    Vec::new()
                }
            };
            (
                crate::volumes::encrypted(&held.store, &me),
                keepers(&held.store, &me),
                forgot,
            )
        };
        if !forgot.is_empty() {
            let at = state.clone();
            let erased = tokio::task::spawn_blocking(move || {
                forgot
                    .into_iter()
                    .map(|path| (forget(&at, &path), path))
                    .collect::<Vec<_>>()
            });
            for (done, path) in erased.await.unwrap_or_default() {
                let at = path.display().to_string();
                match done {
                    Ok(()) => {
                        news(&mut unsaid, &at, None);
                        eprintln!("kithd: {at} is erased: its Volume has been gone for a day");
                        // (Its key goes from memory too: that is for a volume's own file.)
                        if let (Some(name), Some(namespace)) =
                            (path.file_name(), path.parent().and_then(Path::file_name))
                            && !path.starts_with(state.join("volume-keys"))
                        {
                            keys.remove(&format!("{}/{}", namespace.to_string_lossy(), name.to_string_lossy()));
                        }
                    }
                    Err(e) => {
                        if news(&mut unsaid, &at, Some(&e.to_string())) {
                            eprintln!("kithd: {at} is not erased (tried again later): {e}");
                        }
                    }
                }
            }
        }
        // Which files it holds, in its own Node: its keepers erase their copies of a key only when it lets go.
        let files = files_held(&state);
        let write = {
            let held = shared.store.lock().expect("a handler panicked holding the store");
            held_write(&held.store, &me, &files)
        };
        if let Some((key, fields)) = write {
            let statuses = vec![(key.clone(), fields)];
            let done = shared.submit(kith_store::Command::Patch { statuses }).await;
            let failed = done.err().map(|e| e.to_string());
            if news(&mut unsaid, &key, failed.as_deref()) {
                eprintln!(
                    "kithd: {key} did not say which volume files it holds (tried again later): {}",
                    failed.unwrap_or_default()
                );
            }
        }
        round += 1;
        let cluster = shared.cluster.as_ref();
        for (dir, size) in mine {
            let name = format!("{}/{}", dir.namespace, dir.name);
            let key = keys.entry(name.clone()).or_default();
            let outcome = tend(cluster, &peers, &state, (&dir, size), key, round.is_multiple_of(SPREAD)).await;
            match &outcome {
                Ok(None) => {}
                Ok(Some(what)) => {
                    said.remove(&name);
                    eprintln!(
                        "kithd: {what} the encrypted volume {name}: its key is kept by the cluster's other nodes"
                    );
                }
                Err(why) if said.get(&name) != Some(why) => {
                    eprintln!("kithd: the encrypted volume {name} is not open: {why}");
                    said.insert(name, why.clone());
                }
                Err(_) => {}
            }
            // In the Volume's status too, where `kith get volumes` shows it: what the log says, until it is open.
            let write = {
                let held = shared.store.lock().expect("a handler panicked holding the store");
                reason_write(&held.store, &dir, outcome.as_ref().err().map(String::as_str))
            };
            if let Some((key, fields)) = write {
                let statuses = vec![(key.clone(), fields)];
                let done = shared.submit(kith_store::Command::Patch { statuses }).await;
                let failed = done.err().map(|e| e.to_string());
                if news(&mut unsaid, &key, failed.as_deref()) {
                    eprintln!(
                        "kithd: the status of {key} was not written (tried again later): {}",
                        failed.unwrap_or_default()
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A kept key file is raw bytes in format 1 (what a kithd before the stamp wrote, and still
    /// writes); a later format begins with its stamp. One newer than this kithd reads is refused,
    /// not taken for no key, and not for another volume's (T-0219).
    #[test]
    fn state_file_format_volume_key_newer_is_refused() {
        let dir = Dir {
            namespace: "default".into(),
            name: "vault".into(),
            node: "a".into(),
            path: String::new(),
            encrypted: true,
        };
        let state = state("key-format");
        let file = kept(&state, &dir);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let key = [7u8; KEY];
        std::fs::write(&file, key).unwrap();
        assert_eq!(held(&state, &dir).unwrap().as_deref(), Some(&key[..]));
        let newer = KEY_FORMAT + 1;
        std::fs::write(
            &file,
            [format!("kith-volume-key format {newer}\n").as_bytes(), &key].concat(),
        )
        .unwrap();
        let said = held(&state, &dir).unwrap_err();
        assert!(
            said.contains(&format!("format {newer}")) && said.contains(&format!("up to format {KEY_FORMAT}")),
            "{said}"
        );
        let _ = std::fs::remove_dir_all(&state);
    }

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

    /// [`store`], with both Nodes saying they hold no volume file (`[]`: that is not saying nothing).
    fn quiet(extra: &str) -> Store {
        let mut store = store(extra);
        for node in ["a", "b"] {
            let none = Some(serde_json::json!({ "encrypted": [] }));
            store.set_status(&format!("Node/{node}"), none).unwrap();
        }
        store
    }

    /// What [`due`] lists for what is on the disk under `state`.
    fn forgotten(store: &Store, state: &Path, seen: &mut BTreeMap<PathBuf, u64>, now: u64) -> Vec<PathBuf> {
        due(store, found(state), seen, now)
    }

    /// Another node keeps the key for the volume's node and nobody else, keeps the first
    /// A worker is given no key to keep and asked for none.
    #[test]
    fn encrypted_volume_keys_are_kept_by_control_nodes() {
        let node = |name: &str, trust: &str| {
            format!("---\napiVersion: kith.dev/v1\nkind: Node\nmetadata: {{ name: {name} }}\nspec: {{ {trust} }}\n")
        };
        let mut store = store(&format!("{}{}", node("c", ""), node("w", "trust: worker")));
        for (name, address) in [
            ("a", "10.0.0.1:7443"),
            ("b", "10.0.0.2:7443"),
            ("c", "10.0.0.3:7443"),
            ("w", "10.0.0.9:7443"),
        ] {
            let status = serde_json::json!({ "address": address });
            store.set_status(&format!("Node/{name}"), Some(status)).unwrap();
        }
        let addresses = |me| {
            keepers(&store, me)
                .into_iter()
                .map(|node| node.address)
                .collect::<Vec<_>>()
        };
        assert_eq!(addresses("a"), ["10.0.0.2:7443", "10.0.0.3:7443"]);
        // (A worker's own encrypted Volume is kept by the control nodes, all of them.)
        assert_eq!(addresses("w").len(), 3);
    }

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
        assert_eq!(held(&state, &dir).unwrap(), None);
        keep(&state, &dir, &first).unwrap();
        assert_eq!(held(&state, &dir).unwrap().as_deref(), Some(&first[..]));
        // The same again is kept already; another is refused, and the first stays.
        keep(&state, &dir, &first).unwrap();
        assert!(keep(&state, &dir, &other).unwrap_err().contains("keeps another key"));
        assert_eq!(held(&state, &dir).unwrap().as_deref(), Some(&first[..]));
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
                .real()
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

    /// A volume that is not open says why in its status (`reason`), once, and says no more when
    /// it is open; the leader's work of the status leaves it, and only its node may write it.
    #[test]
    fn encrypted_volume_not_open_says_why() {
        let mut store = store("");
        let dir = asked(&store, "default", "vault", "a").unwrap();
        let key = "Volume/default/vault";
        let wrong = "the key the cluster keeps does not open it: mounting it: EINVAL";
        let (at, fields) = reason_write(&store, &dir, Some(wrong)).expect("said");
        assert_eq!((at.as_str(), fields["reason"].as_str()), (key, Some(wrong)));
        // Open, and nothing said before: nothing to write.
        assert_eq!(reason_write(&store, &dir, None), None);
        store
            .set_status(key, Some(serde_json::json!({ "reason": wrong })))
            .unwrap();
        // Said already: not written again. Another reason replaces it; open clears it.
        assert_eq!(reason_write(&store, &dir, Some(wrong)), None);
        let (_, fields) = reason_write(&store, &dir, Some("no seed")).unwrap();
        assert_eq!(fields["reason"], "no seed");
        let (_, fields) = reason_write(&store, &dir, None).unwrap();
        assert!(fields["reason"].is_null());
        // Cut at 1 KiB, on a character.
        let (_, long) = reason_write(&store, &dir, Some(&"é".repeat(2000))).unwrap();
        assert!(long["reason"].as_str().unwrap().len() <= 1024);
        // The leader works the status of every Volume again: it keeps what its node said.
        // (Nothing to write, as its status is just that, or a write with it in.)
        let kept = crate::volumes::writes(&store);
        let said = kept
            .iter()
            .find(|(at, _)| at == key)
            .map(|(_, now)| now.as_ref().map(|now| &now["reason"]));
        assert!(matches!(said, None | Some(Some(_))), "{kept:?}");
        assert!(
            said.is_none_or(|reason| reason == Some(&serde_json::json!(wrong))),
            "{kept:?}"
        );
        // (Of a Volume that is no encrypted one any more it does not.)
        let plain = "Volume/default/plain";
        store
            .set_status(plain, Some(serde_json::json!({ "reason": "stale" })))
            .unwrap();
        assert!(
            crate::volumes::writes(&store)
                .iter()
                .any(|(key, now)| key == plain && now.is_none())
        );
        // Its node says it, with the shape of a reason; another node does not.
        let nothing = |_: &str| false;
        let patch = |node: &str, fields: serde_json::Value| {
            let who = crate::worker::Worker {
                name: node,
                prefix: None,
                held: &nothing,
            };
            crate::worker::patch(&store, &who, key, fields.as_object().unwrap())
        };
        assert!(patch("a", serde_json::json!({ "reason": "no seed" })).is_ok());
        assert!(patch("a", serde_json::json!({ "reason": null })).is_ok());
        assert!(patch("a", serde_json::json!({ "reason": 7 })).is_err());
        assert!(patch("a", serde_json::json!({ "reason": "x".repeat(1025) })).is_err());
        assert!(patch("a", serde_json::json!({ "reason": "x", "primary": "a" })).is_err());
        assert!(patch("b", serde_json::json!({ "reason": "no seed" })).is_err());
        // Text, not a terminal's: no control character (it is shown where `kith get` prints it).
        assert!(patch("a", serde_json::json!({ "reason": "no\nseed" })).is_err());
        assert!(patch("a", serde_json::json!({ "reason": "no\u{1b}[2Jseed" })).is_err());
    }

    /// A node says which volume files it holds (`status.encrypted` of its own Node): the shape of
    /// a short list of names, from that node only.
    #[test]
    fn encrypted_node_says_which_files_it_holds() {
        let state = state("held");
        assert!(files_held(&state).is_empty());
        for (namespace, name) in [("default", "vault"), ("kith-system", "anywhere")] {
            let path = backing(&state, namespace, name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"sealed").unwrap();
        }
        // (A partial file of a start that got no further is no volume's.)
        std::fs::write(state.join("encrypted/default/.vault.new"), b"half").unwrap();
        let files = files_held(&state);
        assert_eq!(files, ["default/vault", "kith-system/anywhere"]);
        let mut store = store("");
        // Said once: nothing more to write when the Node says it.
        let (at, fields) = held_write(&store, "a", &files).expect("said");
        assert_eq!(
            (at.as_str(), &fields["encrypted"]),
            ("Node/a", &serde_json::json!(files))
        );
        store
            .set_status("Node/a", Some(serde_json::json!({ "encrypted": files })))
            .unwrap();
        assert_eq!(held_write(&store, "a", &files), None);
        // None held: `[]` (said once too), which is not the same as nothing said.
        let (_, fields) = held_write(&store, "a", &[]).unwrap();
        assert_eq!(fields["encrypted"], serde_json::json!([]));
        store
            .set_status("Node/a", Some(serde_json::json!({ "encrypted": [] })))
            .unwrap();
        assert_eq!(held_write(&store, "a", &[]), None);
        // A Node that says nothing yet is told `[]` as well, when it holds none.
        let (_, fields) = held_write(&self::store(""), "b", &[]).unwrap();
        assert_eq!(fields["encrypted"], serde_json::json!([]));
        assert_eq!(held_write(&store, "nobody", &files), None);
        let nothing = |_: &str| false;
        let patch = |node: &str, fields: serde_json::Value| {
            let who = crate::worker::Worker {
                name: node,
                prefix: None,
                held: &nothing,
            };
            crate::worker::patch(&store, &who, "Node/a", fields.as_object().unwrap())
        };
        assert!(patch("a", serde_json::json!({ "encrypted": ["default/vault"] })).is_ok());
        assert!(patch("a", serde_json::json!({ "encrypted": null })).is_ok());
        assert!(patch("a", serde_json::json!({ "encrypted": "default/vault" })).is_err());
        assert!(patch("a", serde_json::json!({ "encrypted": [7] })).is_err());
        assert!(patch("a", serde_json::json!({ "encrypted": ["x".repeat(127)] })).is_ok());
        assert!(patch("a", serde_json::json!({ "encrypted": ["x".repeat(128)] })).is_err());
        assert!(patch("a", serde_json::json!({ "encrypted": vec!["x"; 1024] })).is_ok());
        assert!(patch("a", serde_json::json!({ "encrypted": vec!["x"; 1025] })).is_err());
        assert!(patch("b", serde_json::json!({ "encrypted": ["default/vault"] })).is_err());
        let _ = std::fs::remove_dir_all(&state);
    }

    /// A key copy is kept while the node it is for says it holds the Volume's file: that node
    /// may be running it still, and a Volume applied again then finds its file and its key.
    #[test]
    fn encrypted_forgotten_key_is_kept_while_its_owner_holds_the_file() {
        let state = state("forgotten-owner");
        let dir = asked(&store(""), "default", "vault", "a").unwrap();
        let dir = Dir {
            name: "ghost".into(),
            ..dir
        };
        keep(&state, &dir, &[8u8; KEY]).unwrap();
        let key = kept(&state, &dir);
        let said = |files: serde_json::Value| {
            let mut store = store("");
            store
                .set_status("Node/a", Some(serde_json::json!({ "encrypted": files })))
                .unwrap();
            store
        };
        let mut seen = BTreeMap::new();
        let holds = said(serde_json::json!(["default/ghost"]));
        // Days on, the owner still has it: kept.
        let _ = forgotten(&holds, &state, &mut seen, 0);
        assert!(forgotten(&holds, &state, &mut seen, 3 * GONE).is_empty());
        // Another volume of its is no reason to keep this one.
        let other = said(serde_json::json!(["default/else"]));
        assert!(forgotten(&other, &state, &mut seen, 3 * GONE).is_empty());
        // It lets go of the file (erased on its node): a day more, and the copy goes.
        assert!(forgotten(&other, &state, &mut seen, 4 * GONE - 1).is_empty());
        assert_eq!(forgotten(&other, &state, &mut seen, 4 * GONE), vec![key.clone()]);
        // It holds the file again: the clock starts over when it lets go.
        assert!(forgotten(&holds, &state, &mut seen, 5 * GONE).is_empty());
        assert!(seen.is_empty());
        // A node that has said nothing of its files (no list, or a null) is not known to hold
        // none: kept, however long. Only `[]` says it holds none.
        let unknown = store("");
        assert!(forgotten(&unknown, &state, &mut seen, 5 * GONE).is_empty());
        assert!(forgotten(&unknown, &state, &mut seen, 9 * GONE).is_empty());
        let null = said(serde_json::Value::Null);
        assert!(forgotten(&null, &state, &mut seen, 9 * GONE).is_empty());
        assert!(seen.is_empty());
        let none = said(serde_json::json!([]));
        let _ = forgotten(&none, &state, &mut seen, 10 * GONE);
        assert_eq!(forgotten(&none, &state, &mut seen, 11 * GONE), vec![key.clone()]);
        // A node that is not in the store holds nothing.
        let mut seen = BTreeMap::new();
        let gone = Store::default();
        let _ = forgotten(&gone, &state, &mut seen, 6 * GONE);
        assert_eq!(forgotten(&gone, &state, &mut seen, 7 * GONE), [key]);
        let _ = std::fs::remove_dir_all(&state);
    }

    /// What is erased is told by where it is: a key is written over and unlinked, a volume's file
    /// is only unlinked; neither is an error when it is gone already.
    #[test]
    fn encrypted_forgotten_is_erased_by_what_it_is() {
        let state = state("forgotten-by-what");
        let dir = asked(&store(""), "default", "vault", "a").unwrap();
        let dir = Dir {
            name: "ghost".into(),
            ..dir
        };
        keep(&state, &dir, &[8u8; KEY]).unwrap();
        let (key, file) = (kept(&state, &dir), backing(&state, "default", "ghost"));
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"sealed").unwrap();
        let (key_copy, file_copy) = (state.join("key-copy"), state.join("file-copy"));
        std::fs::hard_link(&key, &key_copy).unwrap();
        std::fs::hard_link(&file, &file_copy).unwrap();
        forget(&state, &key).unwrap();
        let closed = |_: &Path| Ok(());
        let ok = |_: &str| Ok(());
        forget_with(&state, &file, &closed, &ok).unwrap();
        assert!(!key.exists() && !file.exists());
        assert_eq!(std::fs::read(&key_copy).unwrap(), vec![0u8; KEY]);
        assert_eq!(std::fs::read(&file_copy).unwrap(), b"sealed");
        assert!(forget(&state, &key).is_ok() && forget_with(&state, &file, &closed, &ok).is_ok());
        let _ = std::fs::remove_dir_all(&state);
    }

    /// A volume's file is closed before it is erased: its root unmounted if that is mounted, and
    /// its mapping removed if there is one, mounted or not (an unmount that went through and a
    /// removal that did not must not leave the file unlinked under a mapping). Busy leaves the
    /// file, an error, to be tried again; a mapping that is not there is closed already.
    #[test]
    fn encrypted_forgotten_open_file_is_closed_before_it_is_erased() {
        let state = state("forgotten-open");
        let file = |name: &str| {
            let path = backing(&state, "default", name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"sealed").unwrap();
            path
        };
        let (open, half, shut) = (file("open"), file("half"), file("shut"));
        // `open` is mounted over: a different device from the folder above it.
        std::fs::create_dir_all(state.join("volumes/default")).unwrap();
        std::os::unix::fs::symlink("/proc", state.join("volumes/default/open")).unwrap();
        let called = std::cell::RefCell::new(Vec::<String>::new());
        let (busy, no_device) = (16, 6);
        let umount = |fails: Option<i32>| {
            let called = &called;
            move |at: &Path| {
                called.borrow_mut().push(format!("umount {}", at.display()));
                fails.map_or(Ok(()), |e| Err(std::io::Error::from_raw_os_error(e)))
            }
        };
        let unmap = |fails: Option<i32>| {
            let called = &called;
            move |name: &str| {
                called.borrow_mut().push(format!("unmap {name}"));
                fails.map_or(Ok(()), |e| Err(std::io::Error::from_raw_os_error(e)))
            }
        };
        let (ok, stuck) = (umount(None), umount(Some(busy)));
        let at = root(&state, "default", "open").display().to_string();
        // The root is busy: an error, the mapping is not touched, the file stays.
        assert!(forget_with(&state, &open, &stuck, &unmap(None)).is_err());
        assert!(open.exists());
        assert_eq!(*called.borrow(), [format!("umount {at}")]);
        called.borrow_mut().clear();
        // Unmounted, but the mapping is in use: an error, the file stays.
        assert!(forget_with(&state, &open, &ok, &unmap(Some(busy))).is_err());
        assert!(open.exists());
        called.borrow_mut().clear();
        // The next pass: the root is not mounted (`half`'s is not) and the mapping is still
        // there: it is removed again, not skipped, and the file is not unlinked while that fails.
        assert!(forget_with(&state, &half, &stuck, &unmap(Some(busy))).is_err());
        assert!(half.exists());
        assert_eq!(*called.borrow(), [format!("unmap {}", mapping("default", "half"))]);
        // It goes through: then the file is unlinked.
        forget_with(&state, &half, &stuck, &unmap(None)).unwrap();
        assert!(!half.exists());
        // Both close, the root and then the mapping it was opened under; then it is erased.
        called.borrow_mut().clear();
        forget_with(&state, &open, &ok, &unmap(None)).unwrap();
        assert!(!open.exists());
        assert_eq!(
            *called.borrow(),
            [format!("umount {at}"), format!("unmap {}", mapping("default", "open"))]
        );
        // A mapping that is not there (no such device, or no device mapper) is closed: erased.
        forget_with(&state, &shut, &stuck, &unmap(Some(no_device))).unwrap();
        assert!(!shut.exists());
        let _ = std::fs::remove_dir_all(&state);
    }

    /// The half-made `.NAME.new` of a key kept that was cut short holds a key too: erased when
    /// NAME is gone, kept while it is in the store; another dot name is none of ours.
    #[test]
    fn encrypted_forgotten_stray_key_is_erased_with_its_volume() {
        let state = state("forgotten-stray");
        let folder = state.join("volume-keys/a/default");
        std::fs::create_dir_all(&folder).unwrap();
        let (ghost, live, other) = (
            folder.join(".ghost.new"),
            folder.join(".vault.new"),
            folder.join(".other"),
        );
        for path in [&ghost, &live, &other] {
            std::fs::write(path, [9u8; KEY]).unwrap();
        }
        let mut seen = BTreeMap::new();
        let none = quiet("");
        let _ = forgotten(&none, &state, &mut seen, 0);
        assert_eq!(forgotten(&none, &state, &mut seen, GONE), vec![ghost.clone()]);
        forget(&state, &ghost).unwrap();
        assert!(!ghost.exists() && live.exists() && other.exists());
        let _ = std::fs::remove_dir_all(&state);
    }

    /// A reason says what went wrong, not where the node keeps its state (`kith get` shows it to
    /// whoever reads the namespace).
    #[test]
    fn encrypted_reason_names_no_state_path() {
        let state = state("no-path");
        let dir = asked(&store(""), "default", "vault", "a").unwrap();
        // No file to open: what `map` fails with, before it asks the kernel for anything.
        let why = mount(&state, &dir, &[1u8; KEY]).unwrap_err();
        assert!(why.starts_with("its file: "), "{why}");
        assert!(
            !why.contains(state.to_str().unwrap()) && !why.contains("encrypted/"),
            "{why}"
        );
        let why = map(&state.join("nothing"), "m", &[1u8; KEY]).unwrap_err();
        assert!(!why.contains(state.to_str().unwrap()), "{why}");
        let _ = std::fs::remove_dir_all(&state);
    }

    /// What goes wrong is said once for each thing, until it goes right or is another thing.
    #[test]
    fn encrypted_news_is_said_once() {
        let mut said = BTreeMap::new();
        assert!(news(&mut said, "a", Some("no")));
        assert!(!news(&mut said, "a", Some("no")));
        assert!(news(&mut said, "b", Some("no")));
        assert!(news(&mut said, "a", Some("still no")));
        // It went right: nothing to say, and a fault after is news again.
        assert!(!news(&mut said, "a", None));
        assert!(news(&mut said, "a", Some("still no")));
    }

    /// A key file or a volume's file under `state`: a Volume that is gone from the store for a
    /// day has them erased, one gone for less keeps them.
    #[test]
    fn encrypted_forgotten_key_is_erased_after_a_day_and_a_younger_gap_keeps_it() {
        let state = state("forgotten");
        let dir = asked(&store(""), "default", "vault", "a").unwrap();
        keep(&state, &dir, &[7u8; KEY]).unwrap();
        let ghost = Dir {
            name: "ghost".into(),
            ..dir.clone()
        };
        keep(&state, &ghost, &[8u8; KEY]).unwrap();
        let (live, gone) = (kept(&state, &dir), kept(&state, &ghost));
        let mut seen = BTreeMap::new();
        // First seen gone at 100: not yet at a day less a second, listed at the day (the
        // Volume that is in the store is never listed).
        assert!(forgotten(&quiet(""), &state, &mut seen, 100).is_empty());
        assert!(forgotten(&quiet(""), &state, &mut seen, 100 + GONE - 1).is_empty());
        assert_eq!(forgotten(&quiet(""), &state, &mut seen, 100 + GONE), vec![gone.clone()]);
        // Back in the store before then, it starts again: a Volume applied again is kept.
        let back = "---\napiVersion: kith.dev/v1\nkind: Volume\nmetadata: { name: ghost }\nspec: { node: a, path: d, size: 1Gi, encrypted: true }\n";
        assert!(forgotten(&store(back), &state, &mut seen, 100 + GONE).is_empty());
        assert!(seen.is_empty());
        assert!(forgotten(&quiet(""), &state, &mut seen, 200 + GONE).is_empty());
        assert_eq!(
            forgotten(&quiet(""), &state, &mut seen, 200 + 2 * GONE),
            vec![gone.clone()]
        );
        // A Volume of the name that is on another node now is in the store still: kept.
        let moved = back.replace("node: a", "node: c");
        assert!(forgotten(&store(&moved), &state, &mut seen, 200 + 2 * GONE).is_empty());

        // Erased: written over with zeros first (a second name for it shows what was left), then gone.
        let copy = state.join("copy");
        std::fs::hard_link(&gone, &copy).unwrap();
        erase(&gone).unwrap();
        assert!(!gone.exists() && live.exists());
        assert_eq!(std::fs::read(&copy).unwrap(), vec![0u8; KEY]);
        // (One that is not there is not an error: a second round finds it gone.)
        assert!(erase(&gone).is_ok());
        let _ = std::fs::remove_dir_all(&state);
    }

    /// The volume's file on its node is listed when its Volume is gone (open or not: an open one
    /// is closed when it is erased), and left when its Volume is in the store (whatever it says now).
    #[test]
    fn encrypted_forgotten_file_is_left_while_in_the_store() {
        let state = state("forgotten-file");
        let file = |name: &str| {
            let path = backing(&state, "default", name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"sealed").unwrap();
            path
        };
        let (vault, ghost, open) = (file("vault"), file("ghost"), file("open"));
        // `open` is mounted over: a different device from the folder above it.
        std::fs::create_dir_all(state.join("volumes/default")).unwrap();
        std::os::unix::fs::symlink("/proc", state.join("volumes/default/open")).unwrap();
        // (A partial file of a start that got no further is no volume's: not listed or erased.)
        std::fs::write(state.join("encrypted/default/.ghost.new"), b"half").unwrap();
        let mut seen = BTreeMap::new();
        // `vault` stays however it is now said (plain, say): its data is under the file.
        let plain =
            "---\napiVersion: kith.dev/v1\nkind: Volume\nmetadata: { name: vault }\nspec: { node: a, path: data }\n";
        let there = store("");
        let _ = forgotten(&there, &state, &mut seen, 0);
        // (`open` is listed: `forget` closes it first.)
        let mut listed = forgotten(&there, &state, &mut seen, GONE);
        listed.sort();
        assert_eq!(listed, [ghost.clone(), open.clone()]);
        let mut seen = BTreeMap::new();
        let mut now = Store::default();
        for resource in kith_api::Resource::from_source(plain).unwrap() {
            now.apply(resource.unwrap()).unwrap();
        }
        let _ = forgotten(&now, &state, &mut seen, 0);
        let listed = forgotten(&now, &state, &mut seen, GONE);
        assert!(
            listed.contains(&ghost) && !listed.contains(&vault) && listed.contains(&open),
            "{listed:?}"
        );
        let _ = std::fs::remove_dir_all(&state);
    }
}
