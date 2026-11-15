//! A Volume's files, into it and out of it over the API, as a tar stream.
//!
//! PUT /v1/volumes/NS/NAME/files   a tar: its files into the Volume, beside what is there
//! GET /v1/volumes/NS/NAME/files   the Volume's files, as a tar
//!
//! Both are for whoever may apply a Volume and a Workload in the namespace: a workload that
//! mounts the Volume reads and writes the same files. Any node is asked; the node that has
//! the Volume does it.
//!
//! Neither what comes in nor what is in the Volume is trusted (a container that mounts it
//! may be writing it now): every file is made through a handle on its directory and never
//! through a link, first in a directory of the put's own inside the Volume (`.kith-put`:
//! on the same disk, and under the same key when it is encrypted) and moved in once the
//! whole stream was good. A put that is refused or cut short leaves the Volume as it was.
//
// ponytail: one put at a time on a node, since they share that directory's name; a backup
// or a get taken while one runs carries it. A name for each put when puts queue up.

use crate::Shared;
use crate::access::Caller;
use crate::api::{ApiError, permit};
use crate::backups::{DEEPEST, open_in, within};
use crate::volumes::{Dir, SYSTEM};
use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Extension, Path as UrlPath, State};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use kith_api::kinds::Verb;
use kith_api::store::Error;
use serde_json::{Value, json};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Where a put keeps what has come until all of it has: a name no file of a put may have.
const STAGING: &str = ".kith-put";
/// What a put leaves free on the disk its Volume is on (kithd's store may be on it too).
const RESERVE: u64 = 64 << 20;
/// A put or a get whose other end does nothing for this long is given up on.
const QUIET: Duration = Duration::from_secs(60);
/// How long the rest of a refused put is read for, so its sender reads why and not only
/// a closed connection.
const DRAIN: Duration = Duration::from_secs(10);
/// How many gets a node packs at once: each holds a thread while its reader reads.
const GETS: usize = 4;

/// What a put did.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Put {
    files: u64,
    bytes: u64,
    /// Links that point out of the Volume, which were not made: `path -> where`.
    left_out: Vec<String>,
}

/// The directory `name` in the directory `dir` is open at, made first if `make`: never
/// through a link, whoever put one there.
fn sub(dir: &File, name: &OsStr, make: bool) -> io::Result<File> {
    if make {
        match std::fs::create_dir(within(dir, name)) {
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
            _ => {}
        }
    }
    let found = open_in(dir, name).map_err(|e| match e.raw_os_error() {
        Some(code) if code == nix::errno::Errno::ELOOP as i32 => io::Error::other("a link is in the way"),
        _ => e,
    })?;
    if found.metadata()?.is_dir() {
        Ok(found)
    } else {
        Err(io::Error::other("a file is in the way"))
    }
}

/// The names `path` goes through, if it stays where it starts: no `..`, no root.
fn inside(path: &Path) -> Option<Vec<OsString>> {
    let mut parts = Vec::new();
    for part in path.components() {
        match part {
            Component::Normal(part) => parts.push(part.to_owned()),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (parts.len() <= DEEPEST).then_some(parts)
}

/// Whether a link `depth` directories down that says `to` points out of the Volume, or
/// may: a `..` after a name counts as out, since the name may be a link itself.
fn leaves(depth: usize, to: &Path) -> bool {
    let (mut depth, mut named) = (depth as i64, false);
    for part in to.components() {
        match part {
            Component::Normal(_) => named = true,
            Component::CurDir => {}
            Component::ParentDir if !named => depth -= 1,
            _ => return true,
        }
        if depth < 0 {
            return true;
        }
    }
    false
}

/// The entries of the tar `from` into the empty directory `staged`, each the user's that
/// `owner` is. Refused, with the entry's name: a path that leaves the Volume, anything
/// that is not a file, a directory or a link, more than `bound` bytes, and what would
/// leave the disk (`free()` bytes of it are) with less than [`RESERVE`].
//
// ponytail: `bound` counts this stream's files, not what the Volume holds already, and
// many empty files are bounded by the disk's inodes only (they fail the put, and are
// removed); a quota on the directory when a Volume's `size` has to hold.
fn stage(from: impl Read, staged: &File, owner: (u32, u32), bound: u64, free: &dyn Fn() -> u64) -> Result<Put, String> {
    // (Where kithd is not root everything is its user's already, the container's one user.)
    let own = |done: io::Result<()>| match done {
        Err(e) if e.kind() != io::ErrorKind::PermissionDenied => Err(e),
        _ => Ok(()),
    };
    let (uid, gid) = (Some(owner.0), Some(owner.1));
    let mut put = Put::default();
    let mut tar = tar::Archive::new(from);
    for entry in tar.entries().map_err(|e| format!("reading the tar: {e}"))? {
        let mut entry = entry.map_err(|e| format!("reading the tar: {e}"))?;
        let kind = entry.header().entry_type();
        if kind == tar::EntryType::XGlobalHeader {
            continue;
        }
        let path = entry.path().map_err(|e| format!("reading the tar: {e}"))?.into_owned();
        // (How the oldest tars say a directory: a file whose name ends in a slash.)
        let old = kind.is_file() && path.as_os_str().as_encoded_bytes().ends_with(b"/");
        let kind = if old { tar::EntryType::Directory } else { kind };
        let said = |e: io::Error| format!("{}: {e}", path.display());
        let leaving = || format!("{}: a path that leaves the volume, or is too deep", path.display());
        let mut parts = inside(&path).ok_or_else(leaving)?;
        if parts.first().is_some_and(|top| top == STAGING) {
            return Err(format!("{}: {STAGING} is a name kithd keeps for a put", path.display()));
        }
        let shown: std::path::PathBuf = parts.iter().collect();
        // (The directory itself, `.`: it is there.)
        let Some(name) = parts.pop() else { continue };
        let mut parent = staged.try_clone().map_err(said)?;
        for part in &parts {
            parent = sub(&parent, part, true).map_err(said)?;
            own(std::os::unix::fs::fchown(&parent, uid, gid)).map_err(said)?;
        }
        let at = within(&parent, &name);
        let mode = entry.header().mode().map_err(said)? & 0o1777;
        // (Asked for every entry: a directory or a link is a block of the disk too.)
        let (size, left) = (if kind.is_file() { entry.size() } else { 0 }, free());
        if left < size.saturating_add(RESERVE) {
            return Err(format!(
                "{}: the node's disk has {left} bytes free, and a put leaves {RESERVE} of them",
                path.display()
            ));
        }
        match kind {
            tar::EntryType::Directory => {
                let dir = sub(&parent, &name, true).map_err(said)?;
                // (Whoever owns a directory can use it: what comes after goes into it.)
                let set = dir.set_permissions(PermissionsExt::from_mode(mode | 0o700));
                set.and_then(|()| own(std::os::unix::fs::fchown(&dir, uid, gid)))
                    .map_err(said)?;
            }
            // (Not a sparse file: it is as long as it says only once its holes are filled.)
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                put.bytes = put.bytes.saturating_add(size);
                if put.bytes > bound {
                    return Err(format!(
                        "{}: with it the files are more than the {bound} bytes the volume says it holds",
                        path.display()
                    ));
                }
                // (An earlier entry of the same name gives way, as it does in a tar.)
                let _ = std::fs::remove_file(&at);
                let mut file = File::create_new(&at).map_err(said)?;
                io::copy(&mut (&mut entry).take(size), &mut file).map_err(said)?;
                let set = file.set_permissions(PermissionsExt::from_mode(mode));
                set.and_then(|()| own(std::os::unix::fs::fchown(&file, uid, gid)))
                    .map_err(said)?;
                if let Ok(at) = entry.header().mtime() {
                    let _ = file.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(at));
                }
                put.files += 1;
            }
            tar::EntryType::Symlink => {
                let to = entry.link_name().map_err(said)?;
                let to = to.ok_or_else(|| said(io::Error::other("a link to nowhere")))?;
                if leaves(parts.len(), &to) {
                    put.left_out.push(format!("{} -> {}", shown.display(), to.display()));
                    continue;
                }
                let _ = std::fs::remove_file(&at);
                let made = std::os::unix::fs::symlink(&to, &at);
                made.and_then(|()| own(std::os::unix::fs::lchown(&at, uid, gid)))
                    .map_err(said)?;
            }
            tar::EntryType::Link => {
                // Another name for a file that came earlier in this stream.
                let to = entry.link_name().map_err(said)?;
                let to = to.as_deref().and_then(inside).ok_or_else(leaving)?;
                let Some((to, through)) = to.split_last() else {
                    return Err(leaving());
                };
                let mut from = staged.try_clone().map_err(said)?;
                for part in through {
                    from = sub(&from, part, false).map_err(said)?;
                }
                let _ = std::fs::remove_file(&at);
                std::fs::hard_link(within(&from, to), &at).map_err(said)?;
            }
            _ => {
                return Err(format!(
                    "{}: only files, directories and links go into a volume (this is a {kind:?})",
                    path.display()
                ));
            }
        }
    }
    Ok(put)
}

/// Everything in the directory `from` is open at into the one `to` is open at, both `at`
/// in the Volume: a directory that is on both sides is gone into, anything else takes the
/// place of what has its name. With `moved` unset nothing moves, and what could not is
/// said: a directory on one side with a file (or a link) of its name on the other.
fn merge(from: &File, to: &File, at: &Path, moved: bool) -> Result<(), String> {
    let listed = std::fs::read_dir(within(from, ".".as_ref())).map_err(|e| format!("{}: {e}", at.display()))?;
    for entry in listed {
        let name = entry.map_err(|e| format!("{}: {e}", at.display()))?.file_name();
        let path = at.join(&name);
        let said = |e: io::Error| format!("{}: {e}", path.display());
        let new = std::fs::symlink_metadata(within(from, &name)).map_err(said)?;
        let old = std::fs::symlink_metadata(within(to, &name)).ok();
        match (new.is_dir(), old.map(|old| old.is_dir())) {
            (true, Some(true)) => {
                let (from, to) = (
                    sub(from, &name, false).map_err(said)?,
                    sub(to, &name, false).map_err(said)?,
                );
                merge(&from, &to, &path, moved)?;
            }
            (true, Some(false)) => {
                return Err(format!(
                    "{}: a directory in what was sent, a file or a link in the volume",
                    path.display()
                ));
            }
            (false, Some(true)) => {
                return Err(format!(
                    "{}: a directory in the volume, a file or a link in what was sent",
                    path.display()
                ));
            }
            _ if moved => std::fs::rename(within(from, &name), within(to, &name)).map_err(said)?,
            _ => {}
        }
    }
    Ok(())
}

/// The tar `from` into the directory `into` (a Volume's, as [`crate::volumes::host_dir`]
/// gives it), beside what is there: see the top of this file.
pub(crate) fn unpack(from: impl Read, into: &Path, bound: u64, free: &dyn Fn() -> u64) -> Result<Put, String> {
    let failed = |e: io::Error| format!("{}: {e}", into.display());
    let root = File::open(into).map_err(failed)?;
    let owner = root.metadata().map(|has| (has.uid(), has.gid())).map_err(failed)?;
    let staging = within(&root, STAGING.as_ref());
    // (Left by a put that kithd did not live to the end of.)
    let _ = std::fs::remove_dir_all(&staging).or_else(|_| std::fs::remove_file(&staging));
    std::fs::create_dir(&staging).map_err(failed)?;
    let put = sub(&root, STAGING.as_ref(), false).map_err(failed).and_then(|staged| {
        let put = stage(from, &staged, owner, bound, free)?;
        merge(&staged, &root, Path::new(""), false)?;
        merge(&staged, &root, Path::new(""), true)?;
        Ok(put)
    });
    let _ = std::fs::remove_dir_all(&staging);
    put
}

/// A put's body, read where reading may wait. It ends where its sender says it does (a
/// chunk of no bytes): a sender that only goes away has not sent all of it.
struct In {
    from: mpsc::Receiver<io::Result<Bytes>>,
    rest: Bytes,
    ended: bool,
}

impl Read for In {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.rest.is_empty() && !self.ended {
            match self.from.blocking_recv() {
                Some(chunk) => self.rest = chunk?,
                None => return Err(io::Error::other("the upload ended early")),
            }
            self.ended = self.rest.is_empty();
        }
        let n = buf.len().min(self.rest.len());
        buf[..n].copy_from_slice(&self.rest.split_to(n));
        Ok(n)
    }
}

/// A get's body, written where writing may wait: for [`QUIET`] and no longer.
struct Out {
    to: mpsc::Sender<io::Result<Vec<u8>>>,
    runtime: tokio::runtime::Handle,
}

impl Write for Out {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let sent = self.runtime.block_on(self.to.send_timeout(Ok(buf.to_vec()), QUIET));
        sent.map(|()| buf.len())
            .map_err(|_| io::Error::other("the reader went away"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn invalid(why: String) -> ApiError {
    ApiError::Store(Error::Invalid(why))
}

/// Where the Volume is and how many bytes it says it holds, for a caller who may mount it,
/// and the address of the node that has it.
fn held(shared: &Shared, caller: &Caller, namespace: &str, name: &str) -> Result<(Dir, u64, Option<String>), ApiError> {
    let both = [("Volume", namespace), ("Workload", namespace)];
    permit(shared, caller, Verb::Apply, |_| {
        both.map(|(kind, namespace)| (kind.to_string(), Some(namespace.to_string())))
            .to_vec()
    })?;
    if namespace == SYSTEM {
        let why = format!("a Volume in {SYSTEM} is a directory of the host's, which the API does not read or write");
        return Err(invalid(why));
    }
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let key = format!("Volume/{namespace}/{name}");
    let dir = crate::volumes::dir(&state.store, namespace, name);
    let dir = dir.ok_or(ApiError::Store(Error::NotFound(key)))?;
    // (Asked by a node, it was sent here as the node that has it: never sent on again.)
    if caller.node().is_some() && dir.node != shared.members.me() {
        return Err(invalid(format!("node {} has that volume, not this node", dir.node)));
    }
    let bound = crate::volumes::size(&state.store, namespace, name).unwrap_or(u64::MAX);
    let there = state.store.get(&format!("Node/{}", dir.node));
    let address = there.and_then(|node| Some(node.status.as_ref()?["address"].as_str()?.to_string()));
    Ok((dir, bound, address))
}

/// The same request to the node that has the Volume, as this node, which has just checked
/// the caller: its answer if it is a yes, why not otherwise.
async fn elsewhere(
    shared: &Shared,
    caller: &Caller,
    dir: &Dir,
    address: Option<String>,
    body: Option<Body>,
) -> Result<reqwest::Response, String> {
    let (Some(cluster), Some(address)) = (&shared.cluster, address) else {
        return Err(format!("node {} that has the volume has no address yet", dir.node));
    };
    let url = format!("https://{address}/v1/volumes/{}/{}/files", dir.namespace, dir.name);
    let asked = match body {
        Some(body) => cluster
            .client
            .put(url)
            .body(reqwest::Body::wrap_stream(body.into_data_stream())),
        None => cluster.client.get(url),
    };
    let failed = |e: reqwest::Error| format!("asking node {}: {e}", dir.node);
    // (For whoever asked this node: the node that has the Volume asks what they may.)
    let asked = asked.header(crate::access::FOR, caller.to_string());
    let answer = asked.send().await.map_err(failed)?;
    let status = answer.status();
    if status.is_success() {
        return Ok(answer);
    }
    let said: Value = answer.json().await.unwrap_or_default();
    let why = said["error"].as_str().map(String::from);
    Err(why.unwrap_or_else(|| format!("node {} answered {status}", dir.node)))
}

/// `PUT /v1/volumes/NS/NAME/files`: the tar's files into the Volume.
pub async fn put(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    UrlPath((namespace, name)): UrlPath<(String, String)>,
    body: Body,
) -> Result<Json<Value>, ApiError> {
    let (dir, bound, address) = held(&shared, &caller, &namespace, &name)?;
    let what = vec![format!("files into Volume/{namespace}/{name}")];
    let done = if dir.node == shared.members.me() {
        here(&shared, dir, bound, body).await
    } else {
        match elsewhere(&shared, &caller, &dir, address, Some(body)).await {
            Ok(answer) => answer.json().await.map_err(|e| e.to_string()),
            Err(why) => Err(why),
        }
    };
    let outcome = done.as_ref().map(drop).map_err(Clone::clone);
    shared.audit.record(&caller, "put", what, outcome);
    done.map(Json).map_err(invalid)
}

/// A put into a Volume this node has.
async fn here(shared: &Shared, dir: Dir, bound: u64, body: Body) -> Result<Value, String> {
    static BUSY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    // (Held by the unpacking itself: a caller that goes away does not end it sooner.)
    let one = BUSY.lock().await;
    let state = shared.logs.parent().ok_or("kithd has no state directory")?;
    let (state, node) = (state.to_path_buf(), dir.node.clone());
    let (to, from) = mpsc::channel(16);
    let unpacking = tokio::task::spawn_blocking(move || {
        let _one = one;
        let into = crate::volumes::host_dir(&state, &dir)?;
        // (A disk that cannot be asked has nothing free.)
        let free = || {
            let disk = nix::sys::statvfs::statvfs(&into);
            disk.map_or(0, |disk| disk.blocks_available() * disk.fragment_size())
        };
        let (rest, ended) = (Bytes::new(), false);
        unpack(In { from, rest, ended }, &into, bound, &free)
    });
    let mut chunks = body.into_data_stream();
    loop {
        let chunk = match tokio::time::timeout(QUIET, chunks.next()).await {
            // (That was all of it: said with a chunk of no bytes, as [`In`] wants.)
            Ok(None) => Ok(Bytes::new()),
            Ok(Some(Ok(chunk))) if chunk.is_empty() => continue,
            Ok(Some(chunk)) => chunk.map_err(|e| io::Error::other(format!("the upload ended early: {e}"))),
            Err(_) => Err(io::Error::other(format!("nothing came for {} s", QUIET.as_secs()))),
        };
        let last = chunk.as_ref().map_or(true, Bytes::is_empty);
        if to.send(chunk).await.is_err() {
            // (It was refused: see [`DRAIN`].)
            let rest = async { while chunks.next().await.is_some() {} };
            let _ = tokio::time::timeout(DRAIN, rest).await;
            break;
        }
        if last {
            break;
        }
    }
    drop(to);
    let put = unpacking.await.map_err(|e| e.to_string())??;
    Ok(json!({ "files": put.files, "bytes": put.bytes, "leftOut": put.left_out, "node": node }))
}

/// `GET /v1/volumes/NS/NAME/files`: the Volume's files as a tar.
pub async fn get(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    UrlPath((namespace, name)): UrlPath<(String, String)>,
) -> Result<Response, ApiError> {
    let (dir, _, address) = held(&shared, &caller, &namespace, &name)?;
    let what = vec![format!("files of Volume/{namespace}/{name}")];
    let started = if dir.node == shared.members.me() {
        out(&shared, &dir)
    } else {
        elsewhere(&shared, &caller, &dir, address, None).await.map(|answer| {
            let chunks = futures_util::stream::unfold(answer, |mut answer| async move {
                answer.chunk().await.transpose().map(|chunk| (chunk, answer))
            });
            Body::from_stream(chunks).into_response()
        })
    };
    let outcome = started.as_ref().map(drop).map_err(Clone::clone);
    shared.audit.record(&caller, "get", what, outcome);
    started.map_err(invalid)
}

/// A get of a Volume this node has: packed as it is read.
fn out(shared: &Shared, dir: &Dir) -> Result<Response, String> {
    static PACKING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(GETS);
    let busy = |_| format!("this node is packing {GETS} volumes already: ask again when one is done");
    let one = PACKING.try_acquire().map_err(busy)?;
    let state = shared.logs.parent().ok_or("kithd has no state directory")?;
    let from = crate::volumes::host_dir(state, dir)?;
    let (to, packed) = mpsc::channel(16);
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let _one = one;
        let (failed, waiting) = (to.clone(), runtime.clone());
        let out = io::BufWriter::with_capacity(64 << 10, Out { to, runtime });
        // (A stream that ends in an error is cut short, which its reader can tell: if it
        // still reads.)
        if let Err(e) = crate::backups::stream(&from, out).and_then(|mut out| out.flush()) {
            let _ = waiting.block_on(failed.send_timeout(Err(e), QUIET));
        }
    });
    let chunks = futures_util::stream::unfold(packed, |mut packed| async move {
        packed.recv().await.map(|chunk| (chunk, packed))
    });
    Ok(Body::from_stream(chunks).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tar::EntryType::{Char, Directory, Fifo, Link, Regular, Symlink};

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kith-volume-files-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("volume")).unwrap();
        dir
    }

    /// A tar of `entries` (kind, path, link or content, mode), each as written: a path a
    /// tar program would not write is written too.
    fn tar_of(entries: &[(tar::EntryType, &str, &str, u32)]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (kind, path, said, mode) in entries {
            let (link, data) = if [Symlink, Link].contains(kind) {
                (*said, "")
            } else {
                ("", *said)
            };
            let mut header = tar::Header::new_gnu();
            let old = header.as_old_mut();
            old.name[..path.len()].copy_from_slice(path.as_bytes());
            old.linkname[..link.len()].copy_from_slice(link.as_bytes());
            header.set_entry_type(*kind);
            if *kind == tar::EntryType::GNUSparse {
                // (One byte of it, where it says: a sparse file that reads as one.)
                let gnu = header.as_gnu_mut().unwrap();
                gnu.realsize.copy_from_slice(b"00000000001\0");
                gnu.sparse[0].offset.copy_from_slice(b"00000000000\0");
                gnu.sparse[0].numbytes.copy_from_slice(b"00000000001\0");
            }
            header.set_mode(*mode);
            header.set_size(data.len() as u64);
            header.set_mtime(1_700_000_000);
            header.set_cksum();
            tar.append(&header, data.as_bytes()).unwrap();
        }
        tar.into_inner().unwrap()
    }

    fn sent(tar: &[u8], into: &Path) -> Result<Put, String> {
        unpack(tar, into, u64::MAX, &|| u64::MAX)
    }

    /// Every name under `dir`, sorted.
    fn names(dir: &Path) -> Vec<String> {
        fn walk(dir: &Path, under: &Path, names: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = under.join(entry.file_name());
                names.push(path.display().to_string());
                if entry.file_type().unwrap().is_dir() {
                    walk(&entry.path(), &path, names);
                }
            }
        }
        let mut names = Vec::new();
        walk(dir, Path::new(""), &mut names);
        names.sort();
        names
    }

    #[test]
    fn files_go_in_beside_what_is_there_and_come_out_as_they_are() {
        let root = temp("round");
        let into = root.join("volume");
        std::fs::create_dir(into.join("conf")).unwrap();
        std::fs::write(into.join("conf/old"), b"stays").unwrap();
        std::fs::write(into.join("conf/new"), b"gives way").unwrap();
        let tar = tar_of(&[
            (Directory, "./", "", 0o755),
            (Directory, "./conf/", "", 0o750),
            (Regular, "old/", "", 0o755),
            (Regular, "./conf/new", "what was sent", 0o640),
            (Regular, "a/b/c", "deep", 0o644),
            (Symlink, "conf/link", "../a/b/c", 0o777),
            (Link, "again", "conf/new", 0o640),
            (Regular, "tool", "#!", 0o6755),
        ]);
        let done = sent(&tar, &into).unwrap();
        assert_eq!((done.files, done.bytes, done.left_out.len()), (3, 19, 0));
        let all = [
            "a",
            "a/b",
            "a/b/c",
            "again",
            "conf",
            "conf/link",
            "conf/new",
            "conf/old",
            "old",
            "tool",
        ];
        assert!(into.join("old").is_dir(), "a name that ends in a slash is a directory");
        assert_eq!(names(&into), all, "and nothing of the put's own is left");
        assert_eq!(std::fs::read(into.join("conf/old")).unwrap(), b"stays");
        assert_eq!(std::fs::read(into.join("conf/new")).unwrap(), b"what was sent");
        let mode = |name: &str| std::fs::metadata(into.join(name)).unwrap().mode() & 0o7777;
        assert_eq!((mode("conf/new"), mode("tool")), (0o640, 0o755), "as sent, less set-id");
        assert_eq!(
            std::fs::read_link(into.join("conf/link")).unwrap(),
            Path::new("../a/b/c")
        );
        let inode = |name: &str| std::fs::metadata(into.join(name)).unwrap().ino();
        assert_eq!(inode("again"), inode("conf/new"), "one file under two names");
        assert_eq!(std::fs::metadata(into.join("a/b/c")).unwrap().mtime(), 1_700_000_000);

        // Out again: no name climbs.
        let packed = crate::backups::stream(&into, Vec::new()).unwrap();
        let mut out = tar::Archive::new(&packed[..]);
        let paths = out
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().into_owned());
        let paths: Vec<PathBuf> = paths.collect();
        assert!(paths.contains(&PathBuf::from("conf/new")), "{paths:?}");
        assert!(paths.iter().all(|path| inside(path).is_some()), "{paths:?}");
        let again = root.join("again");
        std::fs::create_dir(&again).unwrap();
        sent(&packed, &again).unwrap();
        assert_eq!(names(&again), all);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn what_climbs_out_or_is_no_file_is_refused_by_name_and_nothing_of_it_is_left() {
        let root = temp("refused");
        let into = root.join("volume");
        std::fs::write(into.join("kept"), b"as it was").unwrap();
        let wrong: [(tar::EntryType, &str, &str); 9] = [
            (Regular, "../evil", "leaves the volume"),
            (Regular, "/evil", "leaves the volume"),
            (Regular, "a/../../evil", "leaves the volume"),
            (Link, "evil", "leaves the volume"),
            (Char, "evil", "only files, directories and links"),
            (Fifo, "evil", "only files, directories and links"),
            (tar::EntryType::GNUSparse, "evil", "only files, directories and links"),
            (Regular, ".kith-put/evil", "a name kithd keeps"),
            (Regular, "kept/evil", "a file is in the way"),
        ];
        for (kind, path, why) in wrong {
            let link = if kind == Link { "../kept" } else { "x" };
            let good = (Regular, "good", "came first", 0o644);
            let kept = (Regular, "kept", "replaced", 0o644);
            // (The last one makes `kept` a file in the stream before it is gone into.)
            let first = if path == "kept/evil" { kept } else { good };
            let refused = sent(&tar_of(&[first, (kind, path, link, 0o644)]), &into).unwrap_err();
            assert!(refused.contains(why) && refused.contains("evil"), "{path}: {refused}");
            assert_eq!(names(&into), ["kept"], "{path}");
            assert_eq!(std::fs::read(into.join("kept")).unwrap(), b"as it was", "{path}");
            assert!(!root.join("evil").exists() && !root.join("kept").exists());
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_link_out_is_left_out_and_said_and_no_link_is_ever_gone_through() {
        let root = temp("links");
        let (into, outside) = (root.join("volume"), root.join("outside"));
        std::fs::create_dir(&outside).unwrap();
        let tar = tar_of(&[
            (Symlink, "etc", "/etc", 0o777),
            (Symlink, "deep/up", "../../outside", 0o777),
            (Symlink, "deep/beside", "../file", 0o777),
            (Symlink, "deep/around", "beside/../../..", 0o777),
            (Regular, "file", "x", 0o644),
        ]);
        // (A file of the name a put keeps for itself, left by who knows what, is no hindrance.)
        std::fs::write(into.join(STAGING), b"in the way").unwrap();
        let done = sent(&tar, &into).unwrap();
        let out = [
            "etc -> /etc",
            "deep/up -> ../../outside",
            "deep/around -> beside/../../..",
        ];
        assert_eq!(done.left_out, out);
        assert_eq!(names(&into), ["deep", "deep/beside", "file"]);

        // A link the stream made is not a directory to the entries after it.
        let through = tar_of(&[(Symlink, "way", "deep", 0o777), (Regular, "way/evil", "x", 0o644)]);
        let refused = sent(&through, &into).unwrap_err();
        assert!(refused.contains("way/evil: a link is in the way"), "{refused}");
        // Nor is one a container made in the Volume, whatever it points at.
        std::os::unix::fs::symlink(&outside, into.join("data")).unwrap();
        let refused = sent(&tar_of(&[(Regular, "data/evil", "x", 0o644)]), &into).unwrap_err();
        assert!(
            refused.contains("data: a directory in what was sent, a file or a link in the volume"),
            "{refused}"
        );
        assert_eq!(names(&outside), [""; 0]);
        // (And a file of that name takes the link's place, not what it points at.)
        sent(&tar_of(&[(Regular, "data", "x", 0o644)]), &into).unwrap();
        assert!(std::fs::symlink_metadata(into.join("data")).unwrap().is_file());
        assert_eq!(names(&outside), [""; 0]);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_put_stops_at_what_the_volume_holds_and_at_what_the_disk_must_keep() {
        let root = temp("bound");
        let into = root.join("volume");
        let two = tar_of(&[(Regular, "one", "12345678", 0o644), (Regular, "two", "12345678", 0o644)]);
        let refused = unpack(&two[..], &into, 10, &|| u64::MAX).unwrap_err();
        assert!(
            refused.starts_with("two: with it the files are more than the 10 bytes"),
            "{refused}"
        );
        let refused = unpack(&two[..], &into, u64::MAX, &|| RESERVE + 7).unwrap_err();
        assert!(refused.starts_with("one: the node's disk has"), "{refused}");
        // (Directories and links are not free either.)
        let dirs = tar_of(&[(Directory, "a/", "", 0o755), (Symlink, "b", "a", 0o777)]);
        let refused = unpack(&dirs[..], &into, u64::MAX, &|| RESERVE - 1).unwrap_err();
        assert!(refused.starts_with("a/: the node's disk has"), "{refused}");
        assert_eq!(names(&into), [""; 0]);
        assert_eq!(unpack(&two[..], &into, 16, &|| RESERVE + 8).unwrap().bytes, 16);

        // What cannot go in is found before anything moves: `one` is not replaced either.
        std::fs::remove_file(into.join("two")).unwrap();
        std::fs::create_dir(into.join("two")).unwrap();
        let other = tar_of(&[(Regular, "one", "other", 0o644), (Regular, "two", "x", 0o644)]);
        let refused = sent(&other, &into).unwrap_err();
        assert!(refused.starts_with("two: a directory in the volume"), "{refused}");
        assert_eq!(std::fs::read(into.join("one")).unwrap(), b"12345678");
        // A stream that is cut short is no put at all.
        let cut = &two[..two.len() - 1024 - 512 - 4];
        assert!(sent(cut, &into).is_err());
        assert_eq!(names(&into), ["one", "two"]);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_body_whose_sender_only_goes_away_is_not_all_of_it() {
        let read = |ends: bool| {
            let (to, from) = mpsc::channel(4);
            to.blocking_send(Ok(Bytes::from_static(b"some"))).unwrap();
            if ends {
                to.blocking_send(Ok(Bytes::new())).unwrap();
            }
            drop(to);
            let (rest, ended) = (Bytes::new(), false);
            let mut all = Vec::new();
            In { from, rest, ended }.read_to_end(&mut all).map(|_| all)
        };
        assert_eq!(read(true).unwrap(), b"some");
        assert!(read(false).is_err());
    }

    #[tokio::test]
    async fn the_routes_are_for_who_may_mount_the_volume_and_carry_its_files() {
        let dir = std::env::temp_dir().join(format!("kithd-volume-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
        let me = shared.members.me().to_string();
        let volume = |namespace: &str, path: &str| {
            let volume = json!({
                "apiVersion": "kith.dev/v1", "kind": "Volume",
                "metadata": { "name": "data", "namespace": namespace },
                "spec": { "node": me, "path": path },
            });
            serde_json::from_value(volume).unwrap()
        };
        let resources = vec![
            volume("default", "d"),
            volume(SYSTEM, dir.join("host").to_str().unwrap()),
        ];
        let at = kith_api::store::now();
        let applied = shared.write(kith_store::Command::Apply { resources, at }).await;
        applied.unwrap();
        let ask = |caller: Caller, namespace: &str, tar: Vec<u8>| {
            let route = (namespace.to_string(), "data".to_string());
            put(
                State(shared.clone()),
                Extension(caller),
                UrlPath(route),
                Body::from(tar),
            )
        };
        let tar = tar_of(&[(Regular, "deep/file", "what was sent", 0o644)]);

        // Not an Identity no Role lets mount it, and not a directory of the host's.
        let refused = ask(Caller::Identity("carol".into()), "default", tar.clone()).await;
        let Err(ApiError::Refused(why)) = refused else {
            panic!("carol was let in")
        };
        assert!(why.contains("carol may not apply Volume in namespace default"), "{why}");
        let Err(ApiError::Store(Error::Invalid(why))) = ask(Caller::Admin, SYSTEM, tar.clone()).await else {
            panic!("a host directory was written")
        };
        assert!(why.contains("a directory of the host's"), "{why}");
        assert!(!dir.join("host").exists());

        let Json(done) = ask(Caller::Admin, "default", tar).await.ok().unwrap();
        assert_eq!(
            (&done["files"], &done["bytes"], done["node"].as_str()),
            (&json!(1), &json!(13), Some(&*me))
        );
        let file = dir.join("volumes/default/data/d/deep/file");
        assert_eq!(std::fs::read(&file).unwrap(), b"what was sent");
        // A stream that is refused says why, and is in the audit log with who sent it.
        let evil = ask(Caller::Admin, "default", tar_of(&[(Regular, "../evil", "x", 0o644)])).await;
        let Err(ApiError::Store(Error::Invalid(why))) = evil else {
            panic!("it was let out")
        };
        assert!(why.contains("../evil"), "{why}");

        let route = UrlPath(("default".to_string(), "data".to_string()));
        let got = get(State(shared.clone()), Extension(Caller::Admin), route)
            .await
            .ok()
            .unwrap();
        let packed = axum::body::to_bytes(got.into_body(), 1 << 20).await.unwrap();
        let mut out = tar::Archive::new(&packed[..]);
        let mut read = String::new();
        for entry in out.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap() == Path::new("deep/file") {
                entry.read_to_string(&mut read).unwrap();
            }
        }
        assert_eq!(read, "what was sent");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
