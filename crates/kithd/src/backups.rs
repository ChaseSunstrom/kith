//! Backups: a Volume's directory as an archive, kept somewhere else, every so often.
//!
//! POST /v1/backups/NS/NAME/restore[?at=SECONDS]   the backup back into its (empty) volume
//!
//! A `Backup` names a Volume, how often (`every: 24h`) and how many to keep. The node the
//! volume is on makes a tar of its directory when one is due and keeps it as a blob (so
//! other nodes hold it too: [`crate::blobs`]), or sends it to the S3 bucket the Backup
//! names. `status.backups` lists them, oldest first: `{at, size, blob | object}`.
//!
//! The archive is of the directory as it is while it is read: what a crash at that moment
//! would have left. (A snapshot first needs a filesystem that has them.)

use crate::Shared;
use crate::access::Caller;
use crate::api::{ApiError, permit};
use crate::blobs::Incoming;
use crate::volumes::Dir;
use axum::Json;
use axum::extract::{Extension, Path as UrlPath, Query, State};
use kith_api::kinds::{BackupSpec, S3, SecretSpec, Verb, every};
use kith_api::store::{Error, Store};
use kith_store::Command;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// How often a node looks for a backup that is due.
const ROUND: Duration = Duration::from_secs(10);
/// How many are kept, when the Backup does not say.
const KEEP: usize = 7;
/// A backup that failed is tried again after this long, or after `every` if that is less.
const AGAIN: u64 = 600;
/// A bucket that says nothing for this long is given up on.
const QUIET: Duration = Duration::from_secs(60);

/// A backup to make now.
#[derive(Debug)]
struct Job {
    key: String,
    namespace: String,
    name: String,
    dir: Dir,
    spec: BackupSpec,
    /// Those there are, oldest first.
    backups: Vec<Value>,
}

/// The Backups of volumes on `me` that are due at `now`.
fn due(store: &Store, me: &str, now: u64) -> Vec<Job> {
    let job = |backup: &kith_api::Resource| {
        let spec: BackupSpec = serde_json::from_value(backup.spec.clone()).ok()?;
        let namespace = backup.metadata.namespace.clone().unwrap_or_else(|| "default".into());
        let dir = crate::volumes::dir(store, &namespace, &spec.volume).filter(|dir| dir.node == me)?;
        let status = backup.status.clone().unwrap_or_default();
        let backups = status["backups"].as_array().cloned().unwrap_or_default();
        let last = backups.last().and_then(|last| last["at"].as_u64());
        let tried = status["tried"].as_u64();
        let wait = every(&spec.every)?;
        let wait = if tried > last { wait.min(AGAIN) } else { wait };
        let since = tried.max(last);
        since.is_none_or(|since| now >= since + wait).then(|| Job {
            key: backup.key(),
            namespace,
            name: backup.metadata.name.clone(),
            dir,
            spec,
            backups,
        })
    };
    store.list(Some("Backup")).filter_map(job).collect()
}

/// `backups` with `new` at its end and no more than `keep` of them: (kept, let go). One let
/// go whose blob a kept one has too (nothing changed between them) is not in the second.
fn kept(mut backups: Vec<Value>, new: Value, keep: usize) -> (Vec<Value>, Vec<Value>) {
    backups.push(new);
    let over = backups.len().saturating_sub(keep.max(1));
    let kept = backups.split_off(over);
    let held = |old: &Value| !old["blob"].is_null() && kept.iter().any(|kept| kept["blob"] == old["blob"]);
    backups.retain(|old| !held(old));
    (kept, backups)
}

/// `dir` as a tar in the blob store at `blobs`: the blob's name and size.
///
/// Whatever runs in the volume can change it while it is read, so nothing in it is reached
/// by a path the volume could turn elsewhere: every directory is held open and its entries
/// are opened from that handle, never through a link. A link is kept as the link it is
/// (what it points at is not this volume's to read); an entry that became a link while it
/// was looked at is left out. Entries go in by name, so the same files make the same blob.
pub(crate) fn archive(dir: &Path, blobs: &Path) -> Result<(String, u64), String> {
    let failed = |e: std::io::Error| format!("archiving {}: {e}", dir.display());
    let packed = Incoming::new(blobs).and_then(|blob| stream(dir, blob));
    packed.map_err(failed)?.keep(None)
}

/// `dir` as a tar written to `out`, as [`archive`] says: what it was written to, once all
/// of it is.
pub(crate) fn stream<W: std::io::Write>(dir: &Path, out: W) -> std::io::Result<W> {
    let mut tar = tar::Builder::new(out);
    let root = std::fs::File::open(dir)?;
    let mut header = tar::Header::new_gnu();
    header.set_metadata(&root.metadata()?);
    tar.append_data(&mut header, ".", std::io::empty())?;
    pack(&mut tar, &root, Path::new("."))?;
    tar.into_inner()
}

/// `name` in the directory `dir` is open at, as a path through that handle.
pub(crate) fn within(dir: &std::fs::File, name: &std::ffi::OsStr) -> PathBuf {
    use std::os::fd::AsRawFd;
    Path::new("/proc/self/fd").join(dir.as_raw_fd().to_string()).join(name)
}

/// Open `name` in `dir`: not if it is a link, and without waiting on a pipe put there.
pub(crate) fn open_in(dir: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
    use nix::fcntl::OFlag;
    use std::os::unix::fs::OpenOptionsExt;
    let flags = OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_NOCTTY;
    let mut open = std::fs::OpenOptions::new();
    open.read(true).custom_flags(flags.bits()).open(within(dir, name))
}

/// How many directories deep an archive goes.
// ponytail: a directory inside another is a call inside another and one more open file,
// and a volume's own program can nest them without end (a held directory has no longest
// path), so the walk stops here and the archive fails with these words. Walk with a list
// of its own instead if a real volume is ever deeper.
pub(crate) const DEEPEST: usize = 128;

/// Every entry of the directory `dir` is open at into `tar`, under `at`.
fn pack<W: std::io::Write>(tar: &mut tar::Builder<W>, dir: &std::fs::File, at: &Path) -> std::io::Result<()> {
    // (As an unpack counts: `.` is no directory down, so what a restore takes is packed again.)
    let down = at
        .components()
        .filter(|part| matches!(part, std::path::Component::Normal(_)));
    if down.count() > DEEPEST {
        let said = format!("{} is more than {DEEPEST} directories deep", at.display());
        return Err(std::io::Error::other(said));
    }
    let listed = std::fs::read_dir(within(dir, ".".as_ref()))?;
    let mut names = listed
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    for name in names {
        // (One that is gone since it was listed is no part of the archive.)
        if let Ok(seen) = std::fs::symlink_metadata(within(dir, &name)) {
            put(tar, dir, &name, &at.join(&name), &seen)?;
        }
    }
    Ok(())
}

/// What opening an entry says when it is no longer the file or directory it was: a link
/// now, gone, or a socket.
const SWAPPED: [nix::errno::Errno; 3] = [
    nix::errno::Errno::ELOOP,
    nix::errno::Errno::ENOENT,
    nix::errno::Errno::ENXIO,
];

/// `name` in `dir` into `tar` as `path`. `seen` is what it looked like a moment ago, and
/// decides only how it is opened: what is written is what was opened.
fn put<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    dir: &std::fs::File,
    name: &std::ffi::OsStr,
    path: &Path,
    seen: &std::fs::Metadata,
) -> std::io::Result<()> {
    let mut header = tar::Header::new_gnu();
    if seen.file_type().is_symlink() {
        if let Ok(to) = std::fs::read_link(within(dir, name)) {
            header.set_metadata(seen);
            tar.append_link(&mut header, path, to)?;
        }
    } else if seen.is_dir() || seen.is_file() {
        // (A link put there since, or gone since: nothing of it goes in. Anything else
        // that keeps a file from being read is an archive that was not made.)
        let file = match open_in(dir, name) {
            Ok(file) => file,
            Err(e) if SWAPPED.iter().any(|gone| e.raw_os_error() == Some(*gone as i32)) => return Ok(()),
            Err(e) => return Err(std::io::Error::new(e.kind(), format!("{}: {e}", path.display()))),
        };
        let found = file.metadata()?;
        header.set_metadata(&found);
        if found.is_dir() {
            tar.append_data(&mut header, path, std::io::empty())?;
            pack(tar, &file, path)?;
        } else if found.is_file() {
            // (As long as it was a moment ago, whether it grows or is cut short meanwhile:
            // an entry of another length than its header says breaks every entry after it.)
            let whole = std::io::Read::chain(file, std::io::repeat(0));
            tar.append_data(&mut header, path, std::io::Read::take(whole, found.len()))?;
        }
    }
    // (Pipes, sockets and devices are no part of an archive, and are never opened.)
    Ok(())
}

/// What a Volume that says its size may be sent, as an archive: the size, doubled (a tar
/// spends 512 bytes on a header and pads each file to 512) and a megabyte. What the archive
/// unpacks to is counted by [`unpack_beside`], which is what fills the disk: this stops a
/// download that never ends. (No size: no end.)
pub(crate) fn download_cap(size: u64) -> u64 {
    size.saturating_mul(2).saturating_add(1 << 20)
}

/// What `answer` sends into `incoming`, as long as it is no more than `most` bytes: more
/// is an error, said before a byte is taken when the length is said, and as soon as the
/// last byte that may come has.
pub(crate) async fn receive(
    answer: &mut reqwest::Response,
    incoming: &mut Incoming,
    quiet: Duration,
    most: u64,
) -> Result<(), String> {
    let over = || format!("it sends more than {most} bytes, more than the Volume may hold");
    if answer.content_length().is_some_and(|length| length > most) {
        return Err(over());
    }
    let mut got = 0u64;
    loop {
        let chunk = tokio::time::timeout(quiet, answer.chunk()).await;
        let chunk = chunk.map_err(|_| format!("nothing came for {} s", quiet.as_secs()))?;
        let Some(chunk) = chunk.map_err(|e| e.to_string())? else {
            return Ok(());
        };
        got += chunk.len() as u64;
        if got > most {
            return Err(over());
        }
        incoming.write(&chunk).map_err(|e| e.to_string())?;
    }
}

/// The tar at `archive` into `dir`, which must have nothing in it. Unpacked beside it and
/// moved into its place when all of it is there: a restore that fails leaves `dir` as it was.
/// `cap`: how many bytes it may unpack to (see [`unpack_beside`]).
fn unpack(archive: &Path, dir: &Path, cap: u64) -> Result<(), String> {
    let failed = |e: std::io::Error| format!("restoring into {}: {e}", dir.display());
    let full = || "the volume has files in it: a backup is restored into an empty volume".to_string();
    if std::fs::read_dir(dir).map_err(failed)?.next().is_some() {
        return Err(full());
    }
    // (An archive may come from a bucket others can write: nothing in it becomes a program
    // that runs as its owner.)
    unpack_beside(archive, dir, 0o6000, cap).and_then(|beside| into_place(&beside, dir))
}

/// The directory `beside` moved to `dir`, which must still be empty. It is renamed over
/// `dir`, with nothing removed first: a move that fails leaves `dir` there as it was, its mode
/// and owner too, and `beside` goes.
fn into_place(beside: &Path, dir: &Path) -> Result<(), String> {
    let moved = std::fs::rename(beside, dir).map_err(|e| {
        // (A rename takes the place of an empty directory only.)
        let full = [nix::errno::Errno::ENOTEMPTY, nix::errno::Errno::EEXIST];
        if full.iter().any(|full| e.raw_os_error() == Some(*full as i32)) {
            "the volume has files in it: a backup is restored into an empty volume".to_string()
        } else {
            format!("restoring into {}: {e}", dir.display())
        }
    });
    if moved.is_err() {
        remove_unpacked(beside);
    }
    moved
}

/// The object `object` of `bucket` restored into `dir` (see [`unpack`]), to at most `cap`
/// bytes. It is downloaded into `blobs` and unpacked from there, and the download is
/// removed when the unpack is done or refused: it is not a blob of the store.
async fn from_bucket(bucket: &Bucket, object: &str, blobs: &Path, dir: PathBuf, cap: u64) -> Result<(), String> {
    let mut answer = s3(bucket, reqwest::Method::GET, object, None).await?;
    let mut incoming = Incoming::new(blobs).map_err(|e| e.to_string())?;
    let said = |e: String| format!("the bucket: {e}");
    receive(&mut answer, &mut incoming, QUIET, download_cap(cap))
        .await
        .map_err(said)?;
    // (`incoming` goes with the closure, when the unpack ends however it ends: its file with it.)
    let unpacked = tokio::task::spawn_blocking(move || unpack(incoming.path(), &dir, cap)).await;
    unpacked.map_err(|e| e.to_string())?
}

/// What a file, a directory or a link takes of a disk at least, and the unit an unpack counts in.
const BLOCK: u64 = 4096;

/// The tar at `archive` unpacked into a new directory beside `dir`: where it is. Nothing is
/// left there if it fails, nor what an unpack that was killed left.
///
/// `cap` is how many bytes it may unpack to (a Volume with no size: `u64::MAX`). Each entry
/// counts at the size it unpacks to rounded up to `BLOCK` and at least that (a directory, a
/// link and an empty file take a block), before it is unpacked, and the one that passes `cap`
/// is the error. A GNU sparse entry says its whole length (the tar crate gives that as
/// `size()`, and unpacks it as a hole that takes next to no disk): it counts whole, as
/// the next archive of the Volume reads it whole.
pub(crate) fn unpack_beside(archive: &Path, dir: &Path, mask: u32, cap: u64) -> Result<PathBuf, String> {
    let failed = |e: std::io::Error| format!("unpacking for {}: {e}", dir.display());
    let beside = beside(dir).ok_or_else(|| failed(std::io::Error::other("a directory with no name")))?;
    remove_unpacked(&beside);
    let unpacked = std::fs::create_dir(&beside)
        .and_then(|()| beside.canonicalize())
        .and_then(|to| unpack_to(archive, &to, mask, cap));
    if unpacked.is_err() {
        remove_unpacked(&beside);
    }
    unpacked.map(|_| beside).map_err(failed)
}

/// Where [`unpack_beside`] unpacks for `dir`: `.NAME.restoring` in the same directory. A
/// Volume's own directory is named for it, and a name starts with a letter or a digit, so
/// this is no other Volume's (`x.restoring` beside `x` can be); only a `kith-system`
/// Volume, whose path is the admin's to name, could be given one like it.
fn beside(dir: &Path) -> Option<PathBuf> {
    let mut name = std::ffi::OsString::from(".");
    name.push(dir.file_name()?);
    name.push(".restoring");
    Some(dir.with_file_name(name))
}

/// What an unpack left at `beside` removed, its directories first opened to their owner
/// (one the archive shut, with files in it, cannot be emptied otherwise where kithd is not
/// root): the most directories it held open at once. No link is followed: a directory is
/// opened only where it is one. The walk holds the directories it is inside of, each open
/// with its listing read through it and each one in it opened through it, to [`DEEPEST`]
/// below `beside`; one deeper is left to the removal, which empties it where its owner may.
pub(crate) fn remove_unpacked(beside: &Path) -> usize {
    use std::os::unix::fs::PermissionsExt;
    let open = |path: &Path| {
        let dir = open_dir(path).ok()?;
        let mode = dir.metadata().ok()?.permissions().mode();
        if mode & 0o700 != 0o700 {
            let _ = dir.set_permissions(std::fs::Permissions::from_mode(mode & 0o7777 | 0o700));
        }
        let listing = std::fs::read_dir(within(&dir, ".".as_ref())).ok()?;
        Some((dir, listing))
    };
    let (mut inside, mut most) = (Vec::from_iter(open(beside)), 0);
    loop {
        let held = inside.len();
        most = most.max(held);
        let Some((dir, listing)) = inside.last_mut() else { break };
        let Some(entry) = listing.next() else {
            inside.pop();
            continue;
        };
        if held <= DEEPEST
            && let Ok(entry) = entry
            && entry.file_type().is_ok_and(|kind| kind.is_dir())
            && let Some(under) = open(&within(dir, &entry.file_name()))
        {
            inside.push(under);
        }
    }
    // (One left here fails the next unpack for the same Volume: said once, here.)
    match crate::controller::storage::remove_tree(beside, &|| false) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            eprintln!("kithd: {} was not removed: {e}", beside.display());
        }
        _ => {}
    }
    most
}

/// The directory at `path` open, not through a link in its place.
pub(crate) fn open_dir(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let flags = nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_DIRECTORY;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits())
        .open(path)
}

/// The archive that [`unpack_to`] reads, which counts what the tar crate reads of it while
/// it finds the next entry (its header, and a long name, PAX header or sparse map it reads
/// whole) and refuses more than [`HEADERS`].
struct Metered {
    file: std::fs::File,
    /// How long the archive is: what an entry skips goes no further.
    len: u64,
    /// What was read since the last entry was asked for; none while an entry is unpacked.
    read: std::rc::Rc<std::cell::Cell<Option<u64>>>,
}

/// The most an entry's headers may take, read: a path is 4 KiB at most.
const HEADERS: u64 = 256 * 1024;

impl std::io::Read for Metered {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let got = self.file.read(buf)?;
        // The tar crate adds each map block after a GNU sparse header to where the next entry
        // starts, unchecked, and reads them while it finds the entry (before kithd has the
        // entry): a header of 512 bytes, type `S`, with its is-extended byte (482) set is
        // refused here. (Kith's own archives have no sparse entry. A long name's data block
        // that looks so is refused too: a path of over 482 bytes, with an `S` at byte 156.)
        if self.read.get().is_some() && got == 512 && buf[156] == b'S' && buf[482] != 0 {
            let name = buf[..100].split(|b| *b == 0).next().unwrap_or_default();
            return Err(std::io::Error::other(format!(
                "{} is a sparse entry with an extended sparse map, which is not restored",
                String::from_utf8_lossy(name).escape_debug()
            )));
        }
        if let Some(read) = self.read.get() {
            let read = read.saturating_add(got as u64);
            if read > HEADERS {
                return Err(std::io::Error::other(format!(
                    "an entry has headers of more than {HEADERS} bytes (a long name, a PAX header or a sparse map)"
                )));
            }
            self.read.set(Some(read));
        }
        Ok(got)
    }
}

impl std::io::Seek for Metered {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        // (Past the end, a read would find nothing, which the tar crate takes for the
        // archive's end: the archive is cut short, and refused.)
        match self.file.seek(to)? {
            at if at > self.len => Err(std::io::Error::other("the archive ends inside an entry")),
            at => Ok(at),
        }
    }
}

/// A directory an unpack is inside of, as the archive says it: given its mode and time when
/// the archive leaves it.
struct Inside {
    /// Where, under the directory unpacked to.
    path: PathBuf,
    mode: Option<u32>,
    time: Option<std::time::SystemTime>,
}

/// The tar at `archive` unpacked into `to`, which is canonical, as [`unpack_beside`] says:
/// the most directories it held at once.
///
/// (The tar crate lets no entry out of where it unpacks: no `..`, no absolute path, no way
/// through a link.) Each directory is made when it comes, open to its owner until the archive
/// leaves it, and then given its mode and time: an archive in depth-first order (kith's own,
/// GNU tar's) leaves a directory once all that is in it is there, so a mode that shuts it
/// does not shut out what is in it, and the time it is given stays. The directories held are
/// those the archive is inside of, as many as it is deep and no more than [`DEEPEST`].
fn unpack_to(archive: &Path, to: &Path, mask: u32, cap: u64) -> std::io::Result<usize> {
    use std::os::unix::fs::PermissionsExt;
    let read = std::rc::Rc::new(std::cell::Cell::new(None));
    let file = std::fs::File::open(archive)?;
    let len = file.metadata()?.len();
    let mut tar = tar::Archive::new(Metered {
        file,
        len,
        read: read.clone(),
    });
    tar.set_preserve_permissions(true);
    tar.set_preserve_mtime(true);
    tar.set_mask(mask);
    // (Whose each file is, where kithd may say: as root, which it is on a node.)
    tar.set_preserve_ownerships(std::fs::metadata("/proc/self").is_ok_and(|me| {
        use std::os::unix::fs::MetadataExt;
        me.uid() == 0
    }));
    let (mut held, mut inside, mut most) = (0u64, Vec::<Inside>::new(), 0);
    // (With seek: what an entry leaves unread is skipped, not read and counted.)
    let mut entries = tar.entries_with_seek()?;
    loop {
        read.set(Some(0));
        let Some(entry) = entries.next() else { break };
        read.set(None);
        let mut entry = entry?;
        // (In blocks, as the disk has it: a directory, a link and a file of a byte take 4 KiB.)
        held = held.saturating_add(entry.size().div_ceil(BLOCK).max(1).saturating_mul(BLOCK));
        if held > cap {
            return Err(std::io::Error::other(format!(
                "the archive unpacks to more than {cap} bytes, more than the Volume may hold"
            )));
        }
        // (Where it goes, as the tar crate reads it: `.` and `/` are nothing, and an entry
        // with `..` is not unpacked at all.)
        let path = entry
            .path()?
            .components()
            .try_fold(PathBuf::new(), |path, part| match part {
                std::path::Component::Normal(part) => Some(path.join(part)),
                std::path::Component::ParentDir => None,
                _ => Some(path),
            });
        let Some(path) = path.filter(|path| !path.as_os_str().is_empty()) else {
            entry.unpack_in(to)?;
            continue;
        };
        while inside
            .last()
            .is_some_and(|dir| path == dir.path || !path.starts_with(&dir.path))
        {
            close(to, inside.pop().expect("there is one"))?;
        }
        // (Those held are the ones it is in: as many as its path has parts, at most. A file
        // is in one fewer, which the tar crate makes where the archive did not: as deep, too.
        // A directory is also what the tar crate makes of an old header's name that ends in
        // `/`, unless it is a link.)
        let kind = entry.header().entry_type();
        let is_dir = kind.is_dir()
            || (!kind.is_hard_link()
                && !kind.is_symlink()
                && entry.header().as_ustar().is_none()
                && entry.path_bytes().ends_with(b"/"));
        if path.components().count() - usize::from(!is_dir) > DEEPEST {
            let said = format!("{} is more than {DEEPEST} directories deep", path.display());
            return Err(std::io::Error::other(said));
        }
        if entry.unpack_in(to)? && is_dir {
            let mode = entry.header().mode().ok().map(|mode| mode & 0o7777 & !mask);
            if mode.is_some_and(|mode| mode & 0o700 != 0o700) {
                // (Made a moment ago by the tar crate, as a directory: opened as one, and not
                // through a link in its place, whatever the crate makes of one there.)
                let open = std::fs::Permissions::from_mode(mode.unwrap_or(0) | 0o700);
                open_dir(&to.join(&path))?.set_permissions(open)?;
            }
            let time = entry.header().mtime().ok();
            // (A time past what the clock holds, which a base-256 header can say, is no time.)
            let time = time.and_then(|at| std::time::UNIX_EPOCH.checked_add(Duration::from_secs(at)));
            inside.push(Inside { path, mode, time });
            most = most.max(inside.len());
        }
    }
    while let Some(dir) = inside.pop() {
        close(to, dir)?;
    }
    Ok(most)
}

/// `dir`, under `to`, given its mode and time: only where its path still leads to it, with
/// no link on the way, and through no link in its place.
fn close(to: &Path, dir: Inside) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let at = to.join(&dir.path);
    if at.canonicalize()? != at {
        return Ok(());
    }
    let file = open_dir(&at)?;
    if let Some(time) = dir.time {
        file.set_times(std::fs::FileTimes::new().set_accessed(time).set_modified(time))?;
    }
    if let Some(mode) = dir.mode {
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

// ---- S3 ----

/// A bucket and who to be there.
struct Bucket {
    /// `https://host[:port]`
    endpoint: String,
    bucket: String,
    region: String,
    prefix: String,
    access: String,
    secret: String,
    /// The cluster's mesh, which no bucket is on.
    mesh: Option<std::net::Ipv6Addr>,
    /// (A test's bucket is on this machine.)
    anywhere: bool,
}

/// The bucket `s3` names, with the keys in its Secret (`accessKey`, `secretKey`).
fn bucket(shared: &Shared, namespace: &str, s3: &S3) -> Result<Bucket, String> {
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let key = format!("Secret/{namespace}/{}", s3.secret);
    let secret = state.store.get(&key).ok_or(format!("{key} is not there"))?;
    let secret: SecretSpec = serde_json::from_value(secret.spec.clone()).map_err(|e| e.to_string())?;
    let field = |name: &str| secret.data.get(name).cloned().ok_or(format!("{key} has no {name}"));
    Ok(Bucket {
        endpoint: s3.endpoint.trim_end_matches('/').to_string(),
        bucket: s3.bucket.clone(),
        region: s3.region.clone().unwrap_or_else(|| "us-east-1".into()),
        prefix: s3.prefix.clone().unwrap_or_default(),
        access: field("accessKey")?,
        secret: field("secretKey")?,
        mesh: shared
            .cluster
            .as_ref()
            .map(|cluster| crate::mesh::prefix(&cluster.me.ca)),
        anywhere: false,
    })
}

/// May a bucket be at `address`? Whoever may write a Backup names the endpoint kithd then
/// talks to, as the node: not this machine, not a link-local address (where a cloud's
/// metadata service is) and not the cluster's own mesh. An address on the LAN may: that is
/// where a NAS is.
fn outside(address: std::net::IpAddr, mesh: Option<std::net::Ipv6Addr>) -> bool {
    use std::net::IpAddr;
    match address.to_canonical() {
        IpAddr::V4(at) => {
            !(at.is_loopback() || at.is_link_local() || at.is_unspecified() || at.is_multicast() || at.is_broadcast())
        }
        IpAddr::V6(at) => {
            let local = at.is_loopback() || at.is_unspecified() || at.is_multicast() || at.is_unicast_link_local();
            !local && mesh.is_none_or(|mesh| mesh.octets()[..6] != at.octets()[..6])
        }
    }
}

/// Seconds since 1970 as S3 wants a time: `20130524T000000Z`.
fn stamp(at: u64) -> String {
    let (days, rest) = ((at / 86400) as i64, at % 86400);
    // (Days to a date, after Howard Hinnant's `civil_from_days`.)
    let z = days + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The `Authorization` of a request to S3 (AWS Signature Version 4). `headers`: every header
/// that is signed, names in lower case and in order; `path` needs no escaping (ours do not).
fn authorization(
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    payload: &str,
    stamp: &str,
    bucket: &Bucket,
) -> String {
    use ring::{digest, hmac};
    let hex = crate::pki::hex;
    let sign = |key: &[u8], text: &str| hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), text.as_bytes());
    let names: Vec<&str> = headers.iter().map(|(name, _)| *name).collect();
    let names = names.join(";");
    let lines: String = headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect();
    let request = format!("{method}\n{path}\n\n{lines}\n{names}\n{payload}");
    let day = &stamp[..8];
    let scope = format!("{day}/{}/s3/aws4_request", bucket.region);
    let request = hex(digest::digest(&digest::SHA256, request.as_bytes()).as_ref());
    let text = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{request}");
    let mut key = sign(format!("AWS4{}", bucket.secret).as_bytes(), day);
    for part in [bucket.region.as_str(), "s3", "aws4_request"] {
        key = sign(key.as_ref(), part);
    }
    let signature = hex(sign(key.as_ref(), &text).as_ref());
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={signature}",
        bucket.access
    )
}

/// One request for `object` in the bucket (path style: `endpoint/bucket/object`).
async fn s3(
    bucket: &Bucket,
    method: reqwest::Method,
    object: &str,
    body: Option<(reqwest::Body, u64)>,
) -> Result<reqwest::Response, String> {
    let said = |e: reqwest::Error| format!("{} {object} in bucket {}: {e}", method.as_str(), bucket.bucket);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let path = format!("/{}/{object}", bucket.bucket);
    let url = reqwest::Url::parse(&format!("{}{path}", bucket.endpoint)).map_err(|e| e.to_string())?;
    let name = url.host_str().unwrap_or_default().trim_matches(['[', ']']).to_string();
    let host = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_string(),
    };
    // Looked up here, checked, and the connection made to what was checked: a name cannot
    // say one address now and another when the request is sent. No redirect is followed.
    let port = url.port_or_known_default().unwrap_or(443);
    let found = tokio::net::lookup_host((name.as_str(), port)).await;
    let found: Vec<std::net::SocketAddr> = found.map_err(|e| format!("looking up {name}: {e}"))?.collect();
    let refused = found
        .iter()
        .find(|at| !bucket.anywhere && !outside(at.ip(), bucket.mesh));
    if let Some(at) = refused {
        return Err(format!(
            "{name} is at {}: a bucket is not on this machine, a link-local address or the mesh",
            at.ip()
        ));
    }
    let at = *found.first().ok_or(format!("{name} has no address"))?;
    // ponytail: a client a request; they are minutes apart. Keep one when they are not.
    let client = reqwest::Client::builder()
        .connect_timeout(QUIET)
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&name, at)
        .build()
        .map_err(said)?;
    let stamp = stamp(kith_api::store::now());
    // (The body is not hashed into the signature: it is as long as a volume, and goes over TLS.)
    let payload = "UNSIGNED-PAYLOAD";
    let headers = [
        ("host", host.as_str()),
        ("x-amz-content-sha256", payload),
        ("x-amz-date", stamp.as_str()),
    ];
    let authorization = authorization(method.as_str(), &path, &headers, payload, &stamp, bucket);
    let mut request = client
        .request(method.clone(), url)
        .header("x-amz-content-sha256", payload)
        .header("x-amz-date", &stamp)
        .header("authorization", authorization);
    // How long until the answer starts: a minute, and what the body takes at 100 kB/s or better.
    let mut patience = QUIET;
    if let Some((body, size)) = body {
        patience += Duration::from_secs(size / 100_000);
        request = request.header("content-length", size).body(body);
    }
    let slow = |_| {
        format!(
            "{} {object} in bucket {}: no answer in {} s",
            method.as_str(),
            bucket.bucket,
            patience.as_secs()
        )
    };
    let answer = tokio::time::timeout(patience, request.send()).await.map_err(slow)?;
    answer.and_then(reqwest::Response::error_for_status).map_err(said)
}

// ---- Making them ----

/// One at a time on a node, a backup or a restore: neither reads what the other half wrote.
static BUSY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Said of a Blob a backup made, so that pruning never takes one that was put by hand.
const MADE: &str = "kith.dev/made-by";

/// One backup of `job`: what `status.backups` says of it.
async fn make(shared: &Shared, state: &Path, job: &Job, at: u64) -> Result<Value, String> {
    // (Before the volume is read: a Secret that is not there fails at once, every time.)
    let bucket = job
        .spec
        .s3
        .as_ref()
        .map(|s3| bucket(shared, &job.namespace, s3))
        .transpose()?;
    let _alone = BUSY.lock().await;
    let from = crate::root_part::volume(state, &job.dir)?;
    let blobs = crate::blobs::dir(shared);
    let into = blobs.clone();
    let archived = tokio::task::spawn_blocking(move || archive(&from, &into)).await;
    let (blob, size) = archived.map_err(|e| e.to_string())??;
    let Some(bucket) = bucket else {
        let key = format!("Blob/{}/{blob}", job.namespace);
        let there = shared
            .store
            .lock()
            .expect("a handler panicked holding the store")
            .store
            .get(&key)
            .is_some();
        // (The same bytes as a Blob that is there: it is that Blob, whoever made it.)
        if !there {
            let mut spec = json!({ "size": size });
            if let Some(copies) = job.spec.copies {
                spec["copies"] = copies.into();
            }
            let wanted = json!({
                "apiVersion": "kith.dev/v1", "kind": "Blob",
                "metadata": { "name": blob, "namespace": job.namespace, "annotations": { MADE: "backup" } },
                "spec": spec,
            });
            let resources = vec![serde_json::from_value(wanted).map_err(|e| e.to_string())?];
            let applied = shared
                .write(Command::Apply {
                    resources,
                    at: kith_api::store::now(),
                })
                .await;
            applied.map_err(|e| e.to_string())?;
        }
        return Ok(json!({ "at": at, "size": size, "blob": blob }));
    };
    // (The file is no Blob's: the blob store removes it in ten minutes.)
    let object = format!("{}{}/{}-{}.tar", bucket.prefix, job.namespace, job.name, stamp(at));
    let file = std::fs::File::open(blobs.join(&blob)).map_err(|e| e.to_string())?;
    let body = reqwest::Body::wrap_stream(crate::blobs::chunks(file));
    s3(&bucket, reqwest::Method::PUT, &object, Some((body, size))).await?;
    Ok(json!({ "at": at, "size": size, "object": object }))
}

/// Does a Backup or an Image of `namespace` other than `but` still list `blob`? (The same
/// bytes are one blob, whichever of them made it first.)
pub(crate) fn listed(store: &Store, namespace: &str, but: &str, blob: &str) -> bool {
    let lists = |other: &kith_api::Resource| {
        let Some(status) = &other.status else { return false };
        let backups = status["backups"].as_array().into_iter().flatten();
        let pieces = status["blobs"].as_object().into_iter().flatten();
        backups.into_iter().any(|entry| entry["blob"] == blob) || pieces.into_iter().any(|(_, piece)| piece == blob)
    };
    let others = store.list(Some("Backup")).chain(store.list(Some("Image")));
    others
        .filter(|other| other.key() != but)
        .filter(|other| other.metadata.namespace.as_deref().unwrap_or("default") == namespace)
        .any(lists)
}

/// Lets go of a backup that is no longer kept. (What fails here is left behind, and said.)
async fn forget(shared: &Shared, job: &Job, old: &Value) -> Result<(), String> {
    if let Some(blob) = old["blob"].as_str() {
        let key = format!("Blob/{}/{blob}", job.namespace);
        // Only a Blob a backup made, and that no other Backup has too (the same volume
        // backed up daily and weekly, with nothing changed, is one blob).
        let ours = {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            let made = state
                .store
                .get(&key)
                .is_some_and(|blob| blob.metadata.annotations.contains_key(MADE));
            made && !listed(&state.store, &job.namespace, &job.key, blob)
        };
        if !ours {
            return Ok(());
        }
        return match shared.submit(Command::Delete { key }).await {
            Ok(_) | Err(Error::NotFound(_)) => Ok(()),
            Err(e) => Err(e.to_string()),
        };
    }
    let (Some(object), Some(s3_spec)) = (old["object"].as_str(), &job.spec.s3) else {
        return Ok(());
    };
    let bucket = bucket(shared, &job.namespace, s3_spec)?;
    s3(&bucket, reqwest::Method::DELETE, object, None).await.map(drop)
}

/// Makes the backups that are due of the volumes on this node.
pub async fn run(shared: Arc<Shared>, state: PathBuf, mut stopping: watch::Receiver<bool>) {
    let me = shared.members.me().to_string();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(ROUND) => {}
            _ = stopping.changed() => return,
        }
        let now = kith_api::store::now();
        let jobs = {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            due(&state.store, &me, now)
        };
        // ponytail: one at a time; a long archive holds up the next volume's.
        for job in jobs {
            let fields = match make(&shared, &state, &job, now).await {
                Ok(new) => {
                    let keep = job.spec.keep.map_or(KEEP, |keep| keep as usize);
                    let (kept, gone) = kept(job.backups.clone(), new, keep);
                    let mut message = Value::Null;
                    for old in &gone {
                        if let Err(e) = forget(&shared, &job, old).await {
                            message = format!("an old backup was not removed: {e}").into();
                        }
                    }
                    eprintln!("kithd: backup {} made ({} kept)", job.key, kept.len());
                    json!({ "backups": kept, "message": message, "tried": null })
                }
                Err(e) => {
                    eprintln!("kithd: backup {} was not made: {e}", job.key);
                    json!({ "message": e, "tried": now })
                }
            };
            let statuses = vec![(job.key.clone(), fields.as_object().expect("an object").clone())];
            if let Err(e) = shared.submit(Command::Patch { statuses }).await {
                eprintln!("kithd: backup {}: its status was not written: {e}", job.key);
                // (Refused whole, as a worker's that names a blob another node made is: said
                // on it and tried again later, not made anew each round.)
                let failed = json!({ "message": e.to_string(), "tried": now });
                let statuses = vec![(job.key.clone(), failed.as_object().expect("an object").clone())];
                drop(shared.submit(Command::Patch { statuses }).await);
            }
        }
    }
}

// ---- Restoring ----

#[derive(serde::Deserialize)]
pub struct Restore {
    /// Which: the `at` of one in `status.backups`. None: the last.
    at: Option<u64>,
}

/// `POST /v1/backups/NS/NAME/restore`: a backup back into its volume, on the volume's node.
pub async fn restore(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    UrlPath((namespace, name)): UrlPath<(String, String)>,
    Query(which): Query<Restore>,
) -> Result<Json<Value>, ApiError> {
    let both = [
        ("Backup".to_string(), Some(namespace.clone())),
        ("Volume".into(), Some(namespace.clone())),
    ];
    permit(&shared, &caller, Verb::Apply, |_| both.to_vec())?;
    let key = format!("Backup/{namespace}/{name}");
    let invalid = |why: String| ApiError::Store(Error::Invalid(why));
    let io = |why: String| ApiError::Store(Error::Io(why));
    let me = shared.members.me();
    let (spec, dir, entry, address, cap) = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let backup = state
            .store
            .get(&key)
            .ok_or_else(|| ApiError::Store(Error::NotFound(key.clone())))?;
        let spec: BackupSpec = serde_json::from_value(backup.spec.clone()).map_err(|e| invalid(e.to_string()))?;
        let dir = crate::volumes::dir(&state.store, &namespace, &spec.volume);
        let dir = dir.ok_or_else(|| invalid(format!("{key}: there is no Volume {} to restore into", spec.volume)))?;
        let backups = backup.status.as_ref().and_then(|status| status["backups"].as_array());
        let mut backups = backups.into_iter().flatten();
        let entry = match which.at {
            Some(at) => backups.find(|entry| entry["at"].as_u64() == Some(at)),
            None => backups.next_back(),
        };
        let entry = entry
            .cloned()
            .ok_or_else(|| invalid(format!("{key} has no such backup")))?;
        let there = state.store.get(&format!("Node/{}", dir.node));
        let address = there.and_then(crate::view::Upstream::of);
        // (What the Volume holds, where it says: no more than that is restored into it.)
        let cap = crate::volumes::size(&state.store, &namespace, &spec.volume).unwrap_or(u64::MAX);
        (spec, dir, entry, address, cap)
    };
    let what = vec![format!(
        "{key} at {} into Volume/{namespace}/{}",
        entry["at"], spec.volume
    )];
    // (Asked by a node, it was sent here as the node that has the volume: never sent on again.)
    if caller.node().is_some() && dir.node != me {
        return Err(invalid(format!("node {} has that volume, not this node", dir.node)));
    }
    // The volume is another node's: it is asked, for the caller (whom it checks as this node did).
    if dir.node != me {
        let (Some(cluster), Some(there)) = (&shared.cluster, address) else {
            return Err(io(format!("node {} that has the volume has no address yet", dir.node)));
        };
        // (A signed restore goes on as it came: its signature covers the path and body it was made
        // for, so nothing is added to them. Unsigned, the node that has the volume is told the backup
        // this node chose.)
        let carried = match crate::access_sign::current() {
            None => None,
            Some(signed) => match signed.relay {
                Some(relay) => Some(relay),
                None => return Err(invalid("a signed restore cannot be passed on as it came".into())),
            },
        };
        let url = match &carried {
            Some(relay) => format!("https://{}{}", there.address, relay.path),
            None => format!(
                "https://{}/v1/backups/{namespace}/{name}/restore?at={}",
                there.address, entry["at"]
            ),
        };
        // (The node that has the volume, and no other at its address.)
        let client = cluster.to(&there).map_err(io)?;
        // (As long as a volume takes to unpack, and no longer than an hour.)
        let asked = client.post(url).timeout(Duration::from_secs(3600));
        let asked = match carried {
            Some(relay) => asked.body(relay.body),
            None => asked,
        };
        let asked = crate::access_sign::pass_on(asked.header(crate::access::FOR, caller.to_string()));
        let asked = asked.send().await;
        let failed = |e: reqwest::Error| {
            io(format!(
                "asking node {} to restore: {}",
                dir.node,
                crate::cluster::why(&e)
            ))
        };
        let answer = asked.map_err(failed)?;
        let (fine, status) = (answer.status().is_success(), answer.status());
        let said: Value = answer.json().await.map_err(failed)?;
        let outcome = if fine {
            Ok(())
        } else {
            Err(said["error"]
                .as_str()
                .map_or(format!("node {} answered {status}", dir.node), String::from))
        };
        shared.audit.record(&caller, "restore", what, outcome.clone());
        return outcome.map(|()| Json(said)).map_err(invalid);
    }
    let restored = async {
        let _alone = BUSY.lock().await;
        let state = shared.logs.parent().ok_or("kithd has no state directory")?;
        let into = crate::root_part::restore(state, &dir)?;
        match (entry["blob"].as_str(), entry["object"].as_str(), &spec.s3) {
            (Some(blob), _, _) => {
                let archive = crate::blobs::here(&shared, &format!("Blob/{namespace}/{blob}")).await?;
                let unpacked = tokio::task::spawn_blocking(move || unpack(&archive, &into, cap)).await;
                unpacked.map_err(|e| e.to_string())?
            }
            (None, Some(object), Some(s3_spec)) => {
                let bucket = bucket(&shared, &namespace, s3_spec)?;
                from_bucket(&bucket, object, &crate::blobs::dir(&shared), into, cap).await
            }
            _ => Err("the backup says neither which blob nor which object it is".to_string()),
        }
    };
    let restored: Result<(), String> = restored.await;
    shared.audit.record(&caller, "restore", what, restored.clone());
    restored.map_err(invalid)?;
    Ok(Json(
        json!({ "restored": entry, "volume": spec.volume, "node": dir.node }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kith-backup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_backup_archive_restores_byte_for_byte_and_only_into_an_empty_volume() {
        let root = temp("archive");
        let (from, blobs, into) = (root.join("from"), root.join("blobs"), root.join("into"));
        std::fs::create_dir_all(from.join("deep/er")).unwrap();
        std::fs::create_dir_all(&into).unwrap();
        std::fs::write(from.join("a"), b"one").unwrap();
        std::fs::write(from.join("deep/er/b"), vec![7u8; 100_000]).unwrap();
        std::fs::set_permissions(from.join("a"), std::fs::Permissions::from_mode(0o640)).unwrap();
        // A link out of the volume is kept as the link it is; what it points at is not read.
        std::os::unix::fs::symlink("/etc/hostname", from.join("link")).unwrap();

        let (name, size) = archive(&from, &blobs).unwrap();
        assert!(crate::blobs::named(&name) && size > 100_000);
        unpack(&blobs.join(&name), &into, u64::MAX).unwrap();
        assert_eq!(std::fs::read(into.join("a")).unwrap(), b"one");
        assert_eq!(std::fs::read(into.join("deep/er/b")).unwrap(), vec![7u8; 100_000]);
        assert_eq!(
            std::fs::metadata(into.join("a")).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            std::fs::read_link(into.join("link")).unwrap(),
            Path::new("/etc/hostname")
        );

        // Not over what is there.
        let refused = unpack(&blobs.join(&name), &into, u64::MAX).unwrap_err();
        assert!(refused.contains("restored into an empty volume"), "{refused}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// What a workload does to its volume while the node archives it: a directory or a
    /// file swapped for a link out of the volume. The walk holds each directory open and
    /// opens nothing through a link, so the link is left out and never followed.
    #[test]
    fn archive_follows_no_link_put_in_its_way() {
        let root = temp("swap");
        let (from, blobs, outside) = (root.join("from"), root.join("blobs"), root.join("outside"));
        std::fs::create_dir_all(from.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(from.join("sub/inner"), b"the volume's own").unwrap();
        std::fs::write(from.join("file"), b"the volume's own").unwrap();
        std::fs::write(outside.join("secret"), b"the node's").unwrap();
        let held = std::fs::File::open(&from).unwrap();
        let seen = |name: &str| std::fs::symlink_metadata(from.join(name)).unwrap();
        let (was_dir, was_file) = (seen("sub"), seen("file"));
        let sub = open_in(&held, "sub".as_ref()).unwrap();

        // Swapped after they were looked at, and after `sub` was walked into.
        std::fs::rename(from.join("sub"), root.join("moved")).unwrap();
        std::os::unix::fs::symlink(&outside, from.join("sub")).unwrap();
        std::fs::remove_file(from.join("file")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), from.join("file")).unwrap();
        assert!(open_in(&held, "sub".as_ref()).is_err() && open_in(&held, "file".as_ref()).is_err());

        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        put(&mut tar, &held, "sub".as_ref(), Path::new("./sub"), &was_dir).unwrap();
        put(&mut tar, &held, "file".as_ref(), Path::new("./file"), &was_file).unwrap();
        // The directory that was walked into is still the volume's, wherever its name points now.
        pack(&mut tar, &sub, Path::new("./walked")).unwrap();
        let (name, _) = tar.into_inner().unwrap().keep(None).unwrap();
        let mut packed = tar::Archive::new(std::fs::File::open(blobs.join(name)).unwrap());
        let mut found = Vec::new();
        for entry in packed.entries().unwrap() {
            let mut entry = entry.unwrap();
            let mut text = String::new();
            std::io::Read::read_to_string(&mut entry, &mut text).unwrap();
            found.push((entry.path().unwrap().display().to_string(), text));
        }
        assert_eq!(found, [("walked/inner".to_string(), "the volume's own".to_string())]);

        // As it is now, links and all: each link is kept as a link, and nothing it names is read.
        let (name, _) = archive(&from, &blobs).unwrap();
        let mut packed = tar::Archive::new(std::fs::File::open(blobs.join(name)).unwrap());
        let kinds: Vec<_> = packed
            .entries()
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.path().unwrap().display().to_string(),
                    entry.header().entry_type().is_symlink(),
                    entry.size(),
                )
            })
            .collect();
        assert_eq!(
            kinds,
            [
                (".".to_string(), false, 0),
                ("file".to_string(), true, 0),
                ("sub".to_string(), true, 0)
            ]
        );

        // Directories without end are not walked without end.
        let deep = root.join("deep");
        std::fs::create_dir_all(deep.join("d/".repeat(DEEPEST + 1))).unwrap();
        let said = archive(&deep, &blobs).unwrap_err();
        assert!(said.contains("more than 128 directories deep"), "{said}");
        std::fs::create_dir_all(root.join("fits").join("d/".repeat(DEEPEST - 1))).unwrap();
        archive(&root.join("fits"), &blobs).unwrap();

        // A file that cannot be read is an archive that is not made, not one without it.
        // (Root reads whatever the mode: nothing to see there.)
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(root.join("fits/shut"), b"x").unwrap();
        std::fs::set_permissions(root.join("fits/shut"), std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(root.join("fits/shut")).is_err() {
            let said = archive(&root.join("fits"), &blobs).unwrap_err();
            assert!(said.contains("shut: "), "{said}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_backup_archive_cannot_write_outside_the_volume() {
        let root = temp("escape");
        let (blobs, into) = (root.join("blobs"), root.join("into"));
        std::fs::create_dir_all(&into).unwrap();
        // An archive nobody made with kith: an entry that names a path above the volume.
        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        let path = b"../escaped";
        header.as_old_mut().name[..path.len()].copy_from_slice(path);
        header.set_cksum();
        tar.append(&header, &b"out!"[..]).unwrap();
        let (name, _) = tar.into_inner().unwrap().keep(None).unwrap();
        let _ = unpack(&blobs.join(name), &into, u64::MAX);
        assert!(!root.join("escaped").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn store(status: Value) -> Store {
        let mut store = Store::default();
        let resources = [
            json!({ "apiVersion": "kith.dev/v1", "kind": "Volume", "metadata": { "name": "data" },
                    "spec": { "node": "a", "path": "d" } }),
            json!({ "apiVersion": "kith.dev/v1", "kind": "Backup", "metadata": { "name": "nightly" },
                    "spec": { "volume": "data", "every": "1h", "keep": 2 } }),
            json!({ "apiVersion": "kith.dev/v1", "kind": "Backup", "metadata": { "name": "of-nothing" },
                    "spec": { "volume": "none", "every": "1h" } }),
        ];
        let resources = resources
            .into_iter()
            .map(|r| serde_json::from_value(r).unwrap())
            .collect();
        kith_store::run(&mut store, Command::Apply { resources, at: 0 }).unwrap();
        let statuses = vec![(
            "Backup/default/nightly".to_string(),
            status.as_object().unwrap().clone(),
        )];
        kith_store::run(&mut store, Command::Patch { statuses }).unwrap();
        store
    }

    #[test]
    fn a_backup_is_due_on_its_volumes_node_when_its_time_has_come() {
        let never = store(json!({}));
        let due_on = |store: &Store, node: &str, now: u64| due(store, node, now).len();
        // None yet: due at once, on the node that has the volume and no other.
        assert_eq!((due_on(&never, "a", 5), due_on(&never, "b", 5)), (1, 0));
        assert_eq!(due(&never, "a", 5)[0].key, "Backup/default/nightly");
        let made = store(json!({ "backups": [{ "at": 1000, "blob": "x", "size": 1 }] }));
        assert_eq!((due_on(&made, "a", 4599), due_on(&made, "a", 4600)), (0, 1));
        // One that failed is tried again in ten minutes, not in an hour and not at once.
        let failed = store(json!({ "backups": [{ "at": 1000, "blob": "x", "size": 1 }], "tried": 4600 }));
        assert_eq!((due_on(&failed, "a", 5199), due_on(&failed, "a", 5200)), (0, 1));
    }

    #[test]
    fn a_backup_blob_another_backup_lists_is_not_let_go() {
        let both = store(json!({ "backups": [{ "at": 1, "blob": "same", "size": 1 }] }));
        assert!(listed(&both, "default", "Backup/default/of-nothing", "same"));
        // Not its own listing, not another namespace's, not another blob.
        assert!(!listed(&both, "default", "Backup/default/nightly", "same"));
        assert!(!listed(&both, "other", "Backup/other/x", "same"));
        assert!(!listed(&both, "default", "Backup/default/of-nothing", "else"));
    }

    #[test]
    fn a_restored_backup_has_no_setuid_program_and_a_failed_one_leaves_the_volume_empty() {
        let root = temp("mask");
        let (from, blobs, into) = (root.join("from"), root.join("blobs"), root.join("into"));
        std::fs::create_dir_all(&from).unwrap();
        std::fs::create_dir_all(&into).unwrap();
        std::fs::write(from.join("tool"), b"#!/bin/sh").unwrap();
        std::fs::set_permissions(from.join("tool"), std::fs::Permissions::from_mode(0o6755)).unwrap();
        let (name, _) = archive(&from, &blobs).unwrap();
        unpack(&blobs.join(&name), &into, u64::MAX).unwrap();
        assert_eq!(
            std::fs::metadata(into.join("tool")).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        // Not an archive at all: nothing is left in the volume, which can be restored into again.
        let empty = root.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::write(root.join("junk"), vec![0xffu8; 4096]).unwrap();
        assert!(unpack(&root.join("junk"), &empty, u64::MAX).is_err());
        assert_eq!(std::fs::read_dir(&empty).unwrap().count(), 0);
        assert!(!root.join(".empty.restoring").exists());
        unpack(&blobs.join(&name), &empty, u64::MAX).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn backups_beyond_keep_are_let_go_but_never_a_blob_a_kept_one_has() {
        let entry = |at: u64, blob: &str| json!({ "at": at, "blob": blob, "size": 1 });
        let (kept2, gone) = kept(vec![entry(1, "a"), entry(2, "b")], entry(3, "c"), 2);
        assert_eq!((kept2, gone), (vec![entry(2, "b"), entry(3, "c")], vec![entry(1, "a")]));
        // Nothing changed in the volume: the same blob, which stays for the one that is kept.
        let (kept1, gone) = kept(vec![entry(1, "a")], entry(2, "a"), 1);
        assert_eq!((kept1, gone), (vec![entry(2, "a")], vec![]));
        assert_eq!(kept(vec![], entry(1, "a"), 0).0.len(), 1);
    }

    fn example() -> Bucket {
        Bucket {
            endpoint: String::new(),
            bucket: "examplebucket".into(),
            region: "us-east-1".into(),
            prefix: String::new(),
            access: "AKIAIOSFODNN7EXAMPLE".into(), // pragma: allowlist secret
            secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(), // pragma: allowlist secret
            mesh: None,
            anywhere: true,
        }
    }

    #[test]
    fn an_s3_signature_is_the_one_amazons_own_example_has() {
        // "Example: GET Object" of Amazon's "Signature Calculations for the Authorization Header".
        assert_eq!(stamp(1_369_353_600), "20130524T000000Z");
        // (The store's clock is in seconds, which is what a stamp is made of.)
        assert!(stamp(kith_api::store::now()).as_str() > "2025");
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let headers = [
            ("host", "examplebucket.s3.amazonaws.com"),
            ("range", "bytes=0-9"),
            ("x-amz-content-sha256", empty),
            ("x-amz-date", "20130524T000000Z"),
        ];
        let signed = authorization("GET", "/test.txt", &headers, empty, "20130524T000000Z", &example());
        assert_eq!(
            signed,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41" // pragma: allowlist secret
        );
        assert_eq!(stamp(951_782_400 + 86399), "20000229T235959Z");
    }

    #[test]
    fn an_s3_bucket_is_not_this_machine_a_link_local_address_or_the_mesh() {
        let mesh: std::net::Ipv6Addr = "fd12:3456:789a::".parse().unwrap();
        let may = |at: &str| outside(at.parse().unwrap(), Some(mesh));
        for at in ["192.168.1.20", "10.0.0.5", "93.184.216.34", "2001:db8::1", "fd00:1::1"] {
            assert!(may(at), "{at}");
        }
        let not = [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ];
        for at in not
            .into_iter()
            .chain(["::ffff:169.254.169.254", "fd12:3456:789a:1::1", "224.0.0.1"])
        {
            assert!(!may(at), "{at}");
        }
    }

    #[tokio::test]
    async fn an_s3_request_to_this_machine_is_refused_before_anything_is_sent() {
        let mut bucket = example();
        (bucket.endpoint, bucket.anywhere) = ("https://localhost:1".into(), false);
        let refused = s3(&bucket, reqwest::Method::DELETE, "x.tar", None).await.unwrap_err();
        assert!(refused.contains("a bucket is not on this machine"), "{refused}");
    }

    /// What a bucket would do, on 127.0.0.1: keeps what is put, gives it back, forgets it,
    /// and takes nothing whose signature is not the one its own sum comes to.
    async fn fake_s3() -> (
        Bucket,
        Arc<std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
    ) {
        use axum::http::{HeaderMap, Method, StatusCode, Uri};
        let kept = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut bucket = example();
        bucket.endpoint = format!("http://127.0.0.1:{port}");
        let objects = kept.clone();
        let serve = move |method: Method, uri: Uri, headers: HeaderMap, body: axum::body::Bytes| {
            let objects = objects.clone();
            async move {
                let header = |name: &str| {
                    headers
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string()
                };
                let (host, payload, date) = (header("host"), header("x-amz-content-sha256"), header("x-amz-date"));
                let signed = [
                    ("host", host.as_str()),
                    ("x-amz-content-sha256", payload.as_str()),
                    ("x-amz-date", date.as_str()),
                ];
                let mut bucket = example();
                bucket.endpoint = String::new();
                // (And nothing dated long ago: a real bucket takes a request of the last minutes only.)
                if date.as_str() < "2025"
                    || header("authorization")
                        != authorization(method.as_str(), uri.path(), &signed, &payload, &date, &bucket)
                {
                    return (StatusCode::FORBIDDEN, Vec::new());
                }
                let mut objects = objects.lock().unwrap();
                match method {
                    Method::PUT => drop(objects.insert(uri.path().to_string(), body.to_vec())),
                    Method::DELETE => drop(objects.remove(uri.path())),
                    _ => {
                        return objects
                            .get(uri.path())
                            .map_or((StatusCode::NOT_FOUND, Vec::new()), |found| {
                                (StatusCode::OK, found.clone())
                            });
                    }
                }
                (StatusCode::OK, Vec::new())
            }
        };
        let app = axum::Router::new()
            .fallback(serve)
            .layer(axum::extract::DefaultBodyLimit::disable());
        tokio::spawn(async move { axum::serve(listener, app).await });
        (bucket, kept)
    }

    /// A tar of files of these sizes (`/` in a name makes a directory of what is before it).
    fn tar_of(blobs: &Path, files: &[(&str, usize)]) -> PathBuf {
        let mut tar = tar::Builder::new(Incoming::new(blobs).unwrap());
        for (name, size) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(*size as u64);
            header.set_mode(0o644);
            tar.append_data(&mut header, name, &vec![9u8; *size][..]).unwrap();
        }
        blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0)
    }

    /// A tar with one GNU sparse entry `hole`: 512 bytes of data at the end of `real` bytes
    /// that say they are all there.
    fn sparse_tar(blobs: &Path, real: u64) -> PathBuf {
        let mut tar = tar::Builder::new(Incoming::new(blobs).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNUSparse);
        header.set_mode(0o644);
        header.set_size(512);
        let gnu = header.as_gnu_mut().unwrap();
        gnu.set_real_size(real);
        gnu.sparse[0].set_offset(real - 512);
        gnu.sparse[0].set_length(512);
        let path = b"hole";
        header.as_old_mut().name[..path.len()].copy_from_slice(path);
        header.set_cksum();
        tar.append(&header, &[7u8; 512][..]).unwrap();
        blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0)
    }

    #[test]
    fn restore_capped_stops_where_the_archive_unpacks_past_the_volumes_size() {
        let root = temp("capped");
        let (blobs, into) = (root.join("blobs"), root.join("into"));
        std::fs::create_dir_all(&into).unwrap();
        // (Each file counts in blocks of 4 KiB: 61,440 bytes.)
        let archive = tar_of(&blobs, &[("a", 60_000), ("b/c", 60_000)]);
        // Over by a byte: an error, the volume empty and nothing beside it.
        let refused = unpack(&archive, &into, 122_879).unwrap_err();
        assert!(refused.contains("more than 122879 bytes"), "{refused}");
        assert_eq!(std::fs::read_dir(&into).unwrap().count(), 0);
        assert!(!root.join(".into.restoring").exists());
        // As much as it may hold: restored. (A volume with no size is `u64::MAX`.)
        unpack(&archive, &into, 122_880).unwrap();
        assert_eq!(std::fs::metadata(into.join("b/c")).unwrap().len(), 60_000);
        // What a killed kithd left beside the volume does not count, and is gone.
        let empty = root.join("empty");
        std::fs::create_dir_all(root.join(".empty.restoring")).unwrap();
        std::fs::write(root.join(".empty.restoring/junk"), vec![0u8; 5000]).unwrap();
        std::fs::create_dir_all(&empty).unwrap();
        unpack(&archive, &empty, u64::MAX).unwrap();
        assert!(!root.join(".empty.restoring").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unpack_meters_an_entry_that_says_it_is_larger_than_its_bytes() {
        // Real: the tar crate gives a GNU sparse entry its whole length as `size()`, and
        // unpacks it as a hole (a file of that length that takes next to no disk), so
        // the meter counts what an archive of the volume afterwards reads, not the tar's bytes.
        let root = temp("sparse");
        let (blobs, into) = (root.join("blobs"), root.join("into"));
        std::fs::create_dir_all(&into).unwrap();
        let real = 64 << 20;
        let archive = sparse_tar(&blobs, real);
        assert!(std::fs::metadata(&archive).unwrap().len() < 4096);
        let refused = unpack(&archive, &into, 1 << 20).unwrap_err();
        assert!(refused.contains("more than 1048576 bytes"), "{refused}");
        assert_eq!(std::fs::read_dir(&into).unwrap().count(), 0);
        assert!(!root.join(".into.restoring").exists());
        unpack(&archive, &into, real).unwrap();
        assert_eq!(std::fs::metadata(into.join("hole")).unwrap().len(), real);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unpack_meters_in_blocks_what_a_directory_or_a_file_of_a_byte_takes() {
        // 300 directories and 300 files of one byte are a few KB of tar, and 600 blocks on a disk.
        let root = temp("blocks");
        let (blobs, into) = (root.join("blobs"), root.join("into"));
        std::fs::create_dir_all(&into).unwrap();
        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        for n in 0..300 {
            let mut dir = tar::Header::new_gnu();
            dir.set_entry_type(tar::EntryType::Directory);
            dir.set_size(0);
            dir.set_mode(0o755);
            tar.append_data(&mut dir, format!("d{n}/"), &[][..]).unwrap();
            let mut file = tar::Header::new_gnu();
            file.set_size(1);
            file.set_mode(0o644);
            tar.append_data(&mut file, format!("d{n}/f"), &[1u8][..]).unwrap();
        }
        let archive = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
        let refused = unpack(&archive, &into, 1 << 20).unwrap_err();
        assert!(refused.contains("more than 1048576 bytes"), "{refused}");
        assert_eq!(std::fs::read_dir(&into).unwrap().count(), 0);
        assert!(!root.join(".into.restoring").exists());
        unpack(&archive, &into, 4 << 20).unwrap();
        assert_eq!(std::fs::metadata(into.join("d299/f")).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A directory entry of a tar, of this mode.
    fn dir_entry<W: std::io::Write>(tar: &mut tar::Builder<W>, path: &str, mode: u32) {
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_size(0);
        dir.set_mode(mode);
        tar.append_data(&mut dir, path, &[][..]).unwrap();
    }

    #[test]
    fn unpack_holds_no_more_directories_than_the_archive_is_deep() {
        let root = temp("wide");
        let (blobs, to) = (root.join("blobs"), root.join("to"));
        std::fs::create_dir_all(&to).unwrap();
        let to = to.canonicalize().unwrap();
        // Ten thousand side by side: one held at a time.
        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        for n in 0..10_000 {
            dir_entry(&mut tar, &format!("d{n}/"), 0o755);
        }
        let wide = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
        let most = unpack_to(&wide, &to, 0, u64::MAX).unwrap();
        assert!(most <= 2, "{most}");
        assert!(to.join("d9999").is_dir());
        // Kith's own, five deep: five.
        let from = root.join("from");
        std::fs::create_dir_all(from.join("a/b/c/d/e")).unwrap();
        std::fs::create_dir_all(from.join("z")).unwrap();
        let (name, _) = archive(&from, &blobs).unwrap();
        let again = root.join("again");
        std::fs::create_dir_all(&again).unwrap();
        assert_eq!(
            unpack_to(&blobs.join(name), &again.canonicalize().unwrap(), 0, u64::MAX).unwrap(),
            5
        );
        // Deeper than an archive kith makes: refused.
        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        let mut path = String::new();
        for _ in 0..=DEEPEST {
            path.push_str("d/");
            dir_entry(&mut tar, &path, 0o755);
        }
        let deepest = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
        let deep = root.join("deep");
        std::fs::create_dir_all(&deep).unwrap();
        let said = unpack_to(&deepest, &deep.canonicalize().unwrap(), 0, u64::MAX).unwrap_err();
        assert!(said.to_string().contains("more than 128 directories deep"), "{said}");
        // One entry 200 deep, with none of the 199 above it said: refused as well.
        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        dir_entry(&mut tar, &"e/".repeat(200), 0o755);
        let one = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
        let deep = root.join("deeper");
        std::fs::create_dir_all(&deep).unwrap();
        let said = unpack_to(&one, &deep.canonicalize().unwrap(), 0, u64::MAX).unwrap_err();
        assert!(said.to_string().contains("more than 128 directories deep"), "{said}");
        // A file in 128: unpacked; in 129 (the tar crate would make them): refused.
        for (dirs, fits) in [(DEEPEST, true), (DEEPEST + 1, false)] {
            let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
            let mut file = tar::Header::new_gnu();
            file.set_size(1);
            file.set_mode(0o644);
            tar.append_data(&mut file, format!("{}f", "f/".repeat(dirs)), &[1u8][..])
                .unwrap();
            let filed = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
            let deep = root.join(format!("file{dirs}"));
            std::fs::create_dir_all(&deep).unwrap();
            let unpacked = unpack_to(&filed, &deep.canonicalize().unwrap(), 0, u64::MAX);
            assert_eq!(unpacked.is_ok(), fits, "{dirs}: {unpacked:?}");
            // What a restore takes, the Volume's next backup packs again.
            if fits {
                archive(&deep, &blobs).unwrap();
            }
        }
        // An old header's name that ends in `/` is a directory to the tar crate, whatever
        // its type: as deep as one, and held as one (shut, with a file in it after).
        for (dirs, fits) in [(DEEPEST, true), (DEEPEST + 1, false)] {
            let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
            let mut old = tar::Header::new_gnu();
            old.set_entry_type(tar::EntryType::Regular);
            old.set_size(0);
            old.set_mode(0o755);
            for depth in 1..dirs {
                tar.append_data(&mut old, "o/".repeat(depth), &[][..]).unwrap();
            }
            old.set_mode(0o500);
            tar.append_data(&mut old, "o/".repeat(dirs), &[][..]).unwrap();
            let mut file = tar::Header::new_gnu();
            file.set_size(1);
            file.set_mode(0o644);
            tar.append_data(&mut file, format!("{}f", "o/".repeat(dirs)), &[1u8][..])
                .unwrap();
            let olds = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
            let deep = root.join(format!("old{dirs}"));
            std::fs::create_dir_all(&deep).unwrap();
            let unpacked = unpack_to(&olds, &deep.canonicalize().unwrap(), 0, u64::MAX);
            let deeper = |e: &std::io::Error| e.to_string().contains("more than 128 directories deep");
            assert!(
                if fits {
                    unpacked.is_ok()
                } else {
                    unpacked.as_ref().is_err_and(deeper)
                },
                "{dirs}: {unpacked:?}"
            );
            if fits {
                let last = deep.join("o/".repeat(dirs));
                let mode = std::fs::metadata(&last).unwrap().permissions().mode();
                assert_eq!(mode & 0o7777, 0o500);
                assert_eq!(std::fs::read(last.join("f")).unwrap(), [1]);
                std::fs::set_permissions(&last, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        // A directory's time past what the clock holds: unpacked, with no time given.
        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        let mut late = tar::Header::new_gnu();
        late.set_entry_type(tar::EntryType::Directory);
        late.set_size(0);
        late.set_mode(0o755);
        late.set_mtime(u64::MAX);
        tar.append_data(&mut late, "late/", &[][..]).unwrap();
        let latest = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
        let later = root.join("later");
        std::fs::create_dir_all(&later).unwrap();
        unpack_to(&latest, &later.canonicalize().unwrap(), 0, u64::MAX).unwrap();
        assert!(later.join("late").is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unpack_gives_each_directory_its_mode_owner_and_time_in_a_depth_first_archive() {
        use std::os::unix::fs::MetadataExt;
        let root = temp("modes");
        let (from, blobs, into) = (root.join("from"), root.join("blobs"), root.join("into"));
        std::fs::create_dir_all(from.join("deep/er/est")).unwrap();
        std::fs::create_dir_all(from.join("shut")).unwrap();
        std::fs::create_dir_all(&into).unwrap();
        std::fs::write(from.join("deep/er/est/f"), b"x").unwrap();
        // Read-only for its owner, with a file in it.
        std::fs::write(from.join("shut/in"), b"kept").unwrap();
        let dirs = [
            ("deep/er/est", 0o700, 3_000_000),
            ("deep/er", 0o711, 2_000_000),
            ("deep", 0o750, 1_000_000),
            ("shut", 0o500, 4_000_000),
        ];
        let at = |secs: u64| std::time::UNIX_EPOCH + Duration::from_secs(secs);
        for (path, mode, time) in dirs {
            std::fs::File::open(from.join(path))
                .unwrap()
                .set_modified(at(time))
                .unwrap();
            std::fs::set_permissions(from.join(path), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let (name, _) = archive(&from, &blobs).unwrap();
        unpack(&blobs.join(name), &into, u64::MAX).unwrap();
        for (path, mode, time) in dirs {
            let (was, is) = (
                std::fs::metadata(from.join(path)).unwrap(),
                std::fs::metadata(into.join(path)).unwrap(),
            );
            assert_eq!(is.mode() & 0o7777, mode, "{path}");
            assert_eq!(is.modified().unwrap(), at(time), "{path}");
            assert_eq!((is.uid(), is.gid()), (was.uid(), was.gid()), "{path}");
        }
        assert_eq!(std::fs::read(into.join("shut/in")).unwrap(), b"kept");
        for shut in [from.join("shut"), into.join("shut")] {
            std::fs::set_permissions(shut, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The mode and time of what is outside the directory an unpack is in.
    fn mode_and_time(path: &Path) -> (u32, std::time::SystemTime) {
        let seen = std::fs::metadata(path).unwrap();
        (seen.permissions().mode() & 0o7777, seen.modified().unwrap())
    }

    #[test]
    fn unpack_link_put_where_a_directory_was_gets_no_mode_or_time_outside() {
        let root = temp("relink");
        let (blobs, outside) = (root.join("blobs"), root.join("outside"));
        std::fs::create_dir_all(outside.join("d")).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(outside.join("d"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let before = (mode_and_time(&outside), mode_and_time(&outside.join("d")));
        // An archive that makes a directory and later puts a link where it was, or where
        // one above it was: refused by the tar crate, or unpacked; either way nothing outside changes.
        let link = |tar: &mut tar::Builder<Incoming>, path: &str| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            tar.append_link(&mut header, path, &outside).unwrap();
        };
        for (dirs, at) in [(&["d/"][..], "d"), (&["e/", "e/d/"][..], "e")] {
            let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
            for dir in dirs {
                dir_entry(&mut tar, dir, 0o777);
            }
            link(&mut tar, at);
            let archive = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
            let into = root.join(format!("into-{at}"));
            std::fs::create_dir_all(&into).unwrap();
            let _ = unpack(&archive, &into, u64::MAX);
            assert_eq!((mode_and_time(&outside), mode_and_time(&outside.join("d"))), before);
        }
        // A link first, then a directory entry of its name that is shut to its owner (the
        // one the unpack opens again): refused, and what the link names keeps its mode.
        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        link(&mut tar, "d");
        dir_entry(&mut tar, "d/", 0o500);
        let archive = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
        let into = root.join("into-first");
        std::fs::create_dir_all(&into).unwrap();
        assert!(unpack(&archive, &into, u64::MAX).is_err());
        assert_eq!((mode_and_time(&outside), mode_and_time(&outside.join("d"))), before);
        // Where the tar crate's own refusal is not what stops it: a directory the unpack is in,
        // swapped for a link before it is given its mode and time, is left as it is.
        let to = root.join("to");
        std::fs::create_dir_all(to.join("x")).unwrap();
        std::os::unix::fs::symlink(&outside, to.join("d")).unwrap();
        std::os::unix::fs::symlink(&outside, to.join("x/up")).unwrap();
        let to = to.canonicalize().unwrap();
        for path in ["d", "x/up/d"] {
            let swapped = Inside {
                path: PathBuf::from(path),
                mode: Some(0o777),
                time: Some(std::time::UNIX_EPOCH),
            };
            close(&to, swapped).unwrap();
        }
        assert_eq!((mode_and_time(&outside), mode_and_time(&outside.join("d"))), before);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn restore_that_cannot_move_into_place_leaves_the_volumes_directory_as_it_was() {
        use std::os::unix::fs::MetadataExt;
        let root = temp("move");
        let (beside, dir) = (root.join(".v.restoring"), root.join("v"));
        std::fs::create_dir_all(beside.join("restored")).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o701)).unwrap();
        let inode = std::fs::metadata(&dir).unwrap().ino();
        // What the Volume's workload wrote meanwhile: the move fails, and nothing was removed first.
        std::fs::write(dir.join("late"), b"its own").unwrap();
        let refused = into_place(&beside, &dir).unwrap_err();
        assert!(refused.contains("restored into an empty volume"), "{refused}");
        let now = std::fs::metadata(&dir).unwrap();
        assert_eq!((now.ino(), now.mode() & 0o7777), (inode, 0o701));
        assert_eq!(std::fs::read(dir.join("late")).unwrap(), b"its own");
        assert!(!beside.exists());
        // Empty: the unpacked directory is renamed over it.
        std::fs::remove_file(dir.join("late")).unwrap();
        std::fs::create_dir_all(beside.join("restored")).unwrap();
        into_place(&beside, &dir).unwrap();
        assert!(dir.join("restored").is_dir() && !beside.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// What a move that fails on an empty Volume leaves: the Volume's own directory, mode
    /// 0701 and all (the old way removed it first and made it again with kithd's mode).
    #[test]
    fn restore_that_cannot_move_into_an_empty_volume_keeps_its_directory() {
        use std::os::unix::fs::MetadataExt;
        let root = temp("moveempty");
        let (beside, dir) = (root.join(".v.restoring"), root.join("v"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o701)).unwrap();
        let inode = std::fs::metadata(&dir).unwrap().ino();
        // Nothing beside it to move: the rename fails.
        assert!(into_place(&beside, &dir).is_err());
        let now = std::fs::metadata(&dir).unwrap();
        assert_eq!((now.ino(), now.mode() & 0o7777), (inode, 0o701));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unpack_that_fails_after_a_shut_directory_leaves_nothing_beside() {
        // (Root empties a shut directory anyway: nothing to see there.)
        if std::fs::metadata("/proc/self").is_ok_and(|me| std::os::unix::fs::MetadataExt::uid(&me) == 0) {
            eprintln!("skipped: as root, a shut directory shuts no one out");
            return;
        }
        let root = temp("shutleft");
        let (blobs, dir) = (root.join("blobs"), root.join("v"));
        std::fs::create_dir_all(&dir).unwrap();
        let beside = root.join(".v.restoring");
        // A directory shut to its owner, with a file in it, closed by the file after it
        // (the three take the cap's three blocks); then one more than the cap.
        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        dir_entry(&mut tar, "shut/", 0o500);
        let mut file = tar::Header::new_gnu();
        file.set_size(5);
        file.set_mode(0o644);
        tar.append_data(&mut file, "shut/in", &b"hello"[..]).unwrap();
        tar.append_data(&mut file, "after", &b"after"[..]).unwrap();
        file.set_size(BLOCK * 4);
        tar.append_data(&mut file, "big", &vec![0u8; BLOCK as usize * 4][..])
            .unwrap();
        let archive = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
        assert!(unpack(&archive, &dir, BLOCK * 3).is_err());
        assert!(!beside.exists(), "a shut directory kept what was unpacked");
        // One left from before, shut: the next restore takes its place.
        std::fs::create_dir_all(beside.join("shut")).unwrap();
        std::fs::write(beside.join("shut/in"), b"old").unwrap();
        std::fs::set_permissions(beside.join("shut"), std::fs::Permissions::from_mode(0o500)).unwrap();
        unpack(&archive, &dir, u64::MAX).unwrap();
        assert_eq!(std::fs::read(dir.join("shut/in")).unwrap(), b"hello");
        assert!(!beside.exists());
        std::fs::set_permissions(dir.join("shut"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unpack_refuses_headers_longer_than_a_path_and_sizes_that_wrap() {
        let root = temp("headers");
        let blobs = root.join("blobs");
        let to = root.join("to");
        std::fs::create_dir_all(&to).unwrap();
        let to = to.canonicalize().unwrap();
        // A long name a path can have: unpacked.
        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        let long = format!("{}/{}", "a".repeat(200), "b".repeat(200));
        dir_entry(&mut tar, &format!("{long}/"), 0o755);
        let fine = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
        unpack_to(&fine, &to, 0, u64::MAX).unwrap();
        assert!(to.join(&long).is_dir());
        // A long name of a MiB: refused before it is read whole.
        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        dir_entry(&mut tar, &format!("{}/", "c".repeat(1 << 20)), 0o755);
        let huge = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
        let said = unpack_to(&huge, &to, 0, u64::MAX).unwrap_err();
        assert!(said.to_string().contains("headers of more than"), "{said}");
        // A size near 2^64 (base-256): over the cap, not wrapped to nothing.
        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        let mut big = tar::Header::new_gnu();
        big.set_size(u64::MAX - 1024);
        big.set_mode(0o644);
        big.set_path("big").unwrap();
        big.set_cksum();
        std::io::Write::write_all(tar.get_mut(), big.as_bytes()).unwrap();
        let wraps = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
        let said = unpack_to(&wraps, &to, 0, 1 << 40).unwrap_err();
        assert!(said.to_string().contains("more than the Volume may hold"), "{said}");
        // Cut short where an entry's last block is padded out: refused, not taken for the end.
        // (Written as it is: a tar::Builder would end it with two blocks of zeros.)
        let mut short = Incoming::new(&blobs).unwrap();
        let mut cut = tar::Header::new_gnu();
        cut.set_size(1);
        cut.set_mode(0o644);
        cut.set_path("cut").unwrap();
        cut.set_cksum();
        std::io::Write::write_all(&mut short, cut.as_bytes()).unwrap();
        std::io::Write::write_all(&mut short, b"x").unwrap();
        let short = blobs.join(short.keep(None).unwrap().0);
        let said = unpack_to(&short, &to, 0, u64::MAX).unwrap_err();
        assert!(said.to_string().contains("ends inside an entry"), "{said}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A GNU sparse entry that says it is near 2^64 bytes long, with sparse maps after it
    /// (the tar crate adds 512 to where the next entry starts for each map, unchecked, past
    /// where its length put it): refused by name, as every sparse entry with maps after it is.
    #[test]
    fn unpack_sparse_entry_near_two_to_the_64_fails() {
        let root = temp("sparsewrap");
        let blobs = root.join("blobs");
        let to = root.join("to");
        std::fs::create_dir_all(&to).unwrap();
        let to = to.canonicalize().unwrap();
        let huge = u64::MAX - 2048;
        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNUSparse);
        header.set_mode(0o644);
        header.set_size(huge);
        header.set_path("hole").unwrap();
        let gnu = header.as_gnu_mut().unwrap();
        gnu.set_real_size(huge);
        gnu.sparse[0].set_offset(0);
        gnu.sparse[0].set_length(huge);
        gnu.set_is_extended(true);
        header.set_cksum();
        std::io::Write::write_all(tar.get_mut(), header.as_bytes()).unwrap();
        for more in [true, true, true, false] {
            let mut map = tar::GnuExtSparseHeader::new();
            map.set_is_extended(more);
            std::io::Write::write_all(tar.get_mut(), map.as_bytes()).unwrap();
        }
        std::io::Write::write_all(tar.get_mut(), &[7u8; 4096]).unwrap();
        let archive = blobs.join(tar.into_inner().unwrap().keep(None).unwrap().0);
        // (Refused by kithd before the tar crate adds the maps up: no panic to catch, in a
        // debug or a release build.)
        for cap in [1 << 40, u64::MAX] {
            let said = unpack_to(&archive, &to, 0, cap).unwrap_err();
            assert!(said.to_string().contains("extended sparse map"), "{cap}: {said}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Restoring `x` leaves alone the directory `x.restoring` beside it (a Volume of that
    /// name, or a system Volume's path), when the restore fails and when it is done.
    #[test]
    fn restore_leaves_a_directory_named_like_its_own_with_restoring_after_it() {
        let root = temp("othername");
        let (blobs, dir, other) = (root.join("blobs"), root.join("x"), root.join("x.restoring"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("data"), b"its own").unwrap();
        let archive = tar_of(&blobs, &[("a", 60_000)]);
        assert!(unpack(&archive, &dir, 4096).is_err());
        assert_eq!(std::fs::read(other.join("data")).unwrap(), b"its own");
        unpack(&archive, &dir, u64::MAX).unwrap();
        assert_eq!(std::fs::read(other.join("data")).unwrap(), b"its own");
        assert!(dir.join("a").is_file() && !root.join(".x.restoring").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Removing what an unpack left holds the directories it is inside of, not each one it
    /// has seen: a thousand side by side are two at once. A shut one is opened and emptied,
    /// and a link is not followed.
    #[test]
    fn remove_unpacked_holds_the_directories_it_is_inside_of() {
        let root = temp("remove");
        let (beside, outside) = (root.join(".v.restoring"), root.join("outside"));
        std::fs::create_dir_all(outside.join("shut")).unwrap();
        std::fs::set_permissions(outside.join("shut"), std::fs::Permissions::from_mode(0o500)).unwrap();
        for n in 0..1000 {
            let side = beside.join(format!("s{n}"));
            std::fs::create_dir_all(&side).unwrap();
            std::fs::write(side.join("f"), b"x").unwrap();
            std::fs::set_permissions(&side, std::fs::Permissions::from_mode(0o500)).unwrap();
        }
        std::fs::create_dir_all(beside.join("a/b/c/d/e")).unwrap();
        std::os::unix::fs::symlink(&outside, beside.join("out")).unwrap();
        assert_eq!(remove_unpacked(&beside), 6);
        assert!(!beside.exists());
        assert_eq!(mode_and_time(&outside.join("shut")).0, 0o500);
        // Deeper than an unpack makes: the walk holds no more than that, and the removal
        // takes the rest.
        std::fs::create_dir_all(beside.join("d/".repeat(DEEPEST + 5))).unwrap();
        assert_eq!(remove_unpacked(&beside), DEEPEST + 1);
        assert!(!beside.exists());
        // Nothing there: nothing held.
        assert_eq!(remove_unpacked(&beside), 0);
        std::fs::set_permissions(outside.join("shut"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A chain 2,000 directories deep under what an unpack left (more than `remove_dir_all`
    /// holds descriptors for) is freed, and no level is left beside it.
    #[test]
    fn remove_unpacked_deep_chain_is_freed() {
        crate::controller::storage::tests::few_files(
            concat!(module_path!(), "::remove_unpacked_deep_chain_is_freed"),
            || {
                let root = temp("deep-chain");
                let beside = root.join(".v.restoring");
                std::fs::create_dir_all(&beside).unwrap();
                crate::controller::storage::tests::chain(&beside, 2000);
                remove_unpacked(&beside);
                let left: Vec<_> = std::fs::read_dir(&root)
                    .unwrap()
                    .flatten()
                    .map(|e| e.file_name())
                    .collect();
                let _ = std::fs::remove_dir_all(&root);
                assert!(left.is_empty(), "{left:?}");
            },
        );
    }

    #[tokio::test]
    async fn restore_from_a_bucket_leaves_no_download_when_it_is_refused_or_done() {
        let root = temp("leftover");
        let (made, blobs) = (root.join("made"), root.join("blobs"));
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (bucket, kept) = fake_s3().await;
        let tar = std::fs::read(tar_of(&made, &[("a", 60_000), ("b/c", 60_000)])).unwrap();
        kept.lock()
            .unwrap()
            .insert("/examplebucket/junk.tar".into(), vec![0xffu8; 4096]);
        kept.lock().unwrap().insert("/examplebucket/good.tar".into(), tar);
        let left = || std::fs::read_dir(&blobs).map_or(0, |files| files.count());
        // Not an archive; over the Volume's size; restored.
        for (object, cap, fine) in [
            ("junk.tar", u64::MAX, false),
            ("good.tar", 4096, false),
            ("good.tar", u64::MAX, true),
        ] {
            let into = root.join(format!("into-{object}-{cap}"));
            std::fs::create_dir_all(&into).unwrap();
            let restored = from_bucket(&bucket, object, &blobs, into.clone(), cap).await;
            assert_eq!(restored.is_ok(), fine, "{object} {cap}: {restored:?}");
            assert_eq!(left(), 0, "{object} {cap}");
            assert_eq!(into.join("b/c").exists(), fine);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// What a peer or a bucket does that sends without end: `bytes` of them, in chunks and
    /// with no length said first. On 127.0.0.1.
    async fn endless(bytes: usize) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let serve = move || async move {
            let chunks = (0..bytes / 10_000).map(|_| Ok::<_, std::io::Error>(vec![1u8; 10_000]));
            axum::body::Body::from_stream(futures_util::stream::iter(chunks))
        };
        tokio::spawn(async move { axum::serve(listener, axum::Router::new().fallback(serve)).await });
        url
    }

    #[tokio::test]
    async fn restore_capped_stops_a_download_past_the_size_and_leaves_nothing() {
        let root = temp("download");
        let blobs = root.join("blobs");
        // Chunked, no length said: counted as it comes.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut answer = reqwest::get(endless(300_000).await).await.unwrap();
        let mut incoming = Incoming::new(&blobs).unwrap();
        let said = receive(&mut answer, &mut incoming, QUIET, 100_000).await.unwrap_err();
        assert!(said.contains("more than 100000 bytes"), "{said}");
        drop(incoming);
        assert_eq!(std::fs::read_dir(&blobs).unwrap().count(), 0);
        // The same, from a bucket that says its length: refused before a byte is taken.
        let (bucket, kept) = fake_s3().await;
        kept.lock()
            .unwrap()
            .insert("/examplebucket/big.tar".into(), vec![3u8; 300_000]);
        let mut answer = s3(&bucket, reqwest::Method::GET, "big.tar", None).await.unwrap();
        let mut incoming = Incoming::new(&blobs).unwrap();
        let said = receive(&mut answer, &mut incoming, QUIET, 100_000).await.unwrap_err();
        assert!(said.contains("more than 100000 bytes"), "{said}");
        // As much as it may: taken whole.
        let mut answer = s3(&bucket, reqwest::Method::GET, "big.tar", None).await.unwrap();
        receive(&mut answer, &mut incoming, QUIET, 300_000).await.unwrap();
        assert_eq!(incoming.keep(None).unwrap().1, 300_000);
        // A tar's own overhead is let through: the size, doubled and a megabyte.
        assert_eq!(download_cap(100), 1_048_776);
        assert_eq!(download_cap(u64::MAX), u64::MAX);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn an_s3_bucket_is_sent_the_archive_gives_it_back_and_forgets_it() {
        let (mut bucket, kept) = fake_s3().await;
        let root = temp("s3");
        let bytes = vec![42u8; 300_000];
        std::fs::write(root.join("archive"), &bytes).unwrap();
        let body = || {
            let file = std::fs::File::open(root.join("archive")).unwrap();
            reqwest::Body::wrap_stream(crate::blobs::chunks(file))
        };
        s3(
            &bucket,
            reqwest::Method::PUT,
            "pre/nightly-1.tar",
            Some((body(), 300_000)),
        )
        .await
        .unwrap();
        assert!(kept.lock().unwrap()["/examplebucket/pre/nightly-1.tar"] == bytes);
        let got = s3(&bucket, reqwest::Method::GET, "pre/nightly-1.tar", None)
            .await
            .unwrap();
        assert!(got.bytes().await.unwrap() == bytes[..]);
        s3(&bucket, reqwest::Method::DELETE, "pre/nightly-1.tar", None)
            .await
            .unwrap();
        assert!(kept.lock().unwrap().is_empty());
        // Somebody else's key: refused, and said with the object's name but never the key.
        bucket.secret = "not-the-key".into(); // pragma: allowlist secret
        let refused = s3(&bucket, reqwest::Method::PUT, "x.tar", Some((body(), 300_000)))
            .await
            .unwrap_err();
        assert!(
            refused.contains("x.tar") && refused.contains("403") && !refused.contains("not-the-key"),
            "{refused}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
