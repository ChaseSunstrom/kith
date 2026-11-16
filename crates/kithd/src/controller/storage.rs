//! What a pod writes outside its Volumes: its containers' writable roots, its disk scratch and
//! the files its processes keep open after deleting them, counted together, and which pod is
//! replaced for it.

use nix::dir::{Dir, OwningIter};
use nix::fcntl::{AtFlags, OFlag};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};
use std::collections::BTreeSet;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// One pod as it was counted.
pub struct Pod {
    /// Its id (`pod_of`).
    pub id: String,
    /// The sum of what its containers state in `resources.storage`; `None` when none does.
    pub limit: Option<u64>,
    /// Bytes on disk under its roots; past its limit, where the count stopped.
    pub bytes: u64,
    /// The count got to its end, or past the limit: not stopped by `SPELL` or `DEEP`.
    pub finished: bool,
    /// Its last count did not finish either (`missed`).
    pub again: bool,
    /// It is held to its limit as it writes (`Projects`): its bytes are its project's, read
    /// and not counted, and a write past its limit fails rather than it being replaced.
    pub held: bool,
}

/// How the message of a unit replaced for what its pod wrote begins.
pub const REPLACED: &str = "replaced: ";

/// How the message of a running unit whose pod holds all its limit lets it begins.
pub const REACHED: &str = "reached its storage limit: ";

/// How near its limit a held pod is said to have reached it (a write stops short of it by
/// less than a block), and how far past it it may be before it is replaced all the same:
/// a past it is what no write of the pod's makes, but kithd's own (a new container's root
/// directories, put in the project as they are made) may.
const NEAR: u64 = 64 << 10;

/// Whether this node holds each pod to its limit as it writes: its state disk keeps projects
/// and is mounted to hold them (`-O quota,project`, `prjquota`), and kithd is root, who puts
/// a pod's directories in its project. Elsewhere what a pod wrote is counted every 10 s.
pub fn held_at_write(state: &Path) -> bool {
    nix::unistd::getuid().is_root() && kith_dm_sys::projects_held(state)
}

/// How a node holds pods' storage limits, as kithd says it once at its start and its Node's
/// status says it.
pub fn how(held: bool) -> &'static str {
    match held {
        true => "at the write, by the state disk's project quota",
        false => "by a count every 10 s of what each pod wrote",
    }
}

/// What a held pod's running units say while it holds all its limit lets it, if it does.
pub fn reached(pod: &Pod) -> Option<String> {
    let limit = pod
        .limit
        .filter(|limit| pod.held && pod.bytes.saturating_add(NEAR) >= *limit)?;
    Some(format!(
        "{REACHED}its pod holds {} bytes outside its volumes, of its limit of {limit}: a write past it fails",
        pod.bytes
    ))
}

/// Each pod's project on the state disk, which holds it to its limit as it writes: its
/// replica directory names it (in it, and kept with it however kithd starts again), its
/// scratch and its containers' roots are in it and so is all made in them.
pub struct Projects {
    state: PathBuf,
    /// The id the next pod is given: past every one on the disk when kithd started.
    next: u32,
}

/// The id given after `ids`, never 0 (what is in no project).
fn next_of(ids: impl Iterator<Item = u32>) -> u32 {
    ids.max().unwrap_or(0).saturating_add(1)
}

impl Projects {
    /// The projects of the pods whose directories are on `state`.
    pub fn read(state: &Path) -> Projects {
        let dirs = std::fs::read_dir(state.join(crate::files::REPLICAS))
            .into_iter()
            .flatten();
        let ids = dirs.flatten().filter_map(|dir| kith_dm_sys::project(&dir.path()).ok());
        Projects {
            state: state.to_path_buf(),
            next: next_of(ids.map(|(id, _)| id)),
        }
    }

    /// The project of the pod `pod`, given it if it has none (ids are never given twice
    /// while a file of the last one to have it is left, anywhere on the disk), held to
    /// `limit` (none: no limit) before anything is put in it, with its scratch in it if that
    /// holds nothing yet. Done before each of its containers starts, so what it starts with
    /// is held.
    pub fn give(&mut self, pod: &str, limit: Option<u64>) -> std::io::Result<u32> {
        let dir = crate::files::of(&self.state, pod)?;
        let had = kith_dm_sys::project(&dir)?.0;
        let id = match had {
            0 => {
                // ponytail: ids past u32::MAX are not wrapped round; 4 billion pods first.
                while kith_dm_sys::project_usage(&self.state, self.next).is_ok_and(|(bytes, files)| bytes + files > 0) {
                    self.next = self.next.saturating_add(1);
                }
                self.next
            }
            id => id,
        };
        // Its limit first: an id given before may still hold the last pod's.
        kith_dm_sys::set_project_limit(&self.state, id, limit.unwrap_or(0))?;
        if had == 0 {
            // (The directory alone: its maps' files, which kithd writes, are in no project.)
            kith_dm_sys::set_project(&dir, id, false)?;
        }
        self.next = self.next.max(id.saturating_add(1));
        let scratch = dir.join("scratch");
        std::fs::create_dir_all(&scratch)?;
        if kith_dm_sys::project(&scratch)? == (id, true) {
            return Ok(id);
        }
        // A scratch that holds files from before (a kithd that gave no projects) would keep
        // them in none, where no quota counts them: it is left as it is, and its pod counted
        // every 10 s ([`Projects::usage`]) till it is replaced with an empty one ([`aside`]).
        let empty = |path: &Path| std::fs::read_dir(path).is_ok_and(|mut d| d.next().is_none());
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&scratch)? {
            let entry = entry?;
            match entry.file_type()?.is_dir() && empty(&entry.path()) {
                true => names.push(entry.path()),
                false => return Ok(id),
            }
        }
        // The scratch itself last: in its project, all in it is.
        for dir in names.iter().chain([&scratch]) {
            kith_dm_sys::set_project(dir, id, true)?;
        }
        Ok(id)
    }

    /// What the pod `pod` holds of the state disk, if it is held to its limit as it writes:
    /// it has a project, and its scratch is in it.
    pub fn usage(state: &Path, pod: &str) -> Option<u64> {
        let dir = state.join(crate::files::REPLICAS).join(pod);
        let id = kith_dm_sys::project(&dir)
            .ok()
            .map(|(id, _)| id)
            .filter(|id| *id != 0)?;
        if kith_dm_sys::project(&dir.join("scratch")).ok()? != (id, true) {
            return None;
        }
        kith_dm_sys::project_usage(state, id).ok().map(|(bytes, _)| bytes)
    }
}

/// The longest one pod is counted, each count.
pub const SPELL: Duration = Duration::from_secs(5);

/// How many directories deep a count goes (each holds a descriptor open while it is walked).
pub const DEEP: usize = 128;

/// Files with several links (or deleted, held open) remembered a count to be counted once; past
/// that many each is counted at every link: more, never less.
const LINKED: usize = 65536;

/// The most cgroups, and processes, of one pod read a count; past them it did not finish.
const CGROUPS: usize = 100_000;

/// When a count gives up: at `at`, or once `stop` is set, by a kithd stopping, so that nothing
/// it has open on the state disk keeps that from being unmounted.
#[derive(Clone, Copy)]
pub struct Until<'a> {
    pub at: Instant,
    pub stop: &'a AtomicBool,
}

impl Until<'_> {
    fn passed(self) -> bool {
        Instant::now() >= self.at || self.stop.load(Ordering::Relaxed)
    }
}

/// The reserve a node keeps when its flag does not say: 5% of its state disk, at most 1 GiB; none
/// for a kithd that is not root, which cannot read all a pod writes and shares its disk with a desk.
pub fn default_reserve(total: u64, root: bool) -> u64 {
    match root {
        true => (total / 20).min(1 << 30),
        false => 0,
    }
}

/// Whether a pod is counted at all: one with a limit always, one without only while the state
/// disk has less than twice its reserve free (it is counted for the reserve alone).
pub fn walked(limit: Option<u64>, free: u64, reserve: u64) -> bool {
    limit.is_some() || free < reserve.saturating_mul(2)
}

fn is_dir(meta: &FileStat) -> bool {
    SFlag::from_bits_truncate(meta.st_mode) & SFlag::S_IFMT == SFlag::S_IFDIR
}

/// The directory `name` under `parent` (or the path `name`), opened without following a
/// symlink, and what it is, if it is a directory on `device`. (Not `backups::open_dir`, which
/// opens a path and holds it to no filesystem.)
fn open_dir_on(parent: Option<&OwningIter>, name: &(impl nix::NixPath + ?Sized), device: u64) -> Option<OwningIter> {
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let dir = Dir::openat(parent.map(|p| p.as_raw_fd()), name, flags, Mode::empty()).ok()?;
    // (What was looked at before it was opened may have been swapped since.)
    let meta = fstat(dir.as_raw_fd()).ok()?;
    (is_dir(&meta) && meta.st_dev == device).then(|| dir.into_iter())
}

/// Bytes on disk under `roots`, and whether the count got to its end. Opens each directory from
/// the one above it and follows no symlink, counts a file with several links once and leaves out
/// what another filesystem holds. Stops as soon as it is past `stop` (finished: it is known to be
/// past), at `until`, and below `DEEP` directories (both unfinished). What cannot be read is
/// passed over.
//
// ponytail: the files a pod made are walked one by one, so millions of small ones make a slow
// count; an ext4 project quota on each root would hold the line at the write instead.
pub fn count(roots: &[PathBuf], stop: u64, until: Until) -> (u64, bool) {
    let mut linked = BTreeSet::new();
    let (mut bytes, mut finished) = (0u64, true);
    for root in roots {
        let Ok(top) = fstatat(None, root.as_path(), AtFlags::AT_SYMLINK_NOFOLLOW) else {
            continue;
        };
        let device = top.st_dev;
        bytes = bytes.saturating_add(top.st_blocks as u64 * 512);
        let mut open: Vec<OwningIter> = match is_dir(&top) {
            true => open_dir_on(None, root.as_path(), device).into_iter().collect(),
            false => Vec::new(),
        };
        while let Some(at) = open.last_mut() {
            if bytes > stop {
                return (bytes, true);
            }
            if until.passed() {
                return (bytes, false);
            }
            // (A directory that fails to read on is left where it failed.)
            let Some(Ok(entry)) = at.next() else {
                open.pop();
                continue;
            };
            let name = entry.file_name();
            if name == c"." || name == c".." {
                continue;
            }
            let Ok(meta) = fstatat(Some(at.as_raw_fd()), name, AtFlags::AT_SYMLINK_NOFOLLOW) else {
                continue;
            };
            let dir = is_dir(&meta);
            if meta.st_dev != device || (!dir && meta.st_nlink > 1 && !first(&mut linked, &meta)) {
                continue;
            }
            bytes = bytes.saturating_add(meta.st_blocks as u64 * 512);
            if !dir {
                continue;
            }
            if open.len() >= DEEP {
                finished = false;
                continue;
            }
            let below = open_dir_on(open.last(), name, device);
            open.extend(below);
        }
    }
    (bytes, finished)
}

/// Whether `meta`'s file is met for the first time (or too many were to remember).
fn first(seen: &mut BTreeSet<(u64, u64)>, meta: &FileStat) -> bool {
    seen.len() >= LINKED || seen.insert((meta.st_dev, meta.st_ino))
}

/// The processes in the cgroup `cgroup` and the cgroups under it, and whether all were read
/// before `until` and within `CGROUPS`.
pub fn pids(cgroup: &Path, until: Until) -> (Vec<u32>, bool) {
    let mut pids = Vec::new();
    let mut cgroups = vec![(cgroup.to_path_buf(), 0)];
    let mut read = 0;
    while let Some((cgroup, depth)) = cgroups.pop() {
        read += 1;
        if until.passed() || read > CGROUPS || pids.len() > CGROUPS {
            return (pids, false);
        }
        let procs = std::fs::read_to_string(cgroup.join("cgroup.procs")).unwrap_or_default();
        pids.extend(procs.lines().filter_map(|pid| pid.parse::<u32>().ok()));
        if depth < 16 {
            for entry in std::fs::read_dir(&cgroup).into_iter().flatten().flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    cgroups.push((entry.path(), depth + 1));
                }
                if cgroups.len() > CGROUPS {
                    return (pids, false);
                }
            }
        }
    }
    (pids, true)
}

/// Whether the open file `link` (under `/proc/PID/fd` or `map_files`) names a deleted one. Its
/// link is read, not followed: nothing is asked of the filesystem it is on, which may not answer.
fn deleted(link: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    std::fs::read_link(link).is_ok_and(|to| to.as_os_str().as_bytes().ends_with(b" (deleted)"))
}

/// Bytes on disk of the files the processes `pids` keep open, or mapped, after they were deleted
/// (they have no name left to walk to), on the filesystem of one of `roots` or the one each
/// process sees as `/`; each file once. Whether it got to its end before `until`.
pub fn unlinked(pids: &[u32], roots: &[PathBuf], until: Until) -> (u64, bool) {
    let devices: BTreeSet<u64> = roots
        .iter()
        .filter_map(|root| std::fs::symlink_metadata(root).ok())
        .map(|meta| meta.dev())
        .collect();
    let mut seen = BTreeSet::new();
    let mut bytes = 0u64;
    for pid in pids {
        let process = PathBuf::from(format!("/proc/{pid}"));
        let mut devices = devices.clone();
        devices.extend(std::fs::metadata(process.join("root")).map(|m| m.dev()));
        for held in ["fd", "map_files"] {
            for entry in std::fs::read_dir(process.join(held)).into_iter().flatten().flatten() {
                if until.passed() {
                    return (bytes, false);
                }
                // (Followed, once it names a deleted file: the link is the open file itself.)
                if !deleted(&entry.path()) {
                    continue;
                }
                let Ok(meta) = std::fs::metadata(entry.path()) else {
                    continue;
                };
                if meta.is_file()
                    && meta.nlink() == 0
                    && devices.contains(&meta.dev())
                    && (seen.len() >= LINKED || seen.insert((meta.dev(), meta.ino())))
                {
                    bytes = bytes.saturating_add(meta.blocks() * 512);
                }
            }
        }
    }
    (bytes, true)
}

/// Moves the directory `scratch` aside, to a new name beside it (`scratch.N`): what is made at
/// `scratch` next is empty. False when there is none.
pub fn aside(scratch: &Path) -> bool {
    std::fs::rename(scratch, scratch_name(scratch)).is_ok()
}

/// A new name `scratch.N` (nanoseconds since the epoch) beside `near`.
fn scratch_name(near: &Path) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    near.with_file_name(format!("scratch.{}", nanos.unwrap_or_default().as_nanos()))
}

/// Removes every scratch moved aside in the replica directory `replica`, till `stop` is set. A
/// scratch the stop cut short is left as it is, with the levels its removal made beside it
/// (each a `scratch.*` of its own): they go at the next count of its pod's roots (which only a
/// pod with running roots that is walked has), or when the pod is gone and its replica
/// directory is removed. One that is gone or made while the directory is listed is no error.
pub fn sweep(replica: &Path, stop: &AtomicBool) {
    sweep_until(replica, &|| stop.load(Ordering::Relaxed));
}

fn sweep_until(replica: &Path, halted: &dyn Fn() -> bool) {
    for entry in std::fs::read_dir(replica).into_iter().flatten().flatten() {
        if halted() {
            return;
        }
        if entry.file_name().to_string_lossy().starts_with("scratch.") {
            match remove_tree(&entry.path(), halted) {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!(
                        "kithd: stopped removing {}: what is left of it is in it and in the scratch.* levels made beside it, each removed as a tree of its own at the pod's next count, or with its replica directory",
                        entry.path().display()
                    );
                    return;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => eprintln!("kithd: removing {}: {e}", entry.path().display()),
            }
        }
    }
}

/// How many steps of a removal (an entry looked at) pass between two looks at the stop.
const BATCH: usize = 1024;

/// Removes the directory `root` and all in it, asking `halted` first and then every [`BATCH`]
/// steps (a step is an entry looked at): true once it is done, false when it was halted (what
/// is left stays). A pod wrote what is in it and kithd is root here, so no path is walked down
/// and up (a chain thousands of directories deep holds more descriptors than kithd has, and
/// listing a directory again after each child makes the work grow with the square of its
/// entries): the tree is removed a level at a time, and each directory is listed once, so the
/// work is linear in the entries.
///
/// A level is a directory whose entries are to be removed, the first being `root` (a
/// `scratch.N` in a replica directory only kithd writes). Each entry of it is looked at once: a
/// file or a link is unlinked (a link is never followed), a directory is tried with `rmdir`,
/// and one that is not empty is opened (through the level's descriptor, never through a link;
/// one that shuts its owner out is opened up first) and emptied flat: its files and links are
/// unlinked, its empty directories removed, and each directory in it that is not empty is
/// moved, with `renameat`, into the next level, a new directory `scratch.N` beside `root`
/// (made when the first one is moved). Then it is closed and removed through the level's
/// descriptor. When the level's listing is done it is removed by its path, and the next
/// level, if there is one, becomes the level; done when there is none. So at most four
/// directories are open (the level, the next level, the one being emptied, and a new one for
/// a moment), memory does not grow with the tree, `..` is taken nowhere (nothing moved under
/// the walk can lead it above `root`), and a directory on another file system than `root`'s
/// (a mount point is `EBUSY` to remove, and one opened is seen by its device) ends the removal.
/// Where the disk has no room or no file left to make a level of (a full disk is why a pod may
/// be replaced), the first directory to move is the next level itself, by a rename; one moved
/// into a level that holds its new name already (a level that was a pod's directory may) takes
/// the next name.
///
/// A halt leaves `root` and the levels where they are, each named `scratch.*` in the replica
/// directory, for a sweep to remove as a tree of its own. A second remover of the same
/// scratch at the same moment is harmless: what the first removed is `ENOENT` to the other,
/// which ignores it (a directory that leaves not empty ends the removal at its own `rmdir`).
/// Any other error that leaves an entry in place ends the removal with it, as `remove_dir_all`
/// does: no path goes round again. A `root` that is a link or a file is unlinked.
fn remove_tree(root: &Path, halted: &dyn Fn() -> bool) -> std::io::Result<bool> {
    remove_tree_with(root, halted, |path| {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)
    })
}

/// [`remove_tree`], with what makes a level's directory (a test's has no room).
fn remove_tree_with(
    root: &Path,
    halted: &dyn Fn() -> bool,
    make: fn(&Path) -> std::io::Result<()>,
) -> std::io::Result<bool> {
    use nix::errno::Errno;
    use std::os::fd::IntoRawFd;
    let mut here = match crate::backups::open_dir(root) {
        Err(e)
            if matches!(
                e.raw_os_error().map(Errno::from_raw),
                Some(Errno::ELOOP | Errno::ENOTDIR)
            ) =>
        {
            return std::fs::remove_file(root).map(|()| true);
        }
        opened => (Dir::from_fd(opened?.into_raw_fd())?, root.to_path_buf()),
    };
    let mut run = Removal {
        halted,
        steps: 0,
        device: None,
        moved: 0,
        next: None,
        beside: root.to_path_buf(),
        make,
    };
    loop {
        let (mut level, path) = here;
        let fd = level.as_raw_fd();
        let device = fstat(fd)?.st_dev;
        if *run.device.get_or_insert(device) != device {
            return Err(std::io::Error::other(format!(
                "a file system is mounted at {}",
                path.display()
            )));
        }
        for entry in level.iter() {
            if run.halt() {
                return Ok(false);
            }
            let entry = entry?;
            let name = entry.file_name();
            if is_dots(name) {
                continue;
            }
            if clear(fd, name, is_directory(fd, &entry))? && !run.empty(fd, name)? {
                return Ok(false);
            }
        }
        drop(level);
        match std::fs::remove_dir(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        match run.next.take() {
            Some(next) => here = next,
            None => return Ok(true),
        }
    }
}

/// What [`remove_tree`] carries from one level to the next.
struct Removal<'a> {
    halted: &'a dyn Fn() -> bool,
    steps: usize,
    /// The file system of the first level, which all of them are on.
    device: Option<u64>,
    /// Directories moved into a next level so far, which names them there.
    moved: u64,
    /// The level after the one being removed, once a directory was moved to it.
    next: Option<(Dir, PathBuf)>,
    /// The first level, beside which the next ones are made.
    beside: PathBuf,
    /// Makes a level's directory.
    make: fn(&Path) -> std::io::Result<()>,
}

impl Removal<'_> {
    /// Counts one entry looked at; true when this is one to ask the stop at, and it is set.
    fn halt(&mut self) -> bool {
        self.steps += 1;
        self.steps % BATCH == 1 && (self.halted)()
    }

    /// `name` in the directory `fd`, opened up if it shuts out, and on the first level's file system.
    fn open(&self, fd: i32, name: &std::ffi::CStr) -> std::io::Result<Dir> {
        use nix::errno::Errno;
        use nix::sys::stat::{FchmodatFlags, fchmod, fchmodat};
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let dir = match Dir::openat(Some(fd), name, flags, Mode::empty()) {
            Err(Errno::EACCES) => {
                let shut = Mode::from_bits_truncate(0o700);
                fchmodat(Some(fd), name, shut, FchmodatFlags::NoFollowSymlink)?;
                Dir::openat(Some(fd), name, flags, Mode::empty())?
            }
            opened => opened?,
        };
        let meta = fstat(dir.as_raw_fd())?;
        if Some(meta.st_dev) != self.device {
            let said = format!("a file system is mounted at {}", name.to_string_lossy());
            return Err(std::io::Error::other(said));
        }
        if meta.st_mode & 0o700 != 0o700 {
            fchmod(dir.as_raw_fd(), Mode::from_bits_truncate(meta.st_mode | 0o700))?;
        }
        Ok(dir)
    }

    /// Empties `name`, a directory of the level `level`, flat, and removes it: false when halted.
    fn empty(&mut self, level: i32, name: &std::ffi::CStr) -> std::io::Result<bool> {
        use nix::errno::Errno;
        use nix::unistd::{UnlinkatFlags, unlinkat};
        let mut dir = match self.open(level, name) {
            // (Gone since it was listed: another remover took it.)
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            opened => opened?,
        };
        let fd = dir.as_raw_fd();
        for entry in dir.iter() {
            if self.halt() {
                return Ok(false);
            }
            let entry = entry?;
            let child = entry.file_name();
            if !is_dots(child) && clear(fd, child, is_directory(fd, &entry))? {
                self.shift(fd, child)?;
            }
        }
        drop(dir);
        match unlinkat(Some(level), name, UnlinkatFlags::RemoveDir) {
            Ok(()) | Err(Errno::ENOENT) => Ok(true),
            Err(e) => Err(e.into()),
        }
    }

    /// Moves `name`, a directory that is not empty in the directory `from`, into the next level.
    fn shift(&mut self, from: i32, name: &std::ffi::CStr) -> std::io::Result<()> {
        use nix::errno::Errno;
        use nix::fcntl::renameat;
        use nix::sys::stat::{FchmodatFlags, fchmodat};
        use std::io::ErrorKind::{QuotaExceeded, StorageFull};
        use std::os::fd::IntoRawFd;
        if self.next.is_none() {
            // (A name that is taken is an error: it is not for this removal to take it over.)
            let path = scratch_name(&self.beside);
            match (self.make)(&path) {
                Ok(()) => {
                    let dir = Dir::from_fd(crate::backups::open_dir(&path)?.into_raw_fd())?;
                    self.next = Some((dir, path));
                }
                // A disk with no room or no file left to make (why a pod may be replaced at
                // all) makes no directory: the one to move is the next level itself, by a
                // rename, which takes neither. (Opened first: that opens it up, too.)
                Err(e) if matches!(e.kind(), StorageFull | QuotaExceeded) => {
                    let dir = self.open(from, name)?;
                    return match renameat(Some(from), name, None, &path) {
                        Ok(()) => {
                            self.next = Some((dir, path));
                            Ok(())
                        }
                        Err(Errno::ENOENT) => Ok(()),
                        Err(e) => Err(e.into()),
                    };
                }
                Err(e) => return Err(e),
            }
        }
        let to = self.next.as_ref().map_or(-1, |(dir, _)| dir.as_raw_fd());
        let mut opened_up = false;
        let moved = loop {
            self.moved += 1;
            let new = std::ffi::CString::new(format!("d{}", self.moved)).unwrap_or_default();
            match renameat(Some(from), name, Some(to), new.as_c_str()) {
                // Moving a directory to another parent takes write access to it, where kithd is not root.
                Err(Errno::EACCES) if !opened_up => {
                    let shut = Mode::from_bits_truncate(0o700);
                    fchmodat(Some(from), name, shut, FchmodatFlags::NoFollowSymlink)?;
                    opened_up = true;
                }
                // (A level that was a pod's own directory may hold the name: the next name, then.
                // Each try is a name that is there, so there are no more tries than names.)
                Err(Errno::ENOTEMPTY | Errno::EEXIST | Errno::ENOTDIR) => {}
                moved => break moved,
            }
        };
        match moved {
            Ok(()) | Err(Errno::ENOENT) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

fn is_dots(name: &std::ffi::CStr) -> bool {
    matches!(name.to_bytes(), b"." | b"..")
}

/// Whether the entry of the directory `fd` is a directory, by what the listing says or a look.
fn is_directory(fd: i32, entry: &nix::dir::Entry) -> bool {
    match entry.file_type() {
        Some(kind) => kind == nix::dir::Type::Directory,
        None => fstatat(Some(fd), entry.file_name(), AtFlags::AT_SYMLINK_NOFOLLOW).is_ok_and(|meta| is_dir(&meta)),
    }
}

/// Removes `name` in the directory `fd` if it is a file, a link or an empty directory; true
/// when it is a directory that is not empty. One that is gone already is removed.
fn clear(fd: i32, name: &std::ffi::CStr, dir: bool) -> std::io::Result<bool> {
    use nix::errno::Errno;
    use nix::unistd::{UnlinkatFlags, unlinkat};
    let gone = if dir {
        match unlinkat(Some(fd), name, UnlinkatFlags::RemoveDir) {
            Err(Errno::ENOTEMPTY | Errno::EEXIST) => return Ok(true),
            // (A link put there since the listing is unlinked, not followed.)
            Err(Errno::ENOTDIR) => unlinkat(Some(fd), name, UnlinkatFlags::NoRemoveDir),
            gone => gone,
        }
    } else {
        unlinkat(Some(fd), name, UnlinkatFlags::NoRemoveDir)
    };
    match gone {
        Ok(()) | Err(Errno::ENOENT) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Whether a pod whose running units (none stopping) started at `started` may be replaced for a
/// count that began at `began`: one that started since was not counted.
pub fn replaceable(started: &[Instant], began: Instant) -> bool {
    !started.is_empty() && started.iter().all(|at| *at <= began)
}

/// Whether a run of a pod replaced at `at` is still there: of its units' runs, whether each is
/// stopping and when it started.
pub fn replacing(runs: &[(bool, Instant)], at: Instant) -> bool {
    runs.iter().any(|(stopping, started)| *stopping || *started <= at)
}

/// Notes which limited pods' counts did not finish, in `last` (this count's, for the next):
/// each that did not the last time either is `again`. The ones that did not for the first time,
/// to be said.
pub fn missed(pods: &mut [Pod], last: &mut BTreeSet<String>) -> Vec<usize> {
    let mut first = Vec::new();
    let mut now = BTreeSet::new();
    for (i, pod) in pods.iter_mut().enumerate() {
        if pod.finished || pod.limit.is_none() {
            continue;
        }
        pod.again = last.contains(&pod.id);
        if !pod.again {
            first.push(i);
        }
        now.insert(pod.id.clone());
    }
    *last = now;
    first
}

/// The pods to replace, by index into `pods`, and why. Every pod past its limit, or with one whose
/// count did not finish twice in a row (once may be a slow disk, slow for all); while `free` is under `reserve` and none is, the one that wrote the most
/// (one a count), if what it wrote is a tenth of the reserve or more: replacing a pod that wrote
/// less frees nothing much.
pub fn choose(pods: &[Pod], free: u64, reserve: u64) -> Vec<(usize, String)> {
    let over: Vec<(usize, String)> = pods
        .iter()
        .enumerate()
        .filter_map(|(i, pod)| {
            let limit = pod.limit?;
            let past = if pod.held { NEAR } else { 0 };
            let why = match pod.finished {
                true if pod.bytes > limit.saturating_add(past) => format!(
                    "replaced: its pod wrote {} bytes outside its volumes, over its limit of {limit}",
                    pod.bytes
                ),
                true => return None,
                false if !pod.again => return None,
                false => format!(
                    "replaced: its pod's files outside its volumes could not all be counted twice in a row, in {} s or {DEEP} directories deep, to hold its limit of {limit}",
                    SPELL.as_secs()
                ),
            };
            Some((i, why))
        })
        .collect();
    if !over.is_empty() || free >= reserve {
        return over;
    }
    let most = pods.iter().enumerate().max_by_key(|(_, pod)| pod.bytes);
    let most = most.filter(|(_, pod)| pod.bytes.saturating_mul(10) >= reserve);
    most.map(|(i, pod)| {
        let why = format!(
            "replaced: the node's state disk has {free} bytes free, under its reserve of {reserve}, and its pod wrote the most outside its volumes, {} bytes",
            pod.bytes
        );
        (i, why)
    })
    .into_iter()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kithd-storage-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pod(id: &str, limit: Option<u64>, bytes: u64) -> Pod {
        Pod {
            id: id.into(),
            limit,
            bytes,
            finished: true,
            again: false,
            held: false,
        }
    }

    /// A pod held to its limit as it writes stops short of it: it is said to have reached
    /// it, never replaced for it; past it by more than kithd's own writes make (what none of
    /// the pod's can), it is replaced as a counted one is. One counted never says it reached
    /// it: past it, it is replaced.
    #[test]
    fn storage_projects_a_held_pod_says_it_reached_its_limit_and_is_not_replaced() {
        let held = |bytes| Pod {
            held: true,
            ..pod("p", Some(64 * MIB), bytes)
        };
        let said = reached(&held(64 * MIB - 4096)).unwrap();
        assert!(
            said.starts_with(REACHED) && said.contains("of its limit of 67108864"),
            "{said}"
        );
        assert!(reached(&held(32 * MIB)).is_none());
        assert!(reached(&pod("p", Some(64 * MIB), 64 * MIB)).is_none());
        assert!(
            reached(&Pod {
                held: true,
                ..pod("p", None, 64 * MIB)
            })
            .is_none()
        );
        assert!(choose(&[held(64 * MIB), held(64 * MIB + 8192)], u64::MAX, 0).is_empty());
        assert_eq!(choose(&[held(65 * MIB)], u64::MAX, 0).len(), 1);
        assert_eq!(
            choose(&[pod("p", Some(64 * MIB), 64 * MIB + 8192)], u64::MAX, 0).len(),
            1
        );
        // For the reserve a held pod is chosen as any other.
        assert_eq!(choose(&[held(32 * MIB)], 0, 8 * MIB).len(), 1);
    }

    /// The next project given is past every one there, and never 0 (no project); with no
    /// project anywhere (a state disk that never kept them), and at the end of the ids, it is
    /// what it can be.
    #[test]
    fn storage_projects_the_next_id_is_past_every_one_there() {
        assert_eq!(next_of([3, 9, 4].into_iter()), 10);
        assert_eq!(next_of(std::iter::empty()), 1);
        assert_eq!(next_of([0, 0].into_iter()), 1);
        assert_eq!(next_of([u32::MAX].into_iter()), u32::MAX);
        // A pod's directory in no project (from a node that kept none) is given none and
        // counts none: it is given one at its next start.
        let state = dir("projects");
        std::fs::create_dir_all(state.join(crate::files::REPLICAS).join("default.web-0")).unwrap();
        assert_eq!(Projects::read(&state).next, 1);
        assert!(Projects::usage(&state, "default.web-0").is_none());
        std::fs::remove_dir_all(state).unwrap();
    }

    /// Where the state disk holds projects (as root: ci/vm.sh --test quota), a pod's
    /// directory is given one, kept as kithd starts again, its scratch and one from before
    /// are put in it, and its limit holds; skipped by name elsewhere.
    #[test]
    fn storage_projects_a_pod_is_given_one_kept_across_starts() {
        let state = dir("given");
        if !held_at_write(&state) {
            eprintln!("storage_projects_a_pod_is_given_one_kept_across_starts: skipped: {state:?} holds no projects");
            return std::fs::remove_dir_all(state).unwrap();
        }
        let older = state
            .join(crate::files::REPLICAS)
            .join("default.b-0")
            .join("scratch")
            .join("old");
        std::fs::create_dir_all(&older).unwrap();
        let mut projects = Projects::read(&state);
        let a = projects.give("default.a-0", Some(MIB)).unwrap();
        let b = projects.give("default.b-0", None).unwrap();
        assert!(a != 0 && b != a, "{a} {b}");
        assert_eq!(kith_dm_sys::project(&older).unwrap(), (b, true));
        let files = state.join(crate::files::REPLICAS).join("default.a-0");
        assert_eq!(kith_dm_sys::project(&files).unwrap(), (a, false));
        // kithd started again: the same ids, and a new pod's is past both.
        let mut again = Projects::read(&state);
        assert_eq!(
            (
                again.give("default.a-0", Some(MIB)).unwrap(),
                again.give("default.b-0", None).unwrap()
            ),
            (a, b)
        );
        assert!(again.give("default.c-0", None).unwrap() > a.max(b));
        // What is written in its scratch is its (root, who writes it here, is held to no
        // limit: a pod's write past it is the VM test's to show).
        let scratch = files.join("scratch");
        std::fs::write(scratch.join("some"), vec![1u8; MIB as usize]).unwrap();
        std::fs::File::open(scratch.join("some")).unwrap().sync_all().unwrap();
        assert!(Projects::usage(&state, "default.a-0").unwrap() >= MIB);
        for id in [a, b, a.max(b) + 1] {
            kith_dm_sys::set_project_limit(&state, id, 0).unwrap();
        }
        std::fs::remove_dir_all(state).unwrap();
    }

    /// Where the state disk holds projects: an id a pod gone left held to its limit is given
    /// again with the new pod's limit, set before anything is put in it; one with a file left
    /// anywhere on the disk is not given again; a pod's limit goes with its directory once
    /// nothing is left in its project; a scratch holding files from before stays in none, its
    /// pod counted, till it is made anew. Skipped by name elsewhere.
    #[test]
    fn storage_projects_an_id_is_given_again_only_with_nothing_left_in_it() {
        let state = dir("again");
        if !held_at_write(&state) {
            eprintln!(
                "storage_projects_an_id_is_given_again_only_with_nothing_left_in_it: skipped: {state:?} holds no projects"
            );
            return std::fs::remove_dir_all(state).unwrap();
        }
        // (Ids of its own, far past what other tests on the disk give.)
        let first = 0x4000_0000 + (std::process::id() & 0xffff) * 16;
        kith_dm_sys::set_project_limit(&state, first, 4096).unwrap();
        let mut projects = Projects {
            state: state.clone(),
            next: first,
        };
        assert_eq!(projects.give("default.a-0", Some(64 * MIB)).unwrap(), first);
        assert_eq!(kith_dm_sys::project_limit(&state, first).unwrap(), 64 * MIB);

        // A container's root left in it outside the pod's directory: its id is not given again,
        // and its limit stays.
        let root = state.join("root");
        std::fs::create_dir(&root).unwrap();
        kith_dm_sys::set_project(&root, first, true).unwrap();
        crate::files::sweep(&[&state], &std::collections::BTreeSet::new());
        assert_eq!(kith_dm_sys::project_limit(&state, first).unwrap(), 64 * MIB);
        let mut again = Projects {
            state: state.clone(),
            next: first,
        };
        let b = again.give("default.b-0", Some(MIB)).unwrap();
        assert!(b > first, "{b}");
        std::fs::remove_dir(&root).unwrap();
        crate::files::sweep(&[&state], &std::collections::BTreeSet::new());
        assert_eq!(kith_dm_sys::project_limit(&state, b).unwrap(), 0);

        // A scratch with a file from before is left as it is, its pod counted; made anew, held.
        let scratch = state.join(crate::files::REPLICAS).join("default.c-0").join("scratch");
        std::fs::create_dir_all(scratch.join("work")).unwrap();
        std::fs::write(scratch.join("work/old"), b"x").unwrap();
        let c = again.give("default.c-0", Some(MIB)).unwrap();
        assert_eq!(kith_dm_sys::project(&scratch).unwrap(), (0, false));
        assert_eq!(kith_dm_sys::project(&scratch.join("work")).unwrap(), (0, false));
        assert!(Projects::usage(&state, "default.c-0").is_none());
        assert!(aside(&scratch));
        assert_eq!(again.give("default.c-0", Some(MIB)).unwrap(), c);
        assert_eq!(kith_dm_sys::project(&scratch).unwrap(), (c, true));
        assert!(Projects::usage(&state, "default.c-0").is_some());
        for id in [first, b, c] {
            kith_dm_sys::set_project_limit(&state, id, 0).unwrap();
        }
        std::fs::remove_dir_all(state).unwrap();
    }

    /// A flag never set: no test's count is stopped but the one that sets its own.
    static GOING: AtomicBool = AtomicBool::new(false);

    fn later() -> Until<'static> {
        Until {
            at: Instant::now() + Duration::from_secs(600),
            stop: &GOING,
        }
    }

    fn now() -> Until<'static> {
        Until {
            at: Instant::now(),
            stop: &GOING,
        }
    }

    const MIB: u64 = 1 << 20;

    #[test]
    fn storage_limit_count_stops_past_its_limit_and_counts_blocks() {
        let root = dir("stop");
        for n in 0..8 {
            std::fs::write(root.join(n.to_string()), vec![1u8; MIB as usize]).unwrap();
        }
        let (all, finished) = count(std::slice::from_ref(&root), u64::MAX, later());
        assert!((8 * MIB..9 * MIB).contains(&all) && finished, "{all}");
        // Past 2 MiB it stops: a file or two more at most, never the whole.
        let (stopped, finished) = count(std::slice::from_ref(&root), 2 * MIB, later());
        assert!(stopped > 2 * MIB && stopped < 4 * MIB && finished, "{stopped}");
        // A sparse file is what it holds on disk, not its length.
        let sparse = dir("sparse");
        std::fs::File::create(sparse.join("hole"))
            .unwrap()
            .set_len(1 << 30)
            .unwrap();
        assert!(count(std::slice::from_ref(&sparse), u64::MAX, later()).0 < MIB);
        // A root that is not there is nothing.
        assert_eq!(count(&[root.join("gone")], u64::MAX, later()), (0, true));
        for d in [root, sparse] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn storage_limit_a_hard_linked_file_is_counted_once_and_no_symlink_is_followed() {
        let root = dir("links");
        let (a, b) = (root.join("a"), root.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("file"), vec![1u8; 4 * MIB as usize]).unwrap();
        let alone = count(&[a.clone(), b.clone()], u64::MAX, later()).0;
        // Linked again in the same root and in another root of the pod: no more bytes.
        std::fs::hard_link(a.join("file"), a.join("again")).unwrap();
        std::fs::hard_link(a.join("file"), b.join("again")).unwrap();
        assert_eq!(count(&[a.clone(), b.clone()], u64::MAX, later()).0, alone);
        // A symlink to what is outside, a file or a directory, adds nothing of what it names.
        let outside = dir("outside");
        std::fs::write(outside.join("big"), vec![1u8; 4 * MIB as usize]).unwrap();
        std::os::unix::fs::symlink(&outside, b.join("dir")).unwrap();
        std::os::unix::fs::symlink(outside.join("big"), b.join("file")).unwrap();
        std::os::unix::fs::symlink(&b, b.join("loop")).unwrap();
        assert!(count(&[a.clone(), b.clone()], u64::MAX, later()).0 < alone + MIB);
        // A directory swapped for a symlink after it was looked at is not opened through it.
        let parent = open_dir_on(None, b.as_path(), std::fs::metadata(&b).unwrap().dev()).unwrap();
        assert!(open_dir_on(Some(&parent), c"dir", std::fs::metadata(&outside).unwrap().dev()).is_none());
        for d in [root, outside] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn storage_limit_a_count_too_deep_or_too_long_is_unfinished() {
        let root = dir("deep");
        let mut at = root.clone();
        for _ in 0..DEEP + 2 {
            at = at.join("d");
        }
        std::fs::create_dir_all(&at).unwrap();
        std::fs::write(at.join("file"), vec![1u8; MIB as usize]).unwrap();
        // What is below the deepest directory walked is not counted, and the count says so.
        let (bytes, finished) = count(std::slice::from_ref(&root), u64::MAX, later());
        assert!(!finished && bytes < MIB, "{bytes}");
        // Out of time before it began: unfinished.
        let shallow = dir("shallow");
        std::fs::create_dir(shallow.join("d")).unwrap();
        assert!(!count(std::slice::from_ref(&shallow), u64::MAX, now()).1);
        for d in [root, shallow] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn storage_limit_a_count_and_a_removal_end_once_kithd_stops() {
        // A wide, deep tree: a count of it is well under way when kithd stops.
        let root = dir("stopped");
        let mut at = root.clone();
        for _ in 0..DEEP - 1 {
            at = at.join("d");
            for i in 0..50 {
                std::fs::create_dir_all(at.join(i.to_string())).unwrap();
            }
        }
        let stop = AtomicBool::new(false);
        let until = Until {
            at: Instant::now() + Duration::from_secs(600),
            stop: &stop,
        };
        let began = Instant::now();
        let (bytes, finished) = std::thread::scope(|s| {
            let counting = s.spawn(|| count(std::slice::from_ref(&root), u64::MAX, until));
            stop.store(true, Ordering::Relaxed);
            counting.join().unwrap()
        });
        assert!(!finished && began.elapsed() < Duration::from_secs(1), "{bytes}");
        // Stopped, the processes, the open files and the removal give up too.
        assert!(!pids(Path::new("/proc/self"), until).1);
        assert!(!unlinked(&[std::process::id()], std::slice::from_ref(&root), until).1);
        let replica = dir("stopped-replica");
        std::fs::create_dir_all(replica.join("scratch.1")).unwrap();
        sweep(&replica, &stop);
        assert!(replica.join("scratch.1").exists());
        for d in [root, replica] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn storage_limit_another_filesystem_under_a_root_is_not_counted() {
        // /dev/shm is a filesystem of its own under /dev, where there is one to write.
        let shm = Path::new("/dev/shm").join(format!("kithd-storage-{}", std::process::id()));
        let devices = (std::fs::metadata("/dev"), std::fs::metadata("/dev/shm"));
        let (Ok(dev), Ok(shm_dev)) = devices else { return };
        if dev.dev() == shm_dev.dev() || std::fs::write(&shm, vec![1u8; 4 * MIB as usize]).is_err() {
            return;
        }
        let under_dev = count(&[PathBuf::from("/dev")], u64::MAX, later()).0;
        let alone = count(&[PathBuf::from("/dev/shm")], u64::MAX, later()).0;
        std::fs::remove_file(&shm).unwrap();
        assert!(alone >= 4 * MIB && under_dev < 4 * MIB, "{alone} {under_dev}");
    }

    #[test]
    fn storage_limit_a_deleted_file_held_open_is_counted() {
        use std::io::Write;
        let root = dir("unlinked");
        let (me, roots) = ([std::process::id()], std::slice::from_ref(&root));
        let before = unlinked(&me, roots, later()).0;
        let mut file = std::fs::File::create(root.join("held")).unwrap();
        file.write_all(&vec![1u8; 4 * MIB as usize]).unwrap();
        file.sync_all().unwrap();
        std::fs::remove_file(root.join("held")).unwrap();
        // Gone from its directory: the walk finds nothing, the processes' open files do.
        assert!(count(roots, u64::MAX, later()).0 < MIB);
        let (held, finished) = unlinked(&me, roots, later());
        assert!(held >= before + 4 * MIB && finished, "{held} {before}");
        drop(file);
        assert!(unlinked(&me, roots, later()).0 < held);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn storage_limit_only_a_deleted_files_descriptor_is_looked_through() {
        let root = dir("deleted");
        let fds = Path::new("/proc/self/fd");
        // A live file and a pipe are known by their link alone: nothing on their filesystem is asked.
        let live = std::fs::File::create(root.join("live")).unwrap();
        let (read, write) = nix::unistd::pipe().unwrap();
        assert!(!deleted(&fds.join(live.as_raw_fd().to_string())));
        assert!(!deleted(&fds.join(read.as_raw_fd().to_string())));
        let gone = std::fs::File::create(root.join("gone")).unwrap();
        std::fs::remove_file(root.join("gone")).unwrap();
        assert!(deleted(&fds.join(gone.as_raw_fd().to_string())));
        // What is not there is not deleted.
        assert!(!deleted(&fds.join("999999")));
        drop((live, read, write, gone));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn storage_limit_a_pods_processes_are_read_from_its_cgroups_in_time() {
        let top = dir("cgroups");
        std::fs::create_dir_all(top.join("a").join("b")).unwrap();
        std::fs::write(top.join("cgroup.procs"), "1\n2\n").unwrap();
        std::fs::write(top.join("a").join("b").join("cgroup.procs"), "3\n").unwrap();
        let (mut all, finished) = pids(&top, later());
        all.sort();
        assert!(all == [1, 2, 3] && finished, "{all:?}");
        // Out of time: not all were read, and it says so.
        assert!(!pids(&top, now()).1);
        std::fs::remove_dir_all(top).unwrap();
    }

    #[test]
    fn storage_limit_a_pod_over_its_limit_is_replaced_and_says_by_how_much() {
        let pods = [
            pod("a", Some(10 * MIB), 12 * MIB),
            pod("b", Some(10 * MIB), 9 * MIB),
            pod("c", None, 0),
        ];
        let chosen = choose(&pods, u64::MAX, MIB);
        assert_eq!(chosen.len(), 1);
        let (which, why) = &chosen[0];
        assert_eq!(*which, 0);
        assert!(why.starts_with(REPLACED), "{why}");
        assert!(
            why.contains(&(12 * MIB).to_string()) && why.contains(&(10 * MIB).to_string()),
            "{why}"
        );
        // Under its limit, or at it, it is left alone.
        let under = [pod("a", Some(10 * MIB), 10 * MIB)];
        assert!(choose(&under, u64::MAX, MIB).is_empty());
        // Two past their limits: both go.
        let two = [pod("a", Some(MIB), 2 * MIB), pod("b", Some(MIB), 3 * MIB)];
        assert_eq!(choose(&two, u64::MAX, MIB).len(), 2);
    }

    #[test]
    fn storage_limit_a_pod_whose_count_did_not_finish_twice_in_a_row_is_replaced() {
        let unfinished = |id: &str, limit| Pod {
            finished: false,
            ..pod(id, limit, MIB)
        };
        let mut last = BTreeSet::new();
        // Once (a slow disk slows every count together): nothing goes, and it is said once.
        let mut pods = [unfinished("slow", Some(10 * MIB)), unfinished("free", None)];
        assert_eq!(missed(&mut pods, &mut last), [0]);
        assert!(choose(&pods, u64::MAX, MIB).is_empty());
        // Twice in a row it cannot be held to its limit: it goes, and says why. Without a
        // limit, what was counted stands.
        let mut pods = [unfinished("slow", Some(10 * MIB)), unfinished("free", None)];
        assert!(missed(&mut pods, &mut last).is_empty());
        let chosen = choose(&pods, u64::MAX, MIB);
        assert_eq!(chosen.len(), 1);
        assert!(
            chosen[0].0 == 0 && chosen[0].1.contains("could not all be counted"),
            "{chosen:?}"
        );
        // A count that finished in between starts it over.
        let mut last = BTreeSet::new();
        let mut slow = [unfinished("slow", Some(10 * MIB))];
        missed(&mut slow, &mut last);
        missed(&mut [pod("slow", Some(10 * MIB), MIB)], &mut last);
        let mut slow = [unfinished("slow", Some(10 * MIB))];
        assert_eq!(missed(&mut slow, &mut last), [0]);
        assert!(choose(&slow, u64::MAX, MIB).is_empty());
        // So does a replacement, whatever it was for (`Controller::replace` forgets the miss).
        last.remove("slow");
        let mut slow = [unfinished("slow", Some(10 * MIB))];
        assert_eq!(missed(&mut slow, &mut last), [0]);
    }

    #[test]
    fn storage_limit_a_replaced_pods_scratch_is_set_aside_whole_and_swept() {
        let replica = dir("aside");
        let scratch = replica.join("scratch");
        std::fs::create_dir_all(scratch.join("cache")).unwrap();
        std::fs::write(scratch.join("cache").join("file"), "written").unwrap();
        assert!(aside(&scratch));
        assert!(!scratch.exists());
        let gone: Vec<_> = std::fs::read_dir(&replica)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        assert!(
            gone.len() == 1 && gone[0].join("cache").join("file").exists(),
            "{gone:?}"
        );
        // Nothing there: nothing to set aside.
        assert!(!aside(&scratch));
        // Swept: every scratch set aside goes, what is not one stays.
        std::fs::create_dir_all(replica.join("scratch.1")).unwrap();
        std::fs::create_dir_all(scratch.join("new")).unwrap();
        sweep(&replica, &GOING);
        let left: Vec<_> = std::fs::read_dir(&replica)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(left, ["scratch"]);
        std::fs::remove_dir_all(replica).unwrap();
    }

    #[test]
    fn storage_limit_a_pod_is_replaced_once_for_a_count_and_waits_for_its_old_runs() {
        let began = Instant::now();
        let before = began - Duration::from_secs(1);
        let after = began + Duration::from_secs(1);
        assert!(replaceable(&[before, began], began));
        // One that started after the count began was not counted; none running, nothing to replace.
        assert!(!replaceable(&[before, after], began));
        assert!(!replaceable(&[], began));
        // Replaced at `began`: still so while a run from before is there or one is stopping.
        assert!(replacing(&[(false, before)], began));
        assert!(replacing(&[(true, after)], began));
        assert!(!replacing(&[(false, after)], began));
        assert!(!replacing(&[], began));
    }

    #[test]
    fn storage_reserve_the_pod_that_wrote_most_is_replaced_one_a_count() {
        let reserve = 100 * MIB;
        let pods = [
            pod("small", None, 20 * MIB),
            pod("big", None, 50 * MIB),
            pod("limited", Some(80 * MIB), 30 * MIB),
        ];
        // Free above the reserve: nothing.
        assert!(choose(&pods, reserve, reserve).is_empty());
        // Under it: the biggest writer, alone, and it says why.
        let chosen = choose(&pods, reserve - 1, reserve);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].0, 1);
        assert!(chosen[0].1.contains("reserve"), "{}", chosen[0].1);
        // One past its limit goes before the biggest writer, which is left for a later count.
        let over = [pod("big", None, 50 * MIB), pod("over", Some(MIB), 2 * MIB)];
        let chosen = choose(&over, 0, reserve);
        assert_eq!(chosen.iter().map(|c| c.0).collect::<Vec<_>>(), [1]);
        // A pod that wrote too little to free anything is not replaced for the reserve.
        assert!(choose(&[pod("tiny", None, 4096)], 0, reserve).is_empty());
        // A reserve of 0 is none.
        assert!(choose(&pods, 0, 0).is_empty());
    }

    #[test]
    fn storage_reserve_a_pod_without_a_limit_is_counted_only_when_the_disk_is_low() {
        let reserve = 100 * MIB;
        assert!(walked(Some(MIB), u64::MAX, reserve));
        assert!(!walked(None, 2 * reserve, reserve));
        assert!(walked(None, 2 * reserve - 1, reserve));
        assert!(!walked(None, 0, 0));
        assert_eq!(default_reserve(10 * MIB * 20, true), 10 * MIB);
        assert_eq!(default_reserve(1 << 40, true), 1 << 30);
        // A kithd that is not root keeps none unless told.
        assert_eq!(default_reserve(1 << 40, false), 0);
    }

    #[test]
    fn storage_stop_ends_a_removal_between_entries_and_follows_no_link() {
        use std::os::unix::fs::PermissionsExt;
        let top = dir("walk");
        let (root, outside) = (top.join("scratch.1"), top.join("outside"));
        std::fs::create_dir_all(outside.join("shut")).unwrap();
        std::fs::write(outside.join("shut/kept"), "x").unwrap();
        std::fs::set_permissions(outside.join("shut"), std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        for n in 0..2500 {
            std::fs::write(root.join(format!("a/f{n}")), "x").unwrap();
        }
        // A directory the pod shut, with a file in it, and a link to a directory outside.
        std::fs::create_dir_all(root.join("a/b/closed")).unwrap();
        std::fs::write(root.join("a/b/closed/f"), "x").unwrap();
        std::fs::set_permissions(root.join("a/b/closed"), std::fs::Permissions::from_mode(0o000)).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("a/out")).unwrap();
        // (And one made after the files: a listing gives one of the two early, whichever its order.)
        std::fs::create_dir_all(root.join("a/late/closed")).unwrap();
        std::fs::write(root.join("a/late/closed/f"), "x").unwrap();
        std::fs::set_permissions(root.join("a/late/closed"), std::fs::Permissions::from_mode(0o000)).unwrap();
        // Asked to stop at its second look: the walk ends, with the rest left where it is.
        let looks = std::cell::Cell::new(0);
        let stopped = remove_tree(&root, &|| {
            looks.set(looks.get() + 1);
            looks.get() > 1
        });
        assert!(!stopped.unwrap(), "stopped");
        assert!(root.exists());
        let left = std::fs::read_dir(root.join("a")).unwrap().count();
        assert!(0 < left && left < 2500, "{left}");
        // Let alone, it takes all of it, and no more. (The stop may have left a level beside the
        // root, with the shut directory in it, by the order the directory was listed in: the
        // sweep takes it.)
        assert!(remove_tree(&root, &|| false).unwrap());
        assert!(!root.exists());
        sweep(&top, &AtomicBool::new(false));
        assert_eq!(levels(&top), (0, 1));
        assert_eq!(
            std::fs::metadata(outside.join("shut")).unwrap().permissions().mode() & 0o777,
            0
        );
        std::fs::set_permissions(outside.join("shut"), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(outside.join("shut/kept").exists());
        std::fs::remove_dir_all(top).unwrap();
    }

    /// `depth` directories `d` inside one another below `top`, a file at the bottom: made through
    /// the handle of each (a path that long is no path).
    fn chain(top: &Path, depth: usize) {
        use crate::backups::{open_dir, within};
        let mut at = open_dir(top).unwrap();
        for _ in 0..depth {
            std::fs::create_dir(within(&at, "d".as_ref())).unwrap();
            at = open_dir(&within(&at, "d".as_ref())).unwrap();
        }
        std::fs::write(within(&at, "bottom".as_ref()), "x").unwrap();
    }

    /// How many directories `d` deep `top` goes.
    fn deep(top: &Path) -> usize {
        use crate::backups::{open_dir, within};
        let mut at = open_dir(top).unwrap();
        let mut down = 0;
        while let Ok(under) = open_dir(&within(&at, "d".as_ref())) {
            (at, down) = (under, down + 1);
        }
        down
    }

    #[test]
    fn storage_stop_a_chain_of_thousands_of_directories_is_removed_a_level_at_a_time() {
        let top = dir("chain");
        let root = top.join("scratch.1");
        std::fs::create_dir(&root).unwrap();
        chain(&root, 2000);
        assert_eq!(deep(&root), 2000);
        // Stopped from inside the walk, hundreds of levels down: what is left in the replica
        // directory is the root and levels, each named `scratch.*`.
        let looks = std::cell::Cell::new(0);
        let stopped = remove_tree(&root, &|| {
            looks.set(looks.get() + 1);
            looks.get() > 1
        });
        assert!(!stopped.unwrap());
        let (scratch, others) = levels(&top);
        assert!(scratch >= 1 && others == 0, "{scratch} {others}");
        // A sweep that is not stopped removes each as a tree of its own, and leaves none.
        sweep(&top, &AtomicBool::new(false));
        assert_eq!(levels(&top), (0, 0));
        // Let alone from the start, all of it goes.
        std::fs::create_dir(&root).unwrap();
        chain(&root, 2000);
        assert!(remove_tree(&root, &|| false).unwrap());
        assert_eq!(levels(&top), (0, 0));
        std::fs::remove_dir_all(top).unwrap();
    }

    #[test]
    fn storage_stop_a_directory_moved_up_under_the_walk_does_not_take_it_above_the_root() {
        let top = dir("moved");
        let (root, beside) = (top.join("scratch.1"), top.join("beside"));
        std::fs::create_dir_all(root.join("a/b/c/d")).unwrap();
        std::fs::create_dir_all(&beside).unwrap();
        std::fs::write(beside.join("kept"), "x").unwrap();
        for n in 0..2000 {
            std::fs::write(root.join(format!("a/b/c/d/f{n}")), "x").unwrap();
        }
        // On its second look, inside `d` (in whichever level holds it by then), a writer that is
        // still alive moves what the level holds up to the replica directory.
        let looks = std::cell::Cell::new(0);
        let done = remove_tree(&root, &|| {
            looks.set(looks.get() + 1);
            if looks.get() == 2 {
                for level in std::fs::read_dir(&top).unwrap().flatten() {
                    if level.file_name().to_string_lossy().starts_with("scratch.") {
                        for held in std::fs::read_dir(level.path()).unwrap().flatten() {
                            std::fs::rename(held.path(), top.join("moved")).unwrap();
                        }
                    }
                }
            }
            false
        });
        assert!(done.unwrap());
        assert!(looks.get() >= 2);
        assert!(!root.exists());
        assert_eq!(std::fs::read_to_string(beside.join("kept")).unwrap(), "x");
        // The walk held the directory, not its path: what was in it is gone, wherever it went.
        assert_eq!(std::fs::read_dir(top.join("moved")).unwrap().count(), 0);
        let mut left: Vec<_> = std::fs::read_dir(&top)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        left.sort();
        assert_eq!(left, ["beside", "moved"]);
        std::fs::remove_dir_all(top).unwrap();
    }

    /// The names in `top`, those of the levels of a removal (`scratch.*`) apart from others.
    fn levels(top: &Path) -> (usize, usize) {
        let names: Vec<_> = std::fs::read_dir(top).unwrap().flatten().collect();
        let scratch = names
            .iter()
            .filter(|e| e.file_name().to_string_lossy().starts_with("scratch."))
            .count();
        (scratch, names.len() - scratch)
    }

    #[test]
    fn storage_stop_a_wide_tree_is_removed_whole_each_directory_listed_once() {
        let top = dir("wide");
        let root = top.join("scratch.1");
        std::fs::create_dir_all(root.join("a/b/wide")).unwrap();
        for n in 0..2000 {
            std::fs::create_dir(root.join(format!("a/b/wide/s{n}"))).unwrap();
            std::fs::write(root.join(format!("a/b/wide/s{n}/f")), "x").unwrap();
        }
        assert!(remove_tree(&root, &|| false).unwrap());
        assert_eq!(std::fs::read_dir(&top).unwrap().count(), 0);
        std::fs::remove_dir_all(top).unwrap();
    }

    /// A disk with no room makes no level: the directories themselves become the levels, and one
    /// that holds the names a move would take (a non-empty `d1`, a file `d2`, a link `d3`) is no
    /// trouble, nor is the link followed.
    #[test]
    fn storage_stop_a_tree_is_removed_whole_where_no_level_can_be_made() {
        let top = dir("full");
        let (root, outside) = (top.join("scratch.1"), top.join("outside"));
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("kept"), "x").unwrap();
        // Whichever of these is moved first becomes the level, and holds the first names the
        // others would be moved in under: two directories that are not empty, a file, a link.
        for n in 0..50 {
            let s = root.join(format!("a/s{n}"));
            std::fs::create_dir_all(s.join("d1")).unwrap();
            std::fs::create_dir_all(s.join("d2")).unwrap();
            std::fs::write(s.join("d1/f"), "x").unwrap();
            std::fs::write(s.join("d2/f"), "x").unwrap();
            std::fs::write(s.join("d3"), "x").unwrap();
            std::os::unix::fs::symlink(&outside, s.join("d4")).unwrap();
        }
        let full = |_: &Path| Err(std::io::Error::from(std::io::ErrorKind::StorageFull));
        assert!(remove_tree_with(&root, &|| false, full).unwrap());
        assert_eq!(levels(&top), (0, 1));
        // A chain: each directory is the next level in its turn.
        std::fs::create_dir(&root).unwrap();
        chain(&root, 300);
        assert!(remove_tree_with(&root, &|| false, full).unwrap());
        assert_eq!(levels(&top), (0, 1));
        assert!(outside.join("kept").exists());
        std::fs::remove_dir_all(top).unwrap();
    }

    /// A directory another remover took between the listing and the open does not end the removal.
    #[test]
    fn storage_stop_a_directory_gone_before_it_is_opened_is_no_error() {
        let top = dir("gone");
        let root = top.join("scratch.1");
        std::fs::create_dir_all(root.join("a")).unwrap();
        let run = Removal {
            halted: &|| false,
            steps: 0,
            device: None,
            moved: 0,
            next: None,
            beside: root.clone(),
            make: |_| Ok(()),
        };
        let mut run = run;
        let level = crate::backups::open_dir(&root).unwrap();
        let gone = std::ffi::CString::new("never-there").unwrap();
        assert!(run.empty(level.as_raw_fd(), &gone).unwrap());
        std::fs::remove_dir_all(top).unwrap();
    }

    #[test]
    fn storage_stop_a_removal_that_fails_ends_with_its_error_and_the_next_scratch_is_swept() {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            return; // root removes in a read-only directory
        }
        let replica = dir("failing");
        for scratch in ["scratch.1", "scratch.2"] {
            std::fs::create_dir_all(replica.join(scratch)).unwrap();
            for n in 0..2000 {
                std::fs::write(replica.join(scratch).join(format!("f{n}")), "x").unwrap();
            }
        }
        // Its looks: 1 the sweep's before the first scratch, 2 and 3 that scratch's (at its start
        // and 1,024 steps in), 4 the sweep's before the second. Between 3 and 4 the replica
        // directory is read-only, so the first scratch is emptied and cannot be removed.
        let looks = std::cell::Cell::new(0);
        sweep_until(&replica, &|| {
            looks.set(looks.get() + 1);
            let mode = if looks.get() == 3 { 0o500 } else { 0o700 };
            std::fs::set_permissions(&replica, std::fs::Permissions::from_mode(mode)).unwrap();
            false
        });
        assert!(looks.get() >= 5, "{}", looks.get());
        // One scratch is left, emptied; the other, swept after the error, is gone.
        let left: Vec<_> = std::fs::read_dir(&replica).unwrap().flatten().collect();
        assert_eq!(left.len(), 1);
        assert_eq!(std::fs::read_dir(left[0].path()).unwrap().count(), 0);
        sweep_until(&replica, &|| false);
        assert_eq!(levels(&replica), (0, 0));
        std::fs::remove_dir_all(replica).unwrap();
    }

    #[test]
    fn storage_stop_a_scratch_that_is_a_link_or_a_file_is_unlinked_not_followed() {
        let top = dir("odd");
        let outside = top.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("kept"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, top.join("scratch.1")).unwrap();
        std::fs::write(top.join("scratch.2"), "x").unwrap();
        sweep(&top, &AtomicBool::new(false));
        assert!(top.join("scratch.1").symlink_metadata().is_err());
        assert!(top.join("scratch.2").symlink_metadata().is_err());
        assert!(outside.join("kept").exists());
        std::fs::remove_dir_all(top).unwrap();
    }

    #[test]
    fn storage_stop_a_sweep_halted_inside_a_scratch_leaves_it_and_the_ones_after() {
        let replica = dir("halted");
        for scratch in ["scratch.1", "scratch.2"] {
            std::fs::create_dir_all(replica.join(scratch)).unwrap();
            for n in 0..2000 {
                std::fs::write(replica.join(scratch).join(format!("f{n}")), "x").unwrap();
            }
        }
        // Its looks: before the first scratch, at the start of its removal, and 1,024 steps in.
        let looks = std::cell::Cell::new(0);
        sweep_until(&replica, &|| {
            looks.set(looks.get() + 1);
            looks.get() > 2
        });
        let left: Vec<usize> = ["scratch.1", "scratch.2"]
            .iter()
            .map(|scratch| std::fs::read_dir(replica.join(scratch)).map_or(0, Iterator::count))
            .collect();
        assert!(
            left.contains(&2000) && left.iter().any(|n| 0 < *n && *n < 2000),
            "{left:?}"
        );
        sweep_until(&replica, &|| false);
        assert_eq!(std::fs::read_dir(&replica).unwrap().count(), 0);
        std::fs::remove_dir_all(replica).unwrap();
    }
}
