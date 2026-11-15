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
}

/// How the message of a unit replaced for what its pod wrote begins.
pub const REPLACED: &str = "replaced: ";

/// The longest one pod is counted, each count.
pub const SPELL: Duration = Duration::from_secs(5);

/// How many directories deep a count goes (each holds a descriptor open while it is walked).
pub const DEEP: usize = 128;

/// Files with several links (or deleted, held open) remembered a count to be counted once; past
/// that many each is counted at every link: more, never less.
const LINKED: usize = 65536;

/// The most cgroups, and processes, of one pod read a count; past them it did not finish.
const CGROUPS: usize = 100_000;

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
/// symlink, and what it is, if it is a directory on `device`.
fn open_dir(parent: Option<&OwningIter>, name: &(impl nix::NixPath + ?Sized), device: u64) -> Option<OwningIter> {
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
pub fn count(roots: &[PathBuf], stop: u64, until: Instant) -> (u64, bool) {
    let mut linked = BTreeSet::new();
    let (mut bytes, mut finished) = (0u64, true);
    for root in roots {
        let Ok(top) = fstatat(None, root.as_path(), AtFlags::AT_SYMLINK_NOFOLLOW) else {
            continue;
        };
        let device = top.st_dev;
        bytes = bytes.saturating_add(top.st_blocks as u64 * 512);
        let mut open: Vec<OwningIter> = match is_dir(&top) {
            true => open_dir(None, root.as_path(), device).into_iter().collect(),
            false => Vec::new(),
        };
        while let Some(at) = open.last_mut() {
            if bytes > stop {
                return (bytes, true);
            }
            if Instant::now() >= until {
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
            let below = open_dir(open.last(), name, device);
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
pub fn pids(cgroup: &Path, until: Instant) -> (Vec<u32>, bool) {
    let mut pids = Vec::new();
    let mut cgroups = vec![(cgroup.to_path_buf(), 0)];
    let mut read = 0;
    while let Some((cgroup, depth)) = cgroups.pop() {
        read += 1;
        if Instant::now() >= until || read > CGROUPS || pids.len() > CGROUPS {
            return (pids, false);
        }
        let procs = std::fs::read_to_string(cgroup.join("cgroup.procs")).unwrap_or_default();
        pids.extend(procs.lines().filter_map(|pid| pid.parse::<u32>().ok()));
        if depth < 16 {
            for entry in std::fs::read_dir(&cgroup).into_iter().flatten().flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    cgroups.push((entry.path(), depth + 1));
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
pub fn unlinked(pids: &[u32], roots: &[PathBuf], until: Instant) -> (u64, bool) {
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
                if Instant::now() >= until {
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
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    let gone = scratch.with_file_name(format!("scratch.{}", nanos.unwrap_or_default().as_nanos()));
    std::fs::rename(scratch, gone).is_ok()
}

/// Removes every scratch moved aside in the replica directory `replica`.
pub fn sweep(replica: &Path) {
    for entry in std::fs::read_dir(replica).into_iter().flatten().flatten() {
        if entry.file_name().to_string_lossy().starts_with("scratch.")
            && let Err(e) = std::fs::remove_dir_all(entry.path())
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("kithd: removing {}: {e}", entry.path().display());
        }
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
            let why = match pod.finished {
                true if pod.bytes > limit => format!(
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
        }
    }

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(600)
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
        let parent = open_dir(None, b.as_path(), std::fs::metadata(&b).unwrap().dev()).unwrap();
        assert!(open_dir(Some(&parent), c"dir", std::fs::metadata(&outside).unwrap().dev()).is_none());
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
        assert!(!count(std::slice::from_ref(&shallow), u64::MAX, Instant::now()).1);
        for d in [root, shallow] {
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
        assert!(!pids(&top, Instant::now()).1);
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
        sweep(&replica);
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
}
