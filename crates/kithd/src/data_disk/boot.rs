//! The task that mounts a node's known data disks, after its state is open (docs/adr-second-disk.md,
//! section 2): each disk this node could use, other than the one it runs from and a stick, has
//! its first 4 KiB read; one whose header is a kith data disk's and whose id the state holds a
//! `ready` entry for is mapped under the key kept in the state and mounted at
//! `disks/<id>/data`, and every other is left exactly as it was (it is read, never written).
//! What was found is said once on the console, and kept for `kith status` (`status.disks`).
//!
//! Only kithd as the machine's init does this: a development start has no business with the
//! machine's disks. A disk that will not open is said and the others go on, and one that does
//! not answer is let go of after [`OPEN`] (its thread, stuck in the kernel, is not waited for).
use super::seed::{self, RealDisk};
use super::{Dev, Id, Standing, dir_of, hex_id, off_ours, read_entry, read_key, standing};
use crate::install::Disk;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// How long one disk may take to be read, mapped and mounted.
const OPEN: Duration = Duration::from_secs(60);

/// What a disk was found to be.
#[derive(Debug, PartialEq)]
pub enum What {
    /// Known, and its file system is open at `disks/<id>/data`.
    Mounted(Id),
    /// Not this node's: no header, another's, a header whose add never finished.
    Unknown,
    /// A kith header that does not check out: not opened, not repaired.
    Damaged(String),
    /// Its first 4 KiB could not be read, or it did not answer in time.
    Unreadable(String),
    /// Known, and not opened (its key, its mapping or its file system).
    Failed(Id, String),
}

/// A disk (as the installer shows it: name, size, serial) and what it was found to be.
#[derive(Debug, PartialEq)]
pub struct Seen {
    pub disk: String,
    pub what: What,
}

/// A disk the state has a `ready` entry for that no disk showed.
#[derive(Debug, PartialEq)]
pub struct Gone {
    pub id: String,
    pub serial: String,
}

/// Read the first 4 KiB of `disk` and, if it is a known disk, `open` it with its key and its
/// mount point. Nothing is written to the disk here, and `open` is called for a known disk only:
/// one whose `serial` is the one its entry was made for (a copy of a disk's first 4 KiB, or of the
/// whole disk, on another disk carries the header and not the serial).
pub fn judge<D: Dev>(
    state: &Path,
    disk: &D,
    serial: &str,
    open: impl FnOnce(&Id, &[u8; 64], &Path) -> Result<(), String>,
) -> What {
    let room = match disk.first() {
        Ok(room) => room,
        Err(e) => return What::Unreadable(e.to_string()),
    };
    match standing(state, &room) {
        Standing::Unknown => What::Unknown,
        Standing::Damaged(why) => What::Damaged(why),
        Standing::Ours(id) => {
            let dir = dir_of(state, &id);
            if read_entry(&dir).is_none_or(|entry| entry.serial != serial) {
                return What::Failed(id, "its header is this node's, its serial is not the one added".into());
            }
            let Some(key) = read_key(&dir) else {
                return What::Failed(id, "its key is not kept whole in the state".into());
            };
            match open(&id, &key, &dir.join("data")) {
                Ok(()) => What::Mounted(id),
                Err(why) => What::Failed(id, why),
            }
        }
    }
}

/// The disks the state has a `ready` entry for that are not among `seen` (ids): the disk is
/// not in this machine, or it is, with a header that is not its own any more.
pub fn missing(state: &Path, seen: &[Id]) -> Vec<Gone> {
    let mut gone: Vec<Gone> = std::fs::read_dir(state.join("disks"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|item| {
            let id = hex_id(item.file_name().to_str()?)?;
            let entry = read_entry(&item.path()).filter(|entry| entry.ready)?;
            (!seen.contains(&id)).then(|| Gone {
                id: crate::pki::hex(&id),
                serial: entry.serial,
            })
        })
        .collect();
    gone.sort_by(|a, b| a.id.cmp(&b.id));
    gone
}

/// The id of the disk when it is a known one (opened or not).
pub fn id_of(what: &What) -> Option<&Id> {
    match what {
        What::Mounted(id) | What::Failed(id, _) => Some(id),
        _ => None,
    }
}

/// The one status line on the console: the known disks, then the unknown ones.
pub fn line(seen: &[Seen], gone: &[Gone]) -> String {
    let mut known = Vec::new();
    let mut unknown = Vec::new();
    for one in seen {
        let disk = &one.disk;
        match &one.what {
            What::Mounted(_) => known.push(format!("{disk} mounted")),
            What::Failed(_, why) => known.push(format!("{disk} not mounted: {why}")),
            What::Unknown => unknown.push(format!("{disk} left alone")),
            What::Damaged(why) => unknown.push(format!("{disk} has a damaged header ({why}), left alone")),
            What::Unreadable(why) => unknown.push(format!("{disk} cannot be read ({why}), left alone")),
        }
    }
    for one in gone {
        known.push(format!(
            "{} (serial {}) not found",
            &one.id[..8.min(one.id.len())],
            one.serial
        ));
    }
    let list = |items: Vec<String>| {
        if items.is_empty() {
            "none".into()
        } else {
            items.join("; ")
        }
    };
    format!("kithd: data disks: known: {}; unknown: {}", list(known), list(unknown))
}

/// The same for `status.disks`: `known` (each with its id, and `mounted`, `failed` or `not
/// found`) and `unknown` (`not ours`, `damaged` or `unreadable`).
pub fn status(seen: &[Seen], gone: &[Gone]) -> Value {
    let mut known = Vec::new();
    let mut unknown = Vec::new();
    for one in seen {
        let disk = &one.disk;
        let id = id_of(&one.what).map(|id| crate::pki::hex(id));
        match &one.what {
            What::Mounted(_) => known.push(json!({"disk": disk, "id": id, "state": "mounted"})),
            What::Failed(_, why) => known.push(json!({"disk": disk, "id": id, "state": "failed", "why": why})),
            What::Unknown => unknown.push(json!({"disk": disk, "state": "not ours"})),
            What::Damaged(why) => unknown.push(json!({"disk": disk, "state": "damaged", "why": why})),
            What::Unreadable(why) => unknown.push(json!({"disk": disk, "state": "unreadable", "why": why})),
        }
    }
    for one in gone {
        known.push(json!({"id": one.id, "serial": one.serial, "state": "not found"}));
    }
    json!({"known": known, "unknown": unknown})
}

/// What the start found, for `kith status` (`update.rs` reads it): set once.
static SAID: OnceLock<Value> = OnceLock::new();

pub fn said() -> Option<Value> {
    SAID.get().cloned()
}

/// One id is one disk: the first to ask has it, a second disk with the same id is refused.
fn claim(claimed: &Mutex<HashSet<Id>>, id: &Id) -> Result<(), String> {
    if claimed.lock().unwrap_or_else(|e| e.into_inner()).insert(*id) {
        Ok(())
    } else {
        Err("another disk has this id".into())
    }
}

/// Open one disk (`open`) unless it was `abandoned` (the wait for it ran out), and if it was
/// abandoned while it was opening, close it again (`undo`): a late answer from a stuck disk must
/// not leave a mount nothing knows of. An opened disk is `keep`t for [`close`].
fn open_unless_abandoned(
    abandoned: &AtomicBool,
    open: impl FnOnce() -> Result<(), String>,
    keep: impl FnOnce(),
    undo: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let let_go = || format!("it did not answer in {} s, let go of", OPEN.as_secs());
    if abandoned.load(Ordering::SeqCst) {
        return Err(let_go());
    }
    open()?;
    if abandoned.load(Ordering::SeqCst) {
        undo().map_err(|e| format!("{}, and not closed: {e}", let_go()))?;
        return Err(let_go());
    }
    keep();
    Ok(())
}

/// The disks mounted, as (kernel name, mount point): what [`close`] lets go of.
static OPEN_NOW: Mutex<Vec<(String, PathBuf)>> = Mutex::new(Vec::new());

/// `name` (a kernel name) is mounted at `at` now: [`close`] lets go of it. The verbs' add does this
/// for the disk it mounts after the start's scan has run.
pub fn keep(name: &str, at: &Path) {
    let mut open = OPEN_NOW.lock().unwrap_or_else(|e| e.into_inner());
    open.retain(|(kept, _)| kept != name);
    open.push((name.to_string(), at.to_path_buf()));
}

/// Forget that `name` is mounted (the verbs' remove unmounted it).
pub fn forget_open(name: &str) {
    OPEN_NOW
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(kept, _)| kept != name);
}

/// Whether `name` is mounted by this kithd.
pub fn is_open(name: &str) -> bool {
    OPEN_NOW
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|(kept, _)| kept == name)
}

/// Whether a disk is mounted by this kithd at `at`.
pub fn is_mounted_at(at: &Path) -> bool {
    OPEN_NOW
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|(_, kept)| kept == at)
}

/// The disks this machine could use for data: every one besides the one it runs from (and the one
/// the state is on), and a stick. What the scan at start and `list` look at.
pub fn offered(verity: bool, ours: Option<&str>, state_disk: Option<&str>) -> Vec<Disk> {
    crate::install::disks(Path::new("/sys/block"), ours)
        .into_iter()
        .filter(|disk| !disk.removable && off_ours(verity, ours, state_disk, &disk.name))
        .collect()
}

/// Unmount the data disks and remove their mappings: before the state is unmounted (they are
/// mounted under it), at the end of the machine's run. Each is tried, and one that is busy is said.
pub fn close() {
    let open = std::mem::take(&mut *OPEN_NOW.lock().unwrap_or_else(|e| e.into_inner()));
    for (name, at) in open {
        let Some(disk) = RealDisk::new(&name, false) else {
            continue;
        };
        if let Err(e) = seed::close(&disk, &at) {
            eprintln!("kithd: the data disk {name} is not closed: {e}");
        }
    }
}

/// Look at every disk this machine has besides the one it runs from, and open the known ones.
/// Runs once, from the storage tasks after the state is open; only as init.
pub async fn run(state: PathBuf) {
    if !crate::init::is_init() {
        return;
    }
    // (A disk verb and this scan would race for the mappings and the state's `disks/`.)
    let _turn = super::verbs::wait().await;
    let (verity, ours, state_disk) = crate::init::whose_disks();
    let disks = offered(verity, ours.as_deref(), state_disk.as_deref());
    let mut tasks = tokio::task::JoinSet::new();
    // The ids opened so far: one id is one disk, a second disk with it (a copy) is not opened.
    let claimed = Arc::new(Mutex::new(HashSet::new()));
    for disk in disks {
        let state = state.clone();
        let claimed = claimed.clone();
        tasks.spawn(async move {
            let shown = disk.to_string();
            let abandoned = Arc::new(AtomicBool::new(false));
            let late = abandoned.clone();
            let job = tokio::task::spawn_blocking(move || match RealDisk::new(&disk.name, disk.removable) {
                None => What::Unreadable("its name is not one".into()),
                Some(real) => judge(&state, &real, &disk.serial, |id, key, at| {
                    claim(&claimed, id)?;
                    open_unless_abandoned(
                        &late,
                        || seed::open(&real, at, key),
                        || {
                            OPEN_NOW
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push((real.name().to_string(), at.to_path_buf()));
                        },
                        || seed::close(&real, at).map_err(|e| e.to_string()),
                    )
                }),
            });
            let what = match tokio::time::timeout(OPEN, job).await {
                Ok(Ok(what)) => what,
                Ok(Err(e)) => What::Unreadable(format!("looking at it failed: {e}")),
                Err(_) => {
                    // (Its thread goes on, stuck: whatever it opens late, it closes again.)
                    abandoned.store(true, Ordering::SeqCst);
                    What::Unreadable(format!("it did not answer in {} s", OPEN.as_secs()))
                }
            };
            Seen { disk: shown, what }
        });
    }
    let mut seen = Vec::new();
    while let Some(one) = tasks.join_next().await {
        match one {
            Ok(one) => seen.push(one),
            Err(e) => eprintln!("kithd: a data disk's look failed: {e}"),
        }
    }
    seen.sort_by(|a, b| a.disk.cmp(&b.disk));
    let ids: Vec<Id> = seen.iter().filter_map(|one| id_of(&one.what).copied()).collect();
    let gone = missing(&state, &ids);
    eprintln!("{}", line(&seen, &gone));
    let _ = SAID.set(status(&seen, &gone));
}

#[cfg(test)]
mod tests {
    use super::super::support::*;
    use super::super::*;
    use super::*;
    use std::cell::RefCell;

    /// `ID` made this node's: its entry `ready` (serial `S1`) and a key in the state.
    fn known(state: &Path, disk: &Fake) {
        put(&disk.0, &ID);
        let dir = dir_of(state, &ID);
        std::fs::create_dir_all(&dir).unwrap();
        put_file(&dir, "key", &[9; 64]).unwrap();
        put_file(&dir, "entry", entry_text("S1", true).as_bytes()).unwrap();
    }

    fn bytes(disk: &Fake) -> Vec<u8> {
        let mut all = vec![0; 1 << 20];
        disk.0.read_exact_at(&mut all, 0).unwrap();
        all
    }

    /// What `judge` opened: the key and the mount point, for each call.
    type Opened = RefCell<Vec<([u8; 64], PathBuf)>>;

    fn opening<'a>(
        opened: &'a Opened,
        answer: Result<(), String>,
    ) -> impl FnOnce(&Id, &[u8; 64], &Path) -> Result<(), String> + 'a {
        move |_, key, at| {
            opened.borrow_mut().push((*key, at.to_path_buf()));
            answer
        }
    }

    #[test]
    fn a_known_disk_is_opened_with_its_key_at_its_mount_point() {
        let (_dir, disk, state) = rig("boot-known");
        known(&state, &disk);
        let opened = Opened::default();
        let what = judge(&state, &disk, "S1", opening(&opened, Ok(())));
        assert_eq!(what, What::Mounted(ID));
        let at = dir_of(&state, &ID).join("data");
        assert_eq!(*opened.borrow(), vec![([9; 64], at)]);
    }

    #[test]
    fn a_second_disk_with_an_id_is_refused() {
        let claimed = Mutex::new(HashSet::new());
        assert_eq!(claim(&claimed, &ID), Ok(()));
        assert_eq!(claim(&claimed, &[7; 16]), Ok(()));
        assert_eq!(claim(&claimed, &ID), Err("another disk has this id".into()));
    }

    #[test]
    fn a_disk_whose_serial_is_not_the_one_added_is_not_opened() {
        // A copy of a known disk: the header is the same, the disk is another.
        let (_dir, disk, state) = rig("boot-serial");
        known(&state, &disk);
        let opened = Opened::default();
        for serial in ["S2", ""] {
            let what = judge(&state, &disk, serial, opening(&opened, Ok(())));
            assert!(
                matches!(&what, What::Failed(id, why) if *id == ID && why.contains("serial")),
                "{what:?}"
            );
        }
        assert!(opened.borrow().is_empty());
    }

    #[test]
    fn a_disk_that_is_abandoned_is_not_opened_and_one_opened_late_is_closed_again() {
        let calls = RefCell::new(Vec::new());
        let go = |abandoned: &AtomicBool, during: bool, close: Result<(), String>| {
            calls.borrow_mut().clear();
            let said = open_unless_abandoned(
                abandoned,
                || {
                    calls.borrow_mut().push("open");
                    abandoned.store(during, Ordering::SeqCst);
                    Ok(())
                },
                || calls.borrow_mut().push("keep"),
                || {
                    calls.borrow_mut().push("undo");
                    close
                },
            );
            (said, calls.borrow().clone())
        };
        let (said, calls) = go(&AtomicBool::new(false), false, Ok(()));
        assert_eq!((said, calls), (Ok(()), vec!["open", "keep"]));
        let (said, calls) = go(&AtomicBool::new(true), true, Ok(()));
        assert!(said.is_err());
        assert!(calls.is_empty(), "an abandoned disk is not opened: {calls:?}");
        let (said, calls) = go(&AtomicBool::new(false), true, Ok(()));
        assert!(said.is_err());
        assert_eq!(calls, vec!["open", "undo"], "opened late: closed, not kept");
        let (said, calls) = go(&AtomicBool::new(false), true, Err("busy".into()));
        assert!(
            said.is_err_and(|why| why.contains("busy")),
            "a close that fails is said"
        );
        assert_eq!(calls, vec!["open", "undo"]);
    }

    #[test]
    fn an_unknown_disk_is_not_opened_and_not_written() {
        // Empty, a file system, a header of another node, one whose entry is still pending.
        let (_dir, empty, state) = rig("boot-unknown");
        let (_d2, other, _) = rig("boot-other");
        other.0.write_all_at(&[0x53, 0xef], 1080).unwrap();
        let (_d3, foreign, _) = rig("boot-foreign");
        put(&foreign.0, &ID);
        let (_d4, pending, state4) = rig("boot-pending");
        put(&pending.0, &ID);
        std::fs::create_dir_all(dir_of(&state4, &ID)).unwrap();
        put_file(&dir_of(&state4, &ID), "entry", entry_text("S1", false).as_bytes()).unwrap();
        let opened = Opened::default();
        for (disk, state) in [
            (&empty, &state),
            (&other, &state),
            (&foreign, &state),
            (&pending, &state4),
        ] {
            let before = bytes(disk);
            assert_eq!(judge(state, disk, "S1", opening(&opened, Ok(()))), What::Unknown);
            assert_eq!(bytes(disk), before, "an unknown disk is read, never written");
        }
        assert!(opened.borrow().is_empty(), "no unknown disk is opened");
    }

    #[test]
    fn a_damaged_header_is_named_and_left_alone() {
        let (_dir, disk, state) = rig("boot-damaged");
        known(&state, &disk);
        disk.0.write_all_at(b"X", 20).unwrap();
        let before = bytes(&disk);
        let opened = Opened::default();
        let what = judge(&state, &disk, "S1", opening(&opened, Ok(())));
        assert!(matches!(what, What::Damaged(_)), "{what:?}");
        assert_eq!(bytes(&disk), before);
        assert!(opened.borrow().is_empty());
    }

    #[test]
    fn a_known_disk_that_will_not_open_is_failed_with_the_reason_and_the_others_go_on() {
        let (_dir, disk, state) = rig("boot-failed");
        known(&state, &disk);
        let opened = Opened::default();
        let what = judge(
            &state,
            &disk,
            "S1",
            opening(&opened, Err("no file system under that key".into())),
        );
        assert_eq!(what, What::Failed(ID, "no file system under that key".into()));
        // A key that is not whole is the state's fault, and said so: the disk is not opened.
        std::fs::write(dir_of(&state, &ID).join("key"), [1; 10]).unwrap();
        let what = judge(&state, &disk, "S1", opening(&opened, Ok(())));
        assert!(
            matches!(&what, What::Failed(id, why) if *id == ID && why.contains("key")),
            "{what:?}"
        );
        assert_eq!(opened.borrow().len(), 1, "the second was not opened");
    }

    #[test]
    fn a_disk_that_cannot_be_read_is_unreadable() {
        let (_dir, file) = disk_file("boot-short", 100);
        let what = judge(
            Path::new("/nonexistent"),
            &Fake(file, "sdb", false),
            "S1",
            opening(&Opened::default(), Ok(())),
        );
        assert!(matches!(what, What::Unreadable(_)), "{what:?}");
    }

    #[test]
    fn a_ready_entry_no_seen_disk_showed_is_listed_as_not_found() {
        let (_dir, disk, state) = rig("boot-missing");
        known(&state, &disk);
        // A pending entry is no disk the node had; a ready one is.
        let other: Id = [7; 16];
        std::fs::create_dir_all(dir_of(&state, &other)).unwrap();
        put_file(&dir_of(&state, &other), "entry", entry_text("S2", true).as_bytes()).unwrap();
        let pending: Id = [8; 16];
        std::fs::create_dir_all(dir_of(&state, &pending)).unwrap();
        put_file(&dir_of(&state, &pending), "entry", entry_text("S3", false).as_bytes()).unwrap();
        assert_eq!(
            missing(&state, &[ID]),
            vec![Gone {
                id: crate::pki::hex(&other),
                serial: "S2".into()
            }]
        );
        assert!(missing(&state, &[ID, other]).is_empty());
        assert!(
            missing(&state.join("none"), &[]).is_empty(),
            "no disks directory, none missing"
        );
    }

    fn seen() -> Vec<Seen> {
        let shown = |name: &str, serial: &str| format!("{name} (1.0 GB, serial {serial})");
        vec![
            Seen {
                disk: shown("sdb", "A1"),
                what: What::Mounted(ID),
            },
            Seen {
                disk: shown("sdc", "B2"),
                what: What::Unknown,
            },
            Seen {
                disk: shown("sdd", "C3"),
                what: What::Damaged("a wrong sum".into()),
            },
            Seen {
                disk: shown("sde", "D4"),
                what: What::Failed(ID, "no file system".into()),
            },
        ]
    }

    #[test]
    fn the_status_line_lists_the_known_disks_and_the_unknown_ones() {
        let gone = [Gone {
            id: crate::pki::hex(&[7; 16]),
            serial: "S2".into(),
        }];
        let line = line(&seen(), &gone);
        assert!(!line.contains('\n'), "one line: {line}");
        let (known, unknown) = line.split_once("unknown:").expect(&line);
        assert!(known.starts_with("kithd: data disks: known:"), "{line}");
        assert!(known.contains("sdb (1.0 GB, serial A1) mounted"), "{line}");
        assert!(known.contains("sde") && known.contains("no file system"), "{line}");
        assert!(known.contains("serial S2") && known.contains("not found"), "{line}");
        assert!(unknown.contains("sdc") && unknown.contains("left alone"), "{line}");
        assert!(unknown.contains("sdd") && unknown.contains("a wrong sum"), "{line}");
        assert!(!unknown.contains("sdb"), "{line}");
        assert_eq!(super::line(&[], &[]), "kithd: data disks: known: none; unknown: none");
    }

    #[test]
    fn the_status_json_lists_known_and_unknown_disks() {
        let said = status(&seen(), &[]);
        let known = said["known"].as_array().unwrap();
        let unknown = said["unknown"].as_array().unwrap();
        assert_eq!(known.len(), 2);
        assert_eq!(known[0]["disk"], "sdb (1.0 GB, serial A1)");
        assert_eq!(known[0]["state"], "mounted");
        assert_eq!(known[0]["id"], crate::pki::hex(&ID));
        assert_eq!(known[1]["state"], "failed");
        assert_eq!(known[1]["why"], "no file system");
        assert_eq!(unknown.len(), 2);
        assert_eq!(unknown[0]["state"], "not ours");
        assert_eq!(unknown[1]["state"], "damaged");
    }
}
