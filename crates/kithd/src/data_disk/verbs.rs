//! The verbs of a second disk (docs/adr-second-disk.md, sections 2 and 3): `kith node disk add`,
//! `remove` and `list`, at `/v1/disks/{node}` on the API, and on the machine's own socket with no
//! cluster at all (an owner's one machine has a disk to add, and the local socket's admin may
//! apply a NodeKey there: the answer needs no cluster and no peer).
//!
//! The owner names a disk by its serial, as the installer does, and by nothing else (a kernel name
//! changes from one start to the next). What decides is the core in `data_disk.rs` (the refusals,
//! the order of writes, the remove); what is here is which disk the serial is, whether this node's
//! state is encrypted (a disk's key is kept in it: in the clear, the key would sit beside the
//! data it protects), the mount that follows an add, and the wording. The pure parts take the
//! machine as arguments, so a file and a fake show them all; [`real_add`] and its two are the
//! parts that touch `/sys`, `/dev` and the mounts.
//!
//! One verb runs at a time ([`one`]): an add takes minutes to hours (it overwrites the disk), and
//! two at once would race the mapping names and the state's `disks/`. Not built (docs/adr-second-disk.md
//! says where it goes): an add for another node's disk, the node asked at its own address, and
//! `remove --discard`.
use super::boot::{self, Seen, What};
use super::seed::{self, Real, RealDisk};
use super::{AddError, Dev, Id, Mapper, Root, audit, dir_of, hex_id, read_entry, read_key};
use crate::Shared;
use crate::access::Caller;
use crate::cluster::refuse;
use crate::install::Disk;
use axum::extract::{Path as Named, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use kith_api::kinds::Verb;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The name of the mapping the state of an encrypted node is open under (`crypt.rs`).
const STATE_MAPPING: &str = "kith-state";

/// Whether this node's state is encrypted: a device-mapper device named [`STATE_MAPPING`] is under
/// `sys` (`/sys/block`, where each has its `dm/name`).
pub fn encrypted(sys: &Path) -> bool {
    std::fs::read_dir(sys)
        .into_iter()
        .flatten()
        .flatten()
        .any(|item| std::fs::read_to_string(item.path().join("dm/name")).is_ok_and(|name| name.trim() == STATE_MAPPING))
}

/// The one disk of `disks` with the serial `serial` (as typed: blanks at its ends are not part of
/// it). None, an empty serial and two disks of one serial are each refused, naming the disks seen.
pub fn pick<'a>(disks: &'a [Disk], serial: &str) -> Result<&'a Disk, String> {
    let serial = serial.trim();
    let seen = || match disks.iter().map(Disk::to_string).collect::<Vec<_>>() {
        shown if shown.is_empty() => "none".to_string(),
        shown => shown.join("; "),
    };
    if serial.is_empty() {
        return Err(format!(
            "name the disk by its serial (--serial). Disks seen: {}",
            seen()
        ));
    }
    let mut found = disks.iter().filter(|disk| disk.serial == serial);
    match (found.next(), found.next()) {
        (Some(disk), None) => Ok(disk),
        (None, _) => Err(format!("no disk has the serial {serial:?}. Disks seen: {}", seen())),
        (Some(_), Some(_)) => Err(format!(
            "more than one disk has the serial {serial:?}, and a disk is named by its serial alone. Disks seen: {}",
            seen()
        )),
    }
}

/// What an add that did not finish says to the owner.
fn said(error: AddError, disk: &Disk, wipe: bool) -> String {
    match error {
        AddError::Refused(why) if why.wipeable() && !wipe => format!(
            "{}: {why}. If it is the disk meant, and what is on it may go, add it again with --wipe",
            disk.name
        ),
        AddError::Refused(why) => format!("{}: {why}", disk.name),
        AddError::Added => already(disk),
        AddError::Half(why) => format!(
            "an add of {} began and did not finish ({why}): add it again with --wipe to start over",
            disk.name
        ),
        AddError::Failed(why) => format!(
            "{}: {why}. Add it again; if that fails too, kith node disk list shows what the node sees of it, and its cable and the disk itself are the next to look at",
            disk.name
        ),
    }
}

fn already(disk: &Disk) -> String {
    format!(
        "{} is already added as this node's disk: kith node disk list shows it",
        disk.name
    )
}

/// Add the disk of `serial` as this node's: refused when the state is not `encrypted`, when no
/// one disk of `disks` has the serial, and for what the core refuses ([`super::add`]). `take`
/// makes the disk and its mapper for the one found (the real ones hold the disk exclusively; a
/// test has a file), and is not called for a disk that is not to be touched. The mapping the core
/// leaves open comes back with the disk's id and the disk, for the caller to let go of.
pub fn add<'a, D: Dev, M: Mapper>(
    state: &Path,
    encrypted: bool,
    disks: &'a [Disk],
    root: Option<&Root>,
    serial: &str,
    (wipe, quick): (bool, bool),
    take: impl FnOnce(&Disk) -> Result<(D, M), String>,
) -> Result<(Id, &'a Disk, M), String> {
    if !encrypted {
        return Err("this node's state is not encrypted, and a data disk's key is kept in the state: with the state in the clear, the key would sit beside the data it protects. Install the node with encrypt: true first".into());
    }
    let disk = pick(disks, serial)?;
    // (Asked first: a disk added is mapped, and taking it would be refused as held by another.)
    if super::entry_of(state, &disk.serial, true).is_some() {
        return Err(already(disk));
    }
    let (dev, mut mapper) = take(disk)?;
    let id =
        super::add(state, &dev, root, &disk.serial, (wipe, quick), &mut mapper).map_err(|e| said(e, disk, wipe))?;
    Ok((id, disk, mapper))
}

/// Remove the disk `id` (32 hex digits, as `list` shows): the disk it was added as is found by the
/// serial the state kept, among `disks` (this machine's, a stick and the system's own left out by
/// the caller), and the core's checks follow ([`super::remove`]). Returns the id and the disk. A
/// disk that is not among `disks` (unplugged, dead) cannot be zeroed, and it is not kept for ever
/// in the state: its entry and key are forgotten, and no disk comes back (`take` is not called).
pub fn remove<'a, D: Dev, M: Mapper>(
    state: &Path,
    disks: &'a [Disk],
    id: &str,
    take: impl FnOnce(&Disk, &Id) -> Result<(D, M), String>,
) -> Result<(Id, Option<&'a Disk>), String> {
    let id = hex_id(id).ok_or("a disk's id is 32 lower-case hex digits: kith node disk list shows them")?;
    let entry = read_entry(&dir_of(state, &id)).ok_or("this node has no such disk")?;
    let found = || disks.iter().filter(|disk| disk.serial == entry.serial);
    let disk = match (found().next(), found().nth(1)) {
        (Some(disk), None) => disk,
        (None, _) => {
            // (A disk unplugged while mounted leaves its mount point busy: that stops the forget
            // before any key is erased, and the next start, with no mount, lets a second remove end it.)
            super::forget(state, &id).map_err(|e| {
                format!("forgetting the key of a disk that is not there: {e}. Restart the node, then remove it again")
            })?;
            return Ok((id, None));
        }
        (Some(_), Some(_)) => return Err(format!("more than one disk has the serial {}", entry.serial)),
    };
    let (dev, mut mapper) = take(disk, &id)?;
    let next = ". kith node disk list shows the disk's state: remove it again once that is put right";
    super::remove(state, &dev, &id, &entry.serial, &mut mapper).map_err(|e| format!("{e}{next}"))?;
    Ok((id, Some(disk)))
}

/// What the disks offered show of this node: the known (`mounted` is what asks whether kithd has
/// the disk of that kernel name mounted) and the unknown, as the status at start has them
/// ([`boot::status`]); the disks the state has an entry for that no disk showed are among the known.
/// Nothing is written, and a disk is read for its first 4 KiB only.
pub fn list<D: Dev>(
    state: &Path,
    disks: &[Disk],
    open: impl Fn(&Disk) -> Option<D>,
    mounted: impl Fn(&str) -> bool,
) -> Value {
    let mut seen: Vec<Seen> = disks
        .iter()
        .map(|disk| {
            let what = match open(disk) {
                None => What::Unreadable("its name is not one".into()),
                Some(dev) => boot::judge(state, &dev, &disk.serial, |_, _, _| {
                    if mounted(&disk.name) {
                        Ok(())
                    } else {
                        Err("not mounted: it is at the next start".into())
                    }
                }),
            };
            Seen {
                disk: disk.to_string(),
                what,
            }
        })
        .collect();
    seen.sort_by(|a, b| a.disk.cmp(&b.disk));
    let ids: Vec<Id> = seen.iter().filter_map(|one| boot::id_of(&one.what).copied()).collect();
    boot::status(&seen, &boot::missing(state, &ids))
}

/// One disk verb at a time, and not with the scan at start ([`boot::run`] waits its turn). A `list`
/// does not take it: it only reads.
static BUSY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

type Turn = tokio::sync::MutexGuard<'static, ()>;

fn one() -> Result<Turn, String> {
    BUSY.try_lock()
        .map_err(|_| "another disk verb is running (or the disks are being looked at at start): wait for it".into())
}

/// The scan at start's turn: it waits for a verb that is running, and a verb asked while it runs is told so.
pub async fn wait() -> Turn {
    BUSY.lock().await
}

/// The machine, as `init` finds it: the disks that may be offered, with what the core needs.
struct Machine {
    sys: &'static Path,
    verity: bool,
    ours: Option<String>,
    state_disk: Option<String>,
}

impl Machine {
    fn find() -> Machine {
        let (verity, ours, state_disk) = crate::init::whose_disks();
        Machine {
            sys: Path::new("/sys/block"),
            verity,
            ours,
            state_disk,
        }
    }

    /// Every disk the kernel shows (but the system's own, when it can be told), for the core's
    /// own refusals of the root and of a stick to be said.
    fn all(&self) -> Vec<Disk> {
        crate::install::disks(self.sys, self.ours.as_deref())
    }

    /// Those a data disk may be: the scan at start's own list.
    fn offered(&self) -> Vec<Disk> {
        boot::offered(self.verity, self.ours.as_deref(), self.state_disk.as_deref())
    }

    /// The disk the system runs from, as the core's fence takes it.
    fn root(&self) -> Option<Root> {
        let ours = if self.verity { &self.ours } else { &self.state_disk };
        Root::new(ours.as_deref().unwrap_or(""))
    }
}

/// A disk and the mapper over it, as the machine has them: for each, a handle of its own
/// (the mapper owns its handle). `at` is where it is mounted, if a remove is to unmount it first.
fn real(disk: &Disk, at: Option<PathBuf>) -> Result<(RealDisk, Real), String> {
    let name = "its name is not one a disk has";
    let dev = RealDisk::new(&disk.name, disk.removable).ok_or(name)?;
    let own = RealDisk::new(&disk.name, disk.removable).ok_or(name)?;
    Ok((dev, Real::new(own, at)))
}

/// What an add made, as the answer says it.
struct Added {
    id: Id,
    serial: String,
    disk: String,
    /// Mounted now, or why not (the add stands: it is mounted at the next start).
    mounted: Result<(), String>,
}

impl Added {
    fn json(&self) -> Value {
        let mut answer = json!({
            "id": crate::pki::hex(&self.id),
            "serial": self.serial,
            "disk": self.disk,
            "mounted": self.mounted.is_ok(),
        });
        if let Err(why) = &self.mounted {
            answer["why"] = format!("it is added, and will be mounted at the next start: {why}").into();
        }
        answer
    }
}

/// The add on this machine: what [`add`] does, then the mapping the add left is let go of and the
/// disk opened the way the start opens it (its key from the state, mounted at `disks/<id>/data`).
fn real_add(state: &Path, given: &Given) -> Result<Added, String> {
    let _one = one()?;
    let machine = Machine::find();
    let disks = machine.all();
    let (id, disk, mut mapper) = add(
        state,
        encrypted(machine.sys),
        &disks,
        machine.root().as_ref(),
        &given.serial,
        (given.wipe, given.quick),
        |disk| {
            let (dev, mapper) = real(disk, None)?;
            dev.unheld().map_err(|e| {
                format!(
                    "{} is held by something else (mounted, mapped or open): {e}. Let it go, or take the disk out, and add it again",
                    disk.name
                )
            })?;
            Ok((dev, mapper))
        },
    )?;
    let mounted = open_now(state, &id, disk, &mut mapper);
    Ok(Added {
        id,
        serial: disk.serial.clone(),
        disk: disk.name.clone(),
        mounted,
    })
}

fn open_now(state: &Path, id: &Id, disk: &Disk, mapper: &mut Real) -> Result<(), String> {
    mapper
        .unmap()
        .map_err(|e| format!("its mapping is not let go of: {e}"))?;
    let dir = dir_of(state, id);
    let key = read_key(&dir).ok_or("its key is not kept whole")?;
    let (dev, _) = real(disk, None)?;
    let at = dir.join("data");
    seed::open(&dev, &at, &key)?;
    boot::keep(&disk.name, &at);
    Ok(())
}

/// The remove on this machine: [`remove`], with the mount let go of first, then forgotten here.
/// The answer is the id and whether the disk was not there (only its entry and key were forgotten).
fn real_remove(state: &Path, id: &str) -> Result<(Id, bool), String> {
    let _one = one()?;
    let machine = Machine::find();
    let disks = machine.offered();
    let (id, disk) = remove(state, &disks, id, |disk, id| {
        real(disk, Some(dir_of(state, id).join("data")))
    })?;
    if let Some(disk) = disk {
        boot::forget_open(&disk.name);
    }
    Ok((id, disk.is_none()))
}

/// The serial the node kept for the disk `typed` (an id), if it is one and the node has it.
fn serial_of(state: &Path, typed: &str) -> Option<String> {
    let id = hex_id(typed)?;
    read_entry(&dir_of(state, &id)).map(|entry| entry.serial)
}

fn real_list(state: &Path) -> Value {
    let machine = Machine::find();
    list(
        state,
        &machine.offered(),
        |disk| RealDisk::new(&disk.name, disk.removable),
        boot::is_open,
    )
}

/// What `POST /v1/disks/{node}` is given.
#[derive(serde::Deserialize)]
pub struct Given {
    serial: String,
    #[serde(default)]
    wipe: bool,
    #[serde(default)]
    quick: bool,
}

/// Who may ask, for which node, on what machine: the state's directory, or the refusal to send.
/// A NodeKey's right is the one needed (as for the node's passphrase): the disk's key is the
/// node's. With a cluster, a disk is added by the node it is in: asking another is refused here
/// (the verb is not forwarded; the refusal is written to the audit log as `name`). With no cluster
/// there is one node, whatever it is called. The right asked is `verb` on a NodeKey: an add applies
/// one, a remove deletes one, a list gets them.
#[allow(clippy::result_large_err)] // the refusal is the answer itself, built once and returned
fn gate(shared: &Shared, caller: &Caller, node: &str, (verb, name): (Verb, &str)) -> Result<PathBuf, Response> {
    crate::api::permit(shared, caller, verb, |_| vec![("NodeKey".to_string(), None)])
        .map_err(IntoResponse::into_response)?;
    if let Some(cluster) = &shared.cluster
        && node != cluster.me.name
    {
        let why = format!(
            "a disk is added to the node it is in: ask {node} at its own API address (this node is {})",
            cluster.me.name
        );
        audit::misdirected(&shared.audit, caller, name, node, why.clone());
        return Err(refuse(StatusCode::CONFLICT, why).into_response());
    }
    if !crate::init::is_init() {
        return Err(refuse(
            StatusCode::CONFLICT,
            "only kith OS's kithd, running as the machine's init, adds a disk: a kithd started by hand has no business with the machine's disks",
        )
        .into_response());
    }
    shared
        .logs
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| refuse(StatusCode::CONFLICT, "kithd has no state directory").into_response())
}

/// `POST /v1/disks/{node}`: add the disk of the serial in the body (`wipe`, `quick`). It runs in a
/// task of its own, so a client that goes away does not cut it, and the audit is written when it ends.
pub async fn add_one(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Named(node): Named<String>,
    Json(given): Json<Given>,
) -> Response {
    let state = match gate(&shared, &caller, &node, (Verb::Apply, "disk add")) {
        Ok(state) => state,
        Err(refused) => return refused,
    };
    let task = tokio::spawn(async move {
        let flags = (given.wipe, given.quick);
        let serial = given.serial.clone();
        audit::adding(&shared.audit, &caller, &serial, flags);
        let done = tokio::task::spawn_blocking(move || real_add(&state, &given))
            .await
            .unwrap_or_else(|e| Err(format!("the add stopped: {e}")));
        audit::add(
            &shared.audit,
            &caller,
            &serial,
            flags,
            done.as_ref().map(|added| added.id).map_err(String::clone),
        );
        done
    });
    match task.await {
        Ok(Ok(added)) => Json(added.json()).into_response(),
        Ok(Err(why)) => refuse(StatusCode::CONFLICT, why).into_response(),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, format!("the add stopped: {e}")).into_response(),
    }
}

/// `DELETE /v1/disks/{node}/{id}`: remove the disk `id`.
pub async fn remove_one(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Named((node, id)): Named<(String, String)>,
) -> Response {
    let state = match gate(&shared, &caller, &node, (Verb::Delete, "disk remove")) {
        Ok(state) => state,
        Err(refused) => return refused,
    };
    let task = tokio::spawn(async move {
        let typed = id.clone();
        let serial = serial_of(&state, &typed);
        audit::removing(&shared.audit, &caller, &typed, serial.as_deref());
        let done = tokio::task::spawn_blocking(move || real_remove(&state, &id))
            .await
            .unwrap_or_else(|e| Err(format!("the remove stopped: {e}")));
        audit::remove(
            &shared.audit,
            &caller,
            &typed,
            serial.as_deref(),
            done.as_ref().map(drop).map_err(String::clone),
        );
        done
    });
    match task.await {
        Ok(Ok((id, absent))) => {
            Json(json!({ "id": crate::pki::hex(&id), "removed": true, "absent": absent })).into_response()
        }
        Ok(Err(why)) => refuse(StatusCode::CONFLICT, why).into_response(),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, format!("the remove stopped: {e}")).into_response(),
    }
}

/// `GET /v1/disks/{node}`: the disks, known and unknown.
pub async fn list_all(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Named(node): Named<String>,
) -> Response {
    let state = match gate(&shared, &caller, &node, (Verb::Get, "disk list")) {
        Ok(state) => state,
        Err(refused) => return refused,
    };
    match tokio::task::spawn_blocking(move || real_list(&state)).await {
        Ok(shown) => Json(shown).into_response(),
        Err(e) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("looking at the disks stopped: {e}"),
        )
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::support::*;
    use super::super::*;
    use super::*;
    // (The core's own `add` and `remove` are in `super::super::*` too: these are the verbs'.)
    use super::{add, remove};

    fn disk(name: &str, serial: &str) -> Disk {
        Disk {
            name: name.into(),
            bytes: 1 << 20,
            model: String::new(),
            serial: serial.into(),
            removable: false,
        }
    }

    /// The system's own disk (`sda`) and the file's (`sdb`, serial `S1`).
    fn machine() -> [Disk; 2] {
        [disk("sda", "R0"), disk("sdb", "S1")]
    }

    /// Another handle on the disk file: the disk and the mapper `take` gives.
    fn again(disk: &Fake) -> (Fake, Map) {
        (Fake(disk.0.try_clone().unwrap(), disk.1, disk.2), Map::new(disk))
    }

    fn bytes(disk: &Fake) -> Vec<u8> {
        let mut all = vec![0; 1 << 20];
        disk.0.read_exact_at(&mut all, 0).unwrap();
        all
    }

    /// One node with no cluster: the state is a directory, the verbs are these functions.
    #[test]
    fn a_node_with_no_cluster_adds_lists_and_removes_a_disk() {
        let (_dir, file, state) = rig("verbs-flow");
        let disks = machine();
        let (id, found, _) = add(&state, true, &disks, Some(&root("sda")), "S1", (false, false), |_| {
            Ok(again(&file))
        })
        .unwrap();
        assert_eq!(found.name, "sdb");
        assert_eq!(parse(&room(&file)), Ok(id));
        assert!(read_entry(&dir_of(&state, &id)).unwrap().ready);

        let shown = list(&state, &disks[1..], |_| Some(again(&file).0), |name| name == "sdb");
        assert_eq!(shown["known"][0]["id"], crate::pki::hex(&id));
        assert_eq!(shown["known"][0]["state"], "mounted");
        assert_eq!(shown["unknown"], json!([]));

        let (gone, at) = remove(&state, &disks, &crate::pki::hex(&id), |_, _| Ok(again(&file))).unwrap();
        assert_eq!((gone, at.unwrap().name.as_str()), (id, "sdb"));
        assert!(room(&file).iter().all(|&byte| byte == 0), "its header is zeroed");
        assert!(ids(&state).is_empty(), "its key and entry are forgotten");

        let shown = list(&state, &disks[1..], |_| Some(again(&file).0), |_| false);
        assert_eq!(shown["known"], json!([]));
        assert_eq!(shown["unknown"][0]["state"], "not ours");
    }

    #[test]
    fn a_known_disk_that_is_not_mounted_is_listed_so() {
        let (_dir, file, state) = rig("verbs-unmounted");
        let disks = machine();
        add(&state, true, &disks, Some(&root("sda")), "S1", (false, false), |_| {
            Ok(again(&file))
        })
        .unwrap();
        let shown = list(&state, &disks[1..], |_| Some(again(&file).0), |_| false);
        assert_eq!(shown["known"][0]["state"], "failed");
    }

    #[test]
    fn a_disk_with_a_signature_is_refused_and_left_as_it_was() {
        let (_dir, file, state) = rig("verbs-signature");
        file.0.write_all_at(b"EFI PART", 512).unwrap();
        let before = bytes(&file);
        let disks = machine();
        let (flags, root) = ((false, false), root("sda"));
        let why = add(&state, true, &disks, Some(&root), "S1", flags, |_| Ok(again(&file))).unwrap_err();
        assert!(why.contains("a GPT") && why.contains("--wipe"), "{why}");
        assert_eq!(bytes(&file), before);
        assert!(!state.join("disks").exists(), "nothing was kept for a refused disk");
        // The one who says so may pass what the disk holds: not which disk it is.
        add(&state, true, &disks, Some(&root), "S1", (true, false), |_| {
            Ok(again(&file))
        })
        .unwrap();
        assert!(
            read_entry(&dir_of(&state, &parse(&room(&file)).unwrap()))
                .unwrap()
                .ready
        );
    }

    #[test]
    fn a_disk_that_is_not_empty_is_refused_without_wipe() {
        let (_dir, file, state) = rig("verbs-not-empty");
        file.0.write_all_at(b"data", 100).unwrap();
        let disks = machine();
        let why = add(&state, true, &disks, Some(&root("sda")), "S1", (false, false), |_| {
            Ok(again(&file))
        })
        .unwrap_err();
        assert!(why.contains("not zero") && why.contains("--wipe"), "{why}");
    }

    #[test]
    fn wipe_passes_neither_the_system_s_disk_nor_a_stick() {
        let (_dir, file, state) = rig("verbs-fence");
        let disks = machine();
        let wipe = (true, false);
        let why = add(&state, true, &disks, Some(&root("sdb")), "S1", wipe, |_| {
            Ok(again(&file))
        })
        .unwrap_err();
        assert!(why.contains("runs from"), "{why}");
        // (And with the system's disk not known: every disk is refused.)
        let why = add(&state, true, &disks, None, "S1", wipe, |_| Ok(again(&file))).unwrap_err();
        assert!(why.contains("runs from"), "{why}");
        let stick = |disk: &Fake| (Fake(disk.0.try_clone().unwrap(), "sdb", true), Map::new(disk));
        let why = add(&state, true, &disks, Some(&root("sda")), "S1", wipe, |_| {
            Ok(stick(&file))
        })
        .unwrap_err();
        assert!(why.contains("removable"), "{why}");
        assert!(!state.join("disks").exists());
    }

    #[test]
    fn an_unencrypted_state_is_refused_before_any_disk_is_touched() {
        let (_dir, _file, state) = rig("verbs-plain");
        let disks = machine();
        let took = |_: &Disk| -> Result<(Fake, Map), String> { panic!("the disk was taken") };
        let why = add(&state, false, &disks, Some(&root("sda")), "S1", (false, false), took).unwrap_err();
        assert!(why.contains("not encrypted"), "{why}");
    }

    #[test]
    fn a_disk_is_named_by_one_serial_and_by_nothing_else() {
        let disks = [disk("sda", "R0"), disk("sdb", "S1"), disk("sdc", ""), disk("sdd", "S1")];
        assert_eq!(pick(&disks, "R0").unwrap().name, "sda");
        assert_eq!(
            pick(&disks, "  R0\n").unwrap().name,
            "sda",
            "blanks at its ends are not it"
        );
        for typed in ["", "  ", "nope", "r0", "sdb"] {
            let why = pick(&disks, typed).unwrap_err();
            assert!(
                why.contains("Disks seen: sda (0.0 GB, serial R0); sdb"),
                "{typed:?}: {why}"
            );
        }
        // Two disks of one serial are neither: the owner is told, and nothing is guessed.
        assert!(pick(&disks, "S1").unwrap_err().contains("more than one"));
        // (A disk with no serial cannot be named: there is no serial to type.)
        assert!(pick(&disks[2..3], "").is_err());
    }

    #[test]
    fn the_disk_nobody_named_is_not_written() {
        let (_dir, file, state) = rig("verbs-named");
        let (_other_dir, other) = {
            let (dir, other, _) = rig("verbs-other");
            (dir, other)
        };
        other.0.write_all_at(b"someone else's data", 0).unwrap();
        let before = bytes(&other);
        let disks = [disk("sda", "R0"), disk("sdb", "S1"), disk("sdc", "S2")];
        add(
            &state,
            true,
            &disks,
            Some(&root("sda")),
            "S1",
            (false, false),
            |taken| {
                assert_eq!(taken.name, "sdb");
                Ok(again(&file))
            },
        )
        .unwrap();
        assert_eq!(bytes(&other), before);
        // An empty serial never reaches a disk.
        assert!(
            add(&state, true, &disks, Some(&root("sda")), " ", (false, true), |_| Ok(
                again(&other)
            ))
            .is_err()
        );
        assert_eq!(bytes(&other), before);
    }

    #[test]
    fn a_disk_already_added_is_not_added_again() {
        let (_dir, file, state) = rig("verbs-twice");
        let disks = machine();
        let first = add(&state, true, &disks, Some(&root("sda")), "S1", (false, false), |_| {
            Ok(again(&file))
        });
        let id = first.unwrap().0;
        let why = add(&state, true, &disks, Some(&root("sda")), "S1", (true, false), |_| {
            Ok(again(&file))
        })
        .unwrap_err();
        assert!(why.contains("already"), "{why}");
        assert_eq!(
            parse(&room(&file)),
            Ok(id),
            "even with --wipe, a disk of this node's is kept"
        );
    }

    #[test]
    fn a_remove_is_refused_for_a_wrong_id_a_disk_not_there_and_a_mapping_in_use() {
        let (_dir, file, state) = rig("verbs-remove");
        let disks = machine();
        let id = add(&state, true, &disks, Some(&root("sda")), "S1", (false, false), |_| {
            Ok(again(&file))
        })
        .unwrap()
        .0;
        let hex = crate::pki::hex(&id);
        let refused = |disks: &[Disk], typed: &str, fail: Option<&'static str>| {
            remove(&state, disks, typed, |_, _| {
                let (disk, mut map) = again(&file);
                map.fail = fail;
                Ok((disk, map))
            })
            .unwrap_err()
        };
        assert!(refused(&disks, "not an id", None).contains("32 lower-case hex"));
        assert!(refused(&disks, &hex.to_uppercase(), None).contains("32 lower-case hex"));
        assert!(refused(&disks, &"0".repeat(32), None).contains("no such disk"));
        assert!(refused(&disks, &hex, Some("unmap")).contains("in use"));
        // Each left it whole: the header, the key and the entry.
        assert_eq!(parse(&room(&file)), Ok(id));
        assert!(read_entry(&dir_of(&state, &id)).unwrap().ready && read_key(&dir_of(&state, &id)).is_some());
    }

    /// A disk that is gone (unplugged, dead) cannot be zeroed: the remove forgets what the node kept
    /// of it, so the entry and the key are not left for good, and says the disk was not there.
    #[test]
    fn a_remove_of_a_disk_that_is_not_there_forgets_its_entry_and_key() {
        let (_dir, file, state) = rig("verbs-remove-gone");
        let disks = machine();
        let id = add(&state, true, &disks, Some(&root("sda")), "S1", (false, false), |_| {
            Ok(again(&file))
        })
        .unwrap()
        .0;
        let took = |_: &Disk, _: &Id| -> Result<(Fake, Map), String> { panic!("a disk that is not there was taken") };
        let (gone, at) = remove(&state, &disks[..1], &crate::pki::hex(&id), took).unwrap();
        assert_eq!((gone, at.is_none()), (id, true));
        assert!(ids(&state).is_empty(), "its key and entry are forgotten");
        // (A second remove finds nothing: it is done.)
        let again_ = remove(&state, &disks[..1], &crate::pki::hex(&id), took).unwrap_err();
        assert!(again_.contains("no such disk"), "{again_}");
    }

    /// A disk this node has added, added again: told so before the disk is touched (taken it
    /// would be held by the mapping, and the owner would be told it is "held by something else").
    #[test]
    fn an_add_of_a_disk_that_is_already_added_says_so_before_the_disk_is_taken() {
        let (_dir, file, state) = rig("verbs-added");
        let disks = machine();
        add(&state, true, &disks, Some(&root("sda")), "S1", (false, false), |_| {
            Ok(again(&file))
        })
        .unwrap();
        let took = |_: &Disk| -> Result<(Fake, Map), String> { panic!("the disk was taken") };
        let why = add(&state, true, &disks, Some(&root("sda")), "S1", (true, false), took).unwrap_err();
        assert!(
            why.contains("already added") && why.contains("kith node disk list"),
            "{why}"
        );
    }

    /// Each way an add can end without the disk added tells the owner what to do next.
    #[test]
    fn a_failed_add_names_what_to_do_next() {
        let d = disk("sdb", "S1");
        let failed = said(AddError::Failed("the disk did not answer".into()), &d, false);
        assert!(
            failed.contains("Add it again") && failed.contains("kith node disk list") && failed.contains("cable"),
            "{failed}"
        );
        assert!(said(AddError::Half("x".into()), &d, false).contains("--wipe"));
        assert!(said(AddError::Added, &d, false).contains("already added"));
    }

    #[test]
    fn the_state_is_encrypted_when_a_kith_state_mapping_is_there() {
        let (dir, _file, _state) = rig("verbs-sys");
        let sys = dir.path().join("sys");
        let mapping = |device: &str, name: &str| {
            let at = sys.join(device).join("dm");
            std::fs::create_dir_all(&at).unwrap();
            std::fs::write(at.join("name"), format!("{name}\n")).unwrap();
        };
        assert!(!encrypted(&sys), "no sysfs, no mapping");
        std::fs::create_dir_all(sys.join("sda")).unwrap();
        mapping("dm-0", "kith-disk-sdb");
        assert!(!encrypted(&sys), "a data disk's mapping is not the state's");
        mapping("dm-1", "kith-state");
        assert!(encrypted(&sys));
    }

    /// The local socket's admin, with no cluster and an empty store, may apply a NodeKey: the
    /// right a disk verb is asked for (`gate`), so a node alone can add its disk.
    #[test]
    fn the_sockets_admin_may_apply_a_node_key_with_no_cluster() {
        let grants = crate::access::Grants::of(&Caller::Admin, &kith_api::store::Store::default());
        assert!(grants.may(&Verb::Apply, "NodeKey", None) && grants.may(&Verb::Get, "NodeKey", None));
        assert!(grants.may(&Verb::Delete, "NodeKey", None), "a remove is a delete");
        // (Someone else is not: no Identity is no right.)
        let nobody = crate::access::Grants::of(&Caller::Identity("nobody".into()), &kith_api::store::Store::default());
        assert!(!nobody.may(&Verb::Apply, "NodeKey", None));
    }

    /// A claimed Identity (what `kith --server` and the VM test are) reaches the verbs' paths over
    /// TLS; they are then decided by its grants on a NodeKey (`gate`), not by the path.
    #[test]
    fn an_identity_reaches_the_verbs_paths() {
        let reaches = crate::access::for_identities;
        assert!(reaches("/v1/disks/n1") && reaches("/v1/disks/n1/0123"));
        assert!(!reaches("/v1/disksx/n1"));
    }
}
