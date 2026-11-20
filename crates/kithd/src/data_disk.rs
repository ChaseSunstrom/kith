//! A second disk for a node's data (docs/adr-second-disk.md, sections 1 and 2), the part a file
//! can show: the 4 KiB plain header that says a disk is a kith data disk, the disk's own random
//! key, and the refusal of a disk that is anyone else's.
//!
//! Nothing here maps, mounts or writes a disk on its own: `write_header` is the one write, it
//! needs the [`Clear`] that [`refuse`] gives for that disk, and the order it comes in (last,
//! after the mapping) is the add's, not this file's. Nothing here reads more than a disk's
//! first 4 KiB.
//!
//! The add's order of writes ([`add`]), what a disk is to this node ([`standing`], [`off_ours`])
//! and the remove ([`remove`]) are here too; the mapping step is the [`Mapper`] trait, so a file
//! and a fake show every cut of the order. The real mapper and the mount are [`seed`], the task
//! that mounts the known disks after the state opens is [`boot`]; the verbs (`kith node disk add`,
//! `remove`, `list`) are [`verbs`], and what they tell the audit log is [`audit`].

pub mod audit;
pub mod boot;
pub mod seed;
pub mod verbs;

use ring::digest;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The room of the header at the start of the disk; the mapping begins after it (8 sectors).
pub const ROOM: usize = 4096;
const FIRST: &str = "kith-disk v1";

/// A disk's id: 16 random bytes, 32 hex digits in the header.
pub type Id = [u8; 16];

pub fn new_id() -> Id {
    crate::crypt::random::<16>()
}

/// What a header says of `id`, no padding: the line, the id, and the SHA-256 of both in hex.
fn text(id: &Id) -> String {
    let body = format!("{FIRST}\nid: {}\n", crate::pki::hex(id));
    let sum = digest::digest(&digest::SHA256, body.as_bytes());
    format!("{body}sum: {}\n", crate::pki::hex(sum.as_ref()))
}

/// The 4 KiB of the header of `id`: its text, the rest of the room zero.
fn room_of(id: &Id) -> [u8; ROOM] {
    let mut room = [0u8; ROOM];
    let text = text(id);
    room[..text.len()].copy_from_slice(text.as_bytes());
    room
}

/// Write the header for `id` over the first 4 KiB of the disk `refuse` cleared, and sync it.
/// A disk that was not cleared has no `Clear`, so it cannot be written to here.
pub fn write_header(clear: &Clear<impl Dev>, id: &Id) -> io::Result<()> {
    clear.0.write_first(&room_of(id))
}

/// The id of the header at the start of `file`, or why there is none. Strict: the header is
/// taken only when it is, byte for byte, what [`write_header`] writes for the id it names
/// (a sum that is wrong, a byte of the room that is not zero, an upper-case digit all fail).
#[allow(dead_code)] // the tests read a file with it; the boot and the verbs have the 4 KiB already and call `parse`
pub fn read_header(file: &File) -> Result<Id, String> {
    let mut room = [0u8; ROOM];
    file.read_exact_at(&mut room, 0)
        .map_err(|e| format!("reading the first 4 KiB: {e}"))?;
    parse(&room)
}

/// [`read_header`] on the 4 KiB already read.
fn parse(room: &[u8; ROOM]) -> Result<Id, String> {
    if !room.starts_with(FIRST.as_bytes()) {
        return Err("no kith-disk header".into());
    }
    let end = room.iter().position(|&byte| byte == 0).unwrap_or(ROOM);
    let said = std::str::from_utf8(&room[..end]).map_err(|_| "the header is not text")?;
    let id = said
        .lines()
        .nth(1)
        .and_then(|line| line.strip_prefix("id: "))
        .and_then(hex_id)
        .ok_or("the header's id cannot be read")?;
    if said != text(&id) || room[end..].iter().any(|&byte| byte != 0) {
        return Err("the header's sum is wrong, or it is damaged".into());
    }
    Ok(id)
}

/// 32 lower-case hex digits, and nothing else.
fn hex_id(digits: &str) -> Option<Id> {
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let (pairs, rest) = digits.as_bytes().as_chunks::<2>();
    if pairs.len() != 16 || !rest.is_empty() {
        return None;
    }
    let mut id = [0; 16];
    for (out, [high, low]) in id.iter_mut().zip(pairs) {
        *out = digit(*high)? << 4 | digit(*low)?;
    }
    Some(id)
}

/// What a disk is to the checks that decide whether it may be taken. A disk on a stick of the
/// installer, a file in a test, and a block device implement it alike.
pub trait Dev {
    fn name(&self) -> &str;
    /// A stick or a card reader (`install::Disk::removable`).
    fn removable(&self) -> bool;
    /// Its first 4 KiB, no more; an error when it has fewer.
    fn first(&self) -> io::Result<[u8; ROOM]>;
    /// Write `room` over its first 4 KiB and sync it. Only [`write_header`] calls it.
    fn write_first(&self, room: &[u8; ROOM]) -> io::Result<()>;
}

/// The kernel name of the whole disk the system runs from (`sda`, `nvme0n1`, `vda`), never one
/// of its partitions (`sda2`, `nvme0n1p2`) or a mapping (`dm-0`): `refuse` compares it with a
/// disk's name, so a partition's name would match no disk and offer the root. The caller
/// resolves a partition to its parent disk (as `init::booted` does) before it makes one; an
/// empty name or one with a `/` is none, and `refuse` with no `Root` refuses every disk.
#[derive(Debug, PartialEq)]
pub struct Root(String);

impl Root {
    pub fn new(name: &str) -> Option<Root> {
        (!name.is_empty() && !name.contains('/')).then(|| Root(name.to_string()))
    }
}

/// A disk `refuse` looked at and found takeable: the one witness `write_header` takes.
#[derive(Debug)]
pub struct Clear<'a, D: Dev>(&'a D);

/// Why a disk is not taken. `Root` and `Removable` are final; `Signature` and `NotEmpty` are
/// the two a `--wipe` may pass ([`Refused::wipeable`]), and `Unreadable` is a disk that cannot
/// be looked at.
#[derive(Debug, PartialEq)]
pub enum Refused {
    Root,
    Removable,
    Signature(&'static str),
    NotEmpty,
    Unreadable(String),
}

impl Refused {
    /// Whether a `--wipe` may go on past this: only what the disk holds, never which disk it is.
    pub fn wipeable(&self) -> bool {
        matches!(self, Refused::Signature(_) | Refused::NotEmpty)
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Refused::Root => f.write_str("it is the disk this system runs from, or that cannot be told"),
            Refused::Removable => f.write_str("it is removable (a stick or a card reader)"),
            Refused::Signature(what) => write!(f, "it holds {what}"),
            Refused::NotEmpty => f.write_str("its first 4 KiB are not zero"),
            Refused::Unreadable(why) => write!(f, "its first 4 KiB cannot be read: {why}"),
        }
    }
}

/// Where each thing a disk may hold says so, in its first 4 KiB: the kith header's own
/// (so a disk already made one is named, and not just "not empty"), a LUKS header, a GPT
/// (after its protective MBR), an MBR, and ext4's superblock.
const SIGNATURES: [(usize, &[u8], &str); 5] = [
    (0, FIRST.as_bytes(), "a kith-disk header"),
    (0, b"LUKS\xba\xbe", "a LUKS header"),
    (512, b"EFI PART", "a GPT"),
    (510, &[0x55, 0xaa], "an MBR"),
    (1080, &[0x53, 0xef], "an ext4 file system"),
];

/// The two refusals no `--wipe` passes: which disk it is.
fn fence(disk: &impl Dev, root: Option<&Root>) -> Result<(), Refused> {
    if disk.name().is_empty() || root.is_none_or(|root| root.0 == disk.name()) {
        return Err(Refused::Root);
    }
    if disk.removable() {
        return Err(Refused::Removable);
    }
    Ok(())
}

/// Whether `disk` may be made a data disk, and if so the [`Clear`] to write its header with.
/// `root` is the disk the system runs from, `None` when that cannot be told: then every disk
/// is refused (it fails closed, as the state's own fence does, `init::on_ours`), and so is one
/// that names itself nothing. The root disk and a removable disk come first, since no
/// `--wipe` passes them; then what its first 4 KiB say.
///
/// **What passes as empty:** only the first 4 KiB are read (the ADR's rule), so a signature
/// further in passes: an md 1.2 or a bcachefs superblock (at 4 KiB), a btrfs one (at 64 KiB),
/// ZFS labels, or a GPT whose only copy is the backup at the disk's end. The overwrite of the
/// whole mapping at `add` (ADR section 1), not this check, is what destroys them.
pub fn refuse<'a, D: Dev>(disk: &'a D, root: Option<&Root>) -> Result<Clear<'a, D>, Refused> {
    fence(disk, root)?;
    let room = disk.first().map_err(|e| Refused::Unreadable(e.to_string()))?;
    if let Some((_, _, what)) = SIGNATURES.iter().find(|(at, magic, _)| room[*at..].starts_with(magic)) {
        return Err(Refused::Signature(what));
    }
    if room.iter().any(|&byte| byte != 0) {
        return Err(Refused::NotEmpty);
    }
    Ok(Clear(disk))
}

/// A new aes-xts-plain64 key for a disk: 64 random bytes, the disk's own (docs/adr-second-disk.md,
/// section 1). It is derived from nothing, so the state's key and a header's id cannot draw it
/// again once the copy kept in the state is gone: that is what makes remove an erase. Keeping
/// it (`disks/<id>/key`, synced) before anything uses it is the add's order, not this function's.
pub fn new_key() -> zeroize::Zeroizing<[u8; 64]> {
    zeroize::Zeroizing::new(crate::crypt::random::<64>())
}

/// What a disk is to this node, from its first 4 KiB and the state's `disks/`: `Ours` has a
/// header whose sum is right and an id whose entry is `ready`; `Unknown` is everything else that
/// is not a damaged kith header (no header, another's id, a `pending` entry, an empty disk);
/// `Damaged` starts as a kith header and is not one (a wrong sum, a byte out of place).
/// Nothing is written, and nothing but the 4 KiB it is given is looked at.
#[derive(Debug, PartialEq)]
pub enum Standing {
    Ours(Id),
    Unknown,
    Damaged(String),
}

pub fn standing(state: &Path, room: &[u8; ROOM]) -> Standing {
    match parse(room) {
        Ok(id) if read_entry(&dir_of(state, &id)).is_some_and(|entry| entry.ready) => Standing::Ours(id),
        Ok(_) => Standing::Unknown,
        Err(why) if room.starts_with(FIRST.as_bytes()) => Standing::Damaged(why),
        Err(_) => Standing::Unknown,
    }
}

/// Whether the disk `disk` may be offered as a data disk (ADR section 2, and the only place
/// that decides it). With a verity root, the disk it is read from is `ours`: every other is
/// offered, and none when `ours` cannot be read. With none, `state_disk` (the disk of the
/// partition `init::labelled("state")` finds) is ours, and none is offered when there is none.
/// A disk that names itself nothing is never offered.
pub fn off_ours(verity: bool, ours: Option<&str>, state_disk: Option<&str>, disk: &str) -> bool {
    let ours = if verity { ours } else { state_disk };
    // A name that is empty or a path is no disk's: fail closed, as `Root::new` does.
    !disk.is_empty() && ours.is_some_and(|ours| !ours.is_empty() && !ours.contains('/') && ours != disk)
}

/// The mapping of a data disk, the part that needs root and device-mapper (T-0958). `add` and
/// `remove` take it as a trait, so a file and a fake show every point of the order.
pub trait Mapper {
    /// Map the disk from its sector 8 under `key`.
    fn map(&mut self, key: &[u8; 64]) -> io::Result<()>;
    /// Write zeros through the whole mapping, or discard the disk (`quick`).
    fn zero(&mut self, quick: bool) -> io::Result<()>;
    /// Write the seed file system and grow it to the disk's size.
    fn seed(&mut self) -> io::Result<()>;
    /// Whether the file system in the open mapping answers (the resume's check).
    fn answers(&mut self) -> io::Result<bool>;
    /// Remove the mapping; an error while it is in use. A mapping that is not there is `Ok`
    /// (or `NotFound`, which `remove` also takes as done): a node restarted after a cut has none.
    fn unmap(&mut self) -> io::Result<()>;
}

const ENTRY: &str = "kith-disk-entry v1";

/// What the state knows of a disk: the serial it was added by, and whether the add finished.
#[derive(Debug, PartialEq)]
struct Entry {
    serial: String,
    ready: bool,
}

fn dir_of(state: &Path, id: &Id) -> PathBuf {
    state.join("disks").join(crate::pki::hex(id))
}

fn read_entry(dir: &Path) -> Option<Entry> {
    let mut text = String::new();
    File::open(dir.join("entry"))
        .ok()?
        .take(1024)
        .read_to_string(&mut text)
        .ok()?;
    let mut lines = text.lines();
    (lines.next()? == ENTRY).then_some(())?;
    let ready = match lines.next()?.strip_prefix("state: ")? {
        "ready" => true,
        "pending" => false,
        _ => return None,
    };
    let serial = lines.next()?.strip_prefix("serial: ")?.to_string();
    lines.next().is_none().then_some(Entry { serial, ready })
}

fn entry_text(serial: &str, ready: bool) -> String {
    format!(
        "{ENTRY}\nstate: {}\nserial: {serial}\n",
        if ready { "ready" } else { "pending" }
    )
}

/// The kept key, when it is whole.
fn read_key(dir: &Path) -> Option<Zeroizing<[u8; 64]>> {
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(dir.join("key"))
        .ok()?
        .take(65)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(Zeroizing::new(bytes.as_slice().try_into().ok()?))
}

/// `dir/name` holds `bytes` whole or as it was, and the directory entry is synced.
fn put_file(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, dir.join(name))?;
    File::open(dir)?.sync_all()
}

/// Every file in `dir` has its bytes overwritten with zeros, synced and removed, the `entry`
/// LAST (the key, and a key left in a cut write's `.key.tmp`, go first: a cut in between leaves
/// an entry that a second remove still finds and finishes), then the `data` mount point and
/// the directory.
fn forget(state: &Path, id: &Id) -> io::Result<()> {
    let dir = dir_of(state, id);
    let mut paths = Vec::new();
    for item in std::fs::read_dir(&dir)? {
        paths.push(item?.path());
    }
    // The mount point first (a busy one stops before any key is erased), the entry last.
    paths.sort_by_key(|path| (!path.is_dir(), path.file_name().is_some_and(|name| name == "entry")));
    for path in paths {
        if path.is_dir() {
            std::fs::remove_dir(&path)?;
        } else {
            let file = std::fs::OpenOptions::new().write(true).open(&path)?;
            file.write_all_at(&vec![0; file.metadata()?.len() as usize], 0)?;
            file.sync_all()?;
            std::fs::remove_file(&path)?;
        }
    }
    std::fs::remove_dir(&dir)?;
    File::open(dir.parent().unwrap_or(state))?.sync_all()
}

/// The points of an add, each reached just before its step: a cut is a stop at one of them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Point {
    Pending,
    Key,
    Map,
    Zero,
    Seed,
    Header,
    Ready,
}

#[derive(Debug, PartialEq)]
pub enum AddError {
    /// The disk is not taken; some of these a `--wipe` passes ([`Refused::wipeable`]).
    Refused(Refused),
    /// It is this node's disk already (a header and a `ready` entry).
    Added,
    /// It has this add's header, but its file system does not answer: `--wipe` starts over.
    Half(String),
    Failed(String),
}

impl From<io::Error> for AddError {
    fn from(e: io::Error) -> Self {
        AddError::Failed(e.to_string())
    }
}

/// A serial is what the owner typed, and goes into a line of the entry: printable, no space at
/// its ends, no newline.
fn serial_ok(serial: &str) -> bool {
    !serial.is_empty()
        && serial.len() <= 128
        && serial.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        && serial.trim() == serial
}

/// Add `disk` as a data disk of this node's `state`, in the ADR's order, each step surviving a
/// cut: the entry `pending`, the key kept and synced, the mapping, the zeros through it, the seed,
/// the header last, the entry `ready`. The disk's first 4 KiB stay zero until the header. A disk
/// that holds the header of this add (its id a `pending` entry of this `serial`) is resumed: it
/// is mapped with the kept key and, if its file system answers, marked `ready`. `serial` is the
/// one typed and matched with the disk's by the caller (the code that runs this, the verbs of T-0958: no
/// `Dev` reports a serial, so it is not checked here). An unknown disk is not written unless
/// `wipe` is said and what refuses it is [`Refused::wipeable`]. Leaves the mapping open.
pub fn add<D: Dev>(
    state: &Path,
    disk: &D,
    root: Option<&Root>,
    serial: &str,
    (wipe, quick): (bool, bool),
    mapper: &mut impl Mapper,
) -> Result<Id, AddError> {
    add_with(state, disk, root, serial, (wipe, quick), mapper, &mut |_| Ok(()))
}

fn add_with<D: Dev>(
    state: &Path,
    disk: &D,
    root: Option<&Root>,
    serial: &str,
    (wipe, quick): (bool, bool),
    mapper: &mut impl Mapper,
    hit: &mut dyn FnMut(Point) -> io::Result<()>,
) -> Result<Id, AddError> {
    if !serial_ok(serial) {
        return Err(AddError::Failed("a disk with no usable serial is not added".into()));
    }
    fence(disk, root).map_err(AddError::Refused)?;
    let room = disk
        .first()
        .map_err(|e| AddError::Refused(Refused::Unreadable(e.to_string())))?;
    if let Ok(id) = parse(&room) {
        match read_entry(&dir_of(state, &id)) {
            Some(Entry { ready: true, .. }) => return Err(AddError::Added),
            Some(Entry { serial: said, .. }) if said == serial => match resume(state, &id, mapper, hit) {
                Err(AddError::Half(_)) if wipe => forget(state, &id)?,
                done => return done.map(|()| id),
            },
            _ => {}
        }
    }
    let clear = match refuse(disk, root) {
        Ok(clear) => clear,
        Err(refused) if wipe && refused.wipeable() => {
            disk.write_first(&[0; ROOM])?;
            refuse(disk, root).map_err(AddError::Refused)?
        }
        Err(refused) => return Err(AddError::Refused(refused)),
    };
    let result = fresh(state, &clear, serial, quick, mapper, hit);
    if result.is_err() {
        let _ = mapper.unmap();
    }
    result
}

/// The disk that has this add's header: map it, and mark `ready` if its file system answers;
/// a failure leaves it unmapped.
fn resume(
    state: &Path,
    id: &Id,
    mapper: &mut impl Mapper,
    hit: &mut dyn FnMut(Point) -> io::Result<()>,
) -> Result<(), AddError> {
    let done = resume_mapped(state, id, mapper, hit);
    if done.is_err() {
        let _ = mapper.unmap();
    }
    done
}

fn resume_mapped(
    state: &Path,
    id: &Id,
    mapper: &mut impl Mapper,
    hit: &mut dyn FnMut(Point) -> io::Result<()>,
) -> Result<(), AddError> {
    let dir = dir_of(state, id);
    let key = read_key(&dir).ok_or_else(|| AddError::Half("its key is not kept".into()))?;
    mapper.map(&key)?;
    // An error is not "does not answer": a `--wipe` must not discard a key over a failed read.
    if !mapper.answers()? {
        return Err(AddError::Half("its file system does not answer".into()));
    }
    hit(Point::Ready)?;
    let serial = read_entry(&dir).map(|entry| entry.serial).unwrap_or_default();
    Ok(put_file(&dir, "entry", entry_text(&serial, true).as_bytes())?)
}

fn fresh<D: Dev>(
    state: &Path,
    clear: &Clear<D>,
    serial: &str,
    quick: bool,
    mapper: &mut impl Mapper,
    hit: &mut dyn FnMut(Point) -> io::Result<()>,
) -> Result<Id, AddError> {
    // A `pending` entry of this serial that no header followed is taken again, not left behind.
    let id = pending_of(state, serial).unwrap_or_else(new_id);
    let dir = dir_of(state, &id);
    hit(Point::Pending)?;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    put_file(&dir, "entry", entry_text(serial, false).as_bytes())?;
    File::open(dir.parent().unwrap_or(state))?.sync_all()?;
    hit(Point::Key)?;
    let key = match read_key(&dir) {
        Some(key) => key,
        None => {
            let key = new_key();
            put_file(&dir, "key", &*key)?;
            key
        }
    };
    hit(Point::Map)?;
    mapper.map(&key)?;
    hit(Point::Zero)?;
    mapper.zero(quick)?;
    hit(Point::Seed)?;
    mapper.seed()?;
    hit(Point::Header)?;
    write_header(clear, &id)?;
    hit(Point::Ready)?;
    put_file(&dir, "entry", entry_text(serial, true).as_bytes())?;
    Ok(id)
}

/// The id of a `pending` entry of `serial`, the first by id when there are several.
fn pending_of(state: &Path, serial: &str) -> Option<Id> {
    let mut found: Vec<Id> = std::fs::read_dir(state.join("disks"))
        .ok()?
        .filter_map(|item| {
            let item = item.ok()?;
            let id = hex_id(item.file_name().to_str()?)?;
            let entry = read_entry(&item.path())?;
            (!entry.ready && entry.serial == serial).then_some(id)
        })
        .collect();
    found.sort();
    found.first().copied()
}

/// Remove the data disk `id` (`disk` is the disk typed as `serial`): unmapped first (refused
/// while in use, before anything is written), then its header's 4 KiB zeroed, then its key
/// overwritten and its directory removed. A disk that is neither that header nor zero is not
/// written, and a second call finishes a cut one (a zero header, an entry still there). As for
/// [`add`], the caller (the verbs) matches `serial` with the disk's own; here it is the entry's.
pub fn remove<D: Dev>(state: &Path, disk: &D, id: &Id, serial: &str, mapper: &mut impl Mapper) -> Result<(), String> {
    let entry = read_entry(&dir_of(state, id)).ok_or("this node has no such disk")?;
    if entry.serial != serial {
        return Err("that is not the serial this disk was added by".into());
    }
    let room = disk
        .first()
        .map_err(|e| format!("its first 4 KiB cannot be read: {e}"))?;
    let zero = room.iter().all(|&byte| byte == 0);
    if !zero && parse(&room) != Ok(*id) {
        return Err("its header is not this disk's".into());
    }
    match mapper.unmap() {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(format!("the mapping is in use: {e}")),
        _ => {}
    }
    if !zero {
        disk.write_first(&[0; ROOM])
            .map_err(|e| format!("zeroing its header: {e}"))?;
    }
    forget(state, id).map_err(|e| format!("forgetting its key: {e}"))
}

#[cfg(test)]
mod support {
    use super::*;
    use std::path::PathBuf;

    /// A disk as the checks see it: a file, a name, and whether it is removable.
    pub struct Fake(pub File, pub &'static str, pub bool);

    impl Dev for Fake {
        fn name(&self) -> &str {
            self.1
        }
        fn removable(&self) -> bool {
            self.2
        }
        fn first(&self) -> io::Result<[u8; ROOM]> {
            let mut room = [0; ROOM];
            self.0.read_exact_at(&mut room, 0).map(|()| room)
        }
        fn write_first(&self, room: &[u8; ROOM]) -> io::Result<()> {
            self.0.write_all_at(room, 0)?;
            self.0.sync_all()
        }
    }

    /// The header of `id` put on `file` as it is, with no check: for the tests of the reading.
    pub fn put(file: &File, id: &Id) {
        file.write_all_at(&room_of(id), 0).unwrap();
    }

    /// `refuse`'s verdict without the witness, to compare.
    pub fn check(disk: &Fake, root: Option<&Root>) -> Result<(), Refused> {
        refuse(disk, root).map(|_| ())
    }

    pub fn root(name: &str) -> Root {
        Root::new(name).unwrap()
    }

    /// A directory of its own in the temp dir, removed when it goes out of scope.
    pub struct Dir(PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl Dir {
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    /// A mapper that writes nothing and says what was asked of it. `fail` makes one call fail
    /// (by its name), `answers` is what the resume's check says, and `headed` lists the calls
    /// made while the disk's first 4 KiB were not zero (the header comes last, so none for an add).
    #[derive(Debug)]
    pub struct Map {
        pub disk: File,
        pub calls: Vec<&'static str>,
        pub headed: Vec<&'static str>,
        pub fail: Option<&'static str>,
        pub answers: bool,
        /// There is no mapping to remove: `unmap` says `NotFound`.
        pub gone: bool,
    }

    impl Map {
        pub fn new(disk: &Fake) -> Map {
            Map {
                disk: disk.0.try_clone().unwrap(),
                calls: vec![],
                headed: vec![],
                fail: None,
                answers: true,
                gone: false,
            }
        }
        fn call(&mut self, what: &'static str) -> io::Result<()> {
            let mut room = [0u8; ROOM];
            self.disk.read_exact_at(&mut room, 0).unwrap();
            if what != "unmap" && room.iter().any(|&byte| byte != 0) {
                self.headed.push(what);
            }
            self.calls.push(what);
            (self.fail != Some(what))
                .then_some(())
                .ok_or_else(|| io::Error::other(what))
        }
    }

    impl Mapper for Map {
        fn map(&mut self, _: &[u8; 64]) -> io::Result<()> {
            self.call("map")
        }
        fn zero(&mut self, _: bool) -> io::Result<()> {
            self.call("zero")
        }
        fn seed(&mut self) -> io::Result<()> {
            self.call("seed")
        }
        fn answers(&mut self) -> io::Result<bool> {
            self.call("answers").map(|()| self.answers)
        }
        fn unmap(&mut self) -> io::Result<()> {
            self.call("unmap")?;
            if self.gone {
                return Err(io::ErrorKind::NotFound.into());
            }
            Ok(())
        }
    }

    /// A disk file, its state directory (not made yet) and its tempdir to keep alive.
    pub fn rig(tag: &str) -> (Dir, Fake, PathBuf) {
        let (dir, file) = disk_file(tag, 1 << 20);
        let state = dir.path().join("state");
        (dir, Fake(file, "sdb", false), state)
    }

    pub const ALL: [Point; 7] = [
        Point::Pending,
        Point::Key,
        Point::Map,
        Point::Zero,
        Point::Seed,
        Point::Header,
        Point::Ready,
    ];

    /// The disk's first 4 KiB.
    pub fn room(disk: &Fake) -> [u8; ROOM] {
        disk.first().unwrap()
    }

    /// The names under the state's `disks/`, sorted.
    pub fn ids(state: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(state.join("disks"))
            .map(|items| {
                items
                    .map(|item| item.unwrap().file_name().into_string().unwrap())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    pub fn fake(tag: &str, len: u64, writes: &[(u64, &[u8])]) -> Fake {
        let (_dir, file) = disk_file(tag, len);
        for (at, bytes) in writes {
            file.write_all_at(bytes, *at).unwrap();
        }
        Fake(file, "sdb", false)
    }

    /// A directory of its own in the temp dir, and a disk file of `len` bytes in it.
    pub fn disk_file(tag: &str, len: u64) -> (Dir, File) {
        let dir = std::env::temp_dir().join(format!("kith-data-disk-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = Dir(dir);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.0.join("disk"))
            .unwrap();
        file.set_len(len).unwrap();
        (dir, file)
    }

    pub const ID: Id = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
}

#[cfg(test)]
mod header {
    use super::support::*;
    use super::*;

    /// A header written to a disk file reads back with its id, in the text the ADR gives, with
    /// a sum of a known vector; a file with no header, or a short one, has none.
    #[test]
    fn header_reads_back_its_id() {
        let (_dir, file) = disk_file("header-back", 1 << 20);
        assert!(read_header(&file).unwrap_err().contains("no kith-disk header"));
        put(&file, &ID);
        assert_eq!(read_header(&file), Ok(ID));
        let mut room = [0u8; ROOM];
        file.read_exact_at(&mut room, 0).unwrap();
        // The sum is sha256("kith-disk v1\nid: 00112233445566778899aabbccddeeff\n"), from python.
        let want = "kith-disk v1\nid: 00112233445566778899aabbccddeeff\n\
                    sum: c83efb5aa60a3d36db3765efffd1ebaa6bada192bec4d35c48cab849f42e184d\n";
        assert_eq!(&room[..want.len()], want.as_bytes());
        assert!(room[want.len()..].iter().all(|&byte| byte == 0));
        // A random id differs from the next, and reads back too.
        let (a, b) = (new_id(), new_id());
        assert_ne!(a, b);
        put(&file, &a);
        assert_eq!(read_header(&file), Ok(a));
        let (_dir, short) = disk_file("header-short", 100);
        assert!(read_header(&short).unwrap_err().contains("4 KiB"));
    }

    /// A flipped byte fails, wherever in the 4 KiB it is: in the line, the id, the sum, the
    /// newline, or the room after them. So do an upper-case id with the sum of its own, a
    /// byte after the room's end, and an id whose sum is that of another.
    #[test]
    fn header_fails_on_a_flipped_byte() {
        let (_dir, file) = disk_file("header-flip", 1 << 20);
        put(&file, &ID);
        for at in 0..ROOM as u64 {
            let mut byte = [0u8];
            file.read_exact_at(&mut byte, at).unwrap();
            file.write_all_at(&[byte[0] ^ 1], at).unwrap();
            assert!(read_header(&file).is_err(), "byte {at} flipped was taken");
            file.write_all_at(&byte, at).unwrap();
        }
        assert_eq!(read_header(&file), Ok(ID));

        // A header that is whole in itself but for the id of another: the sum is for the first.
        let forged = text(&ID).replacen(&crate::pki::hex(&ID), &crate::pki::hex(&[7; 16]), 1);
        file.write_all_at(forged.as_bytes(), 0).unwrap();
        assert!(read_header(&file).unwrap_err().contains("sum"));
        // Upper-case digits are not what the header writes, with a sum made for them.
        let upper = format!("{FIRST}\nid: {}\n", crate::pki::hex(&ID).to_uppercase());
        let sum = digest::digest(&digest::SHA256, upper.as_bytes());
        let upper = format!("{upper}sum: {}\n", crate::pki::hex(sum.as_ref()));
        let mut room = [0u8; ROOM];
        room[..upper.len()].copy_from_slice(upper.as_bytes());
        file.write_all_at(&room, 0).unwrap();
        assert!(read_header(&file).is_err());
    }
}

#[cfg(test)]
mod refuse {
    use super::support::*;
    use super::*;

    /// A file with a GPT, MBR, ext4 or LUKS signature, a kith header, or any non-zero byte in
    /// its first 4 KiB is refused, each for what it is; an empty one is not. Bytes after the
    /// 4 KiB are not looked at; the root disk, an unknown root and a removable disk are refused
    /// whatever they hold.
    #[test]
    fn refuse_a_signature_the_root_and_a_removable_disk() {
        let sda = root("sda");
        let root = Some(&sda);
        assert_eq!(check(&fake("refuse-empty", 1 << 20, &[]), root), Ok(()));
        // What passes as empty: a signature past the first 4 KiB (md 1.2 at 4096, btrfs at 64 KiB).
        let late: &[(u64, &[u8])] = &[(4096, b"LUKS\xba\xbe"), (65600, b"_BHRfS_M"), (1 << 19, b"x")];
        assert_eq!(check(&fake("refuse-late", 1 << 20, late), root), Ok(()));
        type Writes<'a> = &'a [(u64, &'a [u8])];
        let cases: [(&str, Writes, Refused); 8] = [
            ("luks", &[(0, b"LUKS\xba\xbe")], Refused::Signature("a LUKS header")),
            (
                "gpt",
                &[(512, b"EFI PART"), (510, &[0x55, 0xaa])],
                Refused::Signature("a GPT"),
            ),
            ("mbr", &[(510, &[0x55, 0xaa])], Refused::Signature("an MBR")),
            (
                "ext4",
                &[(1080, &[0x53, 0xef])],
                Refused::Signature("an ext4 file system"),
            ),
            (
                "kith",
                &[(0, b"kith-disk v1\n")],
                Refused::Signature("a kith-disk header"),
            ),
            ("last", &[(4095, &[1])], Refused::NotEmpty),
            ("first", &[(0, &[1])], Refused::NotEmpty),
            ("middle", &[(2000, b"data")], Refused::NotEmpty),
        ];
        for (tag, writes, want) in cases {
            assert_eq!(check(&fake(tag, 1 << 20, writes), root), Err(want), "{tag}");
        }
        // A disk with a header written through its witness is refused as a kith disk.
        let made = fake("refuse-made", 1 << 20, &[]);
        write_header(&refuse(&made, root).unwrap(), &ID).unwrap();
        assert_eq!(read_header(&made.0), Ok(ID));
        assert_eq!(check(&made, root), Err(Refused::Signature("a kith-disk header")));

        let empty = |name, removable| Fake(disk_file("refuse-name", 1 << 20).1, name, removable);
        assert_eq!(check(&empty("sda", false), root), Err(Refused::Root));
        assert_eq!(check(&empty("sdb", false), None), Err(Refused::Root));
        assert_eq!(check(&empty("sdb", true), root), Err(Refused::Removable));
        // The root disk that is also removable, and holds a signature: Root first, never wiped.
        assert_eq!(
            check(&Fake(made.0.try_clone().unwrap(), "sda", true), root),
            Err(Refused::Root)
        );
        // A disk shorter than the room cannot be looked at, so it is not taken.
        let short = fake("refuse-short", 100, &[]);
        assert!(matches!(check(&short, root), Err(Refused::Unreadable(_))));
        assert!(Refused::NotEmpty.to_string().contains("4 KiB"));
    }

    /// A root that is no disk name fails closed: `Some("")` makes no `Root`, so the check gets
    /// none and refuses every disk (before, an empty string matched no disk and offered the
    /// root); a disk that names itself nothing is refused too.
    #[test]
    fn refuse_fails_closed_on_an_empty_or_path_root() {
        assert_eq!(Root::new(""), None);
        assert_eq!(Root::new("/dev/sda"), None);
        assert!(Root::new("sda").is_some());
        let disk = fake("refuse-closed", 1 << 20, &[]);
        assert_eq!(check(&disk, Root::new("").as_ref()), Err(Refused::Root));
        assert_eq!(
            check(&Fake(disk.0.try_clone().unwrap(), "", false), Some(&root("sda"))),
            Err(Refused::Root)
        );
        assert_eq!(check(&disk, Some(&root("sda"))), Ok(()));
    }

    /// A `--wipe` may pass what a disk holds and nothing else: the root, a removable disk and
    /// one that cannot be read are not wipeable.
    #[test]
    fn refuse_wipeable_is_only_what_the_disk_holds() {
        assert!(Refused::Signature("a GPT").wipeable() && Refused::NotEmpty.wipeable());
        assert!(!Refused::Root.wipeable() && !Refused::Removable.wipeable());
        assert!(!Refused::Unreadable("x".into()).wipeable());
    }
}

#[cfg(test)]
mod key {
    use super::*;

    /// A key is 64 bytes, and two made for one disk differ (it takes no id and no state key, so
    /// nothing can make one the same twice); neither is zero, and the two XTS halves differ.
    #[test]
    fn key_is_random_and_64_bytes() {
        let (a, b) = (new_key(), new_key());
        assert_eq!(a.len(), 64);
        assert_ne!(a[..], b[..]);
        for key in [&a, &b] {
            assert!(key.iter().any(|&byte| byte != 0));
            assert_ne!(key[..32], key[32..]);
        }
    }
}

#[cfg(test)]
mod order {
    use super::support::*;
    use super::*;

    use std::os::unix::fs::PermissionsExt;

    const NO: (bool, bool) = (false, false);

    fn sda() -> Root {
        root("sda")
    }

    fn add_cut(state: &Path, disk: &Fake, map: &mut Map, at: Option<Point>) -> Result<Id, AddError> {
        let cut = |point| {
            if Some(point) == at {
                Err(io::Error::other("cut"))
            } else {
                Ok(())
            }
        };
        add_with(state, disk, Some(&sda()), "SER1", NO, map, &mut { cut })
    }

    /// An add that is not cut maps, zeros and seeds with the disk's first 4 KiB still zero, then
    /// writes the header and marks `ready`: the disk is ours, its key is 64 bytes and its own file.
    #[test]
    fn order_a_whole_add_writes_the_header_last() {
        let (_dir, disk, state) = rig("order-whole");
        let mut map = Map::new(&disk);
        let id = add(&state, &disk, Some(&sda()), "SER1", NO, &mut map).unwrap();
        assert_eq!(map.calls, ["map", "zero", "seed"]);
        assert!(
            map.headed.is_empty(),
            "the header was there before the mapping was done"
        );
        assert_eq!(read_header(&disk.0), Ok(id));
        assert_eq!(standing(&state, &room(&disk)), Standing::Ours(id));
        let dir = dir_of(&state, &id);
        assert_eq!(
            read_entry(&dir),
            Some(Entry {
                serial: "SER1".into(),
                ready: true
            })
        );
        assert_eq!(read_key(&dir).unwrap().len(), 64);
        assert_eq!(
            std::fs::metadata(dir.join("key")).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        // No temporary file is left behind.
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|i| i.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["entry", "key"]);
        // The same disk again is this node's already, and nothing is asked of the mapper.
        let mut again = Map::new(&disk);
        assert_eq!(
            add(&state, &disk, Some(&sda()), "SER1", NO, &mut again),
            Err(AddError::Added)
        );
        assert!(again.calls.is_empty());
    }

    /// A cut before each step: what is left is never `ours`; the header is there only from
    /// `Ready` on, the key only from `Map` on, and one entry at most. The next add, with no
    /// `--wipe`, finishes it: after the header it resumes (map, check, `ready`), before it starts
    /// over with the same entry and the same key. No second entry is left.
    #[test]
    fn order_a_cut_at_each_point_resumes_with_no_wipe() {
        for at in ALL {
            let (_dir, disk, state) = rig("order-cut");
            let mut map = Map::new(&disk);
            assert!(
                matches!(add_cut(&state, &disk, &mut map, Some(at)), Err(AddError::Failed(_))),
                "{at:?}"
            );
            assert!(map.headed.is_empty());
            let left = ids(&state);
            assert_eq!(left.len(), usize::from(at != Point::Pending), "{at:?}: {left:?}");
            let headed = matches!(at, Point::Ready);
            assert_eq!(room(&disk).iter().any(|&byte| byte != 0), headed, "{at:?}");
            assert!(
                !matches!(standing(&state, &room(&disk)), Standing::Damaged(_)),
                "{at:?}"
            );
            assert!(!matches!(standing(&state, &room(&disk)), Standing::Ours(_)), "{at:?}");
            let dir = state.join("disks").join(left.first().cloned().unwrap_or_default());
            let key = read_key(&dir);
            assert_eq!(key.is_some(), !matches!(at, Point::Pending | Point::Key), "{at:?}");
            if let Some(entry) = read_entry(&dir) {
                assert!(!entry.ready, "{at:?}");
            }

            let mut next = Map::new(&disk);
            let id =
                add(&state, &disk, Some(&sda()), "SER1", NO, &mut next).unwrap_or_else(|e| panic!("{at:?}: {e:?}"));
            let want: &[&str] = if headed {
                &["map", "answers"]
            } else {
                &["map", "zero", "seed"]
            };
            assert_eq!(next.calls, want, "{at:?}");
            assert_eq!(standing(&state, &room(&disk)), Standing::Ours(id), "{at:?}");
            assert_eq!(ids(&state), [crate::pki::hex(&id)], "{at:?}: an entry is left over");
            if at != Point::Pending {
                assert_eq!(left, ids(&state), "{at:?}: another id");
            }
            if let Some(key) = key {
                assert_eq!(
                    read_key(&dir_of(&state, &id)).unwrap()[..],
                    key[..],
                    "{at:?}: another key"
                );
            }
        }
    }

    /// A cut twice in a row (the resume cut too) still comes out whole at the third try.
    #[test]
    fn order_a_cut_of_the_resume_is_resumed() {
        let (_dir, disk, state) = rig("order-twice");
        let mut map = Map::new(&disk);
        add_cut(&state, &disk, &mut map, Some(Point::Ready)).unwrap_err();
        let cut = |point| {
            if point == Point::Ready {
                Err(io::Error::other("cut"))
            } else {
                Ok(())
            }
        };
        let mut second = Map::new(&disk);
        let r = add_with(&state, &disk, Some(&sda()), "SER1", NO, &mut second, &mut { cut });
        assert!(matches!(r, Err(AddError::Failed(_))));
        assert_eq!(second.calls, ["map", "answers", "unmap"]);
        let mut third = Map::new(&disk);
        let id = add(&state, &disk, Some(&sda()), "SER1", NO, &mut third).unwrap();
        assert_eq!(standing(&state, &room(&disk)), Standing::Ours(id));
    }

    /// A header whose file system does not answer is `Half`: nothing is changed on the disk or in
    /// the state, and the mapping is removed. With `--wipe` the add starts over under a new id
    /// and the old entry and key are gone.
    #[test]
    fn order_a_resume_that_does_not_answer_needs_a_wipe() {
        let (_dir, disk, state) = rig("order-half");
        add_cut(&state, &disk, &mut Map::new(&disk), Some(Point::Ready)).unwrap_err();
        let (before, old) = (room(&disk), ids(&state));
        let mut silent = Map::new(&disk);
        silent.answers = false;
        assert!(matches!(
            add(&state, &disk, Some(&sda()), "SER1", NO, &mut silent),
            Err(AddError::Half(_))
        ));
        assert_eq!(silent.calls, ["map", "answers", "unmap"]);
        assert_eq!((room(&disk), ids(&state)), (before, old.clone()));

        let mut wiped = Map::new(&disk);
        wiped.answers = false;
        let id = add(&state, &disk, Some(&sda()), "SER1", (true, false), &mut wiped).unwrap();
        assert_eq!(wiped.calls, ["map", "answers", "unmap", "map", "zero", "seed"]);
        assert_eq!(
            wiped.headed,
            ["map", "answers"],
            "the header must be gone before the second map"
        );
        assert_eq!(ids(&state), [crate::pki::hex(&id)]);
        assert_ne!(ids(&state), old);
        assert_eq!(standing(&state, &room(&disk)), Standing::Ours(id));
    }

    /// A resume whose check of the file system fails (an error, not "no answer") is `Failed`: the
    /// mapping is removed and, even with `--wipe`, the key, the entry and the header are kept.
    #[test]
    fn order_a_resume_whose_check_errs_keeps_everything() {
        let (_dir, disk, state) = rig("order-answers-err");
        add_cut(&state, &disk, &mut Map::new(&disk), Some(Point::Ready)).unwrap_err();
        let (before, old) = (room(&disk), ids(&state));
        let key = read_key(&state.join("disks").join(&old[0])).unwrap();
        let mut broken = Map::new(&disk);
        broken.fail = Some("answers");
        let r = add(&state, &disk, Some(&sda()), "SER1", (true, false), &mut broken);
        assert!(matches!(r, Err(AddError::Failed(_))), "{r:?}");
        assert_eq!(broken.calls, ["map", "answers", "unmap"]);
        assert_eq!((room(&disk), ids(&state)), (before, old.clone()));
        assert_eq!(read_key(&state.join("disks").join(&old[0])).unwrap()[..], key[..]);
    }

    /// A header of this add under another serial is not resumed (it is another disk's header).
    #[test]
    fn order_a_pending_header_of_another_serial_is_not_resumed() {
        let (_dir, disk, state) = rig("order-serial");
        add_cut(&state, &disk, &mut Map::new(&disk), Some(Point::Ready)).unwrap_err();
        let before = room(&disk);
        let mut map = Map::new(&disk);
        let r = add(&state, &disk, Some(&sda()), "OTHER", NO, &mut map);
        assert_eq!(r, Err(AddError::Refused(Refused::Signature("a kith-disk header"))));
        assert!(map.calls.is_empty());
        assert_eq!(room(&disk), before);
    }

    /// A step that fails (not a cut) takes the mapping away and leaves the entry `pending`, to be
    /// added again; and a key that was kept before the failure is the one the next add uses.
    #[test]
    fn order_a_failed_step_unmaps_and_the_entry_stays_pending() {
        for step in ["map", "zero", "seed"] {
            let (_dir, disk, state) = rig("order-fail");
            let mut map = Map::new(&disk);
            map.fail = Some(step);
            assert!(matches!(
                add(&state, &disk, Some(&sda()), "SER1", NO, &mut map),
                Err(AddError::Failed(_))
            ));
            assert_eq!(map.calls.last(), Some(&"unmap"), "{step}");
            assert!(room(&disk).iter().all(|&byte| byte == 0), "{step}");
            let dir = state.join("disks").join(&ids(&state)[0]);
            assert_eq!(
                read_entry(&dir),
                Some(Entry {
                    serial: "SER1".into(),
                    ready: false
                })
            );
            let key = read_key(&dir).unwrap();
            assert_eq!(
                add(&state, &disk, Some(&sda()), "SER1", NO, &mut Map::new(&disk)).map(|_| ()),
                Ok(())
            );
            assert_eq!(read_key(&dir).unwrap()[..], key[..]);
        }
    }

    /// A serial that cannot be a line of the entry, the root disk and a removable disk are
    /// refused before anything is written: no state directory, no call.
    #[test]
    fn order_refuses_before_it_writes_anything() {
        let (_dir, disk, state) = rig("order-refuse");
        for serial in ["", " a", "a ", "a\nstate: ready", "a\u{e9}", &"x".repeat(129)] {
            let mut map = Map::new(&disk);
            assert!(
                matches!(
                    add(&state, &disk, Some(&sda()), serial, NO, &mut map),
                    Err(AddError::Failed(_))
                ),
                "{serial:?}"
            );
            assert!(map.calls.is_empty());
        }
        let (a, b) = (
            Fake(disk.0.try_clone().unwrap(), "sda", false),
            Fake(disk.0.try_clone().unwrap(), "sdb", true),
        );
        for (disk, want) in [(&a, Refused::Root), (&b, Refused::Removable)] {
            let mut map = Map::new(disk);
            let r = add(&state, disk, Some(&sda()), "SER1", (true, true), &mut map);
            assert_eq!(r, Err(AddError::Refused(want)));
            assert!(map.calls.is_empty());
        }
        assert_eq!(
            add(&state, &disk, None, "SER1", NO, &mut Map::new(&disk)),
            Err(AddError::Refused(Refused::Root))
        );
        assert!(!state.exists());
        assert!(room(&disk).iter().all(|&byte| byte == 0));
    }
}

#[cfg(test)]
mod ours {
    use super::support::*;
    use super::*;

    const NO: (bool, bool) = (false, false);

    fn all_of(disk: &Fake) -> Vec<u8> {
        let mut bytes = vec![0; disk.0.metadata().unwrap().len() as usize];
        disk.0.read_exact_at(&mut bytes, 0).unwrap();
        bytes
    }

    /// Ours has a header and a `ready` entry; no header, an empty disk, another's id, a `pending`
    /// entry are unknown; a kith header that is not one is damaged, wherever the byte is.
    #[test]
    fn ours_tells_ours_unknown_and_damaged_apart() {
        let (_dir, disk, state) = rig("ours-apart");
        let id = add(&state, &disk, Some(&root("sda")), "SER1", NO, &mut Map::new(&disk)).unwrap();
        let good = room(&disk);
        assert_eq!(standing(&state, &good), Standing::Ours(id));

        assert_eq!(standing(&state, &[0; ROOM]), Standing::Unknown);
        let mut gpt = [0; ROOM];
        gpt[512..520].copy_from_slice(b"EFI PART");
        assert_eq!(standing(&state, &gpt), Standing::Unknown);
        // Another node's disk: a good header, an id this state does not list.
        assert_eq!(standing(&state.join("elsewhere"), &good), Standing::Unknown);
        assert_eq!(standing(&state, &room_of(&ID)), Standing::Unknown);
        // A half-made one: the entry is `pending`.
        let dir = dir_of(&state, &id);
        put_file(&dir, "entry", entry_text("SER1", false).as_bytes()).unwrap();
        assert_eq!(standing(&state, &good), Standing::Unknown);
        put_file(&dir, "entry", b"junk").unwrap();
        assert_eq!(standing(&state, &good), Standing::Unknown);
        put_file(&dir, "entry", entry_text("SER1", true).as_bytes()).unwrap();
        assert_eq!(standing(&state, &good), Standing::Ours(id));

        // Damaged: a byte flipped in the 4 KiB, a cut header, an id that is not hex.
        for at in [12, 20, 40, 70, 120, 4095] {
            let mut bad = good;
            bad[at] ^= 1;
            assert!(matches!(standing(&state, &bad), Standing::Damaged(_)), "byte {at}");
        }
        let mut cut = [0; ROOM];
        cut[..13].copy_from_slice(b"kith-disk v1\n");
        assert!(matches!(standing(&state, &cut), Standing::Damaged(_)));
        // A first byte flipped is not a kith header at all, so it is unknown, not damaged.
        let mut other = good;
        other[0] ^= 1;
        assert_eq!(standing(&state, &other), Standing::Unknown);
    }

    /// The three cases of the ADR: with a verity root every disk but the root's own, none when
    /// that is unreadable; with none, every disk but the one with the state, none when there is
    /// no state partition; a disk with no name never.
    #[test]
    fn ours_off_ours_in_three_cases() {
        // A verity root on vda.
        assert!(off_ours(true, Some("vda"), None, "vdb"));
        assert!(off_ours(true, Some("vda"), Some("vda"), "vdb"));
        assert!(!off_ours(true, Some("vda"), None, "vda"));
        // A verity root that cannot be read: none, whatever else is known.
        assert!(!off_ours(true, None, None, "vdb"));
        assert!(!off_ours(true, None, Some("vda"), "vdb"));
        // No verity root: the state's disk is ours.
        assert!(off_ours(false, None, Some("vda"), "vdb"));
        assert!(!off_ours(false, None, Some("vda"), "vda"));
        assert!(!off_ours(false, Some("vdb"), Some("vda"), "vda"));
        // No verity root and no state partition found: none.
        assert!(!off_ours(false, None, None, "vdb"));
        assert!(!off_ours(false, Some("vda"), None, "vdb"));
        // A disk with no name.
        assert!(!off_ours(true, Some("vda"), None, ""));
        assert!(!off_ours(false, None, Some("vda"), ""));
        // A root or state disk with no name, or a path, is no disk's: none, not every one.
        assert!(!off_ours(true, Some(""), None, "vdb"));
        assert!(!off_ours(false, None, Some(""), "vdb"));
        assert!(!off_ours(true, Some("dev/vda"), None, "vdb"));
        assert!(!off_ours(false, None, Some("/dev/vda"), "vdb"));
    }

    /// An unknown disk (another's header, a damaged one, a signature, data, a pending header of
    /// another serial) is not written by an add with no `--wipe`: its bytes are as they were, the
    /// mapper is not called and the state has no entry. With `--wipe` the root disk and a removable
    /// one are still not written, and only a refusal that `wipeable` says is passed.
    #[test]
    fn ours_an_unknown_disk_is_never_written() {
        let other = {
            let (_d, d, s) = rig("ours-other");
            add(&s, &d, Some(&root("sda")), "SER9", NO, &mut Map::new(&d)).unwrap();
            room(&d)
        };
        let mut damaged = other;
        damaged[30] ^= 1;
        type Writes = Vec<(u64, Vec<u8>)>;
        let cases: [(&str, Writes); 5] = [
            ("another-header", vec![(0, other.to_vec())]),
            ("damaged", vec![(0, damaged.to_vec())]),
            ("gpt", vec![(512, b"EFI PART".to_vec()), (510, vec![0x55, 0xaa])]),
            ("data", vec![(3000, b"my files".to_vec())]),
            ("late-data", vec![(1 << 19, b"my files".to_vec())]),
        ];
        for (tag, writes) in cases {
            let (_dir, disk, state) = rig(tag);
            for (at, bytes) in &writes {
                disk.0.write_all_at(bytes, *at).unwrap();
            }
            let before = all_of(&disk);
            let mut map = Map::new(&disk);
            let r = add(&state, &disk, Some(&root("sda")), "SER1", NO, &mut map);
            let late = tag == "late-data";
            assert!(late == r.is_ok(), "{tag}: {r:?}");
            if !late {
                assert!(
                    matches!(r, Err(AddError::Refused(ref why)) if why.wipeable()),
                    "{tag}: {r:?}"
                );
                assert!(map.calls.is_empty() && !state.exists(), "{tag}");
                assert_eq!(all_of(&disk), before, "{tag}: written");
                assert_eq!(
                    standing(&state, &room(&disk)) == Standing::Unknown,
                    tag != "damaged",
                    "{tag}"
                );
            }
        }
        // `--wipe` passes what the disk holds, and never which disk it is.
        let (_dir, disk, state) = rig("ours-wipe");
        disk.0.write_all_at(&damaged, 0).unwrap();
        let id = add(
            &state,
            &disk,
            Some(&root("sda")),
            "SER1",
            (true, false),
            &mut Map::new(&disk),
        )
        .unwrap();
        assert_eq!(standing(&state, &room(&disk)), Standing::Ours(id));
        for (name, removable) in [("sda", false), ("sdb", true)] {
            let (_dir, file) = disk_file("ours-fenced", 1 << 20);
            file.write_all_at(b"my files", 100).unwrap();
            let fenced = Fake(file, name, removable);
            let before = all_of(&fenced);
            let r = add(
                &state,
                &fenced,
                Some(&root("sda")),
                "SER2",
                (true, true),
                &mut Map::new(&fenced),
            );
            assert!(
                matches!(r, Err(AddError::Refused(ref why)) if !why.wipeable()),
                "{name}: {r:?}"
            );
            assert_eq!(all_of(&fenced), before);
        }
        assert_eq!(ids(&state).len(), 1);
    }
}

#[cfg(test)]
mod remove {
    use super::support::*;
    use super::*;

    const NO: (bool, bool) = (false, false);

    fn added(tag: &str) -> (Dir, Fake, PathBuf, Id) {
        let (dir, disk, state) = rig(tag);
        let id = add(&state, &disk, Some(&root("sda")), "SER1", NO, &mut Map::new(&disk)).unwrap();
        (dir, disk, state, id)
    }

    /// Remove unmaps, zeroes the header's 4 KiB, overwrites the key file's bytes (a handle opened
    /// before still reads zeros) and takes the directory away: the disk is unknown again, and an
    /// add (with no `--wipe`) takes it as new.
    #[test]
    fn remove_zeroes_the_header_and_the_key() {
        let (_dir, disk, state, id) = added("remove-whole");
        let kept = File::open(dir_of(&state, &id).join("key")).unwrap();
        let mut key = [0u8; 64];
        kept.read_exact_at(&mut key, 0).unwrap();
        assert!(key.iter().any(|&byte| byte != 0));
        let mut map = Map::new(&disk);
        remove(&state, &disk, &id, "SER1", &mut map).unwrap();
        assert_eq!(map.calls, ["unmap"]);
        assert!(room(&disk).iter().all(|&byte| byte == 0));
        let mut after = [1u8; 64];
        kept.read_exact_at(&mut after, 0).unwrap();
        assert_eq!(after, [0; 64], "the key's bytes were not overwritten");
        assert!(!dir_of(&state, &id).exists());
        assert_eq!(standing(&state, &room(&disk)), Standing::Unknown);
        // Gone: a second remove has nothing, and the disk is added again as new.
        assert!(remove(&state, &disk, &id, "SER1", &mut Map::new(&disk)).is_err());
        let again = add(&state, &disk, Some(&root("sda")), "SER1", NO, &mut Map::new(&disk)).unwrap();
        assert_ne!(again, id);
    }

    /// A mapping in use is refused before anything is zeroed; so are a wrong serial and a disk
    /// that holds another's header or data: no byte of it or of the state changes.
    #[test]
    fn remove_refuses_before_it_writes() {
        let (_dir, disk, state, id) = added("remove-refuse");
        let (header, key) = (room(&disk), read_key(&dir_of(&state, &id)).unwrap());
        let mut busy = Map::new(&disk);
        busy.fail = Some("unmap");
        assert!(
            remove(&state, &disk, &id, "SER1", &mut busy)
                .unwrap_err()
                .contains("in use")
        );
        assert!(remove(&state, &disk, &id, "OTHER", &mut Map::new(&disk)).is_err());
        assert!(
            remove(&state, &disk, &[9; 16], "SER1", &mut Map::new(&disk))
                .unwrap_err()
                .contains("no such")
        );
        // The right id and serial, on a disk that is another's.
        let (_d2, elsewhere, _) = rig("remove-else");
        elsewhere.0.write_all_at(b"my files", 2000).unwrap();
        let mut map = Map::new(&elsewhere);
        assert!(remove(&state, &elsewhere, &id, "SER1", &mut map).is_err());
        assert!(map.calls.is_empty());
        let mut data = [0u8; 8];
        elsewhere.0.read_exact_at(&mut data, 2000).unwrap();
        assert_eq!(&data, b"my files");
        assert_eq!(room(&disk), header);
        assert_eq!(read_key(&dir_of(&state, &id)).unwrap()[..], key[..]);
        assert_eq!(standing(&state, &header), Standing::Ours(id));
    }

    /// A remove cut after the header was zeroed (or after the key was) is finished by the next:
    /// the disk is zero, the entry is there, and the leftover temporary key file goes too.
    #[test]
    fn remove_finishes_a_cut_remove() {
        let (_dir, disk, state, id) = added("remove-cut");
        disk.write_first(&[0; ROOM]).unwrap();
        let dir = dir_of(&state, &id);
        std::fs::write(dir.join(".key.tmp"), [7u8; 64]).unwrap();
        std::fs::create_dir(dir.join("data")).unwrap();
        remove(&state, &disk, &id, "SER1", &mut Map::new(&disk)).unwrap();
        assert!(!dir.exists());
        assert!(ids(&state).is_empty());
    }

    /// The entry goes last: a remove cut after the key is gone leaves the entry, and the next
    /// remove finishes. A mapping that is not there (`NotFound`) is no refusal.
    #[test]
    fn remove_goes_on_after_the_key_is_gone_and_with_no_mapping() {
        let (_dir, disk, state, id) = added("remove-nokey");
        let dir = dir_of(&state, &id);
        std::fs::remove_file(dir.join("key")).unwrap();
        assert!(dir.join("entry").exists());
        let mut gone = Map::new(&disk);
        gone.gone = true;
        remove(&state, &disk, &id, "SER1", &mut gone).unwrap();
        assert_eq!(gone.calls, ["unmap"]);
        assert!(room(&disk).iter().all(|&byte| byte == 0));
        assert!(!dir.exists());
    }

    /// A `data` that cannot be removed (still mounted, so not empty) stops `forget` before the
    /// key is erased: the entry and the key are both still there for the next remove.
    #[test]
    fn remove_stops_at_a_busy_mount_point_with_the_key_kept() {
        let (_dir, _disk, state, id) = added("remove-busy");
        let dir = dir_of(&state, &id);
        std::fs::create_dir(dir.join("data")).unwrap();
        std::fs::write(dir.join("data").join("f"), b"x").unwrap();
        assert!(forget(&state, &id).is_err());
        assert!(dir.join("entry").exists() && read_key(&dir).is_some());
    }
}
