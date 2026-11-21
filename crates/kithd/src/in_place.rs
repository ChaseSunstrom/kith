//! The engine that encrypts a partition in place (docs/adr-encrypt-in-place.md): a pass over
//! the partition in chunks, every chunk read plain, written back through the dm-crypt mapping,
//! with a journal in the config partition that a power cut resumes from.
//!
//! Nothing here maps, mounts or finds a disk: it is given the raw partition, the mapping and the
//! journal as [`Disk`]s (files in the tests), and the state's key. Its order of writes, and why
//! a cut at any point of it leaves every chunk either plain or encrypted with the journal saying
//! which, is the ADR's, section 2 and 3; the comments here say only what a line must not move
//! past.
//!
//! [`at_boot`] is what init calls before the state is mounted: it decides from the marker, the
//! journal and the lock record's key whether a pass is due, runs it, and clears the marker and
//! then the journal.

use ring::{aead, digest, hkdf, hmac};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// The most a chunk is: what one backup and one write through the mapping hold.
pub const CHUNK: usize = 256 << 10;
const SECTOR: usize = 512;
/// The room of a header copy, and what the lock record's room is as well.
const ROOM: usize = 4096;
/// The journal's places in the config partition: two header copies, then the backup slot. The
/// node's config is the first 64 KiB and the lock record is at `crypt::AT` (512 KiB), 4 KiB and
/// its copy; `layout` in the tests holds these clear of both.
const HEAD1: u64 = 128 << 10;
const HEAD2: u64 = HEAD1 + ROOM as u64;
const SLOT: u64 = 192 << 10;
const SLOT_ROOM: usize = CHUNK + ROOM;
/// The marker: this node's state is to be encrypted in place, at the next start. It is the first
/// 4 KiB past the node's config, clear of the journal and of the lock record.
const MARK: u64 = 64 << 10;
const MARKED: &[u8] = b"kith-inplace pending v1\n";
const MAGIC: &[u8; 16] = b"kith-inplace v1\n";
const NONCE: usize = aead::NONCE_LEN;
const TAG: usize = aead::MAX_TAG_LEN;
/// What a header holds before its sum: the magic, the pass's id, the partition's size, the chunk
/// size, the chunks done, the key's fingerprint and the next chunk's check.
const BODY: usize = 16 + 16 + 8 + 4 + 8 + 16 + 32;

/// Read, write and sync at an offset: the raw partition, the mapping over it (a write lands
/// encrypted), and the journal. A short read or write is an error.
pub trait Disk {
    fn read_at(&self, buf: &mut [u8], at: u64) -> io::Result<()>;
    fn write_at(&self, buf: &[u8], at: u64) -> io::Result<()>;
    /// Everything written before it is on the disk when it returns.
    fn sync(&self) -> io::Result<()>;
}

impl Disk for File {
    fn read_at(&self, buf: &mut [u8], at: u64) -> io::Result<()> {
        self.read_exact_at(buf, at)
    }
    fn write_at(&self, buf: &[u8], at: u64) -> io::Result<()> {
        self.write_all_at(buf, at)
    }
    fn sync(&self) -> io::Result<()> {
        self.sync_all()
    }
}

/// The points of a pass, each reached just after its step: a cut is a stop at one of them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Point {
    /// A chunk's backup is written, not synced.
    BackupWritten,
    BackupSynced,
    /// The first half of the chunk is through the mapping, the rest is not.
    ChunkPart,
    /// The chunk is through the mapping and synced; the journal still says it is not.
    ChunkDone,
    /// A header's first copy is written and synced, the second is not.
    HeaderFirst,
    /// The second copy is written, not synced.
    HeaderSecond,
    HeaderBoth,
}

fn bad(why: &str) -> io::Error {
    io::Error::other(format!("in-place encryption: {why}"))
}

/// What the journal's header says: a pass, the partition it is over and how far it is.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Header {
    id: [u8; 16],
    total: u64,
    chunk: u32,
    done: u64,
    /// The key's fingerprint: a pass is not gone on with under another key.
    key: [u8; 16],
    /// The check of the plain chunk `done` (zeros when all are done): what tells a chunk still
    /// plain from one part written, when its backup does not open.
    next: [u8; 32],
}

impl Header {
    /// Every chunk is done: the pass's terminal state.
    fn finished(&self) -> bool {
        self.done >= self.total.div_ceil(self.chunk.max(1) as u64)
    }

    fn bytes(&self) -> [u8; ROOM] {
        let mut room = [0; ROOM];
        room[..16].copy_from_slice(MAGIC);
        room[16..32].copy_from_slice(&self.id);
        room[32..40].copy_from_slice(&self.total.to_le_bytes());
        room[40..44].copy_from_slice(&self.chunk.to_le_bytes());
        room[44..52].copy_from_slice(&self.done.to_le_bytes());
        room[52..68].copy_from_slice(&self.key);
        room[68..BODY].copy_from_slice(&self.next);
        let sum = digest::digest(&digest::SHA256, &room[..BODY]);
        room[BODY..BODY + 32].copy_from_slice(sum.as_ref());
        room
    }

    /// Whole or nothing: the magic, the sum, and zeros to the room's end.
    fn parse(room: &[u8; ROOM]) -> Option<Header> {
        let sum = digest::digest(&digest::SHA256, &room[..BODY]);
        let whole = room.starts_with(MAGIC) && room[BODY..BODY + 32] == *sum.as_ref();
        (whole && room[BODY + 32..].iter().all(|&byte| byte == 0)).then(|| Header {
            id: room[16..32].try_into().expect("16 bytes"),
            total: u64::from_le_bytes(room[32..40].try_into().expect("8 bytes")),
            chunk: u32::from_le_bytes(room[40..44].try_into().expect("4 bytes")),
            done: u64::from_le_bytes(room[44..52].try_into().expect("8 bytes")),
            key: room[52..68].try_into().expect("16 bytes"),
            next: room[68..BODY].try_into().expect("32 bytes"),
        })
    }
}

/// Both header copies, each whole or not, and whether the second is all zero (a pass that never
/// finished its first write).
fn heads(journal: &impl Disk) -> io::Result<(Option<Header>, Option<Header>, bool)> {
    let (mut one, mut two) = ([0; ROOM], [0; ROOM]);
    journal.read_at(&mut one, HEAD1)?;
    journal.read_at(&mut two, HEAD2)?;
    Ok((
        Header::parse(&one),
        Header::parse(&two),
        two.iter().all(|&byte| byte == 0),
    ))
}

/// `head` in both copies, the first synced before the second is written: a cut tears at most
/// one of them.
fn put(journal: &impl Disk, head: &Header, hit: &mut dyn FnMut(Point) -> io::Result<()>) -> io::Result<()> {
    let room = head.bytes();
    journal.write_at(&room, HEAD1)?;
    journal.sync()?;
    hit(Point::HeaderFirst)?;
    journal.write_at(&room, HEAD2)?;
    hit(Point::HeaderSecond)?;
    journal.sync()?;
    hit(Point::HeaderBoth)
}

/// What a chunk's backup is sealed with: ChaCha20-Poly1305 under a key drawn from the state's;
/// and the checks the header keeps (HMAC under another drawn key: no one without the state's key
/// can test a guess of a chunk against one).
struct Sealer {
    aead: aead::LessSafeKey,
    check: hmac::Key,
}

impl Sealer {
    fn new(key: &[u8; 64]) -> Sealer {
        let drawn = hkdf::Salt::new(hkdf::HKDF_SHA256, b"kith-in-place").extract(key);
        let sealing = drawn.expand(&[b"backup"], &aead::CHACHA20_POLY1305);
        let check = drawn.expand(&[b"check"], hmac::HMAC_SHA256);
        Sealer {
            aead: aead::LessSafeKey::new(aead::UnboundKey::from(sealing.expect("a key's length"))),
            check: hmac::Key::from(check.expect("a key's length")),
        }
    }

    /// What the header keeps of a plain chunk.
    fn mac(&self, plain: &[u8]) -> [u8; 32] {
        hmac::sign(&self.check, plain).as_ref().try_into().expect("32 bytes")
    }

    /// The key's fingerprint (a chunk is a whole number of sectors, so no chunk's check is this).
    fn fingerprint(&self) -> [u8; 16] {
        hmac::sign(&self.check, b"key").as_ref()[..16]
            .try_into()
            .expect("16 bytes")
    }

    /// The pass and the chunk's number are in what the tag covers: a slot from another pass, or
    /// of another chunk, does not open.
    fn aad(id: &[u8; 16], chunk: u64) -> [u8; 24] {
        let mut aad = [0; 24];
        aad[..16].copy_from_slice(id);
        aad[16..].copy_from_slice(&chunk.to_le_bytes());
        aad
    }

    /// A nonce, then the chunk sealed.
    fn seal(&self, id: &[u8; 16], chunk: u64, plain: &[u8]) -> Vec<u8> {
        let nonce: [u8; NONCE] = crate::crypt::random();
        let mut sealed = Zeroizing::new(plain.to_vec());
        let nonced = aead::Nonce::assume_unique_for_key(nonce);
        let done = self
            .aead
            .seal_in_place_append_tag(nonced, aead::Aad::from(Self::aad(id, chunk)), &mut *sealed);
        done.expect("a chunk is short enough to seal");
        [&nonce[..], &sealed].concat()
    }

    /// The plain chunk of `len` bytes, if the slot holds the backup of `chunk` of this pass.
    fn open(&self, id: &[u8; 16], chunk: u64, len: usize, slot: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let (nonce, sealed) = slot.get(..NONCE + len + TAG)?.split_at(NONCE);
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut sealed = Zeroizing::new(sealed.to_vec());
        let plain = self
            .aead
            .open_in_place(nonce, aead::Aad::from(Self::aad(id, chunk)), &mut sealed);
        Some(Zeroizing::new(plain.ok()?.to_vec()))
    }
}

/// Encrypt the partition's `total` bytes in place, `chunk` bytes at a time, or go on from where
/// a cut left it. `part` is the raw partition, `mapped` the same partition under `key` (a write
/// to it lands encrypted), `journal` the config partition.
///
/// A pass already finished is a no-op (it writes nothing). `hit` is called at each [`Point`]; an
/// error from it stops the pass there, as a power cut would. A chunk part written whose backup
/// does not open is an error naming it, with nothing more written. The journal says "finished"
/// ([`finished`]) when this returns: [`forget`] it only once the lock record is on the disk.
pub fn pass(
    part: &impl Disk,
    mapped: &(impl Disk + ?Sized),
    journal: &impl Disk,
    key: &[u8; 64],
    (total, chunk): (u64, usize),
    hit: &mut dyn FnMut(Point) -> io::Result<()>,
) -> io::Result<()> {
    if chunk == 0 || chunk > CHUNK || chunk % SECTOR != 0 || total == 0 || total % SECTOR as u64 != 0 {
        return Err(bad(
            "the partition and the chunk are a whole number of sectors, and a chunk is at most 256 KiB",
        ));
    }
    let sealer = Sealer::new(key);
    let n = total.div_ceil(chunk as u64);
    let of = |i: u64| (i * chunk as u64, (total - i * chunk as u64).min(chunk as u64) as usize);
    // A chunk as the partition has it, with its check.
    let look = |i: u64| -> io::Result<(Zeroizing<Vec<u8>>, [u8; 32])> {
        let (at, len) = of(i);
        let mut plain = Zeroizing::new(vec![0; len]);
        part.read_at(&mut plain, at)?;
        let check = sealer.mac(&plain);
        Ok((plain, check))
    };
    let mut carry = None;
    let mut head = match heads(journal)? {
        (None, None, true) => {
            let first = look(0)?;
            let fresh = Header {
                id: crate::crypt::random(),
                total,
                chunk: chunk as u32,
                done: 0,
                key: sealer.fingerprint(),
                next: first.1,
            };
            put(journal, &fresh, hit)?;
            carry = Some(first);
            fresh
        }
        (None, None, false) => {
            return Err(bad(
                "both copies of the journal's header are damaged: nothing is written",
            ));
        }
        (one, two, _) => {
            let head = [one, two]
                .into_iter()
                .flatten()
                .max_by_key(|head| head.done)
                .expect("one is whole");
            if [one, two].into_iter().flatten().any(|other| other.id != head.id) {
                return Err(bad("the journal's two headers are of two passes: nothing is written"));
            }
            if head.total != total || head.chunk as usize != chunk || head.done > n {
                return Err(bad("the journal is of a partition of another size: nothing is written"));
            }
            if head.key != sealer.fingerprint() {
                return Err(bad("the journal is of another key: nothing is written"));
            }
            if (one, two) != (Some(head), Some(head)) {
                put(journal, &head, hit)?;
            }
            head
        }
    };
    // The backup of the chunk the header says is next, if there is one: that chunk may be plain,
    // part written or whole, and this puts it right in all three.
    let mut backup = None;
    if head.done < n {
        let mut slot = vec![0; SLOT_ROOM];
        journal.read_at(&mut slot, SLOT)?;
        backup = sealer.open(&head.id, head.done, of(head.done).1, &slot);
    }
    while head.done < n {
        let (at, len) = of(head.done);
        let plain = match backup.take() {
            Some(plain) => plain,
            None => {
                let (plain, check) = match carry.take() {
                    Some(read) => read,
                    None => look(head.done)?,
                };
                // No backup that opens: the chunk must still be plain, or this is a half written
                // one with nothing to put it right from, and a backup of it would seal the half.
                if check != head.next {
                    return Err(bad(&format!(
                        "chunk {} is neither plain nor backed up: nothing more is written",
                        head.done
                    )));
                }
                journal.write_at(&sealer.seal(&head.id, head.done, &plain), SLOT)?;
                hit(Point::BackupWritten)?;
                // (The chunk is not written before its backup is on the disk.)
                journal.sync()?;
                hit(Point::BackupSynced)?;
                plain
            }
        };
        let half = (len / 2) & !(SECTOR - 1);
        if half > 0 {
            mapped.write_at(&plain[..half], at)?;
        }
        hit(Point::ChunkPart)?;
        mapped.write_at(&plain[half..], at + half as u64)?;
        mapped.sync()?;
        hit(Point::ChunkDone)?;
        // (The next chunk's backup is not written before both headers say this one is done.)
        head.done += 1;
        // (The header keeps the check of the chunk it now says is next, read while it is plain.)
        match head.done < n {
            true => {
                let next = look(head.done)?;
                head.next = next.1;
                carry = Some(next);
            }
            false => head.next = [0; 32],
        }
        put(journal, &head, hit)?;
    }
    // The slot empty once the pass is finished, and a finished pass found again writes only if it
    // is not.
    let mut slot = vec![0; SLOT_ROOM];
    journal.read_at(&mut slot, SLOT)?;
    if slot.iter().any(|&byte| byte != 0) {
        slot.fill(0);
        journal.write_at(&slot, SLOT)?;
        journal.sync()?;
    }
    Ok(())
}

/// Whether the journal holds a pass that is finished: every chunk through the mapping. The
/// journal keeps it so, and a [`pass`] over it is a no-op, until [`forget`].
pub fn finished(journal: &impl Disk) -> io::Result<bool> {
    let (one, two, _) = heads(journal)?;
    let newest = [one, two].into_iter().flatten().max_by_key(|head| head.done);
    Ok(newest.is_some_and(|head| head.finished()))
}

/// The journal emptied, headers and slot: the pass is forgotten, and a [`pass`] after it starts
/// from the partition's first byte, which is only right over a partition that is still plain.
/// So not before the node's lock record (T-1137) says the partition is encrypted and is on the
/// disk: until then "no journal" and "a pass never begun" are the same to this engine.
pub fn forget(journal: &impl Disk) -> io::Result<()> {
    // (The second header first, each to the disk before the next: a cut in the first's write leaves
    // it torn beside a second that is zero, which reads as a pass never begun, not as a damaged one.)
    journal.write_at(&[0; ROOM], HEAD2)?;
    journal.sync()?;
    journal.write_at(&[0; ROOM], HEAD1)?;
    journal.sync()?;
    journal.write_at(&vec![0; SLOT_ROOM], SLOT)?;
    journal.sync()
}

/// Whether the journal holds a pass at all: a header that is whole or one that is not (a pass
/// whose two copies are both damaged is begun, and [`pass`] says what is wrong with it).
pub fn begun(journal: &impl Disk) -> io::Result<bool> {
    let (one, two, zero) = heads(journal)?;
    Ok(one.is_some() || two.is_some() || !zero)
}

/// How far the journal's pass is: the chunks done and the chunks in all, if it holds one.
pub fn progress(journal: &impl Disk) -> io::Result<Option<(u64, u64)>> {
    let (one, two, _) = heads(journal)?;
    let newest = [one, two].into_iter().flatten().max_by_key(|head| head.done);
    Ok(newest.map(|head| (head.done, head.total.div_ceil(head.chunk.max(1) as u64))))
}

/// One progress line: the percent through, and the text the console and the panel show.
#[derive(Debug, PartialEq)]
pub struct Line {
    pub percent: u64,
    pub text: String,
}

/// A pass's progress line, at most one a second (T-1139). It counts from the chunks the journal
/// already had, so a resumed pass rates only what it did since it resumed.
pub struct Meter {
    total: u64,
    chunk: usize,
    first: u64,
    began: Instant,
    last: Instant,
}

impl Meter {
    pub fn new(total: u64, chunk: usize, done: u64, now: Instant) -> Meter {
        Meter {
            total,
            chunk: chunk.max(1),
            first: done,
            began: now,
            last: now,
        }
    }

    /// The bytes `done` chunks cover, the last chunk stopping at the partition's end.
    fn bytes(&self, done: u64) -> u64 {
        (done * self.chunk as u64).min(self.total)
    }

    /// How far through the partition `done` chunks are, in whole percent (bytes, not chunks).
    pub fn percent(&self, done: u64) -> u64 {
        self.bytes(done) * 100 / self.total.max(1)
    }

    /// The line for `done` chunks done at `now`, if a second has passed since the last one.
    pub fn due(&mut self, done: u64, now: Instant) -> Option<Line> {
        if now.duration_since(self.last) < Duration::from_secs(1) {
            return None;
        }
        self.last = now;
        let total = self.total.max(1);
        let through = self.bytes(done);
        let percent = self.percent(done);
        let since = through.saturating_sub(self.bytes(self.first));
        let secs = now.duration_since(self.began).as_secs_f64();
        let rate = if secs > 0.0 { since as f64 / secs } else { 0.0 };
        let left = if rate > 0.0 {
            format!("about {} left", eta((total - through) as f64 / rate))
        } else {
            "estimate unknown".to_string()
        };
        let chunks = self.total.div_ceil(self.chunk as u64);
        Some(Line {
            percent,
            text: format!(
                "{percent}% of {} MB, {:.1} MB/s, {left} (chunk {done} of {chunks})",
                self.total / 1_000_000,
                rate / 1e6
            ),
        })
    }

    /// What the pass says when it starts: its size, or where a resumed pass resumes.
    pub fn start_line(&self) -> String {
        let chunks = self.total.div_ceil(self.chunk as u64);
        if self.first == 0 {
            format!("{chunks} chunks of {} KiB", self.chunk >> 10)
        } else {
            let at = self.bytes(self.first);
            let percent = self.percent(self.first);
            format!("resumed at chunk {} of {chunks}, at byte {at} ({percent}%)", self.first)
        }
    }
}

/// An estimate in seconds, minutes or hours, rounded up so that it is never short.
fn eta(secs: f64) -> String {
    let s = secs.ceil() as u64;
    if s < 60 {
        format!("{s} s")
    } else if s < 3600 {
        format!("{} min", s.div_ceil(60))
    } else {
        format!("{} h", s.div_ceil(3600))
    }
}

/// Whether the node's state is to be encrypted in place at this start.
pub fn marked(config: &impl Disk) -> io::Result<bool> {
    let mut room = [0; ROOM];
    config.read_at(&mut room, MARK)?;
    Ok(room.starts_with(MARKED))
}

/// Put the marker down: the next start runs the pass. The lock record, holding the state's key,
/// is on the disk before this (init has no key to pass under without it), and the journal is
/// empty: a pass of an older journal would be taken for this one's.
#[allow(dead_code, reason = "what the verb writes (T-1106 slice b)")]
pub fn mark(config: &impl Disk) -> io::Result<()> {
    if begun(config)? {
        return Err(bad("the journal holds a pass already: it is not marked over"));
    }
    let mut room = [0; ROOM];
    room[..MARKED.len()].copy_from_slice(MARKED);
    config.write_at(&room, MARK)?;
    config.sync()
}

/// Take the marker away.
pub fn unmark(config: &impl Disk) -> io::Result<()> {
    config.write_at(&[0; ROOM], MARK)?;
    config.sync()
}

/// What [`at_boot`] did.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outcome {
    /// No marker and no journal: a node that is as it was.
    Nothing,
    /// A finished pass's journal, left by a cut after the marker went, forgotten.
    Cleaned,
    /// The pass ran (or was found finished) and the marker and the journal are gone.
    Encrypted,
}

/// Makes the mapping of the partition under a key and hands it to what it is given; closes it
/// after (a mapping that cannot be closed is an error).
pub type Open<'a> = &'a dyn Fn(&[u8; 64], &mut dyn FnMut(&dyn Disk) -> io::Result<()>) -> io::Result<()>;

/// What init does before the state is mounted or opened: decide from the marker, the journal and
/// the lock record's `key` (the state's, while no other node holds it) whether a pass is due,
/// and run it over the partition's `total` bytes.
///
/// - Marked, with a key: the pass (a finished one is a no-op), then the marker goes, and then the
///   journal; in that order, so that a cut between them leaves a finished journal with no marker
///   ([`Outcome::Cleaned`] at the next start) and never a marker with no journal over a state
///   that is encrypted already, which would be encrypted again.
/// - Marked, with no key: an error. Nothing is written.
/// - Not marked, a finished journal: forgotten. A journal not finished: an error, the state is
///   part encrypted and nothing to mount it as.
/// - Neither: nothing.
///
/// An error leaves the marker and the journal as they are, and the caller does not mount the
/// state: it is not a plain file system to mount as it lies.
pub fn at_boot(
    config: &impl Disk,
    part: &impl Disk,
    total: u64,
    key: Option<&[u8]>,
    open: Open,
    hit: &mut dyn FnMut(Point) -> io::Result<()>,
) -> io::Result<Outcome> {
    match (marked(config)?, begun(config)?) {
        (false, false) => Ok(Outcome::Nothing),
        (false, true) if finished(config)? => forget(config).map(|()| Outcome::Cleaned),
        (false, true) => Err(bad(
            "a pass was begun and its marker is gone: the state is part encrypted, and not mounted as either",
        )),
        (true, _) => {
            let key = key.and_then(|key| <&[u8; 64]>::try_from(key).ok());
            let key =
                key.ok_or_else(|| bad("a pass is due, and the lock record holds no key of 64 bytes to do it with"))?;
            open(key, &mut |mapped| {
                pass(part, mapped, config, key, (total, CHUNK), &mut *hit)
            })?;
            // (The marker first: see above.)
            unmark(config)?;
            forget(config)?;
            Ok(Outcome::Encrypted)
        }
    }
}

#[cfg(test)]
mod support {
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub const KEY: [u8; 64] = [7; 64];
    /// Seven chunks of 4 KiB and a short one of 1 KiB.
    pub const SMALL: (u64, usize) = (7 * 4096 + 1024, 4096);

    /// What the disk does to writes that were not synced when the power went.
    #[derive(Clone, Copy, Debug)]
    pub enum Crash {
        /// None of them reached the disk.
        Lost,
        /// All of them did.
        Kept,
        /// The first half of each did (a torn write).
        Torn,
        /// The first 64 bytes of each did: a header with its new count and its old sum.
        Sliver,
    }
    pub const CRASHES: [Crash; 4] = [Crash::Lost, Crash::Kept, Crash::Torn, Crash::Sliver];

    /// A file whose writes wait for a sync, so that a missing sync shows: reads see them (a page
    /// cache does), a crash drops them, keeps them or tears them.
    pub struct Lossy {
        pub file: File,
        pending: RefCell<Vec<(u64, Vec<u8>)>>,
    }

    impl Lossy {
        pub fn crash(&self, how: Crash) {
            for (at, bytes) in self.pending.take() {
                let kept = match how {
                    Crash::Lost => 0,
                    Crash::Kept => bytes.len(),
                    Crash::Torn => bytes.len() / 2,
                    Crash::Sliver => bytes.len().min(64),
                };
                self.file.write_all_at(&bytes[..kept], at).unwrap();
            }
        }
        /// What is on the file, not what a read would see.
        pub fn on_disk(&self) -> Vec<u8> {
            let mut all = vec![0; self.file.metadata().unwrap().len() as usize];
            self.file.read_exact_at(&mut all, 0).unwrap();
            all
        }
    }

    impl Disk for Lossy {
        fn read_at(&self, buf: &mut [u8], at: u64) -> io::Result<()> {
            self.file.read_exact_at(buf, at)?;
            for (from, bytes) in self.pending.borrow().iter() {
                let (lo, hi) = (at.max(*from), (at + buf.len() as u64).min(from + bytes.len() as u64));
                if lo < hi {
                    buf[(lo - at) as usize..(hi - at) as usize]
                        .copy_from_slice(&bytes[(lo - from) as usize..(hi - from) as usize]);
                }
            }
            Ok(())
        }
        fn write_at(&self, buf: &[u8], at: u64) -> io::Result<()> {
            self.pending.borrow_mut().push((at, buf.to_vec()));
            Ok(())
        }
        fn sync(&self) -> io::Result<()> {
            for (at, bytes) in self.pending.take() {
                self.file.write_all_at(&bytes, at)?;
            }
            Ok(())
        }
    }

    /// The byte the fake mapping adds at a place; never zero, so no byte stays what it was.
    fn stream(at: u64) -> u8 {
        (at.wrapping_mul(0x9E37_79B1) >> 5) as u8 | 1
    }

    /// The fake mapping: what a write puts on the partition is the bytes XOR the stream of their
    /// place (one place, one ciphertext, as dm-crypt's), and a read undoes it.
    pub struct Xor<'a>(pub &'a Lossy);

    impl Disk for Xor<'_> {
        fn read_at(&self, buf: &mut [u8], at: u64) -> io::Result<()> {
            self.0.read_at(buf, at)?;
            buf.iter_mut()
                .zip(at..)
                .for_each(|(byte, place)| *byte ^= stream(place));
            Ok(())
        }
        fn write_at(&self, buf: &[u8], at: u64) -> io::Result<()> {
            let sealed: Vec<u8> = buf.iter().zip(at..).map(|(byte, place)| byte ^ stream(place)).collect();
            self.0.write_at(&sealed, at)
        }
        fn sync(&self) -> io::Result<()> {
            self.0.sync()
        }
    }

    /// A partition file full of plain data, and a config partition file (1 MiB) of zeros, in a
    /// directory of their own that goes with the rig.
    pub struct Rig {
        dir: PathBuf,
        pub raw: Lossy,
        pub journal: Lossy,
        pub plain: Vec<u8>,
        pub total: u64,
        pub chunk: usize,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl Rig {
        pub fn new((total, chunk): (u64, usize)) -> Rig {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "kith-in-place-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let make = |name: &str, len: u64| {
                let mut options = File::options();
                let file = options.read(true).write(true).create(true).truncate(true);
                let file = file.open(dir.join(name)).unwrap();
                file.set_len(len).unwrap();
                Lossy {
                    file,
                    pending: RefCell::new(Vec::new()),
                }
            };
            let (raw, journal) = (make("part", total), make("config", 1 << 20));
            // Random-looking plain data, so that a chunk found anywhere else is found by its start.
            let mut state = 0x2545_F491_4F6C_DD1Du64;
            let plain: Vec<u8> = (0..total)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    (state >> 24) as u8
                })
                .collect();
            raw.file.write_all_at(&plain, 0).unwrap();
            Rig {
                dir,
                raw,
                journal,
                plain,
                total,
                chunk,
            }
        }

        /// A pass, with `hit` at each point.
        pub fn run(&self, hit: &mut dyn FnMut(Point) -> io::Result<()>) -> io::Result<()> {
            pass(
                &self.raw,
                &Xor(&self.raw),
                &self.journal,
                &KEY,
                (self.total, self.chunk),
                hit,
            )
        }

        /// A pass that stops at the `k`th time it reaches `at`; whether it did.
        pub fn cut(&self, at: Point, k: usize) -> bool {
            let mut seen = 0;
            let done = self.run(&mut |point| {
                if point == at {
                    seen += 1;
                    if seen > k {
                        return Err(io::Error::other("cut"));
                    }
                }
                Ok(())
            });
            match done {
                Ok(()) => false,
                Err(e) => {
                    assert_eq!(e.to_string(), "cut", "a pass fails for a reason of its own: {e}");
                    true
                }
            }
        }

        pub fn crash(&self, how: Crash) {
            self.raw.crash(how);
            self.journal.crash(how);
        }

        /// Whether a start of some chunk's plain bytes is anywhere in the journal's file.
        pub fn leaks(&self) -> bool {
            let journal = self.journal.on_disk();
            let found = |needle: &[u8]| {
                let mut from = 0;
                while let Some(at) = journal[from..].iter().position(|&byte| byte == needle[0]) {
                    from += at;
                    if journal[from..].starts_with(needle) {
                        return true;
                    }
                    from += 1;
                }
                false
            };
            self.plain.chunks(self.chunk).any(|chunk| found(&chunk[..16]))
        }

        /// The end state of any pass: every byte of the partition encrypted, all of it readable
        /// through the mapping, the slot empty, and the journal saying all done.
        pub fn assert_done(&self, why: &str) {
            self.assert_encrypted(why);
            let journal = self.journal.on_disk();
            let head = Header::parse(journal[HEAD1 as usize..][..ROOM].try_into().unwrap());
            assert_eq!(
                head.map(|head| head.done),
                Some(self.total.div_ceil(self.chunk as u64)),
                "{why}"
            );
        }

        /// The partition is the plain data encrypted and reads back through the mapping, the
        /// slot is empty, and no plain data is in the journal: what a journal that was forgotten
        /// leaves too.
        pub fn assert_encrypted(&self, why: &str) {
            let on_disk = self.raw.on_disk();
            let want: Vec<u8> = self.plain.iter().zip(0..).map(|(byte, at)| byte ^ stream(at)).collect();
            assert!(on_disk == want, "{why}: the partition is not the plain data encrypted");
            let mut through = vec![0; self.plain.len()];
            Xor(&self.raw).read_at(&mut through, 0).unwrap();
            assert!(
                through == self.plain,
                "{why}: the mapping does not read back the plain data"
            );
            let journal = self.journal.on_disk();
            let slot = &journal[SLOT as usize..SLOT as usize + SLOT_ROOM];
            assert!(
                slot.iter().all(|&byte| byte == 0),
                "{why}: the backup slot is not empty"
            );
            assert!(!self.leaks(), "{why}: plain data is in the journal");
        }
    }
}

#[cfg(test)]
mod layout {
    use super::*;

    /// The journal's places are clear of each other, of the node's config (the first 64 KiB), of
    /// the lock record and its copy (`crypt::AT`, 4 KiB each), and inside the 1 MiB partition.
    #[test]
    fn the_journal_fits_clear_of_the_config_and_the_lock_record() {
        let lock = crate::crypt::AT..crate::crypt::AT + 2 * 4096;
        let places = [
            ("marker", MARK..MARK + ROOM as u64),
            ("header 1", HEAD1..HEAD1 + ROOM as u64),
            ("header 2", HEAD2..HEAD2 + ROOM as u64),
            ("backup slot", SLOT..SLOT + SLOT_ROOM as u64),
        ];
        let clear = |a: &std::ops::Range<u64>, b: &std::ops::Range<u64>| a.end <= b.start || b.end <= a.start;
        for (name, place) in &places {
            assert!(clear(place, &(0..64 << 10)), "{name} is in the node's config");
            assert!(clear(place, &lock), "{name} is on the lock record");
            assert!(place.end <= 1 << 20, "{name} is past the partition's end");
        }
        for (i, (one, a)) in places.iter().enumerate() {
            for (two, b) in &places[i + 1..] {
                assert!(clear(a, b), "{one} and {two} overlap");
            }
        }
        // A whole sealed chunk (nonce, chunk, tag) is in its slot, and the slot is sector aligned.
        const { assert!(NONCE + CHUNK + TAG <= SLOT_ROOM) };
        assert_eq!((HEAD1 | HEAD2 | SLOT) % SECTOR as u64, 0);
        const { assert!(BODY + 32 <= ROOM) };
    }

    /// A header reads back what it was made of, and not after one flipped byte, wherever it is.
    #[test]
    fn a_header_is_whole_or_nothing() {
        let head = Header {
            id: [9; 16],
            total: 1 << 30,
            chunk: 4096,
            done: 77,
            key: [3; 16],
            next: [4; 32],
        };
        let room = head.bytes();
        assert_eq!(Header::parse(&room), Some(head));
        for at in [
            0,
            16,
            31,
            33,
            41,
            45,
            52,
            67,
            68,
            99,
            BODY,
            BODY + 31,
            BODY + 32,
            ROOM - 1,
        ] {
            let mut torn = room;
            torn[at] ^= 1;
            assert_eq!(Header::parse(&torn), None, "a flipped byte at {at}");
        }
    }
}

#[cfg(test)]
mod pass {
    use super::support::*;
    use super::*;

    /// A pass over a file leaves every chunk encrypted and the whole readable through the
    /// mapping; the chunk is the real 256 KiB, with a short one at the end.
    #[test]
    fn a_pass_encrypts_every_chunk_and_the_mapping_reads_it_back() {
        let rig = Rig::new((2 * CHUNK as u64 + 3 * 512, CHUNK));
        rig.run(&mut |_| Ok(())).unwrap();
        rig.assert_done("a pass over 3 chunks");
    }

    /// Small chunks, a short one last; and every byte differs from what it was (no chunk left plain).
    #[test]
    fn a_pass_leaves_no_byte_plain() {
        let rig = Rig::new(SMALL);
        rig.run(&mut |_| Ok(())).unwrap();
        rig.assert_done("a pass over 8 chunks");
        let raw = rig.raw.on_disk();
        assert!(raw.iter().zip(&rig.plain).all(|(a, b)| a != b));
    }

    /// A second pass after the first is done writes nothing to the partition and reaches no point
    /// of a chunk.
    #[test]
    fn a_pass_that_is_done_is_a_no_op() {
        let rig = Rig::new(SMALL);
        rig.run(&mut |_| Ok(())).unwrap();
        let mut points = Vec::new();
        rig.run(&mut |point| {
            points.push(point);
            Ok(())
        })
        .unwrap();
        assert_eq!(points, []);
        rig.assert_done("a second pass");
    }

    /// What a pass refuses, and that it writes nothing when it does.
    #[test]
    fn a_pass_refuses_what_does_not_fit_and_writes_nothing() {
        let rig = Rig::new(SMALL);
        let go = |total: u64, chunk: usize| {
            pass(
                &rig.raw,
                &Xor(&rig.raw),
                &rig.journal,
                &KEY,
                (total, chunk),
                &mut |_| Ok(()),
            )
        };
        for (total, chunk) in [
            (SMALL.0, 0),
            (SMALL.0, 100),
            (SMALL.0, CHUNK + 512),
            (0, 4096),
            (SMALL.0 + 1, 4096),
        ] {
            assert!(go(total, chunk).is_err(), "{total} {chunk}");
        }
        // A journal of a pass over another size, or in another chunk, is not taken over this one.
        assert!(rig.cut(Point::ChunkDone, 2));
        let before = (rig.raw.on_disk(), rig.journal.on_disk());
        for (total, chunk) in [(SMALL.0 + 512, 4096), (SMALL.0, 2048)] {
            let why = go(total, chunk).unwrap_err().to_string();
            assert!(why.contains("another size"), "{why}");
        }
        assert!(before == (rig.raw.on_disk(), rig.journal.on_disk()));
        // And the pass it was is still finished by its own size.
        rig.run(&mut |_| Ok(())).unwrap();
        rig.assert_done("after the refusals");
    }

    /// Both header copies damaged, with a pass begun: nothing is written, not a start over.
    #[test]
    fn a_pass_with_both_headers_torn_stops() {
        let rig = Rig::new(SMALL);
        assert!(rig.cut(Point::HeaderBoth, 3));
        rig.crash(Crash::Kept);
        // The pass's random id with 0xff at byte 20 of the header, as one pass in 256 has it.
        let (Some(mut head), _, _) = heads(&rig.journal).unwrap() else {
            panic!("no header")
        };
        head.id[4] = 0xff;
        for at in [HEAD1, HEAD2] {
            rig.journal.file.write_all_at(&head.bytes(), at).unwrap();
        }
        // So the damage goes in the magic, which 0xff always changes (at byte 20 it changed nothing).
        for head in [HEAD1, HEAD2] {
            rig.journal.file.write_all_at(&[0xff], head + 4).unwrap();
        }
        let before = (rig.raw.on_disk(), rig.journal.on_disk());
        let why = rig.run(&mut |_| Ok(())).unwrap_err().to_string();
        assert!(why.contains("damaged"), "{why}");
        assert!(before == (rig.raw.on_disk(), rig.journal.on_disk()));
    }

    /// A finished pass stays finished, in the journal, until `forget`: `finished` says so before
    /// and after a cut at the last header, a pass over it writes not one byte, and `forget`
    /// empties the headers and the slot and touches nothing else of the config partition.
    #[test]
    fn a_finished_pass_stays_finished_until_forgotten() {
        let rig = Rig::new(SMALL);
        rig.journal.file.write_all_at(&[5; 64], 0).unwrap();
        rig.journal.file.write_all_at(&[6; 64], crate::crypt::AT).unwrap();
        assert!(!finished(&rig.journal).unwrap(), "a journal with no pass");
        assert!(rig.cut(Point::ChunkDone, 7));
        assert!(!finished(&rig.journal).unwrap(), "a pass one chunk short");
        rig.run(&mut |_| Ok(())).unwrap();
        assert!(finished(&rig.journal).unwrap());
        let before = (rig.raw.on_disk(), rig.journal.on_disk());
        rig.run(&mut |_| panic!("a finished pass reaches no point")).unwrap();
        assert!(
            before == (rig.raw.on_disk(), rig.journal.on_disk()),
            "a finished pass wrote"
        );
        forget(&rig.journal).unwrap();
        let journal = rig.journal.on_disk();
        assert!(!finished(&rig.journal).unwrap());
        assert_eq!(heads(&rig.journal).unwrap(), (None, None, true));
        assert!(journal[..64] == [5; 64] && journal[crate::crypt::AT as usize..][..64] == [6; 64]);
    }

    /// A finished pass cut before its slot was emptied empties it on the next call, and only then
    /// writes.
    #[test]
    fn a_finished_pass_cut_before_its_slot_is_empty_empties_it() {
        let rig = Rig::new(SMALL);
        assert!(rig.cut(Point::HeaderBoth, 8));
        rig.crash(Crash::Lost);
        assert!(finished(&rig.journal).unwrap());
        rig.run(&mut |_| Ok(())).unwrap();
        rig.assert_done("a finished pass with a backup left");
    }

    /// A journal of another key is not gone on with, and nothing is written.
    #[test]
    fn a_journal_of_another_key_stops() {
        let rig = Rig::new(SMALL);
        assert!(rig.cut(Point::ChunkDone, 3));
        let before = (rig.raw.on_disk(), rig.journal.on_disk());
        let other = pass(
            &rig.raw,
            &Xor(&rig.raw),
            &rig.journal,
            &[8; 64],
            (rig.total, rig.chunk),
            &mut |_| Ok(()),
        );
        let why = other.unwrap_err().to_string();
        assert!(why.contains("another key"), "{why}");
        assert!(before == (rig.raw.on_disk(), rig.journal.on_disk()));
        rig.run(&mut |_| Ok(())).unwrap();
        rig.assert_done("after the refusal");
    }
}

#[cfg(test)]
mod cut {
    use super::support::*;
    use super::*;

    const POINTS: [Point; 7] = [
        Point::BackupWritten,
        Point::BackupSynced,
        Point::ChunkPart,
        Point::ChunkDone,
        Point::HeaderFirst,
        Point::HeaderSecond,
        Point::HeaderBoth,
    ];
    /// More than the times any point is reached in a pass over [`SMALL`] (8 chunks, 9 headers).
    const MOST: usize = 10;

    /// A cut at every point of a chunk, at every chunk, with the disk losing, keeping or tearing
    /// what was not synced: the next pass reaches the end state of one that was never cut, and
    /// no plain chunk is in the journal at the cut.
    #[test]
    fn a_cut_at_every_point_resumes_to_the_same_end_state() {
        let mut cuts = 0;
        for how in CRASHES {
            for point in POINTS {
                for k in 0..MOST {
                    let rig = Rig::new(SMALL);
                    if !rig.cut(point, k) {
                        assert!(k > 0, "{point:?} is never reached");
                        break;
                    }
                    cuts += 1;
                    rig.crash(how);
                    assert!(
                        !rig.leaks(),
                        "plain data in the journal after a cut at {point:?} {k} ({how:?})"
                    );
                    rig.run(&mut |_| Ok(())).unwrap();
                    rig.assert_done(&format!("a cut at {point:?} {k} ({how:?})"));
                }
            }
        }
        // Eight chunks reach each point of a chunk eight times, and the headers nine.
        assert_eq!(cuts, 4 * (4 * 8 + 3 * 9));
    }

    /// A second cut, in the resume, at every point it reaches: the third pass still ends the same.
    #[test]
    fn a_cut_in_the_resume_resumes_too() {
        for how in CRASHES {
            for point in POINTS {
                for k in [0, 1, 4, 7] {
                    for again in POINTS {
                        let rig = Rig::new(SMALL);
                        assert!(rig.cut(point, k));
                        rig.crash(how);
                        let cut = rig.cut(again, 0);
                        rig.crash(how);
                        rig.run(&mut |_| Ok(())).unwrap();
                        rig.assert_done(&format!(
                            "cuts at {point:?} {k} then {again:?} ({how:?}, cut again: {cut})"
                        ));
                    }
                }
            }
        }
    }

    /// The real chunk: a cut part way through a 256 KiB chunk (the pass has to put the half back).
    #[test]
    fn a_cut_in_a_real_chunk_resumes() {
        for point in POINTS {
            let rig = Rig::new((CHUNK as u64 + 8192, CHUNK));
            assert!(rig.cut(point, 1));
            rig.crash(Crash::Torn);
            rig.run(&mut |_| Ok(())).unwrap();
            rig.assert_done(&format!("a cut at {point:?} in a real chunk"));
        }
    }

    /// A first header copy that is torn (the second says the chunk before): the pass takes the
    /// second, writes the chunk again from the slot that is still its backup, and ends the same.
    #[test]
    fn a_torn_first_header_copy_resumes_from_the_second() {
        for k in 0..9 {
            let rig = Rig::new(SMALL);
            assert!(rig.cut(Point::HeaderFirst, k));
            rig.crash(Crash::Lost);
            rig.journal.file.write_all_at(&[0xff; 100], HEAD1 + 10).unwrap();
            rig.run(&mut |_| Ok(())).unwrap();
            rig.assert_done(&format!("a torn first copy at header {k}"));
        }
    }

    /// A backup torn after the sync that cut it is a disk fault, but one that is only fatal when
    /// the chunk was already part written: before that, the chunk is read plain again.
    #[test]
    fn a_torn_backup_before_the_chunk_is_written_resumes() {
        for k in 0..8 {
            let rig = Rig::new(SMALL);
            assert!(rig.cut(Point::BackupSynced, k));
            rig.crash(Crash::Lost);
            rig.journal.file.write_all_at(&[0xff; 100], SLOT + 20).unwrap();
            rig.run(&mut |_| Ok(())).unwrap();
            rig.assert_done(&format!("a torn backup of chunk {k}"));
        }
    }

    /// A chunk part written whose backup does not open (a bad sector in the slot, say) is neither
    /// plain nor backed up: the pass stops at it, names it, and writes nothing, rather than seal
    /// half of it as if it were plain. Cut before the chunk is written, the same torn slot is no
    /// matter (the test above).
    #[test]
    fn a_part_written_chunk_with_no_backup_stops_and_writes_nothing() {
        for (point, k) in [
            (Point::ChunkPart, 0),
            (Point::ChunkPart, 3),
            (Point::ChunkPart, 7),
            (Point::ChunkDone, 4),
        ] {
            let rig = Rig::new(SMALL);
            assert!(rig.cut(point, k));
            rig.crash(Crash::Kept);
            rig.journal.file.write_all_at(&[0xff; 100], SLOT + 20).unwrap();
            let before = (rig.raw.on_disk(), rig.journal.on_disk());
            let why = rig.run(&mut |_| Ok(())).unwrap_err().to_string();
            assert!(
                why.contains(&format!("chunk {k} ")) && why.contains("backed up"),
                "{point:?} {k}: {why}"
            );
            assert!(
                before == (rig.raw.on_disk(), rig.journal.on_disk()),
                "{point:?} {k} wrote"
            );
        }
    }

    /// A slot left by another pass does not open for this one.
    #[test]
    fn a_backup_of_another_pass_is_not_used() {
        let rig = Rig::new(SMALL);
        let (id, other) = ([1; 16], [2; 16]);
        let sealed = Sealer::new(&KEY).seal(&id, 0, &rig.plain[..4096]);
        assert!(Sealer::new(&KEY).open(&id, 0, 4096, &sealed).is_some());
        assert!(Sealer::new(&KEY).open(&other, 0, 4096, &sealed).is_none());
        assert!(Sealer::new(&KEY).open(&id, 1, 4096, &sealed).is_none());
        assert!(Sealer::new(&[8; 64]).open(&id, 0, 4096, &sealed).is_none());
        assert!(sealed[NONCE..].windows(16).all(|window| window != &rig.plain[..16]));
    }
}

/// What init does at a start (T-1137): the marker, the journal and the key decide whether a pass
/// runs, and the marker and the journal go only after it did.
#[cfg(test)]
mod boot {
    use super::support::*;
    use super::*;
    use std::cell::Cell;

    /// Three chunks of the real size, the last one short.
    const THREE: (u64, usize) = (2 * CHUNK as u64 + 1024, CHUNK);
    const POINTS: [Point; 7] = [
        Point::BackupWritten,
        Point::BackupSynced,
        Point::ChunkPart,
        Point::ChunkDone,
        Point::HeaderFirst,
        Point::HeaderSecond,
        Point::HeaderBoth,
    ];

    /// `at_boot` over the rig, the mapping the fake one: it says it was made under `KEY`.
    fn boot(rig: &Rig, key: Option<&[u8]>, hit: &mut dyn FnMut(Point) -> io::Result<()>) -> io::Result<Outcome> {
        let open = |got: &[u8; 64], run: &mut dyn FnMut(&dyn Disk) -> io::Result<()>| {
            assert_eq!(got, &KEY, "the mapping is made under the lock record's key");
            run(&Xor(&rig.raw))
        };
        at_boot(&rig.journal, &rig.raw, rig.total, key, &open, hit)
    }

    fn go(rig: &Rig) -> io::Result<Outcome> {
        boot(rig, Some(&KEY), &mut |_| Ok(()))
    }

    /// The journal's headers and slot are all zero: forgotten, or never begun.
    fn forgotten(rig: &Rig) -> bool {
        let journal = rig.journal.on_disk();
        journal[HEAD1 as usize..][..2 * ROOM].iter().all(|&b| b == 0)
            && journal[SLOT as usize..][..SLOT_ROOM].iter().all(|&b| b == 0)
    }

    /// A node with no marker and no journal is not touched: nothing is mapped, nothing written.
    #[test]
    fn a_node_with_no_marker_and_no_journal_is_left_alone() {
        let rig = Rig::new(THREE);
        let before = (rig.raw.on_disk(), rig.journal.on_disk());
        let mapped = Cell::new(false);
        let open = |_: &[u8; 64], _: &mut dyn FnMut(&dyn Disk) -> io::Result<()>| {
            mapped.set(true);
            Ok(())
        };
        let done = at_boot(&rig.journal, &rig.raw, rig.total, Some(&KEY), &open, &mut |_| Ok(()));
        assert_eq!(done.unwrap(), Outcome::Nothing);
        assert!(!mapped.get(), "a mapping was made for no pass");
        assert!(
            before == (rig.raw.on_disk(), rig.journal.on_disk()),
            "something was written"
        );
    }

    /// The marker is written and read back, and cleared; a zeroed room is none.
    #[test]
    fn a_marker_is_written_read_and_cleared() {
        let rig = Rig::new(THREE);
        assert!(!marked(&rig.journal).unwrap());
        mark(&rig.journal).unwrap();
        assert!(marked(&rig.journal).unwrap());
        assert!(rig.journal.on_disk()[MARK as usize..].starts_with(MARKED));
        unmark(&rig.journal).unwrap();
        assert!(!marked(&rig.journal).unwrap());
    }

    /// A marker over a journal that holds a pass is refused: that pass is another's, and the
    /// new one would be taken for it.
    #[test]
    fn a_marker_is_not_put_over_a_journal() {
        let rig = Rig::new(THREE);
        assert!(rig.cut(Point::ChunkDone, 1));
        let why = mark(&rig.journal).unwrap_err().to_string();
        assert!(why.contains("journal"), "{why}");
        assert!(!marked(&rig.journal).unwrap());
    }

    /// A marked node with a key: the pass runs, the partition is its plain data encrypted, and
    /// only then the marker and the journal are gone.
    #[test]
    fn a_marked_node_is_encrypted_and_then_the_marker_and_journal_go() {
        let rig = Rig::new(THREE);
        mark(&rig.journal).unwrap();
        assert_eq!(go(&rig).unwrap(), Outcome::Encrypted);
        rig.assert_encrypted("a marked node");
        assert!(!marked(&rig.journal).unwrap(), "the marker stays");
        assert!(!begun(&rig.journal).unwrap() && forgotten(&rig), "the journal stays");
        // (The next start has nothing to do.)
        assert_eq!(go(&rig).unwrap(), Outcome::Nothing);
    }

    /// A marker and no key (or one that is not a key of 64 bytes) is an error that writes
    /// nothing: the marker stays, and the partition is plain.
    #[test]
    fn a_marker_with_no_usable_key_is_an_error_and_writes_nothing() {
        for key in [None, Some(&KEY[..32]), Some(&[][..])] {
            let rig = Rig::new(THREE);
            mark(&rig.journal).unwrap();
            let before = (rig.raw.on_disk(), rig.journal.on_disk());
            let why = boot(&rig, key, &mut |_| Ok(())).unwrap_err().to_string();
            assert!(why.contains("key"), "{why}");
            assert!(before == (rig.raw.on_disk(), rig.journal.on_disk()));
            assert!(marked(&rig.journal).unwrap());
        }
    }

    /// A cut at every point of the pass, the disk losing, keeping or tearing what was not
    /// synced: the marker is still there, and the next start ends in the same state as an
    /// uncut one.
    #[test]
    fn a_cut_pass_resumes_at_the_next_start() {
        let mut cuts = 0;
        for how in CRASHES {
            for point in POINTS {
                for k in 0..5 {
                    let rig = Rig::new(THREE);
                    mark(&rig.journal).unwrap();
                    let mut seen = 0;
                    let cut = boot(&rig, Some(&KEY), &mut |at| {
                        seen += usize::from(at == point);
                        if at == point && seen > k {
                            return Err(io::Error::other("cut"));
                        }
                        Ok(())
                    });
                    match cut {
                        Ok(done) => {
                            assert!(k > 0, "{point:?} is never reached");
                            assert_eq!(done, Outcome::Encrypted);
                            break;
                        }
                        Err(e) => assert_eq!(e.to_string(), "cut", "{e}"),
                    }
                    cuts += 1;
                    rig.crash(how);
                    assert!(
                        marked(&rig.journal).unwrap(),
                        "the marker went with the pass cut at {point:?} {k}"
                    );
                    assert!(!rig.leaks(), "plain data in the journal at {point:?} {k} ({how:?})");
                    let why = format!("a cut at {point:?} {k} ({how:?})");
                    assert_eq!(go(&rig).unwrap(), Outcome::Encrypted, "{why}");
                    rig.assert_encrypted(&why);
                    assert!(!marked(&rig.journal).unwrap() && forgotten(&rig), "{why}");
                }
            }
        }
        assert!(cuts > 4 * 7 * 2, "{cuts}");
    }

    /// A pass that is finished with the marker still there (a cut between the pass and the
    /// marker's clearing): nothing is written to the partition, and the marker and the journal go.
    #[test]
    fn a_finished_pass_with_its_marker_is_cleared_and_not_run_again() {
        let rig = Rig::new(THREE);
        mark(&rig.journal).unwrap();
        rig.run(&mut |_| Ok(())).unwrap();
        let raw = rig.raw.on_disk();
        assert_eq!(go(&rig).unwrap(), Outcome::Encrypted);
        assert!(raw == rig.raw.on_disk(), "the partition was written again");
        rig.assert_encrypted("a finished pass");
        assert!(!marked(&rig.journal).unwrap() && forgotten(&rig));
    }

    /// A finished journal with no marker (a cut between the marker's clearing and the journal's):
    /// the journal is forgotten, the partition untouched.
    #[test]
    fn a_finished_journal_with_no_marker_is_forgotten() {
        let rig = Rig::new(THREE);
        rig.run(&mut |_| Ok(())).unwrap();
        let raw = rig.raw.on_disk();
        assert_eq!(go(&rig).unwrap(), Outcome::Cleaned);
        assert!(raw == rig.raw.on_disk() && forgotten(&rig));
        rig.assert_encrypted("a finished journal");
    }

    /// A journal's `forget` cut at each of its writes and syncs (the operation itself not done),
    /// the unsynced writes then lost, kept, torn or cut to a sliver: the marker was cleared before,
    /// so the next start must not find an error in a state that is fully encrypted. It ends with
    /// no pass in the journal, whatever was torn.
    #[test]
    fn a_forget_that_is_cut_never_leaves_a_journal_the_next_start_refuses() {
        /// Fails the `at`th write or sync it is asked for.
        struct Cutting<'a>(&'a Lossy, Cell<usize>);
        impl Cutting<'_> {
            fn step(&self) -> io::Result<()> {
                let left = self.1.get();
                self.1.set(left.wrapping_sub(1));
                if left == 0 {
                    Err(io::Error::other("cut"))
                } else {
                    Ok(())
                }
            }
        }
        impl Disk for Cutting<'_> {
            fn read_at(&self, buf: &mut [u8], at: u64) -> io::Result<()> {
                self.0.read_at(buf, at)
            }
            fn write_at(&self, buf: &[u8], at: u64) -> io::Result<()> {
                self.step()?;
                self.0.write_at(buf, at)
            }
            fn sync(&self) -> io::Result<()> {
                self.step()?;
                self.0.sync()
            }
        }
        let mut cuts = 0;
        for at in 0..8 {
            for how in CRASHES {
                let rig = Rig::new(THREE);
                rig.run(&mut |_| Ok(())).unwrap();
                rig.journal.sync().unwrap();
                let cut = forget(&Cutting(&rig.journal, Cell::new(at))).is_err();
                cuts += usize::from(cut);
                rig.crash(how);
                let why = format!("a forget cut at step {at} ({how:?})");
                let done = go(&rig).unwrap_or_else(|e| panic!("{why}: the next start refuses it: {e}"));
                assert!(matches!(done, Outcome::Nothing | Outcome::Cleaned), "{why}: {done:?}");
                rig.assert_encrypted(&why);
                // (A first header torn beside a zero second is what a cut leaves: a pass never begun.)
                assert!(
                    !begun(&rig.journal).unwrap(),
                    "{why}: the journal is still a pass after it"
                );
            }
        }
        assert!(
            cuts >= 6 * CRASHES.len(),
            "the forget was cut {cuts} times: it has six steps"
        );
    }

    /// A journal that is not finished and no marker: the state is part encrypted and no
    /// plain file system. An error that keeps the journal, as it was; nothing is mapped.
    #[test]
    fn an_unfinished_journal_with_no_marker_is_an_error_that_keeps_it() {
        let rig = Rig::new(THREE);
        assert!(rig.cut(Point::ChunkDone, 1));
        rig.crash(Crash::Lost);
        let before = (rig.raw.on_disk(), rig.journal.on_disk());
        let why = go(&rig).unwrap_err().to_string();
        assert!(why.contains("marker"), "{why}");
        assert!(before == (rig.raw.on_disk(), rig.journal.on_disk()));
    }

    /// The pass's own error (a chunk neither plain nor backed up, here) leaves the marker and
    /// the journal, and says so.
    #[test]
    fn a_pass_that_fails_leaves_the_marker_and_the_journal() {
        let rig = Rig::new(THREE);
        mark(&rig.journal).unwrap();
        assert!(
            boot(&rig, Some(&KEY), &mut |at| match at == Point::ChunkPart {
                true => Err(io::Error::other("cut")),
                false => Ok(()),
            })
            .is_err()
        );
        rig.crash(Crash::Kept);
        rig.journal.file.write_all_at(&[0xff; 100], SLOT + 20).unwrap();
        let why = go(&rig).unwrap_err().to_string();
        assert!(why.contains("backed up"), "{why}");
        assert!(marked(&rig.journal).unwrap() && begun(&rig.journal).unwrap());
    }

    /// How far a pass is, for what init says of it and the screen of a later slice shows.
    #[test]
    fn progress_is_the_chunks_done_and_the_chunks_in_all() {
        let rig = Rig::new(THREE);
        assert_eq!(progress(&rig.journal).unwrap(), None);
        assert!(rig.cut(Point::HeaderBoth, 2));
        assert_eq!(progress(&rig.journal).unwrap(), Some((2, 3)));
        rig.run(&mut |_| Ok(())).unwrap();
        assert_eq!(progress(&rig.journal).unwrap(), Some((3, 3)));
    }
}

/// The progress line of a pass (T-1139): the percent, the rate and the estimate, at most one a
/// second; and where a resumed pass starts.
#[cfg(test)]
mod progress {
    use super::support::*;
    use super::*;
    use std::time::{Duration, Instant};

    /// A line is due a second after the last one, not before.
    #[test]
    fn a_line_is_due_at_most_once_a_second() {
        let t0 = Instant::now();
        let mut meter = Meter::new(100_000_000, 1_000_000, 0, t0);
        assert!(meter.due(1, t0 + Duration::from_millis(999)).is_none());
        assert!(meter.due(2, t0 + Duration::from_secs(1)).is_some());
        assert!(meter.due(3, t0 + Duration::from_millis(1500)).is_none());
        assert!(meter.due(4, t0 + Duration::from_secs(2)).is_some());
    }

    /// 20 of 100 MB in 2 s is 10 MB a second, so 8 s are left: the line says the percent, the rate,
    /// the estimate and the chunk.
    #[test]
    fn a_line_says_the_percent_the_rate_and_the_estimate() {
        let t0 = Instant::now();
        let mut meter = Meter::new(100_000_000, 1_000_000, 0, t0);
        let line = meter.due(20, t0 + Duration::from_secs(2)).unwrap();
        assert_eq!(line.percent, 20);
        assert_eq!(line.text, "20% of 100 MB, 10.0 MB/s, about 8 s left (chunk 20 of 100)");
    }

    /// Nothing through yet: no rate to divide by, so no estimate, and not a made-up one.
    #[test]
    fn a_line_with_nothing_through_has_no_estimate() {
        let t0 = Instant::now();
        let mut meter = Meter::new(100_000_000, 1_000_000, 0, t0);
        let line = meter.due(0, t0 + Duration::from_secs(1)).unwrap();
        assert_eq!(line.text, "0% of 100 MB, 0.0 MB/s, estimate unknown (chunk 0 of 100)");
    }

    /// A resumed pass rates what it did since it resumed, not what the journal already had.
    #[test]
    fn a_resumed_pass_rates_only_what_it_did_since() {
        let t0 = Instant::now();
        let mut meter = Meter::new(100_000_000, 1_000_000, 50, t0);
        let line = meter.due(60, t0 + Duration::from_secs(1)).unwrap();
        assert_eq!(line.percent, 60);
        assert!(line.text.contains("10.0 MB/s, about 4 s left"), "{}", line.text);
    }

    /// The estimate in seconds, minutes or hours.
    #[test]
    fn an_estimate_is_said_in_seconds_minutes_or_hours() {
        assert_eq!(eta(8.0), "8 s");
        assert_eq!(eta(600.0), "10 min");
        assert_eq!(eta(7300.0), "3 h");
    }

    /// A fresh pass says its size; a resumed one says the chunk and byte it resumes at, and the percent.
    #[test]
    fn a_pass_says_where_it_starts() {
        let t0 = Instant::now();
        let fresh = Meter::new(2 * CHUNK as u64 + 1024, CHUNK, 0, t0);
        assert_eq!(fresh.start_line(), "3 chunks of 256 KiB");
        let resumed = Meter::new(2 * CHUNK as u64 + 1024, CHUNK, 2, t0);
        assert_eq!(resumed.start_line(), "resumed at chunk 2 of 3, at byte 524288 (99%)");
    }

    /// A pass cut in two and resumed: the start line names the chunk the journal says it resumes at.
    #[test]
    fn a_resume_names_the_chunk_the_journal_resumes_at() {
        let rig = Rig::new((2 * CHUNK as u64 + 1024, CHUNK));
        assert!(rig.cut(Point::ChunkDone, 1));
        rig.crash(Crash::Kept);
        let (done, chunks) = progress(&rig.journal).unwrap().unwrap();
        assert_eq!((done, chunks), (1, 3));
        let line = Meter::new(rig.total, rig.chunk, done, Instant::now()).start_line();
        assert!(line.starts_with("resumed at chunk 1 of 3, at byte 262144"), "{line}");
    }

    /// A real pass, a chunk every 40 ms: the lines it prints come at most a second apart, eight of
    /// them over its eight seconds.
    #[test]
    fn a_pass_prints_at_most_a_line_a_second() {
        let rig = Rig::new((200 * 4096, 4096));
        let t0 = Instant::now();
        let mut meter = Meter::new(rig.total, rig.chunk, 0, t0);
        let (mut at, mut done, mut lines) = (t0, 0, Vec::new());
        rig.run(&mut |point| {
            if point == Point::ChunkDone {
                done += 1;
                at += Duration::from_millis(40);
                lines.extend(meter.due(done, at).map(|line| (at, line)));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(lines.len(), 8, "200 chunks of 40 ms are 8 s");
        for pair in lines.windows(2) {
            assert!(pair[1].0 - pair[0].0 >= Duration::from_secs(1));
        }
        rig.assert_done("a pass over 200 chunks");
    }
}
