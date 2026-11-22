//! kith OS's two slots (PLAN §4.9). A node runs from one (`kith.slot=a` on its kernel
//! command line) and an update is written into the other: the root, its verity tree, and
//! on the ESP the kernel image that names them, as `kith-N-SLOT+3.efi`. N is one more
//! than any other there, so the boot loader (systemd-boot) starts it first; `+3` is three
//! tries, which the loader counts down in the name each time it starts it. A slot that
//! comes up is marked good by dropping the counter ([`settle`]); one that has no tries
//! left is passed over, and the machine is back on the slot that worked.
//!
//! An update is one file: a 4096-byte header (a line of JSON, padded: os/update.sh) and
//! then the pieces it names, in order. An update the cluster hands out (an OSRelease, see
//! `update`) must have its header signed by the release's key ([`signed`]); one given
//! with `kith.update=` must carry a signature by one of the image's release keys after its last
//! piece ([`stick_trailer`], [`Vouch`]) when the image holds any, and a version over the node's
//! floor; with none it is taken on the word of whoever is at the machine's boot menu.

use serde::Deserialize;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const HEADER: usize = 4096;
/// Why an update is not written yet: nothing is wrong with it, and it may be tried again.
pub const TOO_EARLY: &str = "the slot this node runs from is not marked good yet: an update waits for that";

/// How often the boot loader starts a new slot before it gives up on it.
const TRIES: u32 = 3;
const ESP: &str = "/run/esp";
/// The wait before a restart after a failed start: ten seconds, doubled for each failed
/// start in a row before it, and ten minutes at most.
const WAIT: u64 = 10;
const WAIT_MAX: u64 = 600;
/// How many starts in a row have failed. Beside the kernel images, not one of them.
const FAILED: &str = "kith.failed";

#[derive(Deserialize)]
struct Header {
    format: u32,
    version: String,
    /// The root's verity hash, which is on the command line of a node that runs it.
    hash: String,
    pieces: Vec<Piece>,
    /// Optional, and signed with the rest of the header: see [`digests`]. An older kithd
    /// does not read it; one that cannot make sense of it takes the update in full.
    #[serde(default)]
    kithd: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Piece {
    name: String,
    size: u64,
    sha256: String,
}

fn header(block: &[u8]) -> Result<Header, String> {
    let header: Header =
        serde_json::from_slice(block.trim_ascii()).map_err(|e| format!("this is not a kith OS update: {e}"))?;
    let names: Vec<&str> = header.pieces.iter().map(|piece| piece.name.as_str()).collect();
    let hash = header.hash.len() == 64 && header.hash.bytes().all(|b| b.is_ascii_hexdigit());
    if header.format != 1 || names != ["root", "verity", "a", "b"] || !hash {
        return Err("this update is of a kind this kithd does not know".into());
    }
    Ok(header)
}

/// What an update's header says it is made of, for [`way`] (the header's `kithd` object, made
/// by the build, see os/build.sh): the digests of kithd (`sha256`), of what the boot file is
/// but for the root's own hash (`kernel`), and of the root but for kithd and its os-release
/// (`rest`), as 64 hex digits each. `None` for a header without them or with them malformed.
pub fn digests(block: &[u8]) -> Option<[String; 3]> {
    let header = header(block).ok()?;
    let kithd = header.kithd?;
    let get = |name: &str| {
        let digest = kithd.get(name)?.as_str()?;
        (digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())).then(|| digest.to_ascii_lowercase())
    };
    Some([get("sha256")?, get("kernel")?, get("rest")?])
}

/// How an update is taken. (The code asks [`why_full`] and `Keys::kithd_only` for the reason; this
/// names the answer for the tests of slice 1.)
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub enum Way {
    /// Only kithd differs from the running system: the kernel and the rest of the root are the same.
    KithdOnly,
    /// A slot written and a reboot, as ever.
    Full,
}

/// `new`, the header of an update, against `running`, the header that wrote the system that
/// runs (kept: [`keep_signed`]; the caller has shown it is the system's own). Kithd alone only
/// when both say what they are made of and the kernel and the rest of the root are the same;
/// on any doubt, in full.
#[cfg(test)]
pub fn way(new: &[u8], running: &[u8]) -> Way {
    match why_full(new, running) {
        None => Way::KithdOnly,
        Some(_) => Way::Full,
    }
}

/// Why [`way`] is [`Way::Full`] (for the log): `None` where it is kithd alone.
pub fn why_full(new: &[u8], running: &[u8]) -> Option<&'static str> {
    match (digests(new), digests(running)) {
        (None, _) => Some("the update's header does not say what it is made of (no kithd object)"),
        (_, None) => Some("the header kept for the running system does not say what it is made of"),
        (Some([_, kernel, _]), Some([_, kernel_now, _])) if kernel != kernel_now => Some("the kernel image differs"),
        (Some([_, _, rest]), Some([_, _, rest_now])) if rest != rest_now => Some("the rest of the root differs"),
        _ => None,
    }
}

/// `kith-7-b+2-1.efi`: generation 7, slot b, 2 tries left. Without a counter it is good.
fn entry(name: &str) -> Option<(u64, char, Option<u32>)> {
    let name = name.to_ascii_lowercase();
    let stem = name.strip_prefix("kith-")?.strip_suffix(".efi")?;
    let (id, counter) = match stem.split_once('+') {
        Some((id, counter)) => (id, Some(counter)),
        None => (stem, None),
    };
    let (generation, slot) = id.split_once('-')?;
    let slot = ['a', 'b'].into_iter().find(|s| slot == s.to_string())?;
    let tries = match counter {
        Some(counter) => Some(counter.split('-').next()?.parse().ok()?),
        None => None,
    };
    Some((generation.parse().ok()?, slot, tries))
}

/// The kernel images on the ESP: file name, generation, slot, tries left.
fn entries(esp: &Path) -> Vec<(String, u64, char, Option<u32>)> {
    let names = std::fs::read_dir(esp).into_iter().flatten().flatten();
    names
        .filter_map(|file| {
            let name = file.file_name().into_string().ok()?;
            let (generation, slot, tries) = entry(&name)?;
            Some((name, generation, slot, tries))
        })
        .collect()
}

/// A piece, from the update into `to`: all of it, and the bytes its header promised.
fn piece(from: &mut impl Read, to: &mut impl Write, piece: &Piece) -> Result<(), String> {
    let mut sum = ring::digest::Context::new(&ring::digest::SHA256);
    let (mut left, mut some) = (piece.size, vec![0; 1 << 16]);
    while left > 0 {
        let now = usize::try_from(left).map_or(some.len(), |left| left.min(some.len()));
        from.read_exact(&mut some[..now])
            .map_err(|e| format!("the update ends before its {} does: {e}", piece.name))?;
        sum.update(&some[..now]);
        to.write_all(&some[..now])
            .map_err(|e| format!("writing {}: {e}", piece.name))?;
        left -= now as u64;
    }
    if crate::pki::hex(sum.finish().as_ref()) != piece.sha256.to_ascii_lowercase() {
        return Err(format!(
            "the update is damaged: its {} is not what its header says",
            piece.name
        ));
    }
    Ok(())
}

/// For [`install`]: the header must be signed (`signature`, hex) by the key `public`.
pub fn signed<'a>(
    signature: Option<&'a str>,
    public: Option<&'a str>,
) -> impl FnOnce(&[u8]) -> Result<(), String> + 'a {
    move |header| {
        let (Some(signature), Some(public)) = (signature, public) else {
            return Err("the release is not signed: it names no publicKey, or no signature".into());
        };
        match kith_packages::artifact::signed_by(header, signature, public)? {
            true => Ok(()),
            false => Err("the signature is not the release's key's over this update".into()),
        }
    }
}

/// Where a slot is: its two partitions and the ESP's directory of kernel images.
pub struct Places {
    pub root: PathBuf,
    pub verity: PathBuf,
    pub esp: PathBuf,
}

/// Write an update into slot `into` (the one this node does not run from) and hand the
/// next start to it. Says the version written, or nothing when `running` (this node's
/// kernel command line) shows it is what runs already.
///
/// The slot's old kernel image goes first and its new one comes last, by a rename: stopped
/// anywhere in between, the boot loader knows nothing of this slot and the node starts as
/// it did before.
///
/// `vouched` is asked about the header before anything is touched: the header names every
/// piece's hash, so whoever vouches for it vouches for all of the update.
pub fn install(
    from: &mut impl Read,
    running: &str,
    into: char,
    places: &Places,
    vouched: impl FnOnce(&[u8]) -> Result<(), String>,
) -> Result<Option<String>, String> {
    let mut block = [0; HEADER];
    from.read_exact(&mut block)
        .map_err(|e| format!("this is not a kith OS update: {e}"))?;
    vouched(&block)?;
    let header = header(&block)?;
    if running.contains(&header.hash) {
        return Ok(None);
    }
    let listed = entries(&places.esp);
    let next = listed.iter().map(|(_, generation, ..)| generation).max().unwrap_or(&0) + 1;
    // The slot that is kept must be one that is known to start: `into` is about to lose
    // its kernel image, and if what is written there fails, the other is all there is.
    if !listed
        .iter()
        .any(|(_, _, slot, tries)| *slot != into && tries.is_none())
    {
        return Err(TOO_EARLY.into());
    }
    let new = places.esp.join("kith.new");
    let _ = std::fs::remove_file(&new);
    for (name, ..) in listed.iter().filter(|(_, _, slot, _)| *slot == into) {
        std::fs::remove_file(places.esp.join(name)).map_err(|e| format!("removing {name}: {e}"))?;
    }
    let settled = |what: &Path| std::fs::File::open(what).and_then(|file| file.sync_all());
    settled(&places.esp).map_err(|e| format!("writing the ESP: {e}"))?;

    for piece in &header.pieces {
        let to = match piece.name.as_str() {
            "root" => &places.root,
            "verity" => &places.verity,
            name if name == into.to_string() => &new,
            _ => {
                self::piece(from, &mut std::io::sink(), piece)?;
                continue;
            }
        };
        let failed = |e: std::io::Error| format!("{}: {e}", to.display());
        let mut file = if to == &new {
            std::fs::File::create(to).map_err(failed)?
        } else {
            let mut partition = std::fs::OpenOptions::new().write(true).open(to).map_err(failed)?;
            let room = partition.seek(SeekFrom::End(0)).map_err(failed)?;
            partition.seek(SeekFrom::Start(0)).map_err(failed)?;
            if piece.size > room {
                return Err(format!(
                    "the update's {} is {} bytes and {} has room for {room}",
                    piece.name,
                    piece.size,
                    to.display()
                ));
            }
            partition
        };
        self::piece(from, &mut file, piece)?;
        file.sync_all().map_err(failed)?;
    }
    let name = format!("kith-{next}-{into}+{TRIES}.efi");
    std::fs::rename(&new, places.esp.join(&name))
        .and_then(|()| settled(&places.esp))
        .map_err(|e| format!("adding {name} to the ESP: {e}"))?;
    Ok(Some(header.version))
}

/// Counts one more failed start in a row on the ESP, and says how many there now are. The
/// count is written to a file of its own and renamed into place, so a power cut leaves
/// the old count or the new one (or, FAT having no rename over a file that is one step,
/// none: the next wait is then the first). If it cannot be written, the count is still returned.
pub fn failed(esp: &Path) -> u32 {
    let count = std::fs::read_to_string(esp.join(FAILED))
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok())
        .unwrap_or(0)
        .saturating_add(1);
    let new = esp.join("kith.failed.new");
    let written = std::fs::File::create(&new)
        .and_then(|mut file| {
            file.write_all(format!("{count}\n").as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&new, esp.join(FAILED)))
        .and_then(|()| std::fs::File::open(esp)?.sync_all());
    if let Err(e) = written {
        eprintln!("kithd: init: counting the failed start: {e}");
    }
    count
}

/// How long to wait before a restart after the `failures`th failed start in a row. Zero
/// failures is the first wait: ten seconds, then doubling, to ten minutes.
pub fn wait(failures: u32) -> std::time::Duration {
    let doublings = failures.saturating_sub(1).min(16);
    std::time::Duration::from_secs((WAIT << doublings).min(WAIT_MAX))
}

/// Whether the slot this node runs from is marked good: `settle` has found it so, or made it so.
pub static GOOD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// This node came up from `slot`: mark it good (the boot loader stops counting its
/// tries), and say what became of a slot that did not come up. What to say is returned.
/// The count of failed starts is cleared too: this start came up.
pub fn settle(slot: char, esp: &Path) -> Vec<String> {
    let mut said = Vec::new();
    match std::fs::remove_file(esp.join(FAILED)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => said.push(format!("clearing the count of failed starts: {e}")),
    }
    for (name, generation, its, tries) in entries(esp) {
        match tries {
            Some(_) if its == slot => {
                let good = format!("kith-{generation}-{slot}.efi");
                said.push(match std::fs::rename(esp.join(&name), esp.join(&good)) {
                    Ok(()) => format!("slot {slot} is good"),
                    Err(e) => format!("marking slot {slot} good: {e}"),
                });
            }
            // (Said at every start until an update replaces that slot: it is still there.)
            Some(0) => said.push(format!(
                "slot {its} did not come up in {TRIES} tries: this is slot {slot}, which ran before it"
            )),
            _ => {}
        }
    }
    GOOD.fetch_or(good(slot, esp), std::sync::atomic::Ordering::Relaxed);
    said
}

/// Is `slot` marked good: there, and its tries no longer counted?
fn good(slot: char, esp: &Path) -> bool {
    let is = |(_, _, its, tries): &(String, u64, char, Option<u32>)| *its == slot && tries.is_none();
    entries(esp).iter().any(is)
}

/// The ESP's directory of kernel images, mounted for as long as `with` runs. One caller at a
/// time (there is one mount point): a second waits, and a `with` that panics still unmounts.
/// Not for a runtime's thread while an update (`into_slot`) runs: it holds the mount as long as the download.
pub fn esp<T>(with: impl FnOnce(&Path) -> T) -> Result<T, String> {
    use nix::mount::{MsFlags, mount, umount};
    let device = crate::init::labelled("esp").ok_or("no partition is labelled esp")?;
    let mounting = || {
        let _ = std::fs::create_dir_all(ESP);
        let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
        mount(Some(&device), ESP, Some("vfat"), flags, None::<&str>)
            .map_err(|e| format!("mounting {}: {e}", device.display()))
    };
    // (What was done there is done; left mounted, it is written out when the node stops.)
    let unmounting = || {
        if let Err(e) = umount(ESP) {
            eprintln!("kithd: init: unmounting the ESP: {e}");
        }
    };
    mounted(mounting, unmounting, || with(&Path::new(ESP).join("EFI/Linux")))
}

/// `with`, between `mount` and `unmount`, one caller at a time. The lock is held for as long
/// as the mount is, and a panic in `with` unmounts on the way out (the lock is not poisoned
/// for later callers: what it guards is the mount, which is let go of).
fn mounted<T>(
    mount: impl FnOnce() -> Result<(), String>,
    unmount: impl FnOnce(),
    with: impl FnOnce() -> T,
) -> Result<T, String> {
    struct Unmount<F: FnOnce()>(Option<F>);
    impl<F: FnOnce()> Drop for Unmount<F> {
        fn drop(&mut self) {
            if let Some(unmount) = self.0.take() {
                unmount();
            }
        }
    }
    static MOUNTED: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = MOUNTED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    mount()?;
    let _mounted = Unmount(Some(unmount));
    Ok(with())
}

/// What a stick's update must show (see `update::Keys::for_stick`): a signature of its header
/// by one of `keys` (none: nothing is asked), and a version at or over `floor`'s.
pub struct Vouch {
    pub keys: Vec<String>,
    pub floor: Option<PathBuf>,
}

/// The signature after a stick update's last piece (`sh os/update.sh --sign KEY UPDATE`,
/// appended to the file): 128 hex digits, the first on the stick after the pieces and any white
/// space, and whatever follows is not read (a stick written with `dd` has the device's old
/// bytes after it). Not checked here: the header it is of is the one `install` reads, see
/// [`Vouch::vouches`]. Leaves `from` at its start.
pub fn stick_trailer(from: &mut (impl Read + Seek)) -> Result<String, String> {
    let mut block = [0; HEADER];
    from.read_exact(&mut block)
        .map_err(|e| format!("this is not a kith OS update: {e}"))?;
    let size = header(&block)?
        .pieces
        .iter()
        .try_fold(HEADER as u64, |at, piece| at.checked_add(piece.size))
        .ok_or("this update's pieces are larger than any disk")?;
    let mut trailer = Vec::new();
    let read = from
        .seek(SeekFrom::Start(size))
        .and_then(|_| Read::take(&mut *from, 256).read_to_end(&mut trailer));
    from.seek(SeekFrom::Start(0))
        .map_err(|e| format!("reading the update again: {e}"))?;
    let hex = trailer
        .trim_ascii_start()
        .get(..128)
        .filter(|hex| hex.iter().all(u8::is_ascii_hexdigit));
    match (read, hex) {
        (Ok(_), Some(hex)) => Ok(String::from_utf8_lossy(hex).into_owned()),
        _ => Err("the update is not signed: this node holds release keys, so an update from a stick carries a signature of its header after its last piece".into()),
    }
}

impl Vouch {
    /// For [`install`]: the header it parses (the very bytes, not a second reading of the
    /// stick) is signed by one of the keys, with `signature` from [`stick_trailer`], and is
    /// not of a version under the floor.
    pub fn vouches<'a>(&'a self, signature: &'a str) -> impl FnOnce(&[u8]) -> Result<(), String> + 'a {
        move |block| {
            if self.keys.is_empty() {
                return Ok(());
            }
            let by = |key: &String| signed(Some(signature), Some(key))(block).is_ok();
            if !self.keys.iter().any(by) {
                return Err("the update's signature is by none of this node's release keys".into());
            }
            match &self.floor {
                Some(floor) => crate::update::above(floor, &header(block)?.version),
                None => Ok(()),
            }
        }
    }
}

/// `kith.update=DEVICE`: the update on that disk (a stick, a second disk) goes into the
/// slot this node does not run from. When the node holds release keys (`vouch`, see
/// `update::Keys::for_stick`) the stick must carry a signature by one of them
/// ([`stick_trailer`]) and a version over the floor; with none, nobody vouches for it but
/// whoever plugged it in. A `vouch` that is an error (keys that cannot be read) refuses.
pub fn update(device: &str, slot: char, running: &str, vouch: Result<Vouch, String>) -> Result<Option<String>, String> {
    let vouch = vouch?;
    let device = Path::new("/dev").join(device);
    // ponytail: a stick takes a moment to be there; ten seconds of looking, not an event.
    for _ in 0..100 {
        if device.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let mut from = std::fs::File::open(&device).map_err(|e| format!("{}: {e}", device.display()))?;
    let signature = if vouch.keys.is_empty() {
        String::new()
    } else {
        stick_trailer(&mut from)?
    };
    into_other_slot(&mut from, slot, running, vouch.vouches(&signature))
}

/// The update read from `from` goes into the slot this node (running from `slot`) does not
/// run from, if `vouched` says its header may. Says the version written; `None` when it
/// is what runs here already.
pub fn into_other_slot(
    from: &mut impl Read,
    slot: char,
    running: &str,
    vouched: impl FnOnce(&[u8]) -> Result<(), String>,
) -> Result<Option<String>, String> {
    Ok(into_slot(from, slot, running, vouched, false)?.0)
}

/// The two boot files a key is sealed ahead from (docs/adr-unlock.md): what the node
/// started from, and what the update has put in the other slot, which it will start.
pub struct Boots {
    pub running: Vec<u8>,
    pub new: Vec<u8>,
}

/// What [`into_slot`] says: the version written (`None`: what runs already) and, when asked
/// and something was written, the boot files (or why they could not be had).
pub type Written = (Option<String>, Option<Result<Boots, String>>);

/// [`into_other_slot`], and with `ahead`, when something was written, the boot files too
/// (read back from the ESP, and the new one proven to be the piece the header promised);
/// that may fail without the update failing.
pub fn into_slot(
    from: &mut impl Read,
    slot: char,
    running: &str,
    vouched: impl FnOnce(&[u8]) -> Result<(), String>,
    ahead: bool,
) -> Result<Written, String> {
    let into = other(slot);
    let part = |name: String| crate::init::labelled(&name).ok_or(format!("no partition is labelled {name}"));
    let (root, verity) = (part(format!("root-{into}"))?, part(format!("verity-{into}"))?);
    esp(|esp| {
        let places = Places {
            root,
            verity,
            esp: esp.into(),
        };
        let mut block = Vec::new();
        let version = install(from, running, into, &places, |header| {
            block = header.to_vec();
            vouched(header)
        })?;
        let boots = (ahead && version.is_some()).then(|| boots(esp, slot, into, &block));
        Ok((version, boots))
    })?
}

/// The slot an update is written into, beside `slot` (the one that runs).
pub fn other(slot: char) -> char {
    if slot == 'a' { 'b' } else { 'a' }
}

/// The kernel image on the ESP for `slot`: the newest, counting its tries (`counting`), or
/// the good one.
fn image(esp: &Path, slot: char, counting: bool) -> Result<PathBuf, String> {
    let newest = entries(esp)
        .into_iter()
        .filter(|(_, _, its, tries)| *its == slot && tries.is_some() == counting)
        .max_by_key(|(_, generation, ..)| *generation);
    newest
        .map(|(name, ..)| esp.join(name))
        .ok_or(format!("no kernel image for slot {slot} on the ESP"))
}

/// The good kernel image of `slot` as it is on the ESP: the image that runs from it.
pub fn running_image(esp: &Path, slot: char) -> Result<Vec<u8>, String> {
    let from = image(esp, slot, false)?;
    std::fs::read(&from).map_err(|e| format!("reading {}: {e}", from.display()))
}

/// [`running_image`], from where the ESP is mounted already: only inside a `with` of [`esp`]
/// (an update's `vouched` is one).
pub fn running_image_here(slot: char) -> Result<Vec<u8>, String> {
    running_image(&Path::new(ESP).join("EFI/Linux"), slot)
}

/// The header of the update that wrote `slot`, kept with its signature and key (`os-release-signed-`
/// and the slot: the signature and the key's hex, a line each, then the header block).
pub fn keep_signed(
    state: &Path,
    slot: char,
    signature: Option<&str>,
    public: Option<&str>,
    block: &[u8],
) -> Result<(), String> {
    let (Some(signature), Some(public)) = (signature, public) else {
        return Err("the release is not signed: it names no publicKey, or no signature".into());
    };
    let mut bytes = format!("{signature}\n{public}\n").into_bytes();
    bytes.extend_from_slice(block);
    let file = state.join(format!("os-release-signed-{slot}"));
    crate::pki::write_whole(&file, &bytes)
        .map_err(|e| format!("keeping the release's header ({}): {e}", file.display()))
}

/// What [`keep_signed`] kept for `slot`: the signature, the key, and the header block.
pub fn kept_signed(state: &Path, slot: char) -> Result<(String, String, Vec<u8>), String> {
    let file = state.join(format!("os-release-signed-{slot}"));
    let bytes = std::fs::read(&file).map_err(|e| format!("no release header is kept for slot {slot} ({e})"))?;
    let text = |line: Option<&[u8]>| line.and_then(|line| std::str::from_utf8(line).ok()).map(str::to_string);
    let mut parts = bytes.splitn(3, |byte| *byte == b'\n');
    match (text(parts.next()), text(parts.next()), parts.next()) {
        (Some(signature), Some(public), Some(block)) => Ok((signature, public, block.to_vec())),
        _ => Err(format!("the release header kept for slot {slot} is not what was kept")),
    }
}

/// The version `block` (a header) names, when its piece for `slot` is the image that `running`
/// is: the one check that a kept header is the system's own.
pub fn piece_of(block: &[u8], slot: char, running: &[u8]) -> Result<String, String> {
    let header = header(block)?;
    let name = slot.to_string();
    let promised = header
        .pieces
        .iter()
        .find(|piece| piece.name == name)
        .map(|piece| piece.sha256.to_ascii_lowercase());
    match promised {
        Some(promised) if promised == sha256(running) => Ok(header.version),
        _ => Err(format!(
            "the image that runs is not the piece the release names for slot {slot}"
        )),
    }
}

/// The boot files on the ESP for `running` (its image, marked good) and `into` (the one
/// just written, still counting its tries), where `block` is the header of what was written.
fn boots(esp: &Path, running: char, into: char, block: &[u8]) -> Result<Boots, String> {
    let read = |from: PathBuf| std::fs::read(&from).map_err(|e| format!("reading {}: {e}", from.display()));
    let (running, new) = (running_image(esp, running)?, read(image(esp, into, true)?)?);
    let promised = header(block)?
        .pieces
        .into_iter()
        .find(|piece| piece.name == into.to_string())
        .map(|piece| piece.sha256.to_ascii_lowercase());
    if promised.as_deref() != Some(sha256(&new).as_str()) {
        return Err(format!(
            "the kernel image on the ESP for slot {into} is not the piece the update promised"
        ));
    }
    Ok(Boots { running, new })
}

pub fn sha256(bytes: &[u8]) -> String {
    crate::pki::hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

/// Is `slot` on the ESP in `esp` still counting its tries: an update that has not come up yet?
pub fn trial(slot: char, esp: &Path) -> bool {
    entries(esp)
        .iter()
        .any(|(_, _, its, tries)| *its == slot && tries.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(bytes: &[u8]) -> String {
        crate::pki::hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
    }

    /// The header kept for a slot is read back as it was written, and it vouches for the
    /// image that runs only as the piece of its own slot: another image, or a slot with no
    /// header kept, is no.
    #[test]
    fn seals_again_the_signed_header_is_kept_per_slot_and_bound_to_its_image() {
        let dir = std::env::temp_dir().join(format!("kithd-os-signed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let running = b"the kernel image that runs".to_vec();
        let all = packed(
            &[("root", b""), ("verity", b""), ("a", b""), ("b", &running)],
            &"0".repeat(64),
        );
        let block = all[..HEADER].to_vec();
        assert!(kept_signed(&dir, 'b').is_err());
        keep_signed(&dir, 'b', Some("signature"), Some("public"), &block).unwrap();
        assert_eq!(
            kept_signed(&dir, 'b'),
            Ok(("signature".into(), "public".into(), block.clone()))
        );
        assert!(kept_signed(&dir, 'a').is_err());
        assert!(keep_signed(&dir, 'a', None, Some("public"), &block).is_err());
        assert_eq!(piece_of(&block, 'b', &running), Ok("9.9".to_string()));
        assert!(piece_of(&block, 'b', b"another image").is_err());
        assert!(piece_of(&block, 'a', &running).is_err());
        assert_eq!((other('a'), other('b')), ('b', 'a'));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An update as os/update.sh packs it.
    fn packed(pieces: &[(&str, &[u8])], hash: &str) -> Vec<u8> {
        let list: Vec<String> = pieces
            .iter()
            .map(|(name, bytes)| {
                format!(
                    r#"{{"name":"{name}","size":{},"sha256":"{}"}}"#,
                    bytes.len(),
                    sha(bytes)
                )
            })
            .collect();
        let line = format!(
            r#"{{"format":1,"version":"9.9","hash":"{hash}","pieces":[{}]}}"#,
            list.join(",")
        );
        let mut all = format!("{line:<4095}\n").into_bytes();
        pieces.iter().for_each(|(_, bytes)| all.extend_from_slice(bytes));
        all
    }

    /// A slot's places as files: partitions of 64 bytes, and an ESP with slot a in it.
    fn places(test: &str) -> Places {
        let dir = std::env::temp_dir().join(format!("kith-os-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let esp = dir.join("esp");
        std::fs::create_dir_all(&esp).unwrap();
        for partition in ["root", "verity"] {
            std::fs::write(dir.join(partition), [0; 64]).unwrap();
        }
        std::fs::write(esp.join("kith-1-a.efi"), "old a").unwrap();
        Places {
            root: dir.join("root"),
            verity: dir.join("verity"),
            esp,
        }
    }

    fn names(esp: &Path) -> Vec<String> {
        let mut names: Vec<String> = entries(esp).into_iter().map(|(name, ..)| name).collect();
        names.sort();
        names
    }

    const HASH: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const PIECES: [(&str, &[u8]); 4] = [
        ("root", b"a root"),
        ("verity", b"its tree"),
        ("a", b"for a"),
        ("b", b"for b"),
    ];

    #[test]
    fn os_reads_the_names_the_boot_loader_counts_in() {
        assert_eq!(entry("kith-1-a.efi"), Some((1, 'a', None)));
        assert_eq!(entry("kith-12-b+3.efi"), Some((12, 'b', Some(3))));
        assert_eq!(entry("KITH-7-B+0-3.EFI"), Some((7, 'b', Some(0))));
        for other in [
            "kith.new",
            "kith-a.efi",
            "kith-1-c.efi",
            "kith-x-a.efi",
            "kith-1-a+x.efi",
            "linux.efi",
        ] {
            assert_eq!(entry(other), None, "{other}");
        }
    }

    #[test]
    fn os_writes_an_update_into_the_other_slot_with_three_tries() {
        let places = places("writes");
        std::fs::write(places.esp.join("kith-0-b+0-3.efi"), "a b that failed").unwrap();
        let update = packed(&PIECES, HASH);
        let wrote = install(&mut update.as_slice(), "kith.slot=a", 'b', &places, |_| Ok(())).unwrap();
        assert_eq!(wrote.as_deref(), Some("9.9"));
        assert!(std::fs::read(&places.root).unwrap().starts_with(b"a root"));
        assert!(std::fs::read(&places.verity).unwrap().starts_with(b"its tree"));
        // One above every other, so first for the boot loader; the old b is gone.
        assert_eq!(names(&places.esp), ["kith-1-a.efi", "kith-2-b+3.efi"]);
        assert_eq!(std::fs::read(places.esp.join("kith-2-b+3.efi")).unwrap(), b"for b");

        // A slot still on trial is not the one to keep: no update until it is good.
        let early = install(
            &mut packed(&PIECES, &HASH.replace('0', "1")).as_slice(),
            "kith.slot=b",
            'a',
            &places,
            |_| Ok(()),
        );
        assert!(early.unwrap_err().contains("not marked good yet"));
        assert_eq!(names(&places.esp), ["kith-1-a.efi", "kith-2-b+3.efi"]);

        // What runs already is not written again (a `kith.update=` left on the command line).
        let again = install(
            &mut update.as_slice(),
            &format!("verity {HASH} kith.slot=b"),
            'a',
            &places,
            |_| Ok(()),
        );
        assert_eq!(again, Ok(None));
        assert_eq!(names(&places.esp), ["kith-1-a.efi", "kith-2-b+3.efi"]);
    }

    #[test]
    fn tpm_next_boots_are_the_two_images_and_the_new_one_is_proven() {
        let places = places("boots");
        let update = packed(&PIECES, HASH);
        assert!(!trial('b', &places.esp));
        install(&mut update.as_slice(), "kith.slot=a", 'b', &places, |_| Ok(())).unwrap();
        assert!(trial('b', &places.esp));
        assert!(!trial('a', &places.esp));
        let got = boots(&places.esp, 'a', 'b', &update[..HEADER]).unwrap();
        assert_eq!((&got.running[..], &got.new[..]), (&b"old a"[..], &b"for b"[..]));
        // a header that promises another image than the one on the ESP
        let mut other = PIECES;
        other[3] = ("b", b"for B");
        let why = boots(&places.esp, 'a', 'b', &packed(&other, HASH)[..HEADER])
            .err()
            .unwrap();
        assert!(why.contains("not the piece the update promised"), "{why}");
        // a header that is no header, a running slot with no good image, a new one with none
        assert!(boots(&places.esp, 'a', 'b', b"{}").is_err());
        assert!(boots(&places.esp, 'b', 'b', &update[..HEADER]).is_err());
        assert!(boots(&places.esp, 'a', 'a', &update[..HEADER]).is_err());
        // once the new slot is good it is no longer counting
        std::fs::rename(places.esp.join("kith-2-b+3.efi"), places.esp.join("kith-2-b.efi")).unwrap();
        assert!(!trial('b', &places.esp));
        assert!(boots(&places.esp, 'a', 'b', &update[..HEADER]).is_err());
    }

    #[test]
    fn os_refuses_an_update_that_is_damaged_cut_short_too_big_or_unknown() {
        let refused = |update: &[u8], test: &str| {
            let places = places(test);
            let why = install(&mut &*update, "kith.slot=a", 'b', &places, |_| Ok(())).unwrap_err();
            // The slot the node runs from is as it was, and no kernel image offers the other.
            assert_eq!(names(&places.esp), ["kith-1-a.efi"], "{why}");
            why
        };
        let mut damaged = packed(&PIECES, HASH);
        *damaged.last_mut().unwrap() ^= 1;
        assert!(refused(&damaged, "damaged").contains("damaged: its b"));
        let whole = packed(&PIECES, HASH);
        assert!(refused(&whole[..whole.len() - 2], "short").contains("ends before"));
        let big = [0; 65];
        let pieces = [("root", &big[..]), PIECES[1], PIECES[2], PIECES[3]];
        assert!(refused(&packed(&pieces, HASH), "big").contains("has room for 64"));
        assert!(refused(&packed(&PIECES[..3], HASH), "kind").contains("does not know"));
        assert!(refused(&packed(&PIECES, "short"), "hash").contains("does not know"));
        assert!(refused(b"not an update", "other").contains("not a kith OS update"));
    }

    #[test]
    fn os_writes_a_release_only_when_its_key_signed_the_header() {
        let (secret, public) = kith_packages::artifact::keygen().unwrap();
        let (_, another) = kith_packages::artifact::keygen().unwrap();
        let update = packed(&PIECES, HASH);
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(&unhex(&secret)).unwrap();
        let signature = crate::pki::hex(pair.sign(&update[..HEADER]).as_ref());
        let run = |update: &[u8], signature: Option<&str>, public: Option<&str>, test: &str| {
            let places = places(test);
            let done = install(&mut &*update, "kith.slot=a", 'b', &places, signed(signature, public));
            // Refused before anything is touched: slot b's partitions are as they were.
            if done.is_err() {
                assert_eq!(std::fs::read(&places.root).unwrap(), [0; 64]);
                assert_eq!(names(&places.esp), ["kith-1-a.efi"]);
            }
            done
        };
        assert_eq!(
            run(&update, Some(&signature), Some(&public), "signed"),
            Ok(Some("9.9".into()))
        );
        let not = |done: Result<Option<String>, String>, why: &str| assert!(done.unwrap_err().contains(why));
        not(run(&update, None, Some(&public), "unsigned"), "not signed");
        not(run(&update, Some(&signature), None, "keyless"), "not signed");
        not(
            run(&update, Some(&signature), Some(&another), "other-key"),
            "not the release's key's",
        );
        not(run(&update, Some("zz"), Some(&public), "not-hex"), "not hex");
        // A header that says other hashes than the one that was signed.
        let other: [(&str, &[u8]); 4] = [("root", b"b root"), PIECES[1], PIECES[2], PIECES[3]];
        not(
            run(&packed(&other, HASH), Some(&signature), Some(&public), "altered"),
            "not the release's key's",
        );
    }

    /// `update` with `signature` (hex, or none) on its end, as `sh os/update.sh --sign` prints it.
    fn stick(update: &[u8], signature: Option<&str>) -> Vec<u8> {
        let mut stick = update.to_vec();
        stick.extend(signature.map(|s| format!("{s}\n")).unwrap_or_default().bytes());
        stick
    }

    fn sign(secret: &str, update: &[u8]) -> String {
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(&unhex(secret)).unwrap();
        crate::pki::hex(pair.sign(&update[..HEADER]).as_ref())
    }

    /// What `update` does with a stick, less the device: the trailer, then `install` with the
    /// check over the block it parses.
    fn from_stick(
        from: &mut (impl Read + Seek),
        keys: &[String],
        floor: Option<PathBuf>,
        test: &str,
    ) -> Result<Option<String>, String> {
        let vouch = Vouch {
            keys: keys.to_vec(),
            floor,
        };
        let signature = if keys.is_empty() {
            String::new()
        } else {
            stick_trailer(from)?
        };
        install(from, "kith.slot=a", 'b', &places(test), vouch.vouches(&signature))
    }

    #[test]
    fn a_stick_update_is_taken_on_a_trailer_signed_by_an_image_key() {
        let (secret, public) = kith_packages::artifact::keygen().unwrap();
        let (_, another) = kith_packages::artifact::keygen().unwrap();
        let update = packed(&PIECES, HASH);
        let stick = stick(&update, Some(&sign(&secret, &update)));
        let keys = [another, public];
        let mut from = std::io::Cursor::new(&stick);
        assert_eq!(
            from_stick(&mut from, &keys, None, "stick-signed"),
            Ok(Some("9.9".into()))
        );
    }

    #[test]
    fn a_stick_update_is_taken_with_what_a_dd_leaves_after_the_trailer() {
        let (secret, public) = kith_packages::artifact::keygen().unwrap();
        let update = packed(&PIECES, HASH);
        for (left, test) in [(0u8, "dd-zeros"), (0xff, "dd-ones")] {
            let mut stick = stick(&update, Some(&sign(&secret, &update)));
            stick.extend([left; 300]);
            let mut from = std::io::Cursor::new(&stick);
            assert_eq!(
                from_stick(&mut from, std::slice::from_ref(&public), None, test),
                Ok(Some("9.9".into())),
                "{test}"
            );
        }
        // (White space before the signature is the same: a newline, say, after the last piece.)
        let mut stick = update.clone();
        stick.extend(*b"\n\n");
        stick.extend(sign(&secret, &update).bytes());
        let mut from = std::io::Cursor::new(&stick);
        assert_eq!(
            from_stick(&mut from, &[public], None, "dd-newlines"),
            Ok(Some("9.9".into()))
        );
    }

    #[test]
    fn a_stick_update_with_no_trailer_or_another_key_is_refused_untouched() {
        let (secret, public) = kith_packages::artifact::keygen().unwrap();
        let (other_secret, _) = kith_packages::artifact::keygen().unwrap();
        let update = packed(&PIECES, HASH);
        let keys = [public];
        let mut n = 0;
        let mut refused = |stick: &[u8]| {
            n += 1;
            let mut from = std::io::Cursor::new(stick.to_vec());
            from_stick(&mut from, &keys, None, &format!("stick-refused-{n}")).unwrap_err()
        };
        assert!(refused(&stick(&update, None)).contains("not signed"));
        assert!(refused(&stick(&update, Some(&sign(&other_secret, &update)))).contains("none of"));
        assert!(refused(&stick(&update, Some("zz"))).contains("not signed"));
        let mut short = stick(&update, Some(&sign(&secret, &update)));
        short.truncate(short.len() - 20);
        assert!(refused(&short).contains("not signed"));
        // A signature over another header than the one on the stick.
        let other: [(&str, &[u8]); 4] = [("root", b"b root"), PIECES[1], PIECES[2], PIECES[3]];
        let altered = stick(&packed(&other, HASH), Some(&sign(&secret, &update)));
        assert!(refused(&altered).contains("none of"));
        // A stick that is no update is refused too; and so is a node whose keys cannot be read.
        assert!(refused(b"not an update").contains("not a kith OS update"));
        let unread = update_of(Err("unreadable".into()));
        assert!(unread.contains("unreadable"));
    }

    /// `update` with a vouch that is an error: it is refused before any device is looked at.
    fn update_of(vouch: Result<Vouch, String>) -> String {
        update("/nonexistent", 'b', "kith.slot=a", vouch).unwrap_err()
    }

    #[test]
    fn a_stick_update_is_unchecked_when_the_image_has_no_key() {
        let update = packed(&PIECES, HASH);
        let mut from = std::io::Cursor::new(update);
        assert_eq!(
            from_stick(&mut from, &[], None, "stick-keyless"),
            Ok(Some("9.9".into()))
        );
    }

    /// A stick that answers with one header the first time it is read and another after it is
    /// read again from its start: what a device that is changed under the node does.
    struct Lying {
        now: std::io::Cursor<Vec<u8>>,
        then: Vec<u8>,
    }

    impl Read for Lying {
        fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
            self.now.read(into)
        }
    }

    impl Seek for Lying {
        fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
            if to == SeekFrom::Start(0) {
                self.now = std::io::Cursor::new(self.then.clone());
            }
            self.now.seek(to)
        }
    }

    #[test]
    fn a_stick_update_is_vouched_on_the_header_install_reads() {
        let (secret, public) = kith_packages::artifact::keygen().unwrap();
        let update = packed(&PIECES, HASH);
        let signed = stick(&update, Some(&sign(&secret, &update)));
        // The same pieces and trailer, under a header of another hash: the one install would parse.
        let mut swapped = signed.clone();
        swapped[..HEADER].copy_from_slice(&packed(&PIECES, &HASH.replace('0', "1"))[..HEADER]);
        let mut from = Lying {
            now: std::io::Cursor::new(signed),
            then: swapped,
        };
        let why = from_stick(&mut from, &[public], None, "stick-lying").unwrap_err();
        assert!(why.contains("none of"), "{why}");
    }

    #[test]
    fn a_stick_update_under_the_floor_is_refused() {
        let (secret, public) = kith_packages::artifact::keygen().unwrap();
        let update = packed(&PIECES, HASH);
        let stick = stick(&update, Some(&sign(&secret, &update)));
        let floor = places("stick-floor").root.with_file_name("floor");
        std::fs::write(&floor, "10.0\n").unwrap();
        let keys = [public];
        let mut from = std::io::Cursor::new(&stick);
        let why = from_stick(&mut from, &keys, Some(floor.clone()), "stick-floor-old").unwrap_err();
        assert!(why.contains("older than 10.0"), "{why}");
        std::fs::write(&floor, "9.0\n").unwrap();
        let mut from = std::io::Cursor::new(&stick);
        assert_eq!(
            from_stick(&mut from, &keys, Some(floor), "stick-floor-new"),
            Ok(Some("9.9".into()))
        );
    }

    fn unhex(text: &str) -> Vec<u8> {
        let pair = |at| u8::from_str_radix(&text[at..at + 2], 16).unwrap();
        (0..text.len()).step_by(2).map(pair).collect()
    }

    #[test]
    fn os_marks_its_slot_good_and_says_which_slot_failed() {
        let places = places("settles");
        std::fs::write(places.esp.join("kith-2-b+2-1.efi"), "b").unwrap();
        // (While its tries are counted a slot is not good; the other one here is.)
        assert!(!good('b', &places.esp) && good('a', &places.esp) && !good('c', &places.esp));
        assert_eq!(settle('b', &places.esp), ["slot b is good"]);
        assert!(good('b', &places.esp));
        assert!(
            GOOD.load(std::sync::atomic::Ordering::Relaxed),
            "and the node's floor may be raised"
        );
        assert_eq!(names(&places.esp), ["kith-1-a.efi", "kith-2-b.efi"]);
        assert!(settle('b', &places.esp).is_empty());

        std::fs::write(places.esp.join("kith-3-a+0-3.efi"), "a, broken").unwrap();
        std::fs::remove_file(places.esp.join("kith-1-a.efi")).unwrap();
        let said = settle('b', &places.esp);
        assert_eq!(said.len(), 1);
        assert!(
            said[0].starts_with("slot a did not come up in 3 tries: this is slot b"),
            "{}",
            said[0]
        );
    }

    #[test]
    fn os_waits_longer_after_each_failed_start_up_to_ten_minutes() {
        let secs = |failures| wait(failures).as_secs();
        assert_eq!([secs(0), secs(1), secs(2), secs(3), secs(4)], [10, 10, 20, 40, 80]);
        assert_eq!([secs(6), secs(7), secs(8), secs(u32::MAX)], [320, 600, 600, 600]);
    }

    #[test]
    fn os_esp_is_mounted_by_one_caller_at_a_time_and_a_panic_unmounts() {
        use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
        // (Mounts stacked: the most there were at once; a count of mounts not yet unmounted.)
        let (now, most) = (AtomicU32::new(0), AtomicU32::new(0));
        let mount = || {
            most.fetch_max(now.fetch_add(1, SeqCst) + 1, SeqCst);
            Ok(())
        };
        let unmount = || {
            now.fetch_sub(1, SeqCst);
        };
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    mounted(mount, unmount, || {
                        std::thread::sleep(std::time::Duration::from_millis(20))
                    })
                    .unwrap();
                });
            }
        });
        assert_eq!(
            (now.load(SeqCst), most.load(SeqCst)),
            (0, 1),
            "no two were mounted together"
        );
        // A panic while mounted: unmounted, and the next caller is not refused.
        let panicked = std::thread::spawn(|| {
            let _ = mounted(|| Ok(()), || UNMOUNTED.store(true, SeqCst), || panic!("settle"));
        })
        .join();
        assert!(panicked.is_err() && UNMOUNTED.load(SeqCst), "the panic unmounted");
        assert_eq!(mounted(|| Ok(()), || (), || 7), Ok(7));
        // A mount that fails is the caller's error, and the lock is let go.
        assert_eq!(mounted(|| Err("no".into()), || (), || 7), Err("no".into()));
        assert_eq!(mounted(|| Ok(()), || (), || 8), Ok(8));
    }

    static UNMOUNTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// A small linux-firmware tarball of this test's own (a top directory, a WHENCE with `Link:`
    /// lines, files) and a directory to extract into, and what `sh os/firmware.sh` says of `globs`
    /// (os/build.sh's built-in firmware): its exit status's success and its stderr.
    /// None when there is no tar or xz here.
    fn firmware(name: &str, globs: &[&str]) -> Option<(PathBuf, Result<(), String>)> {
        firmware_with(name, globs, None)
    }

    /// `firmware`, with `path` (a directory of stand-in programs) first in the script's PATH.
    fn firmware_with(name: &str, globs: &[&str], path: Option<&str>) -> Option<(PathBuf, Result<(), String>)> {
        let sh = |script: &str| std::process::Command::new("sh").args(["-c", script]).output().unwrap();
        if !(sh("command -v tar && command -v xz").status.success()) {
            eprintln!("skipped: no tar or xz here");
            return None;
        }
        let base = std::env::temp_dir().join(format!("kithd-firmware-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let top = base.join("linux-firmware-1");
        let put = |file: &str, text: &str| {
            let path = top.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        put(
            "WHENCE",
            "Driver: a made-up one\n\
             Link: a/x -> ../b/x\n\
             Link: a/y -> x\n\
             Link: c/only -> ../b/z\n\
             Link: d/deep/n -> ../../b/x\n\
             Link: loop/p -> q\n\
             Link: loop/q -> p\n\
             Link: bad/out -> ../../etc/passwd\n\
             Link: bad/up -> ../../../etc/passwd\n\
             Link: abs/out -> /etc/passwd\n\
             Link: dangling/x -> ../b/missing\n\
             Link: long/a -> b/../../../etc/passwd\n\
             Link: dirlink -> b\n\
             Link: dirlink/z -> x\n\
             Link: this line is prose, not a link\n",
        );
        for file in [
            "b/x", "b/z", "b/other", "a/file", "d/f", "d/deep/m", "e/one/f", "e/two/g",
        ] {
            put(file, file);
        }
        let tarball = base.join("linux-firmware-1.tar.xz");
        let made = sh(&format!(
            "tar -cJf {} -C {} linux-firmware-1",
            tarball.display(),
            base.display()
        ));
        assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
        let dir = base.join("out");
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../os/firmware.sh");
        let mut cmd = std::process::Command::new("sh");
        cmd.args([script, tarball.to_str().unwrap(), dir.to_str().unwrap()])
            .args(globs);
        if let Some(path) = path {
            cmd.env("PATH", format!("{path}:{}", std::env::var("PATH").unwrap_or_default()));
        }
        let ran = cmd.output().unwrap();
        let said = String::from_utf8_lossy(&ran.stderr).to_string();
        Some((dir, if ran.status.success() { Ok(()) } else { Err(said) }))
    }

    /// What a link in `dir` points at as written, none if `name` is no link.
    fn pointing(dir: &Path, name: &str) -> Option<String> {
        Some(std::fs::read_link(dir.join(name)).ok()?.to_str()?.to_string())
    }

    /// The files and links under `dir`, as paths from it, sorted.
    fn found(dir: &Path) -> Vec<String> {
        let mut found = Vec::new();
        let mut walk = vec![dir.to_path_buf()];
        while let Some(at) = walk.pop() {
            for entry in std::fs::read_dir(&at).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() && !path.is_symlink() {
                    walk.push(path);
                } else {
                    found.push(path.strip_prefix(dir).unwrap().to_str().unwrap().to_string());
                }
            }
        }
        found.sort();
        found
    }

    /// A glob's links are made as WHENCE says, with what they point at taken, links in turn;
    /// a file the glob names is taken; what no glob names is not.
    #[test]
    fn built_in_firmware_makes_the_links_a_glob_names_and_takes_their_targets() {
        let Some((dir, said)) = firmware("links", &["a/*"]) else {
            return;
        };
        assert_eq!(said, Ok(()));
        assert_eq!(pointing(&dir, "a/x").as_deref(), Some("../b/x"));
        // A link to a link: a/y is made, a/x it points at is too, and b/x at the end.
        assert_eq!(pointing(&dir, "a/y").as_deref(), Some("x"));
        assert_eq!(found(&dir), ["a/file", "a/x", "a/y", "b/x"]);
        // They are all readable from where they are: no link dangles.
        assert_eq!(std::fs::read_to_string(dir.join("a/y")).unwrap(), "b/x");
        assert!(!dir.join("WHENCE").exists());
    }

    /// A glob that names only links (no file of linux-firmware's own) works, not a tar "not found".
    #[test]
    fn built_in_firmware_takes_a_glob_that_names_only_links() {
        let Some((dir, said)) = firmware("only-links", &["c/*"]) else {
            return;
        };
        assert_eq!(said, Ok(()));
        assert_eq!(found(&dir), ["b/z", "c/only"]);
        assert_eq!(pointing(&dir, "c/only").as_deref(), Some("../b/z"));
    }

    /// A glob that names neither a file nor a link is an error, and says which.
    #[test]
    fn built_in_firmware_dies_for_a_glob_that_matches_nothing() {
        let Some((_, said)) = firmware("nothing", &["a/*", "zz/*"]) else {
            return;
        };
        let said = said.unwrap_err();
        assert!(said.contains("zz/*") && !said.contains("a/*"), "{said}");
    }

    /// Links that point at each other stop with an error, not a loop that never ends.
    #[test]
    fn built_in_firmware_stops_a_cycle_of_links() {
        let Some((_, said)) = firmware("cycle", &["loop/*"]) else {
            return;
        };
        assert!(said.unwrap_err().contains("cycle"));
    }

    /// A link that leaves the tree (an absolute target, or `..` past its top, however deep it
    /// goes first) is refused, and so is one that points at what linux-firmware lacks.
    #[test]
    fn built_in_firmware_refuses_a_link_out_of_the_tree() {
        for (glob, why) in [
            ("bad/out", "out of"),
            ("bad/up", "out of"),
            ("abs/*", "out of"),
            ("long/*", "out of"),
            ("dangling/*", "lacks"),
        ] {
            let Some((dir, said)) = firmware("out-of-tree", &[glob]) else {
                return;
            };
            let said = said.unwrap_err();
            assert!(said.contains(why), "{glob}: {said}");
            // Nothing leaves the tree: no link was made for it, in the directory or beside it.
            assert!(
                !dir.join("etc").exists() && !dir.parent().unwrap().join("etc").exists(),
                "{glob}"
            );
            assert!(
                found(&dir)
                    .iter()
                    .all(|f| !f.starts_with("bad/") && !f.starts_with("abs/") && !f.starts_with("long/")),
                "{glob}"
            );
        }
    }

    /// A link in a directory that is itself a link (WHENCE: `dirlink -> b`, `dirlink/z -> x`) lands
    /// where the lexical walk does not say, so it is refused.
    #[test]
    fn built_in_firmware_refuses_a_link_whose_directory_is_a_link() {
        let Some((_, said)) = firmware("dirlink", &["dirlink/*"]) else {
            return;
        };
        assert!(said.unwrap_err().contains("directory that is a link"));
    }

    /// A glob that matches only a directory takes nothing (tar does not recurse here): an error that
    /// says so, not an empty directory and a build without its firmware.
    #[test]
    fn built_in_firmware_dies_for_a_glob_that_names_only_directories() {
        let Some((_, said)) = firmware("dirs", &["e/*"]) else {
            return;
        };
        let said = said.unwrap_err();
        assert!(said.contains("e/*") && said.contains("directories"), "{said}");
    }

    /// An awk that fails is a build that stops, not one without its links.
    #[test]
    fn built_in_firmware_stops_when_awk_fails() {
        let fake = std::env::temp_dir().join(format!("kithd-fake-awk-{}", std::process::id()));
        std::fs::create_dir_all(&fake).unwrap();
        std::fs::write(fake.join("awk"), "#!/bin/sh\nexit 2\n").unwrap();
        let mut mode = std::fs::metadata(fake.join("awk")).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut mode, 0o755);
        std::fs::set_permissions(fake.join("awk"), mode).unwrap();
        let Some((_, said)) = firmware_with("awk-fails", &["a/*"], fake.to_str()) else {
            return;
        };
        assert!(said.is_err(), "an awk that failed was not noticed");
    }

    /// `*` stands for one piece of a path, as tar's does here: `d/*` takes d/f and no link or
    /// file deeper, and `e/*/*` goes down two.
    #[test]
    fn built_in_firmware_star_does_not_cross_a_slash() {
        let Some((dir, said)) = firmware("star", &["d/*"]) else {
            return;
        };
        assert_eq!(said, Ok(()));
        assert_eq!(found(&dir), ["d/f"]);
        let Some((dir, said)) = firmware("star-down", &["e/*/*", "d/*/*"]) else {
            return;
        };
        assert_eq!(said, Ok(()));
        assert_eq!(found(&dir), ["b/x", "d/deep/m", "d/deep/n", "e/one/f", "e/two/g"]);
    }

    #[test]
    fn os_counts_failed_starts_on_the_esp_until_one_comes_up() {
        let places = places("counts");
        // A start that fails three times in a row (what init::end does each time: count it,
        // then wait by the count): the count rises and the wait grows.
        let starts: Vec<(u32, u64)> = (0..3)
            .map(|_| {
                let count = failed(&places.esp);
                (count, wait(count).as_secs())
            })
            .collect();
        assert_eq!(starts, [(1, 10), (2, 20), (3, 40)]);
        assert!(places.esp.join("kith.failed").is_file());
        // Not a kernel image: the boot loader does not start from it.
        assert_eq!(names(&places.esp), ["kith-1-a.efi"]);
        // A start that comes up (settle runs for it) clears the count.
        assert!(settle('a', &places.esp).is_empty());
        assert!(!places.esp.join("kith.failed").exists());
        assert_eq!(failed(&places.esp), 1);
    }
}
