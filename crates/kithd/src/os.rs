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
//! with `kith.update=` is taken on the word of whoever is at the machine's boot menu.

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

/// The ESP's directory of kernel images, mounted for as long as `with` runs.
pub fn esp<T>(with: impl FnOnce(&Path) -> T) -> Result<T, String> {
    use nix::mount::{MsFlags, mount, umount};
    let device = crate::init::labelled("esp").ok_or("no partition is labelled esp")?;
    let _ = std::fs::create_dir_all(ESP);
    let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    mount(Some(&device), ESP, Some("vfat"), flags, None::<&str>)
        .map_err(|e| format!("mounting {}: {e}", device.display()))?;
    let out = with(&Path::new(ESP).join("EFI/Linux"));
    // (What was done there is done; left mounted, it is written out when the node stops.)
    if let Err(e) = umount(ESP) {
        eprintln!("kithd: init: unmounting the ESP: {e}");
    }
    Ok(out)
}

/// `kith.update=DEVICE`: the update on that disk (a stick, a second disk) goes into the
/// slot this node does not run from. Nobody vouches for it but whoever plugged it in.
pub fn update(device: &str, slot: char, running: &str) -> Result<Option<String>, String> {
    let device = Path::new("/dev").join(device);
    // ponytail: a stick takes a moment to be there; ten seconds of looking, not an event.
    for _ in 0..100 {
        if device.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let mut from = std::fs::File::open(&device).map_err(|e| format!("{}: {e}", device.display()))?;
    into_other_slot(&mut from, slot, running, |_| Ok(()))
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
    let into = if slot == 'a' { 'b' } else { 'a' };
    let part = |name: String| crate::init::labelled(&name).ok_or(format!("no partition is labelled {name}"));
    let (root, verity) = (part(format!("root-{into}"))?, part(format!("verity-{into}"))?);
    esp(|esp| {
        let places = Places {
            root,
            verity,
            esp: esp.into(),
        };
        install(from, running, into, &places, vouched)
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(bytes: &[u8]) -> String {
        crate::pki::hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
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
    fn os_counts_failed_starts_on_the_esp_until_one_comes_up() {
        let places = places("counts");
        assert_eq!([failed(&places.esp), failed(&places.esp)], [1, 2]);
        assert_eq!(failed(&places.esp), 3);
        assert!(places.esp.join("kith.failed").is_file());
        // Not a kernel image: the boot loader does not start from it.
        assert_eq!(names(&places.esp), ["kith-1-a.efi"]);
        // A start that comes up (settle runs for it) clears the count.
        assert!(settle('a', &places.esp).is_empty());
        assert!(!places.esp.join("kith.failed").exists());
        assert_eq!(failed(&places.esp), 1);
    }
}
