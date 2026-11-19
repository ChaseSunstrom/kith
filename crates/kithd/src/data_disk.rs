//! A second disk for a node's data (docs/adr-second-disk.md, sections 1 and 2), the part a file
//! can show: the 4 KiB plain header that says a disk is a kith data disk, the disk's own random
//! key, and the refusal of a disk that is anyone else's.
//!
//! Nothing here maps, mounts or writes a disk on its own: `write_header` is the one write, and
//! the order it comes in (last, after the mapping) is the add's, not this file's. Nothing here
//! reads more than a disk's first 4 KiB.
// (Nothing calls this yet: the add order and the verbs come in the slices after it.)
#![allow(dead_code)]

use ring::digest;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

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

/// Write the header for `id` over the first 4 KiB of `file` (the rest of the room zero) and
/// sync it.
pub fn write_header(file: &File, id: &Id) -> io::Result<()> {
    let mut room = [0u8; ROOM];
    let text = text(id);
    room[..text.len()].copy_from_slice(text.as_bytes());
    file.write_all_at(&room, 0)?;
    file.sync_all()
}

/// The id of the header at the start of `file`, or why there is none. Strict: the header is
/// taken only when it is, byte for byte, what [`write_header`] writes for the id it names
/// (a sum that is wrong, a byte of the room that is not zero, an upper-case digit all fail).
pub fn read_header(file: &File) -> Result<Id, String> {
    let mut room = [0u8; ROOM];
    file.read_exact_at(&mut room, 0)
        .map_err(|e| format!("reading the first 4 KiB: {e}"))?;
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
}

/// Why a disk is not taken. `Root` and `Removable` are final; `Signature` and `NotEmpty` are
/// the two a `--wipe` may pass, and `Unreadable` is a disk that cannot be looked at.
#[derive(Debug, PartialEq)]
pub enum Refused {
    Root,
    Removable,
    Signature(&'static str),
    NotEmpty,
    Unreadable(String),
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

/// Whether `disk` may be made a data disk. `root` is the name of the disk the system runs
/// from, `None` when that cannot be told: then every disk is refused (it fails closed, as the
/// state's own fence does, `init::on_ours`). A removable disk and the root disk first, since
/// no `--wipe` passes them; then what its first 4 KiB say.
pub fn refuse(disk: &impl Dev, root: Option<&str>) -> Result<(), Refused> {
    if root.is_none_or(|root| root == disk.name()) {
        return Err(Refused::Root);
    }
    if disk.removable() {
        return Err(Refused::Removable);
    }
    let room = disk.first().map_err(|e| Refused::Unreadable(e.to_string()))?;
    if let Some((_, _, what)) = SIGNATURES.iter().find(|(at, magic, _)| room[*at..].starts_with(magic)) {
        return Err(Refused::Signature(what));
    }
    if room.iter().any(|&byte| byte != 0) {
        return Err(Refused::NotEmpty);
    }
    Ok(())
}

/// A new aes-xts-plain64 key for a disk: 64 random bytes, the disk's own (docs/adr-second-disk.md,
/// section 1). It is derived from nothing, so the state's key and a header's id cannot draw it
/// again once the copy kept in the state is gone: that is what makes remove an erase. Keeping
/// it (`disks/<id>/key`, synced) before anything uses it is the add's order, not this function's.
pub fn new_key() -> zeroize::Zeroizing<[u8; 64]> {
    zeroize::Zeroizing::new(crate::crypt::random::<64>())
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
    }

    pub fn fake(tag: &str, len: u64, writes: &[(u64, &[u8])]) -> Fake {
        let (_dir, file) = disk_file(tag, len);
        for (at, bytes) in writes {
            file.write_all_at(bytes, *at).unwrap();
        }
        Fake(file, "sdb", false)
    }

    /// A directory of its own in the temp dir, and a disk file of `len` bytes in it.
    pub fn disk_file(tag: &str, len: u64) -> (PathBuf, File) {
        let dir = std::env::temp_dir().join(format!("kith-data-disk-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.join("disk"))
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
        write_header(&file, &ID).unwrap();
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
        write_header(&file, &a).unwrap();
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
        write_header(&file, &ID).unwrap();
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
        let root = Some("sda");
        assert_eq!(refuse(&fake("refuse-empty", 1 << 20, &[]), root), Ok(()));
        assert_eq!(
            refuse(
                &fake("refuse-late", 1 << 20, &[(4096, b"LUKS\xba\xbe"), (1 << 19, b"x")]),
                root
            ),
            Ok(())
        );
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
            assert_eq!(refuse(&fake(tag, 1 << 20, writes), root), Err(want), "{tag}");
        }
        // A disk with a header written by write_header is refused as a kith disk.
        let made = fake("refuse-made", 1 << 20, &[]);
        write_header(&made.0, &ID).unwrap();
        assert_eq!(refuse(&made, root), Err(Refused::Signature("a kith-disk header")));

        let empty = |name, removable| Fake(disk_file("refuse-name", 1 << 20).1, name, removable);
        assert_eq!(refuse(&empty("sda", false), root), Err(Refused::Root));
        assert_eq!(refuse(&empty("sdb", false), None), Err(Refused::Root));
        assert_eq!(refuse(&empty("sdb", true), root), Err(Refused::Removable));
        // The root disk that is also removable, and holds a signature: Root first, never wiped.
        assert_eq!(
            refuse(&Fake(made.0.try_clone().unwrap(), "sda", true), root),
            Err(Refused::Root)
        );
        // A disk shorter than the room cannot be looked at, so it is not taken.
        let short = fake("refuse-short", 100, &[]);
        assert!(matches!(refuse(&short, root), Err(Refused::Unreadable(_))));
        assert!(Refused::NotEmpty.to_string().contains("4 KiB"));
    }
}

#[cfg(test)]
mod key {
    use super::support::*;
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
