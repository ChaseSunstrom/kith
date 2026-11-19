//! The real mapping of a data disk (docs/adr-second-disk.md, sections 1, 2 and 4): the disk from
//! its sector 8 under aes-xts-plain64 through `kith_dm_sys::crypt`, zeros or a discard through it,
//! the seed file system written to it, and the mount that grows that file system to the disk.
//!
//! The seed ([`SEED`]) is a small ext4 that kith OS carries (a node has no mkfs), made by
//! os/build.sh with 4 KiB blocks and `-E resize=` for the largest disk a node takes ([`CEILING`]):
//! an ext4 grown online reaches no further than the descriptor blocks mkfs reserved, and one made
//! as small as the seed reserves few. [`mount`] grows it, as `encrypted.rs` does a volume's.
//!
//! Nothing here reads or writes a disk that is not the one named, and a disk is named by the
//! caller (`data_disk::boot` for a known one, the verbs for an added one): never found by looking.
use super::{Dev, Mapper, ROOM};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The file system a data disk starts as: made when kith OS is built (os/build.sh).
pub const SEED: &str = "/usr/share/kith/data.ext4";
/// The seed's block size, and the grown file system's.
pub const BLOCK: u64 = 4096;
/// The most blocks a data disk's file system grows to (`resize=` of the seed, os/build.sh):
/// 4 TiB. A bigger disk is refused, not left part unused without a word.
pub const CEILING: u64 = 1 << 30;
/// The mapping begins this many sectors in: after the header's room.
const FROM: u64 = (ROOM / 512) as u64;
/// How much a zeroing or a discard is asked at once.
const STEP: u64 = 1 << 30;

/// The device-mapper name of the mapping over the kernel's disk `disk` (`kith-disk-vdb`).
pub fn mapping(disk: &str) -> String {
    format!("kith-disk-{disk}")
}

/// The sectors a disk of `bytes` has under the mapping: past the header's room, whole blocks,
/// and no more than the seed's file system can grow to.
pub fn sectors(bytes: u64) -> Result<u64, String> {
    let sectors = (bytes / 512).saturating_sub(FROM) / (BLOCK / 512) * (BLOCK / 512);
    if sectors == 0 {
        return Err("it is too small to hold a file system".into());
    }
    if sectors * 512 / BLOCK > CEILING {
        let tib = CEILING * BLOCK >> 40;
        return Err(format!("it is bigger than the {tib} TiB the seed file system grows to"));
    }
    Ok(sectors)
}

/// A device's length: a block device says 0 for `len`, so the end is where it is sought to.
fn length(file: &mut File) -> io::Result<u64> {
    file.seek(SeekFrom::End(0))
}

/// A data disk as the kernel has it: `/dev/NAME`.
#[derive(Debug)]
pub struct RealDisk {
    name: String,
    removable: bool,
}

/// The kernel's name for a disk is one path part: no empty name, no `/`, no blank (it goes into
/// a device-mapper name and a path).
fn plain(name: &str) -> bool {
    !name.is_empty() && !name.contains(|c: char| c == '/' || c.is_whitespace() || c.is_control())
}

impl RealDisk {
    pub fn new(name: &str, removable: bool) -> Option<RealDisk> {
        plain(name).then(|| RealDisk {
            name: name.to_string(),
            removable,
        })
    }

    fn path(&self) -> PathBuf {
        Path::new("/dev").join(&self.name)
    }

    /// Whether nothing holds the disk (mounted, mapped, a file system on it): the open for
    /// writing with `O_EXCL` the ADR asks of an add, and let go at once. (Not kept open: the
    /// mapping that follows would hold it itself, and the header is written under it.)
    // ponytail: a check, not a claim: a disk taken between this and the mapping is the
    // mapping's to refuse (dm-crypt opens it exclusively).
    pub fn unheld(&self) -> io::Result<()> {
        File::options()
            .write(true)
            .custom_flags(nix::fcntl::OFlag::O_EXCL.bits())
            .open(self.path())
            .map(drop)
    }

    /// Its length in bytes.
    pub fn bytes(&self) -> io::Result<u64> {
        length(&mut File::open(self.path())?)
    }
}

impl Dev for RealDisk {
    fn name(&self) -> &str {
        &self.name
    }
    fn removable(&self) -> bool {
        self.removable
    }
    fn first(&self) -> io::Result<[u8; ROOM]> {
        let mut room = [0; ROOM];
        File::open(self.path())?.read_exact_at(&mut room, 0)?;
        Ok(room)
    }
    fn write_first(&self, room: &[u8; ROOM]) -> io::Result<()> {
        // (Not exclusive: the header is written with the mapping open, which holds the disk.)
        let disk = File::options()
            .write(true)
            .custom_flags(nix::fcntl::OFlag::O_SYNC.bits())
            .open(self.path())?;
        disk.write_all_at(room, 0)?;
        disk.sync_all()
    }
}

/// What the mapping of one disk is, as far as the add and the remove ask: its device-mapper
/// name over the disk, and where it is mounted (if a mount is to be let go before it is removed).
#[derive(Debug)]
pub struct Real {
    disk: RealDisk,
    at: Option<PathBuf>,
    mapped: Option<PathBuf>,
    sectors: u64,
}

impl Real {
    /// `at` is where the file system of the mapping is (or will be) mounted: `unmap` lets it go
    /// first, and a mount in use refuses it.
    pub fn new(disk: RealDisk, at: Option<PathBuf>) -> Real {
        Real {
            disk,
            at,
            mapped: None,
            sectors: 0,
        }
    }

    fn name(&self) -> String {
        mapping(&self.disk.name)
    }

    /// The device the mapping is, once [`Mapper::map`] made it.
    fn device(&self) -> io::Result<&Path> {
        self.mapped
            .as_deref()
            .ok_or_else(|| io::Error::other("the disk is not mapped"))
    }

    fn mapped_file(&self, write: bool) -> io::Result<File> {
        File::options().read(true).write(write).open(self.device()?)
    }
}

impl Mapper for Real {
    fn map(&mut self, key: &[u8; 64]) -> io::Result<()> {
        let sectors = sectors(self.disk.bytes()?).map_err(io::Error::other)?;
        let name = self.name();
        // (One left by a start that got no further. One in use stays, and making it fails.)
        let _ = kith_dm_sys::remove(&name);
        self.mapped = Some(kith_dm_sys::crypt(&name, &self.disk.path(), FROM, sectors, key)?);
        self.sectors = sectors;
        Ok(())
    }

    fn zero(&mut self, quick: bool) -> io::Result<()> {
        let bytes = self.sectors * 512;
        if quick {
            // (The disk's own blocks: what dm-crypt writes through the mapping is not zero.)
            let disk = File::options().write(true).open(self.disk.path())?;
            let mut done = 0;
            while done < bytes {
                let more = STEP.min(bytes - done);
                kith_dm_sys::discard(&disk, ROOM as u64 + done, more)?;
                done += more;
            }
            return Ok(());
        }
        let through = self.mapped_file(true)?;
        let zeros = vec![0; 1 << 20];
        let mut done = 0;
        while done < bytes {
            let more = (zeros.len() as u64).min(bytes - done);
            through.write_all_at(&zeros[..more as usize], done)?;
            done += more;
        }
        through.sync_all()
    }

    fn seed(&mut self) -> io::Result<()> {
        let mut seed = File::open(SEED).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("{SEED}: {e}: the file system it starts as comes with kith OS"),
            )
        })?;
        copy_seed(&mut seed, &self.mapped_file(true)?, self.sectors * 512)
    }

    fn answers(&mut self) -> io::Result<bool> {
        let mut magic = [0; 2];
        // (An error is an error, not "no": a key that is not its own reads garbage, which is.)
        self.mapped_file(false)?.read_exact_at(&mut magic, 1080)?;
        Ok(magic == [0x53, 0xef])
    }

    fn unmap(&mut self) -> io::Result<()> {
        if let Some(at) = &self.at {
            match nix::mount::umount(at) {
                // (Nothing is mounted there, or there is no such place: a node started after a cut.)
                Ok(()) | Err(nix::errno::Errno::EINVAL | nix::errno::Errno::ENOENT) => {}
                Err(e) => return Err(e.into()),
            }
        }
        match kith_dm_sys::remove(&self.name()) {
            Ok(()) => Ok(()),
            // No mapping of that name: it was not made, or a restart took it.
            Err(e) if e.raw_os_error() == Some(nix::errno::Errno::ENXIO as i32) => Ok(()),
            // (Not `NotFound`: `remove` takes that as done, and a missing control file is not it.)
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }
}

/// The seed written to the start of `to`, synced: `room` bytes are all the mapping has.
fn copy_seed(seed: &mut impl Read, to: &File, room: u64) -> io::Result<()> {
    // In chunks, not all at once: the seed is 64 MiB and kithd is the machine's first process.
    // (One byte more than the room is read: a seed that does not fit is told apart from one that
    // fills it. A seed that does not fit leaves what was written, on a disk whose header is not
    // written yet.)
    let mut seed = seed.take(room + 1);
    let mut chunk = vec![0; 1 << 20];
    let mut at = 0u64;
    loop {
        let got = seed.read(&mut chunk)?;
        if got == 0 {
            break;
        }
        if at + got as u64 > room {
            return Err(io::Error::other("the seed file system is bigger than the disk"));
        }
        to.write_all_at(&chunk[..got], at)?;
        at += got as u64;
    }
    to.sync_all()
}

/// Mount the ext4 on `device` at `at` (made if it is not there) and grow it to `device`'s size:
/// asked each time, the kernel does nothing when it is that big already. Not grown, it is
/// unmounted again: a disk is never open at less than its size.
pub fn mount(device: &Path, at: &Path) -> Result<(), String> {
    use nix::mount::MsFlags;
    let said = |e: io::Error| format!("{}: {e}", device.display());
    let bytes = length(&mut File::open(device).map_err(said)?).map_err(said)?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(at)
        .map_err(|e| format!("{}: {e}", at.display()))?;
    let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOATIME;
    // (Under a key that is not its own there is no file system to find.)
    nix::mount::mount(Some(device), at, Some("ext4"), flags, None::<&str>).map_err(|e| format!("mounting it: {e}"))?;
    let block = nix::sys::statvfs::statvfs(at).map_or(BLOCK, |stat| stat.fragment_size().max(512));
    kith_dm_sys::grow(at, bytes / block).map_err(|e| {
        let _ = nix::mount::umount(at);
        format!("growing its file system to its size: {e}")
    })
}

/// Open the known disk `disk`: map it under `key` and mount it at `at`, or leave it unmapped.
pub fn open(disk: &RealDisk, at: &Path, key: &[u8; 64]) -> Result<(), String> {
    let mut real = Real::new(
        RealDisk::new(&disk.name, disk.removable).ok_or("its name is not one")?,
        None,
    );
    real.map(key).map_err(|e| format!("dm-crypt: {e}"))?;
    let device = real.device().map_err(|e| e.to_string())?.to_path_buf();
    mount(&device, at).inspect_err(|_| drop(real.unmap()))
}

/// Close what [`open`] opened of `disk`, at `at`: unmounted, then unmapped.
pub fn close(disk: &RealDisk, at: &Path) -> io::Result<()> {
    Real::new(
        RealDisk::new(&disk.name, disk.removable).expect("a name that opened"),
        Some(at.into()),
    )
    .unmap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// os/build.sh's own text: the seed's parameters are pinned where they are made, since a
    /// node has no mkfs to make one and the unit test cannot.
    const BUILD: &str = include_str!("../../../../os/build.sh");

    /// The `mkfs.ext4` command that makes the data disk's seed, with its continuation lines.
    fn made() -> String {
        let at = BUILD.find("mkfs.ext4").and_then(|_| {
            BUILD
                .match_indices("mkfs.ext4")
                .map(|(at, _)| at)
                .find(|at| BUILD[*at..].lines().take(3).any(|line| line.contains("data.ext4")))
        });
        let from = at.expect("os/build.sh makes a data.ext4");
        let mut command = String::new();
        for line in BUILD[from..].lines() {
            command.push_str(line);
            if !line.ends_with('\\') {
                break;
            }
        }
        command
    }

    #[test]
    fn the_seed_is_made_with_4096_byte_blocks_and_room_to_grow_to_the_ceiling() {
        let command = made();
        assert!(command.contains("-b 4096"), "4096-byte blocks: {command}");
        assert_eq!(BLOCK, 4096);
        assert!(
            command.contains(&format!("resize={CEILING}")),
            "resize= is the ceiling, {CEILING} blocks: {command}"
        );
        // (And it is its own file: the Volume's seed and its bytes are as they were.)
        assert!(command.contains("usr/share/kith/data.ext4"), "{command}");
        assert!(SEED.ends_with("/data.ext4"));
    }

    /// mke2fs's rule for the descriptor blocks it keeps for growing (with 64-byte descriptors,
    /// which ext4 has by default): enough for `resize=` blocks, at the most one block of
    /// block numbers. The seed has to hold them, its journal and its inodes, and room to spare.
    #[test]
    fn the_seed_holds_the_blocks_it_reserves_for_growing() {
        let size = BUILD
            .lines()
            .find(|line| line.contains("truncate -s") && line.contains("data.ext4"))
            .and_then(|line| line.split("truncate -s ").nth(1))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|size| size.strip_suffix('M'))
            .and_then(|mb| mb.parse::<u64>().ok())
            .expect("the seed's size in MB");
        let blocks = size << 20 >> 12;
        let groups = CEILING.div_ceil(32768);
        let reserved = groups.div_ceil(BLOCK / 64);
        assert!(
            reserved <= BLOCK / 4,
            "mke2fs keeps at most {} of them, not {reserved}",
            BLOCK / 4
        );
        // The journal (-J size=, in MiB), 4096 inodes of 256 bytes, a group's descriptor, two
        // bitmaps, and the reserved blocks.
        let journal = made()
            .split("-J size=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|mb| mb.parse::<u64>().ok())
            .expect("the journal's size in MB")
            << 20
            >> 12;
        let used = journal + 4096 * 256 / BLOCK + 1 + 2 + reserved;
        // (mke2fs refuses a journal over half the free blocks.)
        assert!(
            journal <= (blocks - used + journal) / 2,
            "{journal} journal blocks are too many for {blocks}"
        );
        assert!(used + 256 <= blocks, "{used} blocks of {blocks} are spoken for");
        // The grow is one transaction of 3 + 1 + the descriptor blocks it adds + every reserved
        // one (ext4_flex_group_add), and jbd2 allows a quarter of the journal: a VM got ENOSPC
        // from a journal of 1024 blocks and 512 reserved.
        assert!(
            journal / 4 >= 4 + reserved + 64,
            "a journal of {journal} blocks is too small to grow in one go"
        );
        assert_eq!(blocks, 16384, "the seed is 64 MiB, 16384 blocks");
    }

    #[test]
    fn a_disk_maps_from_its_sector_8_in_whole_blocks_and_none_is_too_big_or_too_small() {
        assert_eq!(sectors(1 << 20), Ok((1 << 20) / 512 - 8));
        // A disk of 1 MiB and a bit: the bit is not a block.
        assert_eq!(sectors((1 << 20) + 700), Ok((1 << 20) / 512 - 8));
        assert!(sectors(4096).is_err());
        assert!(sectors(0).is_err());
        assert!(sectors(4096 + 4095).is_err(), "a part of a block is no block");
        let most = CEILING * BLOCK + ROOM as u64;
        assert_eq!(sectors(most), Ok(CEILING * BLOCK / 512));
        assert!(sectors(most + BLOCK).unwrap_err().contains("4 TiB"));
    }

    #[test]
    fn a_disk_is_named_as_the_kernel_names_it_and_nothing_else() {
        for name in ["vdb", "sda", "nvme0n1", "mmcblk0"] {
            assert!(RealDisk::new(name, false).is_some(), "{name}");
        }
        for name in ["", "../vdb", "vd b", "a/b", "vdb\n", "/dev/vdb"] {
            assert!(RealDisk::new(name, false).is_none(), "{name:?}");
        }
        assert_eq!(mapping("vdb"), "kith-disk-vdb");
    }

    fn scratch(tag: &str) -> (std::path::PathBuf, File) {
        let dir = std::env::temp_dir().join(format!("kith-seed-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.join("device"))
            .unwrap();
        (dir, file)
    }

    #[test]
    fn the_seed_is_written_to_the_start_of_the_mapping_and_one_too_big_is_refused() {
        let (dir, device) = scratch("copy");
        device.set_len(16384).unwrap();
        let mut seed = io::Cursor::new(vec![7u8; 8192]);
        copy_seed(&mut seed, &device, 16384).unwrap();
        let mut back = vec![0u8; 16384];
        device.read_exact_at(&mut back, 0).unwrap();
        assert!(back[..8192].iter().all(|&b| b == 7) && back[8192..].iter().all(|&b| b == 0));
        // One that fills the room is fine; one byte more is not, and nothing of it is written.
        let (_, device) = scratch("copy2");
        device.set_len(100).unwrap();
        assert!(copy_seed(&mut io::Cursor::new(vec![1u8; 100]), &device, 100).is_ok());
        let err = copy_seed(&mut io::Cursor::new(vec![9u8; 101]), &device, 100).unwrap_err();
        assert!(err.to_string().contains("bigger than the disk"), "{err}");
        let mut first = [0u8; 1];
        device.read_exact_at(&mut first, 0).unwrap();
        assert_eq!(first, [1], "the refused seed was not written over it");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_unmapped_disk_says_so_and_is_not_asked_for_what_it_does_not_have() {
        let disk = RealDisk::new("vdz", false).unwrap();
        let mut real = Real::new(disk, None);
        assert!(real.answers().is_err(), "an answer needs a mapping");
        assert!(real.zero(false).is_err());
        assert!(real.seed().is_err() || !Path::new(SEED).exists());
    }
}
