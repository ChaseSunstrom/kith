//! Device-mapper by ioctl (linux/dm-ioctl.h): what `dmsetup create` and `dmsetup remove`
//! do, for a machine with no dmsetup. One mapping of one dm-crypt target. And two more
//! things such a machine has no tool for: a file as a block device (`losetup`), and an ext4
//! file system grown where it is mounted (`resize2fs`). And one that has no tool anywhere
//! but a container runtime: the program a cgroup asks which devices its processes may
//! open (`bpf(2)`).
//!
//! The `unsafe` of the workspace is here: the ioctl call and the bpf call themselves (and
//! taking the file descriptor bpf answers with). Each request is put together as bytes, so
//! there is no struct whose layout has to match the kernel's.

use std::fs::File;
use std::io::{Error, Result};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

/// `struct dm_ioctl`: version, sizes, flags, the device's number, its name and uuid.
const HEADER: usize = 312;
const CREATE: u8 = 3;
const REMOVE: u8 = 4;
const SUSPEND: u8 = 6;
const LOAD: u8 = 9;
/// DM_SECURE_DATA_FLAG: the kernel wipes its copy of the request (it holds the key).
const SECURE: u32 = 1 << 15;

/// A request about the mapping `name`, with one target (its length in sectors, its
/// kind and what that kind is told) or none.
fn request(name: &str, flags: u32, target: Option<(u64, &str, &str)>) -> Result<Vec<u8>> {
    if name.is_empty() || name.len() > 127 || name.contains(['/', '\0']) {
        return Err(Error::other(format!("`{name}` cannot name a mapping")));
    }
    // (Room for all of it at once: growing would leave a copy of a key behind.)
    let mut bytes = Vec::with_capacity(HEADER + 48 + target.map_or(0, |target| target.2.len()));
    bytes.resize(HEADER, 0);
    bytes[0..4].copy_from_slice(&4u32.to_ne_bytes());
    bytes[16..20].copy_from_slice(&(HEADER as u32).to_ne_bytes());
    bytes[28..32].copy_from_slice(&flags.to_ne_bytes());
    bytes[48..48 + name.len()].copy_from_slice(name.as_bytes());
    if let Some((sectors, kind, told)) = target {
        if kind.len() > 15 || told.contains('\0') {
            return Err(Error::other("not a target"));
        }
        bytes[20..24].copy_from_slice(&1u32.to_ne_bytes());
        // `struct dm_target_spec`: where it starts (0), its length, a status, where the
        // next one is, its kind; then what it is told, ended by a zero, in whole 8 bytes.
        let mut spec = [0; 40];
        spec[8..16].copy_from_slice(&sectors.to_ne_bytes());
        spec[24..24 + kind.len()].copy_from_slice(kind.as_bytes());
        bytes.extend(spec);
        bytes.extend(told.as_bytes());
        bytes.resize((bytes.len() + 1).next_multiple_of(8), 0);
    }
    let size = bytes.len() as u32;
    bytes[12..16].copy_from_slice(&size.to_ne_bytes());
    Ok(bytes)
}

/// Hand `request` to the kernel; what it answers is written over it.
fn call(control: &File, command: u8, mut request: Vec<u8>) -> Result<Vec<u8>> {
    // _IOWR(0xfd, command, struct dm_ioctl)
    let number = (3u32 << 30) | ((HEADER as u32) << 16) | (0xfd << 8) | u32::from(command);
    // (The kernel reads and writes no more than `data_size` bytes of the buffer, which
    // `request` set to the buffer's length.)
    if let Err(failed) = ioctl(control, number, &mut request) {
        request.fill(0);
        return Err(failed);
    }
    Ok(request)
}

/// The ioctl `number` on `file`, with `bytes` as what it points at. What the kernel answers.
///
/// For the numbers of this file only: each is one whose argument the kernel takes as a
/// pointer to no more than `bytes` holds (or does not look at). One of them (BLKPG) holds
/// a pointer itself, to bytes its caller keeps for as long as the call takes.
fn ioctl(file: &File, number: u32, bytes: &mut [u8]) -> Result<i32> {
    // SAFETY: the kernel reads and writes within `bytes` (see above), which lives past the call.
    let said = unsafe { libc::ioctl(file.as_raw_fd(), number as _, bytes.as_mut_ptr()) };
    if said < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(said)
    }
}

/// Give `file` a block device (`/dev/loopN`): what `losetup --find` does. The device is
/// gone again when the last thing that has it open closes it, so keep what is returned open
/// until something else (a mapping over it) holds the device.
pub fn attach(file: &File) -> Result<(File, PathBuf)> {
    const GET_FREE: u32 = 0x4C82;
    const CONFIGURE: u32 = 0x4C0A;
    let control = File::options().read(true).write(true).open("/dev/loop-control")?;
    let mut failed = Error::other("no loop device");
    // (Another process can take the one that was free between the two calls: ask again.)
    for _ in 0..8 {
        let path = PathBuf::from(format!("/dev/loop{}", ioctl(&control, GET_FREE, &mut [])?));
        let device = File::options().read(true).write(true).open(&path)?;
        // `struct loop_config`: the file, a block size (the default), then `struct
        // loop_info64`, whose flags are 52 bytes in: LO_FLAGS_AUTOCLEAR.
        let mut config = [0u8; 304];
        config[0..4].copy_from_slice(&(file.as_raw_fd() as u32).to_ne_bytes());
        config[60..64].copy_from_slice(&4u32.to_ne_bytes());
        match ioctl(&device, CONFIGURE, &mut config) {
            Ok(_) => return Ok((device, path)),
            Err(busy) => failed = busy,
        }
    }
    Err(failed)
}

/// Grow the ext4 file system mounted at `mounted` to `blocks` of its blocks, as it is in use:
/// what `resize2fs` asks of the kernel. The device under it must be that big already.
pub fn grow(mounted: &Path, blocks: u64) -> Result<()> {
    // EXT4_IOC_RESIZE_FS: _IOW('f', 16, __u64)
    ioctl(&File::open(mounted)?, 0x4008_6610, &mut blocks.to_ne_bytes()).map(drop)
}

/// Tell the kernel that partition `number` (from 1) of `disk`, which starts at byte `start`,
/// is now `length` bytes long: the disk's partition table says so already, and a disk in
/// use is one whose table the kernel will not read again by itself.
pub fn resize_partition(disk: &File, number: u32, start: u64, length: u64) -> Result<()> {
    // `struct blkpg_partition`: start and length in bytes, the number, and two names
    // nobody reads.
    let mut partition = [0u8; 152];
    partition[0..8].copy_from_slice(&start.to_ne_bytes());
    partition[8..16].copy_from_slice(&length.to_ne_bytes());
    partition[16..20].copy_from_slice(&number.to_ne_bytes());
    // `struct blkpg_ioctl_arg`: what to do (BLKPG_RESIZE_PARTITION), flags, how long the
    // above is, and where it is (after four bytes that line the pointer up).
    let mut request = [0u8; 24];
    request[0..4].copy_from_slice(&3u32.to_ne_bytes());
    request[8..12].copy_from_slice(&(partition.len() as u32).to_ne_bytes());
    request[16..24].copy_from_slice(&(partition.as_mut_ptr() as usize as u64).to_ne_bytes());
    // BLKPG: _IO(0x12, 105). (The kernel reads `partition` through the request: it is
    // kept until the call is over.)
    let said = ioctl(disk, 0x1269, &mut request).map(drop);
    std::hint::black_box(&mut partition);
    said
}

fn control() -> Result<File> {
    File::options().read(true).write(true).open("/dev/mapper/control")
}

/// Make the mapping `name`: `sectors` (512 bytes each) of `device` from its sector `from`,
/// under aes-xts with `key` (64 bytes). Says where the opened device is (`/dev/dm-N`).
///
/// (Sectors are counted from the mapping's start, wherever on `device` that is: a
/// partition mapped from 0 and its disk mapped from where the partition starts read alike.)
pub fn crypt(name: &str, device: &Path, from: u64, sectors: u64, key: &[u8]) -> Result<PathBuf> {
    let device = device.to_str().filter(|path| !path.contains(' '));
    let device = device.ok_or_else(|| Error::other("the device's path cannot be told to the kernel"))?;
    let mut told = String::with_capacity(2 * key.len() + device.len() + 32);
    told.push_str("aes-xts-plain64 ");
    key.iter().for_each(|byte| told.push_str(&format!("{byte:02x}")));
    told.push_str(&format!(" 0 {device} {from}"));
    let load = request(name, SECURE, Some((sectors, "crypt", &told)));
    // (The key is in `told` and in the request: neither is left lying in memory.)
    told.into_bytes().fill(0);
    let control = control()?;
    let made = call(&control, CREATE, request(name, 0, None)?)?;
    let loaded = load.and_then(|load| call(&control, LOAD, load).map(|mut said| said.fill(0)));
    // (Suspend without its flag is resume: the table loaded becomes the one in use.)
    if let Err(failed) = loaded.and_then(|()| call(&control, SUSPEND, request(name, 0, None)?)) {
        let _ = call(&control, REMOVE, request(name, 0, None)?);
        return Err(failed);
    }
    // The device's number as the kernel packs it: the minor's low byte, the major, the rest.
    let dev = u64::from_ne_bytes(made[40..48].try_into().expect("8 bytes"));
    let minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
    Ok(format!("/dev/dm-{minor}").into())
}

/// Remove the mapping `name`: what it showed is unreadable again. Refused while it is in use.
pub fn remove(name: &str) -> Result<()> {
    call(&control()?, REMOVE, request(name, 0, None)?).map(drop)
}

/// `bpf(2)`: `command` with `request` as its `union bpf_attr`, as far as it is filled in
/// (the kernel takes what is past the request's end as zeros). What the kernel answers.
///
/// For the two commands of [`device_filter`] only: neither has the kernel write through
/// the request, and what the request points at is alive for the call.
fn bpf(command: libc::c_int, request: &[u8]) -> Result<libc::c_long> {
    // SAFETY: `request` is `request.len()` readable bytes, and the pointers in it (see
    // `device_filter`) are to memory its caller holds until this returns.
    let said = unsafe { libc::syscall(libc::SYS_bpf, command, request.as_ptr(), request.len()) };
    if said < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(said)
    }
}

/// Make `program` (BPF instructions, eight bytes each) what `cgroup` (a cgroup's
/// directory, opened) asks at every open and mknod of a device node by a process in it:
/// the kernel checks the program before it takes it. It takes the place of the one put
/// there this way before; the cgroup keeps it, and it goes with the cgroup.
pub fn device_filter(cgroup: &File, program: &[u8]) -> Result<()> {
    use std::os::fd::{FromRawFd, OwnedFd};
    if program.is_empty() || !program.len().is_multiple_of(8) {
        return Err(Error::other("not a program of whole instructions"));
    }
    let license = b"Apache-2.0\0";
    // BPF_PROG_LOAD: the kind of program (BPF_PROG_TYPE_CGROUP_DEVICE), how many
    // instructions, where they are, where the licence's name is.
    let mut load = [0u8; 48];
    load[0..4].copy_from_slice(&15u32.to_ne_bytes());
    load[4..8].copy_from_slice(&((program.len() / 8) as u32).to_ne_bytes());
    load[8..16].copy_from_slice(&(program.as_ptr() as u64).to_ne_bytes());
    load[16..24].copy_from_slice(&(license.as_ptr() as u64).to_ne_bytes());
    let loaded = bpf(5, &load)?;
    // SAFETY: a descriptor the kernel just made for this process, and nobody else's.
    let loaded = unsafe { OwnedFd::from_raw_fd(loaded as libc::c_int) };
    // BPF_PROG_ATTACH: to which cgroup, which program, as what (BPF_CGROUP_DEVICE), and
    // with no flags: the one program of this cgroup, replaced by the next.
    let mut attach = [0u8; 16];
    attach[0..4].copy_from_slice(&cgroup.as_raw_fd().to_ne_bytes());
    attach[4..8].copy_from_slice(&loaded.as_raw_fd().to_ne_bytes());
    attach[8..12].copy_from_slice(&6u32.to_ne_bytes());
    bpf(8, &attach).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypt_requests_are_laid_out_as_the_kernel_reads_them() {
        let plain = request("kith-state", 0, None).unwrap();
        assert_eq!(plain.len(), 312);
        assert_eq!(plain[..4], 4u32.to_ne_bytes());
        assert_eq!(plain[12..20], [312u32.to_ne_bytes(), 312u32.to_ne_bytes()].concat()[..]);
        assert_eq!(&plain[48..59], b"kith-state\0");

        let load = request(
            "kith-state",
            SECURE,
            Some((2048, "crypt", "aes-xts-plain64 00ff 0 /dev/vda7 0")),
        )
        .unwrap();
        // One target, right after the header; the whole is a multiple of 8 and ends in zeros.
        assert_eq!(load[20..24], 1u32.to_ne_bytes());
        assert_eq!(load[28..32], (1u32 << 15).to_ne_bytes());
        assert_eq!(load[312 + 8..312 + 16], 2048u64.to_ne_bytes());
        assert_eq!(&load[312 + 24..312 + 30], b"crypt\0");
        assert!(load[352..].starts_with(b"aes-xts-plain64 00ff 0 /dev/vda7 0\0"));
        assert_eq!((load.len() % 8, load.len()), (0, 392));
        assert_eq!(load[12..16], 392u32.to_ne_bytes());

        assert!(request("", 0, None).is_err() && request("a/b", 0, None).is_err());
        assert!(request(&"n".repeat(128), 0, None).is_err());
        assert!(request("n", 0, Some((1, "a-kind-too-long-to-be-one", ""))).is_err());
    }

    /// Where device-mapper can be reached (as root, on Linux with dm-crypt): a mapping over
    /// a loop-free block device is the VM test's to show (ci/vm.sh --test crypt); here,
    /// that a request the kernel refuses comes back as its error and leaves nothing.
    #[test]
    fn crypt_refusals_are_errors() {
        if control().is_err() {
            return;
        }
        assert!(crypt("kith-dm-sys-test", Path::new("/dev/null/none"), 0, 8, &[0; 64]).is_err());
        assert!(remove("kith-dm-sys-test").is_err());
    }

    /// A program the kernel's checker refuses (it ends nowhere), and what is no program:
    /// errors, and nothing attached (a filter that holds is the VM test's to show:
    /// ci/vm.sh --test pods).
    #[test]
    fn filter_refusals_are_errors() {
        let Ok(here) = File::open("/sys/fs/cgroup") else {
            return;
        };
        assert!(device_filter(&here, &[]).is_err() && device_filter(&here, &[0; 7]).is_err());
        // r0 = 1, and no exit.
        assert!(device_filter(&here, &[0xb7, 0, 0, 0, 1, 0, 0, 0]).is_err());
    }

    /// What is no ext4 file system is not grown, and says so (a loop device and a real
    /// grow are the VM test's to show: ci/vm.sh --test share).
    #[test]
    fn grow_refusals_are_errors() {
        assert!(grow(Path::new("/proc"), 1 << 20).is_err());
        assert!(grow(Path::new("/nowhere/at/all"), 1).is_err());
    }
}
