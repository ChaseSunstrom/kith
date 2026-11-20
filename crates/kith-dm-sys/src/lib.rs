//! Device-mapper by ioctl (linux/dm-ioctl.h): what `dmsetup create` and `dmsetup remove`
//! do, for a machine with no dmsetup. One mapping of one dm-crypt target. And two more
//! things such a machine has no tool for: a file as a block device (`losetup`), and an ext4
//! file system grown where it is mounted (`resize2fs`), and a directory's project held to a
//! limit of its space (`chattr -p`, `setquota -P`). And what has no tool anywhere but
//! a container runtime: the program a cgroup asks which devices its processes may open
//! (`bpf(2)`), and a mount whose owners are seen through a user namespace
//! (`mount_setattr(2)`), with such a namespace to see them through.
//!
//! The `unsafe` of the workspace is here: the ioctl, bpf and mount calls themselves (and
//! taking the file descriptors they answer with), and the forks of a child that holds a
//! user namespace while it is made and of one that makes a container (see [`fork_start`]). Each request is put together as bytes, so there is no
//! struct whose layout has to match the kernel's.

use std::fs::File;
use std::io::{Error, Result};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
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

/// The ioctl `number` on `file` with `value` as its argument (a number, not a pointer).
fn ioctl_value(file: &File, number: u32, value: u64) -> Result<i32> {
    // SAFETY: the kernel takes `value` as a number and reads no memory through it.
    let said = unsafe { libc::ioctl(file.as_raw_fd(), number as _, value as libc::c_ulong) };
    if said < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(said)
    }
}

/// The bit each of the red, green and blue channels starts at in a pixel of the framebuffer
/// `file` (a /dev/fbN), as FBIOGET_VSCREENINFO reports them.
pub fn fb_channels(file: &File) -> Result<[u32; 3]> {
    const GET_SCREEN_INFO: u32 = 0x4600; // FBIOGET_VSCREENINFO
    let mut screen = vec![0u8; FB_VAR_SCREENINFO];
    ioctl(file, GET_SCREEN_INFO, &mut screen)?;
    Ok(fb_channels_of(&screen))
}

/// `struct fb_var_screeninfo`, in bytes.
const FB_VAR_SCREENINFO: usize = 160;
/// Where the `offset` (a u32) of the red, green and blue `fb_bitfield` sit in it.
const FB_CHANNEL_OFFSETS: [usize; 3] = [32, 44, 56];

fn fb_channels_of(screen: &[u8]) -> [u32; 3] {
    FB_CHANNEL_OFFSETS.map(|at| u32::from_ne_bytes([screen[at], screen[at + 1], screen[at + 2], screen[at + 3]]))
}

/// Put the console `tty` (/dev/tty0) in graphics mode, where the kernel draws no text over
/// a picture on the framebuffer, or back in text mode.
pub fn set_graphics(tty: &File, graphics: bool) -> Result<()> {
    const SET_MODE: u32 = 0x4B3A; // KDSETMODE
    const KD_TEXT: u64 = 0;
    const KD_GRAPHICS: u64 = 1;
    ioctl_value(tty, SET_MODE, if graphics { KD_GRAPHICS } else { KD_TEXT })?;
    Ok(())
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

/// Discard `length` bytes of the block device `disk` from `start` (both whole 512-byte
/// sectors): what `blkdiscard` asks. What it held reads as zeros or as it was, as the device
/// says; a device that cannot discard answers EOPNOTSUPP.
pub fn discard(disk: &File, start: u64, length: u64) -> Result<()> {
    // BLKDISCARD: _IO(0x12, 119), its argument a `uint64_t[2]`: where, and how long.
    let mut range = [0u8; 16];
    range[..8].copy_from_slice(&start.to_ne_bytes());
    range[8..].copy_from_slice(&length.to_ne_bytes());
    ioctl(disk, 0x1277, &mut range).map(drop)
}

/// `struct fsxattr`: flags, two sizes, the project (12 bytes in), one more size.
const FSXATTR: usize = 28;
/// FS_XFLAG_PROJINHERIT: what is made in a directory is of its project.
const INHERIT: u32 = 0x200;

/// The project of `dir` (ext4's, as `chattr -p` and `lsattr -p` know it), and whether
/// what is made in it is of the project too.
pub fn project(dir: &Path) -> Result<(u32, bool)> {
    let mut attr = [0u8; FSXATTR];
    // FS_IOC_FSGETXATTR: _IOR('X', 31, struct fsxattr)
    ioctl(&opened(dir)?, 0x801c_581f, &mut attr)?;
    let flags = u32::from_ne_bytes(attr[0..4].try_into().unwrap());
    Ok((
        u32::from_ne_bytes(attr[12..16].try_into().unwrap()),
        flags & INHERIT != 0,
    ))
}

/// The user namespace that owns the namespace `ns` is an open file of (`/proc/PID/ns/pid`,
/// say): `NS_GET_USERNS`.
pub fn owner_userns(ns: &File) -> Result<File> {
    // SAFETY: an ioctl on a descriptor `ns` holds open; it takes no memory and returns a new
    // descriptor or -1.
    let owner = unsafe { libc::ioctl(ns.as_raw_fd(), 0xb701) };
    if owner < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: the descriptor the ioctl just made, whose only owner this is.
    Ok(unsafe { File::from_raw_fd(owner) })
}

/// Put the directory `dir` in project `id`, and with `inherit` what is made in it from now on
/// too (what it holds already stays as it is). Root's alone to do, outside a user namespace,
/// on a file system that keeps projects: elsewhere it is refused.
pub fn set_project(dir: &Path, id: u32, inherit: bool) -> Result<()> {
    let dir = opened(dir)?;
    let mut attr = [0u8; FSXATTR];
    ioctl(&dir, 0x801c_581f, &mut attr)?;
    let flags = u32::from_ne_bytes(attr[0..4].try_into().unwrap());
    let flags = if inherit { flags | INHERIT } else { flags & !INHERIT };
    attr[0..4].copy_from_slice(&flags.to_ne_bytes());
    attr[12..16].copy_from_slice(&id.to_ne_bytes());
    // FS_IOC_FSSETXATTR: _IOW('X', 32, struct fsxattr)
    ioctl(&dir, 0x401c_5820, &mut attr).map(drop)
}

/// A directory by itself: never what a link in its place points at.
fn opened(dir: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
}

/// quotactl_fd(2) of a project on the file system `on` is on, with `bytes` as what it reads
/// or writes (each command's own size, which the caller gives).
fn quota(on: &Path, command: u32, id: u32, bytes: &mut [u8]) -> Result<()> {
    // QCMD(command, PRJQUOTA)
    let command = (command << 8) | 2;
    let on = opened(on)?;
    // SAFETY: the kernel reads and writes no more than the command's struct, which `bytes`
    // is at least the size of, and which lives past the call.
    let said = unsafe { libc::syscall(libc::SYS_quotactl_fd, on.as_raw_fd(), command, id, bytes.as_mut_ptr()) };
    if said < 0 { Err(Error::last_os_error()) } else { Ok(()) }
}

/// Whether the file system `on` is on holds each project to its limit: it has projects, and
/// is mounted to enforce them (ext4's `-O quota,project` and `prjquota`).
pub fn projects_held(on: &Path) -> bool {
    // Q_XGETQSTAT into `struct fs_quota_stat`, whose flags (2 bytes in) say FS_QUOTA_PDQ_ENFD.
    let mut stat = [0u8; 128];
    quota(on, 0x5805, 0, &mut stat).is_ok() && u16::from_ne_bytes([stat[2], stat[3]]) & 0x20 != 0
}

/// `struct if_dqblk`: limits and use of space (1 KiB blocks; use in bytes) and of files,
/// two times, and which of them are meant.
const DQBLK: usize = 72;

/// What sets a project's limits on space to `bytes` and on files to `files` (none, for 0),
/// and on nothing else.
fn limit_request(bytes: u64, files: u64) -> [u8; DQBLK] {
    let mut request = [0u8; DQBLK];
    request[0..8].copy_from_slice(&bytes.div_ceil(1024).to_ne_bytes());
    request[24..32].copy_from_slice(&files.to_ne_bytes());
    // QIF_BLIMITS | QIF_ILIMITS
    request[64..68].copy_from_slice(&5u32.to_ne_bytes());
    request
}

/// Hold project `id` on the file system `on` is on to `bytes` of it and to `files` files
/// (0: no limit), both in one call.
pub fn set_project_limit(on: &Path, id: u32, bytes: u64, files: u64) -> Result<()> {
    // Q_SETQUOTA
    quota(on, 0x80_0008, id, &mut limit_request(bytes, files))
}

/// The bytes and files project `id` holds of the file system `on` is on: as the kernel
/// counts them as they are written, with what is deleted but still open.
pub fn project_usage(on: &Path, id: u32) -> Result<(u64, u64)> {
    let mut answer = [0u8; DQBLK];
    // Q_GETQUOTA
    quota(on, 0x80_0007, id, &mut answer)?;
    let at = |from: usize| u64::from_ne_bytes(answer[from..from + 8].try_into().unwrap());
    Ok((at(16), at(40)))
}

/// The limits project `id` is held to on the file system `on` is on, in bytes and in files
/// (0: none).
pub fn project_limit(on: &Path, id: u32) -> Result<(u64, u64)> {
    let mut answer = [0u8; DQBLK];
    // Q_GETQUOTA
    quota(on, 0x80_0007, id, &mut answer)?;
    let at = |from: usize| u64::from_ne_bytes(answer[from..from + 8].try_into().unwrap());
    Ok((at(0).saturating_mul(1024), at(24)))
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
/// For the two commands of [`cgroup_program`] only: the kernel writes only to the log
/// room a load may point at, and what the request points at is alive for the call.
fn bpf(command: libc::c_int, request: &[u8]) -> Result<libc::c_long> {
    // SAFETY: `request` is `request.len()` readable bytes, and the pointers in it (see
    // `cgroup_program`) are to memory its caller holds until this returns, the log room
    // writable and as big as the request says.
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
    // BPF_PROG_TYPE_CGROUP_DEVICE, as BPF_CGROUP_DEVICE.
    cgroup_program(cgroup, program, 15, 6)
}

/// Make `program` what `cgroup` asks at every connect() of an IPv6 socket by a process
/// in it, before the kernel looks at the address: the program may write another address
/// and port in its place. As [`device_filter`]: it takes the place of the one before.
pub fn connect_filter(cgroup: &File, program: &[u8]) -> Result<()> {
    // BPF_PROG_TYPE_CGROUP_SOCK_ADDR, as BPF_CGROUP_INET6_CONNECT.
    cgroup_program(cgroup, program, 18, 11)
}

/// The last lines of what the verifier wrote in `log` (to its first NUL), to follow the
/// error: none where it wrote nothing, and said to be cut short where it filled the room.
fn verifier_said(log: &[u8], cut: bool) -> String {
    let said = String::from_utf8_lossy(&log[..log.iter().position(|&b| b == 0).unwrap_or(log.len())]);
    let lines: Vec<&str> = said.lines().filter(|line| !line.trim().is_empty()).collect();
    if lines.is_empty() {
        return String::new();
    }
    let tail = lines[lines.len().saturating_sub(6)..].join(" / ");
    format!(": the verifier: {tail}{}", if cut { " (cut short)" } else { "" })
}

/// Load `program` as a `kind` of program for `attach`, and put it on `cgroup` as that.
fn cgroup_program(cgroup: &File, program: &[u8], kind: u32, attach: u32) -> Result<()> {
    if program.is_empty() || !program.len().is_multiple_of(8) {
        return Err(Error::other("not a program of whole instructions"));
    }
    let license = b"Apache-2.0\0";
    // BPF_PROG_LOAD: the kind of program, how many instructions, where they are, where
    // the licence's name is; and (at 68) what it is to be attached as.
    let mut load = [0u8; 72];
    load[0..4].copy_from_slice(&kind.to_ne_bytes());
    load[4..8].copy_from_slice(&((program.len() / 8) as u32).to_ne_bytes());
    load[8..16].copy_from_slice(&(program.as_ptr() as u64).to_ne_bytes());
    load[16..24].copy_from_slice(&(license.as_ptr() as u64).to_ne_bytes());
    load[68..72].copy_from_slice(&attach.to_ne_bytes());
    let loaded = match bpf(5, &load) {
        Ok(loaded) => loaded,
        Err(refused) => {
            // Loaded once more with room for what the verifier says (at 24: how much, how
            // big the room is, where it is), whose last lines say why.
            let mut log = vec![0u8; 1 << 16];
            load[24..28].copy_from_slice(&1u32.to_ne_bytes());
            load[28..32].copy_from_slice(&(log.len() as u32).to_ne_bytes());
            load[32..40].copy_from_slice(&(log.as_mut_ptr() as u64).to_ne_bytes());
            match bpf(5, &load) {
                Ok(loaded) => loaded,
                // (ENOSPC: what it had to say did not fit.)
                Err(again) => {
                    let said = verifier_said(&log, again.raw_os_error() == Some(libc::ENOSPC));
                    return Err(Error::new(refused.kind(), format!("{refused}{said}")));
                }
            }
        }
    };
    // SAFETY: a descriptor the kernel just made for this process, and nobody else's.
    let loaded = unsafe { OwnedFd::from_raw_fd(loaded as libc::c_int) };
    // BPF_PROG_ATTACH: to which cgroup, which program, as what, and with no flags: the
    // one program of this cgroup, replaced by the next.
    let mut request = [0u8; 16];
    request[0..4].copy_from_slice(&cgroup.as_raw_fd().to_ne_bytes());
    request[4..8].copy_from_slice(&loaded.as_raw_fd().to_ne_bytes());
    request[8..12].copy_from_slice(&attach.to_ne_bytes());
    bpf(8, &request).map(drop)
}

/// The cookie of the network namespace this process is in: what a program's
/// bpf_get_netns_cookie() says for a socket made in it.
pub fn netns_cookie() -> Result<u64> {
    let socket = std::net::UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0))
        .or_else(|_| std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)))?;
    let mut cookie = 0u64;
    let mut size = std::mem::size_of::<u64>() as libc::socklen_t;
    // SAFETY: SO_NETNS_COOKIE writes at most `size` bytes to `cookie`, which is that big.
    let said = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            71,
            (&raw mut cookie).cast(),
            &raw mut size,
        )
    };
    if said < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(cookie)
    }
}

/// `prctl(PR_CAPBSET_DROP, cap)`: takes capability number `cap` out of the bounding set of
/// the calling thread (and so of what it starts afterwards). The set is per thread: a thread
/// made before this keeps its own. Needs CAP_SETPCAP.
pub fn bounding_drop(cap: u32) -> Result<()> {
    // SAFETY: PR_CAPBSET_DROP takes the capability number and reads no memory.
    if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0, 0, 0) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// The most descriptors one message carries (the kernel's `SCM_MAX_FD`).
pub const MOST_FDS: usize = 253;

/// A connected pair of unix sockets, close-on-exec, of `SOCK_SEQPACKET`: a message is read whole
/// or not at all (a datagram's boundary), it is not lost, and an end that is closed reads as end
/// of file at the other (a datagram pair has none, so a reader of one would wait for ever). Each
/// takes a message of 256 KiB and more at once (`SO_SNDBUF`, as far as the system allows).
pub fn socketpair() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: socketpair writes two descriptors into `fds`, which holds two.
    let made = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if made < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: both descriptors are new, and nothing else holds them.
    let (a, b) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for end in [&a, &b] {
        let size: libc::c_int = 1 << 19;
        // SAFETY: SO_SNDBUF reads one int, `size`. (A refusal leaves the default.)
        unsafe {
            libc::setsockopt(
                end.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const size).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    Ok((a, b))
}

/// Whole of `socket`'s message `bytes` sent, with the descriptors `fds` (at most [`MOST_FDS`])
/// beside it (`SCM_RIGHTS`): the other end gets its own copies. Waits as long as the socket's send
/// timeout allows (`SO_SNDTIMEO`), and then says `WouldBlock`.
pub fn send_fds(socket: BorrowedFd, bytes: &[u8], fds: &[BorrowedFd]) -> Result<()> {
    if fds.len() > MOST_FDS {
        return Err(Error::other(format!("{} descriptors: at most {MOST_FDS}", fds.len())));
    }
    let raw: Vec<libc::c_int> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    let data = std::mem::size_of_val(raw.as_slice()) as libc::c_uint;
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE(data) } as usize;
    // (`u64`s: the control buffer is aligned for a `cmsghdr`.)
    let mut control = vec![0u64; space.div_ceil(8)];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: an all-zero msghdr is a valid one (null pointers, zero lengths).
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &raw mut iov;
    header.msg_iovlen = 1;
    if !raw.is_empty() {
        header.msg_control = control.as_mut_ptr().cast();
        header.msg_controllen = space as _;
        // SAFETY: the control buffer is `space` bytes, room for one header and `data` bytes after
        // it, so CMSG_FIRSTHDR is inside it and CMSG_DATA has `data` bytes to write.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&header);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(data) as _;
            std::ptr::copy_nonoverlapping(raw.as_ptr().cast::<u8>(), libc::CMSG_DATA(cmsg), data as usize);
        }
    }
    loop {
        // SAFETY: `header` points at `iov` (the bytes) and `control`, alive for the call, which
        // only reads them.
        let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &header, libc::MSG_NOSIGNAL) };
        match sent {
            n if n as usize == bytes.len() => return Ok(()),
            n if n >= 0 => return Err(Error::other("a message sent in part")),
            _ => match Error::last_os_error() {
                e if e.kind() == std::io::ErrorKind::Interrupted => continue,
                e => return Err(e),
            },
        }
    }
}

/// One message of `socket` read into `buf`, and the descriptors that came with it (at most
/// `most`, itself at most [`MOST_FDS`]; close-on-exec): how many bytes, and the descriptors. Zero
/// bytes is the other end closed (or an empty message). A message longer than `buf`, or with more
/// descriptors than `most`, is refused whole, its descriptors closed. Waits as long as the receive
/// timeout allows (`SO_RCVTIMEO`), and then says `WouldBlock`.
pub fn recv_fds(socket: BorrowedFd, buf: &mut [u8], most: usize) -> Result<(usize, Vec<OwnedFd>)> {
    let most = most.min(MOST_FDS);
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE((most * std::mem::size_of::<libc::c_int>()) as libc::c_uint) } as usize;
    let mut control = vec![0u64; space.div_ceil(8)];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: an all-zero msghdr is a valid one.
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &raw mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = space as _;
    let got = loop {
        // SAFETY: `header` points at `iov` (`buf`) and `control`, alive and writable for the call,
        // which writes no more than their lengths.
        let got = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut header, libc::MSG_CMSG_CLOEXEC) };
        if got >= 0 {
            break got as usize;
        }
        match Error::last_os_error() {
            e if e.kind() == std::io::ErrorKind::Interrupted => continue,
            e => return Err(e),
        }
    };
    // Every descriptor taken before anything is refused, so that none is left open.
    let mut fds = Vec::new();
    // SAFETY: the kernel filled `control` with `msg_controllen` bytes of well-formed headers; each
    // SCM_RIGHTS payload is whole descriptors, which are ours now and nothing else's.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&header);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let data = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
                for at in 0..bytes / std::mem::size_of::<libc::c_int>() {
                    fds.push(OwnedFd::from_raw_fd(data.add(at).read_unaligned()));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&header, cmsg);
        }
    }
    // (The control buffer is padded to eight bytes: room for one more than `most` can be left.)
    if fds.len() > most || header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(Error::new(
            std::io::ErrorKind::InvalidData,
            "a message longer than the room for it, or with more descriptors",
        ));
    }
    Ok((got, fds))
}

/// `prctl(PR_SET_NO_NEW_PRIVS)`: no program this thread starts, or its children, has more
/// privilege than it had (set-user-id bits and file capabilities do nothing). It cannot be
/// undone.
pub fn no_new_privs() -> Result<()> {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes its flag by value and reads no memory.
    match unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

/// Replaces this process's whole environment with `vars`, through the C library and not
/// through `std::env`: std keeps a lock on the environment that `Command::spawn` of any
/// other thread holds across its fork, so a child forked then holds it for good and
/// `remove_var` there waits forever. For a process that has one thread (a forked child): in
/// one with more it is refused, for another thread may read the environment meanwhile, which
/// C allows no more than std does; such a process must use `std::env`. A name or value C
/// cannot hold (an empty name, a `=` in a name, a NUL) is refused before anything is changed.
pub fn replace_environ(vars: &[(String, String)]) -> Result<()> {
    if std::fs::read_dir("/proc/self/task")?.count() != 1 {
        return Err(Error::new(
            std::io::ErrorKind::Unsupported,
            "the environment is replaced only by a process with one thread",
        ));
    }
    let bad = |what: &str| {
        Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("an environment variable {what}"),
        )
    };
    let mut cs = Vec::with_capacity(vars.len());
    for (key, value) in vars {
        if key.is_empty() || key.contains(['=', '\0']) || value.contains('\0') {
            return Err(bad("has a name or value that C cannot hold"));
        }
        let pair = |s: &str| std::ffi::CString::new(s).map_err(|_| bad("has a NUL"));
        cs.push((pair(key)?, pair(value)?));
    }
    // SAFETY: clearenv takes no argument; setenv copies its two NUL-ended strings (live here).
    // No other thread of this process exists (checked above), and none can start: this is the
    // only one running.
    unsafe {
        if libc::clearenv() != 0 {
            return Err(Error::last_os_error());
        }
        for (key, value) in &cs {
            if libc::setenv(key.as_ptr(), value.as_ptr(), 1) != 0 {
                return Err(Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// `setresuid(2)` of the process: real, effective and saved user id, `None` for one left as
/// it is. (The C library sets it on every thread.)
pub fn setresuid(real: Option<u32>, effective: Option<u32>, saved: Option<u32>) -> Result<()> {
    let id = |id: Option<u32>| id.unwrap_or(u32::MAX);
    // SAFETY: setresuid takes three ids by value; u32::MAX is "unchanged".
    match unsafe { libc::setresuid(id(real), id(effective), id(saved)) } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

/// The capabilities of the calling thread: `[effective, permitted, inheritable]`, as bit sets
/// (capability `n` is bit `n`).
pub fn capget() -> Result<[u64; 3]> {
    let (header, mut data) = cap_header();
    // SAFETY: capget reads the header and writes two `__user_cap_data_struct`s (version 3) to `data`.
    match unsafe { libc::syscall(libc::SYS_capget, &raw const header, data.as_mut_ptr()) } {
        0 => Ok([0, 1, 2].map(|set| u64::from(data[0][set]) | u64::from(data[1][set]) << 32)),
        _ => Err(Error::last_os_error()),
    }
}

/// `capset(2)` of the calling thread (per thread, as the kernel has it): `[effective, permitted,
/// inheritable]` as bit sets. The kernel refuses what is not a subset of what the thread has.
pub fn capset(sets: [u64; 3]) -> Result<()> {
    let (header, mut data) = cap_header();
    for (set, bits) in sets.into_iter().enumerate() {
        data[0][set] = bits as u32;
        data[1][set] = (bits >> 32) as u32;
    }
    // SAFETY: capset reads the header and two `__user_cap_data_struct`s (version 3) from `data`.
    match unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

/// A version 3 `__user_cap_header_struct` (the calling thread: pid 0) and room for its two
/// `{effective, permitted, inheritable}` data structs, as `[low, high][set]`.
fn cap_header() -> ([u32; 2], [[u32; 3]; 2]) {
    ([0x2008_0522, 0], [[0; 3]; 2])
}

/// Makes the part of this program that is written only while it starts (the addresses set
/// right at its start: tables of functions, the table of its own addresses) read-only, as the
/// loader of a program that is not static does. A static program of musl's sets those addresses
/// right by itself and leaves the pages writable, so a write that goes astray in the process
/// could change which function a call reaches. Called first in `main`, before any thread.
///
/// The program's headers say which part (`PT_GNU_RELRO`). Its start is rounded down to a page
/// (a linker starts it on one). Its end is rounded up only where nothing else of the program
/// is in the rest of that page (lld leaves it so; GNU ld ends it on a page), else down, so no
/// page with something still written is shut. Returns how many bytes were made read-only.
#[cfg(target_env = "musl")]
pub fn seal_relro() -> Result<usize> {
    use std::ffi::{c_int, c_void};
    /// What is asked of each program header table: `data` is a `usize` that the bytes shut
    /// are added to, or `usize::MAX` once a page could not be shut.
    unsafe extern "C" fn each(info: *mut libc::dl_phdr_info, _size: usize, data: *mut c_void) -> c_int {
        // SAFETY: musl calls this once, for the program itself, with a valid `info` whose
        // `dlpi_phdr` is the table of `dlpi_phnum` headers the kernel mapped; `data` is the
        // `usize` passed below.
        let (base, headers) = unsafe {
            let info = &*info;
            (
                info.dlpi_addr as usize,
                std::slice::from_raw_parts(info.dlpi_phdr, usize::from(info.dlpi_phnum)),
            )
        };
        // SAFETY: sysconf has no precondition.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        for (start, end) in relro_ranges(
            headers
                .iter()
                .map(|h| (h.p_type, h.p_vaddr as usize, h.p_memsz as usize)),
            page,
        ) {
            // SAFETY: the range is whole pages of this program's own mapping, which nothing
            // writes after the start files have run (that is what the linker's header says).
            let shut = unsafe { libc::mprotect((base + start) as *mut c_void, end - start, libc::PROT_READ) };
            // SAFETY: `data` is the `usize` passed to dl_iterate_phdr below.
            let total = unsafe { &mut *data.cast::<usize>() };
            *total = if shut == 0 {
                total.saturating_add(end - start)
            } else {
                usize::MAX
            };
        }
        1
    }
    let mut total = 0usize;
    // SAFETY: `each` matches the callback's type, and `total` outlives the call.
    unsafe { libc::dl_iterate_phdr(Some(each), (&raw mut total).cast()) };
    match total {
        usize::MAX => Err(Error::last_os_error()),
        total => Ok(total),
    }
}

/// Elsewhere the loader has done it already.
#[cfg(not(target_env = "musl"))]
pub fn seal_relro() -> Result<usize> {
    Ok(0)
}

/// A user namespace in which the ids 0..`count` are this one's `from`..`from + count`
/// (users and groups alike), as a descriptor for [`mount_mapped`]: no process is left in
/// it. A child makes it and waits while this process writes its maps, which only root may
/// do for ids that are not its own; the child is gone when this returns, collected here or
/// by whoever collects this process's children.
pub fn user_namespace(from: u32, count: u32) -> Result<OwnedFd> {
    use std::io::{Read, Write};
    let map = format!("0 {from} {count}\n");
    let pipe = || -> Result<(File, File)> {
        let mut ends = [0 as libc::c_int; 2];
        // SAFETY: pipe2 writes two descriptors to `ends`, which has room for them.
        if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(Error::last_os_error());
        }
        // SAFETY: two descriptors the kernel just made for this process, and nobody else's.
        Ok(unsafe { (File::from_raw_fd(ends[0]), File::from_raw_fd(ends[1])) })
    };
    let (mut made, made_in) = pipe()?;
    let (go_out, mut go) = pipe()?;
    let (said, wait) = (made_in.as_raw_fd(), go_out.as_raw_fd());
    // SAFETY: the child calls nothing but unshare, write, read and _exit, which a child of
    // a process with threads may call, and touches no memory but its own stack.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(Error::last_os_error());
    }
    if child == 0 {
        // SAFETY: as above; `said` and `wait` are this child's copies of the pipes' ends.
        unsafe {
            let errno = match libc::unshare(libc::CLONE_NEWUSER) {
                0 => 0,
                _ => *libc::__errno_location(),
            };
            libc::write(said, (&raw const errno).cast(), 4);
            // (A byte and not the end of the pipe: another child made at the same time
            // may hold a copy of this one's writing end.)
            let mut byte = 0u8;
            libc::read(wait, (&raw mut byte).cast(), 1);
            libc::_exit(0);
        }
    }
    drop((made_in, go_out));
    // The child by descriptor, taken while it lives (it waits for `go`): whoever collects
    // this process's children may collect it first, and its number may be another child's
    // by the time it is waited for here.
    // SAFETY: pidfd_open takes a process id and flags, and gives a descriptor or -1.
    let held = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) };
    // SAFETY: a descriptor the kernel just made for this process, and nobody else's.
    let held = (held >= 0).then(|| unsafe { OwnedFd::from_raw_fd(held as libc::c_int) });
    let mut errno = [0u8; 4];
    let users = made
        .read_exact(&mut errno)
        .and_then(|()| match i32::from_ne_bytes(errno) {
            0 => {
                std::fs::write(format!("/proc/{child}/uid_map"), &map)?;
                std::fs::write(format!("/proc/{child}/gid_map"), &map)?;
                Ok(OwnedFd::from(File::open(format!("/proc/{child}/ns/user"))?))
            }
            errno => Err(Error::from_raw_os_error(errno)),
        });
    let _ = go.write_all(&[0]);
    // SAFETY: a wait for a child of this process, with no status asked for. (Another thread
    // collecting it first is no harm: the descriptor is that child's and no later one's.)
    unsafe {
        match &held {
            Some(held) => libc::waitid(
                libc::P_PIDFD,
                held.as_raw_fd() as libc::id_t,
                std::ptr::null_mut(),
                libc::WEXITED,
            ),
            // (No pidfd: a kernel before 5.3, or no descriptor left. By its number, then.)
            None => libc::waitpid(child, std::ptr::null_mut(), 0),
        }
    };
    users
}

/// The most bytes [`fork_start`]'s child brings back (a pipe holds 64 KiB, so its blocking write
/// of this much never waits for the parent, which reads after the child has ended).
pub const FORKED_MOST: usize = 32 * 1024;

/// A child made by [`fork_start`], not yet collected.
pub struct Forked {
    pid: i32,
    read: File,
}

/// Runs `f` in a child made by `fork(2)`; [`Forked::collect`] waits for it and brings back the
/// first [`FORKED_MOST`] bytes it gave. Split in two so that a caller can say who the child is
/// (to a reaper that would otherwise collect it) while it is made.
///
/// For a call that clones a process itself with a raw `clone3`, as libcontainer does: from a
/// process with other threads, the clone's child starts with whatever lock a thread held at
/// that instant (the allocator's) and waits for it forever, since a raw `clone3` skips the
/// handlers `fork` runs to put the allocator right. In a child of `fork` there is one thread,
/// so the clone is safe. Whatever `f` makes with `clone` that outlives the child is the
/// nearest child subreaper's afterwards.
///
/// The child runs with no signal blocked, whatever the forking thread blocks, and with SIGPIPE
/// as the default again, not the ignored one Rust's runtime sets: both outlive the `clone` and
/// the exec of a container's process.
///
/// `fork` puts right only the allocator's locks. Any other lock of this process that a thread
/// holds at the fork (tracing's registry, the environment's, stderr's, a `Mutex` of the
/// program's own) is held for good in the child, which then waits for it: the caller keeps
/// those off the child's path, or holds them across the call, and `collect` gives it a deadline.
///
/// A reaper that waits for any child (kith-runtime's `reap_orphans`, `waitid(Id::All)`) can take
/// this child's status before `collect` does, which then fails with ECHILD: a caller in a process
/// with such a reaper registers the child with it (kith-runtime's `spawn_awaited`) while it is made.
pub fn fork_start(f: impl FnOnce() -> Vec<u8>) -> Result<Forked> {
    use std::io::Write;
    let mut ends = [0; 2];
    // SAFETY: pipe2 writes two descriptors into `ends`.
    if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: both are open, and this is their only owner.
    let (read, mut write) = unsafe { (File::from_raw_fd(ends[0]), File::from_raw_fd(ends[1])) };
    // (Only the read end is nonblocking, for `collect`: a process `f` cloned holds the write
    // end until it execs, so the pipe is never read to its end.)
    // SAFETY: fcntl on a descriptor this process owns.
    if unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } != 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: the child runs `f` and `_exit`s; it returns nowhere, and runs no destructor of
    // what this process holds. (`f` takes no lock another thread may hold: see above.)
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(Error::last_os_error());
    }
    if child == 0 {
        // A child starts with the mask of the thread that forked it, and a container's process
        // (made from this child, and exec'd) keeps it: a pod with SIGTERM blocked never hears
        // `kith stop`. kithd's threads hold the keeper's block (SIGINT, SIGTERM, SIGCHLD).
        // Likewise Rust's runtime ignores SIGPIPE, and that stays ignored through clone and exec.
        // SAFETY: sigemptyset fills a set this child owns; pthread_sigmask sets its one thread's
        // mask; signal sets this one process's disposition (both are async-signal-safe).
        unsafe {
            let mut none = std::mem::zeroed::<libc::sigset_t>();
            libc::sigemptyset(&mut none);
            libc::pthread_sigmask(libc::SIG_SETMASK, &none, std::ptr::null_mut());
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
        let mut bytes = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_default();
        bytes.truncate(FORKED_MOST);
        // (A short write is the parent's empty or cut answer.)
        let _ = write.write_all(&bytes);
        // SAFETY: ends this process at once, with no handler or destructor.
        unsafe { libc::_exit(0) }
    }
    Ok(Forked { pid: child, read })
}

/// The parent of process `pid`, as `/proc` says now.
fn parent_of(pid: i32) -> Option<i32> {
    stat_of(pid).map(|(_, parent)| parent)
}

/// The state letter (`R`, `S`, `T`, `Z`, ...) and the parent of process `pid`, as `/proc` says now.
fn stat_of(pid: i32) -> Option<(char, i32)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // (The name in `stat` may hold spaces and `)`: the fields follow the last one.)
    let (_, rest) = stat.rsplit_once(") ")?;
    let mut fields = rest.split(' ');
    Some((fields.next()?.chars().next()?, fields.next()?.parse::<i32>().ok()?))
}

/// How long `collect` waits for a killed helper to be reaped, and for a stopped one to stop.
const REAP_WITHIN: std::time::Duration = std::time::Duration::from_secs(5);
const STOP_WITHIN: std::time::Duration = std::time::Duration::from_millis(100);

/// Waits up to `limit` for this process's child `pid` to end and takes it: true once it is gone
/// (or was taken by another). A child stuck in the kernel (D state, a hung mount) outlasts it:
/// false, and the zombie is left to the reaper.
fn reap_within(pid: i32, limit: std::time::Duration) -> bool {
    let until = std::time::Instant::now() + limit;
    loop {
        // SAFETY: waitpid on this process's own child, with no status wanted.
        let said = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        let interrupted = said < 0 && Error::last_os_error().kind() == std::io::ErrorKind::Interrupted;
        if said == pid || (said < 0 && !interrupted) {
            return true;
        }
        if std::time::Instant::now() >= until {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Waits up to `limit` for `pid` to show as stopped (a SIGSTOP is queued when `kill` returns,
/// and acted on when the process next runs in the kernel's own time).
fn stopped_within(pid: i32, limit: std::time::Duration) {
    let until = std::time::Instant::now() + limit;
    while stat_of(pid).is_some_and(|(state, _)| state != 'T') && std::time::Instant::now() < until {
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// A process to kill, held by descriptor: it names that process for as long as it is held,
/// whatever its number becomes.
struct Victim {
    held: OwnedFd,
}

impl Victim {
    /// Process `pid` if it is still `parent`'s child, `None` if it is gone or is not: a
    /// descriptor is opened first and the parent read after, so that a match is of the process
    /// the descriptor names. No descriptor (no file left, a kernel before 5.3, a sandbox) is an
    /// error, not a kill by number: a number may be another process's by then.
    fn pin(pid: i32, parent: i32) -> Result<Option<Victim>> {
        // SAFETY: pidfd_open takes a process id and flags, and gives a descriptor or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            let e = Error::last_os_error();
            return if e.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(e)
            };
        }
        // SAFETY: a descriptor the kernel just made for this process, and nobody else's.
        let held = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
        Ok((parent_of(pid) == Some(parent)).then_some(Victim { held }))
    }

    fn kill(&self) {
        // SAFETY: pidfd_send_signal on a descriptor this holds, with no info.
        unsafe { libc::syscall(libc::SYS_pidfd_send_signal, self.held.as_raw_fd(), libc::SIGKILL, 0, 0) };
    }
}

/// What `descendants` found under a process, and what it could not.
struct Tree {
    victims: Vec<Victim>,
    /// What went unlisted or unheld, for the error `collect` gives ("" where nothing did).
    missed: String,
}

/// Every process under `root` (its children, theirs, ...) as `/proc` lists them now, each held
/// by descriptor and checked to be still its parent's child once held.
// ponytail: a process that forks while this reads may escape it, one reparented away mid-scan
// (its parent ended) is dropped by the check, one already reparented (to a subreaper) is not
// under `root` to be found, and one no descriptor could be opened for is skipped and named;
// `collect` stops the child first, which closes the first for its own children. A cgroup kill,
// where the caller has the cgroup, catches all of them.
fn descendants(root: i32) -> Result<Tree> {
    let mut parents = std::collections::HashMap::<i32, Vec<i32>>::new();
    let mut unread = (0, None);
    // (A `/proc` that cannot be listed, not mounted or hidden, is an error: not an empty tree.)
    for entry in std::fs::read_dir("/proc")? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                unread = (unread.0 + 1, unread.1.or(Some(e)));
                continue;
            }
        };
        let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse::<i32>().ok()) else {
            continue;
        };
        if let Some(parent) = parent_of(pid) {
            parents.entry(parent).or_default().push(pid);
        }
    }
    let mut victims = Vec::new();
    let mut skipped = (0, None);
    let mut next = vec![root];
    while let Some(parent) = next.pop() {
        for &child in parents.get(&parent).into_iter().flatten() {
            match Victim::pin(child, parent) {
                Ok(Some(victim)) => {
                    victims.push(victim);
                    next.push(child);
                }
                Ok(None) => {}
                Err(e) => skipped = (skipped.0 + 1, skipped.1.or(Some(e))),
            }
        }
    }
    let mut missed = String::new();
    if let (n, Some(e)) = skipped {
        missed += &format!("; {n} descendants skipped: pidfd_open: {e}");
    }
    if let (n, Some(e)) = unread {
        missed += &format!("; {n} /proc entries unreadable: {e}");
    }
    Ok(Tree { victims, missed })
}

impl Forked {
    /// The child's process number.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Waits for the child, and returns what it gave: empty where it ended without giving any
    /// (it panicked, or was killed). A child that has not ended within `deadline` is killed and
    /// collected, with every process it started, and the error says it did not end.
    pub fn collect(self, deadline: std::time::Duration) -> Result<Vec<u8>> {
        use std::io::Read;
        let until = std::time::Instant::now() + deadline;
        loop {
            // SAFETY: waitpid on this process's own child, with no status wanted.
            let said = unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), libc::WNOHANG) };
            if said == self.pid {
                break;
            }
            if said < 0 {
                let e = Error::last_os_error();
                if e.kind() != std::io::ErrorKind::Interrupted {
                    return Err(e);
                }
            } else if std::time::Instant::now() >= until {
                // What the child started (a tenant, an init: the very process that hung may be
                // one) is killed with it: stopped first, so it starts no more, and listed
                // before it is killed, as its children are this process's after.
                // SAFETY: kill and waitpid on this process's own child.
                unsafe { libc::kill(self.pid, libc::SIGSTOP) };
                stopped_within(self.pid, STOP_WITHIN);
                let tree = descendants(self.pid);
                // SAFETY: kill on this process's own child.
                unsafe {
                    libc::kill(self.pid, libc::SIGKILL);
                }
                if let Ok(tree) = &tree {
                    tree.victims.iter().for_each(Victim::kill);
                }
                // (Bounded: a helper stuck in the kernel must not hold the caller past its deadline.)
                let reaped = reap_within(self.pid, REAP_WITHIN);
                return Err(Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "the forked helper did not end within {} s and {}{}",
                        deadline.as_secs_f32(),
                        if reaped {
                            "was killed"
                        } else {
                            "did not die (left to the reaper)"
                        },
                        match &tree {
                            Ok(tree) => tree.missed.clone(),
                            Err(e) => format!("; its descendants could not be listed: {e}"),
                        }
                    ),
                ));
            }
            // ponytail: a poll every 10 ms; a create takes tens, so the cost is the wait's own.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut got = Vec::new();
        // (Nonblocking: where nothing is left, or the child wrote none, it says so and stops.)
        let _ = (&self.read).take(FORKED_MOST as u64).read_to_end(&mut got);
        Ok(got)
    }
}

/// What a mount made by [`mount_mapped`] is besides mapped: read-only, without setuid,
/// without devices.
pub const RDONLY: u64 = 0x1;
pub const NOSUID: u64 = 0x2;
pub const NODEV: u64 = 0x4;

/// Mount `from` (with every mount under it) at `to`, which is there already and of the same
/// kind (a directory, a file), seen through `users` (from [`user_namespace`]): to the
/// processes of a namespace with the same maps, a file owned by id n on disk is their n's,
/// and what they make there as n is n's on disk. `flags` are of [`RDONLY`], [`NOSUID`],
/// [`NODEV`]. A mount under `from` on a file system that takes no mapping (NFS, say)
/// refuses the whole.
pub fn mount_mapped(from: &Path, to: &Path, users: BorrowedFd, flags: u64) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(from.as_os_str().as_bytes()).map_err(Error::other)?;
    mapped(libc::AT_FDCWD, &from, 0, to, users, flags)
}

/// [`mount_mapped`] of what `from` is open on (from [`beneath`]): nothing is resolved by path
/// on its side, so what a container wrote there meanwhile changes nothing of what is mounted.
pub fn mount_mapped_fd(from: BorrowedFd, to: &Path, users: BorrowedFd, flags: u64) -> Result<()> {
    mapped(
        from.as_raw_fd(),
        c"",
        libc::AT_EMPTY_PATH as libc::c_uint,
        to,
        users,
        flags,
    )
}

fn mapped(
    at: libc::c_int,
    from: &std::ffi::CStr,
    empty: libc::c_uint,
    to: &Path,
    users: BorrowedFd,
    flags: u64,
) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let to = std::ffi::CString::new(to.as_os_str().as_bytes()).map_err(Error::other)?;
    const OPEN_TREE_CLONE: libc::c_uint = 1;
    const AT_RECURSIVE: libc::c_uint = 0x8000;
    const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 4;
    let flags = flags & (RDONLY | NOSUID | NODEV);
    // SAFETY: open_tree reads the string `from`, which lives through the call.
    let tree = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            at,
            from.as_ptr(),
            OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint | AT_RECURSIVE | empty,
        )
    };
    if tree < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: a descriptor the kernel just made for this process, and nobody else's.
    let tree = unsafe { OwnedFd::from_raw_fd(tree as libc::c_int) };
    // struct mount_attr: what to set, what to clear, the propagation, the user namespace.
    let attr: [u64; 4] = [MOUNT_ATTR_IDMAP | flags, 0, 0, users.as_raw_fd() as u64];
    // SAFETY: mount_setattr reads the empty string and `attr`, whose size it is told; both
    // live through the call.
    let set = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            tree.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH as libc::c_uint | AT_RECURSIVE,
            attr.as_ptr(),
            std::mem::size_of_val(&attr),
        )
    };
    if set < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: move_mount reads the two strings, which live through the call.
    let moved = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            tree.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    match moved < 0 {
        true => Err(Error::last_os_error()),
        false => Ok(()),
    }
}

/// The part `part` of the directory `dir`, open (`O_PATH`), for [`mount_mapped_fd`]. What is
/// in `dir` is a container's to write, links included: no step of `part` may be a link, wherever
/// it points, nor `..`, nor leave `dir`'s file system. A directory on the way that is not there
/// is made (as Kubernetes makes a subPath), on the step opened before it.
/// A directory it makes is its parent's user's and group's, with its parent's mode.
pub fn beneath(dir: &Path, part: &str) -> Result<OwnedFd> {
    use std::os::unix::fs::OpenOptionsExt;
    let steps: Vec<&str> = part
        .split('/')
        .filter(|step| !step.is_empty() && *step != ".")
        .collect();
    if part.starts_with('/') || steps.is_empty() || steps.contains(&"..") {
        return Err(Error::other(format!("`{part}` is not a path under the directory")));
    }
    let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
    let mut at: OwnedFd = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(dir)?
        .into();
    for step in steps {
        let name = std::ffi::CString::new(step).map_err(Error::other)?;
        let open = |at: &OwnedFd| {
            // struct open_how: flags, mode, resolve.
            let how: [u64; 3] = [
                (libc::O_PATH | libc::O_CLOEXEC) as u64,
                0,
                libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV,
            ];
            // SAFETY: openat2 reads `name` and `how`, whose size it is told; both live through it.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    at.as_raw_fd(),
                    name.as_ptr(),
                    how.as_ptr(),
                    std::mem::size_of_val(&how),
                )
            };
            match fd < 0 {
                true => Err(Error::last_os_error()),
                // SAFETY: a descriptor the kernel just made for this process, and nobody else's.
                false => Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) }),
            }
        };
        at = match open(&at) {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                // SAFETY: fstat writes `parent`, which is its own; `at` is an open descriptor.
                let mut parent: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(at.as_raw_fd(), &mut parent) } < 0 {
                    return Err(Error::last_os_error());
                }
                // SAFETY: mkdirat reads `name`, which lives through the call. (A name made there
                // meanwhile, a link say, is EEXIST, and the open after refuses a link.)
                let made = unsafe { libc::mkdirat(at.as_raw_fd(), name.as_ptr(), parent.st_mode & 0o7777) };
                if made < 0 && Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                    return Err(Error::last_os_error());
                }
                let new = open(&at)?;
                // SAFETY: fchownat of the descriptor itself (AT_EMPTY_PATH): nothing is resolved.
                let owned = unsafe {
                    libc::fchownat(
                        new.as_raw_fd(),
                        c"".as_ptr(),
                        parent.st_uid,
                        parent.st_gid,
                        libc::AT_EMPTY_PATH,
                    )
                };
                if owned < 0 {
                    return Err(Error::last_os_error());
                }
                new
            }
            other => other.map_err(|e| Error::new(e.kind(), format!("`{step}` of `{part}`: {e}")))?,
        };
    }
    Ok(at)
}

const PT_LOAD: u32 = 1;
const PT_GNU_RELRO: u32 = 0x6474_e552;

/// The page ranges to make read-only, from a program's headers as (type, address, size in
/// memory): see [`seal_relro`].
pub fn relro_ranges(headers: impl Iterator<Item = (u32, usize, usize)> + Clone, page: usize) -> Vec<(usize, usize)> {
    let down = |at: usize| at & !(page - 1);
    headers
        .clone()
        .filter(|(kind, _, _)| *kind == PT_GNU_RELRO)
        .filter_map(|(_, at, size)| {
            // (Headers are the file's to say: a size of 0 or one that wraps is no range.)
            let end = at.checked_add(size).filter(|_| size > 0)?;
            let up = down(end.checked_add(page - 1)?);
            // (The part's own PT_LOAD ends where it does or goes on past it: only what begins
            // or goes on inside the rest of the page counts.)
            let shared = headers
                .clone()
                .any(|(kind, from, len)| kind == PT_LOAD && from < up && from.saturating_add(len) > end);
            let (start, end) = (down(at), if shared { down(end) } else { up });
            (start < end).then_some((start, end))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::time::Duration;

    /// Held by each test here that has a child, so the one that looks for any ended child
    /// (mapped_mount_refusals_are_errors) sees none of another test's.
    static CHILDREN: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn children() -> std::sync::MutexGuard<'static, ()> {
        CHILDREN.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn forked_brings_back_what_the_child_gave() {
        let _children = children();
        let got = fork_start(|| b"said it".to_vec())
            .unwrap()
            .collect(Duration::from_secs(30));
        assert_eq!(got.unwrap(), b"said it");
    }

    /// Puts back the signal mask this thread had, when dropped.
    struct Unblock(libc::sigset_t);

    impl Drop for Unblock {
        fn drop(&mut self) {
            // SAFETY: sets the mask of this thread only.
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
        }
    }

    /// Blocks SIGINT, SIGTERM and SIGCHLD on the calling thread, as the keeper's mask does
    /// (bit N-1 of SigBlk is signal N); the mask comes back when the guard drops.
    fn block_the_keepers_signals() -> Unblock {
        // SAFETY: sigset_t is plain data; sigemptyset and sigaddset fill it, and
        // pthread_sigmask changes only this thread's mask.
        unsafe {
            let (mut set, mut old) = (std::mem::zeroed::<libc::sigset_t>(), std::mem::zeroed());
            libc::sigemptyset(&mut set);
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGCHLD] {
                libc::sigaddset(&mut set, signal);
            }
            assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old), 0);
            Unblock(old)
        }
    }

    /// What a forked child's status says on `field` (`SigBlk`, `SigIgn`), with the mask blocked.
    fn forked_status(field: &'static str) -> Vec<u8> {
        let _children = children();
        let _blocked = block_the_keepers_signals();
        fork_start(move || {
            let key = format!("{field}:\t").into_bytes();
            std::fs::read("/proc/thread-self/status")
                .unwrap_or_default()
                .split(|&b| b == b'\n')
                .find_map(|line| line.strip_prefix(key.as_slice()))
                .unwrap_or(b"unread")
                .to_vec()
        })
        .unwrap()
        .collect(Duration::from_secs(30))
        .unwrap()
    }

    /// A container's process inherits the mask of the thread that forks it, and kithd's tokio
    /// threads keep the keeper's block: the child starts with nothing blocked.
    #[test]
    fn forked_child_has_no_signal_blocked() {
        assert_eq!(forked_status("SigBlk"), b"0000000000000000");
    }

    /// Rust's runtime ignores SIGPIPE in this process, an ignored signal stays ignored across
    /// clone and exec, and a pod's process would not hear it: bit 13 (0x1000) of SigIgn is clear.
    #[test]
    fn forked_child_does_not_ignore_sigpipe() {
        let ignored = u64::from_str_radix(std::str::from_utf8(&forked_status("SigIgn")).unwrap(), 16).unwrap();
        assert_eq!(ignored & (1 << (libc::SIGPIPE - 1)), 0, "SigIgn {ignored:#x}");
    }

    #[test]
    fn forked_cuts_an_answer_over_the_most() {
        let _children = children();
        let got = fork_start(|| vec![7; FORKED_MOST + 100])
            .unwrap()
            .collect(Duration::from_secs(30));
        assert_eq!(got.unwrap(), vec![7; FORKED_MOST]);
    }

    #[test]
    fn forked_gives_nothing_where_the_child_panicked() {
        let _children = children();
        let got = fork_start(|| panic!("no answer"))
            .unwrap()
            .collect(Duration::from_secs(30));
        assert!(got.unwrap().is_empty());
    }

    /// A child that does not end is killed and collected at the deadline, and says so.
    #[test]
    fn forked_kills_a_child_that_outlasts_the_deadline() {
        let _children = children();
        let forked = fork_start(|| {
            std::thread::sleep(Duration::from_secs(300));
            Vec::new()
        })
        .unwrap();
        let pid = forked.pid();
        let said = forked.collect(Duration::from_millis(200)).unwrap_err();
        assert!(said.to_string().contains("did not end"), "{said}");
        // Collected: there is no child of that number left to wait for.
        // SAFETY: waitpid on a number that is no child of this process, with no status wanted.
        assert_eq!(unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) }, -1);
    }

    #[test]
    fn a_victim_is_held_only_while_its_parent_is_the_one_listed() {
        let _children = children();
        let me = std::process::id() as i32;
        // SAFETY: getppid takes nothing.
        let parent = unsafe { libc::getppid() };
        let mine = match Victim::pin(me, parent) {
            Ok(held) => held.expect("this process is its parent's child"),
            // (A sandbox that blocks pidfd_open: nothing here can be tried.)
            Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM | libc::ENOSYS)) => return,
            Err(e) => panic!("pidfd_open: {e}"),
        };
        drop(mine);
        // (A number whose parent is not the one it was listed under, as a reused one is: dropped.)
        assert!(Victim::pin(me, parent + 1).unwrap().is_none());
        assert!(Victim::pin(i32::MAX, parent).unwrap().is_none());
        // The signal goes by descriptor to the process it names.
        let mut sleeper = std::process::Command::new("sleep").arg("300").spawn().unwrap();
        Victim::pin(sleeper.id() as i32, me)
            .unwrap()
            .expect("the sleeper is this process's child")
            .kill();
        assert!(!sleeper.wait().unwrap().success());
    }

    #[test]
    fn a_process_no_descriptor_can_be_opened_for_is_an_error_not_a_kill_by_number() {
        let _children = children();
        let said = fork_start(|| {
            let me = std::process::id() as i32;
            // SAFETY: getppid takes nothing; setrlimit takes a limit and a pointer to its value.
            let parent = unsafe { libc::getppid() };
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: as above; the soft limit goes to 0 under the hard one it has.
            unsafe {
                libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit);
                limit.rlim_cur = 0;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                    return b"the limit was not lowered".to_vec();
                }
            }
            match Victim::pin(me, parent) {
                Err(e) if e.raw_os_error() == Some(libc::EMFILE) => b"ok".to_vec(),
                Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM | libc::ENOSYS)) => b"ok".to_vec(),
                Err(e) => format!("{e}").into_bytes(),
                Ok(_) => b"a victim was made with no descriptor to hold it".to_vec(),
            }
        })
        .unwrap()
        .collect(Duration::from_secs(30))
        .unwrap();
        assert_eq!(String::from_utf8_lossy(&said), "ok");
    }

    // (Taken by `reap_within`, the thing under test, not by `Child::wait`.)
    #[allow(clippy::zombie_processes)]
    #[test]
    fn a_child_that_will_not_die_is_given_up_on_within_the_limit() {
        let _children = children();
        // A child nobody signalled stands in for one stuck in the kernel: it will not end.
        let sleeper = std::process::Command::new("sleep").arg("300").spawn().unwrap();
        let pid = sleeper.id() as i32;
        let begun = std::time::Instant::now();
        assert!(!reap_within(pid, Duration::from_millis(100)));
        assert!(begun.elapsed() < Duration::from_secs(5), "the wait is bounded");
        // SAFETY: kill on this test's own child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        assert!(reap_within(pid, Duration::from_secs(10)));
        // (Taken already: gone, so true, not a wait for the limit.)
        assert!(reap_within(pid, Duration::from_millis(100)));
    }

    #[allow(clippy::zombie_processes)]
    #[test]
    fn a_stopped_process_shows_as_stopped_before_the_list_is_taken() {
        let _children = children();
        let sleeper = std::process::Command::new("sleep").arg("300").spawn().unwrap();
        let pid = sleeper.id() as i32;
        // SAFETY: kill on this test's own child.
        unsafe { libc::kill(pid, libc::SIGSTOP) };
        stopped_within(pid, Duration::from_secs(10));
        assert_eq!(stat_of(pid).map(|(state, _)| state), Some('T'));
        // SAFETY: kill on this test's own child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        assert!(reap_within(pid, Duration::from_secs(10)));
    }

    /// What the helper made (a tenant, an init) is the one that may hang, and it outlives the
    /// helper that is killed: at the deadline the whole tree under the child goes, not only it.
    #[test]
    fn forked_kills_what_the_child_started_too() {
        let _children = children();
        let note = std::env::temp_dir().join(format!("kith-dm-sys-grandchild-{}", std::process::id()));
        let _ = std::fs::remove_file(&note);
        let forked = fork_start({
            let note = note.clone();
            move || {
                // SAFETY: the child has one thread; the grandchild only waits for signals.
                let grandchild = unsafe { libc::fork() };
                if grandchild == 0 {
                    loop {
                        // SAFETY: pause takes nothing.
                        unsafe { libc::pause() };
                    }
                }
                let _ = std::fs::write(&note, grandchild.to_string());
                std::thread::sleep(Duration::from_secs(300));
                Vec::new()
            }
        })
        .unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(10);
        let grandchild = loop {
            match std::fs::read_to_string(&note)
                .ok()
                .and_then(|text| text.parse::<i32>().ok())
            {
                Some(pid) => break pid,
                None if std::time::Instant::now() < until => std::thread::sleep(Duration::from_millis(10)),
                None => panic!("the child never started a process"),
            }
        };
        assert!(forked.collect(Duration::from_millis(300)).is_err());
        let _ = std::fs::remove_file(&note);
        // (Gone, or a zombie its new parent has yet to collect.)
        let dead = || {
            std::fs::read_to_string(format!("/proc/{grandchild}/stat")).map_or(true, |stat| {
                stat.rsplit_once(") ").is_some_and(|(_, rest)| rest.starts_with('Z'))
            })
        };
        let until = std::time::Instant::now() + Duration::from_secs(10);
        while !dead() && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(dead(), "the process the child started outlived it");
    }

    /// A name or a value C cannot hold is refused before the environment is touched, and what
    /// is allowed replaces it whole; a process with other threads is refused outright.
    #[test]
    fn replace_environ_refuses_what_c_cannot_hold_and_leaves_the_environment() {
        let _children = children();
        let refused = replace_environ(&[("A".into(), "1".into())]).unwrap_err();
        assert_eq!(
            refused.kind(),
            std::io::ErrorKind::Unsupported,
            "this test process has threads"
        );
        // The environment as libc holds it: `std::env::vars` takes std's environment lock, which
        // another test's spawn may hold across its fork into this child (the stall this guards).
        fn environ_now() -> Vec<(String, String)> {
            let mut vars = Vec::new();
            // SAFETY: read in a forked child of one thread, where nothing writes it; each entry
            // is a NUL-ended `NAME=value` string, and the list ends in a null pointer.
            unsafe {
                let mut at = libc::environ;
                while !at.is_null() && !(*at).is_null() {
                    let entry = std::ffi::CStr::from_ptr(*at).to_string_lossy().into_owned();
                    vars.extend(entry.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())));
                    at = at.add(1);
                }
            }
            vars
        }
        let said = fork_start(|| {
            let before = environ_now();
            let bad = [("", "x"), ("A=B", "x"), ("A\0B", "x"), ("A", "x\0y")];
            for (key, value) in bad {
                // (A good pair first: the refusal is of the whole call, before any change.)
                let vars = [
                    ("GOOD".to_string(), "1".to_string()),
                    (key.to_string(), value.to_string()),
                ];
                if replace_environ(&vars).is_ok() || environ_now() != before {
                    return format!("{key:?}={value:?} was not refused whole").into_bytes();
                }
            }
            if replace_environ(&[("ONLY".into(), "1".into())]).is_err() {
                return b"a good environment was refused".to_vec();
            }
            let now = environ_now();
            if now != [("ONLY".to_string(), "1".to_string())] {
                return format!("{now:?}").into_bytes();
            }
            b"ok".to_vec()
        })
        .unwrap()
        .collect(Duration::from_secs(30))
        .unwrap();
        assert_eq!(String::from_utf8_lossy(&said), "ok");
    }

    #[test]
    fn fb_var_screeninfo_is_160_bytes_with_the_channels_offsets_at_32_44_56() {
        assert_eq!(FB_VAR_SCREENINFO, 160, "struct fb_var_screeninfo");
        assert_eq!(
            FB_CHANNEL_OFFSETS,
            [32, 44, 56],
            "red, green and blue fb_bitfield.offset"
        );
        // A pixel of BGR: blue in the low byte, red at 16.
        let mut screen = vec![0u8; FB_VAR_SCREENINFO];
        for (at, offset) in FB_CHANNEL_OFFSETS.into_iter().zip([16u32, 8, 0]) {
            screen[at..at + 4].copy_from_slice(&offset.to_ne_bytes());
        }
        assert_eq!(fb_channels_of(&screen), [16, 8, 0]);
    }

    const PAGE: usize = 0x1000;
    fn relro(at: usize, size: usize) -> (u32, usize, usize) {
        (PT_GNU_RELRO, at, size)
    }
    fn load(at: usize, size: usize) -> (u32, usize, usize) {
        (PT_LOAD, at, size)
    }

    #[test]
    fn relro_ends_on_a_page() {
        let headers = [
            load(0, 0x1000),
            load(0x1000, 0x3000),
            relro(0x1000, 0x2000),
            load(0x4000, 0x800),
        ];
        assert_eq!(relro_ranges(headers.into_iter(), PAGE), [(0x1000, 0x3000)]);
    }

    /// lld: the part ends inside a page and its segment ends there too, with nothing in the rest.
    #[test]
    fn relro_ends_inside_a_page_with_nothing_else_in_it_rounds_up() {
        let headers = [load(0x1000, 0x1800), relro(0x1000, 0x1800), load(0x4000, 0x100)];
        assert_eq!(relro_ranges(headers.into_iter(), PAGE), [(0x1000, 0x3000)]);
    }

    /// The segment goes on past the part (written data after it): that page stays writable.
    #[test]
    fn relro_ends_inside_a_page_a_load_goes_on_in_rounds_down() {
        let headers = [load(0x1000, 0x3000), relro(0x1000, 0x1800)];
        assert_eq!(relro_ranges(headers.into_iter(), PAGE), [(0x1000, 0x2000)]);
        // Another segment that begins in the rest of the page is the same.
        let headers = [load(0x1000, 0x1800), load(0x2900, 0x100), relro(0x1000, 0x1800)];
        assert_eq!(relro_ranges(headers.into_iter(), PAGE), [(0x1000, 0x2000)]);
    }

    #[test]
    fn a_range_that_rounds_to_nothing_is_not_asked_for() {
        let headers = [load(0x1000, 0x3000), relro(0x1100, 0x200)];
        assert!(relro_ranges(headers.into_iter(), PAGE).is_empty());
    }

    #[test]
    fn a_header_near_the_top_of_the_address_space_gives_no_range_and_no_panic() {
        for headers in [
            [relro(usize::MAX - 0x100, 0x80)],
            [relro(usize::MAX - 0x100, 0x200)],
            [relro(usize::MAX, usize::MAX)],
        ] {
            assert!(relro_ranges(headers.into_iter(), PAGE).is_empty());
        }
        // A segment whose size wraps does not make the part shared, or panic.
        let headers = [load(usize::MAX - 1, usize::MAX), relro(0x1000, 0x1000)];
        assert_eq!(relro_ranges(headers.into_iter(), PAGE), [(0x1000, 0x2000)]);
    }

    #[test]
    fn a_relro_header_of_size_zero_gives_no_range() {
        let headers = [load(0x1000, 0x3000), relro(0x1000, 0)];
        assert!(relro_ranges(headers.into_iter(), PAGE).is_empty());
    }

    #[test]
    fn no_relro_header_no_range() {
        let headers = [load(0, 0x1000), load(0x1000, 0x1000), (7, 0x1000, 0x100)];
        assert!(relro_ranges(headers.into_iter(), PAGE).is_empty());
    }

    /// Only that the stub answers: this test program is built for glibc, where `seal_relro`
    /// does nothing (the loader did it). That the shipped musl programs are sealed is shown by
    /// `python3 ci/budgets.py`, against their /proc/PID/maps.
    #[test]
    fn sealing_a_running_test_program_answers() {
        assert!(seal_relro().is_ok());
    }

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

    /// Of what the verifier wrote: its last lines, said to be cut short where it filled
    /// the room, and nothing where it wrote nothing.
    #[test]
    fn the_verifier_says_why_in_its_last_lines() {
        let log = b"0: (b7) r0 = 1\n\n1: (95) exit\nR0 !read_ok\n\0\0junk";
        assert_eq!(
            verifier_said(log, false),
            ": the verifier: 0: (b7) r0 = 1 / 1: (95) exit / R0 !read_ok"
        );
        assert_eq!(
            verifier_said(b"a\nb\nc\nd\ne\nf\ng\n\0", true),
            ": the verifier: b / c / d / e / f / g (cut short)"
        );
        assert_eq!(verifier_said(b"\0\0\0", false), "");
        assert_eq!(verifier_said(b" \n\n", false), "");
    }

    /// What is no ext4 file system is not grown, and says so (a loop device and a real
    /// grow are the VM test's to show: ci/vm.sh --test share).
    #[test]
    fn grow_refusals_are_errors() {
        assert!(grow(Path::new("/proc"), 1 << 20).is_err());
        assert!(grow(Path::new("/nowhere/at/all"), 1).is_err());
    }

    /// A project's limits are asked for in whole KiB, rounded up, and in files, as hard
    /// limits on space and on files alone (no soft limit, no use, no time).
    #[test]
    fn project_limits_are_laid_out_as_the_kernel_reads_them() {
        let request = limit_request(64 << 20, 8192);
        assert_eq!(request[0..8], (64u64 << 10).to_ne_bytes());
        assert_eq!(request[8..24], [0; 16]);
        assert_eq!(request[24..32], 8192u64.to_ne_bytes());
        assert_eq!(request[32..64], [0; 32]);
        assert_eq!(request[64..68], 5u32.to_ne_bytes());
        assert_eq!(limit_request(1, 0)[0..8], 1u64.to_ne_bytes());
        assert_eq!(limit_request(0, 0)[0..8], 0u64.to_ne_bytes());
    }

    /// What keeps no projects says so: no limit is set or read there, and none is held.
    #[test]
    fn project_refusals_are_errors() {
        let (proc, nowhere) = (Path::new("/proc"), Path::new("/nowhere/at/all"));
        for on in [proc, nowhere] {
            assert!(!projects_held(on), "{on:?}");
            assert!(project(on).is_err() && set_project(on, 7, true).is_err(), "{on:?}");
            assert!(set_project_limit(on, 7, 1 << 20, 4096).is_err() && project_usage(on, 7).is_err());
        }
        // (Never through a link: what it points at is not the directory named.)
        let dir = std::env::temp_dir().join(format!("kith-project-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink(".", dir.join("link")).unwrap();
        assert!(set_project(&dir.join("link"), 7, true).is_err() && project(&dir.join("link")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// On a file system that holds projects (as root: the VM test's, ci/vm.sh --test quota),
    /// a directory's project is set, its limit holds and its use is counted. Skipped by name
    /// where there is none.
    #[test]
    fn projects_hold_where_the_file_system_keeps_them() {
        let on = std::env::temp_dir();
        if !projects_held(&on) {
            eprintln!("projects_hold_where_the_file_system_keeps_them: skipped: {on:?} holds no projects");
            return;
        }
        let dir = on.join(format!("kith-project-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        set_project(&dir, 4243, false).unwrap();
        assert_eq!(project(&dir).unwrap(), (4243, false));
        set_project(&dir, 4242, true).unwrap();
        assert_eq!(project(&dir).unwrap(), (4242, true));
        set_project_limit(&dir, 4242, 1 << 20, 3).unwrap();
        assert_eq!(project_limit(&dir, 4242).unwrap(), (1 << 20, 3));
        std::fs::write(dir.join("some"), vec![1u8; 64 << 10]).unwrap();
        File::open(dir.join("some")).unwrap().sync_all().unwrap();
        let (bytes, files) = project_usage(&dir, 4242).unwrap();
        assert!(bytes >= 64 << 10 && files >= 2, "{bytes} {files}");
        assert!(std::fs::write(dir.join("more"), vec![1u8; 2 << 20]).is_err());
        // (The directory, and two files made: its three. No fourth is.)
        assert!(File::create(dir.join("fourth")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
        set_project_limit(&on, 4242, 0, 0).unwrap();
    }

    /// A part of a directory whose path a container writes (a subPath): opened beneath it, each
    /// missing directory made, and refused where any step is a link, wherever it points, or
    /// `..`; what comes back is the part itself, open.
    #[test]
    fn subpath_beneath_makes_the_part_and_follows_no_link() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let dir = std::env::temp_dir().join(format!("kith-subpath-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a")).unwrap();
        std::fs::write(dir.join("a/file"), b"x").unwrap();
        symlink("/", dir.join("root")).unwrap();
        symlink("a", dir.join("inside")).unwrap();
        std::fs::create_dir(dir.join("a/real")).unwrap();
        symlink("/etc", dir.join("a/real/etc")).unwrap();
        let inode = |fd: &OwnedFd| {
            std::fs::metadata(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                .unwrap()
                .ino()
        };
        let made = beneath(&dir, "a/b/c").unwrap();
        assert!(dir.join("a/b/c").is_dir());
        assert_eq!(inode(&made), std::fs::metadata(dir.join("a/b/c")).unwrap().ino());
        assert_eq!(
            inode(&beneath(&dir, "a/file").unwrap()),
            std::fs::metadata(dir.join("a/file")).unwrap().ino()
        );
        assert_eq!(
            inode(&beneath(&dir, "./a//b/").unwrap()),
            std::fs::metadata(dir.join("a/b")).unwrap().ino()
        );
        for refused in [
            "root",
            "root/etc",
            "inside",
            "inside/b",
            "a/real/etc",
            "a/real/etc/x",
            "..",
            "a/../a",
            "/a",
            "",
        ] {
            assert!(beneath(&dir, refused).is_err(), "{refused}");
        }
        // (Nothing was made through a link: no `x` under the host's /etc, none under `a`.)
        assert!(!Path::new("/etc/x").exists() && !dir.join("a/x").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Ids that are not its own are mapped by root alone, and a mapped mount of nothing,
    /// or through what is no user namespace, is refused (a mapped mount that holds is the
    /// VM test's to show: ci/vm.sh --test share).
    #[test]
    fn mapped_mount_refusals_are_errors() {
        use std::os::fd::AsFd;
        use std::os::unix::fs::MetadataExt;
        let _children = children();
        let no_users = File::open("/proc/self/stat").unwrap();
        let (nowhere, elsewhere) = (Path::new("/nowhere/at/all"), Path::new("/nowhere/else"));
        assert!(mount_mapped(nowhere, elsewhere, no_users.as_fd(), RDONLY).is_err());
        assert!(mount_mapped_fd(no_users.as_fd(), elsewhere, no_users.as_fd(), RDONLY).is_err());
        assert!(user_namespace(u32::MAX, 2).is_err() && user_namespace(1 << 16, 0).is_err());
        let root = std::fs::metadata("/proc/self").unwrap().uid() == 0;
        match user_namespace(7 << 16, 1 << 16) {
            Ok(users) => {
                assert!(root, "a user namespace of ids not its own, made by no root");
                let kind = std::fs::read_link(format!("/proc/self/fd/{}", users.as_raw_fd())).unwrap();
                assert!(kind.to_string_lossy().starts_with("user:["), "{kind:?}");
                // (Of a mount this process has not got, and none is made.)
                assert!(mount_mapped(nowhere, elsewhere, users.as_fd(), NOSUID | NODEV).is_err());
            }
            Err(e) => assert!(!root, "root made no user namespace: {e}"),
        }
        // Its helper is collected when it returns, made or refused: no child of this
        // process is left that has ended. (The other tests here with a child hold CHILDREN.)
        // SAFETY: waitid that looks (WNOWAIT) at any child, writing to `info`, which is its own.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let looked = unsafe {
            libc::waitid(
                libc::P_ALL,
                0,
                &raw mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        // SAFETY: waitid filled `info` (or left it zeroed: no child has ended).
        assert!(
            looked != 0 || unsafe { info.si_pid() } == 0,
            "a child was left uncollected"
        );
    }

    fn timeout(end: &OwnedFd, option: libc::c_int, millis: i64) {
        let at = libc::timeval {
            tv_sec: millis / 1000,
            tv_usec: (millis % 1000) * 1000,
        };
        // SAFETY: the option reads one timeval.
        let set = unsafe {
            libc::setsockopt(
                end.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw const at).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        assert_eq!(set, 0);
    }

    #[test]
    fn a_message_and_a_descriptor_cross_a_socketpair() {
        let (a, b) = socketpair().unwrap();
        let file = tempfile_with(b"through the socket");
        send_fds(a.as_fd(), b"hello", &[file.as_fd()]).unwrap();
        let mut buf = [0u8; 64];
        let (n, fds) = recv_fds(b.as_fd(), &mut buf, 4).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(fds.len(), 1);
        let mut copy = File::from(fds.into_iter().next().unwrap());
        let mut text = String::new();
        std::io::Read::read_to_string(&mut copy, &mut text).unwrap();
        assert_eq!(text, "through the socket");
    }

    #[test]
    fn a_big_message_crosses_whole_and_a_short_buffer_refuses_it() {
        let (a, b) = socketpair().unwrap();
        let big = vec![7u8; 256 * 1024];
        send_fds(a.as_fd(), &big, &[]).unwrap();
        let mut buf = vec![0u8; 256 * 1024];
        let (n, fds) = recv_fds(b.as_fd(), &mut buf, 0).unwrap();
        assert_eq!((n, fds.len()), (big.len(), 0));
        send_fds(a.as_fd(), &big, &[]).unwrap();
        let mut small = [0u8; 16];
        let refused = recv_fds(b.as_fd(), &mut small, 0).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn more_descriptors_than_the_room_are_refused_and_closed() {
        let (a, b) = socketpair().unwrap();
        let file = tempfile_with(b"x");
        send_fds(a.as_fd(), b"two", &[file.as_fd(), file.as_fd()]).unwrap();
        let mut buf = [0u8; 8];
        let refused = recv_fds(b.as_fd(), &mut buf, 1).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData);
        assert!(send_fds(a.as_fd(), b"", &vec![file.as_fd(); MOST_FDS + 1]).is_err());
    }

    #[test]
    fn a_closed_end_reads_as_end_of_file_and_a_quiet_one_times_out() {
        let (a, b) = socketpair().unwrap();
        timeout(&b, libc::SO_RCVTIMEO, 50);
        let mut buf = [0u8; 8];
        let quiet = recv_fds(b.as_fd(), &mut buf, 0).unwrap_err();
        assert_eq!(quiet.kind(), std::io::ErrorKind::WouldBlock);
        drop(a);
        // (Another test's fork may hold a copy of the closed end for a moment: wait it out.)
        let end = (0..40).find_map(|_| match recv_fds(b.as_fd(), &mut buf, 0) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
            done => Some(done),
        });
        assert_eq!(end.expect("an end of file").unwrap().0, 0);
    }

    #[test]
    fn a_full_socket_times_out_a_sender() {
        let (a, _b) = socketpair().unwrap();
        timeout(&a, libc::SO_SNDTIMEO, 50);
        let chunk = vec![0u8; 64 * 1024];
        let stuck = (0..10_000).find_map(|_| send_fds(a.as_fd(), &chunk, &[]).err());
        assert_eq!(
            stuck.expect("a socket that never fills").kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn the_privilege_wrappers_keep_what_the_thread_has() {
        // Own thread: capset and no_new_privs are per thread, and setresuid to what is already
        // ours changes nothing.
        std::thread::spawn(|| {
            let [effective, permitted, inheritable] = capget().unwrap();
            assert_eq!(effective & !permitted, 0);
            capset([effective, permitted, inheritable]).unwrap();
            let uid = unsafe { libc::getuid() };
            setresuid(None, None, None).unwrap();
            setresuid(Some(uid), Some(uid), Some(uid)).unwrap();
            no_new_privs().unwrap();
            no_new_privs().unwrap();
            // Raising a capability the thread lacks is refused.
            if permitted != u64::MAX {
                assert!(capset([effective, u64::MAX, inheritable]).is_err());
            }
        })
        .join()
        .unwrap();
    }

    fn tempfile_with(bytes: &[u8]) -> File {
        let path = std::env::temp_dir().join(format!(
            "kith-dm-sys-fd-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, bytes).unwrap();
        let file = File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        file
    }
}
