//! Device-mapper by ioctl (linux/dm-ioctl.h): what `dmsetup create` and `dmsetup remove`
//! do, for a machine with no dmsetup. One mapping of one dm-crypt target. And two more
//! things such a machine has no tool for: a file as a block device (`losetup`), and an ext4
//! file system grown where it is mounted (`resize2fs`). And one that has no tool anywhere
//! but a container runtime: the program a cgroup asks which devices its processes may
//! open (`bpf(2)`). And what lets the kernel pass the bytes of a TCP connection on to
//! another itself: a socket map with a program, and what the kernel counts of a socket.
//!
//! The `unsafe` of the workspace is here: the ioctl, bpf and socket option calls
//! themselves (and taking the file descriptor bpf answers with). Each request is put together as bytes, so
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
/// For the commands of [`device_filter`] and [`SocketMap`] only: none has the kernel write
/// through the request, and what the request points at is alive for the call.
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
    if program.is_empty() || !program.len().is_multiple_of(8) {
        return Err(Error::other("not a program of whole instructions"));
    }
    // BPF_PROG_TYPE_CGROUP_DEVICE.
    let loaded = load(15, program)?;
    // BPF_PROG_ATTACH: to which cgroup, which program, as what (BPF_CGROUP_DEVICE), and
    // with no flags: the one program of this cgroup, replaced by the next.
    let mut attach = [0u8; 16];
    attach[0..4].copy_from_slice(&cgroup.as_raw_fd().to_ne_bytes());
    attach[4..8].copy_from_slice(&loaded.as_raw_fd().to_ne_bytes());
    attach[8..12].copy_from_slice(&6u32.to_ne_bytes());
    bpf(8, &attach).map(drop)
}

/// BPF_PROG_LOAD of `program` (whole instructions) as a program of the kind `kind`: its
/// descriptor. The kernel checks the program before it takes it.
fn load(kind: u32, program: &[u8]) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let license = b"Apache-2.0\0";
    // The kind, how many instructions, where they are, where the licence's name is.
    let mut load = [0u8; 48];
    load[0..4].copy_from_slice(&kind.to_ne_bytes());
    load[4..8].copy_from_slice(&((program.len() / 8) as u32).to_ne_bytes());
    load[8..16].copy_from_slice(&(program.as_ptr() as u64).to_ne_bytes());
    load[16..24].copy_from_slice(&(license.as_ptr() as u64).to_ne_bytes());
    let loaded = bpf(5, &load)?;
    // SAFETY: a descriptor the kernel just made for this process, and nobody else's.
    Ok(unsafe { OwnedFd::from_raw_fd(loaded as libc::c_int) })
}

/// A socket map of the kernel's (BPF_MAP_TYPE_SOCKHASH): TCP sockets, each under a
/// number. A program attached to the map is run on what each socket in it is sent, before
/// anyone reads it ([`SocketMap::redirect_to`]).
pub struct SocketMap(std::os::fd::OwnedFd);

impl SocketMap {
    /// An empty map for up to `capacity` sockets (room is taken as sockets are put in).
    pub fn new(capacity: u32) -> Result<SocketMap> {
        use std::os::fd::{FromRawFd, OwnedFd};
        // BPF_MAP_CREATE: the kind, the key's size (a u64), the value's (a descriptor),
        // how many.
        let mut create = [0u8; 20];
        create[0..4].copy_from_slice(&18u32.to_ne_bytes());
        create[4..8].copy_from_slice(&8u32.to_ne_bytes());
        create[8..12].copy_from_slice(&4u32.to_ne_bytes());
        create[12..16].copy_from_slice(&capacity.to_ne_bytes());
        let made = bpf(0, &create)?;
        // SAFETY: a descriptor the kernel just made for this process, and nobody else's.
        Ok(SocketMap(unsafe { OwnedFd::from_raw_fd(made as libc::c_int) }))
    }

    /// Put `socket` (an established TCP connection's) in the map under `key`, in place of
    /// what was there. The kernel refuses a socket in any other state: one that has had
    /// its end of the connection, say.
    pub fn insert(&self, key: u64, socket: std::os::fd::BorrowedFd) -> Result<()> {
        let value = socket.as_raw_fd() as u32;
        // BPF_MAP_UPDATE_ELEM: the map, where the key is, where the value is, BPF_ANY.
        let mut update = [0u8; 32];
        update[0..4].copy_from_slice(&self.0.as_raw_fd().to_ne_bytes());
        update[8..16].copy_from_slice(&(&key as *const u64 as u64).to_ne_bytes());
        update[16..24].copy_from_slice(&(&value as *const u32 as u64).to_ne_bytes());
        bpf(2, &update).map(drop)
    }

    /// Take what is under `key` out of the map (the socket itself stays open).
    pub fn remove(&self, key: u64) -> Result<()> {
        // BPF_MAP_DELETE_ELEM: the map, where the key is.
        let mut delete = [0u8; 16];
        delete[0..4].copy_from_slice(&self.0.as_raw_fd().to_ne_bytes());
        delete[8..16].copy_from_slice(&(&key as *const u64 as u64).to_ne_bytes());
        bpf(3, &delete).map(drop)
    }

    /// What a socket in this map is sent is sent on, by the kernel, on the socket `peers`
    /// has under this one's cookie ([`socket_cookie`]); none is read by anyone here. With
    /// no socket under that cookie, the bytes are dropped: so a socket's peer is put in
    /// `peers` before the socket is put here, and taken out after it.
    pub fn redirect_to(&self, peers: &SocketMap) -> Result<()> {
        // if the packet has no bytes (an end alone), return SK_DROP;
        // r6 = the packet; *(u64 *)(r10 - 8) = bpf_get_socket_cookie(r6);
        // return bpf_sk_redirect_hash(r6, peers, r10 - 8, 0) (SK_PASS, with where it
        // goes, or SK_DROP: nothing under the key).
        // (An end alone sent on is an error to the kernel (6.18): it marks the socket it
        // was sent to as broken and sends it nothing more. The end is the connection's
        // state, which the socket keeps; dropping its packet loses nothing.)
        let mut program: Vec<u8> = [
            [0x61, 0x12, 0, 0, 0, 0, 0, 0],
            [0x55, 0x02, 2, 0, 0, 0, 0, 0],
            [0xb7, 0, 0, 0, 0, 0, 0, 0],
            [0x95, 0, 0, 0, 0, 0, 0, 0],
            [0xbf, 0x16, 0, 0, 0, 0, 0, 0],
            [0x85, 0, 0, 0, 46, 0, 0, 0],
            [0x7b, 0x0a, 0xf8, 0xff, 0, 0, 0, 0],
            [0xbf, 0x61, 0, 0, 0, 0, 0, 0],
            [0x18, 0x12, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0],
            [0xbf, 0xa3, 0, 0, 0, 0, 0, 0],
            [0x07, 0x03, 0, 0, 0xf8, 0xff, 0xff, 0xff],
            [0xb7, 0x04, 0, 0, 0, 0, 0, 0],
            [0x85, 0, 0, 0, 72, 0, 0, 0],
            [0x95, 0, 0, 0, 0, 0, 0, 0],
        ]
        .concat();
        // (The map is named by its descriptor in the load of a 64-bit number: the kernel
        // puts the map itself there.)
        program[68..72].copy_from_slice(&peers.0.as_raw_fd().to_ne_bytes());
        // BPF_PROG_TYPE_SK_SKB.
        let loaded = load(14, &program)?;
        // BPF_PROG_ATTACH to this map, as BPF_SK_SKB_VERDICT: the map keeps it.
        let mut attach = [0u8; 16];
        attach[0..4].copy_from_slice(&self.0.as_raw_fd().to_ne_bytes());
        attach[4..8].copy_from_slice(&loaded.as_raw_fd().to_ne_bytes());
        attach[8..12].copy_from_slice(&38u32.to_ne_bytes());
        bpf(8, &attach).map(drop)
    }
}

/// `getsockopt(2)` of `socket`'s option `name` at `level` into `value`: how much of it the
/// kernel filled in.
fn option(socket: std::os::fd::BorrowedFd, level: libc::c_int, name: libc::c_int, value: &mut [u8]) -> Result<usize> {
    let mut length = value.len() as libc::socklen_t;
    // SAFETY: `value` is `length` writable bytes, and `length` is a socklen_t for the call.
    let said = unsafe { libc::getsockopt(socket.as_raw_fd(), level, name, value.as_mut_ptr().cast(), &mut length) };
    if said < 0 {
        return Err(Error::last_os_error());
    }
    Ok(length as usize)
}

/// The number the kernel gave `socket` when it was made, the same for its whole life and
/// never another's (SO_COOKIE).
pub fn socket_cookie(socket: std::os::fd::BorrowedFd) -> Result<u64> {
    let mut cookie = [0u8; 8];
    match option(socket, libc::SOL_SOCKET, libc::SO_COOKIE, &mut cookie)? {
        8 => Ok(u64::from_ne_bytes(cookie)),
        _ => Err(Error::other("no cookie")),
    }
}

/// What the kernel counts of a TCP connection (TCP_INFO).
#[derive(Clone, Copy, Debug)]
pub struct TcpCounts {
    /// Its state (`TCP_ESTABLISHED`, 1; `TCP_CLOSE_WAIT`, 8, once the other end is done
    /// sending; `TCP_CLOSE`, 7, once it is over or was reset).
    pub state: u8,
    /// How long since it was last sent a byte.
    pub since_received: std::time::Duration,
    /// How many of the bytes it sent the other end has said it has (and its end).
    pub acked: u64,
    /// How many bytes it was sent (and the other end's end of them).
    pub received: u64,
    /// How many of those wait in it to be read (FIONREAD).
    pub unread: u64,
}

/// What the kernel counts of the TCP connection `socket`.
pub fn tcp_counts(socket: std::os::fd::BorrowedFd) -> Result<TcpCounts> {
    let mut info = [0u8; 136];
    if option(socket, libc::IPPROTO_TCP, libc::TCP_INFO, &mut info)? < 136 {
        return Err(Error::other("a kernel that counts less of a connection"));
    }
    let word = |at: usize| u32::from_ne_bytes(info[at..at + 4].try_into().unwrap());
    let long = |at: usize| u64::from_ne_bytes(info[at..at + 8].try_into().unwrap());
    let mut unread: libc::c_int = 0;
    // SAFETY: FIONREAD writes one c_int, and `unread` is one, writable for the call.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::FIONREAD, &mut unread) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(TcpCounts {
        state: info[0],
        since_received: std::time::Duration::from_millis(word(52).into()),
        acked: long(120),
        received: long(128),
        unread: unread.max(0) as u64,
    })
}

/// Ask the kernel to look at what `socket` was sent and nobody has read, as when a byte
/// comes (SO_RCVLOWAT of one byte, which it is already): bytes that came before a program
/// was attached to it are then passed to that program.
pub fn look_again(socket: std::os::fd::BorrowedFd) -> Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: `one` is a c_int, readable for the call.
    let said = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVLOWAT,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if said < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
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

    /// What the kernel counts of a connection over the loopback: the bytes either way,
    /// and the end of them; and a cookie for each socket, its own.
    #[test]
    fn connections_are_counted() {
        use std::io::{Read, Write};
        use std::net::{Shutdown, TcpListener, TcpStream};
        use std::os::fd::AsFd;
        let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
            return;
        };
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut receiver, _) = listener.accept().unwrap();
        // (Acked and received, as the sender and the receiver count them; the state of each.)
        let (sending, receiving) = (sender.try_clone().unwrap(), receiver.try_clone().unwrap());
        let counts = || {
            let (sent, heard) = (
                tcp_counts(sending.as_fd()).unwrap(),
                tcp_counts(receiving.as_fd()).unwrap(),
            );
            (sent.acked, heard.received, sent.state, heard.state)
        };
        // The end that connected counts its start as acked; the one that accepted does not.
        assert_eq!(counts(), (1, 0, 1, 1));
        assert_eq!(tcp_counts(receiver.as_fd()).unwrap().acked, 0);
        sender.write_all(&[7; 1000]).unwrap();
        let mut waited = 0;
        while tcp_counts(receiver.as_fd()).unwrap().unread < 1000 && waited < 100 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            waited += 1;
        }
        assert_eq!(tcp_counts(receiver.as_fd()).unwrap().unread, 1000);
        let mut got = [0; 1000];
        receiver.read_exact(&mut got).unwrap();
        assert_eq!(tcp_counts(receiver.as_fd()).unwrap().unread, 0);
        let mut waited = 0;
        while counts().0 < 1001 && waited < 100 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            waited += 1;
        }
        assert_eq!(counts(), (1001, 1000, 1, 1));
        // An end is counted as one more byte, both ways; the receiver is in CLOSE_WAIT.
        sender.shutdown(Shutdown::Write).unwrap();
        assert_eq!(receiver.read(&mut got).unwrap(), 0);
        while counts().0 < 1002 && waited < 200 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            waited += 1;
        }
        assert_eq!(counts(), (1002, 1001, 5, 8));
        let cookie = |s: &TcpStream| socket_cookie(s.as_fd()).unwrap();
        assert_ne!(cookie(&sender), cookie(&receiver));
        assert_eq!(cookie(&sender), cookie(&sender));
    }

    /// Where the kernel lets this process make a socket map (as root): sockets in it, and
    /// the redirect program attached. Otherwise the refusal is an error.
    #[test]
    fn socket_maps_take_connections() {
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::AsFd;
        let Ok(map) = SocketMap::new(4) else {
            return;
        };
        let peers = SocketMap::new(4).unwrap();
        map.redirect_to(&peers).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let near = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (far, _) = listener.accept().unwrap();
        peers.insert(1, far.as_fd()).unwrap();
        map.insert(2, near.as_fd()).unwrap();
        look_again(near.as_fd()).unwrap();
        // (A listening socket is not a connection's.)
        assert!(map.remove(2).is_ok() && map.remove(2).is_err() && peers.remove(1).is_ok());
    }

    /// What is no ext4 file system is not grown, and says so (a loop device and a real
    /// grow are the VM test's to show: ci/vm.sh --test share).
    #[test]
    fn grow_refusals_are_errors() {
        assert!(grow(Path::new("/proc"), 1 << 20).is_err());
        assert!(grow(Path::new("/nowhere/at/all"), 1).is_err());
    }
}
