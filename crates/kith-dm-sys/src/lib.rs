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
    use std::os::fd::{FromRawFd, OwnedFd};
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
        for (start, end) in relro_ranges(headers.iter().map(|h| (h.p_type, h.p_vaddr as usize, h.p_memsz as usize)), page) {
            // SAFETY: the range is whole pages of this program's own mapping, which nothing
            // writes after the start files have run (that is what the linker's header says).
            let shut = unsafe { libc::mprotect((base + start) as *mut c_void, end - start, libc::PROT_READ) };
            // SAFETY: `data` is the `usize` passed to dl_iterate_phdr below.
            let total = unsafe { &mut *data.cast::<usize>() };
            *total = if shut == 0 { total.saturating_add(end - start) } else { usize::MAX };
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
            let (end, up) = (at + size, down(at + size + page - 1));
            // (The part's own PT_LOAD ends where it does or goes on past it: only what begins
            // or goes on inside the rest of the page counts.)
            let shared = headers
                .clone()
                .any(|(kind, from, len)| kind == PT_LOAD && from < up && from + len > end);
            let (start, end) = (down(at), if shared { down(end) } else { up });
            (start < end).then_some((start, end))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 0x1000;
    fn relro(at: usize, size: usize) -> (u32, usize, usize) {
        (PT_GNU_RELRO, at, size)
    }
    fn load(at: usize, size: usize) -> (u32, usize, usize) {
        (PT_LOAD, at, size)
    }

    #[test]
    fn relro_ends_on_a_page() {
        let headers = [load(0, 0x1000), load(0x1000, 0x3000), relro(0x1000, 0x2000), load(0x4000, 0x800)];
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
    fn no_relro_header_no_range() {
        let headers = [load(0, 0x1000), load(0x1000, 0x1000), (7, 0x1000, 0x100)];
        assert!(relro_ranges(headers.into_iter(), PAGE).is_empty());
    }

    /// A program that is not static has had it done by the loader, so this is a no-op or
    /// shuts what is already shut: either way it answers and the program goes on.
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
}
