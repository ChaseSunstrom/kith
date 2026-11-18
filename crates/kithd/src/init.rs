//! What kithd does when it is the machine's first process (kith OS, PLAN §4.1): it mounts
//! what a system needs, names the machine, and when it is done it restarts or powers off
//! the machine, since process 1 may never exit. Orphans are collected as on any machine
//! (`kith_runtime::reap_orphans`: kithd is a subreaper anyway).
//!
//! Told on the kernel command line: `kith.hostname=NAME`; `kith.ip=ADDRESS/BITS[,GATEWAY]`
//! and `kith.dns=ADDRESS` for a machine whose network gives no addresses (without them
//! every network card asks by DHCP); `kith.update=DISK` for an update to install from a
//! disk (see `os`); `kith.grow=off` for a state partition that stays as long as it is on a
//! longer disk (see `gpt`); and whatever follows ` -- `, which the kernel hands
//! to its first process as arguments: kithd's own, as in
//! `console=ttyS0 kith.hostname=alpha -- --listen 0.0.0.0:7443 --advertise 10.0.0.5:7443`.
//!
//! Ctrl-Alt-Del (the kernel turns it into SIGINT) restarts the machine, SIGTERM powers it
//! off, each after kithd has stopped what it runs. So does the power button (what a VPS
//! panel's shutdown presses): kithd reads it from the input devices.

use nix::mount::{MsFlags, mount};
use nix::sys::reboot::{RebootMode, reboot, set_cad_enabled};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};

/// Set when kithd was told to stop with SIGTERM: the machine is to power off, not restart.
pub static POWER_OFF: AtomicBool = AtomicBool::new(false);

/// Woken when the power button is pressed: to be waited for beside SIGTERM, which it is.
pub static BUTTON: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// The kernel's `EV_KEY` event type, and the code of the power button.
const EV_KEY: u16 = 1;
const KEY_POWER: u16 = 116;
/// One `input_event` as a 64-bit kernel writes it: two 8-byte time fields, then a u16 type,
/// a u16 code and an i32 value (1 is a press).
const EVENT: usize = 24;

/// Input events as a device gives them, in whatever pieces a read returns.
#[derive(Default)]
struct Events(Vec<u8>);

impl Events {
    /// Takes the next bytes; whether they complete a press of the power button.
    fn power_pressed(&mut self, bytes: &[u8]) -> bool {
        self.0.extend_from_slice(bytes);
        let whole = self.0.len() / EVENT * EVENT;
        let pressed = self.0.as_chunks::<EVENT>().0.iter().any(|event| {
            event[16..18] == EV_KEY.to_ne_bytes()
                && event[18..20] == KEY_POWER.to_ne_bytes()
                && event[20..24] == 1i32.to_ne_bytes()
        });
        self.0.drain(..whole);
        pressed
    }
}

/// Reads one input device until it goes away; a press of the power button is SIGTERM's.
fn listen(mut device: std::fs::File) {
    use std::io::{ErrorKind, Read};
    let (mut events, mut buf) = (Events::default(), [0u8; EVENT * 16]);
    loop {
        match device.read(&mut buf) {
            Ok(n) if n > 0 => {
                if events.power_pressed(&buf[..n]) {
                    eprintln!("kithd: init: the power button is pressed");
                    POWER_OFF.store(true, Ordering::Relaxed);
                    BUTTON.notify_one();
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            // (Nothing more, or the device is gone.)
            _ => return,
        }
    }
}

/// Listens on every input device there is, each in a thread of its own (a read of one
/// waits as long as it takes). Only as the first process; nothing else opens /dev/input.
//
// ponytail: the devices there at this moment. A button that appears later (hot-plug) is
// not heard: watch /dev/input with inotify when a machine needs that.
fn power_button() {
    let found = std::fs::read_dir("/dev/input").into_iter().flatten().flatten();
    for entry in found.filter(|entry| entry.file_name().as_encoded_bytes().starts_with(b"event")) {
        if let Ok(device) = std::fs::File::open(entry.path()) {
            std::thread::spawn(move || listen(device));
        }
    }
}

/// Where a node of kith OS keeps its state: the partition labelled `state` is mounted
/// here, and where there is none (a kernel and kithd alone, as ci/vm.sh boots them) it is
/// in memory.
pub const STATE: &str = "/var/lib/kith";

/// How long kithd has run when the slot it started from is marked good.
const GOOD: std::time::Duration = std::time::Duration::from_secs(10);

pub fn is_init() -> bool {
    FIRST.load(Ordering::Relaxed)
}

/// kithd is the machine's first: kept by process 1 (keeper.rs). Set once, at start.
pub static FIRST: AtomicBool = AtomicBool::new(false);

/// What the kernel command line says to kithd.
#[derive(Debug, Default, PartialEq)]
pub struct Options {
    pub hostname: Option<String>,
    /// The first network card's address, how many bits of it are the network's, the way out.
    pub ip: Option<(Ipv4Addr, u8, Option<Ipv4Addr>)>,
    pub dns: Option<IpAddr>,
    /// Which of kith OS's two slots this kernel's root is (the image says, not a person).
    pub slot: Option<char>,
    /// A disk under /dev with an update on it, for the other slot (see `os`).
    pub update: Option<String>,
    /// This is the installer (see `install`): the URL of its answers, or empty.
    pub install: Option<String>,
    /// `kith.grow=off`: the state partition stays as long as it is on a longer disk.
    pub keep: bool,
}

/// The address this machine was given: by its command line, or else the first its network
/// handed out. (kithd tells other nodes where it is, and a node that asks its network
/// does not know before.)
pub static ADDRESS: std::sync::OnceLock<Ipv4Addr> = std::sync::OnceLock::new();

/// What a node's `config` partition says (the installer wrote it): more of the kernel
/// command line, as its `kith.` words and kithd's own arguments. Of the first only a
/// name and addresses: which slot runs, and whether to install, is the image's to say.
pub fn configured(text: &str) -> (String, Vec<String>) {
    let text = text.split(['\0', '\n']).next().unwrap_or_default();
    // (` -- ` as a word of its own: a name may end in dashes.)
    let text = format!(" {text} ");
    let (kernel, arguments) = text.split_once(" -- ").unwrap_or((&text, ""));
    let ours = |word: &&str| {
        ["kith.hostname=", "kith.ip=", "kith.dns="]
            .iter()
            .any(|key| word.starts_with(key))
    };
    let kernel: Vec<&str> = kernel.split_whitespace().filter(ours).collect();
    (
        kernel.join(" "),
        arguments.split_whitespace().map(str::to_string).collect(),
    )
}

/// The config partition's words for kithd, with each `--release-key` that the signed system
/// does not hold taken out, and what to say of each. `image`: the keys in
/// /etc/kith/release-keys (none: the config may name any), or `None` when that file could
/// not be read (then no config key is taken). The partition is measured by no firmware
/// unless the state is sealed: anyone with the disk can write it, and a key it names would
/// be whose releases, root and all, the node takes.
fn vetted(args: Vec<String>, image: Option<&[String]>) -> (Vec<String>, Vec<String>) {
    let (mut kept, mut said) = (Vec::new(), Vec::new());
    let mut words = args.into_iter();
    while let Some(word) = words.next() {
        let keys = match word.strip_prefix("--release-key") {
            Some("") => words.next().unwrap_or_default(),
            Some(given) if given.starts_with('=') => given[1..].to_string(),
            _ => {
                kept.push(word);
                continue;
            }
        };
        let held: Vec<&str> = keys.split(',').map(str::trim).filter(|key| !key.is_empty()).collect();
        let held: Vec<&str> = match image {
            Some([]) => held,
            Some(image) => held
                .into_iter()
                .filter(|key| {
                    let ours = image.iter().any(|mine| mine == key);
                    if !ours {
                        said.push(format!(
                            "kithd: init: the config partition's --release-key {key} is not one of this system's (/etc/kith/release-keys): it is not taken; a new key comes by a release's handover or a new image"
                        ));
                    }
                    ours
                })
                .collect(),
            None => {
                said.push(
                    "kithd: init: this system's release keys (/etc/kith/release-keys) could not be read: the config partition's --release-key is not taken".to_string(),
                );
                Vec::new()
            }
        };
        if !held.is_empty() {
            kept.extend(["--release-key".to_string(), held.join(",")]);
        }
    }
    (kept, said)
}

/// The slaves of dm-0, the verity device the root is: the one this system runs from.
const ROOT_SLAVES: &str = "/sys/block/dm-0/slaves";

/// The entries of `dir`, sorted; none if it is not there.
fn sorted(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut all: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    all.sort();
    all
}

/// The slave of dm-0 that the root is on: the first by name, so the same one every time. `booted`
/// and `labelled` both take it here.
fn root_slave(slaves: &std::path::Path) -> Option<std::path::PathBuf> {
    sorted(slaves).into_iter().next()
}

/// The disk this system runs from (`vda`), where its root is a verity device.
pub fn booted() -> Option<String> {
    let under = root_slave(std::path::Path::new(ROOT_SLAVES))?;
    disk(&under)?.into_string().ok()
}

fn static_ip(value: &str) -> Option<(Ipv4Addr, u8, Option<Ipv4Addr>)> {
    let (address, gateway) = match value.split_once(',') {
        Some((address, gateway)) => (address, Some(gateway.parse().ok()?)),
        None => (value, None),
    };
    let (address, bits) = address.split_once('/')?;
    let bits = bits.parse().ok().filter(|bits| *bits <= 32)?;
    Some((address.parse().ok()?, bits, gateway))
}

/// kithd's own arguments among those the kernel hands its first process: it also hands on
/// every bare word it did not know itself (`splash`), ahead of what followed ` -- `.
pub fn arguments(given: impl Iterator<Item = String>) -> Vec<String> {
    let mut given = given.peekable();
    let me = given.next().unwrap_or_default();
    while given.peek().is_some_and(|word| !word.starts_with('-')) {
        given.next();
    }
    std::iter::once(me).chain(given).collect()
}

/// Read `kith.*` from a kernel command line; what is not understood is returned to be said,
/// not fatal: a machine that will not start over a misspelt option helps nobody.
pub fn options(line: &str) -> (Options, Vec<String>) {
    let (mut options, mut unknown) = (Options::default(), Vec::new());
    // (After ` -- ` come the first process's arguments, which are clap's to read.)
    let kernel = line.split(" -- ").next().unwrap_or_default();
    for word in kernel.split_whitespace().filter(|word| word.starts_with("kith.")) {
        if word == "kith.install" {
            options.install.get_or_insert_default();
            continue;
        }
        let name = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
        match word.split_once('=') {
            // A hostname is a DNS label, as a Node's name is.
            Some(("kith.hostname", value)) if !value.is_empty() && value.len() <= 63 && value.chars().all(name) => {
                options.hostname = Some(value.into());
            }
            Some(("kith.ip", value)) if static_ip(value).is_some() => options.ip = static_ip(value),
            Some(("kith.dns", value)) if value.parse::<IpAddr>().is_ok() => options.dns = value.parse().ok(),
            // (The first one: the image's own, which what is typed at a boot menu follows.)
            Some(("kith.slot", "a")) => drop(options.slot.get_or_insert('a')),
            Some(("kith.slot", "b")) => drop(options.slot.get_or_insert('b')),
            // (A name in /dev, not a path out of it.)
            Some(("kith.update", value)) if !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric()) => {
                options.update = Some(value.into());
            }
            Some(("kith.grow", "off")) => options.keep = true,
            Some(("kith.install", url)) if url.starts_with("http://") || url.starts_with("https://") => {
                options.install = Some(url.into());
            }
            _ => unknown.push(word.into()),
        }
    }
    (options, unknown)
}

/// The machine's name when it is told none: the same at every start, from the address of
/// its first network card (`mac`, as /sys/class/net/*/address has it).
pub fn name_from(mac: Option<&str>) -> String {
    let digits: String = mac
        .unwrap_or_default()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect();
    match digits.len() {
        12 if digits != "000000000000" => format!("kith-{}", digits[6..].to_ascii_lowercase()),
        _ => "kith".into(),
    }
}

fn first_mac() -> Option<String> {
    let mut cards: Vec<_> = std::fs::read_dir("/sys/class/net").ok()?.flatten().collect();
    cards.sort_by_key(std::fs::DirEntry::file_name);
    let wired = |card: &std::fs::DirEntry| {
        // (1: Ethernet. The loopback is 772.)
        let kind = std::fs::read_to_string(card.path().join("type")).ok()?;
        (kind.trim() == "1").then(|| std::fs::read_to_string(card.path().join("address")).ok())?
    };
    cards.iter().find_map(wired)
}

fn resolvers(servers: &[IpAddr]) {
    let lines: String = servers.iter().map(|server| format!("nameserver {server}\n")).collect();
    // (The image's root is read-only: its /etc/resolv.conf points here. Where the root
    // can be written and has none, it is pointed here now.)
    let _ = std::fs::create_dir_all("/etc").and_then(|()| {
        // (A file already there, on a root that can be written, would win over it.)
        let _ = std::fs::remove_file("/etc/resolv.conf");
        std::os::unix::fs::symlink("/run/resolv.conf", "/etc/resolv.conf")
    });
    // (Written whole: kithd reads it again while it runs, and half a file is other resolvers.)
    let whole = std::fs::write("/run/resolv.conf.new", lines)
        .and_then(|()| std::fs::rename("/run/resolv.conf.new", "/run/resolv.conf"));
    if let Err(e) = whole {
        eprintln!("kithd: init: writing /run/resolv.conf: {e}");
    }
}

/// The device of the partition a GPT names `label`, from what /sys says of one block
/// device (its `uevent`).
fn partition<'a>(uevent: &'a str, label: &str) -> Option<&'a str> {
    let said = |key: &str| uevent.lines().find_map(|line| line.strip_prefix(key));
    (said("PARTNAME=") == Some(label)).then(|| said("DEVNAME="))?
}

/// The disk a partition is on: `vda` for `/sys/class/block/vda6`.
fn disk(partition: &std::path::Path) -> Option<std::ffi::OsString> {
    Some(std::fs::canonicalize(partition).ok()?.parent()?.file_name()?.to_owned())
}

/// The device of the partition named `label`. Where the root is a verity device, only
/// a partition of the disk the root is on will do: a stick with a partition named `state`
/// must not become the node's store, nor one named `root-b` its next system.
pub(crate) fn labelled(label: &str) -> Option<std::path::PathBuf> {
    let slaves = std::path::Path::new(ROOT_SLAVES);
    let verity = slaves.parent().is_some_and(std::path::Path::exists);
    let ours = root_slave(slaves).and_then(|under| disk(&under));
    sorted(std::path::Path::new("/sys/class/block"))
        .into_iter()
        .find_map(|device| {
            let uevent = std::fs::read_to_string(device.join("uevent")).ok()?;
            let name = partition(&uevent, label)?;
            on_ours(verity, ours.as_deref(), disk(&device).as_deref()).then(|| std::path::Path::new("/dev").join(name))
        })
}

/// Whether a partition on `disk` may be taken: any, where there is no verity root (the
/// installer from its stick, a development start); where there is one, only one on the disk
/// it is read from, and none when that disk cannot be read (it fails closed).
fn on_ours(verity: bool, ours: Option<&std::ffi::OsStr>, disk: Option<&std::ffi::OsStr>) -> bool {
    match (verity, ours) {
        (false, _) => true,
        (true, None) => false,
        (true, Some(ours)) => disk == Some(ours),
    }
}

/// The firmware's variables, and the one systemd-boot sets to the partition GUID of the ESP it
/// started kith from.
const EFIVARS: &str = "/sys/firmware/efi/efivars";
const LOADER: &str = "LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
/// The most a firmware variable is read as: this one is 78 bytes.
const VARIABLE_MAX: u64 = 1024;

/// The bytes of the firmware variable `name` in `dir`, or `None` when there is no such one.
fn variable(dir: &std::path::Path, name: &str) -> Result<Option<Vec<u8>>, String> {
    use std::io::Read;
    let file = match std::fs::File::open(dir.join(name)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("reading {name}: {e}")),
    };
    let mut bytes = Vec::new();
    file.take(VARIABLE_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("reading {name}: {e}"))?;
    if bytes.len() as u64 > VARIABLE_MAX {
        return Err(format!("{name} is longer than a firmware variable is"));
    }
    Ok(Some(bytes))
}

/// The GUID a firmware variable's bytes hold: four attribute bytes, then its text as UTF-16LE
/// with a NUL after it. Lower case, as a GPT writes one.
fn partuuid(bytes: &[u8]) -> Result<String, String> {
    let text = bytes.get(4..).ok_or("the firmware's boot partition is not written")?;
    if text.len() % 2 != 0 {
        return Err("the firmware's boot partition is not UTF-16".into());
    }
    let units: Vec<u16> = text
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let text = String::from_utf16(&units).map_err(|_| "the firmware's boot partition is not UTF-16")?;
    let text = text.trim_end_matches('\0').to_ascii_lowercase();
    let shaped = text.len() == 36
        && text.char_indices().all(|(at, c)| match at {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    if !shaped {
        return Err("the firmware's boot partition is not a partition's GUID".into());
    }
    Ok(text)
}

/// Whether the partition the firmware's variable names is one of `guids`, the unique GUIDs of
/// a disk's partitions.
fn holds_boot_partition(variable: &[u8], guids: &[String]) -> Result<bool, String> {
    Ok(guids.contains(&partuuid(variable)?))
}

/// Refuses a root whose disk is not the one the firmware started kith from. Where the root is
/// a verity device, a stick with a copy of the public root and verity partitions, and its own
/// config and state, would boot as the node. systemd-boot sets the variable to its ESP's GUID,
/// and the root's disk must hold a partition of that GUID. With no variable (a kernel started
/// without systemd-boot) the disk goes on unchecked, and that is said. No verity root, nothing
/// to check.
fn check_boot_disk() -> Result<(), String> {
    let Some(disk) = booted() else { return Ok(()) };
    let dir = std::path::Path::new(EFIVARS);
    let efi = std::path::Path::new("/sys/firmware/efi");
    if efi.is_dir() && std::fs::read_dir(dir).map_or(true, |mut all| all.next().is_none()) {
        let quiet = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
        match mount(Some("efivarfs"), EFIVARS, Some("efivarfs"), quiet, None::<&str>) {
            // (Already there: as in `early`.)
            Ok(()) | Err(nix::errno::Errno::EBUSY) => {}
            Err(e) => return Err(format!("mounting the firmware's variables: {e}")),
        }
    }
    let Some(bytes) = variable(dir, LOADER)? else {
        eprintln!("kithd: init: the firmware names no boot partition, so the disk {disk} is not checked against one");
        return Ok(());
    };
    let sectors = std::fs::read_to_string(format!("/sys/block/{disk}/size"))
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .ok_or_else(|| format!("the size of {disk} is not known"))?;
    let opened =
        std::fs::File::open(std::path::Path::new("/dev").join(&disk)).map_err(|e| format!("opening {disk}: {e}"))?;
    let guids = crate::gpt::guids(&opened, sectors).map_err(|e| format!("{disk}: {e}"))?;
    if holds_boot_partition(&bytes, &guids)? {
        Ok(())
    } else {
        Err(format!(
            "the firmware started kith from a partition that {disk} does not hold: its root is not this machine's"
        ))
    }
}

/// Where the disk this node runs from goes on past its state partition, make the partition
/// end where the disk does (see `gpt`): the image's is 32 MB, whatever it was written to.
/// Before the state is mounted or opened; `mount_state` grows the file system to it.
fn widen() {
    let Some(device) = labelled("state") else { return };
    let Some(disk) = disk(&std::path::Path::new("/sys/class/block").join(device.file_name().unwrap_or_default()))
    else {
        return;
    };
    let said = |what: &str| {
        let text = std::fs::read_to_string(std::path::Path::new("/sys/block").join(&disk).join(what));
        text.ok().and_then(|text| text.trim().parse::<u64>().ok())
    };
    // (A partition table counts in sectors of 512 bytes: a disk that counts otherwise is left.)
    let (Some(512), Some(sectors)) = (said("queue/logical_block_size"), said("size")) else {
        return;
    };
    let opened = std::fs::File::options()
        .read(true)
        .write(true)
        .open(std::path::Path::new("/dev").join(&disk));
    let widened = opened.map_err(|e| e.to_string()).and_then(|disk| {
        let Some(now) = crate::gpt::widen(&disk, sectors, "state")? else {
            return Ok(None);
        };
        // (Refused, the kernel reads the table at the next start, and the state grows then.)
        kith_dm_sys::resize_partition(&disk, now.number, now.start * 512, now.sectors * 512)
            .map_err(|e| format!("its table is written, and the kernel will not take it before the next start: {e}"))?;
        Ok(Some(now.sectors / 2048))
    });
    match widened {
        Ok(Some(size)) => eprintln!("kithd: init: the state partition now ends where its disk does: {size} MB"),
        Ok(None) => {}
        Err(e) => eprintln!("kithd: init: the state partition stays as long as it is: {e}"),
    }
}

/// How many blocks the ext4 file system with this superblock has, and how long one is.
fn ext4_blocks(superblock: &[u8]) -> Option<(u64, u64)> {
    let word = |at: usize| {
        superblock
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    if superblock.get(0x38..0x3A) != Some(&[0x53, 0xEF]) {
        return None;
    }
    // (The upper half counts only where the file system says it has one: 64bit.)
    let upper = if word(0x60)? & 0x80 != 0 { word(0x150)? } else { 0 };
    // (A block is 1 to 64 KiB.)
    let block = 1024u64 << word(0x18).filter(|shift| *shift <= 6)?;
    Some((u64::from(upper) << 32 | u64::from(word(4)?), block))
}

/// Grow the state's file system to the device it is on, where it is smaller: what to say
/// of it. (Not asked of the kernel otherwise: it says a line on the console each time, in
/// the middle of whatever this is saying.)
fn grow(device: &std::path::Path) -> Option<String> {
    use std::os::unix::fs::FileExt;
    // (`kith.grow=off` is for this too: a partition made longer at an earlier start.)
    if std::fs::read_to_string("/proc/cmdline").is_ok_and(|line| options(&line).0.keep) {
        return None;
    }
    let file = std::fs::File::open(device).ok()?;
    let read = || {
        let mut superblock = [0; 1024];
        file.read_exact_at(&mut superblock, 1024).ok()?;
        ext4_blocks(&superblock)
    };
    let (before, block) = read()?;
    let fits = std::io::Seek::seek(&mut &file, std::io::SeekFrom::End(0)).ok()? / block;
    if fits <= before {
        return None;
    }
    match kith_dm_sys::grow(std::path::Path::new(STATE), fits) {
        // (Blocks too few for another group of them are left: nothing grew, nothing is said.)
        Ok(()) => read().filter(|(now, _)| *now > before).map(|(now, _)| {
            format!(
                "kithd: init: the state's file system grown to {} MB",
                (now * block) >> 20
            )
        }),
        Err(e) => Some(format!(
            "kithd: init: the state's file system is not as big as its partition: {e}"
        )),
    }
}

/// Mount the state partition, or say that there is none and keep the state in memory.
fn state() {
    let found = labelled("state");
    let Some(device) = found else {
        let _ = std::fs::create_dir_all(STATE);
        let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
        eprintln!(
            "kithd: init: no partition is labelled state: this node's state is in memory, and gone when it restarts"
        );
        if let Err(e) = mount(Some("tmpfs"), STATE, Some("tmpfs"), flags, Some("mode=0700")) {
            eprintln!("kithd: init: mounting {STATE}: {e}");
        }
        return;
    };
    mount_state(&device)
}

/// Mount the state's file system from `device`: the partition, or what it is under its key.
pub fn mount_state(device: &std::path::Path) {
    let _ = std::fs::create_dir_all(STATE);
    let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOATIME;
    // Holding each project to its limit, where the file system keeps projects (made since
    // kith OS does); one from before, which keeps none, mounts as it did, its pods counted.
    let mounted = mount(Some(device), STATE, Some("ext4"), flags, Some("prjquota"))
        .or_else(|_| mount(Some(device), STATE, Some("ext4"), flags, None::<&str>));
    match mounted {
        Ok(()) => {
            // (The kernel's own lines about growing first, then this one whole.)
            let grown = grow(device);
            eprintln!("kithd: init: state on {}", device.display());
            if let Some(grown) = grown {
                eprintln!("{grown}");
            }
        }
        // (Not in memory instead: the node would come up as a new one, with nothing.)
        Err(e) => {
            eprintln!(
                "kithd: init: mounting {}: {e}: the state partition is damaged",
                device.display()
            );
            end(true)
        }
    }
}

/// What is left to do once kithd's runtime runs: the cards that ask their network for an
/// address.
#[derive(Default)]
pub struct Boot {
    name: String,
    asking: Vec<kith_mesh::Card>,
    dns: Option<IpAddr>,
    slot: Option<char>,
    /// kithd's arguments from the node's config partition: ahead of the command line's.
    pub args: Vec<String>,
    /// Set in the installer: the URL of its answers, or empty.
    pub install: Option<String>,
    /// The node's state is encrypted and not mounted yet (see crypt.rs): its lock record,
    /// and the config partition that holds it.
    pub sealed: Option<(crate::crypt::Record, std::path::PathBuf)>,
}

/// Told once this node has its state to use: at once where it is not encrypted, and where
/// it is, when it has been opened (crypt.rs), however long the key takes to come.
pub static STATE_OPEN: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Wait for `open`, then `wait` more. A system that cannot open the node's state is not a
/// good one: marked good while it waited for a key, the boot loader would never go back to
/// the one that could (T-0572).
async fn state_then(open: &tokio::sync::Notify, wait: std::time::Duration) {
    open.notified().await;
    tokio::time::sleep(wait).await;
}

impl Boot {
    /// Ask for as long as kithd runs (it serves meanwhile). Call inside the runtime.
    pub fn network(self) {
        power_button();
        for card in self.asking {
            // (A name server on the command line is one the network's own may not replace.)
            let told = self.dns;
            let got = move |lease: &crate::dhcp::Lease| {
                let _ = ADDRESS.set(lease.address);
                match told {
                    Some(server) => resolvers(&[server]),
                    None => resolvers(&lease.dns.iter().copied().map(IpAddr::from).collect::<Vec<_>>()),
                }
            };
            tokio::spawn(crate::dhcp::keep(card, self.name.clone(), got));
        }
        let Some(slot) = self.slot else { return };
        // ponytail: good means kithd started, has its state to use, and is still running a
        // little later (one that cannot start ends, and the machine restarts, well within
        // that). Whether the node is healthy in its cluster is the update plan's to judge
        // (T-0073).
        tokio::spawn(async move {
            state_then(&STATE_OPEN, GOOD).await;
            let said = tokio::task::spawn_blocking(move || crate::os::esp(|esp| crate::os::settle(slot, esp)));
            match said.await {
                Ok(Ok(said)) => said.iter().for_each(|line| eprintln!("kithd: init: {line}")),
                Ok(Err(e)) => eprintln!("kithd: init: slot {slot} is not marked good: {e}"),
                Err(e) => eprintln!("kithd: init: slot {slot} is not marked good: {e}"),
            }
        });
    }
}

/// Links up, and the address the command line gives the first card. The cards returned
/// are left to ask their networks: all of them, or with such an address all but the first.
//
// ponytail: the cards there at this moment. One plugged in later, or whose driver loads
// later, stays down: watch the kernel's link messages when a machine needs that.
fn links(options: &Options) -> Vec<kith_mesh::Card> {
    let (cards, loopback) = match kith_mesh::cards() {
        Ok(found) => found,
        Err(e) => {
            eprintln!("kithd: init: listing the network cards: {e}");
            return Vec::new();
        }
    };
    let named = cards.iter().map(|card| (card.index, &*card.name));
    for (index, what) in loopback.iter().map(|lo| (*lo, "lo")).chain(named) {
        if let Err(e) = kith_mesh::up(index) {
            eprintln!("kithd: init: bringing {what} up: {e}");
        }
    }
    if let (Some((address, bits, gateway)), Some(card)) = (options.ip, cards.first()) {
        match kith_mesh::address4(card.index, address, bits, gateway) {
            Ok(()) => {
                let _ = ADDRESS.set(address);
                eprintln!("kithd: init: {} has {address}/{bits}", card.name);
            }
            Err(e) => eprintln!("kithd: init: giving {} {address}/{bits}: {e}", card.name),
        }
        resolvers(&options.dns.into_iter().collect::<Vec<_>>());
        // (The other cards still ask their networks: a second network is not the first's.)
        return cards.into_iter().skip(1).collect();
    }
    cards
}

/// What kithd says goes to every console the kernel has (a screen and a serial line, say),
/// not to the last one named alone, which is all a first process is given.
fn consoles() {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    let active = std::fs::read_to_string("/sys/class/tty/console/active").unwrap_or_default();
    let open = |name: &str| {
        std::fs::OpenOptions::new()
            .write(true)
            .open(format!("/dev/{name}"))
            .ok()
    };
    let mut all: Vec<std::fs::File> = active.split_whitespace().filter_map(open).collect();
    // (Closed in what kithd starts: a workload must not read what kithd says.)
    let Ok((read, write)) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC) else {
        return;
    };
    if all.len() < 2 || nix::unistd::dup2(write.as_raw_fd(), 2).is_err() {
        return;
    }
    let _ = nix::unistd::dup2(write.as_raw_fd(), 1);
    // (A thread that only reads and writes: it holds nothing a forked child could want.)
    std::thread::spawn(move || {
        let (mut from, mut some) = (std::fs::File::from(read), [0; 4096]);
        while let Ok(read @ 1..) = from.read(&mut some) {
            for console in &mut all {
                let _ = console.write_all(&some[..read]);
            }
        }
    });
}

/// Whether something is mounted at `path`: it is on another device than its parent.
fn mounted(path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let path = std::path::Path::new(path);
    let dev = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.dev());
    matches!((dev(path), path.parent().map(dev)), (Ok(a), Some(Ok(b))) if a != b)
}

/// What the first process mounts: (kind, where, flags, options). Nothing runs a program
/// from /dev/shm, /run or /tmp (a container's image and volumes under /run are mounts of
/// their own, with their own flags), so none may.
fn mounts() -> [(&'static str, &'static str, MsFlags, &'static str); 8] {
    let quiet = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    [
        ("proc", "/proc", quiet, ""),
        ("sysfs", "/sys", quiet, ""),
        ("devtmpfs", "/dev", MsFlags::MS_NOSUID, "mode=0755"),
        (
            "devpts",
            "/dev/pts",
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            "gid=5,mode=620,ptmxmode=666",
        ),
        ("tmpfs", "/dev/shm", quiet, "mode=1777"),
        ("tmpfs", "/run", quiet, "mode=0755"),
        ("tmpfs", "/tmp", quiet, "mode=1777"),
        ("cgroup2", "/sys/fs/cgroup", quiet, ""),
    ]
}

/// The first things, before anything else of kithd runs. Each is tried and said if it
/// fails: with part of them kithd may still serve, and a console line says what is missing.
/// What process 1 does before it starts kithd (keeper.rs): the file systems every process
/// needs, and the consoles made one.
pub fn first_things() {
    // Ctrl-Alt-Del comes to process 1 as SIGINT instead of restarting the machine at once.
    let _ = set_cad_enabled(false);
    for (kind, at, flags, data) in mounts() {
        let made = std::fs::create_dir_all(at).map_err(|e| e.to_string());
        let mounted = made.and_then(|()| {
            match mount(
                Some(kind),
                at,
                Some(kind),
                flags,
                Some(data).filter(|data| !data.is_empty()),
            ) {
                // (Already there: the kernel may have mounted /dev itself.)
                Ok(()) | Err(nix::errno::Errno::EBUSY) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        });
        if let Err(e) = mounted {
            eprintln!("kithd: init: mounting {at}: {e}");
        }
    }
    consoles();
}

/// kithd as the machine's first (under the keeper): what it learns of the machine, and, on
/// the machine's first start of it (`again` false), what it does to it once. Started again
/// (`again`), it reads the command line and the config as before and changes nothing: the
/// state is mounted, the TPM measured, the disk grown already.
pub fn early(again: bool) -> Boot {
    // Drivers first (a started-again kithd finds them loaded, and only listens again).
    crate::modules::start();
    // (Before anything is read from the root's disk: see `check_boot_disk`.)
    if !again && let Err(e) = check_boot_disk() {
        eprintln!("kithd: init: {e}");
        end(true);
    }
    let line = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let installing = options(&line).0.install.is_some();
    // What the installer was told of this node, from the disk the node runs from. (The
    // installer itself has none, and keeps nothing: its state is in memory.)
    let told = labelled("config").filter(|_| !installing).and_then(|device| {
        use std::io::Read;
        let mut text = Vec::new();
        let read = std::fs::File::open(device).ok()?.take(64 << 10).read_to_end(&mut text);
        read.ok().map(|_| text)
    });
    let config = told.as_ref().map(|text| configured(&String::from_utf8_lossy(text)));
    let (config, args) = config.unwrap_or_default();
    let image = crate::update::keys_in(std::path::Path::new("/etc/kith/release-keys"));
    let (args, said) = vetted(args, image.as_deref().ok());
    for line in said {
        eprintln!("{line}");
    }
    // (An encrypted state waits for its key, and that for the network: see `main`.)
    // (Started again: an encrypted state was opened by the kithd before, and is mounted.)
    let sealed = labelled("config").filter(|_| !installing && !(again && mounted(STATE)));
    let sealed = sealed.and_then(|device| match crate::crypt::Record::read(&device) {
        Ok(record) => Some((record?, device)),
        Err(e) => {
            eprintln!("kithd: init: {e}");
            // (An erased record stays erased: a restart would only find it again.)
            let erased = e == crate::crypt::ERASED;
            POWER_OFF.store(erased, Ordering::Relaxed);
            end(!erased)
        }
    });
    // What the config says is obeyed below and measured by no firmware: it goes into the
    // TPM before the TPM is asked for the state's key (tpm.rs).
    if let (Some(told), Some(_), false) = (&told, &sealed, again) {
        crate::tpm::measure(told);
    }
    if !installing && !again && !options(&line).0.keep {
        widen();
    }
    if !installing && !again && sealed.is_none() {
        state();
    }
    // (The command line after the config: what is typed at a boot menu is the last word.)
    let (options, unknown) = options(&format!("{config} {}", line.split(" -- ").next().unwrap_or_default()));
    for word in unknown {
        eprintln!("kithd: init: `{word}` on the kernel command line is not understood");
    }
    let name = options
        .hostname
        .clone()
        .unwrap_or_else(|| name_from(first_mac().as_deref()));
    if let Err(e) = nix::unistd::sethostname(&name) {
        eprintln!("kithd: init: naming the machine {name}: {e}");
    }
    // A panic ends kithd, wherever it is: the keeper starts it again, and what runs goes on.
    std::panic::set_hook(Box::new(|info| {
        eprintln!("kithd: {info}");
        std::process::abort();
    }));
    if let (Some(slot), Some(device), false) = (options.slot, &options.update, again) {
        match crate::os::update(device, slot, &line) {
            Ok(Some(version)) => {
                eprintln!("kithd: init: kith OS {version} from {device} is in the other slot: starting it");
                end(false)
            }
            Ok(None) => eprintln!("kithd: init: the update on {device} is what runs here already"),
            Err(e) => eprintln!("kithd: init: no update from {device}: {e}"),
        }
    }
    eprintln!("kithd: init: {name} is up");
    Boot {
        asking: links(&options),
        dns: options.dns,
        slot: options.slot.filter(|_| !installing),
        name,
        args,
        install: options.install,
        sealed,
    }
}

/// Is a failed start of the machine this kernel command line started counted? One from a
/// slot is: that is what gets marked good, which clears the count. An installer, or a
/// kernel and kithd alone, never would be.
fn counted(line: &str) -> bool {
    let options = options(line).0;
    options.slot.is_some() && options.install.is_none()
}

/// What this kithd holds in memory, in kB as the kernel counts it: all of it, and the part
/// that is files (its own program, mostly; a file of a memory disk is counted as shared
/// memory, so that is added). Said on the console when the machine's first process is told
/// to stop, so the number of a real node is there to read.
pub fn resident() -> Option<(u64, u64)> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb = |name: &str| {
        let line = status.lines().find_map(|line| line.strip_prefix(name))?;
        line.split_whitespace().next()?.parse().ok()
    };
    Some((kb("VmRSS:")?, kb("RssFile:")? + kb("RssShmem:")?))
}

/// kithd is done (it has stopped what it ran): restart the machine or power it off.
/// After a failure it restarts, once the reason has had time to be read on a console. A
/// start that fails again waits longer, the count being on the ESP (see `os::wait`).
pub fn end(failed: bool) -> ! {
    if failed {
        // (With no ESP to count on, this is the first wait.)
        let counted = std::fs::read_to_string("/proc/cmdline").is_ok_and(|line| counted(&line));
        let wait = match counted.then(|| crate::os::esp(crate::os::failed)) {
            Some(Ok(count)) => crate::os::wait(count),
            Some(Err(e)) => {
                eprintln!("kithd: init: counting the failed start: {e}");
                crate::os::wait(0)
            }
            None => crate::os::wait(0),
        };
        eprintln!("kithd: init: restarting in {} s", wait.as_secs());
        // The power button is still heard (its thread outlives the runtime): it ends the
        // wait, and the machine powers off.
        // ponytail: SIGTERM is not, with the runtime that listened for it gone.
        for _ in 0..wait.as_secs() {
            if POWER_OFF.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    let off = POWER_OFF.load(Ordering::Relaxed);
    eprintln!("kithd: init: {}", if off { "powering off" } else { "restarting" });
    // ponytail: time for that line to reach the consoles (see `consoles`), not a handshake.
    std::thread::sleep(std::time::Duration::from_millis(200));
    // Written out, then let go of: by now kithd has closed what it had open there. (If
    // not, as after a panic, the file system's journal is what keeps it whole.)
    nix::unistd::sync();
    // (What is mounted from a file of the state, first.)
    crate::encrypted::close(std::path::Path::new(STATE));
    // (EINVAL: nothing is mounted there, as in the installer.)
    if let Err(e) = nix::mount::umount(STATE).or_else(|e| if e == nix::errno::Errno::EINVAL { Ok(()) } else { Err(e) })
    {
        eprintln!("kithd: init: unmounting {STATE}: {e}");
    }
    let mode = if off {
        RebootMode::RB_POWER_OFF
    } else {
        RebootMode::RB_AUTOBOOT
    };
    let e = reboot(mode).unwrap_err();
    eprintln!("kithd: init: {e}");
    // Process 1 of a container, not of a machine: there, ending is how to stop or be
    // started again. On a machine the kernel does not refuse its first process this.
    if e == nix::errno::Errno::EPERM {
        std::process::exit(i32::from(failed));
    }
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn a_config_release_key_that_the_system_does_not_hold_is_dropped() {
        let image = ["A".to_string()];
        for (config, kept) in [
            (
                "--listen 0.0.0.0:7443 --release-key B --claim t",
                "--listen 0.0.0.0:7443 --claim t",
            ),
            ("--release-key=B --claim t", "--claim t"),
            ("--release-key A,B", "--release-key A"),
            ("--release-key=B,A --listen x", "--release-key A --listen x"),
        ] {
            let (args, said) = vetted(words(config), Some(&image));
            assert_eq!(args, words(kept), "{config}");
            assert_eq!(said.len(), 1, "{config}: {said:?}");
            assert!(
                said[0].contains("--release-key B is not one of this system's"),
                "{said:?}"
            );
        }
        // A file of keys that could not be read: no key of the config is taken.
        let (args, said) = vetted(words("--release-key A --claim t"), None);
        assert_eq!(args, words("--claim t"));
        assert!(said[0].contains("could not be read"), "{said:?}");
    }

    #[test]
    fn a_config_release_key_stays_when_the_system_holds_none_or_the_same() {
        let config = words("--claim t --release-key A,B --listen x");
        assert_eq!(vetted(config.clone(), Some(&[])), (config.clone(), Vec::new()));
        let both = ["B".to_string(), "A".to_string()];
        assert_eq!(vetted(config.clone(), Some(&both)), (config, Vec::new()));
        let none = words("--claim t --listen x");
        assert_eq!(vetted(none.clone(), None), (none, Vec::new()));
    }

    /// A slot on trial is good only once the node has its state: however long it waits
    /// for a key, the wait before it is marked good has not begun.
    #[tokio::test]
    async fn slot_is_good_only_after_the_state_is_open() {
        let open = std::sync::Arc::new(tokio::sync::Notify::new());
        let wait = std::time::Duration::from_millis(20);
        let waiting = tokio::spawn({
            let open = open.clone();
            async move { state_then(&open, wait).await }
        });
        tokio::time::sleep(wait * 5).await;
        assert!(!waiting.is_finished(), "good before the state is open");
        open.notify_one();
        tokio::time::timeout(wait * 50, waiting).await.unwrap().unwrap();
        // (Opened before anything waits, as on a node whose state is not encrypted: the same.)
        open.notify_one();
        tokio::time::timeout(wait * 50, state_then(&open, wait)).await.unwrap();
    }

    #[test]
    fn init_counts_a_file_systems_blocks() {
        let mut superblock = vec![0u8; 1024];
        assert_eq!(ext4_blocks(&superblock), None);
        superblock[0x38..0x3A].copy_from_slice(&[0x53, 0xEF]);
        superblock[4..8].copy_from_slice(&8192u32.to_le_bytes());
        superblock[0x18] = 2;
        superblock[0x150] = 1;
        assert_eq!(ext4_blocks(&superblock), Some((8192, 4096)));
        superblock[0x60] = 0x80;
        assert_eq!(ext4_blocks(&superblock), Some(((1 << 32) + 8192, 4096)));
        superblock[0x18] = 60;
        assert_eq!(
            (ext4_blocks(&superblock), ext4_blocks(&superblock[..100])),
            (None, None)
        );
    }

    /// With a verity root whose disk cannot be read, no partition is taken (a stick's `state`
    /// would have been); with no verity root, any is, as the installer's stick needs.
    #[test]
    fn labelled_refuses_every_disk_when_dm0_exists_with_no_slave_but_not_when_it_is_absent() {
        let (vda, sdb) = (Some(std::ffi::OsStr::new("vda")), Some(std::ffi::OsStr::new("sdb")));
        assert!(!on_ours(true, None, vda) && !on_ours(true, None, sdb) && !on_ours(true, None, None));
        assert!(on_ours(true, vda, vda) && !on_ours(true, vda, sdb) && !on_ours(true, vda, None));
        assert!(on_ours(false, None, vda) && on_ours(false, None, sdb));
    }

    /// /dev/shm, /run and /tmp are mounted noexec, nosuid and nodev, as /proc and /sys are.
    #[test]
    fn run_tmp_and_shm_are_mounted_noexec() {
        let all = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
        for at in ["/dev/shm", "/run", "/tmp"] {
            let (_, _, flags, _) = mounts().into_iter().find(|(_, there, _, _)| *there == at).unwrap();
            assert!(flags.contains(all), "{at}: {flags:?}");
        }
    }

    /// `booted` and `labelled` read the same slave of dm-0: the first by name, whatever order the
    /// directory lists them in, so the disk of the root is the one a partition label must be on.
    #[test]
    fn booted_and_labelled_read_the_same_slave_of_dm0() {
        let root = std::env::temp_dir().join(format!("kith-init-{}-slaves", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let slaves = root.join("slaves");
        std::fs::create_dir_all(&slaves).unwrap();
        for (disk_name, part) in [("vdb", "vdb2"), ("vda", "vda3")] {
            let dir = root.join("devices").join(disk_name).join(part);
            std::fs::create_dir_all(&dir).unwrap();
            std::os::unix::fs::symlink(&dir, slaves.join(part)).unwrap();
        }
        let first = root_slave(&slaves).expect("a slave of dm-0");
        assert_eq!(first.file_name().and_then(|n| n.to_str()), Some("vda3"));
        assert_eq!(disk(&first).and_then(|d| d.into_string().ok()).as_deref(), Some("vda"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn init_reads_the_kernel_command_line() {
        let read = |line| options(line);
        assert_eq!(read("console=ttyS0 panic=-1"), (Options::default(), vec![]));
        let named = Options {
            hostname: Some("alpha".into()),
            ip: Some(([10, 0, 0, 5].into(), 24, Some([10, 0, 0, 1].into()))),
            dns: Some([9, 9, 9, 9].into()),
            slot: Some('b'),
            update: Some("sdb".into()),
            install: None,
            keep: false,
        };
        let line =
            "quiet kith.hostname=alpha kith.ip=10.0.0.5/24,10.0.0.1 kith.dns=9.9.9.9 kith.slot=b kith.update=sdb";
        assert_eq!(read(line), (named, vec![]));
        assert_eq!(read("kith.ip=10.0.0.5/8").0.ip, Some(([10, 0, 0, 5].into(), 8, None)));
        assert_eq!(read("kith.slot=a kith.slot=b").0.slot, Some('a'));
        assert_eq!(
            (read("kith.grow=off").0.keep, read("kith.grow=on").1),
            (true, vec!["kith.grow=on".to_string()])
        );
        // Not a name, or not an option: said, and the machine starts all the same.
        let bad = ["kith.hostname=", "kith.hostname=Al_pha", "kith.nope=1", "kith.hostname"];
        for bad in bad
            .into_iter()
            .chain(["kith.ip=10.0.0.5", "kith.ip=10.0.0.5/33", "kith.ip=x/8", "kith.dns=x"])
            .chain([
                "kith.slot=c",
                "kith.update=../sda",
                "kith.update=",
                "kith.install=ftp://x",
            ])
        {
            assert_eq!(read(bad), (Options::default(), vec![bad.to_string()]), "{bad}");
        }
        // What follows ` -- ` is kithd's own arguments.
        assert_eq!(read("a=b -- --name kith.hostname=x"), (Options::default(), vec![]));
        // The installer: answers from whoever is there, or from a URL.
        assert_eq!(read("kith.slot=a kith.install").0.install, Some(String::new()));
        assert!(counted("quiet kith.slot=b") && !counted("kith.slot=a kith.install") && !counted("quiet"));
        assert_eq!(
            read("kith.install=http://10.0.2.2/a.yaml").0.install.as_deref(),
            Some("http://10.0.2.2/a.yaml")
        );
    }

    #[test]
    fn init_reads_the_node_config_the_installer_wrote() {
        // A name and addresses for the kernel's side, and kithd's arguments; to the first NUL.
        let text = "kith.hostname=alpha kith.ip=10.0.0.5/24 -- --listen 0.0.0.0:7443 --claim\0\0old --junk";
        let (kernel, args) = configured(text);
        assert_eq!(kernel, "kith.hostname=alpha kith.ip=10.0.0.5/24");
        assert_eq!(args, ["--listen", "0.0.0.0:7443", "--claim"]);
        assert_eq!(options(&kernel).0.hostname.as_deref(), Some("alpha"));
        // Which slot runs, what updates it and whether to install are not a config's to say.
        let (kernel, args) = configured("kith.slot=b kith.update=sdb kith.install kith.dns=9.9.9.9 quiet");
        assert_eq!((kernel.as_str(), args.len()), ("kith.dns=9.9.9.9", 0));
        // An empty partition, and one with arguments only.
        assert_eq!(configured("\0\0\0"), (String::new(), vec![]));
        assert_eq!(configured("-- --claim").1, ["--claim"]);
        // A name that ends in dashes is a name, not where the arguments start.
        let (kernel, args) = configured("kith.hostname=a-- -- --claim");
        assert_eq!(
            (kernel.as_str(), args),
            ("kith.hostname=a--", vec!["--claim".to_string()])
        );
        // The command line comes after the config, and is the last word.
        let both = format!("{} {}", configured(text).0, "kith.hostname=beta");
        assert_eq!(options(&both).0.hostname.as_deref(), Some("beta"));
    }

    #[test]
    fn init_takes_its_arguments_from_the_kernel() {
        let given = |words: &[&str]| arguments(words.iter().map(|word| word.to_string()));
        assert_eq!(given(&["/init"]), ["/init"]);
        assert_eq!(given(&["/init", "splash", "rhgb"]), ["/init"]);
        assert_eq!(
            given(&["/init", "splash", "--listen", "a", "b"]),
            ["/init", "--listen", "a", "b"]
        );
    }

    #[test]
    fn init_finds_the_state_partition() {
        let disk = "MAJOR=254\nMINOR=0\nDEVNAME=vda\nDEVTYPE=disk\n";
        let root = "MAJOR=254\nMINOR=2\nDEVNAME=vda2\nDEVTYPE=partition\nPARTN=2\nPARTNAME=root-a\n";
        let state = "MAJOR=259\nMINOR=6\nDEVNAME=nvme0n1p6\nDEVTYPE=partition\nPARTN=6\nPARTNAME=state\n";
        assert_eq!(partition(disk, "state"), None);
        assert_eq!(partition(root, "state"), None);
        assert_eq!(partition(state, "state"), Some("nvme0n1p6"));
    }

    #[test]
    fn init_names_the_machine_from_its_first_card() {
        assert_eq!(name_from(Some("52:54:00:AB:cd:01\n")), "kith-abcd01");
        assert_eq!(name_from(Some("00:00:00:00:00:00")), "kith");
        assert_eq!(name_from(Some("not one")), "kith");
        assert_eq!(name_from(None), "kith");
    }

    /// An `input_event` with the time left zero.
    fn event(kind: u16, code: u16, value: i32) -> Vec<u8> {
        let mut record = vec![0u8; 16];
        record.extend(kind.to_ne_bytes());
        record.extend(code.to_ne_bytes());
        record.extend(value.to_ne_bytes());
        record
    }

    #[test]
    fn power_button_press_is_told_from_other_events() {
        let (sync, key_a, press, release) = (event(0, 0, 0), event(1, 30, 1), event(1, 116, 1), event(1, 116, 0));
        let mut events = Events::default();
        assert!(!events.power_pressed(&[sync.clone(), key_a.clone(), release.clone()].concat()));
        // The code of the power button under another type is not a press, nor is a repeat.
        assert!(!events.power_pressed(&event(2, 116, 1)));
        assert!(!events.power_pressed(&event(1, 116, 2)));
        assert!(events.power_pressed(&[sync, key_a, press.clone(), release].concat()));
        // Split across reads: the press is heard when its last byte comes, and once.
        assert!(!events.power_pressed(&press[..10]));
        assert!(!events.power_pressed(&press[10..23]));
        assert!(events.power_pressed(&press[23..]));
        assert!(!events.power_pressed(&[]));
    }

    /// A firmware variable as the kernel's efivarfs holds one: four attribute bytes, then
    /// `text` as UTF-16LE with its NUL, as systemd-boot writes it.
    fn variable_bytes(text: &str) -> Vec<u8> {
        let mut bytes = vec![7, 0, 0, 0];
        for unit in text.encode_utf16().chain([0]) {
            bytes.extend(unit.to_le_bytes());
        }
        bytes
    }

    const FIRST: &str = "41414141-4141-4141-4141-414141414141";
    const SECOND: &str = "42424242-4242-4242-4242-424242424242";

    #[test]
    fn firmware_variable_names_the_boot_partition_as_its_text() {
        // Written in capitals, as the variable might be: read as the lower case a GPT writes.
        let bytes = variable_bytes("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");
        assert_eq!(partuuid(&bytes), Ok("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7".into()));
        let guids = [FIRST.to_string(), SECOND.to_string()];
        assert_eq!(holds_boot_partition(&variable_bytes(SECOND), &guids), Ok(true));
        let other = variable_bytes("43434343-4343-4343-4343-434343434343");
        assert_eq!(holds_boot_partition(&other, &guids), Ok(false));
        // A disk with no partitions holds none of them.
        assert_eq!(holds_boot_partition(&variable_bytes(FIRST), &[]), Ok(false));
    }

    #[test]
    fn firmware_variable_text_is_checked_as_it_is_read() {
        let mut odd = variable_bytes(FIRST);
        odd.push(0);
        let mut surrogate = vec![7, 0, 0, 0];
        surrogate.extend([0x00, 0xD8]);
        surrogate.extend(variable_bytes(FIRST)[4..].iter().copied());
        let mut one_more = variable_bytes(FIRST);
        one_more.splice(one_more.len() - 2..one_more.len() - 2, [b'0', 0]);
        let refused = [
            ("nothing after the attributes", vec![7, 0, 0, 0]),
            ("less than the attributes", vec![7, 0]),
            ("an odd number of bytes", odd),
            ("a lone surrogate", surrogate),
            ("not a GUID", variable_bytes("hello")),
            ("a GUID too long", one_more),
            ("a NUL in the middle", variable_bytes(&format!("{FIRST}\0{FIRST}"))),
        ];
        for (what, bytes) in refused {
            assert!(holds_boot_partition(&bytes, &[FIRST.to_string()]).is_err(), "{what}");
        }
        assert!(partuuid(&[]).is_err());
    }

    #[test]
    fn an_absent_firmware_variable_is_none_and_a_huge_one_refused() {
        let dir = std::env::temp_dir().join(format!("kith-efivars-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let name = "LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
        assert_eq!(variable(&dir, name), Ok(None));
        std::fs::write(dir.join(name), variable_bytes(FIRST)).unwrap();
        assert_eq!(variable(&dir, name), Ok(Some(variable_bytes(FIRST))));
        std::fs::write(dir.join(name), vec![0; 1 << 20]).unwrap();
        assert!(variable(&dir, name).unwrap_err().contains("longer"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
