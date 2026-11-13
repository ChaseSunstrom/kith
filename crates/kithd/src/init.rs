//! What kithd does when it is the machine's first process (kith OS, PLAN §4.1): it mounts
//! what a system needs, names the machine, and when it is done it restarts or powers off
//! the machine, since process 1 may never exit. Orphans are collected as on any machine
//! (`kith_runtime::reap_orphans`: kithd is a subreaper anyway).
//!
//! Told on the kernel command line: `kith.hostname=NAME`; `kith.ip=ADDRESS/BITS[,GATEWAY]`
//! and `kith.dns=ADDRESS` for a machine whose network gives no addresses (without them
//! every network card asks by DHCP); `kith.update=DISK` for an update to install from a
//! disk (see `os`); and whatever follows ` -- `, which the kernel hands
//! to its first process as arguments: kithd's own, as in
//! `console=ttyS0 kith.hostname=alpha -- --listen 0.0.0.0:7443 --advertise 10.0.0.5:7443`.
//!
//! Ctrl-Alt-Del (the kernel turns it into SIGINT) restarts the machine, SIGTERM powers it
//! off, each after kithd has stopped what it runs.

use nix::mount::{MsFlags, mount};
use nix::sys::reboot::{RebootMode, reboot, set_cad_enabled};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};

/// Set when kithd was told to stop with SIGTERM: the machine is to power off, not restart.
pub static POWER_OFF: AtomicBool = AtomicBool::new(false);

/// Where a node of kith OS keeps its state: the partition labelled `state` is mounted
/// here, and where there is none (a kernel and kithd alone, as ci/vm.sh boots them) it is
/// in memory.
pub const STATE: &str = "/var/lib/kith";

/// How long kithd has run when the slot it started from is marked good.
const GOOD: std::time::Duration = std::time::Duration::from_secs(10);

pub fn is_init() -> bool {
    std::process::id() == 1
}

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
    if let Err(e) = std::fs::write("/run/resolv.conf", lines) {
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
    let entries = |dir: &str| -> Vec<std::path::PathBuf> {
        let mut all: Vec<_> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect();
        all.sort();
        all
    };
    let ours = entries("/sys/block/dm-0/slaves").first().and_then(|under| disk(under));
    entries("/sys/class/block").into_iter().find_map(|device| {
        let uevent = std::fs::read_to_string(device.join("uevent")).ok()?;
        let name = partition(&uevent, label)?;
        (ours.is_none() || disk(&device) == ours).then(|| std::path::Path::new("/dev").join(name))
    })
}

/// Mount the state partition, or say that there is none and keep the state in memory.
fn state() {
    let _ = std::fs::create_dir_all(STATE);
    let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
    let found = labelled("state");
    let Some(device) = found else {
        eprintln!(
            "kithd: init: no partition is labelled state: this node's state is in memory, and gone when it restarts"
        );
        if let Err(e) = mount(Some("tmpfs"), STATE, Some("tmpfs"), flags, Some("mode=0700")) {
            eprintln!("kithd: init: mounting {STATE}: {e}");
        }
        return;
    };
    match mount(
        Some(&device),
        STATE,
        Some("ext4"),
        flags | MsFlags::MS_NOATIME,
        None::<&str>,
    ) {
        Ok(()) => eprintln!("kithd: init: state on {}", device.display()),
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
}

impl Boot {
    /// Ask for as long as kithd runs (it serves meanwhile). Call inside the runtime.
    pub fn network(self) {
        for card in self.asking {
            // (A name server on the command line is one the network's own may not replace.)
            let told = self.dns;
            let got = move |lease: &crate::dhcp::Lease| match told {
                Some(server) => resolvers(&[server]),
                None => resolvers(&lease.dns.iter().copied().map(IpAddr::from).collect::<Vec<_>>()),
            };
            tokio::spawn(crate::dhcp::keep(card, self.name.clone(), got));
        }
        let Some(slot) = self.slot else { return };
        // ponytail: good means kithd started and is still running a little later (one that
        // cannot start ends, and the machine restarts, well within that). Whether the node
        // is healthy in its cluster is the update plan's to judge (T-0073).
        tokio::spawn(async move {
            tokio::time::sleep(GOOD).await;
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
            Ok(()) => eprintln!("kithd: init: {} has {address}/{bits}", card.name),
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

/// The first things, before anything else of kithd runs. Each is tried and said if it
/// fails: with part of them kithd may still serve, and a console line says what is missing.
pub fn early() -> Boot {
    // Ctrl-Alt-Del comes to this process as SIGINT instead of restarting the machine at once.
    let _ = set_cad_enabled(false);
    let quiet = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    let shared = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
    let mounts = [
        ("proc", "/proc", quiet, ""),
        ("sysfs", "/sys", quiet, ""),
        ("devtmpfs", "/dev", MsFlags::MS_NOSUID, "mode=0755"),
        (
            "devpts",
            "/dev/pts",
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            "gid=5,mode=620,ptmxmode=666",
        ),
        ("tmpfs", "/dev/shm", shared, "mode=1777"),
        ("tmpfs", "/run", shared, "mode=0755"),
        ("tmpfs", "/tmp", shared, "mode=1777"),
        ("cgroup2", "/sys/fs/cgroup", quiet, ""),
    ];
    for (kind, at, flags, data) in mounts {
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
    state();
    let line = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let (options, unknown) = options(&line);
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
    // A panic would end process 1, and with it the kernel: say it and restart instead.
    std::panic::set_hook(Box::new(|info| {
        eprintln!("kithd: {info}");
        end(true);
    }));
    if let (Some(slot), Some(device)) = (options.slot, &options.update) {
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
        slot: options.slot,
        name,
    }
}

/// kithd is done (it has stopped what it ran): restart the machine or power it off.
/// After a failure it restarts, once the reason has had time to be read on a console.
pub fn end(failed: bool) -> ! {
    let off = !failed && POWER_OFF.load(Ordering::Relaxed);
    if failed {
        eprintln!("kithd: init: restarting in 10 s");
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
    eprintln!("kithd: init: {}", if off { "powering off" } else { "restarting" });
    // ponytail: time for that line to reach the consoles (see `consoles`), not a handshake.
    std::thread::sleep(std::time::Duration::from_millis(200));
    // Written out, then let go of: by now kithd has closed what it had open there. (If
    // not, as after a panic, the file system's journal is what keeps it whole.)
    nix::unistd::sync();
    if let Err(e) = nix::mount::umount(STATE) {
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
        };
        let line =
            "quiet kith.hostname=alpha kith.ip=10.0.0.5/24,10.0.0.1 kith.dns=9.9.9.9 kith.slot=b kith.update=sdb";
        assert_eq!(read(line), (named, vec![]));
        assert_eq!(read("kith.ip=10.0.0.5/8").0.ip, Some(([10, 0, 0, 5].into(), 8, None)));
        assert_eq!(read("kith.slot=a kith.slot=b").0.slot, Some('a'));
        // Not a name, or not an option: said, and the machine starts all the same.
        let bad = ["kith.hostname=", "kith.hostname=Al_pha", "kith.nope=1", "kith.hostname"];
        for bad in bad
            .into_iter()
            .chain(["kith.ip=10.0.0.5", "kith.ip=10.0.0.5/33", "kith.ip=x/8", "kith.dns=x"])
            .chain(["kith.slot=c", "kith.update=../sda", "kith.update="])
        {
            assert_eq!(read(bad), (Options::default(), vec![bad.to_string()]), "{bad}");
        }
        // What follows ` -- ` is kithd's own arguments.
        assert_eq!(read("a=b -- --name kith.hostname=x"), (Options::default(), vec![]));
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
}
