//! What kithd does when it is the machine's first process (kith OS, PLAN §4.1): it mounts
//! what a system needs, names the machine, and when it is done it restarts or powers off
//! the machine, since process 1 may never exit. Orphans are collected as on any machine
//! (`kith_runtime::reap_orphans`: kithd is a subreaper anyway).
//!
//! Told on the kernel command line: `kith.hostname=NAME`; `kith.ip=ADDRESS/BITS[,GATEWAY]`
//! and `kith.dns=ADDRESS` for a machine whose network gives no addresses (without them
//! every network card asks by DHCP); and whatever follows ` -- `, which the kernel hands
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

/// Where a node of kith OS keeps its state.
// ponytail: in memory until there is a state partition to mount here (T-0072).
pub const STATE: &str = "/var/lib/kith";

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
    let written = std::fs::create_dir_all("/etc").and_then(|()| std::fs::write("/etc/resolv.conf", lines));
    if let Err(e) = written {
        eprintln!("kithd: init: writing /etc/resolv.conf: {e}");
    }
}

/// What is left to do once kithd's runtime runs: the cards that ask their network for an
/// address.
#[derive(Default)]
pub struct Boot {
    name: String,
    asking: Vec<kith_mesh::Card>,
    dns: Option<IpAddr>,
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
    }
}

/// Links up, and the address the command line gives the first card; without one, every
/// card is left to ask its network.
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
        return Vec::new();
    }
    cards
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
    eprintln!("kithd: init: {name} is up");
    Boot {
        asking: links(&options),
        dns: options.dns,
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
    // ponytail: nothing on a disk is mounted yet; unmount the state partition here (T-0072).
    nix::unistd::sync();
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
        };
        let line = "quiet kith.hostname=alpha kith.ip=10.0.0.5/24,10.0.0.1 kith.dns=9.9.9.9";
        assert_eq!(read(line), (named, vec![]));
        assert_eq!(read("kith.ip=10.0.0.5/8").0.ip, Some(([10, 0, 0, 5].into(), 8, None)));
        // Not a name, or not an option: said, and the machine starts all the same.
        let bad = ["kith.hostname=", "kith.hostname=Al_pha", "kith.nope=1", "kith.hostname"];
        for bad in bad
            .into_iter()
            .chain(["kith.ip=10.0.0.5", "kith.ip=10.0.0.5/33", "kith.ip=x/8", "kith.dns=x"])
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
    fn init_names_the_machine_from_its_first_card() {
        assert_eq!(name_from(Some("52:54:00:AB:cd:01\n")), "kith-abcd01");
        assert_eq!(name_from(Some("00:00:00:00:00:00")), "kith");
        assert_eq!(name_from(Some("not one")), "kith");
        assert_eq!(name_from(None), "kith");
    }
}
