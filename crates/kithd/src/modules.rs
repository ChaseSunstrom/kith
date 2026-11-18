//! Kernel modules by modalias, as udev and kmod do it, for kith OS (init.rs): when
//! `/lib/modules/<release>` exists, every device's `modalias` under `/sys/devices` is matched
//! against its `modules.alias` (globs) and the module is loaded after what `modules.dep` says
//! it needs; then each kernel uevent (`ACTION=add` with a `MODALIAS=`) the same, so a card
//! put in later gets its driver. The plain image has no such directory: nothing is done.
//!
//! Not supported: module parameters, `modprobe.d` (blacklists, options), soft dependencies.
//! A compressed module (`.ko.xz`, `.zst`, `.gz`) is loaded with `MODULE_INIT_COMPRESSED_FILE`:
//! the kernel (5.17 or later) must have been built to decompress it.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// `modules.alias`, `modules.dep` and `modules.builtin` of one kernel's modules directory.
#[derive(Debug, Default)]
pub struct Tree {
    dir: PathBuf,
    aliases: Vec<(String, String)>,
    /// A module's file (relative to `dir`) and the names it needs, the nearest first.
    deps: HashMap<String, (String, Vec<String>)>,
    builtin: HashSet<String>,
}

/// A module's name as the kernel and `modules.alias` write it: no directory, no `.ko` and
/// what follows, `-` as `_`.
fn name(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    file.split(".ko").next().unwrap_or(file).replace('-', "_")
}

/// `pattern` as `fnmatch` reads it (`*`, `?`, `[a-z]`, `[!x]`) against `text`.
fn glob(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        let step = match p.get(pi) {
            Some(b'*') => {
                (star, mark, pi) = (Some(pi), ti, pi + 1);
                continue;
            }
            Some(b'?') => Some(pi + 1),
            Some(b'[') => match class(p, pi, t[ti]) {
                Some((hit, next)) => hit.then_some(next),
                None => (t[ti] == b'[').then_some(pi + 1),
            },
            Some(&c) => (c == t[ti]).then_some(pi + 1),
            None => None,
        };
        if let Some(next) = step {
            (pi, ti) = (next, ti + 1);
        } else if let Some(s) = star {
            mark += 1;
            (pi, ti) = (s + 1, mark);
        } else {
            return false;
        }
    }
    while p.get(pi) == Some(&b'*') {
        pi += 1;
    }
    pi == p.len()
}

/// The `[...]` at `p[at]`: whether `c` is in it, and where the pattern goes on. None when
/// it is never closed (the `[` is then only a `[`).
fn class(p: &[u8], at: usize, c: u8) -> Option<(bool, usize)> {
    let mut i = at + 1;
    let negated = matches!(p.get(i), Some(b'!' | b'^'));
    i += usize::from(negated);
    let (mut hit, first) = (false, i);
    loop {
        let &lo = p.get(i)?;
        if lo == b']' && i > first {
            return Some((hit != negated, i + 1));
        }
        if p.get(i + 1) == Some(&b'-') && p.get(i + 2).is_some_and(|&hi| hi != b']') {
            hit |= (lo..=p[i + 2]).contains(&c);
            i += 3;
        } else {
            hit |= lo == c;
            i += 1;
        }
    }
}

/// The names in `/proc/modules` (the first word of each line).
fn loaded(text: &str) -> HashSet<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// What a uevent says to load: the MODALIAS of an `ACTION=add` (the message is the
/// `ACTION@path` header, then `KEY=value` strings, NUL between).
fn uevent_modalias(message: &[u8]) -> Option<&str> {
    let mut add = false;
    let mut alias = None;
    for line in message.split(|&b| b == 0).filter_map(|l| std::str::from_utf8(l).ok()) {
        add |= line == "ACTION=add";
        alias = alias.or_else(|| line.strip_prefix("MODALIAS="));
    }
    alias.filter(|_| add)
}

/// Every device's modalias under `root`, each once. (Links are not followed.)
fn modaliases(root: &Path) -> Vec<String> {
    let (mut found, mut todo) = (Vec::new(), vec![root.to_path_buf()]);
    while let Some(dir) = todo.pop() {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let Ok(kind) = entry.file_type() else { continue };
            if kind.is_dir() {
                todo.push(entry.path());
            } else if kind.is_file()
                && entry.file_name() == "modalias"
                && let Ok(text) = std::fs::read_to_string(entry.path())
                && !text.trim().is_empty()
                && !found.contains(&text.trim().to_string())
            {
                found.push(text.trim().to_string());
            }
        }
    }
    found
}

impl Tree {
    /// None when `dir` has no `modules.alias`: the plain image, where nothing is done.
    pub fn read(dir: &Path) -> Option<Tree> {
        let alias = std::fs::read_to_string(dir.join("modules.alias")).ok()?;
        let dep = std::fs::read_to_string(dir.join("modules.dep")).unwrap_or_default();
        let builtin = std::fs::read_to_string(dir.join("modules.builtin")).unwrap_or_default();
        Some(Tree::parse(dir, &alias, &dep, &builtin))
    }

    fn parse(dir: &Path, alias: &str, dep: &str, builtin: &str) -> Tree {
        let aliases = alias
            .lines()
            .filter_map(|l| {
                let mut words = l.split_whitespace();
                (words.next() == Some("alias")).then_some(())?;
                Some((words.next()?.to_string(), name(words.next()?)))
            })
            .collect();
        let deps = dep
            .lines()
            .filter_map(|l| {
                let (path, needs) = l.split_once(':')?;
                Some((
                    name(path),
                    (path.to_string(), needs.split_whitespace().map(name).collect()),
                ))
            })
            .collect();
        Tree {
            dir: dir.to_path_buf(),
            aliases,
            deps,
            builtin: builtin.lines().map(name).collect(),
        }
    }

    /// What to load for `modalias`, in order: for each module its aliases match, what it
    /// needs (modules.dep lists the nearest first: the farthest is loaded first), then it.
    /// Not what `skip` holds (loaded, tried, built in) nor what is already in the plan.
    fn plan(&self, modalias: &str, skip: &HashSet<String>) -> Vec<(String, PathBuf)> {
        let mut out: Vec<(String, PathBuf)> = Vec::new();
        for (_, module) in self.aliases.iter().filter(|(pattern, _)| glob(pattern, modalias)) {
            let Some((_, needs)) = self
                .deps
                .get(module)
                .filter(|_| !skip.contains(module) && !self.builtin.contains(module))
            else {
                continue;
            };
            for one in needs.iter().rev().chain(std::iter::once(module)) {
                let Some((path, _)) = self.deps.get(one) else { continue };
                if !skip.contains(one) && !self.builtin.contains(one) && !out.iter().any(|(n, _)| n == one) {
                    out.push((one.clone(), self.dir.join(path)));
                }
            }
        }
        out
    }

    /// Load for `modalias` what `plan` says, each module at most once over the life of
    /// `tried` (a module that failed is not tried again at every uevent). A failure is for
    /// `load` to say (and answer false); it is never an end. How many `load` answered true.
    fn load_for(
        &self,
        modalias: &str,
        loaded: &HashSet<String>,
        tried: &mut HashSet<String>,
        load: &mut impl FnMut(&str, &Path) -> bool,
    ) -> usize {
        let skip: HashSet<String> = loaded.union(tried).cloned().collect();
        let mut count = 0;
        for (module, path) in self.plan(modalias, &skip) {
            tried.insert(module.clone());
            count += usize::from(load(&module, &path));
        }
        count
    }
}

/// `finit_module` of one module file, no parameters: whether it is loaded now.
fn finit(module: &str, path: &Path) -> bool {
    use nix::kmod::{ModuleInitFlags, finit_module};
    let compressed = matches!(path.extension().and_then(|e| e.to_str()), Some("xz" | "zst" | "gz"));
    // (MODULE_INIT_COMPRESSED_FILE, 4: nix has no name for it.)
    let flags = if compressed {
        ModuleInitFlags::from_bits_retain(4)
    } else {
        ModuleInitFlags::empty()
    };
    match std::fs::File::open(path).map_err(|e| e.to_string()).and_then(|f| {
        match finit_module(&f, c"", flags) {
            Ok(()) | Err(nix::errno::Errno::EEXIST) => Ok(()),
            Err(nix::errno::Errno::EINVAL) if compressed => {
                Err("Invalid argument: the kernel cannot load compressed modules (it needs 5.17 or later and MODULE_DECOMPRESS)".into())
            }
            Err(e) => Err(e.to_string()),
        }
    }) {
        Ok(()) => {
            eprintln!("kithd: init: module {module} loaded");
            true
        }
        Err(e) => {
            eprintln!("kithd: init: module {module}: {e}");
            false
        }
    }
}

/// Load for every device there is, and go on loading for each one that is added. With no
/// `/lib/modules/<release>` (the plain image) it does nothing and starts nothing.
pub fn start() {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let Some(tree) = Tree::read(&Path::new("/lib/modules").join(release.trim())).filter(|_| !release.trim().is_empty())
    else {
        return;
    };
    // The socket first: what the scan loads brings devices, and their uevents wait in it.
    let socket =
        listener().map_err(|e| eprintln!("kithd: init: no uevents, modules are loaded for the devices there are: {e}"));
    // The scan before init goes on: the network card's driver may be a module, and the
    // node's name is made from its address next.
    // ponytail: every alias line is matched against every device (a distro's modules.alias
    // is ~25k lines); bucket the lines by bus if a start is measured slow.
    let (mut tried, start) = (HashSet::new(), std::time::Instant::now());
    let count = scan(&tree, &mut tried);
    eprintln!(
        "kithd: init: {count} kernel modules loaded for the devices there are, in {} ms",
        start.elapsed().as_millis()
    );
    // (A thread for what is added later: it only reads, loads and logs.)
    if let Ok(socket) = socket {
        std::thread::spawn(move || listen(&socket, &tree, tried));
    }
}

/// Load for every device in /sys/devices: how many modules were loaded.
fn scan(tree: &Tree, tried: &mut HashSet<String>) -> usize {
    // (What was loaded before the scan; what it loads is in `tried`.)
    let now = loaded(&std::fs::read_to_string("/proc/modules").unwrap_or_default());
    modaliases(Path::new("/sys/devices"))
        .iter()
        .map(|alias| tree.load_for(alias, &now, tried, &mut finit))
        .sum()
}

fn listener() -> nix::Result<std::os::fd::OwnedFd> {
    use nix::sys::socket::{
        AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, setsockopt, socket, sockopt,
    };
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkKObjectUEvent,
    )?;
    // (A boot's uevents come in a burst: the default buffer is 208 KB. Forced, as udev does:
    // the plain one is capped at net.core.rmem_max even for root. ENOBUFS rescans anyway.)
    let _ = setsockopt(&fd, sockopt::RcvBufForce, &(1 << 20));
    // Group 1: the kernel's own events (udev's re-sent ones are group 2).
    bind(std::os::fd::AsRawFd::as_raw_fd(&fd), &NetlinkAddr::new(0, 1))?;
    Ok(fd)
}

fn listen(socket: &std::os::fd::OwnedFd, tree: &Tree, mut tried: HashSet<String>) {
    use nix::errno::Errno;
    use nix::sys::socket::{NetlinkAddr, recvfrom};
    let mut buf = [0u8; 8192];
    loop {
        match recvfrom::<NetlinkAddr>(std::os::fd::AsRawFd::as_raw_fd(socket), &mut buf) {
            // (Only the kernel, portid 0, is believed.)
            Ok((n, from)) if from.is_some_and(|a| a.pid() == 0) => {
                if let Some(alias) = uevent_modalias(&buf[..n]) {
                    let now = loaded(&std::fs::read_to_string("/proc/modules").unwrap_or_default());
                    tree.load_for(alias, &now, &mut tried, &mut finit);
                }
            }
            Ok(_) | Err(Errno::EINTR) => {}
            // Events were lost: look at every device again.
            Err(Errno::ENOBUFS) => drop(scan(tree, &mut tried)),
            Err(e) => {
                eprintln!("kithd: init: uevents: {e}: no more modules are loaded for new devices");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALIAS: &str = "# Aliases extracted from modules themselves.\n\
        alias pci:v00008086d00001234sv*sd*bc02sc*i* e1000_x\n\
        alias usb:v1D6Bp000[23]d*dc*dsc*dp*ic*isc*ip*in* xhci-hcd\n\
        alias pci:v0000[!8]* never\n\
        alias of:N*T*Cfoo,bar? thing\n\
        alias pci:v00008086d00001234* in_kernel\n";
    const DEP: &str = "kernel/net/e1000_x.ko.xz: kernel/lib/b.ko.xz kernel/lib/c.ko.xz\n\
        kernel/lib/b.ko.xz: kernel/lib/c.ko.xz\n\
        kernel/lib/c.ko.xz:\n\
        kernel/usb/xhci-hcd.ko:\n\
        kernel/misc/never.ko:\n\
        kernel/misc/in-kernel.ko:\n";
    const NIC: &str = "pci:v00008086d00001234sv00001AF4sd00001100bc02sc00i00";

    fn tree() -> Tree {
        Tree::parse(Path::new("/m"), ALIAS, DEP, "kernel/in-kernel.ko\n")
    }

    #[test]
    fn modalias_globs_match_as_fnmatch_does() {
        assert!(glob("a*c", "abbc") && glob("a?c", "abc") && glob("*", ""));
        assert!(!glob("a?c", "ac") && !glob("a*c", "abd") && !glob("abc", "abcd"));
        assert!(glob("v[0-9a-f]x", "vbx") && !glob("v[0-9a-f]x", "vzx"));
        assert!(glob("v[!8]x", "v7x") && !glob("v[!8]x", "v8x"));
        assert!(glob("v[]]x", "v]x") && glob("a[b", "a[b"));
        assert!(glob("pci:v*d*sv*sd*bc02sc*i*", NIC));
        assert!(
            tree()
                .plan("usb:v1D6Bp0003d0100dc09dsc00dp00ic09isc00ip00in00", &HashSet::new())
                .len()
                == 1
        );
        assert!(tree().plan("usb:v1D6Bp0004d0100", &HashSet::new()).is_empty());
    }

    #[test]
    fn modalias_dependencies_load_first_and_names_are_normalised() {
        let plan: Vec<String> = tree().plan(NIC, &HashSet::new()).into_iter().map(|(n, _)| n).collect();
        // (modules.dep lists the nearest first: c is the farthest.)
        assert_eq!(plan, ["c", "b", "e1000_x"]);
        let usb = tree().plan("usb:v1D6Bp0002d0001dc00dsc00dp00ic00isc00ip00in00", &HashSet::new());
        assert_eq!(
            usb,
            [("xhci_hcd".to_string(), PathBuf::from("/m/kernel/usb/xhci-hcd.ko"))]
        );
        // (A module built into the kernel is not loaded.)
        assert!(!plan.contains(&"in_kernel".to_string()));
    }

    #[test]
    fn modalias_a_loaded_module_is_not_loaded_twice() {
        let t = tree();
        let now = loaded("c 16384 1 e1000_x, Live 0xffff\ne1000_x 4096 0 - Live 0xffff\nb 4096 1 e1000_x, Live 0x0\n");
        let (mut tried, mut seen) = (HashSet::new(), Vec::new());
        t.load_for(NIC, &now, &mut tried, &mut |m, _| {
            seen.push(m.to_string());
            true
        });
        assert!(seen.is_empty(), "e1000_x is in: {seen:?}");
        // (b is not, but its module is: the plan has what is missing only.)
        let now = loaded("c 16384 1 - Live 0x0\n");
        t.load_for(NIC, &now, &mut tried, &mut |m, _| {
            seen.push(m.to_string());
            true
        });
        assert_eq!(seen, ["b", "e1000_x"]);
        // (The same device again, and the kernel does not list them yet: not tried again.)
        t.load_for(NIC, &now, &mut tried, &mut |m, _| {
            seen.push(m.to_string());
            false
        });
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn modalias_no_modules_dir_does_nothing() {
        let dir = std::env::temp_dir().join(format!("kith-modules-{}-none", std::process::id()));
        assert!(Tree::read(&dir).is_none());
    }

    #[test]
    fn modalias_of_a_made_up_sysfs_and_modules_dir() {
        let root = std::env::temp_dir().join(format!("kith-modules-{}-sys", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (sys, lib) = (root.join("sys/devices/pci0000:00/0000:00:03.0"), root.join("lib"));
        std::fs::create_dir_all(&sys).unwrap();
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::write(sys.join("modalias"), format!("{NIC}\n")).unwrap();
        std::fs::write(sys.join("uevent"), "x").unwrap();
        std::fs::write(root.join("sys/devices/pci0000:00/modalias"), format!("{NIC}\n")).unwrap();
        std::fs::write(lib.join("modules.alias"), ALIAS).unwrap();
        std::fs::write(lib.join("modules.dep"), DEP).unwrap();
        std::fs::write(lib.join("modules.builtin"), "kernel/in-kernel.ko\n").unwrap();
        assert_eq!(modaliases(&root.join("sys/devices")), [NIC]);
        let t = Tree::read(&lib).unwrap();
        let mut seen = Vec::new();
        for alias in modaliases(&root.join("sys/devices")) {
            t.load_for(&alias, &HashSet::new(), &mut HashSet::new(), &mut |m, p| {
                seen.push((m.to_string(), p.to_path_buf()));
                true
            });
        }
        assert_eq!(
            seen.last().unwrap(),
            &("e1000_x".to_string(), lib.join("kernel/net/e1000_x.ko.xz"))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn modalias_uevent_add_with_a_modalias_only() {
        let add = b"add@/devices/pci0000:00/0000:00:03.0\0ACTION=add\0DEVPATH=/devices/x\0MODALIAS=pci:v1\0SEQNUM=9\0";
        assert_eq!(uevent_modalias(add), Some("pci:v1"));
        assert_eq!(uevent_modalias(b"remove@/x\0ACTION=remove\0MODALIAS=pci:v1\0"), None);
        assert_eq!(uevent_modalias(b"add@/x\0ACTION=add\0DEVPATH=/x\0"), None);
        assert_eq!(uevent_modalias(b"libudev\0\xff\xfe\0"), None);
    }
}
