//! The serving part's confinement (docs/adr-privilege.md, "The serving part"): what it still
//! reaches once its listeners and its store are open is its own state directory, and nothing that
//! makes the machine different.
//!
//! WHAT HOLDS TODAY: the confinement is built and held to what it says by `kithd confine-probe`
//! (a test build, ci/vm/privilege.sh) and by the unit tests. NO LIVE SERVING PART IS CONFINED: the
//! root part is still a thread of kithd, and `--split` does not yet start a serving process that
//! calls [`serving`]. This module is in no release build.
//!
//! The steps are [`Steps`], run by [`serving`] in this order, each after the one before: a mount
//! namespace holding only the state directory (no exec) and a `/proc` of its own that shows its own
//! process alone, a user and group id that are not 0 (no supplementary group), every capability set
//! emptied (the bounding set included), no_new_privs and, last, a seccomp allow-list
//! ([`Plan::filter`] off is `--no-filter`, for a call the list misses). A step that fails ends the
//! confinement there with an error, and the caller ends: a serving part half confined serves
//! nothing. A process that holds a directory open (or an O_PATH descriptor) is refused before the
//! first step: such a descriptor reaches the node's tree past the pivot.
//!
//! All five are the calling thread's (the filter and the user ids every thread's). A thread made
//! before keeps the mount namespace and the bounding set it had, so the serving part runs this
//! while it is one thread, and what it starts after, it starts confined.
//!
//! WHAT STAYS OPEN: the serving part keeps the node's network namespace, so it reaches the host's
//! loopback and every abstract AF_UNIX socket of the node (the filter allows AF_UNIX, INET and
//! INET6 only, but a name in the abstract space is not a file of a mount). Closing it is a
//! `CLONE_NEWNET` after the listeners are open, which holds only if the part makes no outbound
//! connection. Nothing beyond what is listed here is claimed closed.
//!
//! `kithd confine-probe DIR` is the process this is held to: it opens a listener and a file in `DIR`
//! as root, confines itself, then says what it is (its status, its mounts) and what it still can do.
//! (ci/vm/privilege.sh reads it.)
#![cfg_attr(
    not(feature = "confine-probe"),
    allow(
        dead_code,
        reason = "the steps are run by the probe build alone until the serving process calls them"
    )
)]

use std::path::{Path, PathBuf};

/// The user and group id the serving part runs as: owner of its state directory, and of nothing else.
pub const SERVING_ID: u32 = 4100;

/// Where the serving part is confined to, and as whom.
pub struct Plan {
    /// The directory it keeps: its state.
    pub state: PathBuf,
    pub uid: u32,
    pub gid: u32,
    /// The seccomp filter, last (off for `--no-filter`).
    pub filter: bool,
}

/// What the five steps do. The real ones are [`System`]'s; a test records them.
pub trait Steps {
    /// A mount namespace of its own that holds `keep` and `/proc`, and nothing the node has.
    fn mount_namespace(&mut self, keep: &Path) -> Result<(), String>;
    /// The group id and no supplementary group, then the user id: real, effective and saved.
    fn ids(&mut self, uid: u32, gid: u32) -> Result<(), String>;
    /// Every capability set (bounding, ambient, inheritable, permitted, effective) emptied.
    fn capabilities(&mut self) -> Result<(), String>;
    fn no_new_privs(&mut self) -> Result<(), String>;
    /// The allow-list of calls, for the thread and every other.
    fn seccomp(&mut self) -> Result<(), String>;
}

/// The listeners and then the store opened (as the privilege they need is still there), then the
/// five steps in order: what the two gave, once the serving part is confined.
pub fn serving<L, S, T: Steps>(
    steps: &mut T,
    plan: &Plan,
    listeners: impl FnOnce() -> Result<L, String>,
    store: impl FnOnce() -> Result<S, String>,
) -> Result<(L, S), String> {
    // (Before anything is opened: a plan that would leave root is not one.)
    if plan.uid == 0 || plan.gid == 0 {
        return Err("the serving part runs as a user and a group that are not 0".into());
    }
    plain(&plan.state)?;
    let opened = (listeners()?, store()?);
    let named = |what: &str, done: Result<(), String>| done.map_err(|e| format!("confining: {what}: {e}"));
    named("the mount namespace", steps.mount_namespace(&plan.state))?;
    named("the user and group", steps.ids(plan.uid, plan.gid))?;
    named("the capabilities", steps.capabilities())?;
    named("no_new_privs", steps.no_new_privs())?;
    if plan.filter {
        named("the seccomp filter", steps.seccomp())?;
    }
    Ok(opened)
}

/// `at` without its root: an absolute path of names alone, which is where it lies in a new root.
/// Not `..` (it would put the bind outside the new root), not a relative path, not `/` itself (the
/// state would be the root).
fn plain(at: &Path) -> Result<PathBuf, String> {
    use std::path::Component;
    let mut names = PathBuf::new();
    for part in at.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => names.push(name),
            _ => {
                return Err(format!(
                    "the state directory {} has `..` or no root in it",
                    at.display()
                ));
            }
        }
    }
    if !at.is_absolute() || names.as_os_str().is_empty() {
        return Err(format!(
            "the state directory {} is not an absolute path to a directory of its own",
            at.display()
        ));
    }
    Ok(names)
}

/// Whether the text of `/proc/self/fdinfo/N` says the descriptor was opened with O_PATH.
fn opened_for_path(fdinfo: &str) -> bool {
    const O_PATH: u32 = 0o10_000_000;
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .and_then(|flags| u32::from_str_radix(flags.trim(), 8).ok())
        .is_some_and(|flags| flags & O_PATH != 0)
}

/// The line of `/proc/self/mountinfo` for the mount at `at`, when its options lack one of `want`
/// (or there is no such mount): what a remount said it did, read back from the kernel.
fn lacking(mountinfo: &str, at: &Path, want: &[&str]) -> Option<String> {
    let line = mountinfo
        .lines()
        .rev()
        .find(|l| l.split(' ').nth(4).is_some_and(|p| Path::new(p) == at));
    match line {
        Some(l)
            if want
                .iter()
                .all(|w| l.split(' ').nth(5).is_some_and(|o| o.split(',').any(|o| o == *w))) =>
        {
            None
        }
        Some(l) => Some(l.to_string()),
        None => Some(format!("no mount at {}", at.display())),
    }
}

/// The descriptors this process holds that reach the node's tree whatever the pivot: a directory
/// (`fchdir`, then `..` or a relative open) and an O_PATH descriptor (the same, through its mount)
/// keep the mount they were opened on, which the new namespace unmounts and they do not. Each as
/// "fd N (where it points)". The confinement ends before it begins when this is not empty: a
/// descriptor is no part of the process's own that can be closed from here without the owner knowing.
fn held_directories() -> Result<Vec<String>, String> {
    // (Listed first and the listing closed, so its own descriptor is not among them.)
    let names: Vec<String> = std::fs::read_dir("/proc/self/fd")
        .map_err(|e| format!("its descriptors are not listed: {e}"))?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect();
    let mut held = Vec::new();
    for name in names {
        let at = format!("/proc/self/fd/{name}");
        let directory = std::fs::metadata(&at).is_ok_and(|m| m.is_dir());
        let by_path = std::fs::read_to_string(format!("/proc/self/fdinfo/{name}")).is_ok_and(|t| opened_for_path(&t));
        if directory || by_path {
            let to = std::fs::read_link(&at).map_or("?".to_string(), |p| p.display().to_string());
            held.push(format!("fd {name} ({to})"));
        }
    }
    Ok(held)
}

/// The steps on this process.
pub struct System;

/// Where the new root is made, on the node's `/run` (a tmpfs, so what is left of it is a directory).
const ROOT: &str = "/run/kith-serving";

impl Steps for System {
    fn mount_namespace(&mut self, keep: &Path) -> Result<(), String> {
        use nix::mount::{MntFlags, MsFlags, mount, umount2};
        let said = |what: &str| {
            let what = what.to_string();
            move |e: &dyn std::fmt::Display| format!("{what}: {e}")
        };
        let none = None::<&str>;
        // (Before anything is changed: a descriptor of a directory outlives the pivot.)
        let held = held_directories()?;
        if !held.is_empty() {
            return Err(format!(
                "it holds directories open that reach past the new root ({}): the part that confines holds none",
                held.join(", ")
            ));
        }
        kith_dm_sys::unshare_mounts().map_err(|e| said("unshare")(&e))?;
        // What the node mounts after this must not reach in, nor what is done here reach out.
        mount(none, "/", none, MsFlags::MS_REC | MsFlags::MS_PRIVATE, none).map_err(|e| said("private")(&e))?;
        let root = Path::new(ROOT);
        std::fs::create_dir_all(root).map_err(|e| said("the new root")(&e))?;
        // (No exec anywhere: the serving part runs what it is, and the filter has no execve for it.)
        let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
        mount(Some("tmpfs"), root, Some("tmpfs"), flags, Some("size=1m,mode=0755")).map_err(|e| said("tmpfs")(&e))?;
        let made = |at: &Path| -> Result<PathBuf, String> {
            let to = root.join(plain(at)?);
            std::fs::create_dir_all(&to).map_err(|e| said("a mount point")(&e))?;
            Ok(to)
        };
        // The state directory, the tree of it (what is mounted under it too: nothing).
        let to = made(keep)?;
        mount(Some(keep), &to, none, MsFlags::MS_BIND | MsFlags::MS_REC, none).map_err(|e| said("bind")(&e))?;
        let again = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | flags;
        mount(none, &to, none, again, none).map_err(|e| said("remount")(&e))?;
        // (Read back: the kernel's word for what the remount did, not ours.)
        let seen = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| said("mountinfo")(&e))?;
        if let Some(line) = lacking(&seen, &to, &["nosuid", "nodev", "noexec"]) {
            return Err(format!(
                "the state directory's mount is not nosuid,nodev,noexec: {line}"
            ));
        }
        // A /proc of its own, not a bind of the node's: it shows no process that is not the part's
        // (hidepid=invisible: another user's are not listed or opened) and nothing but processes
        // (subset=pid: not /proc/sys, kcore, the node's mounts and the rest).
        let to = made(Path::new("/proc"))?;
        mount(
            Some("proc"),
            &to,
            Some("proc"),
            flags | MsFlags::MS_RDONLY,
            Some("hidepid=invisible,subset=pid"),
        )
        .map_err(|e| said("proc")(&e))?;
        let old = root.join(".old");
        std::fs::create_dir(&old).map_err(|e| said("the old root")(&e))?;
        nix::unistd::pivot_root(root, &old).map_err(|e| said("pivot_root")(&e))?;
        nix::unistd::chdir("/").map_err(|e| said("chdir")(&e))?;
        umount2("/.old", MntFlags::MNT_DETACH).map_err(|e| said("umount")(&e))?;
        std::fs::remove_dir("/.old").map_err(|e| said("the old root")(&e))?;
        let ro = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | flags;
        mount(none, "/", none, ro, none).map_err(|e| said("read only")(&e))?;
        let seen = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| said("mountinfo")(&e))?;
        match lacking(&seen, keep, &["nosuid", "nodev", "noexec"]) {
            None => Ok(()),
            Some(line) => Err(format!(
                "at the end the state directory's mount is not nosuid,nodev,noexec: {line}"
            )),
        }
    }

    fn ids(&mut self, uid: u32, gid: u32) -> Result<(), String> {
        use kith_dm_sys as sys;
        let ids = |e: std::io::Error| e.to_string();
        sys::drop_groups().map_err(ids)?;
        sys::setresgid(Some(gid), Some(gid), Some(gid)).map_err(ids)?;
        // (Permitted capabilities kept through the change of user, for the next step to drop the
        // bounding set with; every other thread's go with the change, which is the point.)
        sys::keep_caps(true).map_err(ids)?;
        sys::setresuid(Some(uid), Some(uid), Some(uid)).map_err(ids)?;
        sys::keep_caps(false).map_err(ids)
    }

    fn capabilities(&mut self) -> Result<(), String> {
        use kith_dm_sys as sys;
        let ids = |e: std::io::Error| e.to_string();
        // Effective again from the permitted ones kept: dropping from the bounding set needs one.
        let [_, permitted, inheritable] = sys::capget().map_err(ids)?;
        sys::capset([permitted, permitted, inheritable]).map_err(ids)?;
        for cap in 0..64 {
            // (EINVAL: no such capability here.)
            if let Err(e) = sys::bounding_drop(cap)
                && e.raw_os_error() != Some(22)
            {
                return Err(format!("the bounding set, capability {cap}: {e}"));
            }
        }
        sys::ambient_clear().map_err(ids)?;
        sys::capset([0; 3]).map_err(ids)?;
        match sys::capget().map_err(ids)? {
            [0, 0, 0] => Ok(()),
            left => Err(format!("capabilities left: {left:x?}")),
        }
    }

    fn no_new_privs(&mut self) -> Result<(), String> {
        kith_dm_sys::no_new_privs().map_err(|e| e.to_string())
    }

    fn seccomp(&mut self) -> Result<(), String> {
        kith_dm_sys::seccomp_serving().map_err(|e| e.to_string())
    }
}

/// Started as `kithd confine-probe DIR [--no-filter] [--hold-dir]`? Then this never returns: the
/// confinement held to what it says (see the top of this file). `--hold-dir`: a directory of the
/// node is open when it confines, which it must refuse (it says so, and ends well).
#[cfg(feature = "confine-probe")]
pub fn probe_shim() {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("confine-probe")) {
        return;
    }
    let state = args.next().map(PathBuf::from).unwrap_or_default();
    let rest: Vec<_> = args.collect();
    let has = |flag: &str| rest.iter().any(|a| a == flag);
    let filter = !has("--no-filter");
    let hold = has("--hold-dir").then(|| std::fs::File::open("/etc"));
    let plan = Plan {
        state: state.clone(),
        uid: SERVING_ID,
        gid: SERVING_ID,
        filter,
    };
    // The state directory is the serving part's, as the root part makes it before.
    let given = std::fs::create_dir_all(&state)
        .and_then(|()| std::os::unix::fs::chown(&state, Some(SERVING_ID), Some(SERVING_ID)));
    let listeners = || std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("listening: {e}"));
    let store = || std::fs::File::create(state.join("store")).map_err(|e| format!("the store: {e}"));
    let done = given
        .map_err(|e| format!("the state directory's owner: {e}"))
        .and_then(|()| serving(&mut System, &plan, listeners, store));
    if let Some(dir) = hold {
        // (Refused, with the directory still open and nothing done: not a half-made confinement.)
        let refused = matches!(&done, Err(e) if e.contains("holds directories open"));
        println!(
            "confine: hold {}",
            if dir.is_ok() && refused { "refused" } else { "ALLOWED" }
        );
        std::process::exit(0);
    }
    let done = done.and_then(|(listener, store)| report(&plan, listener, store));
    if let Err(e) = done {
        eprintln!("kithd: confine-probe: {e}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

/// One line each: what the process is, and each thing it must not do, tried.
#[cfg(feature = "confine-probe")]
fn report(plan: &Plan, listener: std::net::TcpListener, mut store: std::fs::File) -> Result<(), String> {
    use std::io::Write;
    let say = |line: String| println!("confine: {line}");
    let status = std::fs::read_to_string("/proc/self/status").map_err(|e| format!("status: {e}"))?;
    status
        .lines()
        .filter(|line| {
            ["Uid:", "Gid:", "Groups:", "Cap", "NoNewPrivs:", "Seccomp:"]
                .iter()
                .any(|k| line.starts_with(k))
        })
        .for_each(|line| say(format!("status {line}")));
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| format!("mountinfo: {e}"))?;
    mounts.lines().for_each(|line| say(format!("mountinfo {line}")));
    // What still works: the listener takes a connection, the store is written.
    let at = listener.local_addr().map_err(|e| e.to_string())?;
    let _client = std::net::TcpStream::connect(at).map_err(|e| format!("connecting: {e}"))?;
    listener.accept().map_err(|e| format!("accepting: {e}"))?;
    store.write_all(b"written\n").map_err(|e| format!("the store: {e}"))?;
    say("serves ok".into());
    // What does not: each is `refused` or `ALLOWED`.
    let word = |refused: bool| if refused { "refused" } else { "ALLOWED" };
    let uid = kith_dm_sys::setresuid(Some(0), Some(0), Some(0));
    say(format!("setuid {}", word(uid.is_err())));
    let cap = kith_dm_sys::capset([1 << 21; 3]);
    say(format!("capability {}", word(cap.is_err())));
    // (The node's disk: nothing of it is in the root, and a device of it is not a name there.)
    let names: Vec<_> = std::fs::read_dir("/")
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect();
    let on_disk = std::fs::File::open("/etc/passwd").is_ok() || std::fs::read_dir("/dev").is_ok();
    say(format!("root {names:?}"));
    say(format!("disk {}", word(!on_disk)));
    // (Its /proc: no process of another user listed, and nothing of the node's that is no process's.)
    let me = std::process::id().to_string();
    let others: Vec<_> = std::fs::read_dir("/proc")
        .map_err(|e| format!("proc: {e}"))?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.bytes().all(|b| b.is_ascii_digit()) && *n != me)
        .collect();
    say(format!("procs {} {others:?}", word(others.is_empty())));
    let global = ["sys", "kcore", "mounts", "net", "modules"].map(|n| Path::new("/proc").join(n).exists());
    say(format!("proc-global {} {global:?}", word(global.iter().all(|g| !g))));
    let mounted = nix::mount::mount(
        Some("tmpfs"),
        &plan.state,
        Some("tmpfs"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    );
    say(format!("mount {}", word(mounted.is_err())));
    // A call the filter alone refuses (any process may make it).
    let call = nix::unistd::getpgid(None);
    say(format!(
        "filter {}",
        if plan.filter { word(call.is_err()) } else { "off" }
    ));
    // What a filter alone must refuse in the calls it allows in part: a namespace made by clone
    // (each flag), clone3 (not there), a push of input into a terminal, a socket of a family the
    // part has no use for (netlink).
    use kith_dm_sys::Try;
    use nix::errno::Errno;
    let is = |t: Try, errno: Errno| kith_dm_sys::try_call(t).is_err_and(|e| e.raw_os_error() == Some(errno as i32));
    // CLONE_NEWUSER, and each other kind of namespace with it: with the user namespace a process
    // with no capability makes any of them, so the kernel lets every one through and only the filter
    // is what refuses (the run with --no-filter shows it: they are `made` there).
    const NEWUSER: u64 = 0x1000_0000;
    // (NEWNS, NEWNET, NEWPID, NEWIPC, NEWUTS, NEWCGROUP.)
    let kinds: [u64; 6] = [
        0x0002_0000,
        0x4000_0000,
        0x2000_0000,
        0x0800_0000,
        0x0400_0000,
        0x0200_0000,
    ];
    let namespaces = std::iter::once(NEWUSER).chain(kinds.iter().map(|f| NEWUSER | f));
    let clone = if plan.filter {
        word(namespaces.clone().all(|f| is(Try::Clone(f), Errno::EPERM)))
    } else if namespaces.clone().all(|f| kith_dm_sys::try_call(Try::Clone(f)).is_ok()) {
        "made"
    } else {
        "NOT_MADE"
    };
    say(format!("clone {clone}"));
    let tries = [
        ("clone3", is(Try::Clone3, Errno::ENOSYS)),
        ("ioctl", is(Try::Tiocsti, Errno::EPERM)),
        ("socket", is(Try::Socket(16), Errno::EPERM)),
    ];
    for (name, refused) in tries {
        say(format!("{name} {}", if plan.filter { word(refused) } else { "off" }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake of the steps: what each did, in order, in `log` (shared with the listeners and the store).
    struct Fake<'a> {
        log: &'a std::cell::RefCell<Vec<String>>,
        fails: Option<&'static str>,
    }

    impl Fake<'_> {
        fn step(&mut self, name: &'static str) -> Result<(), String> {
            self.log.borrow_mut().push(name.into());
            if self.fails == Some(name) {
                Err("no".into())
            } else {
                Ok(())
            }
        }
    }

    impl Steps for Fake<'_> {
        fn mount_namespace(&mut self, keep: &Path) -> Result<(), String> {
            assert_eq!(keep, Path::new("/state"));
            self.step("mount namespace")
        }
        fn ids(&mut self, uid: u32, gid: u32) -> Result<(), String> {
            assert_eq!((uid, gid), (SERVING_ID, SERVING_ID));
            self.step("ids")
        }
        fn capabilities(&mut self) -> Result<(), String> {
            self.step("capabilities")
        }
        fn no_new_privs(&mut self) -> Result<(), String> {
            self.step("no_new_privs")
        }
        fn seccomp(&mut self) -> Result<(), String> {
            self.step("seccomp")
        }
    }

    fn plan(filter: bool) -> Plan {
        Plan {
            state: "/state".into(),
            uid: SERVING_ID,
            gid: SERVING_ID,
            filter,
        }
    }

    fn run(plan: &Plan, fails: Option<&'static str>) -> (Result<(u8, u8), String>, Vec<String>) {
        let log = std::cell::RefCell::new(Vec::new());
        let opened = |what: &'static str, gave: u8| {
            let log = &log;
            move || {
                log.borrow_mut().push(what.to_string());
                Ok(gave)
            }
        };
        let done = serving(
            &mut Fake { log: &log, fails },
            plan,
            opened("listeners", 1),
            opened("store", 2),
        );
        (done, log.into_inner())
    }

    #[test]
    fn confine_runs_in_order_after_the_listeners_and_the_store_are_open() {
        let (done, log) = run(&plan(true), None);
        assert_eq!(done, Ok((1, 2)));
        assert_eq!(
            log,
            [
                "listeners",
                "store",
                "mount namespace",
                "ids",
                "capabilities",
                "no_new_privs",
                "seccomp"
            ]
        );
    }

    #[test]
    fn confine_without_the_filter_runs_no_seccomp() {
        let (done, log) = run(&plan(false), None);
        assert!(done.is_ok());
        assert_eq!(log.last().map(String::as_str), Some("no_new_privs"));
    }

    #[test]
    fn confine_ends_at_the_first_step_that_fails_and_serves_nothing() {
        for failing in ["mount namespace", "ids", "capabilities", "no_new_privs", "seccomp"] {
            let (done, log) = run(&plan(true), Some(failing));
            let said = done.expect_err("a step failed");
            assert!(said.starts_with("confining: "), "{said}");
            assert_eq!(
                log.last().map(String::as_str),
                Some(failing),
                "nothing after the failed step"
            );
        }
    }

    #[test]
    fn confine_with_a_failed_listener_or_store_does_not_begin() {
        let log = std::cell::RefCell::new(Vec::new());
        let done = serving(
            &mut Fake { log: &log, fails: None },
            &plan(true),
            || Err::<(), _>("in use".to_string()),
            || Ok(()),
        );
        assert_eq!(done, Err("in use".to_string()));
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn confine_reads_back_the_options_of_a_mount() {
        let at = Path::new("/run/s/var/lib/kith/a");
        let info = "40 30 8:1 / /run/s rw - tmpfs tmpfs rw\n\
                    45 40 8:1 /a /run/s/var/lib/kith/a rw,nosuid,nodev,noexec,noatime - ext4 /dev/x rw";
        assert_eq!(lacking(info, at, &["nosuid", "nodev", "noexec"]), None);
        let bare = info.replace(",noexec", "");
        assert!(lacking(&bare, at, &["noexec"]).is_some_and(|l| l.contains("/run/s/var/lib/kith/a")));
        // (A mount not there is not one that holds.)
        assert!(lacking(info, Path::new("/run/s/other"), &["noexec"]).is_some());
    }

    #[test]
    fn confine_keeps_only_a_directory_named_plainly() {
        assert_eq!(plain(Path::new("/var/lib/kith/a")), Ok(PathBuf::from("var/lib/kith/a")));
        assert_eq!(plain(Path::new("/var/./lib")), Ok(PathBuf::from("var/lib")));
        // (`..` would put the bind outside the new root; "/" would make the state the root.)
        for refused in ["/var/../etc", "/..", "/", "", "var/lib", "/var/lib/.."] {
            assert!(plain(Path::new(refused)).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn confine_finds_the_directories_and_o_path_descriptors_a_process_holds() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let dir = std::fs::File::open("/").expect("the root");
        // (O_PATH on a file that is no directory: a way to a directory's tree all the same, through
        // the descriptor's mount.)
        let path = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0o10_000_000)
            .open(std::env::current_exe().expect("this test's file"))
            .expect("O_PATH");
        let plain_file = std::fs::File::open(std::env::current_exe().expect("this test's file")).expect("a file");
        let held = held_directories().expect("the descriptors are listed");
        let has = |fd: i32| held.iter().any(|h| h.starts_with(&format!("fd {fd} ")));
        assert!(has(dir.as_raw_fd()), "{held:?}");
        assert!(has(path.as_raw_fd()), "{held:?}");
        assert!(!has(plain_file.as_raw_fd()), "a file read is no way out: {held:?}");
    }

    #[test]
    fn confine_reads_o_path_from_the_flags_of_a_descriptor() {
        assert!(opened_for_path("pos:\t0\nflags:\t010000000\nmnt_id:\t26\n"));
        assert!(opened_for_path("pos:\t0\nflags:\t012000000\nmnt_id:\t26\n"));
        assert!(!opened_for_path("pos:\t0\nflags:\t02000000\nmnt_id:\t26\n"));
        assert!(!opened_for_path("nothing of the kind"));
    }

    #[test]
    fn confine_refuses_to_stay_root_or_to_keep_a_relative_directory() {
        for plan in [
            Plan { uid: 0, ..plan(true) },
            Plan { gid: 0, ..plan(true) },
            Plan {
                state: "state".into(),
                ..plan(true)
            },
            Plan {
                state: "/state/../etc".into(),
                ..plan(true)
            },
            Plan {
                state: "/".into(),
                ..plan(true)
            },
        ] {
            let (done, log) = run(&plan, None);
            assert!(done.is_err());
            assert!(log.is_empty(), "nothing is opened for a plan that is refused: {log:?}");
        }
    }
}
