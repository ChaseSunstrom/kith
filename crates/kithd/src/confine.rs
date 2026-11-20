//! The serving part's confinement (docs/adr-privilege.md, "The serving part"): what it still
//! reaches once its listeners and its store are open is its own state directory, and nothing that
//! makes the machine different.
//!
//! The steps are [`Steps`], run by [`serving`] in this order, each after the one before: a mount
//! namespace holding only the state directory (and `/proc`), a user and group id that are not 0
//! (no supplementary group), every capability set emptied (the bounding set included), no_new_privs
//! and, last, a seccomp allow-list ([`Plan::filter`] off is `--no-filter`, for a call the list
//! misses). A step that fails ends the confinement there with an error, and the caller ends: a
//! serving part half confined serves nothing.
//!
//! All five are the calling thread's (the filter and the user ids every thread's). A thread made
//! before keeps the mount namespace and the bounding set it had, so the serving part runs this
//! while it is one thread, and what it starts after, it starts confined.
//!
//! `kithd confine-probe DIR` is the process this is held to: it opens a listener and a file in `DIR`
//! as root, confines itself, then says what it is (its status, its mounts) and what it still can do.
//! (ci/vm/privilege.sh reads it.)

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
    if !plan.state.is_absolute() {
        return Err(format!(
            "the state directory {} is not an absolute path",
            plan.state.display()
        ));
    }
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
        kith_dm_sys::unshare_mounts().map_err(|e| said("unshare")(&e))?;
        // What the node mounts after this must not reach in, nor what is done here reach out.
        mount(none, "/", none, MsFlags::MS_REC | MsFlags::MS_PRIVATE, none).map_err(|e| said("private")(&e))?;
        let root = Path::new(ROOT);
        std::fs::create_dir_all(root).map_err(|e| said("the new root")(&e))?;
        let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
        mount(Some("tmpfs"), root, Some("tmpfs"), flags, Some("size=1m,mode=0755")).map_err(|e| said("tmpfs")(&e))?;
        let inside = |at: &Path| root.join(at.strip_prefix("/").unwrap_or(at));
        // (`/proc` alone, not what is mounted under it: the mounts of this namespace are the two.)
        let bind = |from: &Path, tree: MsFlags, extra: MsFlags| -> Result<(), String> {
            let to = inside(from);
            std::fs::create_dir_all(&to).map_err(|e| said("a mount point")(&e))?;
            mount(Some(from), &to, none, MsFlags::MS_BIND | tree, none).map_err(|e| said("bind")(&e))?;
            let again = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | flags | extra;
            mount(none, &to, none, again, none).map_err(|e| said("remount")(&e))
        };
        bind(keep, MsFlags::MS_REC, MsFlags::empty())?;
        bind(
            Path::new("/proc"),
            MsFlags::empty(),
            MsFlags::MS_RDONLY | MsFlags::MS_NOEXEC,
        )?;
        let old = root.join(".old");
        std::fs::create_dir(&old).map_err(|e| said("the old root")(&e))?;
        nix::unistd::pivot_root(root, &old).map_err(|e| said("pivot_root")(&e))?;
        nix::unistd::chdir("/").map_err(|e| said("chdir")(&e))?;
        umount2("/.old", MntFlags::MNT_DETACH).map_err(|e| said("umount")(&e))?;
        std::fs::remove_dir("/.old").map_err(|e| said("the old root")(&e))?;
        let ro = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | flags;
        mount(none, "/", none, ro, none).map_err(|e| said("read only")(&e))
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

/// Started as `kithd confine-probe DIR [--no-filter]`? Then this never returns: the confinement
/// held to what it says (see the top of this file).
pub fn probe_shim() {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("confine-probe")) {
        return;
    }
    let state = args.next().map(PathBuf::from).unwrap_or_default();
    let filter = args.next().as_deref() != Some(std::ffi::OsStr::new("--no-filter"));
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
        .and_then(|()| serving(&mut System, &plan, listeners, store))
        .and_then(|(listener, store)| report(&plan, listener, store));
    if let Err(e) = done {
        eprintln!("kithd: confine-probe: {e}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

/// One line each: what the process is, and each thing it must not do, tried.
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
    // (each flag), clone3 (not there), and a push of input into a terminal.
    use kith_dm_sys::Try;
    use nix::errno::Errno;
    let is = |t: Try, errno: Errno| kith_dm_sys::try_call(t).is_err_and(|e| e.raw_os_error() == Some(errno as i32));
    // (CLONE_NEWUSER, NEWNS, NEWNET, NEWPID, NEWIPC, NEWUTS, NEWCGROUP.)
    let namespaces: [u64; 7] = [
        0x1000_0000,
        0x0002_0000,
        0x4000_0000,
        0x2000_0000,
        0x0800_0000,
        0x0400_0000,
        0x0200_0000,
    ];
    let tries = [
        ("clone", namespaces.iter().all(|f| is(Try::Clone(*f), Errno::EPERM))),
        ("clone3", is(Try::Clone3, Errno::ENOSYS)),
        ("ioctl", is(Try::Tiocsti, Errno::EPERM)),
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
    fn confine_refuses_to_stay_root_or_to_keep_a_relative_directory() {
        for plan in [
            Plan { uid: 0, ..plan(true) },
            Plan { gid: 0, ..plan(true) },
            Plan {
                state: "state".into(),
                ..plan(true)
            },
        ] {
            let (done, log) = run(&plan, None);
            assert!(done.is_err());
            assert!(log.is_empty(), "nothing is opened for a plan that is refused: {log:?}");
        }
    }
}
