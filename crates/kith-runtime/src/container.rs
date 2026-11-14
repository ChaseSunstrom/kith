//! Running one container from an [`Image`].

use crate::{Context, Image, ImageStore, Result, err};
use caps::CapSet;
use libcgroups::common::{CgroupManager, ControllerOpt};
use libcontainer::container::Container;
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;
use libcontainer::workload::default::DefaultExecutor;
use libcontainer::workload::{Executor, ExecutorError, ExecutorValidationError};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use oci_spec::runtime::{
    Capability, LinuxCapabilitiesBuilder, LinuxCpuBuilder, LinuxDevice, LinuxDeviceBuilder, LinuxDeviceCgroup,
    LinuxDeviceCgroupBuilder, LinuxDeviceType, LinuxMemoryBuilder, LinuxResources, LinuxResourcesBuilder, MountBuilder,
    RootBuilder, Spec, UserBuilder,
};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// First argument of the helper an exec unit starts as (see [`exec_shim`]).
const SHIM: &str = "--kith-exec-unit";
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Call this first thing in `main` of the program that owns a [`Runtime`].
///
/// [`Runtime::exec`] starts that program again as a helper: it waits until its cgroup
/// and limits are in place, then becomes the unit's command. That way the command
/// never runs a single instruction outside its cgroup, and no shell is needed.
/// Returns at once when the process is not such a helper.
pub fn exec_shim() {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new(SHIM)) {
        return;
    }
    // One byte means go. End of input without it: the parent gave up or died.
    let mut go = [0u8];
    if !matches!(std::io::Read::read(&mut std::io::stdin(), &mut go), Ok(1)) {
        std::process::exit(125);
    }
    let Some(command) = args.next() else {
        std::process::exit(127);
    };
    let e = Command::new(&command).args(args).stdin(Stdio::null()).exec();
    eprintln!("{}: {e}", command.to_string_lossy());
    std::process::exit(127);
}

pub struct Runtime {
    root: PathBuf,
    cgroup_parent: String,
    pub images: ImageStore,
    /// The program [`Runtime::exec`] starts as its helper: this one, which must call [`exec_shim`].
    pub shim: PathBuf,
}

/// What to run. Everything is already resolved: the controller turns a
/// `Workload`'s container (quantities, secrets, config maps) into this.
#[derive(Debug, Clone, Default)]
pub struct Unit {
    /// Replaces the image's entrypoint when not empty.
    pub command: Vec<String>,
    /// Replaces the image's default arguments when not empty.
    pub args: Vec<String>,
    /// Added to, and overriding, the image's environment.
    pub env: Vec<(String, String)>,
    pub working_dir: Option<String>,
    pub memory_bytes: Option<u64>,
    /// Thousandths of a CPU: 500 is half a core.
    pub cpu_millis: Option<u64>,
    /// Host device nodes the container is given (and allowed in its cgroup), e.g. `/dev/dri/card0`.
    /// An exec unit ignores them: it sees all of `/dev` already.
    pub devices: Vec<PathBuf>,
    /// Host directories bound into the container. An exec unit gets none: it has no mount namespace.
    pub mounts: Vec<Mount>,
    /// The user (and group) the container's process is: `None` is the image's own, or 65534
    /// where the image names none. An exec unit ignores it: it is kithd's user.
    pub user: Option<u32>,
    /// No filter on its system calls. An exec unit has none either way.
    pub unconfined: bool,
    /// Calls the filter refuses that this container may make: names of [`crate::REFUSED`].
    pub allow: Vec<String>,
}

/// A host directory bound into a container: where it is, where the container sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Mount {
    /// An absolute path on the host.
    pub host: PathBuf,
    /// An absolute path in the container, not `/` nor under `/proc`, `/sys` or `/dev`.
    pub container: String,
    pub read_only: bool,
    /// A directory kith made for this: where kithd is root and the container's user is
    /// not, it is made that user's, with all that is in it, unless it is theirs already.
    pub give: bool,
}

/// A created container or exec unit. Dropping it does not stop it; call [`Handle::delete`].
pub struct Handle {
    /// `None` for an exec unit.
    container: Option<Container>,
    /// An exec unit's helper waits on this for the word to go.
    go: Option<std::process::ChildStdin>,
    pid: Pid,
    /// Its exit status has been collected; the pid may belong to something else by now.
    reaped: bool,
    bundle: PathBuf,
    /// Path of the container's cgroup under `/sys/fs/cgroup`.
    pub cgroup: PathBuf,
}

impl Runtime {
    /// A runtime keeping images, bundles and container state under `root`.
    ///
    /// Makes the calling process a child subreaper, so containers stay its
    /// children and [`Handle::wait`] can collect their exit codes.
    pub fn new(root: impl Into<PathBuf>) -> Result<Runtime> {
        let root = root.into();
        let images = ImageStore::new(&root)?;
        fs::create_dir_all(root.join("containers")).ctx("creating the runtime directory")?;
        fs::create_dir_all(root.join("state")).ctx("creating the runtime directory")?;
        nix::sys::prctl::set_child_subreaper(true).ctx("becoming a child subreaper")?;
        Ok(Runtime {
            root,
            cgroup_parent: cgroup_parent()?,
            images,
            // Not `current_exe()`: after an upgrade replaces the file, that names a path that is gone.
            shim: "/proc/self/exe".into(),
        })
    }

    /// Kill and remove every container a previous owner of `root` left behind,
    /// e.g. after a crash. Returns how many there were.
    pub fn cleanup(&self) -> Result<usize> {
        let mut found = 0;
        for entry in fs::read_dir(self.root.join("state"))
            .ctx("listing old containers")?
            .flatten()
        {
            found += 1;
            // State we cannot load is removed below along with the bundle.
            if let Ok(mut container) = Container::load(entry.path()) {
                let _ = container.delete(true);
            }
            // An exec unit has no container state, only its cgroup.
            let name = entry.file_name();
            let _ = manager(&format!("{}/kith-{}", self.cgroup_parent, name.to_string_lossy())).remove();
            let _ = fs::remove_dir_all(entry.path());
            let _ = fs::remove_dir_all(self.root.join("containers").join(name));
        }
        Ok(found)
    }

    /// Create the container `id`: namespaces and cgroup are set up and the
    /// process is ready, but it does not run until [`Handle::start`].
    ///
    // ponytail: the image's rootfs is shared read-only, with tmpfs on /tmp and /run,
    // and the host's network. A writable overlay per container and a network
    // namespace of its own are not there: volumes are where a container writes.
    pub fn create(&self, id: &str, image: &Image, unit: &Unit, stdout: File, stderr: File) -> Result<Handle> {
        let what = format!("creating container `{id}`");
        let bundle = self.root.join("containers").join(id);
        let cgroup = format!("{}/kith-{id}", self.cgroup_parent);

        // Validate the id before it is used as a directory name.
        let builder = ContainerBuilder::new(id.into(), SyscallType::Linux)
            .validate_id()
            .ctx(&what)?;
        let spec = spec(id, image, unit, &cgroup).ctx(&what)?;
        // (The spec names a user only where kithd is root: see `spec`.)
        let user = spec.process().as_ref().map(|process| process.user());
        if let Some(user) = user.filter(|user| user.uid() != 0) {
            for volume in unit.mounts.iter().filter(|volume| volume.give && !volume.read_only) {
                give(&volume.host, user.uid(), user.gid()).ctx(format!(
                    "{what}: giving {} to user {}",
                    volume.host.display(),
                    user.uid()
                ))?;
            }
        }
        fs::create_dir_all(&bundle).ctx(&what)?;
        let built = (|| {
            spec.save(bundle.join("config.json")).ctx(&what)?;
            let container = builder
                .with_root_path(self.root.join("state"))
                .ctx(&what)?
                // Never the caller's stdin: a container must not read kithd's terminal.
                .with_stdin(File::open("/dev/null").ctx(&what)?)
                .with_stdout(stdout)
                .with_stderr(stderr)
                .with_executor(Entry)
                .as_init(&bundle)
                .with_systemd(false)
                .with_detach(true)
                .build()
                .ctx(&what)?;
            match container.pid() {
                Some(pid) => Ok((container, pid)),
                None => err(format!("{what}: no process was created")),
            }
        })();
        if built.is_err() {
            // Nothing half-made stays behind to block the next attempt.
            let _ = fs::remove_dir_all(self.root.join("state").join(id));
            let _ = fs::remove_dir_all(&bundle);
        }
        let (container, pid) = built?;
        let handle = Handle {
            container: Some(container),
            go: None,
            pid,
            reaped: false,
            bundle,
            cgroup: Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/')),
        };
        handle.no_swap(unit, &what)
    }

    /// Create the exec unit `id`: `unit.command` as a plain process of this host (its
    /// files, its network, our user) in its own cgroup with the unit's limits. Like a
    /// container it does not run until [`Handle::start`].
    pub fn exec(&self, id: &str, unit: &Unit, stdout: File, stderr: File) -> Result<Handle> {
        let what = format!("creating exec unit `{id}`");
        ContainerBuilder::new(id.into(), SyscallType::Linux)
            .validate_id()
            .ctx(&what)?;
        let Some((command, args)) = unit.command.split_first() else {
            return err(format!("{what}: no command was given"));
        };
        let limits = resources(unit).ctx(&what)?;
        let cgroup = format!("{}/kith-{id}", self.cgroup_parent);
        // Marks the id as taken, and tells `cleanup` about the cgroup after a crash.
        let marker = self.root.join("state").join(id);
        fs::create_dir(&marker).ctx(&what)?;
        let child = Command::new(&self.shim)
            .arg(SHIM)
            .arg(command)
            .args(args)
            .args(&unit.args)
            .env_clear()
            .env("PATH", DEFAULT_PATH)
            .envs(unit.env.iter().cloned())
            .current_dir(unit.working_dir.as_deref().unwrap_or("/"))
            .stdin(Stdio::piped())
            .stdout(stdout)
            .stderr(stderr)
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(e) => {
                let _ = fs::remove_dir(&marker);
                return Err(e).ctx(&what);
            }
        };
        // From here the handle owns the process: std's `Child` neither kills nor reaps on drop.
        let handle = Handle {
            container: None,
            go: child.stdin.take(),
            pid: Pid::from_raw(child.id() as i32),
            reaped: false,
            bundle: marker,
            cgroup: Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/')),
        };
        let manager = manager(&cgroup);
        let options = ControllerOpt {
            resources: &limits,
            disable_oom_killer: false,
            oom_score_adj: None,
            freezer_state: None,
        };
        // Creates the cgroup with the helper in it; the helper has not run the command yet.
        let confined = manager
            .add_task(handle.pid)
            .and_then(|()| manager.apply(&options))
            .ctx(&what);
        match confined {
            Ok(()) => handle.no_swap(unit, &what),
            Err(e) => {
                let _ = handle.delete();
                Err(e)
            }
        }
    }
}

/// The children someone waits for besides the handles' (see [`spawn_awaited`]).
static AWAITED: std::sync::Mutex<Vec<i32>> = std::sync::Mutex::new(Vec::new());

/// A child whose exit status is its starter's to collect, for as long as this lives.
pub struct Awaited(i32);

impl Drop for Awaited {
    fn drop(&mut self) {
        let mut awaited = AWAITED.lock().expect("nothing panics holding the list");
        awaited.retain(|pid| *pid != self.0);
    }
}

/// Start a child (`spawn`, whose process is `pid`) that [`reap_orphans`] leaves to its
/// starter: without this the reaper may collect it first, and its starter never learns
/// how it ended.
pub fn spawn_awaited<C>(
    spawn: impl FnOnce() -> std::io::Result<C>,
    pid: impl Fn(&C) -> Option<u32>,
) -> std::io::Result<(C, Awaited)> {
    let mut awaited = AWAITED.lock().expect("nothing panics holding the list");
    let child = spawn()?;
    let pid = pid(&child).and_then(|pid| i32::try_from(pid).ok()).unwrap_or(0);
    awaited.push(pid);
    Ok((child, Awaited(pid)))
}

/// Collect the children nobody waits for. As a subreaper this process inherits
/// whatever an exec unit forked and left behind; unreaped, each stays a zombie.
///
/// `mains` are the processes of the handles still held ([`Handle::pid`]): their
/// exit status belongs to [`Handle::try_wait`], so call this after trying those.
pub fn reap_orphans(mains: &[i32]) {
    use nix::sys::wait::{Id, WaitPidFlag, waitid};
    // (Held throughout: nothing is started and taken from its starter in between.)
    let awaited = AWAITED.lock().expect("nothing panics holding the list");
    // WNOWAIT looks without taking, so a handle's status is never taken from it.
    let peek = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
    while let Ok(Some(pid)) = waitid(Id::All, peek).map(|status| status.pid()) {
        if mains.contains(&pid.as_raw()) || awaited.contains(&pid.as_raw()) {
            break; // its handle collects it; whatever queues behind it waits for the next call
        }
        let _ = waitpid(pid, None);
    }
}

/// The most the kernel takes for `cpu.weight` and `io.weight` (the default is 100): a unit with
/// a guarantee goes before everything else on the node when they want the same CPU or disk.
const TOP_WEIGHT: u32 = 10_000;

/// Say in a running unit's cgroup (`Handle::cgroup`) what it is guaranteed and how much CPU it
/// may use: `guaranteed` bytes of memory that are not reclaimed from it, with the top weights
/// (none: no guarantee, the default weights), and `cpu_millis` thousandths of a CPU (none: no
/// limit). What could not be written is returned in plain words, and the rest is written
/// anyway: a kernel or a cgroup without the io controller still gives the memory and the CPU.
pub fn tune(cgroup: &Path, guaranteed: Option<u64>, cpu_millis: Option<u64>) -> Vec<String> {
    let weight = if guaranteed.is_some() { TOP_WEIGHT } else { 100 };
    let cpu = cpu_millis.map_or("max".to_string(), |millis| {
        millis.max(10).saturating_mul(100).to_string()
    });
    let files = [
        ("memory.min", guaranteed.unwrap_or(0).to_string()),
        ("cpu.weight", weight.to_string()),
        ("io.weight", format!("default {weight}")),
        ("cpu.max", format!("{cpu} 100000")),
    ];
    let write = |(file, value): &(&str, String)| {
        let done = fs::write(cgroup.join(file), value);
        done.err().map(|e| format!("{file} = {value}: {e}"))
    };
    files.iter().filter_map(write).collect()
}

fn manager(cgroup: &str) -> libcgroups::v2::manager::Manager {
    libcgroups::v2::manager::Manager::new("/sys/fs/cgroup".into(), cgroup.into()).expect("joining two absolute paths")
}

impl Handle {
    /// A memory limit that swap could stretch is no limit. The OCI resources cannot say
    /// "no swap" (libcgroups reads 0 as "leave it"), so it is written here.
    fn no_swap(self, unit: &Unit, what: &str) -> Result<Handle> {
        if unit.memory_bytes.is_some() {
            match fs::write(self.cgroup.join("memory.swap.max"), "0") {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    let _ = self.delete();
                    return Err(e).ctx(format!("{what}: turning swap off"));
                }
                _ => {} // No such file: this kernel does no swap accounting.
            }
        }
        Ok(self)
    }

    /// The process id of the container's init, or of the exec unit's command.
    pub fn pid(&self) -> i32 {
        self.pid.as_raw()
    }

    pub fn start(&mut self) -> Result<()> {
        match &mut self.container {
            Some(container) => container.start().ctx("starting the container"),
            None => {
                let go = self.go.take().ok_or(crate::Error("it was started before".into()))?;
                std::io::Write::write_all(&mut &go, b"1").ctx("starting the exec unit")
            }
        }
    }

    /// Block until the container's process exits. Returns its exit code, or
    /// 128 + the signal number if a signal killed it (137 for the OOM killer).
    pub fn wait(&mut self) -> Result<i32> {
        loop {
            match waitpid(self.pid, None) {
                Err(nix::errno::Errno::EINTR) => {}
                Ok(WaitStatus::Exited(_, code)) => break self.reaped(code),
                Ok(WaitStatus::Signaled(_, signal, _)) => break self.reaped(128 + signal as i32),
                other => return err(format!("waiting for the container: {other:?}")),
            }
        }
    }

    /// Like [`Handle::wait`], but returns `None` at once if it is still running.
    pub fn try_wait(&mut self) -> Result<Option<i32>> {
        let flags = Some(nix::sys::wait::WaitPidFlag::WNOHANG);
        match waitpid(self.pid, flags).ctx("checking on the container")? {
            WaitStatus::StillAlive => Ok(None),
            WaitStatus::Exited(_, code) => self.reaped(code).map(Some),
            WaitStatus::Signaled(_, signal, _) => self.reaped(128 + signal as i32).map(Some),
            other => err(format!("unexpected wait status {other:?}")),
        }
    }

    fn reaped(&mut self, code: i32) -> Result<i32> {
        self.reaped = true;
        Ok(code)
    }

    pub fn kill(&mut self) -> Result<()> {
        match &mut self.container {
            Some(container) => container
                .kill(nix::sys::signal::Signal::SIGKILL, true)
                .ctx("killing the container"),
            // Everything in the cgroup, whatever the command has forked.
            None => fs::write(self.cgroup.join("cgroup.kill"), "1").ctx("killing the exec unit"),
        }
    }

    /// Kill it if it still runs, then remove its cgroup, state and bundle.
    pub fn delete(mut self) -> Result<()> {
        // A helper still waiting for the word to go ends when its input does.
        drop(self.go.take());
        let deleted = match &mut self.container {
            Some(container) => container.delete(true).ctx("deleting the container"),
            None => {
                let cgroup = self.cgroup.strip_prefix("/sys/fs/cgroup").unwrap_or(&self.cgroup);
                manager(&format!("/{}", cgroup.display()))
                    .remove()
                    .ctx("deleting the exec unit")
            }
        };
        // It was killed just now: collect it, or it stays a zombie for as long as we live.
        if deleted.is_ok() && !self.reaped {
            let _ = waitpid(self.pid, None);
        }
        fs::remove_dir_all(&self.bundle).ctx("deleting the container")?;
        deleted
    }
}

/// Where container cgroups go: `/kith` as root; otherwise next to our own
/// cgroup, in the subtree systemd delegated to this user.
fn cgroup_parent() -> Result<String> {
    if nix::unistd::getuid().is_root() {
        return Ok("/kith".into());
    }
    let own = fs::read_to_string("/proc/self/cgroup").ctx("reading /proc/self/cgroup")?;
    let own = own.lines().find_map(|l| l.strip_prefix("0::")).unwrap_or("/");
    match Path::new(own).parent() {
        Some(parent) if parent != Path::new("/") => Ok(parent.display().to_string()),
        _ => err("no delegated cgroup: run kith inside a systemd user session or scope"),
    }
}

/// Processes and threads one container may have.
const MAX_PIDS: i64 = 4096;

/// Who a container's process is where neither its template nor its image says.
pub const NOBODY: u32 = 65534;

/// The lines of the image's own `/etc/FILE`, split at the colons. Never through a link:
/// an image says where its own files are, not where the host's are.
fn listed(image: &Image, file: &str) -> Vec<Vec<String>> {
    let etc = image.rootfs.join("etc");
    let is = |path: &Path, dir: bool| {
        fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir() == dir && !meta.is_symlink())
    };
    if !is(&etc, true) || !is(&etc.join(file), false) {
        return Vec::new();
    }
    let text = fs::read_to_string(etc.join(file)).unwrap_or_default();
    let fields = |line: &str| line.split(':').map(String::from).collect();
    text.lines().map(fields).collect()
}

/// The user and group a container's process is: the template's, else the image's own
/// (a number, or a name of its `/etc/passwd`), else nobody. User 0 only when the
/// template says so: an image that asks for it gets nobody.
fn who(image: &Image, unit: &Unit) -> std::result::Result<(u32, u32), String> {
    let number = |text: &str| text.parse::<u32>().ok().filter(|id| *id != u32::MAX);
    if let Some(user) = unit.user {
        let user = number(&user.to_string()).ok_or(format!("{user} is not a user"))?;
        return Ok((user, user));
    }
    let Some(said) = image.user.as_deref().filter(|said| !said.is_empty()) else {
        return Ok((NOBODY, NOBODY));
    };
    let (user, group) = said
        .split_once(':')
        .map_or((said, None), |(user, group)| (user, Some(group)));
    // name:x:uid:gid:…
    let users = listed(image, "passwd");
    let entry = users
        .iter()
        .find(|line| line.len() > 3 && (line[0] == user || line[2] == user));
    let uid = number(user).or_else(|| entry.and_then(|line| number(&line[2])));
    let uid = uid.ok_or(format!(
        "the image's user `{user}` is not in its /etc/passwd: say runAsUser"
    ))?;
    let gid = match group {
        None => entry.and_then(|line| number(&line[3])).unwrap_or(uid),
        Some(group) => {
            let groups = listed(image, "group");
            let entry = groups.iter().find(|line| line.len() > 2 && line[0] == group);
            let gid = number(group).or_else(|| entry.and_then(|line| number(&line[2])));
            gid.ok_or(format!(
                "the image's group `{group}` is not in its /etc/group: say runAsUser"
            ))?
        }
    };
    // An image makes its container neither root nor of root's group (which, where there
    // is no user namespace, is the node's own): `runAsUser: 0` is how a template says so.
    Ok(match (uid, gid) {
        (0, _) => (NOBODY, NOBODY),
        (uid, 0) => (uid, uid),
        both => both,
    })
}

/// Where the spec says who the process becomes in a namespace of its own (`USER:GROUP`).
const BECOMES: &str = "dev.kith.becomes";

/// Where the spec says which refused system calls the container is allowed back (names with
/// spaces between), or that it has no filter.
const CALLS: &str = "dev.kith.seccomp";
const UNCONFINED: &str = "unconfined";

/// What happens in a container's first process right before the image's program takes its place.
#[derive(Clone)]
struct Entry;

impl Executor for Entry {
    fn exec(&self, spec: &Spec) -> std::result::Result<(), ExecutorError> {
        let said = spec.annotations().as_ref().and_then(|notes| notes.get(BECOMES));
        if let Some((user, group)) = said.and_then(|said| said.split_once(':')) {
            // Without root there is one user to map, and libcontainer needs it to be 0 while
            // it sets up. So the program gets a user namespace inside that one, where the
            // same one user is the one it is meant to be, and no 0 exists.
            // (Said on the unit's own stderr too: that is where its operator looks.)
            let failed = |what: &str, e: &dyn std::fmt::Display| {
                let said = format!("kith: the container's user {user}:{group}: {what}: {e}\n");
                let _ = std::io::Write::write_all(&mut std::io::stderr(), said.as_bytes());
                ExecutorError::Other(format!("{what}: {e}"))
            };
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER).map_err(|e| failed("a user namespace", &e))?;
            // (A process that changed who it is has files in /proc that only root may
            // write, until it says it may be looked at again.)
            nix::sys::prctl::set_dumpable(true).map_err(|e| failed("its own /proc files", &e))?;
            let wrote = |file: &str, text: String| fs::write(file, text).map_err(|e| failed(file, &e));
            wrote("/proc/self/uid_map", format!("{user} 0 1"))?;
            wrote("/proc/self/setgroups", "deny".into())?;
            wrote("/proc/self/gid_map", format!("{group} 0 1"))?;
            // A new namespace starts with every capability in it: none outlives this.
            for set in [
                CapSet::Bounding,
                CapSet::Inheritable,
                CapSet::Effective,
                CapSet::Permitted,
            ] {
                caps::clear(None, set).map_err(|e| failed("dropping capabilities", &e))?;
            }
        }
        // Last, once nothing above needs a call it refuses. (Not said, the filter is whole.)
        let said = spec.annotations().as_ref().and_then(|notes| notes.get(CALLS));
        if said.map(String::as_str) != Some(UNCONFINED) {
            let allowed: Vec<String> = said
                .iter()
                .flat_map(|said| said.split_whitespace())
                .map(String::from)
                .collect();
            crate::seccomp::filters(&allowed)
                .and_then(|filters| crate::seccomp::install(&filters))
                .map_err(|e| {
                    let _ = std::io::Write::write_all(&mut std::io::stderr(), format!("kith: {e}\n").as_bytes());
                    ExecutorError::Other(e)
                })?;
        }
        DefaultExecutor {}.exec(spec)
    }

    fn validate(&self, spec: &Spec) -> std::result::Result<(), ExecutorValidationError> {
        DefaultExecutor {}.validate(spec)
    }
}

/// Gives a volume to a user: all of it, when its directory is not theirs already (a new
/// volume, one written by root before containers had users, one restored, one whose
/// workload changed its user).
///
/// Each directory is opened as an entry of the one that holds it and never through a link,
/// so a program writing the volume meanwhile cannot have something outside it given away.
//
// ponytail: a walk of the whole volume when its user changes, and two workloads with two
// users on one volume walk it at every start. Idmapped mounts (the files stay as they
// are, each container sees them as its own) when a volume is big enough for that to hurt.
fn give(dir: &Path, uid: u32, gid: u32) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    fn held(dir: &Path) -> io::Result<File> {
        let flags = nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW;
        fs::OpenOptions::new().read(true).custom_flags(flags).open(dir)
    }
    fn walk(dir: File, uid: u32, gid: u32, deeper: u32) -> io::Result<()> {
        for entry in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                std::os::unix::fs::lchown(entry.path(), Some(uid), Some(gid))?;
            } else if deeper == 0 {
                return Err(io::Error::other("directories more than 128 deep"));
            } else {
                walk(held(&entry.path())?, uid, gid, deeper - 1)?;
            }
        }
        // (Last, the top of all included: a walk that was cut short is done again.)
        std::os::unix::fs::fchown(&dir, Some(uid), Some(gid))
    }
    let top = held(dir)?;
    let has = top.metadata()?;
    if (has.uid(), has.gid()) == (uid, gid) {
        return Ok(());
    }
    walk(top, uid, gid, 128)
}

fn spec(id: &str, image: &Image, unit: &Unit, cgroup: &str) -> std::result::Result<Spec, Box<dyn std::error::Error>> {
    spec_of(id, image, unit, cgroup, nix::unistd::getuid(), nix::unistd::getgid())
}

/// [`spec`], for a kithd that is the user `uid`.
fn spec_of(
    id: &str,
    image: &Image,
    unit: &Unit,
    cgroup: &str,
    uid: nix::unistd::Uid,
    gid: nix::unistd::Gid,
) -> std::result::Result<Spec, Box<dyn std::error::Error>> {
    // Who the process is. Where kithd is root it is that user of the node, with nothing
    // root has. Where it is not, the container is a user namespace whose one user is
    // kithd's own, and the program is given a second one inside (`Entry`).
    //
    // ponytail: no user namespace where kithd is root (kith OS): the image's files and the
    // volumes are root's there, and a namespace needs them shifted to its users (idmapped
    // mounts, or a chown of every image). So `runAsUser: 0` on kith OS is the node's root
    // with three capabilities, as before.
    let (user, group) = who(image, unit)?;
    let mut spec = if uid.is_root() {
        Spec::default()
    } else {
        Spec::rootless(uid.as_raw(), gid.as_raw())
    };
    let calls = if unit.unconfined {
        UNCONFINED.to_string()
    } else {
        // (Made here once to find a wrong name before anything is started.)
        crate::seccomp::filters(&unit.allow)?;
        unit.allow.join(" ")
    };
    let mut notes = std::collections::HashMap::from([(CALLS.to_string(), calls)]);
    if !uid.is_root() && user != 0 {
        notes.insert(BECOMES.to_string(), format!("{user}:{group}"));
    }
    spec.set_annotations(Some(notes));
    // No network namespace: containers share the host's network.
    let mut linux = spec.linux().clone().unwrap_or_default();
    let mut namespaces = linux.namespaces().clone().unwrap_or_default();
    namespaces.retain(|ns| ns.typ() != oci_spec::runtime::LinuxNamespaceType::Network);
    linux.set_namespaces(Some(namespaces));
    spec.set_linux(Some(linux));
    spec.set_root(Some(RootBuilder::default().path(&image.rootfs).readonly(true).build()?));
    // Linux refuses hostnames over 64 bytes; ids are ASCII (validated by the caller).
    spec.set_hostname(Some(id.chars().take(63).collect()));

    // Like Kubernetes: `command` replaces the entrypoint and drops the image's
    // default arguments; `args` alone keeps the entrypoint.
    let mut args = if unit.command.is_empty() {
        image.entrypoint.clone()
    } else {
        unit.command.clone()
    };
    match (unit.args.is_empty(), unit.command.is_empty()) {
        (false, _) => args.extend(unit.args.iter().cloned()),
        (true, true) => args.extend(image.cmd.iter().cloned()),
        (true, false) => {}
    }
    if args.is_empty() {
        return Err("nothing to run: the image has no entrypoint and no command was given".into());
    }
    let mut env: Vec<String> = image.env.clone();
    for (name, value) in &unit.env {
        env.retain(|e| e.split_once('=').is_none_or(|(n, _)| n != name));
        env.push(format!("{name}={value}"));
    }
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push(format!("PATH={DEFAULT_PATH}"));
    }
    let mut process = spec.process().clone().unwrap_or_default();
    process.set_args(Some(args));
    process.set_env(Some(env));
    process.set_cwd(
        unit.working_dir
            .clone()
            .or(image.working_dir.clone())
            .unwrap_or("/".into())
            .into(),
    );
    process.set_terminal(Some(false));
    let root = uid.is_root();
    if root {
        // (Its group said once more as the whole list of its groups: with no list,
        // libcontainer leaves the process in kithd's own.)
        let groups = vec![group];
        process.set_user(
            UserBuilder::default()
                .uid(user)
                .gid(group)
                .additional_gids(groups)
                .build()?,
        );
    }
    // Never a way to more than it starts with; and it starts with no capability at all
    // unless it is the namespace's root, who keeps the three a container is given.
    process.set_no_new_privileges(Some(true));
    if user != 0 {
        // (Without root one is left until `Entry` has made the second namespace: the kernel
        // lets a namespace's user 0 be mapped only by who could set file capabilities.
        // The new namespace's are all dropped there, and this one counts for nothing in it.)
        //
        // Where kithd is root, a user of the node keeps one, through every exec: ports under
        // 1024 are what a server is for, and nothing else of root's comes with it.
        let kept = || {
            HashSet::from([if root {
                Capability::NetBindService
            } else {
                Capability::Setfcap
            }])
        };
        let passed = || if root { kept() } else { HashSet::new() };
        let caps = LinuxCapabilitiesBuilder::default().bounding(kept()).effective(kept());
        let caps = caps.permitted(kept()).inheritable(passed()).ambient(passed());
        process.set_capabilities(Some(caps.build()?));
    }
    spec.set_process(Some(process));

    let tmpfs = |at: &str| -> std::result::Result<oci_spec::runtime::Mount, Box<dyn std::error::Error>> {
        let options = ["nosuid", "nodev", "mode=1777"].map(String::from).to_vec();
        Ok(MountBuilder::default()
            .destination(at)
            .typ("tmpfs")
            .source("tmpfs")
            .options(options)
            .build()?)
    };
    let mut mounts = spec.mounts().clone().unwrap_or_default();
    mounts.push(tmpfs("/tmp")?);
    mounts.push(tmpfs("/run")?);
    // The container shares the host's network, so it needs the host's resolver.
    if Path::new("/etc/resolv.conf").exists() {
        let options = ["rbind", "ro"].map(String::from).to_vec();
        let resolv = MountBuilder::default().destination("/etc/resolv.conf").typ("bind");
        mounts.push(resolv.source("/etc/resolv.conf").options(options).build()?);
    }
    for volume in &unit.mounts {
        check_mount(volume)?;
        // Not over a mount the container already has (/tmp, /run, its resolv.conf, another volume).
        if mounts.iter().any(|m| m.destination() == Path::new(&volume.container)) {
            return Err(format!("volume path `{}` in the container is already a mount", volume.container).into());
        }
        let mut options = ["rbind", "nosuid", "nodev"].map(String::from).to_vec();
        if volume.read_only {
            options.push("ro".into());
        }
        let bind = MountBuilder::default().destination(&volume.container).typ("bind");
        mounts.push(bind.source(&volume.host).options(options).build()?);
    }
    spec.set_mounts(Some(mounts));

    let mut linux = spec.linux().clone().unwrap_or_default();
    linux.set_cgroups_path(Some(cgroup.into()));
    let mut limits = resources(unit)?;
    // (Made as the container's user's own where kithd is root; where it is not, a node is the
    // host's own, bound in, and opens for whoever kithd's user could open it.)
    let (nodes, allowed) = device_nodes(&unit.devices, root.then_some((user, group)))?;
    if !nodes.is_empty() {
        linux.set_devices(Some(nodes));
        limits.set_devices(Some(allowed));
    }
    linux.set_resources(Some(limits));
    spec.set_linux(Some(linux));
    Ok(spec)
}

/// Whether a volume may be bound where it says: an absolute path of the container's with no `..`,
/// that is not the root and not the kernel's own `/proc`, `/sys` or `/dev`, which a bind over
/// would hide or replace; the host side must be absolute too.
fn check_mount(volume: &Mount) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::path::Component;
    let at = Path::new(&volume.container);
    let parts: Vec<Component> = at.components().collect();
    let plain = volume.container.starts_with('/') && parts.len() > 1;
    let up = parts.contains(&Component::ParentDir);
    let kernel = ["/proc", "/sys", "/dev"].iter().any(|own| at.starts_with(own));
    if !plain || up || kernel {
        let at = &volume.container;
        return Err(format!(
            "volume path `{at}` in the container must be absolute, with no `..`, and not `/` or under /proc, /sys or /dev"
        )
        .into());
    }
    if !volume.host.is_absolute() {
        return Err(format!(
            "volume directory `{}` on the host must be an absolute path",
            volume.host.display()
        )
        .into());
    }
    Ok(())
}

/// The device nodes at `paths` as the container sees them (made in its `/dev`, or bound there
/// when rootless) and the cgroup rules that let it read and write them. A path that is not
/// there, or is not a character device, is an error: the unit is not made without it.
///
/// An exec unit is not given these: it runs on the host and sees all of `/dev` already.
fn device_nodes(
    paths: &[PathBuf],
    owner: Option<(u32, u32)>,
) -> std::result::Result<(Vec<LinuxDevice>, Vec<LinuxDeviceCgroup>), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let (mut nodes, mut allowed) = (Vec::new(), Vec::new());
    for path in paths {
        // Device nodes live in `/dev`: a path from a resource is not trusted to point elsewhere,
        // by `..` or by a link (`/dev/disk/by-id/…`, `/dev/stdin`): it must be its own real path.
        let real = fs::canonicalize(path).map_err(|e| format!("device {}: {e}", path.display()))?;
        if !path.starts_with("/dev") || real != *path {
            return Err(format!("{} is not a device node under /dev", path.display()).into());
        }
        let meta = fs::metadata(path).map_err(|e| format!("device {}: {e}", path.display()))?;
        // A character device only: a disk is not handed out this way (that is a Volume's part).
        if !meta.file_type().is_char_device() {
            return Err(format!("{} is not a character device node", path.display()).into());
        }
        let kind = LinuxDeviceType::C;
        let (major, minor) = (
            i64::try_from(nix::sys::stat::major(meta.rdev()))?,
            i64::try_from(nix::sys::stat::minor(meta.rdev()))?,
        );
        let node = LinuxDeviceBuilder::default()
            .path(path)
            .typ(kind)
            .major(major)
            .minor(minor);
        let node = match owner {
            Some((user, group)) => node.uid(user).gid(group),
            None => node,
        };
        nodes.push(node.file_mode(meta.mode() & 0o777).build()?);
        let rule = LinuxDeviceCgroupBuilder::default().allow(true).typ(kind);
        allowed.push(rule.major(major).minor(minor).access("rw").build()?);
    }
    Ok((nodes, allowed))
}

/// The cgroup limits of a unit.
fn resources(unit: &Unit) -> std::result::Result<LinuxResources, Box<dyn std::error::Error>> {
    // ponytail: one fixed ceiling against fork bombs; make it a Unit field when a workload needs more.
    let pids = oci_spec::runtime::LinuxPidsBuilder::default().limit(MAX_PIDS).build()?;
    let mut resources = LinuxResourcesBuilder::default().pids(pids);
    if let Some(bytes) = unit.memory_bytes {
        if bytes == 0 {
            return Err("a memory limit of 0 leaves nothing to run in".into());
        }
        resources = resources.memory(LinuxMemoryBuilder::default().limit(i64::try_from(bytes)?).build()?);
    }
    if let Some(millis) = unit.cpu_millis {
        // 1000 millis = one full 100 ms period. The kernel wants at least 1 ms of it, and 0 would mean no limit.
        if millis < 10 {
            return Err(format!("a cpu limit of {millis}m is too small: the least is 10m").into());
        }
        let quota = i64::try_from(millis.saturating_mul(100))?;
        resources = resources.cpu(LinuxCpuBuilder::default().quota(quota).period(100_000u64).build()?);
    }
    Ok(resources.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_limits_and_namespaces() {
        let image = Image {
            entrypoint: vec!["/bin/true".into()],
            ..Image::default()
        };
        let unit = |cpu| Unit {
            cpu_millis: cpu,
            memory_bytes: Some(1 << 20),
            ..Unit::default()
        };
        assert!(
            spec("a", &image, &unit(Some(0)), "/kith/a").is_err(),
            "0 would mean unlimited"
        );
        assert!(spec("a", &image, &unit(Some(9)), "/kith/a").is_err());
        let no_memory = Unit {
            memory_bytes: Some(0),
            ..Unit::default()
        };
        assert!(spec("a", &image, &no_memory, "/kith/a").is_err());

        let made = spec(&"x".repeat(100), &image, &unit(Some(500)), "/kith/a").unwrap();
        assert_eq!(made.hostname().as_ref().unwrap().len(), 63);
        let linux = made.linux().as_ref().unwrap();
        let namespaces = linux.namespaces().as_ref().unwrap();
        assert!(
            namespaces
                .iter()
                .all(|ns| ns.typ() != oci_spec::runtime::LinuxNamespaceType::Network)
        );
        let resources = linux.resources().as_ref().unwrap();
        assert_eq!(resources.cpu().as_ref().unwrap().quota(), Some(50_000));
        assert_eq!(resources.pids().as_ref().unwrap().limit(), MAX_PIDS);
        assert_eq!(resources.memory().as_ref().unwrap().limit(), Some(1 << 20));
        assert!(
            linux.devices().as_ref().is_none_or(Vec::is_empty),
            "no claim, no device"
        );
    }

    #[test]
    fn a_device_is_in_the_spec_and_in_the_cgroups_allow_list() {
        let image = Image {
            entrypoint: vec!["/bin/true".into()],
            ..Image::default()
        };
        let with = |path: &str| Unit {
            devices: vec![path.into()],
            ..Unit::default()
        };
        // /dev/null is the character device 1:3.
        let made = spec("a", &image, &with("/dev/null"), "/kith/a").unwrap();
        let linux = made.linux().as_ref().unwrap();
        let [node] = &linux.devices().as_ref().unwrap()[..] else {
            panic!("one device node")
        };
        assert_eq!(node.path(), Path::new("/dev/null"));
        assert_eq!(node.typ(), oci_spec::runtime::LinuxDeviceType::C);
        assert_eq!((node.major(), node.minor()), (1, 3));
        let allowed = linux.resources().as_ref().unwrap().devices().clone().unwrap();
        let rule = allowed.last().expect("an allow rule");
        assert_eq!(
            (rule.allow(), rule.access().as_deref(), rule.major(), rule.minor()),
            (true, Some("rw"), Some(1), Some(3))
        );
        assert_eq!(rule.typ(), Some(oci_spec::runtime::LinuxDeviceType::C));
        // Missing, or not a device node: the unit is not created, and the reason says which.
        let missing = spec("a", &image, &with("/dev/kith-no-such-device"), "/kith/a").unwrap_err();
        assert!(missing.to_string().contains("/dev/kith-no-such-device"), "{missing}");
        let file = spec("a", &image, &with("/etc"), "/kith/a");
        assert!(file.unwrap_err().to_string().contains("not a device node"));
        for out in ["/dev/../dev/null", "/dev/fd", "/dev/shm"] {
            let refused = spec("a", &image, &with(out), "/kith/a").unwrap_err().to_string();
            assert!(refused.contains("device node"), "{out}: {refused}");
        }
    }

    #[test]
    fn a_guarantee_and_a_cpu_limit_are_written_to_the_cgroup_and_a_refused_file_is_said() {
        let cgroup = std::env::temp_dir().join(format!("kith-tune-guarantee-{}", std::process::id()));
        fs::create_dir_all(&cgroup).unwrap();
        let read = |file: &str| fs::read_to_string(cgroup.join(file)).unwrap();
        assert!(tune(&cgroup, Some(4 << 30), None).is_empty());
        assert_eq!(read("memory.min"), "4294967296");
        assert_eq!(
            (read("cpu.weight"), read("io.weight")),
            ("10000".into(), "default 10000".into())
        );
        assert_eq!(read("cpu.max"), "max 100000");
        // Held back to a twentieth of a CPU, with no guarantee: the defaults, and the limit.
        assert!(tune(&cgroup, None, Some(50)).is_empty());
        assert_eq!((read("memory.min"), read("cpu.weight")), ("0".into(), "100".into()));
        assert_eq!(read("cpu.max"), "5000 100000");
        // A file the kernel will not take (here: a directory in its place) is named; the others are written.
        fs::remove_file(cgroup.join("io.weight")).unwrap();
        fs::create_dir(cgroup.join("io.weight")).unwrap();
        let said = tune(&cgroup, Some(1), Some(500));
        assert!(said.len() == 1 && said[0].starts_with("io.weight"), "{said:?}");
        assert_eq!(
            (read("memory.min"), read("cpu.max")),
            ("1".into(), "50000 100000".into())
        );
        let _ = fs::remove_dir_all(cgroup);
    }

    fn mounted(mounts: Vec<Mount>) -> std::result::Result<Spec, Box<dyn std::error::Error>> {
        let image = Image {
            entrypoint: vec!["/bin/true".into()],
            ..Image::default()
        };
        spec(
            "a",
            &image,
            &Unit {
                mounts,
                ..Unit::default()
            },
            "/kith/a",
        )
    }

    fn bind(host: &str, at: &str, read_only: bool) -> Mount {
        Mount {
            host: host.into(),
            container: at.into(),
            read_only,
            give: false,
        }
    }

    /// What the README says every container gets is what the spec says, with nothing asked
    /// for: where kithd is root, and where it is a user.
    #[test]
    fn hardened_is_what_a_plain_unit_gets() {
        use nix::unistd::{Gid, Uid};
        let image = Image {
            entrypoint: vec!["/bin/true".into()],
            ..Image::default()
        };
        let asked = Unit {
            user: Some(0),
            ..Unit::default()
        };
        let sets = |process: &oci_spec::runtime::Process| {
            let caps = process.capabilities().clone().unwrap();
            let sorted = |set: &Option<HashSet<Capability>>| {
                let mut names: Vec<String> = set.iter().flatten().map(|cap| format!("{cap:?}")).collect();
                names.sort();
                names.join(" ")
            };
            [
                caps.bounding(),
                caps.effective(),
                caps.permitted(),
                caps.inheritable(),
                caps.ambient(),
            ]
            .map(sorted)
        };
        let becomes = |made: &Spec| {
            made.annotations()
                .as_ref()
                .and_then(|notes| notes.get(BECOMES).cloned())
        };
        for (root, kithd) in [(true, 0), (false, 1000)] {
            let (uid, gid) = (Uid::from_raw(kithd), Gid::from_raw(kithd));
            let made = spec_of("a", &image, &Unit::default(), "/kith/a", uid, gid).unwrap();
            let process = made.process().as_ref().unwrap();
            assert_eq!(process.no_new_privileges(), Some(true));
            assert_eq!(made.root().as_ref().unwrap().readonly(), Some(true));
            assert_eq!(made.annotations().as_ref().unwrap()[CALLS], "", "the whole filter");
            let user = process.user();
            if root {
                // That user of the node, in no group of kithd's, with the one capability
                // that outlives its start: the one for ports under 1024.
                assert_eq!((user.uid(), user.gid(), becomes(&made)), (NOBODY, NOBODY, None));
                assert_eq!(user.additional_gids(), &Some(vec![NOBODY]));
                assert_eq!(sets(process), ["NetBindService"; 5]);
            } else {
                // The namespace's one user until `Entry` makes it nobody; what it holds
                // meanwhile is for that step, and is not passed on to a program.
                assert_eq!((user.uid(), becomes(&made)), (0, Some(format!("{NOBODY}:{NOBODY}"))));
                assert_eq!(sets(process), ["Setfcap", "Setfcap", "Setfcap", "", ""]);
            }
            // Root when the template says so, and only then: it keeps what a container is given.
            let made = spec_of("a", &image, &asked, "/kith/a", uid, gid).unwrap();
            let process = made.process().as_ref().unwrap();
            assert_eq!((process.user().uid(), process.no_new_privileges()), (0, Some(true)));
            assert_eq!(becomes(&made), None, "no second namespace for root");
            assert_eq!(sets(process)[0], "AuditWrite Kill NetBindService");
        }
        // No filter, or some of it, only as the unit says.
        let (uid, gid) = (Uid::from_raw(0), Gid::from_raw(0));
        let unit = Unit {
            unconfined: true,
            ..Unit::default()
        };
        let made = spec_of("a", &image, &unit, "/kith/a", uid, gid).unwrap();
        assert_eq!(made.annotations().as_ref().unwrap()[CALLS], UNCONFINED);
        let unit = Unit {
            allow: vec!["ptrace".into(), "unshare".into()],
            ..Unit::default()
        };
        let made = spec_of("a", &image, &unit, "/kith/a", uid, gid).unwrap();
        assert_eq!(made.annotations().as_ref().unwrap()[CALLS], "ptrace unshare");
        let unit = Unit {
            allow: vec![UNCONFINED.into()],
            ..Unit::default()
        };
        let said = spec_of("a", &image, &unit, "/kith/a", uid, gid)
            .unwrap_err()
            .to_string();
        assert!(said.contains("`unconfined` is not a call the filter refuses"), "{said}");
    }

    /// A volume is given whole, and nothing a link in it names is: not a file outside, not
    /// what is under a directory outside. (Run as a user with a second group: only root
    /// can give files to another user, and a group of one's own is what a test can give.)
    #[test]
    fn hardened_volume_is_given_whole_and_no_link_is_followed() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let (uid, gid) = (nix::unistd::getuid().as_raw(), nix::unistd::getgid().as_raw());
        let groups = nix::unistd::getgroups().unwrap();
        let Some(other) = groups.iter().map(|group| group.as_raw()).find(|group| *group != gid) else {
            return eprintln!("skipped: this user has one group, so nothing can be given");
        };
        let dir = std::env::temp_dir().join(format!("kith-give-{}", std::process::id()));
        let (volume, outside) = (dir.join("volume"), dir.join("outside"));
        fs::create_dir_all(volume.join("a/b")).unwrap();
        fs::create_dir_all(outside.join("deep")).unwrap();
        for file in ["volume/top", "volume/a/b/file", "outside/file", "outside/deep/file"] {
            fs::write(dir.join(file), "x").unwrap();
        }
        symlink(outside.join("file"), volume.join("a/to-file")).unwrap();
        symlink(&outside, volume.join("a/to-dir")).unwrap();
        let group = |path: &str| fs::symlink_metadata(dir.join(path)).unwrap().gid();

        give(&volume, uid, other).unwrap();
        for given in [
            "volume",
            "volume/top",
            "volume/a",
            "volume/a/b",
            "volume/a/b/file",
            "volume/a/to-file",
        ] {
            assert_eq!(group(given), other, "{given}");
        }
        for kept in ["outside", "outside/file", "outside/deep", "outside/deep/file"] {
            assert_eq!(group(kept), gid, "{kept}");
        }
        // Theirs already: nothing is walked (what is under it is as it was left).
        nix::unistd::chown(&volume.join("a/b/file"), None, Some(gid.into())).unwrap();
        give(&volume, uid, other).unwrap();
        assert_eq!(group("volume/a/b/file"), gid);
        // A volume that is itself a link is not a volume.
        assert!(give(&volume.join("a/to-dir"), uid, other).is_err());
        assert_eq!(group("outside"), gid);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The user is the template's, else the image's (by number, or by name from the image's
    /// own files and never the host's), else nobody; an image cannot ask for 0.
    #[test]
    fn hardened_user_is_the_templates_then_the_images_then_nobody() {
        let dir = std::env::temp_dir().join(format!("kith-who-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(
            dir.join("etc/passwd"),
            "root:x:0:0::/:/bin/sh\napp:x:1000:1001::/:/bin/sh\nsvc:x:1002:0::/:/bin/sh\n",
        )
        .unwrap();
        fs::write(dir.join("etc/group"), "root:x:0:\nstaff:x:50:\n").unwrap();
        let image = |user: Option<&str>| Image {
            rootfs: dir.clone(),
            user: user.map(String::from),
            ..Image::default()
        };
        let of = |user: Option<&str>| who(&image(user), &Unit::default());
        assert_eq!(of(None), Ok((NOBODY, NOBODY)));
        assert_eq!(of(Some("")), Ok((NOBODY, NOBODY)));
        assert_eq!(of(Some("app")), Ok((1000, 1001)));
        assert_eq!(
            of(Some("1000")),
            Ok((1000, 1001)),
            "a number the image lists has its group"
        );
        assert_eq!(of(Some("2000")), Ok((2000, 2000)));
        assert_eq!(of(Some("app:staff")), Ok((1000, 50)));
        assert_eq!(of(Some("2000:3000")), Ok((2000, 3000)));
        assert_eq!(of(Some("root")), Ok((NOBODY, NOBODY)));
        assert_eq!(of(Some("0:0")), Ok((NOBODY, NOBODY)));
        // Nor root's group: on kith OS it would be the node's own group 0.
        assert_eq!(of(Some("1000:0")), Ok((1000, 1000)));
        assert_eq!(of(Some("app:root")), Ok((1000, 1000)));
        assert_eq!(of(Some("svc")), Ok((1002, 1002)));
        assert!(of(Some("nobody-here")).unwrap_err().contains("not in its /etc/passwd"));
        assert!(of(Some("app:nogroup")).unwrap_err().contains("not in its /etc/group"));
        assert!(of(Some("4294967295")).is_err());
        let said = Unit {
            user: Some(7),
            ..Unit::default()
        };
        assert_eq!(who(&image(Some("app")), &said), Ok((7, 7)));
        assert_eq!(
            who(
                &image(Some("app")),
                &Unit {
                    user: Some(0),
                    ..Unit::default()
                }
            ),
            Ok((0, 0))
        );
        // A passwd that is a link (to the host's, say) is not read.
        fs::remove_file(dir.join("etc/passwd")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.join("etc/passwd")).unwrap();
        assert!(of(Some("root")).is_err() && of(Some("daemon")).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_volume_is_a_bind_mount_in_the_spec_and_read_only_when_asked() {
        let made = mounted(vec![bind("/srv/data", "/data", false), bind("/srv/ro", "/ro/x", true)]).unwrap();
        let all = made.mounts().clone().unwrap();
        let at = |dest: &str| all.iter().find(|m| m.destination() == Path::new(dest)).cloned();
        let data = at("/data").expect("the volume is mounted");
        assert_eq!(data.typ().as_deref(), Some("bind"));
        assert_eq!(data.source().as_deref(), Some(Path::new("/srv/data")));
        let options = data.options().clone().unwrap();
        assert_eq!(options, ["rbind", "nosuid", "nodev"]);
        let ro = at("/ro/x").unwrap().options().clone().unwrap();
        assert_eq!(ro, ["rbind", "nosuid", "nodev", "ro"]);
        // No volume, no extra mount.
        let none = mounted(vec![]).unwrap().mounts().clone().unwrap();
        assert!(none.iter().all(|m| m.destination() != Path::new("/data")));
    }

    #[test]
    fn a_volume_path_in_the_container_that_would_hide_the_system_is_refused() {
        for at in [
            "data", "", "/", "/proc", "/proc/1", "/sys", "/sys/fs", "/dev", "/dev/shm", "/a/../b", "/a/..",
        ] {
            let why = mounted(vec![bind("/srv/data", at, false)]).unwrap_err().to_string();
            assert!(
                why.contains("volume") && why.contains(&format!("`{at}`")),
                "{at:?}: {why}"
            );
        }
        // A name that only starts like one of them is fine.
        assert!(mounted(vec![bind("/srv/data", "/processing", false)]).is_ok());
        // A host path that is not absolute would be taken as relative to the runtime's directory.
        assert!(mounted(vec![bind("srv/data", "/data", false)]).is_err());
        // Nor over a mount the container already has, nor twice on one path.
        assert!(mounted(vec![bind("/srv/data", "/tmp", false)]).is_err());
        assert!(mounted(vec![bind("/srv/a", "/data", false), bind("/srv/b", "/data", false)]).is_err());
    }
}
