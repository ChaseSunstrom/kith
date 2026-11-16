//! Running one container from an [`Image`].

use crate::{Context, Image, ImageStore, Result, devfilter, err};
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
use std::collections::{BTreeSet, HashSet};
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
    /// Not started if the user it would be is root, whoever says so (`user`, or its image).
    pub non_root: bool,
    /// Not started if it would be the node's root: root, where kithd is root, with no range
    /// of ids of its own (see `shifts`). Root of its own range is not the node's.
    pub no_node_root: bool,
    /// Capabilities it starts without, of those it would have: `all`, or names as Linux
    /// has them without `CAP_` (`NET_RAW`).
    pub drop: Vec<String>,
    /// No filter on its system calls. An exec unit has none either way.
    pub unconfined: bool,
    /// Calls the filter refuses that this container may make: names of [`crate::REFUSED`].
    pub allow: Vec<String>,
    /// It may make user namespaces of its own (a sandbox inside it: bubblewrap): the calls
    /// of [`NESTED`] go through, and its `/proc` hides nothing, without which no `/proc`
    /// can be mounted inside. Refused where it would be the node's root.
    pub nested: bool,
    /// As any container runtime runs an image with nothing said: it is the user its image
    /// names (root where it names none), and root has what such a runtime gives root
    /// ([`ROOTS`]). Without it, only `user` makes a container root.
    pub as_image: bool,
    /// The root file system is the container's own to write: what it writes is kept
    /// beside it, never in the image, and goes when it is deleted. Without it the root is
    /// the image, read-only.
    pub writable: bool,
    /// The network namespace it is put in (a pod's), by path. Without one: the host's.
    pub netns: Option<PathBuf>,
    /// What it is called (a pod's containers are all called as the pod is). Without it: its id.
    pub hostname: Option<String>,
    /// It is the node's own users where kithd is root, as a NodeWorkload is: no user namespace
    /// of its own (see `shifts`).
    pub host_users: bool,
}

/// How many ids a container's user namespace has where kithd is root: 0 to 65535, all an
/// image's files may name.
const RANGE: u32 = 65536;
/// How many ranges of [`RANGE`] the node's ids have for containers: all below 2^31 but the
/// first, which is the node's own users'.
const RANGES: u32 = 32767;
/// Where a container's image and volumes are mounted id-mapped before it is made, in a mount
/// namespace that is the making thread's alone (see [`stage`]).
const STAGE: &str = "/run/kith-stage";

/// The ranges of containers being made, which no bundle's `config.json` names yet.
static TAKING: std::sync::Mutex<BTreeSet<u32>> = std::sync::Mutex::new(BTreeSet::new());

fn taking() -> std::sync::MutexGuard<'static, BTreeSet<u32>> {
    TAKING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A range of ids being taken by a container: free again when dropped, by when its bundle
/// names it, or the bundle is gone.
struct Range(u32);

impl Drop for Range {
    fn drop(&mut self) {
        taking().remove(&self.0);
    }
}

/// The lowest range of ids no container has: not one that a bundle under `bundles` maps, nor
/// one being taken. What is taken is what the bundles say, so it holds over a restart of
/// kithd, and a range is free once its container's bundle is removed. A bundle whose
/// config.json is there (or cannot be looked at) and does not load may name any: none is given
/// while it is.
fn take_range(bundles: &Path) -> Result<Range> {
    let mut taken = taking();
    let mut used = taken.clone();
    for entry in fs::read_dir(bundles).ctx("listing containers")? {
        // (One being made has none yet: its range, if it has one, is being taken. Its file
        // comes whole, by a rename: see `create`.)
        let config = entry.ctx("listing containers")?.path().join("config.json");
        let spec = match fs::metadata(&config) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Ok(_) => Spec::load(&config).ok(),
            Err(_) => None,
        };
        let Some(spec) = spec else {
            return err(format!(
                "{} does not load, and may name a range of ids: no container is given one until it is removed",
                config.display()
            ));
        };
        let maps = spec.linux().as_ref().and_then(|linux| linux.uid_mappings().clone());
        used.extend(maps.iter().flatten().map(|map| map.host_id()));
    }
    // (Only a range's first id is looked at: every range is RANGE long from a multiple of RANGE,
    // so two that overlap start at the same id.)
    let Some(base) = (1..=RANGES).map(|k| k * RANGE).find(|base| !used.contains(base)) else {
        return err("every range of ids on this node is a container's");
    };
    taken.insert(base);
    Ok(Range(base))
}

/// Whether a container gets a user namespace of its own where kithd is root: one with a network
/// of its own (a pod's), where a port under 1024 is anyone's. Not one on the node's network: a
/// port it serves is under 1024 as often as not, and no capability of a user namespace reaches
/// the node's network, so it would need the node's ports to be anyone's. Not one that keeps the
/// node's users; not one given device nodes (the node's, whose owners are the node's users); and
/// not one with its image or a volume on a file system that takes no id-mapped mount (NFS: a
/// volume of another node). Those are what they were before: their users are the node's.
/// `Err` names the path that keeps a pod so, which its unit alone would not.
fn shifts<'a>(image: &'a Image, unit: &'a Unit) -> std::result::Result<bool, &'a Path> {
    if !unit.devices.is_empty() || unit.netns.is_none() || unit.host_users {
        return Ok(false);
    }
    unmappable(image, unit).map_or(Ok(true), Err)
}

/// The first of a container's image root and volumes on a file system that takes no id-mapped
/// mount, if one is.
fn unmappable<'a>(image: &'a Image, unit: &'a Unit) -> Option<&'a Path> {
    use nix::sys::statfs::{BTRFS_SUPER_MAGIC, EXT4_SUPER_MAGIC, FsType, TMPFS_MAGIC, statfs};
    // XFS's number, which nix leaves out where libc is musl.
    let xfs = FsType(0x5846_5342 as _);
    let kinds = [EXT4_SUPER_MAGIC, TMPFS_MAGIC, xfs, BTRFS_SUPER_MAGIC];
    let mappable = |path: &Path| statfs(path).is_ok_and(|fs| kinds.contains(&fs.filesystem_type()));
    let paths = std::iter::once(&image.rootfs).chain(unit.mounts.iter().map(|volume| &volume.host));
    paths.map(PathBuf::as_path).find(|path| !mappable(path))
}

/// Mounts, in the calling thread's own mount namespace, what a container whose ids start at
/// `base` is made of: its image at `STAGE/root` and each of its volumes at `STAGE/v<n>`,
/// id-mapped to its range (a file of the image's root is its root's, and one a volume's user
/// owns on disk is that user's in it), and its bundle at `STAGE/bundle`. The container's mount
/// namespace is made as a copy of this one; the node's never has them, and they go with it.
fn stage(image: &Image, unit: &Unit, bundle: &Path, base: u32) -> io::Result<()> {
    use kith_dm_sys::{NODEV, NOSUID, RDONLY, mount_mapped};
    use nix::mount::{MsFlags, mount};
    use std::os::fd::AsFd;
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;
    let stage = Path::new(STAGE);
    fs::create_dir_all(stage)?;
    // (Its root may pass through, to what is its own: nothing else of the node's is on the way.)
    let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
    mount(Some("tmpfs"), stage, Some("tmpfs"), flags, Some("mode=0711"))?;
    let users = kith_dm_sys::user_namespace(base, RANGE)?;
    fs::create_dir(stage.join("root"))?;
    // (Writable until the container's root is made read-only, after its mount points are made
    // in it, as they are in an image that is not mapped; under an overlay, never written.)
    let image_only = if unit.writable { RDONLY } else { 0 };
    mount_mapped(&image.rootfs, &stage.join("root"), users.as_fd(), image_only | NODEV)?;
    if unit.writable {
        fs::create_dir(stage.join("bundle"))?;
        mount(
            Some(bundle),
            &stage.join("bundle"),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )?;
    }
    for (n, volume) in unit.mounts.iter().enumerate() {
        let at = stage.join(format!("v{n}"));
        match fs::metadata(&volume.host)?.is_dir() {
            true => fs::create_dir(&at)?,
            false => drop(File::create(&at)?),
        }
        let only = if volume.read_only { RDONLY } else { 0 };
        mount_mapped(&volume.host, &at, users.as_fd(), NOSUID | NODEV | only)?;
    }
    // Its network is joined here, by the thread it is made from: from inside its own user
    // namespace it may not join one the node's root made.
    if let Some(netns) = &unit.netns {
        nix::sched::setns(File::open(netns)?, nix::sched::CloneFlags::CLONE_NEWNET)?;
    }
    Ok(())
}

/// The words of the refusal of a `no_node_root` unit that would be root, by which whoever
/// set it knows the refusal for its own.
pub const NODE_ROOT: &str = "would be the node's root";

/// What root keeps in a container that is `as_image`, where kithd is root: what Docker and
/// containerd give by default. Nothing in it reaches out of the container's namespaces.
const ROOTS: [Capability; 14] = [
    Capability::Chown,
    Capability::DacOverride,
    Capability::Fsetid,
    Capability::Fowner,
    Capability::Mknod,
    Capability::NetRaw,
    Capability::Setgid,
    Capability::Setuid,
    Capability::Setfcap,
    Capability::Setpcap,
    Capability::NetBindService,
    Capability::SysChroot,
    Capability::Kill,
    Capability::AuditWrite,
];

/// A host directory bound into a container: where it is, where the container sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Mount {
    /// An absolute path on the host.
    pub host: PathBuf,
    /// An absolute path in the container, not `/` nor under `/proc`, `/sys` or `/dev`.
    pub container: String,
    pub read_only: bool,
    /// A directory (or a file) kith made for this: where kithd is root and the
    /// container's user is not, it is made that user's, with all that is in it, unless it
    /// is theirs already.
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
    /// The first of the node's ids its user namespace maps from 0, where it has one of its own.
    range: Option<u32>,
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

    /// Why no container can start here, said once at start; `None` where one can (root's
    /// kithd, on kith OS, makes `/kith` itself and is not asked).
    pub fn cgroup_problem(&self) -> Option<String> {
        if nix::unistd::getuid().is_root() {
            return None;
        }
        probe(Path::new("/sys/fs/cgroup"), &self.cgroup_parent)
    }

    /// Kill and remove every container a previous owner of `root` left behind,
    /// e.g. after a crash. Returns how many were removed.
    pub fn cleanup(&self) -> Result<usize> {
        self.sweep_left(Path::new("/sys/fs/cgroup"))
    }

    /// [`Runtime::cleanup`], with the cgroups asked about under `sys`. What is left is each id
    /// with state, and each bundle with none: a container being made when kithd stopped, whose
    /// config.json may be empty after a power cut (and so give no range: see `take_range`).
    fn sweep_left(&self, sys: &Path) -> Result<usize> {
        let (states, bundles) = (self.root.join("state"), self.root.join("containers"));
        let mut left = BTreeSet::new();
        for dir in [&states, &bundles] {
            for entry in fs::read_dir(dir).ctx("listing old containers")?.flatten() {
                left.insert(entry.file_name());
            }
        }
        let mut removed = 0;
        for name in left {
            let state = states.join(&name);
            let cgroup = format!("{}/kith-{}", self.cgroup_parent, name.to_string_lossy());
            let path = sys.join(cgroup.trim_start_matches('/'));
            let swept = sweep(&state, &bundles.join(&name), &path, || {
                // State we cannot load (or none) is removed along with the bundle.
                if let Ok(mut container) = Container::load(state.clone())
                    && let Err(e) = container.delete(true)
                {
                    eprintln!(
                        "kith: deleting the container {} left behind: {e}",
                        name.to_string_lossy()
                    );
                }
                // An exec unit has no container state, only its cgroup.
                let _ = manager(&cgroup).remove();
            });
            removed += usize::from(swept);
        }
        Ok(removed)
    }

    /// Create the container `id`: namespaces and cgroup are set up and the
    /// process is ready, but it does not run until [`Handle::start`].
    ///
    // ponytail: the image's rootfs is shared read-only, with tmpfs on /tmp and /run, and
    // the host's network, unless the unit says otherwise (`writable`, `netns`). What a
    // writable root holds is on the state's disk with no limit of its own.
    pub fn create(&self, id: &str, image: &Image, unit: &Unit, stdout: File, stderr: File) -> Result<Handle> {
        let what = format!("creating container `{id}`");
        let bundle = self.root.join("containers").join(id);
        let cgroup = format!("{}/kith-{id}", self.cgroup_parent);

        // Validate the id before it is used as a directory name.
        ContainerBuilder::new(id.into(), SyscallType::Linux)
            .validate_id()
            .ctx(&what)?;
        let state = self.root.join("state").join(id);
        let cgroup_dir = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
        clear_kept(&state, &bundle, &cgroup_dir, || {
            let _ = manager(&cgroup).remove();
        })
        .ctx(&what)?;
        let (uid, gid) = (nix::unistd::getuid(), nix::unistd::getgid());
        let range = match uid.is_root().then(|| shifts(image, unit)) {
            Some(Ok(true)) => Some(take_range(&self.root.join("containers")).ctx(&what)?),
            // (Not its Workload's choice, and its status says only `hostUsers`: said here too.)
            Some(Err(path)) => {
                eprintln!(
                    "kith: container `{id}` keeps the node's users, not a range of its own: {} is on a file system that takes no id-mapped mount",
                    path.display()
                );
                None
            }
            Some(Ok(false)) | None => None,
        };
        let shift = range.as_ref().map(|range| range.0);
        let spec = spec_shifted(id, image, unit, &cgroup, &bundle, (uid, gid), shift).ctx(&what)?;
        // (The spec names a user only where kithd is root: see `spec_shifted`.)
        let user = spec.process().as_ref().map(|process| process.user());
        if let Some(user) = user.filter(|user| user.uid() != 0 || shift.is_some()) {
            // Its output is its own: an image that writes its log to /dev/stdout by name
            // opens the file again, and may only if it is its user's (the node's id of it).
            let base = shift.unwrap_or(0);
            for output in [&stdout, &stderr] {
                std::os::unix::fs::fchown(output, Some(base + user.uid()), Some(base + user.gid())).ctx(&what)?;
            }
            // (A volume is its user's on disk as it is in the container: an id-mapped mount
            // shows its owners as they are. A new one is root's until given.)
            for volume in unit.mounts.iter().filter(|volume| volume.give && user.uid() != 0) {
                give(&volume.host, user.uid(), user.gid()).ctx(format!(
                    "{what}: giving {} to user {}",
                    volume.host.display(),
                    user.uid()
                ))?;
            }
        }
        fs::create_dir_all(&bundle).ctx(&what)?;
        let build = || {
            if unit.writable {
                fs::create_dir(bundle.join("upper")).ctx(&what)?;
                fs::create_dir(bundle.join("work")).ctx(&what)?;
                // (Its own layer is its root's: the first id of its range.)
                for layer in shift.iter().flat_map(|_| ["upper", "work"]) {
                    std::os::unix::fs::chown(bundle.join(layer), shift, shift).ctx(&what)?;
                }
            }
            // (From here the bundle names its range: no other container takes it. Written beside
            // it, on the disk, and renamed, so `take_range` never reads half of one.)
            let new = bundle.join("config.json.new");
            spec.save(&new).ctx(&what)?;
            File::open(&new).and_then(|file| file.sync_all()).ctx(&what)?;
            fs::rename(&new, bundle.join("config.json")).ctx(&what)?;
            if let Some(base) = shift {
                stage(image, unit, &bundle, base).ctx(format!("{what}: mounting its image and volumes id-mapped"))?;
            }
            let container = ContainerBuilder::new(id.into(), SyscallType::Linux)
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
        };
        let built = match shift {
            None => build(),
            // (In a thread of its own, whose mount namespace `stage` makes its own: the
            // container's is made from the thread's, and the node's stays as it was.)
            Some(_) => std::thread::scope(|scope| scope.spawn(build).join())
                .unwrap_or_else(|_| err(format!("{what}: its making panicked"))),
        };
        if built.is_err() {
            // Nothing half-made stays behind to block the next attempt, unless a process of it
            // outlives its cgroup's kill: then, as with a delete, its state and bundle (its range)
            // stay until it is gone.
            sweep(&state, &bundle, &cgroup_dir, || {
                let _ = manager(&cgroup).remove();
            });
        }
        let (container, pid) = built?;
        let handle = Handle {
            container: Some(container),
            go: None,
            pid,
            reaped: false,
            bundle,
            cgroup: cgroup_dir,
            range: shift,
        };
        // Before its program runs: the devices it may open, and no other. (Where kithd is
        // root; elsewhere the container is a user namespace, which makes no device node.)
        if nix::unistd::getuid().is_root()
            && let Err(e) = devfilter::attach(&handle.cgroup, &allowed(&spec))
        {
            handle.discard(&state);
            return Err(e).ctx(&what);
        }
        match handle.no_swap(unit, &what) {
            Ok(()) => Ok(handle),
            Err(e) => {
                handle.discard(&state);
                Err(e)
            }
        }
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
        // Marks the id as taken, and tells `cleanup` about the cgroup after a crash. Its marker is
        // its state and its bundle: a kept id (see `discard_leftovers`) is taken only once it is gone.
        let marker = self.root.join("state").join(id);
        clear_kept(
            &marker,
            &marker,
            &Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/')),
            || {
                let _ = manager(&cgroup).remove();
            },
        )
        .ctx(&what)?;
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
            bundle: marker.clone(),
            cgroup: Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/')),
            range: None,
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
        match confined.and_then(|()| handle.no_swap(unit, &what)) {
            Ok(()) => Ok(handle),
            Err(e) => {
                handle.discard(&marker);
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

/// The device rules of a container's spec: each one device it was given (`device_nodes`).
fn allowed(spec: &Spec) -> Vec<LinuxDeviceCgroup> {
    let limits = spec.linux().as_ref().and_then(|linux| linux.resources().as_ref());
    limits.and_then(|limits| limits.devices().clone()).unwrap_or_default()
}

/// Change `made` so that the node's `path` is the character device numbered `device`, or
/// (with none) no device of the container's: its nodes and its rules, which are returned.
/// What a path was is read from `made`, which is kithd's own: the node in the container's
/// `/dev` is the container's to rename, and to put another in the place of.
fn regrant(made: &mut Spec, path: &Path, device: Option<u64>) -> Result<Vec<LinuxDeviceCgroup>> {
    let mut linux = made.linux().clone().unwrap_or_default();
    let mut nodes = linux.devices().clone().unwrap_or_default();
    let mut allowed = allowed(made);
    let was = |node: &LinuxDevice| node.path() == path;
    for node in nodes.iter().filter(|node| was(node)) {
        allowed.retain(|rule| (rule.major(), rule.minor()) != (Some(node.major()), Some(node.minor())));
    }
    nodes.retain(|node| !was(node));
    if let Some(device) = device {
        let (major, minor) = (
            nix::sys::stat::major(device) as i64,
            nix::sys::stat::minor(device) as i64,
        );
        let node = LinuxDeviceBuilder::default().path(path).typ(LinuxDeviceType::C);
        nodes.push(node.major(major).minor(minor).build().ctx("a device node")?);
        let rule = LinuxDeviceCgroupBuilder::default().allow(true).typ(LinuxDeviceType::C);
        allowed.push(
            rule.major(major)
                .minor(minor)
                .access("rw")
                .build()
                .ctx("a device rule")?,
        );
    }
    let mut limits = linux.resources().clone().unwrap_or_default();
    limits.set_devices(Some(allowed.clone()));
    linux.set_resources(Some(limits));
    linux.set_devices(Some(nodes));
    made.set_linux(Some(linux));
    Ok(allowed)
}

/// Is `path` a node of a kind that comes and goes while a unit runs (an input device: a
/// controller plugged in)? A unit that has one is made those that come later in its `/dev`
/// as it runs ([`Handle::plug`]).
pub fn plugged(path: &Path) -> bool {
    path.starts_with("/dev/input")
}

impl Handle {
    /// The directory of the container's own `/dev` that `path` (a node under `/dev`) lies
    /// in, and the node's name there. Opened a name at a time and through no link: what
    /// the container put in its `/dev` leads nowhere else.
    fn in_dev(&self, path: &Path) -> Result<(fs::File, PathBuf)> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let what = format!("{} in the container", path.display());
        let inside = path
            .strip_prefix("/")
            .ok()
            .filter(|_| plugged(path) && self.container.is_some());
        let (Some(parent), Some(name)) = (inside.and_then(Path::parent), inside.and_then(Path::file_name)) else {
            return err(format!("{what}: not a node that is given to a running container"));
        };
        let dir = |path: String| {
            let flags = nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_PATH;
            fs::OpenOptions::new().read(true).custom_flags(flags).open(path)
        };
        // (The one link followed is the kernel's own, to the container's root.)
        let root = fs::File::open(format!("/proc/{}/root/.", self.pid)).ctx(&what)?;
        let mut at = root;
        for part in parent.components() {
            let part = part.as_os_str().to_string_lossy();
            at = dir(format!("/proc/self/fd/{}/{part}", at.as_raw_fd())).ctx(&what)?;
        }
        Ok((at, PathBuf::from(name)))
    }

    /// Give the running container the device node at `path` (one that is [`plugged`]): made
    /// in its `/dev` as its user's own, as those it started with were. Where kithd is not
    /// root nothing can be made there: an error, and the unit is started over for it.
    pub fn plug(&self, path: &Path) -> Result<()> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let what = format!("giving the container {}", path.display());
        let meta = fs::metadata(path).ctx(&what)?;
        if fs::canonicalize(path).ctx(&what)? != path || !meta.file_type().is_char_device() {
            return err(format!("{what}: not a character device node under /dev"));
        }
        let made = oci_spec::runtime::Spec::load(self.bundle.join("config.json")).ctx(&what)?;
        let owner = made
            .process()
            .as_ref()
            .map(|process| (process.user().uid(), process.user().gid()));
        let (dir, name) = self.in_dev(path)?;
        let node = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name);
        let mode = nix::sys::stat::Mode::from_bits_truncate(meta.mode() & 0o777);
        self.allow(made, path, Some(meta.rdev())).ctx(&what)?;
        match nix::sys::stat::mknod(&node, nix::sys::stat::SFlag::S_IFCHR, mode, meta.rdev()) {
            // (There already: the one it had when it started.)
            Err(nix::errno::Errno::EEXIST) => return Ok(()),
            made => made.ctx(&what)?,
        }
        if let Some((user, group)) = owner {
            std::os::unix::fs::lchown(&node, Some(user), Some(group)).ctx(&what)?;
        }
        Ok(())
    }

    /// Take the node at `path` out of the running container's `/dev`: its device is gone.
    pub fn unplug(&self, path: &Path) -> Result<()> {
        use std::os::fd::AsRawFd;
        let what = format!("taking {} from the container", path.display());
        let (dir, name) = self.in_dev(path)?;
        let node = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name);
        // (Its number is some other device's the next time one is plugged in.)
        let made = oci_spec::runtime::Spec::load(self.bundle.join("config.json")).ctx(&what)?;
        self.allow(made, path, None).ctx(&what)?;
        match fs::remove_file(node) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e).ctx(what),
            _ => Ok(()),
        }
    }

    /// Let the container read and write the character device numbered `device` that is
    /// `path` on the node, or, with none, no longer the one that was: in its cgroup's
    /// filter, and in the spec it was made from (`made`), which is what the next change
    /// starts from.
    fn allow(&self, mut made: Spec, path: &Path, device: Option<u64>) -> Result<()> {
        let allowed = regrant(&mut made, path, device)?;
        devfilter::attach(&self.cgroup, &allowed)?;
        made.save(self.bundle.join("config.json"))
            .ctx("keeping the container's device rules")
    }

    /// A memory limit that swap could stretch is no limit. The OCI resources cannot say
    /// "no swap" (libcgroups reads 0 as "leave it"), so it is written here.
    fn no_swap(&self, unit: &Unit, what: &str) -> Result<()> {
        if unit.memory_bytes.is_some() {
            match fs::write(self.cgroup.join("memory.swap.max"), "0") {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(e).ctx(format!("{what}: turning swap off"));
                }
                _ => {} // No such file: this kernel does no swap accounting.
            }
        }
        Ok(())
    }

    /// Drop a handle whose unit is never handed out: see [`discard_leftovers`].
    fn discard(self, state: &Path) {
        discard_leftovers(state, self.delete());
    }

    /// The process id of the container's init, or of the exec unit's command.
    pub fn pid(&self) -> i32 {
        self.pid.as_raw()
    }

    /// The first of the node's ids its user namespace maps 0 to: `None` where its users are
    /// the node's (an exec unit, a container where kithd is not root, or one `shifts` keeps so).
    pub fn range(&self) -> Option<u32> {
        self.range
    }

    /// Where a container's writes to its root land: `None` for an exec unit. A read-only root
    /// never makes the directory.
    pub fn upper(&self) -> Option<PathBuf> {
        self.container.as_ref().map(|_| self.bundle.join("upper"))
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

    /// Whether its exit status has been collected: then `pid` is no longer a zombie to reap.
    pub fn is_reaped(&self) -> bool {
        self.reaped
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

    /// Kill it if it still runs, then remove its cgroup, state and bundle. A failure while the
    /// unit still has processes gives the handle back, and keeps the bundle (see [`Undeleted`]).
    pub fn delete(mut self) -> std::result::Result<(), Undeleted> {
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
        self.finish(deleted)
    }

    /// What a delete leaves once its removal was tried with `deleted`.
    fn finish(self, deleted: Result<()>) -> std::result::Result<(), Undeleted> {
        match deleted {
            Err(error) if has_processes(&self.cgroup) => Err(Undeleted {
                error,
                handle: Some(Box::new(self)),
            }),
            deleted => {
                // It was killed just now: collect it, or it stays a zombie for as long as we live.
                if deleted.is_ok() && !self.reaped {
                    let _ = waitpid(self.pid, None);
                }
                let removed = fs::remove_dir_all(&self.bundle).ctx("deleting the container");
                deleted.and(removed).map_err(|error| Undeleted { error, handle: None })
            }
        }
    }
}

/// A [`Handle::delete`] that failed. `handle` is the unit's handle back while its cgroup still
/// has processes: the unit is not gone, and it can be asked again. `None` means the processes
/// are gone and only the cleanup failed: nothing of the unit runs.
pub struct Undeleted {
    pub error: crate::Error,
    pub handle: Option<Box<Handle>>,
}

/// What a discarded unit leaves: a failed delete with processes left keeps its state (the
/// id stays taken), for the next start's cleanup to find and remove; with them gone, the
/// state goes too, as a delete always removed it.
fn discard_leftovers(state: &Path, deleted: std::result::Result<(), Undeleted>) {
    if let Err(gone) = deleted {
        eprintln!("kith: {}", gone.error);
        if gone.handle.is_none() {
            let _ = fs::remove_dir_all(state);
        }
    }
}

/// Clears the kept id `state` (see [`discard_leftovers`]) before a unit takes it: once its cgroup
/// has no processes, the empty cgroup, state and bundle go. While processes remain nothing is removed
/// and the id is refused. The check comes first: removing a cgroup kills what is in it.
fn clear_kept(state: &Path, bundle: &Path, cgroup: &Path, remove_cgroup: impl FnOnce()) -> Result<()> {
    if !state.exists() {
        return Ok(());
    }
    if has_processes(cgroup) {
        return err(format!(
            "the last run of this id still has processes: it can be run again once they are gone ({})",
            state.display()
        ));
    }
    remove_cgroup();
    let _ = fs::remove_dir_all(state);
    let _ = fs::remove_dir_all(bundle);
    Ok(())
}

/// What [`Runtime::cleanup`] does with a unit left behind (and a failed create with its own): `kill` it, then remove its `state` and
/// `bundle`, unless its `cgroup` still has processes. Then both stay, as [`Handle::delete`] keeps
/// them, and so its id and its range of ids (named by its bundle) stay taken until they are gone;
/// it is said, and `false` returned.
fn sweep(state: &Path, bundle: &Path, cgroup: &Path, kill: impl FnOnce()) -> bool {
    kill();
    if has_processes(cgroup) {
        eprintln!(
            "kith: {} still has processes after it was killed: kept, with its range of ids, until they are gone",
            state.display()
        );
        return false;
    }
    let _ = fs::remove_dir_all(state);
    let _ = fs::remove_dir_all(bundle);
    true
}

/// Whether a cgroup still has processes, its child cgroups' included (`populated` in `cgroup.events`,
/// which a unit's `nested` cgroups set too). A cgroup that is gone has none; one whose events cannot be
/// read may have some. Without `cgroup.events` its own `cgroup.procs` says.
fn has_processes(cgroup: &Path) -> bool {
    match fs::read_to_string(cgroup.join("cgroup.events")) {
        Ok(events) => events.lines().any(|line| line.trim() == "populated 1"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => match fs::read_to_string(cgroup.join("cgroup.procs")) {
            Ok(procs) => !procs.trim().is_empty(),
            Err(e) => e.kind() != io::ErrorKind::NotFound,
        },
        Err(_) => true,
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

/// What to tell the person when a cgroup cannot be made in `parent` (below `root`, the cgroup
/// mount): a mkdir and an rmdir of an empty one. `None` where it can be made.
fn probe(root: &Path, parent: &str) -> Option<String> {
    let dir = root
        .join(parent.trim_start_matches('/'))
        .join(format!("kith-probe-{}", std::process::id()));
    let _ = fs::remove_dir(&dir); // a stale one of a process that had our number
    if let Err(e) = fs::create_dir(&dir) {
        return Some(format!(
            "cannot make a cgroup in {}: {e}; containers will not start (the API still works). \
             A kithd that is not root needs the user's own cgroup (a login's or a system service's is \
             not): run it in the user's systemd with `systemd-run --user --scope kithd`",
            dir.parent().unwrap_or(&dir).display()
        ));
    }
    let _ = fs::remove_dir(&dir);
    None
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
        return Ok(if unit.as_image { (0, 0) } else { (NOBODY, NOBODY) });
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
        both if unit.as_image => both,
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
/// The refused calls a sandbox makes to build namespaces of its own and a root inside them:
/// those for namespaces, and all those that mount (bubblewrap sets a mount's flags with
/// `mount_setattr`, and takes "not permitted" for an answer where "no such call" would do).
pub const NESTED: &[&str] = &[
    "unshare",
    "setns",
    "clone",
    "clone3",
    "mount",
    "umount2",
    "pivot_root",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "mount_setattr",
];
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
// users on one volume walk it at every start. (A container's range of ids never walks one:
// its volumes are id-mapped, see `stage`.) A mount that maps the volume's owner to the
// container's user, when a volume is big enough for that to hurt.
fn give(dir: &Path, uid: u32, gid: u32) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    fn held(dir: &Path) -> io::Result<File> {
        let flags = nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW;
        fs::OpenOptions::new().read(true).custom_flags(flags).open(dir)
    }
    // (One file of a map, mounted alone.)
    if fs::symlink_metadata(dir)?.is_file() {
        let flags = nix::libc::O_NOFOLLOW | nix::libc::O_PATH;
        let file = fs::OpenOptions::new().read(true).custom_flags(flags).open(dir)?;
        return std::os::unix::fs::chown(format!("/proc/self/fd/{}", file.as_raw_fd()), Some(uid), Some(gid));
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

#[cfg(test)]
fn spec(
    id: &str,
    image: &Image,
    unit: &Unit,
    cgroup: &str,
    bundle: &Path,
) -> std::result::Result<Spec, Box<dyn std::error::Error>> {
    spec_of(
        id,
        image,
        unit,
        cgroup,
        bundle,
        nix::unistd::getuid(),
        nix::unistd::getgid(),
    )
}

/// [`spec_shifted`], for a container whose users are kithd's (no range of its own).
#[cfg(test)]
fn spec_of(
    id: &str,
    image: &Image,
    unit: &Unit,
    cgroup: &str,
    bundle: &Path,
    uid: nix::unistd::Uid,
    gid: nix::unistd::Gid,
) -> std::result::Result<Spec, Box<dyn std::error::Error>> {
    spec_shifted(id, image, unit, cgroup, bundle, (uid, gid), None)
}

/// The container's spec, for a kithd that is the user `kithd`, where `shift` is the first id
/// of the range its user namespace maps (where kithd is root, and `shifts` says so).
fn spec_shifted(
    id: &str,
    image: &Image,
    unit: &Unit,
    cgroup: &str,
    bundle: &Path,
    (uid, gid): (nix::unistd::Uid, nix::unistd::Gid),
    shift: Option<u32>,
) -> std::result::Result<Spec, Box<dyn std::error::Error>> {
    // Who the process is. Where kithd is root it is that user of its own range of the node's
    // ids (its root is not the node's), or, where it keeps the node's users, that user of the
    // node with nothing root has. Where kithd is not root, the container is a user namespace
    // whose one user is kithd's own, and the program is given a second one inside (`Entry`).
    let (user, group) = who(image, unit)?;
    if unit.non_root && user == 0 {
        return Err("runAsNonRoot: this container would be root (its image names no other user, or names root): say who with runAsUser".into());
    }
    let shift = shift.filter(|_| uid.is_root());
    if unit.no_node_root && user == 0 && uid.is_root() && shift.is_none() {
        return Err(format!("this container {NODE_ROOT}: its user is root and it keeps the node's users (it has a device, the node's network, `hostUsers`, or its image or a volume is on a file system that takes no id-mapped mount): say who with runAsUser").into());
    }
    let mut spec = match shift {
        _ if !uid.is_root() => Spec::rootless(uid.as_raw(), gid.as_raw()),
        None => Spec::default(),
        // (What a user namespace mounts: the node's /sys bound in, as it may mount no other.)
        Some(base) => {
            if user >= RANGE || group >= RANGE {
                let why = format!("user {user} (group {group}) is past the {RANGE} ids a container has here");
                return Err(why.into());
            }
            let mut spec = Spec::rootless(base, base);
            let map = oci_spec::runtime::LinuxIdMappingBuilder::default()
                .container_id(0u32)
                .host_id(base)
                .size(RANGE)
                .build()?;
            let mut linux = spec.linux().clone().unwrap_or_default();
            linux.set_uid_mappings(Some(vec![map]));
            linux.set_gid_mappings(Some(vec![map]));
            spec.set_linux(Some(linux));
            spec
        }
    };
    // With `/proc` as the kernel has it, the node's root could write the node's settings
    // (`/proc/sys` asks who you are, not what you may): only another user is given that.
    if unit.nested && uid.is_root() && shift.is_none() && user == 0 {
        let why = "userNamespaces: this container is the node's root (runAsUser 0, or its image's user), who is not given a /proc that hides nothing: name another user";
        return Err(why.into());
    }
    let calls = if unit.unconfined {
        UNCONFINED.to_string()
    } else {
        let nested = NESTED.iter().filter(|_| unit.nested).map(|call| call.to_string());
        let allow: Vec<String> = unit.allow.iter().cloned().chain(nested).collect();
        // (Made here once to find a wrong name before anything is started.)
        crate::seccomp::filters(&allow)?;
        allow.join(" ")
    };
    let mut notes = std::collections::HashMap::from([(CALLS.to_string(), calls)]);
    if !uid.is_root() && user != 0 {
        notes.insert(BECOMES.to_string(), format!("{user}:{group}"));
    }
    spec.set_annotations(Some(notes));
    // No network namespace of its own: the host's network, or the one it is given (which one
    // with a range of ids has from the thread that makes it: see `stage`).
    let network = oci_spec::runtime::LinuxNamespaceType::Network;
    let mut linux = spec.linux().clone().unwrap_or_default();
    let mut namespaces = linux.namespaces().clone().unwrap_or_default();
    namespaces.retain(|ns| ns.typ() != network);
    if let Some(netns) = unit.netns.as_ref().filter(|_| shift.is_none()) {
        let given = oci_spec::runtime::LinuxNamespaceBuilder::default().typ(network);
        namespaces.push(given.path(netns).build()?);
    }
    linux.set_namespaces(Some(namespaces));
    spec.set_linux(Some(linux));
    // (A range's image is its id-mapped mount, made by `stage`; so are its own layer and volumes.)
    let staged = |name: &str| Path::new(STAGE).join(name);
    let image_root = shift.map_or(image.rootfs.clone(), |_| staged("root"));
    let rootfs = RootBuilder::default().path(&image_root).readonly(!unit.writable);
    spec.set_root(Some(rootfs.build()?));
    // Linux refuses hostnames over 64 bytes; ids are ASCII (validated by the caller).
    let hostname = unit.hostname.as_deref().unwrap_or(id);
    spec.set_hostname(Some(hostname.chars().take(63).collect()));

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
        // 1024 are what a server is for, and nothing else of root's comes with it. Not one
        // that may nest: bubblewrap does not start as a user who has a capability and is not
        // root (it takes itself for a setuid program set up wrongly).
        let kept = || match root {
            true if unit.nested => HashSet::new(),
            true => HashSet::from([Capability::NetBindService]),
            false => HashSet::from([Capability::Setfcap]),
        };
        let passed = || if root { kept() } else { HashSet::new() };
        let caps = LinuxCapabilitiesBuilder::default().bounding(kept()).effective(kept());
        let caps = caps.permitted(kept()).inheritable(passed()).ambient(passed());
        process.set_capabilities(Some(caps.build()?));
    } else if root && unit.as_image {
        let kept = || HashSet::from(ROOTS);
        let caps = LinuxCapabilitiesBuilder::default().bounding(kept()).effective(kept());
        let caps = caps
            .permitted(kept())
            .inheritable(HashSet::new())
            .ambient(HashSet::new());
        process.set_capabilities(Some(caps.build()?));
    }
    // What it was told to start without, of whatever it would have had. (Not the one a
    // user who is not root is left with where kithd is not root: that one is how its own
    // namespace is made, and is gone before its program starts.)
    if !unit.drop.is_empty() && (root || user == 0) {
        let named = |cap: &Capability| {
            let name = cap.to_string();
            let name = name.strip_prefix("CAP_").unwrap_or(&name);
            unit.drop.iter().any(|dropped| dropped == "all" || dropped == name)
        };
        let left = |caps: &Option<HashSet<Capability>>| -> HashSet<Capability> {
            caps.iter().flatten().filter(|cap| !named(cap)).copied().collect()
        };
        if let Some(has) = process.capabilities().clone() {
            let caps = LinuxCapabilitiesBuilder::default()
                .bounding(left(has.bounding()))
                .effective(left(has.effective()))
                .permitted(left(has.permitted()))
                .inheritable(left(has.inheritable()))
                .ambient(left(has.ambient()));
            process.set_capabilities(Some(caps.build()?));
        }
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
    if unit.writable {
        // The first mount, on the root itself: the image below, the container's own layer
        // over it, and everything after is mounted on the two together. (It is made in the
        // container's mount namespace, and goes with it.)
        let held = shift.map_or(bundle.to_path_buf(), |_| staged("bundle"));
        let layer = |name: &str| held.join(name).display().to_string();
        let mut options = vec![
            format!("lowerdir={}", image_root.display()),
            format!("upperdir={}", layer("upper")),
            format!("workdir={}", layer("work")),
        ];
        if !root || shift.is_some() {
            // (What a user namespace may write its bookkeeping in.)
            options.push("userxattr".into());
        }
        let over = MountBuilder::default().destination("/").typ("overlay");
        mounts.insert(0, over.source("overlay").options(options).build()?);
    }
    mounts.push(tmpfs("/tmp")?);
    mounts.push(tmpfs("/run")?);
    // The container shares the host's network, so it needs the host's resolver (unless it
    // is given a file of its own there).
    let own = |volume: &Mount| volume.container == "/etc/resolv.conf";
    if Path::new("/etc/resolv.conf").exists() && !unit.mounts.iter().any(own) {
        let options = ["rbind", "ro"].map(String::from).to_vec();
        let resolv = MountBuilder::default().destination("/etc/resolv.conf").typ("bind");
        mounts.push(resolv.source("/etc/resolv.conf").options(options).build()?);
    }
    for (n, volume) in unit.mounts.iter().enumerate() {
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
        let source = shift.map_or(volume.host.clone(), |_| staged(&format!("v{n}")));
        mounts.push(bind.source(source).options(options).build()?);
    }
    spec.set_mounts(Some(mounts));

    let mut linux = spec.linux().clone().unwrap_or_default();
    linux.set_cgroups_path(Some(cgroup.into()));
    if unit.nested {
        // (A `/proc` with anything mounted over a part of it is not one the kernel lets a
        // namespace made inside mount again.)
        linux.set_masked_paths(Some(Vec::new()));
        linux.set_readonly_paths(Some(Vec::new()));
    }
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

    /// Held by a test that takes ranges: those being taken are the process's, and a test that
    /// asks which is the lowest free must not meet another's.
    static RANGE_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
            spec("a", &image, &unit(Some(0)), "/kith/a", Path::new("/b")).is_err(),
            "0 would mean unlimited"
        );
        assert!(spec("a", &image, &unit(Some(9)), "/kith/a", Path::new("/b")).is_err());
        let no_memory = Unit {
            memory_bytes: Some(0),
            ..Unit::default()
        };
        assert!(spec("a", &image, &no_memory, "/kith/a", Path::new("/b")).is_err());

        let made = spec(&"x".repeat(100), &image, &unit(Some(500)), "/kith/a", Path::new("/b")).unwrap();
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

    /// A container that may make user namespaces: the calls a sandbox makes go through its
    /// filter beside those it named, and its `/proc` hides nothing; any other keeps both.
    #[test]
    fn a_container_that_may_nest_has_the_calls_and_a_whole_proc() {
        let image = Image {
            entrypoint: vec!["/bin/true".into()],
            user: Some("1000".into()),
            ..Image::default()
        };
        let made = |unit: &Unit| spec("a", &image, unit, "/kith/a", Path::new("/b")).unwrap();
        let calls = |spec: &Spec| spec.annotations().as_ref().unwrap()[CALLS].clone();
        let plain = made(&Unit::default());
        let hidden = plain
            .linux()
            .as_ref()
            .unwrap()
            .masked_paths()
            .clone()
            .unwrap_or_default();
        assert!(hidden.iter().any(|path| path == "/proc/kcore"), "{hidden:?}");
        assert_eq!(calls(&plain), "");
        let nested = made(&Unit {
            nested: true,
            allow: vec!["ptrace".into()],
            ..Unit::default()
        });
        let linux = nested.linux().as_ref().unwrap();
        assert_eq!(linux.masked_paths().as_deref(), Some(&[][..]));
        assert_eq!(linux.readonly_paths().as_deref(), Some(&[][..]));
        assert_eq!(
            calls(&nested),
            "ptrace unshare setns clone clone3 mount umount2 pivot_root open_tree move_mount fsopen fsconfig fsmount fspick mount_setattr"
        );
        assert_eq!(nested.process().as_ref().unwrap().no_new_privileges(), Some(true));
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
        let made = spec("a", &image, &with("/dev/null"), "/kith/a", Path::new("/b")).unwrap();
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
        assert!(plugged(Path::new("/dev/input/event7")) && !plugged(Path::new("/dev/dri/card0")));
        // One plugged in later is a node and a rule more. Taken away, it goes by the node's
        // own name for it: what the container has made of its `/dev` since is not asked.
        let mut later = made.clone();
        let has = |rules: &[LinuxDeviceCgroup], major, minor| {
            let is = |rule: &LinuxDeviceCgroup| (rule.major(), rule.minor()) == (Some(major), Some(minor));
            rules.iter().any(is)
        };
        let pad = Path::new("/dev/input/event5");
        let with_pad = regrant(&mut later, pad, Some(nix::sys::stat::makedev(13, 69))).unwrap();
        assert_eq!(with_pad.len(), allowed.len() + 1);
        assert!(has(&with_pad, 13, 69) && has(&with_pad, 1, 3));
        assert_eq!(super::allowed(&later), with_pad);
        assert_eq!(later.linux().as_ref().unwrap().devices().as_ref().unwrap().len(), 2);
        let without = regrant(&mut later, pad, None).unwrap();
        assert!(!has(&without, 13, 69) && has(&without, 1, 3));
        assert_eq!((&without, super::allowed(&later)), (&allowed, allowed.clone()));
        // One it never had: nothing is taken.
        assert_eq!(
            regrant(&mut later, Path::new("/dev/input/event9"), None).unwrap(),
            allowed
        );
        // Missing, or not a device node: the unit is not created, and the reason says which.
        let missing = spec(
            "a",
            &image,
            &with("/dev/kith-no-such-device"),
            "/kith/a",
            Path::new("/b"),
        )
        .unwrap_err();
        assert!(missing.to_string().contains("/dev/kith-no-such-device"), "{missing}");
        let file = spec("a", &image, &with("/etc"), "/kith/a", Path::new("/b"));
        assert!(file.unwrap_err().to_string().contains("not a device node"));
        for out in ["/dev/../dev/null", "/dev/fd", "/dev/shm"] {
            let refused = spec("a", &image, &with(out), "/kith/a", Path::new("/b"))
                .unwrap_err()
                .to_string();
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
            Path::new("/b"),
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
            let made = spec_of("a", &image, &Unit::default(), "/kith/a", Path::new("/b"), uid, gid).unwrap();
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
            let made = spec_of("a", &image, &asked, "/kith/a", Path::new("/b"), uid, gid).unwrap();
            let process = made.process().as_ref().unwrap();
            assert_eq!((process.user().uid(), process.no_new_privileges()), (0, Some(true)));
            assert_eq!(becomes(&made), None, "no second namespace for root");
            assert_eq!(sets(process)[0], "AuditWrite Kill NetBindService");
        }
        // What it is told to start without is in none of its sets; what makes the
        // namespace of a user who is not root is not its to drop, and is not passed on.
        let (root, user) = (Uid::from_raw(0), Uid::from_raw(1000));
        let dropping = |unit: &Unit, drop: &[&str], uid: Uid| {
            let drop = drop.iter().map(|name| name.to_string()).collect();
            let unit = Unit { drop, ..unit.clone() };
            let made = spec_of(
                "a",
                &image,
                &unit,
                "/kith/a",
                Path::new("/b"),
                uid,
                Gid::from_raw(uid.as_raw()),
            );
            sets(made.unwrap().process().as_ref().unwrap())
        };
        assert_eq!(
            dropping(&asked, &["KILL", "SYS_ADMIN"], root)[..3],
            ["AuditWrite NetBindService"; 3]
        );
        assert_eq!(dropping(&asked, &["all"], root), [""; 5]);
        assert_eq!(dropping(&asked, &["all"], user), [""; 5]);
        assert_eq!(dropping(&Unit::default(), &["NET_BIND_SERVICE"], root), [""; 5]);
        assert_eq!(dropping(&Unit::default(), &["all"], user)[0], "Setfcap");
        let pod = Unit {
            as_image: true,
            ..Unit::default()
        };
        let left = dropping(&pod, &["NET_RAW", "MKNOD"], root);
        assert!(
            left[0].contains("Chown") && !left[0].contains("NetRaw") && !left[0].contains("Mknod"),
            "{left:?}"
        );
        // And a container that would be root is not made where it is told not to be one.
        for (unit, is_root) in [(&asked, true), (&pod, true), (&Unit::default(), false)] {
            let unit = Unit {
                non_root: true,
                ..unit.clone()
            };
            let made = spec_of("a", &image, &unit, "/kith/a", Path::new("/b"), root, Gid::from_raw(0));
            assert_eq!(made.is_err(), is_root);
            assert!(made.err().is_none_or(|e| e.to_string().starts_with("runAsNonRoot")));
        }
        // And where the node takes no root of its own: root is refused only where it would
        // be the node's (kithd is root and the container has no range of its own).
        let nobody = Uid::from_raw(1000);
        for (kithd, shift, refused) in [(root, None, true), (root, Some(100_000), false), (nobody, None, false)] {
            let unit = Unit {
                no_node_root: true,
                ..pod.clone()
            };
            let made = spec_shifted("a", &image, &unit, "/kith/a", Path::new("/b"), (kithd, Gid::from_raw(0)), shift);
            assert_eq!(made.is_err(), refused, "{kithd} {shift:?}");
            assert!(made.err().is_none_or(|e| e.to_string().contains(NODE_ROOT)));
        }
        let user = Unit {
            no_node_root: true,
            ..Unit::default()
        };
        assert!(spec_of("a", &image, &user, "/kith/a", Path::new("/b"), root, Gid::from_raw(0)).is_ok());
        // No filter, or some of it, only as the unit says.
        let (uid, gid) = (Uid::from_raw(0), Gid::from_raw(0));
        let unit = Unit {
            unconfined: true,
            ..Unit::default()
        };
        let made = spec_of("a", &image, &unit, "/kith/a", Path::new("/b"), uid, gid).unwrap();
        assert_eq!(made.annotations().as_ref().unwrap()[CALLS], UNCONFINED);
        let unit = Unit {
            allow: vec!["ptrace".into(), "unshare".into()],
            ..Unit::default()
        };
        let made = spec_of("a", &image, &unit, "/kith/a", Path::new("/b"), uid, gid).unwrap();
        assert_eq!(made.annotations().as_ref().unwrap()[CALLS], "ptrace unshare");
        let unit = Unit {
            allow: vec![UNCONFINED.into()],
            ..Unit::default()
        };
        let said = spec_of("a", &image, &unit, "/kith/a", Path::new("/b"), uid, gid)
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

    /// A pod's container: its root an overlay of its own over the image, the first thing
    /// mounted; the network namespace it is given; the user its image says, root included,
    /// and root with what a container runtime gives root, where kithd is root.
    #[test]
    fn a_pods_container_writes_its_root_joins_its_network_and_is_its_images_user() {
        let image = Image {
            entrypoint: vec!["/bin/true".into()],
            rootfs: "/images/x/rootfs".into(),
            ..Image::default()
        };
        let unit = Unit {
            as_image: true,
            writable: true,
            netns: Some("/proc/1/fd/9".into()),
            ..Unit::default()
        };
        let (uid, gid) = (nix::unistd::Uid::from_raw(0), nix::unistd::Gid::from_raw(0));
        let made = spec_of("a", &image, &unit, "/kith/a", Path::new("/b"), uid, gid).unwrap();
        assert_eq!(made.root().as_ref().unwrap().readonly(), Some(false));
        let first = &made.mounts().as_ref().unwrap()[0];
        assert_eq!(
            (first.destination().to_str(), first.typ().as_deref()),
            (Some("/"), Some("overlay"))
        );
        assert_eq!(
            first.options().as_ref().unwrap(),
            &["lowerdir=/images/x/rootfs", "upperdir=/b/upper", "workdir=/b/work"]
        );
        let namespaces = made.linux().as_ref().unwrap().namespaces().clone().unwrap();
        let network = oci_spec::runtime::LinuxNamespaceType::Network;
        let joined: Vec<_> = namespaces.iter().filter(|ns| ns.typ() == network).collect();
        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].path().as_deref(), Some(Path::new("/proc/1/fd/9")));
        let process = made.process().as_ref().unwrap();
        assert_eq!(process.user().uid(), 0);
        assert_eq!(process.no_new_privileges(), Some(true));
        let caps = process.capabilities().as_ref().unwrap();
        assert_eq!(caps.bounding(), &Some(HashSet::from(ROOTS)));
        assert_eq!(caps.ambient(), &Some(HashSet::new()));
        // An image that names a user: that one, with its group, and nothing of root's but ports.
        let named = Image {
            user: Some("101:0".into()),
            ..image.clone()
        };
        let made = spec_of("a", &named, &unit, "/kith/a", Path::new("/b"), uid, gid).unwrap();
        let process = made.process().as_ref().unwrap();
        assert_eq!((process.user().uid(), process.user().gid()), (101, 0));
        let kept = Some(HashSet::from([Capability::NetBindService]));
        assert_eq!(process.capabilities().as_ref().unwrap().bounding(), &kept);
        // Where kithd is not root, the overlay is a user namespace's own.
        let (uid, gid) = (nix::unistd::Uid::from_raw(1000), nix::unistd::Gid::from_raw(1000));
        let made = spec_of("a", &image, &unit, "/kith/a", Path::new("/b"), uid, gid).unwrap();
        let first = &made.mounts().as_ref().unwrap()[0];
        assert_eq!(
            first.options().as_ref().unwrap().last().map(String::as_str),
            Some("userxattr")
        );
        // Without any of it: as before.
        let made = spec_of("a", &image, &Unit::default(), "/kith/a", Path::new("/b"), uid, gid).unwrap();
        assert_eq!(made.root().as_ref().unwrap().readonly(), Some(true));
        assert!(
            made.mounts()
                .as_ref()
                .unwrap()
                .iter()
                .all(|m| m.typ().as_deref() != Some("overlay"))
        );
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

    /// A failed delete hands the handle back only while the unit's cgroup still has processes:
    /// then the bundle stays too. A failure with the processes gone holds nothing back.
    #[test]
    fn failed_delete_keeps_the_handle_only_while_processes_remain() {
        let root = std::env::temp_dir().join(format!("kith-failed-delete-{}", std::process::id()));
        let (bundle, cgroup) = (root.join("bundle"), root.join("cgroup"));
        let fresh = |procs: Option<&str>| {
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&bundle).unwrap();
            fs::create_dir_all(&cgroup).unwrap();
            if let Some(procs) = procs {
                fs::write(cgroup.join("cgroup.procs"), procs).unwrap();
            }
            Handle {
                container: None,
                go: None,
                pid: Pid::from_raw(0),
                reaped: true,
                bundle: bundle.clone(),
                cgroup: cgroup.clone(),
                range: None,
            }
        };
        // Processes still listed: the handle comes back and the bundle is kept.
        let still = fresh(Some("4242\n")).finish(err("removing the cgroup"));
        let still = still.expect_err("a unit with processes is not gone");
        assert!(still.handle.is_some() && bundle.exists(), "{}", still.error);
        // Only the cleanup failed (no processes): nothing is held back, and the bundle goes.
        let cleanup = fresh(Some("")).finish(err("removing the cgroup"));
        let cleanup = cleanup.expect_err("the removal failed");
        assert!(cleanup.handle.is_none() && !bundle.exists(), "{}", cleanup.error);
        // A cgroup that is gone has no processes either; a deleted unit is deleted.
        let gone = fresh(None).finish(Ok(()));
        assert!(gone.is_ok() && !bundle.exists());
        let _ = fs::remove_dir_all(&root);
    }

    /// A unit that is never handed out keeps its state while processes remain, so the next
    /// start's cleanup finds them; once they are gone, the state goes with the bundle.
    #[test]
    fn a_discarded_unit_keeps_its_state_only_while_processes_remain() {
        let root = std::env::temp_dir().join(format!("kith-discarded-{}", std::process::id()));
        let (state, bundle, cgroup) = (root.join("state"), root.join("bundle"), root.join("cgroup"));
        let fresh = |procs: &str| {
            let _ = fs::remove_dir_all(&root);
            for dir in [&state, &bundle, &cgroup] {
                fs::create_dir_all(dir).unwrap();
            }
            fs::write(cgroup.join("cgroup.procs"), procs).unwrap();
            Handle {
                container: None,
                go: None,
                pid: Pid::from_raw(0),
                reaped: true,
                bundle: bundle.clone(),
                cgroup: cgroup.clone(),
                range: None,
            }
        };
        discard_leftovers(&state, fresh("4242\n").finish(err("removing the cgroup")));
        assert!(state.exists() && bundle.exists(), "the processes are still there");
        discard_leftovers(&state, fresh("").finish(err("removing the cgroup")));
        assert!(!state.exists() && !bundle.exists(), "only the cleanup failed");
        let _ = fs::remove_dir_all(&root);
    }

    /// A kept id is refused by `create` and `exec` (through `clear_kept`, which both call before
    /// they take the id) while its last run has processes: nothing of it is removed. Once they are
    /// gone the id is cleared and can be taken.
    #[test]
    fn create_refuses_a_kept_id() {
        let root = std::env::temp_dir().join(format!("kith-kept-id-{}", std::process::id()));
        let (state, bundle, cgroup) = (root.join("state"), root.join("bundle"), root.join("cgroup"));
        let fresh = |procs: &str| {
            let _ = fs::remove_dir_all(&root);
            for dir in [&state, &bundle, &cgroup] {
                fs::create_dir_all(dir).unwrap();
            }
            fs::write(cgroup.join("cgroup.procs"), procs).unwrap();
        };
        fresh("4242\n");
        let refused = clear_kept(&state, &bundle, &cgroup, || {
            panic!("a cgroup with processes is not removed")
        });
        assert!(refused.is_err(), "the processes are still there");
        assert!(state.exists() && bundle.exists(), "nothing of a live run is removed");
        fresh("");
        assert!(clear_kept(&state, &bundle, &cgroup, || {}).is_ok());
        assert!(
            !state.exists() && !bundle.exists(),
            "its last run is gone: the id is free"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// A unit's processes may sit in its child cgroups (`nested`): `populated` in `cgroup.events`
    /// counts them, where its own `cgroup.procs` is empty.
    #[test]
    fn has_processes_counts_child_cgroups() {
        let cgroup = std::env::temp_dir().join(format!("kith-populated-{}", std::process::id()));
        let _ = fs::remove_dir_all(&cgroup);
        fs::create_dir_all(&cgroup).unwrap();
        fs::write(cgroup.join("cgroup.procs"), "").unwrap();
        fs::write(cgroup.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
        assert!(has_processes(&cgroup), "a child cgroup has processes");
        fs::write(cgroup.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
        assert!(!has_processes(&cgroup), "nothing is left in it or below");
        let _ = fs::remove_dir_all(&cgroup);
        assert!(!has_processes(&cgroup), "a cgroup that is gone has none");
    }

    /// A parent we can make a cgroup in: nothing is said and nothing is left behind. One we
    /// cannot (here a path below a file, which fails for root too): the path, the error, that
    /// containers will not start, and the command that runs kithd in the user's systemd.
    #[test]
    fn cgroup_probe_says_where_a_cgroup_cannot_be_made() {
        let root = std::env::temp_dir().join(format!("kith-cgroup-probe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("user.slice")).unwrap();
        assert_eq!(probe(&root, "/user.slice"), None);
        assert_eq!(
            fs::read_dir(root.join("user.slice")).unwrap().count(),
            0,
            "no cgroup left behind"
        );

        fs::write(root.join("file"), "").unwrap();
        let said = probe(&root, "/file").expect("a file has no cgroups below it");
        for part in [
            root.join("file").to_str().unwrap(),
            "Not a directory",
            "containers will not start",
            "systemd-run --user --scope kithd",
        ] {
            assert!(said.contains(part), "`{part}` is not in: {said}");
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// Where kithd is root and the container has a range: its 65536 ids are the range's, its
    /// root is the image mounted id-mapped (no owner of it changed), each volume is its own
    /// id-mapped mount, and its users are what they would be without the range.
    #[test]
    fn idmapped_a_containers_ids_are_its_range_and_its_image_and_volumes_are_mapped() {
        let (uid, gid) = (nix::unistd::Uid::from_raw(0), nix::unistd::Gid::from_raw(0));
        let image = Image {
            entrypoint: vec!["/bin/true".into()],
            rootfs: "/images/x/rootfs".into(),
            ..Image::default()
        };
        let unit = Unit {
            as_image: true,
            writable: true,
            mounts: vec![bind("/srv/data", "/data", false), bind("/srv/ro", "/ro", true)],
            ..Unit::default()
        };
        let base = 3 * RANGE;
        let made = spec_shifted("a", &image, &unit, "/kith/a", Path::new("/b"), (uid, gid), Some(base)).unwrap();
        let linux = made.linux().as_ref().unwrap();
        for maps in [linux.uid_mappings(), linux.gid_mappings()] {
            let maps = maps.as_ref().unwrap();
            assert_eq!(maps.len(), 1);
            assert_eq!(
                (maps[0].container_id(), maps[0].host_id(), maps[0].size()),
                (0, base, RANGE)
            );
        }
        let user = oci_spec::runtime::LinuxNamespaceType::User;
        assert!(linux.namespaces().as_ref().unwrap().iter().any(|ns| ns.typ() == user));
        assert_eq!(
            made.root().as_ref().unwrap().path(),
            Path::new(STAGE).join("root").as_path()
        );
        let mounts = made.mounts().as_ref().unwrap();
        assert_eq!(
            mounts[0].options().as_ref().unwrap(),
            &[
                "lowerdir=/run/kith-stage/root",
                "upperdir=/run/kith-stage/bundle/upper",
                "workdir=/run/kith-stage/bundle/work",
                "userxattr"
            ]
        );
        let source = |at: &str| {
            let found = mounts.iter().find(|m| m.destination() == Path::new(at)).unwrap();
            found.source().clone().unwrap()
        };
        assert_eq!(source("/data"), Path::new("/run/kith-stage/v0"));
        assert_eq!(source("/ro"), Path::new("/run/kith-stage/v1"));
        // Its root is the range's first id, with what a runtime gives root: none of it the node's.
        let process = made.process().as_ref().unwrap();
        assert_eq!((process.user().uid(), process.user().gid()), (0, 0));
        assert_eq!(
            process.capabilities().as_ref().unwrap().bounding(),
            &Some(HashSet::from(ROOTS))
        );
        // A root that is not the node's may have a /proc that hides nothing.
        let nested = Unit {
            nested: true,
            user: Some(0),
            ..Unit::default()
        };
        assert!(spec_shifted("a", &image, &nested, "/kith/a", Path::new("/b"), (uid, gid), Some(base)).is_ok());
        assert!(spec_shifted("a", &image, &nested, "/kith/a", Path::new("/b"), (uid, gid), None).is_err());
        // A user past the range has no id in it: refused, never the node's.
        let far = Unit {
            user: Some(RANGE + 4),
            ..Unit::default()
        };
        let said = spec_shifted("a", &image, &far, "/kith/a", Path::new("/b"), (uid, gid), Some(base));
        assert!(said.unwrap_err().to_string().contains("past the 65536 ids"));
        // Where kithd is not root a range means nothing: one user, its own.
        let (me, us) = (nix::unistd::Uid::from_raw(1000), nix::unistd::Gid::from_raw(1000));
        let made = spec_shifted("a", &image, &unit, "/kith/a", Path::new("/b"), (me, us), Some(base)).unwrap();
        let maps = made.linux().as_ref().unwrap().uid_mappings().clone().unwrap();
        assert_eq!((maps[0].host_id(), maps[0].size()), (1000, 1));
        assert_eq!(made.root().as_ref().unwrap().path(), Path::new("/images/x/rootfs"));
    }

    /// Two containers never share a range: one being made holds its own until its bundle names
    /// it, a bundle's names it until the bundle goes (also over a restart), and a freed one is
    /// taken again.
    #[test]
    fn idmapped_two_containers_never_share_a_range() {
        let _taking = RANGE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let bundles = std::env::temp_dir().join(format!("kith-ranges-{}", std::process::id()));
        let _ = fs::remove_dir_all(&bundles);
        fs::create_dir_all(bundles.join("exec-unit")).unwrap();
        let first = take_range(&bundles).unwrap();
        let second = take_range(&bundles).unwrap();
        assert_ne!(first.0, second.0);
        assert!(
            first.0 >= RANGE && second.0 >= RANGE,
            "the node's own first range is never given"
        );
        // The first is now named by its bundle, and no longer held: still not given again.
        let image = Image {
            entrypoint: vec!["/bin/true".into()],
            ..Image::default()
        };
        let root = (nix::unistd::Uid::from_raw(0), nix::unistd::Gid::from_raw(0));
        let spec = spec_shifted(
            "a",
            &image,
            &Unit::default(),
            "/kith/a",
            Path::new("/b"),
            root,
            Some(first.0),
        );
        fs::create_dir_all(bundles.join("a")).unwrap();
        spec.unwrap().save(bundles.join("a").join("config.json")).unwrap();
        let named = first.0;
        drop(first);
        let third = take_range(&bundles).unwrap();
        assert!(third.0 != named && third.0 != second.0);
        // Its bundle gone, its range is free again.
        fs::remove_dir_all(bundles.join("a")).unwrap();
        let fourth = take_range(&bundles).unwrap();
        assert_eq!(fourth.0, named);
        let _ = fs::remove_dir_all(&bundles);
    }

    /// A container left behind whose processes outlive its kill (`cleanup`'s `sweep`) keeps its
    /// state and bundle, so its range is not given again while its user namespace has processes;
    /// once they are gone, both go and the range is free.
    #[test]
    fn idmapped_a_bundle_kept_by_a_failed_delete_holds_its_range() {
        let _taking = RANGE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("kith-swept-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (state, bundles, cgroup) = (root.join("state/a"), root.join("containers"), root.join("cgroup"));
        for dir in [&state, &bundles.join("a"), &cgroup] {
            fs::create_dir_all(dir).unwrap();
        }
        let held = take_range(&bundles).unwrap();
        let image = Image {
            entrypoint: vec!["/bin/true".into()],
            ..Image::default()
        };
        let root_ids = (nix::unistd::Uid::from_raw(0), nix::unistd::Gid::from_raw(0));
        let spec = spec_shifted(
            "a",
            &image,
            &Unit::default(),
            "/kith/a",
            Path::new("/b"),
            root_ids,
            Some(held.0),
        );
        spec.unwrap().save(bundles.join("a/config.json")).unwrap();
        let named = held.0;
        drop(held);
        fs::write(cgroup.join("cgroup.events"), "populated 1\n").unwrap();
        let mut killed = false;
        assert!(!sweep(&state, &bundles.join("a"), &cgroup, || killed = true));
        assert!(
            killed && state.exists() && bundles.join("a").exists(),
            "a unit that still runs is kept"
        );
        let taken: Vec<Range> = (0..3).map(|_| take_range(&bundles).unwrap()).collect();
        assert!(
            taken.iter().all(|range| range.0 != named),
            "its range is not given again"
        );
        fs::write(cgroup.join("cgroup.events"), "populated 0\n").unwrap();
        assert!(sweep(&state, &bundles.join("a"), &cgroup, || {}));
        assert!(
            !state.exists() && !bundles.join("a").exists(),
            "gone once nothing of it runs"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// A bundle whose config.json does not load may name a range: no range is given while it is
    /// there, and the refusal names it. One with no config.json (being made) names none.
    #[test]
    fn idmapped_an_unreadable_bundle_takes_no_range_from_anyone() {
        let _taking = RANGE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let bundles = std::env::temp_dir().join(format!("kith-unreadable-{}", std::process::id()));
        let _ = fs::remove_dir_all(&bundles);
        fs::create_dir_all(bundles.join("making")).unwrap();
        assert!(take_range(&bundles).is_ok());
        // (Its config.json cannot be looked at, here as it is under no directory: as unreadable.)
        fs::write(bundles.join("stray"), "").unwrap();
        let refused = take_range(&bundles)
            .err()
            .expect("no range while a bundle's config.json cannot be looked at");
        assert!(refused.to_string().contains("stray"), "{refused}");
        fs::remove_file(bundles.join("stray")).unwrap();
        fs::create_dir_all(bundles.join("torn")).unwrap();
        fs::write(bundles.join("torn/config.json"), "{\"ociVersion\":").unwrap();
        let refused = take_range(&bundles)
            .err()
            .expect("no range while a bundle cannot be read");
        assert!(refused.to_string().contains("torn"), "{refused}");
        let _ = fs::remove_dir_all(&bundles);
    }

    /// What keeps a container's users the node's: the node's network (its ports under 1024 are
    /// the node's root's), devices, a NodeWorkload, or a file system that takes no id-mapped
    /// mount. A pod, with a network of its own, otherwise gets a range, and joins its network
    /// from the thread it is made from rather than by the spec.
    #[test]
    fn idmapped_only_where_every_file_system_takes_it() {
        let here = std::env::temp_dir().join(format!("kith-shifts-{}", std::process::id()));
        fs::create_dir_all(&here).unwrap();
        let image = Image {
            rootfs: here.clone(),
            entrypoint: vec!["/bin/true".into()],
            ..Image::default()
        };
        let mapped = nix::sys::statfs::statfs(&here).unwrap().filesystem_type();
        let takes = [
            nix::sys::statfs::EXT4_SUPER_MAGIC,
            nix::sys::statfs::TMPFS_MAGIC,
            nix::sys::statfs::XFS_SUPER_MAGIC,
            nix::sys::statfs::BTRFS_SUPER_MAGIC,
        ];
        let pod = || Unit {
            netns: Some("/proc/1/ns/net".into()),
            ..Unit::default()
        };
        assert_eq!(shifts(&image, &pod()) == Ok(true), takes.contains(&mapped));
        let kept = [
            Unit::default(),
            Unit {
                devices: vec!["/dev/dri/card0".into()],
                ..pod()
            },
            Unit {
                host_users: true,
                ..pod()
            },
        ];
        let root = (nix::unistd::Uid::from_raw(0), nix::unistd::Gid::from_raw(0));
        let network = oci_spec::runtime::LinuxNamespaceType::Network;
        let joins = |shift: Option<u32>| {
            let spec = spec_shifted("a", &image, &pod(), "/kith/a", Path::new("/b"), root, shift).unwrap();
            let namespaces = spec.linux().clone().unwrap().namespaces().clone().unwrap();
            namespaces.iter().any(|ns| ns.typ() == network)
        };
        assert!(joins(None) && !joins(Some(RANGE)));
        for unit in kept {
            assert_eq!(shifts(&image, &unit), Ok(false), "{unit:?}");
        }
        // A pod kept so by a file system, not by its own unit, is told which path it was.
        // (/proc is no file system an id-mapped mount takes, as NFS is not.)
        let on_proc = Unit {
            mounts: vec![bind("/proc", "/x", true)],
            ..pod()
        };
        assert_eq!(shifts(&image, &on_proc), Err(Path::new("/proc")));
        let elsewhere = Image {
            rootfs: "/proc".into(),
            ..image.clone()
        };
        assert_eq!(shifts(&elsewhere, &pod()), Err(Path::new("/proc")));
        assert_eq!(shifts(&elsewhere, &Unit::default()), Ok(false), "its unit says first");
        let _ = fs::remove_dir_all(&here);
    }

    /// A bundle with no state (a container being made when kithd stopped: its config.json may be
    /// empty after a power cut, and then no range is given) is removed by `cleanup` unless its
    /// cgroup has processes; only what was removed is counted.
    #[test]
    fn idmapped_a_bundle_left_with_no_state_is_swept_unless_its_cgroup_runs() {
        let root = std::env::temp_dir().join(format!("kith-unmade-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        // (A parent under the node's /sys/fs/cgroup that is not there: nothing of the node's is
        // killed; the cgroups asked about are `sys`'s.)
        let parent = format!("/kith-test-unmade-{}", std::process::id());
        let runtime = Runtime {
            root: root.clone(),
            cgroup_parent: parent.clone(),
            images: ImageStore::new(root.join("images")).unwrap(),
            shim: "/proc/self/exe".into(),
        };
        fs::create_dir_all(root.join("state")).unwrap();
        for name in ["torn", "running"] {
            fs::create_dir_all(root.join("containers").join(name)).unwrap();
            fs::write(root.join("containers").join(name).join("config.json"), "").unwrap();
        }
        let sys = root.join("sys");
        let running = sys.join(parent.trim_start_matches('/')).join("kith-running");
        fs::create_dir_all(&running).unwrap();
        fs::write(running.join("cgroup.events"), "populated 1\n").unwrap();
        assert!(take_range(&root.join("containers")).is_err());
        assert_eq!(runtime.sweep_left(&sys).unwrap(), 1, "only what was removed is counted");
        assert!(!root.join("containers/torn").exists(), "nothing of it ran: gone");
        assert!(
            root.join("containers/running").exists(),
            "its cgroup has processes: kept"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
