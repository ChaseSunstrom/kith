//! Running one container from an [`Image`].

use crate::{Context, Image, ImageStore, Result, err};
use libcontainer::container::Container;
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use oci_spec::runtime::{
    LinuxCpuBuilder, LinuxMemoryBuilder, LinuxResourcesBuilder, Mount, MountBuilder, RootBuilder, Spec,
};
use std::fs::{self, File};
use std::path::{Path, PathBuf};

pub struct Runtime {
    root: PathBuf,
    cgroup_parent: String,
    pub images: ImageStore,
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
}

/// A created container. Dropping it does not stop it; call [`Handle::delete`].
pub struct Handle {
    container: Container,
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
            let _ = fs::remove_dir_all(entry.path());
            let _ = fs::remove_dir_all(self.root.join("containers").join(entry.file_name()));
        }
        Ok(found)
    }

    /// Create the container `id`: namespaces and cgroup are set up and the
    /// process is ready, but it does not run until [`Handle::start`].
    ///
    // ponytail: the image's rootfs is shared read-only, with tmpfs on /tmp and /run,
    // and the host's network. A writable overlay per container and a network
    // namespace on the mesh come with volumes and Phase 2.
    pub fn create(&self, id: &str, image: &Image, unit: &Unit, stdout: File, stderr: File) -> Result<Handle> {
        let what = format!("creating container `{id}`");
        let bundle = self.root.join("containers").join(id);
        let cgroup = format!("{}/kith-{id}", self.cgroup_parent);

        // Validate the id before it is used as a directory name.
        let builder = ContainerBuilder::new(id.into(), SyscallType::Linux)
            .validate_id()
            .ctx(&what)?;
        let spec = spec(id, image, unit, &cgroup).ctx(&what)?;
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
        let mut handle = Handle {
            container,
            pid,
            reaped: false,
            bundle,
            cgroup: Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/')),
        };
        // A memory limit that swap could stretch is no limit. The OCI spec cannot say
        // "no swap" (libcgroups reads 0 as "leave it"), so it is written here.
        if unit.memory_bytes.is_some() {
            match fs::write(handle.cgroup.join("memory.swap.max"), "0") {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    let _ = handle.container.delete(true);
                    let _ = fs::remove_dir_all(&handle.bundle);
                    return Err(e).ctx(format!("{what}: turning swap off"));
                }
                _ => {} // No such file: this kernel does no swap accounting.
            }
        }
        Ok(handle)
    }
}

impl Handle {
    pub fn start(&mut self) -> Result<()> {
        self.container.start().ctx("starting the container")
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
        self.container
            .kill(nix::sys::signal::Signal::SIGKILL, true)
            .ctx("killing the container")
    }

    /// Kill it if it still runs, then remove its cgroup, state and bundle.
    pub fn delete(mut self) -> Result<()> {
        let deleted = self.container.delete(true).ctx("deleting the container");
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

fn spec(id: &str, image: &Image, unit: &Unit, cgroup: &str) -> std::result::Result<Spec, Box<dyn std::error::Error>> {
    let (uid, gid) = (nix::unistd::getuid(), nix::unistd::getgid());
    let mut spec = if uid.is_root() {
        Spec::default()
    } else {
        Spec::rootless(uid.as_raw(), gid.as_raw())
    };
    // No network namespace, as root too: containers share the host's network until the mesh (Phase 2).
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
        env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
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
    spec.set_process(Some(process));

    let tmpfs = |at: &str| -> std::result::Result<Mount, Box<dyn std::error::Error>> {
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
    // The container shares the host's network for now, so it needs the host's resolver.
    if Path::new("/etc/resolv.conf").exists() {
        let options = ["rbind", "ro"].map(String::from).to_vec();
        let resolv = MountBuilder::default().destination("/etc/resolv.conf").typ("bind");
        mounts.push(resolv.source("/etc/resolv.conf").options(options).build()?);
    }
    spec.set_mounts(Some(mounts));

    let mut resources = LinuxResourcesBuilder::default();
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
    let mut linux = spec.linux().clone().unwrap_or_default();
    linux.set_cgroups_path(Some(cgroup.into()));
    linux.set_resources(Some(resources.build()?));
    spec.set_linux(Some(linux));
    Ok(spec)
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
        assert_eq!(resources.memory().as_ref().unwrap().limit(), Some(1 << 20));
    }
}
