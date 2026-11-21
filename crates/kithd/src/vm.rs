//! A `vms` unit of a template: a virtual machine, run by a hypervisor that is on the node.
//!
//! kithd runs no machine itself: it works out the hypervisor's command line and runs that
//! as the supervised process an exec unit is (its own cgroup, its output in the unit's log,
//! restarted as the template says). The machine's serial console is the unit's output. Each
//! PCI Device a DeviceClaim of the replica holds is passed through (VFIO): a Device whose
//! path is `/sys/bus/pci/devices/ADDRESS`, which [`crate::devices`] finds for every PCI
//! device bound to `vfio-pci`.
//
// ponytail: kithd does not bind a device to vfio-pci (the node's owner does, on the kernel's
// command line: `vfio-pci.ids=`); a machine reaches out through the hypervisor's own NAT
// under QEMU and has no network under cloud-hypervisor; a disk is a raw image, at a path on
// the node or in a Volume's directory on the node that has the Volume ([`resolve`]); x86-64
// and arm64 machine types only. Each is left for later.
//
// ponytail: a disk in a Volume is opened by the hypervisor by name, after kithd checked it is a
// regular file ([`make_images`]): a container that mounts the same Volume could swap it for a
// link in between. Keep a Volume that holds a disk mounted by no container, and run the machine
// as one replica (two would write one image). Open it by descriptor (QEMU's `fd=` protocol,
// cloud-hypervisor's `fd=`) when a Volume is shared with anything else.
//
// A template that is `confidential` runs its machines with their memory encrypted by the
// processor (AMD SEV-SNP or Intel TDX), where the node has one of the two; nothing of it
// runs on a node that has neither.
//
// ponytail: QEMU's options as its documentation gives them, never run on such a processor
// here; the scheduler does not know which nodes have one (a `placement` says), and nobody
// outside is shown the guest's measurement (attestation). Those are next.

use crate::volumes::Dir;
use kith_api::kinds::{ExecUnit, Hypervisor, VmDisk, VmUnit};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Where the kernel lists PCI devices, and a Device that is one has its path.
pub const PCI: &str = "/sys/bus/pci/devices";

/// The PCI addresses (`0000:01:00.0`) among the device paths a replica was granted.
pub fn pci(devices: &[PathBuf]) -> Vec<String> {
    let address = |path: &PathBuf| {
        let address = path.strip_prefix(PCI).ok()?.to_str()?;
        // DOMAIN:BUS:DEVICE.FUNCTION in hex, and nothing else (it goes into an option).
        // (The domain is four digits, or more behind some bridges: `10000:e0:00.0`.)
        let (domain, rest) = address.split_once(':')?;
        let shaped = (4..=8).contains(&domain.len())
            && domain.bytes().all(|b| b.is_ascii_hexdigit())
            && rest.len() == 7
            && rest.bytes().enumerate().all(|(at, b)| match at {
                2 => b == b':',
                5 => b == b'.',
                _ => b.is_ascii_hexdigit(),
            });
        shaped.then(|| address.to_string())
    };
    devices.iter().filter_map(address).collect()
}

/// What keeps a guest's memory encrypted, out of reach of the node it runs on.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Guard {
    /// AMD SEV-SNP.
    SevSnp,
    /// Intel TDX.
    Tdx,
}

/// What this machine has for that, as its KVM says under `sys` (`/sys`): the processor has
/// it, the firmware has it on, and the kernel uses it.
pub fn guard(sys: &Path) -> Option<Guard> {
    let on = |module: &str, parameter: &str| {
        let said = std::fs::read_to_string(sys.join("module").join(module).join("parameters").join(parameter));
        said.is_ok_and(|said| matches!(said.trim(), "Y" | "1"))
    };
    if on("kvm_amd", "sev_snp") {
        Some(Guard::SevSnp)
    } else {
        on("kvm_intel", "tdx").then_some(Guard::Tdx)
    }
}

/// What a template's machines run under on a machine that has `guard`: nothing more unless
/// the template is `confidential`, which a machine that has no guard refuses.
pub fn confidential(asked: Option<bool>, guard: Option<Guard>) -> Result<Option<Guard>, String> {
    match (asked == Some(true), guard) {
        (false, _) => Ok(None),
        (true, Some(guard)) => Ok(Some(guard)),
        (true, None) => Err("confidential: this node keeps no guest's memory encrypted \
                             (no AMD SEV-SNP and no Intel TDX that its kernel uses), so nothing of this runs here"
            .into()),
    }
}

/// An image a machine's disk is, in a Volume's directory: made once, if the file is not there.
#[derive(Debug, Clone, PartialEq)]
pub struct Image {
    pub dir: Dir,
    pub file: String,
    /// Its size in bytes (the file is sparse).
    pub size: u64,
}

/// `vm` with each disk that names a Volume given the path of its file on this node (in the
/// directory of the Volume among `volumes`, the Volumes this node holds for the workload, by
/// the name the disk gives), and the images that are to be there before it starts. Nothing is
/// made here: a replica that never starts leaves nothing behind. A Volume this node does not
/// hold is why the machine does not run here.
pub fn resolve(
    vm: &VmUnit,
    state: &Path,
    me: &str,
    volumes: &BTreeMap<String, Dir>,
) -> Result<(VmUnit, Vec<Image>), String> {
    // (As `host_dir` has it: the directory it makes is under the state directory as it really is.)
    let state = state.canonicalize().unwrap_or_else(|_| state.to_path_buf());
    let (mut placed, mut images) = (vm.clone(), Vec::new());
    for disk in &mut placed.disks {
        let Some(name) = &disk.volume else { continue };
        let dir = volumes
            .get(name)
            .ok_or_else(|| format!("disks: volume {name} is not on this node"))?;
        // (A shared Volume of another node is mounted into a container, and no file of it is a disk.)
        if dir.node != me {
            return Err(format!(
                "disks: volume {name} is on node {}, not on this node",
                dir.node
            ));
        }
        let file = disk.file.clone().unwrap_or_else(|| VmDisk::FILE.into());
        let at = crate::volumes::planned(&state, dir).join(&file);
        // (It goes into an option of the hypervisor's: a comma would start another.)
        let at = at
            .to_str()
            .filter(|at| !at.contains(',') && !at.contains(char::is_control));
        disk.path = Some(
            at.ok_or("disks: the Volume's directory has a comma or a control character in its path")?
                .into(),
        );
        let size = disk.size.as_ref().map_or(0.0, |size| size.value()) as u64;
        images.push(Image {
            dir: dir.clone(),
            file,
            size,
        });
    }
    Ok((placed, images))
}

/// Make each image that is not in its Volume's directory yet, a sparse file of its size that only
/// kithd can read. A file that is there is left as the machine wrote it, whatever its size; one
/// that is no regular file (a link, a directory put in its place) is refused. Blocking file I/O.
pub fn make_images(state: &Path, images: &[Image]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    for Image { dir, file, size } in images {
        let said = |why: &dyn std::fmt::Display| format!("volume {}: {file}: {why}", dir.name);
        let root = crate::volumes::host_dir(state, dir).map_err(|e| format!("volume {}: {e}", dir.name))?;
        // (Where the machine's command line says it is, and not elsewhere.)
        let planned = crate::volumes::planned(&state.canonicalize().map_err(|e| said(&e))?, dir);
        if root.real() != planned {
            return Err(said(&format!(
                "the directory is at {}, not {}",
                root.real().display(),
                planned.display()
            )));
        }
        let at = root.held().join(file);
        // (`create_new` is O_EXCL: it makes nothing where a link is, and does not follow one.)
        let made = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&at);
        match made {
            Ok(image) => {
                if let Err(e) = image.set_len(*size) {
                    let _ = std::fs::remove_file(&at);
                    return Err(said(&e));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // (Not opened: a FIFO put there would block it.)
                if !std::fs::symlink_metadata(&at).is_ok_and(|kind| kind.is_file()) {
                    return Err(said(&"it is not a regular file"));
                }
            }
            Err(e) => return Err(said(&e)),
        }
    }
    Ok(())
}

/// The hypervisor's command line for `vm`, with the PCI devices at `pci` passed through, its
/// memory encrypted by `guard` if there is one (QEMU's options: the spec has no other then).
/// A disk that names a Volume has its path from [`resolve`]: one that has none is left out.
pub fn command(vm: &VmUnit, pci: &[String], guard: Option<Guard>) -> Vec<String> {
    let (cpus, bytes) = (vm.cpus.unwrap_or(1), vm.memory.value() as u64);
    let read_only = |disk: &kith_api::kinds::VmDisk| disk.read_only == Some(true);
    let mut line: Vec<String> = Vec::new();
    let mut say = |words: &[&str]| line.extend(words.iter().map(|word| word.to_string()));
    match vm.hypervisor.as_ref().unwrap_or(&Hypervisor::Qemu) {
        Hypervisor::Qemu => {
            let arm = std::env::consts::ARCH == "aarch64";
            say(&[if arm {
                "qemu-system-aarch64"
            } else {
                "qemu-system-x86_64"
            }]);
            // Nothing it was not told of, no window, and an end (not a restart from inside)
            // when the machine restarts: the template's restart policy decides what then.
            say(&["-nodefaults", "-no-user-config", "-display", "none", "-no-reboot"]);
            say(&[
                "-enable-kvm",
                "-cpu",
                "host",
                "-machine",
                if arm { "virt" } else { "q35" },
            ]);
            say(&["-smp", &cpus.to_string(), "-m", &format!("{}M", bytes >> 20)]);
            say(&["-serial", "stdio", "-nic", "user,model=virtio-net-pci"]);
            if let Some(firmware) = &vm.firmware {
                say(&["-bios", firmware]);
            }
            if let Some(kernel) = &vm.kernel {
                say(&["-kernel", kernel]);
            }
            if let Some(initrd) = &vm.initrd {
                say(&["-initrd", initrd]);
            }
            if let Some(cmdline) = &vm.cmdline {
                say(&["-append", cmdline]);
            }
            for (disk, path) in vm.disks.iter().filter_map(|disk| Some((disk, disk.path.as_ref()?))) {
                let ro = if read_only(disk) { ",readonly=on" } else { "" };
                say(&["-drive", &format!("file={path},format=raw,if=virtio{ro}")]);
            }
            for address in pci {
                say(&["-device", &format!("vfio-pci,host={address}")]);
            }
            // (A later `-machine` adds to the first.)
            match guard {
                // ponytail: the C bit is bit 51 on every processor that has SEV-SNP so far
                // (EPYC Milan, Genoa, Turin); CPUID 0x8000001F says where it is on another.
                Some(Guard::SevSnp) => {
                    let hashes = if vm.kernel.is_some() { ",kernel-hashes=on" } else { "" };
                    let ram = format!(
                        "memory-backend-memfd,id=ram0,size={}M,share=true,prealloc=false",
                        bytes >> 20
                    );
                    say(&[
                        "-machine",
                        "confidential-guest-support=guard0,memory-backend=ram0",
                        "-object",
                        &ram,
                    ]);
                    let guest = format!("sev-snp-guest,id=guard0,cbitpos=51,reduced-phys-bits=1{hashes}");
                    say(&["-object", &guest]);
                }
                Some(Guard::Tdx) => {
                    say(&["-machine", "confidential-guest-support=guard0,kernel-irqchip=split"]);
                    say(&["-object", "tdx-guest,id=guard0"]);
                }
                None => {}
            }
        }
        Hypervisor::CloudHypervisor => {
            say(&[
                "cloud-hypervisor",
                "--cpus",
                &format!("boot={cpus}"),
                "--memory",
                &format!("size={bytes}"),
            ]);
            say(&["--serial", "tty", "--console", "off"]);
            // (Its firmware is given as the kernel is.)
            if let Some(kernel) = vm.kernel.as_ref().or(vm.firmware.as_ref()) {
                say(&["--kernel", kernel]);
            }
            if let Some(initrd) = &vm.initrd {
                say(&["--initramfs", initrd]);
            }
            if let Some(cmdline) = &vm.cmdline {
                say(&["--cmdline", cmdline]);
            }
            for (disk, path) in vm.disks.iter().filter_map(|disk| Some((disk, disk.path.as_ref()?))) {
                let ro = if read_only(disk) { ",readonly=on" } else { "" };
                say(&["--disk", &format!("path={path}{ro}")]);
            }
            for address in pci {
                say(&["--device", &format!("path={}/", Path::new(PCI).join(address).display())]);
            }
        }
    }
    line
}

/// The name of a machine's control socket in its replica's private runtime directory.
#[allow(dead_code)] // (slice C of T-1135 starts the machine with it)
pub const CONTROL: &str = "qmp.sock";

/// Gives QEMU's command `line` its control socket at `socket` (QMP, for [`crate::qmp`]; the
/// directory is the replica's alone, mode 0700, and the client makes the socket 0600) and, if
/// `incoming`, an incoming mode that waits to be told where from. Another hypervisor's is left as
/// it is. A `socket` that is not UTF-8, or has an `=` in it, is refused: it goes into an option.
#[allow(dead_code)]
pub fn control(line: &mut Vec<String>, socket: &Path, incoming: bool) -> Result<(), String> {
    if !line.first().is_some_and(|binary| binary.starts_with("qemu-system-")) {
        return Ok(());
    }
    let at = match socket.to_str() {
        Some(at) if !at.contains('=') => at,
        _ => return Err(format!("control socket {}: not UTF-8, or has an `=`", socket.display())),
    };
    // (A comma in an option's value is doubled.)
    let at = at.replace(',', ",,");
    let mut flags = vec!["-qmp".to_string(), format!("unix:{at},server=on,wait=off")];
    if incoming {
        flags.extend(["-incoming".to_string(), "defer".to_string()]);
    }
    line.splice(1..1, flags);
    Ok(())
}

/// `vm` as the exec unit that runs it.
pub fn exec(vm: &VmUnit, devices: &[PathBuf], guard: Option<Guard>) -> ExecUnit {
    ExecUnit {
        name: vm.name.clone(),
        command: command(vm, &pci(devices), guard),
        env: Vec::new(),
        resources: vm.resources.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vm(unit: serde_json::Value) -> VmUnit {
        serde_json::from_value(unit).unwrap()
    }

    /// A kernel started directly under QEMU: the machine as asked, its console on the unit's
    /// output, nothing passed as part of another option.
    #[test]
    fn a_vm_unit_is_a_qemu_command_line() {
        let unit = vm(
            json!({ "name": "vm", "kernel": "/boot/vmlinuz", "initrd": "/boot/initrd", "cmdline": "console=ttyS0 quiet", "cpus": 2,
            "memory": "1Gi", "disks": [{ "path": "/var/d.raw" }, { "path": "/var/ro.raw", "readOnly": true }] }),
        );
        let line = command(&unit, &[], None);
        assert!(line[0].starts_with("qemu-system-"));
        let has = |words: &[&str]| line.windows(words.len()).any(|at| at == words);
        assert!(has(&["-smp", "2", "-m", "1024M"]), "{line:?}");
        assert!(has(&["-kernel", "/boot/vmlinuz"]) && has(&["-initrd", "/boot/initrd"]));
        assert!(
            has(&["-append", "console=ttyS0 quiet"]),
            "the command line is one argument"
        );
        assert!(has(&["-serial", "stdio"]) && has(&["-no-reboot"]) && has(&["-enable-kvm"]));
        assert!(has(&["-drive", "file=/var/d.raw,format=raw,if=virtio"]));
        assert!(has(&["-drive", "file=/var/ro.raw,format=raw,if=virtio,readonly=on"]));
        assert!(!line.iter().any(|word| word.contains("vfio")));
        // From a disk: its firmware, and no kernel.
        let disk = command(
            &vm(
                json!({ "name": "vm", "firmware": "/fw/OVMF.fd", "disks": [{ "path": "/var/d.raw" }], "memory": "512Mi" }),
            ),
            &[],
            None,
        );
        assert!(disk.windows(2).any(|at| at == ["-bios", "/fw/OVMF.fd"]) && !disk.contains(&"-kernel".to_string()));
    }

    /// Only a Device that is a PCI device (bound to vfio-pci) is passed through, by its
    /// address as the kernel writes it; a device node, or a path that is not one address, is not.
    #[test]
    fn a_vm_unit_is_given_the_pci_devices_its_claims_hold() {
        let granted: Vec<PathBuf> = [
            "/sys/bus/pci/devices/0000:01:00.0",
            "/dev/dri/card0",
            "/sys/bus/pci/devices/10000:e0:00.1",
            "/sys/bus/pci/devices/0000:01:00.0,x-evil=on",
            "/sys/bus/pci/devices/../../../etc",
            "/sys/bus/pci/devices/0000:01:00.0/driver",
        ]
        .map(PathBuf::from)
        .into();
        let held = pci(&granted);
        assert_eq!(held, ["0000:01:00.0", "10000:e0:00.1"]);
        let unit = vm(
            json!({ "name": "gpu", "firmware": "/fw/OVMF.fd", "disks": [{ "path": "/var/win.raw" }], "memory": "8Gi" }),
        );
        let qemu = exec(&unit, &granted, None);
        assert_eq!(qemu.name, "gpu");
        let has = |line: &[String], words: &[&str]| line.windows(words.len()).any(|at| at == words);
        assert!(has(&qemu.command, &["-device", "vfio-pci,host=0000:01:00.0"]));
        assert!(has(&qemu.command, &["-device", "vfio-pci,host=10000:e0:00.1"]));
        assert_eq!(
            qemu.command.iter().filter(|word| word.starts_with("vfio-pci")).count(),
            2
        );
    }

    /// The same machine under cloud-hypervisor: a microVM.
    #[test]
    fn a_vm_unit_is_a_cloud_hypervisor_command_line() {
        let unit = vm(
            json!({ "name": "vm", "hypervisor": "cloudHypervisor", "kernel": "/boot/vmlinux", "cmdline": "console=ttyS0", "cpus": 4,
            "memory": "256Mi", "disks": [{ "path": "/var/d.raw", "readOnly": true }] }),
        );
        let line = command(&unit, &["0000:01:00.0".to_string()], None);
        let has = |words: &[&str]| line.windows(words.len()).any(|at| at == words);
        assert_eq!(line[0], "cloud-hypervisor");
        assert!(has(&["--cpus", "boot=4", "--memory", "size=268435456"]), "{line:?}");
        assert!(has(&["--kernel", "/boot/vmlinux"]) && has(&["--cmdline", "console=ttyS0"]));
        assert!(has(&["--disk", "path=/var/d.raw,readonly=on"]));
        assert!(has(&["--device", "path=/sys/bus/pci/devices/0000:01:00.0/"]));
        assert!(has(&["--serial", "tty", "--console", "off"]));
    }
    /// A disk that names a Volume is a file in the Volume's directory on this node, and the
    /// sparse image of its size is made there once: what is there is never made again, and
    /// what is no regular file there (a link a container put in its place) is refused.
    #[test]
    fn vm_disk_volume_is_the_volumes_file_made_sparse_once() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let state = std::env::temp_dir().join(format!("kith-vm-disk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        std::fs::create_dir_all(&state).unwrap();
        let state = state.canonicalize().unwrap();
        let dir = crate::volumes::Dir {
            namespace: "default".into(),
            name: "home".into(),
            path: "data".into(),
            node: "a".into(),
            encrypted: false,
        };
        let volumes = BTreeMap::from([("home".to_string(), dir)]);
        let unit = vm(
            json!({ "name": "vm", "firmware": "/fw/OVMF.fd", "memory": "1Gi", "disks": [
            { "volume": "home", "size": "64Mi" },
            { "volume": "home", "file": "scratch.img", "size": "1Mi", "readOnly": true },
            { "path": "/var/d.raw" }] }),
        );
        let (placed, images) = resolve(&unit, &state, "a", &volumes).unwrap();
        let root = state.join("volumes/default/home/data");
        let line = command(&placed, &[], None);
        let has = |words: &[&str]| line.windows(words.len()).any(|at| at == words);
        assert!(has(&[
            "-drive",
            &format!("file={}/disk.img,format=raw,if=virtio", root.display())
        ]));
        assert!(has(&[
            "-drive",
            &format!("file={}/scratch.img,format=raw,if=virtio,readonly=on", root.display())
        ]));
        assert!(has(&["-drive", "file=/var/d.raw,format=raw,if=virtio"]));
        assert_eq!(images.len(), 2, "the disk at a path is no image of the Volume's");
        // (Planning made nothing: a directory made for a replica that never starts is left behind.)
        assert!(!root.exists());

        make_images(&state, &images).unwrap();
        let image = root.join("disk.img");
        let made = std::fs::metadata(&image).unwrap();
        assert!(made.is_file() && made.len() == 64 << 20);
        assert_eq!(made.permissions().mode() & 0o777, 0o600);
        assert!(made.blocks() * 512 < made.len(), "sparse: {} blocks", made.blocks());
        assert_eq!(std::fs::metadata(root.join("scratch.img")).unwrap().len(), 1 << 20);

        // A second start leaves what the guest wrote, and its size, as they are.
        std::fs::write(&image, b"guest").unwrap();
        make_images(&state, &images).unwrap();
        assert_eq!(std::fs::read(&image).unwrap(), b"guest");

        // A link put where the image is, or a directory, is refused and nothing behind it is touched.
        let outside = state.join("outside");
        std::fs::write(&outside, b"mine").unwrap();
        std::fs::remove_file(&image).unwrap();
        std::os::unix::fs::symlink(&outside, &image).unwrap();
        let refused = make_images(&state, &images).unwrap_err();
        assert!(refused.contains("disk.img"), "{refused}");
        assert_eq!(std::fs::read(&outside).unwrap(), b"mine");
        std::fs::remove_file(&image).unwrap();
        std::fs::create_dir(&image).unwrap();
        assert!(make_images(&state, &images).unwrap_err().contains("not a regular file"));

        // No Volume of the name on this node: no machine here, and the reason says which.
        let lacking = resolve(&unit, &state, "a", &BTreeMap::new()).unwrap_err();
        assert!(lacking.contains("home") && lacking.contains("this node"), "{lacking}");
        let elsewhere = resolve(&unit, &state, "b", &volumes).unwrap_err();
        assert!(elsewhere.contains("on node a, not on this node"), "{elsewhere}");
        let _ = std::fs::remove_dir_all(&state);
    }

    /// A confidential template's machine is started with its memory encrypted by what the
    /// node has, and not at all on a node that has neither SEV-SNP nor TDX.
    #[test]
    fn a_confidential_vm_runs_under_what_the_node_has_and_is_refused_where_it_has_nothing() {
        // What KVM says of itself, as files: a machine with none, an AMD one, an Intel one.
        let sys = std::env::temp_dir().join(format!("kith-vm-sys-{}", std::process::id()));
        let says = |module: &str, parameter: &str, value: &str| {
            let _ = std::fs::remove_dir_all(&sys);
            let at = sys.join("module").join(module).join("parameters");
            std::fs::create_dir_all(&at).unwrap();
            std::fs::write(at.join(parameter), value).unwrap();
            guard(&sys)
        };
        assert_eq!(
            says("kvm_amd", "sev", "Y\n"),
            None,
            "SEV alone encrypts with a key the host could misuse"
        );
        assert_eq!(says("kvm_amd", "sev_snp", "N\n"), None);
        assert_eq!(says("kvm_amd", "sev_snp", "Y\n"), Some(Guard::SevSnp));
        assert_eq!(says("kvm_intel", "tdx", "N\n"), None);
        assert_eq!(says("kvm_intel", "tdx", "Y\n"), Some(Guard::Tdx));
        let _ = std::fs::remove_dir_all(&sys);
        assert_eq!(guard(Path::new("/nowhere/at/all")), None);

        // Not asked for: as any machine, whatever the node has. Asked for: only with a guard.
        assert_eq!(confidential(None, Some(Guard::Tdx)), Ok(None));
        assert_eq!(confidential(Some(false), None), Ok(None));
        assert_eq!(confidential(Some(true), Some(Guard::SevSnp)), Ok(Some(Guard::SevSnp)));
        let refused = confidential(Some(true), None).unwrap_err();
        assert!(refused.contains("no AMD SEV-SNP and no Intel TDX"), "{refused}");

        let unit = vm(json!({ "name": "vm", "firmware": "/fw/OVMF.fd", "kernel": "/k", "memory": "2Gi" }));
        let plain = command(&unit, &[], None);
        assert!(
            !plain
                .iter()
                .any(|word| word.contains("guard0") || word.contains("memfd"))
        );
        let has = |line: &[String], words: &[&str]| line.windows(words.len()).any(|at| at == words);
        let snp = command(&unit, &[], Some(Guard::SevSnp));
        assert!(
            has(
                &snp,
                &["-machine", "confidential-guest-support=guard0,memory-backend=ram0"]
            ),
            "{snp:?}"
        );
        assert!(has(
            &snp,
            &[
                "-object",
                "memory-backend-memfd,id=ram0,size=2048M,share=true,prealloc=false"
            ]
        ));
        // (The kernel it was told to start is part of what is measured.)
        assert!(has(
            &snp,
            &[
                "-object",
                "sev-snp-guest,id=guard0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on"
            ]
        ));
        assert!(has(&snp, &["-m", "2048M"]) && has(&snp, &["-bios", "/fw/OVMF.fd"]));
        let tdx = command(&unit, &[], Some(Guard::Tdx));
        assert!(
            has(
                &tdx,
                &["-machine", "confidential-guest-support=guard0,kernel-irqchip=split"]
            ),
            "{tdx:?}"
        );
        assert!(has(&tdx, &["-object", "tdx-guest,id=guard0"]) && !tdx.iter().any(|word| word.contains("sev")));
    }
}
