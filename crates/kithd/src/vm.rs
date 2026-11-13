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
// under QEMU and has no network under cloud-hypervisor; a disk is a raw image at a path on
// the node, not a Volume; x86-64 and arm64 machine types only. Each has its own day.

use kith_api::kinds::{ExecUnit, Hypervisor, VmUnit};
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

/// The hypervisor's command line for `vm`, with the PCI devices at `pci` passed through.
pub fn command(vm: &VmUnit, pci: &[String]) -> Vec<String> {
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
            for disk in &vm.disks {
                let ro = if read_only(disk) { ",readonly=on" } else { "" };
                say(&["-drive", &format!("file={},format=raw,if=virtio{ro}", disk.path)]);
            }
            for address in pci {
                say(&["-device", &format!("vfio-pci,host={address}")]);
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
            for disk in &vm.disks {
                let ro = if read_only(disk) { ",readonly=on" } else { "" };
                say(&["--disk", &format!("path={}{ro}", disk.path)]);
            }
            for address in pci {
                say(&["--device", &format!("path={}/", Path::new(PCI).join(address).display())]);
            }
        }
    }
    line
}

/// `vm` as the exec unit that runs it.
pub fn exec(vm: &VmUnit, devices: &[PathBuf]) -> ExecUnit {
    ExecUnit {
        name: vm.name.clone(),
        command: command(vm, &pci(devices)),
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
        let line = command(&unit, &[]);
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
        let qemu = exec(&unit, &granted);
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
        let line = command(&unit, &["0000:01:00.0".to_string()]);
        let has = |words: &[&str]| line.windows(words.len()).any(|at| at == words);
        assert_eq!(line[0], "cloud-hypervisor");
        assert!(has(&["--cpus", "boot=4", "--memory", "size=268435456"]), "{line:?}");
        assert!(has(&["--kernel", "/boot/vmlinux"]) && has(&["--cmdline", "console=ttyS0"]));
        assert!(has(&["--disk", "path=/var/d.raw,readonly=on"]));
        assert!(has(&["--device", "path=/sys/bus/pci/devices/0000:01:00.0/"]));
        assert!(has(&["--serial", "tty", "--console", "off"]));
    }
}
