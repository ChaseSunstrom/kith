//! The node's own policy: what the cluster's store may have this node do as its root
//! (docs/adr-privilege.md, "The node's own policy"). It is given to kithd where it is
//! started (`--node-policy`: on kith OS the node's config partition, which the installer
//! writes and no API reaches), never read from the store: a stolen certificate of the
//! cluster, or a hole in the store, is then not root on a node whose owner said so.
//!
//! Every key is on where nothing is said: a node does what it did before there was one.

use kith_api::kinds::{DeviceClass, Template};
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// Each key: the word that names it in `--node-policy`, as a Node's status and the design
/// record name it, and what it lets the store have this node do. A new way for the store
/// to be root on a node gets a row here in the same change.
pub const KEYS: [(&str, &str, &str); 10] = [
    (
        "exec-units",
        "execUnits",
        "exec units: processes of the node's root, with all of /dev",
    ),
    (
        "root-containers",
        "rootContainers",
        "containers that are the node's root",
    ),
    (
        "unconfined",
        "unconfined",
        "containers with no system call filter, or with refused calls allowed back",
    ),
    (
        "node-network",
        "nodeNetwork",
        "containers on the node's own network (no pod)",
    ),
    ("vms", "vms", "virtual machines"),
    (
        "vm-paths",
        "vmPaths",
        "a virtual machine's kernel, firmware or disks as paths on the node, or another hypervisor than qemu",
    ),
    ("passthrough", "passthrough", "PCI devices handed to a virtual machine"),
    (
        "host-paths",
        "hostPaths",
        "a Volume of kith-system: a directory anywhere on the node, as its path says",
    ),
    ("run", "run", "POST /v1/run"),
    (
        "wipe",
        "wipe",
        "a NodeKey of the store erasing this node, or changing its duress keys",
    ),
];

/// The keys that, all off, let kithd cut its bounding set: each is a way for the store to
/// have this node exec a process as root with every capability the kernel has (an exec unit,
/// a VM's qemu with the paths it is told, `/v1/run`). With none of them, what kithd execs
/// is a container's process (which gets its own list) or a helper (git, a VM's qemu).
const BOUNDED_BY: [&str; 3] = ["execUnits", "vmPaths", "run"];

/// What a hardened node keeps in its bounding set (docs/adr-privilege.md, "Step A"): the
/// number the kernel gives each capability, its name, and which process that kithd starts
/// by an exec holds it. The bounding set limits only what an exec gives a child, never
/// kithd's own threads (they keep what they have), so kithd's own needs (mounts, links,
/// cgroups, powering off) are not on this list. A capability joins it only for a child
/// that is exec'd (a container's process, the exec shim, a helper) and fails for want of
/// it, with that child named here. Never SYS_MODULE, SYS_RAWIO, SYS_PTRACE or SYS_TIME.
pub const KEPT: [(u32, &str, &str); 14] = [
    (0, "CHOWN", "a root pod: chown of what it owns (ROOTS)"),
    (
        1,
        "DAC_OVERRIDE",
        "a root pod: files of other owners in its own view (ROOTS)",
    ),
    (
        3,
        "FOWNER",
        "a root pod: chmod and utimes of files of other owners (ROOTS)",
    ),
    (4, "FSETID", "a root pod: set-id bits kept on write (ROOTS)"),
    (5, "KILL", "a root pod: signals to processes of other users (ROOTS)"),
    (
        6,
        "SETGID",
        "a root pod: setgid, and the group of a unit that drops to a user (ROOTS)",
    ),
    (
        7,
        "SETUID",
        "a root pod: setuid, and the user of a unit that drops to one (ROOTS)",
    ),
    (8, "SETPCAP", "a root pod: dropping its own capabilities (ROOTS)"),
    (10, "NET_BIND_SERVICE", "a root pod: ports below 1024 (ROOTS)"),
    (13, "NET_RAW", "a root pod: raw sockets, ping (ROOTS)"),
    (18, "SYS_CHROOT", "a root pod: chroot (ROOTS)"),
    (27, "MKNOD", "a root pod: device nodes of its own (ROOTS)"),
    (29, "AUDIT_WRITE", "a root pod: audit records of a login (ROOTS)"),
    (31, "SETFCAP", "a root pod: file capabilities (ROOTS)"),
];

/// The bounding set a node with this policy cuts itself to, as a mask of capability numbers:
/// none where any of the keys of [`BOUNDED_BY`] is on, which is as a node was before.
pub fn kept_mask(policy: &Policy) -> Option<u64> {
    BOUNDED_BY
        .iter()
        .all(|key| !policy.allows(key))
        .then(|| KEPT.iter().fold(0, |mask, (number, _, _)| mask | 1 << number))
}

/// The capabilities kithd cut itself to, as a mask; unset where it did not.
static CUT: OnceLock<u64> = OnceLock::new();

/// Drops from the calling thread's bounding set every capability the kernel has (read from
/// `/proc/sys/kernel/cap_last_cap`, so one a later kernel adds is dropped too) that `kept`
/// does not name. Needs CAP_SETPCAP.
fn drop_to(kept: u64) -> Result<(), String> {
    let last = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|e| format!("cutting the bounding set: /proc/sys/kernel/cap_last_cap: {e}"))?;
    let last: u32 = last
        .trim()
        .parse()
        .map_err(|_| format!("cutting the bounding set: cap_last_cap says {:?}", last.trim()))?;
    for cap in (0..=last).filter(|cap| *cap >= 64 || kept >> cap & 1 == 0) {
        kith_dm_sys::bounding_drop(cap)
            .map_err(|e| format!("cutting the bounding set: dropping capability {cap}: {e}"))?;
    }
    Ok(())
}

/// Cuts the bounding set of the calling thread, and so of everything it starts by an exec
/// (and of the threads it makes later), to what [`kept_mask`] says, if the policy says
/// anything. It limits only what an exec gives a child: kithd's own permitted and effective
/// sets are as they were, so a hole in kithd itself is not held back by it.
/// Call it from `main`'s thread before the runtime or any other thread is made: a thread
/// that exists keeps its own set. Does nothing where kithd is not root (there is nothing to
/// bound); the node's status says what it holds either way.
pub fn cut(policy: &Policy) -> Result<(), String> {
    let Some(kept) = kept_mask(policy) else {
        return Ok(());
    };
    if !nix::unistd::getuid().is_root() {
        return Ok(());
    }
    drop_to(kept)?;
    CUT.set(kept).expect("the bounding set is cut once, at start");
    // (Said once, from what the kernel now says of kithd and of a thread made after the cut,
    // for whoever reads the console and for `ci/vm.sh --test policy`: the bounding set is
    // cut and the effective set is not.)
    let own = capabilities(&format!("/proc/{}/status", std::process::id()));
    let later = std::thread::spawn(|| capabilities("/proc/thread-self/status"))
        .join()
        .unwrap_or_default();
    // (Not `eprintln!`: it panics when stderr cannot be written, and PID 1 may not.)
    let _ = std::io::Write::write_fmt(
        &mut std::io::stderr(),
        format_args!(
            "kithd: capability bounding set cut: CapBnd {} CapEff {}; a later thread: CapBnd {} CapEff {}\n",
            own.0, own.1, later.0, later.1
        ),
    );
    Ok(())
}

/// The `CapBnd` and `CapEff` lines of a `/proc/…/status`, as the kernel writes them (hex).
fn capabilities(path: &str) -> (String, String) {
    let status = std::fs::read_to_string(path).unwrap_or_default();
    let field = |name: &str| {
        let line = status.lines().find_map(|line| line.strip_prefix(name));
        line.unwrap_or("?").trim().to_string()
    };
    (field("CapBnd:"), field("CapEff:"))
}

/// What the node's status says it holds: the names of what it kept, or `all` where it was not cut.
fn held() -> Vec<&'static str> {
    match CUT.get() {
        None => vec!["all"],
        Some(kept) => KEPT
            .iter()
            .filter(|(number, _, _)| kept >> number & 1 == 1)
            .map(|(_, name, _)| *name)
            .collect(),
    }
}

/// The classes of Device a policy may name (`devices=gpu+input`), as a Device's spec does.
const CLASSES: [(&str, DeviceClass); 7] = [
    ("gpu", DeviceClass::Gpu),
    ("display", DeviceClass::Display),
    ("input", DeviceClass::Input),
    ("audio", DeviceClass::Audio),
    ("usb", DeviceClass::Usb),
    ("camera", DeviceClass::Camera),
    ("other", DeviceClass::Other),
];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Policy {
    /// The keys that are off, by their second name in [`KEYS`].
    off: BTreeSet<&'static str>,
    /// The classes of Device a DeviceClaim may hand a unit here; `None` is all of them.
    devices: Option<BTreeSet<&'static str>>,
}

static POLICY: OnceLock<Policy> = OnceLock::new();

/// What `--node-policy` said. A node that cannot read its own policy must not allow what its
/// owner meant to refuse, and as the first process it must not end over it either (the machine
/// would start again for ever, with nobody able to mend the word): there it runs hardened,
/// and says so.
pub fn read(text: Option<&str>, first: bool) -> Result<Policy, String> {
    match text.unwrap_or_default().parse() {
        Err(e) if first => {
            eprintln!("kithd: {e}: until that is mended in this node's config, it runs as `--node-policy hardened`");
            Ok(Policy::hardened())
        }
        read => read,
    }
}

/// Set once at start, before anything is run.
pub fn set(policy: Policy) {
    POLICY.set(policy).expect("the policy is set once, at start");
}

/// This node's policy: everything allowed where none was set.
pub fn get() -> Policy {
    POLICY.get().cloned().unwrap_or_default()
}

impl Policy {
    /// Everything off, and a GPU the only Device handed out.
    pub fn hardened() -> Policy {
        Policy {
            off: KEYS.iter().map(|(_, key, _)| *key).collect(),
            devices: Some(BTreeSet::from(["gpu"])),
        }
    }

    pub fn allows(&self, key: &str) -> bool {
        debug_assert!(
            KEYS.iter().any(|(_, known, _)| *known == key),
            "{key} is no key of the policy"
        );
        !self.off.contains(key)
    }

    /// Does it name the classes of Device handed out? Then a Device is what this node
    /// finds itself, never what the store says one is (`devices::as_found`).
    pub fn names_devices(&self) -> bool {
        self.devices.is_some()
    }

    /// Why what `key` names is not done on this node, where its policy has it off: the key,
    /// and the word that turns it on where the node's kithd is started.
    pub fn refusal(&self, key: &str) -> Option<String> {
        let (word, _, what) = KEYS.iter().find(|(_, known, _)| *known == key).expect("a key of KEYS");
        (!self.allows(key)).then(|| {
            format!(
                "this node's policy refuses {what} ({key} is off: `--node-policy {word}` where the node's kithd is started allows it)"
            )
        })
    }

    pub fn device(&self, class: &DeviceClass) -> bool {
        let name = CLASSES.iter().find(|(_, known)| known == class).map(|(name, _)| *name);
        self.devices
            .as_ref()
            .is_none_or(|allowed| name.is_some_and(|name| allowed.contains(name)))
    }

    /// As a Node's status says it: every key, the classes of Device, and the capabilities
    /// what kithd execs can hold (`all`, or the names of what a hardened node kept in its
    /// bounding set: [`KEPT`]; kithd's own threads hold more). Null where
    /// everything is allowed: a node with no policy says nothing.
    pub fn status(&self) -> serde_json::Value {
        if *self == Policy::default() {
            return serde_json::Value::Null;
        }
        let mut said = serde_json::Map::new();
        for (_, key, _) in KEYS {
            said.insert(key.to_string(), self.allows(key).into());
        }
        let devices: Vec<&str> = match &self.devices {
            None => vec!["all"],
            Some(allowed) => allowed.iter().copied().collect(),
        };
        said.insert("devices".into(), devices.into());
        said.insert("capabilities".into(), held().into());
        said.into()
    }

    /// Why a template is not run on this node, if its policy refuses any of it: one line
    /// for each key, naming the key and where it is set ([`needs`]).
    pub fn refuses(&self, template: &Template, pci: bool) -> Vec<String> {
        let needs = needs(template, pci).into_iter();
        needs.filter_map(|key| self.refusal(key)).collect()
    }

    /// The policy a Node's status says it has (`status.policy`, as [`Policy::status`] wrote
    /// it): the keys it says are off. For the scheduler, which places nothing on a node
    /// that says it refuses it; no node is trusted by it (a node that says otherwise than
    /// it does only has replicas it does not run).
    pub fn said(status: &serde_json::Value) -> Policy {
        let off = KEYS.iter().map(|(_, key, _)| *key);
        Policy {
            off: off.filter(|key| status[key] == false).collect(),
            devices: None,
        }
    }
}

/// The keys a template needs on to run on a node: one for each thing of it a node's policy
/// may refuse. `pci` says a claim of the replica holds a PCI device (which a VM of it
/// would be handed).
pub fn needs(template: &Template, pci: bool) -> Vec<&'static str> {
    let unconfined = |seccomp: &kith_api::kinds::Seccomp| seccomp.unconfined == Some(true) || !seccomp.allow.is_empty();
    let paths = |vm: &kith_api::kinds::VmUnit| {
        let other = vm
            .hypervisor
            .as_ref()
            .is_some_and(|h| *h != kith_api::kinds::Hypervisor::Qemu);
        other || vm.kernel.is_some() || vm.initrd.is_some() || vm.firmware.is_some() || !vm.disks.is_empty()
    };
    let vms = !template.vms.is_empty();
    let asked = [
        ("execUnits", !template.exec.is_empty()),
        (
            "unconfined",
            template
                .containers()
                .any(|c| c.seccomp.as_ref().is_some_and(unconfined)),
        ),
        (
            "nodeNetwork",
            template.containers().next().is_some() && template.pod != Some(true),
        ),
        ("vms", vms),
        ("vmPaths", vms && template.vms.iter().any(paths)),
        ("passthrough", vms && pci),
    ];
    asked
        .into_iter()
        .filter(|(_, asked)| *asked)
        .map(|(key, _)| key)
        .collect()
}

/// `--node-policy`: words with commas between, read left to right. `hardened` turns every
/// key off and leaves a GPU the only Device handed out; `no-KEY` turns one off and `KEY`
/// turns it on again; `devices=gpu+input` names the classes of Device a claim may hand out
/// (`devices=all`, or `devices=` for none). An unknown word is an error: a policy that was
/// half read would allow what its owner meant to refuse.
impl std::str::FromStr for Policy {
    type Err = String;

    fn from_str(text: &str) -> Result<Policy, String> {
        let mut policy = Policy::default();
        for word in text.split(',').map(str::trim).filter(|word| !word.is_empty()) {
            let key = |word: &str| KEYS.iter().find(|(known, _, _)| *known == word).map(|(_, key, _)| *key);
            if word == "hardened" {
                policy = Policy::hardened();
            } else if let Some(classes) = word.strip_prefix("devices=") {
                policy.devices = match classes {
                    "all" => None,
                    classes => {
                        let named = classes.split('+').filter(|class| !class.is_empty()).map(|class| {
                            let known = CLASSES.iter().find(|(name, _)| *name == class);
                            let classes: Vec<&str> = CLASSES.iter().map(|(name, _)| *name).collect();
                            known.map(|(name, _)| *name).ok_or_else(|| {
                                format!(
                                    "--node-policy: '{class}' is no class of Device ({})",
                                    classes.join(", ")
                                )
                            })
                        });
                        Some(named.collect::<Result<_, _>>()?)
                    }
                };
            } else if let Some(key) = word.strip_prefix("no-").and_then(key) {
                policy.off.insert(key);
            } else if let Some(key) = key(word) {
                policy.off.remove(key);
            } else {
                let words: Vec<&str> = KEYS.iter().map(|(word, _, _)| *word).collect();
                return Err(format!(
                    "--node-policy: '{word}' is not a word of the policy: hardened, devices=CLASS+CLASS, or one of these, or no- before it: {}",
                    words.join(", ")
                ));
            }
        }
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template(of: serde_json::Value) -> Template {
        serde_json::from_value(of).unwrap()
    }

    #[test]
    fn policy_says_nothing_is_everything_and_hardened_is_nothing() {
        let all: Policy = "".parse().unwrap();
        assert_eq!(all, Policy::default());
        assert!(KEYS.iter().all(|(_, key, _)| all.allows(key)) && all.device(&DeviceClass::Input));
        let hardened: Policy = "hardened".parse().unwrap();
        assert!(KEYS.iter().all(|(_, key, _)| !hardened.allows(key)));
        assert!(hardened.device(&DeviceClass::Gpu) && !hardened.device(&DeviceClass::Input));
        assert_eq!(hardened.status()["execUnits"], false);
        assert_eq!(hardened.status()["devices"], serde_json::json!(["gpu"]));
        assert!(all.status().is_null());
        // Every key is said in a Node's status, by its name in the record.
        let one: Policy = "no-run".parse().unwrap();
        assert_eq!(one.status().as_object().unwrap().len(), KEYS.len() + 2);
        assert_eq!(one.status()["capabilities"], serde_json::json!(["all"]));
        assert_eq!(
            (&one.status()["run"], &one.status()["vms"]),
            (&false.into(), &true.into())
        );
        assert_eq!(one.status()["devices"], serde_json::json!(["all"]));
        // Unreadable: the start is refused, but a first process runs on, with nothing allowed.
        assert!(read(Some("hardned"), false).is_err());
        assert_eq!(read(Some("hardned"), true), Ok(Policy::hardened()));
        assert_eq!(read(None, true), Ok(Policy::default()));
    }

    #[test]
    fn bounding_set_is_kept_only_where_every_way_to_be_root_is_off() {
        let kept = |words: &str| kept_mask(&words.parse().unwrap());
        // Any one of the three on, or no policy: as before, nothing is cut.
        for on in [
            "",
            "hardened,exec-units",
            "hardened,vm-paths",
            "hardened,run",
            "no-exec-units,no-run",
        ] {
            assert_eq!(kept(on), None, "{on}");
        }
        let mask = kept("no-exec-units,no-vm-paths,no-run").unwrap();
        assert_eq!(kept("hardened"), Some(mask));
        // The other keys are the owner's own: a root pod, an unconfined unit, VMs still run.
        assert_eq!(kept("no-exec-units,no-vm-paths,no-run,vms,unconfined"), Some(mask));
        let has = |name: &str| mask >> KEPT.iter().find(|(_, kept, _)| *kept == name).unwrap().0 & 1 == 1;
        for never in ["SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", "SYS_TIME"] {
            assert!(KEPT.iter().all(|(_, name, _)| *name != never), "{never}");
        }
        // Every capability of a root pod is kept; each numbered once, in order, with its reason.
        for cap in kith_runtime::ROOTS {
            let name = cap.to_string();
            assert!(has(name.strip_prefix("CAP_").unwrap_or(&name)), "{name}");
        }
        // And nothing else: a capability kithd's own threads need is not kept for what it execs.
        assert_eq!(KEPT.len(), kith_runtime::ROOTS.len());
        assert!(KEPT.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert!(KEPT.iter().all(|(number, _, why)| *number < 64 && !why.is_empty()));
        assert_eq!(mask.count_ones() as usize, KEPT.len());
    }

    /// The bounding set is a thread's own: one made here is cut and read, and the others are not.
    /// Needs CAP_SETPCAP, which a plain run lacks: `unshare -Ur cargo test -p kithd --bin kithd
    /// bounding_set -- --ignored` has it in a user namespace, and `ci/vm.sh --test policy` reads
    /// the same of kithd itself.
    #[test]
    #[ignore = "needs root: run in the VM"]
    fn bounding_set_is_cut_to_what_is_kept() {
        let status = |thread: &str| {
            let text = std::fs::read_to_string(format!("/proc/{thread}/status")).unwrap();
            let field = |name: &str| {
                let line = text.lines().find_map(|line| line.strip_prefix(name)).unwrap();
                u64::from_str_radix(line.trim(), 16).unwrap()
            };
            (field("CapBnd:"), field("CapEff:"))
        };
        let (before, _) = status("self");
        let mask = kept_mask(&Policy::hardened()).unwrap();
        let cut = std::thread::spawn(move || {
            let (bounding, effective) = status("thread-self");
            assert_eq!(
                effective >> 8 & 1,
                1,
                "no CAP_SETPCAP to drop with: this test needs root"
            );
            drop_to(mask).unwrap();
            (bounding, status("thread-self").0)
        });
        let (was, now) = cut.join().unwrap();
        assert_eq!(now, was & mask);
        for gone in [16, 17, 19, 25] {
            // SYS_MODULE, SYS_RAWIO, SYS_PTRACE, SYS_TIME
            assert_eq!(now >> gone & 1, 0, "{gone}");
        }
        // (Another thread's, here the test's, is as it was.)
        assert_eq!(status("self").0, before);
    }

    #[test]
    fn policy_words_are_read_left_to_right_and_an_unknown_one_is_refused() {
        let policy: Policy = "hardened, vms,devices=gpu+usb,no-run".parse().unwrap();
        assert!(policy.allows("vms") && !policy.allows("vmPaths") && !policy.allows("run"));
        assert!(policy.device(&DeviceClass::Usb) && !policy.device(&DeviceClass::Camera));
        let policy: Policy = "no-exec-units,no-wipe,devices=".parse().unwrap();
        assert!(!policy.allows("execUnits") && !policy.allows("wipe") && policy.allows("rootContainers"));
        assert!(!policy.device(&DeviceClass::Gpu));
        assert_eq!("devices=all".parse::<Policy>().unwrap(), Policy::default());
        for wrong in ["hardned", "no-everything", "execUnits", "devices=gpus", "no-"] {
            let refused = wrong.parse::<Policy>().unwrap_err();
            assert!(
                refused.contains("--node-policy") && refused.contains(wrong.rsplit('=').next().unwrap()),
                "{refused}"
            );
        }
    }

    #[test]
    fn policy_refuses_each_thing_by_its_key_and_says_where_it_is_set() {
        use serde_json::json;
        let unit = |more: serde_json::Value| {
            let mut unit = json!({ "name": "a", "image": "x" });
            unit.as_object_mut().unwrap().extend(more.as_object().unwrap().clone());
            unit
        };
        let exec = template(json!({ "exec": [{ "name": "a", "command": ["/bin/true"] }] }));
        let plain = template(json!({ "containers": [unit(json!({}))] }));
        let pod = template(json!({ "pod": true, "containers": [unit(json!({}))] }));
        let loose =
            template(json!({ "pod": true, "containers": [unit(json!({ "seccomp": { "unconfined": true } }))] }));
        let allowed =
            template(json!({ "pod": true, "initContainers": [unit(json!({ "seccomp": { "allow": ["mount"] } }))] }));
        let vm = template(json!({ "vms": [{ "name": "a", "memory": "1Gi" }] }));
        let vm_disk =
            template(json!({ "vms": [{ "name": "a", "memory": "1Gi", "disks": [{ "path": "/var/a.raw" }] }] }));
        let vm_other = template(json!({ "vms": [{ "name": "a", "memory": "1Gi", "hypervisor": "cloudHypervisor" }] }));
        let everything = Policy::default();
        for template in [&exec, &plain, &pod, &loose, &allowed, &vm, &vm_disk, &vm_other] {
            assert_eq!(everything.refuses(template, true), Vec::<String>::new());
        }
        let hardened = Policy::hardened();
        let keys = |template: &Template, pci: bool| -> Vec<&str> {
            let said = hardened.refuses(template, pci);
            assert!(said.iter().all(|line| line.contains("--node-policy ")), "{said:?}");
            let named = |line: &String| {
                KEYS.iter()
                    .find(|(_, key, _)| line.contains(&format!("({key} is off")))
                    .unwrap()
                    .1
            };
            said.iter().map(named).collect()
        };
        assert_eq!(keys(&exec, false), ["execUnits"]);
        assert_eq!(keys(&plain, false), ["nodeNetwork"]);
        assert_eq!(keys(&pod, false), Vec::<&str>::new());
        assert_eq!(keys(&loose, false), ["unconfined"]);
        assert_eq!(keys(&allowed, false), ["unconfined"]);
        assert_eq!(keys(&vm, false), ["vms"]);
        assert_eq!(keys(&vm_disk, false), ["vms", "vmPaths"]);
        assert_eq!(keys(&vm_other, true), ["vms", "vmPaths", "passthrough"]);
        // One key back on, and only its thing is run.
        let vms: Policy = "hardened,vms".parse().unwrap();
        assert_eq!(vms.refuses(&vm, false), Vec::<String>::new());
        assert_eq!(vms.refuses(&vm_disk, false).len(), 1);
    }
}
