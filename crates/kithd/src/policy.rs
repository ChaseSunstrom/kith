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

    /// As a Node's status says it: every key, and the classes of Device. Null where
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
        said.into()
    }

    /// Why a template is not run on this node, if its policy refuses any of it: one line
    /// for each key, naming the key and where it is set. `pci` says a claim of the replica
    /// holds a PCI device (which a VM of it would be handed).
    pub fn refuses(&self, template: &Template, pci: bool) -> Vec<String> {
        let mut why = Vec::new();
        let mut refuse = |key: &str| why.extend(self.refusal(key));
        if !template.exec.is_empty() {
            refuse("execUnits");
        }
        let unconfined =
            |seccomp: &kith_api::kinds::Seccomp| seccomp.unconfined == Some(true) || !seccomp.allow.is_empty();
        if template
            .containers()
            .any(|c| c.seccomp.as_ref().is_some_and(unconfined))
        {
            refuse("unconfined");
        }
        if template.containers().next().is_some() && template.pod != Some(true) {
            refuse("nodeNetwork");
        }
        if !template.vms.is_empty() {
            refuse("vms");
            let paths = |vm: &kith_api::kinds::VmUnit| {
                let other = vm
                    .hypervisor
                    .as_ref()
                    .is_some_and(|h| *h != kith_api::kinds::Hypervisor::Qemu);
                other || vm.kernel.is_some() || vm.initrd.is_some() || vm.firmware.is_some() || !vm.disks.is_empty()
            };
            if template.vms.iter().any(paths) {
                refuse("vmPaths");
            }
            if pci {
                refuse("passthrough");
            }
        }
        why
    }
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
        assert_eq!(one.status().as_object().unwrap().len(), KEYS.len() + 1);
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
