//! The node's hardware, listed from `/sys` every half minute as `Device` resources (and
//! one `Seat`, `NODE-seat0`), kept in step with what is found: applied when it turns up,
//! deleted when it is gone. What this makes is labelled `kith.dev/discovered: "true"`, and
//! only that, and only of this node, is ever changed or deleted: a `Device` or `Seat`
//! someone wrote is left alone.
//
// ponytail: a rescan, not udev's uevents: a plugged device shows within 30 s. Uevents
// (netlink) when a claim has to follow a hot-plug at once. The reads are a few dozen small
// files on the daemon's one thread, like the mesh's netlink calls.

use crate::Shared;
use kith_api::{Metadata, Resource, store::Store};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const DISCOVERED: &str = "kith.dev/discovered";
const EVERY: Duration = Duration::from_secs(30);

/// The names in `dir`, sorted; none if it is not there.
fn names(dir: &Path) -> Vec<String> {
    let listed = std::fs::read_dir(dir).into_iter().flatten().flatten();
    let mut names: Vec<String> = listed
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

/// A file's text, trimmed; none if it is missing or empty.
fn read(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    Some(text.trim().to_string()).filter(|text| !text.is_empty())
}

/// A PCI or USB id as the kernel writes it (`0x1002`) without the `0x`, lower case.
fn id(path: &Path) -> Option<String> {
    let text = read(path)?.to_ascii_lowercase();
    Some(text.strip_prefix("0x").unwrap_or(&text).to_string())
}

/// `text` as a label value: letters, digits, `.`, `_` and `-`; anything else is `_`; 63 at most.
fn label(text: &str) -> String {
    let safe = |c: char| {
        if c.is_ascii_alphanumeric() || "._-".contains(c) {
            c
        } else {
            '_'
        }
    };
    text.trim().chars().take(63).map(safe).collect()
}

/// The digits after `prefix` in `name` (`card0` and `card`: `0`), if that is all there is.
fn number<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = name.strip_prefix(prefix)?;
    (!rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())).then_some(rest)
}

/// One piece of hardware found: its class, the kernel's name for it, its device node and its labels.
type Found = (&'static str, String, Option<String>, Vec<(&'static str, String)>);

/// What `sys` (a `/sys`) says the machine has, as the `Device`s and `Seat` of `node`, sorted by name.
pub fn scan(sys: &Path, node: &str) -> Vec<Resource> {
    let mut found: Vec<Found> = Vec::new();
    let drm = sys.join("class/drm");
    for name in names(&drm) {
        let dir = drm.join(&name);
        let card = name.strip_prefix("card").unwrap_or("");
        if number(&name, "card").is_some() {
            let device = dir.join("device");
            let mut labels = Vec::new();
            labels.extend(id(&device.join("vendor")).map(|vendor| ("vendor", vendor)));
            labels.extend(id(&device.join("device")).map(|model| ("model", model)));
            let driver = std::fs::read_link(device.join("driver")).ok();
            let driver = driver.and_then(|link| Some(label(link.file_name()?.to_str()?)));
            labels.extend(driver.map(|driver| ("driver", driver)));
            let vram = read(&device.join("mem_info_vram_total")).filter(|bytes| bytes.parse::<u64>().is_ok());
            labels.extend(vram.map(|bytes| ("vram", bytes)));
            found.push(("gpu", name.clone(), Some(format!("/dev/dri/{name}")), labels));
        } else if card.split_once('-').is_some_and(|(n, _)| number(n, "").is_some())
            && read(&dir.join("status")).as_deref() == Some("connected")
        {
            found.push(("display", name, None, Vec::new()));
        }
    }
    for name in names(&sys.join("class/input")) {
        if number(&name, "event").is_some() {
            let model = read(&sys.join("class/input").join(&name).join("device/name"));
            let labels = model.map(|model| ("model", label(&model))).into_iter().collect();
            found.push(("input", name.clone(), Some(format!("/dev/input/{name}")), labels));
        }
    }
    for name in names(&sys.join("class/sound")) {
        if let Some(n) = number(&name, "card") {
            let model = read(&sys.join("class/sound").join(&name).join("id"));
            let labels = model.map(|model| ("model", label(&model))).into_iter().collect();
            found.push(("audio", name.clone(), Some(format!("/dev/snd/controlC{n}")), labels));
        }
    }
    for name in names(&sys.join("class/video4linux")) {
        if number(&name, "video").is_some() {
            found.push(("camera", name.clone(), Some(format!("/dev/{name}")), Vec::new()));
        }
    }
    let usb = sys.join("bus/usb/devices");
    for name in names(&usb) {
        let dir = usb.join(&name);
        let number = |file: &str| read(&dir.join(file))?.parse::<u32>().ok();
        // (Hubs are the machine's wiring, not something to hand to a workload.)
        let (Some(vendor), Some(bus), Some(device)) = (id(&dir.join("idVendor")), number("busnum"), number("devnum"))
        else {
            continue;
        };
        if read(&dir.join("bDeviceClass")).as_deref() == Some("09") {
            continue;
        }
        let mut labels = vec![("vendor", vendor)];
        labels.extend(id(&dir.join("idProduct")).map(|model| ("model", model)));
        found.push(("usb", name, Some(format!("/dev/bus/usb/{bus:03}/{device:03}")), labels));
    }
    // PCI devices set aside for virtual machines (bound to `vfio-pci`): they have no device
    // node; their path is their place on the bus, which a `vms` unit passes through.
    let pci = sys.join("bus/pci/devices");
    for name in names(&pci) {
        let dir = pci.join(&name);
        let driver = std::fs::read_link(dir.join("driver")).ok();
        if driver.as_deref().and_then(Path::file_name) != Some("vfio-pci".as_ref()) {
            continue;
        }
        let kind = read(&dir.join("class")).unwrap_or_default();
        // (Its class is `pci`, never `gpu`: a selector for a GPU to draw with must not come
        // to a card that only a machine can use. What it is, is in its `function` label.)
        let function = match kind.get(2..6) {
            Some(display) if display.starts_with("03") => "gpu",
            Some(sound) if sound.starts_with("04") => "audio",
            Some("0c03") => "usb",
            _ => "other",
        };
        let mut labels = vec![("driver", "vfio-pci".to_string()), ("function", function.to_string())];
        labels.extend(id(&dir.join("vendor")).map(|vendor| ("vendor", vendor)));
        labels.extend(id(&dir.join("device")).map(|model| ("model", model)));
        found.push(("pci", name.clone(), Some(format!("{}/{name}", crate::vm::PCI)), labels));
    }
    let made = |kind: &str, name: String, labels: BTreeMap<String, String>, spec: Value| Resource {
        api_version: kith_api::API_VERSION.into(),
        kind: kind.into(),
        metadata: Metadata {
            name,
            namespace: None,
            labels,
            annotations: BTreeMap::new(),
            revision: None,
        },
        spec,
        status: None,
    };
    let mut devices: BTreeMap<String, Resource> = BTreeMap::new();
    for (class, name, path, labels) in found {
        // A name of resources' kind: lower case, `a-z0-9.-`, 63 at most, ending in a letter or digit.
        let dns: String = name
            .to_ascii_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '-' })
            .collect();
        let full = format!("{node}-{class}-{dns}");
        let full = full.get(..63).unwrap_or(&full).trim_end_matches(['-', '.']).to_string();
        let mut labels: BTreeMap<String, String> = labels.into_iter().map(|(k, v)| (k.into(), v)).collect();
        labels.insert("kith.dev/node".into(), node.into());
        labels.insert("class".into(), class.into());
        labels.insert(DISCOVERED.into(), "true".into());
        let mut spec = json!({ "node": node, "class": class });
        if let Some(path) = path {
            spec["path"] = path.into();
        }
        // (Two that come to one name, a node name nearly 63 long: the first keeps it.)
        devices
            .entry(full.clone())
            .or_insert_with(|| made("Device", full, labels, spec));
    }
    let seated: Vec<&String> = devices
        .iter()
        .filter(|(_, device)| {
            ["gpu", "display", "input", "audio"].contains(&device.spec["class"].as_str().unwrap_or(""))
        })
        .map(|(name, _)| name)
        .collect();
    let seat = (!seated.is_empty()).then(|| {
        let labels = [("kith.dev/node", node), (DISCOVERED, "true")];
        let labels = labels
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        made(
            "Seat",
            // (Cut like the Devices' names: a node's name may be 63 long by itself.)
            format!("{}-seat0", node.get(..57).unwrap_or(node).trim_end_matches(['-', '.'])),
            labels,
            json!({ "node": node, "devices": seated }),
        )
    });
    devices.into_values().chain(seat).collect()
}

/// Is `resource` one this node's discovery made?
fn ours(resource: &Resource, node: &str) -> bool {
    resource
        .metadata
        .labels
        .get(DISCOVERED)
        .is_some_and(|made| made == "true")
        && resource.spec["node"] == node
}

/// What to do to the store to make this node's discovered `Device`s and `Seat` what was `found`:
/// what to apply (new or changed), and the keys to delete (gone).
fn changes(store: &Store, node: &str, found: &[Resource]) -> (Vec<Resource>, Vec<String>) {
    let apply = found.iter().filter(|new| match store.get(&new.key()) {
        None => true,
        // (One someone wrote under the same name is theirs.)
        Some(live) => ours(live, node) && (live.metadata.labels != new.metadata.labels || live.spec != new.spec),
    });
    let live = store.list(Some("Device")).chain(store.list(Some("Seat")));
    // Gone from this machine, or of a node the cluster has no more (nobody else would).
    let left = |live: &Resource| {
        let of = live.spec["node"].as_str().unwrap_or_default();
        live.metadata.labels.get(DISCOVERED).is_some_and(|made| made == "true")
            && of != node
            && store.get(&format!("Node/{of}")).is_none()
    };
    let gone = live.filter(|live| ours(live, node) && !found.iter().any(|new| new.key() == live.key()) || left(live));
    (apply.cloned().collect(), gone.map(Resource::key).collect())
}

/// Keep the store's `Device`s and `Seat` of this node as `/sys` says, until stopped.
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    use kith_store::Command;
    // (Alone, in agent mode, a node has no name to put on them.)
    let Some(cluster) = &shared.cluster else { return };
    let (sys, me) = (Path::new("/sys"), cluster.me.name.as_str());
    if !sys.join("class").is_dir() {
        return eprintln!("kithd: devices: no /sys/class here: no hardware is listed");
    }
    // The first look soon after start, the rest every half minute.
    let mut wait = Duration::from_secs(5);
    loop {
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = stopping.changed() => break,
        }
        wait = EVERY;
        let found = scan(sys, me);
        let (resources, gone) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            changes(&state.store, me, &found)
        };
        drop(found);
        if !resources.is_empty() {
            let at = kith_api::store::now();
            if let Err(e) = shared.submit(Command::Apply { resources, at }).await {
                eprintln!("kithd: devices: listing this node's hardware: {e}");
            }
        }
        for key in gone {
            if let Err(e) = shared.submit(Command::Delete { key: key.clone() }).await {
                // (The rest wait for the next round: each would wait out the same trouble.)
                eprintln!("kithd: devices: taking {key} away: {e}");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A fresh directory for a made-up `/sys` (never the real one).
    fn tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("kith-devices-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn put(root: &Path, file: &str, text: &str) {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn laptop(root: &Path) {
        put(root, "class/drm/card0/device/vendor", "0x1002\n");
        put(root, "class/drm/card0/device/device", "0x73BF\n");
        put(root, "class/drm/card0/device/mem_info_vram_total", "17163091968\n");
        std::fs::create_dir_all(root.join("class/drm/card0/device")).unwrap();
        std::os::unix::fs::symlink(
            "../../../bus/pci/drivers/amdgpu",
            root.join("class/drm/card0/device/driver"),
        )
        .unwrap();
        put(root, "class/drm/card0-HDMI-A-1/status", "connected\n");
        put(root, "class/drm/card0-DP-1/status", "disconnected\n");
        put(root, "class/drm/renderD128/dev", "226:128\n");
        put(root, "class/input/event3/device/name", "AT Translated Set 2 keyboard\n");
        put(root, "class/input/mouse0/device/name", "not an event\n");
        put(root, "class/sound/card0/id", "PCH\n");
        put(root, "class/sound/controlC0/dev", "116:2\n");
        put(root, "class/video4linux/video0/name", "Integrated Camera\n");
        for (name, class, bus, device) in [("1-2", "00", "1", "4"), ("usb1", "09", "1", "1")] {
            let dir = format!("bus/usb/devices/{name}");
            put(root, &format!("{dir}/idVendor"), "046d\n");
            put(root, &format!("{dir}/idProduct"), "c52b\n");
            put(root, &format!("{dir}/bDeviceClass"), &format!("{class}\n"));
            put(root, &format!("{dir}/busnum"), &format!("{bus}\n"));
            put(root, &format!("{dir}/devnum"), &format!("{device}\n"));
        }
        put(root, "bus/usb/devices/1-2:1.0/bInterfaceClass", "03\n");
    }

    fn get<'a>(found: &'a [Resource], name: &str) -> &'a Resource {
        found
            .iter()
            .find(|r| r.metadata.name == name)
            .unwrap_or_else(|| panic!("no {name}"))
    }

    #[test]
    fn a_made_up_sys_gives_its_devices_and_seat0() {
        let root = tree("laptop");
        laptop(&root);
        let found = scan(&root, "n1");
        let names: Vec<&str> = found.iter().map(|r| r.metadata.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "n1-audio-card0",
                "n1-camera-video0",
                "n1-display-card0-hdmi-a-1",
                "n1-gpu-card0",
                "n1-input-event3",
                "n1-usb-1-2",
                "n1-seat0"
            ]
        );
        let gpu = get(&found, "n1-gpu-card0");
        assert_eq!(gpu.kind, "Device");
        assert_eq!(
            gpu.spec,
            json!({ "node": "n1", "class": "gpu", "path": "/dev/dri/card0" })
        );
        let labels = &gpu.metadata.labels;
        let want = [
            ("vendor", "1002"),
            ("model", "73bf"),
            ("driver", "amdgpu"),
            ("vram", "17163091968"),
            ("kith.dev/node", "n1"),
            ("class", "gpu"),
            ("kith.dev/discovered", "true"),
        ];
        assert_eq!(
            *labels,
            want.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        );
        assert_eq!(
            get(&found, "n1-display-card0-hdmi-a-1").spec,
            json!({ "node": "n1", "class": "display" })
        );
        let key = get(&found, "n1-input-event3");
        assert_eq!(key.spec["path"], "/dev/input/event3");
        assert_eq!(key.metadata.labels["model"], "AT_Translated_Set_2_keyboard");
        assert_eq!(get(&found, "n1-audio-card0").spec["path"], "/dev/snd/controlC0");
        assert_eq!(get(&found, "n1-audio-card0").metadata.labels["model"], "PCH");
        assert_eq!(get(&found, "n1-camera-video0").spec["path"], "/dev/video0");
        let usb = get(&found, "n1-usb-1-2");
        assert_eq!(usb.spec["path"], "/dev/bus/usb/001/004");
        assert_eq!(
            (&usb.metadata.labels["vendor"], &usb.metadata.labels["model"]),
            (&"046d".to_string(), &"c52b".to_string())
        );
        let seat = get(&found, "n1-seat0");
        assert_eq!(seat.kind, "Seat");
        let devices = [
            "n1-audio-card0",
            "n1-display-card0-hdmi-a-1",
            "n1-gpu-card0",
            "n1-input-event3",
        ];
        assert_eq!(seat.spec, json!({ "node": "n1", "devices": devices }));
        assert_eq!(seat.metadata.labels["kith.dev/discovered"], "true");
        // What it makes, the store takes.
        let mut store = Store::default();
        for resource in found {
            store.apply(resource).unwrap();
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A PCI device bound to vfio-pci is a Device a vm unit can be given: named for its place
    /// on the bus, which is its path; no part of the seat. One with any other driver is not.
    #[test]
    fn a_pci_device_set_aside_for_vm_units_is_a_device_and_not_of_the_seat() {
        let root = tree("vfio");
        laptop(&root);
        for (address, class, driver) in [
            ("0000:01:00.0", "0x030000", "vfio-pci"),
            ("0000:01:00.1", "0x040300", "vfio-pci"),
            ("0000:02:00.0", "0x020000", "e1000e"),
        ] {
            let dir = format!("bus/pci/devices/{address}");
            put(&root, &format!("{dir}/class"), &format!("{class}\n"));
            put(&root, &format!("{dir}/vendor"), "0x10de\n");
            put(&root, &format!("{dir}/device"), "0x2684\n");
            std::fs::create_dir_all(root.join("bus/pci/drivers").join(driver)).unwrap();
            let link = root.join(&dir).join("driver");
            std::os::unix::fs::symlink(root.join("bus/pci/drivers").join(driver), link).unwrap();
        }
        let found = scan(&root, "n1");
        let gpu = get(&found, "n1-pci-0000-01-00.0");
        assert_eq!(
            gpu.spec,
            json!({ "node": "n1", "class": "pci", "path": "/sys/bus/pci/devices/0000:01:00.0" })
        );
        assert_eq!(gpu.metadata.labels["driver"], "vfio-pci");
        assert_eq!(
            (
                gpu.metadata.labels["class"].as_str(),
                gpu.metadata.labels["function"].as_str()
            ),
            ("pci", "gpu")
        );
        assert_eq!(
            (
                gpu.metadata.labels["vendor"].as_str(),
                gpu.metadata.labels["model"].as_str()
            ),
            ("10de", "2684")
        );
        assert_eq!(get(&found, "n1-pci-0000-01-00.1").metadata.labels["function"], "audio");
        assert!(!found.iter().any(|device| device.metadata.name.contains("0000-02")));
        let seat = get(&found, "n1-seat0");
        let seated = seat.spec["devices"].as_array().unwrap();
        assert!(
            !seated.iter().any(|name| name.as_str().unwrap().contains("-pci-")),
            "{seated:?}"
        );
        // And it is what a vm unit is given.
        let path = std::path::PathBuf::from(gpu.spec["path"].as_str().unwrap());
        assert_eq!(crate::vm::pci(&[path]), ["0000:01:00.0"]);
    }

    #[test]
    fn no_hardware_is_no_devices_and_no_seat() {
        let root = tree("empty");
        assert!(scan(&root, "n1").is_empty());
        put(&root, "bus/usb/devices/usb1/bDeviceClass", "09\n");
        put(&root, "class/drm/renderD128/dev", "226:128\n");
        assert!(scan(&root, "n1").is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_long_node_name_still_makes_valid_names() {
        let root = tree("long");
        put(&root, "class/video4linux/video0/name", "x\n");
        put(&root, "class/input/event3/device/name", "k\n");
        let found = scan(&root, &"n".repeat(58));
        assert_eq!(found.len(), 3, "a camera, a keyboard and the seat");
        let mut store = Store::default();
        for resource in found {
            store.apply(resource).unwrap();
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    fn written(source: &str) -> Resource {
        Resource::from_source(source).unwrap().remove(0).unwrap()
    }

    #[test]
    fn what_is_gone_is_deleted_and_what_someone_wrote_is_kept() {
        let root = tree("diff");
        laptop(&root);
        let found = scan(&root, "n1");
        let mut store = Store::default();
        for resource in &found {
            store.apply(resource.clone()).unwrap();
        }
        // Nothing changed: nothing to do.
        assert_eq!(changes(&store, "n1", &found), (vec![], vec![]));
        // Another node's discovered one, one written by hand (with a name discovery would use, too).
        // (While the cluster has no Node n2 it is taken away; with one, it is n2's to keep.)
        let theirs = scan(&root, "n2");
        store.apply(theirs[0].clone()).unwrap();
        assert_eq!(changes(&store, "n1", &found).1, [theirs[0].key()]);
        store
            .apply(written(
                "apiVersion: kith.dev/v1\nkind: Node\nmetadata: { name: n2 }\nspec: {}",
            ))
            .unwrap();
        assert_eq!(changes(&store, "n1", &found), (vec![], vec![]));
        let hand = "apiVersion: kith.dev/v1\nkind: Device\nmetadata: { name: HAND }\nspec: { node: n1, class: gpu }";
        store.apply(written(&hand.replace("HAND", "n1-gpu-card7"))).unwrap();
        store.apply(written(&hand.replace("HAND", "n1-camera-video0"))).unwrap();
        store
            .apply(written(
                &hand
                    .replace("HAND", "n1-seat1")
                    .replace("Device", "Seat")
                    .replace(", class: gpu", ""),
            ))
            .unwrap();
        // The camera and the GPU's driver are gone, the keyboard is another.
        let mut now = found.clone();
        now.retain(|r| r.metadata.name != "n1-camera-video0" && r.metadata.name != "n1-usb-1-2");
        let gpu = now.iter_mut().find(|r| r.metadata.name == "n1-gpu-card0").unwrap();
        gpu.metadata.labels.insert("driver".into(), "radeon".into());
        let (apply, delete) = changes(&store, "n1", &now);
        let applied: Vec<&str> = apply.iter().map(|r| r.metadata.name.as_str()).collect();
        // (The hand-written n1-camera-video0 is not ours: not deleted, and not found either.)
        assert_eq!(applied, ["n1-gpu-card0"]);
        assert_eq!(delete, ["Device/n1-usb-1-2"]);
        // A hand-written one under a name discovery would make is not overwritten.
        let (apply, _) = changes(&store, "n1", &found);
        assert!(apply.iter().all(|r| r.metadata.name != "n1-camera-video0"));
        // A machine without hardware loses all its own, and only its own.
        let (_, delete) = changes(&store, "n1", &[]);
        assert_eq!(delete.len(), found.len() - 1, "all but the camera someone wrote over");
        assert!(!delete.contains(&"Device/n1-gpu-card7".to_string()));
        assert!(!delete.contains(&"Seat/n1-seat1".to_string()));
        let _ = std::fs::remove_dir_all(&root);
    }
}
