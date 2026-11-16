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
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const DISCOVERED: &str = "kith.dev/discovered";

/// Every label discovery writes. A worker's Device may carry these and no other
/// (`crate::worker`): one added here is one a control node takes from a worker.
pub(crate) const LABELS: [&str; 9] = [
    DISCOVERED,
    "kith.dev/node",
    "class",
    "vendor",
    "model",
    "pci",
    "driver",
    "vram",
    "function",
];
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

/// What NVIDIA's driver has in `dev` for its card at `address` on the PCI bus: the card's
/// own node (`nvidiaN`, N being the minor the driver gives it in `proc`), and the nodes all
/// its cards share. Only those that are there: the driver makes none itself (its
/// `nvidia-modprobe` does, or udev).
/// Whether a name is a PCI address as the kernel writes it: `0000:01:00.0`.
fn is_pci_address(name: &str) -> bool {
    name.len() == 12
        && name.char_indices().all(|(i, c)| match i {
            4 | 7 => c == ':',
            10 => c == '.',
            _ => c.is_ascii_hexdigit(),
        })
}

fn nvidia(proc: &Path, dev: &Path, address: &str) -> (Option<String>, Vec<String>) {
    let said = read(&proc.join("driver/nvidia/gpus").join(address).join("information"));
    let minor = |line: &str| line.strip_prefix("Device Minor:")?.trim().parse::<u32>().ok();
    let minor = said.and_then(|said| said.lines().find_map(minor));
    let there = |name: String| dev.join(&name).exists().then(|| format!("/dev/{name}"));
    let own = minor.and_then(|minor| there(format!("nvidia{minor}")));
    let shared = ["nvidiactl", "nvidia-uvm", "nvidia-uvm-tools", "nvidia-modeset"];
    (
        own,
        shared.into_iter().filter_map(|name| there(name.to_string())).collect(),
    )
}

/// What `sys` (a `/sys`) says the machine has, as the `Device`s and `Seat` of `node`, sorted by name.
pub fn scan(sys: &Path, node: &str) -> Vec<Resource> {
    scan_in(sys, Path::new("/proc"), Path::new("/dev"), node)
}

/// [`scan`], with the `/proc` and `/dev` in which a driver keeps what `/sys` does not say.
fn scan_in(sys: &Path, proc: &Path, dev: &Path, node: &str) -> Vec<Resource> {
    let mut found: Vec<Found> = Vec::new();
    // The further nodes that come with a Device, by its class and the kernel's name for it;
    // and NVIDIA's cards that are DRM cards, by their place on the PCI bus.
    let mut also: BTreeMap<(&str, String), Vec<String>> = BTreeMap::new();
    let mut drawing: Vec<String> = Vec::new();
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
            let place = std::fs::canonicalize(&device).ok();
            let place = place.and_then(|real| Some(real.file_name()?.to_str()?.to_string()));
            labels.extend(place.clone().filter(|bus| is_pci_address(bus)).map(|bus| ("pci", bus)));
            if let Some(place) = place.filter(|_| driver.as_deref() == Some("nvidia")) {
                let (own, mut nodes) = nvidia(proc, dev, &place);
                nodes.extend(own);
                also.insert(("gpu", name.clone()), nodes);
                drawing.push(place);
            }
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
        let driver = driver
            .as_deref()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str());
        let kind = read(&dir.join("class")).unwrap_or_default();
        // A card on NVIDIA's driver that is no DRM card (the driver loaded to compute, not
        // to draw): a GPU all the same, its node the driver's own.
        if driver == Some("nvidia") && kind.starts_with("0x03") && !drawing.contains(&name) {
            let mut labels = vec![("driver", "nvidia".to_string()), ("pci", name.clone())];
            labels.extend(id(&dir.join("vendor")).map(|vendor| ("vendor", vendor)));
            labels.extend(id(&dir.join("device")).map(|model| ("model", model)));
            let (own, nodes) = nvidia(proc, dev, &name);
            also.insert(("gpu", name.clone()), nodes);
            found.push(("gpu", name, own, labels));
            continue;
        }
        if driver != Some("vfio-pci") {
            continue;
        }
        // (Its class is `pci`, never `gpu`: a selector for a GPU to draw with must not come
        // to a card that only a machine can use. What it is, is in its `function` label.)
        let function = match kind.get(2..6) {
            Some(display) if display.starts_with("03") => "gpu",
            Some(sound) if sound.starts_with("04") => "audio",
            Some("0c03") => "usb",
            _ => "other",
        };
        let mut labels = vec![
            ("driver", "vfio-pci".to_string()),
            ("function", function.to_string()),
            ("pci", name.clone()),
        ];
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
        debug_assert!(labels.keys().all(|label| LABELS.contains(&label.as_str())));
        let mut spec = json!({ "node": node, "class": class });
        if let Some(path) = path {
            spec["path"] = path.into();
        }
        if let Some(nodes) = also.remove(&(class, name)).filter(|nodes| !nodes.is_empty()) {
            spec["nodes"] = nodes.into();
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
            format!("{}-seat0", stem(node)),
            labels,
            json!({ "node": node, "devices": seated }),
        )
    });
    devices.into_values().chain(seat).collect()
}

/// The names of the store's Devices that are what `found` (this node's own look at its
/// hardware, [`scan`]) says they are: the same class, path and further nodes. A node whose
/// policy names the classes of Device it hands out goes by these alone: the store says what
/// class a Device is, and whoever writes the store could call the node's disk a GPU.
pub fn as_found(store: &Store, found: &[Resource]) -> BTreeSet<String> {
    let same =
        |new: &&Resource| new.kind == "Device" && store.get(&new.key()).is_some_and(|live| live.spec == new.spec);
    found.iter().filter(same).map(|new| new.metadata.name.clone()).collect()
}

/// What a long node name is cut to where its discovered names start (57 of a name's 63).
fn stem(node: &str) -> &str {
    node.get(..57).unwrap_or(node).trim_end_matches(['-', '.'])
}

/// Whose a discovered name is: of the cluster's Nodes whose name and a dash start `name` (or,
/// for a node name of 57 or more, whose cut stem does), those that account for the most of it.
/// So `w-b-gpu-card0` is node `w-b`'s and not node `w`'s, and two long names with one stem both
/// have what starts with it. None where no Node's name starts it.
pub(crate) fn whose<'a>(store: &'a Store, name: &str) -> Vec<&'a str> {
    whose_of(&nodes(store), name)
}

/// The names of the cluster's Nodes.
fn nodes(store: &Store) -> Vec<&str> {
    let nodes = store.list(Some("Node"));
    nodes.map(|node| node.metadata.name.as_str()).collect()
}

/// How much of the discovered name `name` node `node`'s name accounts for; 0 where it does not
/// start it. (A node name of 62 or 63 leaves no room: its Devices' names are its own name.)
fn starts(name: &str, node: &str) -> usize {
    match name.strip_prefix(node) {
        Some(rest) if rest.starts_with('-') || (rest.is_empty() && node.len() >= 62) => node.len() + 1,
        _ if node.len() >= 57 && name.starts_with(stem(node)) => stem(node).len(),
        _ => 0,
    }
}

/// [`whose`], of the Nodes named `nodes`.
fn whose_of<'a>(nodes: &[&'a str], name: &str) -> Vec<&'a str> {
    let most = nodes.iter().map(|node| starts(name, node)).max().unwrap_or(0);
    let has = |node: &&'a str| (most > 0 && starts(name, node) == most).then_some(*node);
    nodes.iter().filter_map(has).collect()
}

/// What a node that joined as `joining` would take from a node that has it: a discovered Device
/// or Seat whose name would then be the new node's alone ([`whose`]), and the node it is of.
/// A join under such a name is refused: whoever holds a join token chooses the node's name, and
/// would choose whose hardware a claim by that name comes to.
pub(crate) fn taken_by(store: &Store, joining: &str) -> Option<(String, String)> {
    let nodes = nodes(store);
    let live = store.list(Some("Device")).chain(store.list(Some("Seat")));
    // (Of a node that is there: what a node that is gone left is taken away by itself.)
    let of = |live: &Resource| live.spec["node"].as_str().unwrap_or_default().to_string();
    live.filter(|live| discovered(live) && of(live) != joining && nodes.contains(&of(live).as_str()))
        .find(|live| {
            let name = &live.metadata.name;
            let most = nodes.iter().map(|node| starts(name, node)).max().unwrap_or(0);
            starts(name, joining) > most
        })
        .map(|live| (live.key(), live.spec["node"].as_str().unwrap_or_default().to_string()))
}

/// Is `resource` one a node's discovery made?
fn discovered(resource: &Resource) -> bool {
    resource
        .metadata
        .labels
        .get(DISCOVERED)
        .is_some_and(|made| made == "true")
}

/// Is `resource` one this node's discovery made?
fn ours(resource: &Resource, node: &str) -> bool {
    discovered(resource) && resource.spec["node"] == node
}

/// A name of this node's it does not list, and the node that has it.
type Held = (String, String);

/// What to do to the store to make this node's discovered `Device`s and `Seat` what was `found`:
/// what to apply (new or changed), the keys to delete (gone), and what of its own it does not
/// list because another node has the name: the name is that node's ([`whose`]), or that node's
/// discovery made one under it.
fn changes(store: &Store, node: &str, found: &[Resource]) -> (Vec<Resource>, Vec<String>, Vec<Held>) {
    let (mut apply, mut held) = (Vec::new(), Vec::new());
    let nodes = nodes(store);
    for new in found {
        let theirs = whose_of(&nodes, &new.metadata.name);
        if !theirs.is_empty() && !theirs.contains(&node) {
            held.push((new.key(), theirs.join(", ")));
            continue;
        }
        match store.get(&new.key()) {
            None => apply.push(new.clone()),
            Some(live) if ours(live, node) => {
                // (The namespaces an admin gave it are theirs to set: a pass keeps the label there is.)
                let mut wanted = new.clone();
                if let Some(namespaces) = live.metadata.labels.get(crate::claims::NAMESPACES) {
                    wanted.metadata.labels.insert(crate::claims::NAMESPACES.into(), namespaces.clone());
                }
                if live.metadata.labels != wanted.metadata.labels || live.spec != wanted.spec {
                    apply.push(wanted);
                }
            }
            Some(live) if discovered(live) => {
                held.push((new.key(), live.spec["node"].as_str().unwrap_or_default().to_string()));
            }
            // (One someone wrote under the same name is theirs.)
            Some(_) => {}
        }
    }
    let live = store.list(Some("Device")).chain(store.list(Some("Seat")));
    // Gone from this machine. And, by a control node (a worker leaves those to one: another
    // node's Device is not its to delete): of a node the cluster has no more, or under a name
    // that is another node's (made before that node joined), so that node gets its name.
    let worker = crate::access::is_worker(store, node);
    let left = |live: &Resource| {
        let of = live.spec["node"].as_str().unwrap_or_default();
        let misnamed = || {
            let theirs = whose_of(&nodes, &live.metadata.name);
            !theirs.is_empty() && !theirs.contains(&of)
        };
        let no_more = of != node && !nodes.contains(&of);
        discovered(live) && !worker && (no_more || misnamed())
    };
    let gone = live.filter(|live| ours(live, node) && !found.iter().any(|new| new.key() == live.key()) || left(live));
    let gone: Vec<String> = gone.map(Resource::key).collect();
    // (What this pass takes away holds nothing: the name is listed at the next.)
    held.retain(|(key, _)| !gone.contains(key));
    (apply, gone, held)
}

/// What to say of the names held: each once, and again only when what is held changes.
fn held_lines(said: &mut Vec<Held>, held: Vec<Held>) -> Vec<String> {
    if *said == held {
        return Vec::new();
    }
    *said = held;
    let line = |(key, node): &Held| {
        format!(
            "kithd: devices: this node's {key} is not listed: node {node} has that name (give one of the \
             two nodes another name; or, if {node} should not have it, delete that {key})"
        )
    };
    said.iter().map(line).collect()
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
    let mut said = Vec::new();
    loop {
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = stopping.changed() => break,
        }
        wait = EVERY;
        let found = scan(sys, me);
        let (resources, gone, held) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            changes(&state.store, me, &found)
        };
        drop(found);
        for line in held_lines(&mut said, held) {
            eprintln!("{line}");
        }
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
            // (So that one that went can be traced: the hardware is gone, its node is, or the
            // name is another node's.)
            eprintln!("kithd: devices: {key} is no longer listed");
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

    /// A card on NVIDIA's driver brings the driver's own nodes with it: those every card
    /// shares and its own, by the minor the driver says, and only those that are there.
    /// With no DRM card (the driver loaded to compute, not to draw) it is found on the PCI bus.
    #[test]
    fn an_nvidia_card_lists_the_drivers_nodes_with_it() {
        let root = tree("nvidia");
        let (sys, proc, dev) = (root.join("sys"), root.join("proc"), root.join("dev"));
        for (address, minor) in [("0000:01:00.0", 1), ("0000:02:00.0", 0), ("0000:03:00.0", 2)] {
            let dir = format!("bus/pci/devices/{address}");
            put(&sys, &format!("{dir}/vendor"), "0x10de\n");
            put(&sys, &format!("{dir}/device"), "0x2684\n");
            put(&sys, &format!("{dir}/class"), "0x030000\n");
            std::os::unix::fs::symlink("../../drivers/nvidia", sys.join(&dir).join("driver")).unwrap();
            let said = format!("Model: \t\t NVIDIA GeForce\nIRQ:   \t\t 130\nDevice Minor: \t {minor}\n");
            put(&proc, &format!("driver/nvidia/gpus/{address}/information"), &said);
        }
        // The first draws (nvidia-drm made it a card); the others do not.
        std::fs::create_dir_all(sys.join("class/drm/card1")).unwrap();
        let card = sys.join("class/drm/card1/device");
        std::os::unix::fs::symlink("../../../bus/pci/devices/0000:01:00.0", card).unwrap();
        // (No nvidia-uvm-tools, and no node for the third card.)
        for node in ["nvidiactl", "nvidia-uvm", "nvidia-modeset", "nvidia0", "nvidia1"] {
            put(&dev, node, "");
        }
        let found = scan_in(&sys, &proc, &dev, "n1");
        let shared = ["/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia-modeset"];
        let card = get(&found, "n1-gpu-card1");
        assert_eq!(card.spec["path"], "/dev/dri/card1");
        assert_eq!(
            card.spec["nodes"],
            json!([shared[0], shared[1], shared[2], "/dev/nvidia1"])
        );
        assert_eq!(card.metadata.labels["driver"], "nvidia");
        let compute = get(&found, "n1-gpu-0000-02-00.0");
        assert_eq!(compute.spec["path"], "/dev/nvidia0");
        assert_eq!(compute.spec["nodes"], json!(shared));
        assert_eq!(compute.metadata.labels["vendor"], "10de");
        // A card whose own node is not there is listed, and has nothing of its own to give.
        let bare = get(&found, "n1-gpu-0000-03-00.0");
        assert_eq!(bare.spec, json!({ "node": "n1", "class": "gpu", "nodes": shared }));
        // The card that draws is one Device, not two.
        assert_eq!(found.iter().filter(|r| r.spec["class"] == "gpu").count(), 3);
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

    /// A Device of a card or a PCI device carries its PCI address as the `pci` label, whichever
    /// driver has it: that is how a `vm` unit's card is found again, and what `kith switch` names.
    #[test]
    fn a_device_carries_its_pci_address_as_a_label_under_either_driver() {
        let root = tree("pci-label");
        for (address, driver) in [
            ("0000:04:00.0", "amdgpu"),
            ("0000:01:00.0", "nvidia"),
            ("0000:03:00.0", "nvidia"),
            ("0000:02:00.0", "vfio-pci"),
        ] {
            let dir = format!("bus/pci/devices/{address}");
            put(&root, &format!("{dir}/class"), "0x030000\n");
            put(&root, &format!("{dir}/vendor"), "0x10de\n");
            put(&root, &format!("{dir}/device"), "0x2684\n");
            std::os::unix::fs::symlink(format!("../../drivers/{driver}"), root.join(&dir).join("driver")).unwrap();
        }
        // Two of them draw: their DRM cards point at the PCI device.
        for (card, address) in [("card0", "0000:04:00.0"), ("card1", "0000:01:00.0")] {
            std::fs::create_dir_all(root.join("class/drm").join(card)).unwrap();
            let link = root.join("class/drm").join(card).join("device");
            std::os::unix::fs::symlink(format!("../../../bus/pci/devices/{address}"), link).unwrap();
        }
        let found = scan_in(&root, &root.join("proc"), &root.join("dev"), "n1");
        assert_eq!(get(&found, "n1-gpu-card0").metadata.labels["pci"], "0000:04:00.0");
        assert_eq!(get(&found, "n1-gpu-card1").metadata.labels["pci"], "0000:01:00.0");
        assert_eq!(
            get(&found, "n1-gpu-0000-03-00.0").metadata.labels["pci"],
            "0000:03:00.0"
        );
        assert_eq!(
            get(&found, "n1-pci-0000-02-00.0").metadata.labels["pci"],
            "0000:02:00.0"
        );
        let _ = std::fs::remove_dir_all(&root);
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

    /// A node that names the classes of Device it hands out goes by its own look at its
    /// hardware: a Device the store calls something else, or one only the store has, is not one.
    #[test]
    fn a_device_is_as_found_only_while_the_store_says_what_the_node_found() {
        let root = tree("forged");
        laptop(&root);
        let found = scan(&root, "n1");
        let mut store = Store::default();
        for resource in &found {
            store.apply(resource.clone()).unwrap();
        }
        let devices = found.iter().filter(|r| r.kind == "Device").count();
        assert!(
            devices > 0 && as_found(&store, &found).len() == devices,
            "every Device, and no Seat"
        );
        // Whoever writes the store calls the node's keyboard a GPU, and adds a disk as one.
        let mut forged = found.iter().find(|r| r.spec["class"] == "input").unwrap().clone();
        forged.spec["class"] = "gpu".into();
        store.apply(forged.clone()).unwrap();
        store
            .apply(written(
                "apiVersion: kith.dev/v1\nkind: Device\nmetadata: { name: n1-gpu-disk }\nspec: { node: n1, class: gpu, path: /dev/sda }",
            ))
            .unwrap();
        let named = as_found(&store, &found);
        assert_eq!(named.len(), devices - 1);
        assert!(!named.contains(&forged.metadata.name) && !named.contains("n1-gpu-disk"));
        let _ = std::fs::remove_dir_all(&root);
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
        assert_eq!(changes(&store, "n1", &found), (vec![], vec![], vec![]));
        // Another node's discovered one, one written by hand (with a name discovery would use, too).
        // (While the cluster has no Node n2 it is taken away; with one, it is n2's to keep.)
        let theirs = scan(&root, "n2");
        store.apply(theirs[0].clone()).unwrap();
        assert_eq!(changes(&store, "n1", &found).1, [theirs[0].key()]);
        // (Not by a worker: another node's Device is not its to delete.)
        let mut as_worker = store.clone();
        let worker = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: { name: n1 }\nspec: { trust: worker }";
        as_worker.apply(written(worker)).unwrap();
        assert_eq!(changes(&as_worker, "n1", &found), (vec![], vec![], vec![]));
        store
            .apply(written(
                "apiVersion: kith.dev/v1\nkind: Node\nmetadata: { name: n2 }\nspec: {}",
            ))
            .unwrap();
        assert_eq!(changes(&store, "n1", &found), (vec![], vec![], vec![]));
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
        let (apply, delete, _) = changes(&store, "n1", &now);
        let applied: Vec<&str> = apply.iter().map(|r| r.metadata.name.as_str()).collect();
        // (The hand-written n1-camera-video0 is not ours: not deleted, and not found either.)
        assert_eq!(applied, ["n1-gpu-card0"]);
        assert_eq!(delete, ["Device/n1-usb-1-2"]);
        // A hand-written one under a name discovery would make is not overwritten.
        let (apply, _, _) = changes(&store, "n1", &found);
        assert!(apply.iter().all(|r| r.metadata.name != "n1-camera-video0"));
        // A machine without hardware loses all its own, and only its own.
        let (_, delete, _) = changes(&store, "n1", &[]);
        assert_eq!(delete.len(), found.len() - 1, "all but the camera someone wrote over");
        assert!(!delete.contains(&"Device/n1-gpu-card7".to_string()));
        assert!(!delete.contains(&"Seat/n1-seat1".to_string()));
        let _ = std::fs::remove_dir_all(&root);
    }

    fn node(name: &str, trust: &str) -> Resource {
        let node = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: { name: NAME }\nspec: { trust: TRUST }";
        written(&node.replace("NAME", name).replace("TRUST", trust))
    }

    #[test]
    fn longest_name_has_a_discovered_name() {
        let mut store = Store::default();
        let (long_a, long_b) = (format!("{}aaa", "n".repeat(57)), format!("{}bbb", "n".repeat(57)));
        for name in ["w", "w-b", "w-b-x", &long_a, &long_b] {
            store.apply(node(name, "worker")).unwrap();
        }
        assert_eq!(whose(&store, "w-gpu-card0"), ["w"]);
        assert_eq!(whose(&store, "w-b-gpu-card0"), ["w-b"]);
        assert_eq!(whose(&store, "w-b-seat0"), ["w-b"]);
        assert_eq!(whose(&store, "w-b-x-seat0"), ["w-b-x"]);
        assert_eq!(whose(&store, &format!("{}-seat0", "n".repeat(57))), [&long_a, &long_b]);
        assert_eq!(whose(&store, &format!("{long_a}-gp")), [&long_a]);
        // (Not a name that only begins like a node's: `wb-…` is not `w`'s.)
        assert!(whose(&store, "wb-gpu-card0").is_empty() && whose(&store, "x-gpu-card0").is_empty());
        // A node name of 63 is its Devices' name whole: its own, not a shorter node's that starts it.
        let short = "z".repeat(58);
        let full = format!("{short}-abcd");
        for name in [&short, &full] {
            store.apply(node(name, "worker")).unwrap();
        }
        assert_eq!(whose(&store, &full), [&full]);
        assert_eq!(whose(&store, &format!("{short}-gpu")), [&short]);
    }

    /// A node is not let in under a name that would take a discovered Device's name from the
    /// node that has it; its own from before (it joins again) and a tie are no hindrance.
    #[test]
    fn longest_name_is_not_taken_by_a_node_that_joins() {
        let root = tree("join");
        laptop(&root);
        let mut store = Store::default();
        store.apply(node("w", "worker")).unwrap();
        let found = scan(&root, "w");
        for resource in &found {
            store.apply(resource.clone()).unwrap();
        }
        let gpu = found.iter().find(|r| r.metadata.name.starts_with("w-gpu-")).unwrap();
        assert_eq!(taken_by(&store, "w-gpu"), Some((gpu.key(), "w".to_string())));
        assert_eq!(taken_by(&store, "w-b"), None);
        assert_eq!(taken_by(&store, "x"), None);
        // A long name's Devices (named by its cut stem) are not taken by a name that is the stem
        // and more, which ties; the stem itself as a name would take them.
        let long = format!("{}-abcd", "z".repeat(58));
        store.apply(node(&long, "worker")).unwrap();
        for resource in scan(&root, &long) {
            store.apply(resource).unwrap();
        }
        assert_eq!(taken_by(&store, &format!("{}-abce", "z".repeat(58))), None);
        assert!(taken_by(&store, &"z".repeat(57)).is_some_and(|(_, of)| of == long));
        // (Its own, left from before it was deleted: it joins again.)
        store.delete("Node/w").unwrap();
        assert_eq!(taken_by(&store, "w"), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A name of this node's that another node's discovery made a Device under is not listed, and
    /// said once: again only when what is held changes. One a person wrote is theirs, silently.
    #[test]
    fn held_name_is_said_once_and_a_persons_is_not() {
        let root = tree("held");
        laptop(&root);
        let found = scan(&root, "n1");
        let mut store = Store::default();
        store.apply(node("n1", "worker")).unwrap();
        store.apply(node("n", "worker")).unwrap();
        let mut theirs = found[0].clone();
        theirs.spec["node"] = "n".into();
        theirs.metadata.labels.insert("kith.dev/node".into(), "n".into());
        store.apply(theirs.clone()).unwrap();
        let hand = "apiVersion: kith.dev/v1\nkind: Device\nmetadata: { name: HAND }\nspec: { node: n, class: gpu }";
        store
            .apply(written(&hand.replace("HAND", &found[1].metadata.name)))
            .unwrap();
        let (apply, gone, held) = changes(&store, "n1", &found);
        assert_eq!(held, [(found[0].key(), "n".to_string())]);
        assert_eq!(apply.len(), found.len() - 2, "neither is written over");
        assert!(gone.is_empty(), "a worker takes nothing of another node's away");
        let mut said = Vec::new();
        let lines = held_lines(&mut said, held.clone());
        assert!(
            lines.len() == 1 && lines[0].contains(&found[0].key()) && lines[0].contains("node n "),
            "{lines:?}"
        );
        assert!(held_lines(&mut said, held).is_empty(), "said once");
        assert_eq!(
            held_lines(&mut said, Vec::new()),
            Vec::<String>::new(),
            "and nothing when it is free again"
        );
        // A name that is another node's (this node is named as that one and a class): not listed.
        store.apply(node("n1-gpu", "worker")).unwrap();
        let (apply, _, held) = changes(&store, "n1", &found);
        let gpu = found.iter().find(|r| r.metadata.name.starts_with("n1-gpu-")).unwrap();
        assert!(held.contains(&(gpu.key(), "n1-gpu".to_string())), "{held:?}");
        assert!(apply.iter().all(|r| r.key() != gpu.key()));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A discovered Device under a name that is another node's, made before that node joined, is
    /// taken away by a control node's pass (not by a worker's), so that node gets its name.
    #[test]
    fn taken_back_is_a_name_made_before_its_node_joined() {
        let root = tree("back");
        laptop(&root);
        let mut store = Store::default();
        store.apply(node("c", "control")).unwrap();
        store.apply(node("w", "worker")).unwrap();
        // `w` made what `w-b`'s discovery would, while there was no `w-b`.
        let mut early = scan(&root, "w-b").remove(0);
        early.spec["node"] = "w".into();
        early.metadata.labels.insert("kith.dev/node".into(), "w".into());
        store.apply(early.clone()).unwrap();
        assert!(
            changes(&store, "c", &[]).1.is_empty(),
            "w's, while no node has a longer name"
        );
        store.apply(node("w-b", "worker")).unwrap();
        assert_eq!(changes(&store, "c", &[]).1, [early.key()]);
        assert!(changes(&store, "w-b", &[]).1.is_empty(), "not by a worker");
        // Once it is gone, the node that joined lists its own under the name.
        let mut after = store.clone();
        after.delete(&early.key()).unwrap();
        let found = scan(&root, "w-b");
        let (apply, _, held) = changes(&after, "w-b", &found);
        assert!(apply.iter().any(|r| r.key() == early.key()) && held.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An admin's `kith.dev/namespaces` on this node's Device is not one discovery takes back: a
    /// pass writes the Device without it only if it is written over, and it is not.
    #[test]
    fn an_admins_namespaces_label_is_kept_by_discovery() {
        let root = tree("namespaces");
        laptop(&root);
        let found = scan(&root, "n1");
        let mut store = Store::default();
        store.apply(node("n1", "worker")).unwrap();
        let mut labelled = found[0].clone();
        labelled.metadata.labels.insert("kith.dev/namespaces".into(), "ops".into());
        store.apply(labelled.clone()).unwrap();
        let (apply, gone, _) = changes(&store, "n1", &found);
        let lost = apply.iter().any(|r| {
            r.key() == labelled.key() && r.metadata.labels.get("kith.dev/namespaces").map(String::as_str) != Some("ops")
        });
        assert!(!lost, "a pass writes the Device back without the label");
        assert!(gone.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
