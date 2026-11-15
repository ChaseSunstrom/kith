//! What a workload's `template.deviceClaims` come to: which `Device`s, on which node, and who
//! may hold them. Pure: it reads a store and answers, so the scheduler (to place a replica
//! and to write each `DeviceClaim`'s status) and the node's controller (to hand the replica
//! its device nodes) get the same answer from the same store.
//
// ponytail: a NodeWorkload cannot claim (its copies are on many nodes, a device on one); a
// Job or Workload is placed on one. Replicas of one Workload all hold what it holds.

use kith_api::kinds::{Access, DeviceClaimSpec, DeviceClass, DeviceSpec, SeatSpec};
use kith_api::{Resource, store::Store};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// What a claim, or all of a workload's claims, come to: one node and the names of its `Device`s.
#[derive(Debug, Clone, PartialEq)]
pub struct Held {
    pub node: String,
    pub devices: Vec<String>,
    /// The seat it has the directory of (a workload's: that of the first claim on one), and
    /// whether as a client: to read, and with none of the seat's devices.
    pub seat: Option<(String, bool)>,
}

/// What a workload is given on its node: device nodes, and a seat's directory.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Granted {
    pub devices: Vec<PathBuf>,
    /// The seat whose directory it has at `/run/seat`, and whether to read only.
    pub seat: Option<(String, bool)>,
}

/// The answer for every workload that names claims (its key), and every `DeviceClaim` (its key).
#[derive(Debug, Default)]
pub struct Claims {
    /// The node (and `Device`s) it is placed with, or why it is not placed, in plain words.
    pub owners: BTreeMap<String, Result<Held, String>>,
    /// The status each `DeviceClaim` should have.
    pub status: BTreeMap<String, Value>,
}

/// `a`, `a and b`, `a, b and c`.
fn list(names: &BTreeSet<&str>) -> String {
    let names: Vec<&str> = names.iter().copied().collect();
    match names.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => names.concat(),
    }
}

/// A `DeviceClaim` as it resolves: whether it is shared, the bytes of vram its share asks for, and
/// the `Device`s it names (or why it names none).
struct Known {
    shared: bool,
    share: Option<u64>,
    /// The key of the workload it names as holder (of its own namespace), if it names one.
    holder: Option<String>,
    found: Result<Held, String>,
}

/// The key of the workload a claim's `holder` names: `Workload/NAME` of the claim's namespace
/// is `Workload/{namespace}/NAME`.
fn holder_key(claim: &str, holder: &str) -> Option<String> {
    let namespace = claim.split('/').nth(1)?;
    let (kind, name) = holder.split_once('/')?;
    Some(format!("{kind}/{namespace}/{name}"))
}

/// The vram a `Device` counts its shares against: its `vram` label in bytes. None when it has no
/// such label, or one that is not a number: then nothing is counted there.
fn vram_of(store: &Store, device: &str) -> Option<u64> {
    store
        .get(&format!("Device/{device}"))?
        .metadata
        .labels
        .get("vram")?
        .parse()
        .ok()
}

/// The `Device`s one claim names and the one node they are on, or why it names none.
fn resolve_one(store: &Store, claim: &DeviceClaimSpec) -> Result<Held, String> {
    let (what, names): (&str, Vec<String>) = match (&claim.device, &claim.seat, claim.selector.is_empty()) {
        (Some(device), None, true) => ("the device", vec![device.clone()]),
        (None, Some(seat), true) => {
            let found = store.get(&format!("Seat/{seat}"));
            let found = found.ok_or(format!("there is no Seat {seat}"))?;
            let seat: SeatSpec = serde_json::from_value(found.spec.clone()).map_err(|e| format!("Seat {seat}: {e}"))?;
            ("the seat", seat.devices)
        }
        (None, None, false) => {
            let fits = |device: &&Resource| {
                let have = &device.metadata.labels;
                claim.selector.iter().all(|(k, v)| have.get(k) == Some(v))
            };
            let all = store.list(Some("Device")).filter(fits);
            ("the selector", all.map(|device| device.metadata.name.clone()).collect())
        }
        _ => return Err("name exactly one of seat, device or selector".into()),
    };
    if names.is_empty() {
        return Err(format!("{what} gives no Device"));
    }
    let mut nodes = BTreeSet::new();
    for name in &names {
        let device = store.get(&format!("Device/{name}"));
        let device = device.ok_or(format!("there is no Device {name}"))?;
        let spec: DeviceSpec =
            serde_json::from_value(device.spec.clone()).map_err(|e| format!("Device {name}: {e}"))?;
        nodes.insert(spec.node);
    }
    let nodes: BTreeSet<&str> = nodes.iter().map(String::as_str).collect();
    if nodes.len() > 1 {
        let add = if what == "the selector" {
            ": add kith.dev/node"
        } else {
            ""
        };
        return Err(format!("{what} matches devices on nodes {}{add}", list(&nodes)));
    }
    let mut devices = names;
    devices.sort();
    devices.dedup();
    let client = claim.access == Some(Access::Client);
    Ok(Held {
        node: list(&nodes),
        devices,
        seat: claim.seat.clone().map(|seat| (seat, client)),
    })
}

/// A workload's claims: its key, its namespace and the names it gives.
fn claimants(store: &Store) -> Vec<(String, String, Vec<String>)> {
    let owners = ["Workload", "Job"].into_iter().flat_map(|kind| store.list(Some(kind)));
    owners
        // (A Job that is over holds nothing, nor does a Workload of no replicas.)
        .filter(|owner| crate::sched::wants(owner).is_some_and(|(replicas, ..)| replicas > 0))
        .filter_map(|owner| {
            let names = owner.spec["template"]["deviceClaims"].as_array()?;
            let names: Vec<String> = names.iter().filter_map(|n| Some(n.as_str()?.to_string())).collect();
            let key = owner.key();
            let namespace = key.split('/').nth(1)?.to_string();
            (!names.is_empty()).then_some((key, namespace, names))
        })
        .collect()
}

/// Work out every claim and every workload that names some.
///
/// A claim is `Exclusive` unless it says `Shared`: one workload holds a Device at a time, whichever
/// claim it comes through. The holder is the workload the claim's status already names, then the
/// first by key; but a workload that a claim names as `holder` goes before them all, so it takes
/// the claim from whoever holds it. A workload holds all its claims or none, so two that want each
/// other's never wait for ever.
pub fn resolve(store: &Store) -> Claims {
    let known: BTreeMap<String, Known> = store
        .list(Some("DeviceClaim"))
        .map(|claim| {
            let spec: Result<DeviceClaimSpec, _> = serde_json::from_value(claim.spec.clone());
            let shared = spec.as_ref().is_ok_and(|spec| spec.access == Some(Access::Shared));
            let share = spec
                .as_ref()
                .ok()
                .filter(|_| shared)
                .and_then(|spec| spec.share.as_ref()?.vram.bytes());
            let key = claim.key();
            let holder = spec
                .as_ref()
                .ok()
                .filter(|spec| !matches!(spec.access, Some(Access::Shared | Access::Client)))
                .and_then(|spec| holder_key(&key, spec.holder.as_deref()?));
            let found = spec
                .map_err(|e| e.to_string())
                .and_then(|spec| resolve_one(store, &spec));
            (
                key,
                Known {
                    shared,
                    share,
                    holder,
                    found,
                },
            )
        })
        .collect();
    // The workloads named as holder by a claim that resolves: they go before the others who want
    // the claim, so one that is named takes it from whoever holds it now.
    let switched: BTreeSet<String> = known
        .values()
        .filter(|known| known.found.is_ok())
        .filter_map(|known| known.holder.clone())
        .collect();
    // Who each claim's status says holds it, and the share it was admitted with: a holder keeps its
    // share while it asks for no more than that, even where the Device has less vram than it asks
    // (a smaller label is not their turn lost). Asking for more is fitted again like a new claim.
    let mut kept: BTreeMap<String, (BTreeSet<String>, Option<u64>)> = BTreeMap::new();
    for claim in store.list(Some("DeviceClaim")) {
        let Some(status) = claim.status.as_ref() else { continue };
        let Some(holders) = status["holders"].as_array() else {
            continue;
        };
        let holders = holders.iter().filter_map(Value::as_str).map(String::from).collect();
        kept.insert(claim.key(), (holders, status["shareBytes"].as_u64()));
    }
    let recorded: BTreeSet<&str> = kept
        .values()
        .flat_map(|(holders, _)| holders)
        .map(String::as_str)
        .collect();
    let mut wanting = claimants(store);
    // (Those with a client claim after the others: a client asks who holds its seat.)
    let client = |namespace: &str, names: &[String]| {
        let of = |name: &String| known.get(&format!("DeviceClaim/{namespace}/{name}"));
        let is = |known: &Known| matches!(&known.found, Ok(held) if matches!(held.seat, Some((_, true))));
        names.iter().filter_map(of).any(is)
    };
    wanting.sort_by_key(|(key, namespace, names)| {
        (
            !switched.contains(key),
            !recorded.contains(key.as_str()),
            client(namespace, names),
            key.clone(),
        )
    });
    // The seats that are held, and the namespaces of who holds each: its sessions'.
    let mut sessions: BTreeSet<(String, String)> = BTreeSet::new();
    // Per Device: (claim key, holder, exclusively) for each way it is held.
    let mut taken: BTreeMap<String, Vec<(String, String, bool)>> = BTreeMap::new();
    let mut holders: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // Per Device: the vram bytes its admitted shares ask for.
    let mut asked: BTreeMap<String, u64> = BTreeMap::new();
    let mut claims = Claims::default();
    for (key, namespace, names) in wanting {
        // Per Device: the vram bytes this workload's own shares ask for, so far.
        let mut own: BTreeMap<String, u64> = BTreeMap::new();
        let outcome = (|| {
            let mut node: Option<&str> = None;
            let mut devices = BTreeSet::new();
            let mut seat: Option<(String, bool)> = None;
            for name in &names {
                let claim = format!("DeviceClaim/{namespace}/{name}");
                let Known {
                    shared, share, found, ..
                } = known.get(&claim).ok_or(format!("there is no DeviceClaim {name}"))?;
                let held = found.as_ref().map_err(|why| format!("DeviceClaim {name}: {why}"))?;
                if let Some(other) = node.filter(|other| *other != held.node) {
                    return Err(format!(
                        "its DeviceClaims are on different nodes, {other} and {}",
                        held.node
                    ));
                }
                node = Some(&held.node);
                // (One `/run/seat`: a client of one seat is not also of another, nor its holder.)
                if let (Some(first), Some(this)) = (&seat, &held.seat)
                    && first != this
                    && (first.1 || this.1)
                {
                    return Err(format!(
                        "DeviceClaim {name}: a client of a seat names no other seat, and does not hold its own"
                    ));
                }
                seat = seat.or(held.seat.clone());
                // A client takes no Device: it is beside whoever holds them. And it is an
                // app of its own namespace's session, not of another's: whoever may write a
                // claim in one namespace is not thereby let into a session of another.
                if let Some((seat, true)) = &held.seat {
                    if !sessions.contains(&(seat.clone(), namespace.clone())) {
                        return Err(format!(
                            "waiting for DeviceClaim {name}: no workload of this namespace holds Seat {seat}"
                        ));
                    }
                    continue;
                }
                for device in &held.devices {
                    let mut ways = taken.get(device).into_iter().flatten();
                    let clash = ways.find(|(_, by, exclusive)| *by != key && (*exclusive || !shared));
                    if let Some((via, by, _)) = clash {
                        return Err(if *via == claim {
                            format!("waiting for DeviceClaim {name}, held by {by}")
                        } else {
                            let via = via.strip_prefix("DeviceClaim/").unwrap_or(via);
                            format!(
                                "waiting for DeviceClaim {name}: Device {device} is held by {by} through DeviceClaim {via}"
                            )
                        });
                    }
                }
                // A share is counted against each Device's vram, as far as the Device has room: a
                // Device with no vram it can count admits it, and the status says it is not counted.
                if let Some(amount) = *share {
                    for device in &held.devices {
                        let Some(of) = vram_of(store, device) else { continue };
                        let used = asked
                            .get(device)
                            .copied()
                            .unwrap_or(0)
                            .saturating_add(own.get(device).copied().unwrap_or(0));
                        let free = of.saturating_sub(used);
                        let exempt = kept.get(&claim).is_some_and(|(holders, was)| {
                            holders.contains(&key) && was.is_some_and(|was| amount <= was)
                        });
                        if amount > free && !exempt {
                            return Err(format!(
                                "waiting for DeviceClaim {name}: Device {device} has {free} of its {of} vram bytes free, and the share asks for {amount}"
                            ));
                        }
                        let sum = own.entry(device.clone()).or_default();
                        *sum = sum.saturating_add(amount);
                    }
                }
                devices.extend(held.devices.iter().cloned());
            }
            let node = node.expect("a workload names a claim").to_string();
            Ok(Held {
                node,
                devices: devices.into_iter().collect(),
                seat,
            })
        })();
        if outcome.is_ok() {
            for (device, amount) in own {
                let sum = asked.entry(device).or_default();
                *sum = sum.saturating_add(amount);
            }
            for name in &names {
                let claim = format!("DeviceClaim/{namespace}/{name}");
                let shared = known[&claim].shared;
                holders.entry(claim.clone()).or_default().insert(key.clone());
                let found = known[&claim].found.as_ref().expect("it resolved");
                match &found.seat {
                    Some((_, true)) => continue,
                    Some((seat, false)) => drop(sessions.insert((seat.clone(), namespace.clone()))),
                    None => {}
                }
                for device in &found.devices {
                    taken
                        .entry(device.clone())
                        .or_default()
                        .push((claim.clone(), key.clone(), !shared));
                }
            }
        }
        claims.owners.insert(key, outcome);
    }
    for (claim, Known { share, found, .. }) in known {
        let status = match found {
            Ok(held) => {
                let holding = holders.remove(&claim).unwrap_or_default();
                // What each Device counts of a share: the sum of all the admitted ones, against its vram.
                let counts = share.map(|_| {
                    let counts = held.devices.iter().map(|device| {
                        let counted = match vram_of(store, device) {
                            Some(of) => {
                                json!({ "counted": true, "asked": asked.get(device).copied().unwrap_or(0), "of": of })
                            }
                            None => json!({ "counted": false }),
                        };
                        (device.clone(), counted)
                    });
                    Value::Object(counts.collect())
                });
                // (A client holds no Device: its holders are the seat's apps.)
                let devices = if matches!(held.seat, Some((_, true))) {
                    Vec::new()
                } else {
                    held.devices
                };
                let mut status = json!({ "node": held.node, "devices": devices, "holders": holding });
                if let (Some(amount), Some(counts)) = (share, counts) {
                    status["share"] = counts;
                    status["shareBytes"] = json!(amount);
                }
                status
            }
            // (Who held it still does when it is back: a Device gone for a moment, a USB
            // one plugged in again, is not the holder's turn lost. Nor its share's.)
            Err(message) => {
                let live = store.get(&claim).and_then(|claim| claim.status.as_ref());
                let mut status = json!({ "message": message });
                if let Some(held) = live.map(|status| &status["holders"]).filter(|held| held.is_array()) {
                    status["holders"] = held.clone();
                }
                if let Some(was) = live.and_then(|status| status.get("shareBytes")) {
                    status["shareBytes"] = was.clone();
                }
                status
            }
        };
        claims.status.insert(claim, status);
    }
    claims
}

/// The `DeviceClaim`s whose status is not what it should be: key and new status.
pub fn writes(store: &Store) -> Vec<(String, Option<Value>)> {
    let status = resolve(store).status;
    let differs = |(key, new): &(String, Value)| store.get(key).is_none_or(|claim| claim.status.as_ref() != Some(new));
    status
        .into_iter()
        .filter(differs)
        .map(|(key, new)| (key, Some(new)))
        .collect()
}

/// What to give each workload that is placed on `me` with claims: its key, the paths of
/// its device nodes and the seat whose directory it has, for what runs there. Only
/// `Device`s of `me` are ever in it. `sys` is `/sys`.
///
/// A plain host process (an exec unit) sees all of `/dev` already and needs none of this;
/// only a container is given these.
pub fn granted(store: &Store, me: &str, sys: &Path) -> BTreeMap<String, Granted> {
    let mut granted = BTreeMap::new();
    for (key, outcome) in resolve(store).owners {
        let Ok(held) = outcome else { continue };
        if held.node != me {
            continue;
        }
        // A client of a seat draws on the seat's GPUs and has no more of them: the render
        // nodes, and the nodes of NVIDIA's driver but the one that sets a screen's mode.
        let drawn = held.seat.as_ref().filter(|(_, client)| *client);
        let drawn = drawn.and_then(|(seat, _)| store.get(&format!("Seat/{seat}")));
        let drawn = drawn.and_then(|seat| serde_json::from_value::<SeatSpec>(seat.spec.clone()).ok());
        let drawn = drawn.map(|seat| seat.devices).unwrap_or_default();
        let mut paths = BTreeSet::new();
        let all = held.devices.iter().map(|name| (name, true));
        for (name, whole) in all.chain(drawn.iter().map(|name| (name, false))) {
            let Some(device) = store.get(&format!("Device/{name}")) else {
                continue;
            };
            let Ok(spec) = serde_json::from_value::<DeviceSpec>(device.spec.clone()) else {
                continue;
            };
            if spec.node != me || !(whole || spec.class == DeviceClass::Gpu) {
                continue;
            }
            // (What comes with it: the nodes of NVIDIA's driver.)
            let nodes = spec
                .nodes
                .iter()
                .filter(|node| whole || !node.ends_with("/nvidia-modeset"));
            paths.extend(nodes.map(PathBuf::from));
            // (A display has no path: it grants nothing.)
            let Some(path) = spec.path else {
                continue;
            };
            if spec.class == DeviceClass::Gpu {
                // The card's render node is how a program draws without being the screen's master.
                let card = path.rsplit('/').next().unwrap_or_default();
                let render = sys.join("class/drm").join(card).join("device/drm");
                let found = std::fs::read_dir(render).into_iter().flatten().flatten();
                for entry in found {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.strip_prefix("renderD").is_some_and(|n| !n.is_empty()) {
                        paths.insert(PathBuf::from("/dev/dri").join(name));
                    }
                }
            }
            if whole {
                paths.insert(PathBuf::from(path));
            }
        }
        let (devices, seat) = (paths.into_iter().collect(), held.seat);
        granted.insert(key, Granted { devices, seat });
    }
    granted
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_store::Command;
    use serde_json::json;

    /// Two nodes, each with a GPU and a camera, and a seat on `a`.
    const HARDWARE: &str = "
apiVersion: kith.dev/v1
kind: Device
metadata: { name: a-gpu-card0, labels: { class: gpu, kith.dev/node: a, vendor: '1002' } }
spec: { node: a, class: gpu, path: /dev/dri/card0 }
---
apiVersion: kith.dev/v1
kind: Device
metadata: { name: a-camera-video0, labels: { class: camera, kith.dev/node: a } }
spec: { node: a, class: camera, path: /dev/video0 }
---
apiVersion: kith.dev/v1
kind: Device
metadata: { name: a-display-card0-hdmi-a-1, labels: { class: display, kith.dev/node: a } }
spec: { node: a, class: display }
---
apiVersion: kith.dev/v1
kind: Device
metadata: { name: b-gpu-card0, labels: { class: gpu, kith.dev/node: b, vendor: '1002' } }
spec: { node: b, class: gpu, path: /dev/dri/card0 }
---
apiVersion: kith.dev/v1
kind: Seat
metadata: { name: a-seat0 }
spec: { node: a, devices: [a-gpu-card0, a-display-card0-hdmi-a-1] }
";

    fn store(extra: &str) -> Store {
        let mut store = Store::default();
        for resource in Resource::from_source(&format!("{HARDWARE}---\n{extra}")).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        store
    }

    fn claim(name: &str, spec: &str) -> String {
        format!("---\napiVersion: kith.dev/v1\nkind: DeviceClaim\nmetadata: {{ name: {name} }}\nspec: {spec}\n")
    }

    fn workload(name: &str, claims: &str) -> String {
        format!(
            "---\napiVersion: kith.dev/v1\nkind: Workload\nmetadata: {{ name: {name} }}\n\
             spec:\n  template:\n    containers: [{{ name: run, image: img }}]\n    deviceClaims: {claims}\n"
        )
    }

    /// The status of the DeviceClaim and what `resolve` says, written into the store as the scheduler does.
    fn settle(store: &mut Store) -> Claims {
        let claims = resolve(store);
        let statuses = writes(store);
        kith_store::run(store, Command::Status { statuses }).unwrap();
        assert!(writes(store).is_empty(), "a second look writes nothing");
        claims
    }

    fn held(claims: &Claims, key: &str) -> Result<(String, Vec<String>), String> {
        claims.owners[key].clone().map(|h| (h.node, h.devices))
    }

    #[test]
    fn a_claim_puts_the_workload_on_its_devices_node_and_says_who_holds_it() {
        let source = [
            claim("gpu", "{ device: b-gpu-card0 }"),
            claim("screen", "{ seat: a-seat0, access: shared }"),
            claim("cams", "{ selector: { class: camera } }"),
            workload("render", "[gpu]"),
            workload("kiosk", "[screen]"),
            workload("cam", "[cams]"),
        ]
        .concat();
        let mut store = store(&source);
        let claims = settle(&mut store);
        assert_eq!(
            held(&claims, "Workload/default/render"),
            Ok(("b".into(), vec!["b-gpu-card0".into()]))
        );
        let seat = vec!["a-display-card0-hdmi-a-1".to_string(), "a-gpu-card0".to_string()];
        assert_eq!(held(&claims, "Workload/default/kiosk"), Ok(("a".into(), seat.clone())));
        assert_eq!(
            held(&claims, "Workload/default/cam"),
            Ok(("a".into(), vec!["a-camera-video0".into()]))
        );
        let status = |name: &str| {
            store
                .get(&format!("DeviceClaim/default/{name}"))
                .unwrap()
                .status
                .clone()
        };
        assert_eq!(
            status("gpu"),
            Some(json!({ "node": "b", "devices": ["b-gpu-card0"], "holders": ["Workload/default/render"] }))
        );
        assert_eq!(
            status("screen"),
            Some(json!({ "node": "a", "devices": seat, "holders": ["Workload/default/kiosk"] }))
        );
    }

    #[test]
    fn a_second_exclusive_holder_waits_and_the_first_keeps_the_claim() {
        let source = [
            claim("gpu", "{ device: a-gpu-card0 }"),
            workload("one", "[gpu]"),
            workload("two", "[gpu]"),
        ]
        .concat();
        let mut store = store(&source);
        let claims = settle(&mut store);
        assert!(claims.owners["Workload/default/one"].is_ok());
        assert_eq!(
            claims.owners["Workload/default/two"],
            Err("waiting for DeviceClaim gpu, held by Workload/default/one".into())
        );
        let gpu = store.get("DeviceClaim/default/gpu").unwrap();
        assert_eq!(gpu.status.as_ref().unwrap()["holders"], json!(["Workload/default/one"]));
        // `one` goes, and `two` takes it over; `one` back again waits behind `two`, which keeps it.
        let key = "Workload/default/one";
        let mut gone = store.clone();
        gone.delete(key).unwrap();
        let after = settle(&mut gone);
        assert!(after.owners["Workload/default/two"].is_ok());
        gone.apply(
            Resource::from_source(&workload("one", "[gpu]"))
                .unwrap()
                .remove(0)
                .unwrap(),
        )
        .unwrap();
        let again = resolve(&gone);
        assert!(again.owners["Workload/default/two"].is_ok());
        assert_eq!(
            again.owners[key],
            Err("waiting for DeviceClaim gpu, held by Workload/default/two".into())
        );
        // The Device gone for a moment: nobody holds it, and `two` has it again when it is back.
        let mut device = gone.get("Device/a-gpu-card0").unwrap().clone();
        device.metadata.revision = None;
        gone.delete("Device/a-gpu-card0").unwrap();
        assert!(settle(&mut gone).owners["Workload/default/two"].is_err());
        let status = gone.get("DeviceClaim/default/gpu").unwrap().status.clone().unwrap();
        assert_eq!(status["holders"], json!(["Workload/default/two"]));
        assert!(status["message"].is_string());
        gone.apply(device).unwrap();
        let back = settle(&mut gone);
        assert!(back.owners["Workload/default/two"].is_ok() && back.owners[key].is_err());
        // `two` scaled to nothing runs nothing and holds nothing: `one` has its turn.
        let mut idle = gone.get("Workload/default/two").unwrap().clone();
        idle.metadata.revision = None;
        idle.spec["replicas"] = 0.into();
        gone.apply(idle).unwrap();
        assert!(settle(&mut gone).owners[key].is_ok());
    }

    #[test]
    fn shared_claims_have_any_number_of_holders_but_not_beside_an_exclusive_one() {
        let source = [
            claim("look", "{ device: a-gpu-card0, access: shared }"),
            claim("own", "{ device: a-gpu-card0 }"),
            workload("a1", "[look]"),
            workload("a2", "[look]"),
            workload("b1", "[own]"),
        ]
        .concat();
        let mut store = store(&source);
        let claims = settle(&mut store);
        assert!(claims.owners["Workload/default/a1"].is_ok() && claims.owners["Workload/default/a2"].is_ok());
        // Exclusive across claims: the same Device through another claim is held.
        let waiting = claims.owners["Workload/default/b1"].clone().unwrap_err();
        assert!(waiting.starts_with("waiting for DeviceClaim own: Device a-gpu-card0 is held by Workload/default/a"));
        assert!(waiting.ends_with("through DeviceClaim default/look"), "{waiting}");
        let look = store.get("DeviceClaim/default/look").unwrap();
        let both = json!(["Workload/default/a1", "Workload/default/a2"]);
        assert_eq!(look.status.as_ref().unwrap()["holders"], both);
        assert_eq!(
            store.get("DeviceClaim/default/own").unwrap().status.as_ref().unwrap()["holders"],
            json!([])
        );
    }

    #[test]
    fn two_exclusive_claims_of_one_device_are_one_holder_at_a_time() {
        let source = [
            claim("x", "{ device: a-gpu-card0 }"),
            claim("y", "{ selector: { vendor: '1002', kith.dev/node: a } }"),
            workload("p", "[x]"),
            workload("q", "[y]"),
            // One workload may hold both its own claims of a Device.
            workload("r", "[x, y]"),
        ]
        .concat();
        let claims = resolve(&store(&source));
        assert!(claims.owners["Workload/default/p"].is_ok());
        assert!(
            claims.owners["Workload/default/q"]
                .clone()
                .unwrap_err()
                .contains("Workload/default/p")
        );
        assert!(claims.owners["Workload/default/r"].is_err());
        let only = store(
            &[
                claim("x", "{ device: a-gpu-card0 }"),
                claim("y", "{ device: a-gpu-card0 }"),
                workload("r", "[x, y]"),
            ]
            .concat(),
        );
        assert!(resolve(&only).owners["Workload/default/r"].is_ok());
    }

    #[test]
    fn a_claim_that_does_not_resolve_says_why_and_places_nobody() {
        let source = [
            claim("any-gpu", "{ selector: { class: gpu } }"),
            claim("by-node", "{ selector: { class: gpu, kith.dev/node: b } }"),
            claim("none", "{ selector: { class: tape } }"),
            claim("ghost", "{ device: nowhere }"),
            claim("lost-seat", "{ seat: nowhere }"),
            claim("a-cam", "{ device: a-camera-video0 }"),
            workload("w1", "[any-gpu]"),
            workload("w2", "[by-node]"),
            workload("w3", "[none]"),
            workload("w4", "[ghost]"),
            workload("w5", "[lost-seat]"),
            workload("w6", "[missing]"),
            workload("w7", "[a-cam, by-node]"),
        ]
        .concat();
        let mut store = store(&source);
        let claims = settle(&mut store);
        let why = |n: u8| claims.owners[&format!("Workload/default/w{n}")].clone().unwrap_err();
        assert_eq!(
            why(1),
            "DeviceClaim any-gpu: the selector matches devices on nodes a and b: add kith.dev/node"
        );
        assert!(claims.owners["Workload/default/w2"].is_ok());
        assert_eq!(why(3), "DeviceClaim none: the selector gives no Device");
        assert_eq!(why(4), "DeviceClaim ghost: there is no Device nowhere");
        assert_eq!(why(5), "DeviceClaim lost-seat: there is no Seat nowhere");
        assert_eq!(why(6), "there is no DeviceClaim missing");
        assert_eq!(why(7), "its DeviceClaims are on different nodes, a and b");
        let status = |name: &str| {
            store
                .get(&format!("DeviceClaim/default/{name}"))
                .unwrap()
                .status
                .clone()
        };
        let said = status("any-gpu").unwrap();
        assert!(
            said["message"].as_str().unwrap().contains("add kith.dev/node"),
            "{said}"
        );
        assert_eq!(said.as_object().unwrap().len(), 1);
        // A claim is read in the workload's own namespace.
        let other = format!(
            "{}---\napiVersion: kith.dev/v1\nkind: Workload\nmetadata: {{ name: w, namespace: ops }}\nspec: {{ template: {{ containers: [{{ name: run, image: i }}], deviceClaims: [by-node] }} }}\n",
            ""
        );
        store
            .apply(Resource::from_source(&other).unwrap().remove(0).unwrap())
            .unwrap();
        assert_eq!(
            resolve(&store).owners["Workload/ops/w"],
            Err("there is no DeviceClaim by-node".into())
        );
    }

    /// An app as its own workload: a client of a seat is on the seat's node beside the
    /// session, holds none of its devices, and is given the GPU's render node and the
    /// seat's directory to read.
    #[test]
    fn a_client_of_a_seat_is_beside_its_session_and_takes_none_of_its_devices() {
        let nvidia = "---\napiVersion: kith.dev/v1\nkind: Device\nmetadata: { name: a-gpu-card0 }\n\
                      spec: { node: a, class: gpu, path: /dev/dri/card0, nodes: [/dev/nvidiactl, /dev/nvidia-modeset] }\n";
        let source = [
            nvidia,
            &claim("desk", "{ seat: a-seat0 }"),
            &claim("apps", "{ seat: a-seat0, access: client }"),
            &claim("cam", "{ device: a-camera-video0 }"),
            &workload("session", "[desk]"),
            &workload("editor", "[apps]"),
            &workload("call", "[cam, apps]"),
        ]
        .concat();
        let mut store = store(&source);
        let claims = settle(&mut store);
        let seat_devices = vec!["a-display-card0-hdmi-a-1".to_string(), "a-gpu-card0".to_string()];
        assert_eq!(
            held(&claims, "Workload/default/session"),
            Ok(("a".into(), seat_devices))
        );
        // Any number of clients, each on the seat's node, none holding a Device of it.
        assert_eq!(held(&claims, "Workload/default/editor"), Ok(("a".into(), vec![])));
        assert_eq!(
            held(&claims, "Workload/default/call"),
            Ok(("a".into(), vec!["a-camera-video0".to_string()]))
        );
        // The seat's apps are the holders of its client claims, which hold no Device.
        let apps = store.get("DeviceClaim/default/apps").unwrap().status.clone().unwrap();
        assert_eq!(
            apps["holders"],
            json!(["Workload/default/call", "Workload/default/editor"])
        );
        assert_eq!(apps["devices"], json!([]));

        let root = sys("client");
        let on_a = granted(&store, "a", &root);
        let paths = |key: &str| {
            on_a[key]
                .devices
                .iter()
                .map(|p| p.to_str().unwrap())
                .collect::<Vec<_>>()
        };
        // The session: the card and all that comes with it, and the seat's directory to write.
        assert_eq!(
            paths("Workload/default/session"),
            [
                "/dev/dri/card0",
                "/dev/dri/renderD128",
                "/dev/nvidia-modeset",
                "/dev/nvidiactl"
            ]
        );
        assert_eq!(on_a["Workload/default/session"].seat, Some(("a-seat0".into(), false)));
        // An app: the render node, not the card, nor what sets a screen's mode; the directory to read.
        assert_eq!(
            paths("Workload/default/editor"),
            ["/dev/dri/renderD128", "/dev/nvidiactl"]
        );
        assert_eq!(on_a["Workload/default/editor"].seat, Some(("a-seat0".into(), true)));
        assert_eq!(
            paths("Workload/default/call"),
            ["/dev/dri/renderD128", "/dev/nvidiactl", "/dev/video0"]
        );
        // An app is of its own namespace's session. With none on the seat it waits; and a
        // claim written in another namespace than the session's lets nobody into it.
        let apps = [
            claim("apps", "{ seat: a-seat0, access: client }"),
            workload("editor", "[apps]"),
        ]
        .concat();
        let waits = Err("waiting for DeviceClaim apps: no workload of this namespace holds Seat a-seat0".to_string());
        assert_eq!(held(&resolve(&self::store(&apps)), "Workload/default/editor"), waits);
        let elsewhere = apps.replace("name: apps }", "name: apps, namespace: other }");
        let elsewhere = elsewhere.replace("name: editor }", "name: editor, namespace: other }");
        // (And claiming the seat for itself there, which waits behind the session, is no way in.)
        let pushes = [claim("desk", "{ seat: a-seat0 }"), workload("pushes", "[desk]")].concat();
        let pushes = pushes
            .replace("name: desk }", "name: desk, namespace: other }")
            .replace("name: pushes }", "name: pushes, namespace: other }");
        let mut store = self::store(&[source.as_str(), &elsewhere, &pushes].concat());
        let claims = settle(&mut store);
        assert!(held(&claims, "Workload/default/editor").is_ok());
        let pushed = held(&claims, "Workload/other/pushes").unwrap_err();
        assert!(pushed.contains("held by Workload/default/session"), "{pushed}");
        assert_eq!(held(&claims, "Workload/other/editor"), waits);
        assert!(!granted(&store, "a", &root).contains_key("Workload/other/editor"));
        let theirs = store.get("DeviceClaim/other/apps").unwrap().status.clone().unwrap();
        assert_eq!(theirs["holders"], json!([]));
        // One seat's directory is one workload's: a client that would also hold the seat is
        // refused in either order, beside a session (which is not disturbed) or with none.
        let greedy = |with: &str, both: &str| {
            let store = self::store(&[with, &claim("mine", "{ seat: a-seat0 }"), &workload("greedy", both)].concat());
            let claims = resolve(&store);
            (held(&claims, "Workload/default/greedy").unwrap_err(), claims)
        };
        for both in ["[apps, desk]", "[desk, apps]"] {
            assert!(held(&greedy(&source, both).1, "Workload/default/session").is_ok());
        }
        let alone = claim("apps", "{ seat: a-seat0, access: client }");
        let refused = greedy(&alone, "[mine, apps]").0;
        assert!(refused.contains("a client of a seat names no other seat"), "{refused}");
        // A client is of a seat, and of nothing else.
        let wrong = claim("apps", "{ device: a-gpu-card0, access: client }");
        assert!(Resource::from_source(&wrong).unwrap().remove(0).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A made-up `/sys` with a render node for `card0`.
    fn sys(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("kith-claims-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("class/drm/card0/device/drm/renderD128")).unwrap();
        std::fs::create_dir_all(root.join("class/drm/card0/device/drm/card0")).unwrap();
        root
    }

    #[test]
    fn a_claim_grants_this_nodes_device_nodes_and_a_gpus_render_node() {
        let source = [
            claim("screen", "{ seat: a-seat0 }"),
            claim("cam", "{ device: a-camera-video0 }"),
            claim("far", "{ device: b-gpu-card0 }"),
            workload("kiosk", "[screen, cam]"),
            workload("far", "[far]"),
        ]
        .concat();
        let store = store(&source);
        let root = sys("render");
        let on_a = granted(&store, "a", &root);
        let paths = |key: &str| {
            on_a[key]
                .devices
                .iter()
                .map(|p| p.to_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        // The display has no path; the GPU brings its render node; the camera is a device node.
        assert_eq!(
            paths("Workload/default/kiosk"),
            ["/dev/dri/card0", "/dev/dri/renderD128", "/dev/video0"]
        );
        // What is on b is for b, not for a.
        assert!(!on_a.contains_key("Workload/default/far"));
        // A /sys without the card: the card's own node only.
        let empty = sys("none");
        std::fs::remove_dir_all(empty.join("class")).unwrap();
        assert_eq!(
            granted(&store, "b", &empty)["Workload/default/far"].devices,
            [PathBuf::from("/dev/dri/card0")]
        );
        assert_eq!(granted(&store, "a", &empty)["Workload/default/kiosk"].devices.len(), 2);
        // A Device that lists further nodes (an NVIDIA card's) gives them with its own.
        let nvidia = "---\napiVersion: kith.dev/v1\nkind: Device\nmetadata: { name: a-gpu-card1 }\n\
                      spec: { node: a, class: gpu, path: /dev/dri/card1, nodes: [/dev/nvidiactl, /dev/nvidia0] }\n";
        let source = [
            nvidia,
            &claim("cuda", "{ device: a-gpu-card1 }"),
            &workload("train", "[cuda]"),
        ]
        .concat();
        assert_eq!(
            granted(&self::store(&source), "a", &empty)["Workload/default/train"].devices,
            ["/dev/dri/card1", "/dev/nvidia0", "/dev/nvidiactl"].map(PathBuf::from)
        );
        // And a card with no node of its own (no DRM card) still gives those of its driver.
        let source = source.replace("path: /dev/dri/card1, ", "");
        assert_eq!(
            granted(&self::store(&source), "a", &empty)["Workload/default/train"].devices,
            ["/dev/nvidia0", "/dev/nvidiactl"].map(PathBuf::from)
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&empty);
    }

    /// A stand-in GPU on `a`, with no real card behind it: `extra` is more labels (`, vram: '1073741824'`).
    fn card(name: &str, extra: &str) -> String {
        format!(
            "---\napiVersion: kith.dev/v1\nkind: Device\nmetadata: {{ name: {name}, labels: {{ class: gpu, kith.dev/node: a{extra} }} }}\n\
             spec: {{ node: a, class: gpu, path: /dev/dri/{name} }}\n"
        )
    }

    #[test]
    fn a_share_is_admitted_while_the_device_has_the_vram_and_waits_with_the_numbers() {
        let source = [
            card("a-vram", ", vram: '1073741824'"),
            card("a-tiny", ", vram: '1073741824'"),
            claim("half", "{ device: a-vram, access: shared, share: { vram: 512Mi } }"),
            claim("look", "{ device: a-vram, access: shared }"),
            claim("huge", "{ device: a-tiny, access: shared, share: { vram: 2Gi } }"),
            workload("a1", "[half]"),
            workload("a2", "[half]"),
            workload("a3", "[half]"),
            workload("f1", "[look]"),
            workload("h", "[huge]"),
        ]
        .concat();
        let mut store = store(&source);
        let claims = settle(&mut store);
        // 1 GiB of vram: two halves fill it, and the third waits with the numbers. A shared claim
        // with no share counts as nothing, so `f1` is admitted beside them.
        assert!(claims.owners["Workload/default/a1"].is_ok() && claims.owners["Workload/default/a2"].is_ok());
        assert!(claims.owners["Workload/default/f1"].is_ok());
        assert_eq!(
            claims.owners["Workload/default/a3"],
            Err("waiting for DeviceClaim half: Device a-vram has 0 of its 1073741824 vram bytes free, and the share asks for 536870912".into())
        );
        // A share bigger than the whole card waits for ever, and says so.
        assert_eq!(
            claims.owners["Workload/default/h"],
            Err("waiting for DeviceClaim huge: Device a-tiny has 1073741824 of its 1073741824 vram bytes free, and the share asks for 2147483648".into())
        );
        let status = store.get("DeviceClaim/default/half").unwrap().status.clone().unwrap();
        assert_eq!(status["holders"], json!(["Workload/default/a1", "Workload/default/a2"]));
        assert_eq!(
            status["share"],
            json!({ "a-vram": { "counted": true, "asked": 1073741824, "of": 1073741824 } })
        );
        // A holder that goes frees its share, and the one that waited has its turn.
        store.delete("Workload/default/a1").unwrap();
        assert!(settle(&mut store).owners["Workload/default/a3"].is_ok());
    }

    #[test]
    fn who_holds_a_share_keeps_it_when_the_device_has_less_vram_than_they_ask() {
        let source = [
            card("a-vram", ", vram: '1073741824'"),
            claim("half", "{ device: a-vram, access: shared, share: { vram: 512Mi } }"),
            workload("a1", "[half]"),
            workload("a2", "[half]"),
        ]
        .concat();
        let mut store = store(&source);
        settle(&mut store);
        // The label is written smaller: both holders keep their share, and a new one waits.
        store.delete("Device/a-vram").unwrap();
        let smaller = Resource::from_source(&card("a-vram", ", vram: '536870912'"))
            .unwrap()
            .remove(0)
            .unwrap();
        store.apply(smaller).unwrap();
        store
            .apply(
                Resource::from_source(&workload("a3", "[half]"))
                    .unwrap()
                    .remove(0)
                    .unwrap(),
            )
            .unwrap();
        let after = settle(&mut store);
        assert!(after.owners["Workload/default/a1"].is_ok() && after.owners["Workload/default/a2"].is_ok());
        assert_eq!(
            after.owners["Workload/default/a3"],
            Err("waiting for DeviceClaim half: Device a-vram has 0 of its 536870912 vram bytes free, and the share asks for 536870912".into())
        );
    }

    #[test]
    fn a_holder_that_asks_for_more_than_it_held_is_fitted_again() {
        let source = [
            card("a-vram", ", vram: '1073741824'"),
            claim("half", "{ device: a-vram, access: shared, share: { vram: 512Mi } }"),
            workload("a1", "[half]"),
            workload("a2", "[half]"),
        ]
        .concat();
        let mut store = store(&source);
        settle(&mut store);
        // The claim now asks for all of the card: a1 has the room, and a2 (which held 512Mi) waits.
        let bigger = claim("half", "{ device: a-vram, access: shared, share: { vram: 1Gi } }");
        store
            .apply(Resource::from_source(&bigger).unwrap().remove(0).unwrap())
            .unwrap();
        let after = settle(&mut store);
        assert!(after.owners["Workload/default/a1"].is_ok());
        assert_eq!(
            after.owners["Workload/default/a2"],
            Err("waiting for DeviceClaim half: Device a-vram has 0 of its 1073741824 vram bytes free, and the share asks for 1073741824".into())
        );
    }

    #[test]
    fn a_device_with_no_vram_label_admits_its_shares_and_says_they_are_not_counted() {
        let source = [
            card("a-bare", ""),
            card("a-odd", ", vram: lots"),
            claim("bare", "{ device: a-bare, access: shared, share: { vram: 8Gi } }"),
            claim("odd", "{ device: a-odd, access: shared, share: { vram: 8Gi } }"),
            workload("b1", "[bare]"),
            workload("b2", "[bare]"),
            workload("b3", "[odd]"),
            workload("b4", "[odd]"),
        ]
        .concat();
        let mut store = store(&source);
        let claims = settle(&mut store);
        assert!(claims.owners.values().all(Result::is_ok), "{:?}", claims.owners);
        let status = |name: &str| {
            store
                .get(&format!("DeviceClaim/default/{name}"))
                .unwrap()
                .status
                .clone()
                .unwrap()
        };
        assert_eq!(status("bare")["share"], json!({ "a-bare": { "counted": false } }));
        assert_eq!(status("odd")["share"], json!({ "a-odd": { "counted": false } }));
        assert_eq!(
            status("odd")["holders"],
            json!(["Workload/default/b3", "Workload/default/b4"])
        );
    }

    #[test]
    fn a_workload_asks_for_the_sum_of_its_shares_of_a_device_over_all_its_claims() {
        let source = [
            card("a-vram", ", vram: '1073741824'"),
            claim("p1", "{ device: a-vram, access: shared, share: { vram: 768Mi } }"),
            claim("p2", "{ device: a-vram, access: shared, share: { vram: 768Mi } }"),
            claim("p3", "{ device: a-vram, access: shared, share: { vram: 512Mi } }"),
            claim("p4", "{ device: a-vram, access: shared, share: { vram: 512Mi } }"),
            workload("a-solo", "[p1, p2]"),
            workload("pair", "[p3, p4]"),
        ]
        .concat();
        let claims = resolve(&store(&source));
        assert!(
            claims.owners["Workload/default/a-solo"]
                .clone()
                .unwrap_err()
                .starts_with(
                    "waiting for DeviceClaim p2: Device a-vram has 268435456 of its 1073741824 vram bytes free"
                ),
        );
        assert!(claims.owners["Workload/default/pair"].is_ok());
    }

    #[test]
    fn a_share_is_of_a_shared_claim_and_is_a_whole_number_of_bytes_above_nothing() {
        let valid = claim("ok", "{ device: a-vram, access: shared, share: { vram: 512Mi } }");
        assert!(Resource::from_source(&valid).unwrap().remove(0).is_ok());
        for (spec, names) in [
            ("{ device: a-vram, share: { vram: 512Mi } }", "share"),
            ("{ device: a-vram, access: exclusive, share: { vram: 512Mi } }", "share"),
            ("{ device: a-vram, access: shared, share: { vram: 0 } }", "share"),
            ("{ device: a-vram, access: shared, share: { vram: 0.5 } }", "share"),
            (
                "{ device: a-vram, access: shared, share: { vram: 512Mi, weight: 50 } }",
                "weight",
            ),
            ("{ device: a-vram, access: shared, share: {} }", "vram"),
        ] {
            let refused = Resource::from_source(&claim("x", spec))
                .unwrap()
                .remove(0)
                .unwrap_err()
                .to_string();
            assert!(refused.contains(names), "{spec}: {refused}");
        }
    }

    #[test]
    fn a_claim_holder_takes_it_from_the_recorded_holder_and_gives_it_back() {
        let source = [
            claim("gpu", "{ device: a-gpu-card0 }"),
            workload("one", "[gpu]"),
            workload("two", "[gpu]"),
        ]
        .concat();
        let mut store = store(&source);
        assert!(settle(&mut store).owners["Workload/default/one"].is_ok());
        // Named as holder, each takes the claim from the other, which waits and says so.
        for (holder, other) in [("two", "one"), ("one", "two")] {
            let mut named = store.get("DeviceClaim/default/gpu").unwrap().clone();
            named.metadata.revision = None;
            named.spec["holder"] = format!("Workload/{holder}").into();
            store.apply(named).unwrap();
            let claims = settle(&mut store);
            assert!(claims.owners[&format!("Workload/default/{holder}")].is_ok());
            assert_eq!(
                claims.owners[&format!("Workload/default/{other}")],
                Err(format!(
                    "waiting for DeviceClaim gpu, held by Workload/default/{holder}"
                ))
            );
            let status = store.get("DeviceClaim/default/gpu").unwrap().status.clone().unwrap();
            assert_eq!(status["holders"], json!([format!("Workload/default/{holder}")]));
        }
    }

    /// What a node runs is what `granted` gives: the holder gets the device, and the workload it
    /// takes the claim from gets nothing, so the controller stops that one and starts the other.
    #[test]
    fn a_switched_claim_is_granted_to_its_holder_and_not_to_the_one_it_takes_it_from() {
        let source = [
            claim("gpu", "{ device: a-gpu-card0, holder: Workload/two }"),
            workload("one", "[gpu]"),
            workload("two", "[gpu]"),
        ]
        .concat();
        let store = store(&source);
        let root = sys("switch");
        let on_a = granted(&store, "a", &root);
        assert!(on_a.contains_key("Workload/default/two"));
        assert!(!on_a.contains_key("Workload/default/one"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_holder_is_a_workload_or_job_of_the_claims_own_namespace_on_an_exclusive_claim() {
        for spec in [
            "{ device: a-gpu-card0, holder: Workload/one }",
            "{ device: a-gpu-card0, holder: Job/one }",
        ] {
            assert!(
                Resource::from_source(&claim("ok", spec)).unwrap().remove(0).is_ok(),
                "{spec}"
            );
        }
        for spec in [
            "{ device: a-gpu-card0, holder: Workload/other/one }",
            "{ device: a-gpu-card0, holder: one }",
            "{ device: a-gpu-card0, holder: Seat/one }",
            "{ device: a-gpu-card0, holder: Workload/ }",
            "{ device: a-gpu-card0, access: shared, holder: Workload/one }",
            "{ seat: a-seat0, access: client, holder: Workload/one }",
        ] {
            let refused = Resource::from_source(&claim("x", spec))
                .unwrap()
                .remove(0)
                .unwrap_err()
                .to_string();
            assert!(refused.contains("holder"), "{spec}: {refused}");
        }
    }
}
