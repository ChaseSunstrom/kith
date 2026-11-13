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
    Ok(Held {
        node: list(&nodes),
        devices,
    })
}

/// A workload's claims: its key, its namespace and the names it gives.
fn claimants(store: &Store) -> Vec<(String, String, Vec<String>)> {
    let owners = ["Workload", "Job"].into_iter().flat_map(|kind| store.list(Some(kind)));
    owners
        // (A Job that is over holds nothing.)
        .filter(|owner| crate::sched::wants(owner).is_some())
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
/// first by key; a workload holds all its claims or none, so two that want each other's never
/// wait for ever.
pub fn resolve(store: &Store) -> Claims {
    let known: BTreeMap<String, (bool, Result<Held, String>)> = store
        .list(Some("DeviceClaim"))
        .map(|claim| {
            let spec: Result<DeviceClaimSpec, _> = serde_json::from_value(claim.spec.clone());
            let shared = spec.as_ref().is_ok_and(|spec| spec.access == Some(Access::Shared));
            let found = spec
                .map_err(|e| e.to_string())
                .and_then(|spec| resolve_one(store, &spec));
            (claim.key(), (shared, found))
        })
        .collect();
    // Who each claim's status says holds it: they keep it.
    let recorded: BTreeSet<&str> = store
        .list(Some("DeviceClaim"))
        .filter_map(|claim| claim.status.as_ref()?["holders"].as_array())
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut wanting = claimants(store);
    wanting.sort_by_key(|(key, ..)| (!recorded.contains(key.as_str()), key.clone()));
    // Per Device: (claim key, holder, exclusively) for each way it is held.
    let mut taken: BTreeMap<String, Vec<(String, String, bool)>> = BTreeMap::new();
    let mut holders: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut claims = Claims::default();
    for (key, namespace, names) in wanting {
        let outcome = (|| {
            let mut node: Option<&str> = None;
            let mut devices = BTreeSet::new();
            for name in &names {
                let claim = format!("DeviceClaim/{namespace}/{name}");
                let (shared, found) = known.get(&claim).ok_or(format!("there is no DeviceClaim {name}"))?;
                let held = found.as_ref().map_err(|why| format!("DeviceClaim {name}: {why}"))?;
                if let Some(other) = node.filter(|other| *other != held.node) {
                    return Err(format!(
                        "its DeviceClaims are on different nodes, {other} and {}",
                        held.node
                    ));
                }
                node = Some(&held.node);
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
                devices.extend(held.devices.iter().cloned());
            }
            let node = node.expect("a workload names a claim").to_string();
            Ok(Held {
                node,
                devices: devices.into_iter().collect(),
            })
        })();
        if let Ok(held) = &outcome {
            for name in &names {
                let claim = format!("DeviceClaim/{namespace}/{name}");
                let shared = known[&claim].0;
                holders.entry(claim.clone()).or_default().insert(key.clone());
                for device in &known[&claim].1.as_ref().expect("it resolved").devices {
                    taken
                        .entry(device.clone())
                        .or_default()
                        .push((claim.clone(), key.clone(), !shared));
                }
            }
            debug_assert!(!held.devices.is_empty());
        }
        claims.owners.insert(key, outcome);
    }
    for (claim, (_, found)) in known {
        let status = match found {
            Ok(held) => {
                let holding = holders.remove(&claim).unwrap_or_default();
                json!({ "node": held.node, "devices": held.devices, "holders": holding })
            }
            Err(message) => json!({ "message": message }),
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

/// The device nodes to give each workload that is placed on `me` with claims: its key and
/// the paths, for what runs there. Only `Device`s of `me` are ever in it. `sys` is `/sys`.
///
/// A plain host process (an exec unit) sees all of `/dev` already and needs none of this;
/// only a container is given these.
pub fn granted(store: &Store, me: &str, sys: &Path) -> BTreeMap<String, Vec<PathBuf>> {
    let mut granted = BTreeMap::new();
    for (key, outcome) in resolve(store).owners {
        let Ok(held) = outcome else { continue };
        if held.node != me {
            continue;
        }
        let mut paths = BTreeSet::new();
        for name in &held.devices {
            let Some(device) = store.get(&format!("Device/{name}")) else {
                continue;
            };
            let Ok(spec) = serde_json::from_value::<DeviceSpec>(device.spec.clone()) else {
                continue;
            };
            // (A display has no path: it grants nothing.)
            let Some(path) = spec.path.filter(|_| spec.node == me) else {
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
            paths.insert(PathBuf::from(path));
        }
        granted.insert(key, paths.into_iter().collect());
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
            granted(&store, "b", &empty)["Workload/default/far"],
            [PathBuf::from("/dev/dri/card0")]
        );
        assert_eq!(granted(&store, "a", &empty)["Workload/default/kiosk"].len(), 2);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&empty);
    }
}
