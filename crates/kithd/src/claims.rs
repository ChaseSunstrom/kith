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
    /// A workload's: the vram bytes its shares ask of each Device it counts them on.
    pub shares: BTreeMap<String, u64>,
}

/// What a workload is given on its node: device nodes, and a seat's directory.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Granted {
    pub devices: Vec<PathBuf>,
    /// The seat whose directory it has at `/run/seat`, and whether to read only.
    pub seat: Option<(String, bool)>,
    /// Each Device it draws on here, and its class: the node's own policy may hand out none
    /// of a class, and what holds one is then not run (`policy::Policy::device`).
    pub classes: Vec<(String, DeviceClass)>,
    /// The dmem cgroup's regions its shares are a ceiling on, and the bytes of each.
    pub dmem: Vec<(String, u64)>,
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

/// The region of the dmem cgroup a `Device` is, where its driver gives one: its `dmem` label.
/// (One name, as the kernel writes them: a label written by hand is no more lines of `dmem.max`.)
fn dmem_of(store: &Store, device: &str) -> Option<String> {
    let region = store.get(&format!("Device/{device}"))?.metadata.labels.get("dmem")?;
    (!region.is_empty() && !region.contains(char::is_whitespace)).then(|| region.clone())
}

/// The label on a Device or Seat that names the namespaces it is given to, comma-separated.
pub(crate) const NAMESPACES: &str = "kith.dev/namespaces";

/// Whether a Device or Seat is given to a claim of `namespace`: kith-system's claims always are; a
/// labelled one is given to the namespaces its label lists; an unlabelled GPU is given to all.
pub(crate) fn given(resource: &Resource, namespace: &str) -> bool {
    if namespace == crate::volumes::SYSTEM {
        return true;
    }
    match resource.metadata.labels.get(NAMESPACES) {
        Some(list) => list.split(',').any(|named| named.trim() == namespace),
        None => resource.kind == "Device" && resource.spec["class"] == "gpu",
    }
}

/// The `Device`s one claim of `namespace` names and the one node they are on, or why it names none.
fn resolve_one(store: &Store, namespace: &str, claim: &DeviceClaimSpec) -> Result<Held, String> {
    let (what, names): (&str, Vec<String>) = match (&claim.device, &claim.seat, claim.selector.is_empty()) {
        (Some(device), None, true) => ("the device", vec![device.clone()]),
        (None, Some(seat), true) => {
            let found = store.get(&format!("Seat/{seat}"));
            let found = found.ok_or(format!("there is no Seat {seat}"))?;
            if !given(found, namespace) {
                return Err(format!(
                    "Seat {seat} is not given to namespace {namespace} (its {NAMESPACES} label)"
                ));
            }
            let seat: SeatSpec = serde_json::from_value(found.spec.clone()).map_err(|e| format!("Seat {seat}: {e}"))?;
            ("the seat", seat.devices)
        }
        (None, None, false) => {
            let fits = |device: &&Resource| {
                let have = &device.metadata.labels;
                claim.selector.iter().all(|(k, v)| have.get(k) == Some(v))
            };
            // (One kept while its hardware is gone is passed over.)
            let there = |device: &&Resource| !device.metadata.labels.contains_key(crate::devices::ABSENT);
            let matched: Vec<&Resource> = store.list(Some("Device")).filter(fits).filter(there).collect();
            // (Only the matches given to the namespace are its; the others are not named back.)
            let names: Vec<String> = matched
                .iter()
                .filter(|device| given(device, namespace))
                .map(|device| device.metadata.name.clone())
                .collect();
            if !matched.is_empty() && names.is_empty() {
                return Err(format!("the selector gives no Device given to namespace {namespace}"));
            }
            ("the selector", names)
        }
        _ => return Err("name exactly one of seat, device or selector".into()),
    };
    if names.is_empty() {
        return Err(format!("{what} gives no Device"));
    }
    let mut on = Vec::new();
    for name in &names {
        let device = store.get(&format!("Device/{name}"));
        let device = device.ok_or(format!("there is no Device {name}"))?;
        if device.metadata.labels.contains_key(crate::devices::ABSENT) {
            return Err(format!("Device {name} is absent: its hardware is gone from its node"));
        }
        // (A seat's claim is checked against the Seat's label; a Device of it that has its own label
        // must be given too, and one without follows the Seat's.)
        if (claim.seat.is_none() || device.metadata.labels.contains_key(NAMESPACES)) && !given(device, namespace) {
            return Err(format!(
                "Device {name} is not given to namespace {namespace} (its {NAMESPACES} label)"
            ));
        }
        let spec: DeviceSpec =
            serde_json::from_value(device.spec.clone()).map_err(|e| format!("Device {name}: {e}"))?;
        on.push((spec.node, name.clone()));
    }
    // A selector over Devices on several nodes takes those of the lowest-named: one like them
    // plugged in on another node does not break it (kith.dev/node names the node). It can
    // move to a lower-named node that gets one.
    if what == "the selector" {
        let lowest = on.iter().map(|(node, _)| node.clone()).min();
        on.retain(|(node, _)| Some(node) == lowest.as_ref());
    }
    let nodes: BTreeSet<&str> = on.iter().map(|(node, _)| node.as_str()).collect();
    if nodes.len() > 1 {
        return Err(format!("{what} matches devices on nodes {}", list(&nodes)));
    }
    let mut devices: Vec<String> = on.iter().map(|(_, name)| name.clone()).collect();
    devices.sort();
    devices.dedup();
    let client = claim.access == Some(Access::Client);
    Ok(Held {
        node: list(&nodes),
        devices,
        seat: claim.seat.clone().map(|seat| (seat, client)),
        shares: BTreeMap::new(),
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
/// first by key. A claim's `holder` is granted the claim's Devices ahead of those: it takes them
/// from a recorded holder of its own namespace, and waits behind any other, and it gets nothing
/// else for being named. A workload holds all its claims or none, so two that want each other's
/// never wait for ever.
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
            let namespace = key.split('/').nth(1).unwrap_or_default().to_string();
            let holder = spec
                .as_ref()
                .ok()
                .filter(|spec| !matches!(spec.access, Some(Access::Shared | Access::Client)))
                .and_then(|spec| holder_key(&key, spec.holder.as_deref()?));
            let found = spec
                .map_err(|e| e.to_string())
                .and_then(|spec| resolve_one(store, &namespace, &spec));
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
    // Per Device: the workloads the statuses of the claims that name it record as holding it.
    let mut recorded_on: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (claim, (holders, _)) in &kept {
        let Some(Ok(held)) = known.get(claim).map(|known| &known.found) else {
            continue;
        };
        for device in &held.devices {
            recorded_on
                .entry(device.as_str())
                .or_default()
                .extend(holders.iter().map(String::as_str));
        }
    }
    // The grants: a claim's holder takes the claim's Devices ahead of the others, and so holds them
    // while it is admitted. It is not granted a Device a recorded holder of another namespace holds,
    // nor one another grant has. Granted in key order, so that two of one Device are the same
    // every time. ponytail: a grant its workload cannot be admitted with is dropped and the whole
    // resolve run again: at most one round per grant, so a few. Upgrade if claims number in the hundreds.
    let mut grants: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut ordered = wanting.clone();
    ordered.sort();
    for (key, namespace, names) in &ordered {
        for name in names {
            let claim = format!("DeviceClaim/{namespace}/{name}");
            let Some(known) = known.get(&claim) else { continue };
            let Ok(held) = &known.found else { continue };
            if known.shared || known.holder.as_ref() != Some(key) || matches!(held.seat, Some((_, true))) {
                continue;
            }
            let free = held.devices.iter().all(|device| {
                !grants.contains_key(device)
                    && recorded_on
                        .get(device.as_str())
                        .is_none_or(|who| who.iter().all(|who| who.split('/').nth(1) == Some(namespace.as_str())))
            });
            if free {
                for device in &held.devices {
                    grants.insert(device.clone(), (key.clone(), claim.clone()));
                }
            }
        }
    }
    // (Those with a client claim after the others: a client asks who holds its seat.)
    let client = |namespace: &str, names: &[String]| {
        let of = |name: &String| known.get(&format!("DeviceClaim/{namespace}/{name}"));
        let is = |known: &Known| matches!(&known.found, Ok(held) if matches!(held.seat, Some((_, true))));
        names.iter().filter_map(of).any(is)
    };
    wanting.sort_by_key(|(key, namespace, names)| {
        (!recorded.contains(key.as_str()), client(namespace, names), key.clone())
    });
    let (mut claims, mut holders, asked) = 'rounds: loop {
        // The seats that are held, and the namespaces of who holds each: its sessions'.
        let mut sessions: BTreeSet<(String, String)> = BTreeSet::new();
        // Per Device: (claim key, holder, exclusively) for each way it is held.
        let mut taken: BTreeMap<String, Vec<(String, String, bool)>> = BTreeMap::new();
        for (device, (workload, claim)) in &grants {
            taken
                .entry(device.clone())
                .or_default()
                .push((claim.clone(), workload.clone(), true));
        }
        let mut holders: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        // Per Device: the vram bytes its admitted shares ask for.
        let mut asked: BTreeMap<String, u64> = BTreeMap::new();
        let mut claims = Claims::default();
        for (key, namespace, names) in wanting.clone() {
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
                    shares: own.clone(),
                })
            })();
            // A granted workload that cannot be admitted gives its grant back, and the round is run again.
            if outcome.is_err() && grants.values().any(|(granted, _)| *granted == key) {
                grants.retain(|_, (granted, _)| *granted != key);
                continue 'rounds;
            }
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
        break 'rounds (claims, holders, asked);
    };
    for (claim, Known { share, found, .. }) in known {
        let status = match found {
            Ok(held) => {
                let holding = holders.remove(&claim).unwrap_or_default();
                // What each Device counts of a share: the sum of all the admitted ones, against its vram.
                let counts = share.map(|_| {
                    let counts = held.devices.iter().map(|device| {
                        let counted = match vram_of(store, device) {
                            Some(of) => {
                                let asked = asked.get(device).copied().unwrap_or(0);
                                json!({ "counted": true, "asked": asked, "of": of, "enforced": dmem_of(store, device).is_some() })
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

/// Whether `p` names something under /dev: `/dev/` and then one or more plain names, none
/// empty, `.` or `..` (`/dev`, `/dev/`, `/dev//x`, `/dev/./x` and `//dev/x` are all refused).
fn in_dev(p: &str) -> bool {
    let Some(rest) = p.strip_prefix("/dev/") else {
        return false;
    };
    rest.split('/').all(|c| !matches!(c, "" | "." | ".."))
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
        let (mut paths, mut classes) = (BTreeSet::new(), Vec::new());
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
            // The store is not trusted for a path: one outside /dev, or with a `..`, grants nothing.
            if !spec.path.iter().chain(&spec.nodes).all(|p| in_dev(p)) {
                continue;
            }
            classes.push((name.clone(), spec.class.clone()));
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
        // (A share is a ceiling where the kernel keeps one: on the Device's dmem region.)
        let dmem = held
            .shares
            .iter()
            .filter_map(|(name, bytes)| Some((dmem_of(store, name)?, *bytes)));
        let dmem = dmem.collect();
        let (devices, seat) = (paths.into_iter().collect(), held.seat);
        granted.insert(
            key,
            Granted {
                devices,
                seat,
                classes,
                dmem,
            },
        );
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
metadata: { name: a-camera-video0, labels: { class: camera, kith.dev/node: a, kith.dev/namespaces: default } }
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
metadata: { name: a-seat0, labels: { kith.dev/namespaces: 'default, other' } }
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

    fn in_namespace(kind: &str, name: &str, namespace: &str, spec: &str) -> String {
        format!(
            "---\napiVersion: kith.dev/v1\nkind: {kind}\nmetadata: {{ name: {name}, namespace: {namespace} }}\nspec: {spec}\n"
        )
    }

    /// What a Workload `w` of `namespace` gets from one DeviceClaim `c` of `spec`, over the hardware and `extra`.
    fn claimed(extra: &str, namespace: &str, spec: &str) -> Result<(String, Vec<String>), String> {
        let workload = "{ template: { containers: [{ name: run, image: img }], deviceClaims: [c] } }";
        let source = format!(
            "{extra}{}{}",
            in_namespace("DeviceClaim", "c", namespace, spec),
            in_namespace("Workload", "w", namespace, workload)
        );
        let mut store = store(&source);
        let claims = settle(&mut store);
        held(&claims, &format!("Workload/{namespace}/w"))
    }

    /// Unlabelled hardware on `b` that is kith-system's alone (every class but a GPU), and an unlabelled Seat.
    const OPEN: &str = "
apiVersion: kith.dev/v1
kind: Device
metadata: { name: b-keyboard, labels: { class: input, kith.dev/node: b } }
spec: { node: b, class: input }
---
apiVersion: kith.dev/v1
kind: Device
metadata: { name: b-speaker, labels: { class: audio, kith.dev/node: b } }
spec: { node: b, class: audio }
---
apiVersion: kith.dev/v1
kind: Device
metadata: { name: b-usb0, labels: { class: usb, kith.dev/node: b } }
spec: { node: b, class: usb }
---
apiVersion: kith.dev/v1
kind: Device
metadata: { name: b-camera0, labels: { class: camera, kith.dev/node: b } }
spec: { node: b, class: camera, path: /dev/video1 }
---
apiVersion: kith.dev/v1
kind: Seat
metadata: { name: b-seat0 }
spec: { node: b, devices: [b-keyboard] }
";

    #[test]
    fn unlabelled_devices_and_seats_are_kith_systems_but_a_gpu_is_anyones() {
        let refused = [
            ("{ device: b-keyboard }", "Device b-keyboard"),
            ("{ device: b-speaker }", "Device b-speaker"),
            ("{ device: b-usb0 }", "Device b-usb0"),
            ("{ device: b-camera0 }", "Device b-camera0"),
            ("{ seat: b-seat0 }", "Seat b-seat0"),
            ("{ seat: b-seat0, access: client }", "Seat b-seat0"),
        ];
        for (spec, what) in refused {
            let err = claimed(OPEN, "ops", spec).unwrap_err();
            assert!(
                err.contains(&format!("{what} is not given to namespace ops")),
                "{spec}: {err}"
            );
        }
        assert!(claimed(OPEN, "kith-system", "{ device: b-keyboard }").is_ok());
        assert!(claimed(OPEN, "kith-system", "{ seat: b-seat0 }").is_ok());
        assert!(
            claimed(OPEN, "ops", "{ device: b-gpu-card0 }").is_ok(),
            "an unlabelled GPU is open"
        );
        assert!(
            claimed(OPEN, "ops", "{ device: a-gpu-card0 }").is_ok(),
            "an unlabelled GPU is open"
        );
    }

    #[test]
    fn a_label_names_who_may_claim_and_taking_it_away_refuses_at_the_next_resolve() {
        let keyboard = |labels: &str| {
            format!(
                "---\napiVersion: kith.dev/v1\nkind: Device\nmetadata: {{ name: b-keyboard, labels: {{ class: input, kith.dev/node: b{labels} }} }}\nspec: {{ node: b, class: input }}\n"
            )
        };
        let labelled = keyboard(", kith.dev/namespaces: 'ops, dev'");
        assert!(
            claimed(&labelled, "ops", "{ device: b-keyboard }").is_ok(),
            "listed, spaces trimmed"
        );
        assert!(claimed(&labelled, "dev", "{ device: b-keyboard }").is_ok(), "listed");
        let err = claimed(&labelled, "default", "{ device: b-keyboard }").unwrap_err();
        assert!(
            err.contains("Device b-keyboard is not given to namespace default"),
            "{err}"
        );
        let claim = in_namespace("DeviceClaim", "c", "ops", "{ device: b-keyboard }");
        let workload = "{ template: { containers: [{ name: run, image: img }], deviceClaims: [c] } }";
        let source = format!("{labelled}{claim}{}", in_namespace("Workload", "w", "ops", workload));
        let mut store = store(&source);
        assert!(settle(&mut store).owners["Workload/ops/w"].is_ok());
        store.delete("Device/b-keyboard").unwrap();
        let bare = Resource::from_source(&keyboard("")).unwrap().remove(0).unwrap();
        store.apply(bare).unwrap();
        let err = settle(&mut store).owners["Workload/ops/w"].clone().unwrap_err();
        assert!(err.contains("Device b-keyboard is not given to namespace ops"), "{err}");
    }

    #[test]
    fn a_seat_is_given_by_its_own_label_and_not_by_its_devices() {
        // a-seat0 is labelled for `default` and `other`; its display is unlabelled, and that does not matter to a seat.
        assert!(claimed(OPEN, "default", "{ seat: a-seat0 }").is_ok());
        let err = claimed(OPEN, "ops", "{ seat: a-seat0 }").unwrap_err();
        assert!(err.contains("Seat a-seat0 is not given to namespace ops"), "{err}");
        let err = claimed(OPEN, "ops", "{ seat: a-seat0, access: client }").unwrap_err();
        assert!(err.contains("Seat a-seat0 is not given to namespace ops"), "{err}");
    }

    #[test]
    fn a_selector_keeps_the_devices_given_to_its_namespace_and_names_no_other() {
        assert!(claimed(OPEN, "default", "{ selector: { kith.dev/node: a, class: camera } }").is_ok());
        // a-camera-video0 is given to default alone, and b-camera0 to nobody: neither is named for ops.
        let err = claimed(OPEN, "ops", "{ selector: { kith.dev/node: a, class: camera } }").unwrap_err();
        assert!(
            err.contains("the selector gives no Device given to namespace ops"),
            "{err}"
        );
        let err = claimed(OPEN, "ops", "{ selector: { class: camera } }").unwrap_err();
        assert!(
            err.contains("the selector gives no Device given to namespace ops"),
            "{err}"
        );
        assert!(!err.contains("camera"), "{err}");
        // Of a node's Devices, the one open GPU is kept; the keyboard, speaker and the rest are skipped.
        assert_eq!(
            claimed(OPEN, "ops", "{ selector: { kith.dev/node: b } }"),
            Ok(("b".into(), vec!["b-gpu-card0".into()]))
        );
        assert_eq!(
            claimed(OPEN, "ops", "{ selector: { kith.dev/node: a } }"),
            Ok(("a".into(), vec!["a-gpu-card0".into()]))
        );
    }

    #[test]
    fn a_selector_with_no_node_claims_on_the_lowest_node_that_matches() {
        // A GPU on a and one on b: the selector takes a's, so one like it plugged in on another
        // node does not break the claim (kith.dev/node names the node).
        assert_eq!(
            claimed(OPEN, "ops", "{ selector: { class: gpu } }"),
            Ok(("a".into(), vec!["a-gpu-card0".into()]))
        );
    }

    /// A camera kept on `a` after it was unplugged (discovery marks it absent), one like it on `b`.
    const ABSENT: &str = "
apiVersion: kith.dev/v1
kind: Device
metadata: { name: a-camera-video1, labels: { model: c920, kith.dev/node: a, kith.dev/namespaces: default, kith.dev/absent: 'true' } }
spec: { node: a, class: camera, path: /dev/video1 }
---
apiVersion: kith.dev/v1
kind: Device
metadata: { name: b-camera-video0, labels: { model: c920, kith.dev/node: b, kith.dev/namespaces: default } }
spec: { node: b, class: camera, path: /dev/video0 }
";

    #[test]
    fn an_absent_device_is_refused_and_a_selector_passes_over_it() {
        // Named, it is refused: its holder would get a /dev path that is not there.
        let err = claimed(ABSENT, "default", "{ device: a-camera-video1 }").unwrap_err();
        assert!(err.contains("Device a-camera-video1 is absent"), "{err}");
        // A selector takes the one that is there, though the absent one is on the lower node.
        assert_eq!(
            claimed(ABSENT, "default", "{ selector: { model: c920 } }"),
            Ok(("b".into(), vec!["b-camera-video0".into()]))
        );
    }

    /// A GPU labelled for `dev`, and an unlabelled USB port, on `b`. Seat `b-seat1` (for `ops` and
    /// `dev`) lists both; seat `b-seat2` (for `ops`) lists the unlabelled one.
    const LABELLED_SEATS: &str = "
apiVersion: kith.dev/v1
kind: Device
metadata: { name: b-gpu-card1, labels: { class: gpu, kith.dev/node: b, kith.dev/namespaces: dev } }
spec: { node: b, class: gpu, path: /dev/dri/card1 }
---
apiVersion: kith.dev/v1
kind: Device
metadata: { name: b-usb0, labels: { class: usb, kith.dev/node: b } }
spec: { node: b, class: usb }
---
apiVersion: kith.dev/v1
kind: Seat
metadata: { name: b-seat1, labels: { kith.dev/namespaces: 'ops, dev' } }
spec: { node: b, devices: [b-gpu-card1, b-usb0] }
---
apiVersion: kith.dev/v1
kind: Seat
metadata: { name: b-seat2, labels: { kith.dev/namespaces: ops } }
spec: { node: b, devices: [b-usb0] }
";

    #[test]
    fn a_seat_claim_is_refused_for_a_device_of_it_labelled_for_others() {
        let err = claimed(LABELLED_SEATS, "ops", "{ seat: b-seat1 }").unwrap_err();
        assert!(
            err.contains("Device b-gpu-card1 is not given to namespace ops"),
            "{err}"
        );
        let err = claimed(LABELLED_SEATS, "ops", "{ seat: b-seat1, access: client }").unwrap_err();
        assert!(
            err.contains("Device b-gpu-card1 is not given to namespace ops"),
            "{err}"
        );
        assert!(
            claimed(LABELLED_SEATS, "dev", "{ seat: b-seat1 }").is_ok(),
            "the Device lists dev"
        );
    }

    #[test]
    fn an_unlabelled_device_of_a_seat_follows_the_seats_label() {
        assert!(
            claimed(LABELLED_SEATS, "ops", "{ seat: b-seat2 }").is_ok(),
            "b-usb0 has no label of its own"
        );
        let err = claimed(LABELLED_SEATS, "dev", "{ seat: b-seat2 }").unwrap_err();
        assert!(err.contains("Seat b-seat2 is not given to namespace dev"), "{err}");
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
        assert!(claims.owners["Workload/default/w1"].is_ok());
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
        let said = status("none").unwrap();
        assert!(
            said["message"]
                .as_str()
                .unwrap()
                .contains("the selector gives no Device"),
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

    /// A sound card's Device lists its playback PCM nodes (a control node alone plays nothing):
    /// a claim of it gives the container those with the control node.
    #[test]
    fn a_claim_of_an_audio_device_grants_its_pcm_nodes() {
        let audio = "---\napiVersion: kith.dev/v1\nkind: Device\nmetadata: { name: a-audio-card1 }\n\
                     spec: { node: a, class: audio, path: /dev/snd/controlC1, nodes: [/dev/snd/pcmC1D3p, /dev/snd/pcmC1D7p] }\n";
        // (A seat with the card, as a TV's seat has its speakers, given to the namespace.)
        let seat = "---\napiVersion: kith.dev/v1\nkind: Seat\nmetadata: { name: a-seat1, labels: { kith.dev/namespaces: default } }\n\
                    spec: { node: a, devices: [a-audio-card1] }\n";
        let source = [
            audio,
            seat,
            &claim("tv", "{ seat: a-seat1 }"),
            &workload("player", "[tv]"),
        ]
        .concat();
        let empty = sys("audio-pcm");
        std::fs::remove_dir_all(empty.join("class")).unwrap();
        assert_eq!(
            granted(&store(&source), "a", &empty)["Workload/default/player"].devices,
            ["/dev/snd/controlC1", "/dev/snd/pcmC1D3p", "/dev/snd/pcmC1D7p"].map(PathBuf::from)
        );
        // The card on its own, claimed by name, gives the same to a namespace its label names.
        let source = source.replace("name: a-audio-card1 }", "name: a-audio-card1, labels: { kith.dev/namespaces: default } }");
        let source = source.replace("{ seat: a-seat1 }", "{ device: a-audio-card1 }");
        assert_eq!(
            granted(&store(&source), "a", &empty)["Workload/default/player"].devices.len(),
            3
        );
        let _ = std::fs::remove_dir_all(&empty);
    }

    /// A Device the store holds with a path or node outside /dev, or with a `..`, grants nothing.
    #[test]
    fn forged_device_outside_dev_grants_nothing() {
        let empty = sys("forged");
        std::fs::remove_dir_all(empty.join("class")).unwrap();
        for spec in [
            "{ node: a, class: gpu, path: /etc/shadow }",
            "{ node: a, class: gpu, path: /dev/../etc/shadow }",
            "{ node: a, class: gpu, path: dev/dri/card1 }",
            "{ node: a, class: gpu, path: /dev/dri/card1, nodes: [/etc/shadow] }",
            "{ node: a, class: gpu, path: /dev/dri/card1, nodes: [/dev/../etc/passwd] }",
            "{ node: a, class: gpu, nodes: [/proc/kcore] }",
            "{ node: a, class: gpu, path: /dev }",
            "{ node: a, class: gpu, path: /dev/ }",
            "{ node: a, class: gpu, path: /dev/./x }",
            "{ node: a, class: gpu, path: /dev//x }",
            "{ node: a, class: gpu, path: //dev/x }",
            "{ node: a, class: gpu, path: /dev/dri/card1, nodes: [''] }",
        ] {
            let forged = format!(
                "---\napiVersion: kith.dev/v1\nkind: Device\nmetadata: {{ name: a-gpu-card1 }}\nspec: {spec}\n"
            );
            let source = [
                forged,
                claim("cuda", "{ device: a-gpu-card1 }"),
                workload("train", "[cuda]"),
            ]
            .concat();
            let on_a = granted(&self::store(&source), "a", &empty);
            assert!(on_a["Workload/default/train"].devices.is_empty(), "{spec}");
            assert!(on_a["Workload/default/train"].classes.is_empty(), "{spec}");
        }
        // Real /dev names still pass.
        let ok = "---\napiVersion: kith.dev/v1\nkind: Device\nmetadata: { name: a-gpu-card1 }\n\
                  spec: { node: a, class: gpu, nodes: [/dev/bus/usb/001/002, /dev/input/event3, /dev/nvidia-uvm] }\n";
        let source = [
            ok.to_string(),
            claim("cuda", "{ device: a-gpu-card1 }"),
            workload("train", "[cuda]"),
        ]
        .concat();
        assert_eq!(
            granted(&self::store(&source), "a", &empty)["Workload/default/train"].devices,
            ["/dev/bus/usb/001/002", "/dev/input/event3", "/dev/nvidia-uvm"].map(PathBuf::from)
        );
        // A client of a seat draws on the seat's GPUs (whole = false): a forged one, with a card
        // name that finds a real render node in /sys, still grants nothing.
        let root = sys("forged-client");
        let client = [
            claim("desk", "{ seat: a-seat0 }"),
            claim("apps", "{ seat: a-seat0, access: client }"),
            workload("session", "[desk]"),
            workload("app", "[apps]"),
        ]
        .concat();
        let hardware = |gpu: &str| {
            let hardware = HARDWARE.replace("spec: { node: a, class: gpu, path: /dev/dri/card0 }", gpu);
            let mut store = Store::default();
            for resource in Resource::from_source(&format!("{hardware}---\n{client}")).unwrap() {
                store.apply(resource.unwrap()).unwrap();
            }
            store
        };
        let real = granted(
            &hardware("spec: { node: a, class: gpu, path: /dev/dri/card0 }"),
            "a",
            &root,
        );
        assert_eq!(
            real["Workload/default/app"].devices,
            [PathBuf::from("/dev/dri/renderD128")]
        );
        let forged = granted(&hardware("spec: { node: a, class: gpu, path: /etc/card0 }"), "a", &root);
        assert!(forged["Workload/default/app"].devices.is_empty());
        assert!(forged["Workload/default/app"].classes.is_empty());
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
            json!({ "a-vram": { "counted": true, "asked": 1073741824, "of": 1073741824, "enforced": false } })
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

    /// A share of a Device whose driver gives the dmem cgroup a region is that region's ceiling in
    /// the holder's cgroup (the sum of its shares there), and the status says it is enforced.
    #[test]
    fn a_share_is_the_dmem_ceiling_of_a_device_with_a_region() {
        let source = [
            card("a-held", ", vram: '1073741824', dmem: 'drm/0000:04:00.0/vram'"),
            card("a-bare", ", vram: '1073741824'"),
            claim("held", "{ device: a-held, access: shared, share: { vram: 256Mi } }"),
            claim("more", "{ device: a-held, access: shared, share: { vram: 256Mi } }"),
            claim("bare", "{ device: a-bare, access: shared, share: { vram: 256Mi } }"),
            workload("w", "[held, more, bare]"),
        ]
        .concat();
        let mut store = store(&source);
        settle(&mut store);
        let none = std::env::temp_dir().join("kith-claims-dmem-none");
        let dmem = &granted(&store, "a", &none)["Workload/default/w"].dmem;
        assert_eq!(*dmem, [("drm/0000:04:00.0/vram".to_string(), 536870912)]);
        let status = |name: &str| {
            store
                .get(&format!("DeviceClaim/default/{name}"))
                .unwrap()
                .status
                .clone()
                .unwrap()
        };
        assert_eq!(status("held")["share"]["a-held"]["enforced"], json!(true));
        assert_eq!(status("bare")["share"]["a-bare"]["enforced"], json!(false));
        // A region named by hand with a second line in it is none.
        let odd = card(
            "a-held",
            ", vram: '1073741824', dmem: \"drm/x/vram 1\\nnvidia/y/vidmem\"",
        );
        let mut store = self::store(
            &[
                odd,
                claim("held", "{ device: a-held, access: shared, share: { vram: 256Mi } }"),
                workload("w", "[held]"),
            ]
            .concat(),
        );
        settle(&mut store);
        assert!(granted(&store, "a", &none)["Workload/default/w"].dmem.is_empty());
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
        let refused = Resource::from_source(&claim(
            "x",
            "{ device: a-gpu-card0, access: shared, holder: Workload/one }",
        ))
        .unwrap()
        .remove(0)
        .unwrap_err()
        .to_string();
        assert!(refused.contains("for an exclusive claim"), "{refused}");
    }

    fn add(store: &mut Store, source: &str) {
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
    }

    /// What `claim` or `workload` writes, in another namespace.
    fn within(namespace: &str, source: String) -> String {
        source.replace(
            "metadata: { name:",
            &format!("metadata: {{ namespace: {namespace}, name:"),
        )
    }

    /// Names `holder` on the claim already in the store, as `kith switch` does.
    fn name_holder(store: &mut Store, claim: &str, holder: &str) {
        let mut named = store.get(claim).unwrap().clone();
        named.metadata.revision = None;
        named.spec["holder"] = holder.into();
        store.apply(named).unwrap();
    }

    #[test]
    fn a_holder_takes_a_device_only_from_a_recorded_holder_of_its_own_namespace() {
        let mut store = store(&within(
            "other",
            [claim("gpu", "{ device: a-gpu-card0 }"), workload("one", "[gpu]")].concat(),
        ));
        assert!(settle(&mut store).owners["Workload/other/one"].is_ok());
        let source = within(
            "default",
            [
                claim("gpu", "{ device: a-gpu-card0, holder: Workload/two }"),
                workload("two", "[gpu]"),
            ]
            .concat(),
        );
        add(&mut store, &source);
        let claims = settle(&mut store);
        assert!(claims.owners["Workload/other/one"].is_ok());
        assert!(
            claims.owners["Workload/default/two"]
                .as_ref()
                .is_err_and(|why| why.contains("held by Workload/other/one"))
        );
    }

    #[test]
    fn a_workload_named_holder_by_a_claim_it_does_not_list_gains_nothing() {
        let source = [
            claim("gpu", "{ device: a-gpu-card0 }"),
            claim("spare", "{ device: a-gpu-card0 }"),
            workload("one", "[gpu]"),
            workload("two", "[spare]"),
        ]
        .concat();
        let mut store = store(&source);
        let claims = settle(&mut store);
        assert!(claims.owners["Workload/default/one"].is_ok());
        assert!(claims.owners["Workload/default/two"].is_err());
        name_holder(&mut store, "DeviceClaim/default/gpu", "Workload/two");
        let claims = settle(&mut store);
        assert!(claims.owners["Workload/default/one"].is_ok());
        assert!(claims.owners["Workload/default/two"].is_err());
    }

    #[test]
    fn a_holder_gets_no_priority_on_the_devices_of_another_claim_it_lists() {
        let mut store = store(&[claim("lens", "{ device: a-camera-video0 }"), workload("eye", "[lens]")].concat());
        assert!(settle(&mut store).owners["Workload/default/eye"].is_ok());
        let source = [
            claim("gpu", "{ device: a-gpu-card0, holder: Workload/two }"),
            claim("mon", "{ device: a-camera-video0 }"),
            workload("two", "[gpu, mon]"),
        ]
        .concat();
        add(&mut store, &source);
        let claims = settle(&mut store);
        assert!(claims.owners["Workload/default/eye"].is_ok());
        assert!(
            claims.owners["Workload/default/two"]
                .as_ref()
                .is_err_and(|why| why.contains("a-camera-video0"))
        );
    }

    #[test]
    fn two_claims_that_name_a_holder_each_for_one_device_settle_the_same_way_twice() {
        let source = [
            claim("gpu", "{ device: a-gpu-card0, holder: Workload/one }"),
            claim("spare", "{ device: a-gpu-card0, holder: Workload/two }"),
            workload("one", "[gpu]"),
            workload("two", "[spare]"),
        ]
        .concat();
        let mut store = store(&source);
        let first = settle(&mut store);
        let second = settle(&mut store);
        for key in ["Workload/default/one", "Workload/default/two"] {
            assert_eq!(held(&first, key), held(&second, key), "{key}");
        }
        assert!(first.owners["Workload/default/one"].is_ok());
        assert!(first.owners["Workload/default/two"].is_err());
    }
}
