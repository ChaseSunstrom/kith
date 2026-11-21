//! What a `Seat` gives whatever holds it, and asks of everything else: its `reserve` comes off
//! its node for every other workload, the holder's units get it as a guarantee in their cgroup,
//! and a workload that says `yieldTo` is held back while the seat is in a state it names. The
//! node says what a held seat is doing (`watch`: fullscreen while its sound card plays, active for
//! `ACTIVE_FOR` after its inputs are touched, idle otherwise); a session may say it better
//! (`POST /v1/seats/NAME/activity`) and wins for `EXPLICIT_FOR`.
//
// ponytail: a seat's reserve is taken off its node whether or not anything holds the seat (the
// screen is there; a session may start any moment), and workloads already placed are not moved.
// Every unit of a holder gets the whole memory guarantee (not a share of it). A session that
// hangs after a POST of fullscreen holds the others back for `EXPLICIT_FOR`, then `watch` judges
// again; on a seat with no sound card or input to look at it stays until the session goes: a
// heartbeat if that bites.
// `watch` polls every `TICK` (a few small files; inotify if that is ever felt), and a session
// that grabs its inputs (EVIOCGRAB) hides them from it: only sound counts then.

use crate::cluster::refuse;
use crate::{Shared, access::Caller};
use axum::extract::{Path as Named, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use kith_api::kinds::{Access, Activity, DeviceClaimSpec, DeviceClass, DeviceSpec, SeatSpec, Template, YieldTo};
use kith_api::store::Store;
use kith_sched::Amount;
use kith_store::Command;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

/// What a yielding unit may use of one CPU while the seat is busy, in thousandths: enough to
/// stay alive and answer a probe, too little to be felt by a game.
pub const YIELD_MILLIS: u64 = 50;

/// A seat as read: where it is and what it keeps for its holder.
fn seat(store: &Store, name: &str) -> Option<SeatSpec> {
    serde_json::from_value(store.get(&format!("Seat/{name}"))?.spec.clone()).ok()
}

/// The seats each workload holds (its key): those its `DeviceClaim`s name, once the claims come
/// to a node (a holder that waits for the seat holds nothing yet).
fn holders(store: &Store) -> BTreeMap<String, Vec<String>> {
    let mut found = BTreeMap::new();
    for (key, outcome) in crate::claims::resolve(store).owners {
        let (Ok(_), Some(owner)) = (outcome, store.get(&key)) else {
            continue;
        };
        let namespace = owner.metadata.namespace.as_deref().unwrap_or_default();
        let names = owner.spec["template"]["deviceClaims"].as_array().into_iter().flatten();
        let seats = names.filter_map(|name| {
            let claim = store.get(&format!("DeviceClaim/{namespace}/{}", name.as_str()?))?;
            let claim = serde_json::from_value::<DeviceClaimSpec>(claim.spec.clone()).ok()?;
            // (A client of a seat holds none of it.)
            claim.seat.filter(|_| claim.access != Some(Access::Client))
        });
        let seats: Vec<String> = seats.collect();
        if !seats.is_empty() {
            found.insert(key, seats);
        }
    }
    found
}

/// For the scheduler: what to take off each node (its name) for its seats, and what a
/// holder (its key) has of that already, so it is not asked to fit twice.
pub fn reserves(store: &Store) -> (BTreeMap<String, Amount>, BTreeMap<String, Amount>) {
    let add = |sum: &mut Amount, more: Amount| {
        sum.cpu += more.cpu;
        sum.memory += more.memory;
    };
    let reserve = |spec: &SeatSpec| spec.reserve.as_ref().map(Amount::of_resources);
    let mut nodes: BTreeMap<String, Amount> = BTreeMap::new();
    for found in store.list(Some("Seat")) {
        let Ok(spec) = serde_json::from_value::<SeatSpec>(found.spec.clone()) else {
            continue;
        };
        if let Some(amount) = reserve(&spec) {
            add(nodes.entry(spec.node).or_default(), amount);
        }
    }
    // A reserve came off its node once, so it is one holder's, once: of several that share the
    // seat, the first by key (and the scheduler gives it to that one's first replica).
    let mut owners: BTreeMap<String, Amount> = BTreeMap::new();
    let mut given = std::collections::BTreeSet::new();
    for (key, seats) in holders(store) {
        for name in seats.into_iter().filter(|name| given.insert(name.clone())) {
            if let Some(amount) = seat(store, &name).as_ref().and_then(reserve) {
                add(owners.entry(key.clone()).or_default(), amount);
            }
        }
    }
    (nodes, owners)
}

/// Is a workload that says `yield_to` held back, the seat doing `activity`? (A seat that says
/// nothing is idle.)
pub fn held_back(yield_to: &YieldTo, activity: Option<&str>) -> bool {
    let now = match activity {
        Some("active") => Activity::Active,
        Some("fullscreen") => Activity::Fullscreen,
        _ => Activity::Idle,
    };
    yield_to.when.contains(&now)
}

/// A seat of node `me` that last said `active` or `fullscreen`: its name, and which (the first by
/// the first listed). A seat that says nothing, or idle, or is not on `me`, is not busy (as `held_back` reads it).
pub fn busy(store: &Store, me: &str) -> Option<(String, String)> {
    store.list(Some("Seat")).find_map(|found| {
        let says = found.status.as_ref()?["activity"].as_str()?;
        let on_me = seat(store, &found.metadata.name).is_some_and(|spec| spec.node == me);
        (on_me && matches!(says, "active" | "fullscreen")).then(|| (found.metadata.name.clone(), says.to_string()))
    })
}

/// What the cgroup of each unit of a workload on `me` should say: the memory it is guaranteed
/// (a holder of a seat of `me` with a reserve; 0 when the reserve names no memory) and whether
/// it is held back. Only workloads that hold such a seat or say `yieldTo` are in it.
pub fn tunes(store: &Store, me: &str) -> BTreeMap<String, (Option<u64>, bool)> {
    let mut tunes: BTreeMap<String, (Option<u64>, bool)> = BTreeMap::new();
    for (key, seats) in holders(store) {
        let here = seats.iter().filter_map(|name| seat(store, name));
        let reserves = here.filter(|spec| spec.node == me).filter_map(|spec| spec.reserve);
        let memory: Vec<u64> = reserves.map(|r| Amount::of_resources(&r).memory as u64).collect();
        if !memory.is_empty() {
            tunes.entry(key).or_default().0 = Some(memory.iter().sum());
        }
    }
    let owners = ["Workload", "NodeWorkload", "Job"]
        .into_iter()
        .flat_map(|kind| store.list(Some(kind)));
    for owner in owners {
        let template = serde_json::from_value::<Template>(owner.spec["template"].clone());
        let Some(yield_to) = template.ok().and_then(|template| template.yield_to) else {
            continue;
        };
        // (A seat of another node is not this node's business: nothing here is in its way.)
        let found = store.get(&format!("Seat/{}", yield_to.seat));
        let mine = seat(store, &yield_to.seat).is_some_and(|spec| spec.node == me);
        let activity = found.and_then(|seat| seat.status.as_ref()?["activity"].as_str());
        tunes.entry(owner.key()).or_default().1 = mine && held_back(&yield_to, activity);
    }
    tunes
}

/// A seat's status saying it does `activity` (none: saying nothing), the rest of it kept.
fn saying(seat: &kith_api::Resource, activity: Option<&str>) -> Option<Value> {
    let mut status = seat.status.clone().filter(Value::is_object).unwrap_or(json!({}));
    match activity {
        Some(activity) => status["activity"] = activity.into(),
        None => drop(status.as_object_mut().and_then(|status| status.remove("activity"))),
    }
    status
        .as_object()
        .is_some_and(|status| !status.is_empty())
        .then_some(status)
}

/// The seats that say what they do with nobody holding them: key, and its status without that.
/// (A session that went away while fullscreen would hold the others back for good. One that
/// spoke a moment before its claim came to a node says it again.)
pub fn writes(store: &Store) -> Vec<(String, Option<Value>)> {
    let held: Vec<String> = holders(store).into_values().flatten().collect();
    let stale = store.list(Some("Seat")).filter(|seat| {
        let says = seat.status.as_ref().is_some_and(|status| !status["activity"].is_null());
        says && !held.contains(&seat.metadata.name)
    });
    stale.map(|seat| (seat.key(), saying(seat, None))).collect()
}

/// How often a node looks at what its held seats do.
const TICK: std::time::Duration = std::time::Duration::from_secs(5);
/// How long a seat stays `active` after something of its inputs was touched.
const ACTIVE_FOR: u64 = 180;
/// How long a seat's activity that a POST set (not what this loop wrote) is left as it is.
const EXPLICIT_FOR: u64 = 600;

/// A held seat of this node, and what to look at to tell what it does.
struct Plan {
    seat: kith_api::Resource,
    /// Sound cards (`controlC{N}` of its audio devices).
    cards: Vec<u32>,
    /// Input device files.
    inputs: Vec<String>,
}

/// What the loop keeps of one seat between rounds.
#[derive(Default)]
struct Mark {
    /// What the store said when the loop last wrote or looked (outer `None`: not yet seen).
    wrote: Option<Option<String>>,
    /// An activity set from outside is left alone until then.
    hold_until: Option<u64>,
    touched: Option<u64>,
}

/// What the loop keeps between rounds: a mark per seat, and the open input files (only that
/// something came from them is ever kept, never what).
#[derive(Default)]
pub struct Memory {
    marks: BTreeMap<String, Mark>,
    inputs: BTreeMap<String, std::fs::File>,
    /// Input paths that were refused (and said so), so the reason is said once.
    refused: std::collections::BTreeSet<String>,
    /// Tests only: a regular file stands in for an input, so the device checks are skipped.
    #[cfg(test)]
    lax: bool,
}

/// The `N` of `/dev/input/eventN`, and nothing else (a path in the store is not trusted).
fn event(path: &str) -> Option<&str> {
    path.strip_prefix("/dev/input/event")
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Is this open file an evdev node (a character device of major 13)? Not a regular file, a
/// terminal, a watchdog or any other device.
fn is_evdev(file: &std::fs::File) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    file.metadata()
        .is_ok_and(|meta| meta.file_type().is_char_device() && nix::sys::stat::major(meta.rdev()) == 13)
}

impl Memory {
    #[cfg(test)]
    fn stand_in() -> Memory {
        Memory {
            lax: true,
            ..Memory::default()
        }
    }

    /// The writes did not land: forget they were made, so they are not taken for a POST.
    fn failed(&mut self, writes: &[(String, Option<Value>)]) {
        for (key, _) in writes {
            if let Some(mark) = self.marks.get_mut(key.trim_start_matches("Seat/")) {
                mark.wrote = None;
            }
        }
    }

    /// Whether anything came from the input file `path` since the last look.
    fn touched(&mut self, path: &str) -> bool {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        if self.refused.contains(path) {
            return false;
        }
        if !self.inputs.contains_key(path) {
            let flags = nix::fcntl::OFlag::O_NONBLOCK
                | nix::fcntl::OFlag::O_CLOEXEC
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_NOCTTY;
            let opened = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(flags.bits())
                .open(path);
            let file = match opened {
                Ok(file) => file,
                // (Not there yet: looked for again next round. Any other failure, once.)
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
                Err(e) => {
                    if self.refused.insert(path.to_string()) {
                        eprintln!("kithd: seats: {path} cannot be opened: {e}");
                    }
                    return false;
                }
            };
            // (Opened without a wait, so a node that is not an input could not hold this up; and
            // what was opened is looked at, not what the name said: nothing else is ever read.)
            let real = std::fs::canonicalize(path).ok();
            let sound = real.as_deref() == Some(Path::new(path)) && is_evdev(&file);
            #[cfg(test)]
            let sound = sound || self.lax;
            if !sound {
                if self.refused.insert(path.to_string()) {
                    eprintln!("kithd: seats: {path} is not an input device of this node: not read");
                }
                return false;
            }
            self.inputs.insert(path.to_string(), file);
        }
        let (mut came, mut buf) = (false, [0u8; 4096]);
        // (A bounded drain: a device that never runs dry cannot hold the loop.)
        for _ in 0..64 {
            match self.inputs.get(path).map(|mut file| file.read(&mut buf)) {
                Some(Ok(n)) if n > 0 => came = true,
                Some(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Some(Err(_)) => drop(self.inputs.remove(path)),
                _ => break,
            }
        }
        came
    }
}

/// The held seats of `me` that have something to look at, each with the cards and inputs it has.
/// (The store is not trusted for a path: an input is only a `/dev/input/event<N>` under `dev`,
/// a card only a `/dev/snd/controlC<N>`, and only of a Device of this node. A seat with neither
/// is not judged: what a session said of it stays.)
fn plan(store: &Store, me: &str, dev: &Path) -> Vec<Plan> {
    let mine = |name: &str| seat(store, name).filter(|spec| spec.node == me);
    // (Before `holders`, which resolves every claim: a node with no seat has nothing to look at.)
    if !store
        .list(Some("Seat"))
        .any(|found| mine(&found.metadata.name).is_some())
    {
        return Vec::new();
    }
    let held: std::collections::BTreeSet<String> = holders(store).into_values().flatten().collect();
    let digits = |n: &str| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit());
    let mut plans = Vec::new();
    for name in held {
        let (Some(seat), Some(spec)) = (store.get(&format!("Seat/{name}")), mine(&name)) else {
            continue;
        };
        let mut plan = Plan {
            seat: seat.clone(),
            cards: vec![],
            inputs: vec![],
        };
        for device in &spec.devices {
            let found = store.get(&format!("Device/{device}"));
            let Some(device) = found.and_then(|d| serde_json::from_value::<DeviceSpec>(d.spec.clone()).ok()) else {
                continue;
            };
            if device.node != me {
                continue;
            }
            let path = device.path.unwrap_or_default();
            match device.class {
                DeviceClass::Audio => plan.cards.extend(
                    path.strip_prefix("/dev/snd/controlC")
                        .filter(|n| digits(n))
                        .and_then(|n| n.parse::<u32>().ok()),
                ),
                DeviceClass::Input => {
                    let found = event(&path).map(|n| dev.join(format!("input/event{n}")));
                    plan.inputs
                        .extend(found.map(|path| path.to_string_lossy().into_owned()));
                }
                _ => {}
            }
        }
        if !plan.cards.is_empty() || !plan.inputs.is_empty() {
            plans.push(plan);
        }
    }
    plans
}

/// Does any playback substream of card `card` run? (`proc` is `/proc/asound`; a capture one,
/// a mixer or a closed substream does not count.)
fn playing(proc: &Path, card: u32) -> bool {
    let pcms = std::fs::read_dir(proc.join(format!("card{card}")))
        .into_iter()
        .flatten()
        .flatten();
    let subs = pcms.filter(|pcm| {
        let name = pcm.file_name();
        name.to_string_lossy().starts_with("pcm") && name.to_string_lossy().ends_with('p')
    });
    let subs = subs.flat_map(|pcm| std::fs::read_dir(pcm.path()).into_iter().flatten().flatten());
    subs.filter(|sub| sub.file_name().to_string_lossy().starts_with("sub"))
        .any(|sub| std::fs::read_to_string(sub.path().join("status")).is_ok_and(|s| s.starts_with("state: RUNNING")))
}

/// What a seat does: `fullscreen` while its sound plays, `active` for `ACTIVE_FOR` after its
/// inputs were touched, `idle` otherwise.
fn judge(playing: bool, touched: Option<u64>, now: u64) -> &'static str {
    match touched {
        _ if playing => "fullscreen",
        // (`at` after `now`: the clock went back; a touch from the future is not a touch.)
        Some(at) if now >= at && now - at < ACTIVE_FOR => "active",
        _ => "idle",
    }
}

/// One look at the held seats at `now`: what to write (a seat's key and its new status), only
/// where the activity changes, and not where the store's activity is not what this loop last
/// wrote (a POST set it: that stays for `EXPLICIT_FOR`).
fn round(plans: &[Plan], proc: &Path, memory: &mut Memory, now: u64) -> Vec<(String, Option<Value>)> {
    let names: Vec<&str> = plans.iter().map(|plan| plan.seat.metadata.name.as_str()).collect();
    memory.marks.retain(|name, _| names.contains(&name.as_str()));
    let paths: Vec<&String> = plans.iter().flat_map(|plan| &plan.inputs).collect();
    memory.inputs.retain(|path, _| paths.contains(&path));
    memory.refused.retain(|path| paths.contains(&path));
    let mut writes = Vec::new();
    for plan in plans {
        let name = plan.seat.metadata.name.clone();
        // (Each one drained, not only until the first that was touched.)
        let came = plan.inputs.iter().map(|path| memory.touched(path)).collect::<Vec<_>>();
        let came = came.contains(&true);
        let mark = memory.marks.entry(name).or_default();
        mark.touched = if came { Some(now) } else { mark.touched };
        let says = plan.seat.status.as_ref().and_then(|status| status["activity"].as_str());
        let says = says.map(str::to_string);
        // (On first sight the store's value is taken as the loop's own.)
        let wrote = mark.wrote.take().unwrap_or_else(|| says.clone());
        mark.wrote = Some(says.clone());
        if wrote != says {
            mark.hold_until = Some(now + EXPLICIT_FOR);
        }
        match mark.hold_until {
            // (More than `EXPLICIT_FOR` ahead: the clock went back, so the hold is over.)
            Some(until) if now < until && until - now <= EXPLICIT_FOR => continue,
            _ => mark.hold_until = None,
        }
        let judged = judge(plan.cards.iter().any(|&card| playing(proc, card)), mark.touched, now);
        if says.as_deref().unwrap_or("idle") != judged {
            mark.wrote = Some(Some(judged.to_string()));
            writes.push((plan.seat.key(), saying(&plan.seat, Some(judged))));
        }
    }
    writes
}

/// The loop of a node: every `TICK`, what each held seat of it does, written to its status (a
/// node may write that of its own Seat, and only that).
pub async fn watch(shared: Arc<Shared>, mut stopping: tokio::sync::watch::Receiver<bool>) {
    // (Alone, in agent mode, a node has no name to find its seats by.)
    let Some(cluster) = &shared.cluster else { return };
    let me = cluster.me.name.as_str();
    let (mut memory, mut failing) = (Memory::default(), false);
    // (Seconds since this loop began: the wall clock can be stepped back, this cannot.)
    let began = std::time::Instant::now();
    loop {
        tokio::select! {
            () = tokio::time::sleep(TICK) => {}
            _ = stopping.changed() => break,
        }
        let plans = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            plan(&state.store, me, Path::new("/dev"))
        };
        let statuses = round(
            &plans,
            Path::new("/proc/asound"),
            &mut memory,
            began.elapsed().as_secs(),
        );
        if statuses.is_empty() {
            continue;
        }
        let sent = shared
            .submit(Command::Status {
                statuses: statuses.clone(),
            })
            .await;
        if let Err(e) = &sent {
            // (Once while it fails, not every tick.)
            if !failing {
                eprintln!("kithd: seats: saying what a seat does: {e}");
            }
            memory.failed(&statuses);
        }
        failing = sent.is_err();
    }
}

/// `POST /v1/seats/NAME/activity?state=active|idle|fullscreen`: the session says what the seat
/// is doing. For who may apply Seats (a session is given a certificate of such an Identity).
pub async fn activity(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Named(name): Named<String>,
    Query(asked): Query<BTreeMap<String, String>>,
) -> Response {
    let kind = |_: &_| vec![("Seat".to_string(), None)];
    if let Err(refused) = crate::api::permit(&shared, &caller, kith_api::kinds::Verb::Apply, kind) {
        return refused.into_response();
    }
    let state = asked.get("state").map(String::as_str).unwrap_or_default();
    let key = format!("Seat/{name}");
    let (known, status) = {
        let store = shared.store.lock().expect("a handler panicked holding the store");
        let seat = store.store.get(&key);
        (seat.is_some(), seat.and_then(|seat| saying(seat, Some(state))))
    };
    let done = async {
        if !["active", "idle", "fullscreen"].contains(&state) {
            return Err((StatusCode::BAD_REQUEST, "state=active, idle or fullscreen".to_string()));
        }
        if !known {
            return Err((StatusCode::NOT_FOUND, format!("there is no Seat {name}")));
        }
        let statuses = vec![(key.clone(), status)];
        let written = shared.submit(Command::Status { statuses }).await;
        written.map(drop).map_err(|e| (StatusCode::CONFLICT, e.to_string()))
    }
    .await;
    let said = done.as_ref().map(|_| ()).map_err(|(_, why)| why.clone());
    shared
        .audit
        .record(&caller, &format!("activity {state}"), vec![key], said);
    match done {
        Ok(()) => Json(json!({ "seat": name, "activity": state })).into_response(),
        Err((status, why)) => refuse(status, why).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_api::Resource;

    const SEATED: &str = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a }
spec: {}
---
apiVersion: kith.dev/v1
kind: Device
metadata: { name: a-gpu-card0 }
spec: { node: a, class: gpu, path: /dev/dri/card0 }
---
apiVersion: kith.dev/v1
kind: Seat
metadata: { name: a-seat0, labels: { kith.dev/namespaces: default } }
spec: { node: a, devices: [a-gpu-card0], reserve: { cpu: 2, memory: 4Gi } }
---
apiVersion: kith.dev/v1
kind: DeviceClaim
metadata: { name: desk }
spec: { seat: a-seat0 }
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: desktop }
spec: { template: { exec: [{ name: run, command: [sleep, inf] }], deviceClaims: [desk] } }
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: batch }
spec:
  template:
    exec: [{ name: run, command: [sleep, inf] }]
    yieldTo: { seat: a-seat0, when: [fullscreen] }
";

    fn store(source: &str) -> Store {
        let mut store = Store::default();
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        store
    }

    fn says(store: &mut Store, state: &str) {
        let statuses = vec![("Seat/a-seat0".to_string(), Some(json!({ "activity": state })))];
        kith_store::run(store, Command::Status { statuses }).unwrap();
    }

    #[test]
    fn seat_reserve_comes_off_the_node_and_is_the_holders_guarantee() {
        let store = store(SEATED);
        let (nodes, owners) = reserves(&store);
        let four = 4.0 * 1024.0 * 1024.0 * 1024.0;
        assert_eq!((nodes["a"].cpu, nodes["a"].memory), (2.0, four));
        assert_eq!(owners["Workload/default/desktop"].cpu, 2.0);
        assert!(!owners.contains_key("Workload/default/batch"));
        // Two that share the seat: the reserve came off the node once, and is one holder's.
        let shared = "---\napiVersion: kith.dev/v1\nkind: DeviceClaim\nmetadata: { name: desk }\nspec: { seat: a-seat0, access: shared }\n---\napiVersion: kith.dev/v1\nkind: Workload\nmetadata: { name: also }\nspec: { template: { exec: [{ name: run, command: [sleep, inf] }], deviceClaims: [desk] } }\n";
        let both = self::store(&format!("{SEATED}{shared}"));
        let (nodes, owners) = reserves(&both);
        assert_eq!((nodes["a"].cpu, owners.len()), (2.0, 1));
        assert_eq!(owners["Workload/default/also"].cpu, 2.0);
        // An app of the seat (a client) is not its holder: the reserve is the session's still.
        let app = "---\napiVersion: kith.dev/v1\nkind: DeviceClaim\nmetadata: { name: apps }\nspec: { seat: a-seat0, access: client }\n---\napiVersion: kith.dev/v1\nkind: Workload\nmetadata: { name: app }\nspec: { template: { exec: [{ name: run, command: [sleep, inf] }], deviceClaims: [apps] } }\n";
        let with_app = self::store(&format!("{SEATED}{app}"));
        let (nodes, owners) = reserves(&with_app);
        assert_eq!((nodes["a"].cpu, owners.len()), (2.0, 1));
        assert_eq!(owners["Workload/default/desktop"].cpu, 2.0);
        assert!(!tunes(&with_app, "a").contains_key("Workload/default/app"));
        // On its node the holder's units are guaranteed the memory; on another node nothing is said.
        assert_eq!(
            tunes(&store, "a")["Workload/default/desktop"],
            (Some(four as u64), false)
        );
        assert!(!tunes(&store, "b").contains_key("Workload/default/desktop"));
    }

    #[test]
    fn seat_activity_holds_back_who_yields_and_a_seat_nobody_holds_is_idle() {
        let mut store = store(SEATED);
        let batch = |store: &Store, node: &str| tunes(store, node)["Workload/default/batch"];
        // Nothing said is idle: not held back. Active is not one of its states either.
        assert_eq!(batch(&store, "a"), (None, false));
        assert_eq!(busy(&store, "a"), None);
        says(&mut store, "active");
        assert_eq!(batch(&store, "a"), (None, false));
        assert_eq!(busy(&store, "a"), Some(("a-seat0".into(), "active".into())));
        assert_eq!(busy(&store, "b"), None);
        says(&mut store, "idle");
        assert_eq!(busy(&store, "a"), None);
        says(&mut store, "fullscreen");
        assert_eq!(batch(&store, "a"), (None, true));
        assert_eq!(busy(&store, "a"), Some(("a-seat0".into(), "fullscreen".into())));
        // (A copy of it on another node is in nobody's way.)
        assert_eq!(batch(&store, "b"), (None, false));
        // Held, the seat keeps what it says; its last holder gone, it says nothing again.
        assert!(writes(&store).is_empty());
        store.delete("Workload/default/desktop").unwrap();
        let cleared = writes(&store);
        assert_eq!(cleared, [("Seat/a-seat0".to_string(), None)]);
        kith_store::run(&mut store, Command::Status { statuses: cleared }).unwrap();
        assert_eq!(batch(&store, "a"), (None, false));
        assert!(writes(&store).is_empty());
    }

    #[tokio::test]
    async fn seat_activity_is_for_who_may_apply_seats_and_is_audited() {
        let dir = std::env::temp_dir().join(format!("kithd-seat-activity-{}", std::process::id()));
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
        for resource in Resource::from_source(SEATED).unwrap() {
            let (resources, at) = (vec![resource.unwrap()], kith_api::store::now());
            shared.submit(Command::Apply { resources, at }).await.unwrap();
        }
        let ask = |caller: Caller, seat: &str, state: &str| {
            let asked = BTreeMap::from([("state".to_string(), state.to_string())]);
            activity(
                State(shared.clone()),
                Extension(caller),
                Named(seat.to_string()),
                Query(asked),
            )
        };
        let admin = || Caller::Admin;
        assert_eq!(ask(admin(), "a-seat0", "fullscreen").await.status(), StatusCode::OK);
        let said = |shared: &Shared| {
            let state = shared.store.lock().unwrap();
            state.store.get("Seat/a-seat0").unwrap().status.clone()
        };
        assert_eq!(said(&shared), Some(json!({ "activity": "fullscreen" })));
        assert_eq!(ask(admin(), "a-seat0", "loud").await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(ask(admin(), "nope", "idle").await.status(), StatusCode::NOT_FOUND);
        // An Identity with no Role bound to it may not, and the seat says what it said.
        assert!(crate::access::for_identities("/v1/seats/a-seat0/activity"));
        assert!(crate::access::for_identities("/v1/blobs/default/abc") && crate::access::for_identities("/v1/blobs"));
        assert!(crate::access::for_identities("/v1/volumes/default/data/files"));
        assert!(!crate::access::for_identities("/v1/blob-copy/abc"));
        // (`kith node duress --all` is an admin's, by a certificate: T-0186's VM test.)
        assert!(crate::access::for_identities("/v1/duress") && !crate::access::for_identities("/v1/forget"));
        let stranger = Caller::Identity("mallory".into());
        assert_eq!(ask(stranger, "a-seat0", "idle").await.status(), StatusCode::FORBIDDEN);
        assert_eq!(said(&shared), Some(json!({ "activity": "fullscreen" })));
        let log = shared.audit.tail(10).unwrap();
        assert!(
            log.iter().any(|line| line.to_string().contains("activity fullscreen")),
            "{log:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A made-up `/proc/asound` and input device file for the seat of `SEATED`, with a sound
    /// card (3) and a keyboard in it, and a node that holds the seat.
    struct Tv {
        dir: std::path::PathBuf,
        store: Store,
        memory: Memory,
    }

    impl Drop for Tv {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl Tv {
        fn new(name: &str) -> Tv {
            let dir = std::env::temp_dir().join(format!("kithd-seat-watch-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("asound/card3/pcm0p/sub0")).unwrap();
            std::fs::create_dir_all(dir.join("asound/card3/pcm0c/sub0")).unwrap();
            std::fs::create_dir_all(dir.join("input")).unwrap();
            std::fs::write(dir.join("input/event0"), "").unwrap();
            let more = "---\napiVersion: kith.dev/v1\nkind: Device\nmetadata: { name: a-snd }\nspec: { node: a, class: audio, path: /dev/snd/controlC3 }\n\
                 ---\napiVersion: kith.dev/v1\nkind: Device\nmetadata: { name: a-kbd }\nspec: { node: a, class: input, path: /dev/input/event0 }\n";
            let seated = SEATED.replace("devices: [a-gpu-card0]", "devices: [a-gpu-card0, a-snd, a-kbd]");
            let tv = Tv {
                store: store(&format!("{seated}{more}")),
                dir,
                memory: Memory::stand_in(),
            };
            tv.pcm("closed");
            tv
        }

        /// What the card's playback substream says (its capture one always says it runs).
        fn pcm(&self, state: &str) {
            std::fs::write(self.dir.join("asound/card3/pcm0p/sub0/status"), format!("{state}\n")).unwrap();
            std::fs::write(self.dir.join("asound/card3/pcm0c/sub0/status"), "state: RUNNING\n").unwrap();
        }

        fn touch(&self) {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(self.dir.join("input/event0"))
                .unwrap();
            file.write_all(&[0; 24]).unwrap();
        }

        /// One round of the loop for node `me` at `now`, its writes applied; what it wrote.
        fn round(&mut self, me: &str, now: u64) -> Vec<(String, Option<Value>)> {
            let plans = plan(&self.store, me, &self.dir);
            let writes = round(&plans, &self.dir.join("asound"), &mut self.memory, now);
            let statuses = writes.clone();
            kith_store::run(&mut self.store, Command::Status { statuses }).unwrap();
            writes
        }

        fn batch(&self) -> (Option<u64>, bool) {
            tunes(&self.store, "a")["Workload/default/batch"]
        }
    }

    fn wrote(activity: &str) -> Vec<(String, Option<Value>)> {
        vec![("Seat/a-seat0".to_string(), Some(json!({ "activity": activity })))]
    }

    #[test]
    fn a_held_seat_is_fullscreen_while_its_card_plays_and_idle_after() {
        let mut tv = Tv::new("sound");
        // Nothing plays: idle is what an unsaid seat is, so nothing is written.
        assert_eq!(tv.round("a", 100), []);
        tv.pcm("state: RUNNING\nowner_pid   : 7");
        assert_eq!(tv.round("a", 105), wrote("fullscreen"));
        assert_eq!(tv.batch(), (None, true));
        // Still playing: nothing to write again.
        assert_eq!(tv.round("a", 110), []);
        tv.pcm("closed");
        assert_eq!(tv.round("a", 115), wrote("idle"));
        assert_eq!(tv.batch(), (None, false));
        assert_eq!(tv.round("a", 120), []);
        // (Another node's loop has no say over this seat.)
        tv.pcm("state: RUNNING");
        assert_eq!(tv.round("b", 125), []);
    }

    #[test]
    fn a_touched_input_makes_the_seat_active_for_a_while_and_a_seat_nobody_holds_is_never_written() {
        let mut tv = Tv::new("input");
        assert_eq!(tv.round("a", 100), []);
        tv.touch();
        assert_eq!(tv.round("a", 105), wrote("active"));
        assert_eq!(tv.round("a", 105 + ACTIVE_FOR - 1), []);
        assert_eq!(tv.round("a", 105 + ACTIVE_FOR), wrote("idle"));
        // Sound wins over touch, and a touch is only a moment: the seat goes back to idle.
        tv.touch();
        tv.pcm("state: RUNNING");
        assert_eq!(tv.round("a", 400), wrote("fullscreen"));
        tv.pcm("closed");
        assert_eq!(tv.round("a", 405), wrote("active"));
        // Nobody holds it: no write, whatever plays.
        tv.pcm("state: RUNNING");
        tv.store.delete("Workload/default/desktop").unwrap();
        assert_eq!(tv.round("a", 410), []);
        assert!(plan(&tv.store, "a", &tv.dir).is_empty());
    }

    #[test]
    fn a_post_is_left_alone_for_a_while_then_the_loop_judges_again() {
        let mut tv = Tv::new("post");
        tv.pcm("state: RUNNING");
        assert_eq!(tv.round("a", 100), wrote("fullscreen"));
        // The session says idle: it stays so for EXPLICIT_FOR from when it was seen.
        says(&mut tv.store, "idle");
        assert_eq!(tv.round("a", 105), []);
        assert_eq!(tv.round("a", 105 + EXPLICIT_FOR - 1), []);
        assert_eq!(tv.batch(), (None, false));
        assert_eq!(tv.round("a", 105 + EXPLICIT_FOR), wrote("fullscreen"));
        assert_eq!(tv.batch(), (None, true));
        // A start of kithd (no memory) takes what the store says as its own, and judges at once.
        says(&mut tv.store, "active");
        tv.pcm("closed");
        tv.memory = Memory::stand_in();
        assert_eq!(tv.round("a", 2000), wrote("idle"));
    }

    #[test]
    fn a_clock_that_steps_back_does_not_keep_a_seat_active_or_a_post_in_force() {
        let mut tv = Tv::new("back");
        tv.touch();
        assert_eq!(tv.round("a", 1_000_000), wrote("active"));
        assert_eq!(tv.round("a", 100), wrote("idle"));
        // A POST seen at 2_000_000 holds for EXPLICIT_FOR; a step back ends it, not lengthens it.
        says(&mut tv.store, "fullscreen");
        assert_eq!(tv.round("a", 2_000_000), []);
        assert_eq!(tv.round("a", 200), wrote("idle"));
    }

    #[test]
    fn an_input_that_cannot_be_opened_is_said_once_and_a_missing_one_is_looked_for_again() {
        use std::os::unix::fs::PermissionsExt;
        let mut tv = Tv::new("denied");
        tv.memory = Memory::default();
        let gone = tv.dir.join("input/event9").to_string_lossy().into_owned();
        assert!(!tv.memory.touched(&gone) && tv.memory.refused.is_empty());
        let path = tv.dir.join("input/event0");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0)).unwrap();
        let path = path.to_string_lossy().into_owned();
        assert!(!tv.memory.touched(&path));
        assert!(tv.memory.refused.contains(&path));
    }

    #[test]
    fn a_write_that_failed_is_not_taken_for_a_post() {
        let mut tv = Tv::new("failed");
        tv.pcm("state: RUNNING");
        let plans = plan(&tv.store, "a", &tv.dir);
        let writes = round(&plans, &tv.dir.join("asound"), &mut tv.memory, 100);
        assert_eq!(writes, wrote("fullscreen"));
        // (The store never got it.) The loop forgets it wrote, and says it again next round.
        tv.memory.failed(&writes);
        assert_eq!(tv.round("a", 105), wrote("fullscreen"));
        assert_eq!(tv.round("a", 110), []);
    }

    #[test]
    fn a_path_in_the_store_is_not_trusted_and_a_seat_with_nothing_to_look_at_is_not_judged() {
        let mut tv = Tv::new("paths");
        let device = |node: &str, path: &str| {
            let source = format!(
                "apiVersion: kith.dev/v1\nkind: Device\nmetadata: {{ name: a-kbd }}\nspec: {{ node: {node}, class: input, path: {path} }}\n"
            );
            Resource::from_source(&source).unwrap().remove(0).unwrap()
        };
        let inputs = |tv: &Tv| {
            plan(&tv.store, "a", &tv.dir)
                .into_iter()
                .flat_map(|plan| plan.inputs)
                .collect::<Vec<_>>()
        };
        assert_eq!(inputs(&tv), [tv.dir.join("input/event0").to_string_lossy()]);
        for path in [
            "/dev/input/../x",
            "input/event0",
            "/proc/kmsg",
            "/dev/watchdog",
            "/dev/zero",
            "/dev/input/event",
            "/dev/input/event0x",
            "/dev/input/event0/..",
        ] {
            tv.store.apply(device("a", path)).unwrap();
            assert!(inputs(&tv).is_empty(), "{path}");
        }
        // A Device of another node is not read, whatever its path.
        tv.store.apply(device("b", "/dev/input/event0")).unwrap();
        assert!(inputs(&tv).is_empty());
        tv.store.apply(device("a", "/dev/input/event7")).unwrap();
        assert_eq!(inputs(&tv), [tv.dir.join("input/event7").to_string_lossy()]);
        // A seat with no card and no input (a GPU alone) keeps what a session POSTed.
        let mut gpu = self::store(SEATED);
        says(&mut gpu, "fullscreen");
        assert!(plan(&gpu, "a", &tv.dir).is_empty());
        let mut memory = Memory::default();
        assert_eq!(
            round(&plan(&gpu, "a", &tv.dir), &tv.dir, &mut memory, 5 * EXPLICIT_FOR),
            []
        );
        assert_eq!(tunes(&gpu, "a")["Workload/default/batch"], (None, true));
    }

    #[test]
    fn an_input_that_is_not_an_evdev_node_is_refused_when_opened() {
        assert_eq!(event("/dev/input/event12"), Some("12"));
        assert_eq!(
            [event("/dev/input/mice"), event("/dev/input/by-id/event1")],
            [None, None]
        );
        // A regular file named like an event node, and a character device that is not one.
        let mut tv = Tv::new("refused");
        tv.memory = Memory::default();
        let path = tv.dir.join("input/event0");
        assert!(!is_evdev(&std::fs::File::open(&path).unwrap()));
        assert!(!is_evdev(&std::fs::File::open("/dev/null").unwrap()));
        tv.touch();
        let path = path.to_string_lossy().into_owned();
        assert!(!tv.memory.touched(&path));
        assert!(tv.memory.refused.contains(&path) && tv.memory.inputs.is_empty());
        // (Said once, and not opened again until its path leaves the plan.)
        assert!(!tv.memory.touched(&path));
        assert_eq!(tv.round("a", 100), []);
    }
}
