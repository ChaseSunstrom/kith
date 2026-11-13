//! What a `Seat` gives whatever holds it, and asks of everything else: its `reserve` comes off
//! its node for every other workload, the holder's units get it as a guarantee in their cgroup,
//! and a workload that says `yieldTo` is held back while the seat is in a state it names. The
//! session says what the seat is doing (`POST /v1/seats/NAME/activity`).
//
// ponytail: a seat's reserve is taken off its node whether or not anything holds the seat (the
// screen is there; a session may start any moment), and workloads already placed are not moved.
// Every unit of a holder gets the whole memory guarantee (not a share of it). A session that
// hangs while fullscreen keeps the others held back until it goes: a heartbeat if that bites.

use crate::cluster::refuse;
use crate::{Shared, access::Caller};
use axum::extract::{Path as Named, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use kith_api::kinds::{Activity, DeviceClaimSpec, SeatSpec, Template, YieldTo};
use kith_api::store::Store;
use kith_sched::Amount;
use kith_store::Command;
use serde_json::{Value, json};
use std::collections::BTreeMap;
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
            serde_json::from_value::<DeviceClaimSpec>(claim.spec.clone()).ok()?.seat
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
metadata: { name: a-seat0 }
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
        says(&mut store, "active");
        assert_eq!(batch(&store, "a"), (None, false));
        says(&mut store, "fullscreen");
        assert_eq!(batch(&store, "a"), (None, true));
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
        let shared = crate::replica(None, &dir).await.unwrap();
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
}
