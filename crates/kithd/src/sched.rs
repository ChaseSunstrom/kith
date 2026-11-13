//! The scheduler, on the node that leads the store: says which node runs each replica of
//! a Workload and which one runs a Job, and writes that into their status as `nodes`
//! (replica to node name) and `unschedulable` (replica to why not); a NodeWorkload gets a
//! replica number for each node that matches. Every node's controller runs what is bound to it. The rules are the `kith-sched` crate's: a replica stays where
//! it is until its node has been out of contact for `--lost-after`.
//
// ponytail: every pass looks at every Workload and Job; fine for hundreds. Past that, plan
// only what changed.

use crate::Shared;
use kith_api::Resource;
use kith_api::kinds::{JobSpec, NodeSpec, NodeWorkloadSpec, WorkloadSpec};
use kith_api::store::Store;
use kith_sched::{Amount, Node, Replica};
use kith_store::Command;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// What to write: per Workload or Job key the status fields that changed, and the
/// (node, key) pairs where a node that is gone left containers in a status.
type Writes = (Vec<(String, Map<String, Value>)>, Vec<(String, String)>);

/// The replicas `resource` wants placed: how many, what each asks for, where each may go.
pub(crate) fn wants(resource: &Resource) -> Option<(u32, Amount, Option<kith_api::kinds::Placement>)> {
    let spec = resource.spec.clone();
    match resource.kind.as_str() {
        "Workload" => {
            let spec: WorkloadSpec = serde_json::from_value(spec).ok()?;
            let amount = Amount::of_template(&spec.template);
            Some((spec.replicas.unwrap_or(1), amount, spec.placement))
        }
        // A NodeWorkload is bound by `every_node`, not placed.
        "NodeWorkload" => None,
        // A Job is run by one node, all of its runs; one that is over (as it is now, not
        // as it was before it was changed) needs no node.
        _ => {
            let over = resource.status.as_ref().is_some_and(|s| {
                let this = s["observedRevision"].as_u64() == resource.metadata.revision;
                this && s["state"] != "running" && !s["state"].is_null()
            });
            let spec: JobSpec = serde_json::from_value(spec).ok()?;
            (!over).then(|| (1, Amount::of_template(&spec.template), spec.placement))
        }
    }
}

/// Where a NodeWorkload's copies are: replica number to node name, one for each node that
/// matches. A node keeps its number while it matches; a new one takes the lowest free.
fn every_node(resource: &Resource, nodes: &[Node], grace: Duration) -> Option<Map<String, Value>> {
    let spec: NodeWorkloadSpec = serde_json::from_value(resource.spec.clone()).ok()?;
    let mut left = kith_sched::node_workload(nodes, &spec.selector, grace);
    let old = resource.status.as_ref().and_then(|s| s["nodes"].as_object());
    let mut bound: Map<String, Value> = old.into_iter().flatten().map(|(k, v)| (k.clone(), v.clone())).collect();
    bound.retain(|_, node| node.as_str().is_some_and(|node| left.contains(&node.to_string())));
    left.retain(|name| !bound.values().any(|node| node == name.as_str()));
    let mut number = 0;
    for name in left {
        while bound.contains_key(&number.to_string()) {
            number += 1;
        }
        bound.insert(number.to_string(), name.into());
    }
    Some(bound)
}

/// For a node name: what it has (CPUs, bytes), and for how long it has been lost.
type Seen<'a> = &'a dyn Fn(&str) -> (Option<(f64, f64)>, Option<Duration>);

fn plan(store: &Store, seen: Seen, grace: Duration) -> Writes {
    let node = |node: &Resource| {
        let (capacity, lost_for) = seen(&node.metadata.name);
        let (cpu, memory) = capacity.unwrap_or_default();
        let spec = serde_json::from_value::<NodeSpec>(node.spec.clone()).ok()?;
        // A node that roams is away, not lost, however long: it keeps what it runs and
        // gets nothing new until it is back.
        let lost_for = lost_for.map(|lost| {
            if spec.roaming == Some(true) {
                Duration::ZERO
            } else {
                lost
            }
        });
        Some(Node {
            name: node.metadata.name.clone(),
            labels: node.metadata.labels.clone(),
            spec,
            capacity: Amount { cpu, memory },
            lost_for,
        })
    };
    let mut nodes: Vec<Node> = store.list(Some("Node")).filter_map(node).collect();
    // A seat's reserve is its holder's: the node has that much less for everything else, and
    // the holder is asked to fit only what it wants beyond it.
    let (reserved, seated) = crate::seats::reserves(store);
    let less = |have: Amount, by: Option<&Amount>| Amount {
        cpu: (have.cpu - by.map_or(0.0, |by| by.cpu)).max(0.0),
        memory: (have.memory - by.map_or(0.0, |by| by.memory)).max(0.0),
    };
    for node in &mut nodes {
        node.capacity = less(node.capacity, reserved.get(&node.name));
    }
    let owners = || {
        let kinds = ["Workload", "Job", "NodeWorkload"];
        kinds.into_iter().flat_map(|kind| store.list(Some(kind)))
    };
    let claims = crate::claims::resolve(store).owners;
    let mounts = crate::volumes::resolve(store).owners;
    let (mut replicas, mut waiting) = (Vec::new(), BTreeMap::new());
    for resource in owners() {
        let Some((count, requests, placement)) = wants(resource) else {
            continue;
        };
        let key = resource.key();
        // Where its claimed hardware and its volumes are; one whose claims or volumes do not come
        // to one node waits, with the reason.
        let node = match crate::volumes::together(claims.get(&key), mounts.get(&key)) {
            Ok(node) => node,
            Err(why) => {
                waiting.extend((0..count).map(|replica| (format!("{key}#{replica}"), why.clone())));
                continue;
            }
        };
        for replica in 0..count {
            let bound = resource
                .status
                .as_ref()
                .and_then(|s| s["nodes"][replica.to_string()].as_str());
            replicas.push(Replica {
                id: format!("{key}#{replica}"),
                workload: key.clone(),
                // (A seat's reserve is its holder's first replica's.)
                requests: less(requests, seated.get(&key).filter(|_| replica == 0)),
                placement: placement.clone(),
                bound: bound.map(str::to_string),
                node: node.clone(),
            });
        }
    }
    let mut made = kith_sched::schedule(&nodes, &replicas, grace);
    made.unschedulable.extend(waiting);
    let of = |key: &str, by_id: &BTreeMap<String, String>| {
        let mine = by_id.iter().filter_map(|(id, value)| {
            let (owner, replica) = id.rsplit_once('#')?;
            (owner == key).then(|| (replica.to_string(), Value::from(value.as_str())))
        });
        Value::Object(mine.collect())
    };
    let gone: BTreeSet<&str> = nodes
        .iter()
        .filter(|node| node.lost_for.is_some_and(|lost| lost > grace))
        .map(|node| node.name.as_str())
        .collect();
    let (mut fields, mut left) = (Vec::new(), Vec::new());
    for resource in owners() {
        let key = resource.key();
        let empty = json!({});
        let status = resource.status.as_ref().unwrap_or(&Value::Null);
        let mut changed = Map::new();
        // A Job that is over keeps the node that ran it.
        let mut want = Vec::new();
        if resource.kind == "NodeWorkload" {
            if let Some(bound) = every_node(resource, &nodes, grace) {
                want.push(("replicas", Value::from(bound.len())));
                want.push(("nodes", Value::Object(bound)));
            }
        } else if wants(resource).is_some() {
            want.push(("nodes", of(&key, &made.bind)));
            want.push(("unschedulable", of(&key, &made.unschedulable)));
            // Something to show when no node says anything (none yet, or none any more).
            if resource.kind == "Workload" {
                want.push(("replicas", Value::from(resource.spec["replicas"].as_u64().unwrap_or(1))));
            }
        }
        for (field, value) in want {
            let old = if status[field].is_null() {
                &empty
            } else {
                &status[field]
            };
            if *old != value {
                changed.insert(field.into(), value);
            }
        }
        if !changed.is_empty() {
            fields.push((key.clone(), changed));
        }
        // A node that is gone cannot take back what it said it runs. Neither can one that
        // was deleted.
        let units = status["containers"].as_array().into_iter().flatten();
        let said: BTreeSet<&str> = units.filter_map(|unit| unit["node"].as_str()).collect();
        let known = |name: &str| nodes.iter().any(|node| node.name == name);
        let stale = said.into_iter().filter(|name| gone.contains(name) || !known(name));
        left.extend(stale.map(|name| (name.to_string(), key.clone())));
    }
    (fields, left)
}

/// Schedule whenever the store changes and every few seconds (nodes come and go without
/// a change to the store), while this node leads.
pub async fn run(shared: Arc<Shared>, grace: Duration, mut stopping: watch::Receiver<bool>) {
    let mut generation = shared.generation.subscribe();
    loop {
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(5)) => {}
            _ = stopping.changed() => return,
        }
        let metrics = shared.raft.metrics().borrow().clone();
        if metrics.current_leader != Some(metrics.id) {
            continue;
        }
        let now = Instant::now();
        let seen = |name: &str| {
            // Not heard from for a moment is not lost; too early to say is not lost either.
            let lost = shared.members.lost_for(name, now);
            let lost = lost.filter(|lost| *lost >= crate::members::GRACE);
            // A node that has never said what it has gets nothing new; what it has stays.
            let capacity = shared.members.capacity(name);
            (capacity, lost.or(capacity.is_none().then_some(Duration::ZERO)))
        };
        let (fields, left, claimed) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let (fields, left) = plan(&state.store, &seen, grace);
            let mut claimed = crate::claims::writes(&state.store);
            claimed.extend(crate::volumes::writes(&state.store));
            claimed.extend(crate::seats::writes(&state.store));
            // Where each replicated volume is now, and on which nodes its copies are.
            let lost = |name: &str| seen(name).1;
            let mut fields = fields;
            fields.extend(crate::replicas::writes(&state.store, &lost, grace));
            (fields, left, claimed)
        };
        // What a lost node ran stops counting as ready before its replicas get a new home.
        let mut commands = Vec::new();
        for (node, key) in left {
            let statuses = vec![(key, None)];
            commands.push(Command::Report { node, statuses });
        }
        // Each DeviceClaim says where it is and who holds it, each VolumeClaim and Volume what it is
        // bound to (only when that changed). Before the fields: a Volume's whole status, worked
        // out from what was there, must not undo where its copies were just said to be.
        if !claimed.is_empty() {
            commands.push(Command::Status { statuses: claimed });
        }
        if !fields.is_empty() {
            commands.push(Command::Patch { statuses: fields });
        }
        for command in commands {
            if let Err(e) = shared.submit(command).await {
                eprintln!("kithd: scheduling: {e}");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER: &str = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: b }
spec: {}
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: web }
spec:
  replicas: 2
  template:
    exec: [{ name: run, command: [sleep, inf], resources: { cpu: 1, memory: 1Gi } }]
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: big }
spec:
  template:
    exec: [{ name: run, command: [sleep, inf], resources: { cpu: 64, memory: 1Gi } }]
---
apiVersion: kith.dev/v1
kind: Job
metadata: { name: once }
spec:
  template:
    exec: [{ name: run, command: ['true'] }]
";

    #[test]
    fn replicas_follow_the_nodes_and_stay_on_a_roaming_one() {
        let mut store = Store::default();
        for resource in Resource::from_source(CLUSTER).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let minutes = |m: u64| Duration::from_secs(60 * m);
        let there = |_: &str| (Some((4.0, 8e9)), None);
        let write = |store: &mut Store, (fields, left): Writes| {
            let done = kith_store::run(store, Command::Patch { statuses: fields });
            done.unwrap();
            for (node, key) in left {
                let statuses = vec![(key, None)];
                kith_store::run(store, Command::Report { node, statuses }).unwrap();
            }
        };
        let status = |store: &Store, key: &str| store.get(key).unwrap().status.clone().unwrap();

        // One replica on each node; what fits nowhere says why; a Job gets its one node.
        let first = plan(&store, &there, minutes(5));
        write(&mut store, first);
        let web = status(&store, "Workload/default/web");
        assert_eq!(web["nodes"], json!({ "0": "a", "1": "b" }));
        assert_eq!((&web["unschedulable"], &web["replicas"]), (&Value::Null, &json!(2)));
        let big = status(&store, "Workload/default/big");
        assert_eq!(big["nodes"], Value::Null);
        assert!(big["unschedulable"]["0"].is_string(), "{big}");
        assert!(status(&store, "Job/default/once")["nodes"]["0"].is_string());
        // Nothing more to write.
        assert_eq!(plan(&store, &there, minutes(5)), (vec![], vec![]));

        // b says what it runs, then is lost: for a minute nothing moves; past the grace
        // its replica goes to a, and what b said it runs is taken out.
        let says = Some(json!({ "replicas": 2, "containers": [{ "name": "run", "replica": 1, "ready": true }] }));
        let statuses = vec![("Workload/default/web".to_string(), says)];
        kith_store::run(
            &mut store,
            Command::Report {
                node: "b".into(),
                statuses,
            },
        )
        .unwrap();
        let lost = |m: u64| move |name: &str| (Some((4.0, 8e9)), (name == "b").then(|| minutes(m)));
        let (fields, left) = plan(&store, &lost(1), minutes(5));
        assert!(
            fields.iter().all(|(_, changed)| !changed.contains_key("nodes")),
            "{fields:?}"
        );
        assert_eq!(left, vec![]);
        // Were b a node that roams (a laptop), it would be away, not lost: nothing moves.
        let mut roams = store.clone();
        let mut b = roams.get("Node/b").unwrap().clone();
        b.spec["roaming"] = true.into();
        roams.apply(b).unwrap();
        let (fields, _) = plan(&roams, &lost(600), minutes(5));
        assert!(
            fields.iter().all(|(_, changed)| !changed.contains_key("nodes")),
            "roaming: {fields:?}"
        );
        let moved = plan(&store, &lost(6), minutes(5));
        write(&mut store, moved);
        let web = status(&store, "Workload/default/web");
        assert_eq!(web["nodes"], json!({ "0": "a", "1": "a" }));
        assert_eq!((&web["containers"], &web["ready"]), (&json!([]), &json!(0)));

        // A Job that is over keeps its node and is not placed again.
        let over = Command::Patch {
            statuses: vec![(
                "Job/default/once".into(),
                Map::from_iter([
                    ("state".to_string(), "succeeded".into()),
                    ("observedRevision".to_string(), 1.into()),
                ]),
            )],
        };
        kith_store::run(&mut store, over).unwrap();
        let nobody = |_: &str| (None, Some(minutes(60)));
        let (fields, _) = plan(&store, &nobody, minutes(5));
        assert!(fields.iter().all(|(key, _)| key != "Job/default/once"), "{fields:?}");

        // A node that has never said what it has gets nothing new, and keeps what it has;
        // a Workload scaled to nothing says so though no node reports on it any more.
        let quiet = |name: &str| {
            (
                (name == "a").then_some((4.0, 8e9)),
                (name == "b").then_some(Duration::ZERO),
            )
        };
        let mut scaled = store.get("Workload/default/web").unwrap().clone();
        scaled.spec["replicas"] = 3.into();
        scaled.metadata.revision = None;
        store.apply(scaled.clone()).unwrap();
        let grown = plan(&store, &quiet, minutes(5));
        write(&mut store, grown);
        let web = status(&store, "Workload/default/web");
        assert_eq!((&web["nodes"]["2"], &web["replicas"]), (&json!("a"), &json!(3)));
        scaled.spec["replicas"] = 0.into();
        scaled.metadata.revision = None;
        store.apply(scaled).unwrap();
        let none = plan(&store, &quiet, minutes(5));
        write(&mut store, none);
        let web = status(&store, "Workload/default/web");
        assert_eq!((&web["nodes"], &web["replicas"]), (&json!({}), &json!(0)));
    }

    #[test]
    fn a_node_workload_has_a_copy_on_every_matching_node() {
        let source = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a, labels: { disk: ssd } }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: b, labels: { disk: ssd } }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: c }
spec: {}
---
apiVersion: kith.dev/v1
kind: NodeWorkload
metadata: { name: agent }
spec:
  selector: { disk: ssd }
  template:
    exec: [{ name: run, command: [sleep, inf] }]
";
        let mut store = Store::default();
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let there = |_: &str| (Some((4.0, 8e9)), None);
        let pass = |store: &mut Store, seen: Seen| {
            let (fields, left) = plan(store, seen, Duration::from_secs(300));
            assert_eq!(left, vec![]);
            let wrote = !fields.is_empty();
            kith_store::run(store, Command::Patch { statuses: fields }).unwrap();
            wrote
        };
        let status = |store: &Store| store.get("NodeWorkload/default/agent").unwrap().status.clone().unwrap();
        let label = |store: &mut Store, name: &str, labels: Value| {
            let mut node = store.get(&format!("Node/{name}")).unwrap().clone();
            node.metadata.labels = serde_json::from_value(labels).unwrap();
            node.metadata.revision = None;
            store.apply(node).unwrap();
        };

        // a and b match; c does not. A second pass has nothing to write.
        assert!(pass(&mut store, &there));
        let first = status(&store);
        assert_eq!(
            (&first["nodes"], &first["replicas"]),
            (&json!({ "0": "a", "1": "b" }), &json!(2))
        );
        assert!(!pass(&mut store, &there));

        // c matches too: it takes the next number; a and b keep theirs.
        label(&mut store, "c", json!({ "disk": "ssd" }));
        assert!(pass(&mut store, &there));
        assert_eq!(status(&store)["nodes"], json!({ "0": "a", "1": "b", "2": "c" }));

        // a stops matching: its number is free, the others keep theirs, then a new node takes it.
        label(&mut store, "a", json!({}));
        assert!(pass(&mut store, &there));
        let after = status(&store);
        assert_eq!(
            (&after["nodes"], &after["replicas"]),
            (&json!({ "1": "b", "2": "c" }), &json!(2))
        );
        label(&mut store, "a", json!({ "disk": "ssd" }));
        assert!(pass(&mut store, &there));
        assert_eq!(status(&store)["nodes"], json!({ "0": "a", "1": "b", "2": "c" }));

        // A node lost past the grace loses its copy, and what it said it runs is taken out.
        let lost = |name: &str| (Some((4.0, 8e9)), (name == "b").then(|| Duration::from_secs(600)));
        let says = json!({ "replicas": 3, "containers": [{ "name": "run", "replica": 1, "ready": true }] });
        let report = Command::Report {
            node: "b".into(),
            statuses: vec![("NodeWorkload/default/agent".to_string(), Some(says))],
        };
        kith_store::run(&mut store, report).unwrap();
        let (fields, left) = plan(&store, &lost, Duration::from_secs(300));
        assert_eq!(left, vec![("b".to_string(), "NodeWorkload/default/agent".to_string())]);
        kith_store::run(&mut store, Command::Patch { statuses: fields }).unwrap();
        assert_eq!(status(&store)["nodes"], json!({ "0": "a", "2": "c" }));
    }

    #[test]
    fn a_workload_with_a_claim_goes_to_its_devices_node_and_a_second_holder_waits() {
        let source = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: b }
spec: {}
---
apiVersion: kith.dev/v1
kind: Device
metadata: { name: b-gpu-card0 }
spec: { node: b, class: gpu, path: /dev/dri/card0 }
---
apiVersion: kith.dev/v1
kind: DeviceClaim
metadata: { name: gpu }
spec: { device: b-gpu-card0 }
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: one }
spec: { template: { exec: [{ name: run, command: [sleep, inf] }], deviceClaims: [gpu] } }
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: two }
spec: { template: { exec: [{ name: run, command: [sleep, inf] }], deviceClaims: [gpu] } }
";
        let mut store = Store::default();
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let there = |_: &str| (Some((4.0, 8e9)), None);
        let (fields, _) = plan(&store, &there, Duration::from_secs(300));
        kith_store::run(&mut store, Command::Patch { statuses: fields }).unwrap();
        let statuses = crate::claims::writes(&store);
        kith_store::run(&mut store, Command::Status { statuses }).unwrap();
        let status = |key: &str| store.get(key).unwrap().status.clone().unwrap();
        assert_eq!(status("Workload/default/one")["nodes"], json!({ "0": "b" }));
        let two = status("Workload/default/two");
        assert!(two["nodes"].is_null(), "no node yet: {two}");
        assert_eq!(
            two["unschedulable"]["0"],
            "waiting for DeviceClaim gpu, held by Workload/default/one"
        );
        let held = status("DeviceClaim/default/gpu");
        assert_eq!(
            held,
            json!({ "node": "b", "devices": ["b-gpu-card0"], "holders": ["Workload/default/one"] })
        );
        // Nothing more to write.
        assert_eq!(plan(&store, &there, Duration::from_secs(300)), (vec![], vec![]));
        assert!(crate::claims::writes(&store).is_empty());
    }

    #[test]
    fn a_seat_reserve_is_its_holders_and_the_others_fit_in_what_is_left() {
        let unit = |cpu: u32| format!("exec: [{{ name: run, command: [sleep, inf], resources: {{ cpu: {cpu} }} }}]");
        let source = format!(
            "
apiVersion: kith.dev/v1
kind: Node
metadata: {{ name: a }}
spec: {{}}
---
apiVersion: kith.dev/v1
kind: Device
metadata: {{ name: a-gpu-card0 }}
spec: {{ node: a, class: gpu, path: /dev/dri/card0 }}
---
apiVersion: kith.dev/v1
kind: Seat
metadata: {{ name: a-seat0 }}
spec: {{ node: a, devices: [a-gpu-card0], reserve: {{ cpu: 2 }} }}
---
apiVersion: kith.dev/v1
kind: DeviceClaim
metadata: {{ name: desk }}
spec: {{ seat: a-seat0 }}
---
apiVersion: kith.dev/v1
kind: Workload
metadata: {{ name: desktop }}
spec: {{ template: {{ {}, deviceClaims: [desk] }} }}
---
apiVersion: kith.dev/v1
kind: Workload
metadata: {{ name: fits }}
spec: {{ template: {{ {} }} }}
---
apiVersion: kith.dev/v1
kind: Workload
metadata: {{ name: toobig }}
spec: {{ template: {{ {} }} }}
",
            unit(3),
            unit(1),
            unit(3)
        );
        let mut store = Store::default();
        for resource in Resource::from_source(&source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        // Four CPUs, two of them the seat's: its holder (3) has the two and fits its third; of the
        // other two, one goes to `fits` and three are not there for `toobig`.
        let there = |_: &str| (Some((4.0, 8e9)), None);
        let (fields, _) = plan(&store, &there, Duration::from_secs(300));
        kith_store::run(&mut store, Command::Patch { statuses: fields }).unwrap();
        let status = |key: &str| store.get(key).unwrap().status.clone().unwrap();
        assert_eq!(status("Workload/default/desktop")["nodes"], json!({ "0": "a" }));
        assert_eq!(status("Workload/default/fits")["nodes"], json!({ "0": "a" }));
        let toobig = status("Workload/default/toobig");
        assert!(
            toobig["nodes"].is_null() && toobig["unschedulable"]["0"].is_string(),
            "{toobig}"
        );
    }
}
