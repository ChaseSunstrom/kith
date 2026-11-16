//! The scheduler, on the node that leads the store: says which node runs each replica of
//! a Workload and which one runs a Job, and writes that into their status as `nodes`
//! (replica to node name) and `unschedulable` (replica to why not); a NodeWorkload gets a
//! replica number for each node that matches. Every node's controller runs what is bound to
//! it. The rules are the `kith-sched` crate's: a replica stays where it is until its node has
//! been out of contact for `--lost-after`.
//
// ponytail: every pass looks at every Workload and Job; fine for hundreds. Past that, plan
// only what changed.

use crate::Shared;
use kith_api::Resource;
use kith_api::kinds::{JobSpec, NodeSpec, NodeWorkloadSpec, WorkloadSpec};
use kith_api::store::Store;
use kith_sched::{Amount, Node, Plan, Replica};
use kith_store::Command;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// What to write: per Workload or Job key the status fields that changed, and the
/// (node, key) pairs where a node that is gone left containers in a status.
type Writes = (Vec<(String, Map<String, Value>)>, Vec<(String, String)>);

/// The label every node has for the scheduler, made from its `spec.trust` (`control` or
/// `worker`) whatever its own labels say: `placement.require` of it keeps a template off
/// workers.
pub const TRUST: &str = "kith.dev/trust";

/// What starts the labels every node has for the scheduler from its own policy, one for each
/// key it allows (`kith.dev/policy-allows-execUnits`), whatever its own labels say.
const ALLOWS: &str = "kith.dev/policy-allows-";

/// Whether `resource`'s template names one of `guarded`, the keys of the Secrets that are
/// for control nodes only: it is then placed on those.
fn control_only(guarded: &BTreeSet<String>, resource: &Resource) -> bool {
    // (No such Secret, as in most clusters: no template is read a second time.)
    if guarded.is_empty() {
        return false;
    }
    let namespace = resource.metadata.namespace.as_deref().unwrap_or("default");
    let template = serde_json::from_value::<kith_api::kinds::Template>(resource.spec["template"].clone());
    template.is_ok_and(|template| {
        let mut named = template.secrets();
        named.any(|name| guarded.contains(&format!("Secret/{namespace}/{name}")))
    })
}

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
fn every_node(resource: &Resource, nodes: &[Node], grace: Duration, control: bool) -> Option<Map<String, Value>> {
    let mut spec: NodeWorkloadSpec = serde_json::from_value(resource.spec.clone()).ok()?;
    if control {
        spec.selector.insert(TRUST.into(), "control".into());
    }
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

/// The keys of the Secrets that are for control nodes only.
fn guarded(store: &Store) -> BTreeSet<String> {
    let secrets = store
        .list(Some("Secret"))
        .filter(|secret| secret.spec["trust"] == "control");
    secrets.map(Resource::key).collect()
}

/// The Workloads, Jobs and NodeWorkloads of the store, the ones that have copies on nodes.
fn owners(store: &Store) -> impl Iterator<Item = &Resource> {
    ["Workload", "Job", "NodeWorkload"]
        .into_iter()
        .flat_map(|kind| store.list(Some(kind)))
}

/// Puts the drain on a Node's spec: cordoned, and the `kith.dev/drain` NoExecute taint. A node
/// an owner cordoned already keeps its cordon: its taint says so (`owner`), and undrain
/// leaves it.
pub(crate) fn drain_on(spec: &mut Value) {
    let mut taints = spec["taints"].as_array().cloned().unwrap_or_default();
    if taints.iter().any(|taint| taint["key"] == kith_sched::DRAIN) {
        return;
    }
    let owned = spec["unschedulable"] == true;
    let mut taint = json!({ "key": kith_sched::DRAIN, "effect": "noExecute" });
    if owned {
        taint["value"] = "owner".into();
    } else {
        spec["unschedulable"] = Value::Bool(true);
    }
    taints.push(taint);
    spec["taints"] = Value::Array(taints);
}

/// Takes the drain off a Node's spec: its taint, and the cordon too unless an owner set it.
pub(crate) fn drain_off(spec: &mut Value) {
    let Some(mut taints) = spec["taints"].as_array().cloned() else {
        return;
    };
    let Some(at) = taints.iter().position(|taint| taint["key"] == kith_sched::DRAIN) else {
        return;
    };
    let taint = taints.remove(at);
    spec["taints"] = Value::Array(taints);
    if taint["value"] != "owner"
        && let Some(spec) = spec.as_object_mut()
    {
        spec.remove("unschedulable");
    }
}

/// What the scheduler is told of each node at `now`: its capacity, and for how long it has
/// been lost.
pub(crate) fn seen_at(shared: &Shared, now: Instant) -> impl Fn(&str) -> (Option<(f64, f64)>, Option<Duration>) + '_ {
    move |name: &str| {
        // Not heard from for a moment is not lost; too early to say is not lost either.
        let lost = shared.members.lost_for(name, now);
        let lost = lost.filter(|lost| *lost >= crate::members::GRACE);
        // A node that has never said what it has gets nothing new; what it has stays.
        let capacity = shared.members.capacity(name);
        (capacity, lost.or(capacity.is_none().then_some(Duration::ZERO)))
    }
}

/// The nodes, the replicas asked to be placed and where the scheduler puts them. `drain` is a
/// node to plan with its drain on, as `kith node drain` would leave it.
fn decide(store: &Store, seen: Seen, grace: Duration, drain: Option<&str>) -> (Vec<Node>, Vec<Replica>, Plan) {
    let node = |node: &Resource| {
        let (capacity, lost_for) = seen(&node.metadata.name);
        let (cpu, memory) = capacity.unwrap_or_default();
        let mut value = node.spec.clone();
        if drain == Some(node.metadata.name.as_str()) {
            drain_on(&mut value);
        }
        let spec = serde_json::from_value::<NodeSpec>(value).ok()?;
        // A node that roams is away, not lost, however long: it keeps what it runs and
        // gets nothing new until it is back.
        let lost_for = lost_for.map(|lost| {
            if spec.roaming == Some(true) {
                Duration::ZERO
            } else {
                lost
            }
        });
        let mut labels = node.metadata.labels.clone();
        let trust = match spec.trust {
            Some(kith_api::kinds::Trust::Worker) => "worker",
            _ => "control",
        };
        labels.insert(TRUST.into(), trust.into());
        // And one for each thing its own policy allows (all of them, where it says none):
        // what a node says it refuses is not placed on it.
        let said = node
            .status
            .as_ref()
            .map(|status| crate::policy::Policy::said(&status["policy"]));
        for (_, key, _) in crate::policy::KEYS {
            let allowed = said.as_ref().is_none_or(|said| said.allows(key));
            let label = format!("{ALLOWS}{key}");
            if allowed {
                labels.insert(label, "true".into());
            } else {
                labels.remove(&label);
            }
        }
        Some(Node {
            name: node.metadata.name.clone(),
            labels,
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
    let claims = crate::claims::resolve(store).owners;
    let mounts = crate::volumes::resolve(store).owners;
    let guarded = guarded(store);
    let (mut replicas, mut waiting) = (Vec::new(), BTreeMap::new());
    let mut refused: BTreeMap<String, String> = BTreeMap::new();
    for resource in owners(store) {
        let Some((count, requests, mut placement)) = wants(resource) else {
            continue;
        };
        if control_only(&guarded, resource) {
            let (require, prefer) = Default::default();
            let placement = placement.get_or_insert(kith_api::kinds::Placement { require, prefer });
            placement.require.insert(TRUST.into(), "control".into());
        }
        // What of it a node's policy may refuse: it goes where all of that is allowed. (Not
        // its claimed Devices or its Volumes: those are on one node, which says so itself.)
        let template = crate::controller::template_of(resource).ok();
        let needs = template.map(|(template, _)| crate::policy::needs(&template, false));
        let needs = needs.unwrap_or_default();
        if !needs.is_empty() {
            let (require, prefer) = Default::default();
            let placement = placement.get_or_insert(kith_api::kinds::Placement { require, prefer });
            let allowed = needs.iter().map(|key| (format!("{ALLOWS}{key}"), "true".to_string()));
            placement.require.extend(allowed);
            let refusing = |node: &&Node| {
                needs
                    .iter()
                    .any(|key| !node.labels.contains_key(&format!("{ALLOWS}{key}")))
            };
            if nodes.iter().any(|node| refusing(&node)) {
                refused.insert(resource.key(), needs.join(", "));
            }
        }
        let key = resource.key();
        // Where its claimed hardware and its volumes are; one whose claims or volumes do not come
        // to one node waits, with the reason.
        let node = crate::volumes::together(claims.get(&key), mounts.get(&key));
        // (And where its exit is.)
        let node = match node.and_then(|node| crate::exits::pinned(store, resource, node)) {
            Ok(node) => node,
            Err(why) => {
                waiting.extend((0..count).map(|replica| (format!("{key}#{replica}"), why.clone())));
                continue;
            }
        };
        // A Job that is running now: a drain leaves it where it runs.
        let running = resource.kind == "Job" && resource.status.as_ref().is_some_and(|s| s["state"] == "running");
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
                running,
            });
        }
    }
    let mut made = kith_sched::schedule(&nodes, &replicas, grace);
    // (One that fits nowhere, and asks for what some node's policy refuses: said, so that
    // "missing required labels" is not all there is to go on.)
    for (id, why) in &mut made.unschedulable {
        let workload = id.rsplit_once('#').map_or(id.as_str(), |(workload, _)| workload);
        if let Some(needs) = refused.get(workload) {
            why.push_str(&format!(
                "; it asks for what a node's own policy may refuse ({needs}), and goes only where the Node's status.policy allows it"
            ));
        }
    }
    made.unschedulable.extend(waiting);
    (nodes, replicas, made)
}

fn plan(store: &Store, seen: Seen, grace: Duration) -> Writes {
    let (nodes, _, made) = decide(store, seen, grace, None);
    let guarded = guarded(store);
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
    for resource in owners(store) {
        let key = resource.key();
        let empty = json!({});
        let status = resource.status.as_ref().unwrap_or(&Value::Null);
        let mut changed = Map::new();
        // A Job that is over keeps the node that ran it.
        let mut want = Vec::new();
        if resource.kind == "NodeWorkload" {
            if let Some(bound) = every_node(resource, &nodes, grace, control_only(&guarded, resource)) {
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

/// What `kith node drain` would do to what runs on `node`, as the scheduler works it out with
/// the drain on: one line per Workload, Job and NodeWorkload that has a copy there now.
pub(crate) fn drain_lines(store: &Store, seen: Seen, grace: Duration, node: &str) -> Vec<Value> {
    let (nodes, replicas, made) = decide(store, seen, grace, Some(node));
    let mut lines = Vec::new();
    for r in &replicas {
        let after = made.bind.get(&r.id).map(String::as_str);
        if r.bound.as_deref() != Some(node) && after != Some(node) {
            continue;
        }
        let (key, replica) = r.id.rsplit_once('#').unwrap_or((r.id.as_str(), "0"));
        let (outcome, to, why) = match after {
            Some(to) if to == node => ("stays", None, made.stays.get(&r.id).cloned().unwrap_or_default()),
            Some(to) => ("moves", Some(to.to_string()), String::new()),
            None => (
                "unplaced",
                None,
                made.unschedulable.get(&r.id).cloned().unwrap_or_default(),
            ),
        };
        let if_lost = if r.node.is_some() {
            "waits for the node: pinned by its Volume or Device"
        } else if r.running {
            "starts over on another node once the node is lost, if one can take it"
        } else {
            "moves to another node once the node is lost, if one can take it"
        };
        lines.push(line(key.into(), Some(replica), outcome, to, why, if_lost));
    }
    let guarded = guarded(store);
    for resource in owners(store).filter(|resource| resource.kind == "NodeWorkload") {
        let Some(bound) = every_node(resource, &nodes, grace, control_only(&guarded, resource)) else {
            continue;
        };
        let had = resource.status.as_ref().and_then(|s| s["nodes"].as_object());
        let had = had.is_some_and(|m| m.values().any(|v| v.as_str() == Some(node)));
        let kept = bound.values().any(|v| v.as_str() == Some(node));
        if !had && !kept {
            continue;
        }
        let (outcome, why, if_lost) = if kept {
            (
                "stays",
                "one copy runs on each node its selector matches",
                "its copy waits for the node",
            )
        } else {
            (
                "removed",
                "another NoExecute taint is on the node",
                "its copy comes back when the node does",
            )
        };
        lines.push(line(resource.key(), None, outcome, None, why.into(), if_lost));
    }
    lines
}

/// One line of [`drain_lines`]: what a resource's copy on the drained node does.
fn line(key: String, replica: Option<&str>, outcome: &str, to: Option<String>, why: String, if_lost: &str) -> Value {
    let parts: Vec<&str> = key.split('/').collect();
    let namespace = (parts.len() == 3).then(|| parts[1]);
    json!({
        "kind": parts[0],
        "namespace": namespace,
        "key": key,
        "replica": replica,
        "outcome": outcome,
        "to": to,
        "why": why,
        "if_lost": if_lost,
    })
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
        let seen = seen_at(&shared, Instant::now());
        let (fields, left, claimed, (made, gone)) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let (fields, left) = plan(&state.store, &seen, grace);
            // The Volumes to make for claims that ask for one made, and those to remove.
            let volumes = crate::volumes::provision(&state.store, &|node| seen(node).1.is_none());
            let mut claimed = crate::claims::writes(&state.store);
            claimed.extend(crate::volumes::writes(&state.store));
            claimed.extend(crate::seats::writes(&state.store));
            claimed.extend(crate::share::writes(&state.store));
            // Where each replicated volume is now, and on which nodes its copies are.
            let lost = |name: &str| seen(name).1;
            let mut fields = fields;
            fields.extend(crate::replicas::writes(&state.store, &lost, grace));
            (fields, left, claimed, volumes)
        };
        // What a lost node ran stops counting as ready before its replicas get a new home.
        // (One that cannot be made is said, and holds nothing else back.)
        let gone = gone.into_iter().map(|key| Command::Delete { key });
        let made = made.into_iter().map(|volume| Command::Apply {
            resources: vec![volume],
            at: kith_api::store::now(),
        });
        for command in gone.chain(made) {
            if let Err(e) = shared.submit(command).await {
                eprintln!("kithd: a Volume for a claim: {e}");
            }
        }
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
    fn trust_keeps_what_asks_for_control_nodes_off_a_worker() {
        // b is a worker, whatever label it was given.
        let cluster = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: b, labels: { kith.dev/trust: control } }
spec: { trust: worker }
---
apiVersion: kith.dev/v1
kind: Secret
metadata: { name: key }
spec: { trust: control, data: { k: v } }
---
apiVersion: kith.dev/v1
kind: Secret
metadata: { name: any }
spec: { data: { k: v } }
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: plain }
spec:
  replicas: 2
  template:
    exec: [{ name: run, command: [sleep, inf], env: [{ name: K, secret: { name: any, key: k } }] }]
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: asks }
spec:
  replicas: 2
  placement: { require: { kith.dev/trust: control } }
  template:
    exec: [{ name: run, command: [sleep, inf] }]
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: named }
spec:
  replicas: 2
  template:
    exec: [{ name: run, command: [sleep, inf], env: [{ name: K, secret: { name: key, key: k } }] }]
---
apiVersion: kith.dev/v1
kind: NodeWorkload
metadata: { name: each }
spec:
  template:
    exec: [{ name: run, command: [sleep, inf] }]
---
apiVersion: kith.dev/v1
kind: NodeWorkload
metadata: { name: each-named }
spec:
  template:
    exec: [{ name: run, command: [sleep, inf], env: [{ name: K, secret: { name: key, key: k } }] }]
";
        let mut store = Store::default();
        for resource in Resource::from_source(cluster).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let there = |_: &str| (Some((4.0, 8e9)), None);
        let (fields, _) = plan(&store, &there, Duration::from_secs(300));
        let nodes = |key: &str| {
            let of = fields
                .iter()
                .find(|(of, _)| of == key)
                .unwrap_or_else(|| panic!("{key}: {fields:?}"));
            of.1["nodes"].clone()
        };
        assert_eq!(nodes("Workload/default/plain"), json!({ "0": "a", "1": "b" }));
        // Asked for in `placement`, or by a Secret it names that is for control nodes.
        assert_eq!(nodes("Workload/default/asks"), json!({ "0": "a", "1": "a" }));
        assert_eq!(nodes("Workload/default/named"), json!({ "0": "a", "1": "a" }));
        assert_eq!(nodes("NodeWorkload/default/each"), json!({ "0": "a", "1": "b" }));
        assert_eq!(nodes("NodeWorkload/default/each-named"), json!({ "0": "a" }));
    }

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

    /// The store as `kith node drain a` leaves it: `a` cordoned and under the `kith.dev/drain`
    /// NoExecute taint, with what runs on it given as statuses.
    fn drained_store(source: &str, statuses: &[(&str, Value)]) -> Store {
        let mut store = Store::default();
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        for (key, status) in statuses {
            store.set_status(key, Some(status.clone())).unwrap();
        }
        store
    }

    const DRAINED: &str = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a }
spec: { unschedulable: true, taints: [{ key: kith.dev/drain, effect: noExecute }] }
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: b }
spec: {}
---
apiVersion: kith.dev/v1
kind: Device
metadata: { name: a-gpu-card0 }
spec: { node: a, class: gpu, path: /dev/dri/card0 }
---
apiVersion: kith.dev/v1
kind: DeviceClaim
metadata: { name: gpu }
spec: { device: a-gpu-card0 }
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: pinned }
spec: { template: { exec: [{ name: run, command: [sleep, inf] }], deviceClaims: [gpu] } }
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
kind: Job
metadata: { name: batch }
spec: { template: { exec: [{ name: run, command: [sleep, inf] }] } }
";

    #[test]
    fn drain_moves_what_can_move_and_keeps_a_pinned_replica_and_a_running_job() {
        let store = drained_store(
            DRAINED,
            &[
                ("Workload/default/web", json!({ "nodes": { "0": "a", "1": "a" } })),
                ("Workload/default/pinned", json!({ "nodes": { "0": "a" } })),
                (
                    "Job/default/batch",
                    json!({ "state": "running", "nodes": { "0": "a" } }),
                ),
            ],
        );
        let there = |_: &str| (Some((4.0, 8e9)), None);
        let (fields, _) = plan(&store, &there, Duration::from_secs(300));
        // (Only the `nodes` field is looked at: a drain changes where a thing runs, not its count.)
        let nodes = |key: &str| {
            fields
                .iter()
                .find(|(of, _)| of == key)
                .and_then(|(_, f)| f.get("nodes").cloned())
        };
        assert_eq!(nodes("Workload/default/web"), Some(json!({ "0": "b", "1": "b" })));
        assert_eq!(
            nodes("Workload/default/pinned"),
            None,
            "pinned by its Device: stays on a"
        );
        assert_eq!(
            nodes("Job/default/batch"),
            None,
            "a running Job is not moved by a drain"
        );
    }

    #[test]
    fn drain_keeps_a_replica_that_no_other_node_can_take() {
        // `big` asks for 64 CPUs and b has 4: a is its last node, so it stays and is said so.
        let source = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a }
spec: { unschedulable: true, taints: [{ key: kith.dev/drain, effect: noExecute }] }
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: b }
spec: {}
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: big }
spec: { template: { exec: [{ name: run, command: [sleep, inf], resources: { cpu: 64, memory: 1Gi } }] } }
";
        let store = drained_store(source, &[("Workload/default/big", json!({ "nodes": { "0": "a" } }))]);
        let there = |_: &str| (Some((4.0, 8e9)), None);
        let (fields, _) = plan(&store, &there, Duration::from_secs(300));
        let moved = fields
            .iter()
            .find(|(key, _)| key == "Workload/default/big")
            .and_then(|(_, f)| f.get("nodes"));
        assert!(moved.is_none(), "{fields:?}");
    }

    #[test]
    fn drain_leaves_a_node_workload_copy_on_the_drained_node() {
        let source = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a }
spec: { unschedulable: true, taints: [{ key: kith.dev/drain, effect: noExecute }] }
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: b }
spec: {}
---
apiVersion: kith.dev/v1
kind: NodeWorkload
metadata: { name: each }
spec: { template: { exec: [{ name: run, command: [sleep, inf] }] } }
";
        let copies = json!({ "0": "a", "1": "b" });
        let store = drained_store(source, &[("NodeWorkload/default/each", json!({ "nodes": copies }))]);
        let there = |_: &str| (Some((4.0, 8e9)), None);
        let (fields, _) = plan(&store, &there, Duration::from_secs(300));
        let moved = fields
            .iter()
            .find(|(key, _)| key == "NodeWorkload/default/each")
            .and_then(|(_, f)| f.get("nodes"));
        assert!(moved.is_none(), "{fields:?}");
    }

    #[test]
    fn a_taint_other_than_the_drain_still_moves_a_running_job() {
        let source = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a }
spec: { taints: [{ key: example.dev/other, effect: noExecute }] }
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: b }
spec: {}
---
apiVersion: kith.dev/v1
kind: Job
metadata: { name: batch }
spec: { template: { exec: [{ name: run, command: [sleep, inf] }] } }
";
        let store = drained_store(
            source,
            &[(
                "Job/default/batch",
                json!({ "state": "running", "nodes": { "0": "a" } }),
            )],
        );
        let there = |_: &str| (Some((4.0, 8e9)), None);
        let (fields, _) = plan(&store, &there, Duration::from_secs(300));
        let nodes = fields
            .iter()
            .find(|(of, _)| of == "Job/default/batch")
            .map(|(_, f)| f["nodes"].clone());
        assert_eq!(nodes, Some(json!({ "0": "b" })));
    }

    /// What a node says its own policy refuses is not placed on it, whatever label of the
    /// scheduler's someone gave it; with no node left that allows it, the reason says so.
    #[test]
    fn a_replica_goes_only_where_the_nodes_policy_allows_what_it_asks_for() {
        let source = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a, labels: { kith.dev/policy-allows-execUnits: 'true' } }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: b }
spec: {}
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: tool }
spec: { replicas: 2, template: { exec: [{ name: run, command: [sleep, inf] }] } }
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: web }
spec: { replicas: 2, template: { pod: true, containers: [{ name: web, image: x }] } }
";
        let hardened = json!({ "policy": crate::policy::Policy::hardened().status() });
        let there = |_: &str| (Some((4.0, 8e9)), None);
        let grace = Duration::from_secs(300);
        let store = drained_store(source, &[("Node/a", hardened.clone())]);
        let (_, _, made) = decide(&store, &there, grace, None);
        let on = |made: &Plan, id: &str| made.bind.get(id).cloned();
        let tools = ["Workload/default/tool#0", "Workload/default/tool#1"];
        assert!(tools.iter().all(|id| on(&made, id).as_deref() == Some("b")), "{made:?}");
        // (A pod of containers that are not root asks for nothing a hardened node refuses.)
        let webs = ["Workload/default/web#0", "Workload/default/web#1"].map(|id| on(&made, id));
        assert!(webs.contains(&Some("a".into())), "{made:?}");
        let store = drained_store(source, &[("Node/a", hardened.clone()), ("Node/b", hardened)]);
        let (_, _, made) = decide(&store, &there, grace, None);
        let why = &made.unschedulable["Workload/default/tool#0"];
        assert!(why.contains("execUnits") && why.contains("status.policy"), "{why}");
        assert!(on(&made, "Workload/default/web#0").is_some(), "{made:?}");
    }

    #[test]
    fn drain_undone_places_a_replica_on_the_node_again() {
        // After `kith node undrain a` (no taint, no cordon) a new replica that needs `role: gpu`
        // is placed on a, the only node that has it.
        let source = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a, labels: { role: gpu } }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: b }
spec: {}
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: gpu-work }
spec:
  placement: { require: { role: gpu } }
  template:
    exec: [{ name: run, command: [sleep, inf] }]
";
        let store = drained_store(source, &[]);
        let there = |_: &str| (Some((4.0, 8e9)), None);
        let (fields, _) = plan(&store, &there, Duration::from_secs(300));
        let nodes = fields
            .iter()
            .find(|(of, _)| of == "Workload/default/gpu-work")
            .map(|(_, f)| f["nodes"].clone());
        assert_eq!(nodes, Some(json!({ "0": "a" })));
    }
}
