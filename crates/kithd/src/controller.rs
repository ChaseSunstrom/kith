//! The controller: makes the containers and exec units on this node match the
//! `Workload`s, `NodeWorkload`s and `Job`s in the store, restarts them when they exit, and reports
//! what it sees in each one's status.
//!
// ponytail: one node. Not handled yet, each said so in the status where it
// matters: ports (units share the host's network) and exec probes.
// A rolling update replaces one replica at a time, the old one stopped before the
// new one starts: unit ids (cgroup, log file) are per replica, so two generations
// of a replica cannot run side by side. Images are pulled one at a time.
// A Job's progress lives in memory: kithd restarted under a running Job starts it over.

use crate::Shared;
use kith_api::Resource;
use kith_api::kinds::{
    ConfigMapSpec, Container, EnvVar, ExecUnit, JobSpec, NodeWorkloadSpec, PullPolicy, Resources, RestartPolicy,
    SecretSpec, Strategy, Template, WorkloadSpec,
};
use kith_api::store::Error;
use kith_runtime::{Handle, Runtime, Unit};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

/// How long a unit must have run for its next restart to be immediate again.
const SETTLED: Duration = Duration::from_secs(60);
/// With nothing else to wake it, the controller still looks around this often.
const TICK: Duration = Duration::from_secs(10);
/// Failed runs a Job shrugs off when it does not say (`retries`).
const JOB_RETRIES: u32 = 3;

/// What a slot runs.
// Most slots are containers, so boxing the big variant would save nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq)]
enum Run {
    Container(Container),
    Exec(ExecUnit),
}

impl Run {
    fn name(&self) -> &str {
        match self {
            Run::Container(c) => &c.name,
            Run::Exec(e) => &e.name,
        }
    }
}

/// One unit of one replica of one Workload, of one copy of a NodeWorkload, or of one run of a Job.
struct Slot {
    /// Store key of the Workload, NodeWorkload or Job.
    owner: String,
    replica: u32,
    run: Run,
    policy: RestartPolicy,
    /// Its environment with every Secret and ConfigMap reference looked up, or why that failed.
    /// A unit whose looked-up values changed is replaced like one whose definition changed.
    env: Result<Vec<(String, String)>, String>,
    /// Replace changed replicas one at a time (a Workload unless its strategy is `recreate`).
    rolling: bool,
    probes: Option<crate::probe::Probes>,
    /// The device nodes its DeviceClaims give it (a changed set replaces the unit, like a changed value).
    devices: Vec<PathBuf>,
    /// What its containers mount: the Volume's directory, where in the container, and read-only
    /// (a changed one replaces the unit, as a changed value does). An exec unit mounts nothing.
    volumes: Vec<(crate::volumes::Dir, String, bool)>,
    handle: Option<Handle>,
    state: &'static str,
    restarts: u32,
    /// Failures in a row, for the backoff.
    failures: u32,
    exit_code: Option<i32>,
    message: Option<String>,
    started: Instant,
    /// When to (re)start it; `None` when it is running or done for good.
    start_at: Option<Instant>,
}

impl Slot {
    fn ready(&self) -> bool {
        self.state == "running" && self.probes.as_ref().is_none_or(|p| p.health.borrow().ready)
    }
}

/// How far one Job has come. Kept in memory: a kithd that restarts runs an
/// unfinished Job again from the start; a finished one is recognised by its status.
struct Progress {
    /// The Job revision this is the progress of: a changed Job runs again.
    revision: Option<u64>,
    succeeded: BTreeSet<u32>,
    failed: u32,
    began: Instant,
    /// The next run after a failure waits until then.
    retry_at: Instant,
    /// `succeeded` or `failed`, once it is over.
    outcome: Option<&'static str>,
    message: Option<String>,
}

struct Controller {
    runtime: Runtime,
    logs: PathBuf,
    log_cap: u64,
    slots: BTreeMap<String, Slot>,
    jobs: BTreeMap<String, Progress>,
    /// Log file prefixes of the Workloads, NodeWorkloads and Jobs seen last pass; `None` before the first.
    owners: Option<BTreeSet<String>>,
    /// The status report on its way to the store, if one is.
    report: Option<tokio::task::JoinHandle<()>>,
}

pub async fn run(
    shared: std::sync::Arc<Shared>,
    runtime: kith_runtime::Result<Runtime>,
    log_cap: u64,
    mut stopping: watch::Receiver<bool>,
) {
    let runtime = match runtime.and_then(|rt| rt.cleanup().map(|old| (rt, old))) {
        Ok((runtime, old)) => {
            if old > 0 {
                eprintln!("kithd: removed {old} unit(s) left by an earlier run");
            }
            runtime
        }
        Err(e) => {
            // The API still works, so resources can be inspected and edited.
            eprintln!("kithd: workloads will not run: {e}");
            let _ = stopping.changed().await;
            return;
        }
    };
    if let Err(e) = std::fs::create_dir_all(&shared.logs) {
        eprintln!("kithd: creating {}: {e}", shared.logs.display());
    }
    // After a restart this node's copy of the store is old news: a replica that was moved
    // off it while it was away is still written down as its own. So first catch up: a
    // write that has come back has everything before it.
    // ponytail: so a node that restarts while the cluster has no leader runs nothing until
    // it has one. Running from the old copy instead would be a setting, if that is wanted.
    if shared.cluster.is_some() {
        let caught_up = async {
            let nothing = || kith_store::Command::Patch { statuses: Vec::new() };
            let mut said = false;
            while let Err(e) = shared.submit(nothing()).await {
                if !std::mem::replace(&mut said, true) {
                    eprintln!("kithd: workloads start once this node has the cluster's store: {e}");
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        };
        tokio::select! {
            () = caught_up => {}
            _ = stopping.changed() => return,
        }
    }
    let mut exited = signal(SignalKind::child()).expect("installing a signal handler");
    let mut controller = Controller {
        runtime,
        logs: shared.logs.clone(),
        log_cap,
        slots: BTreeMap::new(),
        jobs: BTreeMap::new(),
        owners: None,
        report: None,
    };
    loop {
        let wake = controller.reconcile(&shared, &stopping).await;
        tokio::select! {
            _ = shared.changed.notified() => {}
            _ = exited.recv() => {}
            _ = tokio::time::sleep(wake) => {}
            _ = stopping.changed() => break,
        }
    }
    for (id, slot) in controller.slots {
        stop(&id, slot.handle);
    }
}

fn stop(id: &str, handle: Option<Handle>) {
    if let Some(Err(e)) = handle.map(Handle::delete) {
        eprintln!("kithd: {id}: {e}");
    }
}

/// `1s, 2s, 4s … 60s`.
fn backoff(failures: u32) -> Duration {
    Duration::from_secs(1 << failures.min(6)).min(Duration::from_secs(60))
}

/// What every unit id (so every log file and cgroup) of one Workload, NodeWorkload or Job starts
/// with. `_` cannot appear in a resource name, so it separates the parts.
fn id_prefix(kind: &str, namespace: &str, name: &str) -> String {
    let kind = match kind {
        "Job" => "j",
        "NodeWorkload" => "n",
        _ => "w",
    };
    format!("{kind}_{namespace}_{name}_")
}

fn unit_id(prefix: &str, replica: u32, unit: &str) -> Result<String, String> {
    let ok = !unit.is_empty()
        && unit
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    match ok {
        true => Ok(format!("{prefix}{replica}_{unit}")),
        false => Err(format!("unit name `{unit}`: use letters, digits, `-` and `.`")),
    }
}

/// The replica numbers the scheduler gave to the nodes of a NodeWorkload (not in a row:
/// a node that stops matching leaves a gap).
fn bound(resource: &Resource) -> Vec<u32> {
    let nodes = resource.status.as_ref().and_then(|s| s["nodes"].as_object());
    nodes
        .into_iter()
        .flatten()
        .filter_map(|(number, _)| number.parse().ok())
        .collect()
}

/// The template of a Workload, NodeWorkload or Job, and how many replicas (or runs) it has.
fn template_of(resource: &Resource) -> Result<(Template, u32), String> {
    let spec = resource.spec.clone();
    match resource.kind.as_str() {
        "Workload" => serde_json::from_value::<WorkloadSpec>(spec).map(|s| (s.template, s.replicas.unwrap_or(1))),
        "Job" => serde_json::from_value::<JobSpec>(spec).map(|s| (s.template, s.completions.unwrap_or(1))),
        // One copy for each node the scheduler has given a number to.
        "NodeWorkload" => {
            serde_json::from_value::<NodeWorkloadSpec>(spec).map(|s| (s.template, bound(resource).len() as u32))
        }
        kind => return Err(format!("a {kind} runs nothing")),
    }
    .map_err(|e| format!("cannot read this {}: {e}", resource.kind))
}

/// For the logs API: the id whose log files hold the output of one unit of
/// `resource`, and whether more output may still come. The id is built from the
/// stored resource, never from what the caller sent.
pub fn log_of(resource: &Resource, unit: Option<&str>, replica: u32) -> Result<(String, bool), Error> {
    let (template, replicas) = template_of(resource).map_err(Error::Invalid)?;
    let mut names = template.containers.iter().map(|c| &c.name);
    let mut names = names.by_ref().chain(template.exec.iter().map(|e| &e.name));
    let name = match unit {
        Some(unit) => names.find(|name| *name == unit),
        None => names.next(),
    };
    let key = resource.key();
    let name = name.ok_or_else(|| Error::NotFound(format!("{key} has no unit `{}`", unit.unwrap_or("?"))))?;
    let numbered = resource.status.as_ref().is_some_and(|s| s.get("nodes").is_some());
    let (has, copies) = match resource.kind.as_str() {
        // A node alone has no scheduler to number its one copy: that is copy 0.
        "NodeWorkload" if !numbered => (replica == 0, String::new()),
        "NodeWorkload" => {
            let mut numbers = bound(resource);
            numbers.sort_unstable();
            let list: Vec<_> = numbers.iter().map(u32::to_string).collect();
            let said = match list.is_empty() {
                true => ": it has no copies".to_string(),
                false => format!(": its copies are {}; pick one with --replica", list.join(", ")),
            };
            (numbers.contains(&replica), said)
        }
        _ => (replica < replicas, String::new()),
    };
    if !has {
        return Err(Error::NotFound(format!("{key} has no replica {replica}{copies}")));
    }
    let namespace = resource.metadata.namespace.as_deref().unwrap_or_default();
    let prefix = id_prefix(&resource.kind, namespace, &resource.metadata.name);
    let id = unit_id(&prefix, replica, name).map_err(Error::Invalid)?;
    let status = resource.status.as_ref();
    let more = match status.and_then(|s| s["state"].as_str()) {
        // A Job: until it is over, another run may write more.
        Some(state) => state == "running",
        None => status.is_none_or(|s| {
            let mut units = s["containers"].as_array().into_iter().flatten();
            units.any(|u| u["name"] == **name && u["replica"] == replica && u["state"] != "exited")
        }),
    };
    Ok((id, more))
}

impl Controller {
    /// One pass: returns how long the controller may sleep if nothing happens.
    async fn reconcile(&mut self, shared: &std::sync::Arc<Shared>, stopping: &watch::Receiver<bool>) -> Duration {
        // 1. What should run, from a snapshot of the store.
        // And, per workload this node may run that holds DeviceClaims, the device nodes of its own
        // Devices they come to (`granted` knows no other node's).
        // And, the same way, the Volumes of this node they mount.
        let (resources, granted, mounted): (Vec<Resource>, _, _) = {
            let file_store = shared.store.lock().expect("a handler panicked holding the store");
            let store = &file_store.store;
            let kinds = ["Workload", "NodeWorkload", "Job"];
            let resources = kinds
                .into_iter()
                .flat_map(|kind| store.list(Some(kind)))
                .cloned()
                .collect();
            let me = shared.cluster.as_ref().map(|cluster| cluster.me.name.as_str());
            let granted = me.map(|me| crate::claims::granted(store, me, Path::new("/sys")));
            let mounted = me.map(|me| crate::volumes::mounts(store, me));
            (resources, granted.unwrap_or_default(), mounted.unwrap_or_default())
        };
        let mut wanted: BTreeMap<String, Slot> = BTreeMap::new();
        // Per Workload, NodeWorkload or Job key: things to say in its status that belong to no unit.
        let mut notes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut owners = BTreeSet::new();
        // Alone, this node runs everything; in a cluster, the replicas the scheduler bound
        // to it (`nodes` in the status), and a Job when its one binding is here.
        let me = shared.cluster.as_ref().map(|cluster| cluster.me.name.as_str());
        // Per key: how many replicas the spec asks for; and the keys this node has a say on.
        let mut counts: BTreeMap<String, u32> = BTreeMap::new();
        let mut ours: BTreeSet<String> = BTreeSet::new();
        self.jobs.retain(|key, _| resources.iter().any(|r| r.key() == *key));
        for resource in &resources {
            let key = resource.key();
            let note = notes.entry(key.clone()).or_default();
            let namespace = resource.metadata.namespace.clone().unwrap_or_default();
            let prefix = id_prefix(&resource.kind, &namespace, &resource.metadata.name);
            owners.insert(prefix.clone());
            let (template, replicas) = match template_of(resource) {
                Ok(found) => found,
                Err(e) => {
                    // Every node says the same of it, so any may.
                    note.push(e);
                    ours.insert(key);
                    continue;
                }
            };
            // The device nodes its claims come to here; a workload with claims that do not come to
            // this node is not run by it (the scheduler has, or will have, put it where they do).
            // ponytail: a NodeWorkload cannot claim (a copy on every node, a device on one), and
            // alone, a node has no name for the Devices to name: both run nothing, and say so.
            let claimed = !template.device_claims.is_empty();
            let devices = granted.get(&key).cloned().unwrap_or_default();
            let allowed = !claimed || (resource.kind != "NodeWorkload" && granted.contains_key(&key));
            if claimed && resource.kind == "NodeWorkload" {
                note.push("a NodeWorkload cannot hold DeviceClaims: it runs nothing (use a Workload)".into());
            } else if claimed && me.is_none() {
                note.push("DeviceClaims need a node with a name in a cluster: this one runs nothing".into());
            }
            // The same for its volumes: it runs where they are (the scheduler has put it there), and
            // not as a NodeWorkload, nor alone (a Volume names a node).
            let volumes = mounted.get(&key).cloned().unwrap_or_default();
            let mounts = template.containers.iter().any(|c| !c.volume_mounts.is_empty());
            let allowed = allowed && (!mounts || (resource.kind != "NodeWorkload" && mounted.contains_key(&key)));
            if mounts && resource.kind == "NodeWorkload" {
                note.push("a NodeWorkload cannot mount volumes: it runs nothing (use a Workload)".into());
            } else if mounts && me.is_none() {
                note.push("volumes need a node with a name in a cluster: this one runs nothing".into());
            }
            let here = |replica: u32| {
                let bound = |status: &Value| status["nodes"][replica.to_string()] == *me.unwrap_or_default();
                allowed && (me.is_none() || resource.status.as_ref().is_some_and(bound))
            };
            if resource.kind == "Job" && !here(0) {
                // Bound here again later, it starts over, like after a restart.
                self.jobs.remove(&key);
                continue;
            }
            // The replicas of a NodeWorkload are the numbers it has nodes for. Alone, there is
            // one copy, unless a selector asks for nodes there are none of.
            let numbers: Vec<u32> = match (resource.kind.as_str(), me) {
                ("NodeWorkload", Some(_)) => bound(resource),
                ("NodeWorkload", None) if resource.spec["selector"].as_object().is_none_or(|s| s.is_empty()) => vec![0],
                ("NodeWorkload", None) => {
                    note.push("no node matches the selector: this one has no labels".into());
                    Vec::new()
                }
                _ => (0..replicas).collect(),
            };
            let replicas = if resource.kind == "NodeWorkload" {
                numbers.len() as u32
            } else {
                replicas
            };
            counts.insert(key.clone(), replicas);
            let strategy = resource.spec["strategy"].clone();
            let strategy = serde_json::from_value::<Option<Strategy>>(strategy).ok().flatten();
            if strategy == Some(Strategy::BlueGreen) {
                note.push("strategy blueGreen is not done yet: this Workload is updated rolling".into());
            }
            let rolling = resource.kind == "Workload" && strategy != Some(Strategy::Recreate);
            // Which replicas (or runs of a Job) should exist, started no sooner than when, restarted how.
            let (replicas, not_before, policy) = match resource.kind.as_str() {
                "Job" => {
                    if template.restart_policy.is_some() {
                        note.push("restartPolicy is ignored: a Job retries whole runs (`retries`)".into());
                    }
                    // The units a run really has: a name counts once, and only if it can be an id.
                    let names = template.containers.iter().map(|c| &c.name);
                    let names: BTreeSet<_> = names.chain(template.exec.iter().map(|e| &e.name)).collect();
                    let units = names.iter().filter(|name| unit_id(&prefix, 0, name).is_ok()).count();
                    let (runs, not_before) = self.job_runs(&key, resource, replicas, units);
                    // A Job retries whole runs, so a unit that exits stays exited.
                    (runs, not_before, RestartPolicy::Never)
                }
                _ => (
                    numbers.into_iter().filter(|replica| here(*replica)).collect(),
                    Instant::now(),
                    template.restart_policy.clone().unwrap_or(RestartPolicy::Always),
                ),
            };
            // (Alone, nobody else says that nothing runs.)
            if resource.kind == "Job" || !replicas.is_empty() || me.is_none() {
                ours.insert(key.clone());
            }
            let containers = template.containers.iter().cloned().map(Run::Container);
            let units: Vec<Run> = containers.chain(template.exec.iter().cloned().map(Run::Exec)).collect();
            if units.is_empty() {
                note.push("the template has nothing to run".into());
            }
            for (i, unit) in units.iter().enumerate() {
                if units[..i].iter().any(|earlier| earlier.name() == unit.name()) {
                    note.push(format!(
                        "{}: two units have this name; only the first runs",
                        unit.name()
                    ));
                }
                if let Run::Container(c) = unit {
                    note.extend(crate::probe::problems(c));
                }
            }
            let envs: Vec<_> = units
                .iter()
                .map(|unit| {
                    let env = match unit {
                        Run::Container(c) => &c.env,
                        Run::Exec(e) => &e.env,
                    };
                    let value = |var: &EnvVar| Ok((var.name.clone(), env_value(shared, &namespace, var)?));
                    env.iter().map(value).collect::<Result<Vec<_>, String>>()
                })
                .collect();
            for replica in replicas {
                for (unit, env) in units.iter().zip(&envs) {
                    match unit_id(&prefix, replica, unit.name()) {
                        // Every node that runs a replica says so, in the same words (one status).
                        Err(e) if !note.contains(&e) => note.push(e),
                        Err(_) => {}
                        Ok(id) => drop(wanted.entry(id).or_insert(Slot {
                            owner: key.clone(),
                            replica,
                            run: unit.clone(),
                            policy: policy.clone(),
                            env: env.clone(),
                            rolling,
                            probes: None,
                            devices: devices.clone(),
                            volumes: mounts_of(unit, &volumes),
                            handle: None,
                            state: "pending",
                            restarts: 0,
                            failures: 0,
                            exit_code: None,
                            message: None,
                            started: Instant::now(),
                            start_at: Some(not_before),
                        })),
                    }
                }
            }
        }

        // 2. Stop what is no longer wanted, and replace what changed: its own definition, or
        // a Secret or ConfigMap value it was started with (a value that can no longer be looked
        // up stops nothing). Scaling or relabelling a Workload leaves its running units alone.
        let mut stale: Vec<String> = Vec::new();
        // Per owner, the replicas with something to replace.
        let mut changed: BTreeMap<&str, BTreeSet<u32>> = BTreeMap::new();
        let differs = |new: &Slot, slot: &Slot| {
            // A Job's run is not started over because a value changed under it.
            let new_values = new.env.is_ok() && new.env != slot.env && !self.jobs.contains_key(&slot.owner);
            new.run != slot.run
                || new.policy != slot.policy
                || new.devices != slot.devices
                || new.volumes != slot.volumes
                || new_values
        };
        for (id, slot) in &self.slots {
            let Some(new) = wanted.get(id) else {
                stale.push(id.clone());
                continue;
            };
            if differs(new, slot) {
                changed.entry(&slot.owner).or_default().insert(slot.replica);
            }
        }
        for (owner, replicas) in changed {
            let mine = || self.slots.values().filter(move |slot| slot.owner == owner);
            let ready = |replica: u32| mine().filter(|slot| slot.replica == replica).all(Slot::ready);
            let rolling = wanted.values().any(|new| new.owner == owner && new.rolling);
            let go: Vec<u32> = if rolling {
                // One replica at a time: one that is down anyway first; a ready one only
                // while every other replica is ready, so at most one is ever down for the update.
                let pick = replicas
                    .iter()
                    .copied()
                    .find(|r| !ready(*r))
                    .or(replicas.first().copied());
                let pick = pick.expect("a changed owner has a changed replica");
                let others_ready = mine().all(|slot| slot.replica == pick || ready(slot.replica));
                if !ready(pick) || others_ready {
                    vec![pick]
                } else {
                    // (No note in a cluster: a status field only one node would say is
                    // rewritten by the others for ever.)
                    if me.is_none() {
                        let note = notes.entry(owner.into()).or_default();
                        note.push(format!(
                            "rolling update: replica {pick} is next, once the others are ready"
                        ));
                    }
                    Vec::new()
                }
            } else {
                replicas.into_iter().collect()
            };
            let ids = self.slots.iter().filter(|(id, slot)| {
                let new = wanted.get(*id);
                slot.owner == owner && go.contains(&slot.replica) && new.is_some_and(|new| differs(new, slot))
            });
            stale.extend(ids.map(|(id, _)| id.clone()));
        }
        for id in stale {
            stop(&id, self.slots.remove(&id).and_then(|slot| slot.handle));
        }
        for (id, slot) in wanted {
            self.slots.entry(id).or_insert(slot);
        }
        self.tend_logs(owners);

        // 3. Notice exits, then start whatever is due.
        // A Job's unit that ended is accounted for in step 1, and a unit that started may be
        // what a rolling update waits for in step 2: go round again at once.
        let mut job_moved = false;
        for (id, slot) in self.slots.iter_mut() {
            if *stopping.borrow() {
                return TICK; // the caller stops everything
            }
            if let Some(handle) = &mut slot.handle {
                if slot.probes.as_ref().is_some_and(|p| !p.health.borrow().live) {
                    // Killed here, noticed as an exit below or next pass, restarted like any other exit.
                    // A kill that failed is tried again next pass: the probes stay.
                    slot.message = Some("the liveness probe failed".into());
                    match handle.kill() {
                        Ok(()) => slot.probes = None,
                        Err(e) => eprintln!("kithd: {id}: {e}"),
                    }
                }
                let code = match handle.try_wait() {
                    Ok(None) => continue,
                    Ok(Some(code)) => code,
                    Err(e) => {
                        slot.message = Some(e.to_string());
                        -1
                    }
                };
                stop(id, slot.handle.take());
                slot.probes = None;
                slot.exit_code = Some(code);
                slot.failures = if slot.started.elapsed() >= SETTLED {
                    0
                } else {
                    slot.failures + 1
                };
                let again = match slot.policy {
                    RestartPolicy::Always => true,
                    RestartPolicy::OnFailure => code != 0,
                    RestartPolicy::Never => false,
                };
                slot.state = if again { "waiting" } else { "exited" };
                slot.start_at = again.then(|| Instant::now() + backoff(slot.failures.saturating_sub(1)));
                if again {
                    slot.restarts += 1;
                }
                job_moved |= self.jobs.contains_key(&slot.owner);
            }
            if slot.start_at.is_some_and(|at| at <= Instant::now()) {
                let mut stop_now = stopping.clone();
                let started = tokio::select! {
                    started = start(&self.runtime, &self.logs, id, slot) => started,
                    // A pull can take minutes; shutting down does not wait for it.
                    _ = stop_now.changed() => return TICK,
                };
                // A cached image starts without ever waiting; let the API answer between starts.
                tokio::task::yield_now().await;
                match started {
                    Ok(handle) => {
                        slot.handle = Some(handle);
                        (slot.state, slot.message, slot.start_at, slot.started) =
                            ("running", None, None, Instant::now());
                        if let Run::Container(c) = &slot.run {
                            slot.probes = crate::probe::start(shared.clone(), c);
                        }
                        job_moved = true;
                    }
                    Err(message) => {
                        (slot.state, slot.message) = ("failed", Some(message));
                        slot.start_at = Some(Instant::now() + backoff(slot.failures));
                        slot.failures += 1;
                        job_moved |= self.jobs.contains_key(&slot.owner);
                    }
                }
            }
        }

        // What exec units forked and left behind is ours to collect, now that every unit's own exit has been.
        let mains: Vec<i32> = self
            .slots
            .values()
            .filter_map(|s| s.handle.as_ref())
            .map(Handle::pid)
            .collect();
        kith_runtime::reap_orphans(&mains);

        // 4. Report.
        let mut statuses = Vec::new();
        let node = shared.members.me();
        for (key, notes) in notes {
            let mine: Vec<&Slot> = self.slots.values().filter(|slot| slot.owner == key).collect();
            let units: Vec<Value> = mine
                .iter()
                .map(|slot| {
                    let mut c = json!({ "name": slot.run.name(), "replica": slot.replica, "state": slot.state, "ready": slot.ready(), "restarts": slot.restarts });
                    if let Some(code) = slot.exit_code {
                        c["exitCode"] = json!(code);
                    }
                    if let Some(message) = &slot.message {
                        c["message"] = json!(message);
                    }
                    c
                })
                .collect();
            let mut status = match self.jobs.get(&key) {
                Some(job) => {
                    let mut status = json!({
                        "state": job.outcome.unwrap_or("running"),
                        "succeeded": job.succeeded.len(),
                        "failed": job.failed,
                        "observedRevision": job.revision,
                        "containers": units,
                    });
                    if let Some(message) = &job.message {
                        status["message"] = json!(message);
                    }
                    status
                }
                // `ready` is counted in the store, over what every node says (kith_store::reported).
                // Everything else here has to follow from the spec: other nodes say it too.
                None => json!({ "replicas": counts.get(&key).copied().unwrap_or(0), "containers": units }),
            };
            if !notes.is_empty() {
                status["notes"] = json!(notes);
            }
            // It may have been deleted while this pass ran; the next pass stops its units.
            let file_store = shared.store.lock().expect("a handler panicked holding the store");
            let Some(live) = file_store.store.get(&key).map(|live| live.status.as_ref()) else {
                continue;
            };
            // What runs elsewhere is for its node to say; this one only takes back what it said.
            let said = ours.contains(&key).then_some(status);
            let units = live.and_then(|status| status["containers"].as_array());
            let spoke = units.into_iter().flatten().any(|unit| unit["node"] == *node);
            let after = kith_store::reported(live.cloned(), node, said.clone());
            if (said.is_some() || spoke) && live != Some(&after) {
                statuses.push((key, said));
            }
        }
        // Not waited for: with no leader it takes a while to fail, and the units cannot
        // wait that long. What is not reported now still differs on the next pass.
        if !statuses.is_empty() && self.report.as_ref().is_none_or(|report| report.is_finished()) {
            let (shared, node) = (shared.clone(), node.to_string());
            self.report = Some(tokio::spawn(async move {
                if let Err(e) = shared.submit(kith_store::Command::Report { node, statuses }).await {
                    eprintln!("kithd: saving status: {e}");
                }
            }));
        }

        if job_moved {
            return Duration::ZERO;
        }
        let next = self.slots.values().filter_map(|slot| slot.start_at).min();
        next.map_or(TICK, |at| at.saturating_duration_since(Instant::now()).min(TICK))
    }

    /// Move one Job along: account for the runs that ended since the last pass, and
    /// say which runs should exist now and from when. A run is one replica of the
    /// template; it succeeds when every unit exits 0 and fails as soon as one does not
    /// (or cannot start). `retries` failed runs are forgiven; one more fails the Job.
    fn job_runs(&mut self, key: &str, resource: &Resource, completions: u32, units: usize) -> (Vec<u32>, Instant) {
        let spec: JobSpec = serde_json::from_value(resource.spec.clone()).expect("read once already");
        let revision = resource.metadata.revision;
        let job = self.jobs.entry(key.into()).or_insert_with(|| {
            // After a restart: a Job that had finished stays finished.
            let status = resource.status.clone().unwrap_or_default();
            let outcome = match status["state"].as_str() {
                _ if status["observedRevision"].as_u64() != revision => None,
                Some("succeeded") => Some("succeeded"),
                Some("failed") => Some("failed"),
                _ => None,
            };
            let done = outcome.map_or(0, |_| status["succeeded"].as_u64().unwrap_or(0) as u32);
            Progress {
                revision,
                succeeded: (0..done).collect(),
                failed: outcome.map_or(0, |_| status["failed"].as_u64().unwrap_or(0) as u32),
                began: Instant::now(),
                retry_at: Instant::now(),
                outcome,
                message: status["message"]
                    .as_str()
                    .filter(|_| outcome.is_some())
                    .map(String::from),
            }
        });
        let mine = |slots: &BTreeMap<String, Slot>, run: Option<u32>| -> Vec<String> {
            let of_run = |slot: &&Slot| slot.owner == key && run.is_none_or(|run| slot.replica == run);
            let ids = slots.iter().filter(|(_, slot)| of_run(slot)).map(|(id, _)| id.clone());
            ids.collect()
        };
        if job.revision != revision {
            // Applied again with changes: it runs again.
            for id in mine(&self.slots, None) {
                stop(&id, self.slots.remove(&id).and_then(|slot| slot.handle));
            }
            *job = Progress {
                revision,
                succeeded: BTreeSet::new(),
                failed: 0,
                began: Instant::now(),
                retry_at: Instant::now(),
                outcome: None,
                message: None,
            };
        }
        if units == 0 && job.outcome.is_none() {
            (job.outcome, job.message) = (Some("failed"), Some("the template has nothing that can run".into()));
        }
        if job.outcome.is_some() {
            return (Vec::new(), Instant::now());
        }
        let runs: BTreeSet<u32> = self
            .slots
            .values()
            .filter(|s| s.owner == key)
            .map(|s| s.replica)
            .collect();
        for run in runs {
            let ids = mine(&self.slots, Some(run));
            let slots = || ids.iter().map(|id| &self.slots[id]);
            let failed = slots().find(|s| s.state == "failed" || (s.state == "exited" && s.exit_code != Some(0)));
            if let Some(culprit) = failed {
                job.failed += 1;
                job.retry_at = Instant::now() + backoff(job.failed - 1);
                let why = culprit.message.clone();
                let why = why.unwrap_or_else(|| format!("exited with code {}", culprit.exit_code.unwrap_or(-1)));
                job.message = Some(format!("run {run}, {}: {why}", culprit.run.name()));
            } else if ids.len() == units && slots().all(|s| s.state == "exited") {
                job.succeeded.insert(run);
            } else {
                continue; // still going
            }
            for id in ids {
                stop(&id, self.slots.remove(&id).and_then(|slot| slot.handle));
            }
        }
        let timeout = spec.timeout_seconds.map(|s| Duration::from_secs(s.into()));
        if job.failed > spec.retries.unwrap_or(JOB_RETRIES) {
            job.outcome = Some("failed");
        } else if timeout.is_some_and(|limit| job.began.elapsed() >= limit) {
            job.outcome = Some("failed");
            job.message = Some(format!("not finished after {} s", spec.timeout_seconds.unwrap_or(0)));
        } else if job.succeeded.len() as u32 >= completions {
            (job.outcome, job.message) = (Some("succeeded"), None);
        }
        if job.outcome.is_some() {
            for id in mine(&self.slots, None) {
                stop(&id, self.slots.remove(&id).and_then(|slot| slot.handle));
            }
            return (Vec::new(), Instant::now());
        }
        let parallelism = spec.parallelism.unwrap_or(1).max(1) as usize;
        let open = (0..completions).filter(|run| !job.succeeded.contains(run));
        (open.take(parallelism).collect(), job.retry_at)
    }

    /// Keep the log directory bounded: a file over the cap is moved aside (one old
    /// copy is kept), and the files of Workloads, NodeWorkloads and Jobs that are gone are removed.
    fn tend_logs(&mut self, owners: BTreeSet<String>) {
        // ponytail: checked once a pass, so a file can pass the cap by what its unit
        // writes in one tick (10 s), and output written between the copy and the
        // truncation is lost. A pipe per unit would bound both; not needed yet.
        for id in self.slots.keys() {
            for stream in ["out", "err"] {
                let path = self.logs.join(format!("{id}.{stream}"));
                if std::fs::metadata(&path).is_ok_and(|meta| meta.len() > self.log_cap) {
                    // The unit holds the file open in append mode, so it carries on at the new end.
                    let rotated = std::fs::copy(&path, self.logs.join(format!("{id}.{stream}.1")))
                        .and_then(|_| File::options().write(true).open(&path)?.set_len(0));
                    if let Err(e) = rotated {
                        eprintln!("kithd: rotating {}: {e}", path.display());
                    }
                }
            }
        }
        if self.owners.as_ref() == Some(&owners) {
            return;
        }
        for entry in std::fs::read_dir(&self.logs).into_iter().flatten().flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // `w_namespace_name_` of `w_namespace_name_0_unit.out`.
            let prefix: String = name.split_inclusive('_').take(3).collect();
            if !owners.contains(&prefix) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        self.owners = Some(owners);
    }
}

/// The value of one environment variable, looked up in the store if it is a reference.
fn env_value(shared: &Shared, namespace: &str, var: &EnvVar) -> Result<String, String> {
    if let Some(value) = &var.value {
        return Ok(value.clone());
    }
    let (kind, key_ref) = match (&var.secret, &var.config_map) {
        (Some(key_ref), _) => ("Secret", key_ref),
        (_, Some(key_ref)) => ("ConfigMap", key_ref),
        _ => return Err(format!("env `{}` has no value", var.name)),
    };
    let key = format!("{kind}/{namespace}/{}", key_ref.name);
    let file_store = shared.store.lock().expect("a handler panicked holding the store");
    let spec = file_store
        .store
        .get(&key)
        .map(|r| r.spec.clone())
        .ok_or(format!("env `{}`: {key} does not exist", var.name))?;
    // Both kinds are `data: {key: value}`.
    let data = match kind {
        "Secret" => serde_json::from_value::<SecretSpec>(spec).map(|s| s.data),
        _ => serde_json::from_value::<ConfigMapSpec>(spec).map(|s| s.data),
    };
    let mut data = data.map_err(|e| format!("env `{}`: {key}: {e}", var.name))?;
    data.remove(&key_ref.key)
        .ok_or(format!("env `{}`: {key} has no key `{}`", var.name, key_ref.key))
}

/// What a unit mounts, from the Volumes its workload's mounts come to: only a container mounts.
fn mounts_of(unit: &Run, volumes: &BTreeMap<String, crate::volumes::Dir>) -> Vec<(crate::volumes::Dir, String, bool)> {
    let Run::Container(c) = unit else { return Vec::new() };
    let mounts = c.volume_mounts.iter();
    let found = mounts.filter_map(|m| {
        Some((
            volumes.get(&m.volume)?.clone(),
            m.path.clone(),
            m.read_only == Some(true),
        ))
    });
    found.collect()
}

async fn start(runtime: &Runtime, logs: &Path, id: &str, slot: &Slot) -> Result<Handle, String> {
    let resources = match &slot.run {
        Run::Container(c) => &c.resources,
        Run::Exec(e) => &e.resources,
    };
    let mut unit = Unit {
        env: slot.env.clone()?,
        // (An exec unit is given none: it sees all of `/dev`.)
        devices: slot.devices.clone(),
        ..Unit::default()
    };
    // The volumes' directories are made here, on the node, under the state directory (the
    // logs', parent), now and not when planned: a directory made for a replica that never starts
    // would be left behind.
    let state = logs.parent().unwrap_or(logs);
    for (dir, at, read_only) in &slot.volumes {
        let host = crate::volumes::host_dir(state, dir).map_err(|e| format!("volume {}: {e}", dir.name))?;
        unit.mounts.push(kith_runtime::Mount {
            host,
            container: at.clone(),
            read_only: *read_only,
        });
    }
    if let Some(Resources { cpu, memory, .. }) = resources {
        unit.memory_bytes = memory.as_ref().map(|q| q.value() as u64);
        unit.cpu_millis = cpu.as_ref().map(|q| (q.value() * 1000.0).round() as u64);
    }
    let log = |ext: &str| {
        let path = logs.join(format!("{id}.{ext}"));
        File::options()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("opening {}: {e}", path.display()))
    };
    let created = match &slot.run {
        Run::Container(c) => {
            (unit.command, unit.args, unit.working_dir) = (c.command.clone(), c.args.clone(), c.working_dir.clone());
            let policy = match c.pull_policy {
                None | Some(PullPolicy::IfNotPresent) => kith_runtime::PullPolicy::IfNotPresent,
                Some(PullPolicy::Always) => kith_runtime::PullPolicy::Always,
                Some(PullPolicy::Never) => kith_runtime::PullPolicy::Never,
            };
            let image = runtime.images.pull(&c.image, policy).await.map_err(|e| e.to_string())?;
            runtime.create(id, &image, &unit, log("out")?, log("err")?)
        }
        Run::Exec(e) => {
            unit.command = e.command.clone();
            runtime.exec(id, &unit, log("out")?, log("err")?)
        }
    };
    let mut handle = created.map_err(|e| e.to_string())?;
    match handle.start() {
        Ok(()) => Ok(handle),
        Err(e) => {
            stop(id, Some(handle));
            Err(e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_backoff() {
        let prefix = id_prefix("Workload", "default", "web.v2");
        assert_eq!(unit_id(&prefix, 1, "app").unwrap(), "w_default_web.v2_1_app");
        assert_eq!(id_prefix("Job", "default", "web.v2"), "j_default_web.v2_");
        for bad in ["", "a/b", "..\\x", "a_b", "a b"] {
            assert!(unit_id(&prefix, 0, bad).is_err(), "{bad:?}");
        }
        assert_eq!(backoff(0), Duration::from_secs(1));
        assert_eq!(backoff(3), Duration::from_secs(8));
        assert_eq!(backoff(40), Duration::from_secs(60));
    }

    #[test]
    fn a_node_workload_log_names_the_copies_it_has() {
        let mut resource: Resource = serde_json::from_value(serde_json::json!({
            "apiVersion": "kith.dev/v1", "kind": "NodeWorkload",
            "metadata": { "name": "x", "namespace": "default" },
            "spec": { "template": { "containers": [{ "name": "run", "image": "img" }] } },
        }))
        .unwrap();
        // No scheduler (a node alone): no `nodes`, and copy 0 is the one.
        assert!(log_of(&resource, None, 0).is_ok());
        assert!(log_of(&resource, None, 1).is_err());
        // Sparse numbers: the error says which exist.
        resource.status = Some(serde_json::json!({ "nodes": { "2": "b", "1": "a" } }));
        assert!(log_of(&resource, None, 1).is_ok());
        let Err(Error::NotFound(said)) = log_of(&resource, None, 0) else {
            panic!("copy 0 found")
        };
        assert!(
            said.ends_with("has no replica 0: its copies are 1, 2; pick one with --replica"),
            "{said}"
        );
    }
}
