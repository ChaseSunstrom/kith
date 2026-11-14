//! The controller: makes the containers and exec units on this node match the
//! `Workload`s, `NodeWorkload`s and `Job`s in the store, restarts them when they exit, and reports
//! what it sees in each one's status.
//!
// ponytail: this node's share of each (the scheduler says which replicas are its own).
// Not handled, and said so in the status where it matters: exec probes. A container's
// ports only name them (units share the host's network).
// A rolling update replaces one replica at a time, the old one stopped before the
// new one starts: unit ids (cgroup, log file) are per replica, so two generations
// of a replica cannot run side by side. Images are pulled one at a time.
// A Job's progress lives in memory: kithd restarted under a running Job starts it over.

use crate::Shared;
use kith_api::Resource;
use kith_api::kinds::{
    ConfigMapSpec, Container, EnvVar, ExecUnit, Field, JobSpec, NodeWorkloadSpec, PullPolicy, Resources, RestartPolicy,
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

/// A ConfigMap or a Secret one of a container's mounts is the files of.
#[derive(Clone, PartialEq)]
struct Files {
    /// Which of its container's `volumeMounts`.
    mount: usize,
    secret: bool,
    /// A path inside the mount, to what is in the file.
    data: BTreeMap<String, String>,
    mode: u32,
}

/// One unit of one replica of one Workload, of one copy of a NodeWorkload, or of one run of a Job.
struct Slot {
    /// Store key of the Workload, NodeWorkload or Job.
    owner: String,
    /// The revision of its owner it runs: the one it was made for, or a later one that
    /// would run it no differently.
    revision: Option<u64>,
    replica: u32,
    run: Run,
    policy: RestartPolicy,
    /// Its environment with every Secret and ConfigMap reference looked up, or why that failed.
    /// A unit whose looked-up values changed is replaced like one whose definition changed.
    env: Result<Vec<(String, String)>, String>,
    /// Replace changed replicas one at a time (a Workload unless its strategy is `recreate`).
    rolling: bool,
    probes: Option<crate::probe::Probes>,
    /// The pod it is of, where its template says `pod`: the pod's id (`pod_of`) and its host name.
    pod: Option<(String, String)>,
    /// Its template's notes: a unit whose notes changed is replaced, as one whose definition changed.
    notes: BTreeMap<String, String>,
    /// The device nodes its DeviceClaims give it (a changed set replaces the unit, like a changed value).
    devices: Vec<PathBuf>,
    /// The seat whose directory it has at `/run/seat`, and whether to read only.
    seat: Option<(String, bool)>,
    /// What its containers mount: the Volume's directory, where in the container, and read-only
    /// (a changed one replaces the unit, as a changed value does). An exec unit mounts nothing.
    volumes: Vec<(crate::volumes::Dir, String, bool)>,
    /// The ConfigMaps and Secrets it mounts as files, as they are, or why one cannot be
    /// read. One that changes is written again where it is mounted: nothing is started over.
    //
    // ponytail: each unit keeps what its maps hold, to tell when one changed; a hash of
    // it when maps mounted by many units are big enough to show in kithd's memory.
    files: Result<Vec<Files>, String>,
    /// One of its template's `initContainers`: run to its end, once.
    init: bool,
    /// How many init containers of its replica end well before it is started.
    after: u32,
    /// Not started yet for that: waiting, with no time to be woken at.
    held: bool,
    /// What its cgroup was last told for its node's seats (memory guaranteed, CPU limit), if
    /// anything; none again each time it starts.
    tuned: Option<(Option<u64>, Option<u64>)>,
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
        match self.init {
            // (What ran first and ended well holds nothing back.)
            true => self.done(),
            false => self.state == "running" && self.probes.as_ref().is_none_or(|p| p.health.borrow().ready),
        }
    }

    /// An init container that ran to its end, well.
    fn done(&self) -> bool {
        self.init && self.state == "exited" && self.exit_code == Some(0)
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

/// May a container that was given the device nodes `was` be given `now` as it runs, with
/// no new start? Where input devices alone came or went, it had one when it started (so
/// its `/dev/input` is there), and each it loses is in `gone`: no longer on the node.
fn in_place(was: &BTreeSet<&PathBuf>, now: &BTreeSet<&PathBuf>, gone: &[&PathBuf]) -> bool {
    let plugged = |path: &&PathBuf| kith_runtime::plugged(path);
    was != now
        && was.iter().any(plugged)
        && was.symmetric_difference(now).all(plugged)
        && was.difference(now).all(|path| gone.contains(path))
}

/// Is a unit that ended with `code` started again? One that runs first (`init`) is run
/// until it ends well, and then no more.
fn again(policy: &RestartPolicy, init: bool, code: i32) -> bool {
    match (policy, init) {
        (RestartPolicy::Never, _) => false,
        (RestartPolicy::OnFailure, _) | (_, true) => code != 0,
        (RestartPolicy::Always, false) => true,
    }
}

/// How long a unit that ended waits before it is started again, having ended `failures`
/// times in a row (a unit that ran a minute starts the count over, and is started at once
/// that time too): not at all the first time, then as [`backoff`] has it for one that
/// keeps ending.
fn restart_wait(failures: u32) -> Duration {
    failures.checked_sub(2).map_or(Duration::ZERO, backoff)
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

/// The id of the pod that replica `replica` of the resource with the store key `owner` is,
/// where its template says `pod`: what its units' ids start with.
pub fn pod_of(owner: &str, replica: u32) -> String {
    let mut parts = owner.split('/');
    let (kind, namespace, name) = (parts.next(), parts.next(), parts.next());
    let prefix = id_prefix(
        kind.unwrap_or_default(),
        namespace.unwrap_or_default(),
        name.unwrap_or_default(),
    );
    format!("{prefix}{replica}")
}

fn unit_id(prefix: &str, replica: u32, unit: &str) -> Result<String, String> {
    // (Not `.` or `..`: a unit's name is a directory's too, under its replica's.)
    let ok = !unit.is_empty()
        && unit.bytes().any(|b| b != b'.')
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
    // (One that runs first is asked for by its name; without a name it is not the one meant.)
    let mut names = template.units().chain(template.init_containers.iter().map(|c| &c.name));
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
        // And what its seats ask of each workload's cgroups here (a guarantee, or holding back).
        let (resources, granted, mounted, tunes): (Vec<Resource>, _, _, _) = {
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
            let tunes = me.map(|me| crate::seats::tunes(store, me));
            (
                resources,
                granted.unwrap_or_default(),
                mounted.unwrap_or_default(),
                tunes.unwrap_or_default(),
            )
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
            let crate::claims::Granted { devices, seat } = granted.get(&key).cloned().unwrap_or_default();
            let allowed = !claimed || (resource.kind != "NodeWorkload" && granted.contains_key(&key));
            if claimed && resource.kind == "NodeWorkload" {
                note.push("a NodeWorkload cannot hold DeviceClaims: it runs nothing (use a Workload)".into());
            } else if claimed && me.is_none() {
                note.push("DeviceClaims need a node with a name in a cluster: this one runs nothing".into());
            }
            // The same for its volumes: it runs where they are (the scheduler has put it there), and
            // not as a NodeWorkload, nor alone (a Volume names a node).
            let volumes = mounted.get(&key).cloned().unwrap_or_default();
            // (A ConfigMap, a Secret and a scratch are on whichever node the replica is.)
            let mut mounts = template.containers().flat_map(|c| &c.volume_mounts);
            let mounts = mounts.any(|mount| mount.volume.is_some());
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
                    let first = template.init_containers.iter().map(|c| &c.name);
                    let names: BTreeSet<_> = template.units().chain(first).collect();
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
            // (Those that run first are first: `after` below counts them.)
            let inits = template.init_containers.len();
            let containers = template.containers().cloned().map(Run::Container);
            // (A VM is the process of its hypervisor: an exec unit, with the command line made here.)
            // A confidential template on a node whose processor encrypts no guest: none of it.
            let guard = crate::vm::confidential(template.confidential, crate::vm::guard(Path::new("/sys")));
            let vms = template
                .vms
                .iter()
                .map(|vm| Run::Exec(crate::vm::exec(vm, &devices, guard.clone().ok().flatten())));
            let mut units: Vec<Run> = containers
                .chain(template.exec.iter().cloned().map(Run::Exec))
                .chain(vms)
                .collect();
            if let Err(why) = &guard {
                note.push(why.clone());
                units.clear();
            } else if units.is_empty() {
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
                    let from = match unit {
                        Run::Container(c) => env_from(shared, &namespace, c)?,
                        Run::Exec(_) => Vec::new(),
                    };
                    let said = env.iter().map(value).collect::<Result<Vec<_>, String>>()?;
                    Ok(from.into_iter().chain(said).collect::<Vec<_>>())
                })
                .collect();
            let files: Vec<_> = units.iter().map(|unit| files_of(shared, &namespace, unit)).collect();
            for replica in replicas {
                for (at, ((unit, env), files)) in units.iter().zip(&envs).zip(&files).enumerate() {
                    // What a variable says of the replica itself (its address is known when
                    // it starts: `start`).
                    let mut env = env.clone();
                    let fields = match unit {
                        Run::Container(c) => &c.env,
                        Run::Exec(e) => &e.env,
                    };
                    for var in fields {
                        let value = match var.field {
                            Some(Field::Name) => format!("{}-{replica}", resource.metadata.name),
                            Some(Field::Namespace) => namespace.clone(),
                            Some(Field::Node) => shared.members.me().to_string(),
                            Some(Field::Address) | None => continue,
                        };
                        let named = env.iter_mut().flatten().find(|(name, _)| *name == var.name);
                        if let Some((_, was)) = named {
                            *was = value;
                        }
                    }
                    match unit_id(&prefix, replica, unit.name()) {
                        // Every node that runs a replica says so, in the same words (one status).
                        Err(e) if !note.contains(&e) => note.push(e),
                        Err(_) => {}
                        Ok(id) => drop(wanted.entry(id).or_insert(Slot {
                            owner: key.clone(),
                            revision: resource.metadata.revision,
                            replica,
                            run: unit.clone(),
                            policy: policy.clone(),
                            env,
                            rolling,
                            probes: None,
                            pod: (template.pod == Some(true)).then(|| {
                                let name = &resource.metadata.name;
                                (pod_of(&key, replica), format!("{name}-{replica}"))
                            }),
                            notes: template.annotations.clone(),
                            devices: devices.clone(),
                            seat: seat.clone(),
                            volumes: mounts_of(unit, &volumes),
                            files: files.clone(),
                            init: at < inits,
                            after: at.min(inits) as u32,
                            held: false,
                            tuned: None,
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
        //
        // But an input device plugged in or pulled (a controller, a keyboard) is given to,
        // or taken from, a container as it runs: a session is not started over for that.
        // (One that is still on the node and no longer the container's is another matter:
        // what the container has open stays open until it is stopped.)
        for (id, slot) in &mut self.slots {
            let (Some(new), Some(handle)) = (wanted.get(id), &slot.handle) else {
                continue;
            };
            let (was, now): (BTreeSet<&PathBuf>, BTreeSet<&PathBuf>) =
                (slot.devices.iter().collect(), new.devices.iter().collect());
            let gone: Vec<&PathBuf> = was.difference(&now).copied().filter(|path| !path.exists()).collect();
            if !in_place(&was, &now, &gone) || !matches!(slot.run, Run::Container(_)) {
                continue;
            }
            let given = now.difference(&was).try_for_each(|path| handle.plug(path));
            let taken = given.and_then(|()| was.difference(&now).try_for_each(|path| handle.unplug(path)));
            match taken {
                Ok(()) => {
                    eprintln!("kithd: {id}: its input devices changed, and it has them as it runs");
                    slot.devices = new.devices.clone();
                }
                // (Started over, as before: by the comparison below.)
                Err(e) => eprintln!("kithd: {id}: {e}"),
            }
        }
        let mut stale: Vec<String> = Vec::new();
        fn of(slot: &Slot) -> (&str, u32) {
            (slot.owner.as_str(), slot.replica)
        }
        // Per owner, the replicas with something to replace.
        let mut changed: BTreeMap<&str, BTreeSet<u32>> = BTreeMap::new();
        let differs = |new: &Slot, slot: &Slot| {
            // A Job's run is not started over because a value changed under it.
            let new_values = new.env.is_ok() && new.env != slot.env && !self.jobs.contains_key(&slot.owner);
            new.run != slot.run
                || new.pod != slot.pod
                || new.notes != slot.notes
                || new.policy != slot.policy
                || new.devices != slot.devices
                || new.seat != slot.seat
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
        // A replica with something replaced is one made anew: what runs first runs again.
        let anew: BTreeSet<(&str, u32)> = stale.iter().filter_map(|id| self.slots.get(id)).map(of).collect();
        let first = self
            .slots
            .iter()
            .filter(|(_, slot)| slot.init && anew.contains(&of(slot)));
        let first: Vec<String> = first
            .map(|(id, _)| id.clone())
            .filter(|id| !stale.contains(id))
            .collect();
        stale.extend(first);
        for id in stale {
            stop(&id, self.slots.remove(&id).and_then(|slot| slot.handle));
        }
        let state = self.logs.parent().unwrap_or(&self.logs).to_path_buf();
        for (id, new) in wanted {
            match self.slots.get_mut(&id) {
                Some(slot) if !differs(&new, slot) => {
                    (slot.revision, slot.init, slot.after) = (new.revision, new.init, new.after);
                    // A ConfigMap or a Secret that changed: written again where it is mounted,
                    // all its files at once, and nothing is started over. (One that can no
                    // longer be read changes nothing, as with a value.)
                    if new.files.is_ok() && new.files != slot.files {
                        let files = new.files.as_deref().unwrap_or_default();
                        match slot.handle.as_ref().map(|_| write_files(&state, &id, slot, files)) {
                            // (Not written: tried again at the next pass.)
                            Some(Err(e)) => eprintln!("kithd: {id}: {e}"),
                            _ => slot.files = new.files,
                        }
                    }
                }
                Some(_) => {}
                None => drop(self.slots.insert(id, new)),
            }
        }
        // What a replica mounted of its own goes with it.
        let replicas = self.slots.values().map(|slot| pod_of(&slot.owner, slot.replica));
        let memory = crate::files::memory_dir();
        let bases: Vec<&Path> = [Some(state.as_path()), memory.as_deref()]
            .into_iter()
            .flatten()
            .collect();
        crate::files::sweep(&bases, &replicas.collect());
        // A pod none of whose units is wanted any more is let go, its network with it.
        let pods: BTreeSet<&str> = self
            .slots
            .values()
            .filter_map(|slot| Some(slot.pod.as_ref()?.0.as_str()))
            .collect();
        let made = shared.pods.lock();
        made.expect("nothing panics holding the pods")
            .keep(|pod| pods.contains(pod));
        self.tend_logs(owners);
        // What this node mounts from the others: a start below mounts it, and what no unit
        // here mounts any more is let go.
        let mesh = shared.cluster.as_ref();
        let mesh = mesh.map(|cluster| (crate::mesh::prefix(&cluster.me.ca), cluster.me.name.as_str()));
        if let Some((_, me)) = mesh {
            let mounts = self
                .slots
                .values()
                .flat_map(|slot| slot.volumes.iter().map(|(dir, _, _)| dir));
            let theirs: Vec<_> = mounts.filter(|dir| dir.node != me).collect();
            crate::share::release(self.logs.parent().unwrap_or(&self.logs), &theirs);
        }

        // 3. Notice exits, then start whatever is due.
        // A Job's unit that ended is accounted for in step 1, and a unit that started may be
        // what a rolling update waits for in step 2: go round again at once.
        let mut job_moved = false;
        // Per replica: how many of its init containers have run to their end, well.
        let mut first: BTreeMap<(String, u32), u32> = BTreeMap::new();
        for slot in self.slots.values().filter(|slot| slot.done()) {
            *first.entry((slot.owner.clone(), slot.replica)).or_default() += 1;
        }
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
                let again = again(&slot.policy, slot.init, code);
                slot.state = if again { "waiting" } else { "exited" };
                slot.start_at = again.then(|| Instant::now() + restart_wait(slot.failures));
                if again {
                    slot.restarts += 1;
                }
                // (What waited for an init container starts in the pass after this one.)
                job_moved |= self.jobs.contains_key(&slot.owner) || slot.init;
            }
            let ended = first.get(&(slot.owner.clone(), slot.replica)).copied().unwrap_or(0);
            slot.held = slot.start_at.is_some() && ended < slot.after;
            if slot.held {
                slot.message = Some(match slot.init {
                    true => "waiting for the init containers before it".into(),
                    false => "waiting for its init containers".into(),
                });
            } else if slot.start_at.is_some_and(|at| at <= Instant::now()) {
                let mut stop_now = stopping.clone();
                let started = tokio::select! {
                    started = start(shared, &self.runtime, &self.logs, mesh, id, slot) => started,
                    // A pull can take minutes; shutting down does not wait for it.
                    _ = stop_now.changed() => return TICK,
                };
                // A cached image starts without ever waiting; let the API answer between starts.
                tokio::task::yield_now().await;
                match started {
                    Ok(handle) => {
                        slot.handle = Some(handle);
                        slot.tuned = None;
                        (slot.state, slot.message, slot.start_at, slot.started) =
                            ("running", None, None, Instant::now());
                        if let Run::Container(c) = &slot.run {
                            let pod = slot.pod.as_ref().map(|(pod, _)| pod.clone());
                            slot.probes = crate::probe::start(shared.clone(), c, pod);
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

        // What the node's seats ask of the running units: the holder's guarantee, and a sliver of
        // CPU for who yields while the seat is busy. Said again only when it changes; a unit
        // never told anything is left as the runtime made it.
        for (id, slot) in self.slots.iter_mut() {
            let Some(handle) = &slot.handle else { continue };
            let asked = tunes.get(&slot.owner).copied();
            if asked.is_none() && slot.tuned.is_none() {
                continue;
            }
            let (guaranteed, held_back) = asked.unwrap_or_default();
            let resources = match &slot.run {
                Run::Container(c) => &c.resources,
                Run::Exec(e) => &e.resources,
            };
            let own = resources.as_ref().and_then(|r| r.cpu.as_ref());
            let own = own.map(|q| (q.value() * 1000.0).round() as u64);
            let sliver = crate::seats::YIELD_MILLIS;
            let cpu = if held_back {
                Some(own.map_or(sliver, |own| own.min(sliver)))
            } else {
                own
            };
            if slot.tuned != Some((guaranteed, cpu)) {
                for refused in kith_runtime::tune(&handle.cgroup, guaranteed, cpu) {
                    eprintln!("kithd: {id}: its seat's arrangement is not all in place: {refused}");
                }
                slot.tuned = Some((guaranteed, cpu));
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
                    let mut c = json!({ "name": slot.run.name(), "replica": slot.replica, "state": slot.state, "ready": slot.ready(), "restarts": slot.restarts, "revision": slot.revision });
                    if let Some(code) = slot.exit_code {
                        c["exitCode"] = json!(code);
                    }
                    if let Some(message) = &slot.message {
                        c["message"] = json!(message);
                    }
                    let pods = shared.pods.lock().expect("nothing panics holding the pods");
                    if let Some(address) = slot.pod.as_ref().and_then(|(pod, _)| pods.address(pod)) {
                        c["address"] = json!(address);
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
        let waiting = self.slots.values().filter(|slot| !slot.held);
        let next = waiting.filter_map(|slot| slot.start_at).min();
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

/// What the ConfigMap (or, `secret`, the Secret) `name` of `namespace` holds.
fn map_of(shared: &Shared, namespace: &str, secret: bool, name: &str) -> Result<BTreeMap<String, String>, String> {
    let kind = if secret { "Secret" } else { "ConfigMap" };
    let key = format!("{kind}/{namespace}/{name}");
    let file_store = shared.store.lock().expect("a handler panicked holding the store");
    let found = file_store.store.get(&key).map(|r| r.spec.clone());
    let spec = found.ok_or(format!("{key} does not exist"))?;
    // Both kinds are `data: {key: value}`.
    let data = match secret {
        true => serde_json::from_value::<SecretSpec>(spec).map(|s| s.data),
        false => serde_json::from_value::<ConfigMapSpec>(spec).map(|s| s.data),
    };
    data.map_err(|e| format!("{key}: {e}"))
}

/// The value of one environment variable, looked up in the store if it is a reference.
fn env_value(shared: &Shared, namespace: &str, var: &EnvVar) -> Result<String, String> {
    if let Some(value) = &var.value {
        return Ok(value.clone());
    }
    let (secret, key_ref) = match (&var.secret, &var.config_map) {
        (Some(key_ref), _) => (true, key_ref),
        (_, Some(key_ref)) => (false, key_ref),
        // (Something of the replica: said per replica, by who plans it.)
        _ if var.field.is_some() => return Ok(String::new()),
        _ => return Err(format!("env `{}` has no value", var.name)),
    };
    let mut data = map_of(shared, namespace, secret, &key_ref.name).map_err(|e| format!("env `{}`: {e}", var.name))?;
    data.remove(&key_ref.key).ok_or(format!(
        "env `{}`: {} has no key `{}`",
        var.name, key_ref.name, key_ref.key
    ))
}

/// The variables a container's `envFrom` comes to: every key of each map, in their order.
fn env_from(shared: &Shared, namespace: &str, c: &Container) -> Result<Vec<(String, String)>, String> {
    let mut env = Vec::new();
    for from in &c.env_from {
        let (secret, name) = match (&from.secret, &from.config_map) {
            (Some(name), _) => (true, name),
            (_, Some(name)) => (false, name),
            _ => continue,
        };
        let data = map_of(shared, namespace, secret, name).map_err(|e| format!("envFrom: {e}"))?;
        let prefix = from.prefix.as_deref().unwrap_or_default();
        // (As Kubernetes: a key that cannot name a variable is passed over.)
        let names = |(key, _): &(String, String)| !key.is_empty() && !key.contains(['=', '\0']);
        env.extend(
            data.into_iter()
                .filter(names)
                .map(|(key, value)| (format!("{prefix}{key}"), value)),
        );
    }
    Ok(env)
}

/// The ConfigMaps and Secrets a unit mounts as files, as they are now: only a container mounts.
fn files_of(shared: &Shared, namespace: &str, unit: &Run) -> Result<Vec<Files>, String> {
    let Run::Container(c) = unit else { return Ok(Vec::new()) };
    let mut files = Vec::new();
    for (mount, m) in c.volume_mounts.iter().enumerate() {
        let (secret, name) = match (&m.secret, &m.config_map) {
            (Some(name), _) => (true, name),
            (_, Some(name)) => (false, name),
            _ => continue,
        };
        let at = |e: String| format!("mount at `{}`: {e}", m.path);
        let mut data = map_of(shared, namespace, secret, name).map_err(at)?;
        if !m.items.is_empty() {
            let item = |(key, file): (&String, &String)| {
                let content = data.get(key).ok_or(at(format!("{name} has no key `{key}`")))?;
                Ok((file.clone(), content.clone()))
            };
            data = m.items.iter().map(item).collect::<Result<_, String>>()?;
        }
        // (Checked when applied: three octal digits, or four that start with 0.)
        let mode = m.mode.as_deref().map_or(Ok(0o444), |mode| u32::from_str_radix(mode, 8));
        let mode = mode.map_err(|e| at(format!("mode: {e}")))?;
        files.push(Files {
            mount,
            secret,
            data,
            mode,
        });
    }
    Ok(files)
}

/// Where the files of the mount `mount` of the unit `id` are written: in memory for a
/// Secret, on the state disk for a ConfigMap, under its replica's directory either way.
fn files_dir(state: &Path, id: &str, slot: &Slot, files: &Files) -> Result<PathBuf, String> {
    let base = match files.secret {
        true => crate::files::memory()?,
        false => state.to_path_buf(),
    };
    let replica = crate::files::of(&base, &pod_of(&slot.owner, slot.replica)).map_err(|e| e.to_string())?;
    let unit = id.rsplit('_').next().unwrap_or(id);
    Ok(replica.join("files").join(unit).join(files.mount.to_string()))
}

/// Write each of `files` where the unit `id` mounts it.
fn write_files(state: &Path, id: &str, slot: &Slot, files: &[Files]) -> Result<(), String> {
    for files in files {
        let dir = files_dir(state, id, slot, files)?;
        crate::files::write(&dir, &files.data, files.mode).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(())
}

/// What a unit mounts, from the Volumes its workload's mounts come to: only a container mounts.
fn mounts_of(unit: &Run, volumes: &BTreeMap<String, crate::volumes::Dir>) -> Vec<(crate::volumes::Dir, String, bool)> {
    let Run::Container(c) = unit else { return Vec::new() };
    let mounts = c.volume_mounts.iter();
    let found = mounts.filter_map(|m| {
        Some((
            volumes.get(m.volume.as_ref()?)?.clone(),
            m.path.clone(),
            m.read_only == Some(true),
        ))
    });
    found.collect()
}

/// `mesh`: the cluster's mesh and this node's name, for a volume another node serves.
async fn start(
    shared: &Shared,
    runtime: &Runtime,
    logs: &Path,
    mesh: Option<(std::net::Ipv6Addr, &str)>,
    id: &str,
    slot: &Slot,
) -> Result<Handle, String> {
    let resources = match &slot.run {
        Run::Container(c) => &c.resources,
        Run::Exec(e) => &e.resources,
    };
    let mut unit = Unit {
        env: slot.env.clone()?,
        // (An exec unit is given none: it sees all of `/dev`. A PCI device held for a VM is
        // no device node: a container gets nothing of it.)
        devices: slot
            .devices
            .iter()
            .filter(|path| !path.starts_with(crate::vm::PCI))
            .cloned()
            .collect(),
        ..Unit::default()
    };
    // The volumes' directories are made here, on the node, under the state directory (the
    // logs', parent), now and not when planned: a directory made for a replica that never starts
    // would be left behind.
    let state = logs.parent().unwrap_or(logs);
    for (dir, at, read_only) in &slot.volumes {
        // (Only a shared volume of another node ever gets here: `volumes::mounts`.)
        let host = match mesh.filter(|(_, me)| *me != dir.node) {
            Some((prefix, me)) => crate::share::mount(state, dir, prefix, me).await,
            None => crate::volumes::host_dir(state, dir),
        };
        let host = host.map_err(|e| format!("volume {}: {e}", dir.name))?;
        unit.mounts.push(kith_runtime::Mount {
            host,
            container: at.clone(),
            read_only: *read_only,
            // (Not a directory of the host's that an admin named: that one is theirs. Nor
            // what it only reads: another workload's user may be who writes it.)
            give: dir.namespace != crate::volumes::SYSTEM && !*read_only,
        });
    }
    // What it mounts that is no Volume: its maps' files, and directories of the replica's own.
    if let Run::Container(c) = &slot.run {
        let files = slot.files.clone()?;
        write_files(state, id, slot, &files)?;
        for (at, mount) in c.volume_mounts.iter().enumerate() {
            let why = |e: std::io::Error| format!("mount at `{}`: {e}", mount.path);
            let host = if let Some(files) = files.iter().find(|files| files.mount == at) {
                let dir = files_dir(state, id, slot, files)?;
                match &mount.sub_path {
                    Some(one) => crate::files::one(&dir, one)
                        .map_err(|e| why(std::io::Error::other(format!("subPath `{one}`: {e}"))))?,
                    None => dir,
                }
            } else if let Some(name) = &mount.scratch {
                let base = match mount.memory {
                    Some(true) => crate::files::memory()?,
                    _ => state.to_path_buf(),
                };
                crate::files::scratch(&base, &pod_of(&slot.owner, slot.replica), name).map_err(why)?
            } else {
                continue;
            };
            unit.mounts.push(kith_runtime::Mount {
                host,
                container: mount.path.clone(),
                // (A map's files are kithd's to write, never the container's.)
                read_only: mount.read_only == Some(true) || mount.scratch.is_none(),
                // A scratch is anyone's as it is made; a map's files are made the container's
                // user's, who may be the only one its mode lets read them.
                give: mount.scratch.is_none(),
            });
        }
    }
    if let Some((seat, client)) = &slot.seat {
        // The seat's own directory: its session puts its sockets there, and its apps find
        // them. It is the session's user's alone, so an app is that user or has nothing.
        let host = state.join("seats").join(seat);
        let made = std::fs::create_dir_all(&host)
            .and_then(|()| std::fs::set_permissions(&host, std::os::unix::fs::PermissionsExt::from_mode(0o700)));
        made.map_err(|e| format!("seat {seat}: {e}"))?;
        unit.mounts.push(kith_runtime::Mount {
            host,
            container: "/run/seat".into(),
            read_only: *client,
            give: !*client,
        });
    }
    // Its address, for a variable that asks: its pod's on the mesh, or else its node's.
    let mut address = mesh.map(|(prefix, me)| std::net::IpAddr::from(kith_mesh::node_address(prefix, me)));
    if let Some((pod, hostname)) = &slot.pod {
        unit.as_image = true;
        // (Only root can make a network: elsewhere the pod shares the node's.)
        if nix::unistd::getuid().is_root() {
            let net = mesh.map(|(prefix, me)| kith_mesh::node_net(prefix, me));
            let namespace = slot.owner.split('/').nth(1).unwrap_or_default();
            let mut pods = shared.pods.lock().expect("nothing panics holding the pods");
            let given = pods.given(state, pod, namespace, hostname, net)?;
            unit.netns = Some(given.netns);
            unit.hostname = Some(given.hostname);
            address = pods.address(pod).or(address);
            for (file, at) in given.files.into_iter().zip(["/etc/resolv.conf", "/etc/hosts"]) {
                unit.mounts.push(kith_runtime::Mount {
                    host: file,
                    container: at.into(),
                    read_only: true,
                    give: false,
                });
            }
        }
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
            unit.user = c.run_as_user;
            (unit.non_root, unit.drop) = (c.run_as_non_root == Some(true), c.drop_capabilities.clone());
            let address = address.unwrap_or(std::net::Ipv4Addr::LOCALHOST.into()).to_string();
            for var in c.env.iter().filter(|var| var.field == Some(Field::Address)) {
                unit.env.retain(|(name, _)| *name != var.name);
                unit.env.push((var.name.clone(), address.clone()));
            }
            unit.writable = !c.read_only_root.unwrap_or(slot.pod.is_none());
            if let Some(seccomp) = &c.seccomp {
                (unit.unconfined, unit.allow) = (seccomp.unconfined == Some(true), seccomp.allow.clone());
            }
            unit.nested = c.user_namespaces == Some(true);
            let policy = match c.pull_policy {
                None | Some(PullPolicy::IfNotPresent) => kith_runtime::PullPolicy::IfNotPresent,
                Some(PullPolicy::Always) => kith_runtime::PullPolicy::Always,
                Some(PullPolicy::Never) => kith_runtime::PullPolicy::Never,
            };
            if let Some(why) = not_its_image(runtime.images.local.as_ref(), &slot.owner, &c.image) {
                return Err(why);
            }
            let image = runtime
                .images
                .pull_signed(&c.image, policy, &c.signed_by)
                .await
                .map_err(|e| e.to_string())?;
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

/// Why a unit of `owner` (`Kind/namespace/name`) is not given `image`: it names an Image
/// of the cluster that is another namespace's. An Image is a packed Volume, and the node
/// keeps what it has pulled by its reference, whoever it was pulled for: so this is asked
/// before every pull, and before the node looks at what it holds.
fn not_its_image(local: Option<&kith_runtime::Local>, owner: &str, image: &str) -> Option<String> {
    let theirs = local?.namespace(image)?;
    // (`Kind/namespace/name`: what has no namespace has no Images.)
    let mine = match owner.split('/').collect::<Vec<_>>()[..] {
        [_, mine, _] => mine,
        _ => "",
    };
    (theirs != mine).then(|| {
        format!(
            "image `{image}` is the Image of namespace `{theirs}`: what runs in `{mine}` runs the Images of `{mine}`"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unit runs the cluster Images of its own namespace and no other's, by either name
    /// of the node's registry; what is not that registry's is nothing to this.
    #[test]
    fn an_image_of_another_namespace_is_not_run() {
        let local = kith_runtime::Local {
            port: 5000,
            password: String::new(),
            certificate: std::sync::Arc::new(|| Ok(Vec::new())),
        };
        let refused = |owner: &str, image: &str| not_its_image(Some(&local), owner, image);
        let by_digest = format!("127.0.0.1:5000/team/hello@sha256:{}", "a".repeat(64));
        for own in ["localhost:5000/team/hello:1", &by_digest] {
            assert_eq!(refused("Workload/team/web", own), None, "{own}");
            for other in ["Workload/default/web", "Job/team2/build", "NodeWorkload/tea/agent"] {
                let why = refused(other, own).unwrap_or_else(|| panic!("{other} was given {own}"));
                assert!(why.contains("namespace `team`") && why.contains(own), "{why}");
            }
        }
        for elsewhere in [
            "docker.io/team/hello:1",
            "localhost:5001/team/hello:1",
            "registry.example:5000/team/hello:1",
            "busybox",
        ] {
            assert_eq!(refused("Workload/default/web", elsewhere), None, "{elsewhere}");
        }
        // What has no namespace is given no namespace's Image, whatever it is called.
        for none in ["Workload/team", "team", "", "Workload/team/web/more"] {
            assert!(refused(none, "localhost:5000/team/hello:1").is_some(), "{none:?}");
        }
        // A node that serves no registry has no Images to keep apart.
        assert_eq!(
            not_its_image(None, "Workload/default/web", "localhost:5000/team/hello:1"),
            None
        );
    }

    /// The names a template may allow back are the names the runtime's filter knows.
    #[test]
    fn seccomp_names_in_the_api_are_the_filters() {
        let filters: Vec<&str> = kith_runtime::REFUSED.iter().map(|(name, _)| *name).collect();
        assert_eq!(kith_api::kinds::REFUSED_CALLS, filters);
    }

    #[test]
    fn input_devices_alone_come_and_go_as_a_container_runs() {
        let paths = |names: &[&str]| names.iter().map(PathBuf::from).collect::<Vec<_>>();
        let fits = |was: &[&str], now: &[&str], gone: &[&str]| {
            let (was, now, gone) = (paths(was), paths(now), paths(gone));
            in_place(
                &was.iter().collect(),
                &now.iter().collect(),
                &gone.iter().collect::<Vec<_>>(),
            )
        };
        let (key, pad, card) = ("/dev/input/event0", "/dev/input/event5", "/dev/dri/card0");
        assert!(fits(&[key, card], &[key, pad, card], &[]), "one plugged in");
        assert!(fits(&[key, pad], &[key], &[pad]), "one pulled");
        // Still on the node, and no longer this container's: only a new start takes it away.
        assert!(!fits(&[key, pad], &[key], &[]));
        // Nothing changed; no /dev/input to make one in; another kind of device.
        assert!(!fits(&[key], &[key], &[]));
        assert!(!fits(&[card], &[card, pad], &[]));
        assert!(!fits(&[key], &[key, card], &[]));
    }

    #[test]
    fn ids_and_backoff() {
        let prefix = id_prefix("Workload", "default", "web.v2");
        assert_eq!(unit_id(&prefix, 1, "app").unwrap(), "w_default_web.v2_1_app");
        assert_eq!(id_prefix("Job", "default", "web.v2"), "j_default_web.v2_");
        for bad in ["", "a/b", "..\\x", "a_b", "a b"] {
            assert!(unit_id(&prefix, 0, bad).is_err(), "{bad:?}");
        }
        // What runs first is run until it ends well, whatever the others are; a Job's never again.
        use RestartPolicy::{Always, Never, OnFailure};
        let started_again = [(Always, false), (Always, true), (OnFailure, true), (Never, true)]
            .map(|(policy, init)| (again(&policy, init, 0), again(&policy, init, 1)));
        assert_eq!(
            started_again,
            [(true, true), (false, true), (false, true), (false, false)]
        );
        assert!(unit_id("w_a_b_", 0, "..").is_err() && unit_id("w_a_b_", 0, "a.b").is_ok());
        assert_eq!(backoff(0), Duration::from_secs(1));
        assert_eq!(backoff(3), Duration::from_secs(8));
        assert_eq!(backoff(40), Duration::from_secs(60));
    }

    /// A container that ends is started again at once the first time, and one that keeps
    /// ending waits longer each time, up to a minute.
    #[test]
    fn the_first_restart_has_no_backoff_and_the_wait_grows() {
        let waits: Vec<u64> = [0, 1, 2, 3, 4, 40]
            .map(|failures| restart_wait(failures).as_secs())
            .into();
        assert_eq!(waits, [0, 0, 1, 2, 4, 60]);
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
        // What ran first is asked for by its name, and is not the unit meant without one.
        let mut first = resource.clone();
        first.spec["template"]["initContainers"] = serde_json::json!([{ "name": "first", "image": "img" }]);
        assert_eq!(log_of(&first, Some("first"), 0).unwrap().0, "n_default_x_0_first");
        assert_eq!(log_of(&first, None, 0).unwrap().0, "n_default_x_0_run");
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
