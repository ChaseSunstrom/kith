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

mod prune;
mod storage;

use crate::Shared;
use futures_util::FutureExt;
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Notify, watch};

/// How long a unit must have run for its next restart to be immediate again.
const SETTLED: Duration = Duration::from_secs(60);
/// With nothing else to wake it, the controller still looks around this often. A store change
/// or a child exit wakes it sooner (`until_woken`). What this covers is a Job's next run and a
/// failed status report, retried on the next pass. Neither is on the measured paths (T-0185).
const TICK: Duration = Duration::from_secs(10);
/// How long a unit whose stop failed with processes left waits before its stop is tried again: a try
/// can block for about 100 ms, on the async thread.
const STOP_RETRY: Duration = Duration::from_secs(2);
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
    /// The Exit its pod leaves by, where its template names one.
    exit: Option<String>,
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
    /// Its handle could not be deleted while processes remain: it is still stopping, and its
    /// id and device nodes are held back from new units until a later pass finds it gone.
    leaving: bool,
    /// Stopped to be replaced or dropped (stale or no longer wanted): once it is gone its slot goes,
    /// and what is wanted starts afresh. Not set for one that ended on its own (see `kept_once_gone`).
    drop: bool,
    /// When its stop was last tried: one still stopping is tried again at most every `STOP_RETRY`.
    tried: Option<Instant>,
    /// Its job run was counted as ended (a run stopped by its revision is counted once).
    accounted: bool,
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
    /// Its last run was ended for what its pod wrote (`replace`): its next run says so.
    replaced: bool,
}

impl Slot {
    fn ready(&self) -> bool {
        if self.leaving {
            return false;
        }
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
    /// Bytes the state disk keeps free: under them the pod that wrote the most is replaced.
    /// `None` for the default (`storage::default_reserve`); 0 for none.
    reserve: Option<u64>,
    /// The count of what pods wrote outside their volumes, on its way.
    count: Option<Job<Counted>>,
    /// When the last count ended.
    counted: Option<Instant>,
    /// The state disk is under its reserve with no pod to replace for it, and it was said.
    low: bool,
    /// The pods replaced for what they wrote, when, and the removal of what they wrote once no run
    /// from before is left: till it is done they are not counted and none is replaced for the reserve.
    replacing: BTreeMap<String, (Instant, Option<Job<()>>)>,
    /// The limited pods whose last count did not finish (`storage::missed`).
    missed: BTreeSet<String>,
    /// Set as kithd stops: a count or removal under way gives up, so the state disk can go.
    stop: std::sync::Arc<AtomicBool>,
    /// How long an image no unit uses is kept (`--image-grace`); zero keeps every image.
    image_grace: Duration,
    /// The removal of unused images on its way, and what it will say; an error is the look at
    /// them failing, which removes nothing.
    pruning: Option<Job<Result<Vec<String>, String>>>,
    /// When the last one ended.
    pruned: Option<Instant>,
    /// The boot and wall clocks as the last one began, to tell a clock set forward.
    clocks: Option<(Duration, SystemTime)>,
    /// No image is unused from before this: this kithd's start (what came before, and the time
    /// it was down, is not known), moved to now by a clock set forward, or back past it.
    floor: SystemTime,
    /// What the last failed look said, said once until it changes.
    look_failed: Option<String>,
}

/// Free bytes on the state disk, its reserve, and the pods as counted.
type Counted = (u64, u64, Vec<storage::Pod>);

/// What a thread of its own is doing (a blocking walk of the disk), to be had once it is done.
struct Job<T> {
    began: Instant,
    waiting: tokio::sync::oneshot::Receiver<T>,
    /// It was said to have run a minute.
    slow: bool,
}

/// How long a job runs before it is said not to have ended: a thread cannot be killed.
const HUNG: Duration = Duration::from_secs(60);

pub async fn run(
    shared: std::sync::Arc<Shared>,
    runtime: kith_runtime::Result<Runtime>,
    log_cap: u64,
    reserve: Option<u64>,
    image_grace: Duration,
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
    let disk = nix::sys::statvfs::statvfs(shared.logs.parent().unwrap_or(&shared.logs));
    if let (Some(reserve), Ok(disk)) = (reserve, disk)
        && reserve > disk.blocks() * disk.fragment_size()
    {
        eprintln!(
            "kithd: --storage-reserve {reserve} is more than the state disk holds, {} bytes: the disk is always under it, and the pod that wrote the most is replaced each count",
            disk.blocks() * disk.fragment_size()
        );
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
        reserve,
        count: None,
        counted: None,
        low: false,
        replacing: BTreeMap::new(),
        missed: BTreeSet::new(),
        stop: std::sync::Arc::new(AtomicBool::new(false)),
        image_grace,
        pruning: None,
        pruned: None,
        clocks: None,
        floor: SystemTime::now(),
        look_failed: None,
    };
    loop {
        let wake = controller.reconcile(&shared, &stopping).await;
        if until_woken(&shared.changed, &mut exited, wake, &mut stopping).await {
            break;
        }
    }
    controller.stop.store(true, Ordering::Relaxed);
    for (id, slot) in &mut controller.slots {
        stop(id, slot).await;
    }
    // A count or removal holds directories of the state disk open: it is waited for, a little,
    // so the disk can be unmounted once kithd is gone.
    let counts = controller
        .count
        .into_iter()
        .map(|job| ("the storage count".to_string(), job.waiting.map(drop).boxed()));
    let removals = controller.replacing.into_iter().filter_map(|(pod, (_, job))| {
        Some((
            format!("the removal of pod {pod}'s old files"),
            job?.waiting.map(drop).boxed(),
        ))
    });
    // An image's tree is one `remove_dir_all`, which the stop does not cut.
    let pruning = controller.pruning.into_iter().map(|job| {
        (
            "the removal of unused images".to_string(),
            job.waiting.map(drop).boxed(),
        )
    });
    let left = wait_for_storage(counts.chain(removals).chain(pruning).collect(), Duration::from_secs(2)).await;
    if !left.is_empty() {
        eprintln!(
            "kithd: gave up waiting after 2 s for {}: the state disk may be busy; what a removal left (the scratch and the scratch.* levels beside it, each listed once, at most four directories open, never `..`, never across a file system) goes as trees of their own at its pod's next count, or with its replica directory once the pod is gone; an image half removed is out of the images already, and goes at the next look at them",
            left.join(", ")
        );
    }
}

/// Waits for the jobs (named for the log) to be done, up to `bound`: the names of those that
/// were not. A removal looks at the stop every 1,024 steps, so it is soon.
async fn wait_for_storage(
    jobs: Vec<(String, futures_util::future::BoxFuture<'static, ()>)>,
    bound: Duration,
) -> Vec<String> {
    let mut left: BTreeSet<String> = jobs.iter().map(|(what, _)| what.clone()).collect();
    let mut running: futures_util::stream::FuturesUnordered<_> =
        jobs.into_iter().map(|(what, job)| job.map(move |()| what)).collect();
    let deadline = tokio::time::Instant::now() + bound;
    while let Ok(Some(what)) = tokio::time::timeout_at(deadline, futures_util::StreamExt::next(&mut running)).await {
        left.remove(&what);
    }
    left.into_iter().collect()
}

/// Waits for the next pass: a store change or a child exit ends the wait at once, and `wake`
/// is the longest it lasts. Returns true when the node is stopping.
async fn until_woken(
    changed: &Notify,
    exited: &mut tokio::signal::unix::Signal,
    wake: Duration,
    stopping: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        _ = changed.notified() => false,
        _ = exited.recv() => false,
        _ = tokio::time::sleep(wake) => false,
        _ = stopping.changed() => true,
    }
}

/// Deletes a unit's handle. One whose processes remain keeps it: the slot is `leaving` (its id
/// and devices held back) until a later pass finds it gone. A cleanup-only failure holds nothing.
async fn stop(id: &str, slot: &mut Slot) {
    let Some(handle) = slot.handle.take() else {
        slot.leaving = false;
        return;
    };
    slot.tried = Some(Instant::now());
    let deleted = delete(handle).await;
    stopped(id, slot, deleted);
}

/// `handle.delete()` on a thread of its own: a delete kills the unit and then waits, asleep
/// between tries, for its cgroup to empty, and on kithd's thread the API, the proxy and DNS
/// would wait with it. Where the node has no thread to give, it runs here after all.
async fn delete(handle: Handle) -> Result<(), kith_runtime::Undeleted> {
    let cell = std::sync::Arc::new(std::sync::Mutex::new(Some(handle)));
    let (theirs, (done, said)) = (cell.clone(), tokio::sync::oneshot::channel());
    let spawned = std::thread::Builder::new().name("stop".into()).spawn(move || {
        let handle = theirs.lock().expect("nothing panics holding it").take();
        if let Some(handle) = handle {
            let _ = done.send(handle.delete());
        }
    });
    if spawned.is_ok()
        && let Ok(deleted) = said.await
    {
        return deleted;
    }
    let handle = cell.lock().expect("nothing panics holding it").take();
    handle
        .expect("the stop's thread took the handle and answered nothing: it panicked")
        .delete()
}

/// What a stop leaves in its slot once the delete was tried with `deleted`.
fn stopped(id: &str, slot: &mut Slot, deleted: Result<(), kith_runtime::Undeleted>) {
    match deleted {
        Ok(()) => {
            // Gone: the "stopping" message of an earlier pass is over.
            if slot.message.as_deref().is_some_and(|m| m.starts_with("stopping: ")) {
                slot.message = None;
            }
        }
        Err(undeleted) => {
            slot.handle = undeleted.handle.map(|handle| *handle);
            if slot.handle.is_some() {
                slot.probes = None;
                if slot.state == "running" {
                    slot.state = "stopping";
                }
                let message = format!(
                    "stopping: {}; its devices and name are held until it is gone",
                    undeleted.error
                );
                // Said once, not on every pass while it stays stuck.
                if slot.message.as_ref() != Some(&message) {
                    eprintln!("kithd: {id}: {}", undeleted.error);
                }
                slot.message = Some(message);
            } else {
                eprintln!("kithd: {id}: {}", undeleted.error);
                // (Its processes are gone: only the cleanup failed, and nothing is held.)
                if slot.message.as_deref().is_some_and(|m| m.starts_with("stopping: ")) {
                    slot.message = None;
                }
            }
        }
    }
    slot.leaving = slot.handle.is_some();
}

/// Stops the unit `id` if it has one. Its slot is kept while it is `leaving`, and once it is gone
/// unless it is dropped: `drop` marks one stopped to be replaced or dropped (see `kept_once_gone`).
async fn stop_unit(slots: &mut BTreeMap<String, Slot>, id: &str, drop: bool) {
    if let Some(mut slot) = slots.remove(id) {
        slot.drop |= drop;
        stop(id, &mut slot).await;
        if slot.leaving || kept_once_gone(slot.drop) {
            slots.insert(id.to_string(), slot);
        }
    }
}

/// Whether a slot whose handle is gone is kept. One stopped to be replaced or dropped is not: what
/// is wanted starts afresh. One that ended on its own is, with its state, exit code and restarts
/// (and its backoff), so it is not run again.
fn kept_once_gone(drop: bool) -> bool {
    !drop
}

/// Whether the running container `slot` takes the devices of `new` as it runs, with no new start
/// (see `in_place`). Then a difference in devices alone is no reason to replace it: a plug that is
/// refused is tried again at the next pass, and the unit keeps running.
fn plugs_in_place(slot: &Slot, new: &Slot) -> bool {
    let running = slot.handle.is_some() && !slot.leaving && matches!(slot.run, Run::Container(_));
    running && devices_in_place(slot, new)
}

/// Whether `new` differs from `slot` in input devices alone, all of which the container takes as it
/// runs (see `in_place`). Only a running container can be given them (see `plugs_in_place`).
fn devices_in_place(slot: &Slot, new: &Slot) -> bool {
    let (was, now): (BTreeSet<&PathBuf>, BTreeSet<&PathBuf>) =
        (slot.devices.iter().collect(), new.devices.iter().collect());
    let gone: Vec<&PathBuf> = was.difference(&now).copied().filter(|path| !path.exists()).collect();
    in_place(&was, &now, &gone)
}

/// Why a unit `id` of `owner`, with the device nodes `devices`, waits: a unit still stopping has its
/// id, and the device nodes it had (its processes may still hold them). Units of one owner share one
/// set of devices, so a sibling's hold is the owner's own and does not hold it back. `None` when
/// nothing is held.
fn held_by_leaving(
    id: &str,
    owner: &str,
    devices: &[PathBuf],
    leaving: &[(String, String, Vec<PathBuf>)],
) -> Option<String> {
    leaving.iter().find_map(|(other, other_owner, held)| {
        if other == id {
            return Some(format!("waiting: {other} is still stopping: its processes remain"));
        }
        if other_owner == owner {
            return None;
        }
        devices
            .iter()
            .find(|path| held.contains(path))
            .map(|path| format!("waiting: {other} is still stopping and has {}", path.display()))
    })
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
pub(crate) fn template_of(resource: &Resource) -> Result<(Template, u32), String> {
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
        // (Where this node's policy names the classes of Device it hands out, a Device is what
        // the node finds itself: looked for before the store is held.)
        let node_policy = crate::policy::get();
        let me = shared.cluster.as_ref().map(|cluster| cluster.me.name.as_str());
        let found = me.filter(|_| node_policy.names_devices());
        let found = found.map(|me| crate::devices::scan(Path::new("/sys"), me));
        let (resources, granted, mounted, tunes, found): (Vec<Resource>, _, _, _, _) = {
            let file_store = shared.store.lock().expect("a handler panicked holding the store");
            let store = &file_store.store;
            let found = found.map(|found| crate::devices::as_found(store, &found));
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
                found,
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
            let crate::claims::Granted { devices, seat, classes } = granted.get(&key).cloned().unwrap_or_default();
            let allowed = !claimed || (resource.kind != "NodeWorkload" && granted.contains_key(&key));
            // What this node's own policy refuses of it is not run here, whoever wrote it and
            // whatever the store says (docs/adr-privilege.md): said where a replica is this
            // node's to run.
            let mut refused = node_policy.refuses(&template, !crate::vm::pci(&devices).is_empty());
            let kept = |(name, class): &&(String, kith_api::kinds::DeviceClass)| {
                !node_policy.device(class) || found.as_ref().is_some_and(|found| !found.contains(name))
            };
            let kept: Vec<&str> = classes.iter().filter(kept).map(|(name, _)| name.as_str()).collect();
            if !kept.is_empty() {
                refused.push(format!(
                    "this node's policy hands out no Device of the class of {}, or it is not what this node finds its own hardware to be (`--node-policy devices=…` where the node's kithd is started names the classes it does)",
                    kept.join(", ")
                ));
            }
            let allowed = allowed && refused.is_empty();
            let nodes = resource.status.as_ref().and_then(|status| status["nodes"].as_object());
            if me.is_none_or(|me| nodes.is_some_and(|nodes| nodes.values().any(|node| node == me))) {
                note.extend(refused);
            }
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
            // And a pod that leaves by an exit starts only with its tunnel up here (fail closed).
            let ready = template
                .exit
                .as_deref()
                .map(|name| crate::exits::ready(shared, name, &namespace));
            if let Some(Err(why)) = &ready {
                let mut nodes = resource
                    .status
                    .iter()
                    .flat_map(|s| s["nodes"].as_object())
                    .flat_map(|n| n.values());
                if me.is_none() || nodes.any(|node| *node == *me.unwrap_or_default()) {
                    note.push(why.clone());
                }
            }
            let allowed = allowed && !matches!(ready, Some(Err(_)));
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
                    let (runs, not_before) = self.job_runs(&key, resource, replicas, units).await;
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
                            exit: template.exit.clone().filter(|_| template.pod == Some(true)),
                            notes: template.annotations.clone(),
                            devices: devices.clone(),
                            seat: seat.clone(),
                            volumes: mounts_of(unit, &volumes),
                            files: files.clone(),
                            init: at < inits,
                            after: at.min(inits) as u32,
                            held: false,
                            leaving: false,
                            drop: false,
                            tried: None,
                            accounted: false,
                            tuned: None,
                            handle: None,
                            state: "pending",
                            restarts: 0,
                            failures: 0,
                            exit_code: None,
                            message: None,
                            started: Instant::now(),
                            start_at: Some(not_before),
                            replaced: false,
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
        // A unit still stopping is asked again first: once it is gone (and removed), what waits
        // for its id or its devices is started in this same pass.
        let stopping_now: Vec<String> = self
            .slots
            .iter()
            .filter(|(_, s)| s.leaving)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &stopping_now {
            // Its main may have died while the cgroup would not go: collect it, or it stays a zombie
            // that `reap_orphans` cannot pass.
            if let Some(handle) = self
                .slots
                .get_mut(id)
                .and_then(|slot| slot.handle.as_mut())
                .filter(|h| !h.is_reaped())
            {
                let _ = handle.try_wait();
            }
            // A stop that failed is tried again after STOP_RETRY: each try can block for a while.
            if self
                .slots
                .get(id)
                .and_then(|slot| slot.tried)
                .is_some_and(|at| at.elapsed() < STOP_RETRY)
            {
                continue;
            }
            // Dropped when nothing is wanted under its id: once gone it is not adopted as an exit.
            stop_unit(&mut self.slots, id, !wanted.contains_key(id)).await;
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
            // (Input devices plugged in or out do not replace a running container: see plugs_in_place.)
            let devices = new.devices != slot.devices && !plugs_in_place(slot, new);
            new.run != slot.run
                || new.pod != slot.pod
                || new.exit != slot.exit
                || new.notes != slot.notes
                || new.policy != slot.policy
                || devices
                || new.seat != slot.seat
                || new.volumes != slot.volumes
                || new_values
        };
        for (id, slot) in &self.slots {
            if slot.leaving {
                continue;
            }
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
                slot.owner == owner
                    && !slot.leaving
                    && go.contains(&slot.replica)
                    && new.is_some_and(|new| differs(new, slot))
            });
            stale.extend(ids.map(|(id, _)| id.clone()));
        }
        // A replica with something replaced is one made anew: what runs first runs again.
        let anew: BTreeSet<(&str, u32)> = stale.iter().filter_map(|id| self.slots.get(id)).map(of).collect();
        let first = self
            .slots
            .iter()
            .filter(|(_, slot)| slot.init && !slot.leaving && anew.contains(&of(slot)));
        let first: Vec<String> = first
            .map(|(id, _)| id.clone())
            .filter(|id| !stale.contains(id))
            .collect();
        stale.extend(first);
        for id in stale {
            stop_unit(&mut self.slots, &id, true).await;
        }
        // The input devices of running units, taken or given as they run. What was taken away
        // first, from every unit: a refused removal replaces its unit (the container may still
        // hold a node whose number the kernel gives to another device), and that unit is
        // stopped before anything is given, so what it still holds is seen below.
        let mut replace: Vec<String> = Vec::new();
        let mut changed: BTreeSet<String> = BTreeSet::new();
        for (id, slot) in &mut self.slots {
            let (Some(new), Some(handle), false) = (wanted.get(id), &slot.handle, slot.leaving) else {
                continue;
            };
            if !plugs_in_place(slot, new) {
                continue;
            }
            let gone: Vec<PathBuf> = slot
                .devices
                .iter()
                .filter(|path| !new.devices.contains(path))
                .cloned()
                .collect();
            for path in gone {
                match handle.unplug(&path) {
                    // (The slot keeps the node until what came is plugged below: whether a unit
                    // takes devices as it runs is asked of what it started with.)
                    Ok(()) => drop(changed.insert(id.clone())),
                    Err(e) => {
                        eprintln!("kithd: {id}: {e}: it is replaced");
                        replace.push(id.clone());
                        break;
                    }
                }
            }
        }
        for id in &replace {
            stop_unit(&mut self.slots, id, true).await;
        }
        // What a unit still stopping holds (one stopped this pass that did not go included) is
        // not given to another, and what waits for it says so in its status.
        let leaving_now: Vec<(String, String, Vec<PathBuf>)> = self
            .slots
            .iter()
            .filter(|(_, s)| s.leaving)
            .map(|(id, s)| (id.clone(), s.owner.clone(), s.devices.clone()))
            .collect();
        for (id, slot) in &mut self.slots {
            let (Some(new), Some(handle), false) = (wanted.get(id), &slot.handle, slot.leaving) else {
                continue;
            };
            if replace.contains(id) || !plugs_in_place(slot, new) {
                continue;
            }
            let added: Vec<PathBuf> = new
                .devices
                .iter()
                .filter(|path| !slot.devices.contains(path))
                .cloned()
                .collect();
            if let Some(why) = held_by_leaving(id, &slot.owner, &added, &leaving_now) {
                slot.message = Some(why);
                continue;
            }
            match added.iter().try_for_each(|path| handle.plug(path)) {
                Ok(()) => {
                    if !added.is_empty() || changed.contains(id) {
                        eprintln!("kithd: {id}: its input devices changed, and it has them as it runs");
                    }
                    slot.devices = new.devices.clone();
                    slot.message = None;
                }
                // Still running: the comparison above does not replace it for this, so the plug
                // is tried again at the next pass.
                Err(e) => {
                    eprintln!("kithd: {id}: {e}");
                    slot.message = Some(format!("waiting: {e}"));
                }
            }
        }
        let state = self.logs.parent().unwrap_or(&self.logs).to_path_buf();
        for (id, new) in wanted {
            match self.slots.get_mut(&id) {
                Some(slot) if slot.leaving => {}
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

        // What pods wrote outside their volumes: one past its limit, or the biggest writer on a
        // disk under its reserve, is killed here and noticed as an exit below.
        self.tend_storage(shared, &state);
        // Images no unit uses, once each unit there is has its slot and before any starts.
        self.tend_images(shared, &state);

        // 3. Notice exits, then start whatever is due.
        // A Job's unit that ended is accounted for in step 1, and a unit that started may be
        // what a rolling update waits for in step 2: go round again at once.
        let mut job_moved = false;
        // Per replica: how many of its init containers have run to their end, well.
        let mut first: BTreeMap<(String, u32), u32> = BTreeMap::new();
        for slot in self.slots.values().filter(|slot| slot.done()) {
            *first.entry((slot.owner.clone(), slot.replica)).or_default() += 1;
        }
        // The units still stopping, with their devices: what is due waits for them (see
        // held_by_leaving). One that starts stopping in this pass is added as it does.
        let mut leaving: Vec<(String, String, Vec<PathBuf>)> = self
            .slots
            .iter()
            .filter(|(_, slot)| slot.leaving)
            .map(|(id, slot)| (id.clone(), slot.owner.clone(), slot.devices.clone()))
            .collect();
        for (id, slot) in self.slots.iter_mut() {
            if *stopping.borrow() {
                return TICK; // the caller stops everything
            }
            if slot.leaving {
                // Asked again by step 2, not here: it has no process left to watch.
                slot.held = true;
                continue;
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
                stop(id, slot).await;
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
                if slot.leaving {
                    // Its processes remain: it is stopping, and what is due waits for it.
                    leaving.push((id.clone(), slot.owner.clone(), slot.devices.clone()));
                    slot.held = true;
                    continue;
                }
            }
            let ended = first.get(&(slot.owner.clone(), slot.replica)).copied().unwrap_or(0);
            slot.held = slot.start_at.is_some() && ended < slot.after;
            if slot.held {
                slot.message = Some(match slot.init {
                    true => "waiting for the init containers before it".into(),
                    false => "waiting for its init containers".into(),
                });
            } else if slot.start_at.is_some_and(|at| at <= Instant::now()) {
                if let Some(why) = held_by_leaving(id, &slot.owner, &slot.devices, &leaving) {
                    slot.held = true;
                    slot.message = Some(why);
                    continue;
                }
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
                        // Why it was replaced for what it wrote stays said while it runs again, once.
                        let replaced = std::mem::take(&mut slot.replaced);
                        let replaced = slot
                            .message
                            .take()
                            .filter(|m| replaced && m.starts_with(storage::REPLACED));
                        (slot.state, slot.message, slot.start_at, slot.started) =
                            ("running", replaced, None, Instant::now());
                        if let Run::Container(c) = &slot.run {
                            let pod = slot.pod.as_ref().map(|(pod, _)| pod.clone());
                            slot.probes = crate::probe::start(shared.clone(), c, pod);
                        }
                        job_moved = true;
                    }
                    Err(message) => {
                        let message = match slot.leaving {
                            true => format!("{message}; its devices and name are held until it is gone"),
                            false => message,
                        };
                        (slot.state, slot.message) = ("failed", Some(message));
                        slot.start_at = Some(Instant::now() + backoff(slot.failures));
                        slot.failures += 1;
                        job_moved |= self.jobs.contains_key(&slot.owner);
                        if slot.leaving {
                            leaving.push((id.clone(), slot.owner.clone(), slot.devices.clone()));
                            slot.held = true;
                        }
                    }
                }
            }
        }

        // What the node's seats ask of the running units: the holder's guarantee, and a sliver of
        // CPU for who yields while the seat is busy. Said again only when it changes; a unit
        // never told anything is left as the runtime made it.
        for (id, slot) in self.slots.iter_mut() {
            let Some(handle) = slot.handle.as_ref().filter(|_| !slot.leaving) else {
                continue;
            };
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
        // (A reaped one has no zombie left under its pid to wait for.)
        let mains: Vec<i32> = self
            .slots
            .values()
            .filter_map(|s| s.handle.as_ref())
            .filter(|h| !h.is_reaped())
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
                    // Where kithd is root: whether its users are the node's (no range of its own:
                    // a NodeWorkload, a pod, devices, or a volume no id-mapped mount takes).
                    if let (Run::Container(_), Some(handle)) = (&slot.run, &slot.handle)
                        && nix::unistd::getuid().is_root()
                    {
                        c["hostUsers"] = json!(handle.range().is_none());
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
            // In parts a control node takes from a worker, the largest report too.
            self.report = Some(tokio::spawn(async move {
                for report in crate::raft::in_parts(&node, statuses) {
                    if let Err(e) = shared.submit(report).await {
                        eprintln!("kithd: saving status: {e}");
                    }
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
    async fn job_runs(
        &mut self,
        key: &str,
        resource: &Resource,
        completions: u32,
        units: usize,
    ) -> (Vec<u32>, Instant) {
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
                stop_unit(&mut self.slots, &id, true).await;
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
            // A run whose units are still stopping was counted when it ended: not again.
            if slots().any(|s| s.accounted) {
                continue;
            }
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
            for id in &ids {
                if let Some(slot) = self.slots.get_mut(id) {
                    slot.accounted = true;
                }
            }
            for id in ids {
                stop_unit(&mut self.slots, &id, true).await;
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
                stop_unit(&mut self.slots, &id, true).await;
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

    /// Counts what each pod wrote outside its volumes, at most every `TICK` after the last count
    /// ended, one count at a time and off the async threads; replaces what the last count says
    /// must go (`storage::choose`).
    fn tend_storage(&mut self, shared: &std::sync::Arc<Shared>, state: &Path) {
        let replicas = state.join(crate::files::REPLICAS);
        // A replaced pod's old runs gone, what they wrote outside the scratch made anew goes.
        let (slots, stop) = (&self.slots, &self.stop);
        self.replacing.retain(|pod, (at, removal)| {
            let runs: Vec<(bool, Instant)> = slots
                .values()
                .filter(|slot| slot.handle.is_some() && pod_of(&slot.owner, slot.replica) == *pod)
                .map(|slot| (slot.leaving, slot.started))
                .collect();
            if storage::replacing(&runs, *at) {
                return true;
            }
            if removal.is_none() {
                let (replica, stop) = (replicas.join(pod), stop.clone());
                *removal = Job::start("storage", &shared.changed, move || storage::sweep(&replica, &stop));
            }
            // (No thread for it: tried again next pass.)
            removal.as_mut().is_none_or(|removal| {
                let hung = || format!("{pod}: removing what it wrote outside its volumes has not ended in 60 s: no pod is replaced for the reserve until it does");
                removal.done(hung).is_none()
            })
        });
        let hung = || "the storage count has not ended in 60 s: no pod's storage is limited until it does".to_string();
        let done = self.count.as_mut().and_then(|job| Some((job.began, job.done(hung)?)));
        if let Some((began, counted)) = done {
            self.count = None;
            self.counted = Some(Instant::now());
            if let Some((free, reserve, mut pods)) = counted {
                for i in storage::missed(&mut pods, &mut self.missed) {
                    eprintln!(
                        "kithd: {}: its files outside its volumes could not all be counted in {} s or {} directories deep: replaced if the next count cannot either",
                        pods[i].id,
                        storage::SPELL.as_secs(),
                        storage::DEEP
                    );
                }
                // While what a replaced pod wrote is not gone yet, none is replaced for the reserve.
                let waiting = !self.replacing.is_empty();
                let chosen = storage::choose(&pods, free, if waiting { 0 } else { reserve });
                // Said once for each spell the disk is under its reserve.
                if free >= reserve {
                    self.low = false;
                } else if chosen.is_empty() && !waiting && !self.low {
                    eprintln!(
                        "kithd: the state disk has {free} bytes free, under its reserve of {reserve}, and no pod wrote enough outside its volumes to free it"
                    );
                    self.low = true;
                }
                for (i, why) in chosen {
                    self.replace(&pods[i].id, began, &why, state);
                }
            }
        }
        if self.count.is_some() || self.counted.is_some_and(|at| at.elapsed() < TICK) {
            return;
        }
        // (A disk that cannot be asked keeps no reserve: the limits still hold.)
        let disk = nix::sys::statvfs::statvfs(state).ok();
        let free = disk
            .as_ref()
            .map_or(u64::MAX, |d| d.blocks_available() * d.fragment_size());
        let total = disk.as_ref().map_or(0, |d| d.blocks() * d.fragment_size());
        let root = nix::unistd::getuid().is_root();
        let reserve = self.reserve.unwrap_or_else(|| storage::default_reserve(total, root));
        // Per pod: its limit, the sum of its containers', and the roots and cgroups of those running.
        type Paths = Vec<PathBuf>;
        let mut pods: BTreeMap<String, (Option<u64>, Paths, Paths)> = BTreeMap::new();
        for slot in self.slots.values() {
            let Run::Container(c) = &slot.run else { continue };
            let (limit, roots, cgroups) = pods.entry(pod_of(&slot.owner, slot.replica)).or_default();
            if let Some(bytes) = c.resources.as_ref().and_then(|r| r.storage.as_ref()?.bytes()) {
                *limit = Some(limit.unwrap_or(0).saturating_add(bytes));
            }
            let running = slot.handle.as_ref().filter(|_| !slot.leaving);
            roots.extend(running.and_then(Handle::upper));
            cgroups.extend(running.map(|handle| handle.cgroup.clone()));
        }
        let pods: Vec<(storage::Pod, Paths, Paths)> = pods
            .into_iter()
            .filter(|(id, (limit, roots, _))| {
                !roots.is_empty() && !self.replacing.contains_key(id) && storage::walked(*limit, free, reserve)
            })
            .map(|(id, (limit, mut roots, cgroups))| {
                roots.push(replicas.join(&id).join("scratch"));
                let pod = storage::Pod {
                    id,
                    limit,
                    bytes: 0,
                    finished: true,
                    again: false,
                };
                (pod, roots, cgroups)
            })
            .collect();
        if pods.is_empty() {
            return;
        }
        let state = state.to_path_buf();
        let stop = self.stop.clone();
        self.count = Job::start("storage", &shared.changed, move || {
            let pods: Vec<storage::Pod> = pods
                .into_iter()
                .map(|(mut pod, roots, cgroups)| {
                    // (A scratch set aside and not removed, by a kithd that stopped first, goes now.)
                    storage::sweep(&replicas.join(&pod.id), &stop);
                    let until = storage::Until {
                        at: Instant::now() + storage::SPELL,
                        stop: &stop,
                    };
                    let limit = pod.limit.unwrap_or(u64::MAX);
                    (pod.bytes, pod.finished) = storage::count(&roots, limit, until);
                    if pod.finished && pod.bytes <= limit {
                        let mut pids = Vec::new();
                        for cgroup in &cgroups {
                            let (more, all) = storage::pids(cgroup, until);
                            pids.extend(more);
                            pod.finished &= all;
                        }
                        let (held, finished) = storage::unlinked(&pids, &roots, until);
                        (pod.bytes, pod.finished) = (pod.bytes.saturating_add(held), pod.finished && finished);
                    }
                    pod
                })
                .collect();
            // Free once what was set aside is gone.
            let disk = nix::sys::statvfs::statvfs(&state).ok();
            let free = disk.map_or(free, |d| d.blocks_available() * d.fragment_size());
            (free, reserve, pods)
        });
        // Done, it wakes the loop to act on it; no thread for it, the next pass tries again.
    }

    /// Removes the images no unit here uses (`prune`), at most every `prune::EVERY` after the
    /// last removal ended, one at a time and off the async threads. In use is the image of
    /// every unit with a slot, whatever it is doing, and every image a container is made from.
    /// With no grace it only finishes what a removal cut short (a kithd that had one) left.
    fn tend_images(&mut self, shared: &std::sync::Arc<Shared>, state: &Path) {
        if let Some(job) = self.pruning.as_mut() {
            let hung = || "removing the images no unit uses has not ended in 60 s".to_string();
            let Some(said) = job.done(hung) else { return };
            match said {
                Some(Ok(said)) => {
                    self.look_failed = None;
                    said.iter().for_each(|line| eprintln!("{line}"));
                }
                // Each pass fails alike until it is mended: said once, not each minute.
                Some(Err(e)) if self.look_failed.as_ref() != Some(&e) => {
                    eprintln!("{e}");
                    self.look_failed = Some(e);
                }
                _ => {}
            }
            (self.pruning, self.pruned) = (None, Some(Instant::now()));
        }
        if self.pruned.is_some_and(|at| at.elapsed() < prune::EVERY) {
            return;
        }
        // A wall clock set forward makes every image look unused for that much longer: the
        // images are unused from now at the earliest (so this pass removes none).
        let boot = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME).map(Duration::from);
        let stepped = boot.ok().and_then(|boot| {
            let now = (boot, SystemTime::now());
            prune::stepped(self.clocks.replace(now), now)
        });
        if let Some(ahead) = stepped {
            eprintln!(
                "kithd: the clock moved {ahead} s further than time went: each image is kept for its grace from now"
            );
        }
        self.floor = prune::floor(self.floor, stepped.is_some(), SystemTime::now());
        let floor = self.floor;
        let keep = images_in_use(&self.slots);
        let (images, grace, stop, state) = (
            self.runtime.images.clone(),
            self.image_grace,
            self.stop.clone(),
            state.to_path_buf(),
        );
        let disk = nix::sys::statvfs::statvfs(&state).ok();
        let total = disk.as_ref().map_or(0, |d| d.blocks() * d.fragment_size());
        let root = nix::unistd::getuid().is_root();
        let reserve = self.reserve.unwrap_or_else(|| storage::default_reserve(total, root));
        self.pruning = Job::start("images", &shared.changed, move || {
            // A second back: an image a pull marks used as this begins stays, however coarse
            // the disk's clock.
            let began = SystemTime::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or(SystemTime::UNIX_EPOCH);
            // What a removal that stopped or failed left, and the layers no image names that
            // are as old as an image must be to go (none with no grace). Said whatever follows.
            let cut = Some(grace).filter(|grace| !grace.is_zero());
            let tidied = images.tidy(cut.and_then(|grace| began.checked_sub(grace.max(prune::LEAST))));
            if tidied > 0 {
                eprintln!("kithd: removed what no image uses any more: {tidied} bytes freed");
            }
            if cut.is_none() {
                return Ok(Vec::new());
            }
            let unused = images
                .unused(&keep, floor)
                .map_err(|e| format!("kithd: no image removed: {e}"))?;
            // (A disk that cannot be asked is not under its reserve.)
            let low =
                || nix::sys::statvfs::statvfs(&state).is_ok_and(|d| d.blocks_available() * d.fragment_size() < reserve);
            let remove = |digest: &str, before| images.remove_image(digest, before).map_err(|e| e.to_string());
            Ok(prune::prune(&unused, began, grace, low, remove, &stop))
        });
    }

    /// Kills every running unit of the pod `pod`, saying `why`, and sets its disk scratch aside,
    /// to be removed once they are gone: each starts again as its restart policy says, from an
    /// empty root. A pod one of whose units started after the count `began` is left to the next
    /// count; one a unit of which could not be killed is tried again then, its scratch where it is.
    fn replace(&mut self, pod: &str, began: Instant, why: &str, state: &Path) {
        let mine =
            |slot: &&mut Slot| pod_of(&slot.owner, slot.replica) == pod && slot.handle.is_some() && !slot.leaving;
        let mut units: Vec<(&String, &mut Slot)> = self.slots.iter_mut().filter(|(_, slot)| mine(slot)).collect();
        let started: Vec<Instant> = units.iter().map(|(_, slot)| slot.started).collect();
        if !storage::replaceable(&started, began) {
            return;
        }
        eprintln!("kithd: {pod}: {why}");
        // Started again, it starts with no count missed.
        self.missed.remove(pod);
        let mut killed = true;
        for (id, slot) in &mut units {
            (slot.message, slot.replaced) = (Some(why.to_string()), true);
            if let Some(Err(e)) = slot.handle.as_mut().map(Handle::kill) {
                eprintln!("kithd: {id}: {e}");
                killed = false;
            }
        }
        if killed {
            // Moved aside at once, so what starts next makes a new one.
            storage::aside(&state.join(crate::files::REPLICAS).join(pod).join("scratch"));
            self.replacing.insert(pod.to_string(), (Instant::now(), None));
        }
    }
}

// (After `impl Controller`: an impl block before it renames its functions, and kithd.order
// links them by name.)
impl<T> Job<T> {
    /// Runs `work` on a thread of its own, waking the loop when it is done; `None` when the
    /// system gives no thread, to be tried again the next pass.
    fn start(name: &str, changed: &std::sync::Arc<Notify>, work: impl FnOnce() -> T + Send + 'static) -> Option<Self>
    where
        T: Send + 'static,
    {
        let (done, waiting) = tokio::sync::oneshot::channel();
        let changed = changed.clone();
        let run = move || {
            let _ = done.send(work());
            changed.notify_one();
        };
        match std::thread::Builder::new().name(name.into()).spawn(run) {
            Ok(_) => Some(Job {
                began: Instant::now(),
                waiting,
                slow: false,
            }),
            Err(e) => {
                eprintln!("kithd: no thread for {name}, tried again next pass: {e}");
                None
            }
        }
    }

    /// What it came to once it is done (`None` within when its thread ended without it); still
    /// on its way, `None`, and `hung` is said once it has been for `HUNG`.
    fn done(&mut self, hung: impl FnOnce() -> String) -> Option<Option<T>> {
        use tokio::sync::oneshot::error::TryRecvError;
        match self.waiting.try_recv() {
            Err(TryRecvError::Empty) => {
                if !self.slow && self.began.elapsed() >= HUNG {
                    eprintln!("kithd: {}", hung());
                    self.slow = true;
                }
                None
            }
            done => Some(done.ok()),
        }
    }
}

/// The images of the units with a slot here: kept, whatever their units are doing.
fn images_in_use(slots: &BTreeMap<String, Slot>) -> Vec<String> {
    let images = slots.values().filter_map(|slot| match &slot.run {
        Run::Container(c) => Some(c.image.clone()),
        _ => None,
    });
    images.collect::<BTreeSet<_>>().into_iter().collect()
}

/// What the ConfigMap (or, `secret`, the Secret) `name` of `namespace` holds.
fn map_of(shared: &Shared, namespace: &str, secret: bool, name: &str) -> Result<BTreeMap<String, String>, String> {
    let kind = if secret { "Secret" } else { "ConfigMap" };
    let key = format!("{kind}/{namespace}/{name}");
    let file_store = shared.store.lock().expect("a handler panicked holding the store");
    let found = file_store.store.get(&key).map(|r| r.spec.clone());
    let spec = found.ok_or(format!("{key} does not exist"))?;
    let me = shared.cluster.as_ref().map(|cluster| cluster.me.name.as_str());
    if let Some(why) = crate::access::withheld(&file_store.store, me, &key, &spec).filter(|_| secret) {
        return Err(why);
    }
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
    slot: &mut Slot,
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
        // A NodeWorkload is the node's own: it keeps the node's users.
        host_users: slot.owner.starts_with("NodeWorkload/"),
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
        let namespace = slot.owner.split('/').nth(1).unwrap_or_default();
        // An exit's pod: asked again here, as it starts (`ready` refuses all but root).
        let exit = slot
            .exit
            .as_deref()
            .map(|name| crate::exits::ready(shared, name, namespace))
            .transpose()?;
        // (Only root can make a network: elsewhere the pod shares the node's.)
        if nix::unistd::getuid().is_root() {
            let net = mesh.map(|(prefix, me)| kith_mesh::node_net(prefix, me));
            let mut pods = shared.pods.lock().expect("nothing panics holding the pods");
            let exit = exit.as_ref().map(|(tunnel, dns)| (*tunnel, dns.as_slice()));
            let given = pods.given(state, pod, namespace, hostname, net, exit)?;
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
            // (Root in a container that keeps the node's users is the node's root: a node
            // whose policy has none of them starts no such container. Root of a range of
            // its own, a pod's, is not the node's.)
            unit.no_node_root = !crate::policy::get().allows("rootContainers");
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
            // (An Image of the cluster is made on a node from a Volume, by whoever may apply an
            // Image in its namespace: no one signs it, and no rule has it.)
            let own = |local: &kith_runtime::Local| local.namespace(&c.image).is_some();
            let signed_by = match runtime.images.local.as_ref().is_some_and(own) {
                true => c.signed_by.clone(),
                false => {
                    let rules = image_rules(&shared.store.lock().expect("a handler panicked holding the store").store);
                    signers(&rules, &c.image, &c.signed_by)?
                }
            };
            let image = runtime
                .images
                .pull_signed(&c.image, policy, &signed_by)
                .await
                .map_err(|e| e.to_string())?;
            let created = runtime.create(id, &image, &unit, log("out")?, log("err")?);
            // The runtime says what the container would be; here whose word refused it.
            let whose = |e: kith_runtime::Error| match e.to_string().contains(kith_runtime::NODE_ROOT) {
                true => format!(
                    "this node's policy refuses containers that are the node's root (rootContainers is off: `--node-policy root-containers` where the node's kithd is started allows them): {e}"
                ),
                false => e.to_string(),
            };
            created.map_err(whose)
        }
        Run::Exec(e) => {
            unit.command = e.command.clone();
            runtime
                .exec(id, &unit, log("out")?, log("err")?)
                .map_err(|e| e.to_string())
        }
    };
    let mut handle = created?;
    match handle.start() {
        Ok(()) => Ok(handle),
        Err(e) => {
            // It never ran; what processes it left are the slot's to hold until they are gone.
            // (Deleted here, not on a thread: this start is given up when kithd ends, and a
            // delete nobody waits for any more would be cut short by the exit.)
            slot.tried = Some(Instant::now());
            stopped(id, slot, handle.delete());
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

/// The Cluster's rules for whose signatures images are taken by (`spec.images` of every
/// Cluster there is): each a prefix and the keys that sign what is under it.
fn image_rules(store: &kith_api::store::Store) -> Vec<(String, Vec<String>)> {
    let rules = store
        .list(Some("Cluster"))
        .filter_map(|cluster| cluster.spec["images"].as_array());
    let rule = |rule: &Value| {
        let keys = rule["signedBy"].as_array().into_iter().flatten();
        let keys = keys.filter_map(Value::as_str).map(String::from).collect();
        // (A rule's registry by its one name, as an image's is read: `ghcr.io:443/acme` is `ghcr.io/acme`.)
        let prefix = rule["prefix"].as_str().unwrap_or_default();
        let prefix = match prefix.split_once('/') {
            _ if prefix.is_empty() => String::new(),
            Some((registry, path)) => format!("{}/{path}", kith_runtime::registry(registry)),
            None => kith_runtime::registry(prefix),
        };
        (prefix, keys)
    };
    rules.flatten().map(rule).collect()
}

/// The keys one of which must have signed `image` for a unit to run it: those of the rule
/// with the longest prefix the image is under (by whole parts: `ghcr.io/acme` has
/// `ghcr.io/acme/tool` and not `ghcr.io/acmex`), narrowed to the ones its template's `signedBy`
/// names too where it names any; the template's alone where no rule has the image. A template
/// cannot widen a rule or leave it: where the lists have no key in common nothing is run. (Two
/// Clusters' rules for one prefix narrow each other the same way.)
fn signers(rules: &[(String, Vec<String>)], image: &str, template: &[String]) -> Result<Vec<String>, String> {
    // (What is no reference is under no rule: the pull refuses it.)
    let Some(name) = kith_runtime::repository(image) else {
        return Ok(template.to_vec());
    };
    let under = |prefix: &str| {
        let rest = name.strip_prefix(prefix);
        prefix.is_empty() || rest.is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    };
    let held = rules.iter().filter(|(prefix, _)| under(prefix));
    let Some(longest) = held.clone().map(|(prefix, _)| prefix.len()).max() else {
        return Ok(template.to_vec());
    };
    // (A key is the same key as its PEM file's text and as the base64 in it.)
    let id = |key: &String| kith_runtime::signed::key(key).ok().map(|key| key.id);
    let lists = held
        .filter(|(prefix, _)| prefix.len() == longest)
        .map(|(_, keys)| keys.as_slice());
    let mut lists = lists.chain((!template.is_empty()).then_some(template));
    let mut keys = lists.next().unwrap_or_default().to_vec();
    for list in lists {
        keys.retain(|key| id(key).is_some_and(|key| list.iter().any(|other| id(other).as_ref() == Some(&key))));
    }
    if keys.is_empty() {
        let prefix = rules
            .iter()
            .find(|(prefix, _)| under(prefix) && prefix.len() == longest);
        let rule = match prefix {
            Some((prefix, _)) if !prefix.is_empty() => format!("rule for `{prefix}`"),
            _ => "rule for every image".to_string(),
        };
        return Err(format!(
            "image `{image}` is under the Cluster's {rule} (spec.images), and no key that rule names is among its \
             template's signedBy: a template's keys narrow a rule's, they do not replace them"
        ));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A public key's text, as `signedBy` takes it: Ed25519, each `n` another.
    fn signing_key(n: u8) -> String {
        format!("MCowBQYDK2VwAyEA{}{}=", (b'B' + n) as char, "A".repeat(42))
    }

    /// An image is held to the Cluster's rule with the longest prefix it is under, by whole
    /// parts and as a pull reads its reference; one under no rule is its template's alone.
    #[test]
    fn image_rules_hold_an_image_to_the_longest_prefix_it_is_under() {
        let [every, registry, acme, other] = [0, 1, 2, 3].map(signing_key);
        let rule =
            |prefix: &str, keys: &[&String]| (prefix.to_string(), keys.iter().map(|key| key.to_string()).collect());
        let rules: Vec<(String, Vec<String>)> = vec![
            rule("", &[&every]),
            rule("ghcr.io", &[&registry]),
            rule("ghcr.io/acme", &[&acme, &every]),
            rule("docker.io/library", &[&other]),
        ];
        let keys = |image: &str| signers(&rules, image, &[]).unwrap();
        assert_eq!(keys("ghcr.io/acme/tool:1"), [acme.clone(), every.clone()]);
        assert_eq!(keys("ghcr.io/acme"), [acme.clone(), every.clone()]);
        // (What is no reference is held to nothing here: the pull, which reads it the same way, refuses it.)
        assert_eq!(keys("ghcr.io/acme/tool@sha256:"), Vec::<String>::new());
        // (By whole parts, and whatever the case of the registry or the tag.)
        assert_eq!(keys("ghcr.io/acmex/tool"), vec![registry.clone()]);
        assert_eq!(keys("GHCR.IO/acme/tool:latest"), [acme.clone(), every.clone()]);
        // (And by the port a pull uses anyway, and Docker Hub by any of its names; another port
        // is another registry.)
        assert_eq!(keys("ghcr.io:443/acme/tool"), [acme.clone(), every.clone()]);
        assert_eq!(keys("ghcr.io:8443/acme/tool"), vec![every.clone()]);
        assert_eq!(keys("ghcr.io:80/acme/tool"), vec![every.clone()]);
        for image in [
            "index.docker.io/library/nginx",
            "registry-1.docker.io/library/nginx:1",
            "docker.io:443/library/nginx",
        ] {
            assert_eq!(keys(image), vec![other.clone()], "{image}");
        }
        // (As a pull reads it: a bare name is docker.io's library.)
        for image in [
            "nginx",
            "nginx:1.27",
            "library/nginx",
            "docker.io/nginx",
            "docker.io/library/nginx",
        ] {
            assert_eq!(keys(image), vec![other.clone()], "{image}");
        }
        assert_eq!(keys("docker.io/acme/tool"), vec![every.clone()]);
        assert_eq!(keys("quay.io/acme/tool"), vec![every.clone()]);
        // With no rule for every image, what is under none is its template's alone, as before.
        let some = &rules[1..];
        assert_eq!(signers(some, "quay.io/acme/tool", &[]), Ok(vec![]));
        assert_eq!(
            signers(some, "quay.io/acme/tool", std::slice::from_ref(&other)),
            Ok(vec![other.clone()])
        );
        assert_eq!(signers(&[], "ghcr.io/acme/tool", &[]), Ok(vec![]));
    }

    /// A template's own keys narrow a rule's and cannot replace or widen them; a key is the
    /// same key as its PEM text; two Clusters' rules for one prefix narrow each other.
    #[test]
    fn image_rules_are_narrowed_by_a_template_and_never_replaced() {
        let [a, b, c] = [0, 1, 2].map(signing_key);
        let rules = vec![("ghcr.io/acme".to_string(), vec![a.clone(), b.clone()])];
        let with = |template: &[String]| signers(&rules, "ghcr.io/acme/tool:1", template);
        assert_eq!(with(&[]), Ok(vec![a.clone(), b.clone()]));
        assert_eq!(with(std::slice::from_ref(&b)), Ok(vec![b.clone()]));
        assert_eq!(with(&[c.clone(), a.clone()]), Ok(vec![a.clone()]));
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{b}\n-----END PUBLIC KEY-----\n");
        assert_eq!(with(&[pem]), Ok(vec![b.clone()]));
        let refused = with(std::slice::from_ref(&c)).unwrap_err();
        assert!(
            refused.contains("rule for `ghcr.io/acme`") && refused.contains("narrow a rule's"),
            "{refused}"
        );
        // A second Cluster's rule for the same prefix: a key both name.
        let mut two = rules.clone();
        two.push(("ghcr.io/acme".to_string(), vec![b.clone(), c.clone()]));
        assert_eq!(signers(&two, "ghcr.io/acme/tool", &[]), Ok(vec![b.clone()]));
        assert!(signers(&two, "ghcr.io/acme/tool", std::slice::from_ref(&a)).is_err());
        // A rule with no key (none can be applied) runs nothing, and says it is every image's.
        let none = vec![(String::new(), vec![])];
        let refused = signers(&none, "nginx", std::slice::from_ref(&a)).unwrap_err();
        assert!(refused.contains("rule for every image"), "{refused}");
    }

    /// The rules are those of every Cluster in the store.
    #[test]
    fn image_rules_are_read_from_the_store() {
        let [a, b] = [0, 1].map(signing_key);
        let cluster = |name: &str, images: Value| -> Resource {
            let cluster = json!({
                "apiVersion": "kith.dev/v1", "kind": "Cluster", "metadata": { "name": name },
                "spec": { "images": images },
            });
            serde_json::from_value(cluster).unwrap()
        };
        let mut store = kith_api::store::Store::default();
        assert!(image_rules(&store).is_empty());
        store
            .apply(cluster(
                "home",
                json!([{ "signedBy": [a] }, { "prefix": "ghcr.io", "signedBy": [a, b] }]),
            ))
            .unwrap();
        store
            .apply(cluster("more", json!([{ "prefix": "quay.io:443", "signedBy": [b] }])))
            .unwrap();
        let hub = json!([{ "prefix": "index.docker.io/library", "signedBy": [b] }]);
        store.apply(cluster("hub", hub)).unwrap();
        store.apply(cluster("none", json!([]))).unwrap();
        let mut rules = image_rules(&store);
        rules.sort();
        // (Each registry by its one name.)
        let expected = [
            ("", vec![&a]),
            ("docker.io/library", vec![&b]),
            ("ghcr.io", vec![&a, &b]),
            ("quay.io", vec![&b]),
        ];
        let expected: Vec<(String, Vec<String>)> = expected
            .into_iter()
            .map(|(prefix, keys)| (prefix.to_string(), keys.into_iter().cloned().collect()))
            .collect();
        assert_eq!(rules, expected);
    }

    /// A store change wakes the controller's loop before its tick: a pass does not wait the
    /// 10 s TICK for a change it is told of (the wait stops at the change, and not at the tick).
    #[tokio::test]
    async fn the_loop_wakes_on_a_change_before_its_tick() {
        let changed = Notify::new();
        let mut exited = signal(SignalKind::child()).expect("installing a signal handler");
        // The sender stays alive: a dropped one would count as stopping.
        let (_stop, mut stopping) = watch::channel(false);
        let poke = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            changed.notify_one();
        };
        let (woken, ()) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(5),
                until_woken(&changed, &mut exited, TICK, &mut stopping)
            ),
            poke
        );
        assert_eq!(
            woken.ok(),
            Some(false),
            "a change did not wake the loop before its {TICK:?} tick"
        );
    }

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

    /// Every unit with a slot keeps its image, leaving or not; an image named twice is one.
    #[test]
    fn image_removal_keeps_the_image_of_every_slot() {
        let mut slots = BTreeMap::new();
        slots.insert("a".to_string(), slot_of("Workload/x/a", &[], "a"));
        let mut leaving = slot_of("Workload/x/b", &[], "b");
        leaving.leaving = true;
        slots.insert("b".to_string(), leaving);
        let mut other = slot_of("Job/x/c", &[], "c");
        let Run::Container(c) = &mut other.run else {
            unreachable!()
        };
        c.image = "registry.example/c:1".into();
        slots.insert("c".to_string(), other);
        assert_eq!(images_in_use(&slots), ["img", "registry.example/c:1"]);
        assert!(images_in_use(&BTreeMap::new()).is_empty());
    }

    /// A slot of `owner`, with the device nodes `devices`, that runs the container `name`.
    fn slot_of(owner: &str, devices: &[&str], name: &str) -> Slot {
        let container: Container = serde_json::from_value(json!({ "name": name, "image": "img" })).unwrap();
        Slot {
            owner: owner.into(),
            revision: None,
            replica: 0,
            run: Run::Container(container),
            policy: RestartPolicy::Always,
            env: Ok(Vec::new()),
            rolling: false,
            probes: None,
            pod: None,
            exit: None,
            notes: BTreeMap::new(),
            devices: devices.iter().map(PathBuf::from).collect(),
            seat: None,
            volumes: Vec::new(),
            files: Ok(Vec::new()),
            init: false,
            after: 0,
            held: false,
            leaving: false,
            drop: false,
            tried: None,
            accounted: false,
            tuned: None,
            handle: None,
            state: "pending",
            restarts: 0,
            failures: 0,
            exit_code: None,
            message: None,
            started: Instant::now(),
            start_at: None,
            replaced: false,
        }
    }

    /// A unit whose stop failed while processes remain is leaving: nothing with its id, or with a
    /// device node it holds, starts until it is gone. A device it does not hold is no hold. Units of
    /// one owner share its devices, so a sibling's hold is no hold for the others.
    #[test]
    fn leaving_units_hold_back_their_id_and_their_device_nodes() {
        let paths = |names: &[&str]| names.iter().map(PathBuf::from).collect::<Vec<_>>();
        let leaving = vec![(
            "w_a_b_0_x".to_string(),
            "Workload/a/b".to_string(),
            paths(&["/dev/dri/card0"]),
        )];
        let same_id = held_by_leaving("w_a_b_0_x", "Workload/a/b", &[], &leaving).expect("the same id is held");
        assert!(same_id.contains("still stopping"), "{same_id}");
        let same_device = held_by_leaving("w_a_b_0_y", "Workload/c/d", &paths(&["/dev/dri/card0"]), &leaving)
            .expect("a device it holds is held");
        assert!(same_device.contains("/dev/dri/card0"), "{same_device}");
        assert_eq!(
            held_by_leaving("w_a_b_0_y", "Workload/c/d", &paths(&["/dev/input/event0"]), &leaving),
            None
        );
        assert_eq!(
            held_by_leaving("w_a_b_0_y", "Workload/c/d", &paths(&["/dev/dri/card0"]), &[]),
            None
        );
        assert_eq!(
            held_by_leaving("w_a_b_1_x", "Workload/a/b", &paths(&["/dev/dri/card0"]), &leaving),
            None,
            "a sibling of the same owner shares the devices"
        );
    }

    /// A unit that ended on its own, with processes left, is kept once they are gone: its state, exit
    /// code and restarts stay, and it is not run again. One stopped to be replaced is removed.
    #[tokio::test]
    async fn leaving_exit_is_not_run_again() {
        let id = "w_a_b_0_app";
        let mut ended = slot_of("Workload/a/b", &[], "app");
        (ended.leaving, ended.state, ended.exit_code) = (true, "exited", Some(0));
        let mut slots = BTreeMap::from([(id.to_string(), ended)]);
        stop_unit(&mut slots, id, false).await;
        let kept = slots.get(id).expect("an exit is kept");
        assert_eq!(
            (kept.state, kept.exit_code, kept.leaving, kept.start_at.is_none()),
            ("exited", Some(0), false, true),
            "kept as it ended, with nothing to start"
        );
        stop_unit(&mut slots, id, true).await;
        assert!(
            !slots.contains_key(id),
            "a replaced unit goes, and what is wanted starts afresh"
        );
    }

    /// An input device plugged into a running container is no reason to start it over, so the device
    /// alone does not make the slot differ. Only a container that runs takes them so; a DRI node, or
    /// an input device the unit did not start with, still restarts it.
    #[test]
    fn input_devices_alone_do_not_replace_a_running_container() {
        let slot = slot_of("Workload/a/b", &["/dev/input/event0"], "app");
        let plugged = slot_of("Workload/a/b", &["/dev/input/event0", "/dev/input/event1"], "app");
        let card = slot_of("Workload/a/b", &["/dev/dri/card0"], "app");
        assert!(devices_in_place(&slot, &plugged), "a plug is taken in place");
        // One pulled and another plugged in one pass: in place while the slot still has the one it
        // started with, which is why it is kept until the new one is in (a refused plug is tried
        // again, the unit is not replaced).
        let (lost, came) = ("/dev/input/event-no-such", "/dev/input/event1");
        let swapped = slot_of("Workload/a/b", &[came], "app");
        assert!(devices_in_place(&slot_of("Workload/a/b", &[lost], "app"), &swapped));
        assert!(!devices_in_place(&slot_of("Workload/a/b", &[], "app"), &swapped));
        assert!(!devices_in_place(&slot, &card), "a DRI node is not");
        // Without a handle nothing runs: the unit is replaced, not plugged.
        assert!(
            !plugs_in_place(&slot, &plugged),
            "a unit that is not running is replaced"
        );
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

    #[tokio::test]
    async fn storage_stop_waits_for_the_jobs_and_names_the_ones_left() {
        let (done, finishing) = tokio::sync::oneshot::channel::<()>();
        let (_held, hung) = tokio::sync::oneshot::channel::<()>();
        let jobs = vec![
            ("the count".to_string(), finishing.map(drop).boxed()),
            ("the removal of pod b".to_string(), hung.map(drop).boxed()),
        ];
        done.send(()).unwrap();
        let left = wait_for_storage(jobs, Duration::from_millis(50)).await;
        assert_eq!(left, ["the removal of pod b"]);
        assert!(wait_for_storage(Vec::new(), Duration::from_millis(50)).await.is_empty());
    }
}
