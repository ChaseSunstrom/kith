//! The controller: makes the containers and exec units on this node match the
//! `Workload`s, `NodeWorkload`s and `Job`s in the store, restarts them when they exit, and reports
//! what it sees in each one's status.
//!
// ponytail: this node's share of each (the scheduler says which replicas are its own).
// A container's ports only name them (units share the host's network).
// A rolling update replaces one replica at a time. A replica that is a pod (as root, no
// device, seat or volume, and room on the node for a second) is replaced by surge: the new
// one starts beside the old (the generations take turns at ids with and without a `b`:
// `unit_id`, `pod_id`), and the old is stopped once the new is ready and has answered for
// a `DRAIN`. Any other is stopped before its replacement starts, and says why in a note.
// Images are pulled one at a time.
// A Job's progress lives in memory: kithd restarted under a running Job starts it over.

mod prune;
pub mod storage;

use crate::Shared;
use crate::root_part::{Direct, Root};
use futures_util::FutureExt;
use kith_api::Resource;
use kith_api::kinds::{
    ConfigMapSpec, Container, EnvVar, ExecUnit, Field, JobSpec, NodeWorkloadSpec, PullPolicy, Resources, RestartPolicy,
    SecretSpec, Strategy, Template, WorkloadSpec,
};
use kith_api::store::Error;
use kith_runtime::{Handle, Left, Runtime, Unit};
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
#[derive(Clone, Debug, PartialEq)]
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
    /// The dmem regions its GPU shares are a ceiling on, and the bytes of each (`claims::Granted`).
    dmem: Vec<(String, u64)>,
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
    /// When a `kubectl delete pod` last restarted it (seconds): its pod's start time from then.
    restarted: Option<u64>,
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

/// Where each unit started is written down for the next kithd ([`kith_runtime::Runtime::record`]).
pub const UNITS: &str = "/run/kith/units";

/// What a unit was started as: what `differs` compares, hashed (its values hold secrets). A
/// kithd started again takes back a running unit only if its slot's mark is the same.
fn mark(slot: &Slot) -> String {
    use sha2::Digest;
    let what = format!(
        "{:?}",
        (
            &slot.run,
            &slot.pod,
            &slot.exit,
            &slot.notes,
            &slot.policy,
            &slot.devices,
            &slot.seat,
            &slot.volumes,
            slot.env.as_ref().ok()
        )
    );
    // (A unit with no GPU share has the mark it had before shares were ceilings.)
    let what = match slot.dmem.is_empty() {
        true => what,
        false => format!("{what}{:?}", slot.dmem),
    };
    sha2::Sha256::digest(what.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Controller {
    /// Units a kithd before this one started that still run, with their marks: each is taken
    /// by its slot when that slot would start, or stopped if it is not wanted or not the same.
    adopted: BTreeMap<String, (Handle, String)>,
    /// When the stop of an adopted unit, or of one in `left`, last failed (it stays in its map,
    /// tried again after STOP_RETRY).
    stuck: BTreeMap<String, Instant>,
    /// Units an earlier kithd left running that the start's sweep could not remove (processes of
    /// theirs remain), by id. They have no slot: they are leaving with no owner (see `leaving_of`),
    /// so their ids and devices go to no other unit, and each is deleted once its processes are gone.
    left: BTreeMap<String, Left>,
    runtime: Runtime,
    logs: PathBuf,
    log_cap: u64,
    slots: BTreeMap<String, Slot>,
    jobs: BTreeMap<String, Progress>,
    /// Log file prefixes of the Workloads, NodeWorkloads and Jobs seen last pass; `None` before the first.
    owners: Option<BTreeSet<String>>,
    /// The status report on its way to the store, if one is.
    report: Option<tokio::task::JoinHandle<()>>,
    /// The removal of the data of made Volumes whose claim is gone, and then their deletion.
    wiping: Option<tokio::task::JoinHandle<()>>,
    /// Bytes the state disk keeps free: under them the pod that wrote the most is replaced.
    /// `None` for the default (`storage::default_reserve`); 0 for none.
    reserve: Option<u64>,
    /// The count of what pods wrote outside their volumes, on its way.
    count: Option<Job<Counted>>,
    /// When the last count ended.
    counted: Option<Instant>,
    /// The removal of scratch set aside and left (`storage::sweep`), beside the count, on its way.
    leftovers: Option<Job<()>>,
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
    /// Each pod's project, where the state disk holds pods to their limits as they write
    /// (`storage::held_at_write`); `None` where they are counted.
    projects: Option<storage::Projects>,
    /// What this node last found its own hardware to be (`devices::scan`), and when: kept for
    /// `SCAN_KEPT`, where a pass at each change of the store would walk `/sys` every time.
    scanned: Option<(Instant, Vec<Resource>)>,
    /// The node runs alone (`alone: run`, no leader answered at its start) until a write comes back
    /// (`record_alone`): its Jobs wait meanwhile (`held_alone`).
    alone: std::sync::Arc<AtomicBool>,
    /// Per (Workload, replica) that has been replaced by surge: which generation is the current
    /// one (false: the ids a replica has always had; true: those with a `b`).
    gens: BTreeMap<(String, u32), bool>,
    /// Per replica being replaced by surge: when it began, and `None` while the new generation is
    /// not ready, then when it became ready (the old one goes `DRAIN` after).
    surging: Surging,
    /// Per Workload: the replica stopped before it is replaced, and why.
    stopped_first: BTreeMap<String, (u32, String)>,
}

type Surging = BTreeMap<(String, u32), (Instant, Option<Instant>)>;

/// How long a look at the node's own hardware is gone by (a walk of `/sys` measured 3.3 ms in
/// a debug build on a machine with 45 devices). Under `TICK`, so an idle node looks at each
/// one; a device plugged in or taken out shows within this.
const SCAN_KEPT: Duration = Duration::from_secs(5);

/// What `slot` holds if it was made less than `kept` ago; else what `make` gives now, kept.
fn fresh<T>(slot: &mut Option<(Instant, T)>, kept: Duration, make: impl FnOnce() -> T) -> &T {
    if slot.as_ref().is_none_or(|(at, _)| at.elapsed() >= kept) {
        *slot = Some((Instant::now(), make()));
    }
    &slot.as_ref().expect("filled above").1
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

/// How long a node whose Node spec says `alone: run` waits, with no write come back, before it runs alone.
const ALONE_AFTER: Duration = Duration::from_secs(30);
/// What running alone risks: said on the console and in the Node's `alone` status.
const ALONE_RISKS: &str = "A replica moved off this node meanwhile runs twice; a Secret or ConfigMap changed meanwhile is the old one; a Job is not started alone.";

/// How a node's start went: a write came back (its copy is the cluster's), or none did in time and
/// it runs alone from its copy, with the last error it had.
#[derive(Debug, PartialEq)]
enum Start {
    Leader,
    Alone(String),
}

/// Waits for a write to come back. Alone (`alone`), gives up after `after` with none and says `Start::Alone`;
/// otherwise waits as long as it takes.
async fn started<T, E: std::fmt::Display, F: std::future::Future<Output = Result<T, E>>>(
    alone: bool,
    after: Duration,
    submit: impl Fn() -> F,
) -> Start {
    let mut last = String::new();
    let caught_up = async {
        let mut said = false;
        loop {
            match submit().await {
                Ok(_) => return Start::Leader,
                Err(e) => {
                    last = e.to_string();
                    if !std::mem::replace(&mut said, true) {
                        eprintln!("kithd: workloads start once this node has the cluster's store: {e}");
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    };
    if !alone {
        return caught_up.await;
    }
    tokio::time::timeout(after, caught_up)
        .await
        .unwrap_or(Start::Alone(last))
}

/// Whether a resource of this kind waits while its node runs alone. A Job does: its runs are the
/// cluster's to start. A Workload or a NodeWorkload runs from the copy.
fn held_alone(kind: &str, alone: bool) -> bool {
    alone && kind == "Job"
}

fn unix(at: SystemTime) -> u64 {
    at.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// The Node's `alone` status: since when the node ran alone, until when (the write that came back),
/// and the risks.
fn alone_status(since: SystemTime, until: SystemTime) -> serde_json::Map<String, Value> {
    let alone = json!({ "since": unix(since), "until": unix(until), "risks": ALONE_RISKS });
    json!({ "alone": alone }).as_object().cloned().unwrap_or_default()
}

/// How many times the `alone` status is written once a leader answers, two seconds apart.
const ALONE_STATUS_TRIES: usize = 3;

/// Ends running alone once a leader answers `probe` (an empty write: a refusal of the status is an
/// answer too, so an old leader that lacks the field cannot keep the node alone). Then the status is
/// written up to `ALONE_STATUS_TRIES` times, and a refusal that stays is said once.
async fn end_alone<
    T,
    E: std::fmt::Display,
    P: std::future::Future<Output = Result<T, E>>,
    S: std::future::Future<Output = Result<T, E>>,
>(
    alone: &AtomicBool,
    probe: impl Fn() -> P,
    status: impl Fn() -> S,
) {
    while probe().await.is_err() {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    alone.store(false, Ordering::Relaxed);
    for attempt in 1..=ALONE_STATUS_TRIES {
        match status().await {
            Ok(_) => break,
            Err(e) => {
                if attempt == 1 {
                    eprintln!("kithd: the alone status is not written: {e}");
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// Ends running alone once a leader answers, and writes the `alone` status then. The node is no
/// longer alone from that answer on, so the reconcile may start Jobs and catch up.
fn record_alone(shared: std::sync::Arc<Shared>, node: String, alone: std::sync::Arc<AtomicBool>, since: SystemTime) {
    tokio::spawn(async move {
        let key = format!("Node/{node}");
        let nothing = || kith_store::Command::Patch { statuses: Vec::new() };
        let status = || kith_store::Command::Patch {
            statuses: vec![(key.clone(), alone_status(since, SystemTime::now()))],
        };
        end_alone(&alone, || shared.submit(nothing()), || shared.submit(status())).await;
        eprintln!(
            "kithd: a leader answers: this node ran alone since unix {}s; it catches up with the cluster's store",
            unix(since)
        );
    });
}

pub async fn run(
    shared: std::sync::Arc<Shared>,
    runtime: kith_runtime::Result<Runtime>,
    log_cap: u64,
    reserve: Option<u64>,
    image_grace: Duration,
    mut stopping: watch::Receiver<bool>,
) {
    // Kept by process 1 (kith OS), what a kithd before this one started runs on: what of it is
    // still wanted is taken back below, the rest stopped; elsewhere all of it is stopped here.
    let runtime = runtime.map(|mut rt| {
        rt.records = crate::init::is_init().then(|| UNITS.into());
        rt
    });
    let swept = runtime.and_then(|rt| {
        // What a kithd before this one made, and this one takes back, is made here too: one the
        // root part does not take is left to the sweep below.
        let adopted = Direct::today(&shared.pods, Some(&rt)).adopt();
        let kept = adopted.keys().cloned().collect();
        rt.cleanup_but(&kept).map(|old| (rt, old, adopted))
    });
    let (runtime, adopted, left) = match swept {
        Ok((runtime, (old, left), adopted)) => {
            if old > 0 {
                eprintln!("kithd: removed {old} unit(s) left by an earlier run");
            }
            // Those the sweep could not remove still run: they hold their ids and devices, and are
            // deleted through the root part (made as the units it took back are) once they are gone.
            // One the root part does not take is not held (it could never be deleted): said once.
            let left = left
                .into_iter()
                .filter(|unit| match Direct::units().keep(&unit.id) {
                    Ok(()) => {
                        eprintln!(
                            "kithd: {} of an earlier run still has processes: stopping, it keeps its name and devices until they are gone",
                            unit.id
                        );
                        true
                    }
                    Err(e) => {
                        eprintln!("kithd: {e}");
                        false
                    }
                })
                .map(|unit| (unit.id.clone(), unit))
                .collect();
            if !adopted.is_empty() {
                let ids: Vec<&str> = adopted.keys().map(String::as_str).collect();
                eprintln!(
                    "kithd: {} unit(s) of an earlier run still run, or ended while no kithd did: taken back where still wanted ({})",
                    ids.len(),
                    ids.join(", ")
                );
            }
            (runtime, adopted, left)
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
    // With no leader, a node whose copy says `alone: run` goes on from the copy after `ALONE_AFTER`,
    // and says so (`record_alone`); any other waits for one.
    let alone = std::sync::Arc::new(AtomicBool::new(false));
    if let Some(cluster) = &shared.cluster {
        let runs_alone = {
            let file_store = shared.store.lock().expect("a handler panicked holding the store");
            file_store
                .store
                .get(&format!("Node/{}", cluster.me.name))
                .is_some_and(|node| node.spec["alone"] == "run")
        };
        let nothing = || kith_store::Command::Patch { statuses: Vec::new() };
        let start = tokio::select! {
            start = started(runs_alone, ALONE_AFTER, || shared.submit(nothing())) => start,
            _ = stopping.changed() => return,
        };
        if let Start::Alone(last) = start {
            eprintln!(
                "kithd: no leader answered for {}s ({last}): running alone from this node's copy of the store. {ALONE_RISKS}",
                ALONE_AFTER.as_secs()
            );
            alone.store(true, Ordering::Relaxed);
            record_alone(
                shared.clone(),
                cluster.me.name.clone(),
                alone.clone(),
                SystemTime::now(),
            );
        }
    }
    let mut exited = signal(SignalKind::child()).expect("installing a signal handler");
    let state = shared.logs.parent().unwrap_or(&shared.logs);
    let held = storage::held_at_write(state);
    eprintln!("kithd: pods' storage limits are held {}", storage::how(held));
    let projects = held.then(|| storage::Projects::read(state));
    let mut controller = Controller {
        runtime,
        logs: shared.logs.clone(),
        log_cap,
        slots: BTreeMap::new(),
        jobs: BTreeMap::new(),
        owners: None,
        report: None,
        wiping: None,
        reserve,
        count: None,
        counted: None,
        leftovers: None,
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
        projects,
        scanned: None,
        adopted,
        alone,
        stuck: BTreeMap::new(),
        left,
        gens: BTreeMap::new(),
        surging: BTreeMap::new(),
        stopped_first: BTreeMap::new(),
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
    let deleted = delete(id, handle).await;
    stopped(id, slot, deleted);
}

/// What a delete gives back when the unit is still there: its handle, if it has one, and why.
type Undeleted = (Option<Handle>, String);

/// The unit `id` deleted by the root part, on a thread of its own: a delete kills the unit and
/// then waits, asleep between tries, for its cgroup to empty, and on kithd's thread the API, the
/// proxy and DNS would wait with it. Where the node has no thread to give, it runs here after all.
#[allow(clippy::result_large_err)] // the handle that comes back is the answer itself, moved once
async fn delete(id: &str, handle: Handle) -> Result<(), Undeleted> {
    let cell = std::sync::Arc::new(std::sync::Mutex::new(Some(handle)));
    let (theirs, (done, said)) = (cell.clone(), tokio::sync::oneshot::channel());
    let name = id.to_string();
    let spawned = std::thread::Builder::new().name("stop".into()).spawn(move || {
        let handle = theirs.lock().expect("nothing panics holding it").take();
        if let Some(handle) = handle {
            let _ = done.send(Direct::units().delete(handle, &name));
        }
    });
    if spawned.is_ok()
        && let Ok(deleted) = said.await
    {
        return deleted;
    }
    let handle = cell.lock().expect("nothing panics holding it").take();
    Direct::units().delete(
        handle.expect("the stop's thread took the handle and answered nothing: it panicked"),
        id,
    )
}

/// The unit `id` deleted again after a stop that failed (`stuck`: when each last failed). Its handle
/// comes back while processes of it remain; with none left, only a cleanup that failed, nothing is
/// held. A failure is said once, not at each retry.
async fn delete_again(id: &str, handle: Handle, stuck: &mut BTreeMap<String, Instant>) -> Option<Handle> {
    kept_if_stuck(id, delete(id, handle).await, stuck)
}

/// [`delete_again`] once the delete was tried: what is kept (and when it failed) is what still has processes.
fn kept_if_stuck<H>(
    id: &str,
    deleted: Result<(), (Option<H>, String)>,
    stuck: &mut BTreeMap<String, Instant>,
) -> Option<H> {
    let Err((left, error)) = deleted else {
        stuck.remove(id);
        return None;
    };
    if !stuck.contains_key(id) {
        eprintln!("kithd: {id}: {error}");
    }
    match left {
        Some(handle) => {
            stuck.insert(id.to_string(), Instant::now());
            Some(handle)
        }
        None => {
            stuck.remove(id);
            None
        }
    }
}

/// What a stop leaves in its slot once the delete was tried with `deleted`.
fn stopped(id: &str, slot: &mut Slot, deleted: Result<(), Undeleted>) {
    match deleted {
        Ok(()) => {
            // Gone: the "stopping" message of an earlier pass is over.
            if slot.message.as_deref().is_some_and(|m| m.starts_with("stopping: ")) {
                slot.message = None;
            }
        }
        Err((handle, error)) => {
            slot.handle = handle;
            if slot.handle.is_some() {
                slot.probes = None;
                if slot.state == "running" {
                    slot.state = "stopping";
                }
                let message = format!("stopping: {error}; its devices and name are held until it is gone");
                // Said once, not on every pass while it stays stuck.
                if slot.message.as_ref() != Some(&message) {
                    eprintln!("kithd: {id}: {error}");
                }
                slot.message = Some(message);
            } else {
                eprintln!("kithd: {id}: {error}");
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

/// Restarts what `kubectl delete pod` asked for (`marked`, taken here): each replica's slots are
/// stopped and set to start at once, whatever their restart policy says (`again`). The start is the
/// pass's own (step 3), which starts a slot once its `start_at` is due.
async fn apply_restarts(slots: &mut BTreeMap<String, Slot>, marked: &mut BTreeSet<(String, u32)>, now: Instant) {
    for (owner, replica) in std::mem::take(marked) {
        let ids: Vec<String> = slots
            .iter()
            .filter(|(_, slot)| slot.owner == owner && slot.replica == replica)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            stop_unit(slots, &id, false).await;
            if let Some(slot) = slots.get_mut(&id) {
                slot.state = "waiting";
                slot.start_at = Some(now);
                slot.restarted = Some(kith_api::store::now());
            }
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

/// The units still stopping, each with its owner and the device nodes it holds: the slots that
/// leave, and `left`, the units an earlier kithd left running, which have no slot and no owner (so
/// nobody shares their devices: they are refused to every other unit).
fn leaving_of<'a>(
    slots: &BTreeMap<String, Slot>,
    left: impl Iterator<Item = (&'a String, &'a [PathBuf])>,
) -> Vec<(String, String, Vec<PathBuf>)> {
    let slots = slots.iter().filter(|(_, s)| s.leaving);
    let slots = slots.map(|(id, s)| (id.clone(), s.owner.clone(), s.devices.clone()));
    slots
        .chain(left.map(|(id, devices)| (id.clone(), String::new(), devices.to_vec())))
        .collect()
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

/// The pod whose storage a unit is counted, limited and replaced with: its own, so that the two
/// generations of a replica being replaced beside the old have each a limit and a project, and what
/// one writes past its own does not replace the other. (Files and scratch stay the replica's: `pod_of`.)
fn storage_pod(slot: &Slot) -> String {
    let own = slot.pod.as_ref().map(|(pod, _)| pod.clone());
    own.unwrap_or_else(|| pod_of(&slot.owner, slot.replica))
}

/// Per pod with a container: its storage limit, the sum of what its containers state in
/// `resources.storage` (`None` where none does).
fn pod_limits(slots: &BTreeMap<String, Slot>) -> BTreeMap<String, Option<u64>> {
    let mut limits: BTreeMap<String, Option<u64>> = BTreeMap::new();
    for slot in slots.values() {
        let Run::Container(c) = &slot.run else { continue };
        let limit = limits.entry(storage_pod(slot)).or_default();
        if let Some(bytes) = c.resources.as_ref().and_then(|r| r.storage.as_ref()?.bytes()) {
            *limit = Some(limit.unwrap_or(0).saturating_add(bytes));
        }
    }
    limits
}

/// The id of a unit: of the second generation of its replica where `b` (see `pod_id`).
fn unit_id(prefix: &str, replica: u32, b: bool, unit: &str) -> Result<String, String> {
    // (Not `.` or `..`: a unit's name is a directory's too, under its replica's.)
    let ok = !unit.is_empty()
        && unit.bytes().any(|b| b != b'.')
        && unit
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    match ok {
        // (And one the root part takes for a name: it is asked of a unit by its id alone.)
        true => {
            let id = format!("{prefix}{replica}{}_{unit}", if b { "b" } else { "" });
            crate::root_part::label("unit id", &id).map(|()| id)
        }
        false => Err(format!("unit name `{unit}`: use letters, digits, `-` and `.`")),
    }
}

/// The pod of one generation of a replica: `pod_of`'s for the first, and for the second (the new
/// replica a rolling update starts beside the old) another network namespace, as its own.
fn pod_id(owner: &str, replica: u32, b: bool) -> String {
    format!("{}{}", pod_of(owner, replica), if b { "b" } else { "" })
}

/// A slot of the second generation of its replica (its pod is not the one `pod_of` names).
fn is_second(slot: &Slot) -> bool {
    slot.pod
        .as_ref()
        .is_some_and(|(pod, _)| *pod != pod_of(&slot.owner, slot.replica))
}

/// The generation that answers for a replica (true: the second): the one its update began,
/// once that is ready, or the only one.
fn live_gen(
    gens: &BTreeMap<(String, u32), bool>,
    surging: &Surging,
    slots: &BTreeMap<String, Slot>,
    owner: &str,
    replica: u32,
) -> bool {
    let key = (owner.to_string(), replica);
    let new = gens.get(&key).copied().unwrap_or(false);
    match surging.contains_key(&key) && !second_is_live(slots, owner, replica, new) {
        true => !new,
        false => new,
    }
}

/// Of a replica being replaced beside the old, the generation that answers: the one the status tells of.
fn answers(
    gens: &BTreeMap<(String, u32), bool>,
    surging: &Surging,
    slots: &BTreeMap<String, Slot>,
    slot: &Slot,
) -> bool {
    is_second(slot) == live_gen(gens, surging, slots, &slot.owner, slot.replica)
}

/// What the status says of a unit: its revision and whether it is ready (a probe passed, if it has one).
fn unit_status(slot: &Slot) -> Value {
    json!({ "name": slot.run.name(), "replica": slot.replica, "state": slot.state, "ready": slot.ready(), "restarts": slot.restarts, "revision": slot.revision })
}

/// Every unit of the generation `b` of the replica is ready: it answers for the replica.
fn second_is_live(slots: &BTreeMap<String, Slot>, owner: &str, replica: u32, b: bool) -> bool {
    let units: Vec<&Slot> = slots
        .values()
        .filter(|slot| slot.owner == owner && slot.replica == replica && is_second(slot) == b)
        .collect();
    !units.is_empty() && units.iter().all(|slot| slot.ready())
}

/// How long the old replica of a surge runs on once its replacement is ready: what a Service on
/// another node, still going to it, is given to see the new one answers.
const DRAIN: Duration = Duration::from_secs(3);

fn drained(ready_since: Option<Instant>) -> bool {
    ready_since.is_some_and(|at| at.elapsed() >= DRAIN)
}

/// How long a replacement is given to answer, beside the start deadlines of its liveness probes,
/// before the status says what it lacks.
const SLOW: Duration = Duration::from_secs(30);

/// The generation (true: the second) of the replica that the unit `id` is of, if it is of it.
fn gen_of(owner: &str, replica: u32, id: &str) -> Option<bool> {
    let rest = id.strip_prefix(&pod_of(owner, replica))?;
    match (rest.starts_with('_'), rest.starts_with("b_")) {
        (true, _) => Some(false),
        (_, true) => Some(true),
        _ => None,
    }
}

/// The pod a unit's id names (`{pod}_{unit}`: a unit's name has no `_`).
fn pod_of_unit(id: &str) -> &str {
    id.rsplit_once('_').map_or(id, |(pod, _)| pod)
}

/// The time `/proc/PID/stat` says its process started, in clock ticks after boot (field 22, after
/// a name that may hold spaces and parentheses).
fn starttime_of(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?.1.split_whitespace().nth(19)?.parse().ok()
}

/// Which generation a replica is wanted as when a kithd started again finds both of its generations
/// running (the old and the one its update began) and does not know which is which: the one that is
/// wanted as it runs is the new, and the other the old; where both or neither is, the one whose
/// processes started later (`starts`, by unit id); the second where that is not known either.
/// ponytail: a third update begun in the same stretch is not told apart; the old is held either way.
fn adopted_gen(
    marks: &BTreeMap<String, String>,
    starts: &BTreeMap<String, u64>,
    wanted: &BTreeMap<String, Slot>,
    owner: &str,
    replica: u32,
) -> bool {
    let runs = |second: bool| {
        wanted
            .iter()
            .filter(|(_, s)| s.owner == owner && s.replica == replica && is_second(s) == second)
            .any(|(id, s)| marks.get(id).is_some_and(|was| *was == mark(s)))
    };
    if runs(false) != runs(true) {
        return runs(true);
    }
    let began = |second: bool| {
        let of = starts
            .iter()
            .filter(|(id, _)| gen_of(owner, replica, id) == Some(second));
        of.map(|(_, at)| *at).min()
    };
    match (began(false), began(true)) {
        (Some(first), Some(second)) => second >= first,
        _ => true,
    }
}

/// What a kithd started again makes of a replica it finds running: `(second, surge)`, the generation
/// wanted and whether the other is held beside it till that answers. Both generations found: the one
/// that [`adopted_gen`] says is new, the other held. One found that is not as wanted: the other
/// generation, where the replica could run twice (as the update itself would, see `no_surge`), so that
/// it is not down for the new one's pull and init; else the one found, replaced as ever.
/// ponytail: no `no_room` check here (what runs is not in `slots`), and no stopped-first note.
fn after_restart(
    marks: &BTreeMap<String, String>,
    starts: &BTreeMap<String, u64>,
    wanted: &BTreeMap<String, Slot>,
    owner: &str,
    replica: u32,
    root: bool,
) -> (bool, bool) {
    let ran = |second: bool| marks.keys().any(|id| gen_of(owner, replica, id) == Some(second));
    if ran(false) && ran(true) {
        return (adopted_gen(marks, starts, wanted, owner, replica), true);
    }
    let found = ran(true);
    let as_wanted = marks
        .iter()
        .filter(|(id, _)| gen_of(owner, replica, id) == Some(found))
        .all(|(id, was)| wanted.get(id).is_some_and(|s| mark(s) == *was));
    let other: Vec<&Slot> = wanted
        .values()
        .filter(|s| s.owner == owner && s.replica == replica && is_second(s) != found)
        .collect();
    let surge = !as_wanted && !other.is_empty() && other.iter().all(|s| s.rolling) && no_surge(&other, root).is_none();
    (found != surge, surge)
}

/// What a slot about to start does with the unit adopted under its id, whose mark it was started as.
#[derive(Debug, PartialEq)]
enum Taken {
    /// None adopted: start it.
    Free,
    /// As it ran: taken back.
    Take,
    /// Another mark, and not stopped yet (a stop that failed): the slot waits, as for a leaving one.
    Stuck,
}

fn taken_back(was: Option<&str>, now: &str) -> Taken {
    match was {
        None => Taken::Free,
        Some(was) if was == now => Taken::Take,
        Some(_) => Taken::Stuck,
    }
}

/// A stop of an adopted unit that failed is tried again at most every `STOP_RETRY` (`tried`: the last).
fn retry_due(tried: Option<Instant>) -> bool {
    tried.is_none_or(|at| at.elapsed() >= STOP_RETRY)
}

/// The pods of the adopted units `ids` that are [`held`]: they answer without a slot, so they are
/// taken back and kept like the pods of the slots.
fn held_pods<'a>(
    ids: impl IntoIterator<Item = &'a str>,
    surging: &Surging,
    wanted: &BTreeMap<String, Slot>,
) -> BTreeSet<String> {
    let held = ids.into_iter().filter(|id| held(surging, wanted, id));
    held.map(|id| pod_of_unit(id).to_string()).collect()
}

/// An adopted unit nothing wants that is the old generation of a replica whose new one has not
/// answered (and drained) yet: it goes on answering till then.
fn held(surging: &Surging, wanted: &BTreeMap<String, Slot>, id: &str) -> bool {
    held_by(surging, wanted, id).is_some()
}

/// The owner whose update holds the unit `id`, if one does (see [`held`]).
fn held_by<'a>(surging: &'a Surging, wanted: &BTreeMap<String, Slot>, id: &str) -> Option<&'a str> {
    if wanted.contains_key(id) {
        return None;
    }
    surging.iter().find_map(|((owner, replica), (_, ready_since))| {
        let rest = id.strip_prefix(&pod_of(owner, *replica));
        let of = rest.is_some_and(|rest| rest.starts_with('_') || rest.starts_with("b_"));
        (!drained(*ready_since) && of).then_some(owner.as_str())
    })
}

/// What the status says of the replicas of `owner` being updated, `(replica, words)`: why one was
/// stopped first, and for one whose replacement does not answer after `SLOW` what that lacks.
fn update_says(
    gens: &BTreeMap<(String, u32), bool>,
    surging: &Surging,
    slots: &BTreeMap<String, Slot>,
    owner: &str,
    stopped: Option<&(u32, String)>,
) -> Vec<(u32, String)> {
    let mut says: Vec<(u32, String)> = stopped.cloned().into_iter().collect();
    for ((_, replica), (began, ready_since)) in surging.iter().filter(|((o, _), _)| o == owner) {
        let new = gens.get(&(owner.to_string(), *replica)).copied().unwrap_or(false);
        let units: Vec<&Slot> = slots
            .values()
            .filter(|s| s.owner == owner && s.replica == *replica && is_second(s) == new)
            .collect();
        let start = units.iter().filter_map(|s| match &s.run {
            Run::Container(c) => c.liveness.as_ref()?.start_seconds,
            Run::Exec(_) => None,
        });
        let given = SLOW + Duration::from_secs(start.max().unwrap_or(0).into());
        if ready_since.is_some() || units.is_empty() || began.elapsed() < given {
            continue;
        }
        let lacks: Vec<String> = units
            .iter()
            .filter(|s| !s.ready())
            .map(|s| format!("{}: {}", s.run.name(), s.message.as_deref().unwrap_or(s.state)))
            .collect();
        says.push((
            *replica,
            format!(
                "rolling update: replica {replica}'s replacement is not ready after {} s ({}); the old one still answers",
                began.elapsed().as_secs(),
                lacks.join(", ")
            ),
        ));
    }
    says
}

/// Why a replica of these units (as the update wants them) cannot run twice at once, if it
/// cannot: what is held once on a node (its network, a device, a volume) or not a container.
fn no_surge(units: &[&Slot], root: bool) -> Option<String> {
    let reason = if !root || units.iter().any(|slot| slot.pod.is_none()) {
        "its units share the node's network (a pod, which kithd makes as root, has its own)"
    } else if units
        .iter()
        .any(|slot| !slot.devices.is_empty() || slot.seat.is_some() || !slot.dmem.is_empty())
    {
        "it holds a device or a seat, which a second replica could not have as well"
    } else if units.iter().any(|slot| !slot.volumes.is_empty()) {
        "it mounts a volume, which a second replica could not have as well"
    } else if units.iter().any(|slot| match &slot.run {
        Run::Container(c) => c.volume_mounts.iter().any(|m| m.scratch.is_some()),
        Run::Exec(_) => false,
    }) {
        // (A ConfigMap's files are the replica's too, but what is written is what is wanted: ponytail.)
        "it mounts a scratch, which both its replicas would share"
    } else if units.iter().any(|slot| !matches!(slot.run, Run::Container(_))) {
        "it has a unit that is not a container"
    } else {
        return None;
    };
    Some(reason.into())
}

/// The CPUs and bytes of memory the units ask for.
fn asks(slot: &Slot) -> (f64, f64) {
    let resources = match &slot.run {
        Run::Container(c) => &c.resources,
        Run::Exec(e) => &e.resources,
    };
    let each = |q: Option<&kith_api::kinds::Quantity>| q.map_or(0.0, |q| q.value());
    resources
        .as_ref()
        .map_or((0.0, 0.0), |r| (each(r.cpu.as_ref()), each(r.memory.as_ref())))
}

/// Why the node, which has `capacity` (CPUs, bytes of memory), has no room for the units `new`
/// beside what its slots ask for, if it has none. What asks for nothing needs no room, and a
/// capacity not known (0) is no ground to refuse.
fn no_room(capacity: (f64, f64), slots: &BTreeMap<String, Slot>, new: &[&Slot]) -> Option<String> {
    let sum = |units: &mut dyn Iterator<Item = &Slot>| units.map(asks).fold((0.0, 0.0), |a, b| (a.0 + b.0, a.1 + b.1));
    let extra = sum(&mut new.iter().copied());
    let used = sum(&mut slots.values());
    if capacity.0 > 0.0 && extra.0 > 0.0 && used.0 + extra.0 > capacity.0 {
        return Some(format!(
            "this node has no CPU to spare for a second replica ({} of {})",
            used.0 + extra.0,
            capacity.0
        ));
    }
    if capacity.1 > 0.0 && extra.1 > 0.0 && used.1 + extra.1 > capacity.1 {
        return Some(format!(
            "this node has no memory to spare for a second replica ({} of {} bytes)",
            used.1 + extra.1,
            capacity.1
        ));
    }
    None
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
    let status = resource.status.as_ref();
    // (A replica a rolling update has replaced runs as its second generation: status says so.)
    let second = status.is_some_and(|s| {
        let mut units = s["containers"].as_array().into_iter().flatten();
        units.any(|u| u["replica"] == replica && u["gen"] == 1)
    });
    let id = unit_id(&prefix, replica, second, name).map_err(Error::Invalid)?;
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
        let found = found.map(|me| {
            fresh(&mut self.scanned, SCAN_KEPT, || {
                crate::devices::scan(Path::new("/sys"), me)
            })
        });
        let (resources, granted, mounted, tunes, found): (Vec<Resource>, _, _, _, _) = {
            let file_store = shared.store.lock().expect("a handler panicked holding the store");
            let store = &file_store.store;
            let found = found.map(|found| crate::devices::as_found(store, found));
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
        // What the root part will give a container: these device nodes and no others.
        crate::root_part::claim(granted.values().flat_map(|granted| granted.devices.iter().cloned()));
        let mut wanted: BTreeMap<String, Slot> = BTreeMap::new();
        // Replicas found running as both generations, which one is wanted is not known yet.
        let mut undecided: Vec<(String, u32)> = Vec::new();
        // Per Workload, NodeWorkload or Job key: things to say in its status that belong to no unit.
        let mut notes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut owners = BTreeSet::new();
        // Alone, this node runs everything; in a cluster, the replicas the scheduler bound
        // to it (`nodes` in the status), and a Job when its one binding is here.
        let me = shared.cluster.as_ref().map(|cluster| cluster.me.name.as_str());
        let alone = self.alone.load(Ordering::Relaxed);
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
            let crate::claims::Granted {
                devices,
                seat,
                classes,
                dmem,
            } = granted.get(&key).cloned().unwrap_or_default();
            let allowed = !claimed || (resource.kind != "NodeWorkload" && granted.contains_key(&key));
            // What this node's own policy refuses of it is not run here, whoever wrote it and
            // whatever the store says (docs/adr-privilege.md): said where a replica is this
            // node's to run.
            let mut refused = node_policy.refuses(
                &template,
                !crate::vm::pci(&devices).is_empty(),
                resource.kind == "NodeWorkload",
            );
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
            if (resource.kind == "Job" && !here(0)) || held_alone(&resource.kind, alone) {
                // Bound here again later, or back from alone, it starts over, like after a restart.
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
                    let units = names
                        .iter()
                        .filter(|name| unit_id(&prefix, 0, false, name).is_ok())
                        .count();
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
                // A replica's own claim whose Volume is not here is not started, whatever else
                // is: it would be on an empty directory, with its data on another node or lost.
                let lacking = template.containers().flat_map(|c| &c.volume_mounts).find_map(|mount| {
                    let name = format!("{}-{replica}", mount.volume.as_ref()?);
                    (mount.per_replica == Some(true) && !volumes.contains_key(&name)).then_some(name)
                });
                if let Some(name) = lacking {
                    let why = format!("replica {replica} waits: its Volume {name} is not ready on this node");
                    if !note.contains(&why) {
                        note.push(why);
                    }
                    continue;
                }
                // Which generation of the replica is wanted: the second where a rolling update has
                // started it beside the old (see `gens`); one found running as it, by a kithd that
                // was started again, is the one it was.
                let surges = resource.kind == "Workload" && template.pod == Some(true);
                let seen = |ran: String| self.adopted.keys().any(|id| id.starts_with(&ran));
                let second = match self.gens.get(&(key.clone(), replica)) {
                    Some(second) => Some(*second),
                    // Found running as both (an update was begun), or as one a rolling update could
                    // replace beside it: both are wanted below, and `after_restart` says which, once
                    // the marks are known.
                    None if surges
                        && (seen(format!("{prefix}{replica}b_")) && seen(format!("{prefix}{replica}_"))
                            || rolling
                                && (seen(format!("{prefix}{replica}b_")) || seen(format!("{prefix}{replica}_")))) =>
                    {
                        undecided.push((key.clone(), replica));
                        None
                    }
                    None => Some(surges && seen(format!("{prefix}{replica}b_"))),
                };
                if let Some(second) = second.filter(|_| surges) {
                    self.gens.insert((key.clone(), replica), second);
                }
                let tries = second.map_or(vec![false, true], |second| vec![second]);
                let each = tries.iter().flat_map(|second| {
                    units
                        .iter()
                        .zip(&envs)
                        .zip(&files)
                        .enumerate()
                        .map(move |x| (*second, x))
                });
                for (second, (at, ((unit, env), files))) in each {
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
                    match unit_id(&prefix, replica, second, unit.name()) {
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
                                (pod_id(&key, replica, second), format!("{name}-{replica}"))
                            }),
                            exit: template.exit.clone().filter(|_| template.pod == Some(true)),
                            notes: template.annotations.clone(),
                            devices: devices.clone(),
                            dmem: dmem.clone(),
                            seat: seat.clone(),
                            volumes: mounts_of(unit, &volumes, replica),
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
                            restarted: None,
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
        // A unit an earlier kithd left running is asked again as the units above are: once its
        // processes are gone it is deleted, and what waits for its id or its devices starts below.
        for id in self.left.keys().cloned().collect::<Vec<_>>() {
            if !retry_due(self.stuck.get(&id).copied()) {
                continue;
            }
            let Some(unit) = self.left.remove(&id) else { continue };
            if let Some(handle) = delete_again(&id, unit.handle, &mut self.stuck).await {
                self.left.insert(id, Left { handle, ..unit });
            }
        }
        // What `kubectl delete pod` asked to restart is stopped here, and started by step 3 as due.
        let mut marked = std::mem::take(&mut *shared.restarts.lock().expect("a handler panicked holding the restarts"));
        apply_restarts(&mut self.slots, &mut marked, Instant::now()).await;
        // A replica found running as both generations by a kithd started again: one is wanted (the
        // new one) and the other held below, so that a restart mid-update stops neither at once.
        let marks: BTreeMap<String, String> = self
            .adopted
            .iter()
            .map(|(id, (_, was))| (id.clone(), was.clone()))
            .collect();
        // (When each started, for the two that are neither as wanted.)
        let starts: BTreeMap<String, u64> = match undecided.is_empty() {
            true => BTreeMap::new(),
            false => self
                .adopted
                .iter()
                .filter_map(|(id, (handle, _))| {
                    let stat = std::fs::read_to_string(format!("/proc/{}/stat", handle.pid())).ok()?;
                    Some((id.clone(), starttime_of(&stat)?))
                })
                .collect(),
        };
        let root = nix::unistd::getuid().is_root();
        for (owner, replica) in undecided {
            let (second, surge) = after_restart(&marks, &starts, &wanted, &owner, replica, root);
            wanted.retain(|_, s| !(s.owner == owner && s.replica == replica && is_second(s) != second));
            self.gens.insert((owner.clone(), replica), second);
            if surge {
                self.surging.entry((owner, replica)).or_insert((Instant::now(), None));
            }
        }
        let mut stale: Vec<String> = Vec::new();
        let mut again_now = false;
        fn of(slot: &Slot) -> (&str, u32) {
            (slot.owner.as_str(), slot.replica)
        }
        // A replica nothing wants any more is no longer being replaced; and a replica whose new
        // generation is ready since a while (and stays so) has its old one let go below.
        let wants = |owner: &str, replica: u32| wanted.values().any(|new| new.owner == owner && new.replica == replica);
        self.surging.retain(|(owner, replica), _| wants(owner, *replica));
        self.gens.retain(|(owner, replica), _| wants(owner, *replica));
        for ((owner, replica), (_, since)) in self.surging.iter_mut() {
            let new = self.gens.get(&(owner.clone(), *replica)).copied().unwrap_or(false);
            *since = match (second_is_live(&self.slots, owner, *replica, new), *since) {
                (true, was) => was.or(Some(Instant::now())),
                (false, _) => None,
            };
        }
        // Taken back units nothing wants any more, or wants otherwise, are stopped: but the old
        // generation of a replica whose update is not over (see `held`) stays till the new one answers.
        // A held unit has no slot, so it has no restart, storage limit or probe, and no place in the
        // status: it only answers till its replacement does. Its pod is taken back here, as a slot's
        // is where it starts (no rule of its pod's link, no Service could reach it), and kept below.
        let mut unwanted: Vec<String> = Vec::new();
        for (id, (handle, was)) in &self.adopted {
            if !wanted.get(id).is_none_or(|new| &mark(new) != was) {
                continue;
            }
            // Its pod is taken back with its owner's egress rules, as a slot's is.
            let adopt = |pod: &str, owner: &str| {
                let egress = {
                    let held = shared.store.lock().expect("a handler panicked holding the store");
                    crate::services::egress_of(&held.store, owner, crate::services::mesh_prefix(shared))
                };
                let mut pods = shared.pods.lock().expect("nothing panics holding the pods");
                pods.adopt(
                    self.logs.parent().unwrap_or(&self.logs),
                    pod,
                    handle.pid(),
                    owner,
                    egress,
                )
            };
            // (One whose pod cannot be taken back answers nobody: stopped, as if not held.)
            let holder = held_by(&self.surging, &wanted, id);
            let kept = holder.is_some()
                && match nix::unistd::getuid().is_root() {
                    true => adopt(pod_of_unit(id), holder.unwrap_or_default())
                        .inspect_err(|e| eprintln!("kithd: {id}: {e}"))
                        .is_ok(),
                    false => true,
                };
            if !kept && retry_due(self.stuck.get(id).copied()) {
                unwanted.push(id.clone());
            }
        }
        for id in unwanted {
            if let Some((handle, was)) = self.adopted.remove(&id) {
                // (Said once: a retry that fails again is quiet.)
                if !self.stuck.contains_key(&id) {
                    eprintln!("kithd: {id}: run by an earlier kithd and not wanted as it is: stopped");
                }
                // One that is not gone is asked again after STOP_RETRY, not forgotten running; its
                // slot, if wanted, waits for it (see `taken_back`).
                if let Some(handle) = delete_again(&id, handle, &mut self.stuck).await {
                    self.adopted.insert(id, (handle, was));
                }
            }
        }
        let held_pods = held_pods(self.adopted.keys().map(String::as_str), &self.surging, &wanted);
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
                || new.dmem != slot.dmem
                || new.seat != slot.seat
                || new.volumes != slot.volumes
                || new_values
        };
        for (id, slot) in &self.slots {
            if slot.leaving {
                continue;
            }
            let Some(new) = wanted.get(id) else {
                // What a replica's replacement began beside stays until that answers (and its
                // drain is over): only then is it not wanted.
                let held = self.surging.get(&(slot.owner.clone(), slot.replica));
                if !held.is_some_and(|(_, ready_since)| !drained(*ready_since)) {
                    stale.push(id.clone());
                }
                continue;
            };
            if differs(new, slot) {
                changed.entry(&slot.owner).or_default().insert(slot.replica);
            }
        }
        self.surging.retain(|_, (_, ready_since)| !drained(*ready_since));
        // What a note on a replica stopped first says is kept while its update goes on.
        self.stopped_first.retain(|owner, _| {
            changed.contains_key(owner.as_str()) || self.slots.values().any(|s| s.owner == *owner && !s.ready())
        });
        for (owner, replicas) in changed {
            let mine = || self.slots.values().filter(move |slot| slot.owner == owner);
            // (Of a replica being replaced beside the old, the one that answers.)
            let live = |slot: &Slot| {
                is_second(slot) == live_gen(&self.gens, &self.surging, &self.slots, &slot.owner, slot.replica)
            };
            let ready = |replica: u32| {
                mine()
                    .filter(|slot| slot.replica == replica && live(slot))
                    .all(Slot::ready)
            };
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
                let others_ready = mine().all(|slot| {
                    slot.replica == pick
                        || (ready(slot.replica) && !self.surging.contains_key(&(owner.to_string(), slot.replica)))
                });
                let (ready_pick, at) = (ready(pick), (owner.to_string(), pick));
                match (self.surging.get(&at).map(|s| s.1), ready_pick) {
                    // Its new replica is not ready, and what it was started as is not what is
                    // wanted now: it is replaced (the old one answers meanwhile).
                    (Some(None), _) | (None, false) => vec![pick],
                    // Its new replica answers and the old one is draining: the next update waits.
                    (Some(Some(_)), _) => Vec::new(),
                    (None, true) if !others_ready => {
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
                    (None, true) => {
                        // Beside the old, the new one starts first, unless it holds what is held
                        // once, or the node has no room for both.
                        let units: Vec<&Slot> = wanted
                            .values()
                            .filter(|new| new.owner == owner && new.replica == pick)
                            .collect();
                        let room = shared.members.capacity(shared.members.me());
                        let why = no_surge(&units, nix::unistd::getuid().is_root())
                            .or_else(|| room.and_then(|room| no_room(room, &self.slots, &units)));
                        match why {
                            None => {
                                let was = self.gens.get(&at).copied().unwrap_or(false);
                                self.gens.insert(at.clone(), !was);
                                self.surging.insert(at, (Instant::now(), None));
                                // (The new one is wanted from the next pass.)
                                again_now = true;
                                Vec::new()
                            }
                            Some(why) => {
                                let said = format!("rolling update: replica {pick} is stopped first: {why}");
                                // (Said in the status on both paths: see the report below.)
                                self.stopped_first.insert(owner.into(), (pick, said));
                                vec![pick]
                            }
                        }
                    }
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
                match Direct::units().unplug(handle, id, &path) {
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
        let leaving_now = leaving_of(&self.slots, self.left.values().map(|l| (&l.id, &l.devices[..])));
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
            match added.iter().try_for_each(|path| Direct::units().plug(handle, id, path)) {
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
        let replicas = self
            .slots
            .values()
            .flat_map(|slot| [pod_of(&slot.owner, slot.replica), storage_pod(slot)])
            .chain(held_pods.iter().cloned());
        let memory = crate::files::memory_dir();
        let bases: Vec<&Path> = [Some(state.as_path()), memory.as_deref()]
            .into_iter()
            .flatten()
            .collect();
        crate::files::sweep(&bases, &replicas.collect());
        // A pod none of whose units is wanted any more is let go, its network with it.
        // (Also the pod of a held old generation, till it is stopped: its record goes with the pod then.)
        let pods: BTreeSet<&str> = self
            .slots
            .values()
            .filter_map(|slot| Some(slot.pod.as_ref()?.0.as_str()))
            .chain(held_pods.iter().map(String::as_str))
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
        // The data of a Volume made for a claim that is gone, where no unit mounts it.
        self.tend_wipes(shared, &state, &mounted);

        // 3. Notice exits, then start whatever is due.
        // A Job's unit that ended is accounted for in step 1, and a unit that started may be
        // what a rolling update waits for in step 2: go round again at once.
        let mut job_moved = false;
        // Per replica: how many of its init containers have run to their end, well.
        // (Of each generation of a replica: the new one runs its init containers itself.)
        let mut first: BTreeMap<(String, u32, bool), u32> = BTreeMap::new();
        for slot in self.slots.values().filter(|slot| slot.done()) {
            *first
                .entry((slot.owner.clone(), slot.replica, is_second(slot)))
                .or_default() += 1;
        }
        // Where a Service looks for a replica: the generation that answers for it.
        let answering: BTreeMap<String, String> = self
            .gens
            .keys()
            .filter(|(owner, replica)| live_gen(&self.gens, &self.surging, &self.slots, owner, *replica))
            .map(|(owner, replica)| (pod_of(owner, *replica), pod_id(owner, *replica, true)))
            .collect();
        shared
            .pods
            .lock()
            .expect("nothing panics holding the pods")
            .set_live(answering);
        // The units still stopping, with their devices: what is due waits for them (see
        // held_by_leaving). One that starts stopping in this pass is added as it does.
        let mut leaving = leaving_of(&self.slots, self.left.values().map(|l| (&l.id, &l.devices[..])));
        let limits = pod_limits(&self.slots);
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
                    match Direct::units().kill(handle, id) {
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
            let ended = first
                .get(&(slot.owner.clone(), slot.replica, is_second(slot)))
                .copied()
                .unwrap_or(0);
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
                // Its pod's project, its limit set, before anything of it starts.
                let pod = storage_pod(slot);
                let given = match (&slot.run, self.projects.as_mut()) {
                    (Run::Container(_), Some(projects)) => Some(
                        projects
                            .give(&pod, limits.get(&pod).copied().flatten())
                            .map_err(|e| format!("putting its pod's files in a project of their own: {e}")),
                    ),
                    _ => None,
                };
                let mut stop_now = stopping.clone();
                let ran_as = mark(slot);
                let taken = match taken_back(self.adopted.get(id).map(|(_, was)| was.as_str()), &ran_as) {
                    Taken::Take => {
                        self.stuck.remove(id);
                        self.adopted.remove(id)
                    }
                    Taken::Free => None,
                    // A unit of this id that could not be stopped yet: its cgroup is still there.
                    Taken::Stuck => {
                        slot.held = true;
                        slot.message = Some("stopping: the unit an earlier kithd ran is not gone yet".into());
                        continue;
                    }
                };
                let started = tokio::select! {
                    started = async {
                        if let Some((handle, _)) = taken {
                            eprintln!("kithd: {id}: taken back, as it ran");
                            if let Some((pod, _)) = slot.pod.as_ref().filter(|_| nix::unistd::getuid().is_root()) {
                                let egress = {
                                    let held = shared.store.lock().expect("a handler panicked holding the store");
                                    let prefix = crate::services::mesh_prefix(shared);
                                    crate::services::egress_of(&held.store, &slot.owner, prefix)
                                };
                                let mut pods = shared.pods.lock().expect("nothing panics holding the pods");
                                let state = self.logs.parent().unwrap_or(&self.logs);
                                if let Err(e) = pods.adopt(state, pod, handle.pid(), &slot.owner, egress) {
                                    eprintln!("kithd: {id}: {e}");
                                }
                            }
                            return Ok(handle);
                        }
                        let project = given.transpose()?;
                        start(shared, &self.runtime, &self.logs, mesh, id, slot, project).await
                    } => started,
                    // A pull can take minutes; shutting down does not wait for it.
                    _ = stop_now.changed() => return TICK,
                };
                // A cached image starts without ever waiting; let the API answer between starts.
                tokio::task::yield_now().await;
                match started {
                    Ok(handle) => {
                        // How it runs differently from what it asked (its root read-only, where the kernel
                        // refuses an overlay) is said while it runs.
                        let note = handle.note;
                        slot.handle = Some(handle);
                        slot.tuned = None;
                        // Why it was replaced for what it wrote stays said while it runs again, once.
                        let replaced = std::mem::take(&mut slot.replaced);
                        let replaced = slot
                            .message
                            .take()
                            .filter(|m| replaced && m.starts_with(storage::REPLACED));
                        (slot.state, slot.message, slot.start_at, slot.started) =
                            ("running", running_said(note, replaced), None, Instant::now());
                        if let Run::Container(c) = &slot.run {
                            let pod = slot.pod.as_ref().map(|(pod, _)| pod.clone());
                            slot.probes = crate::probe::start(shared.clone(), c, id, pod);
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
                match Direct::units().tune(handle, id, guaranteed, cpu) {
                    Ok(refused) => {
                        for refused in refused {
                            eprintln!("kithd: {id}: its seat's arrangement is not all in place: {refused}");
                        }
                    }
                    Err(e) => eprintln!("kithd: {id}: its seat's arrangement is not put in place: {e}"),
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
        for (key, mut notes) in notes {
            // What a rolling update says: in `notes` where one node reports; in a cluster, where a
            // field only this node says is rewritten by the others, on the units of its replica.
            let says = update_says(
                &self.gens,
                &self.surging,
                &self.slots,
                &key,
                self.stopped_first.get(&key),
            );
            if me.is_none() {
                notes.extend(says.iter().map(|(_, said)| said.clone()));
            }
            // Of a replica being replaced beside the old, the one that answers.
            let mine: Vec<&Slot> = self
                .slots
                .values()
                .filter(|slot| slot.owner == key)
                .filter(|slot| answers(&self.gens, &self.surging, &self.slots, slot))
                .collect();
            let units: Vec<Value> = mine
                .iter()
                .map(|slot| {
                    let mut c = unit_status(slot);
                    if let Some(code) = slot.exit_code {
                        c["exitCode"] = json!(code);
                    }
                    if let Some(at) = slot.restarted {
                        c["restarted"] = json!(at);
                    }
                    let said = says
                        .iter()
                        .filter(|(r, _)| *r == slot.replica && me.is_some())
                        .map(|(_, said)| said.as_str());
                    let cannot = slot.probes.as_ref().and_then(|p| p.why());
                    let message: Vec<&str> = slot
                        .message
                        .as_deref()
                        .into_iter()
                        .chain(cannot.as_deref())
                        .chain(said)
                        .collect();
                    if !message.is_empty() {
                        c["message"] = json!(message.join("; "));
                    }
                    // (The logs of a replica replaced beside the old are those of the new: `log_of`.)
                    if is_second(slot) {
                        c["gen"] = json!(1);
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

        if job_moved || again_now {
            return Duration::ZERO;
        }
        let waiting = self.slots.values().filter(|slot| !slot.held);
        let next = waiting.filter_map(|slot| slot.start_at).min();
        let next = next.map_or(TICK, |at| at.saturating_duration_since(Instant::now()).min(TICK));
        // A replica being replaced beside the old is looked at often: its new one answers and its
        // old one goes in about the drain.
        match self.surging.is_empty() {
            true => next,
            false => next.min(DRAIN / 3),
        }
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
                .filter(|slot| slot.handle.is_some() && storage_pod(slot) == *pod)
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
        if let Some(job) = self.leftovers.as_mut() {
            let hung = || {
                "removing the scratch left by an earlier run has not ended in 60 s: it goes on, and holds no pod's count".to_string()
            };
            if job.done(hung).is_some() {
                self.leftovers = None;
            }
        }
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
                // A held pod's running units say while it holds all its limit lets it.
                for pod in &pods {
                    let reached = storage::reached(pod);
                    let theirs =
                        |slot: &&mut Slot| storage_pod(slot) == pod.id && slot.handle.is_some() && !slot.leaving;
                    for slot in self.slots.values_mut().filter(theirs) {
                        let said = slot.message.as_deref();
                        if said.is_none_or(|m| m.starts_with(storage::REACHED)) {
                            slot.message = reached.clone();
                        }
                    }
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
        // Per pod: its limit, the sum of its containers', the roots and cgroups of those running,
        // and whether one is unconfined (one with the node's users may move its files out of
        // its project: its pod is counted).
        type Paths = Vec<PathBuf>;
        let limits = pod_limits(&self.slots);
        let mut pods: BTreeMap<String, (Option<u64>, Paths, Paths, bool)> = BTreeMap::new();
        for slot in self.slots.values() {
            let Run::Container(c) = &slot.run else { continue };
            let pod = storage_pod(slot);
            let limit = limits.get(&pod).copied().flatten();
            let (_, roots, cgroups, unconfined) = pods.entry(pod).or_insert((limit, Vec::new(), Vec::new(), false));
            *unconfined |= c.seccomp.as_ref().is_some_and(|s| s.unconfined == Some(true));
            let running = slot.handle.as_ref().filter(|_| !slot.leaving);
            roots.extend(running.and_then(Handle::upper));
            cgroups.extend(running.map(|handle| handle.cgroup.clone()));
        }
        let held = self.projects.is_some();
        let pods: Vec<(storage::Pod, Paths, Paths)> = pods
            .into_iter()
            .filter(|(id, (limit, roots, _, _))| {
                !roots.is_empty() && !self.replacing.contains_key(id) && storage::walked(*limit, free, reserve)
            })
            .map(|(id, (limit, mut roots, cgroups, unconfined))| {
                roots.push(replicas.join(&id).join("scratch"));
                let pod = storage::Pod {
                    id,
                    limit,
                    bytes: 0,
                    finished: true,
                    again: false,
                    held: held && !unconfined,
                    files: 0,
                    most: 0,
                };
                (pod, roots, cgroups)
            })
            .collect();
        if pods.is_empty() {
            return;
        }
        // (A scratch set aside and not removed, by a kithd that stopped first, goes in a job of
        // its own, one at a time: a huge one holds no pod's count, or its clock.)
        if self.leftovers.is_none() {
            let (dirs, stop) = (
                pods.iter().map(|(pod, ..)| replicas.join(&pod.id)).collect::<Vec<_>>(),
                self.stop.clone(),
            );
            self.leftovers = Job::start("storage", &shared.changed, move || {
                dirs.iter().for_each(|replica| storage::sweep(replica, &stop));
            });
        }
        let state = state.to_path_buf();
        let stop = self.stop.clone();
        self.count = Job::start("storage", &shared.changed, move || {
            let pods: Vec<storage::Pod> = pods
                .into_iter()
                .map(|(pod, roots, cgroups)| storage::measure(pod, &roots, &cgroups, &stop))
                .collect();
            let disk = nix::sys::statvfs::statvfs(&state).ok();
            let free = disk.map_or(free, |d| d.blocks_available() * d.fragment_size());
            (free, reserve, pods)
        });
        // Done, it wakes the loop to act on it; no thread for it, the next pass tries again.
    }

    /// A Volume made for a claim that is gone has its data on this node removed, off the async
    /// threads, and only then is the Volume deleted: a removal that fails (it says why) leaves
    /// the Volume, and is tried again at the next pass. What a unit here mounts, or a workload
    /// that is placed here would, waits for it to stop.
    ///
    /// ponytail: a unit that starts on the Volume while its data goes (a workload that names it
    /// by name, after its claim went) finds its directory made anew, and loses what it wrote
    /// before the Volume is deleted. Hold the Volume with a mark the scheduler reads if that shows.
    fn tend_wipes(
        &mut self,
        shared: &std::sync::Arc<Shared>,
        state: &Path,
        mounted: &BTreeMap<String, BTreeMap<String, crate::volumes::Dir>>,
    ) {
        let Some(me) = shared.cluster.as_ref().map(|cluster| cluster.me.name.clone()) else {
            return;
        };
        if self.wiping.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let mut held = mounting(mounted);
        for slot in self.slots.values() {
            held.extend(slot.volumes.iter().map(|(dir, _, _)| volume_key(dir)));
        }
        let dirs = {
            let file_store = shared.store.lock().expect("a handler panicked holding the store");
            due(&file_store.store, &me, &held)
        };
        if dirs.is_empty() {
            return;
        }
        let (shared, state) = (shared.clone(), state.to_path_buf());
        self.wiping = Some(tokio::spawn(async move {
            let removed = tokio::task::spawn_blocking(move || wipe_all(&state, dirs)).await;
            for key in removed.unwrap_or_default() {
                if let Err(e) = shared.submit(kith_store::Command::Delete { key: key.clone() }).await {
                    eprintln!("kithd: deleting {key} after its data was removed: {e}");
                }
            }
        }));
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
            // (Asked of the root part: the path of an image is its own, from the digest.)
            let remove = |digest: &str, before| crate::root_part::drop_image(digest, before);
            Ok(prune::prune(&unused, began, grace, low, remove, &stop))
        });
    }

    /// Kills every running unit of the pod `pod`, saying `why`, and sets its disk scratch aside,
    /// to be removed once they are gone: each starts again as its restart policy says, from an
    /// empty root. A pod one of whose units started after the count `began` is left to the next
    /// count; one a unit of which could not be killed is tried again then, its scratch where it is.
    fn replace(&mut self, pod: &str, began: Instant, why: &str, state: &Path) {
        let mine = |slot: &&mut Slot| storage_pod(slot) == pod && slot.handle.is_some() && !slot.leaving;
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
            if let Some(Err(e)) = slot.handle.as_mut().map(|handle| Direct::units().kill(handle, id)) {
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

fn volume_key(dir: &crate::volumes::Dir) -> String {
    format!("Volume/{}/{}", dir.namespace, dir.name)
}

/// The Volumes (their keys) the workloads placed on a node mount.
fn mounting(mounted: &BTreeMap<String, BTreeMap<String, crate::volumes::Dir>>) -> BTreeSet<String> {
    mounted
        .values()
        .flat_map(|dirs| dirs.values().map(volume_key))
        .collect()
}

/// The Volumes made for a claim that is gone, with their data on `me`, that nothing mounts
/// (`held`: their keys): the ones to remove now.
fn due(store: &kith_api::store::Store, me: &str, held: &BTreeSet<String>) -> Vec<crate::volumes::Dir> {
    let mut dirs = crate::volumes::wipes(store, me);
    dirs.retain(|dir| !held.contains(&volume_key(dir)));
    dirs
}

/// Remove each Volume's data under `state`; the keys of those that are gone now, to be deleted.
/// One that is refused or cannot be removed is said and kept, with its Volume.
fn wipe_all(state: &Path, dirs: Vec<crate::volumes::Dir>) -> Vec<String> {
    let mut removed = Vec::new();
    for dir in dirs {
        match crate::root_part::volume_gone(state, &dir) {
            Ok(()) => removed.push(volume_key(&dir)),
            Err(e) => eprintln!("kithd: the data of {}: {e}", volume_key(&dir)),
        }
    }
    removed
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

/// What a unit of replica `replica` mounts, from the Volumes its workload's mounts come to: only a
/// container mounts. (A mount that is `perReplica` is of the replica's own claim, `NAME-REPLICA`.)
fn mounts_of(
    unit: &Run,
    volumes: &BTreeMap<String, crate::volumes::Dir>,
    replica: u32,
) -> Vec<(crate::volumes::Dir, String, bool)> {
    let Run::Container(c) = unit else { return Vec::new() };
    let mounts = c.volume_mounts.iter();
    let found = mounts.filter_map(|m| {
        let name = m.volume.as_ref()?;
        let name = if m.per_replica == Some(true) {
            format!("{name}-{replica}")
        } else {
            name.clone()
        };
        Some((volumes.get(&name)?.clone(), m.path.clone(), m.read_only == Some(true)))
    });
    found.collect()
}

/// The subPath of the volume a container mounts at `at`, if it names one.
fn part_of(run: &Run, at: &str) -> Option<String> {
    let Run::Container(c) = run else { return None };
    let mount = c.volume_mounts.iter().find(|m| m.path == at && m.volume.is_some())?;
    mount.sub_path.clone()
}

/// What a unit says while it runs: how its handle runs differently from what it asked, then why it
/// was replaced for what it wrote, each said once.
fn running_said(note: Option<&str>, replaced: Option<String>) -> Option<String> {
    note.map(str::to_string)
        .into_iter()
        .chain(replaced)
        .reduce(|said, more| format!("{said}; {more}"))
}

/// A refusal of a node's root container, said with the policy that allows it: the runtime says what
/// the container would be; here whose word refused it.
fn node_root_refusal(said: String) -> String {
    match said.contains(kith_runtime::NODE_ROOT) {
        true => format!(
            "this node's policy refuses containers that are the node's root (rootContainers is off: `--node-policy root-containers` where the node's kithd is started allows them): {said}"
        ),
        false => said,
    }
}

/// `mesh`: the cluster's mesh and this node's name, for a volume another node serves.
async fn start(
    shared: &Shared,
    runtime: &Runtime,
    logs: &Path,
    mesh: Option<(std::net::Ipv6Addr, &str)>,
    id: &str,
    slot: &mut Slot,
    project: Option<u32>,
) -> Result<Handle, String> {
    let resources = match &slot.run {
        Run::Container(c) => &c.resources,
        Run::Exec(e) => &e.resources,
    };
    // What this node's root part does for the units it starts (docs/adr-privilege.md).
    let root = crate::root_part::Direct::today(&shared.pods, Some(runtime));
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
        dmem: slot.dmem.clone(),
        // A NodeWorkload is the node's own: it keeps the node's users.
        host_users: slot.owner.starts_with("NodeWorkload/"),
        project,
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
            None => crate::root_part::volume(state, dir),
        };
        let host = host.map_err(|e| format!("volume {}: {e}", dir.name))?;
        unit.mounts.push(kith_runtime::Mount {
            host,
            container: at.clone(),
            read_only: *read_only,
            // (Not a directory of the host's that an admin named: that one is theirs. Nor
            // what it only reads: another workload's user may be who writes it.)
            give: dir.namespace != crate::volumes::SYSTEM && !*read_only,
            part: part_of(&slot.run, at),
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
                // (A map's one file is kithd's, found above; a scratch's part is the runtime's
                // to open beneath it.)
                part: mount.scratch.as_ref().and(mount.sub_path.clone()),
            });
        }
    }
    // A Workload that runs as an Identity: its pod's certificate and key, in memory, the files
    // of each container its own.
    if let Run::Container(_) = &slot.run
        && slot.owner.starts_with("Workload/")
    {
        let identity = {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            let workload = state.store.get(&slot.owner);
            workload.and_then(|workload| workload.spec["identity"].as_str().map(str::to_string))
        };
        if let Some(identity) = identity {
            let (pod, container) = (pod_of(&slot.owner, slot.replica), id.rsplit('_').next().unwrap_or(id));
            let host = crate::workload_identity::files(shared, &pod, container, &identity).await?;
            unit.mounts.push(kith_runtime::Mount {
                host,
                container: crate::workload_identity::MOUNTED_AT.into(),
                read_only: true,
                // (Made the container's user's: its mode lets nobody else read them.)
                give: true,
                part: None,
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
            part: None,
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
            // What its policies let it reach, asked of the store before the pods' lock (the
            // pod is made with it: held from its first moment).
            let egress = {
                let state = shared.store.lock().expect("a handler panicked holding the store");
                crate::services::egress_of(&state.store, &slot.owner, crate::services::mesh_prefix(shared))
            };
            let ask = crate::root_part::Request::Pod {
                id: pod.clone(),
                namespace: namespace.into(),
                hostname: hostname.clone(),
                net,
                exit,
                owner: slot.owner.clone(),
                egress,
            };
            let given = crate::root_part::pod(&root, &shared.pods, ask)?;
            unit.netns = Some(given.netns);
            unit.hostname = Some(given.hostname);
            address = Some(given.address).or(address);
            for (file, at) in given.files.into_iter().zip(["/etc/resolv.conf", "/etc/hosts"]) {
                unit.mounts.push(kith_runtime::Mount {
                    host: file,
                    container: at.into(),
                    read_only: true,
                    give: false,
                    part: None,
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
            let named: Vec<String> = c.signed_by.iter().map(kith_api::kinds::Signer::text).collect();
            let signed_by = match runtime.images.local.as_ref().is_some_and(own) {
                true => named,
                false => {
                    let rules = image_rules(&shared.store.lock().expect("a handler panicked holding the store").store);
                    signers(&rules, &c.image, &named)?
                }
            };
            // The layers are unpacked by the root part, which is asked for an image that is not
            // here, with the layers as files; off this thread, which it would block.
            let unpack = |digest: String, manifest: String, files: Vec<std::fs::File>| -> kith_runtime::Unpacking {
                Box::pin(async move {
                    tokio::task::spawn_blocking(move || crate::root_part::unpack(digest, manifest, files))
                        .await
                        .map_err(|e| e.to_string())?
                })
            };
            let image = runtime
                .images
                .pull_with(&c.image, policy, &signed_by, &unpack)
                .await
                .map_err(|e| e.to_string())?;
            let (out, err) = (log("out")?, log("err")?);
            let created = root.create(crate::root_part::Create {
                id,
                image: &image,
                unit: &unit,
                out,
                err,
            });
            // The runtime says what the container would be; here whose word refused it.
            created.map_err(node_root_refusal)
        }
        Run::Exec(e) => {
            unit.command = e.command.clone();
            // (Through the root part, which takes it for made here: Kill and Delete name it.)
            root.exec(id, &unit, log("out")?, log("err")?)
        }
    };
    let handle = created?;
    // Written down before it runs (`Hands::start`): a unit may end kithd at once (as
    // ci/vm/outlive.sh's does), and one that ran with no record would be run again by the next.
    // ponytail: an exec unit whose kithd ends between this and `start` gets no go, ends, and is
    // taken back as ended: a Job fails once in that window of microseconds.
    match root.start(handle, id, &mark(slot)) {
        Ok(handle) => Ok(handle),
        Err((handle, e)) => {
            // It never ran; what processes it left are the slot's to hold until they are gone.
            // (Deleted here, not on a thread: this start is given up when kithd ends, and a
            // delete nobody waits for any more would be cut short by the exit.)
            slot.tried = Some(Instant::now());
            stopped(id, slot, root.delete(handle, id));
            Err(e)
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
        // (Keys and identities alike, as a node is handed them: what is neither is left out,
        // and a rule left with none runs nothing under it.)
        let keys = rule["signedBy"].as_array().into_iter().flatten();
        let signer = |said: &Value| serde_json::from_value::<kith_api::kinds::Signer>(said.clone()).ok();
        let keys = keys.filter_map(signer).map(|signer| signer.text()).collect();
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

    #[test]
    fn a_look_is_kept_for_its_time_and_made_again_after() {
        let (mut slot, mut made) = (None, 0);
        let mut look = |kept| {
            *fresh(&mut slot, kept, || {
                made += 1;
                made
            })
        };
        let hour = Duration::from_secs(3600);
        assert_eq!((look(hour), look(hour)), (1, 1));
        assert_eq!((look(Duration::ZERO), look(hour)), (2, 2));
    }

    /// A running unit's status says how its handle runs differently (its note: its root read-only,
    /// where the kernel refuses an overlay) and why it was replaced for what it wrote: both, in that
    /// order, and each alone where the other is not there. (A `Handle` is made only by the runtime,
    /// so this tests what the start says from the two; the note itself is the runtime's.)
    #[test]
    fn a_running_unit_says_its_handles_note_and_why_it_was_replaced() {
        let note = "root is read-only: this kernel does not mount overlay in a user namespace (kithd is not root)";
        let replaced = storage::REPLACED.to_string();
        assert_eq!(
            running_said(Some(note), Some(replaced.clone())),
            Some(format!("{note}; {replaced}"))
        );
        assert_eq!(running_said(Some(note), None), Some(note.to_string()));
        assert_eq!(running_said(None, Some(replaced.clone())), Some(replaced));
        assert_eq!(running_said(None, None), None);
    }

    /// A refusal the runtime made of a node's root container is said with the policy that allows
    /// it, around the runtime's own text; any other refusal comes back as it was.
    #[test]
    fn node_root_refusal_names_the_policy() {
        let root = format!("this container {}: its user is root's", kith_runtime::NODE_ROOT);
        let said = node_root_refusal(root.clone());
        assert!(said.contains("rootContainers is off"), "{said}");
        assert!(said.contains("--node-policy root-containers"), "{said}");
        assert!(said.ends_with(&root), "{said}");
        assert_eq!(
            node_root_refusal("an unrelated failure".to_string()),
            "an unrelated failure"
        );
    }

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

    /// An identity (signed without a kept key) in a rule is narrowed by a template's as a key
    /// is: the same identity written out otherwise is the same one, and another is not.
    #[test]
    fn image_rules_hold_identities_as_they_hold_keys() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = params.self_signed(&key).unwrap().pem();
        let log = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .unwrap()
            .public_key_pem();
        let identity = |subject: &str, root: &str| {
            json!({ "issuer": "https://issuer.test", "subject": subject, "authority": [root], "log": log }).to_string()
        };
        let ours = identity("dev@example.test", &root);
        let rules = vec![("ghcr.io".to_string(), vec![ours.clone()])];
        let same = identity("dev@example.test", &root.replace('\n', "\r\n"));
        assert_eq!(signers(&rules, "ghcr.io/acme/tool", &[same]), Ok(vec![ours.clone()]));
        assert!(signers(&rules, "ghcr.io/acme/tool", &[identity("them@example.test", &root)]).is_err());
        assert_eq!(signers(&rules, "ghcr.io/acme/tool", &[]), Ok(vec![ours]));
        // An older kithd keeps a rule's strings only: a rule of identities alone is then a rule
        // of no key, and runs nothing under it.
        let older = vec![("ghcr.io".to_string(), Vec::new())];
        assert!(signers(&older, "ghcr.io/acme/tool", &[]).is_err());
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

    /// A restart a `kubectl delete pod` asked for stops that replica's slot and sets it to start
    /// at once, whatever its restart policy says; the replica beside it is not touched, and the
    /// mark is taken once.
    #[tokio::test]
    async fn delete_pod_stops_the_replica_and_starts_it_again_ignoring_policy() {
        let mut slots = BTreeMap::new();
        slots.insert("a".to_string(), slot_of("Workload/default/x", &[], "main"));
        let mut beside = slot_of("Workload/default/x", &[], "main");
        beside.replica = 1;
        slots.insert("b".to_string(), beside);
        let mut marked = BTreeSet::from([("Workload/default/x".to_string(), 0u32)]);
        apply_restarts(&mut slots, &mut marked, Instant::now()).await;
        assert!(marked.is_empty(), "the mark is taken once");
        assert!(slots["a"].start_at.is_some(), "the replica is to start again");
        assert!(slots["b"].start_at.is_none(), "the replica beside it is not touched");
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
            dmem: Vec::new(),
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
            restarted: None,
        }
    }

    /// A unit of replica 0 of the pod `Workload/x/a`, of generation `b` (false: the first, true: the second).
    fn surge_unit(b: bool, state: &'static str) -> (String, Slot) {
        let mut slot = slot_of("Workload/x/a", &[], "app");
        slot.pod = Some((pod_id("Workload/x/a", 0, b), "a-0".into()));
        slot.state = state;
        (unit_id("w_x_a_", 0, b, "app").unwrap(), slot)
    }

    /// The two generations of a replica are told apart by their ids and their pods, so both can
    /// run at once; the first has the ids it always had (a kithd started again takes its units back).
    #[test]
    fn surge_gives_each_generation_its_own_ids() {
        assert_eq!(unit_id("w_x_a_", 0, false, "app").unwrap(), "w_x_a_0_app");
        assert_eq!(unit_id("w_x_a_", 0, true, "app").unwrap(), "w_x_a_0b_app");
        assert_eq!(pod_id("Workload/x/a", 0, false), pod_of("Workload/x/a", 0));
        assert_ne!(pod_id("Workload/x/a", 0, true), pod_of("Workload/x/a", 0));
        let (_, old) = surge_unit(false, "running");
        let (_, new) = surge_unit(true, "running");
        assert!(!is_second(&old) && is_second(&new));
        // (One that is of no pod has one generation.)
        assert!(!is_second(&slot_of("Workload/x/a", &[], "app")));
    }

    /// The new generation is started beside the old, and the old stays what answers (what is
    /// reported, what a Service goes to) until every unit of the new is ready: at no step is there
    /// no generation ready.
    #[test]
    fn surge_keeps_the_old_until_the_new_is_ready() {
        let mut slots = BTreeMap::new();
        let (old_id, old) = surge_unit(false, "running");
        slots.insert(old_id, old);
        let (new_id, new) = surge_unit(true, "pending");
        slots.insert(new_id.clone(), new);
        let ready =
            |slots: &BTreeMap<String, Slot>, b: bool| slots.values().filter(|s| is_second(s) == b).all(Slot::ready);
        // Starting: the old answers.
        assert!(!second_is_live(&slots, "Workload/x/a", 0, true));
        assert!(ready(&slots, false) && !ready(&slots, true));
        // The new one runs: it answers, and the old one still runs, for the drain.
        slots.get_mut(&new_id).unwrap().state = "running";
        assert!(second_is_live(&slots, "Workload/x/a", 0, true));
        assert!(ready(&slots, false) && ready(&slots, true));
        // The old is let go only once the drain is over, and not before it began.
        assert!(!drained(None));
        assert!(!drained(Some(Instant::now())));
        assert!(drained(Some(Instant::now() - DRAIN)));
        // A new unit that failed to start does not take over.
        slots.get_mut(&new_id).unwrap().state = "failed";
        assert!(!second_is_live(&slots, "Workload/x/a", 0, true));
    }

    /// A rollout whose container has only an exec readiness probe: until the command has passed, the
    /// status (and the Deployment kubectl reads off it) keeps the old copy's revision and counts, so
    /// `kubectl rollout status` and `helm --wait` wait for the probe, not for the container to run.
    #[tokio::test]
    async fn rollout_waits_for_exec_readiness() {
        let owner = "Workload/x/a";
        let exec: Container = serde_json::from_value(json!({
            "name": "app", "image": "img", "readiness": { "exec": ["test", "-f", "/tmp/ready"] },
        }))
        .unwrap();
        assert!(crate::probe::problems(&exec).is_empty());
        let (mut slots, mut gens, mut surging) = (BTreeMap::new(), BTreeMap::new(), Surging::new());
        let (old_id, mut old) = surge_unit(false, "running");
        old.revision = Some(1);
        slots.insert(old_id, old);
        let (new_id, mut new) = surge_unit(true, "running");
        new.revision = Some(2);
        // (Started with the probe running and not yet passed: what `probe::start` gives a container with one.)
        let (probes, passed) = crate::probe::held(crate::probe::Health {
            live: true,
            ready: false,
        });
        new.probes = Some(probes);
        slots.insert(new_id, new);
        gens.insert((owner.to_string(), 0), true);
        surging.insert((owner.to_string(), 0), (Instant::now(), None));

        // The Deployment kubectl reads, over what the controller reports.
        let read = |slots: &BTreeMap<String, Slot>| -> Value {
            let units: Vec<Value> = slots
                .values()
                .filter(|slot| answers(&gens, &surging, slots, slot))
                .map(unit_status)
                .collect();
            let resource: Resource = serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": "Workload",
                "metadata": { "name": "a", "namespace": "x", "revision": 2 },
                "spec": {}, "status": { "containers": units },
            }))
            .unwrap();
            crate::kube::status_of("Deployment", &json!({ "spec": { "replicas": 1 } }), &resource).unwrap()
        };
        let counts = |status: &Value| {
            ["replicas", "updatedReplicas", "readyReplicas", "availableReplicas"].map(|n| status[n].as_u64().unwrap())
        };
        // Running, the probe not passed: the old copy answers, at its own revision.
        let before = read(&slots);
        assert_eq!(counts(&before), [1, 0, 1, 1], "{before}");
        assert_eq!(before["conditions"][1]["reason"], "ReplicaSetUpdated");
        // The probe passes: the new copy answers.
        passed.send_modify(|health| health.ready = true);
        let after = read(&slots);
        assert_eq!(counts(&after), [1, 1, 1, 1], "{after}");
        assert_eq!(after["conditions"][1]["reason"], "NewReplicaSetAvailable");
    }

    /// What is held once (a volume, a device, the node's network) is not held by two replicas
    /// at once: its replica is stopped first, and the note says why.
    #[test]
    fn surge_stops_first_what_holds_one_of_something() {
        let (_, plain) = surge_unit(true, "pending");
        assert_eq!(no_surge(&[&plain], true), None);
        let host = slot_of("Workload/x/a", &[], "app");
        assert!(no_surge(&[&host], true).unwrap().contains("network"));
        assert!(no_surge(&[&plain], false).unwrap().contains("network"));
        let mut device = surge_unit(true, "pending").1;
        device.devices = vec!["/dev/dri/card0".into()];
        assert!(no_surge(&[&device], true).unwrap().contains("device"));
        let mut seat = surge_unit(true, "pending").1;
        seat.seat = Some(("s".into(), false));
        assert!(no_surge(&[&seat], true).unwrap().contains("device"));
        let mut volume = surge_unit(true, "pending").1;
        let dir = crate::volumes::Dir {
            namespace: "x".into(),
            name: "v".into(),
            path: "/v".into(),
            node: "n".into(),
            encrypted: false,
        };
        volume.volumes = vec![(dir, "/data".into(), false)];
        assert!(no_surge(&[&volume], true).unwrap().contains("volume"));
        // A scratch is the replica's, shared by the generations of it.
        let mut scratch = surge_unit(true, "pending").1;
        let Run::Container(c) = &mut scratch.run else {
            unreachable!()
        };
        c.volume_mounts = serde_json::from_value(json!([{ "scratch": "work", "path": "/work" }])).unwrap();
        assert!(no_surge(&[&scratch], true).unwrap().contains("scratch"));
        let mut exec = surge_unit(true, "pending").1;
        exec.run = Run::Exec(serde_json::from_value(json!({ "name": "x", "command": ["true"] })).unwrap());
        assert!(no_surge(&[&exec], true).unwrap().contains("container"));
    }

    /// A node with no room for the new replica beside the old stops the old first.
    #[test]
    fn surge_needs_room_on_the_node() {
        let asking = |cpu: f64, memory: f64| {
            let mut slot = surge_unit(false, "running").1;
            let Run::Container(c) = &mut slot.run else {
                unreachable!()
            };
            c.resources = serde_json::from_value(json!({ "cpu": cpu.to_string(), "memory": memory.to_string() })).ok();
            assert!(c.resources.is_some());
            slot
        };
        let mut slots = BTreeMap::new();
        slots.insert("a".to_string(), asking(1.0, 4e9));
        // 2 CPUs and 8 GB: another replica like it fits; with 6 GB it does not, nor with 1 CPU.
        let new = asking(1.0, 4e9);
        assert_eq!(no_room((2.0, 8e9), &slots, &[&new]), None);
        assert!(no_room((2.0, 6e9), &slots, &[&new]).unwrap().contains("memory"));
        assert!(no_room((1.0, 8e9), &slots, &[&new]).unwrap().contains("CPU"));
        // A replica that asks for nothing is never held back for room.
        assert_eq!(no_room((0.5, 1e6), &slots, &[&surge_unit(true, "pending").1]), None);
    }

    /// A kithd started again in the middle of an update finds both generations of a replica running
    /// and does not know which began the update: the one that is wanted as it runs is the new one
    /// (or the second, where neither is), and the other is held until that answers: it is the
    /// replica's only answer meanwhile. (The reconcile pass takes these two as given.)
    #[test]
    fn surge_after_a_restart_holds_the_old_generation() {
        let owner = "Workload/x/a";
        let mut wanted = BTreeMap::new();
        let (id_a, a) = surge_unit(false, "pending");
        let (id_b, b) = surge_unit(true, "pending");
        let (mark_a, mark_b) = (mark(&a), mark(&b));
        wanted.insert(id_a.clone(), a);
        wanted.insert(id_b.clone(), b);
        let adopted = |a: &str, b: &str| BTreeMap::from([(id_a.clone(), a.to_string()), (id_b.clone(), b.to_string())]);
        // The first update: the original is the old one, the second generation what is wanted.
        let no = BTreeMap::new();
        assert!(adopted_gen(&adopted("v1", &mark_b), &no, &wanted, owner, 0));
        // The second: the second generation is the old one, the first what is wanted.
        assert!(!adopted_gen(&adopted(&mark_a, "v2"), &no, &wanted, owner, 0));
        // Neither is what is wanted, and no start is known: the second.
        assert!(adopted_gen(&adopted("v3", "v2"), &no, &wanted, owner, 0));
        // (Another replica is none of these: neither is wanted.)
        assert!(adopted_gen(&adopted(&mark_a, "v2"), &no, &wanted, owner, 1));
        // What is held: the units nothing wants, of a replica whose update is not over.
        let began = Instant::now();
        let surging = BTreeMap::from([((owner.to_string(), 0), (began, None))]);
        wanted.remove(&id_a);
        assert!(held(&surging, &wanted, &id_a));
        assert!(!held(&surging, &wanted, &id_b), "what is wanted is not held");
        assert!(!held(&surging, &wanted, "w_x_a_1_app") && !held(&surging, &wanted, "w_x_a_10_app"));
        assert!(!held(&BTreeMap::new(), &wanted, &id_a));
        let drained_since = BTreeMap::from([((owner.to_string(), 0), (began, Some(Instant::now() - DRAIN)))]);
        assert!(
            !held(&drained_since, &wanted, &id_a),
            "once the new one has answered a while"
        );
        let ready_now = BTreeMap::from([((owner.to_string(), 0), (began, Some(Instant::now())))]);
        assert!(held(&ready_now, &wanted, &id_a), "and while the drain goes on");
    }

    /// A held old generation is still a pod that answers: its pod is taken back (its network and
    /// rules) and kept while it is held, though no slot of it is made. (Its units are named
    /// `{pod}_{unit}`, and a unit name has no `_`.)
    #[test]
    fn surge_after_a_restart_adopts_and_keeps_the_pod_it_holds() {
        let owner = "Workload/x/a";
        let (id_a, _) = surge_unit(false, "pending");
        let (id_b, b) = surge_unit(true, "pending");
        assert_eq!(pod_of_unit(&id_a), pod_of(owner, 0));
        assert_eq!(pod_of_unit(&id_b), pod_id(owner, 0, true));
        let wanted = BTreeMap::from([(id_b.clone(), b)]);
        let ids = [id_a.as_str(), id_b.as_str(), "w_x_a_1_app"];
        let began = Instant::now();
        let surging = BTreeMap::from([((owner.to_string(), 0), (began, None))]);
        assert_eq!(held_pods(ids, &surging, &wanted), BTreeSet::from([pod_of(owner, 0)]));
        let drained_since = BTreeMap::from([((owner.to_string(), 0), (began, Some(Instant::now() - DRAIN)))]);
        assert!(
            held_pods(ids, &drained_since, &wanted).is_empty(),
            "let go once drained"
        );
        assert!(
            held_pods(ids, &BTreeMap::new(), &wanted).is_empty(),
            "none held with no update"
        );
    }

    /// An adopted unit is taken by its slot only as it ran; one with another mark that could not be
    /// stopped (it is still in `adopted`) holds its slot, so the same unit id is not started over its
    /// cgroup; and a stop that failed is tried again only after STOP_RETRY.
    #[test]
    fn a_stuck_adopted_unit_holds_its_slot_and_is_retried_in_time() {
        assert_eq!(taken_back(None, "m"), Taken::Free);
        assert_eq!(taken_back(Some("m"), "m"), Taken::Take);
        assert_eq!(taken_back(Some("old"), "m"), Taken::Stuck);
        assert!(!retry_due(Some(Instant::now())));
        assert!(retry_due(Some(Instant::now() - STOP_RETRY)));
        assert!(retry_due(None));
    }

    /// A kithd started again that finds one generation of a replica running as it is no longer
    /// wanted starts the other beside it (the old keeps answering) where a rolling update could; and
    /// finds one that is as wanted left alone.
    #[test]
    fn surge_after_a_restart_with_one_generation_changed_starts_the_other_beside_it() {
        let owner = "Workload/x/a";
        let rolled = |b: bool| {
            let (id, mut slot) = surge_unit(b, "pending");
            slot.rolling = true;
            (id, slot)
        };
        let (id_a, a) = rolled(false);
        let (id_b, b) = rolled(true);
        let (mark_a, mark_b) = (mark(&a), mark(&b));
        let mut wanted = BTreeMap::from([(id_a.clone(), a), (id_b.clone(), b)]);
        let no = BTreeMap::new();
        let after = |wanted: &BTreeMap<String, Slot>, ran: &str, was: &str, root: bool| {
            after_restart(
                &BTreeMap::from([(ran.to_string(), was.to_string())]),
                &no,
                wanted,
                owner,
                0,
                root,
            )
        };
        // As wanted: left alone, whichever generation it is.
        assert_eq!(after(&wanted, &id_a, &mark_a, true), (false, false));
        assert_eq!(after(&wanted, &id_b, &mark_b, true), (true, false));
        // Not as wanted: the other generation is wanted, the one running held.
        assert_eq!(after(&wanted, &id_a, "v1", true), (true, true));
        assert_eq!(after(&wanted, &id_b, "v1", true), (false, true));
        // Where it could not run twice (not root: no pod of its own), it is stopped first as ever.
        assert_eq!(after(&wanted, &id_a, "v1", false), (false, false));
        // A Recreate Workload is not surged.
        for slot in wanted.values_mut() {
            slot.rolling = false;
        }
        assert_eq!(after(&wanted, &id_a, "v1", true), (false, false));
    }

    /// With neither generation as wanted, the older process is the old generation: the second is not
    /// always the new one (on every even update the first is).
    #[test]
    fn surge_after_a_restart_tells_the_old_generation_by_when_it_started() {
        let owner = "Workload/x/a";
        let (id_a, a) = surge_unit(false, "pending");
        let (id_b, b) = surge_unit(true, "pending");
        let wanted = BTreeMap::from([(id_a.clone(), a), (id_b.clone(), b)]);
        let marks = BTreeMap::from([(id_a.clone(), "v2".to_string()), (id_b.clone(), "v3".to_string())]);
        let starts = |a: u64, b: u64| BTreeMap::from([(id_a.clone(), a), (id_b.clone(), b)]);
        assert!(
            adopted_gen(&marks, &starts(100, 200), &wanted, owner, 0),
            "the second is newer"
        );
        assert!(
            !adopted_gen(&marks, &starts(300, 200), &wanted, owner, 0),
            "the first is newer"
        );
        assert!(
            adopted_gen(&marks, &starts(100, 100), &wanted, owner, 0),
            "no telling: the second"
        );
        // The time is the 22nd field of /proc/PID/stat, after a name that may hold spaces and parentheses.
        let stat = "42 (a b) c) S 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 100 18446744073709551615";
        assert_eq!(starttime_of(stat), Some(987654));
        assert_eq!(starttime_of("garbage"), None);
        let own = std::fs::read_to_string("/proc/self/stat").unwrap();
        assert!(starttime_of(&own).is_some_and(|t| t > 0));
    }

    /// What the status says of a replica mid-update: why it was stopped first, and, once its
    /// replacement has not answered for a while, the replacement's own words (the old keeps answering).
    #[test]
    fn surge_says_why_it_stopped_first_and_what_the_new_one_lacks() {
        let owner = "Workload/x/a";
        let (id_old, old) = surge_unit(false, "running");
        let (id_new, mut new) = surge_unit(true, "pending");
        new.message = Some("pulling img: no route to host".into());
        let slots = BTreeMap::from([(id_old, old), (id_new, new)]);
        let (gens, long_ago) = (
            BTreeMap::from([((owner.to_string(), 0), true)]),
            Instant::now() - SLOW * 2,
        );
        let says = |surging: &BTreeMap<(String, u32), (Instant, Option<Instant>)>, stopped: Option<&(u32, String)>| {
            update_says(&gens, surging, &slots, owner, stopped)
        };
        // Just begun: nothing to say yet.
        let fresh = BTreeMap::from([((owner.to_string(), 0), (Instant::now(), None))]);
        assert!(says(&fresh, None).is_empty());
        // Not ready after a while: what it is, in its own words.
        let slow = BTreeMap::from([((owner.to_string(), 0), (long_ago, None))]);
        let said = says(&slow, None);
        assert_eq!(said.len(), 1);
        assert_eq!(said[0].0, 0);
        assert!(
            said[0].1.contains("no route to host") && said[0].1.contains("still answers"),
            "{said:?}"
        );
        // Ready (and draining): all is well.
        let ready = BTreeMap::from([((owner.to_string(), 0), (long_ago, Some(Instant::now())))]);
        assert!(says(&ready, None).is_empty());
        // A replica stopped first says why.
        let first = (
            0,
            "rolling update: replica 0 is stopped first: it mounts a volume".to_string(),
        );
        assert_eq!(says(&BTreeMap::new(), Some(&first)), vec![first.clone()]);
    }

    /// Each generation of a pod has its own storage: its limit is its own, as it is its project, and
    /// what one writes past it does not replace the other.
    #[test]
    fn surge_counts_the_storage_of_each_generation_apart() {
        let stored = |b: bool, bytes: &str| {
            let (id, mut slot) = surge_unit(b, "running");
            let Run::Container(c) = &mut slot.run else {
                unreachable!()
            };
            c.resources = serde_json::from_value(json!({ "storage": bytes })).ok();
            assert!(c.resources.is_some());
            (id, slot)
        };
        let slots = BTreeMap::from([stored(false, "1000"), stored(true, "1000")]);
        let limits = pod_limits(&slots);
        assert_eq!(limits.len(), 2, "{limits:?}");
        assert!(limits.values().all(|limit| *limit == Some(1000)), "{limits:?}");
        assert_eq!(storage_pod(&slots["w_x_a_0_app"]), pod_of("Workload/x/a", 0));
        assert_ne!(storage_pod(&slots["w_x_a_0b_app"]), pod_of("Workload/x/a", 0));
    }

    /// A unit is taken back by the slot that would start it only when its mark is the slot's:
    /// the same for what a unit's life changes (its state, restarts, when it started), another
    /// for what it was started as (what it runs, its devices, its environment).
    #[test]
    fn adopt_by_a_mark_of_what_a_unit_was_started_as() {
        let slot = slot_of("w", &["/dev/a"], "c");
        let mut lived = slot_of("w", &["/dev/a"], "c");
        (lived.state, lived.restarts, lived.failures, lived.held) = ("running", 3, 2, true);
        assert_eq!(mark(&slot), mark(&lived));
        assert_eq!(mark(&slot).len(), 64);
        let others = [
            slot_of("w", &["/dev/a"], "d"),
            slot_of("w", &["/dev/b"], "c"),
            Slot {
                env: Ok(vec![("A".into(), "1".into())]),
                ..slot_of("w", &["/dev/a"], "c")
            },
            Slot {
                dmem: vec![("drm/0000:04:00.0/vram".into(), 1 << 28)],
                ..slot_of("w", &["/dev/a"], "c")
            },
            Slot {
                policy: RestartPolicy::Never,
                ..slot_of("w", &["/dev/a"], "c")
            },
        ];
        for other in &others {
            assert_ne!(mark(&slot), mark(other), "{:?}", other.run);
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

    /// A unit an earlier kithd left running has no slot and no owner: it is leaving all the same,
    /// beside the slots that are, so its id is refused to every unit, and its devices to every owner
    /// (an owner of the same name is none). One that is gone from the list holds nothing.
    #[test]
    fn left_running_units_hold_their_id_and_devices_from_every_owner() {
        let card = vec![PathBuf::from("/dev/dri/card0")];
        let left = [("w_a_b_0_x".to_string(), card.clone())];
        let mut slots = BTreeMap::from([(
            "w_c_d_0_y".to_string(),
            slot_of("Workload/c/d", &["/dev/input/event0"], "y"),
        )]);
        slots.get_mut("w_c_d_0_y").unwrap().leaving = true;
        let leaving = leaving_of(&slots, left.iter().map(|(id, devices)| (id, &devices[..])));
        assert_eq!(leaving.len(), 2, "the slot that leaves and the unit left running");
        let same_id = held_by_leaving("w_a_b_0_x", "Workload/a/b", &[], &leaving).expect("its id is held");
        assert!(same_id.contains("still stopping"), "{same_id}");
        for owner in ["Workload/a/b", "Workload/e/f"] {
            assert!(
                held_by_leaving("w_e_f_0_z", owner, &card, &leaving).is_some_and(|why| why.contains("/dev/dri/card0")),
                "its devices are held from {owner:?}"
            );
        }
        let elsewhere = [PathBuf::from("/dev/dri/card1")];
        assert_eq!(held_by_leaving("w_e_f_0_z", "Workload/e/f", &elsewhere, &leaving), None);
        let gone = leaving_of(&BTreeMap::new(), std::iter::empty());
        assert_eq!(held_by_leaving("w_a_b_0_x", "Workload/a/b", &card, &gone), None);
    }

    /// A delete retried keeps the handle while processes of the unit remain (and when it failed, so
    /// the next try waits), and drops it once they are gone, whether the cleanup then went well or not.
    #[test]
    fn a_retried_delete_keeps_the_unit_while_it_has_processes_and_drops_it_once_empty() {
        let mut stuck = BTreeMap::new();
        let busy = || Err((Some(7u8), "busy".to_string()));
        assert_eq!(kept_if_stuck("a", busy(), &mut stuck), Some(7));
        assert!(stuck.contains_key("a"), "when it failed is written down");
        assert_eq!(
            kept_if_stuck("a", busy(), &mut stuck),
            Some(7),
            "still there on the next try"
        );
        assert_eq!(
            kept_if_stuck::<u8>("a", Err((None, "cleanup".to_string())), &mut stuck),
            None
        );
        assert!(stuck.is_empty(), "empty: nothing is held, nothing waits");
        stuck.insert("a".into(), Instant::now());
        assert_eq!(kept_if_stuck::<u8>("a", Ok(()), &mut stuck), None);
        assert!(stuck.is_empty());
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
        assert_eq!(unit_id(&prefix, 1, false, "app").unwrap(), "w_default_web.v2_1_app");
        assert_eq!(id_prefix("Job", "default", "web.v2"), "j_default_web.v2_");
        // (`a..b` is no name to the root part, which would never be asked to kill what it holds
        // under it: so no unit of that name is made at all.)
        for bad in ["", "a/b", "..\\x", "a_b", "a b", "a..b", "a..."] {
            let id = unit_id(&prefix, 0, false, bad);
            assert!(id.is_err(), "{bad:?}");
        }
        // And whatever is made is a name to the root part.
        for ok in ["app", "a.b", "a-b", "9"] {
            let id = unit_id(&prefix, 3, true, ok).unwrap();
            assert!(crate::root_part::label("unit id", &id).is_ok(), "{id}");
        }
        // What runs first is run until it ends well, whatever the others are; a Job's never again.
        use RestartPolicy::{Always, Never, OnFailure};
        let started_again = [(Always, false), (Always, true), (OnFailure, true), (Never, true)]
            .map(|(policy, init)| (again(&policy, init, 0), again(&policy, init, 1)));
        assert_eq!(
            started_again,
            [(true, true), (false, true), (false, true), (false, false)]
        );
        assert!(unit_id("w_a_b_", 0, false, "..").is_err() && unit_id("w_a_b_", 0, false, "a.b").is_ok());
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

    /// A Volume made for a claim that is gone has its directory removed by its own node once no
    /// unit mounts it, and only then is the Volume deleted; one a unit mounts waits.
    #[test]
    fn a_made_volume_is_wiped_then_deleted_by_its_node() {
        let source = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a }
spec: {}
---
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: db, annotations: { kith.dev/made-for-claim: \"true\" } }
spec: { node: a, path: data, size: 1Gi }
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: app }
spec: { template: { containers: [{ name: run, image: img, volumeMounts: [{ volume: db, path: /mnt }] }] } }
";
        let mut store = kith_api::store::Store::default();
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let state = std::env::temp_dir().join(format!("kith-controller-wipe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        std::fs::create_dir_all(&state).unwrap();
        let state = state.canonicalize().unwrap();
        let dir = crate::volumes::dir(&store, "default", "db").unwrap();
        let root = crate::volumes::host_dir(&state, &dir).unwrap();
        std::fs::write(root.join("file"), "x").unwrap();
        let data = state.join("volumes/default/db");
        // Not on another node, and not while a unit mounts it.
        let held = |store: &kith_api::store::Store| mounting(&crate::volumes::mounts(store, "a"));
        assert!(due(&store, "b", &held(&store)).is_empty());
        assert_eq!(held(&store), BTreeSet::from(["Volume/default/db".to_string()]));
        assert!(due(&store, "a", &held(&store)).is_empty());
        assert!(data.join("data/file").exists());
        // The unit is gone: the data goes, then the Volume.
        store.delete("Workload/default/app").unwrap();
        let dirs = due(&store, "a", &held(&store));
        assert_eq!(dirs.len(), 1);
        let keys = wipe_all(&state, dirs);
        assert!(!data.exists(), "the data is removed");
        assert_eq!(keys, ["Volume/default/db"]);
        assert!(state.join("volumes/default").exists());
        for key in keys {
            kith_store::run(&mut store, kith_store::Command::Delete { key }).unwrap();
        }
        assert!(store.get("Volume/default/db").is_none());
        let _ = std::fs::remove_dir_all(&state);
    }

    /// A node set to run alone goes on from its copy once no write has come back for `ALONE_AFTER`.
    #[tokio::test(start_paused = true)]
    async fn alone_start_goes_on_from_the_copy_after_thirty_seconds() {
        let began = tokio::time::Instant::now();
        let never = || async { Err::<(), String>("no leader".into()) };
        assert!(matches!(started(true, ALONE_AFTER, never).await, Start::Alone(_)));
        assert_eq!(began.elapsed(), ALONE_AFTER);
    }

    /// A leader that answers before the wait is up wins: the start is the cluster's, not alone.
    #[tokio::test(start_paused = true)]
    async fn alone_a_leader_that_answers_first_wins() {
        let began = tokio::time::Instant::now();
        let answers = || async move {
            match began.elapsed() < Duration::from_secs(10) {
                true => Err("no leader".to_string()),
                false => Ok(()),
            }
        };
        assert_eq!(started(true, ALONE_AFTER, answers).await, Start::Leader);
        assert!(began.elapsed() < ALONE_AFTER, "{:?}", began.elapsed());
    }

    /// A node that is not set to run alone waits for a write for as long as it takes.
    #[tokio::test(start_paused = true)]
    async fn alone_wait_keeps_waiting_however_long() {
        let never = || async { Err::<(), String>("no leader".into()) };
        let waited = tokio::time::timeout(Duration::from_secs(600), started(false, ALONE_AFTER, never)).await;
        assert!(waited.is_err());
    }

    /// A leader that answers ends alone even when the status write is refused every time (an old leader
    /// may not know the field): the status is tried a few times, not forever, and the node starts its Jobs.
    #[tokio::test(start_paused = true)]
    async fn alone_a_refused_status_still_ends_alone() {
        let alone = std::sync::atomic::AtomicBool::new(true);
        let tries = std::sync::atomic::AtomicUsize::new(0);
        let answers = || async { Ok::<(), String>(()) };
        let refused = || async {
            tries.fetch_add(1, Ordering::Relaxed);
            Err::<(), String>("`alone` is not a field this leader knows".into())
        };
        end_alone(&alone, answers, refused).await;
        assert!(!alone.load(Ordering::Relaxed));
        assert_eq!(tries.load(Ordering::Relaxed), ALONE_STATUS_TRIES);
    }

    /// While no leader answers, the node stays alone and writes no status.
    #[tokio::test(start_paused = true)]
    async fn alone_stays_alone_while_no_leader_answers() {
        let alone = std::sync::atomic::AtomicBool::new(true);
        let wrote = std::sync::atomic::AtomicUsize::new(0);
        let never = || async { Err::<(), String>("no leader".into()) };
        let written = || async {
            wrote.fetch_add(1, Ordering::Relaxed);
            Ok::<(), String>(())
        };
        let waited = tokio::time::timeout(Duration::from_secs(600), end_alone(&alone, never, written)).await;
        assert!(waited.is_err());
        assert!(alone.load(Ordering::Relaxed));
        assert_eq!(wrote.load(Ordering::Relaxed), 0);
    }

    /// Jobs are held while alone; Workloads and NodeWorkloads are started from the copy as before.
    #[test]
    fn alone_jobs_are_not_started_and_workloads_are() {
        assert!(held_alone("Job", true));
        assert!(!held_alone("Job", false));
        assert!(!held_alone("Workload", true));
        assert!(!held_alone("NodeWorkload", true));
    }

    /// The Node's status says the risks and since when the node ran alone, and until when.
    #[test]
    fn alone_status_says_the_risks_and_since_when() {
        let since = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let until = since + Duration::from_secs(90);
        let status = alone_status(since, until);
        assert_eq!(status["alone"]["since"], 1_700_000_000u64);
        assert_eq!(status["alone"]["until"], 1_700_000_090u64);
        let risks = status["alone"]["risks"].as_str().expect("the risks are said");
        for said in ["runs twice", "the old one", "Job"] {
            assert!(risks.contains(said), "{said} is not in {risks}");
        }
    }

    #[test]
    fn per_replica_mount_is_the_replicas_own_claim_and_no_other() {
        let source = "
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: db }
spec: { replicas: 2, template: { containers: [{ name: run, image: img, volumeMounts: [{ volume: data, perReplica: true, path: /d }, { volume: log, path: /l }] }] } }
";
        let resource = Resource::from_source(source).unwrap().remove(0).unwrap();
        let (template, _) = template_of(&resource).unwrap();
        let unit = Run::Container(template.containers().next().unwrap().clone());
        let dir = |name: &str| crate::volumes::Dir {
            namespace: "default".into(),
            name: name.into(),
            path: name.into(),
            node: "a".into(),
            encrypted: false,
        };
        let dirs: BTreeMap<String, _> = ["data-0", "data-1", "log"]
            .map(|name| (name.to_string(), dir(name)))
            .into();
        let names = |replica| -> Vec<(String, String)> {
            mounts_of(&unit, &dirs, replica)
                .into_iter()
                .map(|(dir, at, _)| (dir.name, at))
                .collect()
        };
        assert_eq!(names(1), [("data-1".into(), "/d".into()), ("log".into(), "/l".into())]);
        // One that has no Volume here is left out (and `lacking` keeps the replica from starting).
        assert_eq!(names(2), [("log".into(), "/l".into())]);
    }
}
