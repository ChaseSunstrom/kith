//! Usage metrics for the web UI's graphs: each node samples itself every 10 s (CPU, memory, the
//! state disk, its read and write rates, network rates, load) and the cgroup of each unit of a
//! Workload on it (CPU cores, memory), into rings in memory only: 10 s points for an hour and
//! 5 min points for a day. Nothing is written to the store and nothing goes over Raft.
//!
//! `GET /v1/metrics?range=15m|1h|6h|24h` answers every node's series: this node's own, and each
//! other node's asked over node-to-node mTLS (`/v1/node-metrics`, members only) with a short
//! deadline, one that does not answer being `missing` and the answer still coming. The arrays are
//! oldest first, each aligned to `end - step * (len - 1 - i)`, `null` where nothing was sampled.
//!
//! The rings are arrays addressed by time (a slot is the unix time over the step), so the oldest
//! point is overwritten by the one a ring-length later, a gap is a slot nobody wrote, and series
//! of different nodes line up without either knowing the other's clock beyond the step.

use crate::Shared;
use crate::access::Caller;
use crate::api::{ApiError, Reply, permit};
use axum::extract::{Query, State};
use axum::{Extension, Json};
use kith_api::kinds::Verb;
use kith_api::store::Error;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

/// A point every 10 s for an hour, and every 5 min for a day.
const FINE: u64 = 10;
const FINE_N: usize = 360;
const COARSE: u64 = 300;
const COARSE_N: usize = 288;
/// A Workload not seen for this long is forgotten with its history, and no more than
/// `MAX_WORKLOADS` are kept (what a node runs is far fewer: this is a ceiling for memory).
const KEEP_WORKLOAD: u64 = 3600;
const MAX_WORKLOADS: usize = 512;
/// How long another node is given to answer, and the most it may send.
const ASK_FOR: Duration = Duration::from_secs(3);
const MAX_ANSWER: usize = 4 << 20;

/// What a ring keeps for one slot: the sum of the samples in it and how many (a 5 min slot is
/// the mean of what 10 s samples fell in it). A value that is NaN is a value not known: it is
/// not summed, and `got` counts each value's samples apart from the others'.
#[derive(Clone, Copy)]
struct Cell<const K: usize> {
    slot: u64,
    n: u32,
    got: [u32; K],
    sum: [f64; K],
}

impl<const K: usize> Cell<K> {
    const EMPTY: Self = Cell {
        slot: 0,
        n: 0,
        got: [0; K],
        sum: [0.0; K],
    };
}

/// `N` slots of `step` seconds, each of `K` values.
struct Ring<const K: usize, const N: usize> {
    step: u64,
    cells: [Cell<K>; N],
}

impl<const K: usize, const N: usize> Ring<K, N> {
    const fn new(step: u64) -> Self {
        Ring {
            step,
            cells: [Cell::EMPTY; N],
        }
    }

    /// Put the sample taken at unix time `at` in its slot, over what an older slot left there.
    fn add(&mut self, at: u64, values: [f64; K]) {
        let slot = at / self.step;
        let cell = &mut self.cells[(slot % N as u64) as usize];
        if cell.n == 0 || cell.slot != slot {
            *cell = Cell { slot, ..Cell::EMPTY };
        }
        cell.n += 1;
        for (i, value) in values.into_iter().enumerate() {
            if !value.is_nan() {
                cell.sum[i] += value;
                cell.got[i] += 1;
            }
        }
    }

    /// The `points` slots that end with the one `end` is in, oldest first; `None` for a slot
    /// nobody wrote (or one a newer slot took the place of, or one before the epoch). A value of
    /// a slot that no sample had is NaN.
    fn series(&self, end: u64, points: usize) -> Vec<Option<[f64; K]>> {
        let last = end / self.step;
        (0..points)
            .map(|i| {
                let slot = last.checked_sub((points - 1 - i) as u64)?;
                let cell = &self.cells[(slot % N as u64) as usize];
                (cell.n > 0 && cell.slot == slot).then(|| std::array::from_fn(|i| cell.sum[i] / f64::from(cell.got[i])))
            })
            .collect()
    }
}

/// One Workload's two rings: CPU in cores and memory in bytes.
struct Work {
    last: u64,
    fine: Ring<2, FINE_N>,
    coarse: Ring<2, COARSE_N>,
}

/// Everything this node has sampled.
struct Rings {
    cpus: u32,
    mem_total: u64,
    disk_total: u64,
    /// cpu (0 to 1), mem, disk, disk read, disk write, rx, tx (bytes, and per second), load1.
    fine: Ring<8, FINE_N>,
    coarse: Ring<8, COARSE_N>,
    work: BTreeMap<String, Box<Work>>,
}

/// (A static, so that the sampler and the handlers meet without a field in `Shared`.)
static RINGS: Mutex<Rings> = Mutex::new(Rings::new());

fn rings() -> std::sync::MutexGuard<'static, Rings> {
    RINGS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Rings {
    const fn new() -> Self {
        Rings {
            cpus: 0,
            mem_total: 0,
            disk_total: 0,
            fine: Ring::new(FINE),
            coarse: Ring::new(COARSE),
            work: BTreeMap::new(),
        }
    }

    fn node(&mut self, at: u64, values: [f64; 8], cpus: u32, mem_total: u64, disk_total: u64) {
        (self.cpus, self.mem_total, self.disk_total) = (cpus, mem_total, disk_total);
        self.fine.add(at, values);
        self.coarse.add(at, values);
    }

    /// Forget the Workloads not seen for `KEEP_WORKLOAD` as of `at` (once a tick, whether or not
    /// any was seen in it).
    fn purge(&mut self, at: u64) {
        self.work
            .retain(|_, work| at.saturating_sub(work.last) <= KEEP_WORKLOAD);
    }

    fn work(&mut self, at: u64, key: &str, values: [f64; 2]) {
        if !self.work.contains_key(key) && self.work.len() >= MAX_WORKLOADS {
            return;
        }
        let work = self.work.entry(key.to_string()).or_insert_with(|| {
            Box::new(Work {
                last: at,
                fine: Ring::new(FINE),
                coarse: Ring::new(COARSE),
            })
        });
        work.last = at;
        work.fine.add(at, values);
        work.coarse.add(at, values);
    }

    /// This node's series, `points` of `step` ending at `end`, for the node `me`.
    fn local(&self, me: &str, step: u64, points: usize, end: u64) -> Local {
        let fine = step == FINE;
        let rows = if fine {
            self.fine.series(end, points)
        } else {
            self.coarse.series(end, points)
        };
        let node = NodeSeries {
            cpu: column(&rows, 0, 3),
            cpus: self.cpus,
            mem: column(&rows, 1, 0),
            mem_total: self.mem_total,
            disk: column(&rows, 2, 0),
            disk_total: self.disk_total,
            disk_read: column(&rows, 3, 0),
            disk_write: column(&rows, 4, 0),
            rx: column(&rows, 5, 0),
            tx: column(&rows, 6, 0),
            load1: column(&rows, 7, 3),
            missing: false,
        };
        let workloads = self
            .work
            .iter()
            .map(|(key, work)| {
                let rows = if fine {
                    work.fine.series(end, points)
                } else {
                    work.coarse.series(end, points)
                };
                let series = WorkSeries {
                    node: me.to_string(),
                    cpu: column(&rows, 0, 3),
                    mem: column(&rows, 1, 0),
                };
                (key.clone(), series)
            })
            .collect();
        Local { node, workloads }
    }
}

/// Value `i` of each row, to `places` decimals (a JSON number is as short as it can be).
fn column<const K: usize>(rows: &[Option<[f64; K]>], i: usize, places: i32) -> Vec<Option<f64>> {
    let scale = 10f64.powi(places);
    rows.iter()
        .map(|row| {
            let value = row.map(|values| values[i]).filter(|value| !value.is_nan());
            value.map(|value| (value * scale).round() / scale)
        })
        .collect()
}

fn no(value: &bool) -> bool {
    !*value
}

/// One node's series, as `GET /v1/metrics` has them.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeSeries {
    cpu: Vec<Option<f64>>,
    cpus: u32,
    mem: Vec<Option<f64>>,
    mem_total: u64,
    disk: Vec<Option<f64>>,
    disk_total: u64,
    disk_read: Vec<Option<f64>>,
    disk_write: Vec<Option<f64>>,
    rx: Vec<Option<f64>>,
    tx: Vec<Option<f64>>,
    load1: Vec<Option<f64>>,
    #[serde(default, skip_serializing_if = "no")]
    missing: bool,
}

impl NodeSeries {
    /// A node that did not answer: the whole shape, of nothing.
    fn missing(points: usize) -> Self {
        let nulls = vec![None; points];
        NodeSeries {
            cpu: nulls.clone(),
            mem: nulls.clone(),
            disk: nulls.clone(),
            disk_read: nulls.clone(),
            disk_write: nulls.clone(),
            rx: nulls.clone(),
            tx: nulls.clone(),
            load1: nulls,
            missing: true,
            ..NodeSeries::default()
        }
    }

    fn columns(&self) -> [&Vec<Option<f64>>; 8] {
        [
            &self.cpu,
            &self.mem,
            &self.disk,
            &self.disk_read,
            &self.disk_write,
            &self.rx,
            &self.tx,
            &self.load1,
        ]
    }
}

/// One Workload's series on the node it runs on.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct WorkSeries {
    node: String,
    cpu: Vec<Option<f64>>,
    mem: Vec<Option<f64>>,
}

/// What one node says of itself (and what it sends another that asks).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Local {
    node: NodeSeries,
    workloads: BTreeMap<String, WorkSeries>,
}

impl Local {
    /// Only the Workloads (`NS/NAME`) `grants` lets its holder list or get in their namespace:
    /// the names of another namespace's, and what they use, are not for it.
    fn keep_readable(&mut self, grants: &crate::access::Grants) {
        self.workloads.retain(|key, _| {
            let namespace = key.split_once('/').map(|(namespace, _)| namespace);
            [Verb::List, Verb::Get]
                .iter()
                .any(|verb| grants.may(verb, "Workload", namespace))
        });
    }

    /// Only the Workloads `known` says exist (by `NS/NAME`): what another node says of a name this
    /// cluster has no Workload of is not shown.
    fn keep_known(&mut self, known: impl Fn(&str) -> bool) {
        self.workloads.retain(|key, _| known(key));
    }

    /// Whether it is what was asked for: `points` in each series, no more Workloads than a node
    /// keeps, and each named `NS/NAME` (what another node sent is not taken on trust for its size
    /// or its names: an `@` in one would pass for the `NS/NAME@NODE` of another's).
    fn fits(&self, points: usize) -> bool {
        let named = |key: &str| {
            key.split_once('/')
                .is_some_and(|(namespace, name)| !namespace.is_empty() && !name.is_empty() && !name.contains('/'))
                && !key.contains('@')
        };
        self.node.columns().iter().all(|column| column.len() == points)
            && self.workloads.len() <= MAX_WORKLOADS
            && self
                .workloads
                .iter()
                .all(|(key, w)| named(key) && w.cpu.len() == points && w.mem.len() == points)
    }
}

/// The step and number of points of a range.
fn span(range: &str) -> Option<(u64, usize)> {
    match range {
        "15m" => Some((FINE, 90)),
        "1h" => Some((FINE, FINE_N)),
        "6h" => Some((COARSE, 72)),
        "24h" => Some((COARSE, COARSE_N)),
        _ => None,
    }
}

/// The answer: each node's series by name (a node that did not answer is `missing`), and each
/// Workload's by `NS/NAME`. A Workload that runs on more than one node has the first node's (by
/// name) under `NS/NAME` and each other's under `NS/NAME@NODE`.
fn merge(
    range: &str,
    step: u64,
    points: usize,
    end: u64,
    mut locals: Vec<(String, Option<Local>)>,
) -> serde_json::Value {
    locals.sort_by(|a, b| a.0.cmp(&b.0));
    let (mut nodes, mut workloads) = (BTreeMap::new(), BTreeMap::new());
    for (name, local) in locals {
        let Some(Local { node, workloads: work }) = local else {
            nodes.insert(name, NodeSeries::missing(points));
            continue;
        };
        for (key, mut series) in work {
            series.node.clone_from(&name);
            let key = if workloads.contains_key(&key) {
                format!("{key}@{name}")
            } else {
                key
            };
            workloads.insert(key, series);
        }
        nodes.insert(name, node);
    }
    serde_json::json!({ "range": range, "step": step, "end": end, "nodes": nodes, "workloads": workloads })
}

#[derive(Deserialize)]
pub struct Options {
    range: Option<String>,
    /// Only for another node: the end the asking node answers with, so the series line up.
    end: Option<u64>,
}

fn invalid(range: &str) -> ApiError {
    ApiError::Store(Error::Invalid(format!("range {range:?}: it is 15m, 1h, 6h or 24h")))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Every Node but `me`, with where to ask it (none while it has no address: it is shown as
/// missing, not left out as though it were not there).
fn peers_of<'a>(
    nodes: impl Iterator<Item = &'a kith_api::Resource>,
    me: &str,
) -> Vec<(String, Option<crate::view::Upstream>)> {
    nodes
        .filter(|node| node.metadata.name != me)
        .map(|node| (node.metadata.name.clone(), crate::view::Upstream::of(node)))
        .collect()
}

/// `GET /v1/metrics`: every node's series.
// ponytail: not cached, and one call to each peer per request; if many viewers poll, a 2 to 5 s
// cache of the merged answer per (range, grants) is the fix.
pub async fn serve(
    State(shared): State<std::sync::Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Query(options): Query<Options>,
) -> Reply<serde_json::Value> {
    permit(&shared, &caller, Verb::List, |_| vec![("Node".into(), None)])?;
    let range = options.range.as_deref().unwrap_or("1h");
    let (step, points) = span(range).ok_or_else(|| invalid(range))?;
    let end = now() / step * step;
    let me = shared.members.me().to_string();
    let mine = rings().local(&me, step, points, end);
    let peers = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        peers_of(state.store.list(Some("Node")), &me)
    };
    let query = format!("range={range}&end={end}");
    let asked = peers.into_iter().map(|(name, there)| {
        let (shared, query) = (shared.clone(), query.clone());
        async move {
            let local = match (&shared.cluster, there) {
                (Some(cluster), Some(there)) => ask(cluster, &there, &query).await.filter(|local| local.fits(points)),
                _ => None,
            };
            (name, local)
        }
    });
    let mut all = futures_util::future::join_all(asked).await;
    all.push((me, Some(mine)));
    // (Whoever may list Nodes sees every node's series, but a Workload's only in a namespace it
    // may read, and of another node's only one this cluster has; the asked node decides, as the
    // nodes' own answers are for the cluster.)
    {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let grants = crate::access::Grants::of(&caller, &state.store);
        let known = |key: &str| state.store.get(&format!("Workload/{key}")).is_some();
        for (name, local) in &mut all {
            let Some(local) = local else { continue };
            if name != shared.members.me() {
                local.keep_known(known);
            }
            local.keep_readable(&grants);
        }
    }
    Ok(Json(merge(range, step, points, end, all)))
}

/// What the node `there` says of itself, or nothing: it did not answer in time, or what it sent
/// is no answer (too big, not JSON).
async fn ask(cluster: &crate::cluster::Cluster, there: &crate::view::Upstream, query: &str) -> Option<Local> {
    let client = cluster.to(there).ok()?;
    let url = format!("https://{}/v1/node-metrics?{query}", there.address);
    let mut answer = client
        .get(url)
        .timeout(ASK_FOR)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?;
    let mut body = Vec::new();
    while let Some(chunk) = answer.chunk().await.ok()? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_ANSWER {
            return None;
        }
    }
    let mut local: Local = serde_json::from_slice(&body).ok()?;
    // (Whatever it says of itself, it is not missing, and its Workloads run on it.)
    local.node.missing = false;
    Some(local)
}

/// `GET /v1/node-metrics`, members only: this node's own series, for the node that was asked for
/// all (which has checked who asked it).
pub async fn node(State(shared): State<std::sync::Arc<Shared>>, Query(options): Query<Options>) -> Reply<Local> {
    let range = options.range.as_deref().unwrap_or("1h");
    let (step, points) = span(range).ok_or_else(|| invalid(range))?;
    let end = options.end.unwrap_or_else(now) / step * step;
    Ok(Json(rings().local(shared.members.me(), step, points, end)))
}

// What the sampler reads. Each parser takes the text of a file, so that a fixture tests it.

/// `/proc/stat`: the CPUs' busy and total ticks (all of the first line's but guest, which the user's
/// ticks hold already), and how many CPUs there are.
fn parse_stat(text: &str) -> Option<(u64, u64, u32)> {
    let mut lines = text.lines();
    let ticks: Vec<u64> = lines
        .next()?
        .strip_prefix("cpu ")?
        .split_whitespace()
        .take(8)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    let [_, _, _, idle, ..] = ticks[..] else { return None };
    let total: u64 = ticks.iter().sum();
    let waiting = idle + ticks.get(4).copied().unwrap_or(0);
    let cpus = lines.filter(|line| line.starts_with("cpu")).count();
    Some((total.saturating_sub(waiting), total, cpus.max(1) as u32))
}

/// `/proc/meminfo`: the bytes of memory there are, and the bytes in use (not what is available).
fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
    let kb = |name: &str| -> Option<u64> {
        let line = text.lines().find_map(|line| line.strip_prefix(name))?;
        line.trim_start_matches(':').split_whitespace().next()?.parse().ok()
    };
    let (total, available) = (kb("MemTotal")?, kb("MemAvailable")?);
    Some((total * 1024, total.saturating_sub(available) * 1024))
}

/// `/proc/diskstats`: the bytes read and written since boot by the disks `whole` says are (a
/// partition is its disk's, and a loop, ram, md or dm device sits on another or is not one).
fn parse_diskstats(text: &str, whole: impl Fn(&str) -> bool) -> (u64, u64) {
    let (mut read, mut written) = (0, 0u64);
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [_, _, name, _, _, sectors_read, _, _, _, sectors_written, ..] = fields[..] else {
            continue;
        };
        let virtual_ = ["loop", "ram", "dm-", "md", "zram", "sr"];
        if virtual_.iter().any(|prefix| name.starts_with(prefix)) || !whole(name) {
            continue;
        }
        read += sectors_read.parse::<u64>().unwrap_or(0) * 512;
        written += sectors_written.parse::<u64>().unwrap_or(0) * 512;
    }
    (read, written)
}

/// An interface's bytes received and sent since it came.
type Nics = BTreeMap<String, (u64, u64)>;

/// `/proc/net/dev`: the bytes received and sent since each interface but `lo` came (kept apart:
/// containers' veths come and go, and a sum would fall and jump with them).
fn parse_nics(text: &str) -> Nics {
    let mut nics = Nics::new();
    for line in text.lines() {
        let Some((name, counters)) = line.split_once(':') else {
            continue;
        };
        let fields: Vec<&str> = counters.split_whitespace().collect();
        let name = name.trim();
        if name == "lo" || fields.len() < 9 {
            continue;
        }
        let (Ok(rx), Ok(tx)) = (fields[0].parse(), fields[8].parse()) else {
            continue;
        };
        nics.insert(name.to_string(), (rx, tx));
    }
    nics
}

/// `/proc/loadavg`: the load of the last minute.
fn parse_load(text: &str) -> Option<f64> {
    text.split_whitespace().next()?.parse().ok()
}

/// A cgroup's `cpu.stat`: the microseconds of CPU it has used.
fn parse_usage(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix("usage_usec "))?
        .trim()
        .parse()
        .ok()
}

/// What a node's files said at one time.
#[derive(Clone, Debug)]
struct Reading {
    busy: u64,
    total: u64,
    cpus: u32,
    mem_total: u64,
    mem_used: u64,
    read: u64,
    write: u64,
    nics: Nics,
    load1: f64,
}

fn sample(
    stat: &str,
    meminfo: &str,
    diskstats: &str,
    net: &str,
    loadavg: &str,
    whole: impl Fn(&str) -> bool,
) -> Option<Reading> {
    let (busy, total, cpus) = parse_stat(stat)?;
    let (mem_total, mem_used) = parse_meminfo(meminfo)?;
    let (read, write) = parse_diskstats(diskstats, whole);
    Some(Reading {
        busy,
        total,
        cpus,
        mem_total,
        mem_used,
        read,
        write,
        nics: parse_nics(net),
        load1: parse_load(loadavg)?,
    })
}

/// The CPU busy fraction and the rates (bytes per second) between two readings `secs` apart:
/// cpu, disk read, disk write, rx, tx. A counter that went back is a rate of nothing; the network's
/// are the sum of each interface's own, and an interface that is not in both readings, or whose
/// counters went back (it came again), is left out of it.
fn rates(before: &Reading, now: &Reading, secs: f64) -> [f64; 5] {
    if secs <= 0.0 {
        return [0.0; 5];
    }
    let ticks = now.total.saturating_sub(before.total);
    let cpu = if ticks == 0 {
        0.0
    } else {
        (now.busy.saturating_sub(before.busy) as f64 / ticks as f64).clamp(0.0, 1.0)
    };
    let rate = |before: u64, now: u64| now.saturating_sub(before) as f64 / secs;
    let (mut rx, mut tx) = (0, 0u64);
    for (name, (now_rx, now_tx)) in &now.nics {
        if let Some((was_rx, was_tx)) = before.nics.get(name)
            && now_rx >= was_rx
            && now_tx >= was_tx
        {
            rx += now_rx - was_rx;
            tx += now_tx - was_tx;
        }
    }
    [
        cpu,
        rate(before.read, now.read),
        rate(before.write, now.write),
        rx as f64 / secs,
        tx as f64 / secs,
    ]
}

/// The Workload a unit's cgroup directory (`kith-` and the unit's id) is a unit of, as `NS/NAME`
/// (the controller says how its ids are made, so what reads them is not a copy of it).
fn unit_workload(dir: &str) -> Option<String> {
    crate::controller::workload_of_unit(dir.strip_prefix("kith-")?)
}

/// Per unit cgroup directory name: the microseconds of CPU it has used and the bytes of memory
/// (`None` where the cgroup does not say, a controller being off).
type Units = BTreeMap<String, (u64, Option<u64>)>;

/// The units of Workloads in the cgroup directory `dir` (none where it is not there).
fn read_units(dir: &Path) -> Units {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Units::new();
    };
    let mut units = Units::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if unit_workload(&name).is_none() || units.len() >= 4 * MAX_WORKLOADS {
            continue;
        }
        let read = |file: &str| std::fs::read_to_string(entry.path().join(file)).ok();
        let usage = read("cpu.stat").as_deref().and_then(parse_usage);
        let memory = read("memory.current").and_then(|text| text.trim().parse().ok());
        if let Some(usage) = usage {
            units.insert(name, (usage, memory));
        }
    }
    units
}

/// Each Workload's CPU in cores (over `secs`) and memory in bytes, its units' summed: a unit that
/// was not there before has memory and no CPU yet, and the memory of a Workload none of whose units
/// says is NaN (not known).
fn per_workload(before: &Units, now: &Units, secs: f64) -> BTreeMap<String, [f64; 2]> {
    let mut by: BTreeMap<String, [f64; 2]> = BTreeMap::new();
    for (name, (usage, memory)) in now {
        let Some(key) = unit_workload(name) else { continue };
        let cores = match before.get(name) {
            Some((was, _)) if secs > 0.0 => usage.saturating_sub(*was) as f64 / (secs * 1e6),
            _ => 0.0,
        };
        let sum = by.entry(key).or_insert([0.0, f64::NAN]);
        sum[0] += cores;
        if let Some(memory) = memory {
            sum[1] = if sum[1].is_nan() { 0.0 } else { sum[1] } + *memory as f64;
        }
    }
    by
}

/// Everything the sampler reads at one moment.
struct Collected {
    when: Instant,
    reading: Option<Reading>,
    /// The state disk's bytes used and its size; `None` where `statvfs` failed.
    disk: Option<(u64, u64)>,
    units: Units,
}

fn collect(state: &Path, units: Option<&Path>) -> Collected {
    let text = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    // (A partition has no entry in /sys/block: the whole disk is counted, not both.)
    let whole = |name: &str| Path::new("/sys/block").join(name).exists();
    let reading = sample(
        &text("/proc/stat"),
        &text("/proc/meminfo"),
        &text("/proc/diskstats"),
        &text("/proc/net/dev"),
        &text("/proc/loadavg"),
        whole,
    );
    let disk = nix::sys::statvfs::statvfs(state).ok().map(|disk| {
        let size = disk.fragment_size();
        (
            disk.blocks().saturating_sub(disk.blocks_free()) * size,
            disk.blocks() * size,
        )
    });
    Collected {
        when: Instant::now(),
        reading,
        disk,
        units: units.map(read_units).unwrap_or_default(),
    }
}

/// Put what changed between two collections in the rings, as of `at`.
fn feed(rings: &mut Rings, at: u64, before: &Collected, now: &Collected) {
    let secs = now.when.saturating_duration_since(before.when).as_secs_f64();
    if let (Some(was), Some(is)) = (&before.reading, &now.reading) {
        let [cpu, read, write, rx, tx] = rates(was, is, secs);
        // (A disk that could not be read is a gap, and its size is what it was.)
        let used = now.disk.map_or(f64::NAN, |(used, _)| used as f64);
        let values = [cpu, is.mem_used as f64, used, read, write, rx, tx, is.load1];
        let size = now.disk.map_or(rings.disk_total, |(_, size)| size);
        rings.node(at, values, is.cpus, is.mem_total, size);
    }
    rings.purge(at);
    for (key, values) in per_workload(&before.units, &now.units, secs) {
        rings.work(at, &key, values);
    }
}

/// Samples this node every 10 s, on the clock's tens of seconds (so that the nodes' points fall
/// in the same slots), until `stopping`.
pub async fn run(state: PathBuf, mut stopping: watch::Receiver<bool>) {
    // (Where the runtime puts units' cgroups: ask it, not a copy of its rule.)
    let units = kith_runtime::units_cgroup_dir();
    let once = || {
        let (state, units) = (state.clone(), units.clone());
        async move {
            tokio::task::spawn_blocking(move || collect(&state, units.as_deref()))
                .await
                .ok()
        }
    };
    // (A first reading now, so that the first point is one tick away, not two.)
    let mut before = once().await;
    loop {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis() as u64);
        let wait = Duration::from_millis(FINE * 1000 - millis % (FINE * 1000));
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = stopping.changed() => return,
        }
        let Some(now) = once().await else { continue };
        // (The nearest ten, not the floor: a clock a little behind the timer is the same slot.)
        let at = (now_ms() + FINE * 500) / (FINE * 1000) * FINE;
        if let Some(before) = &before {
            feed(&mut rings(), at, before, &now);
        }
        before = Some(now);
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT: &str =
        "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 50 0 25 400 25 0 0 0 0 0\ncpu1 50 0 25 400 25 0 0 0 0 0\nintr 1 2 3\n";
    const STAT_LATER: &str =
        "cpu  160 0 70 900 70 0 0 0 0 0\ncpu0 80 0 35 450 35 0 0 0 0 0\ncpu1 80 0 35 450 35 0 0 0 0 0\n";
    const MEMINFO: &str =
        "MemTotal:       16000000 kB\nMemFree:         1000000 kB\nMemAvailable:    4000000 kB\nBuffers: 5 kB\n";
    const DISKSTATS: &str = "   8       0 sda 100 0 2000 50 200 0 4000 80 0 100 130\n   8       1 sda1 90 0 1800 40 190 0 3900 70 0 90 110\n   7       0 loop0 5 0 40 1 0 0 0 0 0 1 1\n 259       0 nvme0n1 10 0 800 5 20 0 1600 9 0 10 14\n 259       1 nvme0n1p1 10 0 800 5 20 0 1600 9 0 10 14\n 253       0 dm-0 10 0 999 5 20 0 999 9 0 10 14\n";
    const NET: &str = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n  eth0:5000 50 0 0 0 0 0 0 7000 70 0 0 0 0 0 0\n wlan0: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n";
    const LOAD: &str = "0.52 0.40 0.30 1/200 12345\n";

    /// What `/sys/block` says: whole disks only, a partition has no entry there.
    fn whole(name: &str) -> bool {
        matches!(name, "sda" | "loop0" | "nvme0n1" | "dm-0")
    }

    #[test]
    fn metrics_parsers_read_the_proc_files() {
        assert_eq!(parse_stat(STAT), Some((150, 1000, 2)));
        assert_eq!(parse_meminfo(MEMINFO), Some((16_000_000 * 1024, 12_000_000 * 1024)));
        // (sda and nvme0n1 whole; not their partitions, not loop or dm, which sit on a disk or are not one.)
        assert_eq!(
            parse_diskstats(DISKSTATS, whole),
            ((2000 + 800) * 512, (4000 + 1600) * 512)
        );
        // (Per interface, `lo` apart: a sum would fall when one went and jump when one came.)
        assert_eq!(
            parse_nics(NET),
            BTreeMap::from([("eth0".to_string(), (5000, 7000)), ("wlan0".to_string(), (100, 200))])
        );
        assert_eq!(parse_load(LOAD), Some(0.52));
        assert_eq!(
            parse_usage("usage_usec 5000000\nuser_usec 3000000\nsystem_usec 2000000\n"),
            Some(5_000_000)
        );
        // A file that is not what it should be gives nothing, and never a panic.
        assert_eq!(parse_stat(""), None);
        assert_eq!(parse_stat("cpu  a b c\n"), None);
        assert_eq!(parse_meminfo("MemTotal: x kB\n"), None);
        assert_eq!(parse_load("x"), None);
        assert_eq!(parse_usage("user_usec 1\n"), None);
        assert_eq!(parse_diskstats("garbage\n 1 2 sda\n", |_| true), (0, 0));
        assert!(parse_nics("no colon here\n").is_empty());
    }

    #[test]
    fn metrics_unit_names_say_their_workload() {
        assert_eq!(
            unit_workload("kith-w_default_web_0_main").as_deref(),
            Some("default/web")
        );
        assert_eq!(
            unit_workload("kith-w_shop_api_12b_sidecar").as_deref(),
            Some("shop/api")
        );
        // It is the controller's own ids it reads (a pod's id, and a unit in it), not a copy of their shape.
        let pod = crate::controller::pod_of("Workload/default/web.v2", 3);
        assert_eq!(
            unit_workload(&format!("kith-{pod}_main")).as_deref(),
            Some("default/web.v2")
        );
        // A Job, a NodeWorkload, the runtime's own probe and any other name are no Workload's.
        for no in [
            "kith-j_default_job_0_main",
            "kith-n_default_x_0_main",
            "kith-probe-12",
            "kith-w_default",
            "web",
            "",
        ] {
            assert_eq!(unit_workload(no), None, "{no}");
        }
    }

    #[test]
    fn metrics_rates_come_from_two_readings() {
        let reading = |stat, read: u64, write: u64, nics: &[(&str, u64, u64)]| {
            let mut r = sample(stat, MEMINFO, DISKSTATS, NET, LOAD, whole).unwrap();
            (r.read, r.write) = (read, write);
            r.nics = nics
                .iter()
                .map(|(name, rx, tx)| (name.to_string(), (*rx, *tx)))
                .collect();
            r
        };
        let (a, b) = (
            reading(STAT, 1000, 2000, &[("eth0", 10_000, 20_000), ("wlan0", 500, 500)]),
            reading(STAT_LATER, 6000, 3000, &[("eth0", 10_500, 19_000), ("wlan0", 600, 800)]),
        );
        let [cpu, read, write, rx, tx] = rates(&a, &b, 10.0);
        // 80 busy of 200 ticks; bytes over ten seconds; an interface whose counter went back (it
        // came again) is no negative rate, and no rate at all: wlan0's alone is counted.
        assert_eq!((cpu, read, write, rx, tx), (0.4, 500.0, 100.0, 10.0, 30.0));
        assert_eq!(rates(&a, &a, 10.0)[0], 0.0, "no ticks between is no division by zero");
        assert_eq!(rates(&a, &b, 0.0), [0.0; 5], "no time between is no rate");
    }

    #[test]
    fn metrics_net_rate_ignores_an_interface_that_came_or_went() {
        let reading = |nics: &[(&str, u64, u64)]| {
            let mut r = sample(STAT, MEMINFO, DISKSTATS, NET, LOAD, whole).unwrap();
            r.nics = nics
                .iter()
                .map(|(name, rx, tx)| (name.to_string(), (*rx, *tx)))
                .collect();
            r
        };
        // A veth that was there is gone (its bytes were in the sum), and a tap that was not is
        // there with a lifetime of bytes: the rate is eth0's alone, not 0 and not a spike.
        let before = reading(&[("eth0", 1000, 2000), ("veth1", 5_000_000, 5_000_000)]);
        let after = reading(&[("eth0", 1500, 2100), ("tap2", 9_000_000_000, 9_000_000_000)]);
        let [_, _, _, rx, tx] = rates(&before, &after, 10.0);
        assert_eq!((rx, tx), (50.0, 10.0));
        // Nothing in common is a rate of nothing.
        let [_, _, _, rx, tx] = rates(&reading(&[("a", 1, 1)]), &reading(&[("b", 9, 9)]), 10.0);
        assert_eq!((rx, tx), (0.0, 0.0));
    }

    #[test]
    fn metrics_units_are_read_from_their_cgroups() {
        let dir = std::env::temp_dir().join(format!("kithd-metrics-units-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (unit, usec, mem) in [
            ("kith-w_default_web_0_a", 4_000_000, 100),
            ("kith-w_default_web_0_b", 1_000_000, 50),
            ("kith-w_shop_db_0_main", 0, 7),
        ] {
            std::fs::create_dir_all(dir.join(unit)).unwrap();
            std::fs::write(
                dir.join(unit).join("cpu.stat"),
                format!("usage_usec {usec}\nuser_usec 1\n"),
            )
            .unwrap();
            std::fs::write(dir.join(unit).join("memory.current"), format!("{mem}\n")).unwrap();
        }
        // Not a unit of a Workload, or one whose files are not there (it is gone, or not a cgroup).
        std::fs::create_dir_all(dir.join("kith-j_default_job_0_main")).unwrap();
        std::fs::create_dir_all(dir.join("kith-w_default_gone_0_main")).unwrap();
        std::fs::write(dir.join("kith-w_default_afile"), "x").unwrap();
        // A unit with CPU and no `memory.current` (a controller that is off) is kept, its memory unknown.
        std::fs::create_dir_all(dir.join("kith-w_shop_nomem_0_main")).unwrap();
        std::fs::write(dir.join("kith-w_shop_nomem_0_main/cpu.stat"), "usage_usec 1000000\n").unwrap();
        let before = read_units(&dir);
        assert_eq!(before.len(), 4, "{before:?}");
        assert_eq!(before["kith-w_shop_nomem_0_main"], (1_000_000, None));
        std::fs::write(dir.join("kith-w_default_web_0_a/cpu.stat"), "usage_usec 6000000\n").unwrap();
        let after = read_units(&dir);
        // web: 2 s of CPU in 10 s from one unit, the other unchanged; memory is the sum; a unit
        // new since has memory and no CPU yet.
        let mut later = after.clone();
        later.insert("kith-w_shop_new_0_main".into(), (9, Some(3)));
        later.insert("kith-w_shop_nomem_0_main".into(), (3_000_000, None));
        let by = per_workload(&before, &later, 10.0);
        assert_eq!(by["default/web"], [0.2, 150.0]);
        assert_eq!(by["shop/db"], [0.0, 7.0]);
        assert_eq!(by["shop/new"], [0.0, 3.0]);
        // Its CPU is there (0.2 cores), its memory is not known: NaN, which a ring skips and a series shows null.
        assert_eq!(by["shop/nomem"][0], 0.2);
        assert!(by["shop/nomem"][1].is_nan());
        // Another unit of it that has memory is what its memory is.
        later.insert("kith-w_shop_nomem_0_b".into(), (0, Some(40)));
        assert_eq!(per_workload(&before, &later, 10.0)["shop/nomem"][1], 40.0);
        assert_eq!(by.len(), 4);
        assert!(read_units(&dir.join("nothing here")).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn metrics_ring_drops_the_oldest_and_shows_gaps() {
        let mut ring = Ring::<1, 4>::new(10);
        for (at, v) in [(0, 1.0), (10, 2.0), (20, 3.0), (30, 4.0)] {
            ring.add(at, [v]);
        }
        let all = |ring: &Ring<1, 4>, end| {
            ring.series(end, 4)
                .into_iter()
                .map(|p| p.map(|[v]| v))
                .collect::<Vec<_>>()
        };
        assert_eq!(all(&ring, 30), [Some(1.0), Some(2.0), Some(3.0), Some(4.0)]);
        // A fifth slot takes the place of the first: the ring is as big as it was.
        ring.add(40, [5.0]);
        assert_eq!(all(&ring, 40), [Some(2.0), Some(3.0), Some(4.0), Some(5.0)]);
        // Asked as of the past: the slot that was taken over is null, not the other's value, and a
        // time before the epoch is null too.
        assert_eq!(all(&ring, 20), [None, None, Some(2.0), Some(3.0)]);
        // A slot nobody sampled is a gap, and a time not yet reached is too.
        let mut gappy = Ring::<1, 4>::new(10);
        gappy.add(0, [1.0]);
        gappy.add(30, [4.0]);
        assert_eq!(all(&gappy, 30), [Some(1.0), None, None, Some(4.0)]);
        assert_eq!(all(&gappy, 50), [None, Some(4.0), None, None]);
    }

    #[test]
    fn metrics_coarse_slots_average_their_samples() {
        let mut ring = Ring::<2, 3>::new(300);
        ring.add(0, [1.0, 10.0]);
        ring.add(10, [3.0, 30.0]);
        ring.add(290, [5.0, 50.0]);
        ring.add(300, [100.0, 0.0]);
        let rows = ring.series(300, 2);
        assert_eq!(rows, [Some([3.0, 30.0]), Some([100.0, 0.0])]);
    }

    #[test]
    fn metrics_memory_is_bounded() {
        // The rings are arrays: a day of samples is as big as a minute of them.
        let mut rings = Rings::new();
        for at in (0..200_000u64).step_by(10) {
            rings.node(at, [0.5; 8], 4, 1 << 30, 1 << 40);
        }
        let held = |cells: &[Cell<8>]| cells.iter().filter(|cell| cell.n > 0).count();
        assert_eq!((held(&rings.fine.cells), held(&rings.coarse.cells)), (360, 288));
        // (And the two are what an hour and a day are: 10 s and 5 min points.)
        assert_eq!((rings.fine.step * 360, rings.coarse.step * 288), (3600, 86_400));
        assert!(std::mem::size_of::<Ring<8, 360>>() + std::mem::size_of::<Ring<8, 288>>() < 100 << 10);
        // A workload not seen for an hour is forgotten, and no more than MAX_WORKLOADS are kept.
        let mut rings = Rings::new();
        rings.work(1000, "a/old", [1.0, 1.0]);
        rings.purge(1000 + KEEP_WORKLOAD + 10);
        rings.work(1000 + KEEP_WORKLOAD + 10, "a/new", [1.0, 1.0]);
        assert_eq!(rings.work.keys().collect::<Vec<_>>(), ["a/new"]);
        for i in 0..MAX_WORKLOADS + 20 {
            rings.work(9000, &format!("a/w{i}"), [1.0, 1.0]);
        }
        assert_eq!(rings.work.len(), MAX_WORKLOADS);
    }

    #[test]
    fn metrics_ranges_are_four() {
        assert_eq!(span("15m"), Some((10, 90)));
        assert_eq!(span("1h"), Some((10, 360)));
        assert_eq!(span("6h"), Some((300, 72)));
        assert_eq!(span("24h"), Some((300, 288)));
        for no in ["", "2d", "1H", "15", "-1h"] {
            assert_eq!(span(no), None, "{no}");
        }
    }

    fn fed() -> Rings {
        let mut rings = Rings::new();
        // Ten-second samples at 1000..=1040: slot 100 to 104.
        for (i, at) in (1000..=1040).step_by(10).enumerate() {
            let i = i as f64;
            rings.node(
                at,
                [0.1 * i, 1000.0 + i, 5000.0, 10.0, 20.0, 30.0, 40.0, 0.5],
                4,
                2000,
                9000,
            );
            rings.work(at, "default/web", [i / 10.0, 100.0 * i]);
        }
        rings
    }

    #[test]
    fn metrics_series_of_a_node_is_aligned_to_the_end_oldest_first() {
        let Local { node, workloads: work } = fed().local("alpha", 10, 5, 1040);
        assert_eq!(node.cpus, 4);
        assert_eq!((node.mem_total, node.disk_total), (2000, 9000));
        // Five points ending at 1040: 1000, 1010, 1020, 1030, 1040.
        assert_eq!(node.cpu, [Some(0.0), Some(0.1), Some(0.2), Some(0.3), Some(0.4)]);
        assert_eq!(
            node.mem,
            [Some(1000.0), Some(1001.0), Some(1002.0), Some(1003.0), Some(1004.0)]
        );
        assert_eq!(node.disk_read, [Some(10.0); 5]);
        assert_eq!(node.tx, [Some(40.0); 5]);
        assert_eq!(node.load1, [Some(0.5); 5]);
        assert!(!node.missing);
        assert_eq!(work["default/web"].node, "alpha");
        assert_eq!(
            work["default/web"].mem,
            [Some(0.0), Some(100.0), Some(200.0), Some(300.0), Some(400.0)]
        );
        // Two slots ahead of what was sampled, and two behind: nulls at the ends, never a shifted series.
        let Local { node, .. } = fed().local("alpha", 10, 5, 1060);
        assert_eq!(node.cpu, [Some(0.2), Some(0.3), Some(0.4), None, None]);
        let Local { node, .. } = fed().local("alpha", 10, 7, 1040);
        assert_eq!(node.cpu[..2], [None, None]);
        assert_eq!(node.cpu[2], Some(0.0));
    }

    #[test]
    fn metrics_series_of_workloads_are_the_callers_namespaces_only() {
        use crate::access::Grants;
        use kith_api::kinds::AccessRule;
        let mut rings = fed();
        rings.work(1040, "b/db", [1.0, 5.0]);
        rings.work(1040, "a/api", [1.0, 5.0]);
        let local = |name: &str| rings.local(name, 10, 3, 1040);
        let rule = |kinds: &[&str], verbs: Vec<Verb>, namespaces: &[&str]| AccessRule {
            kinds: kinds.iter().map(|kind| kind.to_string()).collect(),
            verbs,
            namespaces: namespaces.iter().map(|ns| ns.to_string()).collect(),
        };
        let keys = |grants: &Grants| {
            let all = vec![
                ("n1".to_string(), Some(local("n1"))),
                ("n2".to_string(), Some(local("n2"))),
            ];
            let mut all = all;
            for (_, local) in &mut all {
                local.as_mut().unwrap().keep_readable(grants);
            }
            let answer = merge("15m", 10, 3, 1040, all);
            answer["workloads"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        };
        // Nodes in every namespace, Workloads in `a` only: the Node series are all there, `b` is not.
        let in_a = Grants::of_rules(vec![
            rule(&["Node"], vec![Verb::List], &[]),
            rule(&["Workload"], vec![Verb::List], &["a"]),
        ]);
        assert_eq!(keys(&in_a), ["a/api", "a/api@n2"]);
        // A right to get one counts as much as one to list; no right to Workloads shows none.
        let get_b = Grants::of_rules(vec![rule(&["Workload"], vec![Verb::Get], &["b"])]);
        assert_eq!(keys(&get_b), ["b/db", "b/db@n2"]);
        let nodes_only = Grants::of_rules(vec![rule(&["Node"], vec![Verb::List], &[])]);
        assert!(keys(&nodes_only).is_empty());
        // The admin (no rules to apply) keeps everything.
        let admin = Grants::of(&Caller::Admin, &kith_api::store::Store::default());
        assert_eq!(keys(&admin).len(), 6);
    }

    #[test]
    fn metrics_series_merge_marks_a_silent_node_and_keeps_every_workload() {
        let local = |name: &str| fed().local(name, 10, 3, 1040);
        let answer = merge(
            "15m",
            10,
            3,
            1040,
            vec![
                ("a".into(), Some(local("a"))),
                ("b".into(), None),
                ("c".into(), Some(local("c"))),
            ],
        );
        assert_eq!(answer["range"], "15m");
        assert_eq!(
            (answer["step"].as_u64(), answer["end"].as_u64()),
            (Some(10), Some(1040))
        );
        let nodes = answer["nodes"].as_object().unwrap();
        assert_eq!(nodes.keys().collect::<Vec<_>>(), ["a", "b", "c"]);
        // The silent one has the whole shape, empty, so a page that reads it has nothing to special-case.
        let b = &answer["nodes"]["b"];
        assert_eq!(b["missing"], true);
        for field in ["cpu", "mem", "disk", "diskRead", "diskWrite", "rx", "tx", "load1"] {
            assert_eq!(b[field], serde_json::json!([null, null, null]), "{field}");
        }
        assert_eq!(
            (b["cpus"].as_u64(), b["memTotal"].as_u64(), b["diskTotal"].as_u64()),
            (Some(0), Some(0), Some(0))
        );
        assert!(answer["nodes"]["a"].get("missing").is_none());
        assert_eq!(answer["nodes"]["a"]["cpu"], serde_json::json!([0.2, 0.3, 0.4]));
        assert_eq!(answer["nodes"]["a"]["memTotal"], 2000);
        // One Workload on two nodes: the first node (by name) has `NS/NAME`, the other `NS/NAME@NODE`.
        let work = answer["workloads"].as_object().unwrap();
        assert_eq!(work.keys().collect::<Vec<_>>(), ["default/web", "default/web@c"]);
        assert_eq!(work["default/web"]["node"], "a");
        assert_eq!(work["default/web@c"]["node"], "c");
        assert_eq!(work["default/web"]["mem"], serde_json::json!([200.0, 300.0, 400.0]));
    }

    #[test]
    fn metrics_series_answer_round_trips_between_nodes() {
        // What a peer sends is what the asking node reads back.
        let local = fed().local("alpha", 10, 5, 1040);
        let sent = serde_json::to_value(&local).unwrap();
        assert_eq!(sent["node"]["memTotal"], 2000);
        assert!(sent["node"].get("missing").is_none());
        let back: Local = serde_json::from_value(sent).unwrap();
        assert_eq!(back, local);
    }

    fn collected(when: Instant, units: Units, disk: Option<(u64, u64)>) -> Collected {
        Collected {
            when,
            reading: sample(STAT, MEMINFO, DISKSTATS, NET, LOAD, whole),
            disk,
            units,
        }
    }

    #[test]
    fn metrics_feed_forgets_a_deleted_workload_even_where_none_runs() {
        // The node's last Workload was deleted: no unit is read, and what it left is still purged.
        let mut rings = Rings::new();
        rings.work(1000, "a/gone", [1.0, 1.0]);
        let idle = collected(Instant::now(), Units::new(), Some((1, 2)));
        feed(&mut rings, 1000 + KEEP_WORKLOAD + 10, &idle, &idle);
        assert!(rings.work.is_empty());
        // And within the hour it is kept.
        rings.work(1000, "a/kept", [1.0, 1.0]);
        feed(&mut rings, 1000 + KEEP_WORKLOAD, &idle, &idle);
        assert_eq!(rings.work.len(), 1);
    }

    #[test]
    fn metrics_a_failed_disk_read_is_a_gap_not_a_full_disk_of_nothing() {
        let t = Instant::now();
        let first = collected(t, Units::new(), Some((50, 100)));
        let mut rings = Rings::new();
        feed(
            &mut rings,
            1000,
            &first,
            &collected(t + Duration::from_secs(10), Units::new(), Some((50, 100))),
        );
        feed(
            &mut rings,
            1010,
            &first,
            &collected(t + Duration::from_secs(10), Units::new(), None),
        );
        let Local { node, .. } = rings.local("n", 10, 2, 1010);
        assert_eq!(node.disk, [Some(50.0), None]);
        assert_eq!(node.load1, [Some(0.52), Some(0.52)], "the rest of the point is there");
        assert_eq!(node.disk_total, 100, "the size it had is not zeroed");
    }

    #[test]
    fn metrics_a_value_that_is_not_known_is_null_and_the_rest_of_the_point_stays() {
        let mut ring = Ring::<2, 3>::new(300);
        ring.add(0, [1.0, f64::NAN]);
        ring.add(10, [3.0, 5.0]);
        ring.add(300, [7.0, f64::NAN]);
        let rows = ring.series(300, 2);
        assert_eq!(column(&rows, 0, 3), [Some(2.0), Some(7.0)]);
        assert_eq!(
            column(&rows, 1, 3),
            [Some(5.0), None],
            "a mean of the samples that had one"
        );
    }

    #[test]
    fn metrics_nodes_to_ask_are_every_other_and_one_with_no_address_is_missing() {
        let node = |name: &str, status: serde_json::Value| -> kith_api::Resource {
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kith.dev/v1", "kind": "Node", "metadata": { "name": name },
                "spec": {}, "status": status,
            }))
            .unwrap()
        };
        let nodes = [
            node("alpha", serde_json::json!({ "address": "127.0.0.1:1" })),
            node("beta", serde_json::json!({ "address": "127.0.0.1:2" })),
            node("gamma", serde_json::Value::Null),
        ];
        let peers = peers_of(nodes.iter(), "alpha");
        let names: Vec<&str> = peers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["beta", "gamma"]);
        assert_eq!(
            peers[0].1.as_ref().map(|there| there.address.as_str()),
            Some("127.0.0.1:2")
        );
        assert!(
            peers[1].1.is_none(),
            "no address: asked of nobody, and shown as missing"
        );
        let mut all: Vec<(String, Option<Local>)> = peers.into_iter().map(|(name, _)| (name, None)).collect();
        all.push(("alpha".into(), Some(fed().local("alpha", 10, 3, 1040))));
        let answer = merge("15m", 10, 3, 1040, all);
        assert_eq!(answer["nodes"]["gamma"]["missing"], true);
        assert_eq!(answer["nodes"]["beta"]["missing"], true);
    }

    #[test]
    fn metrics_what_a_peer_sends_must_be_the_shape_asked_and_of_workloads_that_exist() {
        let local = fed().local("alpha", 10, 3, 1040);
        assert!(local.fits(3));
        let with = |key: &str| {
            let mut local = local.clone();
            local
                .workloads
                .insert(key.into(), local.workloads["default/web"].clone());
            local
        };
        assert!(with("shop/db").fits(3));
        // A key that is not `NS/NAME`, or that has an `@` (which would pass for another node's
        // `NS/NAME@NODE`), is no Workload's.
        for bad in ["", "web", "/web", "shop/", "a/b/c", "shop/db@beta", "@x/y"] {
            assert!(!with(bad).fits(3), "{bad:?}");
        }
        // Only the Workloads this cluster has are kept of what a peer says.
        let mut peer = with("shop/ghost");
        let known = |key: &str| key == "default/web";
        peer.keep_known(known);
        assert_eq!(peer.workloads.keys().collect::<Vec<_>>(), ["default/web"]);
    }
}
