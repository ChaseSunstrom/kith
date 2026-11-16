//! The replicated resource store (PLAN.md §4.3): every kithd keeps its own copy of
//! the resources, and Raft (`openraft`) keeps the copies the same.
//!
//! A change is a [`Command`]. The leader puts it in the log, a majority of voters
//! write it to disk (`redb`), and then every node runs it against its own
//! [`kith_api::store::Store`]. The store itself lives in memory: a node that restarts
//! loads the last snapshot file and replays the log after it.
//
// ponytail: redb commits (an fsync each) run on the caller's thread, so a slow disk
// stalls a single-threaded kithd for that long. Move the log to its own thread if
// ci/bench.py's API stall number says so.

// openraft's storage error is what its traits return; boxing it here would only move it.
#![allow(clippy::result_large_err)]

mod log;
mod machine;
#[cfg(test)]
mod tests;

pub use log::Log;
pub use machine::{Machine, State};
pub use openraft;

use kith_api::Resource;
use kith_api::store::{Change, Error, Store};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// The format of the two files a replica is on disk, the log and the snapshot. It goes up
/// when a build writes what an earlier build would misread; a file with no number is 1.
/// `fixtures/format-N` is a state as format N's builds wrote it, and stays readable.
pub const FORMAT: u32 = 1;

/// A file in a format this build does not know is refused, never read as if it were its own.
fn known(format: u32, file: &Path) -> Result<(), String> {
    if format > FORMAT {
        let file = file.display();
        return Err(format!(
            "{file} is in format {format} and this kithd reads up to format {FORMAT}: start the kithd that wrote it, or a newer one"
        ));
    }
    Ok(())
}

/// One change to the store. Everything a replica needs to repeat it exactly is in here,
/// the time included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    /// All or nothing.
    Apply {
        resources: Vec<Resource>,
        at: u64,
    },
    Delete {
        key: String,
    },
    Rollback {
        key: String,
        to: u64,
        at: u64,
    },
    /// What controllers report. A key that is gone is skipped.
    Status {
        statuses: Vec<(String, Option<serde_json::Value>)>,
    },
    /// Set some fields of a status and leave the others: two writers of one status (a
    /// node's address, its state) do not undo each other. A key that is gone is skipped.
    Patch {
        statuses: Vec<(String, serde_json::Map<String, serde_json::Value>)>,
    },
    /// What `node` says of the resources it runs units of (see [`reported`]); `None`
    /// when it runs none of one any more. A key that is gone is skipped.
    Report {
        node: String,
        statuses: Vec<(String, Option<serde_json::Value>)>,
    },
    /// Replace everything: how a store from before replication comes in.
    Import {
        store: Store,
    },
}

/// What a command that worked gives back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Done {
    Changes(Vec<Change>),
    Deleted(Box<Resource>),
    Nothing,
}

pub type Reply = Result<Done, Error>;

openraft::declare_raft_types!(
    pub TypeConfig:
        D = Command,
        R = Reply,
);

pub type Raft = openraft::Raft<TypeConfig>;
pub type NodeId = u64;

/// Run `command` against `store`. Deterministic: the same store and command give the
/// same store and reply on every node.
pub fn run(store: &mut Store, command: Command) -> Reply {
    match command {
        Command::Apply { resources, at } => {
            store.at(Some(at));
            let changes = store.apply_all(resources);
            store.at(None);
            changes.map(Done::Changes)
        }
        Command::Delete { key } => store.delete(&key).map(|gone| Done::Deleted(Box::new(gone))),
        Command::Rollback { key, to, at } => {
            store.at(Some(at));
            let change = store.rollback(&key, to);
            store.at(None);
            change.map(|change| Done::Changes(vec![change]))
        }
        Command::Status { statuses } => {
            for (key, status) in statuses {
                let _ = store.set_status(&key, status);
            }
            Ok(Done::Nothing)
        }
        Command::Patch { statuses } => {
            for (key, fields) in statuses {
                let mut status = match store.get(&key).and_then(|r| r.status.clone()) {
                    Some(serde_json::Value::Object(status)) => status,
                    _ => serde_json::Map::new(),
                };
                status.extend(fields);
                let _ = store.set_status(&key, Some(status.into()));
            }
            Ok(Done::Nothing)
        }
        Command::Report { node, statuses } => {
            for (key, said) in statuses {
                let old = store.get(&key).and_then(|r| r.status.clone());
                let _ = store.set_status(&key, Some(reported(old, &node, said)));
            }
            Ok(Done::Nothing)
        }
        Command::Import { store: imported } => {
            *store = imported;
            Ok(Done::Nothing)
        }
    }
}

/// The keys `command` changes that it names itself (those of a status), or `None` for the
/// one that replaces the store. What an apply, a delete or a rollback changed is read from
/// its answer ([`changed`]): a resource that names no namespace is kept under the default one.
pub fn keys(command: &Command) -> Option<Vec<String>> {
    let named = |statuses: &mut dyn Iterator<Item = &String>| statuses.cloned().collect();
    Some(match command {
        Command::Import { .. } => return None,
        Command::Status { statuses } | Command::Report { statuses, .. } => {
            named(&mut statuses.iter().map(|(key, _)| key))
        }
        Command::Patch { statuses } => named(&mut statuses.iter().map(|(key, _)| key)),
        Command::Apply { .. } | Command::Delete { .. } | Command::Rollback { .. } => Vec::new(),
    })
}

/// The keys an answer says were changed (none where the command was refused).
pub fn changed(reply: &Reply) -> Vec<String> {
    match reply {
        Ok(Done::Changes(changes)) => changes.iter().map(|change| change.after.key()).collect(),
        Ok(Done::Deleted(gone)) => vec![gone.key()],
        Ok(Done::Nothing) | Err(_) => Vec::new(),
    }
}

/// Whether an answer says a NodeKey's wrapped key went out of the store (wiped, forgotten,
/// replaced or deleted): the store keeps no earlier revision of one, and the node that
/// applied it then snapshots and drops its log up to there ([`scrub`]).
fn drops_a_key(reply: &Reply) -> bool {
    fn wrapped(key: &Resource) -> Option<&str> {
        let wrapped = key.spec["wrapped"].as_str().filter(|wrapped| !wrapped.is_empty());
        wrapped.filter(|_| key.kind == "NodeKey")
    }
    match reply {
        Ok(Done::Changes(changes)) => changes.iter().any(|change| {
            let before = change.before.as_ref().and_then(wrapped);
            before.is_some() && before != wrapped(&change.after)
        }),
        Ok(Done::Deleted(gone)) => wrapped(gone).is_some(),
        Ok(Done::Nothing) | Err(_) => false,
    }
}

/// Snapshot the store at the log's `index` or later, then drop the log up to there: a key
/// the write at `index` took out of the store is then in no file Raft keeps on this node.
/// openraft drops a follower's log at once and a leader's once no replication still reads
/// it: it is asked again while it has not. A node that stops first does it at its next
/// start, as it applies that write again.
async fn scrub(raft: &Raft, index: u64) {
    let wait = || raft.wait(Some(std::time::Duration::from_secs(10)));
    for _ in 0..10 {
        // (An error: Raft has stopped.)
        if raft.trigger().snapshot().await.is_err() {
            return;
        }
        let built =
            |m: &openraft::RaftMetrics<NodeId, openraft::BasicNode>| m.snapshot.is_some_and(|s| s.index >= index);
        if wait().metrics(built, "a snapshot").await.is_err() {
            continue;
        }
        if raft.trigger().purge_log(index).await.is_err() {
            return;
        }
        let purged =
            |m: &openraft::RaftMetrics<NodeId, openraft::BasicNode>| m.purged.is_some_and(|p| p.index >= index);
        if wait().metrics(purged, "the log dropped").await.is_ok() {
            return;
        }
    }
    eprintln!("kith-store: the log up to {index}, which holds a key the cluster forgot, could not be dropped");
}

/// The status of a resource after `node` said `said` of it. Several nodes run replicas of
/// one Workload: each node's `containers` are kept apart by their `node` and replaced only
/// by that node, `ready` is counted over all of them, and what the scheduler wrote (`nodes`,
/// `unschedulable`) stays. Every other field is as the node says, so it must be one that
/// every node says the same (it follows from the spec) or the resource must be run by one
/// node (a Job: its status has a `state`). `None` takes the node's containers out.
pub fn reported(old: Option<serde_json::Value>, node: &str, said: Option<serde_json::Value>) -> serde_json::Value {
    use serde_json::{Map, Value};
    let object = |value: Option<Value>| match value {
        Some(Value::Object(object)) => Some(object),
        _ => None,
    };
    let (old, said) = (object(old).unwrap_or_default(), object(said));
    let units = |status: &Map<String, Value>| {
        let units = status.get("containers").and_then(Value::as_array).cloned();
        units
            .unwrap_or_default()
            .into_iter()
            .filter_map(|unit| object(Some(unit)))
    };
    let mut containers: Vec<_> = units(&old)
        // (One with no node is from before nodes were named: whoever reports now runs it.)
        .filter(|unit| unit.get("node").is_some_and(|other| other != node))
        .collect();
    for mut unit in said.iter().flat_map(units) {
        unit.insert("node".into(), node.into());
        containers.push(unit);
    }
    let place = |unit: &Map<String, Value>| {
        let text = |field: &str| unit.get(field).map(Value::to_string);
        (unit.get("replica").and_then(Value::as_u64), text("node"))
    };
    // Stable: the units of one replica stay in the order its node gave them.
    containers.sort_by_key(place);
    let mut status = said.unwrap_or_else(|| old.clone());
    for kept in ["nodes", "unschedulable"] {
        match old.get(kept) {
            Some(value) => status.insert(kept.into(), value.clone()),
            None => status.remove(kept),
        };
    }
    if !status.contains_key("state") {
        let mut ready = std::collections::BTreeMap::new();
        // A replica two nodes say they run (it is moving) is ready when both say so.
        for unit in &containers {
            *ready.entry(place(unit).0).or_insert(true) &= unit.get("ready") == Some(&true.into());
        }
        status.insert("ready".into(), ready.values().filter(|ready| **ready).count().into());
    }
    status.insert("containers".into(), containers.into());
    status.into()
}

/// A node's id in Raft, from its name (FNV-1a): every node works it out the same way.
pub fn node_id(name: &str) -> NodeId {
    let mix = |hash: u64, byte: &u8| (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    name.as_bytes().iter().fold(0xcbf2_9ce4_8422_2325, mix)
}

/// A node's copy of the store.
pub struct Replica {
    pub raft: Raft,
    /// What has been applied here so far: read from it, change it only through `raft`.
    pub state: Arc<Mutex<State>>,
    /// This node in Raft: the `id` it was first opened with.
    pub id: NodeId,
}

/// Raft's settings. Every field is said here: openraft's `Default` reads its own with a
/// command line parser, which a node would then run, deep on its stack, each time it starts
/// (the test `settings_are_openrafts_but_for_ours` holds the rest to openraft's).
#[allow(deprecated)] // (`send_snapshot_timeout`: a field still, and so said.)
fn settings() -> openraft::Config {
    openraft::Config {
        cluster_name: "kith".into(),
        // Slow enough for a node behind a home uplink, fast enough that a dead leader is
        // replaced within a few seconds.
        heartbeat_interval: 250,
        election_timeout_min: 1000,
        election_timeout_max: 2000,
        // Status updates are log entries too: keep the log short.
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(1000),
        max_in_snapshot_log_to_keep: 100,
        install_snapshot_timeout: 200,
        send_snapshot_timeout: 0,
        max_payload_entries: 300,
        replication_lag_threshold: 5000,
        snapshot_max_chunk_size: 3 * 1024 * 1024,
        purge_batch_size: 1,
        enable_tick: true,
        enable_heartbeat: true,
        enable_elect: true,
    }
}

/// Open (or create) the replica kept in `dir` and start Raft on it. A new directory
/// becomes node `id`; an old one stays the node it was. `changed` is called with every
/// change to the state, while the state is locked.
pub async fn open<N>(
    dir: &Path,
    id: NodeId,
    network: N,
    changed: Arc<dyn Fn() + Send + Sync>,
) -> Result<Replica, String>
where
    N: openraft::RaftNetworkFactory<TypeConfig>,
{
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let id_file = dir.join("id");
    let id = match std::fs::read_to_string(&id_file) {
        Ok(text) => text.trim().parse().map_err(|e| format!("{}: {e}", id_file.display()))?,
        Err(_) => {
            // Whole or not at all: a node that lost power with an empty id file would never start again.
            let new = dir.join("id.new");
            let written = (|| {
                use std::io::Write;
                let mut file = std::fs::File::create(&new)?;
                file.write_all(id.to_string().as_bytes())?;
                file.sync_all()?;
                std::fs::rename(&new, &id_file)?;
                std::fs::File::open(dir)?.sync_all()
            })();
            written.map_err(|e: std::io::Error| format!("writing {}: {e}", id_file.display()))?;
            id
        }
    };
    let log = Log::open(&dir.join("log.redb"))?;
    let machine = Machine::open(dir, changed)?;
    let mut forgotten = machine.forgot.subscribe();
    let state = machine.state.clone();
    let config = Arc::new(settings().validate().map_err(|e| format!("raft settings: {e}"))?);
    let raft = Raft::new(id, config, network, log, machine).await;
    let raft = raft.map_err(|e| format!("starting the store in {}: {e}", dir.display()))?;
    let scrubbing = raft.clone();
    // (Ends when Raft drops the machine, which holds the sender.)
    tokio::spawn(async move {
        while forgotten.changed().await.is_ok() {
            let index = *forgotten.borrow_and_update();
            scrub(&scrubbing, index).await;
        }
    });
    Ok(Replica { raft, state, id })
}
