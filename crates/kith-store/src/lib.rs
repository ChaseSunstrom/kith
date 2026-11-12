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
            std::fs::write(&id_file, id.to_string()).map_err(|e| format!("writing {}: {e}", id_file.display()))?;
            id
        }
    };
    let log = Log::open(&dir.join("log.redb"))?;
    let machine = Machine::open(dir, changed)?;
    let state = machine.state.clone();
    let config = openraft::Config {
        cluster_name: "kith".into(),
        // Slow enough for a node behind a home uplink, fast enough that a dead leader is
        // replaced within a few seconds.
        heartbeat_interval: 250,
        election_timeout_min: 1000,
        election_timeout_max: 2000,
        // Status updates are log entries too: keep the log short.
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(1000),
        max_in_snapshot_log_to_keep: 100,
        ..Default::default()
    };
    let config = Arc::new(config.validate().map_err(|e| format!("raft settings: {e}"))?);
    let raft = Raft::new(id, config, network, log, machine).await;
    let raft = raft.map_err(|e| format!("starting the store in {}: {e}", dir.display()))?;
    Ok(Replica { raft, state, id })
}
