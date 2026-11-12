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
        Command::Import { store: imported } => {
            *store = imported;
            Ok(Done::Nothing)
        }
    }
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
