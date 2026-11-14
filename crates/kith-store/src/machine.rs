//! The state machine: the resource store in memory, and its snapshot file.

use crate::{Reply, TypeConfig, run};
use kith_api::store::Store;
use openraft::storage::RaftStateMachine;
use openraft::{
    AnyError, BasicNode, Entry, EntryPayload, LogId, OptionalSend, RaftSnapshotBuilder, Snapshot, SnapshotMeta,
    StorageError, StorageIOError, StoredMembership,
};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

type Failed = StorageError<u64>;

/// What a node knows: the resources, and how far into the log that is.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct State {
    pub store: Store,
    applied: Option<LogId<u64>>,
    membership: StoredMembership<u64, BasicNode>,
}

/// The snapshot file: a state and the description Raft keeps of it.
#[derive(Serialize, Deserialize)]
struct Saved {
    /// [`crate::FORMAT`] when it was written.
    #[serde(default = "first")]
    format: u32,
    meta: SnapshotMeta<u64, BasicNode>,
    state: State,
}

fn first() -> u32 {
    1
}

/// The snapshot in `bytes`, if this build knows its format. The number is read on its own
/// first: the rest of a newer file may not read at all, or worse, may.
fn read(bytes: &[u8], file: &Path) -> Result<Saved, String> {
    #[derive(Deserialize)]
    struct Stamp {
        #[serde(default = "first")]
        format: u32,
    }
    let reading = |e: serde_json::Error| format!("reading {}: {e}", file.display());
    let stamp: Stamp = serde_json::from_slice(bytes).map_err(reading)?;
    crate::known(stamp.format, file)?;
    serde_json::from_slice(bytes).map_err(reading)
}

#[derive(Clone)]
pub struct Machine {
    pub state: Arc<Mutex<State>>,
    file: PathBuf,
    /// How far the snapshot file goes. Held while it is written: Raft may build one
    /// snapshot while it installs another, and the older must not replace the newer.
    saved: Arc<Mutex<Option<LogId<u64>>>>,
    changed: Arc<dyn Fn() + Send + Sync>,
}

impl Machine {
    /// Start from the snapshot in `dir`, or empty.
    pub fn open(dir: &Path, changed: Arc<dyn Fn() + Send + Sync>) -> Result<Machine, String> {
        let file = dir.join("snapshot.json");
        let state = match std::fs::read(&file) {
            Ok(bytes) => read(&bytes, &file)?.state,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(format!("reading {}: {e}", file.display())),
        };
        Ok(Machine {
            saved: Arc::new(Mutex::new(state.applied)),
            state: Arc::new(Mutex::new(state)),
            file,
            changed,
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("nothing panics holding the state")
    }

    /// Replace the snapshot file, whole or not at all.
    fn save(&self, saved: &Saved) -> Result<(), Failed> {
        let failed = |e: &dyn std::fmt::Display| -> Failed {
            StorageIOError::write_snapshot(Some(saved.meta.signature()), AnyError::error(e)).into()
        };
        let bytes = serde_json::to_vec(saved).map_err(|e| failed(&e))?;
        let mut on_disk = self.saved.lock().expect("nothing panics holding the snapshot");
        if saved.meta.last_log_id < *on_disk {
            return Ok(());
        }
        let partial = self.file.with_extension("json.partial");
        let written = (|| {
            use std::io::Write;
            let mut file = std::fs::File::create(&partial)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&partial, &self.file)?;
            // The rename too has to be on disk before Raft drops the log entries the snapshot covers.
            std::fs::File::open(self.file.parent().unwrap_or(Path::new(".")))?.sync_all()
        })();
        written.map_err(|e| failed(&e))?;
        *on_disk = saved.meta.last_log_id;
        Ok(())
    }

    fn load(&self) -> Result<Option<Saved>, Failed> {
        let failed =
            |e: &dyn std::fmt::Display| -> Failed { StorageIOError::read_snapshot(None, AnyError::error(e)).into() };
        match std::fs::read(&self.file) {
            Ok(bytes) => read(&bytes, &self.file).map(Some).map_err(|e| failed(&e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(failed(&e)),
        }
    }
}

fn snapshot(saved: Saved) -> Result<Snapshot<TypeConfig>, Failed> {
    let failed = |e: serde_json::Error| -> Failed { StorageIOError::read_state_machine(AnyError::error(e)).into() };
    let bytes = serde_json::to_vec(&saved.state).map_err(failed)?;
    Ok(Snapshot {
        meta: saved.meta,
        snapshot: Box::new(Cursor::new(bytes)),
    })
}

impl RaftSnapshotBuilder<TypeConfig> for Machine {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, Failed> {
        let state = self.state().clone();
        let id = state
            .applied
            .map_or("empty".to_string(), |id| format!("{}-{}", id.leader_id, id.index));
        let meta = SnapshotMeta {
            last_log_id: state.applied,
            last_membership: state.membership.clone(),
            snapshot_id: id,
        };
        let saved = Saved {
            format: crate::FORMAT,
            meta,
            state,
        };
        self.save(&saved)?;
        snapshot(saved)
    }
}

impl RaftStateMachine<TypeConfig> for Machine {
    type SnapshotBuilder = Machine;

    async fn applied_state(&mut self) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), Failed> {
        let state = self.state();
        Ok((state.applied, state.membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<Reply>, Failed>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut replies = Vec::new();
        {
            let mut state = self.state();
            for entry in entries {
                state.applied = Some(entry.log_id);
                replies.push(match entry.payload {
                    EntryPayload::Blank => Ok(crate::Done::Nothing),
                    EntryPayload::Normal(command) => run(&mut state.store, command),
                    EntryPayload::Membership(membership) => {
                        state.membership = StoredMembership::new(Some(entry.log_id), membership);
                        Ok(crate::Done::Nothing)
                    }
                });
            }
            (self.changed)();
        }
        Ok(replies)
    }

    async fn get_snapshot_builder(&mut self) -> Machine {
        self.clone()
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<Box<Cursor<Vec<u8>>>, Failed> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), Failed> {
        let failed = |e: serde_json::Error| -> Failed {
            StorageIOError::read_snapshot(Some(meta.signature()), AnyError::error(e)).into()
        };
        let mut state: State = serde_json::from_slice(snapshot.get_ref()).map_err(failed)?;
        // The description is what Raft agreed on; the state has to say the same.
        state.applied = meta.last_log_id;
        state.membership = meta.last_membership.clone();
        let saved = Saved {
            format: crate::FORMAT,
            meta: meta.clone(),
            state,
        };
        self.save(&saved)?;
        let mut state = self.state();
        *state = saved.state;
        (self.changed)();
        Ok(())
    }

    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<TypeConfig>>, Failed> {
        self.load()?.map(snapshot).transpose()
    }
}
