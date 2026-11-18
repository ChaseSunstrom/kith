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
    /// (Not in a snapshot: a node that starts, or is sent one, knows of no change before it.)
    #[serde(skip)]
    touched: Touched,
}

/// How many changed keys are kept: a reader further behind than that reads everything.
/// (Entries are counted, not distinct keys: one command that changes more than this many
/// makes every reader read everything once.)
const TOUCHED: usize = 4096;

/// The keys the last commands changed, oldest first, each with the index of the log it
/// was changed at: what a reader that follows the store reads, instead of all of it.
#[derive(Debug, Default, Clone)]
struct Touched {
    /// Nothing is known of what changed at this index or before.
    floor: u64,
    keys: std::collections::VecDeque<(u64, String)>,
}

impl State {
    /// How far into the log this state is.
    pub fn index(&self) -> u64 {
        self.applied.map_or(0, |id| id.index)
    }

    /// The keys changed after the index `after`: what a reader that saw this state at `after`
    /// has to read again. `None` when that is further back than is kept, or the store was
    /// replaced since: it reads everything.
    pub fn touched(&self, after: u64) -> Option<std::collections::BTreeSet<&str>> {
        let since = self.touched.keys.iter().filter(|(at, _)| *at > after);
        (after >= self.touched.floor).then(|| since.map(|(_, key)| key.as_str()).collect())
    }

    /// Keep the keys the command at `index` changes; `None`: it replaced the store.
    fn note(&mut self, index: u64, keys: Option<Vec<String>>) {
        let Some(keys) = keys else { return self.forget() };
        self.touched.keys.extend(keys.into_iter().map(|key| (index, key)));
        while self.touched.keys.len() > TOUCHED {
            let gone = self.touched.keys.pop_front().expect("it is longer than that");
            self.touched.floor = gone.0;
        }
    }

    /// Nothing is known of what changed up to here.
    fn forget(&mut self) {
        self.touched = Touched {
            floor: self.index(),
            keys: Default::default(),
        };
    }
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
    /// What each entry is asked once the store is in format 3 ([`crate::Check`]).
    check: crate::Check,
    /// The index of the last write applied here whose log entry holds a wrapped key the
    /// store no longer has, and that key's NodeKey (see [`crate::scrub`]).
    pub(crate) forgot: Arc<tokio::sync::watch::Sender<(u64, String)>>,
}

impl Machine {
    /// Start from the snapshot in `dir`, or empty. One from before a NodeKey kept one
    /// revision is cut, and written so at once.
    pub fn open(dir: &Path, changed: Arc<dyn Fn() + Send + Sync>, check: crate::Check) -> Result<Machine, String> {
        let file = dir.join("snapshot.json");
        let mut saved = match std::fs::read(&file) {
            Ok(bytes) => Some(read(&bytes, &file)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("reading {}: {e}", file.display())),
        };
        let cut = saved
            .as_mut()
            .is_some_and(|saved| saved.state.store.cut_node_key_histories());
        let mut state = saved.as_ref().map_or_else(State::default, |saved| saved.state.clone());
        state.forget();
        let machine = Machine {
            saved: Arc::new(Mutex::new(state.applied)),
            state: Arc::new(Mutex::new(state)),
            file,
            changed,
            check,
            forgot: Arc::new(tokio::sync::watch::Sender::new((0, String::new()))),
        };
        if let Some(mut saved) = saved.filter(|_| cut) {
            saved.format = crate::format_of(&saved.state.store);
            machine.save(&saved).map_err(|e| e.to_string())?;
        }
        Ok(machine)
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
            format: crate::format_of(&state.store),
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
        let mut forgot = None;
        {
            let mut state = self.state();
            for entry in entries {
                state.applied = Some(entry.log_id);
                replies.push(match entry.payload {
                    EntryPayload::Blank => Ok(crate::Done::Nothing),
                    EntryPayload::Normal(command) => {
                        let mut keys = crate::keys(&command);
                        let mut carried = crate::carried(&command);
                        // (A store brought in replaces this one: the keys this one holds are
                        // in the log's earlier entries, and count like the ones it carries.)
                        if matches!(crate::inner(&command), crate::Command::Import { .. }) {
                            carried.extend(crate::held(&state.store));
                        }
                        // (Before format 3 nothing is asked: an old log applies as it did.)
                        let leader = entry.log_id.leader_id.node_id;
                        let checked = match crate::format_of(&state.store) >= 3 {
                            true => (self.check)(&state.store, &command, leader),
                            false => Ok(()),
                        };
                        let reply = match checked {
                            Ok(()) => {
                                let signed = matches!(command, crate::Command::Signed { .. });
                                state.store.entry(entry.log_id.index);
                                let reply = run(&mut state.store, command);
                                state.store.entry(0);
                                // (A signed entry refused, whatever it wraps, changed no key:
                                // refused before it ran, or by what it ran, which changes
                                // nothing when it fails. Its readers read nothing again.)
                                if signed && reply.is_err() {
                                    keys = Some(Vec::new());
                                }
                                reply
                            }
                            // Refused: nothing on every node, and nothing changed.
                            Err(refused) => {
                                keys = Some(Vec::new());
                                Err(refused)
                            }
                        };
                        let keys = keys.map(|named| named.into_iter().chain(crate::changed(&reply)).collect());
                        state.note(entry.log_id.index, keys);
                        // (The entry is in the log as it was sent: refused, or a revision of
                        // what it brought in cut, its wrapped key is there still.)
                        let dropped = crate::drops_a_key(&reply);
                        if let Some(key) = dropped.or_else(|| crate::left(&state.store, &carried)) {
                            forgot = Some((entry.log_id.index, key));
                        }
                        reply
                    }
                    EntryPayload::Membership(membership) => {
                        state.membership = StoredMembership::new(Some(entry.log_id), membership);
                        Ok(crate::Done::Nothing)
                    }
                });
            }
            (self.changed)();
        }
        if let Some(forgot) = forgot {
            self.forgot.send_replace(forgot);
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
        // (From a node on a build from before a NodeKey kept one revision.)
        state.store.cut_node_key_histories();
        // The description is what Raft agreed on; the state has to say the same.
        state.applied = meta.last_log_id;
        state.membership = meta.last_membership.clone();
        let saved = Saved {
            format: crate::format_of(&state.store),
            meta: meta.clone(),
            state,
        };
        self.save(&saved)?;
        let mut state = self.state();
        let mut next = saved.state;
        next.store.continue_changes(&state.store);
        *state = next;
        state.forget();
        (self.changed)();
        Ok(())
    }

    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<TypeConfig>>, Failed> {
        self.load()?.map(snapshot).transpose()
    }
}
