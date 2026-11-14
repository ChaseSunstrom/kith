//! The Raft log, the vote and the committed index, in one redb file.

use crate::TypeConfig;
use openraft::storage::{LogFlushed, LogState, RaftLogStorage};
use openraft::{AnyError, Entry, LogId, OptionalSend, RaftLogReader, StorageError, StorageIOError, Vote};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use std::ops::RangeBounds;
use std::path::Path;
use std::sync::Arc;

/// Entries by index, as JSON.
const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("log");
/// `vote`, `committed` and `purged`, as JSON.
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

type Failed = StorageError<u64>;

fn reading(e: impl std::fmt::Display) -> Failed {
    StorageIOError::read_logs(AnyError::error(e)).into()
}

fn writing(e: impl std::fmt::Display) -> Failed {
    StorageIOError::write_logs(AnyError::error(e)).into()
}

#[derive(Clone)]
pub struct Log {
    db: Arc<Database>,
}

impl Log {
    pub fn open(path: &Path) -> Result<Log, String> {
        let failed = |e: &dyn std::fmt::Display| format!("opening {}: {e}", path.display());
        let db = Database::create(path).map_err(|e| match e {
            redb::DatabaseError::DatabaseAlreadyOpen => format!("{} is in use by another kithd", path.display()),
            e => failed(&e),
        })?;
        fn text(e: impl std::fmt::Display) -> String {
            e.to_string()
        }
        // Reading a table that was never written is an error: make both now, and say
        // which format this is. A file with no number is from before they were numbered.
        let stamped = (|| {
            let txn = db.begin_write().map_err(text)?;
            {
                let mut meta = txn.open_table(META).map_err(text)?;
                let old = meta.get("format").map_err(text)?;
                let old = old.map(|value| serde_json::from_slice::<u32>(value.value()));
                let format = old.transpose().map_err(text)?.unwrap_or(1);
                if format > crate::FORMAT {
                    // Nothing is committed: a newer file is left as it was.
                    return Ok(format);
                }
                // (An older format is brought up to this one here, when there is one.)
                let now = crate::FORMAT.to_string();
                meta.insert("format", now.as_bytes()).map_err(text)?;
            }
            txn.open_table(LOG).map_err(text)?;
            txn.commit().map_err(text)?;
            Ok(crate::FORMAT)
        })();
        crate::known(stamped.map_err(|e: String| failed(&e))?, path)?;
        Ok(Log { db: Arc::new(db) })
    }

    fn meta<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, Failed> {
        let txn = self.db.begin_read().map_err(reading)?;
        let table = txn.open_table(META).map_err(reading)?;
        let Some(value) = table.get(key).map_err(reading)? else {
            return Ok(None);
        };
        serde_json::from_slice(value.value()).map(Some).map_err(reading)
    }

    /// One durable transaction.
    fn write(&self, change: impl FnOnce(&redb::WriteTransaction) -> Result<(), Failed>) -> Result<(), Failed> {
        let txn = self.db.begin_write().map_err(writing)?;
        change(&txn)?;
        txn.commit().map_err(writing)
    }

    /// Write `entries`, durably.
    pub(crate) fn put(&self, entries: impl IntoIterator<Item = Entry<TypeConfig>>) -> Result<(), Failed> {
        self.write(|txn| {
            let mut table = txn.open_table(LOG).map_err(writing)?;
            for entry in entries {
                let value = serde_json::to_vec(&entry).map_err(writing)?;
                table.insert(entry.log_id.index, value.as_slice()).map_err(writing)?;
            }
            Ok(())
        })
    }

    fn set_meta(&self, key: &str, value: &impl Serialize) -> Result<(), Failed> {
        let value = serde_json::to_vec(value).map_err(writing)?;
        self.write(|txn| {
            let mut table = txn.open_table(META).map_err(writing)?;
            table.insert(key, value.as_slice()).map_err(writing)?;
            Ok(())
        })
    }
}

impl RaftLogReader<TypeConfig> for Log {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, Failed> {
        let txn = self.db.begin_read().map_err(reading)?;
        let table = txn.open_table(LOG).map_err(reading)?;
        let mut entries = Vec::new();
        for item in table.range(range).map_err(reading)? {
            let (_, value) = item.map_err(reading)?;
            entries.push(serde_json::from_slice(value.value()).map_err(reading)?);
        }
        Ok(entries)
    }
}

impl RaftLogStorage<TypeConfig> for Log {
    type LogReader = Log;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, Failed> {
        let last_purged_log_id: Option<LogId<u64>> = self.meta("purged")?;
        let txn = self.db.begin_read().map_err(reading)?;
        let table = txn.open_table(LOG).map_err(reading)?;
        let last = match table.last().map_err(reading)? {
            Some((_, value)) => {
                let entry: Entry<TypeConfig> = serde_json::from_slice(value.value()).map_err(reading)?;
                Some(entry.log_id)
            }
            None => last_purged_log_id,
        };
        Ok(LogState {
            last_purged_log_id,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Log {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), Failed> {
        self.set_meta("vote", vote)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, Failed> {
        self.meta("vote")
    }

    async fn save_committed(&mut self, committed: Option<LogId<u64>>) -> Result<(), Failed> {
        self.set_meta("committed", &committed)
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<u64>>, Failed> {
        Ok(self.meta::<Option<LogId<u64>>>("committed")?.flatten())
    }

    async fn append<I>(&mut self, entries: I, callback: LogFlushed<TypeConfig>) -> Result<(), Failed>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        self.put(entries)?;
        // The commit in there is the flush.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), Failed> {
        self.write(|txn| {
            let mut table = txn.open_table(LOG).map_err(writing)?;
            table.retain_in(log_id.index.., |_, _| false).map_err(writing)
        })
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), Failed> {
        let purged = serde_json::to_vec(&log_id).map_err(writing)?;
        self.write(|txn| {
            // In one transaction: a crash never leaves entries gone that `purged` does not cover.
            let mut meta = txn.open_table(META).map_err(writing)?;
            meta.insert("purged", purged.as_slice()).map_err(writing)?;
            let mut table = txn.open_table(LOG).map_err(writing)?;
            table.retain_in(..=log_id.index, |_, _| false).map_err(writing)
        })
    }
}
