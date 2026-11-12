//! The resource store: apply, diff and per-resource revision history.
//!
//! Phase 0 keeps everything in memory and, for the CLI, in one JSON file.
// ponytail: whole-file JSON under a file lock; kith-store (openraft + redb, §4.3) replaces it in Phase 2.
// Not here yet: field ownership (server-side apply) and watch streams, both Phase 1.

use crate::Resource;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Revisions kept per resource; older ones are dropped.
pub const HISTORY_LIMIT: usize = 100;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Error {
    Invalid(String),
    NotFound(String),
    /// The resource changed since the revision the caller based its edit on.
    Conflict(String),
    Io(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Invalid(msg) | Error::Io(msg) | Error::Conflict(msg) => f.write_str(msg),
            Error::NotFound(what) => write!(f, "{what} not found"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Revision {
    /// Seconds since the Unix epoch.
    pub at: u64,
    pub resource: Resource,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    Created,
    Updated,
    Unchanged,
}

/// What applying a resource does, or would do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub action: Action,
    pub before: Option<Resource>,
    pub after: Resource,
}

impl Change {
    /// Unified diff of live against desired; empty when nothing changes.
    pub fn diff(&self) -> String {
        if self.action == Action::Unchanged {
            return String::new();
        }
        // The revision always moves, so it would only be noise in the diff.
        let yaml = |r: &Resource| {
            let mut r = r.clone();
            r.metadata.revision = None;
            r.to_yaml()
        };
        let key = self.after.key();
        let old = self.before.as_ref().map(yaml).unwrap_or_default();
        let new = yaml(&self.after);
        let (from, to) = match self.action {
            Action::Created => ("/dev/null".to_string(), format!("{key} (new)")),
            _ => (format!("{key} (live)"), format!("{key} (desired)")),
        };
        similar::TextDiff::from_lines(&old, &new)
            .unified_diff()
            .context_radius(3)
            .header(&from, &to)
            .to_string()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Store {
    /// Revisions per resource key, oldest first. The last one is live.
    resources: BTreeMap<String, Vec<Revision>>,
    /// When the next changes happen, if not now: replicas replaying a change must agree on it.
    #[serde(skip)]
    clock: Option<u64>,
}

impl Store {
    /// Validate `desired` and work out what applying it would change.
    /// `apply` owns labels, annotations and spec; status stays with the controllers,
    /// so a `status` in `desired` is ignored.
    pub fn plan(&self, desired: Resource) -> Result<Change, Error> {
        let mut after = desired.validated().map_err(Error::Invalid)?;
        let before = self.get(&after.key()).cloned();
        let live_revision = before.as_ref().and_then(|b| b.metadata.revision).unwrap_or(0);
        if let Some(based_on) = after.metadata.revision.filter(|r| *r != live_revision) {
            let key = after.key();
            return Err(Error::Conflict(format!(
                "{key} is at revision {live_revision}, but this edit is based on revision {based_on}; fetch it again or drop metadata.revision"
            )));
        }
        after.status = before.as_ref().and_then(|b| b.status.clone());
        after.metadata.revision = Some(live_revision);
        let action = match &before {
            None => Action::Created,
            Some(live) if *live == after => Action::Unchanged,
            Some(_) => Action::Updated,
        };
        if action != Action::Unchanged {
            after.metadata.revision = Some(live_revision + 1);
        }
        Ok(Change { action, before, after })
    }

    /// Stamp the changes that follow with `at` (seconds since the epoch) instead of the clock.
    pub fn at(&mut self, at: Option<u64>) {
        self.clock = at;
    }

    pub fn apply(&mut self, desired: Resource) -> Result<Change, Error> {
        let change = self.plan(desired)?;
        if change.action != Action::Unchanged {
            let history = self.resources.entry(change.after.key()).or_default();
            history.push(Revision {
                at: self.clock.unwrap_or_else(now),
                resource: change.after.clone(),
            });
            if history.len() > HISTORY_LIMIT {
                history.remove(0);
            }
        }
        Ok(change)
    }

    /// Apply several resources, all or nothing: if one is refused the store is left as it was.
    pub fn apply_all(&mut self, desired: Vec<Resource>) -> Result<Vec<Change>, Error> {
        // ponytail: clones the whole store per call; fine until stores are large, then stage per key.
        let mut staged = self.clone();
        let changes = desired.into_iter().map(|r| staged.apply(r)).collect::<Result<_, _>>()?;
        *self = staged;
        Ok(changes)
    }

    pub fn get(&self, key: &str) -> Option<&Resource> {
        self.resources.get(key)?.last().map(|r| &r.resource)
    }

    /// Live resources, optionally of one kind, sorted by key.
    pub fn list<'a>(&'a self, kind: Option<&'a str>) -> impl Iterator<Item = &'a Resource> {
        let live = self.resources.values().filter_map(|h| h.last()).map(|r| &r.resource);
        live.filter(move |r| kind.is_none_or(|k| r.kind == k))
    }

    /// Removes the resource together with its history.
    pub fn delete(&mut self, key: &str) -> Result<Resource, Error> {
        let mut history = self.resources.remove(key).ok_or_else(|| Error::NotFound(key.into()))?;
        // A hand-edited store can hold an empty history.
        history
            .pop()
            .map(|r| r.resource)
            .ok_or_else(|| Error::NotFound(key.into()))
    }

    pub fn history(&self, key: &str) -> Result<&[Revision], Error> {
        self.resources
            .get(key)
            .map(Vec::as_slice)
            .ok_or_else(|| Error::NotFound(key.into()))
    }

    /// Re-apply an earlier revision's content as a new revision.
    pub fn rollback(&mut self, key: &str, to: u64) -> Result<Change, Error> {
        let old = self
            .history(key)?
            .iter()
            .find(|r| r.resource.metadata.revision == Some(to));
        let old = old.ok_or_else(|| Error::NotFound(format!("{key} revision {to}")))?;
        let mut desired = old.resource.clone();
        desired.metadata.revision = None;
        self.apply(desired)
    }

    /// Controllers report here. Status is not versioned: no new revision.
    pub fn set_status(&mut self, key: &str, status: Option<serde_json::Value>) -> Result<(), Error> {
        let live = self
            .resources
            .get_mut(key)
            .and_then(|h| h.last_mut())
            .ok_or_else(|| Error::NotFound(key.into()))?;
        live.resource.status = status;
        Ok(())
    }
}

/// Seconds since the epoch.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A [`Store`] in a JSON file.
pub struct FileStore {
    pub store: Store,
    path: PathBuf,
    /// Held by writers, so two of them never interleave. Readers need no lock:
    /// `save` replaces the file atomically, so they always see a whole store.
    _lock: Option<File>,
}

/// `store.json` -> `store.json.lock`
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

impl FileStore {
    /// Read the store at `path`; a missing file is an empty store. Creates nothing.
    pub fn read(path: &Path) -> Result<FileStore, Error> {
        let store = match std::fs::read(path) {
            // A store we can't read is an error, never silently replaced by an empty one.
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| Error::Io(format!("{} is not a kith store: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Store::default(),
            Err(e) => return Err(Error::Io(format!("reading {}: {e}", path.display()))),
        };
        Ok(FileStore {
            store,
            path: path.into(),
            _lock: None,
        })
    }

    /// Open the store for changing it. Another process changing it is waited for,
    /// briefly: one that keeps it (kithd) is a conflict, not something to wait out.
    pub fn open(path: &Path) -> Result<FileStore, Error> {
        Self::open_within(path, std::time::Duration::from_secs(10))
    }

    /// Like [`FileStore::open`], for something that keeps the store open for good.
    /// The short wait covers a `kith --store` that is just finishing.
    pub fn open_owned(path: &Path) -> Result<FileStore, Error> {
        Self::open_within(path, std::time::Duration::from_secs(2))
    }

    fn open_within(path: &Path, patience: std::time::Duration) -> Result<FileStore, Error> {
        let io = |what: &str, e: std::io::Error| Error::Io(format!("{what} {}: {e}", path.display()));
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| io("creating the directory for", e))?;
        }
        let lock = File::create(sibling(path, ".lock")).map_err(|e| io("locking", e))?;
        let began = std::time::Instant::now();
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::Error(e)) => return Err(io("locking", e)),
                Err(std::fs::TryLockError::WouldBlock) if began.elapsed() < patience => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(Error::Conflict(format!(
                        "{} is in use by another kithd or kith",
                        path.display()
                    )));
                }
            }
        }
        Ok(FileStore {
            _lock: Some(lock),
            ..FileStore::read(path)?
        })
    }

    /// Write to a temporary file, sync it, then rename over the store, so a crash
    /// or a full disk leaves the old store or the new one, never part of one.
    pub fn save(&self) -> Result<(), Error> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let io = |e: std::io::Error| Error::Io(format!("writing {}: {e}", self.path.display()));
        let bytes = serde_json::to_vec(&self.store).map_err(|e| io(e.into()))?;
        let tmp = sibling(&self.path, ".tmp");
        let _ = std::fs::remove_file(&tmp);
        // Owner-only: the store holds Secrets in the clear until §4.3's encryption lands.
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io)?;
        file.write_all(&bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        std::fs::rename(&tmp, &self.path).map_err(io)
    }
}

/// `2026-11-12T09:30:00Z` from seconds since the epoch.
pub fn rfc3339(secs: u64) -> String {
    // Days-to-civil from Howard Hinnant's date algorithms.
    let (days, rem) = (secs / 86400, secs % 86400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (d, m) = (doy - (153 * mp + 2) / 5 + 1, if mp < 10 { mp + 3 } else { mp - 9 });
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}
