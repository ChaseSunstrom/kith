//! Copies of a volume on other nodes, one of which takes over when its node is lost.
//!
//! GET /v1/volume-copy/NS/NAME[?have=HASH]   the volume as a tar, or 304      nodes only
//!
//! A Volume with `replicas: N` is on N nodes: the one that has it now (`status.primary`,
//! its `spec.node` to begin with) and N-1 the leader picks (`status.replicas`). Every
//! `sync` (5m unless said) each replica asks the primary for an archive of the directory,
//! unpacks it beside its own copy and puts it in its place, and writes when in
//! `status.synced`. When the primary is not heard from for as long as a lost node's
//! workloads wait (`--lost-after`), the leader makes the replica that synced last the
//! primary: workloads that mount the volume are placed there, on the copy as it was then.
//!
//! What was written after the last sync is not on the replica: a failover loses it.
//
// ponytail: each sync reads the whole volume on the primary and sends all of it when
// anything changed. For data of modest size; send what changed (rsync's way, or a
// filesystem's snapshots) when volumes are large.

use crate::Shared;
use crate::blobs::Incoming;
use crate::volumes::Dir;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kith_api::store::Store;
use kith_store::Command;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// What a Volume's status says of its copies (kept when the rest of it is worked out again).
pub const FIELDS: [&str; 3] = ["primary", "replicas", "synced"];
/// How often a node looks at what it should bring up to date.
const ROUND: Duration = Duration::from_secs(5);
/// How often a copy is brought up to date, when the Volume does not say.
const SYNC: u64 = 300;
/// A primary that sends nothing for this long is given up on, for this time.
const QUIET: Duration = Duration::from_secs(30);

fn names(value: &Value) -> Vec<String> {
    let names = value.as_array().into_iter().flatten().filter_map(Value::as_str);
    names.map(String::from).collect()
}

/// The leader's part: for each replicated Volume whose `primary` or `replicas` should be
/// other than its status says, what they should be. `lost`: for how long a node has not been
/// heard from (none: it is there).
pub fn writes(
    store: &Store,
    lost: &dyn Fn(&str) -> Option<Duration>,
    grace: Duration,
) -> Vec<(String, Map<String, Value>)> {
    let nodes: Vec<String> = store
        .list(Some("Node"))
        .map(|node| node.metadata.name.clone())
        .collect();
    let there = |node: &str| nodes.iter().any(|name| name == node) && lost(node).is_none();
    let gone = |node: &str| !nodes.iter().any(|name| name == node) || lost(node).is_some_and(|lost| lost >= grace);
    let mut writes = Vec::new();
    for (key, dir, copies) in crate::volumes::replicated(store) {
        let status = store
            .get(&key)
            .and_then(|volume| volume.status.clone())
            .unwrap_or_default();
        let (mut primary, mut replicas) = (dir.node.clone(), names(&status["replicas"]));
        replicas.retain(|node| *node != primary);
        if gone(&primary) {
            // The copy brought up to date last, of those on nodes that are there.
            let synced = |node: &&String| status["synced"][node.as_str()].as_u64();
            let ready = replicas
                .iter()
                .filter(|node| there(node))
                .filter(|node| synced(node).is_some());
            if let Some(next) = ready.max_by_key(synced).cloned() {
                replicas.retain(|node| *node != next);
                primary = next;
            }
        }
        // A replica that is gone gives way to a node that is there, picked the same way
        // whoever leads; one that is only quiet for a moment stays.
        replicas.retain(|node| !gone(node));
        let free: Vec<&str> = nodes.iter().map(String::as_str).filter(|node| there(node)).collect();
        let free: Vec<&str> = free
            .into_iter()
            .filter(|node| *node != primary && !replicas.iter().any(|r| r == node))
            .collect();
        let short = (copies as usize - 1).saturating_sub(replicas.len());
        if short > 0 && !free.is_empty() {
            replicas.extend(crate::blobs::holders(&key, &free, short).into_iter().map(String::from));
        }
        replicas.truncate(copies as usize - 1);
        replicas.sort();
        let mut was = names(&status["replicas"]);
        was.sort();
        // (When a node synced counts only while it is a replica: one picked again starts over.)
        let mut synced = status["synced"].as_object().cloned().unwrap_or_default();
        let before = synced.len();
        synced.retain(|node, _| replicas.contains(node));
        if status["primary"].as_str() != Some(&primary) || was != replicas || synced.len() != before {
            let fields = json!({ "primary": primary, "replicas": replicas, "synced": synced });
            writes.push((key, fields.as_object().expect("an object").clone()));
        }
    }
    writes
}

/// Where this node keeps what it last synced of each volume it is a replica of: a file per
/// volume with the archive's hash in it. None: what is in the volume's directory here is not
/// a copy the primary sent (it was the primary's own, once), and is set aside, not replaced.
fn marker(state: &Path, dir: &Dir) -> PathBuf {
    state.join("replicas").join(&dir.namespace).join(&dir.name)
}

/// Puts the directory at `new` in the place of `dir`. What was in `dir` goes, unless it is
/// not a copy this node was sent (`aside`): then it is kept beside it as `NAME.was-AT`.
fn swap(new: &Path, dir: &Path, aside: Option<u64>) -> std::io::Result<()> {
    let mut old = dir.as_os_str().to_owned();
    old.push(aside.map_or(".old".to_string(), |at| format!(".was-{at}")));
    let old = PathBuf::from(old);
    let _ = std::fs::remove_dir_all(&old);
    let empty = std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_none());
    match std::fs::rename(dir, &old) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Err(e) = std::fs::rename(new, dir) {
        let _ = std::fs::rename(&old, dir);
        return Err(e);
    }
    if aside.is_none() || empty {
        let _ = std::fs::remove_dir_all(&old);
    }
    Ok(())
}

#[derive(serde::Deserialize)]
pub struct Have {
    have: Option<String>,
}

/// `GET /v1/volume-copy/NS/NAME` (members only): the volume as it is now, if this node has it.
pub async fn copy(
    State(shared): State<Arc<Shared>>,
    UrlPath((namespace, name)): UrlPath<(String, String)>,
    Query(have): Query<Have>,
) -> Response {
    let key = format!("Volume/{namespace}/{name}");
    let dir = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let mine = |(_, dir, _): &(String, Dir, u32)| dir.node == shared.members.me();
        crate::volumes::replicated(&state.store)
            .into_iter()
            .filter(|(k, ..)| *k == key)
            .find(mine)
    };
    let (Some((_, dir, _)), Some(state)) = (dir, shared.logs.parent()) else {
        return (StatusCode::NOT_FOUND, "this node does not have that volume").into_response();
    };
    let state = state.to_path_buf();
    // ponytail: one archive at a time on a node, each of the whole volume even when the
    // answer is that nothing changed; see the top of this file.
    static SENDING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _one = SENDING.lock().await;
    let archived = tokio::task::spawn_blocking(move || {
        let from = crate::volumes::host_dir(&state, &dir)?;
        let temp = state.join("replicas/.sending");
        let (hash, _) = crate::backups::archive(&from, &temp)?;
        // (Read through the open file, which has no name any more: nothing is left behind.)
        let file = std::fs::File::open(temp.join(&hash)).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(temp.join(&hash));
        Ok::<_, String>((hash, file))
    });
    match archived.await.map_err(|e| e.to_string()).and_then(|archived| archived) {
        Ok((hash, _)) if have.have.as_deref() == Some(&hash) => StatusCode::NOT_MODIFIED.into_response(),
        Ok((_, file)) => {
            let size = file.metadata().map_or(0, |file| file.len());
            let body = axum::body::Body::from_stream(crate::blobs::chunks(file));
            ([(axum::http::header::CONTENT_LENGTH, size)], body).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

/// Whether `me` is a replica of the volume `dir` was (and not the node that has it).
fn replica(store: &Store, dir: &Dir, me: &str) -> bool {
    let now = crate::volumes::dir(store, &dir.namespace, &dir.name);
    let key = format!("Volume/{}/{}", dir.namespace, dir.name);
    let replicas = store
        .get(&key)
        .and_then(|volume| Some(names(&volume.status.as_ref()?["replicas"])));
    now.is_some_and(|now| now.node != me) && replicas.is_some_and(|replicas| replicas.iter().any(|r| r == me))
}

/// Brings this node's copy of `dir` up to date from the node at `address`. The hash of what
/// it has now.
async fn sync(
    shared: &Arc<Shared>,
    client: &reqwest::Client,
    address: &str,
    state: &Path,
    dir: &Dir,
    now: u64,
) -> Result<String, String> {
    let marker = marker(state, dir);
    let have = std::fs::read_to_string(&marker).ok();
    let have = have.as_deref().map(str::trim).filter(|have| crate::blobs::named(have));
    let query = have.map_or(String::new(), |have| format!("?have={have}"));
    let url = format!("https://{address}/v1/volume-copy/{}/{}{query}", dir.namespace, dir.name);
    let slow = |_| format!("nothing came for {} s", QUIET.as_secs());
    let asked = tokio::time::timeout(QUIET * 20, client.get(url).send())
        .await
        .map_err(slow)?;
    let mut answer = asked
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| e.to_string())?;
    if let (StatusCode::NOT_MODIFIED, Some(have)) = (answer.status(), have) {
        return Ok(have.to_string());
    }
    let temp = state.join("replicas/.receiving");
    let mut incoming = Incoming::new(&temp).map_err(|e| e.to_string())?;
    loop {
        let chunk = tokio::time::timeout(QUIET, answer.chunk()).await.map_err(slow)?;
        let Some(chunk) = chunk.map_err(|e| e.to_string())? else {
            break;
        };
        incoming.write(&chunk).map_err(|e| e.to_string())?;
    }
    let (state, dir, aside) = (state.to_path_buf(), dir.clone(), have.is_none().then_some(now));
    let shared = shared.clone();
    let placed = tokio::task::spawn_blocking(move || {
        let (hash, _) = incoming.keep(None)?;
        let archive = temp.join(&hash);
        let into = crate::volumes::host_dir(&state, &dir)?;
        let marker = self::marker(&state, &dir);
        // (From this cluster's own node, as it is there: modes and all.)
        let placed = crate::backups::unpack_beside(&archive, &into, 0).and_then(|new| {
            // This node may have been made the primary while that came: what is here is the
            // volume itself then, in use, and stays. (The store is held for the two renames.)
            let store = shared.store.lock().expect("a handler panicked holding the store");
            if !replica(&store.store, &dir, shared.members.me()) {
                let _ = std::fs::remove_dir_all(&new);
                return Err("this node is not a replica of it any more".to_string());
            }
            // (No marker while the two are changing places: a crash there starts over.)
            let _ = std::fs::remove_file(&marker);
            swap(&new, &into, aside).map_err(|e| format!("{}: {e}", into.display()))
        });
        let _ = std::fs::remove_file(&archive);
        placed?;
        let wrote =
            std::fs::create_dir_all(marker.parent().unwrap_or(&state)).and_then(|()| std::fs::write(&marker, &hash));
        wrote.map_err(|e| format!("{}: {e}", marker.display()))?;
        Ok::<_, String>(hash)
    });
    placed.await.map_err(|e| e.to_string())?
}

/// Keeps this node's copies of other nodes' volumes up to date.
pub async fn run(shared: Arc<Shared>, state: PathBuf, mut stopping: watch::Receiver<bool>) {
    let me = shared.members.me().to_string();
    // (When each was last tried, so that one that fails is not asked for every round.)
    let mut tried: BTreeMap<String, u64> = BTreeMap::new();
    // (And what went wrong with each, said once and not every round.)
    let mut said: BTreeMap<String, String> = BTreeMap::new();
    // (What a stop in the middle of a sync left behind.)
    for left in [".sending", ".receiving"] {
        let _ = std::fs::remove_dir_all(state.join("replicas").join(left));
    }
    loop {
        tokio::select! {
            _ = tokio::time::sleep(ROUND) => {}
            _ = stopping.changed() => return,
        }
        let Some(cluster) = &shared.cluster else { continue };
        let now = kith_api::store::now();
        let (due, mine) = {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            let store = &state.store;
            let (mut due, mut mine) = (Vec::new(), Vec::new());
            for (key, dir, _) in crate::volumes::replicated(store) {
                if dir.node == me {
                    mine.push(dir);
                    continue;
                }
                let Some(volume) = store.get(&key) else { continue };
                let status = volume.status.clone().unwrap_or_default();
                if !names(&status["replicas"]).contains(&me) {
                    continue;
                }
                let every = volume.spec["sync"]
                    .as_str()
                    .and_then(kith_api::kinds::every)
                    .unwrap_or(SYNC);
                let last = status["synced"][&me].as_u64().max(tried.get(&key).copied());
                let there = store.get(&format!("Node/{}", dir.node));
                let address = there.and_then(|node| Some(node.status.as_ref()?["address"].as_str()?.to_string()));
                if let (true, Some(address)) = (last.is_none_or(|last| now >= last + every), address) {
                    due.push((key, dir, address));
                }
            }
            (due, mine)
        };
        // What this node has as the primary is its own: were it a replica again one day,
        // what is in it then is not a copy it was sent.
        for dir in mine {
            let _ = std::fs::remove_file(marker(&state, &dir));
        }
        for (key, dir, address) in due {
            tried.insert(key.clone(), now);
            match sync(&shared, &cluster.client, &address, &state, &dir, now).await {
                Ok(_) => {
                    said.remove(&key);
                    // ponytail: each replica writes the whole `synced` with its own time in;
                    // two that write at once can put the other's back by one sync, which its
                    // next sync puts right (a takeover then may pick a copy one sync older).
                    // A status field per node, or a merging Patch, would close it.
                    let synced = {
                        let state = shared.store.lock().expect("a handler panicked holding the store");
                        let was = state
                            .store
                            .get(&key)
                            .and_then(|volume| volume.status.as_ref()?["synced"].as_object().cloned());
                        let mut synced = was.unwrap_or_default();
                        synced.insert(me.clone(), now.into());
                        synced
                    };
                    let fields = json!({ "synced": synced });
                    let statuses = vec![(key.clone(), fields.as_object().expect("an object").clone())];
                    if let Err(e) = shared.submit(Command::Patch { statuses }).await {
                        eprintln!("kithd: volume {key}: that its copy is up to date was not said: {e}");
                    }
                }
                Err(e) => {
                    let saying = format!("not brought up to date from node {}: {e}", dir.node);
                    if said.get(&key) != Some(&saying) {
                        eprintln!("kithd: volume {key}: the copy here was {saying}");
                        said.insert(key, saying);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(status: Value) -> Store {
        let mut store = Store::default();
        let node = |name: &str| json!({ "apiVersion": "kith.dev/v1", "kind": "Node", "metadata": { "name": name }, "spec": {} });
        let volume = json!({ "apiVersion": "kith.dev/v1", "kind": "Volume", "metadata": { "name": "data" },
            "spec": { "node": "a", "path": "d", "replicas": 2 } });
        let alone = json!({ "apiVersion": "kith.dev/v1", "kind": "Volume", "metadata": { "name": "alone" },
            "spec": { "node": "a", "path": "e" } });
        let resources = [node("a"), node("b"), node("c"), volume, alone];
        let resources = resources
            .into_iter()
            .map(|r| serde_json::from_value(r).unwrap())
            .collect();
        kith_store::run(&mut store, Command::Apply { resources, at: 0 }).unwrap();
        let statuses = vec![("Volume/default/data".to_string(), status.as_object().unwrap().clone())];
        kith_store::run(&mut store, Command::Patch { statuses }).unwrap();
        store
    }

    const KEY: &str = "Volume/default/data";
    const GRACE: Duration = Duration::from_secs(60);

    fn decided(store: &Store, lost: &[(&str, u64)]) -> Option<(String, Vec<String>)> {
        let lost = |node: &str| {
            lost.iter()
                .find(|(name, _)| *name == node)
                .map(|(_, secs)| Duration::from_secs(*secs))
        };
        let mut writes = writes(store, &lost, GRACE);
        assert!(writes.len() <= 1, "only the volume with replicas is written of");
        let (key, fields) = writes.pop()?;
        assert_eq!(key, KEY);
        Some((
            fields["primary"].as_str().unwrap().to_string(),
            names(&fields["replicas"]),
        ))
    }

    #[test]
    fn a_volumes_replica_is_another_node_that_is_there_and_stays_the_same() {
        let (primary, replicas) = decided(&store(json!({})), &[]).unwrap();
        assert_eq!((primary.as_str(), replicas.len()), ("a", 1));
        assert!(replicas[0] == "b" || replicas[0] == "c");
        // Written once: nothing more to say when the status says it.
        let said = store(json!({ "primary": "a", "replicas": replicas }));
        assert_eq!(decided(&said, &[]), None);
        // Never on a node that is not there, never the primary itself.
        let other = if replicas[0] == "b" { "c" } else { "b" };
        let (_, without) = decided(&store(json!({})), &[(&replicas[0], 0)]).unwrap();
        assert_eq!(without, [other]);
        assert_eq!(
            decided(&store(json!({})), &[("b", 0), ("c", 0)]).unwrap().1,
            Vec::<String>::new()
        );
        // A replica quiet for a moment stays; one gone for the grace gives way to another.
        assert_eq!(decided(&said, &[(&replicas[0], 59)]), None);
        assert_eq!(decided(&said, &[(&replicas[0], 60)]).unwrap().1, [other]);
    }

    #[test]
    fn the_replica_synced_last_takes_over_when_the_primary_is_lost_for_the_grace() {
        let synced = store(json!({ "primary": "a", "replicas": ["b"], "synced": { "b": 100 } }));
        assert_eq!(decided(&synced, &[("a", 59)]), None);
        // b has it now; the copy that is short is made on c (a is not there to be one).
        assert_eq!(
            decided(&synced, &[("a", 60)]).unwrap(),
            ("b".to_string(), vec!["c".to_string()])
        );
        // When a node that is no replica any more synced is forgotten: picked again, it starts over.
        let stale = store(json!({ "primary": "a", "replicas": ["b"], "synced": { "b": 100, "c": 50 } }));
        let (_, fields) = writes(&stale, &|_| None, GRACE).pop().unwrap();
        assert_eq!(fields["synced"], json!({ "b": 100 }));
        // A replica that never had a copy takes nothing over: the volume waits for its node.
        let never = store(json!({ "primary": "a", "replicas": ["b"] }));
        assert_eq!(decided(&never, &[("a", 600)]), None);
        // Of two, the one synced last; of those, only one that is there.
        let mut two = store(json!({ "primary": "a", "replicas": ["b", "c"], "synced": { "b": 100, "c": 200 } }));
        let more = json!({ "apiVersion": "kith.dev/v1", "kind": "Volume", "metadata": { "name": "data" },
            "spec": { "node": "a", "path": "d", "replicas": 3 } });
        let resources = vec![serde_json::from_value(more).unwrap()];
        kith_store::run(&mut two, Command::Apply { resources, at: 1 }).unwrap();
        assert_eq!(
            decided(&two, &[("a", 60)]).unwrap(),
            ("c".to_string(), vec!["b".to_string()])
        );
        assert_eq!(decided(&two, &[("a", 60), ("c", 0)]).unwrap().0, "b");
    }

    #[test]
    fn a_volume_is_where_its_replica_took_over_and_its_status_keeps_saying_so() {
        let moved = store(json!({ "primary": "b", "replicas": ["c"], "synced": { "c": 5 } }));
        assert_eq!(crate::volumes::dir(&moved, "default", "data").unwrap().node, "b");
        // The rest of the status is worked out again each round: what is said of the copies stays.
        let again = crate::volumes::resolve(&moved).status;
        assert_eq!(
            again[KEY],
            Some(json!({ "primary": "b", "replicas": ["c"], "synced": { "c": 5 } }))
        );
        // With `replicas` lowered again it stays where it took over, and says only that:
        // never back, by itself, to the old copy on the node it was made on.
        let mut lowered = moved;
        let one = |node: &str| {
            let volume = json!({ "apiVersion": "kith.dev/v1", "kind": "Volume", "metadata": { "name": "data" },
                "spec": { "node": node, "path": "d" } });
            let resources = vec![serde_json::from_value(volume).unwrap()];
            Command::Apply { resources, at: 2 }
        };
        kith_store::run(&mut lowered, one("a")).unwrap();
        assert_eq!(crate::volumes::dir(&lowered, "default", "data").unwrap().node, "b");
        assert_eq!(
            crate::volumes::resolve(&lowered).status[KEY],
            Some(json!({ "primary": "b" }))
        );
        assert!(!replica(
            &lowered,
            &crate::volumes::dir(&lowered, "default", "data").unwrap(),
            "b"
        ));
        // Until its `node` names where it is: then nothing more is said.
        kith_store::run(&mut lowered, one("b")).unwrap();
        assert_eq!(crate::volumes::resolve(&lowered).status[KEY], None);
    }

    #[test]
    fn a_replica_swaps_in_what_it_was_sent_and_sets_aside_what_it_was_not() {
        let root = std::env::temp_dir().join(format!("kith-replica-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (dir, new) = (root.join("d"), root.join("d.restoring"));
        let fill = |at: &Path, text: &str| {
            std::fs::create_dir_all(at).unwrap();
            std::fs::write(at.join("file"), text).unwrap();
        };
        // The first copy, where there was nothing; then the next, in its place.
        fill(&new, "one");
        swap(&new, &dir, Some(7)).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("file")).unwrap(), "one");
        fill(&new, "two");
        swap(&new, &dir, None).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("file")).unwrap(), "two");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        // What was this node's own (it was the primary) is kept beside the copy.
        fill(&new, "three");
        swap(&new, &dir, Some(9)).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("file")).unwrap(), "three");
        assert_eq!(std::fs::read_to_string(root.join("d.was-9/file")).unwrap(), "two");
        let _ = std::fs::remove_dir_all(&root);
    }
}
