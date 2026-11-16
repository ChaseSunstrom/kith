use crate::{Command, Done, Log, Machine, TypeConfig, node_id, reported, run};
use kith_api::store::{Error, Store};
use openraft::StorageError;
use openraft::testing::{StoreBuilder, Suite};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// A directory under the system's temporary one, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "kith-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Builder;

impl StoreBuilder<TypeConfig, Log, Machine, Scratch> for Builder {
    async fn build(&self) -> Result<(Scratch, Log, Machine), StorageError<u64>> {
        let scratch = Scratch::new();
        let log = Log::open(&scratch.0.join("log.redb")).unwrap();
        let machine = Machine::open(&scratch.0, Arc::new(|| {})).unwrap();
        Ok((scratch, log, machine))
    }
}

/// openraft's own checks of what a log store and a state machine must do.
#[test]
fn storage_passes_the_openraft_suite() {
    Suite::test_all(Builder).unwrap();
}

fn config(name: &str, value: &str) -> kith_api::Resource {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "kith.dev/v1", "kind": "ConfigMap",
        "metadata": { "name": name }, "spec": { "data": { "value": value } },
    }))
    .unwrap()
}

#[test]
fn commands_replay_to_the_same_store() {
    let commands = [
        Command::Apply {
            resources: vec![config("a", "1"), config("b", "1")],
            at: 100,
        },
        Command::Apply {
            resources: vec![config("a", "2")],
            at: 200,
        },
        Command::Rollback {
            key: "ConfigMap/default/a".into(),
            to: 1,
            at: 300,
        },
        Command::Status {
            statuses: vec![
                ("ConfigMap/default/b".into(), Some(serde_json::json!({ "seen": true }))),
                ("ConfigMap/default/gone".into(), None),
            ],
        },
        Command::Delete {
            key: "ConfigMap/default/b".into(),
        },
    ];
    let replay = || {
        let mut store = Store::default();
        let replies: Vec<_> = commands
            .iter()
            .cloned()
            .map(|command| run(&mut store, command))
            .collect();
        (store, replies)
    };
    // A patch sets its fields and leaves the others; a key that is gone is skipped.
    let patch = |key: &str, field: &str| Command::Patch {
        statuses: vec![(
            key.into(),
            serde_json::Map::from_iter([(field.to_string(), true.into())]),
        )],
    };
    let mut store = Store::default();
    for command in [
        commands[0].clone(),
        patch("ConfigMap/default/a", "x"),
        patch("ConfigMap/default/a", "y"),
    ] {
        run(&mut store, command).unwrap();
    }
    run(&mut store, patch("ConfigMap/default/gone", "x")).unwrap();
    let status = store.get("ConfigMap/default/a").unwrap().status.clone();
    assert_eq!(status, Some(serde_json::json!({ "x": true, "y": true })));

    let (first, replies) = replay();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    // Later, on another node: the same store, to the second.
    assert_eq!(replay().0, first);
    assert_eq!(first.history("ConfigMap/default/a").unwrap().last().unwrap().at, 300);
    assert!(matches!(&replies[4], Ok(Done::Deleted(gone)) if gone.metadata.name == "b"));

    // A refused command changes nothing and says why; an import replaces everything.
    let mut store = first.clone();
    let refused = run(
        &mut store,
        Command::Delete {
            key: "ConfigMap/default/nope".into(),
        },
    );
    assert!(matches!(refused, Err(Error::NotFound(_))) && store == first);
    let imported = run(
        &mut store,
        Command::Import {
            store: Store::default(),
        },
    );
    assert!(imported.is_ok() && store == Store::default());
}

#[test]
fn node_ids_are_stable_and_distinct() {
    assert_eq!(node_id("alpha"), node_id("alpha"));
    let ids: std::collections::BTreeSet<u64> = (0..1000).map(|n| node_id(&format!("node-{n}"))).collect();
    assert_eq!(ids.len(), 1000);
}

#[test]
fn nodes_report_on_one_status() {
    use serde_json::json;
    let unit = |replica: u32, ready: bool| json!({ "name": "main", "replica": replica, "ready": ready });
    let says = |units: Vec<serde_json::Value>| Some(json!({ "replicas": 3, "containers": units }));
    // The scheduler's part is there first, and stays whatever a node says.
    let bound = json!({ "nodes": { "0": "a", "1": "b", "2": "b" }, "replicas": 3 });
    let status = reported(Some(bound), "b", says(vec![unit(2, true), unit(1, false)]));
    let status = reported(Some(status), "a", says(vec![unit(0, true)]));
    assert_eq!(status["nodes"]["2"], "b");
    assert_eq!((&status["replicas"], &status["ready"]), (&json!(3), &json!(2)));
    let places = |status: &serde_json::Value| {
        let units = status["containers"].as_array().unwrap().iter();
        units
            .map(|unit| format!("{}{}", unit["replica"], unit["node"].as_str().unwrap()))
            .collect::<Vec<_>>()
    };
    assert_eq!(places(&status), ["0a", "1b", "2b"]);
    // A node replaces only its own, and a node that runs nothing any more is taken out.
    let status = reported(Some(status), "b", says(vec![unit(1, true)]));
    assert_eq!(
        (places(&status), &status["ready"]),
        (vec!["0a".to_string(), "1b".into()], &json!(2))
    );
    let status = reported(Some(status), "a", None);
    assert_eq!(
        (places(&status), &status["ready"], &status["replicas"]),
        (vec!["1b".to_string()], &json!(1), &json!(3))
    );
    // Units from before nodes were named go when a node reports; a replica that two nodes
    // say they run is ready once, and only when both say so.
    let old = json!({ "containers": [unit(0, true), unit(1, true)] });
    let status = reported(Some(old), "a", says(vec![unit(0, true)]));
    assert_eq!((places(&status), &status["ready"]), (vec!["0a".to_string()], &json!(1)));
    let status = reported(Some(status), "b", says(vec![unit(0, false)]));
    assert_eq!(
        (places(&status), &status["ready"]),
        (vec!["0a".to_string(), "0b".into()], &json!(0))
    );
    // A Job (it has a state) is as its one node says; what is no unit is dropped, not a panic.
    let job = json!({ "state": "running", "containers": [unit(0, true), 7, "x"] });
    let status = reported(None, "a", Some(job));
    assert_eq!((places(&status), status.get("ready")), (vec!["0a".to_string()], None));
    assert_eq!(
        reported(None, "a", Some(json!("nonsense"))),
        json!({ "containers": [], "ready": 0 })
    );
}

/// A state as format 1's builds wrote it. Later formats get a directory of their own, and
/// this one stays: a build that cannot read it has broken every node that updates to it.
const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/format-1");
/// How far the fixture's snapshot goes, and how far its log was purged: only the blank
/// entry it starts with is gone, so every kind of entry is still in the file.
const SNAPSHOT: usize = 6;
const PURGED: usize = 1;

fn block<T>(work: impl Future<Output = T>) -> T {
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    runtime.block_on(work)
}

fn fixture_vote() -> openraft::Vote<u64> {
    openraft::Vote::new_committed(3, 7)
}

/// The fixture's log, from index 1: a blank, who is in the cluster, every kind of command, a blank.
fn fixture_entries() -> Vec<openraft::Entry<TypeConfig>> {
    use openraft::{BasicNode, CommittedLeaderId, Entry, EntryPayload, LogId, Membership};
    use serde_json::json;
    let mut old = Store::default();
    let apply = |names: &[(&str, &str)], at| Command::Apply {
        resources: names.iter().map(|(name, value)| config(name, value)).collect(),
        at,
    };
    run(&mut old, apply(&[("old", "0")], 50)).unwrap();
    let a = || "ConfigMap/default/a".to_string();
    let members = std::collections::BTreeMap::from([(7, BasicNode::new("n1"))]);
    let payloads = vec![
        EntryPayload::Blank,
        EntryPayload::Membership(Membership::new(vec![[7].into()], members)),
        EntryPayload::Normal(Command::Import { store: old }),
        EntryPayload::Normal(apply(&[("a", "1"), ("b", "1")], 100)),
        EntryPayload::Normal(apply(&[("a", "2")], 200)),
        EntryPayload::Normal(Command::Status {
            statuses: vec![("ConfigMap/default/b".into(), Some(json!({ "seen": true })))],
        }),
        // (The snapshot ends here.)
        EntryPayload::Normal(Command::Rollback {
            key: a(),
            to: 1,
            at: 300,
        }),
        EntryPayload::Normal(Command::Patch {
            statuses: vec![(a(), serde_json::Map::from_iter([("x".to_string(), true.into())]))],
        }),
        EntryPayload::Normal(Command::Report {
            node: "n1".into(),
            statuses: vec![(
                a(),
                Some(json!({ "containers": [{ "name": "main", "replica": 0, "ready": true }] })),
            )],
        }),
        EntryPayload::Normal(Command::Delete {
            key: "ConfigMap/default/b".into(),
        }),
        EntryPayload::Blank,
    ];
    let entry = |(index, payload)| Entry {
        log_id: LogId::new(CommittedLeaderId::new(3, 7), index as u64 + 1),
        payload,
    };
    payloads.into_iter().enumerate().map(entry).collect()
}

/// Writes the fixture: `cargo test -p kith-store -- --ignored format_fixture`. Once per
/// format: it is what that format's builds wrote, so one that is there is never written again.
#[test]
#[ignore = "writes fixtures/format-N, once per format"]
fn format_fixture_is_written() {
    use openraft::RaftSnapshotBuilder;
    use openraft::storage::{RaftLogStorage, RaftStateMachine};
    let dir = std::path::Path::new(FIXTURE);
    std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
    std::fs::create_dir(dir).expect("this format's fixture is there already, and stays as it was written");
    let mut log = Log::open(&dir.join("log.redb")).unwrap();
    let mut machine = Machine::open(dir, Arc::new(|| {})).unwrap();
    let entries = fixture_entries();
    log.put(entries.clone()).unwrap();
    block(async {
        log.save_vote(&fixture_vote()).await.unwrap();
        log.save_committed(entries.last().map(|entry| entry.log_id))
            .await
            .unwrap();
        machine.apply(entries[..SNAPSHOT].to_vec()).await.unwrap();
        machine.build_snapshot().await.unwrap();
        log.purge(entries[PURGED - 1].log_id).await.unwrap();
    });
}

#[test]
fn format_1_state_is_read_whole_by_this_build() {
    use openraft::RaftLogReader;
    use openraft::storage::{RaftLogStorage, RaftStateMachine};
    let scratch = Scratch::new();
    for file in ["log.redb", "snapshot.json"] {
        std::fs::copy(std::path::Path::new(FIXTURE).join(file), scratch.0.join(file)).unwrap();
    }
    let mut log = Log::open(&scratch.0.join("log.redb")).unwrap();
    let mut machine = Machine::open(&scratch.0, Arc::new(|| {})).unwrap();
    let entries = fixture_entries();
    let index = |id: Option<openraft::LogId<u64>>| id.map(|id| id.index as usize);
    block(async {
        assert_eq!(log.read_vote().await.unwrap(), Some(fixture_vote()));
        assert_eq!(index(log.read_committed().await.unwrap()), Some(entries.len()));
        let state = log.get_log_state().await.unwrap();
        assert_eq!(
            (index(state.last_purged_log_id), index(state.last_log_id)),
            (Some(PURGED), Some(entries.len()))
        );
        let (applied, membership) = machine.applied_state().await.unwrap();
        assert_eq!(index(applied), Some(SNAPSHOT));
        assert_eq!(
            membership
                .nodes()
                .map(|(id, node)| (*id, node.addr.as_str()))
                .collect::<Vec<_>>(),
            [(7, "n1")]
        );
        assert!(machine.get_current_snapshot().await.unwrap().is_some());
        // Every entry the file keeps reads as what was written, the ones the snapshot covers too.
        let kept = log.try_get_log_entries(..).await.unwrap();
        let json = |entries: &[openraft::Entry<TypeConfig>]| serde_json::to_value(entries).unwrap();
        assert_eq!(json(&kept), json(&entries[PURGED..]));
        // The log after the snapshot, run by this build, ends where running every command does.
        machine.apply(kept[SNAPSHOT - PURGED..].to_vec()).await.unwrap();
    });
    let mut whole = Store::default();
    for entry in entries {
        if let openraft::EntryPayload::Normal(command) = entry.payload {
            run(&mut whole, command).unwrap();
        }
    }
    let read = machine.state.lock().unwrap().store.clone();
    assert_eq!(read, whole);
    let a = read.get("ConfigMap/default/a").unwrap();
    let status = a.status.as_ref().unwrap();
    assert_eq!(
        (&status["ready"], &status["containers"][0]["node"]),
        (&1.into(), &"n1".into())
    );
    assert_eq!(read.history("ConfigMap/default/a").unwrap().last().unwrap().at, 300);
    assert!(read.get("ConfigMap/default/old").is_some() && read.get("ConfigMap/default/b").is_none());
}

#[test]
fn format_newer_than_this_build_is_refused_and_no_number_is_the_first() {
    use openraft::storage::RaftLogStorage;
    use redb::{Database, TableDefinition};
    let scratch = Scratch::new();
    let newer = crate::FORMAT + 1;
    let refusal = |said: String| {
        let both =
            said.contains(&format!("format {newer}")) && said.contains(&format!("up to format {}", crate::FORMAT));
        assert!(both, "{said}");
    };
    let open = || Machine::open(&scratch.0, Arc::new(|| {}));
    let write = |snapshot: &serde_json::Value| {
        std::fs::write(scratch.0.join("snapshot.json"), snapshot.to_string()).unwrap();
    };

    let bytes = std::fs::read(std::path::Path::new(FIXTURE).join("snapshot.json")).unwrap();
    let mut snapshot: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(snapshot["format"], 1);
    // From before formats were numbered: read as the first.
    snapshot.as_object_mut().unwrap().remove("format");
    write(&snapshot);
    let state = open().ok().unwrap().state;
    assert!(state.lock().unwrap().store.get("ConfigMap/default/a").is_some());
    // Newer, and what it keeps is nothing this build knows: the number is what it says.
    snapshot["format"] = newer.into();
    snapshot["state"] = "what a later kithd keeps here".into();
    write(&snapshot);
    refusal(open().err().unwrap());
    // Newer, and it would read: refused all the same, since it may not mean the same.
    snapshot["state"] = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["state"].take();
    write(&snapshot);
    refusal(open().err().unwrap());

    // A log from before formats were numbered (two tables, no number) is the first, and is numbered now.
    let path = scratch.0.join("log.redb");
    let meta: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
    let log: TableDefinition<u64, &[u8]> = TableDefinition::new("log");
    let put = |format: Option<u32>| {
        let db = Database::create(&path).unwrap();
        let txn = db.begin_write().unwrap();
        txn.open_table(log).unwrap();
        let vote = serde_json::to_vec(&fixture_vote()).unwrap();
        txn.open_table(meta).unwrap().insert("vote", vote.as_slice()).unwrap();
        if let Some(format) = format {
            let format = format.to_string();
            txn.open_table(meta)
                .unwrap()
                .insert("format", format.as_bytes())
                .unwrap();
        }
        txn.commit().unwrap();
    };
    let format = || {
        let db = Database::create(&path).unwrap();
        let txn = redb::ReadableDatabase::begin_read(&db).unwrap();
        let value = txn.open_table(meta).unwrap().get("format").unwrap();
        value.map(|value| String::from_utf8(value.value().to_vec()).unwrap())
    };
    put(None);
    let mut old = Log::open(&path).ok().unwrap();
    assert_eq!(block(old.read_vote()).unwrap(), Some(fixture_vote()));
    drop(old);
    assert_eq!(format(), Some(crate::FORMAT.to_string()));
    // A newer one is refused, and left as it was.
    put(Some(newer));
    refusal(Log::open(&path).err().unwrap());
    assert_eq!(format(), Some(newer.to_string()));
}

#[test]
fn the_keys_commands_changed_are_kept_for_a_reader_that_is_behind() {
    use openraft::RaftSnapshotBuilder;
    use openraft::storage::RaftStateMachine;
    let scratch = Scratch::new();
    let mut machine = Machine::open(&scratch.0, Arc::new(|| {})).unwrap();
    block(async { machine.apply(fixture_entries()).await.unwrap() });
    let (a, b) = ("ConfigMap/default/a", "ConfigMap/default/b");
    {
        let state = machine.state.lock().unwrap();
        assert_eq!(state.index(), 11);
        let keys = |after| state.touched(after).map(|keys| keys.into_iter().collect::<Vec<_>>());
        // From before the store was replaced (the Import at index 3): everything is read again.
        assert_eq!(keys(2), None);
        assert_eq!(keys(3), Some(vec![a, b]));
        assert_eq!(keys(8), Some(vec![a, b]));
        assert_eq!(keys(9), Some(vec![b]));
        assert_eq!(keys(11), Some(vec![]));
    }
    // More changes than are kept: a reader that far behind reads everything, a near one does not.
    let entry = |index: u64| openraft::Entry {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(3, 7), index),
        payload: openraft::EntryPayload::Normal(Command::Status {
            statuses: vec![(a.to_string(), None)],
        }),
    };
    block(async { machine.apply((12..6000).map(entry)).await.unwrap() });
    {
        let state = machine.state.lock().unwrap();
        assert_eq!(state.touched(11), None);
        assert_eq!(state.touched(5990).map(|keys| keys.len()), Some(1));
    }
    // A node that starts again knows nothing of what changed before it did.
    block(async { machine.build_snapshot().await.unwrap() });
    let again = Machine::open(&scratch.0, Arc::new(|| {})).unwrap();
    let state = again.state.lock().unwrap();
    assert_eq!((state.index(), state.touched(5990)), (5999, None));
    assert_eq!(state.touched(5999).map(|keys| keys.len()), Some(0));
}

/// kith says each of Raft's settings itself (openraft's `Default` runs a command line parser):
/// what it does not choose is still what openraft would have.
#[test]
fn settings_are_openrafts_but_for_ours() {
    let ours = crate::settings();
    let theirs = openraft::Config {
        cluster_name: ours.cluster_name.clone(),
        heartbeat_interval: ours.heartbeat_interval,
        election_timeout_min: ours.election_timeout_min,
        election_timeout_max: ours.election_timeout_max,
        snapshot_policy: ours.snapshot_policy.clone(),
        max_in_snapshot_log_to_keep: ours.max_in_snapshot_log_to_keep,
        ..Default::default()
    };
    assert_eq!(format!("{ours:?}"), format!("{theirs:?}"));
}

/// Raft between replicas in one process. A node that is not in the map is down.
#[derive(Clone, Default)]
struct Net(Arc<std::sync::Mutex<std::collections::BTreeMap<u64, crate::Raft>>>);

struct Link(Net, u64);

impl openraft::RaftNetworkFactory<TypeConfig> for Net {
    type Network = Link;

    async fn new_client(&mut self, target: u64, _: &openraft::BasicNode) -> Link {
        Link(self.clone(), target)
    }
}

type Rpc<A, E = openraft::error::Infallible> =
    Result<A, openraft::error::RPCError<u64, openraft::BasicNode, openraft::error::RaftError<u64, E>>>;

impl Link {
    fn raft<E: std::error::Error>(&self) -> Rpc<crate::Raft, E> {
        let down = || openraft::error::Unreachable::new(&std::io::Error::other("down"));
        Ok(self.0.0.lock().unwrap().get(&self.1).cloned().ok_or_else(down)?)
    }
}

impl openraft::RaftNetwork<TypeConfig> for Link {
    async fn append_entries(
        &mut self,
        rpc: openraft::raft::AppendEntriesRequest<TypeConfig>,
        _: openraft::network::RPCOption,
    ) -> Rpc<openraft::raft::AppendEntriesResponse<u64>> {
        let answer = self.raft()?.append_entries(rpc).await;
        answer.map_err(|e| openraft::error::RemoteError::new(self.1, e).into())
    }

    async fn install_snapshot(
        &mut self,
        rpc: openraft::raft::InstallSnapshotRequest<TypeConfig>,
        _: openraft::network::RPCOption,
    ) -> Rpc<openraft::raft::InstallSnapshotResponse<u64>, openraft::error::InstallSnapshotError> {
        let answer = self.raft()?.install_snapshot(rpc).await;
        answer.map_err(|e| openraft::error::RemoteError::new(self.1, e).into())
    }

    async fn vote(
        &mut self,
        rpc: openraft::raft::VoteRequest<u64>,
        _: openraft::network::RPCOption,
    ) -> Rpc<openraft::raft::VoteResponse<u64>> {
        let answer = self.raft()?.vote(rpc).await;
        answer.map_err(|e| openraft::error::RemoteError::new(self.1, e).into())
    }
}

/// What the test below writes as a node's wrapped key.
const WRAPPED: &str = "5ea1ed0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"; // pragma: allowlist secret

fn node_key(wrapped: &str) -> kith_api::Resource {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "kith.dev/v1", "kind": "NodeKey", "metadata": { "name": "n1" },
        "spec": { "id": "ab".repeat(32), "wrapped": wrapped, "forgotten": wrapped.is_empty() },
    }))
    .unwrap()
}

/// Write `command` through whichever node leads, once one does; the index it is at.
async fn write(net: &Net, command: Command) -> u64 {
    let (index, reply) = written(net, command).await;
    reply.unwrap();
    index
}

/// The same, with the store's answer, refused or not.
async fn written(net: &Net, command: Command) -> (u64, crate::Reply) {
    for _ in 0..100 {
        let rafts: Vec<_> = net.0.lock().unwrap().values().cloned().collect();
        for raft in rafts {
            let leads = raft.metrics().borrow().current_leader == Some(raft.metrics().borrow().id);
            if leads && let Ok(written) = raft.client_write(command.clone()).await {
                return (written.log_id.index, written.data);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("no node led for 10 s");
}

/// Wait until `raft` has applied `index` and dropped every log entry up to `purged`.
async fn caught_up(raft: &crate::Raft, index: u64, purged: u64) {
    let wait = raft.wait(Some(std::time::Duration::from_secs(20)));
    let done = |m: &openraft::RaftMetrics<u64, openraft::BasicNode>| {
        let dropped = m.purged.map_or(0, |at| at.index);
        m.last_applied.is_some_and(|at| at.index >= index) && dropped >= purged
    };
    let id = raft.metrics().borrow().id;
    wait.metrics(done, "applied and purged").await.unwrap_or_else(|e| {
        panic!("node {id} did not drop the log up to {purged}: {e}");
    });
}

/// Whether the snapshot file in `dir`, or an entry its log gives back, holds `text`. The
/// log's own reader: the file itself keeps freed pages, which are not what is asked here.
async fn holds(dir: &std::path::Path, text: &str) -> bool {
    use openraft::RaftLogReader;
    let snapshot = std::fs::read_to_string(dir.join("snapshot.json")).unwrap_or_default();
    let mut log = Log::open(&dir.join("log.redb")).unwrap();
    let entries = log.try_get_log_entries(..).await.unwrap();
    snapshot.contains(text) || serde_json::to_string(&entries).unwrap().contains(text)
}

/// A NodeKey whose wrapped key is forgotten: every replica snapshots and drops the log up to
/// that write, the one that was down when it was made too, and goes on as before.
#[test]
fn forgotten_key_is_in_no_snapshot_or_log_entry() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let dirs = [Scratch::new(), Scratch::new(), Scratch::new()];
        let net = Net::default();
        let start = async |id: u64| {
            let dir = &dirs[id as usize - 1].0;
            let replica = crate::open(dir, id, net.clone(), Arc::new(|| {})).await.unwrap();
            net.0.lock().unwrap().insert(id, replica.raft.clone());
            replica
        };
        let mut replicas = vec![start(1).await, start(2).await, start(3).await];
        let members = (1..=3).map(|id| (id, openraft::BasicNode::default()));
        replicas[0]
            .raft
            .initialize(members.collect::<std::collections::BTreeMap<_, _>>())
            .await
            .unwrap();
        let resources = vec![node_key(WRAPPED), config("a", "1")];
        let at = write(&net, Command::Apply { resources, at: 1 }).await;
        for replica in &replicas {
            caught_up(&replica.raft, at, 0).await;
        }

        // One follower is down while the key is forgotten.
        let leader = replicas[0].raft.metrics().borrow().current_leader.unwrap();
        let down = replicas.iter().position(|replica| replica.id != leader).unwrap();
        let replica = replicas.remove(down);
        net.0.lock().unwrap().remove(&replica.id);
        replica.raft.shutdown().await.unwrap();
        drop(replica);
        let forgot = write(
            &net,
            Command::Apply {
                resources: vec![node_key("")],
                at: 2,
            },
        )
        .await;
        for replica in &replicas {
            caught_up(&replica.raft, forgot, forgot).await;
            let snapshot = std::fs::read_to_string(dirs[replica.id as usize - 1].0.join("snapshot.json"));
            assert!(!snapshot.unwrap().contains(WRAPPED));
        }
        let last = write(
            &net,
            Command::Apply {
                resources: vec![config("b", "2")],
                at: 3,
            },
        )
        .await;
        replicas.push(start(down as u64 + 1).await);
        for replica in &replicas {
            caught_up(&replica.raft, last, forgot).await;
        }
        let stores = |replicas: &[crate::Replica]| -> Vec<String> {
            let store = |replica: &crate::Replica| serde_json::to_string(&replica.state.lock().unwrap().store);
            replicas.iter().map(|replica| store(replica).unwrap()).collect()
        };
        let before = stores(&replicas);
        assert!(
            before
                .iter()
                .all(|store| *store == before[0] && !store.contains(WRAPPED))
        );
        assert!(before[0].contains("ConfigMap/default/b"));

        // Stopped, no file holds the key; started again, each reads the same store.
        for replica in replicas.drain(..) {
            net.0.lock().unwrap().remove(&replica.id);
            replica.raft.shutdown().await.unwrap();
        }
        for dir in &dirs {
            assert!(!holds(&dir.0, WRAPPED).await, "{} holds the key", dir.0.display());
        }
        for id in 1..=3 {
            replicas.push(start(id).await);
        }
        let after = stores(&replicas);
        assert!(after.iter().all(|store| *store == before[0]), "each reads what it had");
        let more = write(
            &net,
            Command::Apply {
                resources: vec![config("c", "3")],
                at: 4,
            },
        )
        .await;
        for replica in &replicas {
            caught_up(&replica.raft, more, forgot).await;
        }
        let history = replicas[0]
            .state
            .lock()
            .unwrap()
            .store
            .history("NodeKey/n1")
            .map(<[_]>::len);
        assert_eq!(history.ok(), Some(1));
        for replica in replicas {
            replica.raft.shutdown().await.unwrap();
        }
    });
}

/// Asked to drop the log at any index, openraft neither panics nor stops. Its `unwrap` of the
/// log id at the clamped index (engine_impl.rs, `trigger_purge_log`) always finds one: an index
/// under what was already dropped returns first, one past the snapshot is cut down to the
/// snapshot's last index, and the list of log ids answers for every index from the last purged
/// one to the last log id, which a snapshot built here or installed from a leader never passes.
#[test]
fn purge_asked_at_any_index_leaves_raft_running() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let dir = Scratch::new();
        let net = Net::default();
        let replica = crate::open(&dir.0, 1, net.clone(), Arc::new(|| {})).await.unwrap();
        net.0.lock().unwrap().insert(1, replica.raft.clone());
        let members = [(1, openraft::BasicNode::default())];
        replica
            .raft
            .initialize(members.into_iter().collect::<std::collections::BTreeMap<_, _>>())
            .await
            .unwrap();
        let mut at = 0;
        for n in 1..=5 {
            at = write(
                &net,
                Command::Apply {
                    resources: vec![config("a", &n.to_string())],
                    at: n,
                },
            )
            .await;
        }
        let raft = &replica.raft;
        raft.trigger().snapshot().await.unwrap();
        let wait = raft.wait(Some(std::time::Duration::from_secs(20)));
        let snapped = |m: &openraft::RaftMetrics<u64, openraft::BasicNode>| m.snapshot.is_some_and(|s| s.index >= at);
        wait.metrics(snapped, "snapshot built").await.unwrap();
        let snapshot = raft.metrics().borrow().snapshot.unwrap().index;

        let mut asks = vec![u64::MAX / 2, snapshot + 1, snapshot, 0, 0, 1, snapshot, u64::MAX / 2];
        asks.push(raft.metrics().borrow().purged.map_or(0, |p| p.index));
        for index in asks {
            raft.trigger().purge_log(index).await.unwrap();
        }
        // The core takes these and the write in order: a panic would fail the write.
        write(
            &net,
            Command::Apply {
                resources: vec![config("b", "1")],
                at: 6,
            },
        )
        .await;
        let state = raft.metrics().borrow().running_state.clone();
        assert!(state.is_ok(), "raft stopped: {state:?}");
        raft.shutdown().await.unwrap();
    });
}

/// Put in `store` (as JSON) an earlier revision of NodeKey/n1 that holds [`WRAPPED`]: what a
/// build from before the one-revision limit kept.
fn keep_the_old_way(store: &mut serde_json::Value) {
    let mut earlier = node_key(WRAPPED);
    earlier.metadata.revision = Some(1);
    let revision = serde_json::json!({ "at": 1, "resource": earlier });
    store["resources"]["NodeKey/n1"]
        .as_array_mut()
        .unwrap()
        .insert(0, revision);
}

/// A store with NodeKey/n1 forgotten, its key in an earlier revision still.
fn old_store() -> Store {
    let mut store = Store::default();
    store.apply(node_key(WRAPPED)).unwrap();
    store.apply(node_key("")).unwrap();
    let mut old = serde_json::to_value(&store).unwrap();
    keep_the_old_way(&mut old);
    serde_json::from_value(old).unwrap()
}

/// A node stopped where its snapshot (at index 3) has the key forgotten and its log has the
/// write of the key (index 2) still; `old_way`: that snapshot keeps the key's earlier revision.
fn stopped_before_the_log_was_dropped(dir: &std::path::Path, old_way: bool) {
    use openraft::storage::{RaftLogStorage, RaftStateMachine};
    use openraft::{BasicNode, CommittedLeaderId, Entry, EntryPayload, LogId, Membership, RaftSnapshotBuilder};
    let apply = |resources| EntryPayload::Normal(Command::Apply { resources, at: 1 });
    let members = std::collections::BTreeMap::from([(1, BasicNode::default())]);
    // (As `initialize` writes it: who is in the cluster at index 0, then the first leader's blank.)
    let payloads = vec![
        EntryPayload::Membership(Membership::new(vec![[1].into()], members)),
        EntryPayload::Blank,
        apply(vec![node_key(WRAPPED)]),
        apply(vec![node_key("")]),
    ];
    let entry = |(index, payload)| Entry::<TypeConfig> {
        log_id: LogId::new(
            CommittedLeaderId::new((index > 0).into(), (index > 0).into()),
            index as u64,
        ),
        payload,
    };
    let entries: Vec<_> = payloads.into_iter().enumerate().map(entry).collect();
    block(async {
        let mut log = Log::open(&dir.join("log.redb")).unwrap();
        let mut machine = Machine::open(dir, Arc::new(|| {})).unwrap();
        log.put(entries.clone()).unwrap();
        log.save_vote(&openraft::Vote::new_committed(1, 1)).await.unwrap();
        log.save_committed(Some(entries[3].log_id)).await.unwrap();
        machine.apply(entries).await.unwrap();
        machine.build_snapshot().await.unwrap();
    });
    if old_way {
        let file = dir.join("snapshot.json");
        let mut snapshot: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        keep_the_old_way(&mut snapshot["state"]["store"]);
        std::fs::write(&file, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    }
}

/// A node that stopped after its snapshot took in a forget, but before it dropped its log:
/// nothing applies that write again, so the store drops the log as it is opened. Opened
/// again, with nothing left to drop, it drops nothing: the entries kept for a follower stay.
#[test]
fn forgotten_key_left_in_the_log_is_dropped_at_open() {
    let dir = Scratch::new();
    stopped_before_the_log_was_dropped(&dir.0, false);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert!(
            holds(&dir.0, WRAPPED).await,
            "the log holds the key, as a node that stopped there left it"
        );
        let net = Net::default();
        let replica = crate::open(&dir.0, 1, net.clone(), Arc::new(|| {})).await.unwrap();
        net.0.lock().unwrap().insert(1, replica.raft.clone());
        caught_up(&replica.raft, 3, 3).await;
        // Entries past the snapshot, then one taken at the last of them, which keeps them.
        let last = write(
            &net,
            Command::Apply {
                resources: vec![config("a", "1")],
                at: 2,
            },
        )
        .await;
        replica.raft.trigger().snapshot().await.unwrap();
        let wait = replica.raft.wait(Some(std::time::Duration::from_secs(20)));
        let built = |m: &openraft::RaftMetrics<u64, openraft::BasicNode>| m.snapshot.is_some_and(|s| s.index >= last);
        wait.metrics(built, "a snapshot").await.unwrap();
        replica.raft.shutdown().await.unwrap();
        net.0.lock().unwrap().clear();
        drop(replica);
        assert!(!holds(&dir.0, WRAPPED).await);

        let replica = crate::open(&dir.0, 1, net.clone(), Arc::new(|| {})).await.unwrap();
        caught_up(&replica.raft, last, 3).await;
        // (What is not done can only be waited for: a drop at open is asked for at once.)
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let purged = replica.raft.metrics().borrow().purged.map(|at| at.index);
        assert_eq!(purged, Some(3), "a second open dropped the log up to {purged:?}");
        replica.raft.shutdown().await.unwrap();
    });
}

/// A snapshot written before a NodeKey kept one revision, with the forgotten key in an
/// earlier one: the store cuts it as it opens, and drops the log that has it.
#[test]
fn forgotten_key_kept_from_before_is_cut_at_open() {
    let dir = Scratch::new();
    stopped_before_the_log_was_dropped(&dir.0, true);
    let snapshot = std::fs::read_to_string(dir.0.join("snapshot.json")).unwrap();
    assert!(snapshot.contains(WRAPPED));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let replica = crate::open(&dir.0, 1, Net::default(), Arc::new(|| {})).await.unwrap();
        caught_up(&replica.raft, 3, 3).await;
        replica.raft.shutdown().await.unwrap();
        drop(replica);
        assert!(!holds(&dir.0, WRAPPED).await);
    });
}

/// The same of a snapshot another node sends, and of a store brought in whole.
#[test]
fn forgotten_key_kept_from_before_is_cut_as_it_comes_in() {
    use openraft::storage::RaftStateMachine;
    let dir = Scratch::new();
    block(async {
        let mut machine = Machine::open(&dir.0, Arc::new(|| {})).unwrap();
        let mut state = serde_json::to_value(crate::State::default()).unwrap();
        state["store"] = serde_json::to_value(old_store()).unwrap();
        let meta = openraft::SnapshotMeta {
            last_log_id: Some(openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 3)),
            last_membership: Default::default(),
            snapshot_id: "sent".into(),
        };
        let sent = std::io::Cursor::new(serde_json::to_vec(&state).unwrap());
        machine.install_snapshot(&meta, Box::new(sent)).await.unwrap();
        assert!(!holds(&dir.0, WRAPPED).await);
        assert!(
            !serde_json::to_string(&machine.state.lock().unwrap().store)
                .unwrap()
                .contains(WRAPPED)
        );
    });
    let dir = Scratch::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let net = Net::default();
        let replica = crate::open(&dir.0, 1, net.clone(), Arc::new(|| {})).await.unwrap();
        net.0.lock().unwrap().insert(1, replica.raft.clone());
        let alone = std::collections::BTreeMap::from([(1, openraft::BasicNode::default())]);
        replica.raft.initialize(alone).await.unwrap();
        let index = write(&net, Command::Import { store: old_store() }).await;
        caught_up(&replica.raft, index, index).await;
        let history = replica
            .state
            .lock()
            .unwrap()
            .store
            .history("NodeKey/n1")
            .map(<[_]>::len);
        assert_eq!(history.ok(), Some(1));
        replica.raft.shutdown().await.unwrap();
        drop(replica);
        assert!(!holds(&dir.0, WRAPPED).await);
    });
}

/// A batch the store refuses is in the log as it was sent, the wrapped key of a NodeKey in
/// it too: the node drops its log up to there all the same.
#[test]
fn forgotten_key_refused_write_is_in_no_log_entry() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let dir = Scratch::new();
        let net = Net::default();
        let replica = crate::open(&dir.0, 1, net.clone(), Arc::new(|| {})).await.unwrap();
        net.0.lock().unwrap().insert(1, replica.raft.clone());
        let alone = std::collections::BTreeMap::from([(1, openraft::BasicNode::default())]);
        replica.raft.initialize(alone).await.unwrap();
        let resources = vec![node_key(WRAPPED), config("Not Valid", "1")];
        let (index, reply) = written(&net, Command::Apply { resources, at: 1 }).await;
        assert!(reply.is_err(), "{reply:?}");
        caught_up(&replica.raft, index, index).await;
        replica.raft.shutdown().await.unwrap();
        drop(replica);
        assert!(!holds(&dir.0, WRAPPED).await);
    });
}
