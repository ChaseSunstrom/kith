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

/// A check at apply that takes every entry.
fn any() -> crate::Check {
    Arc::new(|_, _, _| Ok(()))
}

/// `command`, signed by `who` until `expires`, with the nonce `nonce` (as 32 hex).
fn signed(who: &str, expires: u64, nonce: u8, command: Command) -> Command {
    Command::Signed {
        header: format!("v1; who={who}; target=*; expires={expires}; nonce={nonce:032x}; sig=AAAA"),
        method: "POST".into(),
        path: "/v1/apply".into(),
        body: String::new(),
        command: Box::new(command),
    }
}

struct Builder;

impl StoreBuilder<TypeConfig, Log, Machine, Scratch> for Builder {
    async fn build(&self) -> Result<(Scratch, Log, Machine), StorageError<u64>> {
        let scratch = Scratch::new();
        let log = Log::open(&scratch.0.join("log.redb")).unwrap();
        let machine = Machine::open(&scratch.0, Arc::new(|| {}), any()).unwrap();
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

/// A state as format 2's builds wrote it: format 1's log, then the mark, and a resource
/// made after it. Its snapshot goes that far, so both files hold what format 1 has not.
const FIXTURE_2: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/format-2");
const SNAPSHOT_2: usize = 13;

fn fixture_2_entries() -> Vec<openraft::Entry<TypeConfig>> {
    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};
    let mut entries = fixture_entries();
    let made = Command::Apply {
        resources: vec![config("c", "1")],
        at: 400,
    };
    for payload in [
        EntryPayload::Normal(Command::Mark),
        EntryPayload::Normal(made),
        EntryPayload::Blank,
    ] {
        let log_id = LogId::new(CommittedLeaderId::new(3, 7), entries.len() as u64 + 1);
        entries.push(Entry { log_id, payload });
    }
    entries
}

/// A state as format 3's builds wrote it: format 2's log, then the entry that starts the
/// signers' book, two signed writes and a blank. Its snapshot ends after the first signed
/// write, so both files hold what format 2 has not.
const FIXTURE_3: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/format-3");
const SNAPSHOT_3: usize = 16;

fn fixture_3_entries() -> Vec<openraft::Entry<TypeConfig>> {
    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};
    let mut entries = fixture_2_entries();
    let made = |name: &str, at| Command::Apply {
        resources: vec![config(name, "1")],
        at,
    };
    for payload in [
        EntryPayload::Normal(Command::MarkSigned),
        EntryPayload::Normal(signed("local socket", 1000, 1, made("d", 500))),
        EntryPayload::Normal(signed("local socket", 1100, 2, made("e", 600))),
        EntryPayload::Blank,
    ] {
        let log_id = LogId::new(CommittedLeaderId::new(3, 7), entries.len() as u64 + 1);
        entries.push(Entry { log_id, payload });
    }
    entries
}

/// A state as format 4's builds wrote it: format 3's log, then the entry from which every
/// node checks signed entries, a signed write and a blank. Its snapshot ends after the signed
/// write, so both files hold what format 3 has not.
const FIXTURE_4: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/format-4");
const SNAPSHOT_4: usize = 20;

fn fixture_4_entries() -> Vec<openraft::Entry<TypeConfig>> {
    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};
    let mut entries = fixture_3_entries();
    let made = Command::Apply {
        resources: vec![config("f", "1")],
        at: 700,
    };
    for payload in [
        EntryPayload::Normal(Command::MarkChecked),
        EntryPayload::Normal(signed("local socket", 1200, 3, made)),
        EntryPayload::Blank,
    ] {
        let log_id = LogId::new(CommittedLeaderId::new(3, 7), entries.len() as u64 + 1);
        entries.push(Entry { log_id, payload });
    }
    entries
}

/// Every command of `entries` run in turn, each as its place in the log.
fn whole(entries: Vec<openraft::Entry<TypeConfig>>) -> Store {
    let mut whole = Store::default();
    for entry in entries {
        if let openraft::EntryPayload::Normal(command) = entry.payload {
            whole.entry(entry.log_id.index);
            run(&mut whole, command).unwrap();
        }
    }
    whole.entry(0);
    whole
}

/// The format the files in `dir` say they are in: the log's, the snapshot's.
fn formats(dir: &std::path::Path) -> (u32, u32) {
    let meta: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("meta");
    let db = redb::Database::create(dir.join("log.redb")).unwrap();
    let txn = redb::ReadableDatabase::begin_read(&db).unwrap();
    let log = txn.open_table(meta).unwrap().get("format").unwrap().unwrap();
    let log = serde_json::from_slice(log.value()).unwrap();
    let snapshot = std::fs::read(dir.join("snapshot.json")).unwrap();
    let snapshot: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
    (log, snapshot["format"].as_u64().unwrap() as u32)
}

/// Writes the fixture: `cargo test -p kith-store -- --ignored format_fixture`. Once per
/// format: it is what that format's builds wrote, so one that is there is never written again.
#[test]
#[ignore = "writes fixtures/format-N, once per format"]
fn format_fixture_is_written() {
    use openraft::RaftSnapshotBuilder;
    use openraft::storage::{RaftLogStorage, RaftStateMachine};
    let dir = std::path::Path::new(FIXTURE_4);
    std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
    std::fs::create_dir(dir).expect("this format's fixture is there already, and stays as it was written");
    let mut log = Log::open(&dir.join("log.redb")).unwrap();
    let mut machine = Machine::open(dir, Arc::new(|| {}), any()).unwrap();
    let entries = fixture_4_entries();
    log.put(entries.clone()).unwrap();
    block(async {
        log.save_vote(&fixture_vote()).await.unwrap();
        log.save_committed(entries.last().map(|entry| entry.log_id))
            .await
            .unwrap();
        machine.apply(entries[..SNAPSHOT_4].to_vec()).await.unwrap();
        machine.build_snapshot().await.unwrap();
        log.purge(entries[PURGED - 1].log_id).await.unwrap();
    });
}

#[test]
fn format_1_state_is_read_whole_by_this_build() {
    let (read, dir) = read_whole(FIXTURE, fixture_entries(), SNAPSHOT);
    let a = read.get("ConfigMap/default/a").unwrap();
    let status = a.status.as_ref().unwrap();
    assert_eq!(
        (&status["ready"], &status["containers"][0]["node"]),
        (&1.into(), &"n1".into())
    );
    assert_eq!(read.history("ConfigMap/default/a").unwrap().last().unwrap().at, 300);
    assert!(read.get("ConfigMap/default/old").is_some() && read.get("ConfigMap/default/b").is_none());
    // And left as it was: nothing of this build is in it, so the kithd that wrote it reads it still.
    assert!(!read.marked() && read.born("ConfigMap/default/a").is_none());
    assert_eq!(formats(&dir.0), (1, 1));
}

#[test]
fn format_2_state_is_read_whole_by_this_build() {
    let (read, dir) = read_whole(FIXTURE_2, fixture_2_entries(), SNAPSHOT_2);
    // What there was at the mark: of entry 0, at its oldest kept revision. What was made
    // after: of the entry that made it.
    assert_eq!(read.born("ConfigMap/default/a"), Some((0, 100)));
    assert_eq!(read.born("ConfigMap/default/old"), Some((0, 50)));
    assert_eq!(read.born("ConfigMap/default/c"), Some((13, 400)));
    assert_eq!(read.born("ConfigMap/default/b"), None);
    // Both files say so: a kithd from before reads up to format 1, and refuses a file that
    // says more by that number (the rule `format_newer_than_this_build…` holds this build to).
    assert_eq!(formats(&dir.0), (2, 2));
}

#[test]
fn format_3_state_is_read_whole_by_this_build() {
    let (read, dir) = read_whole(FIXTURE_3, fixture_3_entries(), SNAPSHOT_3);
    // What the signed writes made, at their place in the log; the mark before kept.
    assert_eq!(read.born("ConfigMap/default/d"), Some((16, 500)));
    assert_eq!(read.born("ConfigMap/default/e"), Some((17, 600)));
    assert_eq!(read.born("ConfigMap/default/c"), Some((13, 400)));
    // The signer's book, `[newest, {nonce: expires}]`: its newest expires, both nonces.
    let book = serde_json::to_value(&read).unwrap()["signers"]["local socket"].clone();
    assert_eq!(book[0], 1100);
    let nonces = book[1].as_object().unwrap();
    assert_eq!(
        nonces.keys().map(|nonce| &nonce[30..]).collect::<Vec<_>>(),
        ["01", "02"]
    );
    assert!(read.signing());
    assert_eq!(formats(&dir.0), (3, 3));
}

#[test]
fn format_4_state_is_read_whole_by_this_build() {
    let (read, dir) = read_whole(FIXTURE_4, fixture_4_entries(), SNAPSHOT_4);
    assert_eq!(read.born("ConfigMap/default/f"), Some((20, 700)));
    assert_eq!(read.born("ConfigMap/default/d"), Some((16, 500)));
    let book = serde_json::to_value(&read).unwrap()["signers"]["local socket"].clone();
    assert_eq!(book[0], 1200);
    assert!(read.checking() && read.signing());
    assert_eq!(formats(&dir.0), (4, 4));
}

/// A copy of the state in `fixture`, opened by this build: the log reads as `entries`,
/// and the snapshot (which goes `snapshot` entries in) with the log after it ends where
/// running every command does. The store that gives, and the copy.
fn read_whole(fixture: &str, entries: Vec<openraft::Entry<TypeConfig>>, snapshot: usize) -> (Store, Scratch) {
    use openraft::RaftLogReader;
    use openraft::RaftSnapshotBuilder;
    use openraft::storage::{RaftLogStorage, RaftStateMachine};
    let scratch = Scratch::new();
    for file in ["log.redb", "snapshot.json"] {
        std::fs::copy(std::path::Path::new(fixture).join(file), scratch.0.join(file)).unwrap();
    }
    let mut log = Log::open(&scratch.0.join("log.redb")).unwrap();
    let mut machine = Machine::open(&scratch.0, Arc::new(|| {}), any()).unwrap();
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
        assert_eq!(index(applied), Some(snapshot));
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
        machine.apply(kept[snapshot - PURGED..].to_vec()).await.unwrap();
        // (Written again by this build: in the format the store is in, not this build's newest.)
        machine.build_snapshot().await.unwrap();
    });
    let read = machine.state.lock().unwrap().store.clone();
    assert_eq!(read, whole(entries));
    (read, scratch)
}

/// The mark is in the log, so replicas agree on it: one entry at a time, two give the same
/// store; what a resource is first made of outlives its history's trimming, a snapshot and
/// a restart; and a replica that has not come to the mark orders as before it.
#[test]
fn born_is_the_same_on_every_replica_and_kept_through_a_snapshot_and_a_restart() {
    use openraft::RaftSnapshotBuilder;
    use openraft::storage::RaftStateMachine;
    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};
    let apply = |name: &str, value: String, at| Command::Apply {
        resources: vec![config(name, &value)],
        at,
    };
    let mut commands = vec![
        apply("first", "0".into(), 100),
        Command::Mark,
        apply("held", "0".into(), 200),
    ];
    // (Edited past what a history keeps.)
    let edits = kith_api::store::HISTORY_LIMIT as u64 + 50;
    commands.extend((1..=edits).map(|n| apply("held", n.to_string(), 200 + n)));
    commands.push(apply("late", "0".into(), 150));
    commands.push(Command::Delete {
        key: "ConfigMap/default/first".into(),
    });
    commands.push(apply("first", "1".into(), 900));
    let entry = |(index, command)| Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, 1), index as u64 + 1),
        payload: EntryPayload::Normal(command),
    };
    let entries: Vec<Entry<TypeConfig>> = commands.into_iter().enumerate().map(entry).collect();
    let (one, two, behind) = (Scratch::new(), Scratch::new(), Scratch::new());
    let open = |dir: &Scratch| Machine::open(&dir.0, Arc::new(|| {}), any()).unwrap();
    let store = |machine: &Machine| machine.state.lock().unwrap().store.clone();
    let (mut a, mut b, mut c) = (open(&one), open(&two), open(&behind));
    block(async {
        c.apply(entries[..1].to_vec()).await.unwrap();
        for entry in &entries {
            a.apply([entry.clone()]).await.unwrap();
            b.apply([entry.clone()]).await.unwrap();
            assert_eq!(store(&a), store(&b), "at {}", entry.log_id.index);
        }
        a.build_snapshot().await.unwrap();
        c.build_snapshot().await.unwrap();
    });
    let held = "ConfigMap/default/held";
    let checked = |store: &Store| {
        // Made by the log's third entry, whatever its history says now.
        assert_eq!(store.born(held), Some((3, 200)));
        assert!(store.history(held).unwrap().first().unwrap().at > 250);
        // Made later in the log, though its clock said earlier: the log's order is the order.
        assert!(store.born("ConfigMap/default/late").unwrap() > store.born(held).unwrap());
        // Deleted and made again, it is new.
        assert_eq!(store.born("ConfigMap/default/first"), Some((entries.len() as u64, 900)));
    };
    checked(&store(&a));
    // After a restart (the snapshot file), and on a replica sent the snapshot.
    drop(a);
    checked(&store(&open(&one)));
    let sent = std::fs::read(one.0.join("snapshot.json")).unwrap();
    let sent: serde_json::Value = serde_json::from_slice(&sent).unwrap();
    assert_eq!(sent["format"], 2);
    let meta = serde_json::from_value(sent["meta"].clone()).unwrap();
    let state = serde_json::to_vec(&sent["state"]).unwrap();
    block(async {
        let taken = b.install_snapshot(&meta, Box::new(std::io::Cursor::new(state)));
        taken.await.unwrap();
    });
    checked(&store(&b));
    // The one that stopped before the mark keeps none, writes format 1, and so orders by
    // the oldest revision kept: what the marked ones say of what there was then.
    let before = store(&c);
    assert!(!before.marked() && before.born("ConfigMap/default/first").is_none());
    let written: serde_json::Value =
        serde_json::from_slice(&std::fs::read(behind.0.join("snapshot.json")).unwrap()).unwrap();
    assert_eq!(written["format"], 1);
    let mut marked = before.clone();
    run(&mut marked, Command::Mark).unwrap();
    let oldest = before.history("ConfigMap/default/first").unwrap()[0].at;
    assert_eq!(marked.born("ConfigMap/default/first"), Some((0, oldest)));
}

/// The log file says format 2 from the entry that marks the store, and not before: a
/// kithd started on a format 1 state leaves a file the kithd before it reads.
#[test]
fn format_of_the_log_is_2_with_the_mark_and_not_before() {
    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};
    let scratch = Scratch::new();
    let path = scratch.0.join("log.redb");
    std::fs::write(scratch.0.join("snapshot.json"), r#"{"format":1}"#).unwrap();
    let entry = |index, command| Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, 1), index),
        payload: EntryPayload::Normal(command),
    };
    let made = Command::Apply {
        resources: vec![config("a", "1")],
        at: 100,
    };
    let log = Log::open(&path).unwrap();
    log.put([entry(1, made)]).unwrap();
    drop(log);
    assert_eq!(formats(&scratch.0).0, 1);
    let log = Log::open(&path).unwrap();
    log.put([entry(2, Command::Mark)]).unwrap();
    drop(log);
    assert_eq!(formats(&scratch.0).0, 2);
    // And stays: opened again, it is not put back.
    drop(Log::open(&path).unwrap());
    assert_eq!(formats(&scratch.0).0, 2);
}

/// A Mark after the store is in format 3 (the barrier a relayed write ends with) is a no-op
/// to the store, and leaves the log in format 3: a format 2 kithd still cannot read it.
#[test]
fn format_of_the_log_stays_3_after_a_mark_barrier() {
    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};
    let scratch = Scratch::new();
    let path = scratch.0.join("log.redb");
    std::fs::write(scratch.0.join("snapshot.json"), r#"{"format":1}"#).unwrap();
    let entry = |index, command| Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, 1), index),
        payload: EntryPayload::Normal(command),
    };
    let log = Log::open(&path).unwrap();
    log.put([entry(1, Command::Mark), entry(2, Command::MarkSigned)])
        .unwrap();
    drop(log);
    assert_eq!(formats(&scratch.0).0, 3);
    let log = Log::open(&path).unwrap();
    log.put([entry(3, Command::Mark)]).unwrap();
    drop(log);
    assert_eq!(formats(&scratch.0).0, 3);
    let log = Log::open(&path).unwrap();
    log.put([entry(4, Command::Mark)]).unwrap();
    drop(log);
    assert_eq!(formats(&scratch.0).0, 3);
    // A signed entry is not: before a MarkSigned it is refused at apply, a no-op, and the log
    // stays in the store's format (the leader takes none from another node until then, T-0779).
    let other = Scratch::new();
    std::fs::write(other.0.join("snapshot.json"), r#"{"format":1}"#).unwrap();
    let log = Log::open(&other.0.join("log.redb")).unwrap();
    log.put([entry(1, Command::Mark), entry(2, signed("ann", 1000, 1, Command::Mark))])
        .unwrap();
    drop(log);
    assert_eq!(formats(&other.0).0, 2);
    // And the store: marked again, still in format 3.
    let mut store = Store::default();
    run(&mut store, Command::MarkSigned).unwrap();
    run(&mut store, Command::Mark).unwrap();
    assert_eq!(crate::format_of(&store), 3);
}

/// Format 4 (every node checks signed entries) is the MarkChecked's, in the log and the store,
/// and the marks before it, sent again as barriers, leave both in 4 (T-0783).
#[test]
fn format_of_the_log_is_4_with_mark_checked_and_stays() {
    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};
    let scratch = Scratch::new();
    let path = scratch.0.join("log.redb");
    std::fs::write(scratch.0.join("snapshot.json"), r#"{"format":1}"#).unwrap();
    let entry = |index, command| Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, 1), index),
        payload: EntryPayload::Normal(command),
    };
    let log = Log::open(&path).unwrap();
    log.put([entry(1, Command::Mark), entry(2, Command::MarkSigned)])
        .unwrap();
    drop(log);
    assert_eq!(formats(&scratch.0).0, 3);
    let log = Log::open(&path).unwrap();
    log.put([
        entry(3, Command::MarkChecked),
        entry(4, Command::Mark),
        entry(5, Command::MarkSigned),
    ])
    .unwrap();
    drop(log);
    assert_eq!(formats(&scratch.0).0, 4);
    let mut store = Store::default();
    run(&mut store, Command::MarkSigned).unwrap();
    assert_eq!(crate::format_of(&store), 3);
    run(&mut store, Command::MarkChecked).unwrap();
    run(&mut store, Command::Mark).unwrap();
    run(&mut store, Command::MarkSigned).unwrap();
    assert!(store.checking() && store.signing() && store.marked());
    assert_eq!(crate::format_of(&store), 4);
    // An import keeps it: what comes in is a store, not the cluster's format.
    run(
        &mut store,
        Command::Import {
            store: Store::default(),
        },
    )
    .unwrap();
    assert_eq!(crate::format_of(&store), 4);
}

/// Two nodes fed one log, a signed entry in it the check at apply refuses: both stores end
/// equal, and equal to one fed the log without that entry. The check is asked of nothing
/// before the store is in format 3: what comes before applies as it did.
#[test]
fn signed_entry_refused_is_nothing_on_both_stores() {
    use openraft::storage::RaftStateMachine;
    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};
    use std::sync::atomic::AtomicUsize;
    let made = |name: &str, at| Command::Apply {
        resources: vec![config(name, "1")],
        at,
    };
    let commands = vec![
        made("a", 100),
        // (Before the mark: refused by the store itself, the check not asked.)
        signed("ann", 1000, 1, made("early", 150)),
        Command::Mark,
        Command::MarkSigned,
        signed("ann", 1000, 2, made("b", 200)),
        made("c", 300),
        Command::Mark,
    ];
    let entry = |(index, command)| Entry {
        log_id: LogId::new(CommittedLeaderId::new(4, 9), index as u64 + 1),
        payload: EntryPayload::Normal(command),
    };
    let entries: Vec<Entry<TypeConfig>> = commands.into_iter().enumerate().map(entry).collect();
    let asked = Arc::new(AtomicUsize::new(0));
    let refusing = |asked: Arc<AtomicUsize>| -> crate::Check {
        Arc::new(move |store, command, leader| {
            assert!(store.signing() && leader == 9);
            asked.fetch_add(1, Ordering::Relaxed);
            match command {
                Command::Signed { .. } => Err(Error::Invalid("refused: not checked".into())),
                _ => Ok(()),
            }
        })
    };
    let (one, two, without) = (Scratch::new(), Scratch::new(), Scratch::new());
    let store = |machine: &Machine| machine.state.lock().unwrap().store.clone();
    let mut a = Machine::open(&one.0, Arc::new(|| {}), refusing(asked.clone())).unwrap();
    let mut b = Machine::open(&two.0, Arc::new(|| {}), refusing(Arc::new(AtomicUsize::new(0)))).unwrap();
    let mut c = Machine::open(&without.0, Arc::new(|| {}), any()).unwrap();
    let replies = block(async {
        // (One at a time on the second node: the same.)
        for entry in &entries {
            b.apply([entry.clone()]).await.unwrap();
        }
        let kept = |entry: &&Entry<TypeConfig>| ![2, 5].contains(&entry.log_id.index);
        c.apply(entries.iter().filter(kept).cloned().collect::<Vec<_>>())
            .await
            .unwrap();
        a.apply(entries.clone()).await.unwrap()
    });
    assert!(
        matches!(&replies[1], Err(Error::Invalid(why)) if why.contains("format 3")),
        "{:?}",
        replies[1]
    );
    assert!(matches!(&replies[4], Err(Error::Invalid(why)) if why == "refused: not checked"));
    assert!(
        replies
            .iter()
            .enumerate()
            .all(|(n, reply)| [1, 4].contains(&n) || reply.is_ok())
    );
    // Asked of the three entries from the mark on, and of nothing before.
    assert_eq!(asked.load(Ordering::Relaxed), 3);
    assert_eq!(store(&a), store(&b));
    assert_eq!(store(&a), store(&c));
    assert!(store(&a).get("ConfigMap/default/b").is_none());
    assert_eq!(store(&a).born("ConfigMap/default/c"), Some((6, 300)));
    // The nonce of the refused entry was not taken.
    assert!(
        serde_json::to_value(store(&a)).unwrap()["signers"]
            .as_object()
            .unwrap()
            .is_empty()
    );
}

/// A signed entry refused changes no key, whatever it wraps: a signed import refused (before
/// format 3, its nonce seen, inside another, or by the check at apply) leaves what a reader
/// reads again as it was, rather than sending every reader to read the whole store.
#[test]
fn signed_refused_changes_no_keys() {
    use openraft::storage::RaftStateMachine;
    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};
    let made = |name: &str| Command::Apply {
        resources: vec![config(name, "1")],
        at: 100,
    };
    let import = || Command::Import {
        store: Store::default(),
    };
    let commands = vec![
        made("a"),
        signed("ann", 1000, 1, import()),
        Command::MarkSigned,
        signed("ann", 1000, 1, made("b")),
        signed("ann", 1000, 1, import()),
        signed("ann", 1000, 2, signed("ann", 1000, 3, import())),
        Command::Signed {
            header: "v1; who=ann".into(),
            method: "POST".into(),
            path: "/v1/apply".into(),
            body: String::new(),
            command: Box::new(import()),
        },
    ];
    let entry = |(index, command)| Entry {
        log_id: LogId::new(CommittedLeaderId::new(4, 9), index as u64 + 1),
        payload: EntryPayload::Normal(command),
    };
    let entries: Vec<Entry<TypeConfig>> = commands.into_iter().enumerate().map(entry).collect();
    let both = ["ConfigMap/default/a", "ConfigMap/default/b"];
    let dir = Scratch::new();
    let mut machine = Machine::open(&dir.0, Arc::new(|| {}), any()).unwrap();
    let replies = block(async { machine.apply(entries.clone()).await.unwrap() });
    let refused: Vec<_> = replies.iter().map(Result::is_err).collect();
    assert_eq!(refused, [false, true, false, false, true, true, true], "{replies:?}");
    let touched = |machine: &Machine| {
        let state = machine.state.lock().unwrap();
        state
            .touched(0)
            .map(|keys| keys.into_iter().map(String::from).collect::<Vec<_>>())
    };
    assert_eq!(touched(&machine), Some(both.map(String::from).to_vec()));
    // Refused by the check at apply: the same.
    let refusing: crate::Check = Arc::new(|_, command, _| match command {
        Command::Signed { command, .. } if matches!(**command, Command::Import { .. }) => {
            Err(Error::Invalid("refused".into()))
        }
        _ => Ok(()),
    });
    let dir = Scratch::new();
    let mut machine = Machine::open(&dir.0, Arc::new(|| {}), refusing).unwrap();
    let entries = [&entries[..4], &[entry((4, signed("ann", 1000, 9, import())))]].concat();
    let replies = block(async { machine.apply(entries).await.unwrap() });
    assert!(replies[4].is_err());
    assert_eq!(touched(&machine), Some(both.map(String::from).to_vec()));
}

/// The signers' book: a nonce seen is refused and changes nothing, one whose `expires` is
/// five minutes or more before the signer's newest is refused, and nonces that old are dropped.
#[test]
fn signed_nonce_seen_is_a_no_op() {
    let made = |name: &str| Command::Apply {
        resources: vec![config(name, "1")],
        at: 100,
    };
    let mut store = Store::default();
    run(&mut store, Command::MarkSigned).unwrap();
    let nonces = |store: &Store, who: &str| {
        let book = serde_json::to_value(store).unwrap()["signers"][who][1].clone();
        let nonces = book.as_object().cloned().unwrap_or_default();
        nonces.keys().map(|nonce| nonce[30..].to_string()).collect::<Vec<_>>()
    };
    let refused = |store: &mut Store, command: Command, why: &str| {
        let before = store.clone();
        let reply = run(store, command);
        assert!(
            matches!(&reply, Err(Error::Invalid(said)) if said.contains(why)),
            "{reply:?}"
        );
        assert_eq!(*store, before);
    };
    run(&mut store, signed("ann", 1000, 1, made("a"))).unwrap();
    // Seen: refused, and nothing of it is done.
    refused(&mut store, signed("ann", 1000, 1, made("b")), "seen");
    assert!(store.get("ConfigMap/default/b").is_none());
    // Each signer's book is its own.
    run(&mut store, signed("bob", 1000, 1, made("b"))).unwrap();
    // Ann's newest moves on: a nonce five minutes before it is refused, one less is taken,
    // and the nonce of the first (1000, five minutes before 1300) is dropped.
    run(&mut store, signed("ann", 1300, 2, made("c"))).unwrap();
    assert_eq!(nonces(&store, "ann"), ["02"]);
    refused(&mut store, signed("ann", 1000, 3, made("d")), "five minutes");
    run(&mut store, signed("ann", 1001, 4, made("d"))).unwrap();
    assert_eq!(nonces(&store, "ann"), ["02", "04"]);
    // The dropped nonce is still refused: its expires is too old.
    refused(&mut store, signed("ann", 1000, 1, made("e")), "five minutes");
    // Bob's far-future expires spoils only his own key.
    run(&mut store, signed("bob", u64::MAX, 5, made("e"))).unwrap();
    refused(&mut store, signed("bob", 2000, 6, made("f")), "five minutes");
    run(&mut store, signed("ann", 1300, 7, made("f"))).unwrap();
    // A refused command still takes its nonce: it cannot be sent again once it would work.
    let bad = Command::Delete {
        key: "ConfigMap/default/nothing".into(),
    };
    assert!(matches!(
        run(&mut store, signed("ann", 1300, 8, bad)),
        Err(Error::NotFound(_))
    ));
    assert_eq!(nonces(&store, "ann"), ["02", "04", "07", "08"]);
    // A header that does not read, and one signed inside another: refused, nothing taken.
    let mut torn = signed("ann", 1300, 9, made("g"));
    if let Command::Signed { header, .. } = &mut torn {
        *header = header.replace("nonce=", "nonse=");
    }
    refused(&mut store, torn, "x-kith-signed");
    let twice = signed("ann", 1300, 10, signed("ann", 1300, 11, made("g")));
    refused(&mut store, twice, "inside");
    // Below format 3 there is no book: a signed entry is refused, the store left as it was.
    let mut old = Store::default();
    refused(&mut old, signed("ann", 1000, 1, made("a")), "format 3");
}

/// A signed Import replaces the store, not the signers' book: sent again with the same nonce,
/// it is refused as seen (the book came across the first), and the store is still in format 3.
#[test]
fn signed_import_keeps_the_book() {
    let mut store = Store::default();
    run(&mut store, Command::MarkSigned).unwrap();
    let import = || {
        let mut imported = Store::default();
        imported.apply(config("in", "1")).unwrap();
        signed("ann", 1000, 1, Command::Import { store: imported })
    };
    run(&mut store, import()).unwrap();
    assert!(store.signing() && store.get("ConfigMap/default/in").is_some());
    let again = run(&mut store, import());
    assert!(
        matches!(&again, Err(Error::Invalid(said)) if said.contains("seen")),
        "{again:?}"
    );
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
    let open = || Machine::open(&scratch.0, Arc::new(|| {}), any());
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
    assert_eq!(format(), Some("1".to_string()));
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
    let mut machine = Machine::open(&scratch.0, Arc::new(|| {}), any()).unwrap();
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
    let again = Machine::open(&scratch.0, Arc::new(|| {}), any()).unwrap();
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
            let replica = crate::open(dir, id, net.clone(), Arc::new(|| {}), any()).await.unwrap();
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
        let replica = crate::open(&dir.0, 1, net.clone(), Arc::new(|| {}), any())
            .await
            .unwrap();
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
        let mut machine = Machine::open(dir, Arc::new(|| {}), any()).unwrap();
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
        let replica = crate::open(&dir.0, 1, net.clone(), Arc::new(|| {}), any())
            .await
            .unwrap();
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

        let replica = crate::open(&dir.0, 1, net.clone(), Arc::new(|| {}), any())
            .await
            .unwrap();
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
        let replica = crate::open(&dir.0, 1, Net::default(), Arc::new(|| {}), any())
            .await
            .unwrap();
        caught_up(&replica.raft, 3, 3).await;
        replica.raft.shutdown().await.unwrap();
        drop(replica);
        assert!(!holds(&dir.0, WRAPPED).await);
    });
}

/// A store that has Node/a at `address`, and one change of its kind.
fn node_at(address: &str) -> Store {
    let mut store = Store::default();
    store.put(
        serde_json::from_value(serde_json::json!({
            "apiVersion": "kith.dev/v1", "kind": "Node",
            "metadata": { "name": "a" }, "spec": {}, "status": { "address": address },
        }))
        .unwrap(),
    );
    store
}

/// A snapshot another node sends, at `index`, with `store` as its state.
async fn install(machine: &mut Machine, store: &Store, index: u64) {
    use openraft::storage::RaftStateMachine;
    let meta = openraft::SnapshotMeta {
        last_log_id: Some(openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), index)),
        last_membership: Default::default(),
        snapshot_id: format!("sent-{index}"),
    };
    let mut state = serde_json::to_value(crate::State::default()).unwrap();
    state["store"] = serde_json::to_value(store).unwrap();
    let sent = std::io::Cursor::new(serde_json::to_vec(&state).unwrap());
    machine.install_snapshot(&meta, Box::new(sent)).await.unwrap();
}

/// A store brought in whole (Import, or a snapshot) counts the kinds it changes on from the store
/// it replaces: a reader that kept the counts sees a changed Node come in.
#[test]
fn a_brought_in_store_moves_the_counts_of_the_kinds_it_changes() {
    let mut store = node_at("10.1.2.3:7443");
    let before = store.changes("Node");
    run(
        &mut store,
        Command::Import {
            store: node_at("10.9.9.9:7443"),
        },
    )
    .unwrap();
    assert!(
        store.changes("Node") > before,
        "Import: {before} then {}",
        store.changes("Node")
    );

    let dir = Scratch::new();
    block(async {
        let mut machine = Machine::open(&dir.0, Arc::new(|| {}), any()).unwrap();
        install(&mut machine, &node_at("10.1.2.3:7443"), 3).await;
        let before = machine.state.lock().unwrap().store.changes("Node");
        install(&mut machine, &node_at("10.9.9.9:7443"), 4).await;
        let after = machine.state.lock().unwrap().store.changes("Node");
        assert!(after > before, "a snapshot: {before} then {after}");
    });
}

/// The same of a snapshot another node sends, and of a store brought in whole.
#[test]
fn forgotten_key_kept_from_before_is_cut_as_it_comes_in() {
    use openraft::storage::RaftStateMachine;
    let dir = Scratch::new();
    block(async {
        let mut machine = Machine::open(&dir.0, Arc::new(|| {}), any()).unwrap();
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
        let replica = crate::open(&dir.0, 1, net.clone(), Arc::new(|| {}), any())
            .await
            .unwrap();
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
        let replica = crate::open(&dir.0, 1, net.clone(), Arc::new(|| {}), any())
            .await
            .unwrap();
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

/// A store brought in over one that holds a NodeKey the new one lacks: the log, which has the
/// write of that key still, is dropped up to the Import as it is applied, with no restart.
/// (kithd brings a store in only where there is none; this holds for a caller that does not.)
#[test]
fn import_over_a_key_scrubs_the_log() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let dir = Scratch::new();
        let net = Net::default();
        let replica = crate::open(&dir.0, 1, net.clone(), Arc::new(|| {}), any())
            .await
            .unwrap();
        net.0.lock().unwrap().insert(1, replica.raft.clone());
        let members = [(1, openraft::BasicNode::default())];
        replica
            .raft
            .initialize(members.into_iter().collect::<std::collections::BTreeMap<_, _>>())
            .await
            .unwrap();
        let resources = vec![node_key(WRAPPED), config("a", "1")];
        write(&net, Command::Apply { resources, at: 1 }).await;
        let mut store = Store::default();
        store.apply(config("b", "2")).unwrap();
        let imported = write(&net, Command::Import { store }).await;
        caught_up(&replica.raft, imported, imported).await;
        replica.raft.shutdown().await.unwrap();
        drop(replica);
        assert!(!holds(&dir.0, WRAPPED).await);
    });
}
