use crate::{Command, Done, Log, Machine, TypeConfig, node_id, run};
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
