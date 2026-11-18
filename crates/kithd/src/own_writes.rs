//! What a control node may write as itself (`raft.rs` `write`, a write that names no caller):
//! its own Node's status, its units' status, the Devices, Blobs, NodeKey and Volume syncs it
//! holds. Default-deny: a kind that is not in [`CLASSES`] is refused, and a refusal is audited
//! by the node's name and said on the console (`refused a control node's own write`).

use crate::worker::{self, Worker};
use kith_api::Resource;
use kith_api::store::Store;
use kith_store::Command;
use serde_json::{Map, Value};

/// Every kind kith knows, and whether a control node may write one of its own as itself. A kind
/// marked no is refused whatever it names; one marked yes is still checked field by field.
pub const CLASSES: &[(&str, bool)] = &[
    ("Cluster", false),
    ("Node", true),
    ("Namespace", false),
    ("Workload", true),
    ("NodeWorkload", true),
    ("Job", true),
    ("CronJob", false),
    ("Service", false),
    ("DNSZone", false),
    ("DNSBlockList", false),
    ("DNSRecord", false),
    ("NetworkPolicy", false),
    ("Exit", false),
    ("AccessLevel", false),
    ("RemotePeer", false),
    ("Volume", true),
    ("VolumeClaim", false),
    ("Blob", true),
    ("Backup", true),
    ("Image", true),
    ("Share", false),
    ("Secret", false),
    ("ConfigMap", false),
    ("Seat", true),
    ("Device", true),
    ("DeviceClaim", false),
    ("Package", false),
    ("Release", false),
    ("Repository", false),
    ("Source", false),
    ("OSRelease", false),
    ("UpdatePlan", false),
    ("NodeKey", true),
    ("KindDefinition", false),
    ("Role", false),
    ("RoleBinding", false),
    ("Identity", false),
    ("KubeObject", false),
];

type Fields = Map<String, Value>;

fn refused(what: impl std::fmt::Display, why: impl std::fmt::Display) -> String {
    format!("{what}: {why}: a control node writes as itself only what it holds")
}

/// Is `kind` one a control node may write as itself? Unknown kinds are not.
fn class(kind: &str) -> Result<(), String> {
    match CLASSES.iter().find(|(known, _)| *known == kind) {
        Some((_, true)) => Ok(()),
        _ => Err(refused(kind, "a control node does not write this kind as itself")),
    }
}

/// The kind of a store key (`Kind/namespace/name`, or `Kind/name`).
fn kind_of(key: &str) -> &str {
    key.split('/').next().unwrap_or(key)
}

/// A control node's own Node: any status field, its raft id only as its name gives it (the boot
/// writes that id again, and a follower forwards the write to the leader, which would otherwise
/// hold it as the node's own write), and no mesh key another node holds (as a worker's may not).
fn own_node(store: &Store, name: &str, key: &str, fields: &Fields) -> Result<(), String> {
    let id = kith_store::node_id(name).to_string();
    match fields.get("raftId") {
        Some(said) if said.as_str() != Some(id.as_str()) => Err(refused(key, "the raft id is the one its name gives")),
        _ => worker::mesh_key_elsewhere(store, name, key, fields),
    }
}

/// A resource the control node `who` applies as its own: its own Node only where it has none
/// yet (and no spec), else what a worker may apply of its own.
fn applied(store: &Store, who: &Worker, resource: &mut Resource) -> Result<(), String> {
    class(&resource.kind)?;
    if resource.kind == "Node" {
        let none = store.get(&format!("Node/{}", who.name)).is_none();
        let empty = resource.spec.as_object().is_some_and(|spec| spec.is_empty());
        return match resource.metadata.name == who.name && none && empty {
            true => Ok(()),
            false => Err(refused(
                "a Node",
                "a control node makes its own Node only where it has none",
            )),
        };
    }
    worker::apply(store, who, resource)
}

/// `command` as it is given to Raft for the control node `name`, which names no caller, or why not.
/// What a control node writes as itself is held to the same rules a worker's own writes are, with
/// its own Node's status open to any field (its raft id only as its name gives it), and the kinds
/// of [`CLASSES`] only.
pub fn checked(shared: &crate::Shared, name: &str, command: Command) -> Result<Command, String> {
    let blobs = crate::blobs::dir(shared);
    let held = |blob: &str| blobs.join(blob).exists();
    let prefix = shared
        .cluster
        .as_ref()
        .map(|cluster| crate::mesh::prefix(&cluster.me.ca));
    let who = Worker {
        name,
        prefix,
        held: &held,
    };
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let store = &state.store;
    let mine = format!("Node/{name}");
    match command {
        Command::Patch { statuses } => {
            for (key, fields) in &statuses {
                if *key == mine {
                    own_node(store, name, key, fields)?;
                } else {
                    class(kind_of(key))?;
                    worker::patch(store, &who, key, fields)?;
                }
            }
            Ok(Command::Patch { statuses })
        }
        Command::Status { statuses } => {
            for (key, said) in &statuses {
                class(kind_of(key))?;
                worker::status(store, &who, key, said.as_ref())?;
            }
            Ok(Command::Status { statuses })
        }
        Command::Report { node, statuses } if node == name => {
            let mut taken = Vec::with_capacity(statuses.len());
            for (key, said) in statuses {
                class(kind_of(&key))?;
                let said = worker::report(store, &who, &key, said)?;
                taken.push((key, said));
            }
            Ok(Command::Report { node, statuses: taken })
        }
        Command::Report { node, .. } => Err(refused(
            format!("a report in node {node}'s name"),
            "it is not this node",
        )),
        Command::Apply { mut resources, at } => {
            for resource in &mut resources {
                applied(store, &who, resource)?;
            }
            Ok(Command::Apply { resources, at })
        }
        Command::Delete { key } => {
            class(kind_of(&key))?;
            worker::delete(store, &who, &key)?;
            Ok(Command::Delete { key })
        }
        Command::Rollback { key, .. } => Err(refused(key, "a rollback is not a control node's own write")),
        Command::Import { .. } => Err(refused("a whole store", "only an admin brings one in")),
        // (A follower's relayed write ends with a Mark, the barrier it waits for: a no-op where the
        // store is marked already. Unmarked, it is the leader's to make.)
        Command::Mark if store.marked() => Ok(Command::Mark),
        Command::Mark => Err(refused("the store's format", "only the leader changes it")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Shared;
    use crate::cluster::Peer;
    use crate::cluster::pinned_peer::{at, node, shared_with};
    use crate::cluster::{Cluster, listen, node_router};
    use crate::pki;
    use kith_store::Command;
    use kith_store::openraft::BasicNode;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    /// Each kind kith knows is classified once: a new kind fails here until it is.
    #[test]
    fn every_kind_is_classified() {
        for info in kith_api::KINDS {
            let said = CLASSES.iter().filter(|(kind, _)| *kind == info.kind).count();
            assert_eq!(
                said, 1,
                "{} is classified {said} times: say whether a control node writes it as itself",
                info.kind
            );
        }
        assert_eq!(
            CLASSES.len(),
            kith_api::KINDS.len(),
            "a classified kind kith does not know"
        );
    }

    /// Through the write route: a control node's own write, naming no caller, is let through for
    /// what it holds, and refused and audited by its name for what only an admin may write; a
    /// worker is still held to what it may write, and no control node's kind.
    #[tokio::test]
    async fn own_writes_let_a_control_node_write_what_it_holds_and_refuse_the_rest() {
        let ca = pki::Ca::create().unwrap();
        let (c, w, k) = (node(&ca, "own-c"), node(&ca, "own-w"), node(&ca, "own-k"));
        let shared: Arc<Shared> = shared_with("own", c.clone(), &[]).await;
        for (name, spec) in [("own-w", "{trust: worker}"), ("own-k", "{}")] {
            let text = format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{name: {name}}}\nspec: {spec}\n");
            let node = kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap();
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(node).unwrap();
            // Joined: a Node made by hand is not let in.
            let joined = serde_json::json!({ "raftId": kith_store::node_id(name).to_string() });
            store.set_status(&format!("Node/{name}"), Some(joined)).unwrap();
        }
        let volume = "apiVersion: kith.dev/v1\nkind: Volume\nmetadata: {name: data, namespace: default}\nspec: {node: own-c, path: d}\n";
        let volume = kith_api::Resource::from_source(volume).unwrap().remove(0).unwrap();
        {
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(volume).unwrap();
            let replicas = serde_json::json!({ "replicas": ["own-k"] });
            store.set_status("Volume/default/data", Some(replicas)).unwrap();
        }
        let id = shared.raft.metrics().borrow().id;
        shared
            .raft
            .initialize(BTreeMap::from([(id, BasicNode::new(""))]))
            .await
            .unwrap();
        let leads = shared.raft.wait(Some(Duration::from_secs(30)));
        leads.current_leader(id, "leads").await.unwrap();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap().to_string();
        let listener = listen(tcp, pki::server_config(&c).unwrap()).unwrap();
        let app = node_router(shared.clone()).into_make_service_with_connect_info::<Peer>();
        tokio::spawn(async move { drop(axum::serve(listener, app).await) });
        let client = |who: &pki::Identity| {
            let cluster = Cluster::new(who.clone(), None).unwrap();
            cluster.to(&at("own-c", &address, None)).unwrap()
        };
        let (to_w, to_k) = (client(&w), client(&k));
        let url = format!("https://{address}/v1/raft/write");
        let patch = |key: &str, fields: serde_json::Value| Command::Patch {
            statuses: vec![(key.to_string(), fields.as_object().unwrap().clone())],
        };

        // Its own Node's status, a Volume it is a replica of, and its units (none here).
        let own_id = kith_store::node_id("own-k").to_string();
        let allowed = [
            patch("Node/own-k", serde_json::json!({ "os": "x" })),
            // Its boot writes its raft id again: the id its name gives, forwarded to the leader.
            patch("Node/own-k", serde_json::json!({ "raftId": own_id })),
            patch("Volume/default/data", serde_json::json!({ "synced": { "own-k": 5 } })),
            Command::Report {
                node: "own-k".into(),
                statuses: Vec::new(),
            },
        ];
        for command in &allowed {
            let said = to_k
                .post(&url)
                .json(command)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert!(said.contains("Ok"), "{said}");
        }

        // What only an admin may write, and another node's Node: refused, each one audited by name.
        let refused = [
            Command::Delete {
                key: "Cluster/cluster".into(),
            },
            Command::Delete {
                key: "Secret/default/s".into(),
            },
            Command::Delete {
                key: "Deployment/default/d".into(),
            },
            patch("Node/own-w", serde_json::json!({ "os": "x" })),
            patch("Node/own-k", serde_json::json!({ "raftId": "1" })),
        ];
        for command in &refused {
            let said = to_k
                .post(&url)
                .json(command)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert!(said.contains("Err"), "{said}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let of_k = shared
            .audit
            .tail(200)
            .unwrap()
            .iter()
            .filter(|e| e["who"] == "node own-k" && e["ok"] == false)
            .count();
        assert_eq!(of_k, refused.len(), "each refusal is in the audit log by its name");

        // A worker: no Cluster, whatever it names.
        let theirs = Command::Delete {
            key: "Cluster/cluster".into(),
        };
        let said = to_w
            .post(&url)
            .json(&theirs)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(said.contains("Err"), "{said}");
    }

    /// A follower's relayed write ends with a Mark (`raft.rs` `relayed`): the barrier it waits
    /// for. On a store marked already it is a no-op and let through; an unmarked store is marked
    /// by the leader alone.
    #[tokio::test]
    async fn own_writes_let_a_mark_through_only_where_the_store_is_marked() {
        let ca = pki::Ca::create().unwrap();
        let shared: Arc<Shared> = shared_with("own-mark", node(&ca, "mark-c"), &[]).await;
        assert!(checked(&shared, "mark-c", Command::Mark).is_err());
        shared.store.lock().unwrap().store.mark();
        assert!(checked(&shared, "mark-c", Command::Mark).is_ok());
    }

    /// Another node's mesh key, said in a control node's own Node, is refused as a worker's is:
    /// two nodes that say one key are both left out of the mesh.
    #[tokio::test]
    async fn own_writes_refuse_a_mesh_key_another_node_holds() {
        let ca = pki::Ca::create().unwrap();
        let shared: Arc<Shared> = shared_with("own-mesh", node(&ca, "mesh-c"), &[]).await;
        {
            let text = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: {name: mesh-o}\nspec: {}\n";
            let other = kith_api::Resource::from_source(text).unwrap().remove(0).unwrap();
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(other).unwrap();
            let mesh = serde_json::json!({ "mesh": { "key": "QUFB", "port": 51820 } });
            store.set_status("Node/mesh-o", Some(mesh)).unwrap();
        }
        let own = |key: &str| Command::Patch {
            statuses: vec![(
                "Node/mesh-c".to_string(),
                serde_json::json!({ "mesh": { "key": key, "port": 51820 } })
                    .as_object()
                    .unwrap()
                    .clone(),
            )],
        };
        assert!(checked(&shared, "mesh-c", own("QUFB")).is_err());
        assert!(checked(&shared, "mesh-c", own("TkVX")).is_ok());
    }
}
