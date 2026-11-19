//! What a control node may write as itself (`raft.rs` `write`, a write that names no caller):
//! its own Node's status, its units' status, the Devices, Blobs, NodeKey and Volume syncs it
//! holds. (A Cluster's `status.home` is the leader's, written locally, never through here.)
//! Default-deny: a kind that is not in [`CLASSES`] is refused, and a refusal is audited
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
    raft_id(name, key, fields)?;
    // Which node holds the CA ([`holds_ca`]) is what the CA node's first start wrote, as the one
    // node, leading: said again the same, never changed by a node of itself.
    if let Some(said) = fields.get("ca") {
        let held = store
            .get(key)
            .and_then(|node| node.status.as_ref())
            .map(|status| &status["ca"]);
        if held != Some(said) {
            return Err(refused(key, "which node holds the CA is not a node's own to say"));
        }
    }
    worker::mesh_key_elsewhere(store, name, key, fields)
}

/// A Node's raft id, if it says one, is the one its name gives (`kith_store::node_id`).
fn raft_id(name: &str, key: &str, fields: &Fields) -> Result<(), String> {
    let id = kith_store::node_id(name).to_string();
    match fields.get("raftId") {
        Some(said) if said.as_str() != Some(id.as_str()) => Err(refused(key, "the raft id is the one its name gives")),
        _ => Ok(()),
    }
}

/// Whether `who` holds the CA: its own Node's status says so (`ca`, which the node that makes
/// the CA writes at its start, `main.rs`). The store records which node that is.
fn holds_ca(store: &Store, who: &Worker) -> bool {
    let status = store
        .get(&format!("Node/{}", who.name))
        .and_then(|node| node.status.as_ref());
    status.is_some_and(|status| status["ca"] == true)
}

/// A Node the CA-holding control node `who` admits by its join (`cluster.rs` `join`): a new name,
/// with the spec the join gives it and no other field. Admitting a node by a signed write is
/// layer 3's (`docs/adr-taken-node.md`, "What stays open").
fn admits(store: &Store, who: &Worker, resource: &Resource) -> bool {
    let spec = resource.spec.as_object().is_some_and(|spec| {
        spec.iter().all(|(field, value)| match field.as_str() {
            "roaming" | "ingress" => value.as_bool() == Some(true),
            "trust" => value.as_str() == Some("worker"),
            _ => false,
        })
    });
    let new = store.get(&format!("Node/{}", resource.metadata.name)).is_none();
    holds_ca(store, who) && new && resource.metadata.name != who.name && spec
}

/// What `cluster.rs` `register` says of a Node the CA-holding control node `who` admits: its
/// address, its raft id, its certificate's print, its mesh key and whether it is a view. Once only:
/// a Node that has a certificate is not changed this way.
fn registers(store: &Store, who: &Worker, name: &str, key: &str, fields: &Fields) -> Result<(), String> {
    let node = store.get(key);
    let registered = node
        .and_then(|node| node.status.as_ref())
        .is_some_and(|status| status.get("certificate").is_some());
    if !holds_ca(store, who) || node.is_none() || registered {
        return Err(refused(
            key,
            "a Node is registered by its join, once, by the control node that holds the CA",
        ));
    }
    let fields_ok = fields
        .keys()
        .all(|field| ["address", "raftId", "certificate", "mesh", "view"].contains(&field.as_str()));
    if !fields_ok {
        return Err(refused(
            key,
            "a join gives a Node its address, raft id, certificate, mesh and view alone",
        ));
    }
    raft_id(name, key, fields)?;
    worker::mesh_key_elsewhere(store, name, key, fields)
}

/// A resource the control node `who` applies as its own: its own Node only where it has none
/// yet (and no spec), or a Node it admits by its join; else what a worker may apply of its own.
fn applied(store: &Store, who: &Worker, resource: &mut Resource) -> Result<(), String> {
    class(&resource.kind)?;
    if resource.kind == "Node" {
        let none = store.get(&format!("Node/{}", who.name)).is_none();
        let empty = resource.spec.as_object().is_some_and(|spec| spec.is_empty());
        let own = resource.metadata.name == who.name && none && empty;
        return match own || admits(store, who, resource) {
            true => Ok(()),
            false => Err(refused(
                "a Node",
                "a control node makes its own Node only where it has none, or admits a new one by its join",
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
                } else if let Some(joined) = key.strip_prefix("Node/") {
                    registers(store, &who, joined, key, fields)?;
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
        // The store's format is the leader's to change: a mark it has made already is the barrier
        // an older follower's relayed write ends with, a no-op, and taken (this build's is an
        // empty Patch). A signed entry is the leader's to write from the request it checked:
        // never another node's own write.
        Command::Mark | Command::MarkSigned | Command::MarkChecked => {
            let made = match command {
                Command::Mark => 2,
                Command::MarkSigned => 3,
                _ => 4,
            };
            match kith_store::format_of(store) >= made {
                true => Ok(command),
                false => Err(refused("the store's format", "only the leader changes it")),
            }
        }
        Command::Signed { .. } => Err(refused("a signed change", "only the leader writes them")),
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

    /// The store's format is the leader's to change, and a signed entry the leader's to write: a
    /// Signed is never a control node's own write, and a mark only once the store has made it
    /// (the barrier an older follower's relayed write ends with; this build's is an empty Patch).
    #[tokio::test]
    async fn raft_write_refuses_a_format_or_signed_entry_as_a_control_nodes_own_write() {
        let ca = pki::Ca::create().unwrap();
        let shared: Arc<Shared> = shared_with("own-signed", node(&ca, "sign-c"), &[]).await;
        let signed = || Command::Signed {
            header: String::new(),
            method: "POST".into(),
            path: "/v1/apply".into(),
            body: String::new(),
            command: Box::new(Command::Patch { statuses: vec![] }),
        };
        for format in 1..=4 {
            match format {
                2 => shared.store.lock().unwrap().store.mark(),
                3 => shared.store.lock().unwrap().store.sign(),
                4 => shared.store.lock().unwrap().store.check(),
                _ => {}
            }
            // A mark the store has made already is an older follower's barrier: taken, a no-op.
            for (made, command) in [(2, Command::Mark), (3, Command::MarkSigned), (4, Command::MarkChecked)] {
                match checked(&shared, "sign-c", command) {
                    Ok(_) => assert!(format >= made, "format {format}: format {made}'s mark taken"),
                    Err(said) => assert!(format < made && said.contains("only the leader changes it"), "{said}"),
                }
            }
            let said = checked(&shared, "sign-c", signed()).unwrap_err();
            assert!(said.contains("only the leader writes"), "{said}");
            assert!(checked(&shared, "sign-c", Command::Patch { statuses: vec![] }).is_ok());
        }
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
            let mesh = serde_json::json!({ "mesh": { "key": "ab".repeat(32), "port": 51820 } });
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
        // (The same key in capitals, or any text that is no key, is refused too.)
        for refused in ["ab".repeat(32), "AB".repeat(32), "ab".repeat(31), "zz".repeat(32)] {
            assert!(checked(&shared, "mesh-c", own(&refused)).is_err(), "{refused}");
        }
        assert!(checked(&shared, "mesh-c", own(&"5a".repeat(32))).is_ok());
    }

    /// The key a node is to take next (T-1017) may be neither another node's key nor its next one:
    /// a node that says another's cannot make the others call that node by a key it does not hold.
    #[tokio::test]
    async fn own_writes_refuse_a_next_mesh_key_another_node_holds() {
        let ca = pki::Ca::create().unwrap();
        let shared: Arc<Shared> = shared_with("own-next", node(&ca, "next-c"), &[]).await;
        {
            let text = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: {name: next-o}\nspec: {}\n";
            let other = kith_api::Resource::from_source(text).unwrap().remove(0).unwrap();
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(other).unwrap();
            let mesh =
                serde_json::json!({ "mesh": { "key": "ab".repeat(32), "next": "cd".repeat(32), "port": 51820 } });
            store.set_status("Node/next-o", Some(mesh)).unwrap();
        }
        let own = |next: &str| Command::Patch {
            statuses: vec![(
                "Node/next-c".to_string(),
                serde_json::json!({ "mesh": { "key": "43".repeat(32), "next": next, "port": 51820 } })
                    .as_object()
                    .unwrap()
                    .clone(),
            )],
        };
        // (Another node's key in capitals is that key still, to what reads it: refused too.)
        for refused in ["ab".repeat(32), "cd".repeat(32), "AB".repeat(32), "Cd".repeat(32)] {
            assert!(checked(&shared, "next-c", own(&refused)).is_err(), "{refused}");
        }
        assert!(checked(&shared, "next-c", own(&"5a".repeat(32))).is_ok());
    }

    /// The join a control node that holds the CA makes (`cluster.rs` `join` and `register`), not
    /// the leader: a new name's Node and its status pass; a Node already there is not made again
    /// or patched once registered; a node that holds no CA, and any other field, are refused.
    #[tokio::test]
    async fn own_writes_let_the_ca_node_join_a_new_node_and_not_change_a_registered_one() {
        let ca = pki::Ca::create().unwrap();
        let shared: Arc<Shared> = shared_with("own-join", node(&ca, "join-c"), &[]).await;
        let resource = |name: &str, spec: serde_json::Value| {
            let node = serde_json::json!({
                "apiVersion": kith_api::API_VERSION, "kind": "Node", "metadata": { "name": name }, "spec": spec,
            });
            serde_json::from_value::<kith_api::Resource>(node).unwrap()
        };
        let apply = |name: &str, spec: serde_json::Value| Command::Apply {
            resources: vec![resource(name, spec)],
            at: kith_api::store::now(),
        };
        let patch = |name: &str, fields: serde_json::Value| Command::Patch {
            statuses: vec![(format!("Node/{name}"), fields.as_object().unwrap().clone())],
        };
        let register = |print: &str| {
            serde_json::json!({
                "address": "10.0.0.7:7", "raftId": kith_store::node_id("join-n").to_string(), "certificate": print,
            })
        };
        {
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(resource("join-c", serde_json::json!({}))).unwrap();
            store
                .set_status("Node/join-c", Some(serde_json::json!({ "ca": true })))
                .unwrap();
            store.apply(resource("join-o", serde_json::json!({}))).unwrap();
        }

        // `join`: the Node with the spec it gives, then `register`'s Node when it is not there yet.
        assert!(
            checked(
                &shared,
                "join-c",
                apply("join-n", serde_json::json!({ "roaming": true }))
            )
            .is_ok()
        );
        assert!(checked(&shared, "join-c", apply("join-n", serde_json::json!({}))).is_ok());
        assert!(
            checked(
                &shared,
                "join-c",
                apply("join-x", serde_json::json!({ "trust": "admin" }))
            )
            .is_err()
        );
        assert!(
            checked(&shared, "join-c", apply("join-o", serde_json::json!({}))).is_err(),
            "a Node there is not made again"
        );
        // Its status, once: the address, the raft id its name gives, and the certificate's print.
        shared
            .store
            .lock()
            .unwrap()
            .store
            .apply(resource("join-n", serde_json::json!({ "roaming": true })))
            .unwrap();
        assert!(checked(&shared, "join-c", patch("join-n", register("PRINT"))).is_ok());
        assert!(checked(&shared, "join-c", patch("join-o", serde_json::json!({ "os": "x" }))).is_err());
        let other_id = serde_json::json!({ "address": "10.0.0.7:7", "raftId": "1", "certificate": "PRINT" });
        assert!(
            checked(&shared, "join-c", patch("join-n", other_id)).is_err(),
            "a raft id its name does not give"
        );
        shared
            .store
            .lock()
            .unwrap()
            .store
            .set_status("Node/join-n", Some(register("PRINT")))
            .unwrap();
        assert!(
            checked(&shared, "join-c", patch("join-n", register("OTHER"))).is_err(),
            "a registered Node is not changed this way"
        );

        // Held to the CA: a control node that holds none admits no node.
        shared
            .store
            .lock()
            .unwrap()
            .store
            .apply(resource("join-f", serde_json::json!({})))
            .unwrap();
        assert!(checked(&shared, "join-f", apply("join-m", serde_json::json!({}))).is_err());
    }

    /// Through the write route: a write a node passes on for an admin (`x-kith-for: local
    /// socket`, the local socket's) is checked as the admin's and not as the node's own, so an
    /// Identity, or another node's NodeKey, that a control node could not write as itself goes
    /// through when the admin asked for it (`certificate`, `claim`, the lock and duress routes).
    #[tokio::test]
    async fn own_writes_let_an_admin_write_a_node_passes_on_go_through_as_the_admin() {
        let ca = pki::Ca::create().unwrap();
        let (c, k) = (node(&ca, "fwd-c"), node(&ca, "fwd-k"));
        let shared: Arc<Shared> = shared_with("own-fwd", c.clone(), &[]).await;
        {
            let store = &mut shared.store.lock().unwrap().store;
            for (name, spec) in [("fwd-k", "{}"), ("fwd-w", "{trust: worker}")] {
                let text = format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{name: {name}}}\nspec: {spec}\n");
                store
                    .apply(kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap())
                    .unwrap();
                let joined = serde_json::json!({ "raftId": kith_store::node_id(name).to_string() });
                store.set_status(&format!("Node/{name}"), Some(joined)).unwrap();
            }
            let key = "apiVersion: kith.dev/v1\nkind: NodeKey\nmetadata: {name: fwd-w}\nspec: {id: QUFB}\n";
            store
                .apply(kith_api::Resource::from_source(key).unwrap().remove(0).unwrap())
                .unwrap();
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
        let to_k = Cluster::new(k.clone(), None)
            .unwrap()
            .to(&at("fwd-c", &address, None))
            .unwrap();
        let url = format!("https://{address}/v1/raft/write");
        let own = |command: &Command| to_k.post(&url).json(command);
        let forwarded = |command: &Command| own(command).header(crate::access::FOR, "local socket");
        let said = |call: reqwest::RequestBuilder| async move { call.send().await.unwrap().text().await.unwrap() };

        let identity = "apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: fwd-user}\nspec: {}\n";
        let identity = Command::Apply {
            resources: vec![kith_api::Resource::from_source(identity).unwrap().remove(0).unwrap()],
            at: kith_api::store::now(),
        };
        assert!(
            said(own(&identity)).await.contains("Err"),
            "a node's own Identity is refused"
        );
        assert!(
            said(forwarded(&identity)).await.contains("Ok"),
            "an admin's, passed on, is let through"
        );

        let key = "apiVersion: kith.dev/v1\nkind: NodeKey\nmetadata: {name: fwd-w}\nspec: {id: QUFB, locked: true}\n";
        let key = Command::Apply {
            resources: vec![kith_api::Resource::from_source(key).unwrap().remove(0).unwrap()],
            at: kith_api::store::now(),
        };
        assert!(
            said(own(&key)).await.contains("Err"),
            "a node's own write of another node's NodeKey is refused"
        );
        assert!(
            said(forwarded(&key)).await.contains("Ok"),
            "an admin's lock of it, passed on, is let through"
        );
    }

    /// The holder of the house address is the leader, and its own writes never come through here
    /// (they are not forwarded): a write of a Cluster that is forwarded, status.home as the
    /// holder's own included, is a taken control node's and is refused.
    #[tokio::test]
    async fn own_writes_refuse_a_forwarded_home_status_and_every_other_write_of_a_cluster() {
        let ca = pki::Ca::create().unwrap();
        let shared: Arc<Shared> = shared_with("own-home", node(&ca, "home-c"), &[]).await;
        for (name, spec) in [("house", "{home: {address: 10.9.0.100/24}}"), ("bare", "{}")] {
            let text = format!("apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{name: {name}}}\nspec: {spec}\n");
            let cluster = kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap();
            shared.store.lock().unwrap().store.apply(cluster).unwrap();
        }
        let patch = |key: &str, fields: serde_json::Value| Command::Patch {
            statuses: vec![(key.to_string(), fields.as_object().unwrap().clone())],
        };
        let since = "2026-11-18T10:00:00Z";
        let holder = |who: &str| serde_json::json!({ "home": { "holder": who, "since": since } });
        let refused = [
            patch("Cluster/house", holder("home-c")),
            patch("Cluster/house", holder("home-o")),
            patch("Cluster/bare", holder("home-c")),
            patch("Cluster/house", serde_json::json!({ "home": { "holder": "home-c" } })),
            patch(
                "Cluster/house",
                serde_json::json!({ "home": { "holder": "home-c", "since": 5 } }),
            ),
            patch(
                "Cluster/house",
                serde_json::json!({ "home": { "holder": "home-c", "since": since, "x": 1 } }),
            ),
            patch(
                "Cluster/house",
                serde_json::json!({ "home": holder("home-c")["home"], "signing": "open" }),
            ),
            patch("Cluster/house", serde_json::json!({ "adminKey": "x" })),
            Command::Status {
                statuses: vec![("Cluster/house".into(), Some(holder("home-c")))],
            },
            Command::Delete {
                key: "Cluster/house".into(),
            },
        ];
        for command in refused {
            assert!(checked(&shared, "home-c", command.clone()).is_err(), "{command:?}");
        }
    }

    /// Which node holds the CA is what its first start wrote (it led alone then): a control node
    /// does not say so of itself after, or it would admit nodes by a join it cannot sign.
    #[tokio::test]
    async fn own_writes_refuse_a_control_node_saying_it_holds_the_ca() {
        let ca = pki::Ca::create().unwrap();
        let shared: Arc<Shared> = shared_with("own-ca", node(&ca, "ca-c"), &[]).await;
        let node = |name: &str| {
            let node = serde_json::json!({
                "apiVersion": kith_api::API_VERSION, "kind": "Node", "metadata": { "name": name }, "spec": {},
            });
            serde_json::from_value::<kith_api::Resource>(node).unwrap()
        };
        {
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(node("ca-c")).unwrap();
            store
                .set_status("Node/ca-c", Some(serde_json::json!({ "ca": true })))
                .unwrap();
            store.apply(node("ca-o")).unwrap();
        }
        let patch = |name: &str, fields: serde_json::Value| Command::Patch {
            statuses: vec![(format!("Node/{name}"), fields.as_object().unwrap().clone())],
        };
        assert!(checked(&shared, "ca-o", patch("ca-o", serde_json::json!({ "ca": true }))).is_err());
        assert!(checked(&shared, "ca-c", patch("ca-c", serde_json::json!({ "ca": false }))).is_err());
        // (The CA node's start says it again: the same, and let through.)
        assert!(checked(&shared, "ca-c", patch("ca-c", serde_json::json!({ "ca": true }))).is_ok());
    }
}
