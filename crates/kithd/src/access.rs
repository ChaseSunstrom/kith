//! Who is asking, and what they may do.
//!
//! The local socket is the machine's admin, and a node's certificate is the cluster
//! itself: neither is asked for a Role. Anyone else comes with a certificate made for an
//! `Identity` (`kith identity cert`), and may do what the Roles bound to that Identity
//! (by name, or to one of its groups as `group:NAME`) allow: verbs on kinds, in
//! namespaces. A rule that names namespaces says nothing of cluster-scoped kinds.
//!
//! The certificate stands for the Identity only while the Identity's `publicKey` is
//! the certificate's: deleting the Identity, or minting it a new certificate, ends the
//! old one's access.

use crate::cluster::{Peer, refuse};
use crate::{Shared, pki};
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use kith_api::kinds::{AccessRule, RoleSpec, Verb};
use kith_api::store::Store;
use serde::Deserialize;
use std::sync::Arc;

/// Who a request is from. Every handler of the resource API takes one, and asks.
#[derive(Clone, Debug, PartialEq)]
pub enum Caller {
    /// The local socket: whoever can open it already runs the machine.
    Admin,
    /// A node of the cluster, on the cluster's business.
    Node(String),
    Identity(String),
    /// Someone who asked the node named, which passed their request on: by that node's word.
    Via(String, Box<Caller>),
    /// The same, on a worker that runs from a view: it has no Identity and no Role to ask
    /// again by, and takes the control node's word for what they may do as well.
    Checked(String, Box<Caller>),
}

/// The header by which a node that passes a request on says who asked it.
pub const FOR: &str = "x-kith-for";

impl Caller {
    /// Who a node says asked it, as [`Caller`]'s `Display` writes them: the local socket or
    /// an Identity. Not a node, and not someone that node was itself passed.
    pub fn named(text: &str) -> Option<Caller> {
        match text {
            "local socket" => Some(Caller::Admin),
            // (As an Identity may be named: nothing else is written to the audit log as one.)
            name if !name.is_empty()
                && name
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.')) =>
            {
                Some(Caller::Identity(name.into()))
            }
            _ => None,
        }
    }

    /// The node this came from, where it came from one: by itself, or for someone.
    pub fn node(&self) -> Option<&str> {
        match self {
            Caller::Node(node) | Caller::Via(node, _) | Caller::Checked(node, _) => Some(node),
            _ => None,
        }
    }

    /// The Identity whose Roles decide what this may do, itself or passed on by a node:
    /// whose write is decided again where it is put in the log (`raft.rs`).
    pub fn identity(&self) -> Option<&str> {
        match self {
            Caller::Identity(name) => Some(name),
            Caller::Via(_, who) => who.identity(),
            _ => None,
        }
    }
}

/// As the audit log names them. An Identity's name has no space, so it is never taken for another.
impl std::fmt::Display for Caller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Caller::Admin => f.write_str("local socket"),
            Caller::Node(node) => write!(f, "node {node}"),
            Caller::Identity(name) => f.write_str(name),
            Caller::Via(node, who) | Caller::Checked(node, who) => write!(f, "{who} via node {node}"),
        }
    }
}

/// What a caller may do: everything, or what these rules allow.
pub struct Grants(Option<Vec<AccessRule>>);

fn names(kinds: &[String], kind: &str) -> bool {
    kinds
        .iter()
        .any(|named| named == "*" || named.eq_ignore_ascii_case(kind))
}

impl Grants {
    pub fn of(caller: &Caller, store: &Store) -> Grants {
        let name = match caller {
            Caller::Admin | Caller::Checked(..) => return Grants(None),
            // A node has no right of its own here: what it does for the cluster goes by the
            // node routes, and what it passes on is asked as whoever asked it.
            Caller::Node(_) => return Grants(Some(Vec::new())),
            Caller::Via(_, who) => return Grants::of(who, store),
            Caller::Identity(name) => name,
        };
        // An Identity that is not there is bound to nothing, whatever a binding says of its name.
        let Some(identity) = store.get(&format!("Identity/{name}")) else {
            return Grants(Some(Vec::new()));
        };
        let groups = identity.spec["groups"].as_array().into_iter().flatten();
        let groups: Vec<&str> = groups.filter_map(|group| group.as_str()).collect();
        let bound = |binding: &&kith_api::Resource| {
            let subjects = binding.spec["subjects"].as_array().into_iter().flatten();
            subjects.filter_map(|subject| subject.as_str()).any(|subject| {
                subject == name
                    || subject
                        .strip_prefix("group:")
                        .is_some_and(|group| groups.contains(&group))
            })
        };
        let rules = store.list(Some("RoleBinding")).filter(bound).filter_map(|binding| {
            let role = store.get(&format!("Role/{}", binding.spec["role"].as_str()?))?;
            RoleSpec::deserialize(&role.spec).ok()
        });
        Grants(Some(rules.flat_map(|role| role.rules).collect()))
    }

    /// May it do `verb` to a `kind` in `namespace` (`None`: one that is in no namespace)?
    pub fn may(&self, verb: &Verb, kind: &str, namespace: Option<&str>) -> bool {
        let Some(rules) = &self.0 else { return true };
        rules.iter().any(|rule| {
            let there = match namespace {
                Some(namespace) => rule.namespaces.is_empty() || rule.namespaces.iter().any(|named| named == namespace),
                None => rule.namespaces.is_empty(),
            };
            there && rule.verbs.contains(verb) && names(&rule.kinds, kind)
        })
    }

    /// May it do `verb` to `kind` (to any, without one) anywhere at all?
    pub fn anywhere(&self, verb: &Verb, kind: Option<&str>) -> bool {
        let Some(rules) = &self.0 else { return true };
        let fits = |rule: &AccessRule| rule.verbs.contains(verb) && kind.is_none_or(|kind| names(&rule.kinds, kind));
        rules.iter().any(fits)
    }
}

/// What an Identity can reach on the TLS port. A new route is not open to them until it
/// is named here: name it once its handler asks [`Grants`].
const FOR_IDENTITIES: [&str; 25] = [
    "/v1/duress",
    "/v1/backups",
    "/v1/blobs",
    "/v1/volumes",
    "/v1/seats",
    "/v1/drain",
    "/v1/tokens",
    "/v1/run",
    "/v1/lock",
    "/v1/netboot",
    "/v1/apply",
    "/v1/watch",
    "/v1/resources",
    "/v1/history",
    "/v1/rollback",
    "/v1/logs",
    "/v1/packages",
    "/v1/audit",
    "/v1/schemas",
    "/v1/convert",
    "/v1/diff",
    // The Kubernetes API's paths (kube.rs): the same callers, by the same rules.
    "/version",
    "/api",
    "/apis",
    "/openapi",
];

/// Is `path` one an Identity can reach (one of [`FOR_IDENTITIES`], or under one)?
pub fn for_identities(path: &str) -> bool {
    let open = |route: &&str| {
        let rest = path.strip_prefix(route);
        rest.is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    };
    FOR_IDENTITIES.iter().any(open)
}

/// Is `path` a request one node passes on to another for whoever asked it (a unit's output,
/// a Volume's files, a node's passphrase or new recovery key, a backup's restore: each is done by the node that
/// has the thing)? On these alone is a node's word for who asked ([`FOR`]) read.
fn passed_on(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/v1/") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('/').collect();
    matches!(
        parts[..],
        ["logs", _, ..]
            | ["volumes", _, _, "files"]
            | ["lock", _, "passphrase" | "recovery"]
            | ["backups", _, _, "restore"]
    )
}

/// The public key (DER) of the certificate a request came with, for an Identity or a node:
/// a watch asks again whether it still stands for them once its wait is over.
#[derive(Clone)]
pub struct Certificate(pub Vec<u8>);

/// Does the key `der` still stand for the Identity `name`? Its `publicKey` may have been
/// given another, or the Identity deleted, since the certificate was shown.
pub fn stands(shared: &Shared, name: &str, der: &[u8]) -> bool {
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let pinned = state.store.get(&format!("Identity/{name}"));
    let pinned = pinned.and_then(|identity| identity.spec["publicKey"].as_str());
    pinned.is_some_and(|pem| pki::same_key(pem, der))
}

/// Whether the Node `name` is there and a worker (`spec.trust`): one that is not there yet
/// (this node is still being sent the store) is not said to be one.
pub fn worker(shared: &Shared, name: &str) -> bool {
    let state = shared.store.lock().expect("a handler panicked holding the store");
    is_worker(&state.store, name)
}

pub fn is_worker(store: &Store, name: &str) -> bool {
    let node = store.get(&format!("Node/{name}"));
    node.is_some_and(|node| node.spec["trust"] == "worker")
}

/// Refuses a change that leaves nodes and no control node among them: the workers would
/// follow nobody and nothing could be agreed on again. `after` is what the change makes of
/// each Node it touches: its spec, or `None` where it deletes it.
pub fn control_stays(store: &Store, after: &[(&str, Option<&serde_json::Value>)]) -> Result<(), String> {
    // Two documents for one Node in one change: the last is what the Node becomes.
    let last = |(at, (name, _)): &(usize, &(&str, Option<&serde_json::Value>))| {
        !after[at + 1..].iter().any(|(later, _)| later == name)
    };
    let after: Vec<_> = after.iter().enumerate().filter(last).map(|(_, node)| *node).collect();
    // The node that holds the CA key (it says so as it starts) admits every other: a worker
    // with it would be a worker in name.
    let holds = |name: &str| {
        let status = store.get(&format!("Node/{name}")).and_then(|node| node.status.as_ref());
        status.is_some_and(|status| status["ca"] == true)
    };
    let made_worker = |(name, spec): &&(&str, Option<&serde_json::Value>)| {
        spec.is_some_and(|spec| spec["trust"] == "worker") && holds(name)
    };
    if let Some((name, _)) = after.iter().find(made_worker) {
        return Err(format!(
            "node {name} holds the cluster's CA key: it stays a control node"
        ));
    }
    // A worker that runs from a view erased its copy of the store, and its kithd takes no part
    // in Raft: it does not become a control node by a change to its Node.
    let views = |name: &str| {
        let status = store.get(&format!("Node/{name}")).and_then(|node| node.status.as_ref());
        status.is_some_and(|status| status["view"] == true)
    };
    let made_control = |(name, spec): &&(&str, Option<&serde_json::Value>)| {
        spec.is_some_and(|spec| spec["trust"] != "worker") && views(name)
    };
    if let Some((name, _)) = after.iter().find(made_control) {
        return Err(format!(
            "node {name} is a worker that keeps a view of the store, not the store: delete it \
             (`kith delete node/{name}`) and join it again to make it a control node"
        ));
    }
    let touched = |name: &str| after.iter().any(|(node, _)| *node == name);
    let rest = store.list(Some("Node")).filter(|node| !touched(&node.metadata.name));
    let specs = rest
        .map(|node| &node.spec)
        .chain(after.iter().filter_map(|(_, spec)| *spec));
    let workers: Vec<bool> = specs.map(|spec| spec["trust"] == "worker").collect();
    if after.is_empty() || workers.is_empty() || workers.contains(&false) {
        return Ok(());
    }
    Err("a cluster needs a control node (`spec.trust: control`, or none said): this would leave only workers".into())
}

/// Why the Secret at `key` (`spec`) is given to nothing on the node `me`, if so: one for
/// control nodes only (`trust: control`) on a worker, whoever placed what names it there.
pub fn withheld(store: &Store, me: Option<&str>, key: &str, spec: &serde_json::Value) -> Option<String> {
    let kept = spec["trust"] == "control" && me.is_some_and(|me| is_worker(store, me));
    kept.then(|| format!("{key} is for control nodes (`trust: control`), and this node is a worker"))
}

/// Whoever the control node `node` says asked it (`who`), as this node takes them: by its own
/// store, or, on a worker that runs from a view, by that node's word alone ([`Caller::Checked`]).
pub fn passed(shared: &Shared, node: String, who: Caller) -> Caller {
    match shared.view.borrow().is_some() {
        true => Caller::Checked(node, Box::new(who)),
        false => Caller::Via(node, Box::new(who)),
    }
}

/// Why a worker's word for who asked does nothing.
pub fn not_taken(node: &str) -> String {
    format!("node {node} is a worker: its word for who asked is not taken")
}

/// Where the control nodes this node knows of are, to say to someone who asked a worker.
fn control_nodes(shared: &Shared) -> String {
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let control = state
        .store
        .list(Some("Node"))
        .filter(|node| node.spec["trust"] != "worker");
    let at = |node: &kith_api::Resource| Some(node.status.as_ref()?["address"].as_str()?.to_string());
    let addresses: Vec<String> = control.filter_map(at).collect();
    match addresses.is_empty() {
        true => String::new(),
        false => format!(" ({})", addresses.join(", ")),
    }
}

/// Who a request on the TLS port is from, or why it is refused (and with what status). A
/// certificate that does not stand for an Identity, or none, is refused and written down.
pub fn who(
    shared: &Shared,
    subject: Option<&pki::Subject>,
    method: &str,
    path: &str,
    named: Option<&str>,
) -> Result<Caller, (StatusCode, String)> {
    let (name, key) = match subject {
        Some(pki::Subject::Node(node, key, _)) => {
            let caller = Caller::Node(node.clone());
            let (status, why) = if !crate::cluster::admitted(shared, node, key) {
                (StatusCode::UNAUTHORIZED, crate::cluster::EVICTED.to_string())
            } else if !passed_on(path) {
                // Where nodes pass nothing on it is the node, with no right, whatever it names.
                return Ok(caller);
            } else if worker(shared, node) {
                (
                    StatusCode::FORBIDDEN,
                    format!("{}: ask a control node", not_taken(node)),
                )
            } else {
                // Whoever the node says asked it: the handler asks what that caller may do.
                let why = match named.map(|named| (named, Caller::named(named))) {
                    Some((_, Some(who))) => return Ok(passed(shared, node.clone(), who)),
                    Some((named, None)) => format!("{FOR}: {named:?} is no caller a node passes on"),
                    // (A kithd from before nodes said who asked: nothing is done on its word alone.)
                    None => format!(
                        "node {node} passed this on without saying who asked: its kithd is older than this node's"
                    ),
                };
                (StatusCode::BAD_REQUEST, why)
            };
            // (One a minute, as for someone with no certificate: it can ask as often as it likes.)
            if shared.audit.stranger() {
                shared
                    .audit
                    .record(&caller, method, vec![path.into()], Err(why.clone()));
            }
            return Err((status, why));
        }
        Some(pki::Subject::User(name, key)) => (name, key),
        None => {
            let why = "a certificate from this cluster's CA is needed".to_string();
            if shared.audit.stranger() {
                shared
                    .audit
                    .record(&"no certificate", method, vec![path.into()], Err(why.clone()));
            }
            return Err((StatusCode::UNAUTHORIZED, why));
        }
    };
    let caller = Caller::Identity(name.clone());
    // A worker that runs from a view has no Identity and no Role: it answers no one by their
    // rights, reads included (a list read from a view would be short without saying so).
    if shared.view.borrow().is_some() {
        let why = format!(
            "this node is a worker and answers no one by their rights: ask a control node{}",
            control_nodes(shared)
        );
        if shared.audit.stranger() {
            shared
                .audit
                .record(&caller, method, vec![path.into()], Err(why.clone()));
        }
        return Err((StatusCode::FORBIDDEN, why));
    }
    if !stands(shared, name, key) {
        let why = format!(
            "this certificate does not stand for an Identity {name}: there is none, or it has been given another"
        );
        shared
            .audit
            .record(&caller, method, vec![path.into()], Err(why.clone()));
        return Err((StatusCode::UNAUTHORIZED, why));
    }
    if !for_identities(path) {
        let why = format!("{path} is for the cluster's nodes, not for an Identity");
        shared
            .audit
            .record(&caller, method, vec![path.into()], Err(why.clone()));
        return Err((StatusCode::FORBIDDEN, why));
    }
    Ok(caller)
}

/// Works out the [`Caller`] of a request on the TLS port, for the handlers.
pub async fn caller(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    mut request: Request,
    next: Next,
) -> Response {
    let caller = who(
        &shared,
        peer.subject.as_ref(),
        request.method().as_str(),
        request.uri().path(),
        // (A name that is not text is a name nobody has, not no name.)
        request
            .headers()
            .get(FOR)
            .map(|named| named.to_str().unwrap_or_default()),
    );
    let caller = match caller {
        Ok(caller) => caller,
        Err((status, why)) => return refuse(status, why).into_response(),
    };
    if let Some(pki::Subject::User(_, key) | pki::Subject::Node(_, key, _)) = &peer.subject {
        request.extensions_mut().insert(Certificate(key.clone()));
    }
    request.extensions_mut().insert(caller);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_api::Resource;

    /// A writer written down as a string comes back as the one it names and no other: not as
    /// a node, nor as someone a node passed on (their text has a space no Identity's name has),
    /// nor as the local socket by another spelling.
    #[test]
    fn writer_named_a_text_that_reads_like_another_caller_is_no_caller() {
        assert_eq!(Caller::named("local socket"), Some(Caller::Admin));
        assert_eq!(Caller::named("bob"), Some(Caller::Identity("bob".into())));
        for odd in [
            "node n1",
            "bob via node n1",
            "Local socket",
            "local  socket",
            "local socket ",
            "",
            "bob ",
            "BOB",
        ] {
            assert_eq!(Caller::named(odd), None, "{odd:?}");
        }
        // Whoever a Display writes for a node, or for someone it passed on, is read back as none.
        let node = Caller::Node("n1".into());
        let via = Caller::Via("n1".into(), Box::new(Caller::Identity("bob".into())));
        let checked = Caller::Checked("n1".into(), Box::new(Caller::Admin));
        for written in [node.to_string(), via.to_string(), checked.to_string()] {
            assert_eq!(Caller::named(&written), None, "{written}");
        }
    }

    #[test]
    fn a_worker_is_what_its_node_says_and_a_cluster_keeps_a_control_node() {
        let mut store = Store::default();
        let node = |name: &str, spec: &str| {
            let text = format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{name: {name}}}\nspec: {spec}\n");
            Resource::from_source(&text).unwrap().remove(0).unwrap()
        };
        for (name, spec) in [("a", "{}"), ("b", "{trust: control}"), ("w", "{trust: worker}")] {
            store.apply(node(name, spec)).unwrap();
        }
        // A node that is not there (yet: this one is being sent the store) is not said to be one.
        let workers = ["a", "b", "w", "nobody"].map(|name| is_worker(&store, name));
        assert_eq!(workers, [false, false, true, false]);
        // A Secret for control nodes is given to nothing on a worker; any other is.
        let (guarded, plain) = (serde_json::json!({"trust": "control"}), serde_json::json!({}));
        let why = withheld(&store, Some("w"), "Secret/default/key", &guarded).unwrap();
        assert!(why.starts_with("Secret/default/key is for control nodes"), "{why}");
        assert_eq!(withheld(&store, Some("w"), "Secret/default/any", &plain), None);
        assert_eq!(withheld(&store, Some("a"), "Secret/default/key", &guarded), None);
        assert_eq!(withheld(&store, None, "Secret/default/key", &guarded), None);
        // The last control node is not made a worker, deleted or rolled back to one.
        let (worker, control) = (serde_json::json!({"trust": "worker"}), serde_json::json!({}));
        assert_eq!(control_stays(&store, &[("a", Some(&worker))]), Ok(()));
        assert_eq!(control_stays(&store, &[("a", None)]), Ok(()));
        let both = control_stays(&store, &[("a", Some(&worker)), ("b", None)]).unwrap_err();
        assert!(both.contains("would leave only workers"), "{both}");
        // (Two documents for one Node: the last is what it becomes.)
        let twice = [("b", None), ("a", Some(&control)), ("a", Some(&worker))];
        assert!(control_stays(&store, &twice).is_err());
        let twice = [("b", None), ("a", Some(&worker)), ("a", Some(&control))];
        assert_eq!(control_stays(&store, &twice), Ok(()));
        // (A new control node in the same change counts, and a cluster of no node is no cluster.)
        assert_eq!(
            control_stays(&store, &[("a", None), ("b", None), ("c", Some(&control))]),
            Ok(())
        );
        assert_eq!(control_stays(&store, &[("a", None), ("b", None), ("w", None)]), Ok(()));
        // Nor is the node that holds the CA key, while others are control nodes too.
        store
            .set_status("Node/b", Some(serde_json::json!({"ca": true})))
            .unwrap();
        let holder = control_stays(&store, &[("b", Some(&worker))]).unwrap_err();
        assert!(holder.contains("node b holds the cluster's CA key"), "{holder}");
        assert_eq!(control_stays(&store, &[("b", Some(&control))]), Ok(()));
        // What touches no Node is never refused for it.
        store.apply(node("a", "{trust: worker}")).unwrap();
        store.apply(node("b", "{trust: worker}")).unwrap();
        assert_eq!(control_stays(&store, &[]), Ok(()));
        assert_eq!(control_stays(&store, &[("a", Some(&control))]), Ok(()));
    }

    /// A refused certificate is written down, with who showed it and what for: a 401 is no
    /// less a refusal than a 403.
    #[tokio::test]
    async fn refused_certificates_are_audited() {
        let dir = std::env::temp_dir().join(format!("kithd-401-audited-{}", std::process::id()));
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
        let other = pki::Subject::User("alice".into(), vec![1, 2, 3]);
        let (status, _) = who(&shared, Some(&other), "POST", "/v1/apply", None).unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = who(&shared, None, "GET", "/v1/watch", None).unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let entries = shared.audit.tail(10).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["who"], "alice");
        assert_eq!(
            (&entries[0]["verb"], &entries[0]["ok"]),
            (&"POST".into(), &false.into())
        );
        assert_eq!(entries[0]["what"][0], "/v1/apply");
        assert_eq!(entries[1]["who"], "no certificate");
        // One such line a minute: whoever has no certificate does not fill the log.
        assert!(who(&shared, None, "GET", "/v1/watch", None).is_err());
        assert_eq!(shared.audit.tail(10).unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn store(yaml: &str) -> Store {
        let mut store = Store::default();
        for resource in Resource::from_source(yaml).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        store
    }

    #[test]
    fn access_is_what_bound_roles_allow() {
        let store = store(
            "
apiVersion: kith.dev/v1
kind: Identity
metadata: {name: alice}
spec: {groups: [ops]}
---
apiVersion: kith.dev/v1
kind: Identity
metadata: {name: bob}
spec: {}
---
apiVersion: kith.dev/v1
kind: Role
metadata: {name: web-editor}
spec:
  rules:
    - {kinds: [Workload, Service], verbs: [get, list, apply], namespaces: [web]}
---
apiVersion: kith.dev/v1
kind: Role
metadata: {name: reader}
spec:
  rules:
    - {kinds: ['*'], verbs: [get, list, watch]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: alice-web}
spec: {role: web-editor, subjects: [alice]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: ops-read}
spec: {role: reader, subjects: ['group:ops']}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: dangling}
spec: {role: gone, subjects: [bob]}
",
        );
        let alice = Grants::of(&Caller::Identity("alice".into()), &store);
        // By name: the verbs, kinds and namespaces of the rule, and no others.
        assert!(alice.may(&Verb::Apply, "Workload", Some("web")));
        assert!(alice.may(&Verb::Apply, "service", Some("web")));
        assert!(!alice.may(&Verb::Apply, "Workload", Some("default")));
        assert!(!alice.may(&Verb::Delete, "Workload", Some("web")));
        assert!(!alice.may(&Verb::Apply, "Secret", Some("web")));
        // A rule for namespaces is not one for what is in none.
        assert!(!alice.may(&Verb::Apply, "Workload", None));
        // Through a group: every kind, everywhere, cluster-scoped ones too; reading only.
        assert!(alice.may(&Verb::Get, "Secret", Some("default")) && alice.may(&Verb::Watch, "Node", None));
        assert!(!alice.may(&Verb::Apply, "Node", None) && !alice.may(&Verb::Exec, "Workload", Some("web")));
        assert!(alice.anywhere(&Verb::Apply, Some("Workload")) && alice.anywhere(&Verb::List, None));
        assert!(!alice.anywhere(&Verb::Delete, None) && !alice.anywhere(&Verb::Apply, Some("Secret")));

        // Not in the group, and bound only to a Role that is not there: nothing.
        let bob = Grants::of(&Caller::Identity("bob".into()), &store);
        assert!(!bob.may(&Verb::Get, "Workload", Some("web")) && !bob.anywhere(&Verb::Get, None));
        // No such Identity: nothing, whatever a binding says of the name.
        let nobody = Grants::of(&Caller::Identity("group:ops".into()), &store);
        assert!(!nobody.anywhere(&Verb::Get, None));
        // The machine's admin is not asked for a Role.
        assert!(Grants::of(&Caller::Admin, &store).may(&Verb::Delete, "Node", None));
        // Someone a node passed on has their own rights, whichever node it was.
        let passed = Caller::Via("n1".into(), Box::new(Caller::Identity("alice".into())));
        let passed = Grants::of(&passed, &store);
        assert!(passed.may(&Verb::Apply, "Workload", Some("web")) && !passed.anywhere(&Verb::Delete, None));
    }

    /// A node's certificate has no right of its own on the API: it passes on what someone
    /// asked it, on the routes nodes pass on, naming who; anywhere else the name is not read.
    #[tokio::test]
    async fn a_node_caller_has_no_right_of_its_own_and_names_who_asked_only_where_nodes_pass_on() {
        let dir = std::env::temp_dir().join(format!("kithd-node-caller-{}", std::process::id()));
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
        {
            let node = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: {name: n1}\nspec: {}\n";
            let node = Resource::from_source(node).unwrap().remove(0).unwrap();
            let mut state = shared.store.lock().unwrap();
            state.store.apply(node).unwrap();
            let joined = serde_json::json!({"raftId": "1"});
            state.store.set_status("Node/n1", Some(joined)).unwrap();
        }
        let n1 = pki::Subject::Node("n1".into(), vec![1], None);
        let ask = |path: &str, named: Option<&str>| who(&shared, Some(&n1), "GET", path, named);
        let node = Caller::Node("n1".into());
        let via = |who: Caller| Caller::Via("n1".into(), Box::new(who));
        // By itself, and wherever nodes pass nothing on, it is the node, whatever it names.
        assert_eq!(ask("/v1/apply", None), Ok(node.clone()));
        for path in [
            "/v1/apply",
            "/v1/tokens",
            "/v1/run",
            "/v1/resources/Secret/default/a",
            "/v1/volumes/default/a",
            "/v1/volumes/default/a/files/more",
            "/v1/lock/n1",
            "/v1/backups/default/a",
            "/apis/logs/v1/x",
            "/ui/logs/x",
        ] {
            assert_eq!(ask(path, Some("local socket")), Ok(node.clone()), "{path}");
        }
        {
            let state = shared.store.lock().unwrap();
            let grants = Grants::of(&node, &state.store);
            for verb in [
                Verb::Get,
                Verb::List,
                Verb::Watch,
                Verb::Apply,
                Verb::Delete,
                Verb::Exec,
            ] {
                assert!(!grants.anywhere(&verb, None), "{verb:?}");
            }
            assert!(!grants.may(&Verb::Get, "Secret", Some("default")) && !grants.may(&Verb::Apply, "Node", None));
        }
        // What nodes pass on: who asked is who it is for, by this node's word.
        for path in [
            "/v1/logs/Workload/default/a",
            "/v1/volumes/default/a/files",
            "/v1/lock/n2/passphrase",
            "/v1/backups/default/a/restore",
        ] {
            assert_eq!(
                ask(path, Some("alice")),
                Ok(via(Caller::Identity("alice".into()))),
                "{path}"
            );
        }
        let admin = ask("/v1/lock/n2/passphrase", Some("local socket")).unwrap();
        assert_eq!(admin, via(Caller::Admin));
        assert_eq!(admin.to_string(), "local socket via node n1");
        // Not a node, and not someone a node was itself passed: nothing is passed on twice.
        // Nor nobody: a node that does not say who asked (an older kithd) is told so.
        for named in [
            Some("node n2"),
            Some("alice via node n2"),
            Some("Alice"),
            Some("a\tb"),
            Some(""),
            None,
        ] {
            let (status, why) = ask("/v1/logs/Workload/default/a", named).unwrap_err();
            assert_eq!(status, StatusCode::BAD_REQUEST, "{named:?}: {why}");
        }
        // Each such refusal is written down, once a minute at most.
        let refused = shared.audit.tail(10).unwrap();
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(
            (&refused[0]["who"], &refused[0]["ok"]),
            (&"node n1".into(), &false.into())
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
