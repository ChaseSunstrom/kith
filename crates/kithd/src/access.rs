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
}

/// As the audit log names them. An Identity's name has no space, so it is never taken for another.
impl std::fmt::Display for Caller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Caller::Admin => f.write_str("local socket"),
            Caller::Node(node) => write!(f, "node {node}"),
            Caller::Identity(name) => f.write_str(name),
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
        let Caller::Identity(name) = caller else {
            return Grants(None);
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
const FOR_IDENTITIES: [&str; 22] = [
    "/v1/backups",
    "/v1/blobs",
    "/v1/seats",
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

/// The public key (DER) of the certificate a request came with, for an Identity: a watch
/// asks again whether it still stands for the Identity once its wait is over.
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

/// Who a request on the TLS port is from, or why it is refused (and with what status). A
/// certificate that does not stand for an Identity, or none, is refused and written down.
pub fn who(
    shared: &Shared,
    subject: Option<&pki::Subject>,
    method: &str,
    path: &str,
) -> Result<Caller, (StatusCode, String)> {
    let (name, key) = match subject {
        Some(pki::Subject::Node(node)) => return Ok(Caller::Node(node.clone())),
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
    );
    let caller = match caller {
        Ok(caller) => caller,
        Err((status, why)) => return refuse(status, why).into_response(),
    };
    if let Some(pki::Subject::User(_, key)) = &peer.subject {
        request.extensions_mut().insert(Certificate(key.clone()));
    }
    request.extensions_mut().insert(caller);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_api::Resource;

    /// A refused certificate is written down, with who showed it and what for: a 401 is no
    /// less a refusal than a 403.
    #[tokio::test]
    async fn refused_certificates_are_audited() {
        let dir = std::env::temp_dir().join(format!("kithd-401-audited-{}", std::process::id()));
        let shared = crate::replica(None, &dir).await.unwrap();
        let other = pki::Subject::User("alice".into(), vec![1, 2, 3]);
        let (status, _) = who(&shared, Some(&other), "POST", "/v1/apply").unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = who(&shared, None, "GET", "/v1/watch").unwrap_err();
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
        assert!(who(&shared, None, "GET", "/v1/watch").is_err());
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
        // The machine's admin and the cluster's nodes are not asked for a Role.
        assert!(Grants::of(&Caller::Admin, &store).may(&Verb::Delete, "Node", None));
        assert!(Grants::of(&Caller::Node("n1".into()), &store).anywhere(&Verb::Exec, None));
    }
}
