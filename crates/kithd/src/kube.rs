//! The Kubernetes API's paths, answered from kith's own store, so that `kubectl` and
//! `helm` work as they are. Nothing of Kubernetes runs here: what a client sends is read
//! as the kith resources it means (kith-kube), applied as the caller by the rules `/v1`
//! has, and given back as it was sent with what kith knows of it (its revision, its status).
//!
//! Every kind is a row of [`KINDS`], held one of three ways ([`Held`]): as the kith
//! resource it means, with the object as it was sent beside it in an annotation; as a
//! `KubeObject`, kept and given back, for what nothing in kith reads; or not at all, made
//! up from its owner's status when asked for (a pod, a ReplicaSet). A kith resource that
//! was not made through these paths is not shown on them.
//!
//! `resourceVersion`: of a list, the store's generation; of an object, its kith revision
//! and what its status hashes to. A watch starts from a list's version or is told `410`
//! (the client lists again): a generation is a time, not a place in what the store kept of changes.
//!
//! `metadata.managedFields`: who set which field, kept in the object as it was sent, for
//! server-side apply (a second manager's different value is a 409 unless forced). Only
//! `Apply` writes make a manager; a replace or a patch takes a field from whoever had it.
//!
//! A watch reads what changed: the store keeps the keys each command changed (kith-store's
//! `touched`), so on a change the watch reads those and no other. It reads everything again
//! when it cannot know what changed: a worker that runs from a view (kept apart from Raft's
//! log), a change of who may see what (an Identity, a Role or its binding), more changes
//! than are kept, a store that was replaced, and the Namespaces (made up from every resource).

use crate::Shared;
use crate::access::{Caller, Certificate, Grants};
use crate::api::{self, ApiError, LogOptions};
use crate::websocket;
pub(crate) mod portforward;
use axum::body::{Body, Bytes};
use axum::extract::{Path as Route, Query, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use kith_api::kinds::Verb;
use kith_api::store::{Action, Error, Store, now, rfc3339};
use kith_api::{Metadata, Resource};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

/// The annotation a resource made here carries: the object as the client sent it. What
/// `kubectl apply` works its next change out from is in it, so it is given back whole.
pub const SENT: &str = "kube.kith.dev/sent";
/// And when it was made (seconds): Kubernetes's `creationTimestamp`, and part of its `uid`.
const MADE: &str = "kube.kith.dev/made";

/// The longest a watch is kept open: the client asks again from where it was.
const WATCH_SECS: u64 = 300;

/// How kith holds a kind of Kubernetes object.
#[derive(Clone, Copy, PartialEq)]
enum Held {
    /// As the kith resource of this kind that it means, the object as sent beside it.
    As(&'static str),
    /// As a `KubeObject`: kept and given back, read by nothing in kith. What is said of that.
    Kept(&'static str),
    /// Not held: made up from what the store says of its owner. Read only.
    Made,
}

struct Kind {
    /// Empty for the core group. Every group is at `v1`.
    group: &'static str,
    plural: &'static str,
    kind: &'static str,
    short: &'static str,
    namespaced: bool,
    held: Held,
}

const fn kind(
    group: &'static str,
    plural: &'static str,
    kind: &'static str,
    short: &'static str,
    namespaced: bool,
    held: Held,
) -> Kind {
    Kind {
        group,
        plural,
        kind,
        short,
        namespaced,
        held,
    }
}

/// A Pod sent is held as one of these, by what its `restartPolicy` says (not in `KINDS`: a Pod
/// is found there as what is made up, and this is what a bare one is held as).
static BARE: [Kind; 2] = [
    kind("", "pods", "Pod", "po", true, Held::As("Job")),
    kind("", "pods", "Pod", "po", true, Held::As("Workload")),
];
/// Where each row is in [`BARE`].
const BARE_JOB: usize = 0;
const BARE_WORKLOAD: usize = 1;

/// The row a Pod sent is held as: Job when it is not run again, else a Workload (as Kubernetes
/// says of a missing `restartPolicy`).
fn bare(pod: &Value) -> &'static Kind {
    match kith_kube::pod_holder(pod.pointer("/spec/restartPolicy").and_then(Value::as_str)) {
        "Job" => &BARE[BARE_JOB],
        _ => &BARE[BARE_WORKLOAD],
    }
}

const ACCESS: &str =
    "is kept and gives nothing: who may do what in kith is its own Roles', and a pod has no Kubernetes API to ask";
const BUDGET: &str = "is kept and not read yet: kith drains a node without asking it";
const CLASS: &str = "is kept and not read: kith's edge is the one way in";

/// Every kind these paths know, group by group. One that is not here is not found, as
/// Kubernetes says of a kind it does not have.
/// (A `static`: a kind is known by where its row is.)
static KINDS: &[Kind] = &[
    kind("", "pods", "Pod", "po", true, Held::Made),
    kind("", "services", "Service", "svc", true, Held::As("Service")),
    kind("", "configmaps", "ConfigMap", "cm", true, Held::As("ConfigMap")),
    kind("", "secrets", "Secret", "", true, Held::As("Secret")),
    kind(
        "",
        "persistentvolumeclaims",
        "PersistentVolumeClaim",
        "pvc",
        true,
        Held::As("VolumeClaim"),
    ),
    kind("", "namespaces", "Namespace", "ns", false, Held::As("Namespace")),
    kind("", "nodes", "Node", "no", false, Held::Made),
    kind("", "events", "Event", "ev", true, Held::Made),
    kind("", "serviceaccounts", "ServiceAccount", "sa", true, Held::Kept(ACCESS)),
    kind(
        "apps",
        "deployments",
        "Deployment",
        "deploy",
        true,
        Held::As("Workload"),
    ),
    kind("apps", "statefulsets", "StatefulSet", "sts", true, Held::As("Workload")),
    kind("apps", "daemonsets", "DaemonSet", "ds", true, Held::As("NodeWorkload")),
    kind("apps", "replicasets", "ReplicaSet", "rs", true, Held::Made),
    kind("batch", "jobs", "Job", "", true, Held::As("Job")),
    kind("batch", "cronjobs", "CronJob", "cj", true, Held::As("CronJob")),
    kind("networking.k8s.io", "ingresses", "Ingress", "ing", true, Held::Kept("")),
    kind(
        "networking.k8s.io",
        "ingressclasses",
        "IngressClass",
        "",
        false,
        Held::Kept(CLASS),
    ),
    kind(
        "policy",
        "poddisruptionbudgets",
        "PodDisruptionBudget",
        "pdb",
        true,
        Held::Kept(BUDGET),
    ),
    kind(
        "rbac.authorization.k8s.io",
        "roles",
        "Role",
        "",
        true,
        Held::Kept(ACCESS),
    ),
    kind(
        "rbac.authorization.k8s.io",
        "rolebindings",
        "RoleBinding",
        "",
        true,
        Held::Kept(ACCESS),
    ),
    kind(
        "rbac.authorization.k8s.io",
        "clusterroles",
        "ClusterRole",
        "",
        false,
        Held::Kept(ACCESS),
    ),
    kind(
        "rbac.authorization.k8s.io",
        "clusterrolebindings",
        "ClusterRoleBinding",
        "",
        false,
        Held::Kept(ACCESS),
    ),
];

/// What Kubernetes fills in where an object does not say, for the fields its clients read
/// without asking whether they are there (Helm waits by them).
const DEFAULTS: &[(&str, &str, &str)] = &[
    ("Deployment", "/spec/replicas", "1"),
    ("StatefulSet", "/spec/replicas", "1"),
    ("StatefulSet", "/spec/updateStrategy/type", "\"RollingUpdate\""),
    ("DaemonSet", "/spec/updateStrategy/type", "\"RollingUpdate\""),
    (
        "DaemonSet",
        "/spec/updateStrategy/rollingUpdate",
        r#"{"maxUnavailable":1,"maxSurge":0}"#,
    ),
    ("Job", "/spec/completions", "1"),
    ("Job", "/spec/parallelism", "1"),
    ("Job", "/spec/backoffLimit", "6"),
    ("Service", "/spec/type", "\"ClusterIP\""),
];

/// The lists a strategic merge patch merges item by item, and the field that names an
/// item: every field Kubernetes's types tag `patchMergeKey`, by its JSON name, in the
/// order `python3 ci/kube_proto.py --merge-keys` gives (a test says when they differ).
/// `ports` is by `containerPort` in a container and by `port` in a Service: [`merge_key`]
/// takes the one an item has. Any other list is replaced whole.
const MERGED: &[(&str, &str)] = &[
    ("addresses", "type"),
    ("allocatedResourcesStatus", "name"),
    ("conditions", "type"),
    ("containers", "name"),
    ("env", "name"),
    ("ephemeralContainers", "name"),
    ("evictionResponders", "name"),
    ("healthConditions", "status"),
    ("hostAliases", "ip"),
    ("hostIPs", "ip"),
    ("imagePullSecrets", "name"),
    ("initContainers", "name"),
    ("mapping", "name"),
    ("nodeAllocatableResourceClaimStatuses", "resourceClaimName"),
    ("overhead", "name"),
    ("ownerReferences", "uid"),
    ("podIPs", "ip"),
    ("ports", "containerPort"),
    ("ports", "port"),
    ("resourceClaimStatuses", "name"),
    ("resourceClaims", "name"),
    ("schedulingGates", "name"),
    ("secrets", "name"),
    ("topologySpreadConstraints", "topologyKey"),
    ("volumeDevices", "devicePath"),
    ("volumeMounts", "mountPath"),
    ("volumes", "name"),
];

pub fn router() -> Router<Arc<Shared>> {
    let version =
        || async { Json(json!({ "major": "1", "minor": "37", "gitVersion": "v1.37.0", "platform": "linux/amd64" })) };
    Router::new()
        .route("/version", get(version))
        .route(
            "/api",
            get(|| async { Json(json!({ "kind": "APIVersions", "versions": ["v1"] })) }),
        )
        .route("/apis", get(groups))
        .route("/api/v1", get(|| async { resources("") }))
        .route(
            "/apis/{group}/v1",
            get(|Route(group): Route<String>| async move { resources(&group) }),
        )
        .route("/openapi/v3", get(openapi))
        // (What kubectl checks a kind against that the server does not check for it: of a
        // kind that is not here nothing is known, so nothing: an empty document, as protobuf
        // has one. kubectl then says the kind has no match, not that it could not ask.)
        .route(
            "/openapi/v2",
            get(|| async {
                [(
                    header::CONTENT_TYPE,
                    "application/com.github.proto-openapi.spec.v2.v1.0+protobuf",
                )]
            }),
        )
        .route("/openapi/v3/{*of}", get(checked))
        .route("/api/v1/{*rest}", any(core))
        .route("/apis/{group}/v1/{*rest}", any(grouped))
}

/// `v1`, or `group/v1`.
fn version_of(group: &str) -> String {
    match group {
        "" => "v1".into(),
        group => format!("{group}/v1"),
    }
}

/// The groups there are, but for the core one.
fn named() -> Vec<&'static str> {
    let mut names: Vec<&str> = KINDS.iter().map(|kind| kind.group).filter(|g| !g.is_empty()).collect();
    names.dedup();
    names
}

async fn groups() -> Json<Value> {
    let group = |name: &&str| {
        let version = json!({ "groupVersion": version_of(name), "version": "v1" });
        json!({ "name": name, "versions": [version], "preferredVersion": version })
    };
    let groups: Vec<Value> = named().iter().map(group).collect();
    Json(json!({ "kind": "APIGroupList", "apiVersion": "v1", "groups": groups }))
}

fn scales(kind: &Kind) -> bool {
    matches!(kind.kind, "Deployment" | "StatefulSet")
}

/// What a group has: each kind's plural, its names and what can be done to it.
fn resources(group: &str) -> Response {
    let mut has = Vec::new();
    for kind in KINDS.iter().filter(|kind| kind.group == group) {
        let verbs: &[&str] = match kind.held {
            Held::Made if kind.kind == "Pod" => &["create", "get", "list", "watch"],
            Held::Made => &["get", "list", "watch"],
            _ => &["create", "delete", "get", "list", "patch", "update", "watch"],
        };
        let mut one = json!({
            "name": kind.plural, "singularName": kind.kind.to_lowercase(), "kind": kind.kind,
            "namespaced": kind.namespaced, "verbs": verbs,
        });
        if !kind.short.is_empty() {
            one["shortNames"] = json!([kind.short]);
        }
        // (`kubectl get all`.)
        if matches!(kind.group, "apps" | "batch") || matches!(kind.kind, "Pod" | "Service") {
            one["categories"] = json!(["all"]);
        }
        has.push(one);
        let part = |part: &str, verbs: &[&str]| json!({ "name": format!("{}/{part}", kind.plural), "singularName": "", "namespaced": true, "kind": kind.kind, "verbs": verbs });
        // (`kubectl scale` looks for this to know what a scale of the kind is.)
        if scales(kind) {
            let mut scale = part("scale", &["get", "patch", "update"]);
            for (field, value) in [("group", "autoscaling"), ("version", "v1"), ("kind", "Scale")] {
                scale[field] = value.into();
            }
            has.push(scale);
        }
        if kind.kind == "Pod" {
            has.push(part("log", &["get"]));
        }
    }
    if has.is_empty() {
        return missing().into_response();
    }
    Json(json!({ "kind": "APIResourceList", "apiVersion": "v1", "groupVersion": version_of(group), "resources": has }))
        .into_response()
}

async fn openapi() -> Json<Value> {
    let path = |at: String| (at.clone(), json!({ "serverRelativeURL": format!("/openapi/v3/{at}") }));
    let groups = named().into_iter().map(|group| format!("apis/{group}/v1"));
    let paths: serde_json::Map<String, Value> = std::iter::once("api/v1".to_string()).chain(groups).map(path).collect();
    Json(json!({ "paths": paths }))
}

/// What kubectl and helm ask before they send an object: whether the server checks the
/// fields itself (`fieldValidation`). It does (what is not carried over is said, or refused),
/// so they need no schema of every kind to check them against: none is served.
async fn checked(Route(of): Route<String>) -> Response {
    let group = match of.split('/').collect::<Vec<_>>()[..] {
        ["api", "v1"] => "",
        ["apis", group, "v1"] => group,
        _ => return missing().into_response(),
    };
    let path = |kind: &Kind| {
        let patch = json!({
            "x-kubernetes-group-version-kind": { "group": kind.group, "version": "v1", "kind": kind.kind },
            "parameters": [{ "name": "fieldValidation", "in": "query" }],
        });
        (format!("/{of}/{}/{{name}}", kind.plural), json!({ "patch": patch }))
    };
    let written = KINDS
        .iter()
        .filter(|kind| kind.group == group && kind.held != Held::Made);
    let paths: serde_json::Map<String, Value> = written.map(path).collect();
    Json(json!({ "openapi": "3.0.0", "paths": paths })).into_response()
}

/// A refusal, as Kubernetes says one: kubectl prints `why`, and reads `reason`.
#[derive(Debug)]
struct No {
    code: StatusCode,
    reason: &'static str,
    why: String,
}

impl IntoResponse for No {
    fn into_response(self) -> Response {
        let said = json!({
            "kind": "Status", "apiVersion": "v1", "status": "Failure",
            "message": self.why, "reason": self.reason, "code": self.code.as_u16(),
        });
        (self.code, Json(said)).into_response()
    }
}

fn status(code: StatusCode, reason: &'static str, why: String) -> No {
    No { code, reason, why }
}

fn missing() -> No {
    let why = "the server could not find the requested resource";
    status(StatusCode::NOT_FOUND, "NotFound", why.into())
}

fn not_found(kind: &Kind, name: &str) -> No {
    let of = match kind.group {
        "" => kind.plural.to_string(),
        group => format!("{}.{group}", kind.plural),
    };
    status(StatusCode::NOT_FOUND, "NotFound", format!("{of} \"{name}\" not found"))
}

fn invalid(why: String) -> No {
    status(StatusCode::UNPROCESSABLE_ENTITY, "Invalid", why)
}

fn refusal(e: ApiError) -> No {
    match e {
        ApiError::Refused(why) => status(StatusCode::FORBIDDEN, "Forbidden", why),
        ApiError::Unauthorized(why) => status(StatusCode::UNAUTHORIZED, "Unauthorized", why),
        ApiError::Store(e) => {
            let (code, reason) = match e {
                Error::Invalid(_) => (StatusCode::UNPROCESSABLE_ENTITY, "Invalid"),
                Error::NotFound(_) => (StatusCode::NOT_FOUND, "NotFound"),
                Error::Conflict(_) => (StatusCode::CONFLICT, "Conflict"),
                Error::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
            };
            status(code, reason, e.to_string())
        }
    }
}

/// A UUID's shape, from what names a thing: the same thing has the same one.
fn uid(of: &str) -> String {
    let hex = blake3::hash(of.as_bytes()).to_hex();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn short_hash(of: &str) -> String {
    blake3::hash(of.as_bytes()).to_hex()[..10].to_string()
}

/// An object's `resourceVersion`: its kith revision, and under it what its status hashes
/// to, so that it changes when either does and a writer is held to the revision alone.
fn version(resource: &Resource) -> u64 {
    let status = resource.status.as_ref().map(Value::to_string).unwrap_or_default();
    let hash = blake3::hash(status.as_bytes());
    let low = u32::from_le_bytes(hash.as_bytes()[..4].try_into().expect("four bytes"));
    resource.metadata.revision.unwrap_or(0) << 32 | u64::from(low)
}

fn made_at(resource: &Resource) -> u64 {
    let made = resource.metadata.annotations.get(MADE);
    made.and_then(|made| made.parse().ok()).unwrap_or(0)
}

/// The time (as [`rfc3339`] writes it) when the store first made `resource` (a namespace, a
/// node: nothing a client made here says it): [`Store::born`] once the store is marked, which
/// a trim of the history does not move. Before a mark (a worker's view, a store from before)
/// it is the oldest revision kept, so it can be later than when the thing was made.
fn oldest(store: &Store, resource: &Resource) -> String {
    let key = resource.key();
    let at = store
        .born(&key)
        .map(|(_, at)| at)
        .or_else(|| store.history(&key).ok()?.first().map(|first| first.at));
    rfc3339(at.unwrap_or(0))
}

/// Sets what is at `path` (`/a/b`) of `at`, making the mappings on the way; nothing where
/// something that is not a mapping is in the way.
fn set(mut at: &mut Value, path: &str, value: Value) {
    for part in path.split('/').skip(1) {
        if at.is_null() {
            *at = json!({});
        }
        let Some(map) = at.as_object_mut() else { return };
        at = map.entry(part).or_insert(Value::Null);
    }
    *at = value;
}

/// The kith kind that holds a kind (none for one that is made up).
fn holder(kind: &Kind) -> &'static str {
    match kind.held {
        Held::As(holder) => holder,
        Held::Kept(_) => "KubeObject",
        Held::Made => "",
    }
}

/// The name of the `KubeObject` that keeps an object: its kind's plural and its name, or
/// what the name hashes to where kith could not have it as a name (`system:reader`).
fn kept_name(kind: &Kind, name: &str) -> String {
    let plain = format!("{}.{name}", kind.plural);
    let letter = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let fits = plain.len() <= 63
        && name.bytes().all(|b| letter(b) || b == b'-' || b == b'.')
        && name.bytes().last().is_some_and(letter);
    match fits {
        true => plain,
        false => format!("{}.{}", kind.plural, &blake3::hash(name.as_bytes()).to_hex()[..32]),
    }
}

/// The store key of what holds the object of `kind` named `name`. (A kind that is in no
/// namespace and is kept is kept in `default`: a `KubeObject` is in one.)
fn key(kind: &Kind, namespace: Option<&str>, name: &str) -> String {
    let namespace = namespace.unwrap_or(kith_api::DEFAULT_NAMESPACE);
    match kind.held {
        Held::As("Namespace") => format!("Namespace/{name}"),
        Held::As(holder) => format!("{holder}/{namespace}/{name}"),
        _ => format!("KubeObject/{namespace}/{}", kept_name(kind, name)),
    }
}

/// The object a resource holds as it was sent, and its kind; none for a resource that was
/// not made here. What kith holds elsewhere is put back: a Secret's and a ConfigMap's data
/// are the kith resource's, kept once.
fn raw(resource: &Resource) -> Option<(&'static Kind, Value)> {
    let mut object: Value = match (resource.kind.as_str(), resource.metadata.annotations.get(SENT)) {
        ("KubeObject", _) => resource.spec.get("object")?.clone(),
        (_, Some(sent)) => serde_json::from_str(sent).ok()?,
        // A namespace is there however it was made.
        ("Namespace", None) => json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": { "name": resource.metadata.name, "labels": resource.metadata.labels },
        }),
        _ => return None,
    };
    let kind = KINDS
        .iter()
        .chain(&BARE)
        .find(|kind| object["kind"] == kind.kind && holder(kind) == resource.kind)?;
    let data = resource.spec.get("data").and_then(Value::as_object);
    if let (Some(data), Some(object)) = (data, object.as_object_mut()) {
        use base64::Engine;
        let coded =
            |value: &Value| base64::engine::general_purpose::STANDARD.encode(value.as_str().unwrap_or_default());
        let data: serde_json::Map<String, Value> = match kind.kind {
            "Secret" => data.iter().map(|(k, v)| (k.clone(), coded(v).into())).collect(),
            _ => data.clone(),
        };
        object.insert("data".into(), data.into());
    }
    Some((kind, object))
}

/// The object a resource holds as it is now: as it was sent, with what the server says of
/// an object (its `uid`, versions and age), what Kubernetes would have filled in, and the
/// status kith's controllers wrote, said in the kind's own words.
fn served(resource: &Resource) -> Option<(&'static Kind, Value)> {
    let (kind, mut object) = raw(resource)?;
    let (made, revision) = (made_at(resource), resource.metadata.revision.unwrap_or(1));
    let meta = object.get_mut("metadata")?.as_object_mut()?;
    meta.insert("uid".into(), uid(&format!("{} {made}", resource.key())).into());
    meta.insert("resourceVersion".into(), version(resource).to_string().into());
    meta.insert("generation".into(), revision.into());
    if made > 0 {
        meta.insert("creationTimestamp".into(), rfc3339(made).into());
    }
    for (_, at, value) in DEFAULTS.iter().filter(|(of, ..)| *of == kind.kind) {
        if object.pointer(at).is_none() {
            set(&mut object, at, serde_json::from_str(value).expect("a default is JSON"));
        }
    }
    let live = resource.status.as_ref();
    let said = |field: &str| live.and_then(|live| live[field].as_str());
    match kind.kind {
        // Its address on the mesh; with none it is found by its name alone, which is what
        // Kubernetes calls a Service with `None` here. A headless one has no address, whatever
        // it had before it was made so. (Helm waits for this field to say something.)
        // (Helm sends `clusterIP: ""` for "allocate": it is read as absent.)
        "Service"
            if object
                .pointer("/spec/clusterIP")
                .is_none_or(|ip| ip.as_str() == Some("")) =>
        {
            let address = match crate::services::headless(resource) {
                true => "None",
                false => said("address").unwrap_or("None"),
            };
            set(&mut object, "/spec/clusterIP", address.into());
            set(&mut object, "/spec/clusterIPs", json!([address]));
        }
        "PersistentVolumeClaim" => {
            if let Some(volume) = said("volume") {
                set(&mut object, "/spec/volumeName", volume.into());
            }
        }
        // (`kubectl logs job/NAME` finds the pods by this, as Kubernetes writes it.)
        "Job" if object.pointer("/spec/selector").is_none() => {
            let name = resource.metadata.name.as_str();
            set(
                &mut object,
                "/spec/selector",
                json!({ "matchLabels": { "job-name": name } }),
            );
        }
        _ => {}
    }
    if let Some(status) = status_of(kind.kind, &object, resource) {
        set(&mut object, "/status", status);
    }
    Some((kind, object))
}

/// Of the replicas a status tells of: how many there are, how many run what the resource
/// now says, how many are ready, and how many are both.
fn counts(resource: &Resource) -> [u64; 4] {
    let mut replicas: BTreeMap<u64, (bool, bool)> = BTreeMap::new();
    let units = resource
        .status
        .as_ref()
        .and_then(|status| status["containers"].as_array());
    for unit in units.into_iter().flatten() {
        let Some(replica) = unit["replica"].as_u64() else {
            continue;
        };
        let is = replicas.entry(replica).or_insert((true, true));
        is.0 &= unit["revision"].as_u64() == resource.metadata.revision;
        is.1 &= unit["ready"] == true;
    }
    let count = |of: fn(&(bool, bool)) -> bool| replicas.values().filter(|is| of(is)).count() as u64;
    [
        replicas.len() as u64,
        count(|is| is.0),
        count(|is| is.1),
        count(|is| is.0 && is.1),
    ]
}

fn condition(kind: &str, is: bool, reason: &str) -> Value {
    json!({ "type": kind, "status": if is { "True" } else { "False" }, "reason": reason })
}

/// kith's status of a resource, as the status of the Kubernetes object it holds.
pub(crate) fn status_of(kind: &str, object: &Value, resource: &Resource) -> Option<Value> {
    let live = resource.status.as_ref();
    let revision = resource.metadata.revision.unwrap_or(1);
    let [all, new, ready, both] = counts(resource);
    let wanted = object["spec"]["replicas"].as_u64().unwrap_or(1);
    let number = |field: &str| live.and_then(|live| live[field].as_u64()).unwrap_or(0);
    Some(match kind {
        "Deployment" => {
            let done = all == wanted && both == wanted;
            let moving = if done {
                "NewReplicaSetAvailable"
            } else {
                "ReplicaSetUpdated"
            };
            json!({
                "observedGeneration": revision, "replicas": all, "updatedReplicas": new,
                "readyReplicas": ready, "availableReplicas": ready,
                "conditions": [
                    condition("Available", ready >= wanted, "MinimumReplicasAvailable"),
                    condition("Progressing", true, moving),
                ],
            })
        }
        "StatefulSet" => {
            let name = &resource.metadata.name;
            let current = if new == all {
                revision
            } else {
                revision.saturating_sub(1)
            };
            json!({
                "observedGeneration": revision, "replicas": all, "readyReplicas": ready,
                "availableReplicas": ready, "currentReplicas": new, "updatedReplicas": new,
                "currentRevision": format!("{name}-{current}"), "updateRevision": format!("{name}-{revision}"),
            })
        }
        "DaemonSet" => json!({
            "observedGeneration": revision, "desiredNumberScheduled": number("replicas"),
            "currentNumberScheduled": all, "updatedNumberScheduled": new, "numberReady": ready,
            "numberAvailable": ready, "numberMisscheduled": 0,
        }),
        "Job" => {
            // (What an earlier revision's run came to is not this one's.)
            let live = live.filter(|live| live["observedRevision"].as_u64() == Some(revision));
            let state = live.and_then(|live| live["state"].as_str());
            let number = |field: &str| live.and_then(|live| live[field].as_u64()).unwrap_or(0);
            let mut status = json!({
                "succeeded": number("succeeded"), "failed": number("failed"),
                "active": if state == Some("running") { all } else { 0 }, "ready": ready,
            });
            if live.is_some() {
                status["startTime"] = object["metadata"]["creationTimestamp"].clone();
            }
            match state {
                Some("succeeded") => status["conditions"] = json!([condition("Complete", true, "Completed")]),
                Some("failed") => {
                    let mut failed = condition("Failed", true, "BackoffLimitExceeded");
                    failed["message"] = live.map(|live| live["message"].clone()).unwrap_or_default();
                    status["conditions"] = json!([failed]);
                }
                _ => {}
            }
            status
        }
        "CronJob" => match live.map(|live| &live["last"]) {
            Some(last) if last.is_string() => json!({ "lastScheduleTime": last }),
            _ => json!({}),
        },
        "PersistentVolumeClaim" => {
            let bound = live.is_some_and(|live| live["volume"].is_string());
            json!({ "phase": if bound { "Bound" } else { "Pending" } })
        }
        "Namespace" => json!({ "phase": "Active" }),
        "Service" => json!({ "loadBalancer": {} }),
        _ => return None,
    })
}

fn owner_of(owner: &Value) -> Value {
    json!([{
        "apiVersion": owner["apiVersion"], "kind": owner["kind"], "name": owner["metadata"]["name"],
        "uid": owner["metadata"]["uid"], "controller": true, "blockOwnerDeletion": true,
    }])
}

/// What a Job made for `cron` holds beside it, where the CronJob was sent here: the Job
/// its `jobTemplate` is, by which the Job is shown as one. (Nothing for kith's own.)
pub fn job_of(cron: &Resource, name: &str) -> BTreeMap<String, String> {
    let Some((_, owner)) = served(cron).filter(|(kind, _)| kind.kind == "CronJob") else {
        return BTreeMap::new();
    };
    let template = &owner["spec"]["jobTemplate"];
    let mut job = json!({ "apiVersion": "batch/v1", "kind": "Job", "spec": template["spec"] });
    set(&mut job, "/metadata/labels", template["metadata"]["labels"].clone());
    set(&mut job, "/metadata/name", name.into());
    set(&mut job, "/metadata/namespace", owner["metadata"]["namespace"].clone());
    set(&mut job, "/metadata/ownerReferences", owner_of(&owner));
    BTreeMap::from([(SENT.into(), job.to_string()), (MADE.into(), now().to_string())])
}

/// The one ReplicaSet of a Deployment made here: a Deployment's pods are a ReplicaSet's in
/// Kubernetes, and Helm waits for the one that has the Deployment's template. Made up.
fn replica_set(deployment: &Value, resource: &Resource) -> Value {
    let mut template = deployment["spec"]["template"].clone();
    let hash = short_hash(&template.to_string());
    set(
        &mut template,
        "/metadata/labels/pod-template-hash",
        hash.as_str().into(),
    );
    let [_, new, _, both] = counts(resource);
    let meta = &deployment["metadata"];
    json!({
        "apiVersion": "apps/v1", "kind": "ReplicaSet",
        "metadata": {
            "name": format!("{}-{hash}", resource.metadata.name), "namespace": meta["namespace"],
            "labels": template["metadata"]["labels"], "ownerReferences": owner_of(deployment),
            "uid": uid(&format!("{} {hash}", meta["uid"])), "resourceVersion": meta["resourceVersion"],
            "generation": 1, "creationTimestamp": meta["creationTimestamp"],
            "annotations": { "deployment.kubernetes.io/revision": meta["generation"].to_string() },
        },
        "spec": { "replicas": deployment["spec"]["replicas"], "selector": deployment["spec"]["selector"], "template": template },
        "status": {
            "observedGeneration": 1, "replicas": new, "fullyLabeledReplicas": new,
            "readyReplicas": both, "availableReplicas": both,
        },
    })
}

/// What a pod template says, as two revisions are told apart by it: the whole blake3 of the
/// template without its hash label, its nulls and its empty maps and lists (what kubectl's
/// own encoding adds when it sends one back), and with its keys in order.
/// ponytail: a quantity as `1` and as `"1"` still differ; normalise them if undo shows one.
fn identity(template: &Value) -> String {
    fn bare(value: &Value) -> Option<Value> {
        match value {
            Value::Null => None,
            Value::Object(map) => {
                let map: BTreeMap<_, _> = map.iter().filter_map(|(k, v)| Some((k.clone(), bare(v)?))).collect();
                (!map.is_empty()).then(|| Value::Object(map.into_iter().collect()))
            }
            Value::Array(items) => {
                let items: Vec<Value> = items.iter().map(|v| bare(v).unwrap_or(Value::Null)).collect();
                (!items.is_empty()).then_some(Value::Array(items))
            }
            other => Some(other.clone()),
        }
    }
    let mut template = template.clone();
    if let Some(labels) = template.pointer_mut("/metadata/labels").and_then(Value::as_object_mut) {
        labels.remove("pod-template-hash");
    }
    blake3::hash(bare(&template).unwrap_or_default().to_string().as_bytes())
        .to_hex()
        .to_string()
}

/// A pod template a Deployment's kept revisions held.
struct Kept {
    id: String,
    /// The newest revision that held it (a revision a scale made holds it too).
    revision: u64,
    /// When the oldest revision that held it was made.
    at: u64,
    /// The template as that newest revision was sent.
    template: Value,
}

/// The templates the revisions the store kept of the Deployment `key` held, one for each
/// ([`identity`]), by the revision that last held it. Only a revision made through this
/// API says what it held (a `kith apply` of the same Workload does not): that one is passed over.
/// ponytail: reads every kept revision's sent text (at most `HISTORY_LIMIT`) for each read of
/// a Deployment's ReplicaSets; keep the result with the resource if that shows in a profile.
fn kept(store: &Store, key: &str) -> Vec<Kept> {
    let mut found: Vec<Kept> = Vec::new();
    for old in store.history(key).into_iter().flatten() {
        let Some((_, object)) = raw(&old.resource).filter(|(kind, _)| kind.kind == "Deployment") else {
            continue;
        };
        let Some(revision) = old.resource.metadata.revision else {
            continue;
        };
        let template = object["spec"]["template"].clone();
        let id = identity(&template);
        match found.iter_mut().find(|held| held.id == id) {
            Some(held) => (held.revision, held.template) = (revision, template),
            None => found.push(Kept {
                id,
                revision,
                at: old.at,
                template,
            }),
        }
    }
    found.sort_by_key(|held| held.revision);
    found
}

/// Whether a read of the ReplicaSet `name` (any, for `None`) can find one of the Deployment
/// `owner`'s earlier revisions: the names made of them are the Deployment's, a dash and
/// [`short_hash`]'s ten hex digits. For any other name the history is not read.
fn may_be_history(owner: &str, name: Option<&str>) -> bool {
    let Some(name) = name else { return true };
    let hash = name.strip_prefix(owner).and_then(|rest| rest.strip_prefix('-'));
    hash.is_some_and(|hash| hash.len() == 10 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The ReplicaSets `kubectl rollout history` finds besides the live one: one for each
/// template of an earlier revision of `owner` (the Deployment as it is, of `resource`), made
/// up as the live one is, with no replicas and the number of the revision that last held it.
fn history_sets(store: &Store, owner: &Value, resource: &Resource) -> Vec<Value> {
    let live = identity(&owner["spec"]["template"]);
    let old = kept(store, &resource.key()).into_iter().filter(|held| held.id != live);
    old.map(|held| {
        let mut was = owner.clone();
        set(&mut was, "/spec/template", held.template);
        set(&mut was, "/spec/replicas", 0.into());
        set(&mut was, "/metadata/generation", held.revision.into());
        set(&mut was, "/metadata/creationTimestamp", rfc3339(held.at).into());
        set(&mut was, "/metadata/resourceVersion", (held.revision << 32).to_string().into());
        let mut made = replica_set(&was, resource);
        let none = json!({ "observedGeneration": 1, "replicas": 0, "fullyLabeledReplicas": 0, "readyReplicas": 0, "availableReplicas": 0 });
        set(&mut made, "/status", none);
        made
    })
    .collect()
}

/// The kinds that run pods, and the mark each puts before a replica's number in a pod's
/// name: a Workload's pods are `NAME-N` (a StatefulSet's names are a contract), a Job's
/// `NAME-jN` and a NodeWorkload's `NAME-nN`. A Job and a Workload may share a name, so the
/// mark is what keeps their pods apart.
const POD_MARKS: [(&str, &str); 3] = [("Workload", ""), ("Job", "j"), ("NodeWorkload", "n")];

/// The name of the pod that replica `replica` of `holder` (`Workload`, `Job` or
/// `NodeWorkload`) named `owner` is. The one place a pod's name is made.
fn pod_name(holder: &str, owner: &str, replica: u64) -> String {
    let mark = POD_MARKS
        .iter()
        .find(|(kind, _)| *kind == holder)
        .map_or("", |(_, mark)| mark);
    format!("{owner}-{mark}{replica}")
}

/// Whether a Pod named `name` would be a name a Job, a Workload or the pod of one already has.
fn taken(store: &Store, namespace: Option<&str>, name: &str) -> bool {
    let namespace = namespace.unwrap_or(kith_api::DEFAULT_NAMESPACE);
    let held = |holder: &str, name: &str| store.get(&format!("{holder}/{namespace}/{name}")).is_some();
    held("Job", name) || held("Workload", name) || pod_owner(name).is_some_and(|(holder, owner, _)| held(holder, owner))
}

/// Whether a bare Pod of `namespace` has the name of a pod that `holder`'s resource `name` would run
/// (any replica: `taken`'s own reading, the other way). Two pods of one name are one to every verb.
fn shadowed(store: &Store, namespace: Option<&str>, runs: &str, name: &str) -> bool {
    let namespace = namespace.unwrap_or(kith_api::DEFAULT_NAMESPACE);
    ["Job", "Workload"].into_iter().any(|kind| {
        store.list(Some(kind)).any(|held| {
            let here = held
                .metadata
                .namespace
                .as_deref()
                .unwrap_or(kith_api::DEFAULT_NAMESPACE)
                == namespace;
            let pod = &held.metadata.name;
            here && pod_owner(pod).is_some_and(|(of, owner, _)| of == runs && owner == name)
                && held_bare(store, Some(namespace), pod).is_some()
        })
    })
}

/// What a pod's name says: the kind that runs it, that kind's resource's name and the
/// replica. The one place a pod's name is read, and only what [`pod_name`] makes is read
/// (so `x-j0` is the Workload `x`'s pod 0 only as `x-j0-0`): anything else is no pod.
pub(crate) fn pod_owner(pod: &str) -> Option<(&'static str, &str, u32)> {
    // (Only the part after the last dash is looked at, whatever the owner is called.)
    let (owner, ending) = pod.rsplit_once('-')?;
    let (holder, replica) = POD_MARKS.iter().find_map(|(holder, mark)| {
        let digits = ending.strip_prefix(mark)?;
        // (Digits alone: not `+1`, and not a number with a zero before it, which is another's name.)
        let canonical = !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
        let replica: u32 = digits.parse().ok().filter(|_| canonical)?;
        (pod_name(holder, owner, replica.into()) == pod).then_some((*holder, replica))
    })?;
    (!owner.is_empty()).then_some((holder, owner, replica))
}

/// What a pod named `pod` in `namespace` is, as [`pod_owner`] says it, but a bare Pod's name first: it is
/// its own Job's or Workload's run 0, held under the name sent. The one resolver of every verb that
/// reaches a pod (logs, exec, port-forward and the hop to the node that runs it).
/// A name that both a bare Pod and a replica of an existing Job or Workload have is no pod: it is told
/// as one not found, to every caller and every verb, so that neither can take the other's calls (the
/// mark `kith.dev/pod` is on a resource whoever may apply one can write).
pub(crate) fn resolve_pod<'a>(store: &Store, namespace: &str, pod: &'a str) -> Option<(&'static str, &'a str, u32)> {
    let named = pod_owner(pod);
    match held_bare(store, Some(namespace), pod) {
        Some(row) => {
            let both = named.is_some_and(|(of, owner, _)| store.get(&format!("{of}/{namespace}/{owner}")).is_some());
            (!both).then(|| (holder(row), pod, 0))
        }
        None => named,
    }
}

/// The native apply's own `taken`: a resource marked `kith.dev/pod` (a bare Pod, made by `kith apply` of one)
/// whose name is a pod of an existing Job or Workload, or of one in the same body, is refused. The Kubernetes
/// API's create has refused it by `taken` already; a native apply did not, and so could take a pod's calls.
pub(crate) fn hijacks(store: &Store, resources: &[Resource]) -> Result<(), String> {
    let namespace = |r: &Resource| r.metadata.namespace.clone().unwrap_or_else(|| kith_api::DEFAULT_NAMESPACE.into());
    for bare in resources.iter().filter(|r| {
        matches!(r.kind.as_str(), "Job" | "Workload") && r.metadata.annotations.get("kith.dev/pod").is_some_and(|m| m == "true")
    }) {
        let Some((of, owner, _)) = pod_owner(&bare.metadata.name) else {
            continue;
        };
        let space = namespace(bare);
        let there = store.get(&format!("{of}/{space}/{owner}")).is_some()
            || resources.iter().any(|r| r.kind == of && r.metadata.name == owner && namespace(r) == space);
        if there {
            let name = &bare.metadata.name;
            return Err(format!("{name}: a bare Pod's name is not one that a pod of a Job or Workload has"));
        }
    }
    Ok(())
}

/// The pods of what `owner` runs: one for each replica its status tells of, named by
/// [`pod_name`]. Made up: a pod is not a resource of kith's.
fn pods(owner: &Value, resource: &Resource) -> Vec<Value> {
    let (template, meta) = (&owner["spec"]["template"], &owner["metadata"]);
    let mut replicas: BTreeMap<u64, Vec<&Value>> = BTreeMap::new();
    let units = resource
        .status
        .as_ref()
        .and_then(|status| status["containers"].as_array());
    // A Job that is over runs nothing more, and what its runs wrote is still theirs to be
    // asked for (`kubectl logs job/NAME` asks the Job's pods): a pod for each run that ended.
    //
    // ponytail: the runs that succeeded are counted here, not named, so with `parallelism`
    // a failed Job's pods may be numbered otherwise than its runs were; and the code a
    // failed run exited with is not kept.
    let over = resource.status.as_ref().filter(|status| {
        let ended = matches!(status["state"].as_str(), Some("succeeded" | "failed"));
        owner["kind"] == "Job" && ended && units.is_none_or(|units| units.is_empty())
    });
    let mut ended = Vec::new();
    if let Some(status) = over {
        // (A Job that succeeded ran once at least, whatever count its status kept.)
        let succeeded = status["succeeded"]
            .as_u64()
            .unwrap_or(0)
            .max(u64::from(status["state"] == "succeeded"));
        let runs = succeeded + u64::from(status["state"] == "failed");
        let names = template["spec"]["containers"].as_array();
        for run in 0..runs {
            let code = if run < succeeded { json!(0) } else { Value::Null };
            ended.extend(names.into_iter().flatten().map(|container| {
                json!({
                    "name": container["name"], "replica": run, "state": "exited", "exitCode": code,
                    "ready": false, "restarts": 0, "node": status["nodes"]["0"],
                })
            }));
        }
    }
    for unit in units.into_iter().flatten().chain(&ended) {
        if let Some(replica) = unit["replica"].as_u64() {
            replicas.entry(replica).or_default().push(unit);
        }
    }
    let mut labels = template["metadata"]["labels"].clone();
    let owned = match owner["kind"].as_str() {
        Some("Deployment") => {
            let set_of = replica_set(owner, resource);
            labels = set_of["metadata"]["labels"].clone();
            owner_of(&set_of)
        }
        kind => {
            if kind == Some("Job") {
                set(&mut labels, "/job-name", meta["name"].clone());
            }
            owner_of(owner)
        }
    };
    let state = |unit: &Value| unit["state"].as_str().unwrap_or("pending").to_string();
    // (Which of a pod's are its initContainers: they are told of apart, and are not what is running.)
    let named = |list: &str, unit: &Value| {
        let of = template["spec"][list].as_array();
        of.into_iter().flatten().find(|c| c["name"] == unit["name"])
    };
    let pod = |(replica, all): (u64, Vec<&Value>)| {
        let ready = all.iter().all(|unit| unit["ready"] == true);
        let (first, units): (Vec<&Value>, Vec<&Value>) = all
            .iter()
            .copied()
            .partition(|unit| named("initContainers", unit).is_some());
        let begun = first.iter().all(|unit| unit["ready"] == true);
        let phase = if all.iter().all(|unit| state(unit) == "exited") {
            match all.iter().all(|unit| unit["exitCode"] == 0) {
                true => "Succeeded",
                false => "Failed",
            }
        } else if units.iter().any(|unit| state(unit) == "running") {
            "Running"
        } else {
            "Pending"
        };
        let container = |unit: &&Value| {
            let image = named("initContainers", unit)
                .or_else(|| named("containers", unit))
                .map(|c| c["image"].clone());
            let is = match state(unit).as_str() {
                "running" => json!({ "running": {} }),
                "exited" => {
                    let reason = if unit["exitCode"] == 0 { "Completed" } else { "Error" };
                    json!({ "terminated": { "exitCode": unit["exitCode"], "reason": reason } })
                }
                _ => {
                    let again = unit["restarts"].as_u64().is_some_and(|restarts| restarts > 0);
                    let reason = if again { "CrashLoopBackOff" } else { "ContainerCreating" };
                    json!({ "waiting": { "reason": reason, "message": unit["message"] } })
                }
            };
            json!({
                "name": unit["name"], "image": image, "imageID": "", "ready": unit["ready"],
                "started": state(unit) == "running", "restartCount": unit["restarts"], "state": is,
            })
        };
        let mut spec = template["spec"].clone();
        let (node, address) = (&all[0]["node"], &all[0]["address"]);
        if !node.is_null() {
            set(&mut spec, "/nodeName", node.clone());
        }
        // A replica a delete restarted starts at its restart; the rest at their owner's making.
        let since = all.iter().filter_map(|unit| unit["restarted"].as_u64()).max();
        let started = since.map_or(meta["creationTimestamp"].clone(), |at| rfc3339(at).into());
        let mut status = json!({
            "phase": phase, "startTime": started,
            "conditions": [
                condition("Initialized", begun, ""), condition("PodScheduled", true, ""),
                condition("ContainersReady", ready, ""), condition("Ready", ready, ""),
            ],
            "containerStatuses": units.iter().map(container).collect::<Vec<_>>(),
        });
        if !first.is_empty() {
            status["initContainerStatuses"] = first.iter().map(container).collect();
        }
        if !address.is_null() {
            status["podIP"] = address.clone();
            status["podIPs"] = json!([{ "ip": address }]);
        }
        json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {
                "name": pod_name(&resource.kind, &resource.metadata.name, replica), "namespace": meta["namespace"],
                "labels": labels, "ownerReferences": owned, "uid": uid(&format!("{} {replica}", meta["uid"])),
                "resourceVersion": meta["resourceVersion"], "creationTimestamp": meta["creationTimestamp"],
            },
            "spec": spec, "status": status,
        })
    };
    replicas.into_iter().map(pod).collect()
}

/// The Pod a Job or a Workload holds that was sent as one (`sent`, served), as it was sent: by
/// its own name, labels and annotations, and owned by nothing; its status is its run's. One
/// that has not run yet is Pending (its owner has no units to say so), and of a Job's runs the last is it.
fn bare_pod(sent: &Value, resource: &Resource) -> Option<Value> {
    let owner = json!({
        "kind": resource.kind, "metadata": sent["metadata"],
        "spec": { "template": { "metadata": { "labels": sent["metadata"]["labels"] }, "spec": sent["spec"] } },
    });
    let mut made = pods(&owner, resource);
    if made.is_empty() {
        let containers = ["initContainers", "containers"]
            .into_iter()
            .flat_map(|list| sent["spec"][list].as_array().into_iter().flatten());
        let units: Vec<Value> = containers
            .map(|c| json!({ "name": c["name"], "replica": 0, "state": "pending", "ready": false }))
            .collect();
        let mut waiting = resource.clone();
        waiting.status = Some(json!({ "containers": units }));
        made = pods(&owner, &waiting);
    }
    let mut pod = made.pop()?;
    pod["metadata"] = sent["metadata"].clone();
    Some(pod)
}

/// What a read of the store looks at, and what it did.
#[derive(Default)]
struct Look<'a> {
    /// Only the resources of these keys (none: every one).
    only: Option<&'a BTreeSet<&'a str>>,
    /// How many resources were made into objects.
    translated: usize,
}

/// The resources that are `holder`s: of those the store has, or of those `only` names that it has.
fn held<'a>(
    store: &'a Store,
    holder: &'a str,
    only: Option<&'a BTreeSet<&'a str>>,
) -> Box<dyn Iterator<Item = &'a Resource> + 'a> {
    match only {
        None => Box::new(store.list(Some(holder))),
        Some(keys) => Box::new(
            keys.iter()
                .filter_map(|key| store.get(key))
                .filter(move |r| r.kind == holder),
        ),
    }
}

/// The objects of a kind that is not held, made up from what the store says: `caller` sees
/// those of the resources it may see. Each comes with the key of the resource it is made of.
fn made(
    store: &Store,
    kind: &Kind,
    namespace: Option<&str>,
    name: Option<&str>,
    may: &dyn Fn(&&Resource) -> bool,
    look: &mut Look,
) -> Vec<(String, Value)> {
    let within = |resource: &&Resource| namespace.is_none_or(|ns| resource.metadata.namespace.as_deref() == Some(ns));
    let mut found = Vec::new();
    let owners: &[&str] = match kind.kind {
        "Pod" | "ReplicaSet" => &["Workload", "NodeWorkload", "Job"],
        "Node" => &["Node"],
        _ => &[],
    };
    for resource in owners
        .iter()
        .flat_map(|owner| held(store, owner, look.only))
        .filter(within)
        .filter(may)
    {
        // (A pod's name, and a ReplicaSet's, begin with their owner's.)
        if name.is_some_and(|name| !name.starts_with(&resource.metadata.name)) {
            continue;
        }
        look.translated += 1;
        let of = resource.key();
        if kind.kind == "Node" {
            let said = |field: &str| resource.status.as_ref().and_then(|status| status[field].as_str());
            let address = said("address").and_then(|address| address.rsplit_once(':'));
            let address = address.map(|(host, _)| host.trim_matches(['[', ']']));
            found.push((
                of,
                json!({
                    "apiVersion": "v1", "kind": "Node",
                    "metadata": {
                        "name": resource.metadata.name, "labels": resource.metadata.labels,
                        "uid": uid(&resource.key()), "resourceVersion": version(resource).to_string(),
                        "creationTimestamp": oldest(store, resource),
                    },
                    "spec": {},
                    "status": {
                        "conditions": [condition("Ready", said("state") != Some("unreachable"), "KithdReady")],
                        "addresses": [{ "type": "InternalIP", "address": address }],
                        "nodeInfo": { "kubeletVersion": concat!("kith-", env!("CARGO_PKG_VERSION")) },
                    },
                }),
            ));
            continue;
        }
        let Some((_, owner)) = served(resource) else { continue };
        match kind.kind {
            "Pod" if owner["kind"] == "Pod" => found.extend(bare_pod(&owner, resource).map(|pod| (of.clone(), pod))),
            "Pod" => found.extend(pods(&owner, resource).into_iter().map(|pod| (of.clone(), pod))),
            _ if owner["kind"] == "Deployment" => {
                let before = if may_be_history(&resource.metadata.name, name) {
                    history_sets(store, &owner, resource)
                } else {
                    Vec::new()
                };
                found.extend(before.into_iter().map(|old| (of.clone(), old)));
                found.push((of, replica_set(&owner, resource)));
            }
            _ => {}
        }
    }
    found.retain(|(_, object)| name.is_none_or(|name| object["metadata"]["name"] == name));
    found
}

/// Every object of `kind` there is (in `namespace`, named `name`) that `grants` let be seen.
fn objects(
    store: &Store,
    kind: &'static Kind,
    namespace: Option<&str>,
    name: Option<&str>,
    grants: &Grants,
    verb: &Verb,
) -> Vec<Value> {
    let found = read(store, kind, namespace, name, grants, verb, &mut Look::default());
    found.into_iter().map(|(_, object)| object).collect()
}

/// [`objects`], each with the key of the resource it is made of, and as `look` says: of the
/// resources it names only (not for a namespace, which is made of all of them).
fn read(
    store: &Store,
    kind: &'static Kind,
    namespace: Option<&str>,
    name: Option<&str>,
    grants: &Grants,
    verb: &Verb,
    look: &mut Look,
) -> Vec<(String, Value)> {
    let may = |resource: &&Resource| {
        let (namespace, name) = (
            resource.metadata.namespace.as_deref(),
            Some(resource.metadata.name.as_str()),
        );
        grants.may(verb, &resource.kind, namespace, name)
    };
    let of_kind = |(of, object): (&'static Kind, Value)| std::ptr::eq(of, kind).then_some(object);
    match (kind.held, name) {
        (Held::Made, _) => made(store, kind, namespace, name, &may, look),
        // A namespace is there when it is said to be, and when anything is in it.
        (Held::As("Namespace"), _) => {
            if !grants.may(verb, "Namespace", None, None) {
                return Vec::new();
            }
            let mut names: BTreeSet<&str> = store
                .list(None)
                .filter_map(|r| r.metadata.namespace.as_deref())
                .collect();
            names.insert(kith_api::DEFAULT_NAMESPACE);
            names.extend(store.list(Some("Namespace")).map(|r| r.metadata.name.as_str()));
            let object = |name: &str| {
                let said = store.get(&format!("Namespace/{name}")).and_then(|r| {
                    let (_, mut object) = served(r)?;
                    // (One made through these paths has been given the time it was made.)
                    if object.pointer("/metadata/creationTimestamp").is_none() {
                        set(&mut object, "/metadata/creationTimestamp", oldest(store, r).into());
                    }
                    Some(object)
                });
                said.unwrap_or_else(|| {
                    json!({
                        "apiVersion": "v1", "kind": "Namespace",
                        "metadata": { "name": name, "uid": uid(name), "resourceVersion": "1" },
                        "status": { "phase": "Active" },
                    })
                })
            };
            let asked = names.into_iter().filter(|found| name.is_none_or(|name| name == *found));
            let found: Vec<_> = asked.map(|name| (format!("Namespace/{name}"), object(name))).collect();
            look.translated += found.len();
            found
        }
        (_, Some(name)) => {
            let found = store.get(&key(kind, namespace, name)).filter(may);
            look.translated += usize::from(found.is_some());
            let found = found.and_then(|r| Some((r.key(), served(r)?)));
            found
                .and_then(|(at, served)| Some((at, of_kind(served)?)))
                .into_iter()
                .collect()
        }
        (_, None) => {
            let within = |r: &&Resource| namespace.is_none_or(|ns| r.metadata.namespace.as_deref() == Some(ns));
            // (Of what is kept, only this kind's are read.)
            let this = |r: &&Resource| r.kind != "KubeObject" || r.spec["object"]["kind"] == kind.kind;
            let kept = held(store, holder(kind), look.only)
                .filter(within)
                .filter(may)
                .filter(this);
            let found: Vec<_> = kept
                .filter_map(|r| Some((r.key(), served(r)?)))
                .filter_map(|(at, served)| Some((at, of_kind(served)?)))
                .collect();
            look.translated += found.len();
            found
        }
    }
}

/// Does `object` fit what a request selects: its `labelSelector` (`a=b,c!=d,e,!f,g in
/// (h,i),j notin (k)`) and its `fieldSelector` (`metadata.name=x,status.phase!=Running`)?
fn selected(object: &Value, asked: &Asked) -> bool {
    let labels = &object["metadata"]["labels"];
    let label = |term: &str| {
        let has = |key: &str| labels.get(key.trim()).and_then(Value::as_str);
        let among = |key: &str, set: &str| {
            let set = set.trim().trim_start_matches('(').trim_end_matches(')');
            has(key).is_some_and(|value| set.split(',').any(|one| one.trim() == value))
        };
        if let Some((key, set)) = term.split_once(" notin ") {
            !among(key, set)
        } else if let Some((key, set)) = term.split_once(" in ") {
            among(key, set)
        } else if let Some((key, value)) = term.split_once("!=") {
            has(key) != Some(value.trim())
        } else if let Some((key, value)) = term.split_once("==").or(term.split_once('=')) {
            has(key) == Some(value.trim())
        } else {
            match term.strip_prefix('!') {
                Some(key) => has(key).is_none(),
                None => has(term).is_some(),
            }
        }
    };
    let field = |term: &str| {
        let (path, value, same) = match term.split_once("!=") {
            Some((path, value)) => (path, value, false),
            None => {
                let (path, value) = term.split_once("==").or(term.split_once('=')).unwrap_or((term, ""));
                (path, value, true)
            }
        };
        let found = path.trim().split('.').fold(object, |at, part| &at[part]);
        let found = match found {
            Value::String(text) => text.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        (found == value.trim()) == same
    };
    // (A comma inside `in (a,b)` is not between two terms.)
    let terms = |selector: Option<&String>| {
        let mut depth = 0;
        let between = |c: char| {
            depth += i32::from(c == '(') - i32::from(c == ')');
            c == ',' && depth == 0
        };
        let all = selector.map(String::as_str).unwrap_or_default().split(between);
        all.map(str::trim)
            .filter(|term| !term.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    terms(asked.get("labelSelector")).iter().all(|term| label(term))
        && terms(asked.get("fieldSelector")).iter().all(|term| field(term))
}

/// The seconds since 1970 of a time as [`rfc3339`] writes one.
fn seconds(at: &str) -> Option<u64> {
    let n = |range: std::ops::Range<usize>| at.get(range)?.parse::<u64>().ok();
    let (year, month, day) = (n(0..4)?, n(5..7)?, n(8..10)?);
    // Days from the civil date, as Howard Hinnant's algorithms have it.
    let (year, shifted) = if month <= 2 {
        (year.checked_sub(1)?, month + 9)
    } else {
        (year, month.checked_sub(3)?)
    };
    let of_era = year % 400;
    let days = year / 400 * 146_097 + of_era * 365 + of_era / 4 - of_era / 100 + (153 * shifted + 2) / 5 + day - 1;
    Some(days.checked_sub(719_468)? * 86400 + n(11..13)? * 3600 + n(14..16)? * 60 + n(17..19)?)
}

/// What `kubectl get` shows of an object: each column's name and what is in it.
fn row(kind: &str, object: &Value) -> Vec<(&'static str, Value)> {
    let at = |path: &str| object.pointer(path).cloned().unwrap_or(Value::Null);
    let n = |path: &str| object.pointer(path).and_then(Value::as_u64).unwrap_or(0);
    let of = |have: u64, all: u64| Value::from(format!("{have}/{all}"));
    let list = |path: &str| {
        object
            .pointer(path)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let size = |path: &str| {
        object
            .pointer(path)
            .and_then(Value::as_object)
            .map_or(0, |data| data.len())
    };
    let mut row = vec![("Name", at("/metadata/name"))];
    match kind {
        "Pod" => {
            let units = list("/status/containerStatuses");
            let ready = units.iter().filter(|unit| unit["ready"] == true).count() as u64;
            let restarts: u64 = units.iter().filter_map(|unit| unit["restartCount"].as_u64()).sum();
            let waiting = units.iter().find_map(|unit| unit.pointer("/state/waiting/reason"));
            let is = match (waiting, at("/status/phase")) {
                (Some(reason), _) => reason.clone(),
                (None, phase) if phase == "Succeeded" => "Completed".into(),
                (None, phase) => phase,
            };
            row.extend([
                ("Ready", of(ready, units.len() as u64)),
                ("Status", is),
                ("Restarts", restarts.into()),
                ("IP", at("/status/podIP")),
                ("Node", at("/spec/nodeName")),
            ]);
        }
        "Deployment" => row.extend([
            ("Ready", of(n("/status/readyReplicas"), n("/spec/replicas"))),
            ("Up-to-date", at("/status/updatedReplicas")),
            ("Available", at("/status/availableReplicas")),
        ]),
        "StatefulSet" => row.push(("Ready", of(n("/status/readyReplicas"), n("/spec/replicas")))),
        "DaemonSet" => row.extend([
            ("Desired", at("/status/desiredNumberScheduled")),
            ("Current", at("/status/currentNumberScheduled")),
            ("Ready", at("/status/numberReady")),
            ("Up-to-date", at("/status/updatedNumberScheduled")),
        ]),
        "ReplicaSet" => row.extend([
            ("Desired", at("/spec/replicas")),
            ("Current", at("/status/replicas")),
            ("Ready", at("/status/readyReplicas")),
        ]),
        "Job" => {
            let is = at("/status/conditions/0/type");
            let is = if is.is_null() { "Running".into() } else { is };
            let done = of(n("/status/succeeded"), n("/spec/completions"));
            row.extend([("Status", is), ("Completions", done)]);
        }
        "CronJob" => row.extend([
            ("Schedule", at("/spec/schedule")),
            ("Last schedule", at("/status/lastScheduleTime")),
        ]),
        "Service" => {
            let port = |port: &Value| format!("{}/{}", port["port"], port["protocol"].as_str().unwrap_or("TCP"));
            let ports: Vec<String> = list("/spec/ports").iter().map(port).collect();
            row.extend([
                ("Type", at("/spec/type")),
                ("Cluster-IP", at("/spec/clusterIP")),
                ("Port(s)", ports.join(",").into()),
            ]);
        }
        "Ingress" => {
            let hosts: Vec<Value> = list("/spec/rules").iter().map(|rule| rule["host"].clone()).collect();
            let hosts: Vec<&str> = hosts.iter().filter_map(Value::as_str).collect();
            row.push(("Hosts", hosts.join(",").into()));
        }
        "PersistentVolumeClaim" => row.extend([
            ("Status", at("/status/phase")),
            ("Volume", at("/spec/volumeName")),
            ("Capacity", at("/spec/resources/requests/storage")),
        ]),
        "Secret" => row.extend([("Type", at("/type")), ("Data", size("/data").into())]),
        "ConfigMap" => row.push(("Data", size("/data").into())),
        "Namespace" => row.push(("Status", at("/status/phase"))),
        "Node" => {
            let ready = at("/status/conditions/0/status") == "True";
            let is = if ready { "Ready" } else { "NotReady" };
            row.push(("Status", is.into()));
        }
        _ => {}
    }
    let made = object.pointer("/metadata/creationTimestamp").and_then(Value::as_str);
    let age = made.and_then(seconds).map(|made| match now().saturating_sub(made) {
        secs @ 0..120 => format!("{secs}s"),
        secs @ 120..7200 => format!("{}m", secs / 60),
        secs @ 7200..172_800 => format!("{}h", secs / 3600),
        secs => format!("{}d", secs / 86400),
    });
    row.push(("Age", age.into()));
    row
}

/// Objects as the table `kubectl get` prints: the server says the columns.
fn table(kind: &Kind, objects: &[Value], at: u64) -> Value {
    let column = |(name, _): &(&str, Value)| {
        let wide = matches!(*name, "IP" | "Node");
        let format = if *name == "Name" { "name" } else { "" };
        json!({ "name": name, "type": "string", "format": format, "description": "", "priority": i32::from(wide) })
    };
    let columns: Vec<Value> = row(kind.kind, &Value::Null).iter().map(column).collect();
    let line = |object: &Value| {
        let cells: Vec<Value> = row(kind.kind, object).into_iter().map(|(_, cell)| cell).collect();
        let of =
            json!({ "kind": "PartialObjectMetadata", "apiVersion": "meta.k8s.io/v1", "metadata": object["metadata"] });
        json!({ "cells": cells, "object": of })
    };
    json!({
        "kind": "Table", "apiVersion": "meta.k8s.io/v1", "metadata": { "resourceVersion": at.to_string() },
        "columnDefinitions": columns, "rows": objects.iter().map(line).collect::<Vec<_>>(),
    })
}

/// The field that names an item of the list `list`, where a strategic patch merges it.
fn merge_key(list: &str, item: &Value) -> Option<&'static str> {
    // (Of a list that two keys name, the item's own; an item with neither is by the last.)
    let keys: Vec<&str> = MERGED.iter().filter(|(of, _)| *of == list).map(|(_, by)| *by).collect();
    keys.iter().find(|by| item.get(**by).is_some()).or(keys.last()).copied()
}

/// `patch` laid over `live`: a JSON merge patch, or with `strategic` Kubernetes's own (the
/// lists of [`MERGED`] item by item, and its `$` directives).
fn patched(live: &mut Value, patch: Value, strategic: bool) {
    let Value::Object(patch) = patch else {
        *live = patch;
        return;
    };
    if !live.is_object() || (strategic && patch.get("$patch").is_some_and(|how| how == "replace")) {
        *live = json!({});
    }
    let Some(into) = live.as_object_mut() else { return };
    let (mut orders, mut keep) = (Vec::new(), None);
    for (field, value) in patch {
        // A `$` field of a strategic patch says how to merge, and is not itself merged in.
        if let Some(directive) = field.strip_prefix('$').filter(|_| strategic) {
            match (directive.split_once('/'), value) {
                (None, Value::Array(keys)) if directive == "retainKeys" => keep = Some(keys),
                (Some(("setElementOrder", list)), Value::Array(order)) => orders.push((list.to_string(), order)),
                (Some(("deleteFromPrimitiveList", list)), Value::Array(gone)) => {
                    if let Some(Value::Array(have)) = into.get_mut(list) {
                        have.retain(|value| !gone.contains(value));
                    }
                }
                _ => {}
            }
            continue;
        }
        let by = value.as_array().and_then(|items| merge_key(&field, items.first()?));
        match (value, by.filter(|_| strategic)) {
            (Value::Null, _) => drop(into.remove(&field)),
            (Value::Array(items), Some(by)) => merged(into.entry(field).or_insert(Value::Null), items, by),
            (Value::Object(part), _) if strategic && part.get("$patch").is_some_and(|how| how == "delete") => {
                into.remove(&field);
            }
            (part @ Value::Object(_), _) => patched(into.entry(field).or_insert(Value::Null), part, strategic),
            (value, _) => drop(into.insert(field, value)),
        }
    }
    for (list, order) in orders {
        if let Some(Value::Array(have)) = into.get_mut(&list)
            && let Some(by) = have.first().and_then(|first| merge_key(&list, first))
        {
            let place = |item: &Value| order.iter().position(|named| named[by] == item[by]);
            have.sort_by_key(|item| place(item).unwrap_or(usize::MAX));
        }
    }
    if let Some(keep) = keep {
        into.retain(|field, _| keep.iter().any(|kept| kept == field));
    }
}

/// The list of a strategic patch merged into the list that is there: each item into the
/// one that has its `by`, or added; `$patch: delete` takes one out, `replace` them all.
fn merged(have: &mut Value, items: Vec<Value>, by: &str) {
    if !have.is_array() || items.iter().any(|item| item["$patch"] == "replace") {
        *have = json!([]);
    }
    let Some(have) = have.as_array_mut() else { return };
    for item in items {
        let at = have.iter().position(|had| !item[by].is_null() && had[by] == item[by]);
        match (item["$patch"].as_str().map(|how| how == "delete"), at) {
            (Some(true), Some(at)) => drop(have.remove(at)),
            // (`replace` is of the list, and was done; what is to go and is not there is gone.)
            (Some(_), _) => {}
            (None, Some(at)) => patched(&mut have[at], item, true),
            (None, None) => {
                let mut new = Value::Null;
                patched(&mut new, item, true);
                have.push(new);
            }
        }
    }
}

/// The most operations a JSON patch has, and the most bytes its copies make in all: a copy of
/// a whole document doubles it, so the copies are what is bounded.
// ponytail: one budget for the whole patch; per-copy limits if a real patch ever meets these.
const PATCH_OPS: usize = 256;
const PATCH_COPY_BYTES: usize = 16 << 20;

/// RFC 6902's operations applied in order to a copy of `live`, which is what comes back. One
/// that fails (a `test` not so, a path not there, a pointer not written as one) refuses the
/// whole patch, and `live` is not changed: the caller writes nothing then.
fn json_patch(live: &Value, ops: &Value) -> Result<Value, String> {
    let Value::Array(ops) = ops else {
        return Err("the patch is a list of operations, each { op, path, ... }".into());
    };
    if ops.len() > PATCH_OPS {
        return Err(format!("a patch has at most {PATCH_OPS} operations"));
    }
    let mut doc = live.clone();
    let mut copied = 0;
    for op in ops {
        let kind = op.get("op").and_then(Value::as_str).ok_or("an operation has no op")?;
        let pointer = op
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{kind}: needs a path"))?;
        let value = || {
            op.get("value")
                .cloned()
                .ok_or_else(|| format!("{kind} {pointer}: needs a value"))
        };
        let source = || {
            op.get("from")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{kind} {pointer}: needs a from"))
        };
        match kind {
            "add" => insert(&mut doc, pointer, value()?)?,
            "replace" => {
                let value = value()?;
                *find(&mut doc, pointer)? = value;
            }
            "remove" => drop(take(&mut doc, pointer)?),
            "test" => {
                let want = value()?;
                if !same(find(&mut doc, pointer)?, &want) {
                    return Err(format!("test {pointer}: the value is not the one given"));
                }
            }
            "copy" => {
                let made = find(&mut doc, source()?)?;
                copied += made.to_string().len();
                if copied > PATCH_COPY_BYTES {
                    return Err(format!(
                        "copy {pointer}: the copies make more than {PATCH_COPY_BYTES} bytes"
                    ));
                }
                let made = made.clone();
                insert(&mut doc, pointer, made)?;
            }
            "move" => {
                let from = source()?;
                // (A value is not moved into itself: `from` is not a proper prefix of `pointer`.)
                if pointer.len() > from.len() && pointer.starts_with(from) && pointer[from.len()..].starts_with('/') {
                    return Err(format!("move {pointer}: {from} is above it"));
                }
                let moved = take(&mut doc, from)?;
                insert(&mut doc, pointer, moved)?;
            }
            other => return Err(format!("{other}: not one of add, remove, replace, move, copy, test")),
        }
    }
    Ok(doc)
}

/// The steps of an RFC 6901 pointer: `""` is the whole document, `/a/0` is `a` then `0`, and a
/// `~` in a step is `~0` or `~1`, nothing else.
fn tokens(pointer: &str) -> Result<Vec<String>, String> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    let Some(rest) = pointer.strip_prefix('/') else {
        return Err(format!("{pointer}: a path starts with /"));
    };
    rest.split('/')
        .map(|step| {
            if !step.split('~').skip(1).all(|after| after.starts_with(['0', '1'])) {
                return Err(format!("{pointer}: a ~ is written ~0 or ~1"));
            }
            Ok(step.replace("~1", "/").replace("~0", "~"))
        })
        .collect()
}

/// An index of a list as RFC 6901 writes one: digits, with no leading zero (`-` is not one).
fn index(step: &str, pointer: &str) -> Result<usize, String> {
    let digits =
        !step.is_empty() && step.bytes().all(|b| b.is_ascii_digit()) && !(step.len() > 1 && step.starts_with('0'));
    digits
        .then(|| step.parse::<usize>().ok())
        .flatten()
        .ok_or_else(|| format!("{pointer}: {step} is not an index"))
}

/// The place `pointer` names in `doc`, which must be there.
fn find<'a>(doc: &'a mut Value, pointer: &str) -> Result<&'a mut Value, String> {
    let mut at = doc;
    for step in tokens(pointer)? {
        let next = match at {
            Value::Object(map) => map.get_mut(&step),
            Value::Array(items) => items.get_mut(index(&step, pointer)?),
            _ => None,
        };
        at = next.ok_or_else(|| format!("{pointer}: the path is not there"))?;
    }
    Ok(at)
}

/// Puts `value` at `pointer`: a key of a mapping (made if it is not there), or an index of a
/// list where `-` is its end. The parent must be there; the root is replaced whole.
fn insert(doc: &mut Value, pointer: &str, value: Value) -> Result<(), String> {
    let Some(last) = tokens(pointer)?.pop() else {
        *doc = value;
        return Ok(());
    };
    let parent = find(doc, &pointer[..pointer.rfind('/').unwrap_or(0)])?;
    match parent {
        Value::Object(map) => drop(map.insert(last, value)),
        Value::Array(items) if last == "-" => items.push(value),
        Value::Array(items) => {
            let at = index(&last, pointer)?;
            if at > items.len() {
                return Err(format!("add {pointer}: the index is past the end"));
            }
            items.insert(at, value);
        }
        _ => return Err(format!("add {pointer}: the parent is not a list or a mapping")),
    }
    Ok(())
}

/// Takes out what `pointer` names, which must be there, and says what it was.
fn take(doc: &mut Value, pointer: &str) -> Result<Value, String> {
    let Some(last) = tokens(pointer)?.pop() else {
        return Err("the whole document cannot be removed".into());
    };
    let parent = find(doc, &pointer[..pointer.rfind('/').unwrap_or(0)])?;
    let gone = match parent {
        Value::Object(map) => map.remove(&last),
        Value::Array(items) => {
            let at = index(&last, pointer)?;
            (at < items.len()).then(|| items.remove(at))
        }
        _ => None,
    };
    gone.ok_or_else(|| format!("{pointer}: the path is not there"))
}

/// Whether two values are the same as RFC 6902 has it: a number is its value (2 and 2.0 are one
/// number), a mapping has the same keys with the same values, a list the same items in order.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_i64(), y.as_i64(), x.as_u64(), y.as_u64()) {
            (Some(x), Some(y), _, _) => x == y,
            (_, _, Some(x), Some(y)) => x == y,
            _ => x.as_f64() == y.as_f64(),
        },
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same(x, y)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(key, x)| y.get(key).is_some_and(|y| same(x, y)))
        }
        _ => a == b,
    }
}

// ---- Who set which field: server-side apply ----

/// A field's place in an object, a step at a time as Kubernetes's `fieldsV1` spells it:
/// `f:name` for a field of a mapping, `k:{"name":"web"}` for the item of a list a merge key names.
type Path = Vec<String>;

/// The most field managers one object has, and the longest a manager's name is (Kubernetes's).
const MANAGERS: usize = 64;
const MANAGER_NAME: usize = 128;

/// One entry of `metadata.managedFields`: a manager, and the fields its last apply set.
struct Manager {
    name: String,
    version: String,
    time: String,
    fields: BTreeSet<Path>,
}

/// The merge key that names the items of `list`, if every item has one and no two share it:
/// a list of any other kind is one field, set whole.
fn keyed(list: &str, items: &[Value]) -> Option<&'static str> {
    let by = merge_key(list, items.first()?)?;
    let mut seen = BTreeSet::new();
    let unique = items
        .iter()
        .all(|item| !item[by].is_null() && seen.insert(item[by].to_string()));
    unique.then_some(by)
}

fn item_key(by: &str, item: &Value) -> String {
    Value::Object([(by.to_string(), item[by].clone())].into_iter().collect()).to_string()
}

/// The fields `value` sets, each by its path: a field with a value of its own (a scalar, an
/// empty mapping, a list no key names) is one, and a mapping or a keyed list is its parts.
fn leaves(at: &mut Path, list: &str, value: &Value, out: &mut BTreeMap<Path, Value>) {
    let items = value.as_array().and_then(|items| Some((items, keyed(list, items)?)));
    if let Some((items, by)) = items {
        for item in items {
            at.push(format!("k:{}", item_key(by, item)));
            leaves(at, "", item, out);
            at.pop();
        }
    } else if let Some(map) = value.as_object().filter(|map| !map.is_empty()) {
        for (field, value) in map {
            at.push(format!("f:{field}"));
            leaves(at, field, value, out);
            at.pop();
        }
    } else if !value.is_null() {
        out.insert(at.clone(), value.clone());
    }
}

/// What nobody manages: who the object is, what it is, and what kithd says of it.
const UNMANAGED: [&[&str]; 6] = [
    &["f:apiVersion"],
    &["f:kind"],
    &["f:status"],
    &["f:metadata", "f:name"],
    &["f:metadata", "f:namespace"],
    &["f:metadata", "f:managedFields"],
];

/// Every field of `object` that can be managed, by its path, with its value.
fn fields_of(object: &Value) -> BTreeMap<Path, Value> {
    let mut out = BTreeMap::new();
    leaves(&mut Vec::new(), "", object, &mut out);
    let under =
        |at: &Path, skip: &[&str]| at.len() >= skip.len() && at.iter().zip(skip.iter().copied()).all(|(a, b)| a == b);
    out.retain(|at, _| !UNMANAGED.iter().any(|skip| under(at, skip)));
    out
}

/// A set of paths as `fieldsV1` has it: a mapping of mappings, an empty one at each field.
fn fields_v1(fields: &BTreeSet<Path>) -> Value {
    let mut root = json!({});
    for path in fields {
        let mut at = &mut root;
        for step in path {
            let Some(map) = at.as_object_mut() else { break };
            at = map.entry(step.clone()).or_insert_with(|| json!({}));
        }
    }
    root
}

fn owned(tree: &Value, at: &mut Path, out: &mut BTreeSet<Path>) {
    match tree.as_object().filter(|map| !map.is_empty()) {
        Some(map) => {
            // (`.` says the mapping itself is managed too: no field of ours is that.)
            for (step, below) in map.iter().filter(|(step, _)| *step != ".") {
                at.push(step.clone());
                owned(below, at, out);
                at.pop();
            }
        }
        None if !at.is_empty() => drop(out.insert(at.clone())),
        None => {}
    }
}

/// The managers an object names.
fn managers(object: &Value) -> Vec<Manager> {
    let entries = object.pointer("/metadata/managedFields").and_then(Value::as_array);
    let entry = |entry: &Value| {
        let text = |field: &str| entry[field].as_str().unwrap_or_default().to_string();
        let mut fields = BTreeSet::new();
        owned(&entry["fieldsV1"], &mut Vec::new(), &mut fields);
        let (name, version, time) = (entry["manager"].as_str()?.to_string(), text("apiVersion"), text("time"));
        Some(Manager {
            name,
            version,
            time,
            fields,
        })
    };
    entries.into_iter().flatten().filter_map(entry).collect()
}

/// `object` told to be managed by these (it names none when none manages a field).
fn managed(object: &mut Value, managers: Vec<Manager>) {
    let entries: Vec<Value> = managers
        .into_iter()
        .filter(|manager| !manager.fields.is_empty())
        .map(|manager| {
            json!({
                "manager": manager.name, "operation": "Apply", "apiVersion": manager.version,
                "time": manager.time, "fieldsType": "FieldsV1", "fieldsV1": fields_v1(&manager.fields),
            })
        })
        .collect();
    if let Some(meta) = object.get_mut("metadata").and_then(Value::as_object_mut) {
        match entries.is_empty() {
            true => drop(meta.remove("managedFields")),
            false => drop(meta.insert("managedFields".into(), entries.into())),
        }
    }
}

/// A path as Kubernetes says it in a conflict: `.spec.template.spec.containers[name="web"].image`.
fn shown(path: &Path) -> String {
    let step = |step: &String| match step.split_once(':') {
        Some(("f", field)) => format!(".{field}"),
        Some(("k", key)) => {
            let key: Value = serde_json::from_str(key).unwrap_or_default();
            let parts: Vec<String> = key
                .as_object()
                .into_iter()
                .flatten()
                .map(|(by, is)| format!("{by}={is}"))
                .collect();
            format!("[{}]", parts.join(","))
        }
        _ => step.clone(),
    };
    path.iter().map(step).collect()
}

/// Kubernetes's words for fields another manager has and the apply would change.
fn conflicts(found: &[(String, String, Path)]) -> No {
    let mut by_manager: Vec<(&str, &str, Vec<String>)> = Vec::new();
    for (name, version, path) in found {
        match by_manager.iter_mut().find(|(has, ..)| has == name) {
            Some((.., paths)) => paths.push(shown(path)),
            None => by_manager.push((name, version, vec![shown(path)])),
        }
    }
    let mut why = match (found.len(), &by_manager[..]) {
        (1, [(name, version, paths)]) => {
            format!(
                "Apply failed with 1 conflict: conflict with \"{name}\" using {version}: {}",
                paths[0]
            )
        }
        (many, _) => format!("Apply failed with {many} conflicts:"),
    };
    if found.len() > 1 {
        for (name, version, paths) in &by_manager {
            why.push_str(&format!("\nconflicts with \"{name}\" using {version}:"));
            for path in paths {
                why.push_str(&format!("\n- {path}"));
            }
        }
    }
    status(StatusCode::CONFLICT, "Conflict", why)
}

/// Takes the field at `path` out of `value`, and what it leaves empty with it; whether `value`
/// is itself empty then.
fn unset(value: &mut Value, path: &[String]) -> bool {
    let Some((step, rest)) = path.split_first() else {
        return true;
    };
    match (value, step.split_once(':')) {
        (Value::Object(map), Some(("f", field))) => {
            if let Some(child) = map.get_mut(field)
                && unset(child, rest)
            {
                map.remove(field);
            }
            map.is_empty()
        }
        (Value::Array(items), Some(("k", key))) => {
            let key: Value = serde_json::from_str(key).unwrap_or_default();
            let named = |item: &Value| {
                key.as_object()
                    .is_some_and(|key| key.iter().all(|(by, is)| item.get(by) == Some(is)))
            };
            if let Some(at) = items.iter().position(named)
                && unset(&mut items[at], rest)
            {
                items.remove(at);
            }
            items.is_empty()
        }
        _ => false,
    }
}

/// Whether `at` is the key of an item that other managers still have fields of: the item
/// is theirs, and without its key they could not find it.
fn shielded(at: &Path, others: &[&Manager]) -> bool {
    let [parent @ .., last] = at.as_slice() else {
        return false;
    };
    let key = parent.last().and_then(|step| step.strip_prefix("k:"));
    let key: Value = key.and_then(|key| serde_json::from_str(key).ok()).unwrap_or_default();
    let is_key = last.strip_prefix("f:").is_some_and(|field| key.get(field).is_some());
    is_key
        && others
            .iter()
            .any(|other| other.fields.iter().any(|theirs| theirs.starts_with(parent)))
}

/// What `live` (none: not there) comes to when `who` applies `config` to it: the fields `who`
/// sets, over what is there; the fields `who` set before and leaves out of it taken out, where
/// no other manager has them. Another manager's field `who` would change is a conflict, but
/// with `force`, when it is `who`'s.
fn apply(live: Option<Value>, config: Value, who: &str, version: &str, force: bool) -> Result<Value, No> {
    let mut live = live.unwrap_or_else(|| json!({}));
    let mut all = managers(&live);
    if let Some(meta) = live.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.remove("managedFields");
    }
    let (held, sets) = (fields_of(&live), fields_of(&config));
    let mut found = Vec::new();
    for (at, value) in &sets {
        for other in all.iter().filter(|other| other.name != who) {
            if other.fields.contains(at) && held.get(at) != Some(value) {
                found.push((other.name.clone(), other.version.clone(), at.clone()));
            }
        }
    }
    if !found.is_empty() && !force {
        return Err(conflicts(&found));
    }
    for (name, _, at) in &found {
        for other in all.iter_mut().filter(|other| other.name == *name) {
            other.fields.remove(at);
        }
    }
    let before = all.iter().position(|manager| manager.name == who);
    let mine = before.map(|at| all[at].fields.clone()).unwrap_or_default();
    let others: Vec<&Manager> = all.iter().filter(|other| other.name != who).collect();
    let mut gone: Vec<&Path> = mine
        .iter()
        .filter(|at| !sets.contains_key(*at) && !others.iter().any(|other| other.fields.contains(*at)))
        .filter(|at| !shielded(at, &others))
        .collect();
    gone.sort_by_key(|at| std::cmp::Reverse(at.len()));
    let mut object = live.clone();
    patched(&mut object, config, true);
    for at in gone {
        unset(&mut object, at);
    }
    let fields: BTreeSet<Path> = sets.into_keys().collect();
    // (Kubernetes dates a manager by its last change: a repeat of an apply is not one.)
    let time = match before {
        Some(at) if object == live && fields == mine => all[at].time.clone(),
        _ => rfc3339(now()),
    };
    let (name, version) = (who.to_string(), version.to_string());
    let me = Manager {
        name,
        version,
        time,
        fields,
    };
    match before {
        Some(at) => all[at] = me,
        None => all.push(me),
    }
    all.retain(|manager| !manager.fields.is_empty());
    if all.len() > MANAGERS {
        return Err(invalid(format!(
            "metadata.managedFields: more than {MANAGERS} managers have fields of this object"
        )));
    }
    managed(&mut object, all);
    Ok(object)
}

/// `after`, an object changed by something other than an apply, told what is managed: a field
/// it changed is no apply manager's any more, and the others are as they were.
fn updated(live: &Value, after: &mut Value) {
    let mut all = managers(live);
    if all.is_empty() {
        return;
    }
    let (before, now) = (fields_of(live), fields_of(after));
    for manager in &mut all {
        manager.fields.retain(|at| before.get(at) == now.get(at));
    }
    managed(after, all);
}

type Asked = HashMap<String, String>;

/// One request: who asks, and what its query says.
struct Call {
    shared: Arc<Shared>,
    caller: Caller,
    certificate: Option<Certificate>,
    asked: Asked,
    /// `kubectl get` asks for the rows of its table, not the objects.
    table: bool,
}

/// How an object is written.
#[derive(Clone, Copy, PartialEq)]
enum How {
    Create,
    Replace,
    /// A patch of what is there: a JSON merge patch, or Kubernetes's strategic one.
    Patch {
        strategic: bool,
    },
    /// An RFC 6902 list of operations, applied to what is there (`kubectl patch --type json`).
    JsonPatch,
    /// A server-side apply: what is sent is the object, made if it is not there.
    Apply,
}

async fn core(
    State(shared): State<Arc<Shared>>,
    parts: Parts,
    Route(rest): Route<String>,
    Query(asked): Query<Asked>,
    body: Bytes,
) -> Response {
    let served = serve(shared, parts, "", &rest, asked, &body).await;
    served.unwrap_or_else(No::into_response)
}

async fn grouped(
    State(shared): State<Arc<Shared>>,
    parts: Parts,
    Route((group, rest)): Route<(String, String)>,
    Query(asked): Query<Asked>,
    body: Bytes,
) -> Response {
    let served = serve(shared, parts, &group, &rest, asked, &body).await;
    served.unwrap_or_else(No::into_response)
}

/// `[namespaces/NAMESPACE/]PLURAL[/NAME[/PART]]` of a group, and what is done to it.
async fn serve(
    shared: Arc<Shared>,
    parts: Parts,
    group: &str,
    rest: &str,
    asked: Asked,
    body: &[u8],
) -> Result<Response, No> {
    let said = |name| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    };
    let Some(caller) = parts.extensions.get::<Caller>().cloned() else {
        return Err(status(
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
            "who asks is not known".into(),
        ));
    };
    let call = Call {
        shared,
        caller,
        certificate: parts.extensions.get::<Certificate>().cloned(),
        asked,
        table: said(header::ACCEPT).contains("as=Table"),
    };
    let path: Vec<&str> = rest.split('/').collect();
    let (namespace, path) = match path[..] {
        ["namespaces", namespace, plural, ..] if !matches!(plural, "status" | "finalize") => {
            (Some(namespace), &path[2..])
        }
        _ => (None, &path[..]),
    };
    let found = KINDS
        .iter()
        .find(|kind| kind.group == group && Some(&kind.plural) == path.first());
    let (name, part) = (path.get(1).copied(), path.get(2).copied());
    // (A kind that is in namespaces is named in one; one that is in none is asked for in none.)
    let placed = |kind: &&Kind| match (kind.namespaced, namespace) {
        (true, None) => name.is_none(),
        (false, Some(_)) => false,
        _ => true,
    };
    let Some(kind) = found.filter(placed).filter(|_| path.len() <= 3) else {
        return Err(missing());
    };
    // What is sent: JSON, and an apply may be YAML; `kubectl create` and Helm send a kind
    // Kubernetes itself has in its binary encoding.
    let sent = || -> Result<Value, No> {
        let read = match body.starts_with(crate::kubeproto::MAGIC) {
            true => crate::kubeproto::object(body),
            false => serde_json::from_slice(body).map_err(|e| e.to_string()).or_else(|e| {
                let text = std::str::from_utf8(body).map_err(|_| e)?;
                let mut documents = kith_kube::documents("the request", text)?;
                let one = documents.pop().filter(|_| documents.is_empty());
                one.ok_or("not one object".to_string())
            }),
        };
        let unread = |e| {
            status(
                StatusCode::BAD_REQUEST,
                "BadRequest",
                format!("the body cannot be read: {e}"),
            )
        };
        read.map_err(unread)
    };
    let watching = call
        .asked
        .get("watch")
        .is_some_and(|watch| watch == "true" || watch == "1");
    Ok(match (parts.method.as_str(), name, part) {
        ("GET", None, None) if watching => watch(call, kind, namespace.map(str::to_string))?,
        ("GET", None, None) => list(&call, kind, namespace)?,
        ("GET", Some(name), None | Some("status")) => one(&call, kind, namespace, name, false)?,
        ("GET", Some(name), Some("scale")) if scales(kind) => one(&call, kind, namespace, name, true)?,
        ("GET", Some(name), Some("log")) if kind.kind == "Pod" => {
            log(&call, namespace.unwrap_or_default(), name).await?
        }
        // (A ReplicaSet is the Deployment's, made up for `kubectl rollout`: nothing of it is
        // written, so what the answer says is the same of any name, and tells nothing of which are there.)
        ("POST" | "PUT" | "PATCH" | "DELETE", ..) if kind.kind == "ReplicaSet" => {
            let why = "a ReplicaSet is made up from its Deployment's revisions and is read only: change the Deployment (`kubectl rollout undo` goes back to an earlier revision)";
            return Err(status(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", why.into()));
        }
        ("POST", None, None) => write(&call, kind, namespace, None, How::Create, sent()?)
            .await?
            .into_response(),
        ("PUT", Some(name), None) => {
            let written = write(&call, kind, namespace, Some(name), How::Replace, sent()?).await?;
            written.into_response()
        }
        ("PATCH", Some(name), None) => {
            let how = match said(header::CONTENT_TYPE).split(';').next().unwrap_or_default().trim() {
                "application/strategic-merge-patch+json" => How::Patch { strategic: true },
                "application/merge-patch+json" => How::Patch { strategic: false },
                "application/json-patch+json" => How::JsonPatch,
                "application/apply-patch+yaml" => How::Apply,
                other => {
                    let why = format!(
                        "a patch as {other} is not read: send a merge patch, a strategic merge patch, a JSON patch or an apply"
                    );
                    return Err(status(StatusCode::UNSUPPORTED_MEDIA_TYPE, "UnsupportedMediaType", why));
                }
            };
            write(&call, kind, namespace, Some(name), how, sent()?)
                .await?
                .into_response()
        }
        // A scale is the one number, whichever way it comes.
        ("PUT" | "PATCH", Some(name), Some("scale")) if scales(kind) => {
            let Some(replicas) = sent()?["spec"]["replicas"].as_u64() else {
                return Err(invalid("spec.replicas: a scale says how many".into()));
            };
            let (how, replicas) = (
                How::Patch { strategic: false },
                json!({ "spec": { "replicas": replicas } }),
            );
            let Written(code, object, said) = write(&call, kind, namespace, Some(name), how, replicas).await?;
            Written(code, object.as_ref().map(scale_of), said).into_response()
        }
        ("DELETE", Some(name), None) => {
            let options = if body.is_empty() { Value::Null } else { sent()? };
            delete(&call, kind, namespace, name, &options).await?
        }
        ("PUT" | "PATCH", Some(_), Some("status")) => {
            let why = "status is kithd's own: it is written from what runs and is not taken from a client";
            return Err(status(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", why.into()));
        }
        ("GET" | "POST", Some(name), Some(verb @ ("exec" | "attach"))) if kind.kind == "Pod" => {
            let upgrade = parts.extensions.get::<OnUpgrade>().cloned();
            pod_stream(&call, verb, namespace.unwrap_or_default(), name, &parts, upgrade, false).await?
        }
        ("GET" | "POST", Some(name), Some("portforward")) if kind.kind == "Pod" => {
            let upgrade = parts.extensions.get::<OnUpgrade>().cloned();
            let (method, headers) = (parts.method.as_str(), &parts.headers);
            let namespace = namespace.unwrap_or_default();
            portforward::forward(&call, namespace, name, method, headers, upgrade).await?
        }
        (_, Some(_), Some("exec" | "attach" | "portforward")) => {
            let why = "not answered here: exec and attach are a WebSocket (GET), and so is port-forward; `kith run` runs a command in a replica";
            return Err(status(StatusCode::NOT_IMPLEMENTED, "NotImplemented", why.into()));
        }
        (method, ..) => {
            let why = format!("{method} is not done to {rest}");
            return Err(status(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", why));
        }
    })
}

impl Call {
    /// A refusal unless the caller may `verb` what holds `kind` there. (What is made up is
    /// picked object by object, by who may see what it is made up from.)
    fn allowed(&self, kind: &Kind, namespace: Option<&str>, verb: Verb) -> Result<(), No> {
        let place = match (kind.held, kind.namespaced, namespace) {
            (Held::Made, ..) => return Ok(()),
            // Everywhere: whoever may see some of them, sees those.
            (_, true, None) => {
                let seen = api::sight(&self.shared, &self.caller, verb, Some(holder(kind)));
                return seen.map_err(refusal);
            }
            (Held::As("Namespace"), ..) => None,
            (_, _, namespace) => Some(namespace.unwrap_or(kith_api::DEFAULT_NAMESPACE).to_string()),
        };
        let held = vec![(holder(kind).to_string(), place)];
        api::permit(&self.shared, &self.caller, verb, |_| held).map_err(refusal)
    }

    /// What `verb` lets the caller see of `kind`, and the store's generation with it.
    fn seen(&self, kind: &'static Kind, namespace: Option<&str>, name: Option<&str>, verb: Verb) -> (Vec<Value>, u64) {
        let state = self.shared.store.lock().expect("a handler panicked holding the store");
        let grants = Grants::of(&self.caller, &state.store);
        let mut found = objects(&state.store, kind, namespace, name, &grants, &verb);
        found.retain(|object| selected(object, &self.asked));
        // (Read under the store's lock: a change and its generation come together.)
        (found, *self.shared.generation.borrow())
    }
}

fn one(call: &Call, kind: &'static Kind, namespace: Option<&str>, name: &str, scale: bool) -> Result<Response, No> {
    call.allowed(kind, namespace, Verb::Get)?;
    let (mut found, at) = call.seen(kind, namespace, Some(name), Verb::Get);
    let object = found.pop().ok_or_else(|| not_found(kind, name))?;
    Ok(Json(match (scale, call.table) {
        (true, _) => scale_of(&object),
        (_, true) => table(kind, &[object], at),
        _ => object,
    })
    .into_response())
}

fn list(call: &Call, kind: &'static Kind, namespace: Option<&str>) -> Result<Response, No> {
    call.allowed(kind, namespace, Verb::List)?;
    let (items, at) = call.seen(kind, namespace, None, Verb::List);
    if call.table {
        return Ok(Json(table(kind, &items, at)).into_response());
    }
    let list = json!({
        "kind": format!("{}List", kind.kind), "apiVersion": version_of(kind.group),
        "metadata": { "resourceVersion": at.to_string() }, "items": items,
    });
    Ok(Json(list).into_response())
}

/// What `kubectl scale` reads and writes of a Deployment or a StatefulSet.
fn scale_of(object: &Value) -> Value {
    let labels = object.pointer("/spec/selector/matchLabels").and_then(Value::as_object);
    let label = |(key, value): (&String, &Value)| Some(format!("{key}={}", value.as_str()?));
    let selector: Vec<String> = labels.into_iter().flatten().filter_map(label).collect();
    json!({
        "kind": "Scale", "apiVersion": "autoscaling/v1", "metadata": object["metadata"],
        "spec": { "replicas": object["spec"]["replicas"] },
        "status": { "replicas": object["status"]["replicas"], "selector": selector.join(",") },
    })
}

/// The Ingresses of a namespace as they were sent, and with `services` its Services, but
/// for the one held at `but`: an Ingress is its hosts on the Services behind it, so a
/// Service is read with the Ingresses, and an Ingress with them all.
fn exposed(store: &Store, namespace: &str, but: &str, services: bool) -> Vec<Value> {
    let here = |resource: &&Resource| resource.metadata.namespace.as_deref() == Some(namespace);
    let wanted = |kind: &Kind| kind.kind == "Ingress" || (services && kind.kind == "Service");
    let sent = |resource: &Resource| raw(resource).filter(|(kind, _)| wanted(kind));
    let all = ["Service", "KubeObject"]
        .into_iter()
        .flat_map(|kind| store.list(Some(kind)));
    let objects = all
        .filter(here)
        .filter(|resource| resource.key() != but)
        .filter_map(sent);
    objects.map(|(_, object)| object).collect()
}

/// The kith resources `objects` come to, each with the object it holds beside it as `sent`
/// has it (the one being written) or as the store does; and what is said of them.
fn translated(store: &Store, objects: Vec<Value>, sent: Option<(&str, &Value)>) -> kith_kube::Taken {
    let mut taken = kith_kube::take(objects, false);
    for resource in &mut taken.resources {
        let key = resource.key();
        let live = store.get(&key).map(|live| &live.metadata.annotations);
        let beside = match sent {
            Some((primary, sent)) if primary == key => {
                let mut sent = sent.clone();
                // (A Secret's data is not kept twice, nor a ConfigMap's.)
                if let Some(sent) = sent.as_object_mut().filter(|_| resource.spec.get("data").is_some()) {
                    sent.remove("data");
                    sent.remove("stringData");
                }
                Some(sent.to_string())
            }
            _ => live.and_then(|live| live.get(SENT)).cloned(),
        };
        let made = live.and_then(|live| live.get(MADE)).cloned();
        let notes = &mut resource.metadata.annotations;
        // (What is noted here is this layer's to say: an object that came with such a note has it taken off.)
        notes.retain(|note, _| !note.starts_with("kube.kith.dev/"));
        notes.extend(beside.map(|beside| (SENT.to_string(), beside)));
        notes.insert(MADE.into(), made.unwrap_or_else(|| now().to_string()));
    }
    taken
}

/// The kith resources an object of `kind` comes to (what holds it among them), and what is
/// said of it; or why it is refused.
fn held_as(
    store: &Store,
    kind: &Kind,
    namespace: Option<&str>,
    name: &str,
    sent: &Value,
) -> Result<(Vec<Resource>, Vec<String>), Vec<String>> {
    let primary = key(kind, namespace, name);
    let who = format!("{}/{name}:", kind.kind);
    let place = namespace.unwrap_or(kith_api::DEFAULT_NAMESPACE);
    let live = store.get(&primary);
    let made = live.and_then(|live| live.metadata.annotations.get(MADE)).cloned();
    let noted = |sent: Option<String>| -> BTreeMap<String, String> {
        let made = (MADE.to_string(), made.clone().unwrap_or_else(|| now().to_string()));
        std::iter::once(made)
            .chain(sent.map(|sent| (SENT.to_string(), sent)))
            .collect()
    };
    let resource = |holder: &str, name: String, namespace, labels, annotations, spec| Resource {
        api_version: kith_api::API_VERSION.into(),
        kind: holder.into(),
        metadata: Metadata {
            name,
            namespace,
            labels,
            annotations,
            revision: None,
        },
        spec,
        status: None,
    };
    let (mut resources, others) = match kind.held {
        Held::Made => {
            let why = match kind.kind {
                "Pod" => "a pod is run by what owns it: send a Deployment, a StatefulSet, a DaemonSet or a Job",
                _ => "is not an object that is written: kith makes it up from what it runs",
            };
            return Err(vec![format!("{who} {why}")]);
        }
        // A namespace kith knows more of (its quota, its hosts) keeps that.
        Held::As("Namespace") => {
            let labels = sent["metadata"]["labels"].as_object().into_iter().flatten();
            let labels = labels.filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_string())));
            let spec = live.map_or_else(|| json!({}), |live| live.spec.clone());
            let annotations = noted(Some(sent.to_string()));
            let held = resource("Namespace", name.into(), None, labels.collect(), annotations, spec);
            return Ok((vec![held], Vec::new()));
        }
        Held::Kept(said) => {
            let spec = json!({ "object": sent });
            let within = Some(place.to_string());
            let kept = resource(
                "KubeObject",
                kept_name(kind, name),
                within,
                BTreeMap::new(),
                noted(None),
                spec,
            );
            match kind.kind {
                "Ingress" => (vec![kept], exposed(store, place, &primary, true)),
                _ => {
                    let said = (!said.is_empty()).then(|| format!("{who} {said}"));
                    return Ok((vec![kept], said.into_iter().collect()));
                }
            }
        }
        Held::As(_) if kind.kind == "Service" => (Vec::new(), exposed(store, place, &primary, false)),
        Held::As(_) => (Vec::new(), Vec::new()),
    };
    let objects = others.into_iter().chain([sent.clone()]).collect();
    let taken = translated(store, objects, Some((&primary, sent)));
    let mine =
        |lines: Vec<String>| -> Vec<String> { lines.into_iter().filter(|line| line.starts_with(&who)).collect() };
    let refused = mine(taken.refused);
    if !refused.is_empty() {
        return Err(refused);
    }
    resources.extend(taken.resources);
    // A StatefulSet's claims are objects of their own in Kubernetes: each is shown as its template says.
    for template in sent["spec"]["volumeClaimTemplates"].as_array().into_iter().flatten() {
        // (One for each replica: TEMPLATE-NAME-ORDINAL.)
        let base = format!("{}-{name}-", template["metadata"]["name"].as_str().unwrap_or_default());
        let each = |held: &Resource| {
            let ordinal = held.metadata.name.strip_prefix(&base);
            held.kind == "VolumeClaim" && ordinal.is_some_and(|n| n.parse::<u32>().is_ok())
        };
        for held in resources.iter_mut().filter(|held| each(held)) {
            if held.metadata.annotations.contains_key(SENT) {
                continue;
            }
            let claim = held.metadata.name.clone();
            let mut object = json!({
                "apiVersion": "v1", "kind": "PersistentVolumeClaim",
                "metadata": { "name": claim, "namespace": place }, "spec": template["spec"],
            });
            if let Some(labels) = template.pointer("/metadata/labels") {
                set(&mut object, "/metadata/labels", labels.clone());
            }
            held.metadata.annotations.insert(SENT.into(), object.to_string());
        }
    }
    match resources.iter().any(|resource| resource.key() == primary) {
        true => Ok((resources, mine(taken.hints))),
        false => Err(vec![format!("{who} comes to nothing kith can hold")]),
    }
}

/// Whether `version` (an object's `apiVersion`) is one of Kubernetes's that is taken here.
pub fn speaks(version: &str) -> bool {
    KINDS.iter().any(|kind| version_of(kind.group) == version)
}

/// What a set of Kubernetes manifests comes to, for a Source that has them in its files:
/// the kith resources `kubectl apply` of each in turn would leave (an object that names
/// no namespace is in `home`), and what is said of them; or why one is refused.
pub fn from_files(objects: Vec<Value>, home: &str) -> Result<(Vec<Resource>, Vec<String>), String> {
    let (mut store, mut said) = (Store::default(), Vec::new());
    // (A stack, so that a List's items come in their order.)
    let mut objects: Vec<Value> = objects.into_iter().rev().collect();
    while let Some(mut object) = objects.pop() {
        let text = |at: &str| {
            object
                .pointer(at)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let (version, named, name) = (text("/apiVersion"), text("/kind"), text("/metadata/name"));
        if let Some(items) = object["items"].as_array().filter(|_| named.ends_with("List")) {
            objects.extend(items.iter().rev().cloned());
            continue;
        }
        let is = |kind: &&Kind| kind.kind == named && version_of(kind.group) == version;
        let Some(kind) = KINDS.iter().find(is) else {
            return Err(format!("{named}/{name}: {version} has no kind {named} here"));
        };
        let namespace = kind.namespaced.then(|| text("/metadata/namespace"));
        let namespace = namespace.map(|said| if said.is_empty() { home.to_string() } else { said });
        if let Some(namespace) = &namespace {
            set(&mut object, "/metadata/namespace", namespace.as_str().into());
        }
        let held = held_as(&store, kind, namespace.as_deref(), &name, &object);
        let (resources, hints) = held.map_err(|refused| refused.join("; "))?;
        said.extend(hints);
        for resource in resources {
            store.apply(resource).map_err(|e| format!("{named}/{name}: {e}"))?;
        }
    }
    // (When it was made is the store's to know, not the files': each fetch would say another.)
    let plain = |resource: &Resource| {
        let mut resource = resource.clone();
        resource.metadata.annotations.remove(MADE);
        resource
    };
    Ok((store.list(None).map(plain).collect(), said))
}

/// The revision of the Deployment `key` that `sent` (a JSON patch laid over `was`, as served)
/// goes back to, if it does only that: its template is not the live one but one a kept
/// revision held, and nothing else of it is changed. That is what `kubectl rollout undo`
/// sends, and the store goes back to that revision as `kith rollback` does (its checks
/// too); a patch that is anything else, or the live template again, is written as a patch.
fn going_back(store: &Store, key: &str, was: &Value, sent: &Value) -> Option<u64> {
    let template = |object: &Value| identity(&object["spec"]["template"]);
    let rest = |object: &Value| {
        let mut object = object.clone();
        set(&mut object, "/spec/template", Value::Null);
        // (Its annotations are not the ReplicaSet's, which holds only the revision's number: what
        // kubectl sends for them is empty for a Deployment `apply` or Helm made. The rollback
        // brings back the revision's own.)
        set(&mut object, "/metadata/annotations", Value::Null);
        object
    };
    let now = template(sent);
    if now == template(was) || rest(was) != rest(sent) {
        return None;
    }
    kept(store, key)
        .into_iter()
        .find(|held| held.id == now)
        .map(|held| held.revision)
}

/// What a write came to: its HTTP status, the object as it now is, and what is said of it.
struct Written(StatusCode, Option<Value>, Vec<String>);

impl IntoResponse for Written {
    fn into_response(self) -> Response {
        let mut reply = (self.0, Json(self.1.unwrap_or_default())).into_response();
        // What was taken and changes nothing is said, as Kubernetes says what it took and
        // will not use: kubectl prints each as a warning.
        for hint in self.2 {
            let plain = |c: char| {
                if c.is_control() || c == '"' || c == '\\' {
                    ' '
                } else {
                    c
                }
            };
            let plain: String = hint.chars().map(plain).collect();
            if let Ok(warning) = format!("299 - \"{plain}\"").parse() {
                reply.headers_mut().append("warning", warning);
            }
        }
        reply
    }
}

async fn write(
    call: &Call,
    kind: &'static Kind,
    namespace: Option<&str>,
    name: Option<&str>,
    how: How,
    body: Value,
) -> Result<Written, No> {
    let said = body.pointer("/metadata/name").and_then(Value::as_str);
    let Some(name) = name.or(said).map(str::to_string) else {
        let why = "metadata.name: an object needs a name (kith gives none: `generateName` is not done)";
        return Err(invalid(why.into()));
    };
    // A Pod made is what its restartPolicy says, before anything is asked of the caller or the store.
    // (Helm 4 sends a test hook's Pod as a server-side apply.)
    let kind = if kind.kind == "Pod" && matches!(how, How::Create | How::Apply) {
        bare(&body)
    } else {
        kind
    };
    // Who may not write here is told that, and nothing of what is there; and a change
    // of what is there (a patch is answered with all of it) is for who may read it.
    call.allowed(kind, namespace, Verb::Apply)?;
    if matches!(how, How::Patch { .. } | How::JsonPatch) {
        call.allowed(kind, namespace, Verb::Get)?;
    }
    let primary = key(kind, namespace, &name);
    let exists = || {
        status(
            StatusCode::CONFLICT,
            "AlreadyExists",
            format!("{} \"{name}\" already exists", kind.plural),
        )
    };
    // An apply says who applies, as Kubernetes asks; and one to what is there is answered with
    // all of it (merged, and a conflict names whose field it is): for who may read it. Whether
    // it is there is told to who may write (a create says), so asking after that is no leak.
    let manager = call.asked.get("fieldManager").map(String::as_str).unwrap_or_default();
    let mut there = false;
    if how == How::Apply {
        if manager.is_empty() {
            let why =
                "PatchOptions.meta.k8s.io \"\" is invalid: fieldManager: Required value: is required for apply patch";
            return Err(invalid(why.into()));
        }
        if manager.len() > MANAGER_NAME {
            return Err(invalid(format!(
                "fieldManager: must be no more than {MANAGER_NAME} characters"
            )));
        }
    }
    // (A replace is answered with the managers' fields too: it needs `get` of what is there.)
    if matches!(how, How::Apply | How::Replace) {
        there = call
            .shared
            .store
            .lock()
            .expect("a handler panicked holding the store")
            .store
            .get(&primary)
            .is_some();
        if there {
            call.allowed(kind, namespace, Verb::Get)?;
        }
        // (Only a marked bare Pod is a Pod that is there: a Deployment or Job of the name is a name taken.)
        if there && kind.kind == "Pod" && how == How::Apply {
            let state = call.shared.store.lock().expect("a handler panicked holding the store");
            if held_bare(
                &state.store,
                Some(namespace.unwrap_or(kith_api::DEFAULT_NAMESPACE)),
                &name,
            )
            .is_some()
            {
                let why = format!("Pod/{name}: a Pod that is there is not changed: delete it and send it again");
                return Err(invalid(why));
            }
            return Err(exists());
        }
    }
    // The revision a Deployment is sent back to, where what is sent is `kubectl rollout undo`.
    let mut undo = None;
    let read = {
        let state = call.shared.store.lock().expect("a handler panicked holding the store");
        let live = state.store.get(&primary);
        // A JSON patch is laid over the object as kubectl reads it (defaults and server fields
        // in), so its base and what it is diffed against are served; the rest work on what was sent.
        let before = live
            .and_then(|live| if how == How::JsonPatch { served(live) } else { raw(live) })
            .filter(|(of, _)| std::ptr::eq(*of, kind));
        if live.is_some() && !there && how == How::Apply {
            let why = format!("{primary} was made since: apply it again");
            return Err(status(StatusCode::CONFLICT, "Conflict", why));
        }
        let was = before.as_ref().map(|(_, object)| object.clone());
        // A Pod shares its name space with the Job and the Workload it might have been, and with the
        // pods of what owns one. (ponytail: each check reads under its own lock before `api::applied`
        // writes, so a Pod and a Job or Workload of one name, or of a colliding pod name, made at once
        // may both be made, in either order; a same-kind one cannot. A Job a CronJob spawns and any
        // resource written by `api::applied` itself are not checked: `shadowed` is asked only here.)
        if kind.kind == "Pod"
            && (how == How::Create || (how == How::Apply && !there))
            && taken(&state.store, namespace, &name)
        {
            return Err(exists());
        }
        // And the other way: what runs pods may not be made where a bare Pod has the name of one of them.
        if matches!(kind.held, Held::As("Job" | "Workload" | "NodeWorkload"))
            && (how == How::Create || (how == How::Apply && !there))
            && shadowed(&state.store, namespace, holder(kind), &name)
        {
            return Err(exists());
        }
        // What is there and was not made here, or not as this kind, is not written over.
        if live.is_some() && before.is_none() {
            let why = format!(
                "{primary} is there, and was not made as a {} through this API",
                kind.kind
            );
            return Err(status(StatusCode::CONFLICT, "AlreadyExists", why));
        }
        let revision = live.and_then(|live| live.metadata.revision);
        let mut sent = match (how, before) {
            (How::Create, Some(_)) => return Err(exists()),
            (How::Create | How::Apply, _) | (How::Replace, Some(_)) => body,
            (_, None) => return Err(not_found(kind, &name)),
            (How::Patch { strategic }, Some((_, mut before))) => {
                patched(&mut before, body, strategic);
                before
            }
            // A refused operation refuses the whole patch: what is there is not written.
            (How::JsonPatch, Some((_, mut before))) => {
                // `kubectl rollout undo` replaces a Deployment's annotations, which Kubernetes's
                // always has: one with none has an empty map for the patch, and none again after.
                let bare = kind.kind == "Deployment" && before.pointer("/metadata/annotations").is_none();
                if bare {
                    set(&mut before, "/metadata/annotations", json!({}));
                }
                let mut patched = json_patch(&before, &body).map_err(invalid)?;
                let empty = patched.pointer("/metadata/annotations").and_then(Value::as_object);
                if bare && empty.is_some_and(|annotations| annotations.is_empty()) {
                    patched["metadata"]
                        .as_object_mut()
                        .map(|meta| meta.remove("annotations"));
                }
                patched
            }
        };
        // A dry run only says what the write would do: it is not sent back.
        if how == How::JsonPatch && kind.kind == "Deployment" && !call.asked.contains_key("dryRun") {
            undo = was
                .as_ref()
                .and_then(|was| going_back(&state.store, &primary, was, &sent));
        }
        // A change of what was read is held to it: the revision, whatever its status did since.
        let based = sent.pointer("/metadata/resourceVersion").and_then(Value::as_str);
        let based = based
            .and_then(|based| based.parse::<u64>().ok())
            .filter(|_| how == How::Replace);
        if based.is_some_and(|based| Some(based >> 32) != revision) {
            let why = format!("{primary} has been changed since: read it again, and change that");
            return Err(status(StatusCode::CONFLICT, "Conflict", why));
        }
        let Some(root) = sent.as_object_mut() else {
            return Err(invalid("the object is not a mapping".into()));
        };
        if root.get("kind").is_some_and(|said| said != kind.kind) {
            return Err(invalid(format!("kind: this is where a {} is sent", kind.kind)));
        }
        root.insert("apiVersion".into(), version_of(kind.group).into());
        root.insert("kind".into(), kind.kind.into());
        root.remove("status");
        let meta = root.entry("metadata").or_insert_with(|| json!({}));
        let Some(meta) = meta.as_object_mut() else {
            return Err(invalid("metadata: should be a mapping".into()));
        };
        // What the server says of an object is not the client's to send, and the path says where it is.
        for theirs in [
            "resourceVersion",
            "generation",
            "uid",
            "creationTimestamp",
            "managedFields",
            "selfLink",
        ] {
            meta.remove(theirs);
        }
        let place = namespace.filter(|_| kind.namespaced);
        for (field, said) in [("name", Some(name.as_str())), ("namespace", place)] {
            let other = |sent: &Value| !sent.is_null() && sent.as_str() != said;
            if meta.get(field).is_some_and(other) {
                return Err(invalid(format!("metadata.{field}: is not the request's")));
            }
            match said {
                Some(said) => meta.insert(field.into(), said.into()),
                None => meta.remove(field),
            };
        }
        // Who set which field: an apply is laid over what is there, a change by anything else
        // takes the fields it changes from the managers.
        match (how, was) {
            (How::Apply, was) => {
                let force = call.asked.get("force").is_some_and(|force| force == "true");
                sent = apply(was, sent, manager, &version_of(kind.group), force)?;
            }
            (How::Replace | How::Patch { .. } | How::JsonPatch, Some(was)) => updated(&was, &mut sent),
            _ => {}
        }
        match undo {
            Some(_) => Ok(((Vec::new(), Vec::new()), revision)),
            None => held_as(&state.store, kind, place, &name, &sent).map(|held| (held, revision)),
        }
    };
    let ((mut resources, hints), revision) = read.map_err(|refused| invalid(refused.join("; ")))?;
    if let Some(to) = undo {
        // Sent back to what was read: a write that lands after the lock was let go is not
        // written over, the store answers a conflict (kubectl shows a 409).
        #[cfg(test)]
        tests::pause_before_undo(&call.shared).await;
        let base = Some(revision.unwrap_or(0));
        let back = api::rolled_back(&call.shared, &call.caller, primary, to, base).await;
        let object = back.map_err(refusal)?.after;
        return Ok(Written(
            StatusCode::OK,
            served(&object).map(|(_, object)| object),
            hints,
        ));
    }
    // Made only if it is not there, changed only as it was read: the store holds to that
    // (an apply is laid over what is there, so it is read from that revision too).
    for resource in resources.iter_mut().filter(|resource| resource.key() == primary) {
        resource.metadata.revision = match how {
            How::Create => Some(0),
            How::Apply if !there => Some(0),
            _ => revision,
        };
    }
    let done = match call.asked.contains_key("dryRun") {
        true => api::plan(&call.shared, &call.caller, resources).await,
        false => api::applied(&call.shared, &call.caller, resources).await,
    };
    let changes = done.map_err(|e| match e {
        ApiError::Store(Error::Conflict(_)) if how == How::Create => exists(),
        e => refusal(e),
    })?;
    let change = changes.into_iter().find(|change| change.after.key() == primary);
    let code = match change.as_ref().map(|change| change.action) {
        Some(Action::Created) => StatusCode::CREATED,
        _ => StatusCode::OK,
    };
    let object = change
        .and_then(|change| served(&change.after))
        .map(|(_, object)| object);
    Ok(Written(code, object, hints))
}

async fn delete(
    call: &Call,
    kind: &'static Kind,
    namespace: Option<&str>,
    name: &str,
    options: &Value,
) -> Result<Response, No> {
    if options["propagationPolicy"] == "Orphan" || options["orphanDependents"] == true {
        return Err(invalid(
            "propagationPolicy: Orphan: a replica is not an object that can be left behind".into(),
        ));
    }
    let mut hints = Vec::new();
    if !options["gracePeriodSeconds"].is_null() {
        let kind = kind.kind;
        hints.push(format!(
            "{kind}/{name}: gracePeriodSeconds is taken and changes nothing: what it runs is stopped as kith stops it"
        ));
    }
    // A Pod that is a bare one is deleted as what it is held as, by that holder's own right; any
    // other Pod name is a replica's, and a delete restarts it.
    let mut kind = kind;
    if kind.kind == "Pod" {
        // (Before the store is looked at, for a bare Pod's name or any other: who holds no right to
        // delete a Job or a Workload, or to restart a replica, is told that and nothing of which names exist.)
        let place = Some(namespace.unwrap_or(kith_api::DEFAULT_NAMESPACE));
        if let Err(refused) = call.allowed(&BARE[BARE_WORKLOAD], place, Verb::Apply)
            && !BARE.iter().any(|row| call.allowed(row, place, Verb::Delete).is_ok())
        {
            return Err(refused);
        }
        let held = {
            let state = call.shared.store.lock().expect("a handler panicked holding the store");
            held_bare(&state.store, namespace, name)
        };
        match held {
            // (A caller who may not delete what holds it is told 404, as of a nothing, Apply or not.)
            Some(row) if call.allowed(row, place, Verb::Delete).is_ok() => kind = row,
            Some(_) => return Err(not_found(kind, name)),
            None => return delete_pod(call, kind, namespace, name, hints).await,
        }
    }
    // (Asked first: who may not delete here is not told what is there.)
    call.allowed(kind, namespace, Verb::Delete)?;
    let dry = call.asked.contains_key("dryRun") || options["dryRun"].is_array();
    let primary = key(kind, namespace, name);
    let (keys, said, stay) = {
        let state = call.shared.store.lock().expect("a handler panicked holding the store");
        let store = &state.store;
        let live = store
            .get(&primary)
            .and_then(served)
            .filter(|(of, _)| std::ptr::eq(*of, kind));
        let said = live.as_ref().map(|(_, object)| object["metadata"]["uid"].clone());
        // Asked to delete this one only as it was seen: another by its name, or it changed, stays.
        // (Looked at here and deleted below: a change in between is not seen.)
        for field in ["uid", "resourceVersion"] {
            let (wanted, live) = (&options["preconditions"][field], live.as_ref());
            let is = live.map_or(&Value::Null, |(_, object)| &object["metadata"][field]);
            if !wanted.is_null() && live.is_some() && wanted != is {
                let why = format!("preconditions.{field}: {primary} is not {wanted} but {is}");
                return Err(status(StatusCode::CONFLICT, "Conflict", why));
            }
        }
        match (kind.kind, live.is_some()) {
            // A namespace goes with all that was made in it here; what kith's own files put there stays.
            ("Namespace", there) => {
                let within = |resource: &&Resource| resource.metadata.namespace.as_deref() == Some(name);
                let (ours, theirs): (Vec<_>, Vec<_>) = store.list(None).filter(within).partition(|r| raw(r).is_some());
                if ours.is_empty() && !there {
                    return Err(not_found(kind, name));
                }
                let mut keys: Vec<String> = ours.into_iter().map(Resource::key).collect();
                keys.extend(there.then(|| primary.clone()));
                (keys, said, theirs.len())
            }
            (_, false) => return Err(not_found(kind, name)),
            (_, true) => (vec![primary.clone()], said, 0),
        }
    };
    if !dry {
        // (All of a namespace or none of it: who may not delete one kind in it deletes nothing.)
        let places = |_: &Store| {
            let place = |key: &String| {
                let parts: Vec<&str> = key.split('/').collect();
                let namespace = (parts.len() == 3).then(|| parts[1].to_string());
                (parts[0].to_string(), namespace)
            };
            keys.iter().map(place).collect()
        };
        api::permit(&call.shared, &call.caller, Verb::Delete, places).map_err(refusal)?;
        for key in keys {
            api::deleted(&call.shared, &call.caller, key).await.map_err(refusal)?;
        }
        // The Services an Ingress exposed are read again without it.
        if kind.kind == "Ingress" {
            let place = namespace.unwrap_or(kith_api::DEFAULT_NAMESPACE);
            let left = {
                let state = call.shared.store.lock().expect("a handler panicked holding the store");
                translated(&state.store, exposed(&state.store, place, "", true), None).resources
            };
            api::applied(&call.shared, &call.caller, left).await.map_err(refusal)?;
        }
    }
    let done = json!({
        "kind": "Status", "apiVersion": "v1", "status": "Success",
        "details": { "name": name, "group": kind.group, "kind": kind.plural, "uid": said },
    });
    let stay = (stay > 0).then(|| {
        format!("Namespace/{name}: {stay} resources in it were not made through this API, and stay: `kith delete` removes them")
    });
    hints.extend(stay);
    Ok(Written(StatusCode::OK, Some(done), hints).into_response())
}

/// The row a Pod named exactly `name` is held as when it is a bare one: the Job or the Workload of
/// that name that carries the `kith.dev/pod` mark and is read back as a Pod. The mark alone tells it
/// from a replica of an owner (`web-0` of Workload `web`), which [`delete_pod`] restarts.
fn held_bare(store: &Store, namespace: Option<&str>, name: &str) -> Option<&'static Kind> {
    BARE.iter().find(|row| {
        let Some(held) = store.get(&key(row, namespace, name)) else {
            return false;
        };
        let marked = held
            .metadata
            .annotations
            .get("kith.dev/pod")
            .is_some_and(|mark| mark == "true");
        marked && served(held).is_some_and(|(of, _)| std::ptr::eq(of, *row))
    })
}

/// `kubectl delete pod NAME` on a name that is no bare Pod (see [`held_bare`], which `delete` asks
/// first) restarts that one replica: its node stops it and its Workload starts it again, with the
/// same name and number and a new start time. Needs the apply right on the Workload; a pod that is
/// no Workload's replica is refused by name when it is a Job's run or a NodeWorkload's copy, and is
/// not found when it is nothing. No grace period and no force: what runs is stopped as kith stops it.
async fn delete_pod(
    call: &Call,
    kind: &'static Kind,
    namespace: Option<&str>,
    name: &str,
    hints: Vec<String>,
) -> Result<Response, No> {
    let namespace = namespace.unwrap_or(kith_api::DEFAULT_NAMESPACE);
    let owned = pod_owner(name);
    let Some(("Workload", owner, replica)) = owned else {
        // (A name no Job's run or NodeWorkload's copy has is no pod, as it is not in Kubernetes: Helm
        // deletes the test pod of an earlier run before it makes one, and wants NotFound of what is not there.)
        let held = |holder: &str, owner: &str| {
            let state = call.shared.store.lock().expect("a handler panicked holding the store");
            state.store.get(&format!("{holder}/{namespace}/{owner}")).is_some()
        };
        // (And only for a caller who may delete what holds it: any other is told 404, as of a nothing.)
        let may = |holder: &str| {
            let place = vec![(holder.to_string(), Some(namespace.to_string()))];
            api::permit(&call.shared, &call.caller, Verb::Delete, |_| place).is_ok()
        };
        if !owned.is_some_and(|(holder, owner, _)| may(holder) && held(holder, owner)) {
            return Err(not_found(kind, name));
        }
        let why = format!(
            "Pod/{name}: only a replica of a Workload is restarted by a delete: kith runs no other pod that is restarted so"
        );
        return Err(invalid(why));
    };
    // (Asked before the Workload is looked at, and told 404 as of a nothing: who may not restart it
    // is not told what is there, nor that a bare pod of its name is.)
    api::permit(&call.shared, &call.caller, Verb::Apply, |_| {
        vec![("Workload".to_string(), Some(namespace.to_string()))]
    })
    .map_err(|_| not_found(kind, name))?;
    let key = format!("Workload/{namespace}/{owner}");
    let running = {
        let state = call.shared.store.lock().expect("a handler panicked holding the store");
        state
            .store
            .get(&key)
            .filter(|held| raw(held).is_some())
            .is_some_and(|held| {
                held.status.as_ref().is_some_and(|status| {
                    status["containers"]
                        .as_array()
                        .is_some_and(|units| units.iter().any(|u| u["replica"] == replica))
                })
            })
    };
    if !running {
        return Err(not_found(kind, name));
    }
    let _ = api::restart_replica(&call.shared, &call.caller, &key, replica, false)
        .await
        .map_err(refusal)?;
    let done = json!({
        "kind": "Status", "apiVersion": "v1", "status": "Success",
        "details": { "name": name, "group": kind.group, "kind": kind.plural },
    });
    Ok(Written(StatusCode::OK, Some(done), hints).into_response())
}

/// What a watch has told its client, and what is still to tell.
struct Watch {
    call: Call,
    kind: &'static Kind,
    namespace: Option<String>,
    generation: tokio::sync::watch::Receiver<u64>,
    /// Each object told of, by the key of the resource it is made of and its own: its version,
    /// and enough of it to say it is gone.
    known: BTreeMap<(String, String), (Value, Value)>,
    /// How far into the store's log the last reading was (none before the first).
    after: Option<u64>,
    /// What the readings did: resources made into objects, and objects compared with known ones.
    translated: usize,
    compared: usize,
    /// Events not sent yet, a line each.
    due: Vec<u8>,
    until: tokio::time::Instant,
    over: bool,
}

/// A reading of the store for a watch: the objects, the generation it was at, and the keys
/// of the resources they were made from (none: all of them were read).
struct Seen {
    found: Vec<(String, Value)>,
    at: u64,
    changed: Option<BTreeSet<String>>,
}

impl Watch {
    fn start(call: Call, kind: &'static Kind, namespace: Option<String>, seconds: u64) -> Watch {
        // (Marked as seen before the store is read: a change after the reading wakes the watch.)
        let mut generation = call.shared.generation.subscribe();
        drop(generation.borrow_and_update());
        Watch {
            generation,
            call,
            kind,
            namespace,
            known: BTreeMap::new(),
            after: None,
            translated: 0,
            compared: 0,
            due: Vec::new(),
            until: tokio::time::Instant::now() + Duration::from_secs(seconds),
            over: false,
        }
    }

    /// What `Verb::Watch` lets the caller see of what changed since the last reading, or of
    /// everything when that is not known (see the top of this file). What it shows is what a
    /// list shows: the same grants, and the same selectors, are asked of each resource read.
    fn read(&mut self) -> Seen {
        let call = &self.call;
        let state = call.shared.store.lock().expect("a handler panicked holding the store");
        let grants = Grants::of(&call.caller, &state.store);
        // (A worker that runs from a view has its store put there without a log.)
        let kept = call.shared.view.borrow().is_none();
        let access = |key: &&str| {
            ["Identity/", "RoleBinding/", "Role/"]
                .iter()
                .any(|held| key.starts_with(held))
        };
        let names = !matches!(self.kind.held, Held::As("Namespace"));
        let only = self
            .after
            .filter(|_| kept && names)
            .and_then(|after| state.touched(after));
        let only = only.filter(|keys| !keys.iter().any(access));
        let mut look = Look {
            only: only.as_ref(),
            translated: 0,
        };
        let namespace = self.namespace.as_deref();
        let mut found = read(
            &state.store,
            self.kind,
            namespace,
            None,
            &grants,
            &Verb::Watch,
            &mut look,
        );
        found.retain(|(_, object)| selected(object, &call.asked));
        let changed = only
            .as_ref()
            .map(|keys| keys.iter().map(|key| key.to_string()).collect());
        self.translated += look.translated;
        self.after = Some(state.index());
        // (Read under the store's lock: a change and its generation come together.)
        Seen {
            found,
            at: *call.shared.generation.borrow(),
            changed,
        }
    }

    fn event(&mut self, event: &str, object: &Value, at: u64) {
        let line = match self.call.table && event != "BOOKMARK" {
            true => json!({ "type": event, "object": table(self.kind, std::slice::from_ref(object), at) }),
            false => json!({ "type": event, "object": object }),
        };
        serde_json::to_writer(&mut self.due, &line).expect("JSON into memory");
        self.due.push(b'\n');
    }

    /// Lines up an event for each object of `found` that is new or changed since the last
    /// look, and for each that is gone (none with `quiet`: the client has them from its
    /// list). Then a bookmark, where the client takes them: the generation it is told up to.
    fn tell(&mut self, seen: Seen, quiet: bool, first: bool) {
        let Seen { found, at, changed } = seen;
        // What may be gone: of what was read only the objects of the resources read, else all.
        let mut gone: BTreeSet<(String, String)> = match &changed {
            None => self.known.keys().cloned().collect(),
            Some(keys) => keys
                .iter()
                .flat_map(|key| {
                    let from = (key.clone(), String::new());
                    let told = self.known.range(from..).take_while(move |(of, _)| of.0 == *key);
                    told.map(|(of, _)| of.clone())
                })
                .collect(),
        };
        self.compared += found.len();
        let mut told = false;
        for (of, object) in found {
            let meta = &object["metadata"];
            let id = (of, format!("{}/{}", meta["namespace"], meta["name"]));
            gone.remove(&id);
            let event = match self.known.get(&id) {
                None => "ADDED",
                Some((version, _)) if *version != meta["resourceVersion"] => "MODIFIED",
                Some(_) => continue,
            };
            let last = json!({
                "apiVersion": object["apiVersion"], "kind": object["kind"],
                "metadata": {
                    "name": meta["name"], "namespace": meta["namespace"], "uid": meta["uid"],
                    "resourceVersion": meta["resourceVersion"],
                },
            });
            self.known.insert(id, (meta["resourceVersion"].clone(), last));
            if !quiet {
                self.event(event, &object, at);
                told = true;
            }
        }
        self.compared += gone.len();
        for id in gone {
            if let Some((_, last)) = self.known.remove(&id) {
                self.event("DELETED", &last, at);
                told = true;
            }
        }
        let asked = |name: &str| self.call.asked.get(name).is_some_and(|value| value == "true");
        let (bookmarks, ends) = (asked("allowWatchBookmarks"), first && asked("sendInitialEvents"));
        if (told || first || self.over) && bookmarks {
            let mut mark = json!({
                "apiVersion": version_of(self.kind.group), "kind": self.kind.kind,
                "metadata": { "resourceVersion": at.to_string() },
            });
            // (A client that asked for what is there as events is told where they end.)
            if ends {
                mark["metadata"]["annotations"] = json!({ "k8s.io/initial-events-end": "true" });
            }
            self.event("BOOKMARK", &mark, at);
        }
    }

    /// Does the caller's certificate still stand for it? (A watch is long: an Identity
    /// deleted, or given another key, meanwhile is told no more.)
    fn stands(&self) -> bool {
        match (&self.call.caller, &self.call.certificate) {
            (Caller::Identity(_) | Caller::Node(_), Some(shown)) => shown.stands(&self.call.shared),
            (Caller::Identity(_), None) => false,
            (Caller::Admin | Caller::Console(_), _) => true,
            // (A node shows its certificate, and nothing is passed on to a watch.)
            (Caller::Node(_), None) | (Caller::Via(..) | Caller::Checked(..), _) => false,
        }
    }
}

fn watch(call: Call, kind: &'static Kind, namespace: Option<String>) -> Result<Response, No> {
    call.allowed(kind, namespace.as_deref(), Verb::Watch)?;
    let asked = |name: &str| call.asked.get(name).map(String::as_str);
    let seconds = asked("timeoutSeconds").and_then(|seconds| seconds.parse().ok());
    let seconds = seconds.unwrap_or(WATCH_SECS).min(WATCH_SECS);
    let from = asked("resourceVersion").filter(|from| !from.is_empty() && *from != "0");
    let from = from.map(str::to_string);
    let events = asked("sendInitialEvents") == Some("true");
    let mut watch = Watch::start(call, kind, namespace, seconds);
    let seen = watch.read();
    // From a list's version, only what changes after it is told; and only from the newest:
    // a generation is a time, not a place in the log, so what changed since an older one is not told.
    if let Some(from) = from.as_ref().filter(|from| **from != seen.at.to_string() && !events) {
        let why = format!("too old resource version: {from} ({})", seen.at);
        return Err(status(StatusCode::GONE, "Expired", why));
    }
    watch.tell(seen, from.is_some() && !events, true);
    let events = futures_util::stream::unfold(watch, |mut watch| async move {
        loop {
            if !watch.due.is_empty() {
                let due = std::mem::take(&mut watch.due);
                return Some((Ok::<_, std::io::Error>(Bytes::from(due)), watch));
            }
            if watch.over {
                return None;
            }
            let mut stop = watch.call.shared.stop.subscribe();
            tokio::select! {
                changed = watch.generation.changed() => watch.over = changed.is_err(),
                _ = stop.wait_for(|stop| *stop) => watch.over = true,
                () = tokio::time::sleep_until(watch.until) => watch.over = true,
            }
            if !watch.stands() {
                return None;
            }
            drop(watch.generation.borrow_and_update());
            let seen = watch.read();
            watch.tell(seen, false, false);
        }
    });
    Ok(([(header::CONTENT_TYPE, "application/json")], Body::from_stream(events)).into_response())
}

/// A reading of what a pod's units wrote, and where in each file it has come to.
struct Reading {
    shared: Arc<Shared>,
    caller: Caller,
    /// The resource that runs the pod, and which replica of it the pod is.
    key: String,
    replica: u32,
    unit: Option<String>,
    tail: Option<u64>,
    at: [Option<u64>; 2],
}

impl Reading {
    /// What was written to stdout and to stderr since the last reading, and whether more may come.
    async fn more(&mut self) -> Result<(String, bool), ApiError> {
        let (mut text, mut more) = (String::new(), false);
        for stream in 0..2 {
            let options = LogOptions {
                unit: self.unit.clone(),
                replica: self.replica,
                stderr: stream == 1,
                offset: self.at[stream],
                tail: self.tail.filter(|_| self.at[stream].is_none()),
                ..LogOptions::default()
            };
            let Json(read) = api::output(&self.shared, &self.caller, &self.key, &options).await?;
            text.push_str(read["data"].as_str().unwrap_or_default());
            self.at[stream] = read["next"].as_u64();
            more |= read["more"] == true;
        }
        Ok((text, more))
    }
}

/// What the units of a pod wrote, as `kubectl logs` reads it: plain text, what was
/// written to stdout and then what was written to stderr, and with `follow` what comes after.
//
// ponytail: the two are two files here, so they are not in the order they were written;
// one file with both would be a change of every unit's log.
async fn log(call: &Call, namespace: &str, pod: &str) -> Result<Response, No> {
    let not_kept = ["sinceSeconds", "sinceTime", "timestamps", "previous", "limitBytes"];
    if let Some(asked) = not_kept.iter().find(|asked| call.asked.contains_key(**asked)) {
        let why = format!("{asked}: a unit's output is kept as it was written, all its runs in one file and not when");
        return Err(status(StatusCode::BAD_REQUEST, "BadRequest", why));
    }
    // What a unit wrote is read by who may read the resource that runs it.
    let (key, replica) = pod_run(call, namespace, pod, Verb::Get, false)?;
    let follow = call.asked.get("follow").is_some_and(|follow| follow == "true");
    let mut reading = Reading {
        shared: call.shared.clone(),
        caller: call.caller.clone(),
        key,
        replica,
        unit: call.asked.get("container").cloned(),
        tail: call.asked.get("tailLines").and_then(|lines| lines.parse().ok()),
        at: [None; 2],
    };
    // (The first reading here, so that what cannot be read is said as an error.)
    let (first, _) = reading.more().await.map_err(refusal)?;
    let chunks = futures_util::stream::unfold((reading, Some(first)), move |(mut reading, first)| async move {
        if let Some(first) = first.filter(|first| !first.is_empty()) {
            return Some((Ok::<_, std::io::Error>(Bytes::from(first)), (reading, None)));
        }
        loop {
            let (text, more) = reading.more().await.ok()?;
            if !text.is_empty() {
                return Some((Ok(Bytes::from(text)), (reading, None)));
            }
            if !follow || !more || *reading.shared.stop.borrow() {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
    Ok(([(header::CONTENT_TYPE, "text/plain")], Body::from_stream(chunks)).into_response())
}

/// The resource that runs `pod` in `namespace` and the replica the pod is, for a caller who may `verb`
/// it: a bare Pod's name first (as `delete` does: it is its own Job's or Workload's run 0), else what
/// the pod's name says, checked against what is there. The right is asked before anything of the
/// store is, so a caller with none is told the same of every name, a pod's or not.
/// (`any`, for the UI's terminal: what `kith apply` made is held too, not only what the Kubernetes API sent.)
fn pod_run(call: &Call, namespace: &str, pod: &str, verb: Verb, any: bool) -> Result<(String, u32), No> {
    let may = |of: &str| {
        let place = vec![(of.to_string(), Some(namespace.to_string()))];
        api::permit(&call.shared, &call.caller, verb.clone(), |_| place).map_err(refusal)
    };
    // (Any of the holders a pod might be of; the first refusal, the Workload's, is what is said.)
    if let Err(refused) = may("Workload")
        && ["Job", "NodeWorkload"].into_iter().all(|of| may(of).is_err())
    {
        return Err(refused);
    }
    let found = |key: &str| {
        let state = call.shared.store.lock().expect("a handler panicked holding the store");
        state.store.get(key).is_some_and(|held| any || raw(held).is_some())
    };
    // (Past that gate, a caller who lacks the right on the holder a name points to is told 404, as of a
    // name that is nothing, whether the pod is there or not.)
    let nothing = || not_found(&KINDS[0], pod);
    let named = {
        let state = call.shared.store.lock().expect("a handler panicked holding the store");
        resolve_pod(&state.store, namespace, pod)
    };
    let (of, owner, replica) = named.ok_or_else(nothing)?;
    may(of).map_err(|_| nothing())?;
    // A NodeWorkload's pod runs on the host, as `kith run` runs there: that takes Exec on `Node`, cluster-wide.
    if of == "NodeWorkload" && matches!(verb, Verb::Exec) {
        let node = vec![("Node".to_string(), None)];
        // (Said as a refusal, not as 404: this caller holds the right on the NodeWorkload, so it knows the pod's kind.)
        api::permit(&call.shared, &call.caller, verb, |_| node).map_err(refusal)?;
    }
    let key = format!("{of}/{namespace}/{owner}");
    found(&key).then_some((key, replica)).ok_or_else(nothing)
}

/// The channel protocols kithd answers for exec and attach, in the order it prefers them.
const CHANNELS: [&str; 2] = ["v5.channel.k8s.io", "v4.channel.k8s.io"];

/// `kubectl exec`, `attach` and `cp` (a tar run by exec): the Exec right on the Workload, Job or
/// NodeWorkload that runs the pod is checked first, and only then is the WebSocket upgrade looked at.
/// Each decision is written in the audit log, as `kith run`'s is.
async fn pod_stream(
    call: &Call,
    verb: &str,
    namespace: &str,
    pod: &str,
    parts: &Parts,
    upgrade: Option<OnUpgrade>,
    ui: bool,
) -> Result<Response, No> {
    let decided = pod_decision(call, verb, namespace, pod, parts, upgrade, ui).await;
    let outcome = decided.as_ref().map(|_| ()).map_err(|no| no.why.clone());
    call.shared
        .audit
        .record(&call.caller, verb, vec![format!("pod {namespace}/{pod}")], outcome);
    decided
}

/// Why an upgrade's Origin is refused. kubectl sends none, so on the Kubernetes route any is a browser's and
/// refused. The UI's own route (`ui`) takes one only from the UI's own page: its authority is the one the
/// page was reached by (`Host`; the scheme is `https` direct and `http` behind `kith ui`'s loopback port),
/// and a browser that says `Sec-Fetch-Site` says `same-origin`. A page of another site, or of another port
/// of this host, is refused: it would otherwise hold a shell with the certificate the browser holds.
fn foreign_origin(headers: &axum::http::HeaderMap, ui: bool) -> Option<&'static str> {
    let origin = headers.get(header::ORIGIN)?;
    if !ui {
        return Some("an upgrade that carries an Origin is refused: kubectl sends none");
    }
    let host = headers.get(header::HOST).and_then(|host| host.to_str().ok());
    let host = host.filter(|host| !host.is_empty());
    let own = origin.to_str().ok().is_some_and(|origin| {
        let authority = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"));
        authority.is_some() && authority == host
    });
    let site = headers.get("sec-fetch-site").map(|site| site.as_bytes());
    (!own || site.is_some_and(|site| site != b"same-origin"))
        .then_some("a shell is opened from the UI's own page only: this one's Origin is another's")
}

/// The UI's terminal: the same exec as `kubectl exec` (`GET /v1/exec/NAMESPACE/POD?command=...&tty=true`),
/// under the caller's own Exec right and no other, with the Origin of the UI's own page let through.
pub async fn ui_exec(
    State(shared): State<Arc<Shared>>,
    Route((namespace, pod)): Route<(String, String)>,
    mut parts: Parts,
) -> Response {
    let Some(caller) = parts.extensions.get::<Caller>().cloned() else {
        let why = "who asks is not known".to_string();
        return status(StatusCode::UNAUTHORIZED, "Unauthorized", why).into_response();
    };
    let upgrade = parts.extensions.remove::<OnUpgrade>();
    let call = Call {
        shared,
        caller,
        certificate: parts.extensions.get::<Certificate>().cloned(),
        asked: Asked::default(),
        table: false,
    };
    pod_stream(&call, "exec", &namespace, &pod, &parts, upgrade, true)
        .await
        .unwrap_or_else(No::into_response)
}

async fn pod_decision(
    call: &Call,
    verb: &str,
    namespace: &str,
    pod: &str,
    parts: &Parts,
    upgrade: Option<OnUpgrade>,
    ui: bool,
) -> Result<Response, No> {
    let (method, headers, query) = (
        parts.method.as_str(),
        &parts.headers,
        parts.uri.query().unwrap_or_default(),
    );
    let (key, _) = pod_run(call, namespace, pod, Verb::Exec, ui)?;
    // Root of the container's user namespace (`root=true`, which only kith's own client sends) takes Apply on the
    // holder as well as Exec; the node the pod runs on checks it again where the hop arrives. Attach has no root.
    if verb == "exec" && crate::pod_exec::asks_root(query) {
        let holder = vec![(
            key.split('/').next().unwrap_or_default().to_string(),
            Some(namespace.to_string()),
        )];
        api::permit(&call.shared, &call.caller, Verb::Apply, |_| holder).map_err(refusal)?;
    }
    // kubectl sends no Origin: one is a browser's, and a browser is not let upgrade to a shell,
    // unless it is the UI's route and the page is the UI's own.
    if let Some(why) = foreign_origin(headers, ui) {
        return Err(status(StatusCode::FORBIDDEN, "Forbidden", why.into()));
    }
    let said = |name| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    };
    let offered: Vec<&str> = said(header::SEC_WEBSOCKET_PROTOCOL).split(',').map(str::trim).collect();
    let chosen = CHANNELS.into_iter().find(|channel| offered.contains(channel));
    let accept = websocket::accept_key(said(header::SEC_WEBSOCKET_KEY));
    let upgrading = said(header::UPGRADE).eq_ignore_ascii_case("websocket")
        && said(header::CONNECTION).to_ascii_lowercase().contains("upgrade")
        && said(header::SEC_WEBSOCKET_VERSION) == "13";
    let (Some(upgrade), Some(chosen), Some(accept), true) = (upgrade, chosen, accept, upgrading) else {
        let why = "exec, attach and cp are a WebSocket: a GET that upgrades, with version 13 and a channel protocol kithd answers";
        return Err(status(StatusCode::BAD_REQUEST, "BadRequest", why.into()));
    };
    if method != "GET" {
        let why = "a WebSocket is asked by GET";
        return Err(status(StatusCode::BAD_REQUEST, "BadRequest", why.into()));
    }
    // (The session answers for the signature this request came with: the hop to another node passes it on.)
    let (shared, who, query) = (call.shared.clone(), call.caller.clone(), query.to_string());
    let (verb, namespace, pod) = (verb.to_string(), namespace.to_string(), pod.to_string());
    tokio::spawn(crate::access_sign::within(crate::access_sign::current(), async move {
        if let Ok(upgraded) = upgrade.await {
            crate::pod_exec::session(shared, who, verb, namespace, pod, query, TokioIo::new(upgraded)).await;
        }
    }));
    Ok((
        StatusCode::SWITCHING_PROTOCOLS,
        [
            (header::UPGRADE, "websocket".to_string()),
            (header::CONNECTION, "Upgrade".to_string()),
            (header::SEC_WEBSOCKET_ACCEPT, accept),
            (header::SEC_WEBSOCKET_PROTOCOL, chosen.to_string()),
        ],
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where a test holds an undo (by its `Shared`) between its read of the head and its apply:
    /// it says it is there, then waits to be let go.
    type Hold = (tokio::sync::oneshot::Sender<()>, tokio::sync::oneshot::Receiver<()>);
    static HELD: std::sync::Mutex<Vec<(usize, Hold)>> = std::sync::Mutex::new(Vec::new());

    pub(super) async fn pause_before_undo(shared: &Arc<crate::Shared>) {
        let me = Arc::as_ptr(shared) as usize;
        let hold = {
            let mut held = HELD.lock().unwrap();
            held.iter().position(|(of, _)| *of == me).map(|at| held.remove(at).1)
        };
        if let Some((there, go)) = hold {
            let _ = there.send(());
            let _ = go.await;
        }
    }

    /// The UI's terminal takes an upgrade from its own page only (an Origin that is the Host it was sent to, and no
    /// browser word of another site); the Kubernetes route takes no Origin at all.
    #[test]
    fn foreign_origin_lets_only_the_uis_own_page_open_a_shell() {
        let ask = |pairs: &[(&'static str, &str)], ui: bool| {
            let mut headers = axum::http::HeaderMap::new();
            for (name, value) in pairs {
                headers.insert(*name, value.parse().unwrap());
            }
            foreign_origin(&headers, ui).is_some()
        };
        let own = [("host", "kith:7443"), ("origin", "https://kith:7443")];
        assert!(!ask(&[("host", "kith:7443")], true), "no Origin: not a browser");
        assert!(!ask(&own, true));
        assert!(
            !ask(&[("host", "127.0.0.1:9"), ("origin", "http://127.0.0.1:9")], true),
            "the forwarder's"
        );
        assert!(!ask(&[own[0], own[1], ("sec-fetch-site", "same-origin")], true));
        for (why, pairs) in [
            ("another site", vec![own[0], ("origin", "https://evil.example")]),
            ("another port", vec![own[0], ("origin", "https://kith:1")]),
            ("opaque", vec![own[0], ("origin", "null")]),
            ("no Host", vec![own[1]]),
            ("cross-site", vec![own[0], own[1], ("sec-fetch-site", "cross-site")]),
            ("same-site", vec![own[0], own[1], ("sec-fetch-site", "same-site")]),
        ] {
            assert!(ask(&pairs, true), "{why}");
        }
        assert!(ask(&own, false), "the Kubernetes route refuses any Origin");
        assert!(!ask(&[own[0]], false));
    }

    /// The Kubernetes route carries kith's `root=true` too: it takes Apply on the holder as well as Exec, refused
    /// (403, before any upgrade) for a caller with Exec alone, who still gets a plain exec.
    #[tokio::test]
    async fn exec_root_needs_apply_on_the_kubernetes_route() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-exec-root-{}", std::process::id()));
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
        let held = "
apiVersion: kith.dev/v1
kind: Workload
metadata: {name: web, namespace: default}
spec: {replicas: 1, template: {exec: [{name: sleep, command: [sleep, '3600']}]}}
---
apiVersion: kith.dev/v1
kind: Identity
metadata: {name: alice}
spec: {}
---
apiVersion: kith.dev/v1
kind: Identity
metadata: {name: dana}
spec: {}
---
apiVersion: kith.dev/v1
kind: Role
metadata: {name: execer}
spec:
  rules:
    - {kinds: [Workload], verbs: [exec], namespaces: [default]}
---
apiVersion: kith.dev/v1
kind: Role
metadata: {name: rooter}
spec:
  rules:
    - {kinds: [Workload], verbs: [exec, apply], namespaces: [default]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: alice-execer}
spec: {role: execer, subjects: [alice]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: dana-rooter}
spec: {role: rooter, subjects: [dana]}
";
        {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(held).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        let ask = |who: &str, query: &str| {
            let call = Call {
                shared: shared.clone(),
                caller: Caller::Identity(who.into()),
                certificate: None,
                asked: Asked::new(),
                table: false,
            };
            let request = axum::http::Request::builder()
                .uri(format!("/exec?{query}"))
                .body(())
                .unwrap();
            (call, request.into_parts().0)
        };
        // (A request that is no upgrade is 400 once past the gate: that is the plain exec's way here.)
        for (who, query, want) in [
            ("alice", "command=true", 400),
            ("alice", "command=true&root=true", 403),
            ("alice", "command=true&root=false", 400),
            ("dana", "command=true&root=true", 400),
            ("dana", "command=true", 400),
        ] {
            let (call, parts) = ask(who, query);
            let no = pod_decision(&call, "exec", "default", "web-0", &parts, None, true)
                .await
                .err()
                .unwrap();
            assert_eq!(no.code.as_u16(), want, "{who} {query}: {}", no.why);
            if want == 403 {
                assert!(no.why.contains("alice may not apply Workload"), "{}", no.why);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A status is kithd's own word for what runs: a client's PUT or PATCH of it is refused
    /// in those words, not with the bare 405 of a path nothing is done to.
    #[tokio::test]
    async fn status_is_kithds_own() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-status-{}", std::process::id()));
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
        for method in ["PUT", "PATCH"] {
            let mut request = axum::http::Request::builder().method(method).body(()).unwrap();
            request.extensions_mut().insert(Caller::Admin);
            let (parts, ()) = request.into_parts();
            let rest = "namespaces/default/deployments/web/status";
            let no = serve(shared.clone(), parts, "apps", rest, Asked::new(), b"{}")
                .await
                .unwrap_err();
            assert_eq!(no.code, StatusCode::METHOD_NOT_ALLOWED);
            assert!(no.why.contains("status is kithd's own"), "{method}: {}", no.why);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A headless Service has no address, whatever a status kept from before it was made
    /// headless says: it reads `None`, as Kubernetes reads a headless Service. One that is
    /// not headless reads the address kithd gave it.
    #[test]
    fn a_headless_service_reads_none_whatever_its_stale_address() {
        let service = |headless: &str| service_served(headless, json!({}));
        let headless = service("headless: true,");
        assert_eq!(headless.pointer("/spec/clusterIP"), Some(&json!("None")));
        assert_eq!(headless.pointer("/spec/clusterIPs"), Some(&json!(["None"])));
        let mesh = service("");
        assert_eq!(mesh.pointer("/spec/clusterIP"), Some(&json!("fd00::7")));
    }

    /// Helm renders `clusterIP: ""` to mean "allocate"; it reads back with the address, or
    /// `helm --wait` (a Service is ready once its ClusterIP is not "") never finishes.
    #[test]
    fn a_service_sent_with_an_empty_cluster_ip_reads_its_address() {
        let empty = json!({ "clusterIP": "", "clusterIPs": [""] });
        let mesh = service_served("", empty.clone());
        assert_eq!(mesh.pointer("/spec/clusterIP"), Some(&json!("fd00::7")));
        assert_eq!(mesh.pointer("/spec/clusterIPs"), Some(&json!(["fd00::7"])));
        let headless = service_served("headless: true,", empty);
        assert_eq!(headless.pointer("/spec/clusterIP"), Some(&json!("None")));
        assert_eq!(headless.pointer("/spec/clusterIPs"), Some(&json!(["None"])));
    }

    /// A Service as the Kubernetes API serves it: what was sent (`extra` merged into its
    /// spec), with the status address `fd00::7`.
    fn service_served(headless: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut sent = json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": { "name": "web", "namespace": "default" },
            "spec": { "selector": { "app": "web" }, "ports": [{ "port": 80 }] },
        });
        sent["spec"]
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let sent = serde_json::to_string(&sent.to_string()).unwrap();
        let source = format!(
            "apiVersion: kith.dev/v1\nkind: Service\n\
             metadata: {{name: web, namespace: default, annotations: {{{SENT}: {sent}}}}}\n\
             spec: {{{headless} selector: {{app: web}}, ports: [{{port: 80}}]}}\n"
        );
        let mut resource = kith_api::Resource::from_source(&source)
            .unwrap()
            .pop()
            .unwrap()
            .unwrap();
        resource.status = Some(json!({"address": "fd00::7"}));
        served(&resource).unwrap().1
    }

    /// Who may write a kind and not read it is not answered with what is there by a
    /// change of it, and who may do neither is not told whether it is there.
    #[tokio::test]
    async fn a_write_is_asked_for_before_anything_is_said_of_what_is_there() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-write-{}", std::process::id()));
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
        let held = "
apiVersion: kith.dev/v1
kind: Identity
metadata: {name: carol}
spec: {}
---
apiVersion: kith.dev/v1
kind: Role
metadata: {name: writer}
spec:
  rules:
    - {kinds: [Secret], verbs: [apply]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: carol-writer}
spec: {role: writer, subjects: [carol]}
";
        let call = |who: &str| Call {
            shared: shared.clone(),
            caller: Caller::Identity(who.into()),
            certificate: None,
            asked: Asked::new(),
            table: false,
        };
        {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(held).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        let secrets = KINDS.iter().find(|kind| kind.kind == "Secret").unwrap();
        let kept = json!({ "metadata": { "name": "kept" }, "stringData": { "password": "hunter2" } }); // pragma: allowlist secret
        let admin = Call {
            caller: Caller::Admin,
            ..call("root")
        };
        let made = write(&admin, secrets, Some("default"), None, How::Create, kept).await;
        assert!(made.is_ok_and(|made| made.0 == StatusCode::CREATED));
        let label = || json!({ "metadata": { "labels": { "a": "b" } } });
        let patch = How::Patch { strategic: false };
        let code = |done: Result<Written, No>| done.err().map(|no| no.code);
        let carol = call("carol");
        let done = write(&carol, secrets, Some("default"), Some("kept"), patch, label()).await;
        assert_eq!(
            code(done),
            Some(StatusCode::FORBIDDEN),
            "a patch is answered with all of it"
        );
        // A replace of what is there is answered with all of it, managers' fields too: the same.
        let sent = json!({ "metadata": { "name": "kept" }, "stringData": { "password": "other" } }); // pragma: allowlist secret
        let done = write(
            &carol,
            secrets,
            Some("default"),
            Some("kept"),
            How::Replace,
            sent.clone(),
        )
        .await;
        assert_eq!(code(done), Some(StatusCode::FORBIDDEN), "a replace of what is there");
        let sent = json!({ "metadata": { "name": "fresh" }, "stringData": { "password": "x" } }); // pragma: allowlist secret
        let done = write(&carol, secrets, Some("default"), Some("fresh"), How::Replace, sent).await;
        assert_eq!(
            code(done),
            Some(StatusCode::NOT_FOUND),
            "a replace of what is not there answers 404, as to any writer"
        );
        // What is there and what is not are the same to who may not ask.
        let eve = call("eve");
        for name in ["kept", "nothing"] {
            let done = write(&eve, secrets, Some("default"), Some(name), patch, label()).await;
            assert_eq!(code(done), Some(StatusCode::FORBIDDEN), "{name}");
            let gone = delete(&eve, secrets, Some("default"), name, &json!({})).await;
            assert_eq!(gone.err().map(|no| no.code), Some(StatusCode::FORBIDDEN), "{name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_strategic_patch_merges_lists_by_name_and_a_merge_patch_replaces_them() {
        let live = json!({ "spec": { "replicas": 2, "template": { "spec": { "containers": [
            { "name": "web", "image": "nginx:1", "env": [{ "name": "A", "value": "1" }, { "name": "B", "value": "2" }] },
            { "name": "side", "image": "busybox" },
        ] } } } });
        let patch = json!({ "spec": { "replicas": null, "template": { "spec": {
            "$setElementOrder/containers": [{ "name": "side" }, { "name": "web" }],
            "containers": [
                { "name": "web", "image": "nginx:2", "env": [{ "name": "A", "$patch": "delete" }, { "name": "C", "value": "3" }] },
            ],
        } } } });
        let mut strategic = live.clone();
        patched(&mut strategic, patch.clone(), true);
        let want = json!({ "spec": { "template": { "spec": { "containers": [
            { "name": "side", "image": "busybox" },
            { "name": "web", "image": "nginx:2", "env": [{ "name": "B", "value": "2" }, { "name": "C", "value": "3" }] },
        ] } } } });
        assert_eq!(strategic, want);
        let mut merge = live.clone();
        patched(
            &mut merge,
            json!({ "spec": { "template": { "spec": { "containers": [{ "name": "one" }] } } } }),
            false,
        );
        assert_eq!(
            merge["spec"]["template"]["spec"]["containers"],
            json!([{ "name": "one" }])
        );
        assert_eq!(merge["spec"]["replicas"], 2);
        // What a client sends is never trusted to be the shape it should: none of these panics.
        for odd in [
            json!([1]),
            json!("x"),
            json!({ "spec": [{ "$patch": "replace" }] }),
            json!({ "$retainKeys": 3 }),
        ] {
            patched(&mut live.clone(), odd.clone(), true);
            patched(&mut json!(7), odd, true);
        }
    }

    /// RFC 6902's six operations, in order, over a document: each as the RFC says it works,
    /// and a pointer's escapes (`~1` for a `/` in a key, `~0` for a `~`).
    #[test]
    fn json_patch_applies_the_six_operations_in_order() {
        let live = json!({ "spec": { "replicas": 2, "tags": ["a", "b"] }, "metadata": { "labels": { "app": "web" } } });
        let ops = json!([
            { "op": "add", "path": "/metadata/labels/tier", "value": "front" },
            { "op": "replace", "path": "/spec/replicas", "value": 3 },
            { "op": "test", "path": "/metadata/labels/app", "value": "web" },
            { "op": "copy", "from": "/spec/replicas", "path": "/spec/copied" },
            { "op": "move", "from": "/spec/tags/0", "path": "/spec/tags/-" },
            { "op": "remove", "path": "/metadata/labels/app" },
            { "op": "add", "path": "/spec/tags/0", "value": "first" },
        ]);
        let want = json!({
            "spec": { "replicas": 3, "copied": 3, "tags": ["first", "b", "a"] },
            "metadata": { "labels": { "tier": "front" } },
        });
        assert_eq!(json_patch(&live, &ops), Ok(want));
        let escaped = json!([
            { "op": "add", "path": "/a~1b~0c", "value": 1 },
            { "op": "test", "path": "/a~1b~0c", "value": 1 },
        ]);
        assert_eq!(json_patch(&json!({}), &escaped), Ok(json!({ "a/b~c": 1 })));
        let whole = json!([{ "op": "replace", "path": "", "value": { "whole": true } }]);
        assert_eq!(json_patch(&live, &whole), Ok(json!({ "whole": true })));
    }

    /// Each way a patch can fail is named, and a patch with one in it is refused whole: what
    /// its earlier operations did is not kept, and nothing is added where a path is not there.
    #[test]
    fn json_patch_refuses_each_way_it_can_fail_and_changes_nothing() {
        let live = json!({ "spec": { "replicas": 2, "tags": ["a"] } });
        let refused = [
            (
                json!([{ "op": "test", "path": "/spec/replicas", "value": 9 }]),
                "test /spec/replicas",
            ),
            (
                json!([{ "op": "replace", "path": "/spec/nope", "value": 1 }]),
                "/spec/nope: the path is not there",
            ),
            (
                json!([{ "op": "remove", "path": "/spec/nope" }]),
                "/spec/nope: the path is not there",
            ),
            (
                json!([{ "op": "add", "path": "/spec/nope/deeper", "value": 1 }]),
                "/spec/nope: the path is not there",
            ),
            (
                json!([{ "op": "add", "path": "/spec/tags/9", "value": 1 }]),
                "/spec/tags/9: the index is past the end",
            ),
            (
                json!([{ "op": "replace", "path": "/spec/tags/-", "value": 1 }]),
                "/spec/tags/-: - is not an index",
            ),
            (
                json!([{ "op": "copy", "from": "/spec/nope", "path": "/x" }]),
                "/spec/nope: the path is not there",
            ),
            (
                json!([{ "op": "move", "from": "/spec", "path": "/spec/inside" }]),
                "/spec is above it",
            ),
            (
                json!([{ "op": "add", "path": "spec", "value": 1 }]),
                "spec: a path starts with /",
            ),
            (
                json!([{ "op": "replace", "path": "/spec/~2", "value": 1 }]),
                "/spec/~2: a ~ is written ~0 or ~1",
            ),
            (
                json!([{ "op": "replace", "path": "/spec/replicas" }]),
                "replace /spec/replicas: needs a value",
            ),
            (json!([{ "op": "move", "path": "/x" }]), "move /x: needs a from"),
            (json!([{ "op": "twist", "path": "/x" }]), "twist: not one of"),
            (json!([{ "path": "/x" }]), "an operation has no op"),
            (json!({ "op": "test", "path": "" }), "the patch is a list"),
            (
                json!([{ "op": "replace", "path": "/spec/replicas", "value": 3 }, { "op": "test", "path": "/spec/replicas", "value": 2 }]),
                "test /spec/replicas",
            ),
        ];
        for (ops, why) in refused {
            let got = json_patch(&live, &ops);
            assert!(got.as_ref().is_err_and(|e| e.contains(why)), "{ops}: {got:?}");
        }
        // A patch of too many operations, and copies that would double a document again and again.
        let many = Value::Array(vec![
            json!({ "op": "test", "path": "/spec/replicas", "value": 2 });
            PATCH_OPS + 1
        ]);
        assert!(json_patch(&live, &many).is_err_and(|e| e.contains("operations")));
        let doubling: Vec<Value> = (0..24)
            .map(|n| json!({ "op": "copy", "from": "", "path": format!("/k{n}") }))
            .collect();
        assert!(json_patch(&live, &Value::Array(doubling)).is_err_and(|e| e.contains("copies")));
    }

    /// RFC 6902's `test` compares by value: 2 and 2.0 are one number, at any depth.
    #[test]
    fn json_patch_test_compares_numbers_by_value() {
        let live = json!({ "spec": { "replicas": 2, "ratio": 2.0, "by": { "n": 7 } } });
        let equal = json!([
            { "op": "test", "path": "/spec/replicas", "value": 2.0 },
            { "op": "test", "path": "/spec/ratio", "value": 2 },
            { "op": "test", "path": "/spec/by", "value": { "n": 7.0 } },
        ]);
        assert_eq!(json_patch(&live, &equal), Ok(live.clone()));
        let other = json!([{ "op": "test", "path": "/spec/replicas", "value": 2.5 }]);
        assert!(json_patch(&live, &other).is_err_and(|e| e.contains("test /spec/replicas")));
    }

    /// A copy makes as many bytes as the value it copies has: a megabyte string copied again and
    /// again is refused, where a count of values would let all 256 copies through.
    #[test]
    fn json_patch_bounds_the_bytes_its_copies_make() {
        let live = json!({ "big": "x".repeat(1 << 20) });
        let copies: Vec<Value> = (0..256)
            .map(|n| json!({ "op": "copy", "from": "/big", "path": format!("/c{n}") }))
            .collect();
        assert!(json_patch(&live, &Value::Array(copies)).is_err_and(|e| e.contains("copies")));
    }

    #[test]
    fn selectors_pick_by_labels_and_fields() {
        let object = json!({ "metadata": { "name": "web", "labels": { "app": "shop", "tier": "front" } }, "status": { "phase": "Running" } });
        let picks = |labels: &str, fields: &str| {
            let asked = [("labelSelector", labels), ("fieldSelector", fields)];
            selected(
                &object,
                &asked.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            )
        };
        for yes in [
            "",
            "app=shop",
            "app==shop,tier!=back",
            "app in (shop, bank),tier",
            "!gone,app notin (bank)",
        ] {
            assert!(picks(yes, ""), "{yes}");
        }
        for no in ["app=bank", "gone", "!app", "app notin (shop)", "tier in (back)"] {
            assert!(!picks(no, ""), "{no}");
        }
        assert!(picks("", "metadata.name=web,status.phase!=Pending"));
        assert!(!picks("", "metadata.name=other"));
    }

    /// A pod's initContainers are told of apart from its containers: while one runs the
    /// pod is pending and not initialized, and done it is not counted among what runs.
    #[test]
    fn a_pods_init_containers_are_told_of_apart() {
        let spec = json!({ "initContainers": [{ "name": "first", "image": "i" }], "containers": [{ "name": "web", "image": "w" }] });
        let owner = json!({
            "kind": "StatefulSet", "metadata": { "name": "web", "namespace": "default" },
            "spec": { "template": { "spec": spec } },
        });
        let said = |first: Value, web: Value| -> Value {
            let meta = json!({ "name": "web", "namespace": "default" });
            let held: Resource = serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": "Workload", "metadata": meta, "spec": {},
                "status": { "containers": [first, web] },
            }))
            .unwrap();
            pods(&owner, &held).remove(0)["status"].take()
        };
        let unit = |name: &str, state: &str, ready: bool| json!({ "name": name, "replica": 0, "state": state, "ready": ready, "restarts": 0, "exitCode": 0 });
        let before = said(unit("first", "running", false), unit("web", "pending", false));
        assert_eq!(
            (&before["phase"], &before["conditions"][0]["status"]),
            (&json!("Pending"), &json!("False")),
            "{before}"
        );
        let after = said(unit("first", "exited", true), unit("web", "running", true));
        assert_eq!(
            (&after["phase"], &after["conditions"][0]["status"]),
            (&json!("Running"), &json!("True")),
            "{after}"
        );
        assert_eq!(after["containerStatuses"].as_array().map(Vec::len), Some(1), "{after}");
        assert_eq!(after["initContainerStatuses"][0]["image"], "i", "{after}");
        assert_eq!(
            after["initContainerStatuses"][0]["state"]["terminated"]["reason"], "Completed",
            "{after}"
        );
    }

    /// `kubectl logs job/NAME` after `kubectl wait --for=condition=complete`: the Job runs
    /// nothing any more, and its pod is still there to be asked what it wrote.
    #[test]
    fn a_job_that_is_over_still_has_the_pods_of_its_runs() {
        let job = json!({
            "kind": "Job", "metadata": { "name": "ask", "namespace": "default" },
            "spec": { "template": { "spec": { "containers": [{ "name": "ask", "image": "a" }] } } },
        });
        let held = |status: Value| -> Resource {
            let meta = json!({ "name": "ask", "namespace": "default" });
            serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": "Job", "metadata": meta, "spec": {}, "status": status,
            }))
            .unwrap()
        };
        let nodes = json!({ "0": "n2" });
        let said = |status: Value| -> Vec<(Value, Value, Value)> {
            let pods = pods(&job, &held(status));
            let of = |pod: &Value| {
                assert_eq!(pod["metadata"]["labels"]["job-name"], "ask", "{pod}");
                let code = &pod["status"]["containerStatuses"][0]["state"]["terminated"]["exitCode"];
                (
                    pod["metadata"]["name"].clone(),
                    pod["status"]["phase"].clone(),
                    code.clone(),
                )
            };
            pods.iter().map(of).collect()
        };
        let running = json!({ "state": "running", "succeeded": 0, "containers": [], "nodes": nodes });
        assert!(said(running).is_empty());
        let done = json!({ "state": "succeeded", "succeeded": 1, "containers": [], "nodes": nodes });
        assert_eq!(said(done.clone()), [("ask-j0".into(), "Succeeded".into(), 0.into())]);
        assert_eq!(pods(&job, &held(done))[0]["spec"]["nodeName"], "n2");
        let failed = json!({ "state": "failed", "succeeded": 1, "failed": 1, "containers": [], "nodes": nodes });
        assert_eq!(
            said(failed),
            [
                ("ask-j0".into(), "Succeeded".into(), 0.into()),
                ("ask-j1".into(), "Failed".into(), Value::Null)
            ]
        );
    }

    /// A pod's name says what made it, so one made from a name two kinds hold is two
    /// names; it is made by `pod_name` and read back by `pod_owner`, and nothing else
    /// that ends otherwise is a pod.
    #[test]
    fn pod_name_is_made_and_read_back_for_each_kind() {
        let made = |kind, owner, replica| pod_name(kind, owner, replica);
        assert_eq!(made("Workload", "x", 0), "x-0");
        assert_eq!(made("Job", "x", 0), "x-j0");
        assert_eq!(made("NodeWorkload", "x", 12), "x-n12");
        for owner in ["x", "web-2", "x-j0", "x-n0", "a-b-c", "j", "0", "x-"] {
            for (kind, replica) in [("Workload", 0), ("Job", 3), ("NodeWorkload", 41)] {
                let name = made(kind, owner, replica);
                assert_eq!(pod_owner(&name), Some((kind, owner, replica as u32)), "{name}");
            }
        }
        // An owner named for another's pod is still its own: x-j0's pod is x-j0-0.
        assert_eq!(pod_owner("x-j0-0"), Some(("Workload", "x-j0", 0)));
        assert_eq!(pod_owner("x-j0-j0"), Some(("Job", "x-j0", 0)));
        let all: Vec<_> = ["Workload", "Job", "NodeWorkload"]
            .map(|kind| made(kind, "x", 0))
            .into();
        assert_eq!(all.len(), all.iter().collect::<BTreeSet<_>>().len(), "{all:?}");
        // No other ending is a pod: no number, a sign, a leading zero, a letter of no kind,
        // two marks, a number too big, no owner.
        for no in [
            "x",
            "x-",
            "x-j",
            "x-n",
            "x-+1",
            "x-00",
            "x-01",
            "x-j01",
            "x-jj0",
            "x-jn0",
            "x-J0",
            "x-a0",
            "x-0a",
            "x-j0a",
            "x-4294967296",
            "x-j4294967296",
            "-0",
            "-j0",
            "",
            "-",
            "x_0",
            "x-1.0",
            "x- 1",
        ] {
            assert_eq!(pod_owner(no), None, "{no:?}");
        }
    }

    /// A Deployment and a Job of one name are two kinds and may share it: what the
    /// Kubernetes API says of their pods and logs is of two pods, one each.
    /// (`kubectl` is the real client of this, in tests/kube.rs; this is the same routes.)
    #[tokio::test]
    async fn a_deployment_and_a_job_of_one_name_are_two_pods_for_get_and_log() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-podnames-{}", std::process::id()));
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
        let ask = |method: &str, group: &str, rest: &str, body: Value| {
            let shared = shared.clone();
            let (group, rest, body) = (group.to_string(), rest.to_string(), body.to_string());
            let mut request = axum::http::Request::builder().method(method).body(()).unwrap();
            request.extensions_mut().insert(Caller::Admin);
            async move {
                let (parts, ()) = request.into_parts();
                let answer = serve(shared, parts, &group, &rest, Asked::new(), body.as_bytes()).await;
                match answer {
                    Ok(answer) => {
                        let (code, body) = (answer.status(), answer.into_body());
                        let text = axum::body::to_bytes(body, 1 << 20).await.unwrap();
                        (code, String::from_utf8_lossy(&text).into_owned())
                    }
                    Err(no) => (no.code, no.why),
                }
            }
        };
        let template = json!({ "metadata": { "labels": { "app": "x" } }, "spec": { "containers": [{ "name": "main", "image": "i" }] } });
        let deployment = json!({
            "apiVersion": "apps/v1", "kind": "Deployment", "metadata": { "name": "x" },
            "spec": { "replicas": 1, "selector": { "matchLabels": { "app": "x" } }, "template": template },
        });
        let job = json!({
            "apiVersion": "batch/v1", "kind": "Job", "metadata": { "name": "x" },
            "spec": { "template": { "spec": { "restartPolicy": "Never", "containers": [{ "name": "main", "image": "i" }] } } },
        });
        let made = ask("POST", "apps", "namespaces/default/deployments", deployment).await;
        assert_eq!(made.0, StatusCode::CREATED, "{}", made.1);
        let made = ask("POST", "batch", "namespaces/default/jobs", job).await;
        assert_eq!(made.0, StatusCode::CREATED, "{}", made.1);
        let units = json!({ "containers": [{ "name": "main", "replica": 0, "state": "running", "ready": true, "restarts": 0 }] });
        {
            let mut state = shared.store.lock().unwrap();
            state
                .store
                .set_status("Workload/default/x", Some(units.clone()))
                .unwrap();
            let status = json!({ "state": "running", "containers": units["containers"] });
            state.store.set_status("Job/default/x", Some(status)).unwrap();
        }
        let (code, listed) = ask("GET", "", "namespaces/default/pods", Value::Null).await;
        assert_eq!(code, StatusCode::OK, "{listed}");
        let listed: Value = serde_json::from_str(&listed).unwrap();
        let mut names: Vec<_> = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pod| pod["metadata"]["name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        assert_eq!(names, ["x-0", "x-j0"], "{listed}");
        // Each is got by its name, and is its owner's.
        for (name, owner) in [("x-0", "Deployment"), ("x-j0", "Job")] {
            let (code, one) = ask("GET", "", &format!("namespaces/default/pods/{name}"), Value::Null).await;
            assert_eq!(code, StatusCode::OK, "{name}: {one}");
            let one: Value = serde_json::from_str(&one).unwrap();
            let owned = &one["metadata"]["ownerReferences"][0]["kind"];
            assert!(
                owned == owner || (owner == "Deployment" && owned == "ReplicaSet"),
                "{name}: {one}"
            );
        }
        // A name that is neither is no pod.
        for no in ["x-1", "x-j1", "x-n0", "x-00"] {
            let (code, said) = ask("GET", "", &format!("namespaces/default/pods/{no}"), Value::Null).await;
            assert_eq!(code, StatusCode::NOT_FOUND, "{no}: {said}");
            let (code, said) = ask("GET", "", &format!("namespaces/default/pods/{no}/log"), Value::Null).await;
            assert_eq!(code, StatusCode::NOT_FOUND, "{no}: {said}");
        }
        // What each wrote is its own: the log of the Job's pod is the Job's.
        std::fs::create_dir_all(&shared.logs).unwrap();
        std::fs::write(shared.logs.join("w_default_x_0_main.out"), "the deployment's\n").unwrap();
        std::fs::write(shared.logs.join("j_default_x_0_main.out"), "the job's\n").unwrap();
        for (pod, wrote) in [("x-0", "the deployment's\n"), ("x-j0", "the job's\n")] {
            let (code, said) = ask("GET", "", &format!("namespaces/default/pods/{pod}/log"), Value::Null).await;
            assert_eq!((code, said.as_str()), (StatusCode::OK, wrote), "{pod}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A Pod named `name` that restarts as `policy` says (none: says nothing).
    fn a_pod(name: &str, policy: Option<&str>) -> Value {
        let mut spec =
            json!({ "containers": [{ "name": "main", "image": "i", "env": [{ "name": "A", "value": "1" }] }] });
        if let Some(policy) = policy {
            spec["restartPolicy"] = policy.into();
        }
        let meta = json!({ "name": name, "labels": { "app": name }, "annotations": { "note": "kept" } });
        json!({ "apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": spec })
    }

    async fn send_pod(shared: &Arc<crate::Shared>, caller: Caller, pod: Value) -> (StatusCode, Value) {
        let (code, said) = answer_as(shared.clone(), caller, "POST", "", "namespaces/default/pods", pod).await;
        (code, serde_json::from_str(&said).unwrap_or(Value::String(said)))
    }

    async fn pods_of(shared: &Arc<crate::Shared>, rest: &str) -> (StatusCode, Value) {
        let (code, said) = answer_as(shared.clone(), Caller::Admin, "GET", "", rest, Value::Null).await;
        (code, serde_json::from_str(&said).unwrap_or(Value::String(said)))
    }

    /// A Pod sent is a Job when it is not run again (Never, OnFailure) and a one-replica
    /// Workload when it is (Always, and none said), marked, and got by its own name with the
    /// labels and fields it was sent with.
    #[tokio::test]
    async fn bare_pod_is_a_job_or_a_workload_marked_and_got_by_name() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-barepod-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let cases = [
            ("never", Some("Never"), "Job"),
            ("onfail", Some("OnFailure"), "Job"),
            ("always", Some("Always"), "Workload"),
            ("unset", None, "Workload"),
        ];
        for (name, policy, held) in cases {
            let (code, said) = send_pod(&shared, Caller::Admin, a_pod(name, policy)).await;
            assert_eq!(code, StatusCode::CREATED, "{name}: {said}");
            let key = format!("{held}/default/{name}");
            let marked = {
                let state = shared.store.lock().unwrap();
                let live = state.store.get(&key).unwrap_or_else(|| panic!("{key} is not held"));
                live.metadata.annotations.get("kith.dev/pod").cloned()
            };
            assert_eq!(marked.as_deref(), Some("true"), "{key}");
            let (code, pod) = pods_of(&shared, &format!("namespaces/default/pods/{name}")).await;
            assert_eq!(code, StatusCode::OK, "{name}: {pod}");
            assert_eq!(pod["kind"], "Pod");
            assert_eq!(pod["metadata"]["name"], name, "{pod}");
            assert_eq!(pod["metadata"]["labels"]["app"], name, "{pod}");
            assert_eq!(pod["spec"]["containers"][0]["env"][0]["value"], "1", "{pod}");
            assert_eq!(pod["status"]["phase"], "Pending", "a pod not run yet is Pending: {pod}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A name a Job, a Workload, another Pod or another owner's pod has is taken (409
    /// AlreadyExists) whichever of the two a Pod would be; what kith does not carry is refused
    /// by name; and a Pod is made by who may apply what it comes to, asked before the store is.
    #[tokio::test]
    async fn bare_pod_access_is_the_apply_right_on_the_kind_it_becomes() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-barepod-access-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let roles = "apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: jobber}\nspec: {}\n---\napiVersion: kith.dev/v1\nkind: Role\nmetadata: {name: jobs}\nspec: {rules: [{kinds: [Job], verbs: [apply]}]}\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {name: jobber-jobs}\nspec: {role: jobs, subjects: [jobber]}\n";
        {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(roles).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        // Apply on Job alone makes a Never Pod; an Always one is a Workload, which it may not, and
        // that is told before anything of the store is (the name `taken` is a Workload's).
        let job = Caller::Identity("jobber".into());
        let made = |kind: &str, name: &str| json!({ "apiVersion": "apps/v1", "kind": kind, "metadata": { "name": name }, "spec": { "replicas": 1, "selector": { "matchLabels": { "a": name } }, "template": { "metadata": { "labels": { "a": name } }, "spec": { "containers": [{ "name": "main", "image": "i" }] } } } });
        let (code, said) = answer_as(
            shared.clone(),
            Caller::Admin,
            "POST",
            "apps",
            "namespaces/default/deployments",
            made("Deployment", "taken"),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{said}");
        let (code, said) = send_pod(&shared, job.clone(), a_pod("jobbed", Some("Never"))).await;
        assert_eq!(code, StatusCode::CREATED, "{said}");
        for name in ["fresh", "taken"] {
            let (code, said) = send_pod(&shared, job.clone(), a_pod(name, Some("Always"))).await;
            assert_eq!(code, StatusCode::FORBIDDEN, "{name}: {said}");
        }
        assert!(
            shared
                .store
                .lock()
                .unwrap()
                .store
                .get("Workload/default/fresh")
                .is_none()
        );
        // Taken: by a Workload (as a Job or as one), by a Job, by a Pod, by a Deployment's pod, a Job's, a DaemonSet's.
        let mut daemon = made("DaemonSet", "ds");
        daemon["spec"].as_object_mut().unwrap().remove("replicas");
        let (code, said) = answer_as(
            shared.clone(),
            Caller::Admin,
            "POST",
            "apps",
            "namespaces/default/daemonsets",
            daemon,
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{said}");
        let job_of = json!({ "apiVersion": "batch/v1", "kind": "Job", "metadata": { "name": "j" }, "spec": { "template": { "spec": { "restartPolicy": "Never", "containers": [{ "name": "main", "image": "i" }] } } } });
        let (code, said) = answer_as(
            shared.clone(),
            Caller::Admin,
            "POST",
            "batch",
            "namespaces/default/jobs",
            job_of,
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{said}");
        let names = ["taken", "j", "jobbed", "taken-0", "j-j0", "ds-n0"];
        for name in names {
            for policy in ["Never", "Always"] {
                let (code, said) = send_pod(&shared, Caller::Admin, a_pod(name, Some(policy))).await;
                assert_eq!(code, StatusCode::CONFLICT, "{name} {policy}: {said}");
                assert!(said.to_string().contains("already exists"), "{name} {policy}: {said}");
            }
        }
        // The same name twice: the second is refused, and the first is as it was.
        let (code, _) = send_pod(&shared, Caller::Admin, a_pod("twice", Some("Never"))).await;
        assert_eq!(code, StatusCode::CREATED);
        let (code, said) = send_pod(&shared, Caller::Admin, a_pod("twice", Some("Always"))).await;
        assert_eq!(code, StatusCode::CONFLICT, "{said}");
        assert!(
            shared
                .store
                .lock()
                .unwrap()
                .store
                .get("Workload/default/twice")
                .is_none()
        );
        // What kith does not carry is refused naming the field, and nothing is made.
        for field in ["nodeName", "hostNetwork", "activeDeadlineSeconds", "hostPID"] {
            let mut pod = a_pod("odd", Some("Never"));
            pod["spec"][field] = if field == "nodeName" { json!("n1") } else { json!(true) };
            let (code, said) = send_pod(&shared, Caller::Admin, pod).await;
            assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY, "{field}: {said}");
            assert!(said.to_string().contains(field), "{field}: {said}");
        }
        assert!(shared.store.lock().unwrap().store.get("Job/default/odd").is_none());
        // A Pod that is there is not written over through the Pod's paths.
        let (code, said) = answer_as(
            shared.clone(),
            Caller::Admin,
            "PUT",
            "",
            "namespaces/default/pods/twice",
            a_pod("twice", Some("Never")),
        )
        .await;
        assert_ne!(code, StatusCode::OK, "{said}");
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Get and list give a bare Pod as it was sent, by its own name and not NAME-jN, owned by
    /// nothing, with what its Job or Workload says of its run in its status.
    #[tokio::test]
    async fn bare_pod_reads_back_as_sent_by_its_own_name() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-barepod-read-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        for (name, policy) in [("once", "Never"), ("always", "Always")] {
            let (code, said) = send_pod(&shared, Caller::Admin, a_pod(name, Some(policy))).await;
            assert_eq!(code, StatusCode::CREATED, "{name}: {said}");
        }
        let units = json!({ "containers": [{ "name": "main", "replica": 0, "state": "running", "ready": true, "restarts": 0 }] });
        {
            let mut state = shared.store.lock().unwrap();
            let status = json!({ "state": "running", "containers": units["containers"] });
            state.store.set_status("Job/default/once", Some(status)).unwrap();
            state.store.set_status("Workload/default/always", Some(units)).unwrap();
        }
        let (code, listed) = pods_of(&shared, "namespaces/default/pods").await;
        assert_eq!(code, StatusCode::OK, "{listed}");
        let mut names: Vec<_> = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pod| pod["metadata"]["name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        assert_eq!(names, ["always", "once"], "{listed}");
        for name in ["once", "always"] {
            let (code, pod) = pods_of(&shared, &format!("namespaces/default/pods/{name}")).await;
            assert_eq!(code, StatusCode::OK, "{name}: {pod}");
            assert_eq!(pod["metadata"]["labels"], json!({ "app": name }), "{pod}");
            assert_eq!(pod["metadata"]["annotations"]["note"], "kept", "{pod}");
            assert!(pod["metadata"]["ownerReferences"].is_null(), "owned by nothing: {pod}");
            assert_eq!(pod["spec"]["containers"][0]["env"][0]["name"], "A", "{pod}");
            assert_eq!(pod["status"]["phase"], "Running", "{pod}");
            // (The name it would have as a Job's or a Workload's pod is no pod.)
            let (code, said) = pods_of(&shared, &format!("namespaces/default/pods/{name}-j0")).await;
            assert_eq!(code, StatusCode::NOT_FOUND, "{said}");
        }
        // A Pod is not a Job to the Job's paths.
        let (code, jobs) = answer_as(
            shared.clone(),
            Caller::Admin,
            "GET",
            "batch",
            "namespaces/default/jobs",
            Value::Null,
        )
        .await;
        let jobs: Value = serde_json::from_str(&jobs).unwrap();
        assert_eq!(code, StatusCode::OK, "{jobs}");
        assert!(jobs["items"].as_array().unwrap().is_empty(), "{jobs}");
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What `serve` answers a request by `caller`: the status and the body as text.
    async fn answer_as(
        shared: Arc<crate::Shared>,
        caller: Caller,
        method: &str,
        group: &str,
        rest: &str,
        body: Value,
    ) -> (StatusCode, String) {
        let mut request = axum::http::Request::builder().method(method).body(()).unwrap();
        request.extensions_mut().insert(caller);
        let (parts, ()) = request.into_parts();
        match serve(shared, parts, group, rest, Asked::new(), body.to_string().as_bytes()).await {
            Ok(answer) => {
                let (code, body) = (answer.status(), answer.into_body());
                let text = axum::body::to_bytes(body, 1 << 20).await.unwrap();
                (code, String::from_utf8_lossy(&text).into_owned())
            }
            Err(no) => (no.code, no.why),
        }
    }

    /// A Deployment `x` of two replicas, both running here, and the pods of it by name.
    async fn two_replicas_of_x(shared: &Arc<crate::Shared>) {
        let deployment = json!({
            "apiVersion": "apps/v1", "kind": "Deployment", "metadata": { "name": "x" },
            "spec": { "replicas": 2, "selector": { "matchLabels": { "app": "x" } }, "template": {
                "metadata": { "labels": { "app": "x" } }, "spec": { "containers": [{ "name": "main", "image": "i" }] },
            } },
        });
        let (code, said) = answer_as(
            shared.clone(),
            Caller::Admin,
            "POST",
            "apps",
            "namespaces/default/deployments",
            deployment,
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{said}");
        let units = json!({ "containers": [
            { "name": "main", "replica": 0, "state": "running", "ready": true, "restarts": 0 },
            { "name": "main", "replica": 1, "state": "running", "ready": true, "restarts": 0 },
        ] });
        shared
            .store
            .lock()
            .unwrap()
            .store
            .set_status("Workload/default/x", Some(units))
            .unwrap();
    }

    /// `kubectl delete pod x-0` restarts that one replica: its slot is marked for the
    /// controller to stop and start again, and the other replica and the pods are as they were.
    /// (The controller's side is `delete_pod_stops_the_replica_and_starts_it_again_ignoring_policy`.)
    #[tokio::test]
    async fn delete_pod_restarts_only_that_replica() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-delete-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        two_replicas_of_x(&shared).await;
        let (code, said) = answer_as(
            shared.clone(),
            Caller::Admin,
            "DELETE",
            "",
            "namespaces/default/pods/x-0",
            Value::Null,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{said}");
        let marked: Vec<(String, u32)> = shared.restarts.lock().unwrap().iter().cloned().collect();
        assert_eq!(marked, [("Workload/default/x".to_string(), 0)]);
        let (code, listed) = answer_as(
            shared.clone(),
            Caller::Admin,
            "GET",
            "",
            "namespaces/default/pods",
            Value::Null,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{listed}");
        let listed: Value = serde_json::from_str(&listed).unwrap();
        let mut names: Vec<_> = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pod| pod["metadata"]["name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        assert_eq!(names, ["x-0", "x-1"], "{listed}");
        // A name that is no pod is not found (Helm deletes what it made before, and wants this), and marks nothing.
        for no in ["bare", "x-j0"] {
            let (code, said) = answer_as(
                shared.clone(),
                Caller::Admin,
                "DELETE",
                "",
                &format!("namespaces/default/pods/{no}"),
                Value::Null,
            )
            .await;
            assert_eq!(code, StatusCode::NOT_FOUND, "{no}: {said}");
            assert!(said.contains(no), "{no}: {said}");
        }
        // A Workload that is not there has no such replica.
        let (code, said) = answer_as(
            shared.clone(),
            Caller::Admin,
            "DELETE",
            "",
            "namespaces/default/pods/x-1-0",
            Value::Null,
        )
        .await;
        assert_eq!(code, StatusCode::NOT_FOUND, "{said}");
        // A replica that is not there is no pod.
        let (code, said) = answer_as(
            shared.clone(),
            Caller::Admin,
            "DELETE",
            "",
            "namespaces/default/pods/x-5",
            Value::Null,
        )
        .await;
        assert_eq!(code, StatusCode::NOT_FOUND, "{said}");
        assert_eq!(shared.restarts.lock().unwrap().len(), 1, "only x-0 is marked");
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Deleting a pod of a Workload needs the apply right on that Workload: get alone is
    /// refused 403 and nothing is marked; apply takes it. Reading the pod stays get's.
    #[tokio::test]
    async fn delete_pod_access_needs_apply_on_the_workload() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-delete-access-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let roles = "apiVersion: kith.dev/v1\nkind: Role\nmetadata: {name: readers}\nspec: {rules: [{kinds: [Workload], verbs: [get]}]}\n---\napiVersion: kith.dev/v1\nkind: Role\nmetadata: {name: writers}\nspec: {rules: [{kinds: [Workload], verbs: [apply]}]}\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {name: ann-reads}\nspec: {role: readers, subjects: [ann]}\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {name: bob-writes}\nspec: {role: writers, subjects: [bob]}\n---\napiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: ann}\nspec: {}\n---\napiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: bob}\nspec: {}\n";
        {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(roles).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        two_replicas_of_x(&shared).await;
        let ann = Caller::Identity("ann".into());
        let (code, said) = answer_as(
            shared.clone(),
            ann.clone(),
            "DELETE",
            "",
            "namespaces/default/pods/x-0",
            Value::Null,
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN, "{said}");
        assert!(
            shared.restarts.lock().unwrap().is_empty(),
            "a refused delete marks nothing"
        );
        let (code, said) = answer_as(
            shared.clone(),
            ann,
            "GET",
            "",
            "namespaces/default/pods/x-0",
            Value::Null,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{said}");
        let bob = Caller::Identity("bob".into());
        let (code, said) = answer_as(
            shared.clone(),
            bob,
            "DELETE",
            "",
            "namespaces/default/pods/x-0",
            Value::Null,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{said}");
        assert_eq!(shared.restarts.lock().unwrap().len(), 1);
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn delete_pod_named(shared: &Arc<crate::Shared>, caller: Caller, name: &str) -> (StatusCode, String) {
        answer_as(
            shared.clone(),
            caller,
            "DELETE",
            "",
            &format!("namespaces/default/pods/{name}"),
            Value::Null,
        )
        .await
    }

    /// A marked bare Pod is deleted as the Job or the Workload it is held as, and is then no pod; one
    /// named like a replica (`web-0`, with no Workload `web`) is deleted too and not 404; the pod
    /// of an owner is still restarted, not deleted; and a delete is a delete (nothing is restarted).
    #[tokio::test]
    async fn bare_pod_delete_removes_the_marked_pod_and_still_restarts_an_owners_replica() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-barepod-delete-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        two_replicas_of_x(&shared).await;
        for (name, policy, held) in [
            ("once", Some("Never"), "Job"),
            ("always", None, "Workload"),
            ("web-0", None, "Workload"),
        ] {
            let (code, said) = send_pod(&shared, Caller::Admin, a_pod(name, policy)).await;
            assert_eq!(code, StatusCode::CREATED, "{name}: {said}");
            let (code, said) = delete_pod_named(&shared, Caller::Admin, name).await;
            assert_eq!(code, StatusCode::OK, "{name}: {said}");
            let said: Value = serde_json::from_str(&said).unwrap();
            assert_eq!(said["details"]["name"], name, "{said}");
            assert!(
                shared
                    .store
                    .lock()
                    .unwrap()
                    .store
                    .get(&format!("{held}/default/{name}"))
                    .is_none(),
                "{name}"
            );
            let (code, said) = pods_of(&shared, &format!("namespaces/default/pods/{name}")).await;
            assert_eq!(code, StatusCode::NOT_FOUND, "{name}: {said}");
            let (code, _) = delete_pod_named(&shared, Caller::Admin, name).await;
            assert_ne!(code, StatusCode::OK, "{name} is deleted once");
        }
        assert!(
            shared.restarts.lock().unwrap().is_empty(),
            "a delete of a bare pod restarts nothing"
        );
        // A run of a Job that is there is a pod that is not restarted by a delete: refused by name; one of a Job that is not is no pod.
        let (code, said) = send_pod(&shared, Caller::Admin, a_pod("job", Some("Never"))).await;
        assert_eq!(code, StatusCode::CREATED, "{said}");
        let (code, said) = delete_pod_named(&shared, Caller::Admin, "job-j0").await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY, "{said}");
        let (code, said) = delete_pod_named(&shared, Caller::Admin, "gone-j0").await;
        assert_eq!(code, StatusCode::NOT_FOUND, "{said}");
        // The owner's replica next to them is restarted, and its Workload stays.
        let (code, said) = delete_pod_named(&shared, Caller::Admin, "x-0").await;
        assert_eq!(code, StatusCode::OK, "{said}");
        let marked: Vec<(String, u32)> = shared.restarts.lock().unwrap().iter().cloned().collect();
        assert_eq!(marked, [("Workload/default/x".to_string(), 0)]);
        assert!(shared.store.lock().unwrap().store.get("Workload/default/x").is_some());
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Deleting a bare pod needs the delete right on what it is held as: get alone is 403 and the
    /// pod stays; apply alone is 404 (a delete is not an apply, and it is told nothing of the pod);
    /// delete takes it.
    #[tokio::test]
    async fn bare_pod_delete_needs_the_delete_right_on_its_holder() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-barepod-delete-access-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let mut roles = String::new();
        for (who, verb) in [("ann", "get"), ("bob", "apply"), ("cat", "delete")] {
            roles += &format!(
                "apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {{name: {who}}}\nspec: {{}}\n---\napiVersion: kith.dev/v1\nkind: Role\nmetadata: {{name: {who}-role}}\nspec: {{rules: [{{kinds: [Job, Workload], verbs: [{verb}]}}]}}\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {{name: {who}-binding}}\nspec: {{role: {who}-role, subjects: [{who}]}}\n---\n"
            );
        }
        {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(&roles).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        for (name, policy, held) in [("once", Some("Never"), "Job"), ("always", None, "Workload")] {
            let (code, said) = send_pod(&shared, Caller::Admin, a_pod(name, policy)).await;
            assert_eq!(code, StatusCode::CREATED, "{name}: {said}");
            for who in ["ann", "bob"] {
                let (code, said) = delete_pod_named(&shared, Caller::Identity(who.into()), name).await;
                // (Get alone is refused outright; apply alone gets past that, and is told 404 of a pod it may not delete.)
                let wanted = if who == "ann" {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::NOT_FOUND
                };
                assert_eq!(code, wanted, "{who} {name}: {said}");
                assert!(
                    shared
                        .store
                        .lock()
                        .unwrap()
                        .store
                        .get(&format!("{held}/default/{name}"))
                        .is_some()
                );
            }
            let (code, said) = delete_pod_named(&shared, Caller::Identity("cat".into()), name).await;
            assert_eq!(code, StatusCode::OK, "{name}: {said}");
            assert!(
                shared
                    .store
                    .lock()
                    .unwrap()
                    .store
                    .get(&format!("{held}/default/{name}"))
                    .is_none()
            );
        }
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A caller with no right on Jobs or Workloads is told 403, the same, of a name that is a pod
    /// (a bare one, a replica) and of one that is nothing: a delete is no way to find what exists.
    #[tokio::test]
    async fn bare_pod_delete_of_a_caller_with_no_rights_is_403_for_every_name() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-barepod-delete-oracle-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let who = "apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: nobody}\nspec: {}\n";
        {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(who).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        two_replicas_of_x(&shared).await;
        let (code, said) = send_pod(&shared, Caller::Admin, a_pod("once", Some("Never"))).await;
        assert_eq!(code, StatusCode::CREATED, "{said}");
        let mut answers = Vec::new();
        for name in ["once", "x-0", "x-j0", "ghost"] {
            let (code, said) = delete_pod_named(&shared, Caller::Identity("nobody".into()), name).await;
            assert_eq!(code, StatusCode::FORBIDDEN, "{name}: {said}");
            answers.push(said);
        }
        assert!(answers.windows(2).all(|two| two[0] == two[1]), "{answers:?}");
        assert!(shared.store.lock().unwrap().store.get("Job/default/once").is_some());
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A bare Pod named as a replica of an owner (`x-0` of a Workload `x`, `x-j0` of a Job `x`) and a
    /// Workload, Deployment, DaemonSet or Job `x` made after it would be two pods of one name: the
    /// later create is refused (409), as the Pod create is in the other order. A Job `x` and a Pod
    /// `x-0` do not meet (the Job's pod is `x-j0`), nor does a Pod `x-1` of a Deployment `y`.
    #[tokio::test]
    async fn bare_pod_name_collision() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-barepod-collide-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let template = |name: &str| json!({ "metadata": { "labels": { "a": name } }, "spec": { "restartPolicy": "Never", "containers": [{ "name": "main", "image": "i" }] } });
        let made = |kind: &str, name: &str| {
            let mut object = json!({ "apiVersion": "apps/v1", "kind": kind, "metadata": { "name": name }, "spec": { "selector": { "matchLabels": { "a": name } }, "template": template(name) } });
            if kind == "Deployment" {
                object["spec"]["replicas"] = 1.into();
            }
            if kind == "Job" {
                object["apiVersion"] = "batch/v1".into();
                object["spec"].as_object_mut().unwrap().remove("selector");
            }
            object
        };
        let create = |kind: &'static str, name: &str| {
            let (shared, body) = (shared.clone(), made(kind, name));
            let (group, plural) = match kind {
                "Job" => ("batch", "jobs"),
                "Deployment" => ("apps", "deployments"),
                _ => ("apps", "daemonsets"),
            };
            async move {
                let rest = format!("namespaces/default/{plural}");
                answer_as(shared, Caller::Admin, "POST", group, &rest, body).await
            }
        };
        // A Pod `x-0` (a Workload's replica name, whichever it is held as) and `x-j0` (a Job's).
        for (pod, policy, refused, fine) in [
            ("a-0", None, ["Deployment"], ["Job", "DaemonSet"]),
            ("b-0", Some("Never"), ["Deployment"], ["Job", "DaemonSet"]),
            ("c-j0", Some("Never"), ["Job"], ["Deployment", "DaemonSet"]),
            ("d-j0", None, ["Job"], ["Deployment", "DaemonSet"]),
            ("e-n0", None, ["DaemonSet"], ["Deployment", "Job"]),
        ] {
            let (code, said) = send_pod(&shared, Caller::Admin, a_pod(pod, policy)).await;
            assert_eq!(code, StatusCode::CREATED, "{pod}: {said}");
            let owner = pod.rsplit_once('-').unwrap().0;
            for kind in refused {
                let (code, said) = create(kind, owner).await;
                assert_eq!(code, StatusCode::CONFLICT, "{kind} {owner} after Pod {pod}: {said}");
                let held = match kind {
                    "Job" => "Job",
                    "DaemonSet" => "NodeWorkload",
                    _ => "Workload",
                };
                let key = format!("{held}/default/{owner}");
                assert!(shared.store.lock().unwrap().store.get(&key).is_none(), "{key}");
            }
            for kind in fine {
                let (code, said) = create(kind, owner).await;
                assert_eq!(code, StatusCode::CREATED, "{kind} {owner} after Pod {pod}: {said}");
            }
            // The pod still reads back, once, under the name it was sent as.
            let (code, one) = pods_of(&shared, &format!("namespaces/default/pods/{pod}")).await;
            assert_eq!(code, StatusCode::OK, "{pod}: {one}");
            assert_eq!(one["metadata"]["labels"]["app"], pod, "{one}");
        }
        // The other order: the owner first, then the Pod (a replica number is not asked after).
        for (kind, owner, pod) in [
            ("Deployment", "p", "p-0"),
            ("Job", "q", "q-j3"),
            ("DaemonSet", "r", "r-n4"),
        ] {
            let (code, said) = create(kind, owner).await;
            assert_eq!(code, StatusCode::CREATED, "{kind} {owner}: {said}");
            let (code, said) = send_pod(&shared, Caller::Admin, a_pod(pod, Some("Never"))).await;
            assert_eq!(code, StatusCode::CONFLICT, "Pod {pod} after {kind} {owner}: {said}");
        }
        // Another namespace's Pod is not this one's.
        let other = a_pod("h-0", None);
        let (code, said) = answer_as(shared.clone(), Caller::Admin, "POST", "", "namespaces/else/pods", other).await;
        assert_eq!(code, StatusCode::CREATED, "{said}");
        let (code, said) = create("Deployment", "h").await;
        assert_eq!(code, StatusCode::CREATED, "{said}");
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `kubectl logs` and `exec` on a bare Pod's name find it (a Job-held one and a Workload-held one);
    /// a caller with no right on Jobs or Workloads is told the same 403 for a bare name, a replica's
    /// and one that is nothing, so neither verb tells what exists.
    #[tokio::test]
    async fn bare_pod_logs_and_exec() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-barepod-verbs-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let who = "apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: nobody}\nspec: {}\n";
        {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(who).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        two_replicas_of_x(&shared).await;
        for (name, policy) in [("once", Some("Never")), ("always", None)] {
            let (code, said) = send_pod(&shared, Caller::Admin, a_pod(name, policy)).await;
            assert_eq!(code, StatusCode::CREATED, "{name}: {said}");
        }
        std::fs::create_dir_all(&shared.logs).unwrap();
        std::fs::write(shared.logs.join("j_default_once_0_main.out"), "the job pod's\n").unwrap();
        std::fs::write(shared.logs.join("w_default_always_0_main.out"), "the workload pod's\n").unwrap();
        for (name, wrote) in [("once", "the job pod's\n"), ("always", "the workload pod's\n")] {
            let (code, said) = answer_as(
                shared.clone(),
                Caller::Admin,
                "GET",
                "",
                &format!("namespaces/default/pods/{name}/log"),
                Value::Null,
            )
            .await;
            assert_eq!((code, said.as_str()), (StatusCode::OK, wrote), "{name}");
            // (No upgrade is asked: a pod that is found says so, and one that is not is not found.)
            let (code, said) = answer_as(
                shared.clone(),
                Caller::Admin,
                "GET",
                "",
                &format!("namespaces/default/pods/{name}/exec"),
                Value::Null,
            )
            .await;
            assert_eq!(code, StatusCode::BAD_REQUEST, "{name}: {said}");
        }
        for verb in ["log", "exec"] {
            let (code, said) = answer_as(
                shared.clone(),
                Caller::Admin,
                "GET",
                "",
                &format!("namespaces/default/pods/ghost/{verb}"),
                Value::Null,
            )
            .await;
            assert_eq!(code, StatusCode::NOT_FOUND, "{verb}: {said}");
            let mut answers = Vec::new();
            for name in ["once", "always", "x-0", "x-j0", "x-n0", "ghost"] {
                let rest = format!("namespaces/default/pods/{name}/{verb}");
                let (code, said) = answer_as(
                    shared.clone(),
                    Caller::Identity("nobody".into()),
                    "GET",
                    "",
                    &rest,
                    Value::Null,
                )
                .await;
                assert_eq!(code, StatusCode::FORBIDDEN, "{verb} {name}: {said}");
                answers.push(said);
            }
            assert!(answers.windows(2).all(|two| two[0] == two[1]), "{verb}: {answers:?}");
        }
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A resource marked `kith.dev/pod` that has the name of a Workload's replica takes nobody's calls: the
    /// name is no pod to any verb while both stand (resolve_pod), and a native apply of the mark on such a
    /// name is refused (hijacks), in the body's own Workload's case too; a bare Pod with a name of its own
    /// is found, and `once-0` is one while no Workload `once` is there.
    #[tokio::test]
    async fn a_marked_native_apply_cannot_take_a_pods_name() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-hijack-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let held = |name: &str| {
            let sent = json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": "default"}});
            let text = format!(
                "apiVersion: kith.dev/v1\nkind: Workload\nmetadata:\n  name: {name}\n  namespace: default\n  annotations:\n    kith.dev/pod: 'true'\n    {SENT}: '{sent}'\nspec: {{replicas: 1, template: {{exec: [{{name: m, command: [sleep, '1']}}]}}}}\n"
            );
            Resource::from_source(&text).unwrap().remove(0).unwrap()
        };
        let web: Resource = Resource::from_source(
            "apiVersion: kith.dev/v1\nkind: Workload\nmetadata: {name: web, namespace: default}\nspec: {replicas: 1, template: {exec: [{name: m, command: [sleep, '1']}]}}\n",
        )
        .unwrap()
        .remove(0)
        .unwrap();
        // A bare Pod named `once-0` with no Workload `once` is the bare Pod's.
        let refused = crate::api::applied(&shared, &Caller::Admin, vec![held("once-0"), held("solo")]).await;
        assert!(refused.is_ok(), "{:?}", refused.err().map(|e| e.into_response().status()));
        // With Workload `web` there, the same mark on `web-0` is refused, native apply or not in the body.
        for body in [vec![web.clone(), held("web-0")], vec![held("web-0"), web.clone()]] {
            let refused = crate::api::applied(&shared, &Caller::Admin, body).await;
            assert!(refused.is_err(), "web-0 marked was let in");
        }
        let state = shared.store.lock().unwrap();
        assert!(state.store.get("Workload/default/web-0").is_none());
        drop(state);
        // Both held anyway (the store was written another way): neither takes the calls.
        let mut state = shared.store.lock().unwrap();
        state.store.apply(web).unwrap();
        state.store.apply(held("web-0")).unwrap();
        assert_eq!(resolve_pod(&state.store, "default", "web-0"), None);
        assert_eq!(resolve_pod(&state.store, "default", "once-0").map(|(of, _, n)| (of, n)), Some(("Workload", 0)));
        assert_eq!(resolve_pod(&state.store, "default", "solo").map(|(of, _, n)| (of, n)), Some(("Workload", 0)));
        assert_eq!(resolve_pod(&state.store, "default", "web-1"), Some(("Workload", "web", 1)));
        drop(state);
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An exec session past the upgrade (the WebSocket's own stage, where the pod is placed) finds a bare
    /// Pod by its name as it finds any pod: what it says of one is not "not found"; of a ghost it is.
    #[tokio::test]
    async fn bare_pod_exec_session_places_the_pod() {
        use tokio::io::AsyncReadExt;
        let dir = std::env::temp_dir().join(format!("kithd-kube-barepod-session-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        for (name, policy) in [("once", Some("Never")), ("always", None)] {
            let (code, said) = send_pod(&shared, Caller::Admin, a_pod(name, policy)).await;
            assert_eq!(code, StatusCode::CREATED, "{name}: {said}");
        }
        for (name, found) in [("once", true), ("always", true), ("ghost", false)] {
            let (server, mut client) = tokio::io::duplex(1 << 16);
            let session = tokio::spawn(crate::pod_exec::session(
                shared.clone(),
                Caller::Admin,
                "exec".into(),
                "default".into(),
                name.into(),
                "command=true".into(),
                server,
            ));
            let mut said = Vec::new();
            let mut chunk = [0u8; 4096];
            // (The Status frame, whose code ends the failure; a pod found goes on to enter a unit this test never made.)
            while !String::from_utf8_lossy(&said).contains("\"code\":") {
                let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk))
                    .await
                    .unwrap_or_else(|_| panic!("{name}: the session says something; so far {:?}", String::from_utf8_lossy(&said)))
                    .unwrap();
                assert!(n > 0, "{name}: the session ended without a word");
                said.extend_from_slice(&chunk[..n]);
            }
            let said = String::from_utf8_lossy(&said);
            assert_eq!(said.contains("is not found"), !found, "{name}: {said}");
            session.abort();
        }
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A caller with a right on one holder kind and not on another is told 404, as of a name that is
    /// nothing, of a pod the other kind holds (a bare one, or a Job's or a DaemonSet's replica): log,
    /// exec and delete tell nothing of what exists beyond what the caller's own rights reach.
    #[tokio::test]
    async fn bare_pod_of_a_holder_without_the_right_is_not_found() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-barepod-holder-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let mut roles = String::new();
        for (who, kind, verbs) in [
            ("jobber", "Job", "get, exec, apply, delete"),
            ("wk", "Workload", "get, exec, apply, delete"),
        ] {
            roles += &format!(
                "apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {{name: {who}}}\nspec: {{}}\n---\napiVersion: kith.dev/v1\nkind: Role\nmetadata: {{name: {who}-role}}\nspec: {{rules: [{{kinds: [{kind}], verbs: [{verbs}]}}]}}\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {{name: {who}-binding}}\nspec: {{role: {who}-role, subjects: [{who}]}}\n---\n"
            );
        }
        {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(&roles).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        for (name, policy) in [
            ("once", Some("Never")),
            ("jb-j0", Some("Never")),
            ("always", None),
            ("web-0", None),
            ("web-n0", None),
        ] {
            let (code, said) = send_pod(&shared, Caller::Admin, a_pod(name, policy)).await;
            assert_eq!(code, StatusCode::CREATED, "{name}: {said}");
        }
        let job = json!({ "apiVersion": "batch/v1", "kind": "Job", "metadata": { "name": "foo" },
            "spec": { "template": { "spec": { "restartPolicy": "Never", "containers": [{ "name": "main", "image": "i" }] } } } });
        let (code, said) = answer_as(
            shared.clone(),
            Caller::Admin,
            "POST",
            "batch",
            "namespaces/default/jobs",
            job,
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{said}");
        let set = json!({ "apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": { "name": "foo" },
            "spec": { "selector": { "matchLabels": { "a": "foo" } }, "template": { "metadata": { "labels": { "a": "foo" } }, "spec": { "containers": [{ "name": "main", "image": "i" }] } } } });
        let (code, said) = answer_as(
            shared.clone(),
            Caller::Admin,
            "POST",
            "apps",
            "namespaces/default/daemonsets",
            set,
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{said}");
        // Each caller has the right on one holder kind: every name whose holder it lacks (a bare pod
        // there or not, a Job's or a DaemonSet's by its shape there or not, a nothing) is told the same
        // status and the same body but for the name, in every verb.
        let jobber = || Caller::Identity("jobber".into());
        let jobs = ["web-0", "gone-0", "web-n0", "gone-n0", "foo-n0", "always", "ghost"];
        let workloads = ["jb-j0", "gone-j0", "foo-j0", "gone-n0", "foo-n0", "once", "ghost"];
        for verb in ["log", "exec", "delete"] {
            for (who, names) in [("jobber", jobs.as_slice()), ("wk", workloads.as_slice())] {
                let mut seen = Vec::new();
                for name in names {
                    let caller = Caller::Identity(who.into());
                    let (code, said) = if verb == "delete" {
                        delete_pod_named(&shared, caller, name).await
                    } else {
                        let rest = format!("namespaces/default/pods/{name}/{verb}");
                        answer_as(shared.clone(), caller, "GET", "", &rest, Value::Null).await
                    };
                    seen.push((code, said.replace(name, "NAME")));
                }
                assert_eq!(seen[0].0, StatusCode::NOT_FOUND, "{who} {verb}: {seen:?}");
                assert!(seen.iter().all(|one| *one == seen[0]), "{who} {verb}: {seen:?}");
            }
        }
        assert!(
            shared
                .store
                .lock()
                .unwrap()
                .store
                .get("Workload/default/always")
                .is_some()
        );
        // And the one with the right still finds its own.
        let (code, said) = delete_pod_named(&shared, jobber(), "once").await;
        assert_eq!(code, StatusCode::OK, "{said}");
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A Job that ended with no unit in its status (so no run is counted) is Succeeded or Failed,
    /// and not Pending for ever, whether it is a Job's pod or a bare Pod held as one.
    #[test]
    fn ended_job_pod_phase() {
        let sent = json!({
            "apiVersion": "v1", "kind": "Pod", "metadata": { "name": "once", "namespace": "default" },
            "spec": { "restartPolicy": "Never", "containers": [{ "name": "main", "image": "i" }] },
        });
        let held = |status: Value| -> Resource {
            let meta = json!({ "name": "once", "namespace": "default" });
            serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": "Job", "metadata": meta, "spec": {}, "status": status,
            }))
            .unwrap()
        };
        for (status, phase) in [
            (json!({ "state": "succeeded", "containers": [] }), "Succeeded"),
            (
                json!({ "state": "succeeded", "succeeded": 0, "containers": [] }),
                "Succeeded",
            ),
            (
                json!({ "state": "succeeded", "succeeded": 1, "containers": [] }),
                "Succeeded",
            ),
            (json!({ "state": "failed", "failed": 1, "containers": [] }), "Failed"),
            (json!({ "state": "running", "containers": [] }), "Pending"),
        ] {
            let pod = bare_pod(&sent, &held(status.clone())).expect("a bare pod");
            assert_eq!(pod["status"]["phase"], phase, "{status}: {pod}");
            assert_eq!(pod["metadata"]["name"], "once", "{pod}");
        }
    }

    /// The lists a strategic patch merges by a key are the ones Kubernetes's types tag with
    /// `patchMergeKey`: what ci/kube_proto.py reads of them is the table in this file. It
    /// fails, and does not skip, where that source is not there (run ci/kube_proto.py once to
    /// have it); nothing is fetched here. Ignored in a plain `cargo test`, which touches no
    /// outside host and holds no cache: `ci/kube.sh` fetches the files and runs it with `--ignored`.
    #[test]
    #[ignore = "needs the Kubernetes type files ci/kube.sh fetches (cargo test -- --ignored merge_keys)"]
    fn merge_keys_are_those_of_the_kubernetes_types() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci/kube_proto.py");
        let read = std::process::Command::new("python3")
            .arg(script)
            .arg("--merge-keys")
            .output()
            .expect("python3 is there to read the Kubernetes types");
        let err = String::from_utf8_lossy(&read.stderr);
        assert!(read.status.success(), "ci/kube_proto.py --merge-keys: {err}");
        let read = String::from_utf8(read.stdout).unwrap();
        let ours: Vec<String> = MERGED.iter().map(|(list, by)| format!("{list} {by}")).collect();
        assert_eq!(
            ours,
            read.lines().collect::<Vec<_>>(),
            "the table is not what the types say"
        );
        // What each does with an item: a list of two keys goes by the one the item has.
        let by = |list, item: Value| merge_key(list, &item);
        assert_eq!(by("ports", json!({ "containerPort": 80 })), Some("containerPort"));
        assert_eq!(by("ports", json!({ "port": 80 })), Some("port"));
        assert_eq!(by("conditions", json!({ "type": "Ready" })), Some("type"));
        assert_eq!(by("args", json!("x")), None);
    }

    /// `kubectl get namespaces` and `get nodes` print an AGE: the object's creationTimestamp
    /// is the time of the oldest revision the store kept of what holds it.
    #[test]
    fn age_of_a_namespace_and_a_node_is_its_oldest_revision() {
        let mut store = Store::default();
        let held = |kind: &str, name: &str| -> Resource {
            let meta = json!({ "name": name });
            let status = json!({ "address": "10.0.0.2:7000", "state": "reachable" });
            let spec = if kind == "Node" {
                json!({ "address": "10.0.0.2:7000" })
            } else {
                json!({})
            };
            let mut held: Resource = serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": kind, "metadata": meta, "spec": spec,
            }))
            .unwrap();
            if kind == "Node" {
                held.status = Some(status);
            }
            held
        };
        store.at(Some(1_700_000_000));
        store.apply(held("Namespace", "shop")).unwrap();
        store.put(held("Node", "n2"));
        // A later change of the namespace keeps the age of its first revision.
        store.at(Some(1_700_000_500));
        let mut again = held("Namespace", "shop");
        again.metadata.labels.insert("a".into(), "b".into());
        store.apply(again).unwrap();
        let grants = Grants::of(&Caller::Admin, &store);
        let kind = |of: &str| KINDS.iter().find(|kind| kind.kind == of).unwrap();
        for (of, name) in [("Namespace", "shop"), ("Node", "n2")] {
            let found = objects(&store, kind(of), None, Some(name), &grants, &Verb::Get);
            assert_eq!(found.len(), 1, "{of}");
            assert_eq!(
                found[0]["metadata"]["creationTimestamp"],
                rfc3339(1_700_000_000),
                "{of}: {found:?}"
            );
            let cells: Vec<_> = row(of, &found[0])
                .into_iter()
                .filter(|(name, _)| *name == "Age")
                .collect();
            assert!(
                cells[0].1.as_str().is_some_and(|age| age.ends_with('d')),
                "{of}: {cells:?}"
            );
        }
    }

    /// Once the store is marked, a Node's and a Namespace's creationTimestamp is when the store
    /// first made it, and it holds when a long edit history trims the revisions kept.
    #[test]
    fn the_made_time_holds_past_a_trimmed_history() {
        let held = |kind: &str, name: &str, n: usize| -> Resource {
            let mut held: Resource = serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": kind,
                "metadata": { "name": name }, "spec": {},
            }))
            .unwrap();
            held.metadata.labels.insert("n".into(), n.to_string());
            if kind == "Node" {
                held.status = Some(json!({ "address": "10.0.0.2:7000", "state": "reachable" }));
            }
            held
        };
        let mut store = Store::default();
        store.at(Some(1_700_000_000));
        store.apply(held("Namespace", "shop", 0)).unwrap();
        store.apply(held("Node", "n2", 0)).unwrap();
        store.mark();
        store.at(Some(1_700_000_500));
        let limit = kith_api::store::HISTORY_LIMIT;
        for n in 1..limit + 50 {
            store.apply(held("Namespace", "shop", n)).unwrap();
            store.apply(held("Node", "n2", n)).unwrap();
        }
        assert_eq!(store.history("Node/n2").unwrap().len(), limit);
        let grants = Grants::of(&Caller::Admin, &store);
        let kind = |of: &str| KINDS.iter().find(|kind| kind.kind == of).unwrap();
        for (of, name) in [("Namespace", "shop"), ("Node", "n2")] {
            let found = objects(&store, kind(of), None, Some(name), &grants, &Verb::Get);
            assert_eq!(found.len(), 1, "{of}");
            assert_eq!(
                found[0]["metadata"]["creationTimestamp"],
                rfc3339(1_700_000_000),
                "{of}: {found:?}"
            );
        }
    }

    #[test]
    fn a_time_is_read_back_and_a_name_kith_cannot_hold_is_hashed() {
        for at in [0, 951_782_400, 1_709_251_199, 1_794_614_400] {
            assert_eq!(seconds(&rfc3339(at)), Some(at));
        }
        assert_eq!(seconds("not a time"), None);
        let roles = KINDS.iter().find(|kind| kind.plural == "clusterroles").unwrap();
        assert_eq!(kept_name(roles, "reader"), "clusterroles.reader");
        let hashed = kept_name(roles, "system:reader");
        assert!(hashed.len() == 45 && !hashed.contains(':'), "{hashed}");
        assert_ne!(hashed, kept_name(roles, "system:writer"));
    }

    /// What `api` gave, or why not (`ApiError` has no `Debug`).
    fn must<T>(result: Result<T, api::ApiError>) -> T {
        result.unwrap_or_else(|e| match e {
            api::ApiError::Refused(why) | api::ApiError::Unauthorized(why) => panic!("{why}"),
            api::ApiError::Store(e) => panic!("{e}"),
        })
    }

    /// ConfigMaps `from..to` of `namespace`, each holding `value`, as if made through this API.
    fn maps(namespace: &str, from: usize, to: usize, value: &str) -> Vec<kith_api::Resource> {
        let source: String = (from..to)
            .map(|n| {
                let sent = json!({
                    "apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": { "name": format!("c{n}"), "namespace": namespace }, "data": { "k": value },
                });
                let sent = serde_json::to_string(&sent.to_string()).unwrap();
                format!(
                    "---\napiVersion: kith.dev/v1\nkind: ConfigMap\n\
                     metadata: {{ name: c{n}, namespace: {namespace}, annotations: {{ {SENT}: {sent} }} }}\n\
                     spec: {{ data: {{ k: {value} }} }}\n"
                )
            })
            .collect();
        let resources = kith_api::Resource::from_source(&source).unwrap();
        resources.into_iter().map(Result::unwrap).collect()
    }

    /// What a watch of ConfigMaps does for one change among 2000 of them: it makes one object
    /// and compares one key, where reading everything makes and compares 2000. (The times are
    /// for the reader to see; what is asserted is the work.) It reads everything again where
    /// it cannot know what changed, and what it reads it shows no more of than a list does.
    #[tokio::test]
    async fn watch_work_is_what_changed() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-watch-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let configmaps = KINDS.iter().find(|kind| kind.plural == "configmaps").unwrap();
        let admin = |shared: &Arc<Shared>| Call {
            shared: shared.clone(),
            caller: Caller::Admin,
            certificate: None,
            asked: Asked::new(),
            table: false,
        };
        let put = |resources| {
            let shared = shared.clone();
            async move { must(api::applied(&shared, &Caller::Admin, resources).await) }
        };
        put(maps("default", 0, 2000, "1")).await;
        let mut watch = Watch::start(admin(&shared), configmaps, None, 60);
        let seen = watch.read();
        watch.tell(seen, true, true);
        assert_eq!(
            (watch.translated, watch.compared, watch.known.len()),
            (2000, 2000, 2000)
        );
        // One change: one object made, one key compared, one event.
        let events = |watch: &mut Watch| String::from_utf8(std::mem::take(&mut watch.due)).unwrap();
        let mut times = Vec::new();
        for (n, partial) in [(7, true), (8, false), (9, true)] {
            put(maps("default", n, n + 1, "2")).await;
            watch.after = watch.after.filter(|_| partial);
            (watch.translated, watch.compared) = (0, 0);
            let began = std::time::Instant::now();
            let seen = watch.read();
            watch.tell(seen, false, false);
            times.push((began.elapsed(), watch.translated, watch.compared));
            let told = events(&mut watch);
            assert_eq!(told.lines().count(), 1, "{told}");
            assert!(
                told.contains(&format!("\"name\":\"c{n}\"")) && told.contains("MODIFIED"),
                "{told}"
            );
        }
        eprintln!(
            "watch of 2000 ConfigMaps, one changed: reading what changed {:?}, reading all {:?}",
            times[0].0, times[1].0
        );
        assert_eq!((times[0].1, times[0].2), (1, 1), "what changed");
        assert_eq!((times[1].1, times[1].2), (2000, 2000), "everything");
        assert_eq!((times[2].1, times[2].2), (1, 1), "what changed, again");
        // A deleted one is told gone, from its key alone.
        must(api::deleted(&shared, &Caller::Admin, "ConfigMap/default/c3".into()).await);
        (watch.translated, watch.compared) = (0, 0);
        let seen = watch.read();
        watch.tell(seen, false, false);
        let told = events(&mut watch);
        assert!(told.contains("DELETED") && told.contains("\"name\":\"c3\""), "{told}");
        assert_eq!((watch.translated, watch.compared), (0, 1));
        assert_eq!(watch.known.len(), 1999);
        // Where it cannot know what changed it reads all: who may see what changed, ...
        let access = "---\napiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: eve}\nspec: {}\n";
        let access = kith_api::Resource::from_source(access).unwrap().pop().unwrap().unwrap();
        put(vec![access]).await;
        // ... a worker's view of the store, which has no log, ...
        (watch.translated, watch.compared) = (0, 0);
        let seen = watch.read();
        watch.tell(seen, false, false);
        assert_eq!(watch.translated, 1999, "an Identity changed");
        put(maps("default", 10, 11, "2")).await;
        shared.view.send_replace(Some(0));
        (watch.translated, watch.compared) = (0, 0);
        let seen = watch.read();
        watch.tell(seen, false, false);
        assert_eq!(watch.translated, 1999, "a view");
        shared.view.send_replace(None);
        // ... and more changes than are kept.
        put(maps("other", 0, 4100, "1")).await;
        (watch.translated, watch.compared) = (0, 0);
        let seen = watch.read();
        watch.tell(seen, false, false);
        assert_eq!(watch.translated, 1999 + 4100, "more changes than are kept");
        drop(events(&mut watch));
        let seen = watch.read();
        assert_eq!(watch.translated, 1999 + 4100, "nothing changed since");
        assert!(seen.found.is_empty() && seen.changed.is_some_and(|changed| changed.is_empty()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A watch shows what a list shows: a change to what the caller may not see is not read
    /// into an object, and a change of what the caller may see (a Role) is read at once.
    #[tokio::test]
    async fn watch_work_shows_what_a_list_shows() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-watch-grants-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let configmaps = KINDS.iter().find(|kind| kind.plural == "configmaps").unwrap();
        let source = |namespaces: &str| {
            format!(
                "---\napiVersion: kith.dev/v1\nkind: Identity\nmetadata: {{name: eve}}\nspec: {{}}\n\
                 ---\napiVersion: kith.dev/v1\nkind: Role\nmetadata: {{name: seer}}\n\
                 spec: {{ rules: [{{kinds: [ConfigMap], verbs: [watch, list], namespaces: [{namespaces}]}}] }}\n\
                 ---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {{name: eve-seer}}\n\
                 spec: {{role: seer, subjects: [eve]}}\n"
            )
        };
        let sources = |text: String| -> Vec<kith_api::Resource> {
            kith_api::Resource::from_source(&text)
                .unwrap()
                .into_iter()
                .map(Result::unwrap)
                .collect()
        };
        let put = |resources| {
            let shared = shared.clone();
            async move { must(api::applied(&shared, &Caller::Admin, resources).await) }
        };
        put(sources(source("a"))).await;
        let mut resources = maps("a", 0, 3, "1");
        resources.extend(maps("b", 0, 3, "1"));
        put(resources).await;
        let call = Call {
            shared: shared.clone(),
            caller: Caller::Identity("eve".into()),
            certificate: None,
            asked: Asked::new(),
            table: false,
        };
        let mut watch = Watch::start(call, configmaps, None, 60);
        let seen = watch.read();
        watch.tell(seen, true, true);
        assert_eq!(watch.known.len(), 3, "only a's");
        // A change in b: nothing is made of it, nothing is told.
        put(maps("b", 0, 1, "2")).await;
        (watch.translated, watch.compared) = (0, 0);
        let seen = watch.read();
        watch.tell(seen, false, false);
        assert_eq!((watch.translated, watch.compared, watch.due.len()), (0, 0, 0));
        // A change in a is told; and a Role that lets eve see b makes b's told as new.
        put(maps("a", 1, 2, "2")).await;
        let seen = watch.read();
        watch.tell(seen, false, false);
        assert_eq!(
            String::from_utf8(std::mem::take(&mut watch.due))
                .unwrap()
                .lines()
                .count(),
            1
        );
        put(sources(source("a, b"))).await;
        let seen = watch.read();
        watch.tell(seen, false, false);
        let told = String::from_utf8(std::mem::take(&mut watch.due)).unwrap();
        assert_eq!(told.matches("ADDED").count(), 3, "{told}");
        assert_eq!(watch.known.len(), 6);
        // And one that takes a away: a's are told gone.
        put(sources(source("b"))).await;
        let seen = watch.read();
        watch.tell(seen, false, false);
        let told = String::from_utf8(std::mem::take(&mut watch.due)).unwrap();
        assert_eq!(told.matches("DELETED").count(), 3, "{told}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn map(data: Value) -> Value {
        json!({ "apiVersion": "v1", "kind": "ConfigMap", "metadata": { "name": "m" }, "data": data })
    }

    fn who(object: &Value) -> Vec<(String, Vec<String>)> {
        managers(object)
            .into_iter()
            .map(|m| (m.name, m.fields.iter().map(|at| at.join("/")).collect()))
            .collect()
    }

    /// Two managers keep their own fields; a different value for one of another's is a 409 in
    /// Kubernetes's words, and with force it is the forcer's; what a manager leaves out of its
    /// next apply goes when no one else has it.
    #[test]
    fn apply_keeps_each_managers_fields_and_conflicts_on_the_others() {
        let a = apply(None, map(json!({ "x": "1", "gone": "g" })), "a", "v1", false).unwrap();
        let ab = apply(Some(a), map(json!({ "w": "2" })), "b", "v1", false).unwrap();
        assert_eq!(ab["data"], json!({ "x": "1", "gone": "g", "w": "2" }));
        let no = apply(Some(ab.clone()), map(json!({ "x": "9" })), "b", "v1", false).unwrap_err();
        assert_eq!(no.code, StatusCode::CONFLICT);
        assert_eq!(
            no.why,
            "Apply failed with 1 conflict: conflict with \"a\" using v1: .data.x"
        );
        // The same value is no conflict; both then have it.
        let same = apply(Some(ab.clone()), map(json!({ "x": "1" })), "b", "v1", false).unwrap();
        assert!(
            who(&same)
                .iter()
                .all(|(_, fields)| fields.contains(&"f:data/f:x".to_string()))
        );
        // With force the field is b's, and a is now the one in conflict.
        let forced = apply(Some(ab), map(json!({ "x": "9", "w": "2" })), "b", "v1", true).unwrap();
        assert_eq!(forced["data"]["x"], "9");
        let no = apply(
            Some(forced.clone()),
            map(json!({ "x": "1", "gone": "g" })),
            "a",
            "v1",
            false,
        )
        .unwrap_err();
        assert!(no.why.contains("conflict with \"b\" using v1: .data.x"), "{}", no.why);
        // a leaves out what it set, and no other has: gone. What b has stays.
        let a2 = apply(Some(forced), map(json!({ "keep": "k" })), "a", "v1", false).unwrap();
        assert_eq!(a2["data"], json!({ "x": "9", "w": "2", "keep": "k" }));
        assert_eq!(who(&a2).len(), 2);
    }

    /// An apply that changes nothing is not a change: not of the object, and not of the time
    /// the manager is dated by. Many managers are refused past the cap.
    #[test]
    fn a_repeat_of_an_apply_changes_nothing() {
        let mut once = apply(None, map(json!({ "x": "1" })), "a", "v1", false).unwrap();
        // (A manager's time is a second's; make it one a second can differ from.)
        once["metadata"]["managedFields"][0]["time"] = json!("2001-01-01T00:00:00Z");
        let twice = apply(Some(once.clone()), map(json!({ "x": "1" })), "a", "v1", false).unwrap();
        assert_eq!(once, twice);
        let mut object = once;
        let mut taken = 1; // (a is one)
        loop {
            let (key, name) = (format!("k{taken}"), format!("m{taken}"));
            match apply(Some(object.clone()), map(json!({ key: "v" })), &name, "v1", false) {
                Ok(next) => object = next,
                Err(no) => {
                    assert_eq!(no.code, StatusCode::UNPROCESSABLE_ENTITY);
                    break;
                }
            }
            taken += 1;
        }
        assert_eq!(taken, MANAGERS, "one manager more than {MANAGERS} is refused");
    }

    /// What is managed survives what is stored (FieldsV1, in the object as it was sent) and
    /// keyed list items are told apart by their key, not by their place.
    #[test]
    fn managed_fields_round_trip_and_list_items_are_named_by_key() {
        let deployment = |names: &[&str]| {
            let containers: Vec<Value> = names.iter().map(|name| json!({ "name": name, "image": "i" })).collect();
            json!({
                "apiVersion": "apps/v1", "kind": "Deployment", "metadata": { "name": "web" },
                "spec": { "replicas": 1, "template": { "spec": { "containers": containers } } },
            })
        };
        let applied = apply(None, deployment(&["a", "b"]), "m", "apps/v1", false).unwrap();
        let fields = who(&applied).remove(0).1;
        assert!(
            fields.contains(&r#"f:spec/f:template/f:spec/f:containers/k:{"name":"b"}/f:image"#.to_string()),
            "{fields:?}"
        );
        let again = managers(&applied);
        assert_eq!(again.len(), 1);
        // An update of a field takes it from its manager; the rest stays.
        let mut changed = applied.clone();
        changed["spec"]["replicas"] = json!(3);
        updated(&applied, &mut changed);
        let left = who(&changed).remove(0).1;
        assert!(
            !left.contains(&"f:spec/f:replicas".to_string()) && left.len() == fields.len() - 1,
            "{left:?}"
        );
        // What it costs: the managedFields of one Deployment, against the object.
        let (with, without) = (
            serde_json::to_vec(&applied).unwrap().len(),
            serde_json::to_vec(&deployment(&["a", "b"])).unwrap().len(),
        );
        eprintln!("managedFields: {} bytes on {} of the object", with - without, without);
    }

    /// `serve` answers `caller` a request of `content_type` with `asked` in its query.
    async fn sent_as(
        shared: &Arc<crate::Shared>,
        method: &str,
        content_type: &str,
        rest: &str,
        asked: &[(&str, &str)],
        body: Value,
    ) -> (StatusCode, Value) {
        let mut request = axum::http::Request::builder()
            .method(method)
            .header(header::CONTENT_TYPE, content_type)
            .body(())
            .unwrap();
        request.extensions_mut().insert(Caller::Admin);
        let (parts, ()) = request.into_parts();
        let asked: Asked = asked.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let group = if rest.contains("deployments") || rest.contains("replicasets") {
            "apps"
        } else {
            ""
        };
        match serve(shared.clone(), parts, group, rest, asked, body.to_string().as_bytes()).await {
            Ok(answer) => {
                let (code, body) = (answer.status(), answer.into_body());
                let text = axum::body::to_bytes(body, 1 << 20).await.unwrap();
                (code, serde_json::from_slice(&text).unwrap_or(Value::Null))
            }
            Err(no) => (no.code, json!(no.why)),
        }
    }

    const DEPLOYMENTS: &str = "namespaces/default/deployments";
    const REPLICA_SETS: &str = "namespaces/default/replicasets";

    /// A Deployment `x` of one replica of `image`, as kubectl would send it.
    fn deployment_of(image: &str) -> Value {
        json!({
            "apiVersion": "apps/v1", "kind": "Deployment", "metadata": { "name": "x" },
            "spec": { "replicas": 1, "selector": { "matchLabels": { "app": "x" } }, "template": {
                "metadata": { "labels": { "app": "x" } },
                "spec": { "containers": [{ "name": "main", "image": image }] },
            } },
        })
    }

    /// Makes the Deployment `x` of `image` and changes its image to each of `then`: a revision each.
    async fn revised(shared: &Arc<crate::Shared>, image: &str, then: &[&str]) {
        let made = sent_as(
            shared,
            "POST",
            "application/json",
            DEPLOYMENTS,
            &[],
            deployment_of(image),
        )
        .await;
        assert_eq!(made.0, StatusCode::CREATED, "{}", made.1);
        for image in then {
            let patch =
                json!({ "spec": { "template": { "spec": { "containers": [{ "name": "main", "image": image }] } } } });
            let rest = format!("{DEPLOYMENTS}/x");
            let done = sent_as(shared, "PATCH", "application/merge-patch+json", &rest, &[], patch).await;
            assert_eq!(done.0, StatusCode::OK, "{}", done.1);
        }
    }

    /// The ReplicaSets of `x` as listed: (image, revision annotation, replicas), by revision.
    async fn replica_sets(shared: &Arc<crate::Shared>) -> Vec<(String, String, u64, Value)> {
        let (code, listed) = sent_as(shared, "GET", "application/json", REPLICA_SETS, &[], Value::Null).await;
        assert_eq!(code, StatusCode::OK, "{listed}");
        let mut sets: Vec<_> = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|set| {
                let revision = set["metadata"]["annotations"]["deployment.kubernetes.io/revision"].as_str();
                let image = set["spec"]["template"]["spec"]["containers"][0]["image"].as_str();
                let replicas = set["spec"]["replicas"].as_u64();
                (
                    image.unwrap().to_string(),
                    revision.unwrap().to_string(),
                    replicas.unwrap(),
                    set.clone(),
                )
            })
            .collect();
        sets.sort_by_key(|(_, revision, ..)| revision.parse::<u64>().unwrap());
        sets
    }

    /// Two templates are one revision when they say the same, whatever hash label, null or
    /// empty map kubectl's own encoding left in one; and not when any value differs.
    #[test]
    fn rollout_history_identity_ignores_the_hash_label_nulls_and_empty_maps_only() {
        let plain = json!({ "metadata": { "labels": { "app": "x" } }, "spec": { "containers": [{ "name": "m", "image": "i" }] } });
        let encoded = json!({
            "metadata": { "creationTimestamp": null, "labels": { "pod-template-hash": "abc", "app": "x" } },
            "spec": { "containers": [{ "image": "i", "name": "m", "resources": {} }] },
        });
        assert_eq!(identity(&plain), identity(&encoded));
        assert_eq!(identity(&plain).len(), 64, "the whole hash, not a prefix");
        let other = json!({ "metadata": { "labels": { "app": "y" } }, "spec": { "containers": [{ "name": "m", "image": "i" }] } });
        assert_ne!(identity(&plain), identity(&other));
        let (a, b) = (
            json!({ "spec": { "x": ["1", "2"] } }),
            json!({ "spec": { "x": ["2", "1"] } }),
        );
        assert_ne!(identity(&a), identity(&b), "the order of a list is its meaning");
    }

    /// `kubectl rollout history` lists a ReplicaSet for each template the Deployment's kept
    /// revisions held, numbered as the revision that last held it; the live one is not twice.
    #[tokio::test]
    async fn rollout_history_lists_one_read_only_replica_set_per_kept_template() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-history-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        revised(&shared, "v1", &["v2", "v3"]).await;
        let sets = replica_sets(&shared).await;
        let seen: Vec<_> = sets
            .iter()
            .map(|(image, revision, replicas, _)| (image.as_str(), revision.as_str(), *replicas))
            .collect();
        assert_eq!(seen, [("v1", "1", 0), ("v2", "2", 0), ("v3", "3", 1)]);
        let names: BTreeSet<_> = sets
            .iter()
            .map(|set| set.3["metadata"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), 3, "a name each");
        // Each is owned by the Deployment, which is what `kubectl rollout` finds them by.
        let (_, owner) = sent_as(
            &shared,
            "GET",
            "application/json",
            &format!("{DEPLOYMENTS}/x"),
            &[],
            Value::Null,
        )
        .await;
        for (.., set) in &sets {
            assert_eq!(
                set["metadata"]["ownerReferences"][0]["uid"], owner["metadata"]["uid"],
                "{set}"
            );
            assert_eq!(set["metadata"]["ownerReferences"][0]["controller"], true);
        }
        // A kept one runs nothing: no replicas wanted, none counted.
        for (_, _, _, set) in sets.iter().filter(|set| set.2 == 0) {
            assert_eq!(
                (&set["status"]["replicas"], &set["status"]["readyReplicas"]),
                (&json!(0), &json!(0)),
                "{set}"
            );
        }
        // One is got by its name, as `kubectl rollout history --revision` does.
        let name = sets[0].3["metadata"]["name"].as_str().unwrap();
        let (code, one) = sent_as(
            &shared,
            "GET",
            "application/json",
            &format!("{REPLICA_SETS}/{name}"),
            &[],
            Value::Null,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{one}");
        assert_eq!(one["spec"]["template"]["spec"]["containers"][0]["image"], "v1");
        // Back to v2 (a revision 4) and a scale (5): v2 is the live one, with its newest
        // number; v1 and v3 stay; and what a scale left is not a template of its own.
        let rest = format!("{DEPLOYMENTS}/x");
        let back = json!({ "spec": { "template": { "spec": { "containers": [{ "name": "main", "image": "v2" }] } } } });
        sent_as(&shared, "PATCH", "application/merge-patch+json", &rest, &[], back).await;
        let scale = json!({ "spec": { "replicas": 3 } });
        sent_as(&shared, "PATCH", "application/merge-patch+json", &rest, &[], scale).await;
        let sets = replica_sets(&shared).await;
        let seen: Vec<_> = sets
            .iter()
            .map(|(image, revision, replicas, _)| (image.as_str(), revision.as_str(), *replicas))
            .collect();
        assert_eq!(seen, [("v1", "1", 0), ("v3", "3", 0), ("v2", "5", 3)]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A history ReplicaSet is read: a write or a delete of one, or of any, is a
    /// `MethodNotAllowed` Status that says to change the Deployment, and changes nothing.
    #[tokio::test]
    async fn rollout_history_replica_sets_are_refused_every_write() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-history-write-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        revised(&shared, "v1", &["v2"]).await;
        let sets = replica_sets(&shared).await;
        let name = sets[0].3["metadata"]["name"].as_str().unwrap().to_string();
        let one = format!("{REPLICA_SETS}/{name}");
        let body = sets[0].3.clone();
        for (method, rest, kind) in [
            ("PUT", one.as_str(), "application/json"),
            ("PATCH", one.as_str(), "application/merge-patch+json"),
            ("PATCH", one.as_str(), "application/json-patch+json"),
            ("DELETE", one.as_str(), "application/json"),
            ("POST", REPLICA_SETS, "application/json"),
            ("PATCH", &format!("{one}/scale"), "application/merge-patch+json"),
            (
                "PUT",
                &format!("{REPLICA_SETS}/nothing-by-this-name"),
                "application/json",
            ),
        ] {
            let (code, said) = sent_as(&shared, method, kind, rest, &[], body.clone()).await;
            assert_eq!(code, StatusCode::METHOD_NOT_ALLOWED, "{method} {rest}: {said}");
            assert!(
                said.as_str().is_some_and(|why| why.contains("Deployment")),
                "{method} {rest}: {said}"
            );
        }
        // Nothing moved: the same ReplicaSets, and the Deployment at its revision.
        let again = replica_sets(&shared).await;
        assert_eq!(again.len(), 2);
        let (_, owner) = sent_as(
            &shared,
            "GET",
            "application/json",
            &format!("{DEPLOYMENTS}/x"),
            &[],
            Value::Null,
        )
        .await;
        assert_eq!(owner["metadata"]["generation"], 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A Deployment whose replica names `NAME-N` pass 63 characters is refused by name through
    /// the Kubernetes API (it applies through `submitted`), and one that fits is made.
    #[tokio::test]
    async fn a_deployment_with_a_replica_name_over_63_characters_is_refused_by_name() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-long-name-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let named = |name: &str| {
            let mut body = deployment_of("example.org/web");
            body["metadata"]["name"] = json!(name);
            body
        };
        let long = "a".repeat(63);
        let (code, said) = sent_as(&shared, "POST", "application/json", DEPLOYMENTS, &[], named(&long)).await;
        assert_ne!(code, StatusCode::CREATED, "{said}");
        assert!(
            said.to_string().contains(&long) && said.to_string().contains("replica name"),
            "{said}"
        );
        let (code, said) = sent_as(
            &shared,
            "POST",
            "application/json",
            DEPLOYMENTS,
            &[],
            named(&"a".repeat(60)),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{said}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The JSON patch `kubectl rollout undo` sends for the ReplicaSet `set`: its template
    /// without the hash label, and the Deployment's annotations (it has none: an empty map).
    fn undo_patch(set: &Value) -> Value {
        let mut template = set["spec"]["template"].clone();
        template["metadata"]["labels"]
            .as_object_mut()
            .unwrap()
            .remove("pod-template-hash");
        // (kubectl's own encoding of a container adds an empty `resources`: captured, `-v=8`.)
        template["spec"]["containers"][0]["resources"] = json!({});
        json!([
            { "op": "replace", "path": "/spec/template", "value": template },
            { "op": "replace", "path": "/metadata/annotations", "value": {} },
        ])
    }

    /// `kubectl rollout undo` (a JSON patch back to an old template) is the store's own
    /// rollback to the newest revision that held it: its whole resource comes back as a new
    /// revision (a patch would have kept the replicas), and the history shows it.
    #[tokio::test]
    async fn rollout_undo_goes_back_by_the_stores_rollback() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-undo-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        revised(&shared, "v1", &["v2"]).await;
        // v3 at three replicas, so that a rollback to v2 is told from a patch of its template.
        let rest = format!("{DEPLOYMENTS}/x");
        let v3 = json!({ "spec": { "replicas": 3, "template": { "spec": { "containers": [{ "name": "main", "image": "v3" }] } } } });
        sent_as(&shared, "PATCH", "application/merge-patch+json", &rest, &[], v3).await;
        let sets = replica_sets(&shared).await;
        let v2 = sets.iter().find(|set| set.0 == "v2").unwrap().3.clone();
        let (code, done) = sent_as(
            &shared,
            "PATCH",
            "application/json-patch+json",
            &rest,
            &[],
            undo_patch(&v2),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{done}");
        assert_eq!(
            done["spec"]["template"]["spec"]["containers"][0]["image"], "v2",
            "{done}"
        );
        assert_eq!(done["metadata"]["generation"], 4, "a new revision");
        assert_eq!(done["spec"]["replicas"], 1, "what revision 2 held, replicas and all");
        {
            let state = shared.store.lock().unwrap();
            let history = state.store.history("Workload/default/x").unwrap();
            let [.., two, _, back] = history else {
                panic!("{history:?}")
            };
            assert_eq!(back.resource.metadata.revision, Some(4));
            assert_eq!(back.resource.spec, two.resource.spec);
            assert_eq!(
                back.resource.metadata.annotations.get(SENT),
                two.resource.metadata.annotations.get(SENT)
            );
        }
        // And the history says it: v2 is the live one at 4, v3 is kept at 3.
        let seen: Vec<_> = replica_sets(&shared)
            .await
            .into_iter()
            .map(|(image, revision, ..)| (image, revision))
            .collect();
        assert_eq!(
            seen,
            [
                ("v1".into(), "1".into()),
                ("v3".into(), "3".into()),
                ("v2".into(), "4".into())
            ]
        );
        // The same again is the live template: nothing is done, and no revision is made.
        let live = replica_sets(&shared).await.pop().unwrap().3;
        let mut again = undo_patch(&live);
        again[0]["value"]["spec"]["containers"][0]
            .as_object_mut()
            .unwrap()
            .remove("resources");
        let (code, done) = sent_as(&shared, "PATCH", "application/json-patch+json", &rest, &[], again).await;
        assert_eq!(code, StatusCode::OK, "{done}");
        assert_eq!(done["metadata"]["generation"], 4, "{done}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A write that lands between `kubectl rollout undo` reading the Deployment and its rollback
    /// being applied is not written over: the undo is a 409 Conflict and changes nothing.
    #[tokio::test]
    async fn rollout_undo_head_moved() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-undo-moved-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        revised(&shared, "v1", &["v2", "v3"]).await;
        let rest = format!("{DEPLOYMENTS}/x");
        let v1 = replica_sets(&shared).await.remove(0).3;
        let (there, reached) = tokio::sync::oneshot::channel();
        let (go, wait) = tokio::sync::oneshot::channel();
        HELD.lock()
            .unwrap()
            .push((Arc::as_ptr(&shared) as usize, (there, wait)));
        let undo = tokio::spawn({
            let (shared, rest) = (shared.clone(), rest.clone());
            async move {
                sent_as(
                    &shared,
                    "PATCH",
                    "application/json-patch+json",
                    &rest,
                    &[],
                    undo_patch(&v1),
                )
                .await
            }
        });
        reached.await.unwrap();
        // The undo has read revision 3. Another writer lands 4 before its rollback is applied.
        let v4 = json!({ "spec": { "replicas": 5 } });
        let (code, done) = sent_as(&shared, "PATCH", "application/merge-patch+json", &rest, &[], v4).await;
        assert_eq!(code, StatusCode::OK, "{done}");
        go.send(()).unwrap();
        let (code, said) = undo.await.unwrap();
        assert_eq!(code, StatusCode::CONFLICT, "{said}");
        assert!(said.to_string().contains("is at revision 4"), "{said}");
        let state = shared.store.lock().unwrap();
        let head = state.store.get("Workload/default/x").unwrap();
        assert_eq!(
            head.metadata.revision,
            Some(4),
            "the writer's revision is the head still"
        );
        assert_eq!(head.spec["replicas"], 5);
        drop(state);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A JSON patch that is not a return to a template the Deployment kept is a patch: a new
    /// template is written as one, a patch that dry-runs a return changes nothing, and one that
    /// changes more than the template and annotations is not taken for an undo.
    #[tokio::test]
    async fn rollout_undo_is_only_a_return_to_a_kept_template() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-undo-not-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        revised(&shared, "v1", &["v2"]).await;
        let rest = format!("{DEPLOYMENTS}/x");
        let v1 = replica_sets(&shared).await.remove(0).3;
        let patch = |value: Value| {
            let mut ops = undo_patch(&v1);
            ops.as_array_mut().unwrap().push(value);
            ops
        };
        // A dry run of the return writes nothing.
        let (code, done) = sent_as(
            &shared,
            "PATCH",
            "application/json-patch+json",
            &rest,
            &[("dryRun", "All")],
            undo_patch(&v1),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{done}");
        let (_, now) = sent_as(&shared, "GET", "application/json", &rest, &[], Value::Null).await;
        assert_eq!(now["metadata"]["generation"], 2, "{now}");
        // The return and a change of replicas is a patch: replicas are what it says.
        let both = patch(json!({ "op": "replace", "path": "/spec/replicas", "value": 4 }));
        let (code, done) = sent_as(&shared, "PATCH", "application/json-patch+json", &rest, &[], both).await;
        assert_eq!(code, StatusCode::OK, "{done}");
        assert_eq!(
            (done["spec"]["replicas"].clone(), done["metadata"]["generation"].clone()),
            (json!(4), json!(3))
        );
        // A template none of the revisions held is written as a patch.
        let mut new = undo_patch(&v1);
        new[0]["value"]["spec"]["containers"][0]["image"] = json!("v9");
        let (code, done) = sent_as(&shared, "PATCH", "application/json-patch+json", &rest, &[], new).await;
        assert_eq!(code, StatusCode::OK, "{done}");
        assert_eq!(done["spec"]["template"]["spec"]["containers"][0]["image"], "v9");
        assert_eq!(done["spec"]["replicas"], 4, "a patch keeps what it does not say");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A Deployment with annotations (`kubectl apply` leaves one, Helm several) is sent back
    /// as well: kubectl's patch empties them (the ReplicaSet made up carries none of them),
    /// and the rollback is the store's, bringing back what the revision held.
    #[tokio::test]
    async fn rollout_undo_of_an_annotated_deployment_is_still_the_rollback() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-undo-notes-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let mut first = deployment_of("v1");
        first["metadata"]["annotations"] =
            json!({ "meta.helm.sh/release-name": "x", "kubectl.kubernetes.io/last-applied-configuration": "{}" });
        let made = sent_as(&shared, "POST", "application/json", DEPLOYMENTS, &[], first).await;
        assert_eq!(made.0, StatusCode::CREATED, "{}", made.1);
        let rest = format!("{DEPLOYMENTS}/x");
        let v2 = json!({ "spec": { "replicas": 3, "template": { "spec": { "containers": [{ "name": "main", "image": "v2" }] } } } });
        sent_as(&shared, "PATCH", "application/merge-patch+json", &rest, &[], v2).await;
        let v1 = replica_sets(&shared).await.remove(0).3;
        let (code, done) = sent_as(
            &shared,
            "PATCH",
            "application/json-patch+json",
            &rest,
            &[],
            undo_patch(&v1),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{done}");
        assert_eq!(
            done["spec"]["template"]["spec"]["containers"][0]["image"], "v1",
            "{done}"
        );
        assert_eq!(
            done["spec"]["replicas"], 1,
            "the store's rollback: the whole revision, replicas too"
        );
        assert_eq!(
            done["metadata"]["annotations"]["meta.helm.sh/release-name"], "x",
            "{done}"
        );
        let state = shared.store.lock().unwrap();
        let history = state.store.history("Workload/default/x").unwrap();
        let [first, _, back] = history else {
            panic!("{history:?}")
        };
        assert_eq!(
            back.resource.spec, first.resource.spec,
            "a rollback: the first revision again"
        );
        drop(state);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only a name that is a Deployment's name and ten hex digits can be an earlier revision's
    /// ReplicaSet: a get of any other name does not read the history.
    #[test]
    fn rollout_history_is_read_only_for_a_name_it_could_have_made() {
        assert!(may_be_history("x", None));
        assert!(may_be_history("x", Some("x-0123456789")));
        assert!(!may_be_history("x", Some("x-0123456789ab")));
        assert!(!may_be_history("x", Some("x-0123456xyz")));
        assert!(!may_be_history("x", Some("x-y-0123456789")));
        assert!(!may_be_history("x", Some("x")));
        assert!(!may_be_history("x", Some("xy-0123456789")));
    }
}
