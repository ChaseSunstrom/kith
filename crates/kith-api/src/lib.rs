//! kith resources: the envelope every resource shares, the built-in kinds and
//! their JSON Schemas, and the store that keeps them (PLAN.md §4.2, §4.3).

pub mod kinds;
pub mod schema;
pub mod store;

use kinds::*;
use kith_yaml::Node;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const API_VERSION: &str = "kith.dev/v1";
pub const DEFAULT_NAMESPACE: &str = "default";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    /// Lowercase letters, digits, `-` and `.`; at most 63 characters.
    pub name: String,
    /// Defaults to `default` for namespaced kinds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    /// Set by the store: 1 on creation, +1 on every change. When present in an
    /// applied resource it must match the live revision, so a stale edit is refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
}

/// A resource of any kind, with its spec already validated and normalised.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    pub spec: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Value>,
}

/// The envelope with a typed spec: what validation and the schemas are generated from.
#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Typed<S> {
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: Option<S>,
    /// Written by controllers, never by `apply`.
    status: Option<Value>,
}

pub struct KindInfo {
    pub kind: &'static str,
    pub namespaced: bool,
    pub about: &'static str,
    from_node: fn(&Node) -> Result<Resource, kith_yaml::Error>,
    from_json: fn(Value) -> Result<Resource, String>,
    schema: fn() -> Value,
}

impl KindInfo {
    /// JSON Schema of a whole resource of this kind.
    pub fn schema(&self) -> Value {
        let mut schema = (self.schema)();
        schema["title"] = self.kind.into();
        schema["description"] = self.about.into();
        schema["properties"]["kind"] = serde_json::json!({ "const": self.kind });
        schema["properties"]["apiVersion"] = serde_json::json!({ "const": API_VERSION });
        schema
    }
}

macro_rules! kinds {
    ($($kind:ident: $spec:ty, $scope:ident, $about:literal;)*) => {
        pub const KINDS: &[KindInfo] = &[$(KindInfo {
            kind: stringify!($kind),
            namespaced: kinds!(@ $scope),
            about: $about,
            from_node: |node| finish::<$spec>(Some(node), kith_yaml::from_node(node)?),
            from_json: |json| {
                let typed = serde_json::from_value(json).map_err(|e| e.to_string())?;
                finish::<$spec>(None, typed).map_err(|e| e.msg)
            },
            schema: || schemars::schema_for!(Typed<$spec>).to_value(),
        },)*];
    };
    (@ namespaced) => { true };
    (@ cluster) => { false };
}

kinds! {
    Cluster: ClusterSpec, cluster, "Cluster-wide settings: domain, voter set, update policy, mesh settings";
    Node: NodeSpec, cluster, "One machine: roles, taints, OS version, system extensions, resource reservations";
    Namespace: NamespaceSpec, cluster, "Grouping, quotas, default policies";
    Workload: WorkloadSpec, namespaced, "Long-running replicas";
    NodeWorkload: NodeWorkloadSpec, namespaced, "Runs on every node matching a selector";
    Job: JobSpec, namespaced, "A run-to-completion task";
    CronJob: CronJobSpec, namespaced, "A scheduled task";
    Service: ServiceSpec, namespaced, "Stable name, load balancing and optional public exposure";
    DNSZone: DnsZoneSpec, cluster, "A domain kithd's DNS server answers for";
    DNSRecord: DnsRecordSpec, cluster, "Names in a DNSZone: A, AAAA, CNAME, TXT, SRV, NS, PTR";
    NetworkPolicy: NetworkPolicySpec, namespaced, "Allow or deny traffic between workloads, namespaces and nodes";
    Volume: VolumeSpec, namespaced, "Storage on a node, optionally shared over the mesh";
    VolumeClaim: VolumeClaimSpec, namespaced, "A request for storage";
    Blob: BlobSpec, namespaced, "Bytes named by their BLAKE3 hash, kept on several nodes";
    Backup: BackupSpec, namespaced, "A Volume archived on a schedule, to blobs or S3";
    Secret: SecretSpec, namespaced, "Secrets, delivered as files or env vars";
    ConfigMap: ConfigMapSpec, namespaced, "Configuration, delivered as files or env vars";
    Seat: SeatSpec, cluster, "A group of local display, input and audio devices on a node";
    Device: DeviceSpec, cluster, "A piece of hardware discovered on a node";
    DeviceClaim: DeviceClaimSpec, namespaced, "A workload's claim on a seat or device";
    Package: PackageSpec, cluster, "A versioned bundle of resource templates";
    Release: ReleaseSpec, namespaced, "An installed package with its values";
    Repository: RepositorySpec, cluster, "An OCI registry holding packages";
    Source: SourceSpec, namespaced, "GitOps: sync resources from a git repo or OCI artifact";
    OSRelease: OsReleaseSpec, cluster, "A signed kith OS image version";
    UpdatePlan: UpdatePlanSpec, cluster, "A rollout of an OSRelease across nodes";
    NodeKey: NodeKeySpec, cluster, "The wrapped key of a node's encrypted state";
    KindDefinition: KindDefinitionSpec, cluster, "Defines a new resource kind";
    Role: RoleSpec, cluster, "A set of permissions";
    RoleBinding: RoleBindingSpec, cluster, "Grants a role to identities";
    Identity: IdentitySpec, cluster, "A user, node or workload that can call the API";
}

/// Where kithd listens and `kith` connects: `$KITH_SOCKET`, else
/// `/run/kith/kithd.sock` for root, else `$XDG_RUNTIME_DIR/kith/kithd.sock`.
pub fn default_socket() -> Option<std::path::PathBuf> {
    let env = |name: &str| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from)
    };
    if let Some(path) = env("KITH_SOCKET") {
        return Some(path);
    }
    // Root has no XDG_RUNTIME_DIR under systemd's system manager.
    match env("XDG_RUNTIME_DIR") {
        Some(dir) => Some(dir.join("kith/kithd.sock")),
        None => std::fs::metadata("/run").ok().map(|_| "/run/kith/kithd.sock".into()),
    }
}

/// Look a kind up by name, ignoring case (`workload` finds `Workload`).
pub fn kind(name: &str) -> Option<&'static KindInfo> {
    KINDS.iter().find(|k| k.kind.eq_ignore_ascii_case(name))
}

/// Checks that need more than the shape, then the typed spec back to JSON.
/// `node` is the YAML the resource came from, used to point errors at the right place.
fn finish<S: Spec + Serialize + DeserializeOwned>(
    node: Option<&Node>,
    typed: Typed<S>,
) -> Result<Resource, kith_yaml::Error> {
    let err = |path: &[&str], msg: String| {
        let pos = node.map(|root| path.iter().try_fold(root, |n, key| n.get(key)).unwrap_or(root).pos);
        kith_yaml::Error { msg, pos }
    };
    let info = kind(&typed.kind).expect("finish is only reached through a KindInfo");

    if typed.api_version != API_VERSION {
        let msg = format!(
            "unsupported apiVersion `{}`, expected `{API_VERSION}`",
            typed.api_version
        );
        return Err(err(&["apiVersion"], msg));
    }
    let mut metadata = typed.metadata;
    check_name(&metadata.name).map_err(|msg| err(&["metadata", "name"], msg))?;
    match (&metadata.namespace, info.namespaced) {
        (Some(_), false) => {
            let msg = format!("{} is cluster-scoped and takes no namespace", info.kind);
            return Err(err(&["metadata", "namespace"], msg));
        }
        (Some(ns), true) => check_name(ns).map_err(|msg| err(&["metadata", "namespace"], msg))?,
        (None, true) => metadata.namespace = Some(DEFAULT_NAMESPACE.into()),
        (None, false) => {}
    }
    // A missing `spec` is fine for kinds with no required fields.
    let spec: S = match typed.spec {
        Some(spec) => spec,
        None => {
            serde_json::from_value(Value::Object(Default::default())).map_err(|e| err(&[], format!("spec: {e}")))?
        }
    };
    spec.check().map_err(|msg| err(&["spec"], msg))?;
    Ok(Resource {
        api_version: typed.api_version,
        kind: info.kind.into(),
        metadata,
        spec: serde_json::to_value(spec).expect("specs serialize to JSON"),
        status: typed.status,
    })
}

/// DNS-label-like, so names work in `<service>.<namespace>.kith`.
fn check_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.ends_with(|c: char| c.is_ascii_alphanumeric());
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid name `{name}`: use lowercase letters, digits, `-` and `.`, starting and ending with a letter or digit, at most 63 characters"
        ))
    }
}

impl Resource {
    /// Validate one parsed YAML document. Errors point into the source.
    pub fn from_node(node: &Node) -> Result<Resource, kith_yaml::Error> {
        let fail = |at: &Node, msg: String| Err(kith_yaml::Error { msg, pos: Some(at.pos) });
        let Some(kind_node) = node.get("kind") else {
            return fail(node, "missing field `kind`".into());
        };
        let name = kind_node.as_str().unwrap_or_default();
        let version = node.get("apiVersion").and_then(Node::as_str);
        match KINDS.iter().find(|k| k.kind == name) {
            Some(info) => (info.from_node)(node),
            // Not one of kith's own: a kind some KindDefinition makes, for the store to say.
            None if version.is_some_and(|version| version != API_VERSION) => {
                let typed: Typed<Value> = kith_yaml::from_node(node)?;
                let resource = Resource {
                    api_version: typed.api_version,
                    kind: typed.kind,
                    metadata: typed.metadata,
                    spec: typed.spec.unwrap_or_else(|| Value::Object(Default::default())),
                    status: typed.status,
                };
                resource.custom().or_else(|msg| fail(node, msg))
            }
            None => match kind(name) {
                Some(close) => fail(
                    kind_node,
                    format!("unknown kind `{name}`, did you mean `{}`?", close.kind),
                ),
                None => fail(
                    kind_node,
                    format!("unknown kind `{name}` (`kith schema` lists the kinds)"),
                ),
            },
        }
    }

    /// Validate every document in a YAML or JSON source.
    pub fn from_source(src: &str) -> Result<Vec<Result<Resource, kith_yaml::Error>>, kith_yaml::Error> {
        Ok(kith_yaml::parse(src)?.iter().map(Resource::from_node).collect())
    }

    /// Validate and normalise a resource that did not come from a file.
    pub fn validated(self) -> Result<Resource, String> {
        match KINDS.iter().find(|k| k.kind == self.kind) {
            Some(info) => (info.from_json)(serde_json::to_value(self).expect("resources serialize to JSON")),
            None if self.api_version != API_VERSION => self.custom(),
            None => Err(format!("unknown kind `{}`", self.kind)),
        }
    }

    /// What can be checked of a resource whose kind is not kith's own without the
    /// `KindDefinition` (the store has that, and checks the rest: see `Store::plan`).
    fn custom(self) -> Result<Resource, String> {
        kinds::kind_name(&self.kind)?;
        // (Nor one of kith's own in other capitals: commands would take it for kith's.)
        if let Some(own) = kind(&self.kind) {
            return Err(format!("unknown kind `{}`, did you mean `{}`?", self.kind, own.kind));
        }
        check_name(&self.metadata.name)?;
        self.metadata.namespace.as_deref().map_or(Ok(()), check_name)?;
        match self.spec.is_object() {
            true => Ok(self),
            false => Err("spec: must be a mapping".into()),
        }
    }

    /// `Kind/namespace/name`, or `Kind/name` for cluster-scoped kinds.
    pub fn key(&self) -> String {
        match &self.metadata.namespace {
            Some(ns) => format!("{}/{ns}/{}", self.kind, self.metadata.name),
            None => format!("{}/{}", self.kind, self.metadata.name),
        }
    }

    pub fn to_yaml(&self) -> String {
        kith_yaml::to_string(&serde_json::to_value(self).expect("resources serialize to JSON"))
    }
}

#[cfg(test)]
mod tests;
