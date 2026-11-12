//! Specs of the built-in kinds (PLAN.md §4.2).
//!
//! Kinds whose controllers arrive in later phases (seats, packages, updates,
//! access control) carry the fields the plan names and are expected to grow.
//! Unknown fields are always an error, so a typo never passes silently.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

type Labels = BTreeMap<String, String>;
/// Free-form values, e.g. for packages.
type Values = serde_json::Map<String, serde_json::Value>;

macro_rules! spec {
    ($($item:item)*) => {$(
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        $item
    )*};
}

/// An amount of CPU, memory or storage: `2`, `500m`, `2Gi`, `1.5G`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(extend("pattern" = r"^[0-9]+(\.[0-9]+)?(m|k|M|G|T|Ki|Mi|Gi|Ti)?$"))]
pub struct Quantity(String);

impl TryFrom<String> for Quantity {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        let number = s.trim_end_matches(|c: char| c.is_ascii_alphabetic());
        let unit_ok = ["", "m", "k", "M", "G", "T", "Ki", "Mi", "Gi", "Ti"].contains(&&s[number.len()..]);
        let mut parts = number.splitn(2, '.');
        let digits = |p: Option<&str>| p.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        let number_ok = digits(parts.next()) && (!number.contains('.') || digits(parts.next()));
        if unit_ok && number_ok {
            Ok(Quantity(s))
        } else {
            Err(format!("invalid quantity `{s}`: expected e.g. 2, 500m or 2Gi"))
        }
    }
}

impl Quantity {
    /// The amount as a plain number: `500m` is 0.5, `2Gi` is 2147483648.
    pub fn value(&self) -> f64 {
        let number = self.0.trim_end_matches(|c: char| c.is_ascii_alphabetic());
        let scale = match &self.0[number.len()..] {
            "m" => 1e-3,
            "k" => 1e3,
            "M" => 1e6,
            "G" => 1e9,
            "T" => 1e12,
            "Ki" => 1024.0,
            "Mi" => 1024.0 * 1024.0,
            "Gi" => 1024.0 * 1024.0 * 1024.0,
            "Ti" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
            _ => 1.0,
        };
        // Validated on the way in, so the number always parses.
        number.parse::<f64>().unwrap_or(0.0) * scale
    }
}

impl From<Quantity> for String {
    fn from(q: Quantity) -> String {
        q.0
    }
}

/// `{ weight: 50, node.labels.room: closet }`: a weight plus the labels it rewards.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct Preference {
    pub weight: u32,
    #[serde(flatten)]
    pub labels: Labels,
}

// Hand-written so label values stay strings (serde's `flatten` would coerce them).
impl<'de> Deserialize<'de> for Preference {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Preference;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map with `weight` and at least one label")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Preference, A::Error> {
                let (mut weight, mut labels) = (None, Labels::new());
                while let Some(key) = map.next_key::<String>()? {
                    if key == "weight" {
                        weight = Some(map.next_value()?);
                    } else {
                        labels.insert(key, map.next_value()?);
                    }
                }
                let weight = weight.ok_or_else(|| serde::de::Error::missing_field("weight"))?;
                if labels.is_empty() {
                    return Err(serde::de::Error::custom(
                        "a preference needs at least one label next to `weight`",
                    ));
                }
                Ok(Preference { weight, labels })
            }
        }
        d.deserialize_map(V)
    }
}

spec! {
    pub struct Resources {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cpu: Option<Quantity>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub memory: Option<Quantity>,
    }

    // ---- Cluster, Node, Namespace ----

    pub struct ClusterSpec {
        /// DNS domain for public names.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub domain: Option<String>,
        /// Names of the nodes that vote in Raft.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub voters: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub update_policy: Option<UpdatePolicy>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub mesh: Option<MeshSpec>,
        /// Cluster-wide package values.
        #[serde(default, skip_serializing_if = "Values::is_empty")]
        pub values: Values,
    }

    pub struct UpdatePolicy {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub channel: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub auto: Option<bool>,
        /// Maintenance windows, e.g. `Sat 02:00-05:00`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub windows: Vec<String>,
    }

    pub struct MeshSpec {
        /// IPv6 ULA prefix for mesh addresses.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cidr: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ipv4: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub port: Option<u16>,
    }

    pub struct NodeSpec {
        /// Defaults to `[worker]`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub roles: Vec<NodeRole>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub taints: Vec<Taint>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub os_version: Option<String>,
        /// System extensions layered on at boot.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub extensions: Vec<String>,
        /// Resources kept back from scheduled workloads.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub reserved: Option<Resources>,
        /// Cordoned: no new workloads are placed here.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub unschedulable: Option<bool>,
    }

    pub enum NodeRole { Voter, Worker, Edge }

    pub struct Taint {
        pub key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        pub effect: TaintEffect,
    }

    pub enum TaintEffect { NoSchedule, PreferNoSchedule, NoExecute }

    pub struct NamespaceSpec {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub quota: Option<Resources>,
        /// Namespace-wide package values.
        #[serde(default, skip_serializing_if = "Values::is_empty")]
        pub values: Values,
    }

    // ---- Workloads ----

    pub struct WorkloadSpec {
        /// Defaults to 1.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub replicas: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub strategy: Option<Strategy>,
        pub template: Template,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub placement: Option<Placement>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub priority_class: Option<String>,
    }

    pub enum Strategy { Rolling, Recreate, BlueGreen }

    /// The units one replica runs. `vm` and `wasm` units join in Phase 7.
    pub struct Template {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub containers: Vec<Container>,
        /// Plain supervised processes in a cgroup.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub exec: Vec<ExecUnit>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub restart_policy: Option<RestartPolicy>,
        /// Names of `DeviceClaim`s this replica holds.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub device_claims: Vec<String>,
    }

    pub enum RestartPolicy { Always, OnFailure, Never }

    pub struct Container {
        pub name: String,
        pub image: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub command: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub args: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub env: Vec<EnvVar>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub working_dir: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub resources: Option<Resources>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub ports: Vec<Port>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub volume_mounts: Vec<VolumeMount>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub liveness: Option<Probe>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub readiness: Option<Probe>,
    }

    pub struct ExecUnit {
        pub name: String,
        pub command: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub env: Vec<EnvVar>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub resources: Option<Resources>,
    }

    /// Exactly one of `value`, `secret` or `configMap`.
    pub struct EnvVar {
        pub name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub secret: Option<KeyRef>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub config_map: Option<KeyRef>,
    }

    pub struct KeyRef {
        pub name: String,
        pub key: String,
    }

    pub struct Port {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        pub port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub protocol: Option<Protocol>,
    }

    pub enum Protocol { Tcp, Udp }

    pub struct VolumeMount {
        pub volume: String,
        pub path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub read_only: Option<bool>,
    }

    /// Exactly one of `http`, `tcp` or `exec`.
    pub struct Probe {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub http: Option<HttpProbe>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tcp: Option<TcpProbe>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub exec: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub interval_seconds: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub timeout_seconds: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub failure_threshold: Option<u32>,
    }

    pub struct HttpProbe {
        pub path: String,
        pub port: PortRef,
    }

    pub struct TcpProbe {
        pub port: PortRef,
    }

    pub struct Placement {
        /// Every entry must match, e.g. `node.labels.disks: hdd`.
        #[serde(default, skip_serializing_if = "Labels::is_empty")]
        pub require: Labels,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub prefer: Vec<Preference>,
    }

    pub struct NodeWorkloadSpec {
        /// Node labels to match. Empty means every node.
        #[serde(default, skip_serializing_if = "Labels::is_empty")]
        pub selector: Labels,
        pub template: Template,
    }

    pub struct JobSpec {
        pub template: Template,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub completions: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub parallelism: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub retries: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub timeout_seconds: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub placement: Option<Placement>,
    }

    pub struct CronJobSpec {
        /// Five-field cron expression.
        pub schedule: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub timezone: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub concurrency: Option<Concurrency>,
        pub job: JobSpec,
    }

    pub enum Concurrency { Allow, Forbid, Replace }

    // ---- Networking ----

    pub struct ServiceSpec {
        /// Labels of the workloads behind this service.
        pub selector: Labels,
        pub ports: Vec<ServicePort>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expose: Option<Expose>,
    }

    pub struct ServicePort {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        pub port: u16,
        /// Defaults to `port`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub target_port: Option<PortRef>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub protocol: Option<Protocol>,
    }

    /// Public HTTPS through an edge node.
    pub struct Expose {
        pub host: String,
        pub via: ExposeVia,
    }

    pub enum ExposeVia { Edge }

    pub struct NetworkPolicySpec {
        /// Workloads the policy applies to. Empty means the whole namespace.
        #[serde(default, skip_serializing_if = "Labels::is_empty")]
        pub selector: Labels,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub ingress: Vec<PolicyRule>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub egress: Vec<PolicyRule>,
    }

    pub struct PolicyRule {
        pub action: PolicyAction,
        /// Empty means any peer.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub peers: Vec<Peer>,
        /// Empty means any port.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub ports: Vec<u16>,
    }

    pub enum PolicyAction { Allow, Deny }

    pub struct Peer {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub namespace: Option<String>,
        #[serde(default, skip_serializing_if = "Labels::is_empty")]
        pub selector: Labels,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub node: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cidr: Option<String>,
    }

    // ---- Storage and config ----

    pub struct VolumeSpec {
        /// The node holding the data.
        pub node: String,
        /// A local path, or a btrfs subvolume when `subvolume` is true.
        pub path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub subvolume: Option<bool>,
        /// Export over the mesh so any node can mount it.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub shared: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub size: Option<Quantity>,
    }

    pub struct VolumeClaimSpec {
        pub size: Quantity,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub shared: Option<bool>,
        /// Node labels the backing volume's node must have.
        #[serde(default, skip_serializing_if = "Labels::is_empty")]
        pub selector: Labels,
    }

    pub struct ConfigMapSpec {
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub data: BTreeMap<String, String>,
    }

    /// Encrypted at rest once the Raft store lands (§4.3); the Phase 0 local store is plain JSON.
    pub struct SecretSpec {
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub data: BTreeMap<String, String>,
    }

    // ---- Hardware (§4.6) ----

    pub struct SeatSpec {
        pub node: String,
        /// Names of the `Device`s grouped into this seat.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub devices: Vec<String>,
        /// Slice guaranteed to whatever holds the seat.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub reserve: Option<Resources>,
    }

    pub struct DeviceSpec {
        pub node: String,
        pub class: DeviceClass,
        /// Device node, e.g. `/dev/dri/card0`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
    }

    pub enum DeviceClass { Gpu, Display, Input, Audio, Usb, Camera, Other }

    /// Exactly one of `seat` or `device`, or a `selector` over device labels.
    pub struct DeviceClaimSpec {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub seat: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub device: Option<String>,
        #[serde(default, skip_serializing_if = "Labels::is_empty")]
        pub selector: Labels,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub access: Option<Access>,
    }

    pub enum Access { Exclusive, Shared }

    // ---- Packages and GitOps (§4.8, §4.9) ----

    pub struct PackageSpec {
        pub version: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// Semver range of kith versions the package supports.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub kith_version: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub dependencies: Vec<PackageRef>,
    }

    pub struct PackageRef {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub repo: Option<String>,
        pub name: String,
        /// Exact version or semver range.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
    }

    pub struct ReleaseSpec {
        pub package: PackageRef,
        #[serde(default, skip_serializing_if = "Values::is_empty")]
        pub values: Values,
        /// Follow the version range and upgrade automatically.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub auto_upgrade: Option<bool>,
    }

    pub struct RepositorySpec {
        /// OCI registry path, e.g. `oci://ghcr.io/example/packages`.
        pub url: String,
        /// Key the repository's packages must be signed with.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub public_key: Option<String>,
    }

    /// Exactly one of `git` or `oci`.
    pub struct SourceSpec {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub git: Option<GitSource>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub oci: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub interval_seconds: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub approval: Option<Approval>,
        /// Delete resources that are no longer in the source.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub prune: Option<bool>,
    }

    pub struct GitSource {
        pub url: String,
        /// Branch, tag or commit.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub rev: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub verify_signed_commits: Option<bool>,
    }

    pub enum Approval { Auto, Manual }

    // ---- Self-updates (§4.9) ----

    pub struct OsReleaseSpec {
        pub version: String,
        /// Where the signed image lives.
        pub image: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub digest: Option<String>,
    }

    pub struct UpdatePlanSpec {
        /// Name of the `OSRelease` to roll out.
        pub release: String,
        /// Node labels to match. Empty means every node.
        #[serde(default, skip_serializing_if = "Labels::is_empty")]
        pub selector: Labels,
        /// Nodes updated at a time. Defaults to 1.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub max_unavailable: Option<u32>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub windows: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub drain: Option<bool>,
        /// Hold back nodes with an active seat until it is idle.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub wait_for_idle_seats: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub paused: Option<bool>,
    }

    // ---- Extensibility and access (§4.10, §4.13) ----

    pub struct KindDefinitionSpec {
        pub group: String,
        pub version: String,
        pub kind: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub namespaced: Option<bool>,
        /// JSON Schema of the new kind's `spec`.
        pub schema: serde_json::Value,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub columns: Vec<Column>,
    }

    pub struct Column {
        pub name: String,
        /// Dotted path into the resource, e.g. `spec.replicas`.
        pub path: String,
    }

    pub struct RoleSpec {
        pub rules: Vec<AccessRule>,
    }

    pub struct AccessRule {
        /// Kind names, or `*`.
        pub kinds: Vec<String>,
        pub verbs: Vec<Verb>,
        /// Empty means every namespace.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub namespaces: Vec<String>,
    }

    pub enum Verb { Get, List, Watch, Apply, Delete, Exec }

    pub struct RoleBindingSpec {
        pub role: String,
        /// Names of `Identity` resources.
        pub subjects: Vec<String>,
    }

    pub struct IdentitySpec {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub public_key: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub groups: Vec<String>,
    }
}

/// A port by number or by name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum PortRef {
    Number(u16),
    Name(String),
}

/// Rules a spec must satisfy beyond its shape. Errors name the offending field.
pub trait Spec {
    fn check(&self) -> Result<(), String> {
        Ok(())
    }
}

macro_rules! no_checks {
    ($($spec:ty),* $(,)?) => { $(impl Spec for $spec {})* };
}

no_checks!(
    ClusterSpec,
    NodeSpec,
    NamespaceSpec,
    NetworkPolicySpec,
    VolumeSpec,
    VolumeClaimSpec,
    ConfigMapSpec,
    SecretSpec,
    SeatSpec,
    DeviceSpec,
    PackageSpec,
    ReleaseSpec,
    RepositorySpec,
    OsReleaseSpec,
    UpdatePlanSpec,
    KindDefinitionSpec,
    RoleSpec,
    RoleBindingSpec,
    IdentitySpec,
);

fn exactly_one(at: &str, options: &[(&str, bool)]) -> Result<(), String> {
    if options.iter().filter(|(_, set)| *set).count() == 1 {
        return Ok(());
    }
    let names: Vec<_> = options.iter().map(|(name, _)| format!("`{name}`")).collect();
    Err(format!("{at}: set exactly one of {}", names.join(", ")))
}

impl Template {
    fn check(&self, at: &str) -> Result<(), String> {
        if self.containers.is_empty() && self.exec.is_empty() {
            return Err(format!("{at}: needs at least one entry in `containers` or `exec`"));
        }
        let mut names = std::collections::BTreeSet::new();
        for name in self
            .containers
            .iter()
            .map(|c| &c.name)
            .chain(self.exec.iter().map(|e| &e.name))
        {
            if !names.insert(name) {
                return Err(format!("{at}: two units are named `{name}`"));
            }
        }
        let envs = self
            .containers
            .iter()
            .map(|c| (&c.name, &c.env))
            .chain(self.exec.iter().map(|e| (&e.name, &e.env)));
        for (unit, env) in envs {
            for var in env {
                exactly_one(
                    &format!("{at}, unit `{unit}`, env `{}`", var.name),
                    &[
                        ("value", var.value.is_some()),
                        ("secret", var.secret.is_some()),
                        ("configMap", var.config_map.is_some()),
                    ],
                )?;
            }
        }
        for c in &self.containers {
            for (which, probe) in [("liveness", &c.liveness), ("readiness", &c.readiness)] {
                if let Some(p) = probe {
                    exactly_one(
                        &format!("{at}, container `{}`, {which}", c.name),
                        &[
                            ("http", p.http.is_some()),
                            ("tcp", p.tcp.is_some()),
                            ("exec", p.exec.is_some()),
                        ],
                    )?;
                }
            }
        }
        Ok(())
    }
}

impl Spec for WorkloadSpec {
    fn check(&self) -> Result<(), String> {
        // ponytail: a typo guard, not a design limit; raise it when one Workload really needs more.
        if self.replicas.is_some_and(|n| n > 1000) {
            return Err("replicas: at most 1000".into());
        }
        self.template.check("template")
    }
}

impl Spec for NodeWorkloadSpec {
    fn check(&self) -> Result<(), String> {
        self.template.check("template")
    }
}

impl Spec for JobSpec {
    fn check(&self) -> Result<(), String> {
        self.template.check("template")
    }
}

impl Spec for CronJobSpec {
    fn check(&self) -> Result<(), String> {
        self.job.template.check("job.template")
    }
}

impl Spec for ServiceSpec {
    fn check(&self) -> Result<(), String> {
        if self.ports.is_empty() {
            Err("ports: needs at least one port".into())
        } else {
            Ok(())
        }
    }
}

impl Spec for DeviceClaimSpec {
    fn check(&self) -> Result<(), String> {
        exactly_one(
            "spec",
            &[
                ("seat", self.seat.is_some()),
                ("device", self.device.is_some()),
                ("selector", !self.selector.is_empty()),
            ],
        )
    }
}

impl Spec for SourceSpec {
    fn check(&self) -> Result<(), String> {
        exactly_one("spec", &[("git", self.git.is_some()), ("oci", self.oci.is_some())])
    }
}
