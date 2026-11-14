//! Specs of the built-in kinds (PLAN.md §4.2).
//!
//! `kith.dev/v1` is stable (`stable.rs`): a field is added, never taken away or narrowed.
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
        /// System extensions layered on at boot.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub extensions: Vec<String>,
        /// Resources kept back from scheduled workloads.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub reserved: Option<Resources>,
        /// Cordoned: no new workloads are placed here.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub unschedulable: Option<bool>,
        /// It comes and goes (a laptop): it does not start to vote, peers reach it wherever
        /// it last called from (they keep no address for it: it calls them), and what it runs
        /// is never started elsewhere, however long it is away. Take this off a node that is
        /// gone for good, or delete the node.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub roaming: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub mesh: Option<NodeMesh>,
    }

    pub enum NodeRole { Voter, Worker, Edge }

    pub struct NodeMesh {
        /// `never`: this node's traffic goes straight to the other node or not at all,
        /// never through an edge node (which would see it). Defaults to `auto`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub relay: Option<Relay>,
    }

    pub enum Relay { Auto, Never }

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
        /// The hosts only this namespace's Services expose: a name, or `*.example.org`
        /// for every name under one. A namespace that names any exposes no others.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub hosts: Vec<String>,
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

    /// The units one replica runs: containers, exec units and virtual machines.
    pub struct Template {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub containers: Vec<Container>,
        /// Plain supervised processes in a cgroup.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub exec: Vec<ExecUnit>,
        /// Virtual machines, each run by a hypervisor on the node.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub vms: Vec<VmUnit>,
        /// Run only where the processor keeps a guest's memory encrypted (AMD SEV-SNP or
        /// Intel TDX), and only as `vms`: a node that has neither refuses it.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub confidential: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub restart_policy: Option<RestartPolicy>,
        /// Names of `DeviceClaim`s this replica holds.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub device_claims: Vec<String>,
        /// Hold this replica back (a sliver of one CPU) while a seat of its node is busy.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub yield_to: Option<YieldTo>,
        /// Run each replica as Kubernetes runs a pod: its containers share a network of
        /// their own (any port is theirs, `localhost` is each other, and the replica has
        /// an address on the mesh), each may write its root file system unless it says
        /// `readOnlyRoot`, and each is the user its image names, root included (with what
        /// a container runtime gives root, and nothing of the node's). Where kithd is not
        /// root the replica shares the node's network.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub pod: Option<bool>,
    }

    pub struct YieldTo {
        /// Name of the `Seat`.
        pub seat: String,
        /// What the seat is doing while this is held back, e.g. `[fullscreen]`.
        pub when: Vec<Activity>,
    }

    /// What a session says its seat is doing; a seat that says nothing is idle.
    pub enum Activity { Active, Idle, Fullscreen }

    pub enum RestartPolicy { Always, OnFailure, Never }

    pub struct Container {
        pub name: String,
        pub image: String,
        /// Public keys, one of which the image must be signed by, as `cosign sign --key`
        /// signs: each a PEM file's text or the base64 in it (ECDSA P-256 or Ed25519).
        /// With none, an image is run whoever made it.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub signed_by: Vec<String>,
        /// When to ask the registry what `image` points at. Defaults to `ifNotPresent`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub pull_policy: Option<PullPolicy>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub command: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub args: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub env: Vec<EnvVar>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub working_dir: Option<String>,
        /// The user (and group) its process is, by number. Without it: the image's own
        /// user, or 65534 where the image names none or names 0. `0` is root: of the
        /// container's user namespace where kithd is not root, of the node where it is.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub run_as_user: Option<u32>,
        /// `false`: its root file system is its own to write (what it writes is not the
        /// image's, and goes when the container does). `true`: only volumes, /tmp and
        /// /run are. Without it: `true`, or in a `pod` `false`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub read_only_root: Option<bool>,
        /// What the filter on its system calls lets through that it refuses by default.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub seccomp: Option<Seccomp>,
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

    /// `ifNotPresent` never notices a tag that moved at the registry.
    pub enum PullPolicy { IfNotPresent, Always, Never }

    pub struct ExecUnit {
        pub name: String,
        pub command: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub env: Vec<EnvVar>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub resources: Option<Resources>,
    }

    /// A virtual machine. It starts `kernel` if there is one, or else what its firmware
    /// finds on `disks`. Each PCI Device a DeviceClaim of the replica holds is passed
    /// through to it (VFIO).
    pub struct VmUnit {
        pub name: String,
        /// What runs it [default: qemu].
        #[serde(skip_serializing_if = "Option::is_none")]
        pub hypervisor: Option<Hypervisor>,
        /// A kernel on the node, by absolute path.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub kernel: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub initrd: Option<String>,
        /// The kernel's command line.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cmdline: Option<String>,
        /// A firmware image on the node (UEFI), for a machine that starts from a disk.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub firmware: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub disks: Vec<VmDisk>,
        /// [default: 1]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cpus: Option<u32>,
        /// The machine's memory (`2Gi`).
        pub memory: Quantity,
        /// What the hypervisor's process is held to on the node.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub resources: Option<Resources>,
    }

    pub enum Hypervisor { Qemu, CloudHypervisor }

    pub struct VmDisk {
        /// A raw disk image on the node, by absolute path.
        pub path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub read_only: Option<bool>,
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

    /// A container's system calls go through a filter that refuses the ones in
    /// [`REFUSED_CALLS`]. `allow` names those it may make after all;
    /// `unconfined: true` is no filter.
    pub struct Seccomp {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub unconfined: Option<bool>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub allow: Vec<String>,
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
        /// Send the backend a PROXY protocol v1 line with the client's address before the
        /// client's bytes. Off unless true: a backend that does not expect the line breaks.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub proxy_protocol: Option<bool>,
    }

    pub enum ExposeVia { Edge }

    // ---- DNS ----

    /// A domain kithd answers for itself instead of asking upstream.
    pub struct DnsZoneSpec {
        /// The domain, like `home.example`.
        pub domain: String,
        /// Seconds a resolver may keep an answer, unless a record says otherwise. Defaults to 300.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ttl: Option<u32>,
        /// Split horizon: only clients in these networks (`192.168.0.0/16`, `fd00::/8`,
        /// or one address) get this zone's answers. Empty: everyone does.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub clients: Vec<String>,
    }

    pub struct DnsRecordSpec {
        /// Name of the `DNSZone` the record is in.
        pub zone: String,
        /// The name inside the zone: `nas`, `*.apps`, or `@` for the zone itself.
        pub name: String,
        #[serde(rename = "type")]
        pub record_type: DnsRecordType,
        /// One record per value. `SRV`: `priority weight port target`.
        pub values: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ttl: Option<u32>,
    }

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
        /// Keep this many copies in all, the others on other nodes, one of which takes
        /// over when the volume's node is lost.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub replicas: Option<u32>,
        /// How often the other copies are brought up to date [default: 5m].
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sync: Option<String>,
        /// Keep it encrypted on its node's disk (dm-crypt), the key held by the cluster's
        /// other nodes: needs a `size`, which it has from the start. Set when it is made.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub encrypted: Option<bool>,
    }

    /// Bytes kept by content: a Blob's name is the first 62 hex digits of their BLAKE3
    /// hash, and `kith blob put` makes it.
    pub struct BlobSpec {
        /// How many bytes.
        pub size: u64,
        /// How many nodes keep a copy [default: 2].
        #[serde(skip_serializing_if = "Option::is_none")]
        pub copies: Option<u32>,
    }

    /// A container image made in the cluster: a Volume's directory, packed by the volume's
    /// node as the image's one layer and kept as Blobs. Every node serves it to itself as
    /// `localhost:PORT/NAMESPACE/NAME:TAG`.
    pub struct ImageSpec {
        /// The Volume, in this namespace, whose directory is the image's root.
        pub volume: String,
        /// [default: latest] Made once for a spec: a new tag is a new image.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tag: Option<String>,
        /// A Job, in this namespace, that fills the volume: the image is made when it has succeeded.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub job: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub entrypoint: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub cmd: Vec<String>,
        /// `NAME=value` entries.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub env: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub working_dir: Option<String>,
        /// How many nodes keep the image's blobs [default: 2].
        #[serde(skip_serializing_if = "Option::is_none")]
        pub copies: Option<u32>,
    }

    /// A Volume's directory as an archive, made every so often by the volume's node and
    /// kept as a blob (on other nodes too) or in an S3 bucket.
    pub struct BackupSpec {
        /// The Volume, in this namespace.
        pub volume: String,
        /// How often: a number and `s`, `m`, `h` or `d` (`24h`).
        pub every: String,
        /// How many are kept [default: 7].
        #[serde(skip_serializing_if = "Option::is_none")]
        pub keep: Option<u32>,
        /// How many nodes keep each backup's blob [default: 2].
        #[serde(skip_serializing_if = "Option::is_none")]
        pub copies: Option<u32>,
        /// Send them to an S3-compatible bucket instead of the cluster's blob store.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub s3: Option<S3>,
    }

    pub struct S3 {
        /// `https://host[:port]`; objects are `endpoint/bucket/prefix…` (path style).
        pub endpoint: String,
        pub bucket: String,
        /// [default: us-east-1]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub region: Option<String>,
        /// Put before each object's name (`backups/`).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub prefix: Option<String>,
        /// The Secret, in this namespace, with `accessKey` and `secretKey`.
        pub secret: String,
    }

    /// A Volume given to machines that are not nodes: over NFS by the volume's node, and
    /// over SMB by the `nas` package's file server.
    pub struct ShareSpec {
        /// The Volume, in this namespace.
        pub volume: String,
        /// Nobody may write.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub read_only: Option<bool>,
        /// Whoever uses the share is this user on the volume's files [default: 65534, nobody].
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uid: Option<u32>,
        /// [default: 65534]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub gid: Option<u32>,
        /// Serve it over NFS 4.2 from the volume's node.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub nfs: Option<ShareNfs>,
        /// The Identities that may use it over SMB.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub users: Vec<String>,
    }

    pub struct ShareNfs {
        /// Who may mount it: IPv4 addresses (`192.168.1.20`) or ranges (`192.168.1.0/24`).
        pub clients: Vec<String>,
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

    /// Kept in the store as it is given: on a node's disk it is as safe as the node's state.
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
        /// The package itself: its files by path (`package.yaml`, `templates/web.yaml`),
        /// as `kith package push` puts them here.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub files: BTreeMap<String, String>,
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
        /// With `approval: manual`: the revision that may be applied (the one in
        /// `status.pending`, as `kith source approve` puts here).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub approve: Option<String>,
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
        /// URL of the signed update file.
        pub image: String,
        /// The signing key (hex); required.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub public_key: Option<String>,
        /// Its signature of the file's header.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub signature: Option<String>,
        /// The keys a node takes releases from once it runs this one.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub handover: Option<Handover>,
    }

    /// A release key handing over to others (`sh os/update.sh --handover`).
    pub struct Handover {
        /// The public keys (hex) that count from this release on: 1 to 8, the
        /// release's own among them if it is to go on counting.
        pub keys: Vec<String>,
        /// The release's key's signature of the handover.
        pub signature: String,
        /// The same, by one of `keys`: someone holds a key that is handed to.
        pub proof: String,
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
        /// Let nodes take a release older than the one they run. Refused otherwise.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub allow_downgrade: Option<bool>,
    }

    // ---- Encrypted state ----

    /// The key of a node's encrypted state partition, as the cluster holds it: wrapped
    /// with a secret that only the node's disk has. Written by the node itself.
    pub struct NodeKeySpec {
        /// What the node asks for it by: made from its disk's secret.
        pub id: String,
        /// The key, wrapped (hex). Empty once wiped.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub wrapped: String,
        /// Not handed out while set: the node waits at its next start (`kith node lock`).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub locked: Option<bool>,
        /// Forgotten for good (`kith node wipe`).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub wiped: Option<bool>,
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
        /// Run by kithd for each resource of the kind: says what should exist because
        /// of it, and its status.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub controller: Option<WasmModule>,
        /// Run by kithd before a resource of the kind is written: lets it be, changes
        /// it or refuses it.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub admission: Option<WasmModule>,
    }

    pub struct WasmModule {
        /// The WebAssembly module, base64 (`kith controller set` puts a file here).
        pub wasm: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Txt,
    Srv,
    Ns,
    Ptr,
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
    BlobSpec,
    ClusterSpec,
    NodeSpec,
    NetworkPolicySpec,
    VolumeClaimSpec,
    ConfigMapSpec,
    SecretSpec,
    SeatSpec,
    DeviceSpec,
    PackageSpec,
    ReleaseSpec,
    RepositorySpec,
    UpdatePlanSpec,
    NodeKeySpec,
    RoleSpec,
    RoleBindingSpec,
    IdentitySpec,
);

/// A kind's name: letters and digits, a capital first (`GameServer`).
pub(crate) fn kind_name(name: &str) -> Result<(), String> {
    let fine = name.len() <= 63
        && name.starts_with(|c: char| c.is_ascii_uppercase())
        && name.bytes().all(|b| b.is_ascii_alphanumeric());
    match fine {
        true => Ok(()),
        false => Err(format!(
            "invalid kind `{name}`: letters and digits, a capital first, at most 63"
        )),
    }
}

/// `90s`, `30m`, `24h`, `7d` in seconds.
pub fn every(text: &str) -> Option<u64> {
    let unit = text.chars().next_back()?;
    let number = &text[..text.len() - unit.len_utf8()];
    let unit = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return None,
    };
    let digits = number.bytes().all(|b| b.is_ascii_digit());
    number
        .parse::<u64>()
        .ok()
        .filter(|n| digits && *n > 0)?
        .checked_mul(unit)
}

/// The system calls a container's filter refuses, by the names `seccomp.allow` takes.
/// (`clone` only when it makes a namespace; `clone3` as a kernel without it answers.)
pub const REFUSED_CALLS: &[&str] = &[
    "mount",
    "umount2",
    "pivot_root",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "mount_setattr",
    "open_by_handle_at",
    "unshare",
    "setns",
    "clone",
    "clone3",
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "reboot",
    "swapon",
    "swapoff",
    "acct",
    "settimeofday",
    "clock_settime",
    "bpf",
    "perf_event_open",
    "userfaultfd",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "add_key",
    "request_key",
    "keyctl",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
    "pidfd_getfd",
];

/// The smallest encrypted Volume, in bytes: the file system each starts as.
pub const ENCRYPTED_LEAST: u64 = 8 << 20;

impl Spec for VolumeSpec {
    fn check(&self) -> Result<(), String> {
        if self.replicas == Some(0) {
            return Err("replicas: at least 1 (the volume itself)".into());
        }
        if self.encrypted == Some(true) {
            // (The file system it starts as is this big: crates/kithd/src/encrypted.rs.)
            if self
                .size
                .as_ref()
                .is_none_or(|size| size.value() < ENCRYPTED_LEAST as f64)
            {
                return Err("encrypted: needs a `size` of at least 8Mi".into());
            }
            // ponytail: the nodes that mount a shared one, or keep a copy, would each need the
            // key and a file system of their own under it.
            if self.shared == Some(true) || self.replicas.is_some_and(|replicas| replicas > 1) {
                return Err("encrypted: a volume that is shared or has replicas cannot be encrypted yet".into());
            }
        }
        match &self.sync {
            Some(sync) if every(sync).is_none() => {
                Err(format!("sync: `{sync}` is not a number and s, m, h or d (`5m`)"))
            }
            // (Each sync reads the whole volume on its node.)
            Some(sync) if every(sync) < Some(10) => Err(format!("sync: `{sync}` is under 10s")),
            _ => Ok(()),
        }
    }
}

/// An IPv4 address or range a Share's NFS clients are in, as (network, prefix length).
pub fn share_client(text: &str) -> Option<(std::net::Ipv4Addr, u32)> {
    let (address, length) = text.split_once('/').unwrap_or((text, "32"));
    let plain = length.bytes().all(|b| b.is_ascii_digit());
    let length = length.parse().ok().filter(|length| plain && *length <= 32)?;
    Some((address.parse().ok()?, length))
}

impl Spec for ShareSpec {
    fn check(&self) -> Result<(), String> {
        let clients = self.nfs.as_ref().map(|nfs| nfs.clients.as_slice());
        // (An Identity's name, and nothing a file server's own files would read as more.)
        let plain =
            |user: &&String| !user.is_empty() && user.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b));
        if let Some(user) = self.users.iter().find(|user| !plain(user)) {
            return Err(format!("users: `{user}` is not an Identity's name"));
        }
        for client in clients.unwrap_or_default() {
            match share_client(client) {
                None => return Err(format!("nfs.clients: `{client}` is not an IPv4 address or range")),
                // (A range that is most of the internet is a slip, not a LAN.)
                Some((_, length)) if length < 8 => return Err(format!("nfs.clients: `{client}` is wider than a /8")),
                Some(_) => {}
            }
        }
        Ok(())
    }
}

impl ImageSpec {
    /// The tag it is served under.
    pub fn tag(&self) -> &str {
        self.tag.as_deref().unwrap_or("latest")
    }
}

impl Spec for ImageSpec {
    fn check(&self) -> Result<(), String> {
        // (A tag as registries have them: it is part of a URL's path.)
        let tag = self.tag();
        let plain = |b: u8| b.is_ascii_alphanumeric() || b"._-".contains(&b);
        if tag.is_empty() || tag.len() > 128 || !tag.bytes().all(plain) || tag.starts_with(['.', '-']) {
            return Err(format!("tag: `{tag}` is not a tag (letters, digits, `.`, `_`, `-`)"));
        }
        if let Some(bad) = self
            .env
            .iter()
            .find(|entry| !entry.split_once('=').is_some_and(|(name, _)| !name.is_empty()))
        {
            return Err(format!("env: `{bad}` is not NAME=value"));
        }
        if self.working_dir.as_ref().is_some_and(|dir| !dir.starts_with('/')) {
            return Err("workingDir: an absolute path".into());
        }
        Ok(())
    }
}

impl Spec for BackupSpec {
    fn check(&self) -> Result<(), String> {
        if every(&self.every).is_none() {
            return Err(format!(
                "every: `{}` is not a number and s, m, h or d (`24h`)",
                self.every
            ));
        }
        let Some(s3) = &self.s3 else { return Ok(()) };
        // (What is in a URL's path as it is written, and signed as it is written.)
        let plain = |text: &str| text.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._/".contains(&b));
        if s3.bucket.is_empty() || s3.bucket.contains('/') || !plain(&s3.bucket) {
            return Err(format!("s3.bucket: `{}` is not a bucket's name", s3.bucket));
        }
        if !plain(s3.prefix.as_deref().unwrap_or_default()) {
            return Err("s3.prefix: use letters, digits, `-`, `.`, `_` and `/`".into());
        }
        if !s3.endpoint.starts_with("https://") {
            return Err(format!("s3.endpoint: `{}` must start with https://", s3.endpoint));
        }
        Ok(())
    }
}

impl Spec for KindDefinitionSpec {
    fn check(&self) -> Result<(), String> {
        kind_name(&self.kind).map_err(|e| format!("kind: {e}"))?;
        if let Some(own) = crate::kind(&self.kind) {
            return Err(format!("kind: `{}` is one of kith's own kinds", own.kind));
        }
        // The role resource `Audit` is what lets a role read the audit log: a kind of that
        // name would be granted it.
        if self.kind.eq_ignore_ascii_case("Audit") {
            return Err(format!("kind: `{}` is reserved for the audit log", self.kind));
        }
        let own = self.group == "kith.dev" || self.group.ends_with(".kith.dev");
        if own || !self.group.contains('.') || !dns_name(&self.group) || self.group != self.group.to_ascii_lowercase() {
            return Err(format!(
                "group: `{}` must be a domain name of yours, in lowercase (not kith.dev)",
                self.group
            ));
        }
        let digits = self.version.strip_prefix('v').unwrap_or_default();
        let (number, stage) = digits.split_at(digits.bytes().take_while(u8::is_ascii_digit).count());
        if number.is_empty() || !stage.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
            return Err(format!("version: `{}` must be like v1 or v1beta1", self.version));
        }
        let mut wrong = Vec::new();
        if !self.schema.is_object() {
            wrong.push("schema: must be a mapping".to_string());
        }
        crate::schema::unknown_keywords(&self.schema, "schema", &mut wrong);
        for column in &self.columns {
            let part = |part: &str| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            };
            if column.name.is_empty() || !column.path.split('.').all(part) {
                wrong.push(format!(
                    "columns: `{}` needs a name and a dotted path like spec.size",
                    column.name
                ));
            }
        }
        for (role, module) in [("controller", &self.controller), ("admission", &self.admission)] {
            // (kithd reads the module itself when it is applied there; a store file is only asked for the shape.)
            let base64 = |b: u8| b.is_ascii_alphanumeric() || b"+/=".contains(&b);
            let text = module.as_ref().map(|module| module.wasm.as_str());
            if text.is_some_and(|text| text.is_empty() || !text.bytes().all(base64)) {
                wrong.push(format!("{role}.wasm: must be a WebAssembly module in base64"));
            }
            if text.is_some_and(|text| text.len() > WASM_LIMIT.div_ceil(3) * 4) {
                wrong.push(format!("{role}.wasm: a module is {WASM_LIMIT} bytes at most"));
            }
        }
        match wrong.is_empty() {
            true => Ok(()),
            false => Err(wrong.join("; ")),
        }
    }
}

/// The largest WebAssembly module a `KindDefinition` carries, in bytes.
pub const WASM_LIMIT: usize = 1 << 20;

fn exactly_one(at: &str, options: &[(&str, bool)]) -> Result<(), String> {
    if options.iter().filter(|(_, set)| *set).count() == 1 {
        return Ok(());
    }
    let names: Vec<_> = options.iter().map(|(name, _)| format!("`{name}`")).collect();
    Err(format!("{at}: set exactly one of {}", names.join(", ")))
}

impl VmUnit {
    fn check(&self) -> Result<(), String> {
        if self.kernel.is_none() && self.disks.is_empty() {
            return Err("it has nothing to start: name a `kernel` or `disks`".into());
        }
        if (self.initrd.is_some() || self.cmdline.is_some()) && self.kernel.is_none() {
            return Err("`initrd` and `cmdline` are a `kernel`'s".into());
        }
        // (A comma ends a value in a hypervisor's options.)
        let paths = [
            ("kernel", &self.kernel),
            ("initrd", &self.initrd),
            ("firmware", &self.firmware),
        ];
        let paths = paths
            .into_iter()
            .filter_map(|(field, path)| Some((field, path.as_deref()?)));
        let disks = self.disks.iter().map(|disk| ("disks", disk.path.as_str()));
        for (field, path) in paths.chain(disks) {
            if !path.starts_with('/') || path.contains(',') || path.chars().any(char::is_control) {
                return Err(format!(
                    "{field}: `{path}` must be an absolute path with no comma in it"
                ));
            }
        }
        if self
            .cmdline
            .as_deref()
            .is_some_and(|line| line.chars().any(char::is_control))
        {
            return Err("cmdline: one line".into());
        }
        if !(1..=512).contains(&self.cpus.unwrap_or(1)) {
            return Err("cpus: 1 to 512".into());
        }
        if self.memory.value() < f64::from(1 << 24) {
            return Err("memory: at least 16Mi".into());
        }
        Ok(())
    }
}

impl Template {
    /// The names of its units, in the order they are numbered: containers, exec units, VMs.
    pub fn units(&self) -> impl Iterator<Item = &String> {
        let containers = self.containers.iter().map(|c| &c.name);
        let exec = self.exec.iter().map(|e| &e.name);
        containers.chain(exec).chain(self.vms.iter().map(|vm| &vm.name))
    }

    fn check(&self, at: &str) -> Result<(), String> {
        if self.containers.is_empty() && self.exec.is_empty() && self.vms.is_empty() {
            return Err(format!(
                "{at}: needs at least one entry in `containers`, `exec` or `vms`"
            ));
        }
        for vm in &self.vms {
            vm.check().map_err(|e| format!("{at}, vm `{}`: {e}", vm.name))?;
        }
        if self.confidential == Some(true) {
            if !self.containers.is_empty() || !self.exec.is_empty() {
                return Err(format!(
                    "{at}: confidential: only `vms` (a container or an exec unit runs with its memory in the clear)"
                ));
            }
            // ponytail: QEMU's options alone are known here, and both SEV-SNP and TDX start a
            // guest through firmware that is part of what is measured.
            let plain = |vm: &&VmUnit| vm.firmware.is_none() || !matches!(vm.hypervisor, None | Some(Hypervisor::Qemu));
            if let Some(vm) = self.vms.iter().find(plain) {
                return Err(format!(
                    "{at}, vm `{}`: confidential: needs a `firmware` and QEMU as its hypervisor",
                    vm.name
                ));
            }
        }
        let mut names = std::collections::BTreeSet::new();
        for name in self.units() {
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
            if c.run_as_user == Some(u32::MAX) {
                return Err(format!(
                    "{at}, container `{}`: runAsUser: {} is no user",
                    c.name,
                    u32::MAX
                ));
            }
            if c.signed_by.len() > 16 {
                return Err(format!("{at}, container `{}`: signedBy: at most 16 keys", c.name));
            }
            for key in &c.signed_by {
                // The two kinds of key there are start their files the same way each: told
                // here by that and their length, and read in full by the node that pulls.
                let lines = key.lines().filter(|line| !line.trim_start().starts_with("-----"));
                let text: String = lines.flat_map(str::chars).filter(|c| !c.is_whitespace()).collect();
                let kinds = [("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE", 124), ("MCowBQYDK2VwAyEA", 60)];
                if !kinds
                    .iter()
                    .any(|(start, len)| text.starts_with(start) && text.len() == *len)
                {
                    let shown: String = key.trim().chars().take(40).collect();
                    return Err(format!(
                        "{at}, container `{}`: signedBy: `{shown}` is not a public key kith can check: an ECDSA P-256 or Ed25519 key, as its PEM file's text or the base64 in it",
                        c.name
                    ));
                }
            }
            let allowed = c.seccomp.iter().flat_map(|seccomp| &seccomp.allow);
            if let Some(unknown) = allowed.clone().find(|name| !REFUSED_CALLS.contains(&name.as_str())) {
                return Err(format!(
                    "{at}, container `{}`: seccomp: `{unknown}` is not a call the filter refuses (it refuses: {})",
                    c.name,
                    REFUSED_CALLS.join(", ")
                ));
            }
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
        // (A copy on every node, a device on one.)
        if !self.template.device_claims.is_empty() {
            return Err("template.deviceClaims: a NodeWorkload cannot hold DeviceClaims (use a Workload)".into());
        }
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
            return Err("ports: needs at least one port".into());
        }
        // (The host is asked for in TLS, named in a Secret and in DNS: a name, not a URL.)
        match &self.expose {
            Some(expose) if !dns_name(&expose.host) => Err(format!(
                "expose.host: `{}` is not a domain name like `shop.example.org`",
                expose.host
            )),
            Some(expose) => expose_host_refused(&expose.host).map_or(Ok(()), Err),
            None => Ok(()),
        }
    }
}

impl Spec for NamespaceSpec {
    fn check(&self) -> Result<(), String> {
        for host in &self.hosts {
            let name = host.strip_prefix("*.").unwrap_or(host);
            if !dns_name(name) {
                return Err(format!(
                    "hosts: `{host}` is not a domain name like `shop.example.org`, or `*.example.org` for every name \
                     under one"
                ));
            }
            if let Some(refused) = expose_host_refused(name) {
                return Err(format!("hosts: {refused}"));
            }
        }
        Ok(())
    }
}

impl NamespaceSpec {
    /// Is `host` (in lower case) one of this namespace's own?
    pub fn keeps(&self, host: &str) -> bool {
        self.hosts.iter().any(|kept| {
            let kept = kept.to_ascii_lowercase();
            match kept.strip_prefix("*.") {
                Some(domain) => host.strip_suffix(domain).is_some_and(|under| under.ends_with('.')),
                None => kept == host,
            }
        })
    }
}

/// Why a certificate authority would not issue for `host` (a name that passes
/// `dns_name`), if it would not: an IP address (a last label of digits only, which no
/// top-level domain is), a label that starts or ends with `-`, or a `_` anywhere.
pub fn expose_host_refused(host: &str) -> Option<String> {
    let numeric = |label: &str| !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit());
    let dashed = |label: &str| label.starts_with('-') || label.ends_with('-');
    let why = if host.rsplit('.').next().is_some_and(numeric) {
        "an IP address (or a number), not a name"
    } else if host.split('.').any(dashed) {
        "a label that starts or ends with `-`"
    } else if host.contains('_') {
        "a name with `_` in it"
    } else {
        return None;
    };
    Some(format!(
        "expose.host: `{host}` is {why}: no certificate authority issues for it"
    ))
}

/// Is `name` a domain name: labels of letters, digits, `-` and `_`, at most 63 long, 253 in all?
fn dns_name(name: &str) -> bool {
    let label =
        |l: &str| (1..=63).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    name.len() <= 253 && name.split('.').all(label)
}

impl Spec for DnsZoneSpec {
    fn check(&self) -> Result<(), String> {
        if !dns_name(&self.domain) {
            return Err(format!(
                "domain: `{}` is not a domain name like `home.example`",
                self.domain
            ));
        }
        // Room for the names the server adds in front (`hostmaster.`).
        if self.domain.len() > 240 {
            return Err("domain: longer than 240 characters".into());
        }
        let domain = self.domain.to_ascii_lowercase();
        if domain == "kith" || domain.ends_with(".kith") {
            return Err("domain: names under `kith` are the cluster's own".into());
        }
        for net in &self.clients {
            let (address, bits) = net.split_once('/').map_or((net.as_str(), None), |(a, b)| (a, Some(b)));
            let max = match address.parse::<std::net::IpAddr>() {
                Ok(address) if address.is_ipv4() => 32,
                Ok(_) => 128,
                Err(_) => return Err(format!("clients: `{net}` is not a network like `192.168.0.0/16`")),
            };
            if bits.is_some_and(|bits| !bits.parse::<u8>().is_ok_and(|bits| bits <= max)) {
                return Err(format!("clients: `{net}` has a prefix length that is not 0 to {max}"));
            }
        }
        Ok(())
    }
}

impl DnsRecordSpec {
    /// `SRV` values, taken apart: priority, weight, port, target.
    pub fn srv(value: &str) -> Option<(u16, u16, u16, &str)> {
        let mut parts = value.split_ascii_whitespace();
        let mut number = || parts.next()?.parse().ok();
        let numbers = (number()?, number()?, number()?);
        let target = parts.next().filter(|target| dns_name(target.trim_end_matches('.')))?;
        parts
            .next()
            .is_none()
            .then_some((numbers.0, numbers.1, numbers.2, target))
    }
}

impl Spec for DnsRecordSpec {
    fn check(&self) -> Result<(), String> {
        let host = self.name.strip_prefix("*.").unwrap_or(&self.name);
        if !(["@", "*"].contains(&self.name.as_str()) || dns_name(host)) {
            return Err(format!(
                "name: `{}` is not a name like `nas`, `*.apps` or `@`",
                self.name
            ));
        }
        // ponytail: a typo guard and what one DNS answer comfortably carries.
        if self.values.is_empty() || self.values.len() > 100 {
            return Err("values: needs 1 to 100 values".into());
        }
        use DnsRecordType::*;
        if self.record_type == Cname && (self.values.len() > 1 || self.name == "@") {
            return Err("a CNAME has one value, and cannot be the zone itself (`@`)".into());
        }
        for value in &self.values {
            let name = || dns_name(value.trim_end_matches('.'));
            let (ok, want) = match self.record_type {
                A => (value.parse::<std::net::Ipv4Addr>().is_ok(), "an IPv4 address"),
                Aaaa => (value.parse::<std::net::Ipv6Addr>().is_ok(), "an IPv6 address"),
                Cname | Ns | Ptr => (name(), "a domain name"),
                Srv => (Self::srv(value).is_some(), "`priority weight port target`"),
                Txt => (value.len() <= 4000, "at most 4000 bytes"),
            };
            if !ok {
                return Err(format!("values: `{value}` is not {want}"));
            }
        }
        Ok(())
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

impl Spec for OsReleaseSpec {
    fn check(&self) -> Result<(), String> {
        let Some(handover) = &self.handover else {
            return Ok(());
        };
        let hex = |text: &str, digits: usize| text.len() == digits && text.bytes().all(|b| b.is_ascii_hexdigit());
        if handover.keys.is_empty() || handover.keys.len() > 8 {
            return Err(format!(
                "handover.keys: a handover is to 1 to 8 keys, not {}",
                handover.keys.len()
            ));
        }
        if let Some(key) = handover.keys.iter().find(|key| !hex(key, 64)) {
            return Err(format!(
                "handover.keys: `{key}` is not a public key (64 hex digits, as `kith package keygen` prints it)"
            ));
        }
        for (name, signature) in [("signature", &handover.signature), ("proof", &handover.proof)] {
            if !hex(signature, 128) {
                return Err(format!(
                    "handover: `{name}` is not a signature (128 hex digits, as `sh os/update.sh --handover` prints it)"
                ));
            }
        }
        Ok(())
    }
}

impl Spec for SourceSpec {
    fn check(&self) -> Result<(), String> {
        exactly_one("spec", &[("git", self.git.is_some()), ("oci", self.oci.is_some())])
    }
}
