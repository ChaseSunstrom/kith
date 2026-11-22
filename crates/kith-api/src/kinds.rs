//! Specs of the built-in kinds (PLAN.md §4.2).
//!
//! `kith.dev/v1` is stable (`stable.rs`): a field is added, never taken away or narrowed.
//! Unknown fields are always an error, so a typo never passes silently.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

type Labels = BTreeMap<String, String>;
/// Free-form values, e.g. for packages.
type Values = serde_json::Map<String, serde_json::Value>;

macro_rules! spec {
    ($($item:item)*) => {$(
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[cfg_attr(feature = "generate", derive(schemars::JsonSchema))]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        $item
    )*};
}

/// One an image may be signed by: a public key's text, or an identity that signed without a
/// kept key (cosign's default). docs/adr-keyless.md says what is checked.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "generate", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum Signer {
    Key(String),
    Identity(Identity),
}

// (Not serde's untagged reading: it says only that nothing matched, not what is wrong.)
impl<'de> Deserialize<'de> for Signer {
    fn deserialize<D: serde::Deserializer<'de>>(reader: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        match serde_json::Value::deserialize(reader)? {
            serde_json::Value::String(key) => Ok(Signer::Key(key)),
            said @ serde_json::Value::Object(_) => serde_json::from_value(said)
                .map(Signer::Identity)
                .map_err(|e| D::Error::custom(format!("signedBy: an identity: {e}"))),
            _ => Err(D::Error::custom(
                "signedBy: each is a public key's text, or an identity: { issuer, subject, authority, log }",
            )),
        }
    }
}

spec! {
    /// Whom an authority certified, signed in at an issuer, and the authority's certificates
    /// and the transparency log's key that say so: nothing of these is fetched.
    pub struct Identity {
        /// Where the signer signed in, e.g. `https://token.actions.githubusercontent.com`.
        pub issuer: String,
        /// The email address or URI the certificate names, matched whole.
        pub subject: String,
        /// The authority's root certificate and its intermediates, PEM: 1 to 4.
        pub authority: Vec<String>,
        /// The log's public key, PEM (ECDSA P-256).
        pub log: String,
        /// The root certificates (PEM, 1 to 4) of the timestamp authority whose RFC 3161 timestamp
        /// says when the signature was made. Without it a signature logged to Rekor v2 (which
        /// has no promise of its own) is refused, and with it every signature needs the timestamp.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tsa: Option<Vec<String>>,
    }
}

impl Signer {
    /// As a node is handed it: the key's text, or the identity's JSON.
    pub fn text(&self) -> String {
        match self {
            Signer::Key(key) => key.clone(),
            Signer::Identity(identity) => serde_json::to_string(identity).unwrap_or_default(),
        }
    }
}

/// An amount of CPU, memory or storage: `2`, `500m`, `2Gi`, `1.5G`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "generate", derive(schemars::JsonSchema))]
#[serde(try_from = "String", into = "String")]
#[cfg_attr(feature = "generate", schemars(extend("pattern" = r"^[0-9]+(\.[0-9]+)?(m|k|M|G|T|Ki|Mi|Gi|Ti)?$")))]
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
    /// The amount in whole bytes, where it is some: `512Mi` is 536870912. `500m` is none, and so is
    /// a number at 2^53 or more, where a float stops counting bytes.
    pub fn bytes(&self) -> Option<u64> {
        let value = self.value();
        let whole = value.round();
        // (The float's rounding is not a fraction of a byte: `1.1G` is 1100000000.)
        let exact = (value - whole).abs() <= whole * 4.0 * f64::EPSILON;
        (exact && whole > 0.0 && whole < 9007199254740992.0).then_some(whole as u64)
    }

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
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "generate", derive(schemars::JsonSchema))]
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
        /// What a container's pod may write outside its Volumes, in bytes: its writable root
        /// and its disk scratch, counted together for the pod. Past it the pod is replaced.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub storage: Option<Quantity>,
    }

    // ---- Cluster, Node, Namespace ----

    pub struct ClusterSpec {
        /// DNS domain for public names. Kept and not acted on: nothing reads it.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub domain: Option<String>,
        /// Names of the nodes that vote in Raft. Kept and not acted on: who votes is said
        /// when a node joins (`kith node token`).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub voters: Vec<String>,
        /// Kept and not acted on: an update is an `OSRelease`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub update_policy: Option<UpdatePolicy>,
        /// The mesh switch (`enabled`, `port`): acted on by every node started without `--mesh`.
        /// The rest of it is kept and not acted on: the mesh's addresses come from the CA.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub mesh: Option<MeshSpec>,
        /// Cluster-wide package values. Kept and not acted on: a package takes its own.
        #[serde(default, skip_serializing_if = "Values::is_empty")]
        pub values: Values,
        /// Whose signatures images are taken by: an image under a rule's `prefix` is run only
        /// if one of the rule's keys signed it, whatever its template says. The rule with the
        /// longest prefix an image is under is the one it is held to.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub images: Vec<ImageRule>,
        /// The admin's Ed25519 public key, as 64 hex: a request it signed (`x-kith-signed`) is
        /// the admin's, on whichever node it lands. Changed only by a write it signed.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub admin_key: Option<String>,
        /// Whether a caller one node passes on to another, and a write at a node's local
        /// socket, must be signed: `open` (left out: unsigned is taken, as before) or
        /// `required` (unsigned at the local socket is the node itself, which reads). Changed
        /// only by a write the admin signed.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub signing: Option<Signing>,
        /// The house's one address on its LAN: whichever control node leads holds it, and
        /// answers DNS at it, so a router can name it once (DHCP option 6) and forward to it.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub home: Option<HomeSpec>,
        /// The operator's time server, `ADDRESS[:PORT]` (port 123 left out): every node asks it
        /// alone, at its next check, unless its own `kith.ntp` names one. When Clusters say
        /// different servers, the lowest key's is the one taken.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ntp: Option<String>,
        /// The names only the LAN knows: the domains the cluster's LAN CA signs host
        /// certificates under (`expose.issuer: cluster`), and no others. Left out, `home.arpa`,
        /// `lan`, `internal` and `local`. Changing it makes the LAN CA's certificate again (the
        /// same key): export it again (`kith ca export`) for the devices that trust it. When
        /// Clusters name some, the lowest key's are taken.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub lan_domains: Vec<String>,
    }

    pub struct HomeSpec {
        /// The address with its prefix length, as the LAN has it (`192.168.1.250/24`): an IPv4
        /// address no other machine there has, in the network of a card of the node that holds it.
        pub address: String,
        /// How the outside reaches the house: a name, or an address, with a port
        /// (`house.example.org:51820`). Kept and not acted on: the router forwards to `address`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub endpoint: Option<String>,
    }

    pub enum Signing { Open, Required }

    pub struct ImageRule {
        /// A registry (`ghcr.io`) or a registry and a path under it (`ghcr.io/acme`), matched
        /// by whole parts; empty, or left out, for every image a node pulls.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub prefix: String,
        /// Public keys or identities, as a container's `signedBy` takes them: at least one.
        pub signed_by: Vec<Signer>,
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
        /// The switch: `true` and every node of the cluster that was not started with `--mesh`
        /// brings the WireGuard mesh up (on `port`, 51820 without); off or left out, it does not.
        /// A kith OS node takes it with no reinstall. The rest of this kind is kept and not
        /// acted on.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ipv4: Option<bool>,
        /// The UDP port of the mesh's interface, with `enabled`.
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
        /// How far the node is trusted: `control` (the default) may vote on the store and
        /// its word for who asked is taken by the others; a `worker` never votes, is not
        /// followed as a leader, and gets nothing that asks for control nodes.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub trust: Option<Trust>,
        /// A worker that serves ingress: its view holds the certificates of the hosts the
        /// cluster exposes (and so their keys), and it may say it serves ingress. Written by
        /// the node that admitted it, from its token; a control node orders its certificates.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ingress: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub mesh: Option<NodeMesh>,
        /// What this node does when no leader answers at its start (its own copy of the store
        /// says so). `wait` (the default) starts nothing until a write comes back. `run` starts
        /// what its copy places on it after 30 seconds, Jobs excepted, and says the risks on the
        /// console and in its status (`alone`: since when, until when). A leader that answers
        /// catches it up as on any store change.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub alone: Option<Alone>,
    }

    pub enum NodeRole { Voter, Worker, Edge }

    pub enum Trust { Control, Worker }

    pub enum Alone { Run, Wait }

    pub struct NodeMesh {
        /// `never`: this node's traffic goes straight to the other node or not at all,
        /// never through an edge node (which would see it). Defaults to `auto`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub relay: Option<Relay>,
        /// Rotate this node's WireGuard key: a name of the rotation (any text, up to 64
        /// characters), made once for each new one. The node makes a new key, the nodes it is
        /// connected to take it, and the old key stays in force until they have shaken hands on
        /// the new one; none that do, and it stays. The node's status says the last one made
        /// (`status.mesh.rotated`).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub rotate: Option<String>,
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
        /// The Identity its pods call kith's API as; that Identity's `workloads` names this
        /// Workload's namespace (and the Workload, where it names any).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub identity: Option<String>,
    }

    pub enum Strategy { Rolling, Recreate, BlueGreen }

    /// The units one replica runs: containers, exec units and virtual machines.
    pub struct Template {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub containers: Vec<Container>,
        /// Containers run before `containers`, one at a time in this order, each to its
        /// end: the next starts when one exits 0, and one that fails is run again (unless
        /// the replica's `restartPolicy` is `never`). They mount what the others do.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub init_containers: Vec<Container>,
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
        /// `idle` makes this replica's units take only the node's spare CPU and disk (and their
        /// memory is reclaimed first); `normal`, the default, changes nothing.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub priority: Option<Priority>,
        /// Run each replica as Kubernetes runs a pod: its containers share a network of
        /// their own (any port is theirs, `localhost` is each other, and the replica has
        /// an address on the mesh), each may write its root file system unless it says
        /// `readOnlyRoot`, and each is the user its image names, root included (with what
        /// a container runtime gives root, and nothing of the node's). Where kithd is not
        /// root the replica shares the node's network.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub pod: Option<bool>,
        /// Name of the `Exit` a `pod` leaves by: what it sends beyond the cluster goes
        /// through that tunnel or nowhere. Its replicas run on the exit's node, and only
        /// containers (an exec unit or a VM has the node's network).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub exit: Option<String>,
        /// Notes on each replica, which nothing in kith reads. A replica is made anew
        /// when they change (`kubectl rollout restart` changes one to restart them all).
        #[serde(default, skip_serializing_if = "Labels::is_empty")]
        pub annotations: Labels,
    }

    /// How a replica's units share the node. `idle`: CPU and disk only when nothing else wants
    /// them (`cpu.idle`, the lowest `io.weight`), and memory reclaimed from them first
    /// (`memory.high` at the unit's memory amount, if it has one).
    pub enum Priority { Normal, Idle }

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
        /// Who the image must be signed by, one of these: a public key, as `cosign sign --key`
        /// signs (a PEM file's text or the base64 in it: ECDSA P-256 or Ed25519); or an
        /// identity, as cosign signs without a kept key. With none, an image is run whoever
        /// made it.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub signed_by: Vec<Signer>,
        /// When to ask the registry what `image` points at. Defaults to `ifNotPresent`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub pull_policy: Option<PullPolicy>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub command: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub args: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub env: Vec<EnvVar>,
        /// Every key of a ConfigMap or a Secret as a variable. One in `env` of the same
        /// name wins, and of two here the later.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub env_from: Vec<EnvFrom>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub working_dir: Option<String>,
        /// The user (and group) its process is, by number. Without it: the image's own
        /// user, or 65534 where the image names none or names 0. `0` is root: of the
        /// container's user namespace where kithd is not root, of the node where it is.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub run_as_user: Option<u32>,
        /// Not started if the user it would be is root (0), whoever says so: `runAsUser`
        /// or its image.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub run_as_non_root: Option<bool>,
        /// Capabilities it starts without: `[all]`, or names as Linux has them without
        /// their `CAP_` (`NET_RAW`). Only a container that is root has any to drop.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub drop_capabilities: Vec<String>,
        /// `false`: its root file system is its own to write (what it writes is not the
        /// image's, and goes when the container does). `true`: only volumes, /tmp and
        /// /run are. Without it: `true`, or in a `pod` `false`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub read_only_root: Option<bool>,
        /// What the filter on its system calls lets through that it refuses by default.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub seccomp: Option<Seccomp>,
        /// The container may make user namespaces of its own, as a sandbox inside it does
        /// (bubblewrap: Steam's, Flatpak's). The filter then lets through the calls that
        /// takes (`unshare`, `setns`, `clone`, `clone3`, and those that mount: `mount`,
        /// `umount2`, `pivot_root`, `open_tree`, `move_mount`, the `fs…` four, `mount_setattr`)
        /// and its `/proc` hides nothing, which a `/proc` mounted inside needs; on kith OS it
        /// starts without the capability for ports below 1024, which bubblewrap refuses. In a
        /// namespace of its own a program has every capability over it, and with them far
        /// more of the kernel to call: off unless said, and refused for a container that
        /// is the node's root.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub user_namespaces: Option<bool>,
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

    /// `ifNotPresent` never notices a tag that moved at the registry. A reference of this
    /// node's own registry is always asked, whatever the policy.
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

    /// Exactly one of `path` or `volume`.
    pub struct VmDisk {
        /// A raw disk image on the node, by absolute path.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        /// A Volume (or a VolumeClaim's) that holds the image `file`, so that it is kept on
        /// the Volume's replicas and goes with it when the Volume's node changes: the machine
        /// runs where the Volume is. Needs `size`; one replica of a Workload at most.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub volume: Option<String>,
        /// The image's name inside the Volume [default: disk.img].
        #[serde(skip_serializing_if = "Option::is_none")]
        pub file: Option<String>,
        /// How big the image is made, sparse, when `file` is not in the Volume yet.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub size: Option<Quantity>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub read_only: Option<bool>,
    }

    /// Exactly one of `value`, `secret`, `configMap` or `field`.
    pub struct EnvVar {
        pub name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub secret: Option<KeyRef>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub config_map: Option<KeyRef>,
        /// Something of the replica itself.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub field: Option<Field>,
    }

    /// `name`: the replica's own (`web-0`). `namespace`: its Workload's. `node`: the
    /// node it runs on. `address`: its own on the mesh if it is a `pod`, or its node's.
    pub enum Field { Name, Namespace, Node, Address }

    /// Exactly one of `configMap` or `secret`, by name.
    pub struct EnvFrom {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub config_map: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub secret: Option<String>,
        /// Put before each key to make its variable's name.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub prefix: Option<String>,
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
        /// Reached at the same port of its node's own addresses too: kithd listens there
        /// and passes each connection (or each datagram) on to the pod. Only in a `pod`,
        /// and only ports from 1024.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub publish: Option<bool>,
    }

    pub enum Protocol { Tcp, Udp }

    /// Exactly one of `volume`, `configMap`, `secret` or `scratch`, at `path`.
    pub struct VolumeMount {
        /// A Volume, or a VolumeClaim's.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub volume: Option<String>,
        /// Of a `volume`: it names a VolumeClaim for each replica, `volume` and `-` and the
        /// replica's number (`data-db` is `data-db-0` for the first). Each replica goes on
        /// the node its own Volume is on, and waits while that Volume or its node is gone.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub per_replica: Option<bool>,
        /// A ConfigMap of the namespace: each key a file, read-only, and changed when the
        /// ConfigMap is (all its files at once).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub config_map: Option<String>,
        /// A Secret of the namespace, as `configMap`; its files are kept in memory, never
        /// on a disk.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub secret: Option<String>,
        /// An empty directory of the replica's own, which goes when the replica does:
        /// containers of one replica that name the same one share it.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub scratch: Option<String>,
        pub path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub read_only: Option<bool>,
        /// Of a `configMap` or `secret`: only these keys, each as the file named (which
        /// may be in directories: `conf.d/site`). Without it: every key, as its own name.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub items: BTreeMap<String, String>,
        /// Of a `configMap` or `secret`: its files' mode, in octal (`0400`). Without it:
        /// `0444`.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "generate", schemars(extend("pattern" = "^0?[0-7]{3}$")))]
        pub mode: Option<String>,
        /// Of a `configMap` or `secret`: mount this one file of it at `path`, and not the
        /// directory. It stays as it was when the container started. Of a `volume` or a
        /// `scratch`: mount this directory (or file) of it alone, made if it is not there; no
        /// step of it may be a link, and it is mounted only for a container with users of its
        /// own (not a NodeWorkload's, nor one on the host's network or given devices).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sub_path: Option<String>,
        /// Of a `scratch`: keep it in memory (it counts against the container's).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub memory: Option<bool>,
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
        /// A liveness probe's start deadline: the container is restarted if it has not passed once
        /// this long after it started (until then a failure does not count). Kubernetes'
        /// `initialDelaySeconds` becomes this.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub start_seconds: Option<u32>,
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
        /// How late a minute the schedule named may still be run, where no node led in it
        /// (or kithd was down): the latest missed one only. Without it a missed minute is skipped.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub starting_deadline_seconds: Option<u32>,
        /// Finished Jobs that succeeded and are kept (3 unless said).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub successful_jobs_history_limit: Option<u32>,
        /// Finished Jobs that failed and are kept (3 unless said).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub failed_jobs_history_limit: Option<u32>,
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
        /// No address of its own: its name (`<service>.<namespace>.kith`, and under
        /// `svc.cluster.local`) answers the addresses of its ready replicas, as a headless
        /// Kubernetes Service does. Off unless true.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub headless: Option<bool>,
        /// Sleep the Workloads behind this Service (their `replicas` stay) after no
        /// connection to it for `idle`; kithd holds the first TCP connection to a sleeping
        /// one while a replica starts. Off unless set. TCP only: a datagram wakes nothing.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub scale_to_zero: Option<ScaleToZero>,
    }

    pub struct ScaleToZero {
        /// How long without a connection before it sleeps, from `30s` to `30d`: `90s`, `30m`,
        /// `24h`. Nodes' clocks are taken to agree within a minute, and it is counted to
        /// within about ten seconds.
        pub idle: String,
        /// How long a first connection is held for a replica to start (at most `10m`),
        /// before it is closed with the reason.
        pub start: String,
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
        /// Requests by their path, each to a Service of this one's namespace: the longest
        /// path that fits a request wins, and a request none fits is answered 404. With
        /// none (and no `headers`), the whole host goes to this Service and its HTTP is not
        /// read.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub paths: Vec<ExposePath>,
        /// Headers set on each request on its way to the backend, in place of any of the
        /// same name the client sent.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub headers: BTreeMap<String, String>,
        /// Who vouches for the host's certificate: `acme` (the default) asks the ACME
        /// authority, which needs a name the world can reach; `cluster` has the cluster's own
        /// CA sign it, for a name only the LAN knows (a phone or laptop trusts `kith ca export`
        /// once). The cluster CA then vouches for any name that says so: keep its key safe.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub issuer: Option<ExposeIssuer>,
    }

    /// Where requests under one path go.
    pub struct ExposePath {
        /// `/app` fits `/app` and `/app/x`, not `/application`; `/` fits every request.
        pub path: String,
        /// Fits only the path itself, not what is under it.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub exact: Option<bool>,
        /// A Service of the exposing Service's namespace.
        pub service: String,
        /// The port of that Service.
        pub port: u16,
    }

    pub enum ExposeVia { Edge }

    pub enum ExposeIssuer { Acme, Cluster }

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

    /// Names kithd's DNS server answers as not there, for the clients it names: a ConfigMap key
    /// or a list fetched from an https address, in the format of a hosts file or one name a line.
    /// A listed name blocks every name under it. Exactly one of `configMap` or `url`.
    ///
    /// A `url` list is fetched by each node that serves DNS: the host of the list sees that
    /// node's address and when it asks.
    pub struct DnsBlockListSpec {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub config_map: Option<BlockListMap>,
        /// An `https://` address; no other scheme is fetched.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        /// The list's SHA-256 (64 hex digits): a fetched list that does not match is refused.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sha256: Option<String>,
        /// How often a `url` list is fetched again (`90s`, `30m`, `24h`, `7d`). Defaults to 24h;
        /// at least 5m.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub interval: Option<String>,
        /// What a listed name gets. Defaults to `nxdomain`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub answer: Option<DnsBlockAnswer>,
        /// Only clients in these networks (`192.168.0.0/16`, `fd00::/8`, or one address) are
        /// blocked. Empty: everyone is.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub clients: Vec<String>,
    }

    /// A key of a ConfigMap in `kith-system`: a list decides names for every node's clients,
    /// so it is read from where only the cluster's admins write.
    pub struct BlockListMap {
        pub name: String,
        pub key: String,
    }

    /// `nxdomain`: no such name. `unspecified`: `0.0.0.0` for A and `::` for AAAA.
    pub enum DnsBlockAnswer { Nxdomain, Unspecified }

    /// A WireGuard tunnel one node holds, which the pods there that name it (a template's
    /// `exit`) leave by and by nothing else: no container is given a capability, a sysctl or
    /// a tun device for it. While the tunnel is down what they send to the world is
    /// dropped, IPv6 to anywhere but the mesh always is, and their names are asked of
    /// `dns` through the tunnel or not at all. They reach the cluster as other pods do.
    pub struct ExitSpec {
        /// The node that holds the tunnel; its pods are placed there.
        pub node: String,
        /// A Secret in `kith-system` whose key `wg0.conf` is the provider's WireGuard file
        /// (`PrivateKey`, `Address`, `DNS`; one `[Peer]` with `PublicKey`, `Endpoint`,
        /// `PresharedKey`, `PersistentKeepalive`). kithd reads it; no container mounts it.
        pub secret: String,
        /// The namespaces whose pods may name this exit. At least one of this and `levels`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub namespaces: Vec<String>,
        /// The people's levels (AccessLevels) whose peers may leave by this exit, when the level
        /// names it (its `exit`) and this node, which holds the tunnel, is the one they come to.
        /// Whoever writes the Exit says who spends its provider's key.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub levels: Vec<String>,
        /// Where its pods' names are asked, through the tunnel (IPv4). Without it: the file's `DNS`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub dns: Vec<String>,
    }

    /// What the people a level is given reach (docs/adr-people.md): ranges passed on to, Services,
    /// a resolver, and the internet by this home's own connection or by one Exit. Every field is
    /// optional: an empty level reaches nothing.
    pub struct AccessLevelSpec {
        /// Ranges passed on to, IPv4 or IPv6 (`192.168.0.0/16`, `fd00::/8`). Never `/0`: that is `internet`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub networks: Vec<String>,
        /// Services, each `namespace/name` (its TCP ports), or `*` for every Service.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub services: Vec<String>,
        /// The cluster's API port on the node that ends the tunnel.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub api: Option<bool>,
        /// The resolver its peers are given: one address, IPv4 or IPv6.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub dns: Option<String>,
        /// The internet by the home's own connection. Needs `dns`; not with `exit`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub internet: Option<bool>,
        /// The internet by this Exit only. Needs `dns`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub exit: Option<String>,
    }

    /// A device of one person, which the node named ends the tunnel of, and what it reaches:
    /// the level's. What is stored is its public key only: the private key is never given here.
    pub struct RemotePeerSpec {
        /// The node that ends its tunnel.
        pub node: String,
        /// The AccessLevel that says what it reaches.
        pub level: String,
        /// Its WireGuard public key: 32 bytes in base64 (44 characters, the last one `=`).
        pub public_key: String,
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
        /// Where no Volume fits, one is made for the claim: of its name and size, on the
        /// node that has the fewest (of those its `selector` picks). That Volume fits no
        /// other claim and goes when the claim does; its data stays on the node, as
        /// every Volume's does.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub provision: Option<bool>,
    }

    /// What the Kubernetes API's paths keep of an object kith has no kind for (a
    /// ServiceAccount, a Kubernetes Role): given back as it was sent, and read by nothing.
    pub struct KubeObjectSpec {
        pub object: serde_json::Map<String, serde_json::Value>,
    }

    pub struct ConfigMapSpec {
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub data: BTreeMap<String, String>,
    }

    /// Kept in the store as it is given: on a node's disk it is as safe as the node's state.
    pub struct SecretSpec {
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub data: BTreeMap<String, String>,
        /// `control`: given to units on control nodes only, and what names it is placed
        /// on those.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub trust: Option<Trust>,
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
        /// Further device nodes that come with it and are granted with it: a card on
        /// NVIDIA's driver has `/dev/nvidiactl`, `/dev/nvidia-uvm` and its own `/dev/nvidiaN`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub nodes: Vec<String>,
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
        /// `exclusive` where unsaid. `client` is of a seat: beside whoever holds it, with
        /// the seat's directory (`/run/seat`, where its session puts its sockets) to read
        /// and its GPUs' render nodes, and none of its devices.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub access: Option<Access>,
        /// With `access: shared`: the vram the claim asks for on each Device it holds, which the
        /// scheduler counts against the Device's `vram` label, and a ceiling in each container's
        /// cgroup where the Device has a `dmem` region (docs/guide/hardware.md).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub share: Option<DeviceShare>,
        /// With an exclusive claim: the workload (`Workload/NAME` or `Job/NAME`, of this claim's
        /// namespace) that takes the Device ahead of the others who want it, from whoever holds
        /// it. `kith switch` sets it to hand a GPU over. A shared or client claim has no holder.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub holder: Option<String>,
    }

    pub enum Access { Exclusive, Shared, Client }

    /// `{ vram: 512Mi }`: what a shared claim asks for of a Device's vram.
    pub struct DeviceShare {
        pub vram: Quantity,
    }

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
        /// Drain each node before it restarts (`kith node drain`): what can move runs
        /// elsewhere first.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub drain: Option<bool>,
        /// How long a drain waits for what moves to run elsewhere before the node restarts
        /// anyway. Defaults to 300; at most 3600.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub drain_seconds: Option<u32>,
        /// Pick a node only while its seats last said idle (or it has none).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub wait_for_idle_seats: Option<bool>,
        /// How long a node waits for its seat to be idle before it goes anyway. Defaults to
        /// 3600; at most 86400.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub idle_wait_seconds: Option<u32>,
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
        /// The node may have its own TPM keep the key too, sealed to the system it runs:
        /// it then opens its state with no node asked (`kith node seal`).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub seal: Option<bool>,
        /// The public key (hex) of this node's duress code (`kith node duress`): typed at
        /// its waiting console, the code has the cluster forget this key.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub duress: Option<String>,
        /// And of the cluster's (`kith node duress --all`): every key under it is forgotten.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub duress_all: Option<String>,
        /// The cluster's duress code was typed at another node: the key is gone from here,
        /// the node runs on, and its recovery key opens it (`kith node unlock` has the
        /// cluster hold its key again).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub forgotten: Option<bool>,
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
        /// Empty means every resource of those kinds. Else only the resources of these exact
        /// names: a request that names none (a list is shown only these; one that cannot say
        /// which it reaches) is not covered. (An older kithd refuses the field, never ignores it.)
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub names: Vec<String>,
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
        /// The Workloads that may run as this Identity (`identity:`): whoever may apply a
        /// Workload in a namespace named here may run any image with its rights.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub workloads: Vec<RunAs>,
    }

    /// Workloads that may run as an Identity: those of a namespace, or only the ones named.
    pub struct RunAs {
        pub namespace: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub names: Vec<String>,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "generate", derive(schemars::JsonSchema))]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "generate", derive(schemars::JsonSchema))]
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

/// Why `signers` are not ones an image can be said to be signed by (a container's `signedBy`,
/// or a Cluster's rule's): too many, or one that is not a public key's text or an identity.
fn not_keys(signers: &[Signer]) -> Option<String> {
    if signers.len() > 16 {
        return Some("signedBy: at most 16 keys".into());
    }
    // (Read as P-256 keys are below: a log's key is one.)
    let p256 = |text: &str| {
        let lines = text.lines().filter(|line| !line.trim_start().starts_with("-----"));
        let text: String = lines.flat_map(str::chars).filter(|c| !c.is_whitespace()).collect();
        text.starts_with("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE") && text.len() == 124
    };
    let identity = |identity: &Identity| {
        let name = |text: &str| !text.is_empty() && text.len() <= 1024 && !text.chars().any(char::is_control);
        let who: String = identity.subject.chars().take(40).collect();
        let cert =
            |cert: &String| cert.len() <= 8 << 10 && cert.trim_start().starts_with("-----BEGIN CERTIFICATE-----");
        if !name(&identity.issuer) || !name(&identity.subject) {
            Some("signedBy: an identity names its issuer and its subject (each at most 1024 characters)".to_string())
        } else if identity.authority.is_empty() || identity.authority.len() > 4 || !identity.authority.iter().all(cert)
        {
            Some(format!(
                "signedBy: the identity `{who}` gives its authority as 1 to 4 PEM certificates of at most 8 KiB"
            ))
        } else if !p256(&identity.log) {
            Some(format!(
                "signedBy: the identity `{who}`'s log is not an ECDSA P-256 public key"
            ))
        } else if identity
            .tsa
            .as_ref()
            .is_some_and(|tsa| tsa.is_empty() || tsa.len() > 4 || !tsa.iter().all(cert))
        {
            Some(format!(
                "signedBy: the identity `{who}` gives its tsa as 1 to 4 PEM certificates of at most 8 KiB"
            ))
        } else {
            None
        }
    };
    signers.iter().find_map(|signer| {
        let key = match signer {
            Signer::Key(key) => key,
            Signer::Identity(said) => return identity(said),
        };
        // The two kinds of key there are start their files the same way each: told
        // here by that and their length, and read in full by the node that pulls.
        let lines = key.lines().filter(|line| !line.trim_start().starts_with("-----"));
        let text: String = lines.flat_map(str::chars).filter(|c| !c.is_whitespace()).collect();
        let kinds = [("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE", 124), ("MCowBQYDK2VwAyEA", 60)];
        let known = |(start, len): &(&str, usize)| text.starts_with(start) && text.len() == *len;
        let shown: String = key.trim().chars().take(40).collect();
        (!kinds.iter().any(known)).then(|| {
            format!(
                "signedBy: `{shown}` is not a public key kith can check: an ECDSA P-256 or Ed25519 key, as its PEM file's text or the base64 in it"
            )
        })
    })
}

/// The house address `192.168.1.250/24` as (address, prefix length), or why it is not one a LAN
/// can have: IPv4 with a prefix of 1 to 30, not the network's or broadcast address of that prefix,
/// not loopback, multicast, link-local, in 0.0.0.0/8, 255.255.255.255, or in the default pod range
/// (100.88.0.0/16) or the people range (100.89.0.0/16) that kith's own mesh uses.
pub fn home_address(text: &str) -> Result<(std::net::Ipv4Addr, u8), String> {
    let wrong = || format!("`{text}` is not an IPv4 address with its prefix length, like `192.168.1.250/24`");
    let (address, bits) = text.split_once('/').ok_or_else(wrong)?;
    let address: std::net::Ipv4Addr = address.parse().map_err(|_| wrong())?;
    let bits: u8 = bits
        .parse()
        .ok()
        .filter(|bits| (1..=30).contains(bits))
        .ok_or_else(|| format!("`{text}`: the prefix length is 1 to 30 (a LAN of at least two machines)"))?;
    let as_number = u32::from(address);
    let mask = u32::MAX << (32 - u32::from(bits));
    let in_range = |network: [u8; 4]| as_number & 0xffff_0000 == u32::from(std::net::Ipv4Addr::from(network));
    let why = if address.is_loopback() {
        "loopback"
    } else if address.is_multicast() {
        "a multicast address"
    } else if address.is_link_local() {
        "a link-local address (169.254.0.0/16)"
    } else if address.octets()[0] == 0 {
        "in 0.0.0.0/8"
    } else if address.is_broadcast() {
        "the broadcast address 255.255.255.255"
    } else if in_range([100, 88, 0, 0]) {
        "in the default pod range 100.88.0.0/16"
    } else if in_range([100, 89, 0, 0]) {
        "in the people range 100.89.0.0/16"
    } else if as_number & !mask == 0 {
        "the network address of its prefix"
    } else if as_number | mask == u32::MAX {
        "the broadcast address of its prefix"
    } else {
        return Ok((address, bits));
    };
    Err(format!(
        "`{text}` is {why}: the house address is one machine's own address on the LAN"
    ))
}

/// Why `text` is not how the outside reaches the house: a name or an IPv4 address (or an IPv6 one
/// in brackets), a colon and a port.
pub fn home_endpoint_refused(text: &str) -> Option<String> {
    let wrong = || {
        Some(format!(
            "`{text}` is not a name or an address with a port, like `house.example.org:51820`"
        ))
    };
    let Some((host, port)) = text.rsplit_once(':') else {
        return wrong();
    };
    if port.parse::<u16>().ok().filter(|port| *port > 0).is_none() {
        return wrong();
    }
    let name = |host: &str| {
        host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
    };
    let host_ok = match host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
        Some(v6) => v6.parse::<std::net::Ipv6Addr>().is_ok(),
        None => name(host),
    };
    if host_ok { None } else { wrong() }
}

/// A time server as `kith.ntp` and a Cluster's `spec.ntp` name it: `ADDRESS` (port 123) or
/// `ADDRESS:PORT` (`[ADDRESS]:PORT` for IPv6). A name is not taken: a clock that is not yet set
/// may not resolve one (DNSSEC checks a signature's dates against it).
pub fn ntp_server(word: &str) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr};
    word.parse()
        .ok()
        .or_else(|| word.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 123)))
        .filter(|server: &SocketAddr| server.port() != 0)
}

impl Spec for ClusterSpec {
    fn check(&self) -> Result<(), String> {
        if let Some(ntp) = self.ntp.as_deref().filter(|ntp| ntp_server(ntp).is_none()) {
            return Err(format!(
                "spec.ntp: `{ntp}` is not an address or an address and port, like `10.0.0.7` or `10.0.0.7:123`"
            ));
        }
        if self.lan_domains.len() > 16 {
            return Err("spec.lanDomains: at most 16 domains".into());
        }
        for domain in &self.lan_domains {
            let domain = domain.to_ascii_lowercase();
            if !dns_name(&domain) {
                return Err(format!(
                    "spec.lanDomains: `{domain}` is not a domain name like `home.arpa`"
                ));
            }
            if let Some(zone) = RESERVED_ZONES.iter().find(|zone| under_zone(&domain, zone)) {
                return Err(format!(
                    "spec.lanDomains: `{domain}` is under `{zone}`, a zone of the cluster's own"
                ));
            }
        }
        if let Some(home) = &self.home {
            home_address(&home.address).map_err(|why| format!("spec.home.address: {why}"))?;
            if let Some(why) = home.endpoint.as_deref().and_then(home_endpoint_refused) {
                return Err(format!("spec.home.endpoint: {why}"));
            }
        }
        if self.images.len() > 32 {
            return Err("spec.images: at most 32 rules".into());
        }
        for (n, rule) in self.images.iter().enumerate() {
            let at = format!("spec.images[{n}]");
            let prefix = &rule.prefix;
            // What a reference's registry and path are once read: lower case, parts between
            // slashes, a port only on the registry, no tag and no digest.
            let part = |part: &str| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
            };
            let (registry, path) = prefix.split_once('/').unwrap_or((prefix, ""));
            let (host, port) = registry.split_once(':').unwrap_or((registry, "0"));
            let port = !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
            let shaped = part(host) && port && (!prefix.contains('/') || path.split('/').all(part));
            if !prefix.is_empty() && !shaped {
                return Err(format!(
                    "{at}: prefix: `{prefix}` is not a registry or a registry and a path (`ghcr.io`, `ghcr.io/acme`, `registry.example:5000/team`), in lower case and with no tag"
                ));
            }
            // (As a reference is read: a first part with no dot and no port is a path of docker.io.)
            if !prefix.is_empty() && !(registry.contains(['.', ':']) || registry == "localhost") {
                return Err(format!(
                    "{at}: prefix: `{prefix}` starts with no registry: a prefix starts with a registry (`docker.io/{prefix}`)"
                ));
            }
            if self.images[..n].iter().any(|earlier| earlier.prefix == *prefix) {
                return Err(format!("{at}: prefix: `{prefix}` is named twice"));
            }
            if rule.signed_by.is_empty() {
                return Err(format!(
                    "{at}: signedBy names no key: a rule names the keys that sign what is under it"
                ));
            }
            if let Some(why) = not_keys(&rule.signed_by) {
                return Err(format!("{at}: {why}"));
            }
        }
        let hex = |key: &String| key.len() == 64 && key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if self.admin_key.as_ref().is_some_and(|key| !hex(key)) {
            return Err("spec.adminKey: an Ed25519 public key is 64 lower-case hex".into());
        }
        if self.signing == Some(Signing::Required) && self.admin_key.is_none() {
            return Err("spec.signing: required needs spec.adminKey: nobody could sign".into());
        }
        Ok(())
    }
}

/// `10.0.0.0/8` as an address and its length; `None` for one that cannot be read: not ADDR/LEN, a
/// length over its family's size, or an IPv4 address written as IPv6 (`::ffff:10.0.0.0/104`: a
/// pod's IPv4 packets never meet an IPv6 match, so it would hold nothing).
pub fn parse_cidr(cidr: &str) -> Option<(std::net::IpAddr, u8)> {
    let (address, length) = cidr.split_once('/')?;
    let address: std::net::IpAddr = address.parse().ok()?;
    let size = if address.is_ipv4() { 32 } else { 128 };
    if matches!(address, std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()) {
        return None;
    }
    Some((address, length.parse::<u8>().ok().filter(|length| *length <= size)?))
}

impl NetworkPolicySpec {
    /// What a new policy must meet beyond its shape (`Resource::submitted`, not `check`: replay
    /// takes one an older binary logged, and one that vanished would leave its pods open): a
    /// peer's `cidr` is one `parse_cidr` reads, and on ingress an IPv6 one (a caller comes from
    /// the mesh's IPv6 addresses, so an IPv4 cidr names none). A deny whose cidr kept nothing out
    /// would be a hole; the enforcer keeps everything out for a stored one.
    pub fn submitted(&self) -> Result<(), String> {
        for (side, rules) in [("ingress", &self.ingress), ("egress", &self.egress)] {
            for (i, rule) in rules.iter().enumerate() {
                for (j, peer) in rule.peers.iter().enumerate() {
                    let Some(cidr) = &peer.cidr else { continue };
                    let at = format!("{side}[{i}].peers[{j}].cidr: `{cidr}`");
                    match parse_cidr(cidr) {
                        None => {
                            return Err(format!(
                                "{at} is not ADDR/LEN (`fd00::/8`, `10.0.0.0/8`, a length within its family, not IPv4 written as IPv6)"
                            ));
                        }
                        Some((address, _)) if side == "ingress" && address.is_ipv4() => {
                            return Err(format!("{at} is IPv4: a caller comes from an IPv6 mesh address"));
                        }
                        Some(_) => {}
                    }
                }
            }
        }
        Ok(())
    }
}

no_checks!(
    BlobSpec,
    NetworkPolicySpec,
    VolumeClaimSpec,
    ConfigMapSpec,
    SecretSpec,
    DeviceSpec,
    PackageSpec,
    ReleaseSpec,
    RepositorySpec,
    UpdatePlanSpec,
    NodeKeySpec,
    RoleBindingSpec,
);

impl Spec for RoleSpec {
    /// A name in a rule is a resource's name, as a resource has one: `*` or a pattern is no
    /// wildcard here, it is refused rather than left to name nothing.
    fn check(&self) -> Result<(), String> {
        for (at, rule) in self.rules.iter().enumerate() {
            for name in &rule.names {
                crate::check_name(name).map_err(|e| format!("rules[{at}].names: {e}"))?;
            }
        }
        Ok(())
    }
}

impl Spec for IdentitySpec {
    fn check(&self) -> Result<(), String> {
        for (at, run) in self.workloads.iter().enumerate() {
            crate::check_name(&run.namespace).map_err(|e| format!("workloads[{at}].namespace: {e}"))?;
            for name in &run.names {
                crate::check_name(name).map_err(|e| format!("workloads[{at}].names: {e}"))?;
            }
        }
        // (Its key is a person's or a machine's: a pod's is made again each time it starts.)
        if self.public_key.is_some() && !self.workloads.is_empty() {
            return Err("workloads: an Identity with a publicKey is run as by no Workload".into());
        }
        Ok(())
    }
}

/// `storage` limits a container's pod alone: in the Resources a node keeps back, a namespace's
/// quota or a seat's reserve, `field`, it would look like a limit and limit nothing.
fn storage_unread(field: &str, resources: &Option<Resources>) -> Result<(), String> {
    match resources.as_ref().is_some_and(|r| r.storage.is_some()) {
        true => Err(format!(
            "{field}.storage: is not read here: it limits what a container's pod writes, in the container's resources"
        )),
        false => Ok(()),
    }
}

impl Spec for NodeSpec {
    fn check(&self) -> Result<(), String> {
        storage_unread("reserved", &self.reserved)
    }
}

impl Spec for SeatSpec {
    fn check(&self) -> Result<(), String> {
        storage_unread("reserve", &self.reserve)
    }
}

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

/// Linux's capabilities, by the names `dropCapabilities` takes, in the kernel's order
/// (a name's place here is its number).
#[rustfmt::skip]
pub const CAPABILITIES: &[&str] = &[
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID",
    "SETPCAP", "LINUX_IMMUTABLE", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW",
    "IPC_LOCK", "IPC_OWNER", "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT",
    "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "MKNOD",
    "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG",
    "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF", "CHECKPOINT_RESTORE",
];

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

/// The ports from 1024 kithd serves on unless told otherwise, and what for: never published
/// for a pod (either protocol). A node refuses those it is told to use instead, too.
pub const KITHD_PORTS: &[(u16, &str)] = &[(5000, "registry"), (7443, "API"), (51820, "mesh")];

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
        let disks = self
            .disks
            .iter()
            .filter_map(|disk| Some(("disks", disk.path.as_deref()?)));
        for disk in &self.disks {
            disk.check()?;
        }
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

impl VmDisk {
    /// The image's name in its Volume when `file` is not said.
    pub const FILE: &'static str = "disk.img";

    fn check(&self) -> Result<(), String> {
        exactly_one(
            "disks",
            &[("path", self.path.is_some()), ("volume", self.volume.is_some())],
        )?;
        let Some(volume) = &self.volume else {
            return match (&self.file, &self.size) {
                (None, None) => Ok(()),
                _ => Err("disks: `file` and `size` are a `volume`'s".into()),
            };
        };
        crate::check_name(volume).map_err(|e| format!("disks: volume: {e}"))?;
        let file = self.file.as_deref().unwrap_or(Self::FILE);
        // (One name in the Volume's directory, and a comma ends a value in a hypervisor's options.)
        let plain = !matches!(file, "" | "." | "..")
            && file.len() <= 255
            && !file.contains(|c: char| c == '/' || c == ',' || c.is_control());
        if !plain {
            return Err(format!(
                "disks: file: `{file}` must be one name, with no `/`, no comma and no control character"
            ));
        }
        match &self.size {
            // (At most 1024Ti: the image is sparse, but `ftruncate` has a limit and a typo is not a disk.)
            Some(size) if size.value() >= 1_048_576.0 && size.value() <= 1_125_899_906_842_624.0 => Ok(()),
            _ => Err(
                "disks: size: a `volume` disk needs a size from 1Mi to 1024Ti (the image is made that big, sparse)"
                    .into(),
            ),
        }
    }
}

/// A path inside something mounted: it names what is in it, and nothing above it.
pub fn inside(what: &str, path: &str) -> Result<(), String> {
    // (`..data` and its like are the names a mounted map's own bookkeeping has.)
    let part = |part: &str| !part.is_empty() && part != "." && !part.starts_with("..") && !part.contains('\0');
    match !path.is_empty() && path.split('/').all(part) {
        true => Ok(()),
        false => Err(format!(
            "{what}: `{path}` is not a path inside it (nothing that starts with `..`, no `/` at its start or end)"
        )),
    }
}

impl VolumeMount {
    fn check(&self) -> Result<(), String> {
        exactly_one(
            "it",
            &[
                ("volume", self.volume.is_some()),
                ("configMap", self.config_map.is_some()),
                ("secret", self.secret.is_some()),
                ("scratch", self.scratch.is_some()),
            ],
        )?;
        if self.per_replica.is_some() && self.volume.is_none() {
            return Err("`perReplica` is a `volume`'s".into());
        }
        let data = self.config_map.is_some() || self.secret.is_some();
        if !data && (!self.items.is_empty() || self.mode.is_some()) {
            return Err("`items` and `mode` are a `configMap`'s or a `secret`'s".into());
        }
        if self.memory.is_some() && self.scratch.is_none() {
            return Err("`memory` is a `scratch`'s".into());
        }
        // (A scratch's name is a directory's, under the replica's own.)
        if let Some(scratch) = &self.scratch
            && (scratch.contains('/') || inside("scratch", scratch).is_err())
        {
            return Err(format!("scratch: `{scratch}` is not a name"));
        }
        for file in self.items.values() {
            inside("items", file)?;
            // (Two keys are not one file, and a file is not also a directory.)
            let under = |other: &&String| *other == file || other.starts_with(&format!("{file}/"));
            if self.items.values().filter(under).count() > 1 {
                return Err(format!(
                    "items: `{file}` is named twice, or is a file with files under it"
                ));
            }
        }
        if let Some(sub_path) = &self.sub_path {
            inside("subPath", sub_path)?;
        }
        if let Some(mode) = &self.mode {
            let digits = mode.strip_prefix('0').filter(|rest| rest.len() == 3).unwrap_or(mode);
            if digits.len() != 3 || !digits.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                return Err(format!("mode: `{mode}` is not a file's mode in octal, as `0400` is"));
            }
        }
        Ok(())
    }
}

impl Template {
    /// Its containers, those that run first among them.
    pub fn containers(&self) -> impl Iterator<Item = &Container> {
        self.init_containers.iter().chain(&self.containers)
    }

    /// The names of the Secrets it names: in `env`, `envFrom` and mounts.
    pub fn secrets(&self) -> impl Iterator<Item = &String> {
        fn named(var: &EnvVar) -> Option<&String> {
            var.secret.as_ref().map(|key| &key.name)
        }
        let containers = self.containers().flat_map(move |c| {
            let from = c.env_from.iter().filter_map(|from| from.secret.as_ref());
            let mounted = c.volume_mounts.iter().filter_map(|mount| mount.secret.as_ref());
            c.env.iter().filter_map(named).chain(from).chain(mounted)
        });
        containers.chain(self.exec.iter().flat_map(|e| &e.env).filter_map(named))
    }

    /// The names of the ConfigMaps it names, in the same places.
    pub fn config_maps(&self) -> impl Iterator<Item = &String> {
        fn named(var: &EnvVar) -> Option<&String> {
            var.config_map.as_ref().map(|key| &key.name)
        }
        let containers = self.containers().flat_map(move |c| {
            let from = c.env_from.iter().filter_map(|from| from.config_map.as_ref());
            let mounted = c.volume_mounts.iter().filter_map(|mount| mount.config_map.as_ref());
            c.env.iter().filter_map(named).chain(from).chain(mounted)
        });
        containers.chain(self.exec.iter().flat_map(|e| &e.env).filter_map(named))
    }

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
        let stored = |r: &Option<Resources>| r.as_ref().is_some_and(|r| r.storage.is_some());
        if let Some(e) = self.exec.iter().find(|e| stored(&e.resources)) {
            return Err(format!(
                "{at}, exec `{}`: resources.storage: an exec unit has no root of its own to count",
                e.name
            ));
        }
        if let Some(vm) = self.vms.iter().find(|vm| stored(&vm.resources)) {
            return Err(format!(
                "{at}, vm `{}`: resources.storage: a VM writes to its disks, not to a root of its own",
                vm.name
            ));
        }
        if self.confidential == Some(true) {
            if self.containers().next().is_some() || !self.exec.is_empty() {
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
        let pod = self.pod == Some(true);
        if let Some(exit) = &self.exit {
            if !pod {
                return Err(format!("{at}: exit: only a `pod` leaves by an exit (set `pod: true`)"));
            }
            if !self.exec.is_empty() || !self.vms.is_empty() {
                return Err(format!(
                    "{at}: exit: only containers (an exec unit or a VM has the node's network, not the pod's)"
                ));
            }
            crate::check_name(exit).map_err(|e| format!("{at}: exit: {e}"))?;
        }
        let mut published = std::collections::BTreeSet::new();
        for c in self.containers() {
            for p in c.ports.iter().filter(|p| p.publish == Some(true)) {
                let at = format!("{at}, container `{}`, port {}", c.name, p.port);
                if !pod {
                    return Err(format!("{at}: publish: only a `pod`'s ports are published"));
                }
                if p.port < 1024 {
                    return Err(format!(
                        "{at}: publish: only ports from 1024 (those below are the node's)"
                    ));
                }
                if let Some((_, what)) = KITHD_PORTS.iter().find(|(port, _)| *port == p.port) {
                    return Err(format!(
                        "{at}: publish: port {} is kithd's own (its {what}, by default)",
                        p.port
                    ));
                }
                if !published.insert((p.port, p.protocol == Some(Protocol::Udp))) {
                    return Err(format!("{at}: publish: published twice"));
                }
                // (Each is a listener of kithd's, and the connections it passes on.)
                if published.len() > 8 {
                    return Err(format!("{at}: publish: at most 8 ports a pod"));
                }
            }
        }
        let mut names = std::collections::BTreeSet::new();
        for name in self.units().chain(self.init_containers.iter().map(|c| &c.name)) {
            if !names.insert(name) {
                return Err(format!("{at}: two units are named `{name}`"));
            }
        }
        if !self.init_containers.is_empty() && self.containers.is_empty() {
            return Err(format!(
                "{at}: initContainers run before `containers`, and there are none"
            ));
        }
        if let Some(c) = self
            .init_containers
            .iter()
            .find(|c| c.liveness.is_some() || c.readiness.is_some())
        {
            return Err(format!(
                "{at}, container `{}`: an init container runs to its end, and has no probes",
                c.name
            ));
        }
        let envs = self
            .containers()
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
                        ("field", var.field.is_some()),
                    ],
                )?;
            }
        }
        for c in self.containers() {
            let at = &format!("{at}, container `{}`", c.name);
            for from in &c.env_from {
                exactly_one(
                    &format!("{at}, envFrom"),
                    &[
                        ("configMap", from.config_map.is_some()),
                        ("secret", from.secret.is_some()),
                    ],
                )?;
            }
            for name in &c.drop_capabilities {
                if name != "all" && !CAPABILITIES.contains(&name.as_str()) {
                    return Err(format!(
                        "{at}: dropCapabilities: `{name}` is not a capability: `all`, or one of {}",
                        CAPABILITIES.join(", ")
                    ));
                }
            }
            if c.run_as_non_root == Some(true) && c.run_as_user == Some(0) {
                return Err(format!("{at}: runAsNonRoot, and runAsUser: 0 is root"));
            }
            if let Some(storage) = c.resources.as_ref().and_then(|r| r.storage.as_ref()) {
                let said = String::from(storage.clone());
                match storage.bytes() {
                    None => {
                        return Err(format!(
                            "{at}: resources.storage: `{said}` is not a whole number of bytes from 1 to 2^53 - 1"
                        ));
                    }
                    // What the directories kithd makes for a pod's containers hold by
                    // themselves (4 KiB each): a limit under it fails them, not the pod's writes.
                    Some(bytes) if bytes < 64 << 10 => {
                        return Err(format!(
                            "{at}: resources.storage: `{said}` is less than 64Ki, which a pod's own directories hold"
                        ));
                    }
                    Some(_) => {}
                }
            }
            for mount in &c.volume_mounts {
                mount
                    .check()
                    .map_err(|e| format!("{at}, mount at `{}`: {e}", mount.path))?;
            }
        }
        for c in self.containers() {
            if c.run_as_user == Some(u32::MAX) {
                return Err(format!(
                    "{at}, container `{}`: runAsUser: {} is no user",
                    c.name,
                    u32::MAX
                ));
            }
            if let Some(why) = not_keys(&c.signed_by) {
                return Err(format!("{at}, container `{}`: {why}", c.name));
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
        if let Some(identity) = &self.identity {
            crate::check_name(identity).map_err(|e| format!("identity: {e}"))?;
            // (Each name is one label of the pod's certificate's names.)
            if identity.contains('.') {
                return Err("identity: an Identity a Workload runs as has a name with no `.`".into());
            }
            // The certificate is given to containers, in memory: nothing else is given one.
            if !self.template.exec.is_empty() || !self.template.vms.is_empty() {
                return Err(
                    "identity: only containers are given its certificate: this template has exec units or VMs".into(),
                );
            }
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
        // (A copy on every node, an exit on one.)
        if self.template.exit.is_some() {
            return Err("template.exit: a NodeWorkload cannot leave by an Exit (use a Workload)".into());
        }
        self.template.check("template")
    }
}

impl Spec for ExitSpec {
    fn check(&self) -> Result<(), String> {
        crate::check_name(&self.node).map_err(|e| format!("node: {e}"))?;
        crate::check_name(&self.secret).map_err(|e| format!("secret: {e}"))?;
        if self.namespaces.is_empty() && self.levels.is_empty() {
            return Err(
                "namespaces: at least one (the namespaces whose pods may leave by it), or levels (the people's)".into(),
            );
        }
        for namespace in &self.namespaces {
            crate::check_name(namespace).map_err(|e| format!("namespaces: {e}"))?;
        }
        for level in &self.levels {
            crate::check_name(level).map_err(|e| format!("levels: {e}"))?;
        }
        // (Asked through the tunnel, which carries IPv4 alone.)
        if let Some(bad) = self.dns.iter().find(|a| a.parse::<std::net::Ipv4Addr>().is_err()) {
            return Err(format!("dns: `{bad}` is not an IPv4 address"));
        }
        Ok(())
    }
}

/// Is `net` a range passed on: an address and a prefix length (`192.0.2.0/24`, `fd00::/8`),
/// not a prefix of 0 (the whole internet: that is `internet`), and no bit set past the prefix
/// (`192.0.2.5/24` is no range). A bare address is no range.
fn passed_range(net: &str) -> Result<(), String> {
    let refused = format!("networks: `{net}` is not a range like `192.0.2.0/24` or `fd00::/8`");
    let Some((address, length)) = net.split_once('/') else {
        return Err(refused);
    };
    let address = match address.parse::<std::net::IpAddr>() {
        Ok(address) => address,
        Err(_) => return Err(refused),
    };
    let max = if address.is_ipv4() { 32 } else { 128 };
    let digits = length.bytes().all(|b| b.is_ascii_digit());
    match length.parse::<u8>() {
        Ok(0) if digits => Err(format!("networks: `{net}` is the whole internet: say `internet: true`")),
        Ok(bits) if digits && bits <= max && !host_bits_set(address, bits) => Ok(()),
        _ => Err(refused),
    }
}

/// Is a bit set in `address` past its first `bits` (the host part of a range)?
fn host_bits_set(address: std::net::IpAddr, bits: u8) -> bool {
    match address {
        std::net::IpAddr::V4(a) => (u32::from(a) & u32::MAX.checked_shr(bits.into()).unwrap_or(0)) != 0,
        std::net::IpAddr::V6(a) => (u128::from(a) & u128::MAX.checked_shr(bits.into()).unwrap_or(0)) != 0,
    }
}

/// The value of a base64 character (RFC 4648's standard alphabet), if it is one.
fn base64_value(b: u8) -> Option<u8> {
    Some(match b {
        b'A'..=b'Z' => b - b'A',
        b'a'..=b'z' => b - b'a' + 26,
        b'0'..=b'9' => b - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

/// Is `key` 32 bytes in base64: 44 characters, the last one `=`. Its 43 others hold 258 bits,
/// of which the last two are padding and must be zero (so one key has one text).
fn public_key_checked(key: &str) -> Result<(), String> {
    let bytes = key.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' || bytes[42] == b'=' {
        return Err("publicKey: not 32 bytes of base64: 44 characters, the last one `=`".into());
    }
    if !bytes[..43].iter().all(|&b| base64_value(b).is_some()) {
        return Err("publicKey: a character that is not in base64".into());
    }
    if base64_value(bytes[42]).is_some_and(|last| last & 0b11 != 0) {
        return Err("publicKey: its last character has a bit set past the 32nd byte".into());
    }
    Ok(())
}

/// The IPv4 ranges a network may not lie over: the people's, and the pods' default (`--pod-range`
/// moves the pods', and kithd checks that at start). Their IPv6 ranges are the cluster's own, and
/// kithd refuses those in the AccessLevel's status.
const TAKEN: [(&str, std::net::Ipv4Addr, u8); 2] = [
    ("people", std::net::Ipv4Addr::new(100, 89, 0, 0), 16),
    ("pods", std::net::Ipv4Addr::new(100, 88, 0, 0), 16),
];

/// Does the IPv4 range `net` lie over one of [`TAKEN`]: the first `min` bits of the two agree?
fn taken_range(net: &str) -> Option<String> {
    let (address, length) = net.split_once('/')?;
    let address: std::net::Ipv4Addr = address.parse().ok()?;
    let length: u8 = length.parse().ok()?;
    TAKEN.iter().find_map(|&(name, range, bits)| {
        let mask = u32::MAX.checked_shl(32 - u32::from(length.min(bits))).unwrap_or(0);
        let overlaps = (u32::from(address) & mask) == (u32::from(range) & mask);
        overlaps.then(|| format!("networks: `{net}` overlaps the {name} range {range}/{bits}"))
    })
}

impl Spec for AccessLevelSpec {
    fn check(&self) -> Result<(), String> {
        for net in &self.networks {
            passed_range(net)?;
            if let Some(why) = taken_range(net) {
                return Err(why);
            }
        }
        for service in &self.services {
            // (A Service is named as a Workload's Service is: `namespace/name`, or every one.)
            let named = service
                .split_once('/')
                .is_some_and(|(ns, name)| crate::check_name(ns).is_ok() && crate::check_name(name).is_ok());
            if service != "*" && !named {
                return Err(format!("services: `{service}` is not namespace/name or `*`"));
            }
        }
        if let Some(dns) = &self.dns
            && dns.parse::<std::net::IpAddr>().is_err()
        {
            return Err(format!("dns: `{dns}` is not an IP address"));
        }
        // (The internet is by the home's connection or by one Exit, and a peer that sends
        // everything here needs a resolver.)
        let internet = self.internet == Some(true);
        if internet && self.exit.is_some() {
            return Err("internet and exit: not both (the internet is by the home's connection or by one Exit)".into());
        }
        if let Some(exit) = &self.exit {
            crate::check_name(exit).map_err(|e| format!("exit: {e}"))?;
        }
        if self.dns.is_none() {
            if internet {
                return Err("internet: needs `dns`: a peer that sends everything here needs a resolver".into());
            }
            if self.exit.is_some() {
                return Err("exit: needs `dns`: a peer that sends everything here needs a resolver".into());
            }
        }
        Ok(())
    }
}

impl Spec for RemotePeerSpec {
    fn check(&self) -> Result<(), String> {
        crate::check_name(&self.node).map_err(|e| format!("node: {e}"))?;
        crate::check_name(&self.level).map_err(|e| format!("level: {e}"))?;
        public_key_checked(&self.public_key)
    }
}

impl Spec for JobSpec {
    fn check(&self) -> Result<(), String> {
        if self.template.exit.is_some() {
            return Err("template.exit: only a Workload leaves by an Exit".into());
        }
        self.template.check("template")
    }
}

impl Spec for KubeObjectSpec {
    fn check(&self) -> Result<(), String> {
        match self.object.get("kind").is_some_and(serde_json::Value::is_string) {
            true => Ok(()),
            false => Err("object.kind: a Kubernetes object says what kind it is".into()),
        }
    }
}

impl Spec for CronJobSpec {
    fn check(&self) -> Result<(), String> {
        // (Its schedule and its timezone are read where it is run, which says in the
        // CronJob's status what it cannot read: v1 took any text for both, and still does.)
        if self.job.template.exit.is_some() {
            return Err("job.template.exit: only a Workload leaves by an Exit".into());
        }
        self.job.template.check("job.template")
    }
}

impl Spec for ServiceSpec {
    fn check(&self) -> Result<(), String> {
        if self.ports.is_empty() {
            return Err("ports: needs at least one port".into());
        }
        // (A headless one has no address for a host to go to: refused, not left unserved.)
        if self.headless == Some(true) && self.expose.is_some() {
            return Err(
                "expose: a headless Service has no address to send a host to: its name answers its replicas".into(),
            );
        }
        if let Some(zero) = &self.scale_to_zero {
            let (idle, start) = (every(&zero.idle), every(&zero.start));
            // (A node says what it met every 10 s or so: less than 30 s would put to sleep what is in use.)
            if idle.is_none_or(|s| !(30..=30 * 86400).contains(&s)) || start.is_none_or(|s| s > 600) {
                return Err(
                    "scaleToZero: `idle` and `start` are durations like `90s` or `30m`, `idle` from `30s` to `30d`, `start` at most `10m`"
                        .into(),
                );
            }
            if self.headless == Some(true) {
                return Err("scaleToZero: a headless Service has no address a connection could wake it at".into());
            }
            if self.ports.iter().any(|p| p.protocol == Some(Protocol::Udp)) {
                return Err("scaleToZero: a udp port wakes nothing: only a TCP connection does".into());
            }
        }
        // (The host is asked for in TLS, named in a Secret and in DNS: a name, not a URL.)
        let Some(expose) = &self.expose else { return Ok(()) };
        if !dns_name(&expose.host) {
            return Err(format!(
                "expose.host: `{}` is not a domain name like `shop.example.org`",
                expose.host
            ));
        }
        if let Some(refused) = expose_host_refused(&expose.host) {
            return Err(refused);
        }
        // (The Cluster's own domains are not known here: the signer checks them too.)
        if expose.issuer == Some(ExposeIssuer::Cluster)
            && let Some(refused) = cluster_host_refused(&expose.host.to_ascii_lowercase(), None)
        {
            return Err(refused);
        }
        if expose.proxy_protocol == Some(true) && !(expose.paths.is_empty() && expose.headers.is_empty()) {
            return Err(
                "expose.proxyProtocol: not with paths or headers, whose requests say the client's address in \
                 X-Forwarded-For"
                    .into(),
            );
        }
        if expose.paths.len() > 100 || expose.headers.len() > 32 {
            return Err("expose: at most 100 paths and 32 headers".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for (i, route) in expose.paths.iter().enumerate() {
            // (Matched as the client sends it, byte for byte: no space, no query, nothing
            // that is not printable ASCII.)
            let printable = route
                .path
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'?' && b != b'#');
            if !route.path.starts_with('/') || !printable || route.path.len() > 1024 {
                return Err(format!(
                    "expose.paths[{i}].path: `{}` is not a path like `/app` (printable ASCII, no space, `?` or `#`)",
                    route.path.escape_debug()
                ));
            }
            crate::check_name(&route.service).map_err(|e| format!("expose.paths[{i}].service: {e}"))?;
            if route.port == 0 {
                return Err(format!("expose.paths[{i}].port: 0 is no port"));
            }
            let exact = route.exact == Some(true);
            if !seen.insert((exposed_prefix(&route.path, exact), exact)) {
                return Err(format!("expose.paths[{i}].path: `{}` is there twice", route.path));
            }
        }
        let mut names = std::collections::BTreeSet::new();
        for (name, value) in &expose.headers {
            let lower = name.to_ascii_lowercase();
            if let Some(why) = header_refused(&lower, value) {
                return Err(format!("expose.headers[{}]: {why}", name.escape_debug()));
            }
            if !names.insert(lower) {
                return Err(format!(
                    "expose.headers[{name}]: named twice (names are the same in any case)"
                ));
            }
        }
        Ok(())
    }
}

/// The part of an `expose.paths[].path` a request's path is matched against: a prefix
/// loses its last `/` (`/app/` fits `/app` too, as in a Kubernetes Ingress), an exact
/// path is kept as it is.
pub fn exposed_prefix(path: &str, exact: bool) -> &str {
    match exact {
        true => path,
        false => path.trim_end_matches('/'),
    }
}

/// Why a header may not be set on a request by `expose.headers`, if it may not: `name`
/// is in lower case.
fn header_refused(name: &str, value: &str) -> Option<String> {
    let token = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
    if name.is_empty() || name.len() > 100 || !name.bytes().all(token) {
        return Some("is not a header name (letters, digits and !#$%&'*+-.^_`|~)".into());
    }
    // Hop-by-hop headers, and what frames or addresses the request, are the connection's,
    // not the application's: one set here would say something else than the bytes do.
    const HOP: [&str; 9] = [
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        "forwarded",
    ];
    if HOP.contains(&name) || name.starts_with("proxy-") {
        return Some("is the connection's, not one to set".into());
    }
    if ["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"].contains(&name) {
        return Some("is set by kith itself".into());
    }
    // (A line break would start another header, or the body.)
    if value.len() > 4096 || !value.bytes().all(|b| b == b'\t' || (b' '..=b'~').contains(&b)) {
        return Some("its value has a line break, a control character or what is not ASCII in it".into());
    }
    None
}

impl Spec for NamespaceSpec {
    fn check(&self) -> Result<(), String> {
        storage_unread("quota", &self.quota)?;
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

/// The domains the LAN CA signs under when no Cluster says (`spec.lanDomains`).
pub const LAN_DOMAINS: [&str; 4] = ["home.arpa", "lan", "internal", "local"];

/// The zones kithd answers for itself: no certificate for a name in them is signed by the LAN CA,
/// and no Namespace or Cluster may hand them out.
pub const RESERVED_ZONES: [&str; 2] = ["kith", "cluster.local"];

/// The domains a Cluster's `spec.lanDomains` names, lower case; [`LAN_DOMAINS`] where it names none.
pub fn lan_domains(named: &[String]) -> Vec<String> {
    match named.is_empty() {
        true => LAN_DOMAINS.iter().map(|d| d.to_string()).collect(),
        false => named.iter().map(|d| d.to_ascii_lowercase()).collect(),
    }
}

/// Is the lower case `name` the `zone`, or a name under it?
pub fn under_zone(name: &str, zone: &str) -> bool {
    name == zone || name.strip_suffix(zone).is_some_and(|front| front.ends_with('.'))
}

/// Why the cluster's LAN CA would not sign a certificate for `host` (lower case, a name that passes
/// `dns_name`), if it would not: what `expose_host_refused` says, a name of one label, the
/// cluster's own zones ([`RESERVED_ZONES`]), and, when the Cluster's domains are known (`domains`,
/// where none is [`LAN_DOMAINS`]), a name under none of them. One rule, for the apply and for the
/// signer.
pub fn cluster_host_refused(host: &str, domains: Option<&[String]>) -> Option<String> {
    if let Some(refused) = expose_host_refused(host) {
        return Some(refused);
    }
    let why = if !host.contains('.') {
        "a name of one label".to_string()
    } else if let Some(zone) = RESERVED_ZONES.iter().find(|zone| under_zone(host, zone)) {
        format!("under `{zone}`, a zone of the cluster's own")
    } else {
        let listed = lan_domains(domains.unwrap_or(&[]));
        if domains.is_none() || listed.iter().any(|zone| under_zone(host, zone)) {
            return None;
        }
        format!("not under one of the cluster's LAN domains ({})", listed.join(", "))
    };
    Some(format!(
        "expose.issuer: `cluster` does not sign for `{host}`: it is {why}"
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
        clients_checked(&self.clients)
    }
}

/// Each of `clients` is an address or a network.
fn clients_checked(clients: &[String]) -> Result<(), String> {
    for net in clients {
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

/// The shortest time between two fetches of a list, so a typo cannot make a node hammer a host.
pub const BLOCK_LIST_MIN_INTERVAL: u64 = 300;
/// How often a list is fetched when it does not say.
pub const BLOCK_LIST_INTERVAL: u64 = 86_400;

/// Whether `url` is a plain `https://host[:port]/path` address: no user and password in it, no
/// spaces or control characters, and a host. (The one place kithd and the checks agree on what
/// it will fetch.)
pub fn https_url(url: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("url: `{url}` is not an https:// address"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err("url: needs a host, and no user or password in it".into());
    }
    if url.len() > 2048 || url.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()) {
        return Err("url: longer than 2048 characters, or holds a space or control character".into());
    }
    Ok(())
}

impl Spec for DnsBlockListSpec {
    fn check(&self) -> Result<(), String> {
        match (&self.config_map, &self.url) {
            (Some(map), None) => {
                if map.name.is_empty() || map.key.is_empty() {
                    return Err("configMap: needs a name and a key".into());
                }
                if self.sha256.is_some() || self.interval.is_some() {
                    return Err("sha256 and interval are for a `url` list".into());
                }
            }
            (None, Some(url)) => https_url(url)?,
            _ => return Err("give exactly one of configMap or url".into()),
        }
        if let Some(sha) = &self.sha256
            && !(sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("sha256: not 64 hexadecimal digits".into());
        }
        if let Some(interval) = &self.interval {
            match every(interval) {
                Some(secs) if secs >= BLOCK_LIST_MIN_INTERVAL => {}
                Some(_) => return Err("interval: at least 5m".into()),
                None => return Err(format!("interval: `{interval}` is not like `30m`, `24h` or `7d`")),
            }
        }
        clients_checked(&self.clients)
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
        )?;
        if self.access == Some(Access::Client) && self.seat.is_none() {
            return Err("spec.access: client is of a seat: name one with `seat`".into());
        }
        if let Some(holder) = &self.holder {
            if matches!(self.access, Some(Access::Shared | Access::Client)) {
                return Err("spec.holder: a holder is for an exclusive claim, not one with `access: shared` or `access: client`".into());
            }
            let named = holder.split_once('/').is_some_and(|(kind, name)| {
                matches!(kind, "Workload" | "Job") && !name.is_empty() && !name.contains('/')
            });
            if !named {
                return Err(format!(
                    "spec.holder: {holder} is not a workload of this namespace: say `Workload/NAME` or `Job/NAME`"
                ));
            }
        }
        if let Some(share) = &self.share {
            if self.access != Some(Access::Shared) {
                return Err("spec.share: a share is of a shared claim: say `access: shared`".into());
            }
            if share.vram.bytes().is_none() {
                return Err("spec.share.vram: a share is whole bytes, above 0 and below 8192Ti (such as 512Mi)".into());
            }
        }
        Ok(())
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

#[cfg(test)]
mod access_tests {
    use crate::Resource;

    fn read(kind: &str, spec: &str) -> Result<(), String> {
        let text = format!("apiVersion: kith.dev/v1\nkind: {kind}\nmetadata: {{ name: family }}\nspec: {spec}\n");
        Resource::from_source(&text)
            .and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>())
            .map(drop)
            .map_err(|e| e.msg)
    }

    /// A kithd from before `names` reads a Role with it as an error, not as a rule for every
    /// name of its kinds: that is what keeps a Role narrowed by name from widening on a node
    /// that has not been updated yet.
    #[test]
    fn rule_names_unknown_to_old() {
        #[derive(Debug, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct Old {
            kinds: Vec<String>,
            verbs: Vec<String>,
            #[serde(default)]
            namespaces: Vec<String>,
        }
        let with = serde_json::json!({"kinds": ["OSRelease"], "verbs": ["apply"], "names": ["canary"]});
        let refused = serde_json::from_value::<Old>(with.clone()).unwrap_err().to_string();
        assert!(refused.contains("unknown field `names`"), "{refused}");
        // This build reads it, and keeps it when it writes it again; without it, nothing is written.
        let rule: super::AccessRule = serde_json::from_value(with).unwrap();
        assert_eq!(rule.names, ["canary"]);
        let again = serde_json::to_value(&rule).unwrap();
        assert_eq!(again["names"], serde_json::json!(["canary"]));
        let plain: super::AccessRule =
            serde_json::from_value(serde_json::json!({"kinds": ["*"], "verbs": ["get"]})).unwrap();
        assert!(plain.names.is_empty() && serde_json::to_value(&plain).unwrap().get("names").is_none());
        // It still refuses a field it does not know, and its schema says so.
        let odd = serde_json::json!({"kinds": ["*"], "verbs": ["get"], "name": ["canary"]});
        assert!(serde_json::from_value::<super::AccessRule>(odd).is_err());
        let role = read(
            "Role",
            "{ rules: [{ kinds: [OSRelease], verbs: [apply], names: [canary], nmaes: [x] }] }",
        );
        assert!(role.is_err(), "{role:?}");
        assert!(
            read(
                "Role",
                "{ rules: [{ kinds: [OSRelease], verbs: [apply], names: [canary] }] }"
            )
            .is_ok()
        );
        // A wildcard is not a name: refused, not left to match nothing (or, one day, everything).
        for odd in ["'*'", "'can*'", "Canary", "''"] {
            let refused = read(
                "Role",
                &format!("{{ rules: [{{ kinds: [OSRelease], verbs: [apply], names: [{odd}] }}] }}"),
            );
            assert!(refused.unwrap_err().contains("rules[0].names"), "{odd}");
        }
    }

    #[test]
    fn access_level_refuses_a_range_over_the_people_or_pods_range() {
        // (The people's `100.89.0.0/16` and the pods' default `100.88.0.0/16`, docs/adr-people.md.)
        for (net, range) in [
            ("100.89.0.0/16", "people range 100.89.0.0/16"),
            ("100.89.4.0/24", "people range 100.89.0.0/16"),
            ("100.89.255.255/32", "people range 100.89.0.0/16"),
            ("100.0.0.0/8", "people range 100.89.0.0/16"),
            ("100.64.0.0/10", "people range 100.89.0.0/16"),
            ("100.88.0.0/16", "pods range 100.88.0.0/16"),
            ("100.88.128.0/17", "pods range 100.88.0.0/16"),
        ] {
            let refused = read("AccessLevel", &format!("{{ networks: [{net}] }}")).unwrap_err();
            assert!(
                refused.contains(&format!("`{net}` overlaps the {range}")),
                "{net}: {refused}"
            );
        }
    }

    #[test]
    fn access_level_accepts_a_range_beside_the_people_range() {
        for net in ["100.90.0.0/16", "100.64.0.0/16", "100.128.0.0/9", "100.87.255.255/32"] {
            read("AccessLevel", &format!("{{ networks: [{net}] }}")).unwrap_or_else(|e| panic!("{net}: {e}"));
        }
    }

    /// A deny whose cidr cannot be read would hold nothing back, so a policy is refused for one.
    #[test]
    fn network_policy_cidr_is_an_address_and_a_length_in_its_family() {
        // Refused when submitted, not parsed: replay parses what an older binary logged.
        let submit = |side: &str, action: &str, cidr: &str| {
            let spec = format!("{{ {side}: [{{ action: {action}, peers: [{{ cidr: '{cidr}' }}] }}] }}");
            let text = format!("apiVersion: kith.dev/v1\nkind: NetworkPolicy\nmetadata: {{ name: p }}\nspec: {spec}\n");
            let docs = Resource::from_source(&text).unwrap();
            docs.into_iter().next().unwrap().unwrap().submitted_by_node()
        };
        for cidr in ["fd00::/8", "::/0", "fd00::1/128"] {
            submit("ingress", "deny", cidr).unwrap_or_else(|e| panic!("{cidr}: {e}"));
        }
        for cidr in [
            "10.0.0.0/8",
            "fd00::/8",
            "0.0.0.0/0",
            "::/0",
            "10.0.0.1/32",
            "fd00::1/128",
        ] {
            submit("egress", "allow", cidr).unwrap_or_else(|e| panic!("{cidr}: {e}"));
            submit("egress", "deny", cidr).unwrap_or_else(|e| panic!("{cidr}: {e}"));
        }
        // Not an address and a length within its family, or an IPv4 address as IPv6 (a pod's
        // IPv4 packets never meet it).
        let bad = [
            "nonsense",
            "10.0.0.0/40",
            "10.0.0.1",
            "fd00::/129",
            "10.0.0.0/",
            "/8",
            "10.0.0.0/-1",
        ];
        for cidr in bad.into_iter().chain(["::ffff:10.0.0.0/104", "::ffff:0:0/96"]) {
            for (side, action) in [
                ("ingress", "deny"),
                ("ingress", "allow"),
                ("egress", "deny"),
                ("egress", "allow"),
            ] {
                let refused = submit(side, action, cidr).unwrap_err();
                assert!(
                    refused.contains(&format!("{side}[0].peers[0].cidr")),
                    "{cidr}: {refused}"
                );
            }
        }
        // Callers of an ingress rule come from the mesh's IPv6 addresses: an IPv4 cidr names none.
        for cidr in ["10.0.0.0/8", "0.0.0.0/0"] {
            let refused = submit("ingress", "deny", cidr).unwrap_err();
            assert!(
                refused.contains("ingress[0].peers[0].cidr") && refused.contains("IPv6"),
                "{refused}"
            );
        }
    }

    #[test]
    fn access_remote_peer_needs_its_node_level_and_key() {
        let key = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
        read(
            "RemotePeer",
            &format!("{{ node: n1, level: family, publicKey: '{key}' }}"),
        )
        .unwrap();
        for (spec, why) in [
            (format!("{{ level: family, publicKey: '{key}' }}"), "node"),
            (format!("{{ node: n1, publicKey: '{key}' }}"), "level"),
            ("{ node: n1, level: family }".to_string(), "publicKey"),
            (
                format!("{{ node: n1, level: family, publicKey: '{}' }}", &key[..43]),
                "32 bytes",
            ),
        ] {
            let refused = read("RemotePeer", &spec).unwrap_err();
            assert!(refused.contains(why), "{spec}: {refused}");
        }
    }
}
