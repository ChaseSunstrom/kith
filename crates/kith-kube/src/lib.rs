//! Kubernetes manifests as kith resources.
//!
//! Every field is taken out of the input as it is carried over, so what is left
//! at the end is exactly what was not. Each of those is one of two ([`FIELDS`]): a hint,
//! which is said and changes nothing, or refused. A field nobody wrote down is refused.

use kith_api::kinds::Quantity;
use kith_api::{Metadata, Resource};
use serde_json::{Value, json};
use std::collections::BTreeMap;

type Map = serde_json::Map<String, Value>;
type Strings = BTreeMap<String, String>;

/// Every document of a source as JSON; a document that cannot be read is an error.
pub fn documents(name: &str, src: &str) -> Result<Vec<Value>, String> {
    let nodes = kith_yaml::parse(src).map_err(|e| e.render(name, src))?;
    nodes
        .iter()
        .map(|node| kith_yaml::from_node(node).map_err(|e| e.render(name, src)))
        .collect()
}

// ---- Reading, and remembering what was read ----

const NOISE: &[&str] = &[
    "creationTimestamp",
    "resourceVersion",
    "uid",
    "managedFields",
    "generation",
    "selfLink",
];

/// Labels and annotations that tools put on every object and mean nothing here.
fn noisy(key: &str) -> bool {
    key.contains("helm.sh/")
        || key == "app.kubernetes.io/managed-by"
        || key == "kubectl.kubernetes.io/last-applied-configuration"
        || key == "deployment.kubernetes.io/revision"
}

fn join(at: &str, key: &str) -> String {
    if at.is_empty() {
        key.into()
    } else {
        format!("{at}.{key}")
    }
}

fn is_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// A JSON object of the fields that are there.
fn obj<const N: usize>(fields: [(&str, Option<Value>); N]) -> Value {
    Value::Object(fields.into_iter().filter_map(|(k, v)| Some((k.into(), v?))).collect())
}

fn some<T: Into<Value>>(v: Option<T>) -> Option<Value> {
    v.map(Into::into)
}

fn nonempty(v: Value) -> Option<Value> {
    (!is_empty(&v)).then_some(v)
}

/// Removes `key` when it holds the value Kubernetes would assume anyway.
fn drop_default(m: &mut Map, key: &str, default: Value) {
    if m.get(key) == Some(&default) {
        m.remove(key);
    }
}

/// What becomes of a field of a Kubernetes object.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Field {
    /// kith does what it says.
    Carried,
    /// Taken and said: kith has no use for it, and without it the same thing runs and
    /// may reach the same.
    Hint,
    /// Not taken: without it kith would run something else than was asked, or let it
    /// reach something else.
    Refused,
}
use Field::{Carried, Hint, Refused};

/// The fields of the kinds that are taken, what becomes of each, and a value to try it
/// with (JSON). `meta.` is an object's metadata, `pod.` a pod's spec wherever a kind has
/// one, `podmeta.` its metadata, `container.` one of its containers and `probe.` either
/// of a container's two checks; `[]` is every item of a list. A row stands for all that is under it, and a field that has no row is
/// refused: the refused rows here are the ones worth saying.
pub const FIELDS: &[(&str, Field, &str)] = &[
    ("meta.name", Carried, r#""web""#),
    ("meta.namespace", Carried, r#""default""#),
    ("meta.labels", Carried, r#"{"app":"web"}"#),
    ("meta.annotations", Carried, r#"{"a":"b"}"#),
    ("meta.ownerReferences", Hint, r#"[{"kind":"X","name":"x"}]"#),
    ("meta.finalizers", Hint, r#"["x"]"#),
    ("meta.generateName", Refused, r#""web-""#),
    // A pod.
    ("podmeta.labels", Carried, r#"{"app":"web"}"#),
    ("podmeta.annotations", Hint, r#"{"a":"b"}"#),
    ("pod.containers", Carried, r#"[{"name":"web","image":"nginx"}]"#),
    ("pod.restartPolicy", Carried, r#""Always""#),
    ("pod.nodeSelector", Carried, r#"{"disk":"ssd"}"#),
    ("pod.volumes[].name", Carried, r#""data""#),
    ("pod.volumes[].persistentVolumeClaim.claimName", Carried, r#""data""#),
    ("pod.volumes[].persistentVolumeClaim.readOnly", Refused, "true"),
    ("pod.volumes[].hostPath", Refused, r#"{"path":"/"}"#),
    ("pod.securityContext.runAsUser", Carried, "1000"),
    ("pod.securityContext.runAsGroup", Hint, "1000"),
    ("pod.securityContext.fsGroup", Hint, "1000"),
    ("pod.securityContext.fsGroupChangePolicy", Hint, r#""OnRootMismatch""#),
    ("pod.securityContext.supplementalGroups", Hint, "[1000]"),
    ("pod.securityContext.seLinuxOptions", Hint, r#"{"level":"s0"}"#),
    (
        "pod.securityContext.appArmorProfile",
        Hint,
        r#"{"type":"RuntimeDefault"}"#,
    ),
    (
        "pod.securityContext.seccompProfile.type",
        Carried,
        r#""RuntimeDefault""#,
    ),
    (
        "pod.securityContext.sysctls",
        Refused,
        r#"[{"name":"net.core.somaxconn","value":"1"}]"#,
    ),
    ("pod.hostNetwork", Refused, "true"),
    ("pod.hostPID", Refused, "true"),
    ("pod.hostIPC", Refused, "true"),
    ("pod.shareProcessNamespace", Refused, "true"),
    ("pod.initContainers", Refused, r#"[{"name":"first","image":"busybox"}]"#),
    (
        "pod.ephemeralContainers",
        Refused,
        r#"[{"name":"debug","image":"busybox"}]"#,
    ),
    ("pod.runtimeClassName", Refused, r#""gvisor""#),
    ("pod.serviceAccountName", Hint, r#""web""#),
    ("pod.serviceAccount", Hint, r#""web""#),
    ("pod.automountServiceAccountToken", Hint, "false"),
    ("pod.affinity", Hint, r#"{"podAntiAffinity":{}}"#),
    ("pod.tolerations", Hint, r#"[{"operator":"Exists"}]"#),
    ("pod.topologySpreadConstraints", Hint, r#"[{"maxSkew":1}]"#),
    ("pod.priorityClassName", Carried, r#""high""#),
    ("pod.priority", Hint, "1"),
    ("pod.preemptionPolicy", Hint, r#""Never""#),
    ("pod.schedulerName", Hint, r#""another""#),
    ("pod.nodeName", Hint, r#""a""#),
    ("pod.terminationGracePeriodSeconds", Hint, "10"),
    ("pod.dnsPolicy", Hint, r#""Default""#),
    ("pod.dnsConfig", Hint, r#"{"options":[{"name":"ndots","value":"2"}]}"#),
    ("pod.hostAliases", Hint, r#"[{"ip":"127.0.0.1","hostnames":["a"]}]"#),
    ("pod.hostname", Hint, r#""web""#),
    ("pod.subdomain", Hint, r#""web""#),
    ("pod.enableServiceLinks", Hint, "false"),
    ("pod.imagePullSecrets", Hint, r#"[{"name":"registry"}]"#),
    ("pod.readinessGates", Hint, r#"[{"conditionType":"x"}]"#),
    ("pod.os", Hint, r#"{"name":"linux"}"#),
    // A container.
    ("container.name", Carried, r#""web""#),
    ("container.image", Carried, r#""nginx""#),
    ("container.imagePullPolicy", Carried, r#""Always""#),
    ("container.command", Carried, r#"["sleep"]"#),
    ("container.args", Carried, r#"["1"]"#),
    ("container.workingDir", Carried, r#""/srv""#),
    ("container.env[].name", Carried, r#""A""#),
    ("container.env[].value", Carried, r#""b""#),
    (
        "container.env[].valueFrom.secretKeyRef",
        Carried,
        r#"{"name":"s","key":"k"}"#,
    ),
    (
        "container.env[].valueFrom.configMapKeyRef",
        Carried,
        r#"{"name":"c","key":"k"}"#,
    ),
    ("container.env[].valueFrom.secretKeyRef.optional", Hint, "true"),
    ("container.env[].valueFrom.configMapKeyRef.optional", Hint, "true"),
    (
        "container.env[].valueFrom.fieldRef",
        Refused,
        r#"{"fieldPath":"metadata.name"}"#,
    ),
    (
        "container.env[].valueFrom.resourceFieldRef",
        Refused,
        r#"{"resource":"limits.cpu"}"#,
    ),
    ("container.envFrom", Refused, r#"[{"configMapRef":{"name":"c"}}]"#),
    ("container.ports[].containerPort", Carried, "80"),
    ("container.ports[].name", Carried, r#""http""#),
    ("container.ports[].protocol", Carried, r#""TCP""#),
    ("container.ports[].hostPort", Refused, "80"),
    ("container.ports[].hostIP", Refused, r#""0.0.0.0""#),
    ("container.resources.requests.cpu", Carried, r#""100m""#),
    ("container.resources.requests.memory", Carried, r#""64Mi""#),
    ("container.resources.limits.cpu", Carried, r#""100m""#),
    ("container.resources.limits.memory", Carried, r#""64Mi""#),
    ("container.resources.requests.ephemeral-storage", Hint, r#""1Gi""#),
    ("container.resources.limits.ephemeral-storage", Hint, r#""1Gi""#),
    ("container.volumeMounts[].name", Carried, r#""data""#),
    ("container.volumeMounts[].mountPath", Carried, r#""/data""#),
    ("container.volumeMounts[].readOnly", Carried, "true"),
    ("container.volumeMounts[].subPath", Refused, r#""a""#),
    ("container.volumeMounts[].subPathExpr", Refused, r#""$(A)""#),
    (
        "container.volumeMounts[].mountPropagation",
        Refused,
        r#""Bidirectional""#,
    ),
    (
        "container.volumeDevices",
        Refused,
        r#"[{"name":"data","devicePath":"/dev/x"}]"#,
    ),
    // Its `livenessProbe` and its `readinessProbe`.
    ("probe.httpGet", Carried, r#"{"path":"/","port":80}"#),
    ("probe.tcpSocket", Carried, r#"{"port":80}"#),
    ("probe.exec", Carried, r#"{"command":["true"]}"#),
    ("probe.httpGet.scheme", Refused, r#""HTTPS""#),
    ("probe.httpGet.host", Refused, r#""example.org""#),
    ("probe.httpGet.httpHeaders", Refused, r#"[{"name":"Host","value":"a"}]"#),
    ("probe.tcpSocket.host", Refused, r#""example.org""#),
    ("probe.grpc", Refused, r#"{"port":80}"#),
    ("probe.periodSeconds", Carried, "5"),
    ("probe.timeoutSeconds", Carried, "2"),
    ("probe.failureThreshold", Carried, "3"),
    // (To kith a container is not live before its liveness check first passes.)
    ("probe.initialDelaySeconds", Hint, "10"),
    ("probe.successThreshold", Hint, "1"),
    ("probe.terminationGracePeriodSeconds", Hint, "10"),
    ("container.startupProbe", Hint, r#"{"tcpSocket":{"port":80}}"#),
    (
        "container.lifecycle.preStop",
        Hint,
        r#"{"exec":{"command":["sleep","5"]}}"#,
    ),
    (
        "container.lifecycle.postStart",
        Refused,
        r#"{"exec":{"command":["true"]}}"#,
    ),
    ("container.securityContext.runAsUser", Carried, "1000"),
    ("container.securityContext.readOnlyRootFilesystem", Carried, "true"),
    ("container.securityContext.allowPrivilegeEscalation", Carried, "false"),
    (
        "container.securityContext.seccompProfile.type",
        Carried,
        r#""Unconfined""#,
    ),
    (
        "container.securityContext.seccompProfile.localhostProfile",
        Refused,
        r#""x.json""#,
    ),
    ("container.securityContext.runAsGroup", Hint, "1000"),
    ("container.securityContext.seLinuxOptions", Hint, r#"{"level":"s0"}"#),
    (
        "container.securityContext.appArmorProfile",
        Hint,
        r#"{"type":"RuntimeDefault"}"#,
    ),
    ("container.securityContext.privileged", Refused, "true"),
    (
        "container.securityContext.capabilities",
        Refused,
        r#"{"add":["SYS_ADMIN"]}"#,
    ),
    ("container.securityContext.runAsNonRoot", Refused, "true"),
    ("container.securityContext.procMount", Refused, r#""Unmasked""#),
    ("container.terminationMessagePath", Hint, r#""/tmp/said""#),
    ("container.terminationMessagePolicy", Hint, r#""FallbackToLogsOnError""#),
    ("container.stdin", Hint, "true"),
    ("container.stdinOnce", Hint, "true"),
    ("container.tty", Hint, "true"),
    (
        "container.resizePolicy",
        Hint,
        r#"[{"resourceName":"cpu","restartPolicy":"NotRequired"}]"#,
    ),
    ("container.restartPolicy", Refused, r#""Always""#),
    // The kinds that run pods.
    ("Deployment.spec.replicas", Carried, "2"),
    ("Deployment.spec.strategy.type", Carried, r#""Recreate""#),
    ("Deployment.spec.strategy.rollingUpdate", Hint, r#"{"maxSurge":1}"#),
    ("Deployment.spec.selector.matchLabels", Carried, r#"{"app":"web"}"#),
    (
        "Deployment.spec.selector.matchExpressions",
        Hint,
        r#"[{"key":"a","operator":"Exists"}]"#,
    ),
    ("Deployment.spec.minReadySeconds", Hint, "5"),
    ("Deployment.spec.revisionHistoryLimit", Hint, "3"),
    ("Deployment.spec.progressDeadlineSeconds", Hint, "600"),
    ("Deployment.spec.paused", Refused, "true"),
    ("StatefulSet.spec.replicas", Carried, "1"),
    ("StatefulSet.spec.updateStrategy.type", Carried, r#""RollingUpdate""#),
    (
        "StatefulSet.spec.updateStrategy.rollingUpdate",
        Hint,
        r#"{"partition":0}"#,
    ),
    (
        "StatefulSet.spec.selector.matchExpressions",
        Hint,
        r#"[{"key":"a","operator":"Exists"}]"#,
    ),
    ("StatefulSet.spec.serviceName", Hint, r#""web""#),
    ("StatefulSet.spec.podManagementPolicy", Hint, r#""Parallel""#),
    (
        "StatefulSet.spec.persistentVolumeClaimRetentionPolicy",
        Hint,
        r#"{"whenDeleted":"Retain"}"#,
    ),
    ("StatefulSet.spec.minReadySeconds", Hint, "5"),
    ("StatefulSet.spec.revisionHistoryLimit", Hint, "3"),
    ("StatefulSet.spec.ordinals", Hint, r#"{"start":0}"#),
    (
        "StatefulSet.spec.volumeClaimTemplates[].spec.resources.requests.storage",
        Carried,
        r#""1Gi""#,
    ),
    (
        "StatefulSet.spec.volumeClaimTemplates[].spec.accessModes",
        Carried,
        r#"["ReadWriteOnce"]"#,
    ),
    (
        "StatefulSet.spec.volumeClaimTemplates[].spec.storageClassName",
        Hint,
        r#""fast""#,
    ),
    (
        "DaemonSet.spec.selector.matchExpressions",
        Hint,
        r#"[{"key":"a","operator":"Exists"}]"#,
    ),
    ("DaemonSet.spec.updateStrategy", Hint, r#"{"type":"RollingUpdate"}"#),
    ("DaemonSet.spec.minReadySeconds", Hint, "5"),
    ("DaemonSet.spec.revisionHistoryLimit", Hint, "3"),
    ("Job.spec.completions", Carried, "1"),
    ("Job.spec.parallelism", Carried, "1"),
    ("Job.spec.backoffLimit", Carried, "2"),
    ("Job.spec.activeDeadlineSeconds", Carried, "60"),
    ("Job.spec.ttlSecondsAfterFinished", Hint, "60"),
    ("Job.spec.selector", Hint, r#"{"matchLabels":{"a":"b"}}"#),
    ("Job.spec.manualSelector", Hint, "true"),
    ("Job.spec.podReplacementPolicy", Hint, r#""Failed""#),
    ("Job.spec.completionMode", Refused, r#""Indexed""#),
    ("Job.spec.suspend", Refused, "true"),
    ("CronJob.spec.schedule", Carried, r#""0 * * * *""#),
    ("CronJob.spec.timeZone", Carried, r#""Europe/Helsinki""#),
    ("CronJob.spec.concurrencyPolicy", Carried, r#""Forbid""#),
    ("CronJob.spec.jobTemplate.metadata", Hint, r#"{"labels":{"a":"b"}}"#),
    ("CronJob.spec.jobTemplate.spec.backoffLimit", Carried, "2"),
    ("CronJob.spec.jobTemplate.spec.ttlSecondsAfterFinished", Hint, "60"),
    ("CronJob.spec.startingDeadlineSeconds", Hint, "60"),
    ("CronJob.spec.successfulJobsHistoryLimit", Hint, "3"),
    ("CronJob.spec.failedJobsHistoryLimit", Hint, "1"),
    ("CronJob.spec.suspend", Refused, "true"),
    // What they use.
    ("Service.spec.selector", Carried, r#"{"app":"web"}"#),
    ("Service.spec.ports[].port", Carried, "80"),
    ("Service.spec.ports[].name", Carried, r#""http""#),
    ("Service.spec.ports[].targetPort", Carried, "8080"),
    ("Service.spec.ports[].protocol", Carried, r#""TCP""#),
    ("Service.spec.ports[].nodePort", Hint, "30080"),
    ("Service.spec.ports[].appProtocol", Hint, r#""http""#),
    ("Service.spec.type", Hint, r#""LoadBalancer""#),
    ("Service.spec.clusterIP", Hint, r#""None""#),
    ("Service.spec.clusterIPs", Hint, r#"["None"]"#),
    ("Service.spec.ipFamilies", Hint, r#"["IPv4"]"#),
    ("Service.spec.ipFamilyPolicy", Hint, r#""SingleStack""#),
    ("Service.spec.sessionAffinity", Hint, r#""ClientIP""#),
    (
        "Service.spec.sessionAffinityConfig",
        Hint,
        r#"{"clientIP":{"timeoutSeconds":10}}"#,
    ),
    ("Service.spec.internalTrafficPolicy", Hint, r#""Cluster""#),
    ("Service.spec.externalTrafficPolicy", Hint, r#""Cluster""#),
    ("Service.spec.publishNotReadyAddresses", Hint, "true"),
    ("Service.spec.loadBalancerIP", Hint, r#""192.0.2.1""#),
    ("Service.spec.loadBalancerClass", Hint, r#""x""#),
    ("Service.spec.loadBalancerSourceRanges", Hint, r#"["192.0.2.0/24"]"#),
    ("Service.spec.allocateLoadBalancerNodePorts", Hint, "true"),
    ("Service.spec.healthCheckNodePort", Hint, "30000"),
    ("Service.spec.trafficDistribution", Hint, r#""PreferClose""#),
    ("Service.spec.externalIPs", Hint, r#"["192.0.2.1"]"#),
    ("Service.spec.externalName", Refused, r#""example.org""#),
    ("ConfigMap.data", Carried, r#"{"a":"b"}"#),
    ("ConfigMap.immutable", Hint, "true"),
    ("ConfigMap.binaryData", Refused, r#"{"a":"AA=="}"#),
    ("Secret.data", Carried, r#"{"a":"Yg=="}"#),
    ("Secret.stringData", Carried, r#"{"a":"b"}"#),
    ("Secret.type", Carried, r#""kubernetes.io/tls""#),
    ("Secret.immutable", Hint, "true"),
    (
        "PersistentVolumeClaim.spec.resources.requests.storage",
        Carried,
        r#""1Gi""#,
    ),
    (
        "PersistentVolumeClaim.spec.accessModes",
        Carried,
        r#"["ReadWriteMany"]"#,
    ),
    ("PersistentVolumeClaim.spec.storageClassName", Hint, r#""fast""#),
    ("PersistentVolumeClaim.spec.volumeMode", Refused, r#""Block""#),
    ("PersistentVolumeClaim.spec.volumeName", Refused, r#""pv1""#),
    (
        "PersistentVolumeClaim.spec.selector",
        Refused,
        r#"{"matchLabels":{"a":"b"}}"#,
    ),
    (
        "PersistentVolumeClaim.spec.dataSource",
        Refused,
        r#"{"kind":"VolumeSnapshot","name":"x"}"#,
    ),
    ("Ingress.spec.rules[].host", Carried, r#""web.example.org""#),
    ("Ingress.spec.rules[].http.paths[].path", Carried, r#""/""#),
    ("Ingress.spec.rules[].http.paths[].pathType", Carried, r#""Prefix""#),
    (
        "Ingress.spec.rules[].http.paths[].backend.service",
        Carried,
        r#"{"name":"web","port":{"number":80}}"#,
    ),
    (
        "Ingress.spec.rules[].http.paths[].backend.resource",
        Refused,
        r#"{"kind":"X","name":"x"}"#,
    ),
    (
        "Ingress.spec.tls",
        Hint,
        r#"[{"hosts":["web.example.org"],"secretName":"web-tls"}]"#,
    ),
    ("Ingress.spec.ingressClassName", Hint, r#""nginx""#),
    (
        "Ingress.spec.defaultBackend",
        Refused,
        r#"{"service":{"name":"web","port":{"number":80}}}"#,
    ),
];

/// `at` as [`FIELDS`] says a place: every index is `[]`, and the parts all kinds share
/// have their short names.
fn place(kind: &str, at: &str) -> String {
    let (mut plain, mut inside) = (String::new(), false);
    for c in at.chars() {
        match c {
            '[' => inside = true,
            ']' => {
                inside = false;
                plain.push_str("[]");
            }
            c if !inside => plain.push(c),
            _ => {}
        }
    }
    let shared = [
        ("template.spec.containers[].livenessProbe.", "probe."),
        ("template.spec.containers[].readinessProbe.", "probe."),
        ("template.spec.containers[].", "container."),
        ("template.spec.", "pod."),
        ("template.metadata.", "podmeta."),
    ];
    for (long, short) in shared {
        if let Some((_, rest)) = plain.split_once(long) {
            return format!("{short}{rest}");
        }
    }
    match plain.strip_prefix("metadata.") {
        Some(rest) => format!("meta.{rest}"),
        None => format!("{kind}.{plain}"),
    }
}

/// Is the place `inner` the place `outer`, or under it?
fn within(inner: &str, outer: &str) -> bool {
    let rest = inner.strip_prefix(outer);
    rest.is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '[']))
}

/// What [`FIELDS`] says of a place: its own row, or the nearest one it is under.
fn field(place: &str) -> Field {
    let rows = FIELDS.iter().filter(|(row, ..)| within(place, row));
    // (The longest: `secretKeyRef.optional` is said apart from `secretKeyRef`.)
    rows.max_by_key(|(row, ..)| row.len())
        .map_or(Refused, |(_, field, _)| *field)
}

/// One object being translated: what it collects names it.
struct Cx {
    who: String,
    /// `kith import` writes kith files: there what a kith resource cannot hold is lost,
    /// and Helm's hooks are nobody's to run.
    import: bool,
    hints: Vec<String>,
    refused: Vec<String>,
}

impl Cx {
    fn kind(&self) -> &str {
        self.who.split('/').next().unwrap_or_default()
    }

    fn whole(&mut self, why: &str) {
        self.refused.push(format!("{}: {why}", self.who));
    }

    /// What was asked at `at` is not done.
    fn note(&mut self, at: &str, why: &str) {
        self.refused.push(format!("{}: {at} {why}", self.who));
    }

    /// What was asked at `at` is taken, and changes nothing.
    fn hint(&mut self, at: &str, why: &str) {
        self.hints.push(format!("{}: {at} {why}", self.who));
    }

    /// Takes a mapping out of `m`.
    fn map(&mut self, m: &mut Map, key: &str, at: &str) -> Map {
        match m.remove(key) {
            Some(Value::Object(o)) => o,
            None | Some(Value::Null) => Map::new(),
            Some(_) => {
                self.note(&join(at, key), "should be a mapping: not translated");
                Map::new()
            }
        }
    }

    fn list(&mut self, m: &mut Map, key: &str, at: &str) -> Vec<Value> {
        match m.remove(key) {
            Some(Value::Array(a)) => a,
            None | Some(Value::Null) => Vec::new(),
            Some(_) => {
                self.note(&join(at, key), "should be a list: not translated");
                Vec::new()
            }
        }
    }

    /// A list of mappings.
    fn maps(&mut self, m: &mut Map, key: &str, at: &str) -> Vec<Map> {
        let mut found = Vec::new();
        for (i, item) in self.list(m, key, at).into_iter().enumerate() {
            match item {
                Value::Object(o) => found.push(o),
                _ => self.note(
                    &format!("{}[{i}]", join(at, key)),
                    "should be a mapping: not translated",
                ),
            }
        }
        found
    }

    fn text(&mut self, m: &mut Map, key: &str, at: &str) -> Option<String> {
        match m.remove(key)? {
            Value::String(s) => Some(s),
            v @ (Value::Number(_) | Value::Bool(_)) => Some(v.to_string()),
            Value::Null => None,
            _ => {
                self.note(&join(at, key), "should be text: not translated");
                None
            }
        }
    }

    fn num(&mut self, m: &mut Map, key: &str, at: &str) -> Option<u32> {
        let v = m.remove(key)?;
        let n = v.as_u64().and_then(|n| u32::try_from(n).ok());
        if n.is_none() && !v.is_null() {
            self.note(&join(at, key), "should be a whole number: not translated");
        }
        n
    }

    fn flag(&mut self, m: &mut Map, key: &str, at: &str) -> Option<bool> {
        let v = m.remove(key)?;
        if !v.is_null() && v.as_bool().is_none() {
            self.note(&join(at, key), "should be true or false: not translated");
        }
        v.as_bool()
    }

    /// A port by number or by name.
    fn port(&mut self, m: &mut Map, key: &str, at: &str) -> Option<Value> {
        match m.remove(key)? {
            v @ (Value::Number(_) | Value::String(_)) => Some(v),
            Value::Null => None,
            _ => {
                self.note(&join(at, key), "should be a port number or name: not translated");
                None
            }
        }
    }

    fn strs(&mut self, m: &mut Map, key: &str, at: &str) -> Vec<String> {
        let mut found = Vec::new();
        for (i, item) in self.list(m, key, at).into_iter().enumerate() {
            let mut one = Map::from_iter([("item".to_string(), item)]);
            found.extend(self.text(&mut one, "item", &format!("{}[{i}]", join(at, key))));
        }
        found
    }

    /// A mapping of text to text, as it is.
    fn string_map(&mut self, m: &mut Map, key: &str, at: &str) -> Strings {
        let mut found = Strings::new();
        for (k, v) in self.map(m, key, at) {
            let mut one = Map::from_iter([(k.clone(), v)]);
            if let Some(s) = self.text(&mut one, &k, &join(at, key)) {
                found.insert(k, s);
            }
        }
        found
    }

    /// Labels or annotations, less what is noise.
    fn strings(&mut self, m: &mut Map, key: &str, at: &str) -> Strings {
        let mut found = self.string_map(m, key, at);
        // (Noise, but for these: they change when and whether Helm applies the object.)
        let hooks = found
            .keys()
            .filter(|k| k.starts_with("helm.sh/hook") || *k == "helm.sh/resource-policy");
        let hooks: Vec<String> = hooks.filter(|_| self.import).cloned().collect();
        for k in hooks {
            let why = "not translated: kith has no Helm hooks, this is applied with the rest";
            self.note(&format!("{}[{k}]", join(at, key)), why);
        }
        found.retain(|k, _| !noisy(k));
        found
    }

    /// `v` as one of the kith words in `table`, or a note.
    fn pick(&mut self, at: &str, v: Option<String>, table: &[(&str, &str)]) -> Option<Value> {
        let v = v?;
        match table.iter().find(|(k8s, _)| *k8s == v) {
            Some((_, kith)) => Some(json!(kith)),
            None => {
                self.note(at, &format!("`{v}` not translated"));
                None
            }
        }
    }

    /// Whatever is still in `m` was not carried over: a hint where [`FIELDS`] says so.
    fn rest(&mut self, m: Map, at: &str) {
        for (k, v) in m {
            let at = join(at, &k);
            if is_empty(&v) {
                continue;
            }
            let place = place(self.kind(), &at);
            match (field(&place), v) {
                (Hint, _) => self.hint(&at, "is taken and changes nothing: kith has no use for it"),
                // (A mapping with rows of its own: each part is said for itself.)
                (_, Value::Object(parts)) if FIELDS.iter().any(|(row, ..)| *row != place && within(row, &place)) => {
                    self.rest(parts, &at)
                }
                _ => self.note(&at, "not translated"),
            }
        }
    }

    /// The `metadata` of the object in `root`; none without a name.
    fn meta(&mut self, root: &mut Map, at: &str) -> Option<Metadata> {
        let mut m = self.map(root, "metadata", at);
        let p = join(at, "metadata");
        for key in NOISE {
            m.remove(*key);
        }
        let name = self.text(&mut m, "name", &p);
        let namespace = self.text(&mut m, "namespace", &p);
        let labels = self.strings(&mut m, "labels", &p);
        let annotations = self.strings(&mut m, "annotations", &p);
        self.rest(m, &p);
        Some(Metadata {
            name: name?,
            namespace,
            labels,
            annotations,
            revision: None,
        })
    }
}

/// `cpu` and `memory`: the request, else the limit (kith has one amount).
fn quantities(cx: &mut Cx, mut res: Map, at: &str) -> Option<Value> {
    let (mut requests, mut limits) = (cx.map(&mut res, "requests", at), cx.map(&mut res, "limits", at));
    let (rp, lp) = (join(at, "requests"), join(at, "limits"));
    let mut amounts = [None, None];
    for (slot, key) in amounts.iter_mut().zip(["cpu", "memory"]) {
        let (request, limit) = (cx.text(&mut requests, key, &rp), cx.text(&mut limits, key, &lp));
        if request.is_some() && limit.is_some() && request != limit {
            cx.hint(&join(&lp, key), "is not used: kith has one amount, the request");
        }
        *slot = request.or(limit).filter(|q| match Quantity::try_from(q.clone()) {
            Ok(_) => true,
            Err(e) => {
                cx.note(&join(at, key), &format!("not translated: {e}"));
                false
            }
        });
    }
    cx.rest(requests, &rp);
    cx.rest(limits, &lp);
    cx.rest(res, at);
    let [cpu, memory] = amounts;
    nonempty(obj([("cpu", some(cpu)), ("memory", some(memory))]))
}

/// A `{name, key}` reference from `secretKeyRef` or `configMapKeyRef`.
fn key_ref(cx: &mut Cx, from: &mut Map, key: &str, at: &str) -> Option<Value> {
    let mut r = cx.map(from, key, at);
    let p = join(at, key);
    let (name, k) = (cx.text(&mut r, "name", &p), cx.text(&mut r, "key", &p));
    drop_default(&mut r, "optional", json!(false));
    cx.rest(r, &p);
    Some(json!({ "name": name?, "key": k? }))
}

fn probe(cx: &mut Cx, container: &mut Map, key: &str, at: &str) -> Option<Value> {
    let mut pr = cx.map(container, key, at);
    if pr.is_empty() {
        return None;
    }
    let p = join(at, key);
    let (mut http, mut tcp, mut exec) = (
        cx.map(&mut pr, "httpGet", &p),
        cx.map(&mut pr, "tcpSocket", &p),
        cx.map(&mut pr, "exec", &p),
    );
    let (hp, tp, ep) = (join(&p, "httpGet"), join(&p, "tcpSocket"), join(&p, "exec"));
    let mut checks = Vec::new();
    if !http.is_empty() {
        // k8s: the path is "/" when there is none.
        let path = cx.text(&mut http, "path", &hp).unwrap_or_else(|| "/".into());
        let port = cx.port(&mut http, "port", &hp);
        drop_default(&mut http, "scheme", json!("HTTP"));
        checks.extend(port.map(|port| ("http", json!({ "path": path, "port": port }))));
    }
    if !tcp.is_empty() {
        let port = cx.port(&mut tcp, "port", &tp);
        checks.extend(port.map(|port| ("tcp", json!({ "port": port }))));
    }
    let command = cx.strs(&mut exec, "command", &ep);
    checks.extend((!command.is_empty()).then(|| ("exec", json!(command))));
    cx.rest(http, &hp);
    cx.rest(tcp, &tp);
    cx.rest(exec, &ep);
    if checks.len() > 1 {
        cx.note(&p, "has more than one check: not translated");
    }
    let check = checks.into_iter().next();
    let interval = cx.num(&mut pr, "periodSeconds", &p);
    let timeout = cx.num(&mut pr, "timeoutSeconds", &p);
    let failures = cx.num(&mut pr, "failureThreshold", &p);
    cx.rest(pr, &p);
    let Some((how, value)) = check else {
        cx.note(&p, "has no http, tcp or exec check kith can run: not translated");
        return None;
    };
    Some(obj([
        (how, Some(value)),
        ("intervalSeconds", some(interval)),
        ("timeoutSeconds", some(timeout)),
        ("failureThreshold", some(failures)),
    ]))
}

/// The mounts of a pod's volumes that are claims: volume name to claim name.
type Volumes = BTreeMap<String, Option<String>>;

/// `seccompProfile`: is the filter off? None where nothing is said.
fn unconfined(cx: &mut Cx, security: &mut Map, at: &str) -> Option<bool> {
    let (mut profile, p) = (cx.map(security, "seccompProfile", at), join(at, "seccompProfile"));
    let kind = cx.text(&mut profile, "type", &p);
    cx.rest(profile, &p);
    match kind?.as_str() {
        // (What kith filters is what a runtime's default does.)
        "RuntimeDefault" => Some(false),
        "Unconfined" => Some(true),
        other => {
            cx.note(&join(&p, "type"), &format!("`{other}` not translated"));
            None
        }
    }
}

/// `of_pod`: the user and the filter the pod says for all its containers.
fn container(cx: &mut Cx, mut c: Map, at: &str, vols: &Volumes, of_pod: (Option<u32>, Option<bool>)) -> Option<Value> {
    let (Some(name), p) = (cx.text(&mut c, "name", at), join(at, "containers")) else {
        cx.note(
            &join(at, "containers"),
            "has a container without a name: not translated",
        );
        return None;
    };
    let p = format!("{p}[{name}]");
    let Some(image) = cx.text(&mut c, "image", &p) else {
        cx.note(&p, "has no image: not translated");
        return None;
    };
    let pull = cx.text(&mut c, "imagePullPolicy", &p);
    let pull = cx.pick(
        &join(&p, "imagePullPolicy"),
        pull,
        &[
            ("IfNotPresent", "ifNotPresent"),
            ("Always", "always"),
            ("Never", "never"),
        ],
    );
    let command = cx.strs(&mut c, "command", &p);
    let args = cx.strs(&mut c, "args", &p);
    let mut env = Vec::new();
    for mut e in cx.maps(&mut c, "env", &p) {
        let Some(var) = cx.text(&mut e, "name", &p) else {
            cx.note(&join(&p, "env"), "has a variable without a name: not translated");
            continue;
        };
        let ep = format!("{p}.env[{var}]");
        let mut value = cx.text(&mut e, "value", &ep);
        let from_there = e.contains_key("valueFrom");
        let mut from = cx.map(&mut e, "valueFrom", &ep);
        let fp = join(&ep, "valueFrom");
        let secret = key_ref(cx, &mut from, "secretKeyRef", &fp);
        let config_map = key_ref(cx, &mut from, "configMapKeyRef", &fp);
        cx.rest(from, &fp);
        cx.rest(e, &ep);
        if !from_there && value.is_none() {
            value = Some(String::new());
        }
        if value.is_none() && secret.is_none() && config_map.is_none() {
            cx.note(&ep, "has no value kith can read: not translated");
            continue;
        }
        env.push(obj([
            ("name", Some(json!(var))),
            ("value", some(value)),
            ("secret", secret),
            ("configMap", config_map),
        ]));
    }
    let working_dir = cx.text(&mut c, "workingDir", &p);
    let res = cx.map(&mut c, "resources", &p);
    let resources = quantities(cx, res, &join(&p, "resources"));
    let mut ports = Vec::new();
    for (i, mut port) in cx.maps(&mut c, "ports", &p).into_iter().enumerate() {
        let pp = format!("{p}.ports[{i}]");
        let (pname, number) = (cx.text(&mut port, "name", &pp), cx.num(&mut port, "containerPort", &pp));
        let protocol = cx.text(&mut port, "protocol", &pp);
        let protocol = cx.pick(&join(&pp, "protocol"), protocol, &[("TCP", "tcp"), ("UDP", "udp")]);
        cx.rest(port, &pp);
        match number {
            Some(number) => ports.push(obj([
                ("name", some(pname)),
                ("port", Some(json!(number))),
                ("protocol", protocol),
            ])),
            None => cx.note(&pp, "has no containerPort: not translated"),
        }
    }
    let mut mounts = Vec::new();
    for mut mount in cx.maps(&mut c, "volumeMounts", &p) {
        let volume = cx.text(&mut mount, "name", &p).unwrap_or_default();
        let mp = format!("{p}.volumeMounts[{volume}]");
        let path = cx.text(&mut mount, "mountPath", &mp);
        let read_only = cx.flag(&mut mount, "readOnly", &mp);
        cx.rest(mount, &mp);
        match (vols.get(&volume), path) {
            (Some(Some(claim)), Some(path)) => mounts.push(obj([
                ("volume", Some(json!(claim))),
                ("path", Some(json!(path))),
                ("readOnly", some(read_only)),
            ])),
            (Some(None), _) => cx.note(&mp, "not translated: its volume is not a PersistentVolumeClaim"),
            (None, _) => cx.note(&mp, "not translated: the pod has no volume of that name"),
            (_, None) => cx.note(&mp, "has no mountPath: not translated"),
        }
    }
    let liveness = probe(cx, &mut c, "livenessProbe", &p);
    let readiness = probe(cx, &mut c, "readinessProbe", &p);
    let (mut security, scp) = (cx.map(&mut c, "securityContext", &p), join(&p, "securityContext"));
    let read_only_root = cx.flag(&mut security, "readOnlyRootFilesystem", &scp);
    let user = cx.num(&mut security, "runAsUser", &scp).or(of_pod.0);
    let unconfined = unconfined(cx, &mut security, &scp).or(of_pod.1);
    drop_default(&mut security, "privileged", json!(false));
    if cx.flag(&mut security, "allowPrivilegeEscalation", &scp) == Some(true) {
        let at = join(&scp, "allowPrivilegeEscalation");
        cx.hint(&at, "is not done: nothing kith runs can gain privileges");
    }
    cx.rest(security, &scp);
    drop_default(&mut c, "terminationMessagePath", json!("/dev/termination-log"));
    drop_default(&mut c, "terminationMessagePolicy", json!("File"));
    cx.rest(c, &p);
    Some(obj([
        ("name", Some(json!(name))),
        ("image", Some(json!(image))),
        ("pullPolicy", pull),
        ("command", nonempty(json!(command))),
        ("args", nonempty(json!(args))),
        ("env", nonempty(json!(env))),
        ("workingDir", some(working_dir)),
        ("resources", resources),
        ("ports", nonempty(json!(ports))),
        ("volumeMounts", nonempty(json!(mounts))),
        ("liveness", liveness),
        ("readiness", readiness),
        ("readOnlyRoot", some(read_only_root)),
        ("runAsUser", some(user)),
        (
            "seccomp",
            unconfined.filter(|off| *off).map(|_| json!({ "unconfined": true })),
        ),
    ]))
}

/// A pod template, as kith has it, and the parts of it that live elsewhere in kith.
struct Pod {
    template: Value,
    labels: Strings,
    node_selector: Strings,
    priority_class: Option<String>,
}

/// `claims`: volumes the pod gets from a StatefulSet's `volumeClaimTemplates`, by name.
fn pod(cx: &mut Cx, mut tpl: Map, at: &str, claims: &Strings, has_priority: bool) -> Pod {
    let mut md = cx.map(&mut tpl, "metadata", at);
    let mp = join(at, "metadata");
    let labels = cx.strings(&mut md, "labels", &mp);
    cx.rest(md, &mp);
    let sp = join(at, "spec");
    let mut s = cx.map(&mut tpl, "spec", at);
    cx.rest(tpl, at);

    let mut vols: Volumes = claims.iter().map(|(k, v)| (k.clone(), Some(v.clone()))).collect();
    for mut v in cx.maps(&mut s, "volumes", &sp) {
        let Some(name) = cx.text(&mut v, "name", &sp) else {
            cx.note(&join(&sp, "volumes"), "has a volume without a name: not translated");
            continue;
        };
        let vp = format!("{sp}.volumes[{name}]");
        let mut claim = cx.map(&mut v, "persistentVolumeClaim", &vp);
        let cp = join(&vp, "persistentVolumeClaim");
        let claim_name = cx.text(&mut claim, "claimName", &cp);
        cx.rest(claim, &cp);
        cx.rest(v, &vp);
        vols.insert(name, claim_name);
    }
    let (mut security, scp) = (cx.map(&mut s, "securityContext", &sp), join(&sp, "securityContext"));
    let of_pod = (
        cx.num(&mut security, "runAsUser", &scp),
        unconfined(cx, &mut security, &scp),
    );
    cx.rest(security, &scp);
    let containers = cx.maps(&mut s, "containers", &sp);
    let units: Vec<Value> = containers
        .into_iter()
        .filter_map(|c| container(cx, c, &sp, &vols, of_pod))
        .collect();
    // What Kubernetes assumes anyway, and tools write out.
    for (key, default) in [
        ("hostNetwork", json!(false)),
        ("hostPID", json!(false)),
        ("hostIPC", json!(false)),
        ("shareProcessNamespace", json!(false)),
        ("dnsPolicy", json!("ClusterFirst")),
        ("schedulerName", json!("default-scheduler")),
        ("terminationGracePeriodSeconds", json!(30)),
        ("enableServiceLinks", json!(true)),
    ] {
        drop_default(&mut s, key, default);
    }
    let restart = cx.text(&mut s, "restartPolicy", &sp);
    let restart = cx.pick(
        &join(&sp, "restartPolicy"),
        restart,
        &[("Always", "always"), ("OnFailure", "onFailure"), ("Never", "never")],
    );
    let node_selector = cx.strings(&mut s, "nodeSelector", &sp);
    let priority_class = cx.text(&mut s, "priorityClassName", &sp);
    if !has_priority && priority_class.is_some() {
        cx.hint(
            &join(&sp, "priorityClassName"),
            "is not used: only a Workload has a priority",
        );
    }
    cx.rest(s, &sp);
    Pod {
        // What was written for Kubernetes runs as Kubernetes runs it: a network of the
        // pod's own, a root it can write to, the user its image names.
        template: obj([
            ("containers", nonempty(json!(units))),
            ("restartPolicy", restart),
            ("pod", Some(json!(true))),
        ]),
        labels,
        node_selector,
        priority_class: priority_class.filter(|_| has_priority),
    }
}

/// `nodeSelector` as placement: every label must match.
fn placement(node_selector: &Strings) -> Option<Value> {
    let require: Strings = node_selector
        .iter()
        .map(|(k, v)| (format!("node.labels.{k}"), v.clone()))
        .collect();
    nonempty(json!(require)).map(|require| json!({ "require": require }))
}

/// `strategy` or `updateStrategy`: only its type has a place.
fn strategy(cx: &mut Cx, spec: &mut Map, key: &str, at: &str) -> Option<Value> {
    let mut s = cx.map(spec, key, at);
    let p = join(at, key);
    let kind = cx.text(&mut s, "type", &p);
    let kind = cx.pick(
        &join(&p, "type"),
        kind,
        &[("RollingUpdate", "rolling"), ("Recreate", "recreate")],
    );
    cx.rest(s, &p);
    kind
}

fn selector_is_implied(cx: &mut Cx, spec: &mut Map, at: &str) {
    // ponytail: matchLabels is what the template's labels already say; only matchExpressions is lost.
    let mut selector = cx.map(spec, "selector", at);
    selector.remove("matchLabels");
    cx.rest(selector, &join(at, "selector"));
}

type Out<'a> = &'a mut Vec<Resource>;

fn make(kind: &str, meta: Metadata, spec: Value) -> Resource {
    Resource {
        api_version: "kith.dev/v1".into(),
        kind: kind.into(),
        metadata: meta,
        spec,
        status: None,
    }
}

/// A `PersistentVolumeClaim`'s spec; `at` is its path.
fn claim_spec(cx: &mut Cx, mut s: Map, at: &str) -> Option<Value> {
    let res = cx.map(&mut s, "resources", at);
    let (mut res, rp) = (res, join(at, "resources"));
    let mut requests = cx.map(&mut res, "requests", &rp);
    let size = cx.text(&mut requests, "storage", &join(&rp, "requests"));
    cx.rest(requests, &join(&rp, "requests"));
    cx.rest(res, &rp);
    let modes = cx.strs(&mut s, "accessModes", at);
    for mode in modes
        .iter()
        .filter(|m| !["ReadWriteOnce", "ReadWriteMany"].contains(&m.as_str()))
    {
        cx.hint(&join(at, "accessModes"), &format!("`{mode}` is taken as ReadWriteOnce"));
    }
    drop_default(&mut s, "volumeMode", json!("Filesystem"));
    cx.rest(s, at);
    let shared = modes.iter().any(|m| m == "ReadWriteMany").then_some(true);
    let Some(size) = size else {
        cx.note(&join(&rp, "requests.storage"), "is missing: not translated");
        return None;
    };
    Some(obj([("size", Some(json!(size))), ("shared", some(shared))]))
}

/// Deployment, StatefulSet and DaemonSet.
fn workload(cx: &mut Cx, root: &mut Map, mut meta: Metadata, kind: &str, out: Out) {
    let mut spec = cx.map(root, "spec", "");
    let tpl = cx.map(&mut spec, "template", "spec");
    selector_is_implied(cx, &mut spec, "spec");
    let replicas = if kind == "DaemonSet" {
        None
    } else {
        cx.num(&mut spec, "replicas", "spec")
    };
    let mut claims = Strings::new();
    if kind == "StatefulSet" {
        for (i, mut t) in cx
            .maps(&mut spec, "volumeClaimTemplates", "spec")
            .into_iter()
            .enumerate()
        {
            let tp = format!("spec.volumeClaimTemplates[{i}]");
            let Some(mut claim) = cx.meta(&mut t, &tp) else {
                cx.note(&tp, "has no name: not translated");
                continue;
            };
            let template = std::mem::take(&mut claim.name);
            claim.name = format!("{template}-{}", meta.name);
            claim.namespace.clone_from(&meta.namespace);
            if replicas.is_some_and(|n| n > 1) {
                cx.note(
                    &tp,
                    "would be one claim shared by all replicas: kith has no claim of each replica's own yet",
                );
            }
            let s = cx.map(&mut t, "spec", &tp);
            let spec_of_claim = claim_spec(cx, s, &join(&tp, "spec"));
            t.remove("status");
            cx.rest(t, &tp);
            if let Some(s) = spec_of_claim {
                claims.insert(template, claim.name.clone());
                out.push(make("VolumeClaim", claim, s));
            }
        }
    }
    let node = kind == "DaemonSet";
    let pod = pod(cx, tpl, "spec.template", &claims, !node);
    meta.labels.extend(pod.labels);
    let spec_value = if node {
        let selector = nonempty(json!(pod.node_selector));
        obj([("selector", selector), ("template", Some(pod.template))])
    } else {
        let key = if kind == "StatefulSet" {
            "updateStrategy"
        } else {
            "strategy"
        };
        obj([
            ("replicas", some(replicas)),
            ("strategy", strategy(cx, &mut spec, key, "spec")),
            ("template", Some(pod.template)),
            ("placement", placement(&pod.node_selector)),
            ("priorityClass", some(pod.priority_class)),
        ])
    };
    cx.rest(spec, "spec");
    out.push(make(if node { "NodeWorkload" } else { "Workload" }, meta, spec_value));
}

/// A Job's spec, at `at`; the labels of its pods come back with it.
fn job_spec(cx: &mut Cx, mut spec: Map, at: &str) -> (Value, Strings) {
    let tpl = cx.map(&mut spec, "template", at);
    let completions = cx.num(&mut spec, "completions", at);
    let parallelism = cx.num(&mut spec, "parallelism", at);
    let retries = cx.num(&mut spec, "backoffLimit", at);
    let timeout = cx.num(&mut spec, "activeDeadlineSeconds", at);
    drop_default(&mut spec, "suspend", json!(false));
    drop_default(&mut spec, "completionMode", json!("NonIndexed"));
    cx.rest(spec, at);
    let pod = pod(cx, tpl, &join(at, "template"), &Strings::new(), false);
    let value = obj([
        ("template", Some(pod.template)),
        ("completions", some(completions)),
        ("parallelism", some(parallelism)),
        ("retries", some(retries)),
        ("timeoutSeconds", some(timeout)),
        ("placement", placement(&pod.node_selector)),
    ]);
    (value, pod.labels)
}

fn cron_job(cx: &mut Cx, root: &mut Map, mut meta: Metadata, out: Out) {
    let mut spec = cx.map(root, "spec", "");
    let schedule = cx.text(&mut spec, "schedule", "spec");
    let timezone = cx.text(&mut spec, "timeZone", "spec");
    let concurrency = cx.text(&mut spec, "concurrencyPolicy", "spec");
    let concurrency = cx.pick(
        "spec.concurrencyPolicy",
        concurrency,
        &[("Allow", "allow"), ("Forbid", "forbid"), ("Replace", "replace")],
    );
    drop_default(&mut spec, "suspend", json!(false));
    let mut template = cx.map(&mut spec, "jobTemplate", "spec");
    let jp = "spec.jobTemplate";
    let job = cx.map(&mut template, "spec", jp);
    let (job, labels) = job_spec(cx, job, "spec.jobTemplate.spec");
    cx.rest(template, jp);
    cx.rest(spec, "spec");
    let Some(schedule) = schedule else {
        cx.note("spec.schedule", "is missing: not translated");
        return;
    };
    meta.labels.extend(labels);
    let spec = obj([
        ("schedule", Some(json!(schedule))),
        ("timezone", some(timezone)),
        ("concurrency", concurrency),
        ("job", Some(job)),
    ]);
    out.push(make("CronJob", meta, spec));
}

fn service(cx: &mut Cx, root: &mut Map, meta: Metadata, out: Out) {
    let mut spec = cx.map(root, "spec", "");
    let selector = cx.strings(&mut spec, "selector", "spec");
    let mut ports = Vec::new();
    for (i, mut p) in cx.maps(&mut spec, "ports", "spec").into_iter().enumerate() {
        let pp = format!("spec.ports[{i}]");
        let (name, port) = (cx.text(&mut p, "name", &pp), cx.num(&mut p, "port", &pp));
        let target = cx.port(&mut p, "targetPort", &pp);
        let protocol = cx.text(&mut p, "protocol", &pp);
        let protocol = cx.pick(&join(&pp, "protocol"), protocol, &[("TCP", "tcp"), ("UDP", "udp")]);
        cx.rest(p, &pp);
        match port {
            Some(port) => ports.push(obj([
                ("name", some(name)),
                ("port", Some(json!(port))),
                ("targetPort", target),
                ("protocol", protocol),
            ])),
            None => cx.note(&pp, "has no port: not translated"),
        }
    }
    drop_default(&mut spec, "type", json!("ClusterIP"));
    drop_default(&mut spec, "sessionAffinity", json!("None"));
    cx.rest(spec, "spec");
    if selector.is_empty() {
        cx.note(
            "spec.selector",
            "is missing: kith finds a Service's workloads by label, so it is not translated",
        );
        return;
    }
    out.push(make(
        "Service",
        meta,
        obj([("selector", Some(json!(selector))), ("ports", Some(json!(ports)))]),
    ));
}

fn unbase64(s: &str) -> Option<Vec<u8>> {
    // Strictly: a value that is not base64 to its end is an error, never a shorter value.
    let s: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let data = s.strip_suffix("==").or(s.strip_suffix('=')).unwrap_or(&s);
    if data.len() % 4 == 1 || (data.len() != s.len() && !s.len().is_multiple_of(4)) {
        return None;
    }
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for b in data.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = acc << 6 | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(out)
}

fn config_map(cx: &mut Cx, root: &mut Map, meta: Metadata, out: Out) {
    let data = cx.string_map(root, "data", "");
    drop_default(root, "immutable", json!(false));
    out.push(make("ConfigMap", meta, obj([("data", nonempty(json!(data)))])));
}

fn secret(cx: &mut Cx, root: &mut Map, meta: Metadata, out: Out) {
    let mut data = Strings::new();
    for (k, v) in cx.string_map(root, "data", "") {
        match unbase64(&v).map(String::from_utf8) {
            Some(Ok(text)) => {
                data.insert(k, text);
            }
            Some(Err(_)) => cx.note(&format!("data.{k}"), "is not text: not translated"),
            None => cx.note(&format!("data.{k}"), "is not base64: not translated"),
        }
    }
    // stringData is what data would be, and wins.
    data.extend(cx.string_map(root, "stringData", ""));
    if let Some(kind) = cx.text(root, "type", "").filter(|t| t != "Opaque" && cx.import) {
        cx.hint("type", &format!("`{kind}` is not kept: a kith Secret is its data"));
    }
    drop_default(root, "immutable", json!(false));
    out.push(make("Secret", meta, obj([("data", nonempty(json!(data)))])));
}

fn volume_claim(cx: &mut Cx, root: &mut Map, meta: Metadata, out: Out) {
    let spec = cx.map(root, "spec", "");
    if let Some(spec) = claim_spec(cx, spec, "spec") {
        out.push(make("VolumeClaim", meta, spec));
    }
}

/// An Ingress is not a resource of its own: its hosts become `expose` on the Services behind them.
fn ingress(cx: &mut Cx, meta: Metadata, root: &mut Map, out: Out) {
    // (An Ingress is kept by who took it, as it was sent; a kith file has no place for these.)
    if !meta.labels.is_empty() && cx.import {
        cx.hint("metadata.labels", "are not kept: kith has no resource for an Ingress");
    }
    let import = cx.import;
    for key in meta.annotations.keys().filter(|key| import || key.contains("ingress")) {
        cx.hint(
            &format!("metadata.annotations[{key}]"),
            "is not used: kith's edge has no such setting",
        );
    }
    let namespace = meta.namespace.as_deref().unwrap_or("default");
    let mut spec = cx.map(root, "spec", "");
    for (i, mut tls) in cx.maps(&mut spec, "tls", "spec").into_iter().enumerate() {
        // The hosts come from the rules; `secretName` is what is left to report.
        tls.remove("hosts");
        cx.rest(tls, &format!("spec.tls[{i}]"));
    }
    for (i, mut rule) in cx.maps(&mut spec, "rules", "spec").into_iter().enumerate() {
        let rp = format!("spec.rules[{i}]");
        let host = cx.text(&mut rule, "host", &rp);
        let mut http = cx.map(&mut rule, "http", &rp);
        let hp = join(&rp, "http");
        for (j, mut path) in cx.maps(&mut http, "paths", &hp).into_iter().enumerate() {
            let pp = format!("{hp}.paths[{j}]");
            let route = cx.text(&mut path, "path", &pp);
            // ponytail: pathType is not read; kith sends the whole host to one Service.
            path.remove("pathType");
            let mut backend = cx.map(&mut path, "backend", &pp);
            let bp = join(&pp, "backend");
            let mut svc = cx.map(&mut backend, "service", &bp);
            let sp = join(&bp, "service");
            let name = cx.text(&mut svc, "name", &sp);
            let mut port = cx.map(&mut svc, "port", &sp);
            let (number, port_name) = (cx.num(&mut port, "number", &sp), cx.text(&mut port, "name", &sp));
            cx.rest(port, &join(&sp, "port"));
            cx.rest(svc, &sp);
            cx.rest(backend, &bp);
            cx.rest(path, &pp);
            if route.is_some_and(|r| r != "/") {
                // (Exposing this backend too would have two Services claim one host.)
                cx.note(
                    &pp,
                    "not translated: kith sends a whole host to one Service, the one behind `/`",
                );
                continue;
            }
            let (Some(host), Some(name)) = (&host, name) else {
                cx.note(&pp, "needs a host and a Service backend: not translated");
                continue;
            };
            let taken = out.iter().find(|r| {
                let other =
                    r.metadata.name != name || r.metadata.namespace.as_deref().unwrap_or("default") != namespace;
                r.kind == "Service" && other && r.spec["expose"]["host"] == host.as_str()
            });
            if let Some(taken) = taken {
                let why = format!(
                    "not translated: {host} already goes to Service `{}`",
                    taken.metadata.name
                );
                cx.note(&pp, &why);
                continue;
            }
            let found = out.iter_mut().find(|r| {
                r.kind == "Service"
                    && r.metadata.name == name
                    && r.metadata.namespace.as_deref().unwrap_or("default") == namespace
            });
            let Some(service) = found else {
                let why = format!("Service `{name}` is not there: it is exposed once it is");
                match cx.import {
                    true => cx.note(&bp, &why),
                    false => cx.hint(&bp, &why),
                }
                continue;
            };
            let ports = service.spec["ports"].as_array().cloned().unwrap_or_default();
            if let Some(first) = ports.iter().find(|p| p["protocol"] != "udp") {
                let wrong = number.is_some_and(|n| first["port"] != n)
                    || port_name.as_ref().is_some_and(|n| first["name"] != *n);
                if wrong {
                    cx.note(
                        &join(&sp, "port"),
                        "is not the Service's first TCP port, which is what kith sends the host to",
                    );
                }
            }
            let expose = json!({ "host": host, "via": "edge" });
            match service.spec.get("expose") {
                None => service.spec["expose"] = expose,
                Some(have) if *have == expose => {}
                Some(_) => cx.note(&pp, "is a second host for its Service: not translated"),
            }
        }
        cx.rest(http, &hp);
        cx.rest(rule, &rp);
    }
    cx.rest(spec, "spec");
}

/// What a set of Kubernetes objects comes to.
#[derive(Debug, Default)]
pub struct Taken {
    pub resources: Vec<Resource>,
    /// What was taken and changes nothing, one line each (`Kind/name: where why`).
    pub hints: Vec<String>,
    /// What would not be done as it was asked, one line each: who asked for any of it is
    /// better told no than given the rest.
    pub refused: Vec<String>,
}

/// For `kith import`: the kith resources, and all that was left behind in one report.
pub fn translate(objects: Vec<Value>) -> (Vec<Resource>, Vec<String>) {
    let taken = take(objects, true);
    (taken.resources, [taken.refused, taken.hints].concat())
}

/// Kubernetes objects as kith resources. `import`: they become kith files (what only the
/// object as it was sent can hold is then lost, and is said).
pub fn take(objects: Vec<Value>, import: bool) -> Taken {
    let (mut out, mut ingresses) = (Vec::new(), Vec::new());
    let (mut hints, mut report) = (Vec::new(), Vec::new());
    // A stack, so that a List's items come out in their order.
    let mut queue: Vec<Value> = objects.into_iter().rev().collect();
    let mut n = 0;
    while let Some(object) = queue.pop() {
        n += 1;
        let mut root = match object {
            Value::Null => continue,
            Value::Object(m) => m,
            _ => {
                report.push(format!("object {n}: is not a mapping: not translated"));
                continue;
            }
        };
        let kind = root
            .remove("kind")
            .and_then(|k| k.as_str().map(String::from))
            .unwrap_or_default();
        if kind.ends_with("List")
            && let Some(Value::Array(items)) = root.remove("items")
        {
            queue.extend(items.into_iter().rev());
            continue;
        }
        let name = root.get("metadata").and_then(|m| m["name"].as_str()).unwrap_or("?");
        let mut cx = Cx {
            who: if kind.is_empty() {
                format!("object {n}")
            } else {
                format!("{kind}/{name}")
            },
            import,
            hints: Vec::new(),
            refused: Vec::new(),
        };
        let known = [
            "Deployment",
            "StatefulSet",
            "DaemonSet",
            "Service",
            "ConfigMap",
            "Secret",
            "PersistentVolumeClaim",
            "Job",
            "CronJob",
            "Ingress",
        ];
        if !known.contains(&kind.as_str()) {
            let why = if kind.is_empty() {
                "has no `kind`"
            } else {
                "is a kind kith has nothing for"
            };
            cx.whole(&format!("{why}: not translated"));
            report.append(&mut cx.refused);
            continue;
        }
        root.remove("apiVersion");
        root.remove("status");
        let Some(meta) = cx.meta(&mut root, "") else {
            cx.whole("has no metadata.name: not translated");
            report.append(&mut cx.refused);
            continue;
        };
        if kind == "Ingress" {
            ingresses.push((cx, meta, root));
            continue;
        }
        let mut made = Vec::new();
        match kind.as_str() {
            "Deployment" | "StatefulSet" | "DaemonSet" => workload(&mut cx, &mut root, meta, &kind, &mut made),
            "Service" => service(&mut cx, &mut root, meta, &mut made),
            "ConfigMap" => config_map(&mut cx, &mut root, meta, &mut made),
            "Secret" => secret(&mut cx, &mut root, meta, &mut made),
            "PersistentVolumeClaim" => volume_claim(&mut cx, &mut root, meta, &mut made),
            "Job" => {
                let spec = cx.map(&mut root, "spec", "");
                let (spec, labels) = job_spec(&mut cx, spec, "spec");
                let mut meta = meta;
                meta.labels.extend(labels);
                made.push(make("Job", meta, spec));
            }
            _ => cron_job(&mut cx, &mut root, meta, &mut made),
        }
        cx.rest(root, "");
        for resource in made {
            let key = resource.key();
            match resource.validated() {
                Ok(resource) => out.push(resource),
                Err(e) => cx.whole(&format!("{key} is not valid: {e}")),
            }
        }
        hints.append(&mut cx.hints);
        report.append(&mut cx.refused);
    }
    // Ingresses last: they change Services that may come after them in the input.
    for (mut cx, meta, mut root) in ingresses {
        ingress(&mut cx, meta, &mut root, &mut out);
        cx.rest(root, "");
        hints.append(&mut cx.hints);
        report.append(&mut cx.refused);
    }
    Taken {
        resources: out,
        hints,
        refused: report,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEN: &str = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
  labels:
    app: web
    app.kubernetes.io/managed-by: Helm
  creationTimestamp: "2024-01-01T00:00:00Z"
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web
  strategy:
    type: Recreate
  template:
    metadata:
      labels:
        app: web
    spec:
      nodeSelector:
        disk: ssd
      containers:
        - name: app
          image: nginx:1.27
          imagePullPolicy: IfNotPresent
          args:
            - serve
          env:
            - name: MODE
              value: prod
            - name: TOKEN
              valueFrom:
                secretKeyRef:
                  name: creds
                  key: token
            - name: LEVEL
              valueFrom:
                configMapKeyRef:
                  name: settings
                  key: level
          ports:
            - containerPort: 8080
              name: http
          resources:
            requests:
              cpu: 500m
              memory: 256Mi
            limits:
              cpu: 500m
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            periodSeconds: 5
          livenessProbe:
            tcpSocket:
              port: 8080
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: data
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
spec:
  replicas: 1
  serviceName: db
  selector:
    matchLabels:
      app: db
  volumeClaimTemplates:
    - metadata:
        name: pgdata
      spec:
        accessModes:
          - ReadWriteOnce
        resources:
          requests:
            storage: 10Gi
  template:
    metadata:
      labels:
        app: db
    spec:
      containers:
        - name: pg
          image: postgres:16
          volumeMounts:
            - name: pgdata
              mountPath: /var/lib/postgresql
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: agent
spec:
  selector:
    matchLabels:
      app: agent
  template:
    metadata:
      labels:
        app: agent
    spec:
      nodeSelector:
        role: edge
      containers:
        - name: agent
          image: agent:1
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: shop
spec:
  type: ClusterIP
  selector:
    app: web
  ports:
    - name: http
      port: 80
      targetPort: 8080
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
data:
  level: debug
---
apiVersion: v1
kind: Secret
metadata:
  name: creds
type: Opaque
data:
  token: aHVudGVyMg==
stringData:
  user: admin
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data
  namespace: shop
spec:
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 1Gi
---
apiVersion: batch/v1
kind: Job
metadata:
  name: migrate
spec:
  backoffLimit: 2
  completions: 1
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: m
          image: migrate:1
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
spec:
  schedule: "0 3 * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: c
              image: cleaner:1
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: shop
spec:
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web
                port:
                  number: 80
"#;

    fn run(src: &str) -> (Vec<Resource>, Vec<String>) {
        translate(documents("test", src).unwrap())
    }

    fn find<'a>(all: &'a [Resource], kind: &str, name: &str) -> &'a Resource {
        all.iter()
            .find(|r| r.kind == kind && r.metadata.name == name)
            .unwrap_or_else(|| {
                panic!(
                    "no {kind}/{name} in {:?}",
                    all.iter().map(Resource::key).collect::<Vec<_>>()
                )
            })
    }

    #[test]
    fn import_the_ten_kinds_translate_and_validate() {
        let (all, report) = run(TEN);
        // kith has no headless Service name to carry; it is the one thing left out.
        assert_eq!(
            report,
            ["StatefulSet/db: spec.serviceName is taken and changes nothing: kith has no use for it"]
        );
        let kinds: Vec<_> = all.iter().map(|r| r.kind.as_str()).collect();
        for kind in [
            "Workload",
            "NodeWorkload",
            "Service",
            "ConfigMap",
            "Secret",
            "VolumeClaim",
            "Job",
            "CronJob",
        ] {
            assert!(kinds.contains(&kind), "{kind} missing from {kinds:?}");
        }
        for r in &all {
            r.clone().validated().unwrap_or_else(|e| panic!("{}: {e}", r.key()));
        }
    }

    /// `value` at `path` of `at`: `a[].b` is `b` of the first item of the list `a`.
    fn set(at: &mut Value, path: &str, value: Value) {
        let (head, rest) = path
            .split_once('.')
            .map_or((path, None), |(head, rest)| (head, Some(rest)));
        let (key, list) = head.strip_suffix("[]").map_or((head, false), |key| (key, true));
        let mut slot = &mut at[key];
        if list {
            if !slot.is_array() {
                *slot = json!([{}]);
            }
            slot = &mut slot[0];
        }
        match rest {
            Some(rest) => set(slot, rest, value),
            None => *slot = value,
        }
    }

    /// Every row of FIELDS is tried on an object that is taken whole without it: what the
    /// row says becomes of the field is what does.
    #[test]
    fn every_field_is_carried_said_or_refused() {
        let pod = json!({
            "metadata": { "labels": { "app": "web" } },
            "spec": {
                "containers": [{
                    "name": "web", "image": "nginx",
                    "env": [{ "name": "A", "value": "b" }],
                    "ports": [{ "containerPort": 80 }],
                    "volumeMounts": [{ "name": "data", "mountPath": "/data" }],
                    "livenessProbe": { "httpGet": { "path": "/", "port": 80 } },
                }],
                "volumes": [{ "name": "data", "persistentVolumeClaim": { "claimName": "data" } }],
            },
        });
        let claim = json!({ "accessModes": ["ReadWriteOnce"], "resources": { "requests": { "storage": "1Gi" } } });
        let path = json!({ "path": "/", "pathType": "Prefix", "backend": { "service": { "name": "web", "port": { "number": 80 } } } });
        let service = json!({ "kind": "Service", "metadata": { "name": "web" }, "spec": { "selector": { "app": "web" }, "ports": [{ "port": 80 }] } });
        let base = |kind: &str| {
            let selector = json!({ "matchLabels": { "app": "web" } });
            let spec = match kind {
                "Deployment" | "DaemonSet" => json!({ "selector": selector, "template": pod }),
                "StatefulSet" => json!({
                    "selector": selector, "template": pod,
                    "volumeClaimTemplates": [{ "metadata": { "name": "data" }, "spec": claim }],
                }),
                "Job" => json!({ "template": pod }),
                "CronJob" => json!({ "schedule": "0 * * * *", "jobTemplate": { "spec": { "template": pod } } }),
                "Service" => service["spec"].clone(),
                "PersistentVolumeClaim" => claim.clone(),
                "Ingress" => json!({ "rules": [{ "host": "web.example.org", "http": { "paths": [path] } }] }),
                _ => Value::Null,
            };
            let mut object = json!({ "kind": kind, "metadata": { "name": "web" }, "spec": spec });
            match kind {
                "ConfigMap" => object = json!({ "kind": kind, "metadata": { "name": "web" }, "data": { "a": "b" } }),
                "Secret" => object = json!({ "kind": kind, "metadata": { "name": "web" }, "data": { "a": "Yg==" } }),
                _ => {}
            }
            object
        };
        let places = |lines: &[String]| -> Vec<String> {
            let place = |line: &String| {
                let (who, said) = line.split_once(": ").unwrap();
                place(who.split('/').next().unwrap(), said.split(' ').next().unwrap())
            };
            lines.iter().map(place).collect()
        };
        for (row, field, value) in FIELDS {
            let value: Value = serde_json::from_str(value).unwrap_or_else(|e| panic!("{row}: {value}: {e}"));
            let (kind, at) = row.split_once('.').unwrap();
            let pod_at = "spec.template.spec";
            let (kind, at) = match kind {
                "meta" => ("Deployment", format!("metadata.{at}")),
                "podmeta" => ("Deployment", format!("spec.template.metadata.{at}")),
                "pod" => ("Deployment", format!("{pod_at}.{at}")),
                "container" => ("Deployment", format!("{pod_at}.containers[].{at}")),
                "probe" => ("Deployment", format!("{pod_at}.containers[].livenessProbe.{at}")),
                kind => (kind, at.to_string()),
            };
            let mut object = base(kind);
            // (A check is one of three, and a variable has one value.)
            if ["probe.httpGet", "probe.tcpSocket", "probe.exec"].contains(row) {
                object["spec"]["template"]["spec"]["containers"][0]["livenessProbe"] = json!({});
            }
            if let Some(from) = row.strip_prefix("container.env[].valueFrom.") {
                let mut variable = json!({ "name": "A" });
                if let Some(reference) = from.strip_suffix(".optional") {
                    variable["valueFrom"][reference] = json!({ "name": "s", "key": "k" });
                }
                object["spec"]["template"]["spec"]["containers"][0]["env"][0] = variable;
            }
            // What it is without the field: taken whole, and nothing said.
            let plain = take(vec![object.clone(), service.clone()], false);
            assert!(plain.refused.is_empty() && plain.hints.is_empty(), "{row}: {plain:?}");
            set(&mut object, &at, value);
            let taken = take(vec![object, service.clone()], false);
            let said = places(&taken.hints).iter().any(|place| within(place, row));
            let (hints, refused) = (&taken.hints, &taken.refused);
            match field {
                Carried => assert!(refused.is_empty() && !said, "{row}: {hints:?} {refused:?}"),
                Hint => assert!(refused.is_empty() && said, "{row}: {hints:?} {refused:?}"),
                Refused => assert!(!refused.is_empty(), "{row}: {hints:?}"),
            }
        }
    }

    #[test]
    fn import_deployment_carries_its_fields() {
        let (all, _) = run(TEN);
        let web = find(&all, "Workload", "web");
        assert_eq!(web.metadata.namespace.as_deref(), Some("shop"));
        assert_eq!(web.metadata.labels["app"], "web");
        assert!(!web.metadata.labels.contains_key("app.kubernetes.io/managed-by"));
        let spec = &web.spec;
        assert_eq!(spec["replicas"], 3);
        assert_eq!(spec["strategy"], "recreate");
        assert_eq!(spec["placement"]["require"]["node.labels.disk"], "ssd");
        let c = &spec["template"]["containers"][0];
        assert_eq!(c["image"], "nginx:1.27");
        assert_eq!(c["pullPolicy"], "ifNotPresent");
        assert_eq!(c["resources"], json!({ "cpu": "500m", "memory": "256Mi" }));
        assert_eq!(c["env"][1]["secret"], json!({ "name": "creds", "key": "token" }));
        assert_eq!(c["env"][2]["configMap"], json!({ "name": "settings", "key": "level" }));
        assert_eq!(
            c["readiness"],
            json!({ "http": { "path": "/ready", "port": 8080 }, "intervalSeconds": 5 })
        );
        assert_eq!(c["liveness"], json!({ "tcp": { "port": 8080 } }));
        assert_eq!(c["volumeMounts"][0], json!({ "volume": "data", "path": "/data" }));
        // It runs as Kubernetes would run it.
        assert_eq!(spec["template"]["pod"], true);
    }

    #[test]
    fn import_statefulset_claim_template_becomes_a_volume_claim() {
        let (all, _) = run(TEN);
        let claim = find(&all, "VolumeClaim", "pgdata-db");
        assert_eq!(claim.spec["size"], "10Gi");
        let db = find(&all, "Workload", "db");
        assert_eq!(
            db.spec["template"]["containers"][0]["volumeMounts"][0]["volume"],
            "pgdata-db"
        );
    }

    #[test]
    fn import_daemonset_secret_pvc_ingress() {
        let (all, _) = run(TEN);
        assert_eq!(
            find(&all, "NodeWorkload", "agent").spec["selector"],
            json!({ "role": "edge" })
        );
        let secret = find(&all, "Secret", "creds");
        assert_eq!(secret.spec["data"], json!({ "token": "hunter2", "user": "admin" }));
        assert_eq!(find(&all, "VolumeClaim", "data").spec["shared"], true);
        let svc = find(&all, "Service", "web");
        assert_eq!(svc.spec["expose"], json!({ "host": "shop.example.com", "via": "edge" }));
        assert_eq!(svc.spec["ports"][0]["targetPort"], 8080);
        let cron = find(&all, "CronJob", "nightly");
        assert_eq!(cron.spec["concurrency"], "forbid");
        assert_eq!(cron.spec["job"]["template"]["restartPolicy"], "never");
        let job = find(&all, "Job", "migrate");
        assert_eq!(job.spec["retries"], 2);
        assert_eq!(job.spec["template"]["restartPolicy"], "onFailure");
    }

    #[test]
    fn import_reports_what_it_leaves_out_by_path() {
        let (all, report) = run(r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  annotations:
    note: hello
spec:
  template:
    spec:
      affinity:
        podAntiAffinity:
          x: y
      containers:
        - name: app
          image: nginx
          securityContext:
            privileged: true
---
apiVersion: v1
kind: Pod
metadata:
  name: lone
---
apiVersion: v1
kind: Service
metadata:
  name: nosel
spec:
  ports:
    - port: 80
---
apiVersion: v1
kind: Secret
metadata:
  name: bad
data:
  a: "!!!"
"#);
        let has = |s: &str| report.iter().any(|l| l == s);
        assert!(
            has("Deployment/web: spec.template.spec.affinity is taken and changes nothing: kith has no use for it"),
            "{report:#?}"
        );
        assert!(
            has("Deployment/web: spec.template.spec.containers[app].securityContext.privileged not translated"),
            "{report:#?}"
        );
        assert!(
            has("Pod/lone: is a kind kith has nothing for: not translated"),
            "{report:#?}"
        );
        assert!(
            report.iter().any(|l| l.starts_with("Service/nosel: spec.selector")),
            "{report:#?}"
        );
        assert!(
            report.iter().any(|l| l.starts_with("Secret/bad: data.a is not base64")),
            "{report:#?}"
        );
        // The Deployment and the Secret (less its bad key) still came out.
        assert!(all.iter().any(|r| r.kind == "Workload"));
        assert!(all.iter().any(|r| r.kind == "Secret"));
        assert!(!all.iter().any(|r| r.kind == "Service"));
    }

    #[test]
    fn import_unwraps_lists_and_skips_noise() {
        let (all, report) = run(r#"
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: ConfigMap
    metadata:
      name: a
      uid: abc
      resourceVersion: "5"
      managedFields: []
      annotations:
        meta.helm.sh/release-name: x
    data:
      k: v
    status: {}
"#);
        assert_eq!(report, Vec::<String>::new());
        assert_eq!(all.len(), 1);
        assert!(all[0].metadata.annotations.is_empty());
    }

    #[test]
    fn import_a_document_that_is_not_a_mapping_is_reported() {
        let (all, report) = run("- 1\n- 2\n");
        assert!(all.is_empty());
        assert_eq!(report.len(), 1);
    }

    #[test]
    fn import_base64_decodes() {
        assert_eq!(unbase64("aHVudGVyMg==").unwrap(), b"hunter2");
        assert_eq!(unbase64("aGk").unwrap(), b"hi");
        assert_eq!(unbase64("").unwrap(), b"");
        assert!(unbase64("a$b").is_none());
        for bad in ["A", "QUJD=zzzz", "aGk=x", "aGl=", "aGk==="] {
            assert!(unbase64(bad).is_none(), "{bad}");
        }
        assert_eq!(unbase64("aGk=\n").unwrap(), b"hi");
    }

    #[test]
    fn import_says_what_helm_hooks_and_shared_hosts_lose() {
        let service = |name: &str| {
            format!(
                "apiVersion: v1\nkind: Service\nmetadata: {{ name: {name} }}\nspec: {{ selector: {{ app: {name} }}, ports: [{{ port: 80 }}] }}\n---\n"
            )
        };
        let path = |path: &str, to: &str| {
            format!(
                "{{ path: {path}, pathType: Prefix, backend: {{ service: {{ name: {to}, port: {{ number: 80 }} }} }} }}"
            )
        };
        let ingress = |name: &str, paths: &str| {
            format!(
                "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: {{ name: {name} }}\nspec:\n  rules:\n    - host: shop.example.com\n      http: {{ paths: [{paths}] }}\n---\n"
            )
        };
        let hook = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: migrate\n  annotations: { helm.sh/hook: pre-install, helm.sh/chart: x-1 }\ndata: { a: b }\n";
        let all = [
            service("web"),
            service("api"),
            service("other"),
            ingress("one", &format!("{}, {}", path("/", "web"), path("/api", "api"))),
            ingress("two", &path("/", "other")),
            hook.to_string(),
        ]
        .concat();
        let (resources, report) = run(&all);
        let host =
            |name: &str| resources.iter().find(|r| r.metadata.name == name).unwrap().spec["expose"]["host"].clone();
        assert_eq!(
            (host("web"), host("api"), host("other")),
            (json!("shop.example.com"), Value::Null, Value::Null)
        );
        let said = |what: &str| report.iter().filter(|line| line.contains(what)).count();
        assert_eq!(
            (
                said("the one behind `/`"),
                said("already goes to Service `web`"),
                said("helm.sh/hook")
            ),
            (1, 1, 1),
            "{report:?}"
        );
        assert_eq!(said("helm.sh/chart"), 0);
    }
}
