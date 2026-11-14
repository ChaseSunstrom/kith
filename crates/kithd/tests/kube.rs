//! The real `kubectl` and `helm` against one kithd on 127.0.0.1: nothing of Kubernetes is
//! started, and no image is pulled (the node has an empty one under each name these
//! manifests use, so nothing here runs: what runs is `sh ci/vm.sh --test kube`'s to show).
//! Skips where there is no kubectl (`KITH_KUBECTL` names one, or the one on `PATH`); the
//! tests of Helm skip where `KITH_HELM` names none (`helm3:helm4`, each is used).
//! `sh ci/kube.sh` fetches all three and runs this:
//!
//! ```sh
//! KITH_KUBECTL=/path/to/kubectl KITH_HELM=/path/to/helm cargo test -p kithd --test kube
//! ```

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// One kithd, an Identity that may do everything, and a kubeconfig that is that Identity.
struct Cluster {
    child: Child,
    dir: PathBuf,
    kubectl: String,
    /// The kubeconfig kubectl and helm are run with: alice's, who may do everything.
    config: PathBuf,
}

impl Cluster {
    /// None where no kubectl runs: the test has nothing to say then.
    fn start(test: &str) -> Option<Cluster> {
        let kubectl = std::env::var("KITH_KUBECTL").unwrap_or("kubectl".into());
        let runs = Command::new(&kubectl).args(["version", "--client"]).output();
        if !runs.is_ok_and(|out| out.status.success()) {
            eprintln!("skipped: no kubectl (KITH_KUBECTL or PATH)");
            return None;
        }
        let built = Command::new(env!("CARGO"))
            .args(["build", "--quiet", "-p", "kith-cli"])
            .status();
        assert!(built.unwrap().success());
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // The images the manifests here name, as ones the node has already: nothing in
        // these tests asks a registry. (Each is an empty root: its units do not start,
        // and nothing asked of the API here needs them to.)
        for (n, image) in IMAGES.iter().enumerate() {
            let digest = format!("{n:064x}");
            let root = dir.join("state/runtime/images").join(&digest);
            std::fs::create_dir_all(root.join("rootfs")).unwrap();
            std::fs::create_dir_all(dir.join("state/runtime/refs")).unwrap();
            std::fs::write(root.join("config.json"), "{}").unwrap();
            let said = format!(r#"{{"digest":"sha256:{digest}","entrypoint":[],"cmd":[],"env":[],"user":null}}"#);
            std::fs::write(dir.join("state/runtime/refs").join(image.replace('/', "%2f")), said).unwrap();
        }
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let child = Command::new(env!("CARGO_BIN_EXE_kithd"))
            .current_dir(&dir)
            .args(["--state", "state", "--socket", "kithd.sock", "--name", "alpha"])
            .args(["--listen", &format!("127.0.0.1:{port}")])
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let config = dir.join("kubeconfig");
        let cluster = Cluster {
            child,
            dir,
            kubectl,
            config,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !cluster.dir.join("kithd.sock").exists() {
            assert!(Instant::now() < deadline, "timed out waiting for kithd to serve");
            std::thread::sleep(Duration::from_millis(50));
        }
        cluster.kith(&["identity", "cert", "alice", "--out", "."]);
        let roles = "apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: all }\nspec:\n  rules:\n    - kinds: ['*']\n      verbs: [get, list, watch, apply, delete]\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: alice-all }\nspec:\n  role: all\n  subjects: [alice]\n";
        cluster.write("roles.yaml", roles);
        cluster.kith(&["apply", "-f", "roles.yaml"]);
        // (Every node's certificate is good for the name `kith`.)
        for who in ["alice", "bob", "nobody"] {
            let user = match who {
                "nobody" => "{}".to_string(),
                who => format!("{{ client-certificate: {who}.crt, client-key: {who}.key }}"),
            };
            let config = format!(
                "apiVersion: v1\nkind: Config\ncurrent-context: kith\nclusters:\n- name: kith\n  cluster:\n    server: https://127.0.0.1:{port}\n    certificate-authority: ca.crt\n    tls-server-name: kith\nusers:\n- name: {who}\n  user: {user}\ncontexts:\n- name: kith\n  context: {{ cluster: kith, user: {who} }}\n"
            );
            let name = if who == "alice" {
                "kubeconfig".into()
            } else {
                format!("kubeconfig-{who}")
            };
            cluster.write(&name, &config);
        }
        Some(cluster)
    }

    /// The same cluster, asked as another Identity (its kubeconfig is `kubeconfig-NAME`).
    fn as_(&self, who: &str) -> Cluster {
        Cluster {
            // (Nothing to stop: `true` has ended by the time this one is dropped.)
            child: Command::new("true").spawn().unwrap(),
            dir: self.dir.clone(),
            kubectl: self.kubectl.clone(),
            config: self.dir.join(format!("kubeconfig-{who}")),
        }
    }

    fn write(&self, name: &str, text: &str) {
        std::fs::write(self.dir.join(name), text).unwrap();
    }

    /// Run `kith` on the node's socket; it has to succeed.
    fn kith(&self, args: &[&str]) -> String {
        let kith = Path::new(env!("CARGO_BIN_EXE_kithd")).with_file_name("kith");
        let out = Command::new(kith)
            .args(args)
            .current_dir(&self.dir)
            .env("KITH_SOCKET", self.dir.join("kithd.sock"))
            .env_remove("KITH_STORE")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "kith {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// Run kubectl as alice, with a home of its own; returns (it succeeded, stdout, stderr).
    fn kubectl(&self, args: &[&str]) -> (bool, String, String) {
        self.run(&self.kubectl, args)
    }

    /// Run a client (kubectl, or a helm) as this cluster's Identity, with a home of its own.
    fn run(&self, client: &str, args: &[&str]) -> (bool, String, String) {
        let out = Command::new(client)
            .args(args)
            .current_dir(&self.dir)
            .env("KUBECONFIG", &self.config)
            .env("HOME", &self.dir)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned();
        (out.status.success(), text(out.stdout), text(out.stderr))
    }

    /// What kubectl gets of something, as JSON.
    fn got(&self, what: &[&str]) -> serde_json::Value {
        let out = self.ok(&[&["get", "-o", "json"], what].concat());
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("kubectl get {what:?}: {e}: {out}"))
    }

    /// What kith holds at a key (`workload/web`, or `workload/team/web` in a namespace), as JSON.
    fn held(&self, key: &str) -> serde_json::Value {
        let parts: Vec<&str> = key.split('/').collect();
        let out = match parts[..] {
            [kind, namespace, name] => self.kith(&["get", &format!("{kind}/{name}"), "-n", namespace, "-o", "json"]),
            _ => self.kith(&["get", key, "-o", "json"]),
        };
        serde_json::from_str(&out).unwrap()
    }

    /// The key of everything kith holds (`Workload/default/web`), in every namespace.
    fn holds(&self) -> Vec<String> {
        let all: Vec<serde_json::Value> = serde_json::from_str(&self.kith(&["get", "-o", "json"])).unwrap();
        let part = |value: &serde_json::Value| value.as_str().unwrap_or("-").to_string();
        let key = |one: &serde_json::Value| {
            [&one["kind"], &one["metadata"]["namespace"], &one["metadata"]["name"]]
                .map(part)
                .join("/")
        };
        // (What the node finds of its own hardware comes when it comes: not ours to count.)
        let ours = |key: &String| !key.starts_with("Device/") && !key.starts_with("Seat/");
        all.iter().map(key).filter(ours).collect()
    }

    /// kubectl has to fail, and say every one of `words`.
    fn refused(&self, args: &[&str], words: &[&str]) -> String {
        let (ok, out, err) = self.kubectl(args);
        let said = words.iter().all(|word| err.contains(word));
        assert!(
            !ok && said,
            "kubectl {args:?} should fail saying {words:?}: {ok} {out}{err}"
        );
        err
    }

    fn ok(&self, args: &[&str]) -> String {
        let (ok, out, err) = self.kubectl(args);
        if !ok {
            // What it asked and was answered, to read the failure by.
            let (_, _, asked) = self.kubectl(&[args, &["-v=8"]].concat());
            let asked: Vec<&str> = asked.lines().filter(|line| line.contains("round_trippers")).collect();
            panic!("kubectl {args:?}: {err}\n{}", asked.join("\n"));
        }
        out
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .arg(self.child.id().to_string())
            .stderr(Stdio::null())
            .status();
        let _ = self.child.wait();
    }
}

/// Every image a manifest of these tests names, as a node writes the name of one it has.
const IMAGES: &[&str] = &[
    "mirror.gcr.io/library/busybox:1.36",
    "docker.io/library/nginx:1.27-alpine",
    "docker.io/library/nginx:1.28-alpine",
    "docker.io/library/nginx:1.16.0",
    "docker.io/library/busybox:1.36",
];

const WEB: &str = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  labels: { app: web }
spec:
  replicas: 2
  selector:
    matchLabels: { app: web }
  template:
    metadata:
      labels: { app: web }
    spec:
      containers:
        - name: web
          image: mirror.gcr.io/library/busybox:1.36
          command: [sleep, "3600"]
"#;

#[test]
fn kubectl_applies_a_deployment_and_gets_it_back() {
    let Some(cluster) = Cluster::start("kube-deployment") else {
        return;
    };
    cluster.write("web.yaml", WEB);
    // The file as it was written for Kubernetes: nothing of kith in it.
    assert_eq!(
        cluster.ok(&["apply", "-f", "web.yaml"]).trim(),
        "deployment.apps/web created"
    );
    // kith holds it as the Workload it means,
    let held = cluster.kith(&["get", "workload/web", "-o", "json"]);
    let held: serde_json::Value = serde_json::from_str(&held).unwrap();
    assert_eq!(held["spec"]["replicas"], 2, "{held}");
    assert_eq!(
        held["spec"]["template"]["containers"][0]["image"],
        "mirror.gcr.io/library/busybox:1.36"
    );
    // and kubectl gets back what it sent.
    let got: serde_json::Value =
        serde_json::from_str(&cluster.ok(&["get", "deployment", "web", "-o", "json"])).unwrap();
    assert_eq!(
        (&got["kind"], &got["spec"]["replicas"]),
        (&"Deployment".into(), &2.into())
    );
    assert_eq!(got["spec"]["template"]["spec"]["containers"][0]["command"][1], "3600");
    assert!(got["metadata"]["annotations"]["kubectl.kubernetes.io/last-applied-configuration"].is_string());
    let listed = cluster.ok(&["get", "deployments"]);
    assert!(listed.lines().any(|line| line.starts_with("web ")), "{listed}");
    // One that is not there is not found, as Kubernetes says it.
    let (ok, _, err) = cluster.kubectl(&["get", "deployment", "nothing"]);
    assert!(
        !ok && err.contains("NotFound") && err.contains("\"nothing\" not found"),
        "{err}"
    );
}

/// A shop as its manifests would be written for Kubernetes: what it is told and what it
/// must not say aloud, two of it, and the name they are asked by.
const SHOP: &str = r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: shop-config
data:
  GREETING: hello
  shop.conf: |
    listen 80;
---
apiVersion: v1
kind: Secret
metadata:
  name: shop-secret
type: Opaque
data:
  password: aHVudGVyMg== # pragma: allowlist secret
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shop
  labels:
    app: shop
spec:
  replicas: 2
  selector:
    matchLabels:
      app: shop
  template:
    metadata:
      labels:
        app: shop
    spec:
      containers:
        - name: web
          image: nginx:1.27-alpine
          ports:
            - name: http
              containerPort: 80
          env:
            - name: GREETING
              valueFrom:
                configMapKeyRef:
                  name: shop-config
                  key: GREETING
            - name: PASSWORD
              valueFrom:
                secretKeyRef:
                  name: shop-secret
                  key: password
          readinessProbe:
            httpGet:
              path: /
              port: http
          resources:
            requests:
              cpu: 50m
              memory: 32Mi
            limits:
              memory: 64Mi
---
apiVersion: v1
kind: Service
metadata:
  name: shop
spec:
  selector:
    app: shop
  ports:
    - port: 80
      targetPort: http
"#;

/// The rest of what a stock set of manifests has: something that keeps what it writes,
/// something run by the clock, and a host name on the shop.
const REST: &str = r#"apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
spec:
  serviceName: db
  replicas: 1
  selector:
    matchLabels:
      app: db
  template:
    metadata:
      labels:
        app: db
    spec:
      containers:
        - name: db
          image: busybox:1.36
          command: ["sh", "-c", "date >> /data/started; sleep 3600"]
          volumeMounts:
            - name: data
              mountPath: /data
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 1Gi
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: tick
spec:
  schedule: "* * * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: tick
              image: busybox:1.36
              command: ["sh", "-c", "date"]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: shop
spec:
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: shop
                port:
                  number: 80
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: uploads
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 2Gi
"#;

/// Wait until `done` says so: what a controller writes comes a moment after what it follows.
#[track_caller]
fn eventually(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !done() {
        assert!(Instant::now() < deadline, "{what}: not within {secs} s");
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Every one of `words` is in `text`.
#[track_caller]
fn says(text: &str, words: &[&str]) {
    for word in words {
        assert!(text.contains(word), "no `{word}` in:\n{text}");
    }
}

/// Why `got` does not hold all of `sent`, if it does not: every field sent has to come
/// back as it was, whatever else the server says of the object.
fn lost(sent: &serde_json::Value, got: &serde_json::Value, at: &str) -> Option<String> {
    use serde_json::Value;
    match (sent, got) {
        (Value::Object(sent), Value::Object(got)) => sent
            .iter()
            .find_map(|(key, sent)| lost(sent, got.get(key).unwrap_or(&Value::Null), &format!("{at}.{key}"))),
        (Value::Array(sent), Value::Array(got)) if sent.len() == got.len() => {
            let mut both = sent.iter().zip(got).enumerate();
            both.find_map(|(n, (sent, got))| lost(sent, got, &format!("{at}[{n}]")))
        }
        (sent, got) => (sent != got).then(|| format!("{at}: sent {sent}, got {got}")),
    }
}

/// The helms to try (`KITH_HELM`, `:` between them): none where it names none.
fn helms() -> Vec<String> {
    let named = std::env::var("KITH_HELM").unwrap_or_default();
    let helms: Vec<String> = named
        .split(':')
        .filter(|helm| !helm.is_empty())
        .map(String::from)
        .collect();
    if helms.is_empty() {
        eprintln!("skipped: no helm (KITH_HELM)");
    }
    helms
}

#[test]
fn workflows_kubectl_by_hand() {
    let Some(cluster) = Cluster::start("kube-by-hand") else {
        return;
    };
    let empty = cluster.holds();
    cluster.write("shop.yaml", SHOP);
    let made = cluster.ok(&["apply", "-f", "shop.yaml"]);
    let all = [
        "configmap/shop-config created",
        "secret/shop-secret created",
        "deployment.apps/shop created",
        "service/shop created",
    ];
    says(&made, &all);
    // Sent again it is what is there; and kubectl finds no difference to show.
    let again = cluster.ok(&["apply", "-f", "shop.yaml"]);
    assert_eq!(again.matches(" unchanged").count(), 4, "{again}");
    assert_eq!(cluster.ok(&["diff", "-f", "shop.yaml"]), "");

    // Read every way kubectl reads: tables, a label, every namespace, a path, a description.
    let listed = cluster.ok(&["get", "deployments,services,configmaps,secrets"]);
    let rows = [
        "deployment.apps/shop   0/2     2",
        "service/shop   ClusterIP",
        "80/TCP",
        "configmap/shop-config   2",
        "secret/shop-secret   Opaque   1",
    ];
    says(&listed, &rows);
    let pods = cluster.ok(&["get", "pods", "-l", "app=shop", "-o", "name"]);
    assert_eq!(pods, "pod/shop-0\npod/shop-1\n");
    assert_eq!(cluster.ok(&["get", "pods", "-l", "app=other", "-o", "name"]), "");
    let everything = cluster.ok(&["get", "all", "-A", "-o", "wide"]);
    says(
        &everything,
        &[
            "pod/shop-1",
            "alpha",
            "service/shop",
            "deployment.apps/shop",
            "replicaset.apps/shop-",
        ],
    );
    let image = "jsonpath={.spec.template.spec.containers[0].image}";
    assert_eq!(cluster.ok(&["get", "deploy", "shop", "-o", image]), "nginx:1.27-alpine");
    says(
        &cluster.ok(&["describe", "deployment", "shop"]),
        &["Replicas:", "2 desired", "nginx:1.27-alpine"],
    );
    says(
        &cluster.ok(&["describe", "pod", "shop-0"]),
        &["Controlled By:  ReplicaSet/shop-"],
    );
    says(
        &cluster.ok(&["api-resources"]),
        &["deployments", "deploy", "apps/v1", "cronjobs", "ingresses"],
    );
    says(&cluster.ok(&["get", "nodes"]), &["alpha", "Ready"]);
    cluster.ok(&["get", "events"]);

    // Changed every way kubectl changes: each is the kith Workload's change.
    let workload = || cluster.held("workload/shop");
    cluster.ok(&["scale", "deployment/shop", "--replicas=3"]);
    assert_eq!(workload()["spec"]["replicas"], 3);
    cluster.ok(&["set", "image", "deployment/shop", "web=nginx:1.28-alpine"]);
    assert_eq!(
        workload()["spec"]["template"]["containers"][0]["image"],
        "nginx:1.28-alpine"
    );
    cluster.ok(&[
        "patch",
        "deployment",
        "shop",
        "--type",
        "merge",
        "-p",
        r#"{"spec":{"replicas":1}}"#,
    ]);
    assert_eq!(workload()["spec"]["replicas"], 1);
    // (A strategic patch names a container and adds to what it is told: the rest stays.)
    let more = r#"{"spec":{"template":{"spec":{"containers":[{"name":"web","env":[{"name":"MORE","value":"1"}]}]}}}}"#;
    cluster.ok(&["patch", "deployment", "shop", "-p", more]);
    let told = cluster.ok(&["get", "deploy", "shop", "-o", "jsonpath={..env[*].name}"]);
    let mut told: Vec<&str> = told.split(' ').collect();
    told.sort();
    assert_eq!(told, ["GREETING", "MORE", "PASSWORD"]);
    cluster.ok(&["label", "deployment", "shop", "tier=front"]);
    cluster.ok(&["annotate", "deployment", "shop", "note=hello"]);
    assert_eq!(workload()["metadata"]["labels"]["tier"], "front");
    assert_eq!(
        cluster.ok(&["get", "deploy", "-l", "tier=front", "-o", "name"]),
        "deployment.apps/shop\n"
    );
    // A file changed and sent again, by the client's own three-way patch and by the server's.
    cluster.write("shop2.yaml", &SHOP.replace("GREETING: hello", "GREETING: goodbye"));
    says(
        &cluster.ok(&["apply", "-f", "shop2.yaml"]),
        &["configmap/shop-config configured"],
    );
    assert_eq!(
        cluster.held("configmap/shop-config")["spec"]["data"]["GREETING"],
        "goodbye"
    );
    cluster.ok(&["apply", "--server-side", "--force-conflicts", "-f", "shop.yaml"]);
    assert_eq!(
        cluster.held("configmap/shop-config")["spec"]["data"]["GREETING"],
        "hello"
    );
    assert_eq!(workload()["spec"]["replicas"], 2);
    cluster.ok(&["replace", "-f", "shop.yaml"]);
    // Asked what it would do, it does nothing.
    cluster.ok(&["scale", "deployment/shop", "--replicas=5", "--dry-run=server"]);
    assert_eq!(workload()["spec"]["replicas"], 2);

    // Started again: the replicas are made anew, as a changed template makes them.
    let before = workload();
    cluster.ok(&["rollout", "restart", "deployment/shop"]);
    assert_ne!(workload()["spec"]["template"], before["spec"]["template"]);
    // Its progress is watched (and nothing gets ready here: these images are empty).
    let (ok, out, err) = cluster.kubectl(&["rollout", "status", "deployment/shop", "--timeout=3s"]);
    assert!(
        !ok && out.contains("Waiting for deployment \"shop\" rollout to finish"),
        "{out}{err}"
    );
    // A watch says what is there, and then each change.
    let watched = cluster.ok(&["get", "configmaps", "--watch", "--request-timeout=2s", "-o", "name"]);
    says(&watched, &["configmap/shop-config"]);
    // What a pod wrote (nothing yet), which is not a refusal.
    cluster.ok(&["logs", "shop-0"]);
    cluster.ok(&["logs", "deployment/shop", "--tail=5"]);

    // What kubectl makes without a file, which it sends in Kubernetes's binary encoding.
    cluster.ok(&["create", "namespace", "team"]);
    cluster.ok(&["create", "configmap", "told", "-n", "team", "--from-literal=a=b"]);
    cluster.ok(&[
        "create",
        "secret",
        "generic",
        "kept",
        "-n",
        "team",
        "--from-literal=password=hunter2",
    ]);
    cluster.ok(&[
        "create",
        "deployment",
        "made",
        "-n",
        "team",
        "--image=nginx:1.27-alpine",
        "--replicas=2",
    ]);
    cluster.ok(&[
        "create",
        "job",
        "once",
        "-n",
        "team",
        "--image=busybox:1.36",
        "--",
        "true",
    ]);
    cluster.ok(&[
        "create",
        "cronjob",
        "often",
        "-n",
        "team",
        "--image=busybox:1.36",
        "--schedule=*/5 * * * *",
        "--",
        "true",
    ]);
    cluster.ok(&["create", "job", "now", "-n", "team", "--from=cronjob/often"]);
    let now = cluster.held("job/team/now");
    assert_eq!(now["spec"]["template"]["containers"][0]["command"][0], "true", "{now}");
    cluster.ok(&["create", "serviceaccount", "robot", "-n", "team"]);
    cluster.ok(&["expose", "deployment", "made", "-n", "team", "--port=80"]);
    assert_eq!(cluster.held("configmap/team/told")["spec"]["data"]["a"], "b");
    assert_eq!(cluster.held("workload/team/made")["spec"]["replicas"], 2);
    assert_eq!(cluster.held("cronjob/team/often")["spec"]["schedule"], "*/5 * * * *");
    let password = "jsonpath={.data.password}";
    assert_eq!(
        cluster.ok(&["get", "secret", "kept", "-n", "team", "-o", password]),
        "aHVudGVyMg=="
    ); // pragma: allowlist secret
    cluster.refused(&["create", "namespace", "team"], &["AlreadyExists"]);

    // Deleted: by file, by name, and a namespace with all that was made in it.
    let gone = cluster.ok(&["delete", "-f", "shop.yaml"]);
    assert_eq!(gone.matches(" deleted").count(), 4, "{gone}");
    assert_eq!(cluster.ok(&["get", "all,configmaps,secrets", "-o", "name"]), "");
    cluster.refused(&["delete", "deployment", "shop"], &["NotFound"]);
    cluster.ok(&["delete", "deployment", "made", "-n", "team"]);
    cluster.ok(&["delete", "namespace", "team"]);
    assert_eq!(cluster.ok(&["get", "namespaces", "-o", "name"]), "namespace/default\n");
    assert_eq!(cluster.holds(), empty, "kith holds what it held before any of it");
}

#[test]
fn workflows_helm() {
    for (n, helm) in helms().iter().enumerate() {
        let Some(cluster) = Cluster::start(&format!("kube-helm-{n}")) else {
            return;
        };
        let empty = cluster.holds();
        let run = |args: &[&str]| {
            let (ok, out, err) = cluster.run(helm, args);
            assert!(ok, "helm {args:?}: {out}{err}");
            out + &err
        };
        // The chart Helm itself starts every chart from: a ServiceAccount, a Service, a
        // Deployment with its checks, and a test that is a bare Pod.
        run(&["create", "site"]);
        let said = run(&["install", "site", "./site"]);
        says(
            &said,
            &["STATUS: deployed", "ServiceAccount/site: is kept and gives nothing"],
        );
        says(&run(&["list"]), &["site", "deployed", "site-0.1.0"]);
        let held = cluster.held("workload/site");
        assert_eq!(held["spec"]["replicas"], 1, "{held}");
        assert_eq!(held["spec"]["template"]["containers"][0]["image"], "nginx:1.16.0");
        // What Helm keeps of a release is a Secret, which is a kith Secret.
        says(
            &cluster.ok(&["get", "secrets", "-o", "name"]),
            &["secret/sh.helm.release.v1.site.v1"],
        );
        says(
            &cluster.ok(&["get", "all,serviceaccounts"]),
            &[
                "pod/site-0",
                "service/site",
                "deployment.apps/site",
                "serviceaccount/site",
            ],
        );

        run(&["upgrade", "site", "./site", "--set", "replicaCount=2"]);
        assert_eq!(cluster.held("workload/site")["spec"]["replicas"], 2);
        says(&run(&["get", "manifest", "site"]), &["kind: Deployment", "replicas: 2"]);
        says(&run(&["status", "site"]), &["STATUS: deployed", "REVISION: 2"]);
        run(&["rollback", "site", "1"]);
        assert_eq!(cluster.held("workload/site")["spec"]["replicas"], 1);
        says(
            &run(&["history", "site"]),
            &["Install complete", "Upgrade complete", "Rollback to 1"],
        );
        // With --wait Helm reads the status kith gives a Deployment until it is ready,
        // which nothing is here (these images are empty): it waits, and says what for.
        let (ok, out, err) = cluster.run(
            helm,
            &[
                "upgrade",
                "site",
                "./site",
                "--set",
                "replicaCount=3",
                "--wait",
                "--timeout",
                "4s",
            ],
        );
        assert!(!ok && (out + &err).contains("deadline"), "{err}");
        run(&["uninstall", "site", "--wait", "--timeout", "30s"]);
        assert_eq!(cluster.ok(&["get", "all,serviceaccounts,secrets", "-o", "name"]), "");
        assert_eq!(cluster.holds(), empty, "kith holds what it held before the chart");

        // Into a namespace made for it.
        run(&["install", "site", "./site", "-n", "other", "--create-namespace"]);
        assert_eq!(cluster.held("workload/other/site")["spec"]["replicas"], 1);
        run(&["uninstall", "site", "-n", "other"]);
    }
}

#[test]
fn unchanged_manifests_and_a_chart_are_held_as_they_were_sent() {
    let Some(cluster) = Cluster::start("kube-unchanged") else {
        return;
    };
    // A directory of manifests as they are written for Kubernetes: nothing of kith in them.
    let empty = cluster.holds();
    std::fs::create_dir_all(cluster.dir.join("stock")).unwrap();
    cluster.write("stock/shop.yaml", SHOP);
    cluster.write("stock/rest.yaml", REST);
    let made = cluster.ok(&["apply", "-f", "stock"]);
    assert_eq!(made.matches(" created").count(), 8, "{made}");
    // Every field that was sent comes back as it was sent.
    for (file, text) in [("shop.yaml", SHOP), ("rest.yaml", REST)] {
        for sent in kith_kube::documents(file, text).unwrap() {
            let kind = sent["kind"].as_str().unwrap();
            let name = sent["metadata"]["name"].as_str().unwrap();
            let got = cluster.got(&[kind, name]);
            assert_eq!(lost(&sent, &got, kind), None);
            // and it has what a client expects of the server.
            let meta = &got["metadata"];
            let server = [&meta["uid"], &meta["resourceVersion"], &meta["creationTimestamp"]];
            assert!(server.iter().all(|field| field.is_string()), "{meta}");
            assert_eq!(meta["namespace"], "default");
        }
    }
    // What kith runs for them is its own kinds.
    let db = cluster.held("workload/db");
    assert_eq!(
        db["spec"]["template"]["containers"][0]["volumeMounts"][0]["volume"], "data-db-0",
        "{db}"
    );
    // A claim is given a Volume on the node (Kubernetes would ask a storage class for one).
    for claim in ["data-db-0", "uploads"] {
        eventually("a claim bound to the Volume made for it", 30, || {
            cluster.got(&["pvc", claim])["status"]["phase"] == "Bound"
        });
        let volume = cluster.held(&format!("volume/{claim}"));
        assert_eq!(volume["spec"]["node"], "alpha", "{volume}");
        assert_eq!(cluster.got(&["pvc", claim])["spec"]["volumeName"], claim);
    }
    assert_eq!(
        cluster.got(&["pvc", "data-db-0"])["spec"]["resources"]["requests"]["storage"],
        "1Gi"
    );
    let tick = cluster.held("cronjob/tick");
    assert_eq!(
        (&tick["spec"]["schedule"], &tick["spec"]["concurrency"]),
        (&"* * * * *".into(), &"forbid".into())
    );
    // The Ingress is the Service's way in from outside.
    let shop = cluster.held("service/shop");
    assert_eq!(shop["spec"]["expose"]["host"], "shop.example.com", "{shop}");
    says(&cluster.ok(&["get", "ingress"]), &["shop", "shop.example.com"]);
    // The CronJob's Jobs are made by the clock: within its minute there is one, with a pod.
    let jobs = || cluster.ok(&["get", "jobs", "-o", "name"]);
    eventually("a Job of the CronJob", 75, || jobs().starts_with("job.batch/tick-"));
    eventually("the Job's pod", 30, || {
        cluster.ok(&["get", "pods", "-o", "name"]).contains("pod/tick-")
    });
    eventually("the CronJob saying when", 75, || {
        cluster.got(&["cronjob", "tick"])["status"]["lastScheduleTime"].is_string()
    });
    says(&cluster.ok(&["describe", "job"]), &["Controlled By:  CronJob/tick"]);

    // Sent again nothing changes, and deleted nothing is left: not the Volumes made for the claims either.
    let again = cluster.ok(&["apply", "-f", "stock"]);
    assert_eq!(again.matches(" unchanged").count(), 8, "{again}");
    cluster.ok(&["delete", "-f", "stock"]);
    // (A StatefulSet's claim is not the StatefulSet's to remove, in Kubernetes either.)
    cluster.ok(&["delete", "pvc", "data-db-0"]);
    eventually("the CronJob's Jobs and the claims' Volumes gone with them", 90, || {
        cluster.holds() == empty
    });

    // And a chart as Helm makes one, installed as it is: every field its manifests say
    // comes back from kubectl as it was said.
    if let Some(helm) = helms().first() {
        let run = |args: &[&str]| {
            let (ok, out, err) = cluster.run(helm, args);
            assert!(ok, "helm {args:?}: {out}{err}");
            out
        };
        run(&["create", "site"]);
        run(&["install", "site", "./site"]);
        let manifest = run(&["get", "manifest", "site"]);
        let sent = kith_kube::documents("the chart's manifest", &manifest).unwrap();
        assert!(
            sent.len() >= 3,
            "a ServiceAccount, a Service and a Deployment: {manifest}"
        );
        for sent in sent {
            let kind = sent["kind"].as_str().unwrap();
            let name = sent["metadata"]["name"].as_str().unwrap();
            assert_eq!(lost(&sent, &cluster.got(&[kind, name]), kind), None);
        }
        run(&["uninstall", "site"]);
    }
}

#[test]
fn refused_is_said_with_the_field_and_nothing_is_dropped_in_silence() {
    let Some(cluster) = Cluster::start("kube-refused") else {
        return;
    };
    let empty = cluster.holds();
    let pod = |field: &str| WEB.replace("      containers:", &format!("      {field}\n      containers:"));
    // What kith would run otherwise than asked is not taken, and the field is named.
    for (field, named) in [
        ("hostNetwork: true", "spec.template.spec.hostNetwork"),
        ("hostPID: true", "spec.template.spec.hostPID"),
        (
            "initContainers: [{ name: first, image: busybox }]",
            "spec.template.spec.initContainers",
        ),
        (
            "volumes: [{ name: host, hostPath: { path: / } }]",
            "spec.template.spec.volumes[host].hostPath",
        ),
        ("madeUp: 1", "spec.template.spec.madeUp"),
    ] {
        cluster.write("no.yaml", &pod(field));
        cluster.refused(&["apply", "-f", "no.yaml"], &["Deployment/web:", named]);
    }
    let privileged = WEB.replace(
        "          command:",
        "          securityContext: { privileged: true }\n          command:",
    );
    cluster.write("no.yaml", &privileged);
    cluster.refused(
        &["apply", "-f", "no.yaml"],
        &["spec.template.spec.containers[web].securityContext.privileged"],
    );
    assert_eq!(cluster.holds(), empty, "a refused object is not held");
    // What is taken and changes nothing is said, as a warning.
    cluster.write(
        "hint.yaml",
        &pod("serviceAccountName: robot").replace("replicas: 2", "replicas: 2\n  revisionHistoryLimit: 3"),
    );
    let (ok, out, err) = cluster.kubectl(&["apply", "-f", "hint.yaml"]);
    assert!(ok && out.contains("created"), "{out}{err}");
    says(
        &err,
        &["Warning: Deployment/web: spec.template.spec.serviceAccountName is taken and changes nothing"],
    );
    // and it is still there to read.
    assert_eq!(
        cluster.ok(&["get", "deploy", "web", "-o", "jsonpath={.spec.revisionHistoryLimit}"]),
        "3"
    );

    // Kinds that are not here are not found, as an API server without them says it.
    let policy =
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: { name: none }\nspec: { podSelector: {} }\n";
    cluster.write("policy.yaml", policy);
    cluster.refused(
        &["apply", "-f", "policy.yaml"],
        &["no matches for kind \"NetworkPolicy\""],
    );
    let crd = "apiVersion: example.com/v1\nkind: Widget\nmetadata: { name: one }\n";
    cluster.write("crd.yaml", crd);
    cluster.refused(&["apply", "-f", "crd.yaml"], &["no matches for kind \"Widget\""]);
    let scaler = "apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\nmetadata: { name: web }\nspec:\n  maxReplicas: 3\n  scaleTargetRef: { apiVersion: apps/v1, kind: Deployment, name: web }\n";
    cluster.write("scaler.yaml", scaler);
    cluster.refused(
        &["apply", "-f", "scaler.yaml"],
        &["no matches for kind \"HorizontalPodAutoscaler\""],
    );
    cluster.refused(&["top", "pods"], &["Metrics API not available"]);
    // A CronJob kith could not run when it says is refused, not kept and never run.
    let cron = |more: &str, schedule: &str| {
        format!(
            "apiVersion: batch/v1\nkind: CronJob\nmetadata: {{ name: later }}\nspec:\n  schedule: \"{schedule}\"\n{more}  jobTemplate:\n    spec:\n      template:\n        spec:\n          restartPolicy: Never\n          containers: [{{ name: a, image: busybox:1.36 }}]\n"
        )
    };
    cluster.write("zone.yaml", &cron("  timeZone: Europe/Berlin\n", "0 3 * * *"));
    cluster.refused(&["apply", "-f", "zone.yaml"], &["spec.timeZone is not UTC"]);
    let long = cron("", "0 3 * * *").replace("name: later", &format!("name: {}", "l".repeat(53)));
    cluster.write("long.yaml", &long);
    cluster.refused(&["apply", "-f", "long.yaml"], &["metadata.name is longer than the 52"]);
    cluster.write("never.yaml", &cron("", "61 * * * *"));
    cluster.refused(
        &["apply", "-f", "never.yaml"],
        &["spec.schedule is no schedule", "`61` is not a minute"],
    );
    // A pod alone, and the ways into a running one: each says what to do instead.
    cluster.refused(
        &["run", "one", "--image=busybox:1.36"],
        &["a pod is run by what owns it"],
    );
    cluster.refused(
        &["exec", "web-0", "--", "true"],
        &["exec, attach and port-forward are not answered here", "kith run"],
    );
    cluster.refused(&["attach", "web-0"], &["not answered here"]);
    cluster.refused(&["cp", "web-0:/etc/hostname", "hostname"], &["not answered here"]);
    // (kith keeps a resource's earlier revisions its own way: `kith rollback`.)
    cluster.refused(&["rollout", "undo", "deployment/web"], &["no rollout history found"]);
    // (kubectl asks for no port of a pod that is not running: `sh ci/vm.sh --test kube` does.)
    cluster.refused(&["logs", "web-0", "--previous"], &["previous"]);
    cluster.refused(&["logs", "web-0", "--since=1h"], &["sinceSeconds"]);
    let json = r#"[{"op":"replace","path":"/spec/replicas","value":1}]"#;
    cluster.refused(
        &["patch", "deployment", "web", "--type", "json", "-p", json],
        &["json-patch"],
    );
    cluster.refused(&["delete", "deployment", "web", "--cascade=orphan"], &["Orphan"]);
    // Deleted only as it was seen (not another by its name), and no sooner or later for the asking.
    let seen =
        r#"{"kind":"DeleteOptions","apiVersion":"v1","preconditions":{"uid":"00000000-0000-0000-0000-000000000000"}}"#;
    cluster.write("seen.json", seen);
    let web = "/apis/apps/v1/namespaces/default/deployments/web";
    cluster.refused(&["delete", "--raw", web, "-f", "seen.json"], &["preconditions.uid"]);
    let (ok, _, said) = cluster.kubectl(&["delete", "deployment", "web", "--grace-period=5", "--dry-run=server"]);
    assert!(
        ok && said.contains("gracePeriodSeconds is taken and changes nothing"),
        "{said}"
    );
    cluster.refused(&["delete", "pod", "web-0"], &["web-0"]);
    assert_eq!(cluster.held("workload/web")["spec"]["replicas"], 2);

    // What kith's own files made is not shown as a Kubernetes object, nor written over as one.
    let own = "apiVersion: kith.dev/v1\nkind: Workload\nmetadata: { name: own }\nspec:\n  replicas: 1\n  template:\n    exec: [{ name: sleep, command: [sleep, '3600'] }]\n";
    cluster.write("own.yaml", own);
    cluster.kith(&["apply", "-f", "own.yaml"]);
    assert_eq!(
        cluster.ok(&["get", "deployments", "-o", "name"]),
        "deployment.apps/web\n"
    );
    cluster.write("over.yaml", &WEB.replace("name: web\n", "name: own\n"));
    cluster.refused(
        &["apply", "-f", "over.yaml"],
        &["Workload/default/own is there, and was not made as a Deployment through this API"],
    );
    assert!(cluster.held("workload/own")["spec"]["template"]["exec"].is_array());
    // A StatefulSet and a Deployment are both Workloads: one name is one of them.
    cluster.write("over.yaml", &WEB.replace("kind: Deployment", "kind: StatefulSet"));
    cluster.refused(&["apply", "-f", "over.yaml"], &["was not made as a StatefulSet"]);
}

#[test]
fn access_is_kiths_own_and_the_kubernetes_api_is_no_way_past_it() {
    let Some(cluster) = Cluster::start("kube-access") else {
        return;
    };
    // bob may run things in the namespace `team` and nowhere else, and reads no Secret.
    cluster.kith(&["identity", "cert", "bob", "--out", "."]);
    let role = "apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: team }\nspec:\n  rules:\n    - kinds: [Workload, Service, ConfigMap]\n      verbs: [get, list, watch, apply, delete]\n      namespaces: [team]\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: bob-team }\nspec:\n  role: team\n  subjects: [bob]\n";
    cluster.write("team.yaml", role);
    cluster.kith(&["apply", "-f", "team.yaml"]);
    cluster.write("web.yaml", WEB);
    cluster.write("shop.yaml", SHOP);
    cluster.ok(&["apply", "-f", "shop.yaml"]);
    let bob = cluster.as_("bob");

    bob.ok(&["apply", "-n", "team", "-f", "web.yaml"]);
    assert_eq!(cluster.held("workload/team/web")["spec"]["replicas"], 2);
    // Elsewhere, and what his Role does not name, is forbidden: to write, to read, to delete.
    bob.refused(&["apply", "-f", "web.yaml"], &["Forbidden"]);
    bob.refused(
        &[
            "create",
            "secret",
            "generic",
            "mine",
            "-n",
            "team",
            "--from-literal=a=b",
        ],
        &["bob may not apply Secret in namespace team"],
    );
    bob.refused(&["get", "secret", "shop-secret", "-o", "yaml"], &["Forbidden"]);
    bob.refused(&["get", "secrets", "-A"], &["Forbidden"]);
    bob.refused(&["get", "deployment", "shop"], &["Forbidden"]);
    bob.refused(&["delete", "deployment", "shop"], &["Forbidden"]);
    bob.refused(&["scale", "deployment/shop", "--replicas=0"], &["Forbidden"]);
    bob.refused(&["delete", "namespace", "default"], &["Forbidden"]);
    // (A pod he may not see is, to him, not there.)
    bob.refused(&["logs", "shop-0"], &["NotFound"]);
    // (What is kept as it was sent is a kind of its own, which he was not given.)
    bob.refused(&["create", "serviceaccount", "robot", "-n", "team"], &["bob may not"]);
    assert_eq!(cluster.held("workload/shop")["spec"]["replicas"], 2);
    // Everywhere, he sees what he may see: his own, and the pods of his own.
    assert_eq!(
        bob.ok(&["get", "deployments", "-A", "-o", "name"]),
        "deployment.apps/web\n"
    );
    assert_eq!(bob.ok(&["get", "pods", "-A", "-o", "name"]), "pod/web-0\npod/web-1\n");
    assert_eq!(bob.ok(&["get", "pods", "-o", "name"]), "");
    bob.ok(&["logs", "-n", "team", "web-0"]);
    // A watch tells him of no more than a list does.
    let watched = bob.ok(&[
        "get",
        "deployments",
        "-A",
        "--watch",
        "--request-timeout=2s",
        "-o",
        "name",
    ]);
    assert_eq!(watched, "deployment.apps/web\n");

    // What kith gives no Workload it gives none through here: there is no field to ask it by.
    for (field, named) in [
        ("securityContext: { privileged: true }", "securityContext.privileged"),
        (
            "securityContext: { capabilities: { add: [NET_ADMIN] } }",
            "securityContext.capabilities",
        ),
    ] {
        let asked = WEB.replace("          command:", &format!("          {field}\n          command:"));
        cluster.write("asked.yaml", &asked);
        cluster.refused(&["apply", "-n", "team", "-f", "asked.yaml"], &[named]);
        bob.refused(&["apply", "-n", "team", "-f", "asked.yaml"], &[named]);
    }
    // An Ingress is kept as it was sent, a kind he was not given: it is refused whole, and
    // the Service it names is not exposed by half of it.
    bob.ok(&["expose", "deployment", "web", "-n", "team", "--port=80"]);
    let way = "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: { name: web }\nspec:\n  rules:\n    - host: web.example.com\n      http:\n        paths:\n          - path: /\n            pathType: Prefix\n            backend: { service: { name: web, port: { number: 80 } } }\n";
    cluster.write("way.yaml", way);
    bob.refused(&["apply", "-n", "team", "-f", "way.yaml"], &["bob may not"]);
    let exposed = || cluster.held("service/team/web")["spec"]["expose"]["host"].clone();
    assert!(exposed().is_null());
    // Made by who may, it does not take his Service from him: he changes it, and it stays exposed.
    cluster.ok(&["apply", "-n", "team", "-f", "way.yaml"]);
    assert_eq!(exposed(), "web.example.com");
    bob.ok(&["annotate", "service", "web", "-n", "team", "seen=yes"]);
    assert_eq!(exposed(), "web.example.com");
    // A request that names no namespace is one for `default`, where he may do nothing.
    let told = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"told"},"data":{"a":"b"}}"#;
    cluster.write("told.json", told);
    bob.refused(
        &["create", "--raw", "/api/v1/configmaps", "-f", "told.json"],
        &["Forbidden"],
    );
    assert_eq!(
        cluster
            .ok(&["get", "configmaps", "-A", "-o", "name"])
            .matches("told")
            .count(),
        0
    );
    // Without a certificate nobody is anybody.
    let nobody = cluster.as_("nobody");
    nobody.refused(&["get", "deployments"], &[]);
    nobody.refused(&["apply", "-f", "web.yaml"], &[]);
    let (_, _, err) = nobody.kubectl(&["get", "deployments", "-A"]);
    // (kithd ends a connection that shows no certificate before anything is asked on it.)
    assert!(
        err.contains("Unauthorized") || err.contains("certificate") || err.contains("EOF"),
        "{err}"
    );
    // And a certificate that was taken back is nobody's.
    cluster.kith(&["delete", "identity/bob"]);
    bob.refused(&["get", "deployments", "-n", "team"], &[]);
}
