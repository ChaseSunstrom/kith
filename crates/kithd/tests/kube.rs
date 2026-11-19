//! The real `kubectl` and `helm` against one kithd on 127.0.0.1: nothing of Kubernetes is
//! started, and no image is pulled (the node has an empty one under each name these
//! manifests use, so little here runs: the one test that runs a replica (`kubectl exec` and
//! `cp`) fills its own image from this host's `sh`, and skips where the host takes no container).
//! Skips where there is no kubectl (`KITH_KUBECTL` names one, or the one on `PATH`); the
//! tests of Helm skip where `KITH_HELM` names none (`helm3:helm4`, each is used).
//! `sh ci/kube.sh` fetches all three and runs this:
//!
//! ```sh
//! KITH_KUBECTL=/path/to/kubectl KITH_HELM=/path/to/helm cargo test -p kithd --test kube
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// One kithd, an Identity that may do everything, and a kubeconfig that is that Identity.
struct Cluster {
    child: Child,
    dir: PathBuf,
    kubectl: String,
    /// The port kithd listens on, on 127.0.0.1.
    port: u16,
    /// The kubeconfig kubectl and helm are run with: alice's, who may do everything.
    config: PathBuf,
}

/// Whether a kubectl runs here (`KITH_KUBECTL`, or the one on `PATH`); a test that needs one has nothing to say without.
fn has_kubectl() -> bool {
    let kubectl = std::env::var("KITH_KUBECTL").unwrap_or("kubectl".into());
    let runs = Command::new(&kubectl).args(["version", "--client"]).output();
    let runs = runs.is_ok_and(|out| out.status.success());
    if !runs {
        eprintln!("skipped: no kubectl (KITH_KUBECTL or PATH)");
    }
    runs
}

impl Cluster {
    /// None where no kubectl runs: the test has nothing to say then.
    fn start(test: &str) -> Option<Cluster> {
        has_kubectl().then(|| Cluster::boot(test))
    }

    /// A kithd of its own with its Identities, which need no kubectl: `curl` asks it directly.
    fn boot(test: &str) -> Cluster {
        Cluster::boot_with(test, false)
    }

    /// `host`: a port-forward to a pod this node has not made reaches the host's loopback (`KITHD_PORTFORWARD_HOST`, a
    /// debug build's): the tests here have no network to make a pod with, and one that sets it is the only one to need it.
    fn boot_with(test: &str, host: bool) -> Cluster {
        let kubectl = std::env::var("KITH_KUBECTL").unwrap_or("kubectl".into());
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
            .args(["--listen", &format!("127.0.0.1:{port}"), "--registry-port", "0"])
            // (A silent port-forward stream, and a session with none, end after this long: a debug build of kithd reads it, so a test need not wait minutes.)
            .env("KITHD_PORTFORWARD_IDLE_MS", "10000")
            .envs(host.then_some(("KITHD_PORTFORWARD_HOST", "1")))
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let config = dir.join("kubeconfig");
        let cluster = Cluster {
            child,
            dir,
            kubectl,
            port,
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
        for who in ["alice", "bob", "carol", "nobody"] {
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
        cluster
    }

    /// The same cluster, asked as another Identity (its kubeconfig is `kubeconfig-NAME`).
    fn as_(&self, who: &str) -> Cluster {
        Cluster {
            // (Nothing to stop: `true` has ended by the time this one is dropped.)
            child: Command::new("true").spawn().unwrap(),
            dir: self.dir.clone(),
            kubectl: self.kubectl.clone(),
            port: self.port,
            config: self.dir.join(format!("kubeconfig-{who}")),
        }
    }

    /// The status kithd answers one request of `who` (an Identity of this cluster) with, as
    /// curl asks it. An upgrade to a WebSocket answers 101, and the session then waits for kithd's
    /// 5 s cap, so the 101 comes back at about 5 s; curl's 10 s limit covers that under load.
    fn reply(&self, who: &str, method: &str, path: &str, headers: &[&str], body: Option<&str>) -> String {
        self.reply_in(10, who, method, path, headers, body)
    }

    /// [`Cluster::reply`], with curl's limit `secs` (a session that is not ended by kithd comes back at that).
    fn reply_in(&self, secs: u32, who: &str, method: &str, path: &str, headers: &[&str], body: Option<&str>) -> String {
        let out = self.curl(secs, who, method, path, headers, body).output();
        String::from_utf8_lossy(&out.expect("curl runs").stdout).into_owned()
    }

    /// The curl that asks `reply`'s question, not yet run (a test that holds some sessions open spawns it).
    fn curl(&self, secs: u32, who: &str, method: &str, path: &str, headers: &[&str], body: Option<&str>) -> Command {
        let mut args: Vec<String> = vec![
            "-s".into(),
            "-o".into(),
            "/dev/null".into(),
            "-w".into(),
            "%{http_code}".into(),
            "-m".into(),
            secs.to_string(),
            "-X".into(),
            method.into(),
            "--cacert".into(),
            "ca.crt".into(),
            "--cert".into(),
            format!("{who}.crt"),
            "--key".into(),
            format!("{who}.key"),
            "--resolve".into(),
            format!("kith:{}:127.0.0.1", self.port),
        ];
        for header in headers {
            args.extend(["-H".into(), header.to_string()]);
        }
        if let Some(body) = body {
            args.extend(["--data-binary".into(), format!("@{body}")]);
        }
        args.push(format!("https://kith:{}{path}", self.port));
        let mut curl = Command::new("curl");
        curl.args(&args).current_dir(&self.dir).stdin(Stdio::null());
        curl
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
            .env("KITH_SOCKET", "kithd.sock")
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

    /// kubectl as alice with `input` on its stdin; returns (it succeeded, stdout, stderr).
    fn kubectl_in(&self, args: &[&str], input: &[u8]) -> (bool, Vec<u8>, String) {
        use std::io::Write;
        let mut child = Command::new(&self.kubectl)
            .args(args)
            .current_dir(&self.dir)
            .env("KUBECONFIG", &self.config)
            .env("HOME", &self.dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // (From a thread: a program that answers before it has read it all must not hold this.)
        let mut stdin = child.stdin.take().unwrap();
        let input = input.to_vec();
        let writer = std::thread::spawn(move || drop(stdin.write_all(&input)));
        let out = child.wait_with_output().unwrap();
        let _ = writer.join();
        (
            out.status.success(),
            out.stdout,
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// The image `kith.test/box:1`, which is this host's own `sleep`, `sh`, `cat` and `tar` with the
    /// libraries `ldd` names for them: what a replica that runs needs for `exec` and `cp`.
    fn fill_box(&self) {
        let rootfs = self
            .dir
            .join(format!("state/runtime/images/{:064x}/rootfs", IMAGES.len() - 1));
        for dir in [
            "dev", "etc", "proc", "run", "sys", "tmp", "bin", "lib", "lib64", "usr/lib",
        ] {
            std::fs::create_dir_all(rootfs.join(dir)).unwrap();
        }
        for bin in ["sleep", "sh", "cat", "tar", "test"] {
            let from = Path::new("/usr/bin").join(bin);
            std::fs::copy(&from, rootfs.join("bin").join(bin)).unwrap();
            let listed = Command::new("ldd").arg(&from).output().unwrap();
            for lib in String::from_utf8_lossy(&listed.stdout)
                .lines()
                .filter_map(|line| line.split_whitespace().find(|word| word.starts_with('/')))
            {
                let to = rootfs.join(lib.trim_start_matches('/'));
                std::fs::create_dir_all(to.parent().unwrap()).unwrap();
                let _ = std::fs::copy(lib, to);
            }
        }
        // A replica of a kithd that is not root has one id (its own): the `tar` of `kubectl cp` cannot
        // give a file the ids of the one that sent it, so this image's tar does not try.
        use std::os::unix::fs::PermissionsExt;
        std::fs::rename(rootfs.join("bin/tar"), rootfs.join("bin/tar-real")).unwrap();
        let script = "#!/bin/sh\nexec /bin/tar-real \"$@\" --no-same-owner\n";
        std::fs::write(rootfs.join("bin/tar"), script).unwrap();
        std::fs::set_permissions(rootfs.join("bin/tar"), std::fs::Permissions::from_mode(0o755)).unwrap();
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
    // (Last: `fill_box` puts programs in it.)
    "kith.test/box:1",
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
  startingDeadlineSeconds: 120
  successfulJobsHistoryLimit: 2
  failedJobsHistoryLimit: 0
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
fn workflows_kubectl_delete_pod_restarts_that_replica() {
    let Some(cluster) = Cluster::start("kube-delete-pod") else {
        return;
    };
    cluster.write("web.yaml", WEB);
    cluster.ok(&["apply", "-f", "web.yaml"]);
    let pods = || cluster.ok(&["get", "pods", "-l", "app=web", "-o", "name"]);
    eventually("the two replicas are pods", 30, || pods() == "pod/web-0\npod/web-1\n");
    let started = |name: &str| cluster.got(&["pod", name])["status"]["startTime"].clone();
    // (A pod is listed before it has started: under load its start time comes later.)
    eventually("both replicas started", 30, || {
        !started("web-0").is_null() && !started("web-1").is_null()
    });
    let (first, second) = (started("web-0"), started("web-1"));
    // A start time is whole seconds: wait past one, so the restart is a new one.
    std::thread::sleep(Duration::from_millis(1100));
    says(&cluster.ok(&["delete", "pod", "web-0"]), &["pod \"web-0\" deleted"]);
    eventually("web-0 started again", 30, || started("web-0") != first);
    assert_eq!(started("web-1"), second, "the other replica is not restarted");
    assert_eq!(pods(), "pod/web-0\npod/web-1\n", "the same names");
    assert_eq!(cluster.held("workload/web")["spec"]["replicas"], 2);
    // A pod that is not there is not found, and says its name.
    cluster.refused(&["delete", "pod", "bare"], &["NotFound", "bare"]);
    // A Pod applied over a Deployment of its name is a name taken (AlreadyExists), not a Pod to delete first.
    cluster.write(
        "webpod.yaml",
        "apiVersion: v1\nkind: Pod\nmetadata: { name: web }\nspec:\n  restartPolicy: Never\n  containers: [{ name: a, image: busybox:1.36 }]\n",
    );
    cluster.refused(&["apply", "--server-side", "-f", "webpod.yaml"], &["already exists"]);
}

/// A Pod sent alone is read back as the Pod that was sent, and `kubectl delete pod` deletes it (and
/// does not restart it, as it does the pod of a Workload).
#[track_caller]
fn bare_pod_round_trip(cluster: &Cluster, name: &str, sent: &serde_json::Value, held: &str) {
    let got = cluster.got(&["pod", name]);
    assert_eq!(got["kind"], "Pod", "{got}");
    assert_eq!(got["spec"]["restartPolicy"], "Never", "{got}");
    if let Some(why) = lost(sent, &got, "") {
        panic!("a Pod sent is not read back whole: {why}\n{got}");
    }
    assert_eq!(cluster.held(held)["metadata"]["annotations"]["kith.dev/pod"], "true");
    says(
        &cluster.ok(&["delete", "pod", name]),
        &[&format!("pod \"{name}\" deleted")],
    );
    assert_eq!(cluster.ok(&["get", "pods", "-o", "name"]), "", "no pod is left");
    cluster.refused(&["get", "pod", name], &["NotFound"]);
}

#[test]
fn workflows_kubectl_run_never_is_a_pod_and_delete_pod_deletes_it() {
    let Some(cluster) = Cluster::start("kube-run-never") else {
        return;
    };
    let empty = cluster.holds();
    let image = "--image=mirror.gcr.io/library/busybox:1.36";
    let made = cluster.ok(&[
        "run",
        "one",
        image,
        "--restart=Never",
        "--labels=app=one",
        "--",
        "sleep",
        "3600",
    ]);
    says(&made, &["pod/one created"]);
    // What kubectl sent, asked of it again without sending (what it adds that the server owns is dropped).
    let args = [
        "run",
        "one",
        image,
        "--restart=Never",
        "--labels=app=one",
        "--dry-run=client",
        "-o",
        "json",
    ];
    let mut sent: serde_json::Value =
        serde_json::from_str(&cluster.ok(&[&args[..], &["--", "sleep", "3600"]].concat())).unwrap();
    sent.as_object_mut().unwrap().remove("status");
    sent["metadata"].as_object_mut().unwrap().remove("creationTimestamp");
    bare_pod_round_trip(&cluster, "one", &sent, "job/one");
    assert_eq!(cluster.holds(), empty, "kith holds what it held before the pod");

    // The default restart policy is Always: that pod is a Workload of one, and is deleted all the same.
    says(
        &cluster.ok(&["run", "always", image, "--", "sleep", "3600"]),
        &["pod/always created"],
    );
    assert_eq!(cluster.ok(&["get", "pods", "-o", "name"]), "pod/always\n");
    says(&cluster.ok(&["delete", "pod", "always"]), &["pod \"always\" deleted"]);
    assert_eq!(cluster.holds(), empty);
}

#[test]
fn workflows_helm_test_runs_the_chart_test_pod_and_delete_pod_deletes_it() {
    for (n, helm) in helms().iter().enumerate() {
        let Some(cluster) = Cluster::start(&format!("kube-helm-test-{n}")) else {
            return;
        };
        let empty = cluster.holds();
        let run = |args: &[&str]| cluster.run(helm, args);
        let (ok, out, err) = run(&["create", "site"]);
        assert!(ok, "{out}{err}");
        let (ok, out, err) = run(&["install", "site", "./site"]);
        assert!(ok, "{out}{err}");
        // Nothing runs here (the images are empty), so the test is not passed: helm made the pod, which is
        // what is asked, and gives up waiting for it.
        let (_, out, err) = run(&["test", "site", "--timeout", "5s"]);
        let said = out + &err;
        assert!(
            !said.contains("is invalid") && !said.contains("not found"),
            "helm test: {said}"
        );
        let got = cluster.got(&["pod", "site-test-connection"]);
        assert_eq!(got["kind"], "Pod", "{got}");
        assert_eq!(got["metadata"]["annotations"]["helm.sh/hook"], "test", "{got}");
        assert_eq!(got["spec"]["restartPolicy"], "Never", "{got}");
        assert_eq!(got["spec"]["containers"][0]["image"], "busybox", "{got}");
        assert_eq!(
            cluster.held("job/site-test-connection")["metadata"]["annotations"]["kith.dev/pod"],
            "true"
        );
        says(
            &cluster.ok(&["delete", "pod", "site-test-connection"]),
            &["pod \"site-test-connection\" deleted"],
        );
        cluster.refused(&["get", "pod", "site-test-connection"], &["NotFound"]);
        // The chart's Deployment is still there, and its pod is the Workload's.
        says(&cluster.ok(&["get", "pods", "-o", "name"]), &["pod/site-0"]);
        let (ok, out, err) = run(&["uninstall", "site", "--wait", "--timeout", "30s"]);
        assert!(ok, "{out}{err}");
        assert_eq!(cluster.holds(), empty, "kith holds what it held before the chart");
    }
}

/// The Deployment `web` of one replica whose image is `kith.test/box:1`, made and applied. Its
/// container is `box`: a unit's id holds it, and the containers of the tests that run at once
/// (each in a kithd of its own, in one cgroup tree) must not share an id, or one's delete ends the other's.
fn apply_box(cluster: &Cluster) {
    cluster.fill_box();
    let web = WEB
        .replace("- name: web\n", "- name: box\n")
        .replace("mirror.gcr.io/library/busybox:1.36", "kith.test/box:1")
        .replace("replicas: 2", "replicas: 1")
        .replace("[sleep,", "[/bin/sleep,");
    cluster.write("box.yaml", &web);
    cluster.ok(&["apply", "-f", "box.yaml"]);
}

/// `kubectl exec` and `kubectl cp` (a tar run by exec, both ways) run in the replica's own mount and
/// pid namespaces: stdin, stdout, stderr and the exit status come back as the channels of a
/// WebSocket. Skips where this host's cgroup takes no container.
#[test]
fn workflows_kubectl_exec_and_cp_run_in_the_replica() {
    let Some(cluster) = Cluster::start("kube-exec") else {
        return;
    };
    // (alice's Role is for what kubectl applies and gets: what runs in a replica is a right of its own.)
    let may = "apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: execer }\nspec:\n  rules:\n    - kinds: [Workload]\n      verbs: [exec]\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: alice-execer }\nspec:\n  role: execer\n  subjects: [alice]\n";
    cluster.write("execer.yaml", may);
    cluster.kith(&["apply", "-f", "execer.yaml"]);
    apply_box(&cluster);
    // The replica is up when a process can be run in it (a unit starts a moment after its pod is listed).
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (ok, _, err) = cluster.kubectl(&["exec", "web-0", "--", "sh", "-c", ":"]);
        if ok {
            break;
        }
        let status = cluster.kith(&["get", "workload/web", "-o", "json"]);
        if status.contains("cgroup error") {
            eprintln!("::warning title=SKIP::SKIP (not a pass): this host's cgroup takes no container");
            return;
        }
        assert!(Instant::now() < deadline, "web-0 never took a process: {err}\n{status}");
        std::thread::sleep(Duration::from_millis(250));
    }
    // In the container's pid namespace, its init is pid 1 and the shell has a small pid; its files are the image's.
    says(
        &cluster.ok(&["exec", "web-0", "--", "cat", "/proc/1/cmdline"]),
        &["/bin/sleep"],
    );
    let pid = cluster.ok(&["exec", "web-0", "--", "sh", "-c", "echo $$"]);
    assert!(pid.trim().parse::<u32>().unwrap() < 1000, "{pid}");
    // (The host has /home, and the image does not.)
    cluster.refused(&["exec", "web-0", "--", "sh", "-c", "test -e /home"], &["exit code 1"]);
    // stdout and stderr each on their channel, and the exit status.
    let (ok, out, err) = cluster.kubectl(&[
        "exec",
        "web-0",
        "--",
        "sh",
        "-c",
        "echo to-out; echo to-err >&2; exit 3",
    ]);
    assert!(!ok && out == "to-out\n", "{ok} {out:?} {err}");
    says(&err, &["to-err", "exit code 3"]);
    // stdin, to its end, and more of it than one frame holds.
    let (ok, out, err) = cluster.kubectl_in(&["exec", "-i", "web-0", "--", "cat"], b"hello\n");
    assert!(ok && out == b"hello\n", "{ok} {out:?} {err}");
    let big: Vec<u8> = (0..3u32 << 20).map(|n| (n % 251) as u8).collect();
    let (ok, out, err) = cluster.kubectl_in(&["exec", "-i", "web-0", "--", "cat"], &big);
    assert!(
        ok && out == big,
        "{ok} {} bytes back of {}: {err}",
        out.len(),
        big.len()
    );
    // cp up, then down.
    cluster.write("up.txt", "uploaded\n");
    cluster.ok(&["cp", "up.txt", "web-0:/tmp/up.txt"]);
    assert_eq!(cluster.ok(&["exec", "web-0", "--", "cat", "/tmp/up.txt"]), "uploaded\n");
    cluster.ok(&["cp", "web-0:/tmp/up.txt", "down.txt"]);
    assert_eq!(
        std::fs::read_to_string(cluster.dir.join("down.txt")).unwrap(),
        "uploaded\n"
    );
    // A program the image lacks is an error, and attach and a TTY are refused by name.
    cluster.refused(&["exec", "web-0", "--", "nothing-here"], &[]);
    cluster.refused(&["attach", "web-0"], &["attach to the main process is not carried"]);
}

#[test]
fn workflows_json_patch_by_kubectl() {
    let Some(cluster) = Cluster::start("kube-json-patch") else {
        return;
    };
    cluster.write("web.yaml", WEB);
    cluster.ok(&["apply", "-f", "web.yaml"]);
    // Replicas and the image in one patch: each is the kith Workload's change.
    let ops = r#"[{"op":"replace","path":"/spec/replicas","value":3},{"op":"replace","path":"/spec/template/spec/containers/0/image","value":"docker.io/library/nginx:1.27-alpine"}]"#;
    cluster.ok(&["patch", "deployment", "web", "--type", "json", "-p", ops]);
    let held = cluster.held("workload/web");
    assert_eq!(held["spec"]["replicas"], 3, "{held}");
    assert_eq!(
        held["spec"]["template"]["containers"][0]["image"],
        "docker.io/library/nginx:1.27-alpine"
    );

    // A test that is not so refuses the whole patch (422), and what is there stays as it was.
    // (Its spec, not all of it: the status of the containers is what runs, and moves on its own.)
    let before = cluster.held("workload/web")["spec"].clone();
    let stale =
        r#"[{"op":"test","path":"/spec/replicas","value":2},{"op":"replace","path":"/spec/replicas","value":5}]"#;
    cluster.refused(
        &["patch", "deployment", "web", "--type", "json", "-p", stale],
        &["test /spec/replicas: the value is not the one given"],
    );
    assert_eq!(cluster.held("workload/web")["spec"], before);

    // A replace of a path that is not there is refused, not made.
    let missing = r#"[{"op":"replace","path":"/spec/nope","value":1}]"#;
    cluster.refused(
        &["patch", "deployment", "web", "--type", "json", "-p", missing],
        &["/spec/nope: the path is not there"],
    );
    assert_eq!(cluster.held("workload/web")["spec"], before);

    // A label added, and removed again, as kubectl sees it.
    let add = r#"[{"op":"add","path":"/metadata/labels/tier","value":"front"}]"#;
    cluster.ok(&["patch", "deployment", "web", "--type", "json", "-p", add]);
    assert_eq!(
        cluster.got(&["deployment", "web"])["metadata"]["labels"]["tier"],
        "front"
    );
    let remove = r#"[{"op":"remove","path":"/metadata/labels/tier"}]"#;
    cluster.ok(&["patch", "deployment", "web", "--type", "json", "-p", remove]);
    assert!(
        cluster.got(&["deployment", "web"])["metadata"]["labels"]
            .get("tier")
            .is_none()
    );
}

/// A Deployment with no replicas: the server defaults them to 1, and kubectl reads 1.
const BARE: &str = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  selector:
    matchLabels: { app: api }
  template:
    metadata:
      labels: { app: api }
    spec:
      containers:
        - name: api
          image: mirror.gcr.io/library/busybox:1.36
          command: [sleep, "3600"]
"#;

#[test]
fn workflows_json_patch_sees_what_kubectl_sees() {
    let Some(cluster) = Cluster::start("kube-json-patch-served") else {
        return;
    };
    cluster.write("api.yaml", BARE);
    cluster.ok(&["apply", "-f", "api.yaml"]);
    // The base of the patch is what kubectl reads: the replicas the server defaulted, and the
    // resourceVersion it reads, so a test of that and a replace of the replicas both find their paths.
    // The Deployment may be written (its status) between the read and the patch, as a client
    // under optimistic concurrency sees: then the test op fails and the read is done again.
    let mut said = String::new();
    for _ in 0..10 {
        let version = cluster.got(&["deployment", "api"])["metadata"]["resourceVersion"].clone();
        let ops = serde_json::json!([
            { "op": "test", "path": "/metadata/resourceVersion", "value": version },
            { "op": "replace", "path": "/spec/replicas", "value": 3 },
        ])
        .to_string();
        let (ok, out, err) = cluster.kubectl(&["patch", "deployment", "api", "--type", "json", "-p", ops.as_str()]);
        if ok {
            said.clear();
            break;
        }
        said = format!("{out}{err}");
        assert!(
            said.contains("test /metadata/resourceVersion: the value is not the one given"),
            "kubectl patch: {said}"
        );
    }
    assert!(said.is_empty(), "the test op failed 10 times: {said}");
    assert_eq!(cluster.got(&["deployment", "api"])["spec"]["replicas"], 3);
}

/// `kubectl rollout history` and `undo` of a Deployment: the kept revisions are ReplicaSets
/// to read, and an undo is kith's own rollback to the revision that held that template.
#[test]
fn workflows_rollout_history_and_undo() {
    let Some(cluster) = Cluster::start("kube-rollout") else {
        return;
    };
    cluster.write("api.yaml", BARE);
    cluster.ok(&["apply", "-f", "api.yaml"]);
    // Two more templates, each a revision (a template annotation is what `rollout restart` sets).
    for step in ["two", "three"] {
        let patch = format!(r#"{{"spec":{{"template":{{"metadata":{{"annotations":{{"step":"{step}"}}}}}}}}}}"#);
        cluster.ok(&["patch", "deployment", "api", "-p", patch.as_str()]);
    }
    let step = || {
        let live = cluster.got(&["deployment", "api"]);
        live["spec"]["template"]["metadata"]["annotations"]["step"]
            .as_str()
            .unwrap_or("none")
            .to_string()
    };
    let revisions = || -> Vec<String> {
        let history = cluster.ok(&["rollout", "history", "deployment/api"]);
        let rows = history.lines().filter_map(|line| line.split_whitespace().next());
        rows.filter(|row| row.parse::<u64>().is_ok())
            .map(str::to_string)
            .collect()
    };
    assert_eq!(revisions(), ["1", "2", "3"]);
    // One revision: its pod template.
    let one = cluster.ok(&["rollout", "history", "deployment/api", "--revision=2"]);
    says(&one, &["deployment.apps/api with revision #2", "step: two"]);
    // The ReplicaSets are the same, read: a write or a delete is refused, and says so.
    let sets = cluster.got(&["rs", "-l", "app=api"]);
    assert_eq!(sets["items"].as_array().unwrap().len(), 3, "{sets}");
    let name = sets["items"][0]["metadata"]["name"].as_str().unwrap().to_string();
    cluster.refused(&["delete", "rs", name.as_str()], &["read only"]);
    cluster.refused(&["scale", "rs", name.as_str(), "--replicas=2"], &["read only"]);
    cluster.refused(
        &["patch", "rs", name.as_str(), "-p", r#"{"spec":{"replicas":2}}"#],
        &["read only"],
    );
    // `apply` left its annotation: the undo's patch empties them, and is still taken for an undo.
    let notes = cluster.got(&["deployment", "api"]);
    let last = &notes["metadata"]["annotations"]["kubectl.kubernetes.io/last-applied-configuration"];
    assert!(last.is_string(), "{notes}");
    // Undo to a revision: the Deployment has that template again, as a new revision.
    says(
        &cluster.ok(&["rollout", "undo", "deployment/api", "--to-revision=2"]),
        &["deployment.apps/api rolled back"],
    );
    assert_eq!(step(), "two");
    assert_eq!(revisions(), ["1", "3", "4"], "the template of 2 is revision 4 now");
    assert_eq!(cluster.held("workload/api")["metadata"]["revision"], 4);
    // Undo with none named: the one before the live one (3).
    says(
        &cluster.ok(&["rollout", "undo", "deployment/api"]),
        &["deployment.apps/api rolled back"],
    );
    assert_eq!(step(), "three");
    assert_eq!(revisions(), ["1", "4", "5"]);
    // To the live template is nothing to do, and kubectl says so; to one never kept, it fails.
    says(
        &cluster.ok(&["rollout", "undo", "deployment/api", "--to-revision=5"]),
        &["skipped rollback"],
    );
    assert_eq!(cluster.held("workload/api")["metadata"]["revision"], 5);
    cluster.refused(
        &["rollout", "undo", "deployment/api", "--to-revision=9"],
        &["unable to find specified revision"],
    );
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
    // (Each replica's claim is `data-db-ORDINAL`: the mount names what they share.)
    let mount = &db["spec"]["template"]["containers"][0]["volumeMounts"][0];
    assert_eq!(
        (&mount["volume"], &mount["perReplica"]),
        (&"data-db".into(), &true.into()),
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
    // (What it keeps and how late it may start is carried as Kubernetes says it.)
    let keeps = [
        &tick["spec"]["startingDeadlineSeconds"],
        &tick["spec"]["successfulJobsHistoryLimit"],
        &tick["spec"]["failedJobsHistoryLimit"],
    ];
    assert_eq!(keeps, [120, 2, 0], "{tick}");
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
            "initContainers: [{ name: first, image: busybox, restartPolicy: Always }]",
            "spec.template.spec.initContainers[first].restartPolicy",
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
    // (A pod alone is run: `kubectl run` is proven in `workflows_kubectl_run_…`.) The ways into
    // a running one ask first for the right to exec into what owns it, which alice has not.
    cluster.refused(&["exec", "web-0", "--", "true"], &["alice may not exec Workload"]);
    cluster.refused(&["attach", "web-0"], &["may not exec Workload"]);
    cluster.refused(&["cp", "web-0:/etc/hostname", "hostname"], &["may not exec Workload"]);
    // (kith keeps a resource's earlier revisions its own way: `kith rollback`.)
    cluster.refused(&["rollout", "undo", "deployment/web"], &["no rollout history found"]);
    // (kubectl asks for no port of a pod that is not running: `sh ci/vm.sh --test kube` does.)
    cluster.refused(&["logs", "web-0", "--previous"], &["previous"]);
    cluster.refused(&["logs", "web-0", "--since=1h"], &["sinceSeconds"]);
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
    // (A pod's delete is taken now: it starts that replica again, as `workflows` shows.)
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

/// A Deployment and a Job of one name are two kinds and may share it: their pods are
/// not one, and `kubectl logs job/x` is the Job's output, not the Deployment's.
#[test]
fn a_deployment_and_a_job_of_one_name_make_two_pods() {
    let Some(cluster) = Cluster::start("kube-pod-names") else {
        return;
    };
    let both = "apiVersion: apps/v1\nkind: Deployment\nmetadata: { name: x }\nspec:\n  replicas: 1\n  selector: { matchLabels: { app: x } }\n  template:\n    metadata: { labels: { app: x } }\n    spec:\n      containers: [{ name: main, image: 'nginx:1.27-alpine' }]\n---\napiVersion: batch/v1\nkind: Job\nmetadata: { name: x }\nspec:\n  template:\n    spec:\n      restartPolicy: Never\n      containers: [{ name: main, image: 'busybox:1.36', command: ['true'] }]\n";
    cluster.write("both.yaml", both);
    cluster.ok(&["apply", "-f", "both.yaml"]);
    // Two names: a pod's name says what made it.
    let mut names = Vec::new();
    eventually("a pod of the Deployment and one of the Job", 30, || {
        names = cluster
            .ok(&["get", "pods", "-o", "name"])
            .lines()
            .map(str::to_string)
            .collect();
        names.sort();
        names == ["pod/x-0", "pod/x-j0"]
    });
    // What each wrote, in the files kithd keeps (nothing runs here, these images are empty).
    let logs = cluster.dir.join("state/logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(logs.join("w_default_x_0_main.out"), "the deployment's\n").unwrap();
    std::fs::write(logs.join("j_default_x_0_main.out"), "the job's\n").unwrap();
    assert_eq!(cluster.ok(&["logs", "job/x"]), "the job's\n");
    assert_eq!(cluster.ok(&["logs", "deployment/x"]), "the deployment's\n");
    assert_eq!(cluster.ok(&["logs", "x-j0"]), "the job's\n");
    assert_eq!(cluster.ok(&["logs", "x-0"]), "the deployment's\n");
    // A pod of one name is that kind's: no other ending is a pod.
    for no in ["x-j1", "x-n0", "x-1", "x-j", "x-j00", "x-+0", "x-00"] {
        cluster.refused(&["logs", no], &["NotFound"]);
    }
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
    // (A status change in its 2 s says the same Deployment again: what counts is which ones.)
    let watched: std::collections::BTreeSet<&str> = watched.lines().collect();
    assert_eq!(watched, std::collections::BTreeSet::from(["deployment.apps/web"]));

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

/// `kubectl exec`, `attach` and `cp` (a tar run by exec) are refused before any upgrade to a
/// WebSocket when the caller has no Exec right on the Workload or Job that owns the pod: bob
/// may get alone, and carol may run in `team`. Asked with curl, so no kubectl is needed.
#[test]
fn access_first_exec_attach_and_cp_are_refused_before_any_upgrade() {
    // Without a delegated cgroup kithd runs no workloads ("workloads will not run"), so the pods
    // of the Deployment and the Job never appear.
    if !kith_runtime::has_delegated_cgroup() {
        eprintln!("skipped: no delegated cgroup here");
        return;
    }
    let cluster = Cluster::boot("kube-exec-access");
    cluster.kith(&["identity", "cert", "bob", "--out", "."]);
    cluster.kith(&["identity", "cert", "carol", "--out", "."]);
    let roles = "apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: reader }\nspec:\n  rules:\n    - kinds: [Workload, Job]\n      verbs: [get, list, watch]\n      namespaces: [team]\n---\napiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: runner }\nspec:\n  rules:\n    - kinds: [Workload, Job]\n      verbs: [get, list, exec]\n      namespaces: [team]\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: bob-reader }\nspec:\n  role: reader\n  subjects: [bob]\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: carol-runner }\nspec:\n  role: runner\n  subjects: [carol]\n";
    cluster.write("roles.yaml", roles);
    cluster.kith(&["apply", "-f", "roles.yaml"]);
    // A Deployment `web` of two replicas and a Job `tidy`: their pods are web-0 and tidy-j0.
    let json = ["Content-Type: application/json"];
    cluster.write("web.json", r#"{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"web"},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"web"}},"template":{"metadata":{"labels":{"app":"web"}},"spec":{"containers":[{"name":"web","image":"mirror.gcr.io/library/busybox:1.36","command":["sleep","3600"]}]}}}}"#);
    cluster.write("tidy.json", r#"{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"tidy"},"spec":{"template":{"spec":{"restartPolicy":"Never","containers":[{"name":"tidy","image":"mirror.gcr.io/library/busybox:1.36","command":["true"]}]}}}}"#);
    assert_eq!(
        cluster.reply(
            "alice",
            "POST",
            "/apis/apps/v1/namespaces/team/deployments",
            &json,
            Some("web.json")
        ),
        "201"
    );
    assert_eq!(
        cluster.reply(
            "alice",
            "POST",
            "/apis/batch/v1/namespaces/team/jobs",
            &json,
            Some("tidy.json")
        ),
        "201"
    );
    eventually("the pods of web and of tidy", 30, || {
        cluster.reply("alice", "GET", "/api/v1/namespaces/team/pods/web-0", &[], None) == "200"
            && cluster.reply("alice", "GET", "/api/v1/namespaces/team/pods/tidy-j0", &[], None) == "200"
    });
    let exec = "/api/v1/namespaces/team/pods/web-0/exec?command=true&stdin=true&stdout=true&stderr=true";
    let attach = "/api/v1/namespaces/team/pods/web-0/attach?stdin=true&stdout=true&stderr=true";
    let tar =
        "/api/v1/namespaces/team/pods/web-0/exec?command=tar&command=xf&command=-&stdin=true&stdout=true&stderr=true";
    let job = "/api/v1/namespaces/team/pods/tidy-j0/exec?command=true&stdout=true&stderr=true";
    // (A WebSocket asks for its upgrade as kubectl does: a GET with these headers.)
    let upgrade = [
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Protocol: v4.channel.k8s.io",
    ];

    // bob may get the pod (cp asks for it first), and no more: what runs in it is refused.
    assert_eq!(
        cluster.reply("bob", "GET", "/api/v1/namespaces/team/pods/web-0", &[], None),
        "200"
    );
    for path in [exec, attach, tar, job] {
        assert_eq!(cluster.reply("bob", "POST", path, &[], None), "403", "{path}");
        // Refused before the upgrade is looked at: a WebSocket asked by bob is a 403, not a 101.
        assert_eq!(cluster.reply("bob", "GET", path, &upgrade, None), "403", "{path}");
    }

    // carol may run in `team`: the upgrade is answered with 101 for each of them.
    for path in [exec, attach, tar, job] {
        assert_eq!(cluster.reply("carol", "GET", path, &upgrade, None), "101", "{path}");
    }
    // Without an upgrade, or with a channel protocol kithd does not speak, it is a 400.
    assert_eq!(cluster.reply("carol", "POST", exec, &[], None), "400");
    let other = [
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Protocol: base64.channel.k8s.io",
    ];
    assert_eq!(cluster.reply("carol", "GET", exec, &other, None), "400");
}

/// With the real kubectl: a caller who may get but not exec is refused `exec` and `cp` both ways,
/// and each refusal is written down; the replica's node asks again for itself (see the hop's tests).
#[test]
fn access_kubectl_exec_and_cp_are_refused_without_the_right_to_exec() {
    let Some(cluster) = Cluster::start("kube-exec-refused") else {
        return;
    };
    cluster.kith(&["identity", "cert", "bob", "--out", "."]);
    let roles = "apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: reader }\nspec:\n  rules:\n    - kinds: [Workload]\n      verbs: [get, list, watch]\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: bob-reader }\nspec:\n  role: reader\n  subjects: [bob]\n";
    cluster.write("roles.yaml", roles);
    cluster.kith(&["apply", "-f", "roles.yaml"]);
    apply_box(&cluster);
    eventually("web-0 is a pod", 30, || cluster.kubectl(&["get", "pod", "web-0"]).0);
    let bob = cluster.as_("bob");
    assert!(bob.kubectl(&["get", "pod", "web-0"]).0, "bob may get it");
    cluster.write("up.txt", "uploaded\n");
    for args in [
        &["exec", "web-0", "--", "true"][..],
        &["cp", "up.txt", "web-0:/tmp/up.txt"],
        &["cp", "web-0:/tmp/up.txt", "down.txt"],
    ] {
        let (ok, _, err) = bob.kubectl(args);
        assert!(!ok && err.contains("bob may not exec Workload"), "{args:?}: {ok} {err}");
    }
    assert!(!cluster.dir.join("down.txt").exists());
    let audit = cluster.kith(&["audit"]);
    let refused = audit
        .lines()
        .filter(|line| line.contains("pod default/web-0") && line.split_whitespace().nth(1) == Some("bob"))
        .filter(|line| !line.ends_with(" ok"))
        .count();
    assert!(refused >= 1, "bob's refusals are in the audit log: {audit}");
}

/// A cluster with a NodeWorkload `agent` in `default`: dan may exec any pod of `default`, and
/// erin may exec the NodeWorkload's pods and also `Node`, which the host's run takes cluster-wide.
fn with_node_agent(test: &str) -> Cluster {
    let cluster = Cluster::boot(test);
    cluster.kith(&["identity", "cert", "dan", "--out", "."]);
    cluster.kith(&["identity", "cert", "erin", "--out", "."]);
    let roles = "apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: anything-here }\nspec:\n  rules:\n    - kinds: [\"*\"]\n      verbs: [get, list, exec]\n      namespaces: [default]\n---\napiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: agent-runner }\nspec:\n  rules:\n    - kinds: [NodeWorkload]\n      verbs: [get, list, exec]\n      namespaces: [default]\n    - kinds: [Node]\n      verbs: [exec]\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: dan-anything }\nspec:\n  role: anything-here\n  subjects: [dan]\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: erin-agent }\nspec:\n  role: agent-runner\n  subjects: [erin]\n";
    cluster.write("roles.yaml", roles);
    cluster.kith(&["apply", "-f", "roles.yaml"]);
    // A DaemonSet is a NodeWorkload in kithd's store: its pods are `agent-nN`, in `default`.
    let agent = r#"{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"agent"},"spec":{"selector":{"matchLabels":{"app":"agent"}},"template":{"metadata":{"labels":{"app":"agent"}},"spec":{"containers":[{"name":"agent","image":"mirror.gcr.io/library/busybox:1.36","command":["sleep","3600"]}]}}}}"#;
    cluster.write("agent.json", agent);
    let json = ["Content-Type: application/json"];
    let made = cluster.reply(
        "alice",
        "POST",
        "/apis/apps/v1/namespaces/default/daemonsets",
        &json,
        Some("agent.json"),
    );
    assert_eq!(made, "201");
    cluster
}

/// A NodeWorkload's pod runs on the host, so exec into it also needs the Exec right on `Node`:
/// dan is refused for it though he may exec `default`'s pods, and erin is upgraded. Each attempt
/// is in the audit log, refused or ok.
#[test]
fn access_a_node_workload_pod_also_needs_exec_on_the_node() {
    let cluster = with_node_agent("kube-exec-node");
    let pod = "/api/v1/namespaces/default/pods/agent-n0/exec?command=true&stdout=true&stderr=true";
    let upgrade = [
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Protocol: v4.channel.k8s.io",
    ];
    assert_eq!(cluster.reply("dan", "GET", pod, &upgrade, None), "403");
    assert_eq!(cluster.reply("erin", "GET", pod, &upgrade, None), "101");

    let audit = cluster.kith(&["audit"]);
    let entries: Vec<&str> = audit
        .lines()
        .filter(|line| line.contains("pod default/agent-n0"))
        .collect();
    let of = |who: &str| {
        let found: Vec<&&str> = entries
            .iter()
            .filter(|line| line.split_whitespace().nth(1) == Some(who))
            .collect();
        assert_eq!(found.len(), 1, "one entry for {who} in:\n{audit}");
        *found[0]
    };
    assert_eq!(of("dan").split_whitespace().nth(2), Some("exec"), "{audit}");
    assert!(
        !of("dan").ends_with(" ok"),
        "dan's refusal is written down as one: {audit}"
    );
    assert!(
        of("erin").ends_with(" ok"),
        "erin's upgrade is written down as ok: {audit}"
    );
}

/// A browser's upgrade carries an Origin, which kubectl never sends: it is refused with 403
/// before the upgrade is answered, and written down as refused. Without it the same upgrade is 101.
#[test]
fn access_an_upgrade_that_carries_an_origin_is_refused() {
    let cluster = with_node_agent("kube-exec-origin");
    let pod = "/api/v1/namespaces/default/pods/agent-n0/exec?command=true&stdout=true&stderr=true";
    let upgrade = [
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Protocol: v4.channel.k8s.io",
    ];
    let browser = [&upgrade[..], &["Origin: https://example.org"][..]].concat();
    assert_eq!(cluster.reply("erin", "GET", pod, &browser, None), "403");
    assert_eq!(cluster.reply("erin", "GET", pod, &upgrade, None), "101");

    let audit = cluster.kith(&["audit"]);
    let refused = audit
        .lines()
        .any(|line| line.split_whitespace().nth(1) == Some("erin") && !line.ends_with(" ok"));
    assert!(refused, "the refused upgrade is in the audit log: {audit}");
}

/// The one route between nodes for a pod is `/v1/pod-hop`: the exec route that was there before is no route (404) to a
/// node (here this node's own certificate), and an Identity is refused (403) at both, for the hop is the cluster's nodes'.
#[test]
fn access_one_hop_route_for_a_pod_and_no_identity_uses_it() {
    let cluster = with_team("kube-one-hop");
    for who in ["bob", "carol"] {
        for path in ["/v1/exec-hop", "/v1/pod-hop"] {
            assert_eq!(cluster.reply(who, "POST", path, &[], None), "403", "{who} {path}");
        }
    }
    let node = "state/pki/node";
    assert_eq!(
        cluster.reply(node, "POST", "/v1/exec-hop", &[], None),
        "404",
        "the deleted route"
    );
    // (Found, and asked for what it needs: the upgrade it names.)
    assert_eq!(
        cluster.reply(node, "POST", "/v1/pod-hop", &[], None),
        "400",
        "the one route"
    );
}

/// What kubectl port-forward asks for: a WebSocket that speaks SPDY/3.1 (the plain upgrade it falls back to is a POST).
const FORWARD: [&str; 5] = [
    "Connection: Upgrade",
    "Upgrade: websocket",
    "Sec-WebSocket-Version: 13",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
    "Sec-WebSocket-Protocol: SPDY/3.1+portforward.k8s.io",
];

/// A cluster with a Deployment `web` in `team`, and bob who may get it and carol who may also run in it.
fn with_team(test: &str) -> Cluster {
    with_team_as(test, false)
}

fn with_team_as(test: &str, host: bool) -> Cluster {
    let cluster = Cluster::boot_with(test, host);
    cluster.kith(&["identity", "cert", "bob", "--out", "."]);
    cluster.kith(&["identity", "cert", "carol", "--out", "."]);
    let roles = "apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: reader }\nspec:\n  rules:\n    - kinds: [Workload, Job]\n      verbs: [get, list, watch]\n      namespaces: [team]\n---\napiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: runner }\nspec:\n  rules:\n    - kinds: [Workload, Job]\n      verbs: [get, list, exec]\n      namespaces: [team]\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: bob-reader }\nspec:\n  role: reader\n  subjects: [bob]\n---\napiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: carol-runner }\nspec:\n  role: runner\n  subjects: [carol]\n";
    cluster.write("roles.yaml", roles);
    cluster.kith(&["apply", "-f", "roles.yaml"]);
    cluster.write("web.json", r#"{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"web"},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"web"}},"template":{"metadata":{"labels":{"app":"web"}},"spec":{"containers":[{"name":"web","image":"mirror.gcr.io/library/busybox:1.36","command":["sleep","3600"]}]}}}}"#);
    let json = ["Content-Type: application/json"];
    let made = cluster.reply(
        "alice",
        "POST",
        "/apis/apps/v1/namespaces/team/deployments",
        &json,
        Some("web.json"),
    );
    assert_eq!(made, "201");
    eventually("the pods of web", 30, || {
        cluster.reply("alice", "GET", "/api/v1/namespaces/team/pods/web-1", &[], None) == "200"
    });
    cluster
}

/// kubectl port-forward needs the Exec right on the Workload or Job that owns the pod (get alone reads it and
/// forwards nothing), checked before any upgrade; a pod that is not there, a NodeWorkload's (its host unit) and a
/// browser's upgrade are refused. Each decision is in the audit log.
#[test]
fn access_port_forward_needs_the_run_right_on_the_owning_workload() {
    let cluster = with_team("kube-forward-access");
    let pod = |name: &str| format!("/api/v1/namespaces/team/pods/{name}/portforward");
    // (curl is let wait 2 s: a session that is upgraded stays until its client or its idle time ends it.)
    let ask = |who: &str, method: &str, name: &str, headers: &[&str]| {
        cluster.reply_in(2, who, method, &pod(name), headers, None)
    };
    // bob may get the pod and forwards nothing: refused before the upgrade is looked at, either way kubectl asks.
    assert_eq!(
        cluster.reply("bob", "GET", "/api/v1/namespaces/team/pods/web-0", &[], None),
        "200"
    );
    assert_eq!(ask("bob", "GET", "web-0", &FORWARD), "403");
    assert_eq!(
        ask("bob", "POST", "web-0", &["Connection: Upgrade", "Upgrade: SPDY/3.1"]),
        "403"
    );
    // carol may run in `team`: the WebSocket is upgraded, and without one it is a 400.
    assert_eq!(ask("carol", "GET", "web-0", &FORWARD), "101");
    assert_eq!(ask("carol", "GET", "web-1", &FORWARD), "101");
    assert_eq!(ask("carol", "GET", "web-0", &[]), "400");
    let plain = ["Connection: Upgrade", "Upgrade: websocket", "Sec-WebSocket-Version: 13"];
    assert_eq!(ask("carol", "GET", "web-0", &plain), "400", "no SPDY protocol named");
    // A pod that is not there (a replica past the Deployment's two, an owner it has not, a name no pod has) is a 404.
    for name in ["web-7", "nosuch-0", "web", "web-j0"] {
        assert_eq!(ask("carol", "GET", name, &FORWARD), "404", "{name}");
    }
    // A browser's upgrade carries an Origin, which kubectl never sends.
    let browser = [&FORWARD[..], &["Origin: https://example.org"][..]].concat();
    assert_eq!(ask("carol", "GET", "web-0", &browser), "403");

    let audit = cluster.kith(&["audit"]);
    let of = |who: &str| -> Vec<&str> {
        let ours = |line: &&str| line.contains("pod team/web-0") && line.split_whitespace().nth(1) == Some(who);
        audit.lines().filter(ours).collect()
    };
    let (bob, carol) = (of("bob"), of("carol"));
    assert!(
        bob.len() == 2 && bob.iter().all(|line| !line.ends_with(" ok")),
        "bob is refused twice: {audit}"
    );
    assert!(
        carol.iter().any(|line| line.ends_with(" ok")),
        "carol's upgrade is ok: {audit}"
    );
    assert!(
        bob.iter()
            .chain(&carol)
            .all(|line| line.split_whitespace().nth(2) == Some("portforward")),
        "written down as portforward: {audit}"
    );
}

/// A NodeWorkload's pod is the host's unit, which port-forward does not reach: dan, who has no Exec on `Node`, is
/// refused (403) as exec is, and erin, who has, is told it is not carried (501), not upgraded.
#[test]
fn access_port_forward_does_not_reach_a_node_workloads_host_unit() {
    let cluster = with_node_agent("kube-forward-node");
    let pod = "/api/v1/namespaces/default/pods/agent-n0/portforward";
    assert_eq!(cluster.reply_in(2, "dan", "GET", pod, &FORWARD, None), "403");
    assert_eq!(cluster.reply_in(2, "erin", "GET", pod, &FORWARD, None), "501");
}

/// Sessions are bounded per caller, not streams: carol's sessions over the bound are refused with a 429, another
/// caller is not counted against her, and a session that ends frees its place.
#[test]
fn access_port_forward_sessions_are_bounded_per_caller() {
    let cluster = with_team("kube-forward-bound");
    let pod = "/api/v1/namespaces/team/pods/web-0/portforward";
    // (As many as kithd allows a caller, held open: curl lets go of a 101, openssl keeps the connection while its stdin is.)
    let mut asked = format!("GET {pod} HTTP/1.1\r\nHost: kith\r\n");
    asked.extend(FORWARD.iter().map(|header| format!("{header}\r\n")));
    asked.push_str("\r\n");
    let mut held: Vec<_> = (0..8)
        .map(|_| {
            // (stdbuf: openssl writes to a pipe in blocks, which keeps the 101 from being read.)
            let mut client = Command::new("stdbuf");
            client
                .args([
                    "-o0",
                    "openssl",
                    "s_client",
                    "-quiet",
                    "-CAfile",
                    "ca.crt",
                    "-cert",
                    "carol.crt",
                    "-key",
                    "carol.key",
                ])
                .args([
                    "-servername",
                    "kith",
                    "-connect",
                    &format!("127.0.0.1:{}", cluster.port),
                ])
                .current_dir(&cluster.dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            let mut client = client.spawn().expect("openssl runs");
            client.stdin.as_mut().unwrap().write_all(asked.as_bytes()).unwrap();
            // (Each one is upgraded before the next is asked.)
            let mut line = String::new();
            BufRead::read_line(&mut BufReader::new(client.stdout.as_mut().unwrap()), &mut line).unwrap();
            assert!(line.contains("101"), "{line}");
            client
        })
        .collect();
    eventually("a ninth session of carol's is refused", 10, || {
        cluster.reply_in(2, "carol", "GET", pod, &FORWARD, None) == "429"
    });
    // Another caller's own: bob, who may not forward, is still refused for that and not for her sessions.
    assert_eq!(cluster.reply_in(2, "bob", "GET", pod, &FORWARD, None), "403");
    for session in &mut held {
        session.kill().unwrap();
        session.wait().unwrap();
    }
    eventually("carol's places are free again", 10, || {
        cluster.reply_in(2, "carol", "GET", pod, &FORWARD, None) == "101"
    });
}

/// A Workload name no other test or run shares: a unit's systemd name (`w_team_NAME_0_main`) and container id are made
/// from it, and a kithd that sets up a name another kithd runs kills that one's unit (exit 137, restarts, a pod that is
/// Pending). The process id tells runs (lanes) apart, the counter tests of one run; short, for the 52-character limit.
fn unique(base: &str) -> String {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    format!(
        "{base}{:x}x{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

/// `with_team`, and a Workload of one exec unit that runs on this host (its unique name returned), shown to kubectl
/// as a Deployment (the images of the others are empty, so their pods are never Running, and kubectl asks no port of a
/// pod that is not); None where this host's cgroup takes no container.
fn with_running(test: &str, host: bool) -> Option<(Cluster, String)> {
    let cluster = with_team_as(test, host);
    let name = unique("tool");
    let sent = format!(
        r#"{{"apiVersion":"apps/v1","kind":"Deployment","metadata":{{"name":"{name}","namespace":"team"}},"spec":{{"replicas":1,"selector":{{"matchLabels":{{"app":"{name}"}}}},"template":{{"metadata":{{"labels":{{"app":"{name}"}}}},"spec":{{"containers":[{{"name":"main","image":"busybox:1.36"}}]}}}}}}}}"#
    );
    let tool = format!(
        "apiVersion: kith.dev/v1\nkind: Workload\nmetadata:\n  name: {name}\n  namespace: team\n  annotations:\n    {}: '{sent}'\nspec:\n  replicas: 1\n  template:\n    exec:\n      - name: main\n        command: [sleep, '3600']\n",
        "kube.kith.dev/sent"
    );
    cluster.write("tool.yaml", &tool);
    cluster.kith(&["apply", "-f", "tool.yaml"]);
    // A host whose cgroup takes no container (CI's runner, delegated or not) never runs the tool: skip, as exec does.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let held = cluster.held(&format!("workload/team/{name}"));
        if held["status"]["containers"][0]["state"] == "running" {
            break;
        }
        let status = held.to_string();
        // A container's create says "cgroup error"; an exec unit's says it could not make its dir under /sys/fs/cgroup
        // (CI: "failed to create dir /sys/fs/cgroup/system.slice/kith-w_team_tool_0_main: Permission denied").
        if status.contains("cgroup error") || status.contains("failed to create dir /sys/fs/cgroup") {
            // Straight to stderr: the harness captures eprintln! and drops a passing test's output.
            let _ = writeln!(
                std::io::stderr(),
                "::warning title=SKIP::SKIP (not a pass): this host's cgroup takes no unit"
            );
            return None;
        }
        assert!(Instant::now() < deadline, "{name}-0 to run: not within 60 s\n{status}");
        std::thread::sleep(Duration::from_millis(250));
    }
    Some((cluster, name))
}

/// A `kubectl port-forward` of `team`'s NAME-0, as carol; it ends with this.
struct Forward(Child);

impl Drop for Forward {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// kubectl forwards a port of this host (with `host`, a pod that is not made reaches the host's loopback) as carol, who
/// may run in `team`: the local port, once kubectl says it listens.
fn forward(cluster: &Cluster, tool: &str, remote: u16) -> (Forward, u16) {
    let local = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let carol = cluster.as_("carol");
    let ports = format!("{local}:{remote}");
    let child = Command::new(&carol.kubectl)
        .args([
            "port-forward",
            "--address",
            "127.0.0.1",
            "-n",
            "team",
            &format!("pod/{tool}-0"),
            &ports,
        ])
        .current_dir(&cluster.dir)
        .env("KUBECONFIG", &carol.config)
        .env("HOME", &cluster.dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut forward = Forward(child);
    let mut line = String::new();
    BufRead::read_line(&mut BufReader::new(forward.0.stdout.as_mut().unwrap()), &mut line).unwrap();
    assert!(
        line.starts_with("Forwarding from 127.0.0.1"),
        "kubectl port-forward said: {line:?}"
    );
    (forward, local)
}

/// A server on this host that sends back what it is sent: its port.
fn echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut back = stream.try_clone().unwrap();
                let _ = std::io::copy(&mut &stream, &mut back);
            });
        }
    });
    port
}

fn near(local: u16) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", local)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    stream
}

/// kubectl port-forward carries bytes to a port of the pod and back, a megabyte one way and the other included.
#[test]
fn workflows_kubectl_port_forward_carries_bytes_both_ways() {
    if !has_kubectl() {
        return;
    }
    // Without a delegated cgroup kithd runs no workloads, so tool-0 never runs (CI's runner).
    if !kith_runtime::has_delegated_cgroup() {
        eprintln!("skipped: no delegated cgroup here");
        return;
    }
    let Some((cluster, tool)) = with_running("kube-forward-bytes", true) else {
        return;
    };
    let (_forward, local) = forward(&cluster, &tool, echo());
    let mut stream = near(local);
    stream.write_all(b"hello").unwrap();
    let mut hello = [0u8; 5];
    stream.read_exact(&mut hello).unwrap();
    assert_eq!(&hello, b"hello");
    let payload: Vec<u8> = (0..1u32 << 20).map(|n| (n % 251) as u8).collect();
    let mut sender = stream.try_clone().unwrap();
    let sent = payload.clone();
    let sending = std::thread::spawn(move || sender.write_all(&sent).unwrap());
    let mut back = vec![0u8; payload.len()];
    stream.read_exact(&mut back).unwrap();
    sending.join().unwrap();
    assert!(back == payload, "a megabyte comes back as it went");
}

/// A connection that moves no byte ends after the idle time (10 s here), and a session carries 16 connections: the
/// 17th is refused at once, not left to idle out.
#[test]
fn workflows_kubectl_port_forward_ends_a_silent_stream_and_bounds_its_streams() {
    if !has_kubectl() {
        return;
    }
    // Without a delegated cgroup kithd runs no workloads, so tool-0 never runs (CI's runner).
    if !kith_runtime::has_delegated_cgroup() {
        eprintln!("skipped: no delegated cgroup here");
        return;
    }
    let Some((cluster, tool)) = with_running("kube-forward-bound-streams", true) else {
        return;
    };
    let (_forward, local) = forward(&cluster, &tool, echo());
    let mut silent = near(local);
    let began = Instant::now();
    let mut one = [0u8; 1];
    assert_eq!(silent.read(&mut one).unwrap_or(0), 0, "ended, not answered");
    let took = began.elapsed();
    assert!(
        took >= Duration::from_secs(8) && took < Duration::from_secs(40),
        "a silent stream ended after {took:?}"
    );

    let mut held: Vec<TcpStream> = (0..16).map(|_| near(local)).collect();
    for stream in &mut held {
        stream.write_all(b"x").unwrap();
        stream.read_exact(&mut one).unwrap();
    }
    let mut over = near(local);
    let _ = over.write_all(b"y");
    assert_eq!(
        over.read(&mut one).unwrap_or(0),
        0,
        "the 17th connection is refused, not echoed"
    );
}

/// A pod this node has not made (here, one that runs on the host) has no network to reach: the connection is refused and
/// what listens on the host's loopback is not reached, as it is where `KITHD_PORTFORWARD_HOST` is set.
#[test]
fn workflows_kubectl_port_forward_does_not_reach_the_host_through_a_pod_that_is_not_made() {
    if !has_kubectl() {
        return;
    }
    // Without a delegated cgroup kithd runs no workloads, so tool-0 never runs (CI's runner).
    if !kith_runtime::has_delegated_cgroup() {
        eprintln!("skipped: no delegated cgroup here");
        return;
    }
    let Some((cluster, tool)) = with_running("kube-forward-not-made", false) else {
        return;
    };
    let (_forward, local) = forward(&cluster, &tool, echo());
    let mut stream = near(local);
    let _ = stream.write_all(b"hello");
    let mut back = [0u8; 5];
    assert_eq!(
        stream.read(&mut back).unwrap_or(0),
        0,
        "nothing is echoed: the host's loopback is not reached"
    );
}

/// A session that takes no connection and hears nothing ends after the idle time (10 s here). (Not kubectl's: it pings
/// every 10 s, and a ping is a frame heard.)
#[test]
fn access_port_forward_ends_a_session_that_hears_nothing() {
    let cluster = with_team("kube-forward-idle-session");
    let pod = "/api/v1/namespaces/team/pods/web-0/portforward";
    let mut asked = format!("GET {pod} HTTP/1.1\r\nHost: kith\r\n");
    asked.extend(FORWARD.iter().map(|header| format!("{header}\r\n")));
    asked.push_str("\r\n");
    let mut client = Command::new("stdbuf");
    client
        .args([
            "-o0",
            "openssl",
            "s_client",
            "-quiet",
            "-CAfile",
            "ca.crt",
            "-cert",
            "carol.crt",
            "-key",
            "carol.key",
        ])
        .args([
            "-servername",
            "kith",
            "-connect",
            &format!("127.0.0.1:{}", cluster.port),
        ])
        .current_dir(&cluster.dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut client = client.spawn().expect("openssl runs");
    client.stdin.as_mut().unwrap().write_all(asked.as_bytes()).unwrap();
    let mut line = String::new();
    BufRead::read_line(&mut BufReader::new(client.stdout.as_mut().unwrap()), &mut line).unwrap();
    assert!(line.contains("101"), "{line}");
    // (Its stdin stays open: the connection ends from kithd's side or not at all.)
    let began = Instant::now();
    while client.try_wait().unwrap().is_none() {
        if began.elapsed() > Duration::from_secs(60) {
            client.kill().unwrap();
            panic!("an idle session did not end");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        began.elapsed() >= Duration::from_secs(5),
        "ended after {:?}, before the idle time",
        began.elapsed()
    );
}

/// The Exec right is asked again for each connection: a session whose caller lost it is upgraded still, and the
/// connection it takes next is refused.
#[test]
fn workflows_kubectl_port_forward_asks_the_right_again_for_each_connection() {
    if !has_kubectl() {
        return;
    }
    // Without a delegated cgroup kithd runs no workloads, so tool-0 never runs (CI's runner).
    if !kith_runtime::has_delegated_cgroup() {
        eprintln!("skipped: no delegated cgroup here");
        return;
    }
    let Some((cluster, tool)) = with_running("kube-forward-recheck", true) else {
        return;
    };
    let (_forward, local) = forward(&cluster, &tool, echo());
    let mut first = near(local);
    first.write_all(b"hello").unwrap();
    let mut back = [0u8; 5];
    first.read_exact(&mut back).unwrap();
    assert_eq!(&back, b"hello");
    // carol's binding now names bob: her session is upgraded still, and a connection it takes next is refused.
    cluster.write("revoked.yaml", "apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: carol-runner }\nspec:\n  role: runner\n  subjects: [bob]\n");
    cluster.kith(&["apply", "-f", "revoked.yaml"]);
    let mut second = near(local);
    let _ = second.write_all(b"hello");
    assert_eq!(
        second.read(&mut back).unwrap_or(0),
        0,
        "a connection of a session whose right is gone is refused"
    );
}

/// A StatefulSet of several replicas has a claim and a Volume of each replica's own, named
/// TEMPLATE-NAME-ORDINAL, as Kubernetes names them; scaling down keeps them.
#[test]
fn statefulset_of_three_has_a_claim_and_a_volume_for_each_replica() {
    let Some(cluster) = Cluster::start("kube-statefulset") else {
        return;
    };
    let set = REST
        .split("\n---\n")
        .next()
        .unwrap()
        .replace("replicas: 1", "replicas: 3");
    cluster.write("db.yaml", &set);
    cluster.ok(&["apply", "-f", "db.yaml"]);
    let db = cluster.held("workload/db");
    assert_eq!(db["spec"]["replicas"], 3, "{db}");
    for ordinal in 0..3 {
        let claim = format!("data-db-{ordinal}");
        eventually("a claim bound to the Volume made for it", 30, || {
            cluster.got(&["pvc", &claim])["status"]["phase"] == "Bound"
        });
        let volume = cluster.held(&format!("volume/{claim}"));
        assert_eq!(volume["spec"]["node"], "alpha", "{volume}");
    }
    // Scaled down, the claims (and what they hold) stay, as Kubernetes keeps them.
    cluster.ok(&["scale", "statefulset/db", "--replicas=1"]);
    assert_eq!(cluster.held("workload/db")["spec"]["replicas"], 1);
    let claims = cluster.ok(&["get", "pvc", "-o", "name"]);
    says(&claims, &["data-db-0", "data-db-1", "data-db-2"]);
    // Scaled up again, they are the replicas' again (and nothing new is made for them).
    cluster.ok(&["scale", "statefulset/db", "--replicas=3"]);
    let after = cluster.ok(&["get", "pvc", "-o", "name"]);
    assert_eq!(after.lines().count(), 3, "{after}");
}

/// Server-side apply by two managers: each keeps its own fields, a field one has is not
/// taken by the other without `--force-conflicts`, and what a manager leaves out of its
/// next apply is taken out when no other manager has it.
#[test]
fn two_field_managers_keep_their_own_fields_and_conflict_on_each_others() {
    let Some(cluster) = Cluster::start("kube-managers") else {
        return;
    };
    let apply = |manager: &str, file: &str, force: bool| {
        let mut args = vec!["apply", "--server-side", "--field-manager", manager, "-f", file];
        args.extend(force.then_some("--force-conflicts"));
        cluster.kubectl(&args)
    };
    let map =
        |data: &str| format!("apiVersion: v1\nkind: ConfigMap\nmetadata: {{ name: shared }}\ndata: {{ {data} }}\n");
    let data = || cluster.got(&["configmap", "shared"])["data"].clone();
    cluster.write("a.yaml", &map("x: '1', gone: g"));
    cluster.write("b.yaml", &map("w: '2'"));
    assert!(apply("a", "a.yaml", false).0);
    // b's apply does not name a's fields, so they stay, and are a's.
    assert!(apply("b", "b.yaml", false).0);
    assert_eq!(data(), serde_json::json!({ "x": "1", "gone": "g", "w": "2" }));
    // b wants what a has, differently: Kubernetes's words, and nothing is changed.
    cluster.write("b9.yaml", &map("x: '9', w: '2'"));
    let (ok, _, err) = apply("b", "b9.yaml", false);
    assert!(!ok);
    says(
        &err,
        &["Apply failed with 1 conflict: conflict with \"a\" using v1: .data.x"],
    );
    assert_eq!(data()["x"], "1");
    // The same value is not a conflict: both manage it then.
    cluster.write("b1.yaml", &map("x: '1', w: '2'"));
    assert!(apply("b", "b1.yaml", false).0);
    // With force the field is b's; a, applying its own, is the one in conflict now.
    assert!(apply("b", "b9.yaml", true).0);
    assert_eq!(data()["x"], "9");
    let (ok, _, err) = apply("a", "a.yaml", false);
    assert!(!ok);
    says(&err, &["conflict with \"b\" using v1: .data.x"]);
    // a leaves out what it set, and no one else has: it is taken out. What b has stays.
    cluster.write("a2.yaml", &map("keep: k"));
    assert!(apply("a", "a2.yaml", false).0);
    assert_eq!(data(), serde_json::json!({ "x": "9", "w": "2", "keep": "k" }));
    // Who has what is said as Kubernetes says it, and is not something a client may send.
    let shown = cluster.ok(&["get", "configmap", "shared", "-o", "json", "--show-managed-fields"]);
    let shown: serde_json::Value = serde_json::from_str(&shown).unwrap();
    let entries = shown["metadata"]["managedFields"].as_array().unwrap();
    let managers: Vec<&str> = entries.iter().map(|m| m["manager"].as_str().unwrap()).collect();
    assert_eq!(managers, ["a", "b"]);
    assert_eq!(entries[0]["fieldsV1"]["f:data"]["f:keep"], serde_json::json!({}));
}
