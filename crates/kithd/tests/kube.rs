//! The real `kubectl` against one kithd on 127.0.0.1: nothing of Kubernetes is started.
//! Skips where there is no kubectl (`KITH_KUBECTL` names one, or the one on `PATH`):
//!
//! ```sh
//! KITH_KUBECTL=/path/to/kubectl cargo test -p kithd --test kube
//! ```

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// One kithd, an Identity that may do everything, and a kubeconfig that is that Identity.
struct Cluster {
    child: Child,
    dir: PathBuf,
    kubectl: String,
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
        let cluster = Cluster { child, dir, kubectl };
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
        let config = format!(
            "apiVersion: v1\nkind: Config\ncurrent-context: kith\nclusters:\n- name: kith\n  cluster:\n    server: https://127.0.0.1:{port}\n    certificate-authority: ca.crt\n    tls-server-name: kith\nusers:\n- name: alice\n  user:\n    client-certificate: alice.crt\n    client-key: alice.key\ncontexts:\n- name: kith\n  context: {{ cluster: kith, user: alice }}\n"
        );
        cluster.write("kubeconfig", &config);
        Some(cluster)
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
        let out = Command::new(&self.kubectl)
            .args(args)
            .current_dir(&self.dir)
            .env("KUBECONFIG", self.dir.join("kubeconfig"))
            .env("HOME", &self.dir)
            .output()
            .unwrap();
        let text = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned();
        (out.status.success(), text(out.stdout), text(out.stderr))
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
        let _ = Command::new("kill").arg(self.child.id().to_string()).status();
        let _ = self.child.wait();
    }
}

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
