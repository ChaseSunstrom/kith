//! Two kithd in two network namespaces with a wire between them, meshed, and a Service
//! in front of a Workload with a replica on each. Opt-in (`KITH_E2E=1`), and it needs
//! unprivileged user namespaces and `unshare`, `nsenter`, `ip`, `curl` and `python3`: the test runs
//! itself again inside a namespace where it may make interfaces.
//
// ponytail: its own few lines of harness rather than tests/cluster.rs's, which starts
// every node on 127.0.0.1; one harness when a third test needs namespaces.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(40);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A kithd in the network namespace `name`, which is also the node's name.
struct Node {
    child: Child,
    dir: PathBuf,
}

impl Node {
    fn start(name: &str, address: &str, args: &[&str]) -> Node {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("services").join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // (Not `ip netns exec`: that hides the cgroups kithd puts its units in.)
        let child = Command::new("nsenter")
            .args([&format!("--net=/run/netns/{name}"), env!("CARGO_BIN_EXE_kithd")])
            .current_dir(&dir)
            .args(["--state", "state", "--socket", "kithd.sock", "--name", name])
            .args(["--listen", &format!("{address}:7443"), "--mesh"])
            .args(args)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let node = Node { child, dir };
        wait_for("kithd to serve", || node.dir.join("kithd.sock").exists());
        node
    }

    fn kith(&self, args: &[&str]) -> (bool, String) {
        let kith = Path::new(env!("CARGO_BIN_EXE_kithd")).with_file_name("kith");
        let out = Command::new(kith)
            .args(args)
            .current_dir(&self.dir)
            .env("KITH_SOCKET", self.dir.join("kithd.sock"))
            .env_remove("KITH_STORE")
            .output()
            .unwrap();
        (out.status.success(), String::from_utf8(out.stdout).unwrap())
    }

    fn ok(&self, args: &[&str]) -> String {
        let (ok, out) = self.kith(args);
        assert!(ok, "kith {args:?}");
        out
    }

    fn status(&self, what: &str) -> serde_json::Value {
        let (_, out) = self.kith(&["get", what, "-o", "json"]);
        let got: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
        got["status"].clone()
    }
}

/// A helper process, killed when the test is over.
struct Stop(std::process::Child);

impl Drop for Stop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = Command::new("kill").arg(self.child.id().to_string()).status();
        let _ = self.child.wait();
    }
}

/// Answers every request with the names of this namespace's interfaces (so: which node
/// it is on), and listens on 127.0.0.1 only.
const SERVER: &str = "import http.server, socket\n\
class H(http.server.BaseHTTPRequestHandler):\n\
\x20   def do_GET(self):\n\
\x20       self.send_response(200); self.end_headers()\n\
\x20       self.wfile.write(' '.join(sorted(name for _, name in socket.if_nameindex())).encode())\n\
\x20   def log_message(self, *a): pass\n\
http.server.HTTPServer(('127.0.0.1', 8080), H).serve_forever()\n";

/// The namespaces a and b, a wire between them, then this test again.
const SETUP: &str = "set -e; mount -t tmpfs none /run; \
    ip netns add a; ip netns add b; ip -n a link set lo up; ip -n b link set lo up; \
    ip link add tob netns a type veth peer name toa netns b; \
    ip -n a addr add 10.1.0.1/24 dev tob; ip -n a link set tob up; \
    ip -n b addr add 10.1.0.2/24 dev toa; ip -n b link set toa up; \
    KITH_IN_NAMESPACE=1 exec \"$0\" --exact a_service_spreads_connections --nocapture";

#[test]
fn a_service_spreads_connections() {
    if std::env::var_os("KITH_E2E").is_none() {
        return eprintln!("skipped: set KITH_E2E=1");
    }
    if std::env::var_os("KITH_IN_NAMESPACE").is_none() {
        // (As the user it is, not as root: kithd puts units where a user's cgroups are.)
        let flags = ["-Unm", "--map-current-user", "--keep-caps"];
        let unshare = |args: &[&str]| Command::new("unshare").args(flags).args(args).status();
        if !unshare(&["true"]).is_ok_and(|status| status.success()) {
            return eprintln!(
                "skipped: no unprivileged user namespaces here (unshare -Unm --map-current-user --keep-caps)"
            );
        }
        let built = Command::new(env!("CARGO"))
            .args(["build", "--quiet", "-p", "kith-cli"])
            .status();
        assert!(built.unwrap().success());
        let me = std::env::current_exe().unwrap();
        let status = unshare(&["sh", "-c", SETUP, me.to_str().unwrap()]).unwrap();
        assert!(status.success(), "the test failed inside its namespaces");
        return;
    }
    // A certificate authority of our own, where node a is told to ask (never a real one).
    let authority = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("services")
        .join("authority");
    let _ = std::fs::remove_dir_all(&authority);
    std::fs::create_dir_all(&authority).unwrap();
    std::fs::write(authority.join("fake_acme.py"), include_str!("fake_acme.py")).unwrap();
    let fake = Command::new("nsenter")
        .args([
            "--net=/run/netns/a",
            "python3",
            "fake_acme.py",
            "10.1.0.1",
            "14000",
            ".",
        ])
        .current_dir(&authority)
        .spawn()
        .unwrap();
    let _fake = Stop(fake);
    wait_for("the authority to listen", || authority.join("ca.pem").exists());
    let a = Node::start(
        "a",
        "10.1.0.1",
        &["--ingress", "--acme", "http://10.1.0.1:14000/directory"],
    );
    wait_for("a to lead", || a.kith(&["get", "node"]).0);
    let token = a.ok(&["node", "token"]);
    let b = Node::start("b", "10.1.0.2", &["--join", "10.1.0.1:7443", "--token", token.trim()]);
    wait_for("two ready nodes on the mesh", || {
        let both = a.kith(&["get", "node"]).1.matches("ready at").count() == 2;
        both && b.ok(&["node", "status"]).contains(", handshake ")
    });

    std::fs::write(a.dir.join("server.py"), SERVER).unwrap();
    let server = a.dir.join("server.py");
    let web = format!(
        "apiVersion: kith.dev/v1\nkind: Workload\nmetadata: {{ name: web, labels: {{ app: web }} }}\nspec:\n  \
         replicas: 2\n  template:\n    exec: [{{ name: run, command: [python3, {}] }}]\n---\n\
         apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: web }}\nspec:\n  selector: {{ app: web }}\n  \
         ports: [{{ port: 80, targetPort: 8080 }}]\n  expose: {{ host: web.example.test, via: edge }}\n",
        server.display()
    );
    std::fs::write(a.dir.join("web.yaml"), web).unwrap();
    a.ok(&["apply", "-f", "web.yaml"]);
    wait_for("a replica on each node, both behind the Service", || {
        a.status("workload/web")["ready"] == 2 && a.status("service/web")["backends"] == 2
    });
    let nodes = a.status("workload/web")["nodes"].clone();
    assert_ne!(nodes["0"], nodes["1"], "{nodes}");

    // From either node, the Service's address answers, now from one replica, now from
    // the other: the one on the same machine and the one across the mesh.
    let address = a.status("service/web")["address"].as_str().unwrap().to_string();
    let ask = |from: &str| {
        let url = format!("http://[{address}]:80/");
        let curl = [
            &format!("--net=/run/netns/{from}"),
            "curl",
            "-s",
            "--max-time",
            "5",
            &url,
        ];
        String::from_utf8(Command::new("nsenter").args(curl).output().unwrap().stdout).unwrap()
    };
    wait_for("the Service to answer", || !ask("a").is_empty());
    for from in ["a", "b"] {
        let mut answers: Vec<String> = (0..6).map(|_| ask(from)).collect();
        answers.sort();
        answers.dedup();
        assert_eq!(answers, ["kith0 lo toa", "kith0 lo tob"], "asked from {from}");
    }

    // From outside (b's plain address will do): HTTPS for the Service's host on node a,
    // with a certificate a got from the authority; and port 80 points there.
    wait_for("a certificate", || a.status("service/web")["tls"]["state"] == "ready");
    let outside = |args: &[&str]| {
        let curl = Command::new("nsenter")
            .args(["--net=/run/netns/b", "curl", "-s", "--max-time", "5"])
            .args([
                "--resolve",
                "web.example.test:443:10.1.0.1",
                "--resolve",
                "web.example.test:80:10.1.0.1",
            ])
            .args(args)
            .output();
        String::from_utf8(curl.unwrap().stdout).unwrap()
    };
    let ca = authority.join("ca.pem");
    let https = || outside(&["--cacert", ca.to_str().unwrap(), "https://web.example.test/"]);
    wait_for("HTTPS to answer", || !https().is_empty());
    let mut answers: Vec<String> = (0..6).map(|_| https()).collect();
    answers.sort();
    answers.dedup();
    assert_eq!(answers, ["kith0 lo toa", "kith0 lo tob"]);
    let moved = outside(&[
        "-o",
        "/dev/null",
        "-w",
        "%{http_code} %{redirect_url}",
        "http://web.example.test/x?y=1",
    ]);
    assert_eq!(moved, "308 https://web.example.test/x?y=1");
    // Another name gets no certificate and no way on; and the certificate was asked for once.
    assert_eq!(
        outside(&["-k", "--resolve", "other.test:443:10.1.0.1", "https://other.test/"]),
        ""
    );
    assert_eq!(
        outside(&["-o", "/dev/null", "-w", "%{http_code}", "http://10.1.0.1/x"]),
        "404"
    );
    assert_eq!(outside(&["http://10.1.0.1:14000/orders"]), "1");
    let secret = a.ok(&["get", "secret/tls-web.example.test", "-o", "yaml"]);
    assert!(secret.contains("BEGIN CERTIFICATE"), "{secret}");

    // A replica that is gone gets no more connections: scaled to one, one node answers.
    let one = std::fs::read_to_string(a.dir.join("web.yaml"))
        .unwrap()
        .replace("replicas: 2", "replicas: 1");
    std::fs::write(a.dir.join("web.yaml"), one).unwrap();
    a.ok(&["apply", "-f", "web.yaml"]);
    wait_for("one backend", || a.status("service/web")["backends"] == 1);
    let mut answers: Vec<String> = (0..4).map(|_| ask("b")).collect();
    answers.dedup();
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert!(answers[0].starts_with("kith0 lo to"), "{answers:?}");

    // A NetworkPolicy that lets only node a in: b gets no answer any more, wherever the
    // replica is; a still does.
    let policy = "apiVersion: kith.dev/v1\nkind: NetworkPolicy\nmetadata: { name: web }\nspec:\n  \
                  selector: { app: web }\n  ingress: [{ action: allow, peers: [{ node: a }] }]\n";
    std::fs::write(a.dir.join("policy.yaml"), policy).unwrap();
    a.ok(&["apply", "-f", "policy.yaml"]);
    wait_for("the policy to keep b out", || {
        a.status("networkpolicy/web")["state"] == "enforced" && ask("b").is_empty()
    });
    assert!(ask("a").starts_with("kith0 lo to") && ask("b").is_empty());
}
