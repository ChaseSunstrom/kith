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
            .env("KITH_SOCKET", "kithd.sock")
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

    /// How many threads this kithd passes connections to Services on.
    fn proxies(&self) -> usize {
        self.threads("kith-proxy")
    }

    /// How many of this kithd's threads have names starting with `name`.
    fn threads(&self, name: &str) -> usize {
        let tasks = std::fs::read_dir(format!("/proc/{}/task", self.child.id())).unwrap();
        let comm = |task: std::fs::DirEntry| std::fs::read_to_string(task.path().join("comm")).unwrap_or_default();
        tasks.flatten().map(comm).filter(|comm| comm.starts_with(name)).count()
    }

    /// How long its API takes to answer, half the time or less (the median of many).
    fn answers_in(&self) -> Duration {
        use std::io::{Read, Write};
        let mut took: Vec<Duration> = (0..200)
            .map(|_| {
                let asked = Instant::now();
                let mut api = std::os::unix::net::UnixStream::connect(self.dir.join("kithd.sock")).unwrap();
                api.write_all(b"GET /v1/resources HTTP/1.1\r\nHost: kithd\r\nConnection: close\r\n\r\n")
                    .unwrap();
                let mut reply = Vec::new();
                api.read_to_end(&mut reply).unwrap();
                assert!(reply.starts_with(b"HTTP/1.1 200"));
                asked.elapsed()
            })
            .collect();
        took.sort();
        took[took.len() / 2]
    }

    /// How long its DNS, on port 5353, takes to answer for `name` (the median of many).
    fn names_in(&self, name: &str) -> Duration {
        let netns = format!("--net=/run/netns/{}", self.dir.file_name().unwrap().to_str().unwrap());
        let out = Command::new("nsenter")
            .args([&netns, "python3", "-c", ASK, name])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        Duration::from_micros(String::from_utf8(out.stdout).unwrap().trim().parse().unwrap())
    }
}

/// Asks 127.0.0.1:5353 for `argv[1]` 200 times; prints the median time to an answer, in µs.
const ASK: &str = "import socket, struct, sys, time\n\
labels = b''.join(bytes([len(p)]) + p.encode() for p in sys.argv[1].split('.'))\n\
query = struct.pack('>6H', 7, 0x0100, 1, 0, 0, 0) + labels + b'\\0' + struct.pack('>2H', 1, 1)\n\
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5); s.connect(('127.0.0.1', 5353))\n\
took = []\n\
for _ in range(200):\n\
\x20   asked = time.perf_counter(); s.send(query); answer = s.recv(4096)\n\
\x20   took.append(time.perf_counter() - asked); assert answer[:2] == query[:2]\n\
print(int(sorted(took)[100] * 1e6))\n";

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

/// The namespaces a and b, a wire between them, then the test `$1` again.
const SETUP: &str = "set -e; mount -t tmpfs none /run; \
    ip netns add a; ip netns add b; ip -n a link set lo up; ip -n b link set lo up; \
    ip link add tob netns a type veth peer name toa netns b; \
    ip -n a addr add 10.1.0.1/24 dev tob; ip -n a link set tob up; \
    ip -n b addr add 10.1.0.2/24 dev toa; ip -n b link set toa up; \
    KITH_IN_NAMESPACE=1 exec \"$0\" --exact \"$1\" --nocapture";

/// Whether the test `name` goes on here: it is run again inside the namespaces (and goes
/// on there), or skipped where they cannot be made.
fn in_namespaces(name: &str) -> bool {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return false;
    }
    if std::env::var_os("KITH_IN_NAMESPACE").is_some() {
        return true;
    }
    // (As the user it is, not as root: kithd puts units where a user's cgroups are.)
    let flags = ["-Unm", "--map-current-user", "--keep-caps"];
    let unshare = |args: &[&str]| Command::new("unshare").args(flags).args(args).status();
    if !unshare(&["true"]).is_ok_and(|status| status.success()) {
        eprintln!("skipped: no unprivileged user namespaces here (unshare -Unm --map-current-user --keep-caps)");
        return false;
    }
    let built = Command::new(env!("CARGO"))
        .args(["build", "--quiet", "-p", "kith-cli"])
        .status();
    assert!(built.unwrap().success());
    let me = std::env::current_exe().unwrap();
    // (One test at a time: their nodes have the same names, and so the same directories,
    // whose sockets' paths have no room for a test's name too.)
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let status = unshare(&["sh", "-c", SETUP, me.to_str().unwrap(), name]).unwrap();
    assert!(status.success(), "the test failed inside its namespaces");
    false
}

/// A replica that sends as fast as it can to each connection, for as long as it lasts.
const FLOOD: &str = "import socket, threading\n\
listener = socket.create_server(('127.0.0.1', 8080))\n\
zeros = bytes(1 << 20)\n\
def send(c):\n\
\x20   try:\n\
\x20       while True: c.sendall(zeros)\n\
\x20   except OSError: pass\n\
while True:\n\
\x20   c, _ = listener.accept(); threading.Thread(target=send, args=(c,), daemon=True).start()\n";

/// Sixteen clients of the Service at `argv[1]`, port 80, taking all it sends; says so on
/// its output once each has had some (and says nothing if one has not in a minute).
const LOAD: &str = "import socket, sys, threading\n\
going = threading.Barrier(17, timeout=60)\n\
def take():\n\
\x20   c = socket.create_connection((sys.argv[1], 80)); c.sendall(b'go'); got, buffer = 0, bytearray(1 << 20)\n\
\x20   while got < 64 << 20:\n\
\x20       n = c.recv_into(buffer)\n\
\x20       if not n: return\n\
\x20       got += n\n\
\x20   going.wait()\n\
\x20   while c.recv_into(buffer): pass\n\
for _ in range(16): threading.Thread(target=take, daemon=True).start()\n\
going.wait(); print('flowing', flush=True); threading.Event().wait()\n";

#[test]
fn the_api_answers_as_fast_with_the_proxy_busy() {
    if !in_namespaces("the_api_answers_as_fast_with_the_proxy_busy") {
        return;
    }
    let a = Node::start("a", "10.1.0.1", &["--dns", "127.0.0.1:5353"]);
    wait_for("a to lead", || a.kith(&["get", "node"]).0);
    std::fs::write(a.dir.join("flood.py"), FLOOD).unwrap();
    let web = format!(
        "apiVersion: kith.dev/v1\nkind: Workload\nmetadata: {{ name: web, labels: {{ app: web }} }}\nspec:\n  \
         template:\n    exec: [{{ name: run, command: [python3, {}] }}]\n---\n\
         apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: web }}\nspec:\n  selector: {{ app: web }}\n  \
         ports: [{{ port: 80, targetPort: 8080 }}]\n",
        a.dir.join("flood.py").display()
    );
    std::fs::write(a.dir.join("web.yaml"), web).unwrap();
    a.ok(&["apply", "-f", "web.yaml"]);
    wait_for("the replica behind the Service", || {
        a.status("workload/web")["ready"] == 1 && a.status("service/web")["backends"] == 1
    });
    let address = a.status("service/web")["address"].as_str().unwrap().to_string();
    wait_for("DNS on a thread of its own", || a.threads("kith-dns") == 1);
    let idle = a.answers_in();
    let named = a.names_in("a.node.kith");

    let load = Command::new("nsenter")
        .args(["--net=/run/netns/a", "python3", "-c", LOAD, &address])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut load = Stop(load);
    let mut flowing = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(load.0.stdout.as_mut().unwrap()),
        &mut flowing,
    )
    .unwrap();
    assert_eq!(flowing, "flowing\n", "the clients could not reach the Service");
    let busy = a.answers_in();
    let named_busy = a.names_in("a.node.kith");
    eprintln!("the API answers in {idle:?} with the proxy idle, {busy:?} with it busy");
    eprintln!("DNS answers in {named:?} with the proxy idle, {named_busy:?} with it busy");
    // (Below three cores the proxy's threads and kithd's own share them: nothing to compare.)
    if std::thread::available_parallelism().map_or(1, std::num::NonZero::get) < 3 {
        return;
    }
    // (Four times as long, and two milliseconds, for a machine busy with other things: the
    // API on the proxy's thread took fifteen times as long, 0.36 ms to 5.4 ms.)
    let as_fast = |idle: Duration, busy: Duration| busy <= idle * 4 + Duration::from_millis(2);
    assert!(as_fast(idle, busy), "the API: {idle:?} idle, {busy:?} busy");
    assert!(as_fast(named, named_busy), "DNS: {named:?} idle, {named_busy:?} busy");
}

#[test]
fn a_service_spreads_connections() {
    if !in_namespaces("a_service_spreads_connections") {
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

    // No thread passes connections to Services before there is a Service.
    assert_eq!((a.proxies(), b.proxies()), (0, 0));
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
    // Then one on each core, up to kithd's bound of four, on each node.
    let cores = std::thread::available_parallelism().unwrap().get().min(4);
    wait_for("a thread on each core", || (a.proxies(), b.proxies()) == (cores, cores));
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

    // One that lets neither in: the node without the replica asks the other on a
    // connection the two kept from before, and is told no on that one too.
    std::fs::write(a.dir.join("policy.yaml"), policy.replace("node: a", "node: nobody")).unwrap();
    a.ok(&["apply", "-f", "policy.yaml"]);
    wait_for("the policy to keep both out", || {
        ask("a").is_empty() && ask("b").is_empty()
    });
    assert!(ask("a").is_empty() && ask("b").is_empty());
}
