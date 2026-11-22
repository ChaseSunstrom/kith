//! `kith docker serve` makes a 0600 socket that answers the Docker API. Built only with `--features docker`.
#![cfg(feature = "docker")]

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn docker_serve_listens_on_a_private_socket_and_answers_ping() {
    // (A short root: a socket path is limited to 108 bytes, and a build's target dir can be longer.)
    let dir = std::env::temp_dir().join(format!("docker-serve-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let socket = dir.join("docker.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_kith"))
        .args(["docker", "serve", "--listen"])
        .arg(&socket)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut stream = loop {
        match UnixStream::connect(&socket) {
            Ok(stream) => break stream,
            Err(e) => assert!(Instant::now() < deadline, "no socket after 20 s: {e}"),
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600);
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream
        .write_all(b"GET /_ping HTTP/1.1\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    let _ = child.kill();
    let _ = child.wait();
    assert!(reply.starts_with("HTTP/1.1 200 OK") && reply.ends_with("OK"), "{reply}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A kithd that requires the admin's signature: `docker serve` asks for the passphrase before it
/// serves, or refuses to start with a message. Here there is no terminal and nothing on stdin, so it
/// refuses, and no Docker socket is ever made (a request thread would have had to prompt).
#[test]
fn docker_serve_against_a_signing_cluster_asks_before_serving_or_refuses() {
    use std::os::unix::net::UnixListener;
    let dir = std::env::temp_dir().join(format!("docker-sign-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (kithd, docker) = (dir.join("kithd.sock"), dir.join("docker.sock"));
    let listener = UnixListener::bind(&kithd).unwrap();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut head = [0u8; 1024];
            let _ = stream.read(&mut head);
            let body = r#"{"signing":"required","clusterId":"c1"}"#;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    // (`setsid`: no controlling terminal, so a run from a terminal does not wait for typing.)
    let out = Command::new("setsid")
        .args(["-w", env!("CARGO_BIN_EXE_kith"), "--socket"])
        .arg(&kithd)
        .args(["docker", "serve", "--listen"])
        .arg(&docker)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "it must not start: {err}");
    assert!(
        err.contains("spec.signing: required") && err.contains("before it serves"),
        "{err}"
    );
    assert!(!docker.exists(), "no Docker socket before the passphrase is known");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A child killed when the test ends, however it ends.
struct Stop(std::process::Child);

impl Drop for Stop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for_socket(socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while UnixStream::connect(socket).is_err() {
        assert!(
            Instant::now() < deadline,
            "no socket at {} after 20 s",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The real `docker` CLI, pointed at `kith --store FILE docker serve`: the containers it runs are
/// kith resources in that store, and `kith get` shows them. Where there is no docker CLI the test
/// fails (a green run must not mean nothing ran) unless KITH_SKIP_DOCKER_CLI=1 says to skip it.
#[test]
fn the_docker_cli_runs_containers_through_kith_against_a_store() {
    let docker = Path::new("/usr/bin/docker");
    if !docker.exists() {
        assert!(
            std::env::var_os("KITH_SKIP_DOCKER_CLI").is_some_and(|v| v == "1"),
            "no docker CLI at {}: install it, or set KITH_SKIP_DOCKER_CLI=1 to skip this test",
            docker.display()
        );
        eprintln!("SKIPPED: no docker CLI at {}", docker.display());
        return;
    }
    let dir = std::env::temp_dir().join(format!("docker-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("docker-config")).unwrap();
    let (store, socket) = (dir.join("store.json"), dir.join("docker.sock"));
    let _server = Stop(
        Command::new(env!("CARGO_BIN_EXE_kith"))
            .arg("--store")
            .arg(&store)
            .args(["docker", "serve", "--listen"])
            .arg(&socket)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&socket);
    let host = format!("unix://{}", socket.display());
    // (The CLI's config is the test's own: nothing of the user's is read or written.)
    let cli = |args: &[&str]| {
        let out = Command::new(docker)
            .env("DOCKER_HOST", &host)
            .env("DOCKER_CONFIG", dir.join("docker-config"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    };
    let kith = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_kith"))
            .arg("--store")
            .arg(&store)
            .args(args)
            .output()
            .unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let must = |what: &str, (ok, text): (bool, String)| {
        assert!(ok, "docker {what} failed:\n{text}");
        text
    };

    must(
        "run -d",
        cli(&[
            "run", "-d", "--name", "web", "--label", "team=a", "alpine", "sleep", "300",
        ]),
    );
    must(
        "run -d --restart always",
        cli(&[
            "run",
            "-d",
            "--name",
            "api",
            "--restart",
            "always",
            "alpine",
            "sleep",
            "300",
        ]),
    );
    let ps = must("ps", cli(&["ps"]));
    assert!(ps.contains("web") && ps.contains("api") && ps.contains("Up"), "{ps}");
    let all = must("ps -a", cli(&["ps", "-a"]));
    assert!(all.contains("web") && all.contains("api"), "{all}");
    let inspected = must("inspect", cli(&["inspect", "web"]));
    assert!(
        inspected.contains("\"Name\": \"/web\"") && inspected.contains("\"Running\": true"),
        "{inspected}"
    );

    // A default `docker run -d` (restart no) is a Job while it runs; `--restart always` is a Workload.
    let (ok, job) = kith(&["get", "job", "web", "-n", "docker", "-o", "json"]);
    assert!(ok, "kith get job: {job}");
    assert!(
        job.contains("\"kith.dev/docker\": \"web\"") && job.contains("\"team\": \"a\""),
        "{job}"
    );
    let (ok, api) = kith(&["get", "workload", "api", "-n", "docker", "-o", "json"]);
    assert!(
        ok && api.contains("\"kith.dev/docker\": \"api\""),
        "kith get workload: {api}"
    );

    must("stop", cli(&["stop", "web"]));
    let stopped = must("ps -a after stop", cli(&["ps", "-a"]));
    assert!(stopped.contains("Exited (143)"), "{stopped}");
    must("start", cli(&["start", "web"]));
    must("stop again", cli(&["stop", "web"]));
    assert_eq!(must("wait", cli(&["wait", "web"])).trim(), "143");

    let (ok, shown) = kith(&["get", "Workload", "web", "-n", "docker", "-o", "json"]);
    assert!(ok, "kith get: {shown}");
    assert!(
        shown.contains("\"kith.dev/docker\": \"web\"") && shown.contains("\"team\": \"a\""),
        "{shown}"
    );

    must("rm -f", cli(&["rm", "-f", "web"]));
    let left = must("ps -a after rm", cli(&["ps", "-a"]));
    assert!(!left.contains("web") && left.contains("api"), "{left}");
    assert!(
        !kith(&["get", "Workload", "web", "-n", "docker"]).0,
        "web is still in the store"
    );
}

// What streams (T-1261): logs, a run that is not detached, and exec. The real `docker` CLI talks to
// `kith docker serve`, which talks to a stand-in kithd on a socket: its resources in a map, its
// logs, and its exec WebSocket, played from a script.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Child, ChildStdin};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Stand {
    resources: BTreeMap<String, Value>,
    /// What each container wrote: its name, then [stdout, stderr].
    logs: BTreeMap<String, [String; 2]>,
    /// A Job of this name, when it is made, writes these and ends with the code a moment later.
    script: BTreeMap<String, (i64, [String; 2])>,
    /// The first line of each exec request, and the frames the client sent on it (channel, data).
    heads: Vec<String>,
    frames: Vec<(u8, Vec<u8>)>,
    /// Every request (not exec's) as "METHOD target", for a failure to show.
    calls: Vec<String>,
}

type Shared = Arc<Mutex<Stand>>;

fn key_of(doc: &Value) -> String {
    let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
    format!(
        "{}/{}/{}",
        text(&doc["kind"]),
        text(&doc["metadata"]["namespace"]),
        text(&doc["metadata"]["name"])
    )
}

/// The Job `name` has ended with `code`, as kithd's status says it.
fn finish(stand: &Shared, name: &str, code: i64) {
    if let Some(job) = stand.lock().unwrap().resources.get_mut(&format!("Job/docker/{name}")) {
        job["status"] = match code {
            0 => json!({"state": "succeeded"}),
            _ => json!({"state": "failed", "containers": [{"exitCode": code}]}),
        };
    }
}

/// A frame from the server (never masked): `data` on `channel`.
fn said(channel: u8, data: &[u8]) -> Vec<u8> {
    let len = data.len() + 1;
    let mut out = vec![0x82];
    match len {
        0..126 => out.push(len as u8),
        _ => out.extend([126, (len >> 8) as u8, len as u8]),
    }
    out.push(channel);
    out.extend(data);
    out
}

/// How a process ended, as kithd says it on channel 3.
fn ended(code: i64) -> Vec<u8> {
    let status = match code {
        0 => json!({"kind": "Status", "status": "Success"}),
        _ => json!({"kind": "Status", "status": "Failure", "reason": "NonZeroExitCode",
            "message": format!("command terminated with non-zero exit code: exit status {code}"),
            "details": {"causes": [{"reason": "ExitCode", "message": code.to_string()}]}}),
    };
    said(3, status.to_string().as_bytes())
}

/// The next data frame a client sent, as its channel and bytes; None when it closes.
fn read_frame(from: &mut UnixStream) -> Option<(u8, Vec<u8>)> {
    loop {
        let mut head = [0u8; 2];
        from.read_exact(&mut head).ok()?;
        let mut len = usize::from(head[1] & 127);
        if len == 126 {
            let mut more = [0u8; 2];
            from.read_exact(&mut more).ok()?;
            len = usize::from(u16::from_be_bytes(more));
        }
        let mut mask = [0u8; 4];
        from.read_exact(&mut mask).ok()?;
        let mut data = vec![0u8; len];
        from.read_exact(&mut data).ok()?;
        data.iter_mut().enumerate().for_each(|(i, b)| *b ^= mask[i % 4]);
        match head[0] & 15 {
            8 => return None,
            2 if !data.is_empty() => return Some((data[0], data[1..].to_vec())),
            _ => {}
        }
    }
}

fn reply(stream: &mut UnixStream, code: &str, body: &Value) {
    let body = body.to_string();
    let _ = write!(
        stream,
        "HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

/// The exec of a pod, played from the command: `hello` and `fail` say their piece and end; `cat`
/// says back what is sent to it until its input ends; `sh` does too, on a terminal, until it is sent `exit`.
fn exec(mut stream: UnixStream, stand: &Shared, head: &str, query: &str) {
    let first = head.lines().next().unwrap_or_default().to_string();
    stand.lock().unwrap().heads.push(first);
    let command = query
        .split('&')
        .find_map(|p| p.strip_prefix("command="))
        .unwrap_or_default();
    let tty = query.contains("tty=true");
    let send = |stream: &mut UnixStream, bytes: Vec<u8>| drop(stream.write_all(&bytes));
    stream
        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\nSec-WebSocket-Protocol: v5.channel.k8s.io\r\n\r\n")
        .unwrap();
    match command {
        "hello" => {
            send(&mut stream, said(1, b"hi from pod\n"));
            if !tty {
                send(&mut stream, said(2, b"warn\n"));
            }
            send(&mut stream, ended(0));
        }
        "fail" => send(&mut stream, ended(7)),
        _ => {
            if tty {
                send(&mut stream, said(1, b"$ "));
            }
            while let Some((channel, data)) = read_frame(&mut stream) {
                stand.lock().unwrap().frames.push((channel, data.clone()));
                match channel {
                    0 => {
                        send(&mut stream, said(1, &data));
                        if command == "sh" && String::from_utf8_lossy(&data).contains("exit") {
                            send(&mut stream, ended(5));
                            break;
                        }
                    }
                    // The end of the command's input.
                    255 => {
                        send(&mut stream, ended(0));
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn answer(mut stream: UnixStream, stand: &Shared) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8];
        if stream.read(&mut byte).unwrap_or(0) == 0 {
            return;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let length = head
        .to_ascii_lowercase()
        .lines()
        .find_map(|line| line.strip_prefix("content-length:").and_then(|n| n.trim().parse().ok()))
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).unwrap();
    let mut words = head.split(' ');
    let (method, target) = (words.next().unwrap_or_default(), words.next().unwrap_or_default());
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let param = |name: &str| {
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
    };
    if path.contains("/exec") {
        return exec(stream, stand, &head, query);
    }
    let mut s = stand.lock().unwrap();
    s.calls.push(format!("{method} {target}"));
    match (method, path) {
        ("GET", "/v1/cluster") => reply(
            &mut stream,
            "200 OK",
            &json!({"signing": "optional", "clusterId": "c1"}),
        ),
        ("GET", "/v1/resources") => {
            let kind = param("kind");
            let all: Vec<&Value> = s
                .resources
                .values()
                .filter(|r| kind.is_none_or(|k| r["kind"] == k))
                .collect();
            reply(&mut stream, "200 OK", &json!(all));
        }
        ("POST", "/v1/apply") => {
            let mut changes = Vec::new();
            for doc in serde_json::from_slice::<Vec<Value>>(&body).unwrap() {
                let before = s.resources.insert(key_of(&doc), doc.clone());
                let name = doc["metadata"]["name"].as_str().unwrap_or_default().to_string();
                if doc["kind"] == "Job" && before.is_none() {
                    if let Some((code, out)) = s.script.get(&name).cloned() {
                        s.logs.insert(name.clone(), out);
                        let stand = stand.clone();
                        std::thread::spawn(move || {
                            std::thread::sleep(Duration::from_millis(600));
                            finish(&stand, &name, code);
                        });
                    }
                }
                let action = if before.is_some() { "updated" } else { "created" };
                changes.push(json!({"action": action, "before": before, "after": doc}));
            }
            reply(&mut stream, "200 OK", &json!(changes));
        }
        (_, p) if p.starts_with("/v1/resources/") => {
            let key = &p["/v1/resources/".len()..];
            let found = if method == "DELETE" {
                s.resources.remove(key)
            } else {
                s.resources.get(key).cloned()
            };
            match found {
                Some(doc) => reply(&mut stream, "200 OK", &doc),
                None => reply(
                    &mut stream,
                    "404 Not Found",
                    &json!({"error": format!("{key} not found")}),
                ),
            }
        }
        ("GET", p) if p.starts_with("/v1/logs/") => {
            let key = &p["/v1/logs/".len()..];
            // (Only a Job that is there has logs: a Workload with no replica has none to read.)
            if !key.starts_with("Job/") || !s.resources.contains_key(key) {
                return reply(
                    &mut stream,
                    "404 Not Found",
                    &json!({"error": format!("no logs for {key}")}),
                );
            }
            let all = s
                .logs
                .get(key.rsplit('/').next().unwrap_or_default())
                .cloned()
                .unwrap_or_default();
            let text = &all[usize::from(param("stderr") == Some("true"))];
            let at = match (param("tail"), param("offset")) {
                (Some(n), _) => {
                    let lines: Vec<&str> = text.split_inclusive('\n').collect();
                    text.len() - lines[lines.len().saturating_sub(n.parse().unwrap())..].concat().len()
                }
                (_, Some(offset)) => offset.parse().unwrap(),
                _ => 0,
            };
            reply(
                &mut stream,
                "200 OK",
                &json!({"data": &text[at.min(text.len())..], "next": text.len(), "more": false}),
            );
        }
        _ => reply(
            &mut stream,
            "404 Not Found",
            &json!({"error": format!("{method} {path}: nothing here")}),
        ),
    }
}

/// A `docker` (or anything else) being run: what it printed so far, and its end.
struct Running {
    child: Child,
    out: Arc<Mutex<Vec<u8>>>,
    err: Arc<Mutex<Vec<u8>>>,
    readers: Vec<std::thread::JoinHandle<()>>,
}

impl Running {
    fn new(mut command: Command) -> Running {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (out, err) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
        let mut readers = Vec::new();
        for (mut pipe, into) in [
            (
                Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>,
                out.clone(),
            ),
            (Box::new(child.stderr.take().unwrap()), err.clone()),
        ] {
            readers.push(std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n @ 1..) = pipe.read(&mut buf) {
                    into.lock().unwrap().extend(&buf[..n]);
                }
            }));
        }
        Running {
            child,
            out,
            err,
            readers,
        }
    }

    fn stdin(&mut self) -> &mut ChildStdin {
        self.child.stdin.as_mut().unwrap()
    }

    fn printed(&self) -> String {
        String::from_utf8_lossy(&self.out.lock().unwrap()).into_owned()
    }

    /// Until `what` is printed: false when it is not in 30 seconds.
    fn prints(&self, what: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.printed().contains(what) {
            if Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        true
    }

    /// Its end (its stdin closed first): the exit code and what it printed. Killed after a minute.
    fn finish(&mut self) -> (Option<i32>, String, String) {
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("did not end in 60 s; it printed:\n{}", self.printed());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        self.readers.drain(..).for_each(|r| r.join().unwrap());
        let text = |bytes: &Mutex<Vec<u8>>| String::from_utf8_lossy(&bytes.lock().unwrap()).into_owned();
        (status.code(), text(&self.out), text(&self.err))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `kith docker serve` over the stand-in kithd, and the `docker` CLI's way to it.
struct Rig {
    dir: PathBuf,
    stand: Shared,
    host: String,
    _server: Stop,
}

/// None where there is no docker CLI and the test is told to skip (as the store test is).
fn rig(name: &str) -> Option<Rig> {
    let docker = Path::new("/usr/bin/docker");
    if !docker.exists() {
        assert!(
            std::env::var_os("KITH_SKIP_DOCKER_CLI").is_some_and(|v| v == "1"),
            "no docker CLI at {}: install it, or set KITH_SKIP_DOCKER_CLI=1 to skip this test",
            docker.display()
        );
        eprintln!("SKIPPED: no docker CLI at {}", docker.display());
        return None;
    }
    let dir = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("docker-config")).unwrap();
    let stand = Shared::default();
    let listener = UnixListener::bind(dir.join("kithd.sock")).unwrap();
    let served = stand.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let stand = served.clone();
            std::thread::spawn(move || answer(stream, &stand));
        }
    });
    let socket = dir.join("docker.sock");
    let server = Stop(
        Command::new(env!("CARGO_BIN_EXE_kith"))
            .arg("--socket")
            .arg(dir.join("kithd.sock"))
            .args(["docker", "serve", "--listen"])
            .arg(&socket)
            .env("HOME", &dir)
            .stdin(Stdio::null())
            .stderr(std::fs::File::create(dir.join("serve.log")).unwrap())
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&socket);
    Some(Rig {
        host: format!("unix://{}", socket.display()),
        dir,
        stand,
        _server: server,
    })
}

impl Rig {
    /// The CLI's config is the test's own: nothing of the user's is read or written.
    fn command(&self, program: &str, args: &[&str]) -> Command {
        let mut command = Command::new(program);
        command
            .env("DOCKER_HOST", &self.host)
            .env("DOCKER_CONFIG", self.dir.join("docker-config"))
            .args(args);
        command
    }

    fn docker(&self, args: &[&str]) -> Running {
        Running::new(self.command("/usr/bin/docker", args))
    }

    /// `docker ARGS` with `stdin` typed to it, to its end.
    fn run(&self, args: &[&str], stdin: &str) -> (Option<i32>, String, String) {
        let mut running = self.docker(args);
        running.stdin().write_all(stdin.as_bytes()).unwrap();
        running.finish()
    }

    fn log(&self) -> String {
        let log = std::fs::read_to_string(self.dir.join("serve.log")).unwrap_or_default();
        format!(
            "{log}\nkithd was asked:\n{}",
            self.stand.lock().unwrap().calls.join("\n")
        )
    }

    /// A container that is running, `web`: a Job, since `docker run -d` with no restart policy is one.
    fn web(&self) {
        let (code, out, err) = self.run(&["run", "-d", "--name", "web", "alpine", "sleep", "300"], "");
        assert_eq!(code, Some(0), "docker run -d: {out}{err}\n{}", self.log());
    }

    fn write(&self, name: &str, stdout: &str, stderr: &str) {
        self.stand
            .lock()
            .unwrap()
            .logs
            .insert(name.to_string(), [stdout.to_string(), stderr.to_string()]);
    }
}

#[test]
fn the_docker_cli_reads_logs_and_follows_them_to_the_end_of_the_container() {
    let Some(rig) = rig("docker-logs") else { return };
    rig.web();
    rig.write("web", "one\ntwo\nthree\n", "warn\n");

    // Its two outputs come out as two: the multiplexed frames are what tells them apart.
    let (code, out, err) = rig.run(&["logs", "web"], "");
    assert_eq!(
        (code, out.as_str(), err.as_str()),
        (Some(0), "one\ntwo\nthree\n", "warn\n"),
        "{}",
        rig.log()
    );
    let (_, out, _) = rig.run(&["logs", "--tail", "1", "web"], "");
    assert_eq!(out, "three\n");
    // A container that never started has no logs, and that is not a failure.
    assert_eq!(rig.run(&["create", "--name", "idle", "alpine"], "").0, Some(0));
    let (code, out, err) = rig.run(&["logs", "idle"], "");
    assert_eq!((code, out.as_str(), err.as_str()), (Some(0), "", ""), "{}", rig.log());
    // What kithd has no times for is refused, with the reason.
    let (code, _, err) = rig.run(&["logs", "--timestamps", "web"], "");
    assert_ne!(code, Some(0));
    assert!(err.contains("timestamps"), "{err}");

    // -f: what comes after is printed as it comes, and it ends when the container does.
    let mut follow = rig.docker(&["logs", "-f", "web"]);
    assert!(follow.prints("three\n"), "the log so far: {}", follow.printed());
    rig.stand.lock().unwrap().logs.get_mut("web").unwrap()[0].push_str("four\n");
    assert!(
        follow.prints("four\n"),
        "what came later: {}\n{}",
        follow.printed(),
        rig.log()
    );
    finish(&rig.stand, "web", 0);
    let (code, out, _) = follow.finish();
    assert_eq!(
        (code, out.as_str()),
        (Some(0), "one\ntwo\nthree\nfour\n"),
        "{}",
        rig.log()
    );
    let _ = std::fs::remove_dir_all(&rig.dir);
}

#[test]
fn the_docker_cli_runs_a_container_in_front_and_exits_with_its_code() {
    let Some(rig) = rig("docker-run") else { return };
    let script = |name: &str, code: i64, out: &str, err: &str| {
        rig.stand
            .lock()
            .unwrap()
            .script
            .insert(name.to_string(), (code, [out.to_string(), err.to_string()]));
    };
    script("hi", 0, "hello\n", "warn\n");
    script("boom", 3, "", "bad\n");
    script("raw", 0, "tty\r\n", "");

    let (code, out, err) = rig.run(&["run", "--name", "hi", "alpine", "echo", "hello"], "");
    assert_eq!(
        (code, out.as_str(), err.as_str()),
        (Some(0), "hello\n", "warn\n"),
        "{}",
        rig.log()
    );
    // The container's code is the CLI's.
    let (code, out, err) = rig.run(&["run", "--name", "boom", "alpine", "false"], "");
    assert_eq!(
        (code, out.as_str(), err.as_str()),
        (Some(3), "", "bad\n"),
        "{}",
        rig.log()
    );
    // On a terminal what it writes is raw, with nothing to tell the two outputs apart.
    let (code, out, _) = rig.run(&["run", "-t", "--name", "raw", "alpine", "echo", "tty"], "");
    assert_eq!((code, out.as_str()), (Some(0), "tty\r\n"), "{}", rig.log());

    // Stdin to the main process is refused, with the reason and the way round it.
    let (code, _, err) = rig.run(&["run", "-i", "--name", "typed", "alpine", "cat"], "typed\n");
    assert_ne!(code, Some(0), "{err}");
    assert!(
        err.contains("stdin to a container's main process") && err.contains("docker exec -i"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&rig.dir);
}

#[test]
fn the_docker_cli_execs_in_a_container_through_kithds_exec() {
    let Some(rig) = rig("docker-exec") else { return };
    rig.web();

    let (code, out, err) = rig.run(&["exec", "web", "hello"], "");
    assert_eq!(
        (code, out.as_str(), err.as_str()),
        (Some(0), "hi from pod\n", "warn\n"),
        "{}",
        rig.log()
    );
    let heads = rig.stand.lock().unwrap().heads.clone();
    let line = &heads[0];
    // The Job's pod, and a command with no terminal and no input.
    assert!(
        line.starts_with("GET /api/v1/namespaces/docker/pods/web-j0/exec?"),
        "{line}"
    );
    for want in ["tty=false", "stdin=false", "command=hello"] {
        assert!(line.contains(want), "{want} in {line}");
    }
    // Its code is the CLI's.
    assert_eq!(rig.run(&["exec", "web", "fail"], "").0, Some(7), "{}", rig.log());
    // With -i what is typed is the command's input, and its end is the input's.
    let (code, out, _) = rig.run(&["exec", "-i", "web", "cat"], "ping\n");
    assert_eq!((code, out.as_str()), (Some(0), "ping\n"), "{}", rig.log());
    // What has nowhere to go is refused, with the reason.
    let (code, _, err) = rig.run(&["exec", "-d", "web", "hello"], "");
    assert_ne!(code, Some(0));
    assert!(err.contains("exec -d"), "{err}");
    let _ = std::fs::remove_dir_all(&rig.dir);
}

/// `docker exec -it` on a terminal (the one `script` makes): the window goes on, what is typed goes in
/// raw, and the command's code is the CLI's.
#[test]
fn the_docker_cli_execs_with_a_terminal() {
    let Some(rig) = rig("docker-exec-tty") else { return };
    if !Path::new("/usr/bin/script").exists() {
        eprintln!("SKIPPED: no script(1) to make a terminal with");
        return;
    }
    rig.web();
    let mut shell = Running::new(rig.command(
        "/usr/bin/script",
        &[
            "-qec",
            "stty rows 24 cols 80; /usr/bin/docker exec -it web sh",
            "/dev/null",
        ],
    ));
    assert!(shell.prints("$ "), "the prompt: {}\n{}", shell.printed(), rig.log());
    let deadline = Instant::now() + Duration::from_secs(30);
    let seen = |channel: u8| rig.stand.lock().unwrap().frames.iter().any(|(c, _)| *c == channel);
    while !seen(4) {
        assert!(
            Instant::now() < deadline,
            "no window size reached the exec: {}",
            rig.log()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let window = rig
        .stand
        .lock()
        .unwrap()
        .frames
        .iter()
        .find(|(c, _)| *c == 4)
        .unwrap()
        .1
        .clone();
    assert_eq!(
        serde_json::from_slice::<Value>(&window).unwrap(),
        json!({"Width": 80, "Height": 24})
    );
    // The terminal is raw: what is typed is there at once, not when its line ends, and the command
    // (a terminal's, not a pipe's) is on a terminal.
    shell.stdin().write_all(b"ping\n").unwrap();
    assert!(shell.prints("ping"), "{}", shell.printed());
    shell.stdin().write_all(b"exit\n").unwrap();
    let (code, out, _) = shell.finish();
    assert_eq!(code, Some(5), "{out}\n{}", rig.log());
    let line = rig.stand.lock().unwrap().heads[0].clone();
    assert!(line.contains("tty=true") && line.contains("stdin=true"), "{line}");
    let _ = std::fs::remove_dir_all(&rig.dir);
}
