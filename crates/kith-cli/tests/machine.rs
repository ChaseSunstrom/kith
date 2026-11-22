//! `kith machine` (T-1209): a dev machine is an ordinary Workload of one replica and a
//! replicated Volume, made by the CLI. Run against a local store file.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Sandbox(dir)
    }

    /// `kith ARGS` with HOME as given [default: the sandbox, which the caller owns].
    fn kith_at(&self, home: &Path, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_kith"))
            .args(args)
            .current_dir(&self.0)
            .env("KITH_STORE", self.0.join("store.json"))
            .env("HOME", home)
            .env("USER", "ada")
            .output()
            .unwrap();
        let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
        (out.status.code().unwrap(), text(out.stdout), text(out.stderr))
    }

    fn kith(&self, args: &[&str]) -> (i32, String, String) {
        self.kith_at(&self.0, args)
    }

    /// `kith apply` of a resource of the user's own, not a machine's.
    fn apply(&self, yaml: &str) {
        std::fs::write(self.0.join("own.yaml"), yaml).unwrap();
        let (code, _, err) = self.kith(&["apply", "-f", "own.yaml"]);
        assert_eq!(code, 0, "{err}");
    }

    fn json(&self, key: &str) -> serde_json::Value {
        let (code, out, err) = self.kith(&["get", key, "-o", "json"]);
        assert_eq!(code, 0, "{err}");
        serde_json::from_str(&out).unwrap()
    }
}

fn caller() -> u32 {
    std::fs::metadata("/proc/self").unwrap().uid()
}

#[test]
fn machine_create_builds_a_workload_and_a_replicated_volume() {
    if caller() == 0 {
        return; // root is refused: machine_user
    }
    let sb = Sandbox::new("machine_create");
    let (code, out, err) = sb.kith(&["machine", "create", "dev", "--distro", "alpine", "--node", "alpha"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Workload/default/dev"), "{out}");

    let work = sb.json("workload/dev");
    let spec = &work["spec"];
    assert_eq!(spec["replicas"], 1);
    let c = &spec["template"]["containers"][0];
    assert_eq!(c["image"], "docker.io/library/alpine:3");
    assert_eq!(c["runAsUser"], caller());
    assert_eq!(c["volumeMounts"][0]["volume"], "dev-home");
    assert_eq!(c["volumeMounts"][0]["path"], "/home/ada");
    assert_eq!(work["metadata"]["labels"]["kith.dev/machine"], "dev");

    let vol = sb.json("volume/dev-home");
    assert_eq!(vol["spec"]["node"], "alpha");
    assert_eq!(vol["spec"]["replicas"], 2);

    // A second create is the same machine: nothing changes.
    let (code, out, _) = sb.kith(&["machine", "create", "dev", "--distro", "alpine", "--node", "alpha"]);
    assert_eq!(code, 0);
    assert!(out.contains("unchanged"), "{out}");

    // Three names, or an image reference; a bare word that is neither is refused.
    for (distro, image) in [
        ("debian", "docker.io/library/debian:stable-slim"),
        ("ubuntu", "docker.io/library/ubuntu:24.04"),
    ] {
        let (code, _, err) = sb.kith(&["machine", "create", distro, "--distro", distro, "--node", "alpha"]);
        assert_eq!(code, 0, "{err}");
        assert_eq!(
            sb.json(&format!("workload/{distro}"))["spec"]["template"]["containers"][0]["image"],
            image
        );
    }
    let (code, _, err) = sb.kith(&["machine", "create", "x", "--distro", "gentoo", "--node", "alpha"]);
    assert_eq!(code, 2);
    assert!(err.contains("gentoo"), "{err}");
    let (code, _, _) = sb.kith(&[
        "machine",
        "create",
        "r",
        "--distro",
        "ghcr.io/example/dev:1",
        "--node",
        "alpha",
    ]);
    assert_eq!(code, 0);
}

const WORKLOAD: &str = "apiVersion: kith.dev/v1\nkind: Workload\nmetadata:\n  name: NAME\nspec:\n  replicas: 1\n  template:\n    containers:\n      - name: c\n        image: docker.io/library/alpine:3\n        volumeMounts:\n          - volume: VOLUME\n            path: /data\n";
const VOLUME: &str =
    "apiVersion: kith.dev/v1\nkind: Volume\nmetadata:\n  name: NAME\nspec:\n  node: alpha\n  path: x\n";

#[test]
fn machine_create_never_overwrites_what_is_not_its_own() {
    if caller() == 0 {
        return;
    }
    let sb = Sandbox::new("machine_create_own");
    let args =
        |name: &'static str, distro: &'static str| ["machine", "create", name, "--distro", distro, "--node", "alpha"];
    // A Workload of the user's, of the machine's name: refused, and left as it was.
    sb.apply(&WORKLOAD.replace("NAME", "web").replace("VOLUME", "x"));
    let (code, _, err) = sb.kith(&args("web", "alpine"));
    assert_eq!(code, 2);
    assert!(err.contains("not machine"), "{err}");
    assert_eq!(
        sb.json("workload/web")["spec"]["template"]["containers"][0]["name"],
        "c"
    );
    assert_ne!(sb.kith(&["get", "volume/web-home"]).0, 0, "nothing was written");
    // So is a Volume of theirs called NAME-home.
    sb.apply(&VOLUME.replace("NAME", "box-home"));
    assert_eq!(sb.kith(&args("box", "alpine")).0, 2);
    assert_ne!(sb.kith(&["get", "workload/box"]).0, 0);
    // The machine's own, with other settings: refused; with the same, unchanged.
    assert_eq!(sb.kith(&args("dev", "alpine")).0, 0);
    let (code, _, err) = sb.kith(&args("dev", "debian"));
    assert_eq!(code, 2);
    assert!(err.contains("other settings"), "{err}");
    assert!(sb.kith(&args("dev", "alpine")).1.contains("unchanged"));
    // Another home, the Volume kept: named, and what changes it says it deletes.
    let (code, _, err) = sb.kith(&["machine", "create", "dev", "--node", "alpha", "--distro", "alpine", "--replicas", "3"]);
    assert_eq!(code, 2);
    assert!(err.contains("dev-home") && err.contains("rm dev --purge") && err.contains("data"), "{err}");
    // A home that is copied nowhere is not what a machine is.
    let (code, _, err) = sb.kith(&["machine", "create", "one", "--replicas", "1", "--node", "alpha"]);
    assert_eq!(code, 2);
    assert!(err.contains("replicas"), "{err}");
}

#[test]
fn machine_lifecycle_lists_runs_and_removes() {
    if caller() == 0 {
        return;
    }
    let sb = Sandbox::new("machine_lifecycle");
    sb.apply(&WORKLOAD.replace("NAME", "web").replace("VOLUME", "x"));
    let (code, _, err) = sb.kith(&["machine", "create", "dev", "--distro", "debian", "--node", "alpha"]);
    assert_eq!(code, 0, "{err}");
    let (_, out, _) = sb.kith(&["machine", "list"]);
    assert!(out.contains("dev") && out.contains("debian"), "{out}");
    assert!(
        !out.contains("web"),
        "a Workload of another sort is not a machine: {out}"
    );
    assert_eq!(sb.kith(&["machine", "run", "web", "--", "ls"]).0, 2);

    // `run` is a Job of the machine's own container and home, which the node that has the
    // Volume runs beside it (the guide's recipe); the Volume has a copy elsewhere to move to.
    let (code, out, err) = sb.kith(&["machine", "run", "dev", "--", "make", "index"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Job/default/dev-run-"), "{out}");
    let (_, jobs, _) = sb.kith(&["get", "job"]);
    let job = jobs.lines().find(|l| l.contains("dev-run-")).expect("a Job");
    let name = job.split_whitespace().nth(2).unwrap();
    // A command that fails is not run again behind the user's back.
    assert_eq!(sb.json(&format!("job/{name}"))["spec"]["retries"], 0);
    let c = &sb.json(&format!("job/{name}"))["spec"]["template"]["containers"][0];
    assert_eq!(c["command"], serde_json::json!(["make", "index"]));
    assert_eq!(c["volumeMounts"][0]["volume"], "dev-home");
    assert_eq!(c["runAsUser"], caller());
    assert_eq!(sb.json("volume/dev-home")["spec"]["replicas"], 2);
    let (code, _, err) = sb.kith(&["machine", "run", "ghost", "--", "ls"]);
    assert_eq!(code, 2);
    assert!(err.contains("ghost"), "{err}");

    // Two runs are two Jobs, even in one instant.
    assert_eq!(sb.kith(&["machine", "run", "dev", "--", "ls"]).0, 0);
    assert_eq!(sb.kith(&["get", "job"]).1.matches("dev-run-").count(), 2);

    // A Workload of the user's that mounts the home keeps `--purge` from taking it: nothing goes.
    sb.apply(&WORKLOAD.replace("NAME", "other").replace("VOLUME", "dev-home"));
    let (code, _, err) = sb.kith(&["machine", "rm", "dev", "--purge"]);
    assert_eq!(code, 2);
    assert!(err.contains("mounts"), "{err}");
    assert_eq!(sb.kith(&["get", "workload/dev"]).0, 0);
    assert_eq!(sb.kith(&["get", "volume/dev-home"]).0, 0);
    assert_eq!(sb.kith(&["delete", "workload/other"]).0, 0);

    // rm takes the machine and its Jobs, and keeps the home unless told.
    let (code, out, err) = sb.kith(&["machine", "rm", "dev"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("dev-home") && out.contains("--purge"), "{out}");
    let (_, workloads, _) = sb.kith(&["get", "workload"]);
    assert!(workloads.contains("web") && !workloads.contains("dev"), "{workloads}");
    assert!(!sb.kith(&["get", "job"]).1.contains("dev-run-"));
    assert_eq!(sb.kith(&["get", "volume/dev-home"]).0, 0);
    assert!(!sb.kith(&["machine", "list"]).1.contains("dev"));
    // ... and can be run again, for the home, which only its own `rm` takes.
    let (code, _, err) = sb.kith(&["machine", "rm", "dev", "--purge"]);
    assert_eq!(code, 0, "{err}");
    assert_ne!(sb.kith(&["get", "volume/dev-home"]).0, 0);
    assert_eq!(sb.kith(&["machine", "rm", "dev"]).0, 2);
    assert_eq!(sb.kith(&["get", "workload/web"]).0, 0);
}

#[test]
fn machine_user_is_the_caller_never_root_and_the_home_is_theirs() {
    let sb = Sandbox::new("machine_user");
    // A home that is not the caller's (a root-owned directory): refused, nothing made.
    let (code, _, err) = sb.kith_at(
        Path::new("/usr"),
        &["machine", "create", "dev", "--distro", "alpine", "--node", "alpha"],
    );
    assert_eq!(code, 2);
    assert!(err.contains("home") || err.contains("root"), "{err}");
    assert!(sb.kith(&["get", "workload/dev"]).0 != 0);
    if caller() == 0 {
        // Root is refused even in its own home.
        let (code, _, err) = sb.kith(&["machine", "create", "dev", "--distro", "alpine", "--node", "alpha"]);
        assert_eq!(code, 2);
        assert!(err.contains("root"), "{err}");
        return;
    }
    sb.kith(&["machine", "create", "dev", "--distro", "alpine", "--node", "alpha"]);
    assert_ne!(
        sb.json("workload/dev")["spec"]["template"]["containers"][0]["runAsUser"],
        0
    );
}

// `kith machine shell` (T-1243): a WebSocket to kithd's exec on the machine's pod, against a fake
// kithd on a socket that says what it was asked and plays the channels back.

use nix::sys::signal::{Signal, kill};
use nix::sys::termios::{LocalFlags, tcgetattr};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::Duration;

/// What the fake kithd saw: the head of the exec request, then a client frame's channel and data.
enum Seen {
    Head(String),
    Frame(u8, Vec<u8>),
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
fn ended(code: i32) -> Vec<u8> {
    let status = match code {
        0 => serde_json::json!({"kind": "Status", "status": "Success"}),
        _ => serde_json::json!({"kind": "Status", "status": "Failure", "reason": "NonZeroExitCode",
            "message": format!("command terminated with non-zero exit code: exit status {code}"),
            "details": {"causes": [{"reason": "ExitCode", "message": code.to_string()}]}}),
    };
    said(3, status.to_string().as_bytes())
}

/// A client's frames, unmasked, as `Seen::Frame`s until it closes.
fn read_frames(mut from: UnixStream, seen: mpsc::Sender<Seen>) {
    loop {
        let mut head = [0u8; 2];
        if from.read_exact(&mut head).is_err() {
            return;
        }
        assert!(head[1] & 0x80 != 0, "a client's frame is masked");
        let mut len = usize::from(head[1] & 127);
        if len == 126 {
            let mut more = [0u8; 2];
            from.read_exact(&mut more).unwrap();
            len = usize::from(u16::from_be_bytes(more));
        }
        let mut mask = [0u8; 4];
        from.read_exact(&mut mask).unwrap();
        let mut data = vec![0u8; len];
        from.read_exact(&mut data).unwrap();
        data.iter_mut().enumerate().for_each(|(i, b)| *b ^= mask[i % 4]);
        match head[0] & 15 {
            8 => return,
            2 if !data.is_empty() => drop(seen.send(Seen::Frame(data[0], data[1..].to_vec()))),
            _ => {}
        }
    }
}

/// A kithd that has the Workload `dev` and answers the exec of its pod with a WebSocket: what is
/// sent to the returned sender goes to the client once it has upgraded, and the sender dropped ends it.
fn fake_kithd(dir: &Path, workload: String) -> (PathBuf, mpsc::Receiver<Seen>, mpsc::Sender<Vec<u8>>) {
    let socket = dir.join("kithd.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (seen, saw) = mpsc::channel();
    let (say, to_say) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8];
                if stream.read(&mut byte).unwrap() == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let head = String::from_utf8(head).unwrap();
            let path = head.split(' ').nth(1).unwrap_or_default().to_string();
            if !path.contains("/exec") {
                let (code, body) = match path.as_str() {
                    "/v1/resources/Workload/default/dev" => ("200 OK", workload.clone()),
                    _ => ("404 Not Found", r#"{"error":"nothing here"}"#.to_string()),
                };
                let reply = format!(
                    "HTTP/1.1 {code}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(reply.as_bytes()).unwrap();
                continue;
            }
            let _ = seen.send(Seen::Head(head));
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\nSec-WebSocket-Protocol: v5.channel.k8s.io\r\n\r\n")
                .unwrap();
            let reader = stream.try_clone().unwrap();
            std::thread::spawn(move || read_frames(reader, seen));
            for bytes in to_say {
                if stream.write_all(&bytes).is_err() {
                    break;
                }
            }
            return;
        }
    });
    (socket, saw, say)
}

fn next(saw: &mpsc::Receiver<Seen>) -> Seen {
    saw.recv_timeout(Duration::from_secs(30))
        .expect("kith said nothing for 30 s")
}

/// `kith ARGS` against the fake kithd, with `stdio` for its three streams.
fn kith_shell(sb: &Sandbox, socket: &Path, args: &[&str], stdio: [Stdio; 3]) -> std::process::Child {
    let [stdin, stdout, stderr] = stdio;
    Command::new(env!("CARGO_BIN_EXE_kith"))
        .args(args)
        .current_dir(&sb.0)
        .env("KITH_SOCKET", socket)
        .env_remove("KITH_STORE")
        .env_remove("KITH_SERVER")
        .env("HOME", &sb.0)
        .env("USER", "ada")
        .stdin(stdin)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .unwrap()
}

/// The machine `dev` as a Workload, the way `kith get -o json` says it.
fn machine_json(sb: &Sandbox) -> String {
    let (code, _, err) = sb.kith(&["machine", "create", "dev", "--distro", "alpine", "--node", "alpha"]);
    assert_eq!(code, 0, "{err}");
    sb.kith(&["get", "workload/dev", "-o", "json"]).1
}

#[test]
fn machine_shell_gives_a_terminal_follows_its_window_and_returns_the_exit_code() {
    if caller() == 0 {
        return;
    }
    let sb = Sandbox::new("machine_shell");
    let (socket, saw, say) = fake_kithd(&sb.0, machine_json(&sb));
    say.send(said(1, b"ready$ ")).unwrap();
    let pty = nix::pty::openpty(None, None).unwrap();
    let mut master = File::from(pty.master);
    kith_dm_sys::set_window(&master, 30, 100).unwrap();
    let cooked = tcgetattr(&pty.slave).unwrap();
    let stdio = || Stdio::from(pty.slave.try_clone().unwrap());
    let mut child = kith_shell(&sb, &socket, &["machine", "shell", "dev"], [stdio(), stdio(), stdio()]);

    // The pod of the machine's one replica, on a terminal, with stdin.
    let Seen::Head(head) = next(&saw) else {
        panic!("the request comes first")
    };
    let line = head.lines().next().unwrap();
    assert!(
        line.starts_with("GET /api/v1/namespaces/default/pods/dev-0/exec?"),
        "{line}"
    );
    for want in ["tty=true", "stdin=true", "stdout=true", "command="] {
        assert!(line.contains(want), "{want} in {line}");
    }
    assert!(!line.contains("root=true"), "{line}");
    let lower = head.to_ascii_lowercase();
    assert!(
        lower.contains("upgrade: websocket") && lower.contains("sec-websocket-version: 13"),
        "{head}"
    );
    assert!(lower.contains("sec-websocket-protocol: v5.channel.k8s.io"), "{head}");

    // Its window first, and what the server printed reaches the terminal.
    let Seen::Frame(4, size) = next(&saw) else {
        panic!("the window comes first")
    };
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&size).unwrap(),
        serde_json::json!({"Width": 100, "Height": 30})
    );
    let (to_read, shown) = mpsc::channel();
    let mut output = master.try_clone().unwrap();
    std::thread::spawn(move || {
        let mut chunk = [0u8; 256];
        while let Ok(n @ 1..) = output.read(&mut chunk) {
            let _ = to_read.send(chunk[..n].to_vec());
        }
    });
    let mut text = Vec::new();
    while !String::from_utf8_lossy(&text).contains("ready$ ") {
        text.extend(
            shown
                .recv_timeout(Duration::from_secs(30))
                .expect("the prompt reached the terminal"),
        );
    }
    // The terminal is raw while it runs: nothing is echoed by it, nothing waits for a line.
    let raw = tcgetattr(&pty.slave).unwrap();
    assert!(
        !raw.local_flags.intersects(LocalFlags::ICANON | LocalFlags::ECHO),
        "{:?}",
        raw.local_flags
    );

    // Keys typed go to channel 0 as they are.
    master.write_all(b"bye\n").unwrap();
    let mut typed = Vec::new();
    while typed != b"bye\n" {
        let Seen::Frame(0, data) = next(&saw) else {
            panic!("only keys are sent")
        };
        typed.extend(data);
    }
    // A new window size goes on channel 4 (the window changed: SIGWINCH).
    kith_dm_sys::set_window(&master, 50, 120).unwrap();
    kill(nix::unistd::Pid::from_raw(child.id() as i32), Signal::SIGWINCH).unwrap();
    let Seen::Frame(4, size) = next(&saw) else {
        panic!("the new window is sent")
    };
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&size).unwrap(),
        serde_json::json!({"Width": 120, "Height": 50})
    );

    // The shell's exit code is kith's, and the terminal is as it was.
    say.send(ended(7)).unwrap();
    drop(say);
    assert_eq!(child.wait().unwrap().code(), Some(7));
    assert_eq!(tcgetattr(&pty.slave).unwrap(), cooked, "the terminal is restored");
}

#[test]
fn machine_shell_without_a_terminal_runs_the_command_on_pipes() {
    if caller() == 0 {
        return;
    }
    let sb = Sandbox::new("machine_shell_pipes");
    let (socket, saw, say) = fake_kithd(&sb.0, machine_json(&sb));
    say.send(said(1, b"out\n")).unwrap();
    say.send(said(2, b"err\n")).unwrap();
    // A machine that is not one is refused before anything is opened.
    let none = kith_shell(
        &sb,
        &socket,
        &["machine", "shell", "ghost"],
        [Stdio::null(), Stdio::piped(), Stdio::piped()],
    );
    let out = none.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no machine `ghost`"));
    let piped = || Stdio::piped();
    let args = ["machine", "shell", "dev", "--", "cat", "a b"];
    let mut child = kith_shell(&sb, &socket, &args, [piped(), piped(), piped()]);
    let Seen::Head(head) = next(&saw) else {
        panic!("the request comes first")
    };
    let line = head.lines().next().unwrap();
    // No terminal here: no tty, and the command is its words, one `command` each.
    assert!(
        line.contains("tty=false") && line.contains("command=cat&command=a%20b"),
        "{line}"
    );
    child.stdin.take().unwrap().write_all(b"in").unwrap(); // (dropped: stdin is over)
    let mut got = Vec::new();
    while got.last() != Some(&255) {
        let Seen::Frame(channel, data) = next(&saw) else {
            panic!("frames only")
        };
        got.push(channel);
        if channel == 0 {
            assert_eq!(data, b"in");
        } else {
            assert_eq!((channel, data), (255, vec![0]), "[255, 0]: stdin is over");
        }
    }
    say.send(ended(0)).unwrap();
    drop(say);
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        (out.stdout.as_slice(), out.stderr.as_slice()),
        (&b"out\n"[..], &b"err\n"[..])
    );
}

#[test]
fn machine_shell_root_asks_for_root_and_says_why_it_is_refused() {
    if caller() == 0 {
        return;
    }
    let sb = Sandbox::new("machine_shell_root");
    let (socket, saw, say) = fake_kithd(&sb.0, machine_json(&sb));
    // What kithd says where uid 0 in the container would be the node's root (kith-runtime's own_root).
    let why = "enter machine: --root is refused: the container has no user namespace of its own";
    let refusal = serde_json::json!({"kind": "Status", "status": "Failure", "reason": "InternalError", "code": 500, "message": why});
    say.send(said(3, refusal.to_string().as_bytes())).unwrap();
    drop(say);
    let child = kith_shell(
        &sb,
        &socket,
        &["machine", "shell", "dev", "--root"],
        [Stdio::null(), Stdio::piped(), Stdio::piped()],
    );
    let Seen::Head(head) = next(&saw) else {
        panic!("the request comes first")
    };
    assert!(head.lines().next().unwrap().contains("root=true"), "{head}");
    let out = child.wait_with_output().unwrap();
    // A refusal is kith's own (2), not the shell's exit code, and it says why.
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--root is refused") && err.contains("no user namespace of its own"),
        "{err}"
    );
    assert!(out.stdout.is_empty());
}

/// A read kithd refuses (403) is an error, not "no such resource": nothing is written over what
/// could not be read, and no Volume is called deleted that was skipped.
#[test]
fn machine_get_error_is_not_absent() {
    use std::io::{BufRead, BufReader, Write};
    use std::sync::{Arc, Mutex};
    if caller() == 0 {
        return;
    }
    let sb = Sandbox::new("machine_get_error");
    let socket = sb.0.join("kithd.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut line = String::new();
            let mut reader = BufReader::new(&stream);
            reader.read_line(&mut line).unwrap();
            log.lock().unwrap().push(line.trim().to_string());
            // The cluster is open (a write would go through unsigned); every resource read is refused.
            let (status, body) = if line.contains("/v1/cluster") {
                ("200 OK", r#"{"signing":"open"}"#)
            } else {
                ("403 Forbidden", r#"{"error":"denied by role"}"#)
            };
            let mut stream = &stream;
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    for args in [
        &["machine", "create", "dev", "--node", "alpha"][..],
        &["machine", "rm", "dev", "--purge"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_kith"))
            .args(args)
            .env_remove("KITH_STORE")
            .env("KITH_SOCKET", &socket)
            .env("HOME", &sb.0)
            .env("USER", "ada")
            .output()
            .unwrap();
        let err = String::from_utf8(out.stderr).unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}: {err}");
        assert!(err.contains("denied by role"), "{err}");
        assert!(!String::from_utf8_lossy(&out.stdout).contains("deleted"));
    }
    let seen = seen.lock().unwrap();
    assert!(seen.iter().all(|l| l.starts_with("GET ")), "only reads were sent: {seen:?}");
}
