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
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("docker-serve-{}", std::process::id()));
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
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("docker-cli-{}", std::process::id()));
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
