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
