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

#[test]
fn machine_lifecycle_lists_runs_and_removes() {
    if caller() == 0 {
        return;
    }
    let sb = Sandbox::new("machine_lifecycle");
    // (A Workload of another sort is not a machine.)
    let (code, _, err) = sb.kith(&["machine", "create", "dev", "--distro", "debian", "--node", "alpha"]);
    assert_eq!(code, 0, "{err}");
    let (_, out, _) = sb.kith(&["machine", "list"]);
    assert!(out.contains("dev") && out.contains("debian"), "{out}");

    // `run` is a Job of the machine's own container and home, which the node that has the
    // Volume runs beside it (the guide's recipe); the Volume has a copy elsewhere to move to.
    let (code, out, err) = sb.kith(&["machine", "run", "dev", "--", "make", "index"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Job/default/dev-run-"), "{out}");
    let (_, jobs, _) = sb.kith(&["get", "job"]);
    let job = jobs.lines().find(|l| l.contains("dev-run-")).expect("a Job");
    let name = job.split_whitespace().nth(2).unwrap();
    let c = &sb.json(&format!("job/{name}"))["spec"]["template"]["containers"][0];
    assert_eq!(c["command"], serde_json::json!(["make", "index"]));
    assert_eq!(c["volumeMounts"][0]["volume"], "dev-home");
    assert_eq!(c["runAsUser"], caller());
    assert_eq!(sb.json("volume/dev-home")["spec"]["replicas"], 2);
    let (code, _, err) = sb.kith(&["machine", "run", "ghost", "--", "ls"]);
    assert_eq!(code, 2);
    assert!(err.contains("ghost"), "{err}");

    // rm takes the machine and its Jobs, and keeps the home unless told.
    let (code, _, err) = sb.kith(&["machine", "rm", "dev"]);
    assert_eq!(code, 0, "{err}");
    assert_ne!(sb.kith(&["get", "workload/dev"]).0, 0);
    assert!(!sb.kith(&["get", "job"]).1.contains("dev-run-"));
    assert_eq!(sb.kith(&["get", "volume/dev-home"]).0, 0);
    assert!(!sb.kith(&["machine", "list"]).1.contains("dev"));
    sb.kith(&["machine", "create", "dev", "--distro", "debian", "--node", "alpha"]);
    let (code, _, err) = sb.kith(&["machine", "rm", "dev", "--purge"]);
    assert_eq!(code, 0, "{err}");
    assert_ne!(sb.kith(&["get", "volume/dev-home"]).0, 0);
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
