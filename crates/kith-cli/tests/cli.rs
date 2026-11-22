//! The Phase 0 acceptance line (PLAN.md §7): `kith diff` and `kith apply` work
//! against a local store, and bad YAML produces errors that point at the right
//! file and line.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Make `path` an executable holding `text`, without this process ever opening it for
/// writing: while it does, another test thread that forks keeps a copy of the descriptor
/// until its exec, and running the file meanwhile fails with ETXTBSY. The text goes to a
/// draft that is never run, `cp` (the only writer, which forks nothing) copies it, and
/// chmod opens nothing.
fn write_executable(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    let mut draft = path.to_path_buf().into_os_string();
    draft.push(".draft");
    std::fs::write(&draft, text).unwrap();
    let copied = Command::new("cp").arg(&draft).arg(path).status().unwrap();
    assert!(copied.success(), "cp of {}: {copied}", path.display());
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// The second field says the directory is a short one made for a socket, removed when dropped.
struct Sandbox(PathBuf, bool);

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Sandbox(dir, false)
    }

    /// A sandbox under the temp dir, not CARGO_TARGET_TMPDIR (a merge train's is long): a path
    /// that is to hold a Unix socket must stay under the 107 bytes `sun_path` takes.
    fn short(name: &str) -> Sandbox {
        let dir = std::env::temp_dir().join(format!("kr-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Sandbox(dir, true)
    }

    fn write(&self, file: &str, content: &str) {
        std::fs::write(self.0.join(file), content).unwrap();
    }

    /// Run `kith` in the sandbox; returns (exit code, stdout, stderr).
    fn kith(&self, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_kith"))
            .args(args)
            .current_dir(&self.0)
            .env("KITH_STORE", self.0.join("store/store.json"))
            .output()
            .unwrap();
        let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
        (out.status.code().unwrap(), text(out.stdout), text(out.stderr))
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if self.1 {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

const WEB: &str = "\
apiVersion: kith.dev/v1
kind: Workload
metadata:
  name: web
  labels: { app: web }
spec:
  replicas: 1
  template:
    containers:
      - name: web
        image: nginx:1.27
---
apiVersion: kith.dev/v1
kind: ConfigMap
metadata: { name: web-config }
spec:
  data:
    motd: |
      hello
      world
";

#[test]
fn diff_apply_history_rollback() {
    let sb = Sandbox::new("lifecycle");
    sb.write("web.yaml", WEB);

    // Nothing is stored yet: diff shows two new resources and exits 1.
    let (code, out, err) = sb.kith(&["diff", "-f", "web.yaml"]);
    assert_eq!(code, 1, "{err}");
    assert!(out.contains("--- /dev/null\n+++ Workload/default/web (new)\n"), "{out}");
    assert!(out.contains("+        image: nginx:1.27\n"), "{out}");
    assert!(out.contains("+++ ConfigMap/default/web-config (new)"), "{out}");
    assert_eq!(err, "2 to create, 0 to update, 0 unchanged\n");
    assert_eq!(
        sb.kith(&["get"]).1,
        "KIND  NAMESPACE  NAME  REVISION  STATUS\n",
        "diff must not write"
    );

    // A dry run does not write either.
    let (code, out, _) = sb.kith(&["apply", "-f", "web.yaml", "--dry-run"]);
    assert_eq!(
        (code, out.as_str()),
        (
            0,
            "Workload/default/web created (revision 1) (dry run)\nConfigMap/default/web-config created (revision 1) (dry run)\n"
        )
    );

    let (code, out, _) = sb.kith(&["apply", "-f", "web.yaml"]);
    assert_eq!(
        (code, out.as_str()),
        (
            0,
            "Workload/default/web created (revision 1)\nConfigMap/default/web-config created (revision 1)\n"
        )
    );

    // Now diff is clean (exit 0) and apply is idempotent.
    let (code, out, err) = sb.kith(&["diff", "-f", "web.yaml"]);
    assert_eq!(
        (code, out.as_str(), err.as_str()),
        (0, "", "0 to create, 0 to update, 2 unchanged\n")
    );
    let (_, out, _) = sb.kith(&["apply", "-f", "web.yaml"]);
    assert_eq!(
        out,
        "Workload/default/web unchanged (revision 1)\nConfigMap/default/web-config unchanged (revision 1)\n"
    );

    // Change one field: diff shows exactly that, apply bumps only that resource.
    sb.write("web.yaml", &WEB.replace("replicas: 1", "replicas: 3"));
    let (code, out, err) = sb.kith(&["diff", "-f", "web.yaml"]);
    assert_eq!(code, 1);
    assert!(
        out.contains("--- Workload/default/web (live)\n+++ Workload/default/web (desired)\n"),
        "{out}"
    );
    assert!(out.contains("-  replicas: 1\n+  replicas: 3\n"), "{out}");
    assert!(!out.contains("ConfigMap"), "{out}");
    assert_eq!(err, "0 to create, 1 to update, 1 unchanged\n");
    let (_, out, _) = sb.kith(&["apply", "-f", "web.yaml"]);
    assert_eq!(
        out,
        "Workload/default/web updated (revision 2)\nConfigMap/default/web-config unchanged (revision 1)\n"
    );

    // get: table, one resource as YAML (which applies back cleanly), JSON.
    let (_, out, _) = sb.kith(&["get"]);
    assert_eq!(
        out,
        "KIND       NAMESPACE  NAME        REVISION  STATUS\nConfigMap  default    web-config  1\nWorkload   default    web         2\n"
    );
    let (_, yaml, _) = sb.kith(&["get", "workload/web", "-o", "yaml"]);
    assert!(
        yaml.contains("  revision: 2\n") && yaml.contains("  replicas: 3\n"),
        "{yaml}"
    );
    sb.write("fetched.yaml", &yaml);
    assert_eq!(sb.kith(&["diff", "-f", "fetched.yaml"]).0, 0);
    let (_, out, _) = sb.kith(&["get", "configmap", "web-config", "-o", "json"]);
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["spec"]["data"]["motd"], "hello\nworld\n");
    let (_, out, _) = sb.kith(&["get", "configmap", "-o", "json"]);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&out)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(sb.kith(&["get", "workload", "-n", "elsewhere"]).1.lines().count(), 1);

    // history and rollback.
    let (_, out, _) = sb.kith(&["history", "Workload/web"]);
    let revisions: Vec<_> = out
        .lines()
        .skip(1)
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(revisions, ["1", "2"], "{out}");
    let (code, out, _) = sb.kith(&["rollback", "Workload/web", "--to", "1"]);
    assert_eq!(
        (code, out.as_str()),
        (0, "Workload/default/web rolled back to revision 1 (now revision 3)\n")
    );
    assert!(
        sb.kith(&["get", "Workload/web", "-o", "yaml"])
            .1
            .contains("  replicas: 1\n")
    );
    // The fetched copy is now stale: applying it is refused, not silently merged.
    let (code, _, err) = sb.kith(&["apply", "-f", "fetched.yaml"]);
    assert_eq!(code, 2);
    assert!(
        err.contains("is at revision 3, but this edit is based on revision 2"),
        "{err}"
    );

    let (code, out, _) = sb.kith(&["delete", "configmap", "web-config"]);
    assert_eq!((code, out.as_str()), (0, "ConfigMap/default/web-config deleted\n"));
    let (code, _, err) = sb.kith(&["delete", "configmap/web-config"]);
    assert_eq!(
        (code, err.as_str()),
        (2, "error: ConfigMap/default/web-config not found\n")
    );
}

#[test]
fn bad_yaml_points_at_file_and_line() {
    let sb = Sandbox::new("errors");

    // A syntax error.
    sb.write(
        "syntax.yaml",
        "apiVersion: kith.dev/v1\nkind: Namespace\nmetadata:\n  name: a\n name: b\n",
    );
    let (code, out, err) = sb.kith(&["apply", "-f", "syntax.yaml"]);
    assert_eq!((code, out.as_str()), (2, ""));
    assert!(err.starts_with("syntax.yaml:5:2: "), "{err}");

    // A duplicate key, with the offending line quoted.
    sb.write(
        "dup.yaml",
        "apiVersion: kith.dev/v1\nkind: Namespace\nmetadata:\n  name: a\n  name: b\n",
    );
    let (_, _, err) = sb.kith(&["diff", "-f", "dup.yaml"]);
    assert_eq!(err, "dup.yaml:5:3: duplicate key `name`\n  |   name: b\n  |   ^\n");

    // Schema errors: every problem in every file is reported in one run.
    sb.write("good.yaml", WEB);
    sb.write(
        "schema.yaml",
        &format!(
            "{}---\n{}",
            WEB.replace("replicas: 1", "replicas: yes"),
            WEB.replace("image:", "imagee:")
        ),
    );
    sb.write(
        "kind.json",
        "{\n  \"apiVersion\": \"kith.dev/v1\",\n  \"kind\": \"Deployment\",\n  \"metadata\": {\"name\": \"x\"}\n}\n",
    );
    let (code, out, err) = sb.kith(&["apply", "-f", "good.yaml", "-f", "schema.yaml", "-f", "kind.json"]);
    assert_eq!((code, out.as_str()), (2, ""));
    assert!(
        err.contains(
            "schema.yaml:7:13: invalid type: string \"yes\", expected u32\n  |   replicas: yes\n  |             ^\n"
        ),
        "{err}"
    );
    assert!(err.contains("schema.yaml:32:9: unknown field `imagee`"), "{err}");
    assert!(err.contains("kind.json:3:11: unknown kind `Deployment`"), "{err}");
    // One bad file means nothing was applied, including the good one.
    assert_eq!(sb.kith(&["get"]).1.lines().count(), 1);

    // lint needs no store and reads directories and stdin.
    let (code, _, err) = sb.kith(&["lint", "-f", "."]);
    assert_eq!(code, 2);
    assert_eq!(err.matches("unknown kind").count(), 1, "{err}");
    let (code, _, err) = sb.kith(&["lint", "-f", "missing.yaml"]);
    assert_eq!(code, 2);
    assert!(err.starts_with("error: missing.yaml: "), "{err}");

    // A store that is not a store is reported, never overwritten.
    std::fs::create_dir_all(sb.0.join("store")).unwrap(); // nothing so far created it
    sb.write("store/store.json", "not json");
    let (code, _, err) = sb.kith(&["apply", "-f", "good.yaml"]);
    assert_eq!(code, 2);
    assert!(err.contains("is not a kith store"), "{err}");
    assert_eq!(
        std::fs::read_to_string(sb.0.join("store/store.json")).unwrap(),
        "not json"
    );
}

#[test]
fn examples_and_schemas() {
    let sb = Sandbox::new("examples");
    let examples = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples");
    let (code, out, err) = sb.kith(&["lint", "-f", examples]);
    assert_eq!((code, out.as_str()), (0, "9 resources ok\n"), "{err}");
    let (code, out, _) = sb.kith(&["apply", "-f", examples]);
    assert_eq!(code, 0);
    assert_eq!(out.lines().count(), 9);
    assert_eq!(sb.kith(&["diff", "-f", examples]).0, 0);

    let (_, out, _) = sb.kith(&["schema"]);
    // (A heading and the 38 kinds the README counts.)
    assert_eq!(out.lines().count(), 39);
    let (_, out, _) = sb.kith(&["schema", "workload"]);
    let schema: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(schema["title"], "Workload");
    assert_eq!(sb.kith(&["schema", "gadget"]).0, 2);
}

#[test]
fn a_silent_daemon_times_out() {
    let sb = Sandbox::short("silent");
    let socket = sb.0.join("kithd.sock");
    // Accepts connections (the kernel does) and never answers.
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let began = std::time::Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_kith"))
        .args(["--timeout", "1", "get"])
        .env("KITH_SOCKET", &socket)
        .env_remove("KITH_STORE")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert_eq!(
        err,
        "error: kithd has not answered for 1 s (--timeout sets how long to wait)\n"
    );
    assert!(began.elapsed() < std::time::Duration::from_secs(10));
}

/// A fake carrier (what `waypipe client` is to `kith run`) that writes its pid beside itself,
/// listens on the socket it is given, takes the connection and then does `after`; and a fake
/// kithd that answers `101` to the ask and then holds the tunnel (`hold`) or closes it. Starts
/// `kith run` against them, with its temp dir in the sandbox; the receiver says when the tunnel
/// is up.
fn kith_run(
    sb: &Sandbox,
    tmp: &Path,
    after: &str,
    hold: bool,
) -> (std::process::Child, std::sync::mpsc::Receiver<()>, PathBuf) {
    use std::io::{Read, Write};
    let socket = sb.0.join("kithd.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let (up, tunnel) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        loop {
            let (mut conn, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8];
                if conn.read(&mut byte).unwrap() == 0 {
                    return;
                }
                head.push(byte[0]);
            }
            let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
            let length = head.split("content-length:").nth(1).unwrap().lines().next().unwrap();
            conn.read_exact(&mut vec![0; length.trim().parse().unwrap()]).unwrap();
            if head.starts_with("get ") {
                // kith asks the cluster whether its writes are signed first: they are not.
                let body = r#"{"signing":"none"}"#;
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                conn.write_all(reply.as_bytes()).unwrap();
                continue;
            }
            conn.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: kith-run\r\n\r\n")
                .unwrap();
            let _ = up.send(());
            if hold {
                // Until kith lets go of it.
                let _ = conn.read_to_end(&mut Vec::new());
            }
            return;
        }
    });
    let carrier = sb.0.join("carrier");
    let script = format!(
        "#!/usr/bin/env python3\nimport os, socket, sys, time\nargs = sys.argv[1:]\nif args[0] == \"--secctx\":\n    args = args[2:]\nopen(sys.argv[0] + \".pid\", \"w\").write(str(os.getpid()))\ns = socket.socket(socket.AF_UNIX)\ns.bind(args[1])\ns.listen(1)\ns.accept()\n{after}\n"
    );
    write_executable(&carrier, &script);
    let child = Command::new(env!("CARGO_BIN_EXE_kith"))
        .args(["--timeout", "60", "run", "--on", "b", "--via"])
        .arg(&carrier)
        .args(["--", "true"])
        .env("KITH_SOCKET", &socket)
        .env("TMPDIR", tmp)
        .env_remove("KITH_STORE")
        .spawn()
        .unwrap();
    (child, tunnel, carrier)
}

fn run_dirs(sb: &Sandbox) -> usize {
    let names = std::fs::read_dir(&sb.0).unwrap().map(|e| e.unwrap().file_name());
    names
        .filter(|name| name.to_string_lossy().starts_with("kith-run-"))
        .count()
}

/// The carrier's word is the one `kith run` has of how the run went: its exit status is `kith`'s.
#[test]
fn kith_run_returns_the_status_the_carrier_ends_with() {
    let sb = Sandbox::short("run-status");
    let (mut kith, _, _) = kith_run(&sb, &sb.0, "sys.exit(7)", false);
    assert_eq!(kith.wait().unwrap().code(), Some(7));
    assert_eq!(run_dirs(&sb), 0, "the run's directory stays");
}

/// A carrier a signal ended has no code: `kith run` ends with the shell's 128 and the signal's
/// number, not with 0 (a run that went well).
#[test]
fn kith_run_ends_with_128_and_the_signal_for_a_carrier_a_signal_ended() {
    let sb = Sandbox::short("run-signalled");
    let (mut kith, _, _) = kith_run(&sb, &sb.0, "os.kill(os.getpid(), 9)", false);
    assert_eq!(kith.wait().unwrap().code(), Some(137));
    assert_eq!(run_dirs(&sb), 0, "the run's directory stays");
}

/// A TMPDIR too long for the carrier's socket (past the 107 bytes of `sun_path`, as a build's
/// is) is passed over: the carrier binds, the run goes, and no run directory is made there.
#[test]
fn kith_run_keeps_its_socket_short_whatever_the_temp_dir() {
    let sb = Sandbox::short("run-long");
    let long = sb.0.join("a".repeat(60)).join("b".repeat(60));
    std::fs::create_dir_all(&long).unwrap();
    let (mut kith, _, _) = kith_run(&sb, &long, "sys.exit(7)", false);
    assert_eq!(
        kith.wait().unwrap().code(),
        Some(7),
        "the carrier could not bind its socket"
    );
    assert_eq!(
        std::fs::read_dir(&long).unwrap().count(),
        0,
        "a run directory is in the long temp dir"
    );
}

/// An interrupt ends the run as an end of the tunnel does: the carrier is killed, the directory
/// goes, and the exit status is the shell's for the signal (128 + 2).
#[test]
fn kith_run_cleans_up_and_exits_130_on_an_interrupt() {
    let sb = Sandbox::short("run-interrupt");
    let (mut kith, tunnel, carrier) = kith_run(&sb, &sb.0, "time.sleep(300)", true);
    tunnel.recv_timeout(std::time::Duration::from_secs(90)).unwrap();
    assert_eq!(run_dirs(&sb), 1, "the run's directory is not there while it runs");
    let pid = std::fs::read_to_string(format!("{}.pid", carrier.display())).unwrap();
    let sent = Command::new("kill")
        .args(["-INT", &kith.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    assert_eq!(kith.wait().unwrap().code(), Some(130));
    assert_eq!(run_dirs(&sb), 0, "the run's directory stays after an interrupt");
    let alive = || Path::new(&format!("/proc/{pid}")).exists();
    for _ in 0..100 {
        if !alive() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(!alive(), "the carrier stays after an interrupt");
}

/// The nas package: a Share for the volume, and (when it names SMB users) the Samba
/// container with the volume mounted and each user's password from the Secret.
/// The kith-build package: a Volume for what the build leaves, a Job that runs the steps
/// with it at /out, and an Image of that volume, made when that Job has succeeded.
#[test]
fn the_kith_build_package_renders_a_volume_a_job_and_an_image() {
    let sandbox = Sandbox::new("kith-build");
    let package = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packages/kith-build");
    let (code, out, err) = sandbox.kith(&["package", "lint", package]);
    assert_eq!((code, out.as_str()), (0, "kith-build 0.1.0 ok\n"), "{err}");
    let mine = "node: n1\nbuilder: localhost:5000/default/tools:3\nscript: |\n  cp /bin/hello /out/hello\n  echo 'it''s \"done\"'\ntag: v2\nentrypoint: [/hello]\nenv: [A=b]\n";
    sandbox.write("mine.yaml", mine);
    let (code, out, notes) = sandbox.kith(&["package", "render", package, "--name", "hello", "-f", "mine.yaml"]);
    assert_eq!(code, 0, "{notes}");
    let kinds: Vec<&str> = out.lines().filter(|line| line.starts_with("kind: ")).collect();
    assert_eq!(kinds, ["kind: Volume", "kind: Job", "kind: Image"], "{out}");
    let name = "hello-kith-build";
    assert!(out.contains("  node: n1\n  path: root\n"), "{out}");
    assert!(
        out.contains(&format!("          - volume: {name}-root\n            path: /out\n")),
        "{out}"
    );
    assert!(out.contains("image: localhost:5000/default/tools:3"), "{out}");
    // (The script is one argument, whatever is in it; and it is root's, as an image's files are.)
    let script = "          - |\n            cp /bin/hello /out/hello\n            echo 'it''s \"done\"'\n        runAsUser: 0\n        resources:";
    assert!(out.contains(script), "{out}");
    let image = format!(
        "  volume: {name}-root\n  tag: v2\n  job: {name}-build\n  entrypoint:\n    - /hello\n  env:\n    - A=b\n  copies: 2\n"
    );
    assert!(out.contains(&image), "{out}");
    assert!(notes.contains(&format!("localhost:5000/default/{name}:v2")), "{notes}");
}

#[test]
fn the_nas_package_renders_a_share_and_its_smb_server() {
    let sandbox = Sandbox::new("nas");
    let nas = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packages/nas");
    let (code, out, err) = sandbox.kith(&["package", "lint", nas]);
    assert_eq!((code, out.as_str()), (0, "nas 0.1.0 ok\n"), "{err}");
    // NFS alone: the Share, and no server of the package's.
    let nfs = [
        "package",
        "render",
        nas,
        "--name",
        "films",
        "--set",
        "nfs.clients=[192.168.1.0/24]",
    ];
    let (code, out, err) = sandbox.kith(&nfs);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("kind: Share") && out.contains("- 192.168.1.0/24"), "{out}");
    assert!(!out.contains("kind: Workload"), "{out}");
    // With users: the server, as the volume's user, each password from the Secret by name.
    let mine = "volume: media\nusers: [ada, bob]\npasswords: nas-passwords\nuid: 1000\nreadOnly: true\n";
    sandbox.write("mine.yaml", mine);
    let (code, out, notes) = sandbox.kith(&["package", "render", nas, "--name", "films", "-f", "mine.yaml"]);
    assert_eq!(code, 0, "{notes}");
    assert!(out.contains("kind: Workload") && out.contains("exec smbd"), "{out}");
    // (smbd is started as root: nobody takes port 445 or becomes another user.)
    assert!(out.contains("        runAsUser: 0\n"), "{out}");
    assert!(
        out.contains("volume: media\n            path: /share\n            readOnly: true"),
        "{out}"
    );
    let password =
        "name: KITH_SMB_PASSWORD_2\n            secret:\n              name: nas-passwords\n              key: bob";
    assert!(out.contains(password), "{out}");
    assert!(
        out.contains("users:\n    - ada\n    - bob") && out.contains("uid: 1000"),
        "{out}"
    );
    assert!(notes.contains("port 445, for ada, bob"), "{notes}");
    // And it is what `kith apply` takes.
    sandbox.write("rendered.yaml", &out);
    let (code, out, err) = sandbox.kith(&["apply", "-f", "rendered.yaml"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.matches("created").count(), 2, "{out}");

    // What the container runs, with stand-ins for Samba's two programs and a directory
    // here for /run/samba: each user is given its own password, and the server its share.
    let script = std::fs::read_to_string(format!("{nas}/templates/_serve.sh")).unwrap();
    let run = sandbox.0.join("run");
    let bin = sandbox.0.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let stand_in = |name: &str, does: &str| {
        write_executable(&bin.join(name), &format!("#!/bin/sh\n{does}\n"));
    };
    stand_in(
        "smbpasswd",
        &format!("echo \"$* $(tr '\\n' ' ')\" >>{}/added", run.display()),
    );
    stand_in("smbd", &format!("echo \"$*\" >{}/served", run.display()));
    let script = script.replace("d=/run/samba", &format!("d={}", run.display()));
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let ran = std::process::Command::new("sh")
        .args(["-c", &script])
        .env("PATH", path)
        .env("KITH_SHARE_NAME", "films-nas")
        .env("KITH_SHARE_READ_ONLY", "yes")
        .env("KITH_SHARE_UID", "1000")
        .env("KITH_SHARE_GID", "100")
        .env("KITH_SMB_USERS", "ada bob")
        .env("KITH_SMB_PASSWORD_1", "one $HOME `id`")
        .env("KITH_SMB_PASSWORD_2", "two")
        .output()
        .unwrap();
    assert!(ran.status.success(), "{}", String::from_utf8_lossy(&ran.stderr));
    let read = |name: &str| std::fs::read_to_string(run.join(name)).unwrap();
    let conf = read("smb.conf");
    assert!(
        conf.contains("[films-nas]\npath = /share\nread only = yes\nvalid users = ada bob\n"),
        "{conf}"
    );
    assert!(
        conf.contains("force user = kith-share") && conf.contains("map to guest = never"),
        "{conf}"
    );
    let passwd = read("passwd");
    assert!(
        passwd.contains("kith-share:x:1000:100:") && passwd.contains("bob:x:60002:100:"),
        "{passwd}"
    );
    let added = read("added");
    assert!(added.contains("-s -a ada one $HOME `id` one $HOME `id`"), "{added}");
    assert!(added.contains("-s -a bob two two"), "{added}");
    assert!(read("served").contains("--foreground"));
}

/// A browser desktop: a pod (its image writes under /), port 8080 behind a Service, and the
/// password of both the browser's login and the desktop's user from one Secret, never a value.
#[test]
fn the_selkies_package_is_a_pod_behind_a_password_from_a_secret() {
    let sandbox = Sandbox::new("selkies");
    let selkies = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packages/selkies");
    let (code, out, err) = sandbox.kith(&["package", "lint", selkies]);
    assert_eq!((code, out.as_str()), (0, "selkies 0.1.0 ok\n"), "{err}");
    let (code, out, notes) = sandbox.kith(&["package", "render", selkies, "--name", "desk", "-n", "home"]);
    assert_eq!(code, 0, "{notes}");
    assert!(out.contains("    pod: true\n") && out.contains("port: 8080"), "{out}");
    for name in ["SELKIES_BASIC_AUTH_PASSWORD", "PASSWD"] {
        let from = format!(
            "name: {name}\n            secret:\n              name: selkies-password\n              key: password"
        );
        assert!(out.contains(&from), "{name}: {out}");
    }
    assert!(
        !out.contains("kind: Secret"),
        "the password is the owner's to make: {out}"
    );
    // With no Secret named, nothing renders.
    let (code, _, err) = sandbox.kith(&[
        "package",
        "render",
        selkies,
        "--name",
        "desk",
        "--set",
        "passwordSecret=",
    ]);
    assert_ne!(code, 0, "{err}");
    // What it renders, and the Secret as its notes make it, are what `kith apply` takes.
    sandbox.write("rendered.yaml", &out);
    let (code, _, err) = sandbox.kith(&["apply", "-f", "rendered.yaml"]);
    assert_eq!(code, 0, "{err}");
    let secret = notes
        .split("<<< '")
        .nth(1)
        .and_then(|rest| rest.split('\'').next())
        .unwrap();
    sandbox.write("secret.json", secret);
    let (code, out, err) = sandbox.kith(&["apply", "-f", "secret.json"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Secret/home/selkies-password created"), "{out}");
}

#[test]
fn package_render_and_lint() {
    let sandbox = Sandbox::new("package");
    let web = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packages/web");
    let (code, out, _) = sandbox.kith(&["package", "lint", web]);
    assert_eq!((code, out.as_str()), (0, "web 0.1.0 ok\n"));

    // What it renders to is what `kith apply` takes.
    sandbox.write("mine.yaml", "replicas: 2\nexpose: { host: shop.example.org }\n");
    let args = [
        "package",
        "render",
        web,
        "--name",
        "shop",
        "-n",
        "store",
        "-f",
        "mine.yaml",
    ];
    let (code, out, notes) = sandbox.kith(&[&args[..], &["--set", "replicas=3", "--set", "env.MODE=fast"]].concat());
    assert_eq!(code, 0, "{notes}");
    assert!(notes.contains("https://shop.example.org/"), "{notes}");
    assert!(out.contains("replicas: 3") && out.contains("namespace: store"), "{out}");
    assert!(
        out.contains("kith.dev/release: shop") && out.contains("value: fast"),
        "{out}"
    );
    sandbox.write("rendered.yaml", &out);
    let (code, out, err) = sandbox.kith(&["apply", "-f", "rendered.yaml"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.matches("created").count(), 3, "{out}");

    // Values the package does not have, and a package that is not there.
    let (code, _, err) = sandbox.kith(&["package", "render", web, "--set", "colour=red"]);
    assert_eq!(code, 2);
    assert!(err.contains("values.colour: is not a field the schema has"), "{err}");
    let (code, _, err) = sandbox.kith(&["package", "lint", "nowhere"]);
    assert!(code == 2 && err.contains("nowhere: no package.yaml"), "{err}");
}

/// A package for a newer kith than this one is warned of, by push and by render, and
/// still goes through: the cluster's kithd is what refuses it (T-0990).
#[test]
fn package_kith_version_warns_when_this_kith_does_not_fit() {
    let sandbox = Sandbox::new("package-kith-version");
    for (asked, warned) in [(">=99", true), (">=0.1", false)] {
        let dir = format!("pkg{warned}");
        std::fs::create_dir_all(sandbox.0.join(&dir).join("templates")).unwrap();
        sandbox.write(
            &format!("{dir}/package.yaml"),
            &format!("name: late\nversion: 1.0.0\nkithVersion: '{asked}'\n"),
        );
        sandbox.write(
            &format!("{dir}/templates/map.yaml"),
            "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: late }\nspec: { data: { a: b } }\n",
        );
        let path = sandbox.0.join(&dir);
        let path = path.to_str().unwrap();
        for args in [["package", "render", path], ["package", "push", path]] {
            let (code, _, err) = sandbox.kith(&args);
            assert_eq!(code, 0, "{asked} {args:?}: {err}");
            let said = err.contains("warning: late 1.0.0 needs kith >=99, and this kith is ");
            assert_eq!(said, warned, "{asked} {args:?}: {err}");
        }
    }
}

const K8S: &str = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
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
          image: nginx:1.27
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  selector: { app: web }
  ports:
    - port: 80
---
apiVersion: v1
kind: Secret
metadata:
  name: creds
data:
  token: aHVudGVyMg==
";

#[test]
fn import_k8s_output_applies_and_the_report_gives_the_exit_code() {
    let sb = Sandbox::new("import-k8s");
    sb.write("k8s.yaml", K8S);
    let (code, out, err) = sb.kith(&["import", "k8s", "-f", "k8s.yaml"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(err, "3 resources, 0 things not translated\n");
    assert_eq!(out.matches("---\n").count(), 2, "{out}");
    sb.write("kith.yaml", &out);
    let (code, out, err) = sb.kith(&["apply", "-f", "kith.yaml"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.matches("created").count(), 3, "{out}");

    // Something left out: still printed, exit 1, named on stderr.
    sb.write(
        "more.yaml",
        &format!("{K8S}---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: lone\n"),
    );
    let (code, out, err) = sb.kith(&["import", "k8s", "-f", "more.yaml"]);
    assert_eq!(code, 1, "{err}");
    assert!(out.contains("kind: Workload"), "{out}");
    assert!(err.contains("not translated: Pod/lone:"), "{err}");

    // Unreadable input.
    let (code, _, err) = sb.kith(&["import", "k8s", "-f", "nowhere.yaml"]);
    assert!(code == 2 && err.contains("nowhere.yaml"), "{err}");
    sb.write("bad.yaml", "a: [unclosed\n");
    let (code, out, err) = sb.kith(&["import", "k8s", "-f", "bad.yaml"]);
    assert!(code == 2 && out.is_empty() && err.contains("bad.yaml"), "{err}");
}

/// `kith` with `path` as the only directory on PATH.
fn kith_with_path(sb: &Sandbox, path: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_kith"))
        .args(args)
        .current_dir(&sb.0)
        .env("PATH", path)
        .output()
        .unwrap();
    let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
    (out.status.code().unwrap(), text(out.stdout), text(out.stderr))
}

#[test]
fn import_helm_runs_helm_template_and_translates() {
    let sb = Sandbox::new("import-helm");
    // A stand-in `helm`: it records its arguments and prints a rendered chart.
    let bin = sb.0.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    sb.write("rendered.yaml", K8S);
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{0}/args.txt'\nexec /bin/cat '{0}/rendered.yaml'\n",
        sb.0.display()
    );
    write_executable(&bin.join("helm"), &script);

    let (code, out, err) = kith_with_path(
        &sb,
        &bin,
        &[
            "import", "helm", "./shop", "--name", "shop", "-n", "store", "-f", "v.yaml",
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("kind: Workload") && out.contains("kind: Secret"), "{out}");
    let args = std::fs::read_to_string(sb.0.join("args.txt")).unwrap();
    assert_eq!(args, "template\nshop\n./shop\n--namespace\nstore\n-f\nv.yaml\n");

    // A chart that looks like a flag is not handed to helm.
    let (code, _, err) = kith_with_path(&sb, &bin, &["import", "helm", "--", "-evil"]);
    assert!(code == 2 && err.contains("starts with `-`"), "{err}");
}

#[test]
fn import_helm_without_helm_says_what_to_do() {
    let sb = Sandbox::new("import-no-helm");
    let empty = sb.0.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let (code, out, err) = kith_with_path(&sb, &empty, &["import", "helm", "./shop"]);
    assert_eq!(code, 2);
    assert!(out.is_empty());
    assert!(
        err.contains("helm is not installed: install it, or pipe `helm template ... | kith import k8s -f -`"),
        "{err}"
    );
}

#[test]
fn switch_hands_a_device_claim_to_a_workload() {
    let sb = Sandbox::new("switch");
    sb.write(
        "gpu.yaml",
        "\
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: desktop }
spec:
  replicas: 1
  template:
    containers:
      - { name: desktop, image: desktop:1 }
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: game }
spec:
  replicas: 1
  template:
    containers:
      - { name: game, image: game:1 }
---
apiVersion: kith.dev/v1
kind: DeviceClaim
metadata: { name: gpu }
spec:
  device: gpu0
",
    );
    assert_eq!(sb.kith(&["apply", "-f", "gpu.yaml"]).0, 0);

    // One apply of the claim: revision 2. What came of it is the claim's status, not this line.
    let (code, out, err) = sb.kith(&["switch", "gpu", "game"]);
    assert_eq!(
        (code, out.as_str()),
        (
            0,
            "DeviceClaim/default/gpu asks for Workload/game (revision 2): `kith get deviceclaim gpu` shows who holds it\n"
        ),
        "{err}"
    );
    let (_, yaml, _) = sb.kith(&["get", "DeviceClaim/gpu", "-o", "yaml"]);
    assert!(yaml.contains("holder: Workload/game\n"), "{yaml}");

    // A holder that is not there, or not a workload, changes nothing.
    let (code, _, err) = sb.kith(&["switch", "gpu", "Job/nobody"]);
    assert_eq!(code, 2);
    assert!(err.contains("Job/nobody"), "{err}");
    let (code, _, err) = sb.kith(&["switch", "gpu", "Seat/game"]);
    assert_eq!(code, 2);
    assert!(err.contains("not a workload of this namespace"), "{err}");
    let (_, out, _) = sb.kith(&["history", "DeviceClaim/gpu"]);
    assert_eq!(out.lines().count(), 3, "{out}");
}

/// T-0031: the context verbs over a HOME of their own, and which of the file, the environment
/// and the flags a command takes its server from (a kith without `remote` names the server and
/// identity it was to call, which is all that is read here).
#[test]
fn context_verbs_and_the_order_of_what_names_the_server() {
    let sb = Sandbox::new("contexts");
    for dir in ["alice", "bob"] {
        std::fs::create_dir(sb.0.join(dir)).unwrap();
    }
    let kith = |env: &[(&str, &str)], args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kith"));
        command
            .args(args)
            .current_dir(&sb.0)
            .env("HOME", sb.0.join("home"))
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("KITH_STORE")
            .env_remove("KITH_SERVER")
            .env_remove("KITH_IDENTITY")
            .env_remove("KITH_CONTEXT")
            .env_remove("KITH_SOCKET")
            .envs(env.iter().copied());
        let out = command.output().unwrap();
        let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
        (out.status.code().unwrap(), text(out.stdout), text(out.stderr))
    };
    let file = sb.0.join("home/.config/kith/contexts.yaml");
    let (code, _, err) = kith(
        &[],
        &[
            "context",
            "add",
            "lab",
            "--server",
            "lab.test:7443",
            "--identity",
            "alice",
        ],
    );
    assert_eq!(code, 0, "{err}");
    kith(
        &[],
        &[
            "context",
            "add",
            "other",
            "--server",
            "other.test:7443",
            "--identity",
            "bob",
        ],
    );
    assert!(file.is_file());
    // No current one yet: a command that needs kithd goes to the socket, not to a server.
    let (_, _, err) = kith(&[], &["get"]);
    assert!(!err.contains("test:7443"), "{err}");
    assert_eq!(kith(&[], &["context", "use", "lab"]).0, 0);
    let (code, listing, _) = kith(&[], &["context", "ls"]);
    assert!(
        code == 0 && listing.contains("* lab\tlab.test:7443\t") && listing.contains("  other\t"),
        "{listing}"
    );

    // The current one, the environment's, then the flag's: each names the server it was to call.
    let (_, _, err) = kith(&[], &["get"]);
    assert!(err.contains("lab.test:7443") && err.contains("alice"), "{err}");
    let (_, _, err) = kith(&[("KITH_CONTEXT", "other")], &["get"]);
    assert!(err.contains("other.test:7443") && err.contains("bob"), "{err}");
    let (_, _, err) = kith(&[("KITH_CONTEXT", "other")], &["--context", "lab", "get"]);
    assert!(err.contains("lab.test:7443"), "{err}");
    // A flag wins over the file, each half on its own.
    let (_, _, err) = kith(&[], &["--server", "flag.test:1", "--identity", "bob", "get"]);
    assert!(err.contains("flag.test:1") && err.contains("bob"), "{err}");
    let (_, _, err) = kith(&[], &["--context", "lab", "--identity", "bob", "get"]);
    assert!(err.contains("lab.test:7443") && err.contains("bob"), "{err}");
    // A store, or a socket, named as well: the file's current context is not what is meant.
    let store = sb.0.join("store/store.json").display().to_string();
    let (code, _, err) = kith(&[], &["--store", &store, "get"]);
    assert_eq!(code, 0, "{err}");
    let (_, _, err) = kith(&[], &["--socket", "none.sock", "get"]);
    assert!(!err.contains("test:7443"), "{err}");

    // An unknown name and a missing identity directory name the file.
    let (code, _, err) = kith(&[], &["--context", "nope", "get"]);
    assert!(
        code == 2 && err.contains("no context") && err.contains("contexts.yaml"),
        "{err}"
    );
    std::fs::remove_dir(sb.0.join("alice")).unwrap();
    let (code, _, err) = kith(&[], &["get"]);
    assert!(
        code == 2 && err.contains("identity directory") && err.contains("contexts.yaml"),
        "{err}"
    );
    // A command that calls no kithd does not read the file.
    assert_eq!(kith(&[], &["schema"]).0, 0);

    // rm: the current one is gone, and a second rm says so.
    assert_eq!(kith(&[], &["context", "rm", "lab"]).0, 0);
    assert_eq!(kith(&[], &["context", "rm", "lab"]).0, 2);
    let (_, listing, _) = kith(&[], &["context", "ls"]);
    assert_eq!(listing.lines().count(), 1, "{listing}");
    let (_, _, err) = kith(&[], &["get"]);
    assert!(!err.contains("test:7443"), "{err}");
}

/// A Cluster's fields that nothing reads: `kith lint` says so of each one the file sets, on
/// stderr, and the file is still fine.
#[test]
fn cluster_fields_nothing_reads_are_said() {
    let sandbox = Sandbox::new("cluster-fields");
    let cluster = "apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: { name: home }\nspec:\n";
    sandbox.write("set.yaml", &format!("{cluster}  voters: [a]\n  images: []\n"));
    let (code, _, said) = sandbox.kith(&["lint", "-f", "set.yaml"]);
    let note = "note: Cluster/home: spec.voters is kept and not acted on";
    assert!(code == 0 && said.contains(note), "{code}: {said}");
    assert!(!said.contains("spec.images"), "{said}");
    sandbox.write("read.yaml", &format!("{cluster}  images: []\n"));
    let (code, _, said) = sandbox.kith(&["lint", "-f", "read.yaml"]);
    assert!(code == 0 && !said.contains("note:"), "{code}: {said}");
}
