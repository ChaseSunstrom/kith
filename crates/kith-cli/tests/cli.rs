//! The Phase 0 acceptance line (PLAN.md §7): `kith diff` and `kith apply` work
//! against a local store, and bad YAML produces errors that point at the right
//! file and line.

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
    assert_eq!(out.lines().count(), 29);
    let (_, out, _) = sb.kith(&["schema", "workload"]);
    let schema: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(schema["title"], "Workload");
    assert_eq!(sb.kith(&["schema", "gadget"]).0, 2);
}

#[test]
fn a_silent_daemon_times_out() {
    let sb = Sandbox::new("silent");
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
