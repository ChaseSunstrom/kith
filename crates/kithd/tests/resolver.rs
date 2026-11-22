//! `kithd --resolver` beside a real systemd-resolved: a private dbus-daemon and resolved in a user,
//! network and mount namespace of their own (nothing of this machine's resolver is touched), a
//! kithd that is the leader of a one-node cluster on a mesh interface, and `getent` as the
//! program that asks. Skipped where `unshare --map-auto`, dbus-daemon or systemd-resolved is missing.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const RESOLVED: &str = "/usr/lib/systemd/systemd-resolved";
const DBUS_CONF: &str = r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth>
<policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>
"#;

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// What a command printed, and whether it succeeded.
fn run(program: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(program).args(args).stdin(Stdio::null()).output().unwrap();
    let both = [out.stdout, out.stderr].concat();
    (out.status.success(), String::from_utf8_lossy(&both).into_owned())
}

/// A process of this test's namespace, ended with it.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[test]
fn resolver_gives_this_machine_the_kith_names_through_systemd_resolved_and_takes_them_back() {
    let name = "resolver_gives_this_machine_the_kith_names_through_systemd_resolved_and_takes_them_back";
    if std::env::var_os("KITH_IN_NAMESPACE").is_none() {
        let tools = Path::new(RESOLVED).exists()
            && ["dbus-daemon", "resolvectl", "getent", "ip", "mount"]
                .iter()
                .all(|tool| Command::new(tool).arg("--version").output().is_ok_and(|_| true));
        if !tools {
            return eprintln!("skipped: needs systemd-resolved, resolvectl, dbus-daemon, getent, ip");
        }
        let unshare = |args: &[&str]| {
            Command::new("unshare")
                .args(["-Urnm", "--map-auto"])
                .args(args)
                .status()
        };
        if !unshare(&["true"]).is_ok_and(|status| status.success()) {
            return eprintln!("skipped: no unprivileged user namespaces here (unshare -Urnm --map-auto)");
        }
        let me = std::env::current_exe().unwrap();
        let again = "ip link set lo up && mount -t tmpfs tmpfs /run && mkdir -p /run/dbus /run/systemd/resolve \
                     && KITH_IN_NAMESPACE=1 exec \"$0\" --exact \"$1\" --nocapture";
        let status = unshare(&["sh", "-c", again, me.to_str().unwrap(), name]).unwrap();
        assert!(status.success(), "the test failed inside its namespace");
        return;
    }

    let built = Command::new(env!("CARGO"))
        .args(["build", "--quiet", "-p", "kith-cli"])
        .status()
        .unwrap();
    assert!(built.success());
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("resolver");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = |file: &str| std::fs::File::create(dir.join(file)).unwrap();

    // A bus and a resolved of our own, in this namespace's /run.
    std::fs::write("/run/dbus/conf.xml", DBUS_CONF).unwrap();
    let _bus = Daemon(
        Command::new("dbus-daemon")
            .args(["--config-file=/run/dbus/conf.xml", "--nofork", "--nopidfile"])
            .stderr(log("dbus.log"))
            .spawn()
            .unwrap(),
    );
    wait_for("the bus", || Path::new("/run/dbus/system_bus_socket").exists());
    let _ = run("chown", &["systemd-resolve:systemd-resolve", "/run/systemd/resolve"]);
    let _resolved = Daemon(
        Command::new(RESOLVED)
            .env("RUNTIME_DIRECTORY", "/run/systemd/resolve")
            .stdout(log("resolved.log"))
            .stderr(log("resolved.err"))
            .spawn()
            .unwrap(),
    );
    wait_for("systemd-resolved", || run("resolvectl", &["status"]).0);

    // A link that is not the mesh's, and the machine as it is before kithd.
    for args in [
        &["link", "add", "kt9", "type", "veth", "peer", "name", "kt8"][..],
        &["link", "set", "kt9", "up"],
        &["link", "set", "kt8", "up"],
    ] {
        let (done, said) = run("ip", args);
        assert!(done, "ip {args:?}: {said}");
    }
    let others = || ["lo", "kt9"].map(|link| run("resolvectl", &["status", link]).1);
    let before = others();

    // kithd: the leader of a one-node cluster, on the mesh, with `--resolver`.
    let kith = Path::new(env!("CARGO_BIN_EXE_kithd")).with_file_name("kith");
    let kith = |args: &[&str]| {
        let out = Command::new(&kith)
            .args(args)
            .current_dir(&dir)
            .env("KITH_SOCKET", "kithd.sock")
            .env_remove("KITH_STORE")
            .output()
            .unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let mut kithd = Command::new(env!("CARGO_BIN_EXE_kithd"))
        .current_dir(&dir)
        .args(["--state", "state", "--socket", "kithd.sock", "--name", "alpha"])
        .args([
            "--listen",
            &format!("127.0.0.1:{}", free_port()),
            "--registry-port",
            "0",
        ])
        .args([
            "--mesh",
            &free_port().to_string(),
            "--mesh-interface",
            "kith-res",
            "--resolver",
        ])
        .stdin(Stdio::null())
        .stderr(log("kithd.log"))
        .spawn()
        .unwrap();
    wait_for("alpha to be on the mesh", || {
        kith(&["get", "node/alpha", "-o", "json"]).1.contains("\"mesh\"")
    });
    std::fs::write(
        dir.join("web.yaml"),
        "apiVersion: kith.dev/v1\nkind: Service\nmetadata: { name: web }\nspec:\n  selector: { app: web }\n  \
         ports: [{ port: 80, targetPort: 8080 }]\n",
    )
    .unwrap();
    assert!(kith(&["apply", "-f", "web.yaml"]).0);

    // AC1: a program that asks the system resolver gets the Service's address.
    wait_for("web.default.kith to resolve", || {
        run("getent", &["hosts", "web.default.kith"]).0
    });
    let got = run("getent", &["hosts", "web.default.kith"]).1;
    assert!(got.contains("web.default.kith"), "{got}");

    // AC2: the mesh link has kithd's server for `~kith` and no default route; no other link changed.
    let status = run("resolvectl", &["status", "kith-res"]).1;
    for line in ["DNS Servers: 127.0.0.87", "DNS Domain: ~kith", "Default Route: no"] {
        let said = status.lines().any(|l| l.trim() == line);
        assert!(said, "{line} is not in\n{status}");
    }
    assert_eq!(others(), before, "another link changed");
    // (A name that is not under .kith is not sent to kithd.)
    assert!(!run("getent", &["hosts", "web.default.example"]).0);

    // AC3: SIGTERM, and the link's entry goes before the interface does; resolved still answers.
    assert!(run("kill", &[&kithd.id().to_string()]).0);
    let deadline = Instant::now() + Duration::from_secs(60);
    while kithd.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "kithd did not stop");
        std::thread::sleep(Duration::from_millis(100));
    }
    let (_, after) = run("resolvectl", &["status", "kith-res"]);
    assert!(!after.contains("127.0.0.87") && !after.contains("~kith"), "{after}");
    assert!(!run("getent", &["hosts", "web.default.kith"]).0);
    let (known, said) = run("resolvectl", &["query", "localhost"]);
    assert!(known, "resolved no longer answers: {said}");
    assert_eq!(others(), before, "another link changed when kithd stopped");
}
