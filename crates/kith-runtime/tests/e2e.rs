//! PLAN.md §10 task 4, end to end: pull a real image and run it in a cgroup.
//!
//! Needs a registry, unprivileged user namespaces and a delegated cgroup, so
//! it only runs when asked: `KITH_E2E=1 cargo test -p kith-runtime --test e2e`.

use kith_runtime::{PullPolicy, Runtime, Unit};
use std::fs::{self, File};
use std::path::Path;

/// Docker Hub's busybox through Google's mirror, which does not rate-limit anonymous pulls as hard.
const IMAGE: &str = "mirror.gcr.io/library/busybox:1.36";

/// Run `sh -c script` to completion; returns (exit code, stdout, stderr).
fn sh(rt: &Runtime, image: &kith_runtime::Image, dir: &Path, id: &str, unit: Unit) -> (i32, String, String) {
    let (out, err) = (dir.join(format!("{id}.out")), dir.join(format!("{id}.err")));
    let mut c = rt
        .create(
            id,
            image,
            &unit,
            File::create(&out).unwrap(),
            File::create(&err).unwrap(),
        )
        .unwrap();
    c.start().unwrap();
    let code = c.wait().unwrap();
    c.delete().unwrap();
    (code, fs::read_to_string(out).unwrap(), fs::read_to_string(err).unwrap())
}

fn script(s: &str) -> Unit {
    Unit {
        command: vec!["sh".into(), "-c".into(), s.into()],
        ..Unit::default()
    }
}

/// A runtime of its own with the image pulled, or `None` (and "skipped") where this was not asked for.
async fn rig(name: &str) -> Option<(Runtime, kith_runtime::Image, std::path::PathBuf)> {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1 to run");
        return None;
    }
    let image_ref = std::env::var("KITH_E2E_IMAGE").unwrap_or(IMAGE.into());
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("e2e-{name}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let rt = Runtime::new(dir.join("runtime")).unwrap();
    let image = rt.images.pull(&image_ref, PullPolicy::IfNotPresent).await.unwrap();
    Some((rt, image, dir))
}

/// What every container gets with nothing said: no way to more privileges, no user 0, no capabilities.
#[tokio::test]
async fn hardened() {
    let Some((rt, image, dir)) = rig("hardened").await else {
        return;
    };
    let look = "grep -E 'NoNewPrivs|CapEff|CapBnd' /proc/self/status | tr -s '\\t' ' '; id -u; id -g";
    let (code, out, err) = sh(&rt, &image, &dir, "plain", script(look));
    let none = "0000000000000000";
    assert_eq!(
        (code, out.as_str()),
        (
            0,
            format!("CapEff: {none}\nCapBnd: {none}\nNoNewPrivs: 1\n65534\n65534\n").as_str()
        ),
        "{err}"
    );
    // (No setuid program is run here. What would stop one is read: NoNewPrivs above, and
    // that there is no user 0 in the container for one to become.)
    let (_, out, _) = sh(
        &rt,
        &image,
        &dir,
        "nobody-else",
        script("cat /proc/self/uid_map | wc -l"),
    );
    assert_eq!(out, "1\n", "one user is mapped into the container, and it is not 0");

    // The template may say which user, 0 included; still no way to more.
    let unit = Unit {
        user: Some(1000),
        ..script("id -u; touch /tmp/mine && stat -c %u /tmp/mine")
    };
    assert_eq!(sh(&rt, &image, &dir, "said", unit).1, "1000\n1000\n");
    let unit = Unit {
        user: Some(0),
        ..script("id -u; grep NoNewPrivs /proc/self/status | tr -s '\\t' ' '")
    };
    assert_eq!(sh(&rt, &image, &dir, "root", unit).1, "0\nNoNewPrivs: 1\n");
    fs::remove_dir_all(&dir).unwrap();
}

/// A call the filter refuses fails in a container; allowed back by name, or with no filter,
/// it does not. (A user namespace is what anyone may make, where nothing is in the way.)
#[tokio::test]
async fn seccomp() {
    let Some((rt, image, dir)) = rig("seccomp").await else {
        return;
    };
    let look = "grep Seccomp: /proc/self/status | tr -s '\\t' ' '; unshare -U true";
    let (code, out, err) = sh(&rt, &image, &dir, "filtered", script(look));
    assert_eq!((code != 0, out.as_str()), (true, "Seccomp: 2\n"), "{err}");
    assert!(err.contains("Operation not permitted"), "{err}");

    let unit = Unit {
        allow: vec!["unshare".into()],
        ..script(look)
    };
    let (code, out, err) = sh(&rt, &image, &dir, "allowed", unit);
    assert_eq!((code, out.as_str()), (0, "Seccomp: 2\n"), "{err}");
    let unit = Unit {
        unconfined: true,
        ..script(look)
    };
    let (code, out, err) = sh(&rt, &image, &dir, "unconfined", unit);
    assert_eq!((code, out.as_str()), (0, "Seccomp: 0\n"), "{err}");

    // A name that is no refused call is a mistake found before anything starts.
    let unit = Unit {
        allow: vec!["unshar".into()],
        ..script("true")
    };
    let (out, err) = (
        fs::File::create(dir.join("o")).unwrap(),
        fs::File::create(dir.join("e")).unwrap(),
    );
    let said = rt
        .create("misnamed", &image, &unit, out, err)
        .err()
        .map(|e| e.to_string());
    assert!(
        said.as_ref()
            .is_some_and(|said| said.contains("`unshar` is not a call the filter refuses")),
        "{said:?}"
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// The image is nobody's to write: only volumes and the two tmpfs are.
#[tokio::test]
async fn read_only_root() {
    let Some((rt, image, dir)) = rig("read-only-root").await else {
        return;
    };
    let kept = dir.join("kept");
    fs::create_dir_all(&kept).unwrap();
    let tries = "for at in /x /etc/x /bin/x /tmp/x /run/x /kept/x; do touch $at 2>/dev/null; echo $at $?; done";
    for (id, user) in [("as-nobody", None), ("as-root", Some(0))] {
        let mount = kith_runtime::Mount {
            host: kept.clone(),
            container: "/kept".into(),
            read_only: false,
            give: true,
        };
        let unit = Unit {
            user,
            mounts: vec![mount],
            ..script(tries)
        };
        let (_, out, err) = sh(&rt, &image, &dir, id, unit);
        assert_eq!(
            out, "/x 1\n/etc/x 1\n/bin/x 1\n/tmp/x 0\n/run/x 0\n/kept/x 0\n",
            "{id}: {err}"
        );
    }
    assert!(!image.rootfs.join("x").exists() && kept.join("x").exists());
    fs::remove_dir_all(&dir).unwrap();
}

/// A container that asks has a root of its own to write: what it writes is there for it,
/// never in the image, not in another container of the image, and gone with it.
#[tokio::test]
async fn writable_root() {
    let Some((rt, image, dir)) = rig("writable-root").await else {
        return;
    };
    let writes = "echo mine > /etc/x && mkdir -p /srv/a/b && rm /bin/true && cat /etc/x; ls /bin/true 2>&1 | wc -l";
    let unit = Unit {
        writable: true,
        as_image: true,
        ..script(writes)
    };
    // (Not every kernel lets a user namespace mount an overlay: where kithd is root it can.)
    let (out, err) = (dir.join("o"), dir.join("e"));
    let files = || (File::create(&out).unwrap(), File::create(&err).unwrap());
    let (o, e) = files();
    match rt.create("can", &image, &unit, o, e) {
        Ok(made) => made.delete().unwrap(),
        Err(e) => {
            eprintln!("skipped: no overlay for this user here: {e}");
            return fs::remove_dir_all(&dir).unwrap();
        }
    }
    let (code, out, err) = sh(&rt, &image, &dir, "writes", unit.clone());
    assert_eq!((code, out.as_str()), (0, "mine\n1\n"), "{err}");
    assert!(!image.rootfs.join("etc/x").exists() && image.rootfs.join("bin/true").exists());
    // The next one starts from the image again.
    let again = Unit {
        writable: true,
        ..script("ls /etc/x /srv/a 2>/dev/null | wc -l; ls /bin/true")
    };
    let (_, out, err) = sh(&rt, &image, &dir, "again", again);
    assert_eq!(out, "0\n/bin/true\n", "{err}");
    assert!(!dir.join("runtime/containers/writes").exists());
    fs::remove_dir_all(&dir).unwrap();
}

/// A container's output is its own by name too: an image that opens /dev/stdout writes there.
#[tokio::test]
async fn output_by_name() {
    let Some((rt, image, dir)) = rig("output-by-name").await else {
        return;
    };
    let named = script("echo by name > /dev/stdout; echo too > /proc/self/fd/2");
    let (code, out, err) = sh(&rt, &image, &dir, "named", named);
    assert_eq!((code, out.as_str(), err.as_str()), (0, "by name\n", "too\n"));
    fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn pull_and_run() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1 to run");
        return;
    }
    let image_ref = std::env::var("KITH_E2E_IMAGE").unwrap_or(IMAGE.into());
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("e2e-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let rt = Runtime::new(dir.join("runtime")).unwrap();

    // Pull: layers land in the content-addressed store; pulling again downloads nothing.
    let never = rt.images.pull(&image_ref, PullPolicy::Never).await;
    assert!(never.is_err(), "nothing is here yet");
    let image = rt.images.pull(&image_ref, PullPolicy::IfNotPresent).await.unwrap();
    assert!(image.downloaded >= 1 && !image.from_cache);
    assert!(image.rootfs.join("bin/sh").exists());
    let blobs = fs::read_dir(dir.join("runtime/blobs/sha256")).unwrap().count();
    assert_eq!(blobs, image.downloaded);
    let again = rt.images.pull(&image_ref, PullPolicy::Always).await.unwrap();
    assert_eq!(
        (again.downloaded, &again.digest, &again.rootfs, again.from_cache),
        (0, &image.digest, &image.rootfs, false)
    );
    // A reference pulled before needs no registry: same image, straight from the store.
    for policy in [PullPolicy::IfNotPresent, PullPolicy::Never] {
        let cached = rt.images.pull(&image_ref, policy).await.unwrap();
        assert!(cached.from_cache);
        assert_eq!(
            (
                &cached.digest,
                &cached.rootfs,
                &cached.entrypoint,
                &cached.cmd,
                &cached.env
            ),
            (&image.digest, &image.rootfs, &image.entrypoint, &image.cmd, &image.env)
        );
    }

    // Create: the process sits in its own cgroup with the limits applied, not yet running.
    let unit = Unit {
        memory_bytes: Some(64 << 20),
        cpu_millis: Some(500),
        ..script("echo hello from $(hostname)")
    };
    let out = dir.join("limits.out");
    let mut c = rt
        .create(
            "limits",
            &image,
            &unit,
            File::create(&out).unwrap(),
            File::create(dir.join("e")).unwrap(),
        )
        .unwrap();
    let read = |file: &str| fs::read_to_string(c.cgroup.join(file)).unwrap();
    assert_eq!(read("memory.max").trim(), (64 << 20).to_string());
    assert_eq!(read("cpu.max").trim(), "50000 100000");
    assert_eq!(read("pids.max").trim(), "4096");
    assert_eq!(
        read("memory.swap.max").trim(),
        "0",
        "the memory limit is not stretched by swap"
    );
    assert_eq!(read("cgroup.procs").lines().count(), 1);
    assert_eq!(fs::read_to_string(&out).unwrap(), "", "created, not started");
    let cgroup = c.cgroup.clone();
    c.start().unwrap();
    assert_eq!(c.wait().unwrap(), 0);
    assert_eq!(fs::read_to_string(&out).unwrap(), "hello from limits\n");
    c.delete().unwrap();
    assert!(!cgroup.exists(), "delete removes the cgroup");
    assert!(!dir.join("runtime/containers/limits").exists());

    // Exit codes and stderr come back.
    let (code, out, err) = sh(&rt, &image, &dir, "exit", script("echo oops >&2; exit 7"));
    assert_eq!((code, out.as_str(), err.as_str()), (7, "", "oops\n"));

    // The image's own command runs when none is given; args alone keep the entrypoint.
    let (code, out, _) = sh(&rt, &image, &dir, "default", Unit::default());
    assert_eq!(
        (code, out.as_str()),
        (0, ""),
        "busybox's default command is `sh`, which exits at end of input"
    );

    // Environment: the image's PATH is there, ours is added, working dir applies.
    let unit = Unit {
        env: vec![("GREETING".into(), "hi".into())],
        working_dir: Some("/etc".into()),
        ..script("echo $GREETING $PWD; which sh")
    };
    let (_, out, _) = sh(&rt, &image, &dir, "env", unit);
    assert_eq!(out, "hi /etc\n/bin/sh\n");

    // Isolation: read-only image, writable /tmp, its own PID namespace, nobody inside.
    let (code, out, _) = sh(
        &rt,
        &image,
        &dir,
        "iso",
        script("touch /x 2>/dev/null; echo $?; touch /tmp/x; echo $?; echo $$; id -u"),
    );
    assert_eq!((code, out.as_str()), (0, "1\n0\n1\n65534\n"));
    assert!(!image.rootfs.join("x").exists());

    // A container killed by a signal reports 128 + signal.
    let mut c = rt
        .create(
            "killed",
            &image,
            &script("sleep 60"),
            File::create(dir.join("k")).unwrap(),
            File::create(dir.join("k2")).unwrap(),
        )
        .unwrap();
    c.start().unwrap();
    c.kill().unwrap();
    assert_eq!(c.wait().unwrap(), 137);
    c.delete().unwrap();

    // Bad ids never reach the filesystem.
    let bad = rt.create(
        "../escape",
        &image,
        &Unit::default(),
        File::create(dir.join("b")).unwrap(),
        File::create(dir.join("b2")).unwrap(),
    );
    assert!(bad.is_err());

    fs::remove_dir_all(&dir).unwrap();
}
