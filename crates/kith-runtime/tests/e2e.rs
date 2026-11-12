//! PLAN.md §10 task 4, end to end: pull a real image and run it in a cgroup.
//!
//! Needs a registry, unprivileged user namespaces and a delegated cgroup, so
//! it only runs when asked: `KITH_E2E=1 cargo test -p kith-runtime --test e2e`.

use kith_runtime::{Runtime, Unit};
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
    let image = rt.images.pull(&image_ref).await.unwrap();
    assert!(image.downloaded >= 1);
    assert!(image.rootfs.join("bin/sh").exists());
    let blobs = fs::read_dir(dir.join("runtime/blobs/sha256")).unwrap().count();
    assert_eq!(blobs, image.downloaded);
    let again = rt.images.pull(&image_ref).await.unwrap();
    assert_eq!(
        (again.downloaded, &again.digest, &again.rootfs),
        (0, &image.digest, &image.rootfs)
    );

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

    // Isolation: read-only image, writable /tmp, its own PID namespace, root only inside.
    let (code, out, _) = sh(
        &rt,
        &image,
        &dir,
        "iso",
        script("touch /x 2>/dev/null; echo $?; touch /tmp/x; echo $?; echo $$; id -u"),
    );
    assert_eq!((code, out.as_str()), (0, "1\n0\n1\n0\n"));
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
