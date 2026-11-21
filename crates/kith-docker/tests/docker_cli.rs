//! The real `docker` command against `kith docker serve`'s socket: `docker version` and
//! `docker info` through DOCKER_HOST. Skipped, with the reason printed, where docker is not installed.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DOCKER: &str = "/usr/bin/docker";

/// `docker ARGS` against `socket`, with no config of the user's in the way; (success, stdout, stderr).
fn docker(socket: &Path, config: &Path, args: &[&str]) -> (bool, String, String) {
    let mut child = Command::new(DOCKER)
        .args(args)
        .env("DOCKER_HOST", format!("unix://{}", socket.display()))
        .env("DOCKER_CONFIG", config)
        .env_remove("DOCKER_API_VERSION")
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_TLS_VERIFY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A server that hangs is a failure, not a test that never ends.
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("docker {args:?} did not finish in 60 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kith-docker-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn docker_version_and_docker_info_answer_through_the_socket() {
    if !Path::new(DOCKER).exists() {
        eprintln!("skipping: {DOCKER} is not installed");
        return;
    }
    let dir = scratch();
    let config = dir.join("config");
    std::fs::create_dir_all(&config).unwrap();
    let socket = dir.join("docker.sock");
    let listener = kith_docker::listen(&socket).unwrap();
    std::thread::spawn(move || kith_docker::serve(listener));

    let (ok, out, err) = docker(&socket, &config, &["version"]);
    assert!(ok, "docker version failed: {err}");
    assert!(
        out.contains("Server:") && out.contains("1.47"),
        "docker version printed: {out}"
    );

    let (ok, out, err) = docker(&socket, &config, &["version", "--format", "{{.Server.APIVersion}}"]);
    assert!(ok, "docker version --format failed: {err}");
    assert_eq!(out.trim(), "1.47");

    let (ok, out, err) = docker(&socket, &config, &["info"]);
    assert!(ok, "docker info failed: {err}");
    assert!(
        out.contains("Server Version:") && out.contains("Operating System: kith"),
        "docker info printed: {out}"
    );

    // What kith does not serve is said, not hung on.
    let (ok, _, err) = docker(&socket, &config, &["ps"]);
    assert!(!ok && err.contains("not supported"), "docker ps said: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}
