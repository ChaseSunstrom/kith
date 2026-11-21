//! `kith docker serve` makes a 0600 socket that answers the Docker API. Built only with `--features docker`.
#![cfg(feature = "docker")]

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
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
