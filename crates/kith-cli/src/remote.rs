//! `kith run --on NODE|SELECTOR [--via PROGRAM] -- APP [ARGS…]`: an app on another node,
//! its window on this one.
//!
//! Asks kithd for a byte tunnel (`POST /v1/run`, answered `101`), starts `VIA --socket L
//! client` here (VIA is `waypipe` unless said) and joins L to the tunnel. On the node, kithd
//! starts `VIA --socket S server -- APP…` and joins S to its end. kith does not ship waypipe:
//! it must be installed on both ends.

use super::{Kithd, fail};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

/// A directory only this user can enter, with a name nobody can guess, gone when dropped.
// ponytail: an interrupt (Ctrl-C) ends the process without running this, and leaves the empty
// directory in the temp dir; handling signals needs a dependency or unsafe.
struct Dir(PathBuf);

impl Dir {
    fn make() -> Result<Dir, String> {
        let mut random = [0u8; 16];
        let read = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut random));
        read.or_else(|e| fail(format!("no random numbers: {e}")))?;
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("kith-run-{name}"));
        let made = std::fs::DirBuilder::new().mode(0o700).create(&path);
        made.or_else(|e| fail(format!("cannot make {}: {e}", path.display())))?;
        Ok(Dir(path))
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// The local VIA, killed and waited for when dropped.
struct Client(Child);

impl Drop for Client {
    fn drop(&mut self) {
        drop(self.0.kill());
        drop(self.0.wait());
    }
}

/// Asks kithd for the tunnel: the connection, once kithd has answered `101`.
fn open(kithd: &Kithd, body: &serde_json::Value) -> Result<UnixStream, String> {
    let socket = &kithd.socket;
    let mut stream = UnixStream::connect(socket)
        .or_else(|e| fail(format!("cannot reach kithd at {}: {e}\nStart kithd.", socket.display())))?;
    let _ = stream.set_read_timeout(Some(kithd.timeout));
    let body = body.to_string();
    let head = format!(
        "POST /v1/run HTTP/1.1\r\nHost: kithd\r\nConnection: Upgrade\r\nUpgrade: kith-run\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let sent = stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()));
    sent.or_else(|e| fail(format!("talking to kithd: {e}")))?;
    // One byte at a time: whatever follows the head is the tunnel's, and is not ours to read.
    let mut reply = Vec::new();
    while !reply.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8];
        let got = stream
            .read(&mut byte)
            .map_err(|e| format!("error: kithd has not answered: {e}"))?;
        if got == 0 || reply.len() > 16 << 10 {
            return fail("kithd sent no reply");
        }
        reply.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&reply).into_owned();
    if head.split(' ').nth(1) == Some("101") {
        let _ = stream.set_read_timeout(None);
        return Ok(stream);
    }
    // An API error is `{"error": "..."}` with its length given.
    let lower = head.to_ascii_lowercase();
    let length = lower
        .split("content-length:")
        .nth(1)
        .and_then(|rest| rest.lines().next());
    let length: usize = length.and_then(|n| n.trim().parse().ok()).unwrap_or(0).min(64 << 10);
    let mut body = vec![0; length];
    let _ = stream.read_exact(&mut body);
    let said = serde_json::from_slice::<serde_json::Value>(&body).ok();
    let said = said.as_ref().and_then(|m| m["error"].as_str()).map(String::from);
    let said = said.unwrap_or_else(|| head.lines().next().unwrap_or("kithd refused").to_string());
    // (What another node said is passed on as it came: nothing of it steers this terminal.)
    fail(said.chars().filter(|c| !c.is_control()).collect::<String>())
}

/// What this screen's compositor is told the app's windows are, where it takes the word
/// (Wayland's security-context-v1, which waypipe speaks when given `--secctx`): those of a
/// sandboxed program, kept from what the compositor keeps such a one from (reading the
/// screen, typing as the user). The word is the context's app id.
const TAG: &str = "dev.kith.run";

/// Starts the local VIA and waits for it to listen: with the tag, and where it does not come
/// up so (a waypipe before 0.9, a compositor without the protocol, another program),
/// without it, and why.
fn carried(program: &str, dir: &Path) -> Result<(Client, UnixStream, Option<String>), String> {
    let start = |tag: Option<&str>| -> Result<(Client, UnixStream), String> {
        let socket = dir.join(if tag.is_some() { "t" } else { "c" });
        let mut command = Command::new(program);
        if let Some(tag) = tag {
            command.arg("--secctx").arg(tag);
        }
        let spawned = command
            .arg("--socket")
            .arg(&socket)
            .arg("client")
            .stdin(Stdio::null())
            .spawn();
        let mut client = Client(spawned.or_else(|e| match e.kind() {
            std::io::ErrorKind::NotFound => fail(format!("{program} is not installed here (kith does not ship it)")),
            _ => fail(format!("cannot start {program}: {e}")),
        })?);
        // The client listens on its socket a moment after it starts.
        let started = Instant::now();
        loop {
            match UnixStream::connect(&socket) {
                Ok(local) => return Ok((client, local)),
                Err(e) => {
                    if let Ok(Some(status)) = client.0.try_wait() {
                        return fail(format!("{program} stopped before it listened ({status})"));
                    }
                    if started.elapsed() > Duration::from_secs(5) {
                        return fail(format!("{program} did not listen on {}: {e}", socket.display()));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    };
    match start(Some(TAG)) {
        Ok((client, local)) => Ok((client, local, None)),
        Err(why) => start(None).map(|(client, local)| (client, local, Some(why))),
    }
}

pub fn run(kithd: &Kithd, on: &str, via: Option<&str>, argv: &[String]) -> Result<ExitCode, String> {
    let program = via.unwrap_or("waypipe");
    let dir = Dir::make()?;
    let (client, local, untagged) = carried(program, &dir.0)?;
    if let Some(why) = untagged {
        eprintln!(
            "kith: this screen is not told that the app's windows are a sandboxed program's: with --secctx, {why}"
        );
    }
    let body = serde_json::json!({ "on": on, "via": via, "argv": argv });
    let tunnel = open(kithd, &body)?;
    // Either end done ends both. (The app's own exit status does not come back.)
    let ends = |a: &UnixStream, b: &UnixStream| drop((a.shutdown(Shutdown::Both), b.shutdown(Shutdown::Both)));
    let (mut tunnel_in, mut local_out) = (
        tunnel.try_clone().map_err(|e| e.to_string())?,
        local.try_clone().map_err(|e| e.to_string())?,
    );
    let (mut local_in, mut tunnel_out) = (
        local.try_clone().map_err(|e| e.to_string())?,
        tunnel.try_clone().map_err(|e| e.to_string())?,
    );
    let (a, b) = (
        local.try_clone().map_err(|e| e.to_string())?,
        tunnel.try_clone().map_err(|e| e.to_string())?,
    );
    let up = std::thread::spawn(move || {
        drop(std::io::copy(&mut local_in, &mut tunnel_out));
        ends(&a, &b);
    });
    drop(std::io::copy(&mut tunnel_in, &mut local_out));
    ends(&local, &tunnel);
    drop(up.join());
    drop(client);
    drop(dir);
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::OnceLock;

    /// What `waypipe client` would be here: listens on its socket, answers one line, in
    /// capitals, after the tag it was started with. Under a name that ends in `-old` it is a
    /// waypipe from before there was a tag: it stops at the word.
    const STAND_IN: &str = r#"#!/usr/bin/env python3
import socket, sys
args, tag = sys.argv[1:], b""
if args[0] == "--secctx" and not sys.argv[0].endswith("-old"):
    tag, args = args[1].encode() + b" ", args[2:]
if args[0] != "--socket" or args[2:] != ["client"]:
    sys.exit(3)
s = socket.socket(socket.AF_UNIX)
s.bind(args[1])
s.listen(1)
c, _ = s.accept()
c.sendall(tag + c.makefile("rb").readline().upper())
"#;

    fn stand_in_named(end: &str) -> String {
        let path = std::env::temp_dir().join(format!("kith-cli-run-on-stand-in-{}{end}", std::process::id()));
        std::fs::write(&path, STAND_IN).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    fn stand_in() -> &'static str {
        static PATH: OnceLock<String> = OnceLock::new();
        PATH.get_or_init(|| stand_in_named(""))
    }

    /// The windows are tagged where the carrier takes the word; where it does not, the app
    /// still comes up, and `kith run` has the reason to say.
    #[test]
    fn sandbox_tag_is_given_to_the_carrier_and_its_absence_is_said() {
        let dir = Dir::make().unwrap();
        let (_client, mut local, untagged) = carried(stand_in(), &dir.0).unwrap();
        assert_eq!(untagged, None);
        local.write_all(b"hello\n").unwrap();
        let mut answer = String::new();
        local.read_to_string(&mut answer).unwrap();
        assert_eq!(answer, "dev.kith.run HELLO\n");

        let (dir, old) = (Dir::make().unwrap(), stand_in_named("-old"));
        let (_client, mut local, untagged) = carried(&old, &dir.0).unwrap();
        let why = untagged.expect("an old carrier does not take the tag");
        assert!(why.contains("stopped before it listened (exit status: 3)"), "{why}");
        local.write_all(b"hello\n").unwrap();
        let mut answer = String::new();
        local.read_to_string(&mut answer).unwrap();
        assert_eq!(answer, "HELLO\n");
        std::fs::remove_file(old).unwrap();
    }

    /// A kithd that answers `reply` to one request, and returns what it was asked (head and body)
    /// and, after a 101, what came through the tunnel after it had said "hello".
    fn fake_kithd(tag: &str, reply: &'static str) -> (Kithd, std::thread::JoinHandle<(String, String)>) {
        let path = std::env::temp_dir().join(format!("kith-cli-run-on-{tag}-{}.sock", std::process::id()));
        drop(std::fs::remove_file(&path));
        let listener = UnixListener::bind(&path).unwrap();
        let kithd = Kithd {
            socket: path,
            timeout: Duration::from_secs(10),
        };
        let served = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8];
                conn.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            let head = String::from_utf8(head).unwrap();
            let length = head
                .to_ascii_lowercase()
                .split("content-length: ")
                .nth(1)
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let mut body = vec![0; length];
            conn.read_exact(&mut body).unwrap();
            conn.write_all(reply.as_bytes()).unwrap();
            let mut through = String::new();
            if reply.starts_with("HTTP/1.1 101") {
                conn.write_all(b"hello\n").unwrap();
                conn.read_to_string(&mut through).unwrap();
            }
            (format!("{head}{}", String::from_utf8(body).unwrap()), through)
        });
        (kithd, served)
    }

    const SWITCH: &str = "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: kith-run\r\n\r\n";

    #[test]
    fn run_on_joins_the_local_client_to_the_tunnel() {
        let (kithd, served) = fake_kithd("tunnel", SWITCH);
        let argv = ["two words".to_string(), "$(touch pwned)".to_string()];
        let code = run(&kithd, "role=display", Some(stand_in()), &argv).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
        let (asked, through) = served.join().unwrap();
        assert!(asked.starts_with("POST /v1/run HTTP/1.1\r\n"), "{asked}");
        assert!(asked.to_ascii_lowercase().contains("upgrade: kith-run"), "{asked}");
        let body: serde_json::Value = serde_json::from_str(asked.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        let via = stand_in();
        assert_eq!(
            body,
            serde_json::json!({"on": "role=display", "via": via, "argv": argv})
        );
        // "hello" went to the client, which answered in capitals.
        assert_eq!(through, "dev.kith.run HELLO\n");
    }

    #[test]
    fn run_on_says_why_kithd_refused() {
        let reply = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: 41\r\n\r\n{\"error\":\"bob may not apply Job in here\"}";
        let (kithd, served) = fake_kithd("refused", reply);
        let said = run(&kithd, "b", Some(stand_in()), &["true".to_string()]).unwrap_err();
        assert_eq!(said, "error: bob may not apply Job in here");
        drop(served.join());
    }

    #[test]
    fn run_on_names_the_program_it_cannot_find_before_asking_kithd() {
        let kithd = Kithd {
            socket: "/nonexistent/kithd.sock".into(),
            timeout: Duration::from_secs(1),
        };
        let said = run(&kithd, "b", Some("/nonexistent/waypipe"), &["true".to_string()]).unwrap_err();
        assert!(said.contains("/nonexistent/waypipe is not installed here"), "{said}");
    }
}
