//! `kith machine shell NAME [--root] [-- COMMAND]` (T-1243): kithd's exec on the machine's pod,
//! the Kubernetes WebSocket `kubectl exec -it` speaks (`v5.channel.k8s.io`: channel 0 stdin, 1
//! stdout, 2 stderr, 3 the Status that says how it ended, 4 the window), over the same `Wire` as
//! every other call, so a node reached with `--server` works as the socket does.
//!
//! On a terminal the process there runs on a terminal of its own: this one goes raw (put back
//! when the shell ends, and on a hangup or a kill), its window follows this one's (SIGWINCH), and
//! the shell's exit code is kith's. Without one (a pipe) it is the same on plain pipes.
//!
//! ponytail: the server's Sec-WebSocket-Accept is not checked (what answers is kithd, by its own
//! socket or its certificate); a frame sent in parts is refused (kithd sends none).

use crate::{Backend, Kithd, base64, connect, escape, fail};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::termios::{SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};
use std::io::{IsTerminal, Read, Write};
use std::os::fd::AsFd;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

const PROTOCOL: &str = "v5.channel.k8s.io";
/// The most one frame from kithd may hold (what it sends is a few KiB of output at a time).
const FRAME_MAX: usize = 1 << 20;
/// The most a refusal's reply is read: it is a Status.
const REFUSAL_MAX: usize = 64 << 10;
/// What `shell` runs when it is given no command: bash where the image has it.
const SHELL: &str = "if command -v bash >/dev/null 2>&1; then exec bash; else exec sh; fi";

// kithd's own frame code (one file, no dependency), so both ends of the wire read and write alike.
#[path = "../../../kithd/src/websocket/frame.rs"]
#[allow(dead_code, reason = "kithd's file: what it holds for the server's side is not used here")]
mod frame;
use frame::{Frame, Op};

/// One frame to kithd, masked as a client's are.
fn encode(op: Op, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut mask = [0u8; 4];
    SystemRandom::new()
        .fill(&mut mask)
        .or_else(|_| fail("no randomness for a frame's mask"))?;
    Ok(frame::encode(op, payload, Some(mask)))
}

/// The first whole frame in `buf` from kithd and how many bytes it took. None when more is to come.
fn decode(buf: &[u8]) -> Result<Option<(Frame, usize)>, String> {
    if buf.first().is_some_and(|first| first & 0x80 == 0) {
        return fail("kithd sent a frame in parts, which this kith cannot read");
    }
    match frame::decode(buf, false, FRAME_MAX) {
        Ok(Some((frame, _))) if frame.op == Op::Continue => fail("kithd sent a frame in parts, which this kith cannot read"),
        Ok(found) => Ok(found),
        Err(e) => fail(format!("kithd sent a frame this kith refuses: {e:?}")),
    }
}

/// The terminal as it was, put back when this is dropped.
struct Raw(Termios);

fn restore(saved: &Termios) {
    let _ = tcsetattr(std::io::stdin(), SetArg::TCSADRAIN, saved);
}

impl Raw {
    /// This terminal, raw: every key goes to the shell as it is, and ^C is one of them.
    fn make() -> Result<Raw, String> {
        let saved = tcgetattr(std::io::stdin()).or_else(|e| fail(format!("the terminal: {e}")))?;
        let mut raw = saved.clone();
        cfmakeraw(&mut raw);
        tcsetattr(std::io::stdin(), SetArg::TCSADRAIN, &raw).or_else(|e| fail(format!("the terminal: {e}")))?;
        Ok(Raw(saved))
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        restore(&self.0);
    }
}

/// What kithd's Status on channel 3 says: the shell's exit code, or why there is none.
fn outcome(status: &[u8]) -> Result<ExitCode, String> {
    let status: Value = serde_json::from_slice(status).or_else(|e| fail(format!("kithd's status: {e}")))?;
    if status["status"] == "Success" {
        return Ok(ExitCode::SUCCESS);
    }
    let code = status["details"]["causes"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|cause| cause["reason"] == "ExitCode")
        .and_then(|cause| cause["message"].as_str()?.parse::<i32>().ok());
    match code {
        // (A code outside a process's own range is a failure, never a success.)
        Some(code) => Ok(ExitCode::from(u8::try_from(code).unwrap_or(1))),
        None => fail(status["message"].as_str().unwrap_or("the command did not run")),
    }
}

/// What a reply that is not an upgrade says: a Status's message, or `{"error": …}`, or the text.
fn why(body: &[u8]) -> String {
    let said = serde_json::from_slice::<Value>(body).ok();
    let said = said.as_ref().and_then(|v| v["message"].as_str().or(v["error"].as_str()));
    said.map_or_else(|| String::from_utf8_lossy(body).trim().to_string(), String::from)
}

/// The request line and headers, then the reply's head (and the bytes that came after it, the
/// first of the frames): the upgrade, or why not.
fn upgrade(wire: &mut crate::wire::Wire, path: &str) -> Result<Vec<u8>, String> {
    let mut key = [0u8; 16];
    SystemRandom::new()
        .fill(&mut key)
        .or_else(|_| fail("no randomness for a WebSocket key"))?;
    let head = format!(
        "GET {path} HTTP/1.1\r\nHost: kithd\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Protocol: {PROTOCOL}\r\n\r\n",
        base64(&key)
    );
    wire.write_all(head.as_bytes()).or_else(|e| fail(format!("talking to kithd: {e}")))?;
    let (mut reply, mut chunk) = (Vec::new(), [0u8; 4096]);
    let split = loop {
        if let Some(at) = reply.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        if reply.len() > REFUSAL_MAX {
            return fail("kithd's reply has no end to its head");
        }
        match wire.read(&mut chunk) {
            Ok(0) => return fail("kithd closed the connection before it answered"),
            Ok(n) => reply.extend(&chunk[..n]),
            Err(e) => return fail(format!("talking to kithd: {e}")),
        }
    };
    let text = String::from_utf8_lossy(&reply[..split]).to_ascii_lowercase();
    let mut after = reply[split + 4..].to_vec();
    if text.split(' ').nth(1) == Some("101") {
        return Ok(after);
    }
    // Not an upgrade: its body (up to what its head says, as far as it is sent) says why.
    let length: usize = text
        .lines()
        .find_map(|line| line.strip_prefix("content-length:")?.trim().parse().ok())
        .unwrap_or(0)
        .min(REFUSAL_MAX);
    while after.len() < length {
        match wire.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => after.extend(&chunk[..n]),
        }
    }
    let code = text.split(' ').nth(1).unwrap_or("?");
    match why(&after) {
        said if said.is_empty() => fail(format!("kithd refused the shell ({code})")),
        said => fail(said),
    }
}

/// Sends `bytes` to kithd, one writer at a time: a frame is written whole.
fn send(to: &Mutex<crate::wire::Wire>, bytes: Vec<u8>) -> Result<(), String> {
    let mut wire = to.lock().unwrap_or_else(|e| e.into_inner());
    wire.write_all(&bytes)
        .and_then(|()| wire.flush())
        .or_else(|e| fail(format!("talking to kithd: {e}")))
}

fn channel(number: u8, data: &[u8]) -> Result<Vec<u8>, String> {
    encode(Op::Binary, &[&[number][..], data].concat())
}

/// This terminal's size as channel 4 says it (none while it says 0 by 0, or cannot say).
fn size() -> Option<Vec<u8>> {
    let (rows, cols) = kith_dm_sys::window(std::io::stdout().as_fd()).ok()?;
    (rows > 0 && cols > 0).then(|| channel(4, json!({"Width": cols, "Height": rows}).to_string().as_bytes()).ok())?
}

/// A shell in machine `name`'s container, as root of its own user namespace with `root`.
pub fn shell(backend: &Backend, name: &str, root: bool, argv: Vec<String>) -> Result<ExitCode, String> {
    super::find(backend, name)?;
    let Backend::Daemon(kithd) = backend else {
        return fail("a shell is a connection to kithd: not with --store");
    };
    run(kithd, name, root, argv)
}

fn run(kithd: &Kithd, name: &str, root: bool, argv: Vec<String>) -> Result<ExitCode, String> {
    // A terminal on both ends makes it a terminal there; a pipe makes it a pipe.
    let tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let argv = if argv.is_empty() {
        vec!["sh".to_string(), "-c".to_string(), SHELL.to_string()]
    } else {
        argv
    };
    let mut query = vec![format!("tty={tty}"), "stdin=true".into(), "stdout=true".into()];
    if !tty {
        query.push("stderr=true".into());
    }
    if root {
        query.push("root=true".into());
    }
    query.extend(argv.iter().map(|word| format!("command={}", escape(word))));
    let path = format!(
        "/api/v1/namespaces/{}/pods/{}-0/exec?{}",
        crate::DEFAULT_NAMESPACE,
        escape(name),
        query.join("&")
    );
    let mut wire = connect(kithd)?;
    let mut buf = upgrade(&mut wire, &path)?;
    // A shell is idle as long as its user is: there is no timeout on it (the terminal's hangup ends it).
    wire.set_patience(None).or_else(|e| fail(format!("talking to kithd: {e}")))?;
    let to = Arc::new(Mutex::new(wire.dup().or_else(|e| fail(format!("talking to kithd: {e}")))?));

    // Signals are taken by a thread of their own (blocked here, before any other thread is made):
    // the window follows, and a hangup or a kill puts the terminal back before it ends this.
    let guard = if tty {
        let mut set = SigSet::empty();
        for signal in [Signal::SIGWINCH, Signal::SIGHUP, Signal::SIGTERM, Signal::SIGINT, Signal::SIGQUIT] {
            set.add(signal);
        }
        set.thread_block().or_else(|e| fail(format!("signals: {e}")))?;
        let raw = Raw::make()?;
        // (Moved into the thread: a Termios is Send, not Sync.)
        let (saved, winch) = (raw.0.clone(), to.clone());
        std::thread::spawn(move || {
            while let Ok(signal) = set.wait() {
                match signal {
                    Signal::SIGWINCH => {
                        if let Some(frame) = size() {
                            let _ = send(&winch, frame);
                        }
                    }
                    other => {
                        restore(&saved);
                        std::process::exit(128 + other as i32);
                    }
                }
            }
        });
        if let Some(frame) = size() {
            send(&to, frame)?;
        }
        Some(raw)
    } else {
        None
    };

    // What is typed (or piped) goes to channel 0; its end is `[255, 0]`.
    let keys = to.clone();
    std::thread::spawn(move || {
        let (mut stdin, mut chunk) = (std::io::stdin(), [0u8; 4096]);
        loop {
            let sent = match stdin.read(&mut chunk) {
                Ok(n @ 1..) => channel(0, &chunk[..n]).and_then(|frame| send(&keys, frame)),
                _ => {
                    let _ = channel(255, &[0]).and_then(|frame| send(&keys, frame));
                    return;
                }
            };
            if sent.is_err() {
                return;
            }
        }
    });

    let result = pump(&mut wire, &to, &mut buf);
    drop(guard);
    result
}

/// What kithd sends, until the Status that ends it: output to this one's, a ping answered.
fn pump(wire: &mut crate::wire::Wire, to: &Mutex<crate::wire::Wire>, buf: &mut Vec<u8>) -> Result<ExitCode, String> {
    let (mut stdout, mut stderr, mut chunk) = (std::io::stdout(), std::io::stderr(), [0u8; 8192]);
    let mut ended = None;
    'read: loop {
        while let Some((Frame { op, payload }, used)) = decode(buf)? {
            buf.drain(..used);
            match (op, payload.split_first()) {
                (Op::Close, _) => break 'read,
                (Op::Ping, _) => send(to, encode(Op::Pong, &payload)?)?,
                (Op::Text | Op::Binary, Some((1, data))) => {
                    stdout.write_all(data).and_then(|()| stdout.flush()).or_else(|e| fail(format!("stdout: {e}")))?;
                }
                (Op::Text | Op::Binary, Some((2, data))) => {
                    stderr.write_all(data).or_else(|e| fail(format!("stderr: {e}")))?;
                }
                (Op::Text | Op::Binary, Some((3, status))) => {
                    ended = Some(outcome(status));
                    break 'read;
                }
                _ => {}
            }
        }
        match wire.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend(&chunk[..n]),
            Err(e) => return fail(format!("talking to kithd: {e}")),
        }
    }
    // Say goodbye (kithd waits for it before it shuts the connection) and be done.
    let _ = encode(Op::Close, &frame::close_body(1000, "")).and_then(|frame| send(to, frame));
    wire.end();
    ended.unwrap_or_else(|| fail("kithd ended the session before the command did"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_stay_masked_and_bounded() {
        let sent = encode(Op::Binary, b"\x00hello").unwrap();
        assert_eq!(sent[0], 0x82);
        assert_eq!(sent[1], 0x80 | 6, "a client's frame is masked");
        let unmasked: Vec<u8> = sent[6..].iter().enumerate().map(|(i, b)| b ^ sent[2 + i % 4]).collect();
        assert_eq!(unmasked, b"\x00hello");
        // What kithd sends is not masked; a half frame waits, a long one is refused.
        let from_server = [&[0x82, 3][..], b"\x01ab"].concat();
        assert_eq!(
            decode(&from_server).unwrap(),
            Some((Frame { op: Op::Binary, payload: b"\x01ab".to_vec() }, 5))
        );
        assert_eq!(decode(&from_server[..4]).unwrap(), None);
        assert!(decode(&[0x82, 127, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff]).is_err());
        assert!(decode(&[0x02, 1, 0]).is_err(), "a part of a message");
        assert!(decode(&[0x82, 0x81, 0, 0, 0, 0, 1]).is_err(), "a masked frame from the server");
    }

    #[test]
    fn the_status_says_the_exit_code_or_the_reason() {
        let status = |v: Value| outcome(v.to_string().as_bytes());
        assert_eq!(status(json!({"status": "Success"})).unwrap(), ExitCode::SUCCESS);
        let failed = json!({"status": "Failure", "details": {"causes": [{"reason": "ExitCode", "message": "7"}]}});
        assert_eq!(status(failed).unwrap(), ExitCode::from(7));
        let too_big = json!({"status": "Failure", "details": {"causes": [{"reason": "ExitCode", "message": "256"}]}});
        assert_eq!(status(too_big).unwrap(), ExitCode::from(1));
        let refused = status(json!({"status": "Failure", "message": "--root is refused: no"}));
        assert_eq!(refused.unwrap_err(), "error: --root is refused: no");
    }
}
