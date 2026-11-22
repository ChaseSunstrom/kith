//! The terminal of an exec (`kubectl exec -it`, `kith exec -it`): the master side of the pty its
//! process runs on, read for what the process writes, written for what the client types, and sized
//! by channel 4's `{"Width": W, "Height": H}`. The master is non-blocking, in tokio's reactor.

use serde::Deserialize;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The master of a process's terminal. Clones share it.
#[derive(Clone)]
pub(super) struct Pty(Arc<AsyncFd<File>>);

/// What channel 4 says: the window's size in characters.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Window {
    width: u16,
    height: u16,
}

impl Pty {
    pub(super) fn new(master: File) -> io::Result<Pty> {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        fcntl(master.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
        // (`register` is unsafe, and this crate forbids it; `new` is the same call, deprecated for the
        // reason that the caller must give a descriptor it owns, as a `File` is.)
        #[allow(deprecated)]
        let fd = AsyncFd::new(master)?;
        Ok(Pty(Arc::new(fd)))
    }

    /// Sizes the window as a resize message of channel 4 says. (A message that is no size is no change.)
    pub(super) fn resize(&self, message: &[u8]) {
        if let Ok(Window { width, height }) = serde_json::from_slice(message) {
            let _ = kith_dm_sys::set_window(self.0.get_ref(), height, width);
        }
    }
}

impl AsyncRead for Pty {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut ready = ready!(self.0.poll_read_ready(cx))?;
            if let Ok(read) = ready.try_io(|fd| fd.get_ref().read(buf.initialize_unfilled())) {
                buf.advance(read?);
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl AsyncWrite for Pty {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut ready = ready!(self.0.poll_write_ready(cx))?;
            if let Ok(wrote) = ready.try_io(|fd| fd.get_ref().write(buf)) {
                return Poll::Ready(wrote);
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use std::path::Path;
    use std::time::Instant;
    use tokio::io::DuplexStream;

    /// An exec session as its client sees it: what the process wrote on channel 1 so far, and
    /// the frames not yet read.
    struct Client {
        io: DuplexStream,
        buf: Vec<u8>,
        out: String,
    }

    /// Runs `script` under `sh` on a terminal of 24 rows by 80 columns as an exec session.
    fn session(script: &str) -> (Client, i32, tokio::task::JoinHandle<()>) {
        let run = Entered::on_host(&["sh", "-c", script], Some((24, 80))).expect("a process on a pty");
        let pid = run.pid();
        let (server, io) = tokio::io::duplex(1 << 16);
        let (stop, _) = watch::channel(false);
        let serving = tokio::spawn(async move {
            let (from, to) = tokio::io::split(server);
            pump(from, &Mutex::new(to), run, true, stop.subscribe()).await;
        });
        let client = Client {
            io,
            buf: Vec::new(),
            out: String::new(),
        };
        (client, pid, serving)
    }

    impl Client {
        async fn say(&mut self, channel: u8, bytes: &[u8]) {
            let body = [&[channel][..], bytes].concat();
            let masked = websocket::encode(Op::Binary, &body, Some([5, 6, 7, 8]));
            self.io.write_all(&masked).await.unwrap();
        }

        /// Reads on until the output holds `needle` or the Status comes; that, if it did.
        async fn until(&mut self, needle: &str) -> Option<Value> {
            tokio::time::timeout(Duration::from_secs(10), async {
                let mut out = Vec::new();
                while !self.out.contains(needle) {
                    match websocket::decode(&self.buf, false, FRAME_MAX) {
                        Ok(Some((frame, used))) => {
                            self.buf.drain(..used);
                            match (frame.op, frame.payload.split_first()) {
                                (Op::Binary, Some((1, data))) => {
                                    out.extend_from_slice(data);
                                    self.out.push_str(&String::from_utf8_lossy(&std::mem::take(&mut out)));
                                }
                                (Op::Binary, Some((3, status))) => return serde_json::from_slice(status).ok(),
                                _ => {}
                            }
                        }
                        _ => {
                            let mut chunk = [0u8; 4096];
                            let n = self.io.read(&mut chunk).await.unwrap();
                            assert!(n > 0, "the session ended before {needle:?}: {:?}", self.out);
                            self.buf.extend_from_slice(&chunk[..n]);
                        }
                    }
                }
                None
            })
            .await
            .expect("what it was waiting for, in time")
        }

        async fn status(&mut self) -> Value {
            self.until("\0never").await.expect("the Status")
        }
    }

    async fn gone(pid: i32) -> bool {
        let until = Instant::now() + Duration::from_secs(5);
        while Path::new(&format!("/proc/{pid}")).exists() && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        !Path::new(&format!("/proc/{pid}")).exists()
    }

    /// The process has a terminal of its own, reads what the client types from it (the line
    /// discipline echoes it, and ends its lines with CR LF), and what it writes comes on channel 1.
    #[tokio::test]
    async fn exec_tty_gives_the_process_a_terminal_that_reads_and_writes() {
        let (mut client, _, _serving) = session("test -t 0 && test -t 1 && echo isatty; read l; echo got:$l");
        client.say(0, b"hi\n").await;
        let status = client.status().await;
        let out = &client.out;
        assert!(out.contains("isatty"), "{out:?}");
        assert!(out.contains("got:hi"), "{out:?}");
        assert!(out.contains("\r\n"), "a terminal ends its lines with CR LF: {out:?}");
        assert_eq!(status["status"], "Success", "{status}");
    }

    /// The terminal has the size it was made with, and channel 4's resize sets the window's.
    #[tokio::test]
    async fn exec_tty_resize_on_channel_4_sets_the_window() {
        let (mut client, _, _serving) = session("stty size; read l; stty size; read l; stty size");
        assert!(client.until("24 80").await.is_none());
        client.say(4, br#"{"Width":132,"Height":43}"#).await;
        client.say(0, b"\n").await;
        assert!(client.until("43 132").await.is_none());
        // (A message that is no size changes nothing.)
        client.say(4, b"not a size").await;
        client.say(0, b"\n").await;
        client.status().await;
        assert_eq!(client.out.matches("43 132").count(), 2, "{:?}", client.out);
    }

    /// The exit status comes back as the Status, the way a pipe session's does.
    #[tokio::test]
    async fn exec_tty_says_the_exit_status() {
        let (mut client, _, _serving) = session("exit 7");
        let status = client.status().await;
        assert_eq!(status["reason"], "NonZeroExitCode", "{status}");
        assert_eq!(status["details"]["causes"][0]["message"], "7");
    }

    /// A client that goes hangs the terminal up: the process is sent SIGHUP (a shell says its
    /// goodbye), and one that holds it off is killed once the grace is over.
    #[tokio::test]
    async fn exec_tty_hangs_up_when_the_client_goes() {
        let dir = std::env::temp_dir().join(format!("kith-tty-hup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let said = dir.join("said");
        let script = format!(
            "trap 'echo hup > {}; exit 0' HUP; echo ready; sleep 30 & wait",
            said.display()
        );
        let (mut client, pid, serving) = session(&script);
        // (Ready: the trap is set, or the hangup would end the shell before it.)
        assert!(client.until("ready").await.is_none());
        drop(client);
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .expect("the session ends when its client goes")
            .unwrap();
        assert!(gone(pid).await, "the process is gone");
        assert_eq!(
            std::fs::read_to_string(&said).unwrap_or_default().trim(),
            "hup",
            "SIGHUP reached it"
        );

        let script = "trap '' HUP; echo ready; while :; do sleep 1; done";
        let (mut client, pid, serving) = session(script);
        assert!(client.until("ready").await.is_none());
        drop(client);
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .expect("the session ends when its client goes")
            .unwrap();
        assert!(gone(pid).await, "the process is killed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `tty` and `root` of the query are asked of the process, and a client that sends neither gets what
    /// it always did.
    #[test]
    fn exec_tty_and_root_are_in_the_ask() {
        let ask = Ask::parse("command=sh&stdin=true&tty=true&root=true").unwrap();
        assert!(ask.tty && ask.root && ask.stdin);
        let ask = Ask::parse("command=sh&tty=false").unwrap();
        assert!(!ask.tty && !ask.root);
        // A hop from a node that does not know them has neither.
        let ask: Ask = serde_json::from_str(r#"{"command":["sh"],"container":null,"stdin":false}"#).unwrap();
        assert!(!ask.tty && !ask.root);
    }
}
