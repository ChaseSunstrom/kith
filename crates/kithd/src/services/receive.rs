//! The receiving end of a link between two kithds (T-0326, slice A): the node that has the
//! replicas takes the streams another node's clients ride on one connection ([`link`]).
//! Each stream is what one kept connection is in [`super::taken`], and is admitted as such,
//! by itself: its opening line (`port workload [replica]`, as a kept connection's) goes
//! through `find` (the table and the Workload's NetworkPolicies), takes a relaying place of
//! its own, and is passed on to the replica with the idle end of every connection to a
//! Service. A stream that is not admitted is reset, which is the no: nothing a stream
//! says (or another on the link said, or the link's own opening) admits another.
//! One that is, is answered `+` and then the replica's bytes; the client's follow its line.
//!
//! The link holds the place of the connection it came on, and a cap bounds the streams it
//! has at once: past it a stream is reset with nothing of it read, so that what a link
//! holds is the cap and the window of each ([`link::WINDOW`]) at the most.
//
// ponytail: the streams of a link are all one task's futures (they borrow `find`, which
// borrows the Proxy), so one core carries a link's relaying; split them across tasks when
// slice C measures that a busy link wants more than one.

use super::link::{self, Link, Rx, Stream, Tx};
use super::{CONNECT, FOUND, IDLE, KEPT_THERE, Relay, over_limit};
use crate::ingress::Limits;
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

/// What a link may hold and for how long.
#[derive(Clone, Copy)]
pub(super) struct Bounds {
    /// Streams at once on one link; a stream over this is reset unread.
    pub(super) streams: usize,
    /// How long a stream may move no byte either way (as a connection to a Service).
    pub(super) idle: Duration,
    /// How long a stream has to say its opening line.
    pub(super) asking: Duration,
    /// How long a link with no stream is kept.
    pub(super) empty: Duration,
}

pub(super) const BOUNDS: Bounds = Bounds {
    streams: 256,
    idle: IDLE,
    asking: CONNECT,
    empty: KEPT_THERE,
};

/// The most bytes of an opening line, as of a kept connection's.
const LINE: usize = 300;

// A connection to another node's kithd is a link's transport as it is.
impl AsyncRead for Relay {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.from).poll_read(cx, buf)
    }
}

impl AsyncWrite for Relay {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.to).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.to).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.to).poll_shutdown(cx)
    }
}

/// Serve the link on `io` from node `caller` until it ends: every stream the other end
/// opens is passed on to the replica `find` connects to, each by itself.
pub(super) async fn serve<T, F, Fut>(io: T, relaying: Limits, caller: IpAddr, bounds: Bounds, find: F) -> Option<()>
where
    T: AsyncRead + AsyncWrite + Send + 'static,
    F: Fn(u16, String, Option<u32>) -> Fut,
    Fut: Future<Output = Option<TcpStream>>,
{
    let (link, mut incoming) = link::link(io, false);
    let _down = Down(link);
    let mut running = FuturesUnordered::new();
    loop {
        tokio::select! {
            stream = incoming.accept() => match stream {
                None => return Some(()),
                // (Over the cap: nothing of it is read, and its drop resets it.)
                Some(stream) if running.len() >= bounds.streams => drop(stream),
                Some(stream) => running.push(one(stream, &relaying, caller, bounds, &find)),
            },
            Some(()) = running.next(), if !running.is_empty() => {}
            () = tokio::time::sleep(bounds.empty), if running.is_empty() => return Some(()),
        }
    }
}

/// The link goes down with `serve`, whichever way it ends: its streams are reset and its
/// connection let go.
struct Down(Link);

impl Drop for Down {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// One stream: its line, a place of its own, the replica, and then the bytes. Whatever is not
/// as it should be resets the stream (the no), and nothing else.
async fn one<F, Fut>(stream: Stream, relaying: &Limits, caller: IpAddr, bounds: Bounds, find: &F)
where
    F: Fn(u16, String, Option<u32>) -> Fut,
    Fut: Future<Output = Option<TcpStream>>,
{
    let Stream { mut tx, mut rx } = stream;
    let Ok(Some((port, workload, replica, early))) = tokio::time::timeout(bounds.asking, asked(&mut rx)).await else {
        return tx.reset();
    };
    let Some(_place) = relaying.take(caller) else {
        over_limit(caller);
        return tx.reset();
    };
    let found = tokio::time::timeout(FOUND, find(port, workload, replica)).await;
    let Ok(Some(replica)) = found else {
        return tx.reset();
    };
    if tx.write(b"+").await.is_err() {
        return;
    }
    if !between(&mut tx, &mut rx, replica, early, bounds.idle).await {
        tx.reset();
    }
}

/// A stream's opening line, as a kept connection's (`port workload [replica]`, in 300 bytes
/// at the most, and nothing else on it), and what came after it in the same data.
async fn asked(rx: &mut Rx) -> Option<(u16, String, Option<u32>, Vec<u8>)> {
    let mut line = Vec::new();
    loop {
        let bytes = rx.read().await.ok()??;
        let end = bytes.iter().position(|byte| *byte == b'\n');
        line.extend_from_slice(&bytes[..end.unwrap_or(bytes.len())]);
        if line.len() >= LINE {
            return None;
        }
        let Some(end) = end else { continue };
        let mut words = std::str::from_utf8(&line).ok()?.split(' ');
        let port = words.next()?.parse().ok()?;
        let workload = words.next()?.to_string();
        let replica = match words.next() {
            Some(replica) => Some(replica.parse().ok()?),
            None => None,
        };
        return match words.next() {
            None => Some((port, workload, replica, bytes[end + 1..].to_vec())),
            Some(_) => None,
        };
    }
}

/// Bytes both ways between a stream and its replica until both ways have ended: whether
/// they did, and not a reset, a failed write, or `idle` with no byte moved on either.
async fn between(tx: &mut Tx, rx: &mut Rx, replica: TcpStream, early: Vec<u8>, idle: Duration) -> bool {
    let _ = replica.set_nodelay(true);
    let (mut from, mut to) = replica.into_split();
    // (As in `carry`: when a byte last moved, asked once in `idle`, not a timer for each.)
    let (begun, moved) = (Instant::now(), AtomicU64::new(0));
    let moves = || moved.store(begun.elapsed().as_millis() as u64, Ordering::Relaxed);
    let up = async {
        to.write_all(&early).await?;
        loop {
            match rx.read().await? {
                Some(bytes) => {
                    to.write_all(&bytes).await?;
                    moves();
                }
                None => return to.shutdown().await,
            }
        }
    };
    let down = async {
        let mut chunk = vec![0; 16 * 1024];
        loop {
            match from.read(&mut chunk).await? {
                0 => return Ok(tx.end()),
                size => {
                    tx.write(&chunk[..size]).await?;
                    moves();
                }
            }
        }
    };
    let silent = async {
        loop {
            let until = begun + Duration::from_millis(moved.load(Ordering::Relaxed)) + idle;
            if Instant::now() >= until {
                return;
            }
            tokio::time::sleep_until(until.into()).await;
        }
    };
    tokio::select! {
        passed = async { tokio::try_join!(up, down) } => passed.is_ok(),
        () = silent => false,
    }
}

#[cfg(test)]
mod tests {
    use super::super::link::Incoming;
    use super::super::tests::{apply, pair_from_ipv6, proxy_of, replica, state_with_web};
    use super::super::{Proxy, link};
    use super::*;
    use std::net::{Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    const WAIT: Duration = Duration::from_secs(20);
    const WEB: &str = "Workload/default/web";

    // ---- through Proxy::take, from a client that says `link` ----

    /// The near end of a link to `proxy.take`, run by `body`, which ends the link when it is done.
    async fn on_a_link<B, Fut>(proxy: &Proxy, body: B)
    where
        B: FnOnce(Link) -> Fut,
        Fut: Future<Output = ()>,
    {
        let (mut client, held) = pair_from_ipv6().await;
        client.write_all(b"link\n").await.unwrap();
        let (near, _far) = link::link(client, true);
        let body = async {
            body(near.clone()).await;
            near.close();
        };
        let (taken, ()) = timeout(WAIT, async { tokio::join!(proxy.take(held), body) })
            .await
            .expect("the link ends");
        assert_eq!(taken, Some(()));
    }

    /// A stream that opens with `line`: its two halves if it was answered, none if it was reset.
    async fn ask(near: &Link, line: &str) -> Option<(Tx, Rx)> {
        let Stream { mut tx, mut rx } = near.open().unwrap();
        tx.write(line.as_bytes()).await.unwrap();
        match rx.read().await {
            Ok(Some(answer)) => {
                assert_eq!(answer, b"+");
                Some((tx, rx))
            }
            Ok(None) => panic!("ended with no answer"),
            Err(_) => None,
        }
    }

    /// What a replica that answers `a:` and what it was said (see `replica`) says to `said`.
    async fn say(mut tx: Tx, mut rx: Rx, said: &str) -> Vec<u8> {
        tx.write(said.as_bytes()).await.unwrap();
        tx.end();
        let mut heard = Vec::new();
        while let Some(more) = rx.read().await.unwrap() {
            heard.extend_from_slice(&more);
        }
        heard
    }

    fn policy(cidr: &str) -> String {
        format!(
            "apiVersion: kith.dev/v1\nkind: NetworkPolicy\nmetadata: {{ name: web }}\n\
             spec:\n  selector: {{ app: web }}\n  ingress: [{{ action: allow, peers: [{{ cidr: '{cidr}' }}] }}]\n"
        )
    }

    /// Each stream is asked for by itself: what the table has none of is reset, whatever
    /// way it is not asked for right, and the stream after it on the same link is passed on.
    #[tokio::test]
    async fn take_link_resets_each_stream_the_table_does_not_ask_for_and_carries_on() {
        let (replica, replicas) = replica().await;
        let port = replica.port();
        let proxy = proxy_of(state_with_web("link-each").await, port, WEB, None);
        on_a_link(&proxy, |near| async move {
            let refused = [
                format!("{port} {WEB} 0\n"),
                format!("{port} Workload/default/other\n"),
                format!("{} {WEB}\n", port.wrapping_add(1)),
                format!("99999 {WEB}\n"),
                format!("{port} {WEB} 0 more\n"),
                format!("{port}\n"),
                "not a line\n".into(),
                "\n".into(),
                format!("{port} {WEB}{}\n", " ".repeat(400)),
            ];
            for line in &refused {
                assert!(ask(&near, line).await.is_none(), "{line:?}");
                let (tx, rx) = ask(&near, &format!("{port} {WEB}\n"))
                    .await
                    .expect("the link carries on");
                assert_eq!(say(tx, rx, "q").await, b"a:q");
            }
        })
        .await;
        assert_eq!(
            replicas.load(Ordering::Relaxed),
            9,
            "only the streams asked for right got one"
        );
    }

    /// No stream inherits another's admission, nor the link's: a NetworkPolicy that refuses the
    /// caller refuses every stream of the link, one that lets it in lets each in, and one
    /// changed under a link that a stream went through is held to for the next stream.
    #[tokio::test]
    async fn take_link_admits_each_stream_by_itself_against_the_policies_of_then() {
        for (cidr, passes) in [("fd00::/64", false), ("::ffff:127.0.0.1/128", true)] {
            let (replica, replicas) = replica().await;
            let port = replica.port();
            let shared = state_with_web(if passes { "link-let-in" } else { "link-refused" }).await;
            apply(&shared, &policy(cidr));
            let proxy = proxy_of(shared, port, WEB, None);
            on_a_link(&proxy, |near| async move {
                for _ in 0..3 {
                    let got = ask(&near, &format!("{port} {WEB}\n")).await;
                    assert_eq!(got.is_some(), passes, "{cidr}");
                    if let Some((tx, rx)) = got {
                        assert_eq!(say(tx, rx, "x").await, b"a:x");
                    }
                }
            })
            .await;
            assert_eq!(replicas.load(Ordering::Relaxed), 3 * usize::from(passes), "{cidr}");
        }
        let (replica, replicas) = replica().await;
        let port = replica.port();
        let shared = state_with_web("link-changed").await;
        apply(&shared, &policy("::ffff:127.0.0.1/128"));
        let proxy = proxy_of(shared.clone(), port, WEB, None);
        on_a_link(&proxy, |near| async move {
            let (tx, rx) = ask(&near, &format!("{port} {WEB}\n")).await.expect("let in");
            // The first stream is still open when the policy is changed: it has what it was given.
            apply(&shared, &policy("fd00::/64"));
            assert!(
                ask(&near, &format!("{port} {WEB}\n")).await.is_none(),
                "not let in after"
            );
            assert_eq!(say(tx, rx, "q").await, b"a:q");
        })
        .await;
        assert_eq!(replicas.load(Ordering::Relaxed), 1);
    }

    /// A link holds its cap of streams: one over is reset with nothing of it read (the replica
    /// is not asked for), and a place freed is taken by the next.
    #[tokio::test]
    async fn take_link_resets_streams_over_the_cap_unread() {
        let (replica, replicas) = replica().await;
        let port = replica.port();
        let mut proxy = proxy_of(state_with_web("link-cap").await, port, WEB, None);
        proxy.links.streams = 2;
        let line = format!("{port} {WEB}\n");
        on_a_link(&proxy, |near| async move {
            let a = ask(&near, &line).await.expect("within the cap");
            let b = ask(&near, &line).await.expect("within the cap");
            assert!(ask(&near, &line).await.is_none(), "over the cap");
            assert!(ask(&near, &line).await.is_none(), "over the cap again");
            assert_eq!(say(a.0, a.1, "a").await, b"a:a");
            let c = ask(&near, &line).await.expect("a place was freed");
            assert_eq!(say(b.0, b.1, "b").await, b"a:b");
            assert_eq!(say(c.0, c.1, "c").await, b"a:c");
        })
        .await;
        assert_eq!(
            replicas.load(Ordering::Relaxed),
            3,
            "the ones over the cap were not found for"
        );
    }

    /// Each stream takes a relaying place of its own, on top of the one the link holds, and
    /// gives it back when it ends.
    #[tokio::test]
    async fn take_link_takes_a_relaying_place_for_each_stream() {
        let (replica, _) = replica().await;
        let port = replica.port();
        let mut proxy = proxy_of(state_with_web("link-places").await, port, WEB, None);
        // Two places: the link's own, and one for a stream.
        proxy.relaying = Limits::new(2, 2).per_node();
        let caller = IpAddr::V6(std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        let line = format!("{port} {WEB}\n");
        let places = &proxy.relaying;
        on_a_link(&proxy, |near| async move {
            let a = ask(&near, &line).await.expect("a place for it");
            assert!(places.take(caller).is_none(), "the link's and the stream's are held");
            assert!(ask(&near, &line).await.is_none(), "no place for a second");
            assert_eq!(say(a.0, a.1, "a").await, b"a:a");
            let b = ask(&near, &line).await.expect("the place was given back");
            assert_eq!(say(b.0, b.1, "b").await, b"a:b");
        })
        .await;
        assert!(proxy.relaying.take(caller).is_some(), "the link's place is given back");
    }

    // ---- through serve, from the far end of a pipe ----

    type Connecting = Pin<Box<dyn Future<Output = Option<TcpStream>> + Send>>;

    /// The replicas `known` by workload name; `slow` is one that is never connected.
    fn finder(
        known: Vec<(&'static str, SocketAddr)>,
    ) -> impl Fn(u16, String, Option<u32>) -> Connecting + Send + Sync + 'static {
        move |_, workload, _| {
            let at = known.iter().find(|(name, _)| *name == workload).map(|(_, at)| *at);
            Box::pin(async move {
                match at {
                    Some(at) => TcpStream::connect(at).await.ok(),
                    None if workload == "slow" => std::future::pending().await,
                    None => None,
                }
            })
        }
    }

    /// A server that does `with` to each connection, and counts the connections it is done with.
    async fn listen<H, Fut>(with: H) -> (SocketAddr, Arc<AtomicUsize>)
    where
        H: Fn(TcpStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (at, done) = (listener.local_addr().unwrap(), Arc::new(AtomicUsize::new(0)));
        let counted = done.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (doing, counted) = (with(stream), counted.clone());
                tokio::spawn(async move {
                    doing.await;
                    counted.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        (at, done)
    }

    /// Sends back what it is sent, until the end.
    async fn echoes(mut stream: TcpStream) {
        let (mut from, mut to) = stream.split();
        let _ = tokio::io::copy(&mut from, &mut to).await;
        let _ = to.shutdown().await;
    }

    /// Reads what it is sent, until the end or a reset, and says nothing.
    async fn sinks(mut stream: TcpStream) {
        let mut chunk = vec![0; 4096];
        while stream.read(&mut chunk).await.is_ok_and(|n| n > 0) {}
    }

    const LOOSE: Bounds = Bounds {
        streams: 256,
        idle: Duration::from_secs(60),
        asking: Duration::from_secs(60),
        empty: Duration::from_secs(60),
    };

    /// `serve` on one end of a pipe, the link's near end on the other.
    fn served(
        bounds: Bounds,
        find: impl Fn(u16, String, Option<u32>) -> Connecting + Send + Sync + 'static,
    ) -> (Link, Incoming, tokio::task::JoinHandle<Option<()>>) {
        let (near, far) = tokio::io::duplex(8192);
        let caller = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let task = tokio::spawn(serve(far, Limits::new(4096, 4096), caller, bounds, find));
        let (link, incoming) = link::link(near, true);
        (link, incoming, task)
    }

    /// A pipe to `serve` that is spoken to in frames by hand: (the near end, the task).
    fn raw(
        bounds: Bounds,
        find: impl Fn(u16, String, Option<u32>) -> Connecting + Send + Sync + 'static,
    ) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<Option<()>>) {
        let (near, far) = tokio::io::duplex(8192);
        let caller = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let task = tokio::spawn(serve(far, Limits::new(4096, 4096), caller, bounds, find));
        (near, task)
    }

    const OPEN: u8 = 0;
    const DATA: u8 = 1;
    const END: u8 = 2;
    const RESET: u8 = 3;
    const CREDIT: u8 = 4;

    fn frame(stream: u32, kind: u8, bytes: &[u8]) -> Vec<u8> {
        let mut out = stream.to_be_bytes().to_vec();
        out.push(kind);
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
        out
    }

    /// The next frame from the link, none at its end.
    async fn next(raw: &mut tokio::io::DuplexStream) -> Option<(u32, u8, Vec<u8>)> {
        let mut head = [0; 7];
        raw.read_exact(&mut head).await.ok()?;
        let mut bytes = vec![0; usize::from(u16::from_be_bytes([head[5], head[6]]))];
        raw.read_exact(&mut bytes).await.ok()?;
        Some((u32::from_be_bytes(head[..4].try_into().unwrap()), head[4], bytes))
    }

    /// Frames up to the end of stream `id`, or its reset (or the link's end): the bytes it
    /// was sent, and whether it was reset. Credit is not a stream's bytes. The frames of the
    /// streams in `others` (open ones, that are answered) are passed over; a frame of any
    /// stream else fails the test, and the bytes of `id` are its own alone.
    async fn heard(raw: &mut tokio::io::DuplexStream, id: u32, others: &[u32]) -> (Vec<u8>, bool) {
        let mut bytes = Vec::new();
        loop {
            let Some((stream, kind, more)) = timeout(WAIT, next(raw)).await.expect("a frame in time") else {
                return (bytes, true);
            };
            if others.contains(&stream) {
                continue;
            }
            assert_eq!(stream, id, "a frame of a stream not open");
            match kind {
                DATA => bytes.extend_from_slice(&more),
                END => return (bytes, false),
                RESET => return (bytes, true),
                CREDIT => {}
                other => panic!("kind {other}"),
            }
        }
    }

    /// The echo replica's, opened on stream `id` of a raw link and said `said` to its end.
    async fn echoed(raw: &mut tokio::io::DuplexStream, id: u32, said: &[u8], others: &[u32]) -> (Vec<u8>, bool) {
        raw.write_all(&frame(id, OPEN, b"")).await.unwrap();
        raw.write_all(&frame(id, DATA, &[b"1 echo\n", said].concat()))
            .await
            .unwrap();
        raw.write_all(&frame(id, END, b"")).await.unwrap();
        heard(raw, id, others).await
    }

    /// A stream that is silent (no opening line, or no byte after it) is reset after the time,
    /// and not before; the link, and a stream that began after, are not.
    #[tokio::test]
    async fn link_a_silent_stream_ends_after_idle() {
        let (mute, held) = listen(|mut stream| async move {
            let _ = stream.read_u8().await;
        })
        .await;
        let (echo, _) = listen(echoes).await;
        let bounds = Bounds {
            idle: Duration::from_millis(400),
            asking: Duration::from_millis(400),
            ..LOOSE
        };
        let (near, _incoming, task) = served(bounds, finder(vec![("mute", mute), ("echo", echo)]));
        // One that says nothing at all.
        let Stream { tx: _quiet, mut rx } = near.open().unwrap();
        let begun = Instant::now();
        assert!(timeout(WAIT, rx.read()).await.unwrap().is_err(), "reset");
        assert!(
            begun.elapsed() >= Duration::from_millis(350),
            "not before: {:?}",
            begun.elapsed()
        );
        // One that was passed on, and then says nothing: the replica's connection ends with it.
        let begun = Instant::now();
        let (_tx, mut rx) = ask(&near, "1 mute\n").await.expect("passed on");
        assert!(timeout(WAIT, rx.read()).await.unwrap().is_err(), "reset");
        assert!(
            begun.elapsed() >= Duration::from_millis(350),
            "not before: {:?}",
            begun.elapsed()
        );
        timeout(WAIT, async {
            while held.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the replica's connection ended");
        // The link goes on.
        let (tx, rx) = ask(&near, "1 echo\n").await.expect("a stream after");
        assert_eq!(say(tx, rx, "still here").await, b"still here");
        assert!(!task.is_finished());
    }

    /// Bytes moving keep a stream from being idle: one that is slower than the time in each
    /// direction, but never silent for it, is not cut.
    #[tokio::test]
    async fn link_a_stream_that_moves_bytes_is_not_idle() {
        let (echo, _) = listen(echoes).await;
        let bounds = Bounds {
            idle: Duration::from_millis(600),
            ..LOOSE
        };
        let (near, _incoming, _task) = served(bounds, finder(vec![("echo", echo)]));
        let (mut tx, mut rx) = ask(&near, "1 echo\n").await.expect("passed on");
        let begun = Instant::now();
        for turn in 0..5u8 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            tx.write(&[turn]).await.unwrap();
            assert_eq!(timeout(WAIT, rx.read()).await.unwrap().unwrap().unwrap(), [turn]);
        }
        assert!(
            begun.elapsed() > Duration::from_millis(1000),
            "longer than the idle time"
        );
    }

    /// A frame for a stream nobody opened is dropped, and so is one for a stream that is over
    /// (ended both ways, or reset); a stream number of the wrong kind or none is reset. Through
    /// all of it the streams that are open hear nothing but their own bytes, and the link is up.
    #[tokio::test]
    async fn link_frames_for_unknown_and_closed_streams_are_dropped_and_never_reach_another() {
        let (echo, _) = listen(echoes).await;
        let (sink, sunk) = listen(sinks).await;
        let (mut raw, task) = raw(LOOSE, finder(vec![("echo", echo), ("sink", sink)]));
        // A stream that is passed on to a replica that says nothing, and is open while the rest goes on.
        raw.write_all(&frame(1, OPEN, b"")).await.unwrap();
        raw.write_all(&frame(1, DATA, b"1 sink\n")).await.unwrap();
        // Unknown: never opened. Nothing is answered, and nothing reaches stream 1.
        for junk in [
            frame(99, DATA, b"junk"),
            frame(99, END, b""),
            frame(99, RESET, b""),
            frame(101, CREDIT, &[0, 0, 0, 9]),
        ] {
            raw.write_all(&junk).await.unwrap();
        }
        // Of the wrong kind of number (this end's are even), or none: reset.
        for id in [2, 0] {
            raw.write_all(&frame(id, OPEN, b"")).await.unwrap();
            assert_eq!(heard(&mut raw, id, &[1]).await, (Vec::new(), true), "stream {id}");
        }
        assert_eq!(echoed(&mut raw, 3, b"hello", &[1]).await, (b"+hello".to_vec(), false));
        // Stream 1 is reset, and what follows for it (it is over) is dropped, as for 99.
        raw.write_all(&frame(1, RESET, b"")).await.unwrap();
        raw.write_all(&frame(1, DATA, b"late")).await.unwrap();
        raw.write_all(&frame(1, END, b"")).await.unwrap();
        timeout(WAIT, async {
            while sunk.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the reset was passed on to the replica");
        assert_eq!(echoed(&mut raw, 5, b"again", &[1]).await, (b"+again".to_vec(), false));
        assert!(!task.is_finished(), "the link is up");
    }

    /// A peer that sends more than a stream's window while nothing reads it has that stream reset
    /// (link.rs), and no other: the replica is not asked for it, and the stream beside it goes on.
    #[tokio::test]
    async fn link_a_window_overrun_resets_that_stream_only() {
        let (echo, _) = listen(echoes).await;
        let (mut raw, task) = raw(LOOSE, finder(vec![("echo", echo)]));
        // Nobody reads the stream while its replica is looked for, which never finishes.
        raw.write_all(&frame(1, OPEN, b"")).await.unwrap();
        raw.write_all(&frame(1, DATA, b"1 slow\n")).await.unwrap();
        for _ in 0..5 {
            raw.write_all(&frame(1, DATA, &[9; 16 * 1024])).await.unwrap();
        }
        assert_eq!(heard(&mut raw, 1, &[]).await, (Vec::new(), true));
        assert_eq!(echoed(&mut raw, 3, b"beside", &[]).await, (b"+beside".to_vec(), false));
        assert!(!task.is_finished(), "the link is up");
    }

    /// A frame that is not one (a kind there is none of, a length a kind does not have) takes
    /// the link down, as link.rs says: the streams on it are reset, the replicas let go, and
    /// `serve` is over.
    #[tokio::test]
    async fn link_a_frame_that_is_not_one_takes_the_link_down() {
        for bad in [
            frame(1, 9, b""),
            frame(1, DATA, b""),
            frame(7, OPEN, b"x"),
            frame(1, CREDIT, b""),
        ] {
            let (sink, sunk) = listen(sinks).await;
            let (mut raw, task) = raw(LOOSE, finder(vec![("sink", sink)]));
            raw.write_all(&frame(1, OPEN, b"")).await.unwrap();
            raw.write_all(&frame(1, DATA, b"1 sink\n")).await.unwrap();
            let said = timeout(WAIT, next(&mut raw)).await.expect("a frame in time");
            assert_eq!(said, Some((1, DATA, b"+".to_vec())), "passed on");
            raw.write_all(&bad).await.unwrap();
            assert_eq!(
                timeout(WAIT, task).await.expect("serve ends").unwrap(),
                Some(()),
                "{bad:?}"
            );
            while timeout(WAIT, next(&mut raw)).await.expect("the pipe ends").is_some() {}
            timeout(WAIT, async {
                while sunk.load(Ordering::SeqCst) == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the replica was let go");
        }
    }

    /// Twenty-four clients at once on one link: each its own bytes to its replica and back, in
    /// order and never mixed with another's, more than a window of them each; one whose reader
    /// stopped holds only its own window; one's replica ends and its end is passed on; one
    /// resets and its replica's connection goes; and none of those stops the rest.
    #[tokio::test]
    async fn link_twenty_four_clients_at_once_never_mixed_with_a_reader_that_stops() {
        let (echo, _) = listen(echoes).await;
        let (sink, sunk) = listen(sinks).await;
        let (flood, _) = listen(|mut stream| async move {
            let _ = stream.write_all(&vec![7; 1 << 20]).await;
        })
        .await;
        let (gone, _) = listen(|_stream| async {}).await;
        let known = vec![("echo", echo), ("sink", sink), ("flood", flood), ("gone", gone)];
        let (near, _incoming, task) = served(LOOSE, finder(known));
        let (_stopped_tx, mut stopped) = ask(&near, "1 flood\n").await.expect("passed on");
        let clients: Vec<_> = (0..24usize)
            .map(|id| {
                let near = near.clone();
                tokio::spawn(async move {
                    let (mut tx, mut rx) = ask(&near, "1 echo\n").await.expect("passed on");
                    // More than a window of bytes, each client's of its own.
                    let sent: Vec<u8> = (0..60_000 + id * 1000)
                        .map(|i| ((i * 31 + id * 7) % 251) as u8)
                        .collect();
                    let writing = async {
                        for chunk in sent.chunks(1000 + id * 37) {
                            tx.write(chunk).await.unwrap();
                        }
                        tx.end();
                    };
                    let reading = async {
                        let mut got = Vec::new();
                        while let Some(more) = rx.read().await.unwrap() {
                            got.extend_from_slice(&more);
                        }
                        got
                    };
                    let ((), got) = tokio::join!(writing, reading);
                    assert!(got == sent, "client {id}: its bytes came back changed, or out of order");
                })
            })
            .collect();
        // A replica that ends: the stream ends, as a stream does.
        let (mut tx, mut ended) = ask(&near, "1 gone\n").await.expect("passed on");
        assert_eq!(timeout(WAIT, ended.read()).await.unwrap().unwrap(), None);
        tx.end();
        // A client that resets: its replica is let go.
        let (resetting, _rx) = ask(&near, "1 sink\n").await.expect("passed on");
        resetting.reset();
        for client in clients {
            timeout(WAIT, client).await.expect("a client that finished").unwrap();
        }
        timeout(WAIT, async {
            while sunk.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the reset was passed on to the replica");
        // The one that stopped reading has been held where it was, not reset: it reads on from there.
        assert_eq!(near.streams(), 1, "only the stopped one is left");
        assert!(timeout(WAIT, stopped.read()).await.unwrap().unwrap().is_some());
        near.close();
        assert_eq!(timeout(WAIT, task).await.expect("serve ends").unwrap(), Some(()));
    }
}
