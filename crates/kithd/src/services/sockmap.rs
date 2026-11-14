//! The bytes of a connection from a client to a replica on this node, passed by the kernel
//! instead of copied through kithd: each socket of the pair goes in a socket map whose
//! program sends what the socket receives out of its peer. kithd has accepted the
//! connection, asked its NetworkPolicies and holds its place (services.rs) before; here it
//! watches for either end to finish and passes that on once every byte before it is
//! through, and closes a connection both ends of which have said nothing for `idle`. Where
//! the kernel will not (kithd is not root, the kernel has no socket maps), kithd copies
//! every connection's bytes itself; where a socket can no longer go in a map (its end has
//! closed it already), that connection's, or that one way's; and what a socket that left
//! its map as it closed still holds.

use kith_dm_sys::{SocketMap, TcpCounts, look_again, socket_cookie, tcp_counts};
use nix::errno::Errno;
use nix::poll::PollTimeout;
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags};
use nix::sys::socket::MsgFlags;
use std::net::{Shutdown, TcpStream as Socket};
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::sync::OnceLock;
use std::task::Poll;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncWriteExt, Interest};
use tokio::net::TcpStream;

/// The two maps: every socket of a pair by its own cookie, the program run on what it
/// receives; and by that same cookie its peer, where the program sends it.
struct Kernel {
    watched: SocketMap,
    peers: SocketMap,
}

/// Made at the first connection to a replica on this node (nothing is loaded before), or
/// found refused then: said once, either way.
static KERNEL: OnceLock<Option<Kernel>> = OnceLock::new();

fn kernel() -> Option<&'static Kernel> {
    let made = || {
        // Room for both sockets of every connection kithd serves at once; past it, a
        // connection's go in no map and kithd copies its bytes.
        let room = 2 * super::SERVING as u32;
        let (watched, peers) = (SocketMap::new(room)?, SocketMap::new(room)?);
        watched.redirect_to(&peers)?;
        std::io::Result::Ok(Kernel { watched, peers })
    };
    let kernel = KERNEL.get_or_init(|| match made() {
        Ok(kernel) => {
            eprintln!("kithd: services: the kernel passes the bytes of connections to replicas on this node");
            Some(kernel)
        }
        Err(e) => {
            eprintln!("kithd: services: kithd passes the bytes of connections to replicas on this node itself: {e}");
            None
        }
    });
    kernel.as_ref()
}

/// Bytes both ways between a client and a replica on this node, until both ends have
/// finished, either resets, or `idle` goes by with no byte from either.
pub(super) async fn pass(client: TcpStream, backend: TcpStream, idle: Duration) -> std::io::Result<()> {
    let Some(kernel) = kernel() else {
        return super::pass(client, backend, idle).await.map(drop);
    };
    let mut backend = backend;
    // kithd has read the client's first bytes, perhaps part of what the kernel received in
    // one piece; given that piece, the kernel (6.18) passes it again from its start. So
    // kithd reads and sends on all the client has sent so far, to the last byte, first.
    // (By the socket's own call: tokio's would say nothing is there from what it last saw.)
    let mut buffer = vec![0; super::CHUNK];
    for round in 0.. {
        match nix::sys::socket::recv(client.as_raw_fd(), &mut buffer, MsgFlags::MSG_DONTWAIT) {
            Err(Errno::EAGAIN) => break,
            // Its end has come, or it sends faster than kithd reads: kithd's own way.
            Ok(0) => return super::pass(client, backend, idle).await.map(drop),
            Ok(read) => backend.write_all(&buffer[..read]).await?,
            Err(e) => return Err(e.into()),
        }
        if round == 64 {
            return super::pass(client, backend, idle).await.map(drop);
        }
    }
    drop(buffer);
    let sockets = [client.into_std()?, backend.into_std()?];
    let cookies = [socket_cookie(sockets[0].as_fd())?, socket_cookie(sockets[1].as_fd())?];
    let peers = (kernel.peers.insert(cookies[0], sockets[1].as_fd()))
        .and_then(|()| kernel.peers.insert(cookies[1], sockets[0].as_fd()));
    // (A socket whose far end has finished sending is refused by a map.)
    let entered = peers.and_then(|()| kernel.watched.insert(cookies[0], sockets[0].as_fd()));
    if entered.is_err() {
        for cookie in cookies {
            let _ = kernel.peers.remove(cookie);
        }
        let [client, backend] = sockets;
        return super::pass(TcpStream::from_std(client)?, TcpStream::from_std(backend)?, idle)
            .await
            .map(drop);
    }
    // What the client sent before its socket went in the map is in its queue, where no
    // program has seen it: run now, ahead of what comes next.
    look_again(sockets[0].as_fd())?;
    // The replica's way, likewise; a replica that has finished already (it answered the
    // client's first bytes and closed) has the rest of its bytes copied by kithd.
    let by_kernel = kernel.watched.insert(cookies[1], sockets[1].as_fd()).is_ok();
    if by_kernel {
        look_again(sockets[1].as_fd())?;
    }
    // (Closing a socket takes it out of every map: nothing is left in them after.)
    watch(&sockets, [true, by_kernel], idle).await
}

/// The bytes that the kernel counts as acknowledged by a socket's far end before any of
/// the connection's own: kithd connected the replica's, and its start is counted.
const STARTED: [u64; 2] = [0, 1];

/// Watch a client's and a replica's sockets (in that order) while the kernel passes the
/// bytes each receives to the other where `by_kernel` says so, and kithd copies them
/// otherwise: an end is passed on once all before it is through, and both ends make the
/// connection done.
async fn watch(sockets: &[Socket; 2], by_kernel: [bool; 2], idle: Duration) -> std::io::Result<()> {
    // Woken when either socket's far end finishes or resets, not for every byte it sends.
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?;
    for (at, socket) in sockets.iter().enumerate() {
        epoll.add(
            socket,
            EpollEvent::new(EpollFlags::EPOLLRDHUP | EpollFlags::EPOLLET, at as u64),
        )?;
    }
    // (Said to be unsound for a value that hands out a descriptor it does not own: Woken
    // owns its epoll's, and it is the same for as long as it lives.)
    #[allow(deprecated)]
    let woken = AsyncFd::with_interest(Woken(epoll), Interest::READABLE)?;
    let mut done = [false; 2];
    // kithd's own copy of a way, from the socket that way starts at: the way the kernel
    // was not given, and the rest of one the kernel left (below).
    let mut copies = [None, None];
    for from in [0, 1] {
        if !by_kernel[from] {
            copies[from] = Some(Box::pin(copy(&sockets[from], &sockets[1 - from])));
        }
    }
    // How long to wait to look again for bytes the kernel is still passing on.
    let mut again = Duration::from_millis(1);
    loop {
        let counts = [tcp_counts(sockets[0].as_fd())?, tcp_counts(sockets[1].as_fd())?];
        let ends = [end(&counts[0], &sockets[0]), end(&counts[1], &sockets[1])];
        // (As kithd's own copy does: whatever was on its way either way is gone with it.)
        if ends.iter().any(|end| matches!(end, Some(End::Reset))) {
            return Ok(());
        }
        let mut passing = false;
        for from in [0, 1] {
            let to = 1 - from;
            if done[from] || copies[from].is_some() || ends[from].is_none() {
                continue;
            }
            // An end is counted as a byte received.
            let through = counts[to].acked.saturating_sub(STARTED[to]) + counts[from].unread + 1;
            if through < counts[from].received {
                passing = true;
            } else if counts[from].unread == 0 {
                sockets[to].shutdown(Shutdown::Write)?;
                done[from] = true;
            } else {
                // The kernel takes a socket out of the maps as its connection closes, and
                // what came with the end then stays in it: kithd sends that on, after
                // every byte the kernel passed.
                copies[from] = Some(Box::pin(copy(&sockets[from], &sockets[to])));
            }
        }
        if done == [true; 2] {
            return Ok(());
        }
        let quiet = counts[0].since_received.min(counts[1].since_received);
        if quiet >= idle {
            return Ok(());
        }
        let wait = if passing {
            let wait = again;
            again = (again * 2).min(Duration::from_millis(50));
            wait
        } else {
            again = Duration::from_millis(1);
            idle - quiet
        };
        let copying = copies.iter().any(Option::is_some);
        let copied = std::future::poll_fn(|cx| {
            for (from, copy) in copies.iter_mut().enumerate() {
                if let Some(said) = copy.as_mut().and_then(|copy| match copy.as_mut().poll(cx) {
                    Poll::Ready(said) => Some(said),
                    Poll::Pending => None,
                }) {
                    *copy = None;
                    return Poll::Ready((from, said));
                }
            }
            Poll::Pending
        });
        tokio::select! {
            (from, said) = copied, if copying => {
                // kithd's own way is through (or failed: that ends the connection, as a reset does).
                said?;
                done[from] = true;
            }
            ready = tokio::time::timeout(wait, woken.readable()) => {
                if let Ok(ready) = ready {
                    let mut ready = ready?;
                    let mut events = [EpollEvent::empty(); 2];
                    ready.get_inner().0.wait(&mut events, PollTimeout::ZERO)?;
                    ready.clear_ready();
                }
            }
        }
    }
}

/// How the far end of a socket ended what it sends.
enum End {
    Finished,
    Reset,
}

fn end(counts: &TcpCounts, socket: &Socket) -> Option<End> {
    // CLOSE_WAIT, LAST_ACK, CLOSING and TIME_WAIT: its end was heard. (TIME_WAIT's socket
    // reads as closed.)
    const HEARD: [u8; 4] = [8, 9, 11, 6];
    match counts.state {
        state if HEARD.contains(&state) => Some(End::Finished),
        // Closed: after this end had finished, and then the far one; or by a reset.
        7 => Some(match socket.take_error() {
            Ok(None) => End::Finished,
            _ => End::Reset,
        }),
        _ => None,
    }
}

/// kithd's own copy of the bytes `from` receives to `to`, and then its end.
async fn copy(from: &Socket, to: &Socket) -> std::io::Result<()> {
    let mut from = TcpStream::from_std(from.try_clone()?)?;
    let mut to = TcpStream::from_std(to.try_clone()?)?;
    tokio::io::copy(&mut from, &mut to).await?;
    to.shutdown().await
}

/// An epoll of its own for a connection's two sockets, itself watched by tokio's.
struct Woken(Epoll);

impl AsRawFd for Woken {
    fn as_raw_fd(&self) -> RawFd {
        self.0.0.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Instant;

    /// A connection as kithd holds one, over the loopback: its socket of the client's (which
    /// it accepted) and of the replica's (which it connected); and the client and the replica.
    fn connection() -> ([Socket; 2], Socket, Socket) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = Socket::connect(listener.local_addr().unwrap()).unwrap();
        let (near, _) = listener.accept().unwrap();
        let backend = Socket::connect(listener.local_addr().unwrap()).unwrap();
        let (replica, _) = listener.accept().unwrap();
        for socket in [&near, &backend] {
            socket.set_nonblocking(true).unwrap();
        }
        for socket in [&client, &replica] {
            socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        }
        ([near, backend], client, replica)
    }

    /// The client's end reaches the replica after every byte the client sent before it, not
    /// sooner, and the replica's reaches the client; then the connection is done. (The test
    /// passes the bytes itself, as the kernel would.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_end_is_passed_on_after_the_bytes_before_it() {
        let ([near, backend], mut client, mut replica) = connection();
        let (mut heard, mut onward) = (near.try_clone().unwrap(), backend.try_clone().unwrap());
        let watching =
            tokio::spawn(async move { watch(&[near, backend], [true, true], Duration::from_secs(60)).await });
        // The kernel takes the bytes off the socket as they come (bytes left unread there
        // are kithd's to copy), and holds them a while.
        client.write_all(b"hello").unwrap();
        let mut got = [0; 5];
        heard.set_nonblocking(false).unwrap();
        heard.read_exact(&mut got).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        replica.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let mut early = [0; 5];
        assert!(replica.read(&mut early).is_err(), "the end went before the bytes");
        onward.write_all(&got).unwrap();
        replica.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        replica.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hello");
        assert_eq!(replica.read(&mut got).unwrap(), 0);
        assert!(!watching.is_finished());
        replica.shutdown(Shutdown::Write).unwrap();
        assert_eq!(client.read(&mut got).unwrap(), 0);
        watching.await.unwrap().unwrap();
    }

    /// The replica finished before its socket could go in a map: kithd copies its bytes to
    /// the client, and its end after them, while the client's way is the kernel's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_way_the_kernel_was_not_given_is_copied() {
        let (sockets, mut client, mut replica) = connection();
        replica.write_all(b"bye").unwrap();
        replica.shutdown(Shutdown::Write).unwrap();
        let watching = tokio::spawn(async move { watch(&sockets, [true, false], Duration::from_secs(60)).await });
        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"bye");
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(replica.read(&mut [0; 1]).unwrap(), 0);
        watching.await.unwrap().unwrap();
    }

    /// Bytes the kernel left in a socket that came with its end (it had left the map) are
    /// copied by kithd, and the end after them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bytes_left_with_an_end_are_copied() {
        let (sockets, mut client, mut replica) = connection();
        let watching = tokio::spawn(async move { watch(&sockets, [true, true], Duration::from_secs(60)).await });
        replica.write_all(b"ok\n").unwrap();
        replica.shutdown(Shutdown::Write).unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"ok\n");
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(replica.read(&mut [0; 1]).unwrap(), 0);
        watching.await.unwrap().unwrap();
    }

    /// A connection neither end says anything on is closed after `idle`; one an end resets
    /// at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_silent_connection_is_closed_and_a_reset_one_at_once() {
        let (sockets, mut client, _replica) = connection();
        let started = Instant::now();
        watch(&sockets, [true, true], Duration::from_millis(300)).await.unwrap();
        assert!((Duration::from_millis(250)..Duration::from_secs(5)).contains(&started.elapsed()));
        drop(sockets);
        assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);

        let (sockets, client, _replica) = connection();
        // (Closed with a byte it was sent unread: the kernel resets the connection.)
        (&sockets[0]).write_all(b"x").unwrap();
        std::thread::sleep(Duration::from_millis(50));
        drop(client);
        let started = Instant::now();
        watch(&sockets, [true, true], Duration::from_secs(60)).await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// Bytes both ways, and both ends, through [`pass`]: the kernel's way where kithd may
    /// load its program, kithd's own where it may not (as a test that is not root).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bytes_pass_either_way() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let mut client = Socket::connect(at).unwrap();
        let (near, _) = listener.accept().await.unwrap();
        let backend = TcpStream::connect(at).await.unwrap();
        let (replica, _) = listener.accept().await.unwrap();
        let mut replica = replica.into_std().unwrap();
        replica.set_nonblocking(false).unwrap();
        let passing = tokio::spawn(pass(near, backend, Duration::from_secs(60)));
        let sent: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let writer = {
            let (mut client, sent) = (client.try_clone().unwrap(), sent.clone());
            std::thread::spawn(move || {
                client.write_all(&sent).unwrap();
                client.shutdown(Shutdown::Write).unwrap();
            })
        };
        let mut got = Vec::new();
        replica.read_to_end(&mut got).unwrap();
        assert!(got == sent, "{} bytes of {} came through", got.len(), sent.len());
        writer.join().unwrap();
        replica.write_all(b"done").unwrap();
        drop(replica);
        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"done");
        passing.await.unwrap().unwrap();
    }
}
