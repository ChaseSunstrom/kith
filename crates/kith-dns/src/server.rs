//! The UDP and TCP servers and the forwarder.

use crate::wire::{self, Query, REFUSED};
use crate::{Answer, Cidr, Zones, answer, servfail};
use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::time::{sleep, timeout};

/// How long each upstream gets to answer.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a TCP client gets to send a query, or to take a reply.
const IDLE: Duration = Duration::from_secs(10);
const MAX_TCP_CONNECTIONS: usize = 64;
/// UDP queries being forwarded at once; more are dropped.
const MAX_FORWARDS: usize = 128;
/// Open TCP connections from one client IP.
pub(crate) const TCP_PER_IP: usize = 8;
/// Forwards in flight (UDP and TCP) for one client IP.
const FORWARDS_PER_IP: usize = 16;
/// A TCP connection ends after this long in all, or after this many queries.
const TCP_LIFETIME: Duration = Duration::from_secs(60);
pub(crate) const TCP_QUERIES: usize = 100;

type ZonesRx = watch::Receiver<Arc<Zones>>;

/// How many of something each client IP holds. An entry lives only while it is held.
#[derive(Clone, Default)]
pub(crate) struct PerIp(Arc<Mutex<HashMap<IpAddr, usize>>>);

/// One unit held for `ip`; dropping it gives the unit back.
pub(crate) struct Held(PerIp, IpAddr);

impl PerIp {
    /// A unit for `ip`, unless it already holds `max`.
    pub(crate) fn take(&self, ip: IpAddr, max: usize) -> Option<Held> {
        let ip = ip.to_canonical();
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let n = m.entry(ip).or_default();
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(Held(self.clone(), ip))
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let mut m = self.0.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

/// Whether a client may use the forwarder: one in `allowed`, or, when that is empty, one on a
/// loopback, private, link-local or unique-local address.
pub(crate) fn may_forward(ip: IpAddr, allowed: &[Cidr]) -> bool {
    let ip = ip.to_canonical();
    if !allowed.is_empty() {
        return allowed.iter().any(|n| n.contains(ip));
    }
    match ip {
        IpAddr::V4(a) => a.is_loopback() || a.is_private() || a.is_link_local(),
        IpAddr::V6(a) => a.is_loopback() || a.is_unique_local() || a.is_unicast_link_local(),
    }
}

#[derive(Clone)]
struct Shared {
    zones: ZonesRx,
    upstreams: Arc<[SocketAddr]>,
    forwarders: Arc<[Cidr]>,
    forwards: PerIp,
}

/// Serves DNS on `udp` and `tcp` until the task is dropped. Names outside `zones` go to each of
/// `upstreams` in turn, for clients in `forwarders` (or, when empty, on local networks); the zones
/// in the watch channel can be replaced while it runs.
pub async fn serve(
    udp: UdpSocket,
    tcp: TcpListener,
    zones: ZonesRx,
    upstreams: Vec<SocketAddr>,
    forwarders: Vec<Cidr>,
) {
    let shared = Shared {
        zones,
        upstreams: upstreams.into(),
        forwarders: forwarders.into(),
        forwards: PerIp::default(),
    };
    tokio::join!(serve_udp(udp, shared.clone()), serve_tcp(tcp, shared));
}

async fn serve_udp(sock: UdpSocket, sh: Shared) {
    let sock = Arc::new(sock);
    let slots = Arc::new(Semaphore::new(MAX_FORWARDS));
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            sleep(Duration::from_millis(50)).await;
            continue;
        };
        let zs = sh.zones.borrow().clone();
        match answer(&buf[..n], from.ip(), &zs, true) {
            Answer::Drop => {}
            Answer::Reply(r) => {
                let _ = sock.send_to(&r, from).await;
            }
            Answer::Forward if !may_forward(from.ip(), &sh.forwarders) => {
                let _ = sock.send_to(&wire::failure(&buf[..n], REFUSED), from).await;
            }
            Answer::Forward => {
                let (Ok(permit), Some(held)) = (
                    slots.clone().try_acquire_owned(),
                    sh.forwards.take(from.ip(), FORWARDS_PER_IP),
                ) else {
                    continue;
                };
                let (query, sock, upstreams) = (buf[..n].to_vec(), sock.clone(), sh.upstreams.clone());
                tokio::spawn(async move {
                    let limit = Query::parse(&query).map_or(512, |q| q.udp_limit());
                    let reply = wire::truncate(forward(&query, &upstreams, false).await, limit);
                    let _ = sock.send_to(&reply, from).await;
                    drop((permit, held));
                });
            }
        }
    }
}

async fn serve_tcp(listener: TcpListener, sh: Shared) {
    let slots = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    let conns = PerIp::default();
    loop {
        let Ok((stream, from)) = listener.accept().await else {
            sleep(Duration::from_millis(50)).await;
            continue;
        };
        let (Ok(permit), Some(held)) = (slots.clone().try_acquire_owned(), conns.take(from.ip(), TCP_PER_IP)) else {
            continue;
        };
        let sh = sh.clone();
        tokio::spawn(async move {
            let _ = timeout(TCP_LIFETIME, tcp_connection(stream, from, sh)).await;
            drop((permit, held));
        });
    }
}

/// Fails with TimedOut when `f` takes over `IDLE`.
async fn within<T>(f: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    timeout(IDLE, f)
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
}

/// Answers queries on one connection until the client stops, errs, goes idle or sends `TCP_QUERIES`.
async fn tcp_connection(mut s: TcpStream, from: SocketAddr, sh: Shared) -> io::Result<()> {
    for _ in 0..TCP_QUERIES {
        let query = within(read_frame(&mut s)).await?;
        let zs = sh.zones.borrow().clone();
        let reply = match answer(&query, from.ip(), &zs, false) {
            Answer::Drop => return Ok(()),
            Answer::Reply(r) => r,
            Answer::Forward if !may_forward(from.ip(), &sh.forwarders) => wire::failure(&query, REFUSED),
            Answer::Forward => match sh.forwards.take(from.ip(), FORWARDS_PER_IP) {
                Some(_held) => forward(&query, &sh.upstreams, true).await,
                None => servfail(&query),
            },
        };
        within(write_frame(&mut s, &reply)).await?;
    }
    Ok(())
}

/// One message with its 2-byte length. Anything shorter than a header ends the connection.
async fn read_frame(s: &mut (impl AsyncReadExt + Unpin)) -> io::Result<Vec<u8>> {
    let mut len = [0; 2];
    s.read_exact(&mut len).await?;
    let mut msg = vec![0; usize::from(u16::from_be_bytes(len))];
    if msg.len() < 12 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    s.read_exact(&mut msg).await?;
    Ok(msg)
}

async fn write_frame(s: &mut (impl AsyncWriteExt + Unpin), msg: &[u8]) -> io::Result<()> {
    let len = u16::try_from(msg.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    let mut frame = len.to_be_bytes().to_vec();
    frame.extend(msg);
    s.write_all(&frame).await
}

/// A random 16-bit id, from the keys std seeds its hash maps with.
fn random_id() -> u16 {
    RandomState::new().hash_one(0u8) as u16
}

/// Asks each upstream in turn (over TCP when the client used it, so no truncation) and returns
/// the first reply, or SERVFAIL. Each ask has its own random id; the reply gets the client's back.
async fn forward(query: &[u8], upstreams: &[SocketAddr], tcp: bool) -> Vec<u8> {
    for &up in upstreams {
        let Some(sent) = wire::for_upstream(query, random_id()) else {
            break;
        };
        let ask = async {
            if tcp {
                ask_tcp(&sent, up).await
            } else {
                ask_udp(&sent, up).await
            }
        };
        if let Ok(Ok(mut reply)) = timeout(UPSTREAM_TIMEOUT, ask).await {
            reply[..2].copy_from_slice(&query[..2]);
            return reply;
        }
    }
    servfail(query)
}

/// Whether `reply` answers `sent`: a response with the same id and the same question.
fn answers(sent: &[u8], reply: &[u8]) -> bool {
    let ask = |b: &[u8]| wire::question(b).map(|q| (q.0, q.1, q.2));
    reply.len() >= 12
        && reply[..2] == sent[..2]
        && reply[2] & 0x80 != 0
        && ask(sent).is_some()
        && ask(sent) == ask(reply)
}

async fn ask_udp(query: &[u8], up: SocketAddr) -> io::Result<Vec<u8>> {
    // A fresh socket on a random port, connected so the kernel drops datagrams from anyone else.
    let sock = UdpSocket::bind(if up.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
    sock.connect(up).await?;
    sock.send(query).await?;
    let mut buf = vec![0; usize::from(u16::MAX)];
    loop {
        let n = sock.recv(&mut buf).await?;
        if answers(query, &buf[..n]) {
            return Ok(buf[..n].to_vec());
        }
    }
}

async fn ask_tcp(query: &[u8], up: SocketAddr) -> io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(up).await?;
    write_frame(&mut s, query).await?;
    let reply = read_frame(&mut s).await?;
    if answers(query, &reply) {
        Ok(reply)
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}
