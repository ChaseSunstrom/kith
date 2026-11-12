//! The UDP and TCP servers and the forwarder.

use crate::{Answer, Zones, answer, servfail};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
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

type ZonesRx = watch::Receiver<Arc<Zones>>;

/// Serves DNS on `udp` and `tcp` until the task is dropped. Names outside `zones` go to each of
/// `upstreams` in turn; the zones in the watch channel can be replaced while it runs.
pub async fn serve(udp: UdpSocket, tcp: TcpListener, zones: ZonesRx, upstreams: Vec<SocketAddr>) {
    let upstreams: Arc<[SocketAddr]> = upstreams.into();
    tokio::join!(
        serve_udp(udp, zones.clone(), upstreams.clone()),
        serve_tcp(tcp, zones, upstreams)
    );
}

async fn serve_udp(sock: UdpSocket, zones: ZonesRx, upstreams: Arc<[SocketAddr]>) {
    let sock = Arc::new(sock);
    let slots = Arc::new(Semaphore::new(MAX_FORWARDS));
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            sleep(Duration::from_millis(50)).await;
            continue;
        };
        let zs = zones.borrow().clone();
        match answer(&buf[..n], from.ip(), &zs, true) {
            Answer::Drop => {}
            Answer::Reply(r) => {
                let _ = sock.send_to(&r, from).await;
            }
            Answer::Forward => {
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    continue;
                };
                let (query, sock, upstreams) = (buf[..n].to_vec(), sock.clone(), upstreams.clone());
                tokio::spawn(async move {
                    let _ = sock.send_to(&forward(&query, &upstreams, false).await, from).await;
                    drop(permit);
                });
            }
        }
    }
}

async fn serve_tcp(listener: TcpListener, zones: ZonesRx, upstreams: Arc<[SocketAddr]>) {
    let slots = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let Ok((stream, from)) = listener.accept().await else {
            sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let (zones, upstreams) = (zones.clone(), upstreams.clone());
        tokio::spawn(async move {
            let _ = tcp_connection(stream, from, zones, upstreams).await;
            drop(permit);
        });
    }
}

/// Fails with TimedOut when `f` takes over `IDLE`.
async fn within<T>(f: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    timeout(IDLE, f)
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
}

/// Answers queries on one connection until the client stops, errs or goes idle.
async fn tcp_connection(
    mut s: TcpStream,
    from: SocketAddr,
    zones: ZonesRx,
    upstreams: Arc<[SocketAddr]>,
) -> io::Result<()> {
    loop {
        let query = within(read_frame(&mut s)).await?;
        let zs = zones.borrow().clone();
        let reply = match answer(&query, from.ip(), &zs, false) {
            Answer::Drop => return Ok(()),
            Answer::Reply(r) => r,
            Answer::Forward => forward(&query, &upstreams, true).await,
        };
        within(write_frame(&mut s, &reply)).await?;
    }
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

/// Asks each upstream in turn (over TCP when the client used it, so no truncation) and returns
/// the first reply, or SERVFAIL.
async fn forward(query: &[u8], upstreams: &[SocketAddr], tcp: bool) -> Vec<u8> {
    for &up in upstreams {
        let ask = async {
            if tcp {
                ask_tcp(query, up).await
            } else {
                ask_udp(query, up).await
            }
        };
        if let Ok(Ok(reply)) = timeout(UPSTREAM_TIMEOUT, ask).await {
            return reply;
        }
    }
    servfail(query)
}

/// Whether `reply` answers `query`: a response with the same id.
fn answers(query: &[u8], reply: &[u8]) -> bool {
    reply.len() >= 12 && reply[..2] == query[..2] && reply[2] & 0x80 != 0
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
