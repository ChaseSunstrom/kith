//! What the root part is asked (docs/adr-privilege.md, "The requests"): one typed enum, so
//! that what the serving part may have the root part do is this list and nothing else.
//! [`Root`] is the seam: [`Direct`] does a request in this process, as kithd has always done;
//! the root part as a second process takes the same [`Request`]s over a socket pair, with
//! [`decode`] reading each one. Only the Listeners family is here so far.
//!
//! A request is refused for what it is, never for who asked ([`check`]).

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::OwnedFd;

/// The most a request may be, in bytes (a datagram of the socket pair; bigger things travel
/// as file handles beside it).
pub const MAX_REQUEST: usize = 256 * 1024;

/// The ports kithd serves on itself: its API, the registry and the mesh's WireGuard. The
/// root part refuses to bind them for the serving part, which would otherwise have it take
/// over what it serves.
const OWN_PORTS: [u16; 3] = [7443, 5000, 51820];

/// What a socket is for: only these two, so a request for any other protocol does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

/// One thing the serving part asks of the root part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Request {
    /// A socket bound to `address` and `port`; a tcp one is listening.
    Bind { address: IpAddr, port: u16, proto: Proto },
}

/// Read one request off the wire: at most [`MAX_REQUEST`] bytes, JSON, no field or variant
/// this build does not know.
// (Nothing reads a wire yet: the root part is not a second process. The tests do.)
#[allow(dead_code)]
pub fn decode(bytes: &[u8]) -> Result<Request, String> {
    if bytes.len() > MAX_REQUEST {
        return Err(format!("request of {} bytes: at most {MAX_REQUEST}", bytes.len()));
    }
    serde_json::from_slice(bytes).map_err(|e| format!("request: {e}"))
}

/// Why a request is refused, or `Ok` when the root part may do it. It looks at what is
/// asked and never at who asks.
pub fn check(request: &Request) -> Result<(), String> {
    match request {
        Request::Bind { address, port, .. } => {
            if OWN_PORTS.contains(port) {
                return Err(format!("port {port} is one kithd serves on itself"));
            }
            if address.is_multicast() {
                return Err(format!("{address} is a multicast address: not an address to listen on"));
            }
            Ok(())
        }
    }
}

/// The root part, as the serving part sees it.
pub trait Root {
    /// Do `request` if [`check`] allows it; a `Bind` gives the socket.
    fn request(&self, request: Request) -> Result<OwnedFd, String>;
}

/// The root part inside this process: today's code, called directly.
pub struct Direct;

impl Root for Direct {
    fn request(&self, request: Request) -> Result<OwnedFd, String> {
        check(&request)?;
        let Request::Bind { address, port, proto } = request;
        let at = SocketAddr::new(address, port);
        let made = match proto {
            Proto::Tcp => TcpListener::bind(at).map(OwnedFd::from),
            Proto::Udp => UdpSocket::bind(at).map(OwnedFd::from),
        };
        made.map_err(|e| format!("binding {address} port {port}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(address: &str, port: u16, proto: Proto) -> Request {
        Request::Bind { address: address.parse().unwrap(), port, proto }
    }

    #[test]
    fn wire() {
        // A good Bind reads back, and what is sent is what is read.
        let good = br#"{"Bind":{"address":"::1","port":2049,"proto":"tcp"}}"#;
        assert_eq!(decode(good).unwrap(), ask("::1", 2049, Proto::Tcp));
        let sent = serde_json::to_vec(&ask("127.0.0.1", 53, Proto::Udp)).unwrap();
        assert_eq!(decode(&sent).unwrap(), ask("127.0.0.1", 53, Proto::Udp));
        // Over 256 KiB is refused unread, even where it would otherwise be a good request.
        let mut big = good.to_vec();
        big.resize(MAX_REQUEST + 1, b' ');
        assert!(decode(&big).unwrap_err().contains("at most"));
        big.truncate(MAX_REQUEST);
        assert!(decode(&big).is_ok(), "exactly the limit is taken");
        // An unknown field, an unknown variant, an unknown protocol, a port out of range,
        // a name for an address, and noise are refused.
        for bad in [
            &br#"{"Bind":{"address":"::1","port":2049,"proto":"tcp","path":"/etc"}}"#[..],
            br#"{"Exec":{"argv":["sh"]}}"#,
            br#"{"Bind":{"address":"::1","port":2049,"proto":"sctp"}}"#,
            br#"{"Bind":{"address":"::1","port":70000,"proto":"tcp"}}"#,
            br#"{"Bind":{"address":"localhost","port":2049,"proto":"tcp"}}"#,
            br#"{"Bind":{"address":"::1","port":2049}}"#,
            b"not json",
            b"",
        ] {
            assert!(decode(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn bind() {
        // Whatever the asker says, a port kithd serves on is refused, on either family.
        for port in OWN_PORTS {
            for address in ["127.0.0.1", "::1", "0.0.0.0", "::"] {
                for proto in [Proto::Tcp, Proto::Udp] {
                    let why = Direct.request(ask(address, port, proto)).unwrap_err();
                    assert!(why.contains("serves on itself"), "{address} {port}: {why}");
                }
            }
        }
        // A multicast address is not one to listen on.
        assert!(check(&ask("224.0.0.1", 9000, Proto::Udp)).is_err());
        assert!(check(&ask("ff02::1", 9000, Proto::Udp)).is_err());
        // An allowed one gives a socket: a tcp one listening, a udp one bound.
        let tcp = Direct.request(ask("127.0.0.1", 0, Proto::Tcp)).unwrap();
        let tcp = TcpListener::from(tcp);
        assert!(tcp.local_addr().unwrap().ip().is_loopback());
        let udp = Direct.request(ask("::1", 0, Proto::Udp));
        // (A container with no IPv6 loopback cannot bind it: that is the system's refusal.)
        if let Ok(udp) = udp {
            assert!(UdpSocket::from(udp).local_addr().unwrap().is_ipv6());
        }
        assert!(UdpSocket::from(Direct.request(ask("127.0.0.1", 0, Proto::Udp)).unwrap()).local_addr().is_ok());
        // A port taken is the system's refusal, said with the address.
        let taken = tcp.local_addr().unwrap().port();
        let why = Direct.request(ask("127.0.0.1", taken, Proto::Tcp)).unwrap_err();
        assert!(why.contains("binding 127.0.0.1"), "{why}");
    }
}
