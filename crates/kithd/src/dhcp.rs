//! Asking the network for an address (DHCP, RFC 2131), for a machine whose first process
//! kithd is: nothing else on it would. One UDP socket per card, answers asked for by
//! broadcast (the card has no address to be answered at yet).
//
// ponytail: every renewal asks afresh (DISCOVER, then REQUEST) instead of extending the
// lease with its server alone, and an address the server takes back for another stays on
// the card beside the new one. Servers give a known card the address it had, so neither
// shows; do the RFC's RENEWING state when one does not.

use kith_mesh::Card;
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Debug, Clone, PartialEq)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub bits: u8,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    /// The time servers it names (option 42), first the one it likes best: `clock.rs` asks them.
    pub ntp: Vec<Ipv4Addr>,
    pub server: Ipv4Addr,
    pub secs: u32,
}

const MAGIC: [u8; 4] = [99, 130, 83, 99];
pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const ACK: u8 = 5;

/// A client's message: DISCOVER, or REQUEST for what a server `offered`.
pub fn message(kind: u8, xid: u32, mac: [u8; 6], hostname: &str, offered: Option<&Lease>) -> Vec<u8> {
    let mut message = vec![0; 236];
    (message[0], message[1], message[2]) = (1, 1, 6);
    message[4..8].copy_from_slice(&xid.to_be_bytes());
    message[10] = 0x80; // answer by broadcast
    message[28..34].copy_from_slice(&mac);
    message.extend(MAGIC);
    message.extend([53, 1, kind]);
    if let Some(lease) = offered {
        message.extend([50, 4]);
        message.extend(lease.address.octets());
        message.extend([54, 4]);
        message.extend(lease.server.octets());
    }
    let name = &hostname.as_bytes()[..hostname.len().min(63)];
    if !name.is_empty() {
        message.extend([12, name.len() as u8]);
        message.extend(name);
    }
    // Asked for: the subnet mask, the router, the name servers, how long it is for, the time servers.
    message.extend([55, 5, 1, 3, 6, 51, 42, 255]);
    message.resize(message.len().max(300), 0);
    message
}

/// A server's answer to the message `xid` of the card `mac`: its kind and what it gives.
/// Anything else (another client's, cut short, not DHCP, an address no machine can have,
/// no subnet mask) is `None`.
pub fn reply(packet: &[u8], xid: u32, mac: [u8; 6]) -> Option<(u8, Lease)> {
    let four = |bytes: &[u8]| <[u8; 4]>::try_from(bytes.get(..4)?).ok();
    let ours = packet.len() >= 240 && packet[0] == 2 && packet[4..8] == xid.to_be_bytes();
    if !ours || packet[28..34] != mac || packet[236..240] != MAGIC {
        return None;
    }
    let mut lease = Lease {
        address: four(&packet[16..])?.into(),
        bits: 0,
        router: None,
        dns: Vec::new(),
        ntp: Vec::new(),
        server: Ipv4Addr::UNSPECIFIED,
        secs: 3600,
    };
    let (mut kind, mut rest) = (None, &packet[240..]);
    loop {
        // (One that ends before its end mark was cut short.)
        let (&code, after) = rest.split_first()?;
        match code {
            0 => rest = after,
            255 => break,
            _ => {
                let length = usize::from(*after.first()?);
                let value = after.get(1..1 + length)?;
                match code {
                    53 => kind = value.first().copied(),
                    1 => lease.bits = u32::from_be_bytes(four(value)?).leading_ones() as u8,
                    3 => lease.router = four(value).map(Ipv4Addr::from),
                    6 => lease.dns = value.as_chunks::<4>().0.iter().copied().map(Ipv4Addr::from).collect(),
                    42 => {
                        lease.ntp = value
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .copied()
                            .take(4)
                            .map(Ipv4Addr::from)
                            .collect()
                    }
                    51 => lease.secs = u32::from_be_bytes(four(value)?),
                    54 => lease.server = four(value)?.into(),
                    _ => {}
                }
                rest = &after[1 + length..];
            }
        }
    }
    let a = lease.address;
    let usable = !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || a.is_broadcast());
    (usable && (1..=32).contains(&lease.bits)).then_some((kind?, lease))
}

async fn hear(socket: &UdpSocket, xid: u32, mac: [u8; 6], wanted: u8) -> Result<Lease> {
    let answer = async {
        let mut packet = [0; 1500];
        loop {
            let read = socket.recv(&mut packet).await?;
            match reply(&packet[..read], xid, mac) {
                Some((kind, lease)) if kind == wanted => return Ok(lease),
                Some((6, _)) => return Err(Error::other("the DHCP server refused")),
                _ => {}
            }
        }
    };
    let none = |_| Error::new(ErrorKind::TimedOut, "no DHCP server answered");
    tokio::time::timeout(Duration::from_secs(4), answer)
        .await
        .map_err(none)?
}

/// A socket on `port` of the card named `card` alone, that may send to everyone on its network.
pub fn socket(card: &str, port: u16) -> Result<UdpSocket> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, SockaddrIn, bind, setsockopt, socket, sockopt};
    use std::os::fd::AsRawFd;
    // Tied to the card before it is bound: so every card can have the port at once.
    let fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    setsockopt(&fd, sockopt::BindToDevice, &std::ffi::OsString::from(card))?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    setsockopt(&fd, sockopt::Broadcast, &true)?;
    bind(fd.as_raw_fd(), &SockaddrIn::new(0, 0, 0, 0, port))?;
    UdpSocket::from_std(fd.into())
}

/// Ask once, on `card` (which is up): what a server gives it.
pub async fn ask(card: &Card, hostname: &str) -> Result<Lease> {
    let socket = socket(&card.name, 68)?;
    let mut xid = [0; 4];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut xid)?;
    let xid = u32::from_be_bytes(xid);
    broadcast(card, &message(DISCOVER, xid, card.mac, hostname, None))?;
    let offer = hear(&socket, xid, card.mac, OFFER).await?;
    broadcast(card, &message(REQUEST, xid, card.mac, hostname, Some(&offer)))?;
    hear(&socket, xid, card.mac, ACK).await
}

/// Send `message` to every server on `card`'s network, from no address: as a frame of its
/// own, since the kernel would send it from an address of another card's (a pod's gateway,
/// say) while this one has none.
fn broadcast(card: &Card, message: &[u8]) -> Result<()> {
    send_frame(card, &frame(card.mac, message))
}

/// Send `frame`, an Ethernet frame whole, out of `card` as it is.
pub fn send_frame(card: &Card, frame: &[u8]) -> Result<()> {
    use std::os::fd::AsRawFd;
    let fd = packet_socket(card, false)?;
    nix::sys::socket::send(fd.as_raw_fd(), frame, nix::sys::socket::MsgFlags::empty())?;
    Ok(())
}

/// A raw socket on `card`: sends whole Ethernet frames, and hears every frame that comes or
/// goes on the card if `hear` (else nothing).
pub fn packet_socket(card: &Card, hear: bool) -> Result<std::os::fd::OwnedFd> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, bind, socket};
    use std::os::fd::AsRawFd;
    // (The card's own link address, as the kernel gives it, names it to bind to.)
    let link = nix::ifaddrs::getifaddrs()?
        .filter(|a| a.interface_name == card.name)
        .find_map(|a| a.address.and_then(|a| a.as_link_addr().copied()))
        .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no card {}", card.name)))?;
    let protocol = hear.then_some(SockProtocol::EthAll);
    let fd = socket(AddressFamily::Packet, SockType::Raw, SockFlag::SOCK_CLOEXEC, protocol)?;
    bind(fd.as_raw_fd(), &link)?;
    Ok(fd)
}

/// The Ethernet frame of a client's DHCP `message`: from `mac` and 0.0.0.0:68 to everyone's
/// port 67.
fn frame(mac: [u8; 6], message: &[u8]) -> Vec<u8> {
    let sum = |bytes: &[u8]| {
        let words = bytes
            .chunks(2)
            .map(|w| u32::from(w[0]) << 8 | u32::from(*w.get(1).unwrap_or(&0)));
        let total = words.sum::<u32>();
        let total = (total >> 16) + (total & 0xFFFF);
        !((total + (total >> 16)) as u16)
    };
    let length = 8 + message.len() as u16;
    let mut udp = [68u16.to_be_bytes(), 67u16.to_be_bytes(), length.to_be_bytes(), [0; 2]].concat();
    udp.extend(message);
    // (UDP's checksum is of a pseudo header too: both addresses, the protocol, the length.)
    let pseudo = [
        &[0, 0, 0, 0, 255, 255, 255, 255, 0, 17][..],
        &length.to_be_bytes(),
        &udp,
    ]
    .concat();
    let checksum = match sum(&pseudo) {
        0 => 0xFFFF,
        checksum => checksum,
    };
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    let mut ip = [0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255];
    ip[2..4].copy_from_slice(&(20 + length).to_be_bytes());
    let checksum = sum(&ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    [&[255; 6][..], &mac, &[8, 0], &ip, &udp].concat()
}

/// Keep `card` addressed for as long as this process lives: ask, put the address on it
/// (`got` is told each one), ask again halfway through the lease; until a server answers,
/// every few seconds, then every minute. (A task of kithd's one thread, not a thread of
/// its own: kithd forks containers.)
pub async fn keep(card: Card, hostname: String, got: impl Fn(&Lease)) {
    let (mut wait, mut had) = (1, None);
    loop {
        let lease = ask(&card, &hostname).await.and_then(|lease| {
            kith_mesh::address4(card.index, lease.address, lease.bits, lease.router)?;
            Ok(lease)
        });
        let pause = match lease {
            Ok(lease) => {
                if had.as_ref() != Some(&lease) {
                    eprintln!(
                        "kithd: init: {} has {}/{} by DHCP",
                        card.name, lease.address, lease.bits
                    );
                    got(&lease);
                }
                wait = 1;
                let pause = (lease.secs / 2).clamp(30, 86_400);
                had = Some(lease);
                pause
            }
            Err(e) => {
                // (Said once per silence: a card with no cable asks for ever.)
                if wait == 1 && had.is_none() {
                    eprintln!("kithd: init: {}: no address by DHCP yet: {e}", card.name);
                }
                wait = (wait * 2).min(60);
                wait
            }
        };
        tokio::time::sleep(Duration::from_secs(u64::from(pause))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_dhcp_messages_and_answers() {
        let mac = [0x52, 0x54, 0, 1, 2, 3];
        let discover = message(DISCOVER, 7, mac, "alpha", None);
        assert!(discover.len() >= 300);
        assert_eq!((discover[0], discover[10], &discover[28..34]), (1, 0x80, &mac[..]));
        assert_eq!(&discover[236..243], &[99, 130, 83, 99, 53, 1, DISCOVER]);
        // An answer, as a server writes it: ours by xid and card, with what it gives.
        let mut offer = vec![0; 236];
        offer[0] = 2;
        offer[4..8].copy_from_slice(&7u32.to_be_bytes());
        offer[16..20].copy_from_slice(&[10, 9, 0, 50]);
        offer[28..34].copy_from_slice(&mac);
        offer.extend(MAGIC);
        offer.extend([53, 1, OFFER, 0, 1, 4, 255, 255, 255, 0, 3, 4, 10, 9, 0, 1]);
        offer.extend([
            6, 8, 10, 9, 0, 1, 9, 9, 9, 9, 51, 4, 0, 0, 14, 16, 54, 4, 10, 9, 0, 1, 255,
        ]);
        let lease = Lease {
            address: [10, 9, 0, 50].into(),
            bits: 24,
            router: Some([10, 9, 0, 1].into()),
            dns: vec![[10, 9, 0, 1].into(), [9, 9, 9, 9].into()],
            ntp: Vec::new(),
            server: [10, 9, 0, 1].into(),
            secs: 3600,
        };
        assert_eq!(reply(&offer, 7, mac), Some((OFFER, lease.clone())));
        // The REQUEST names the address and the server it came from.
        let request = message(REQUEST, 7, mac, "", Some(&lease));
        assert_eq!(
            &request[240..255],
            &[53, 1, REQUEST, 50, 4, 10, 9, 0, 50, 54, 4, 10, 9, 0, 1]
        );
        // No address a machine can have, or no mask: not a lease.
        let mut nowhere = offer.clone();
        nowhere[16..20].copy_from_slice(&[0; 4]);
        assert_eq!(reply(&nowhere, 7, mac), None);
        let mut maskless = offer.clone();
        maskless[244] = 0; // (the mask's option, made padding: its value then reads as options 255...)
        assert_eq!(reply(&maskless, 7, mac), None);
        // Not ours, or not whole: nothing, and no panic wherever it is cut.
        assert_eq!(reply(&offer, 8, mac), None);
        assert_eq!(reply(&offer, 7, [0; 6]), None);
        for cut in 0..offer.len() - 1 {
            assert_eq!(reply(&offer[..cut], 7, mac), None, "cut at {cut}");
        }
    }

    #[test]
    fn init_dhcp_frames_go_from_no_address() {
        let mac = [0x52, 0x54, 0, 1, 2, 3];
        for message in [message(DISCOVER, 7, mac, "alpha", None), vec![1, 2, 3]] {
            let frame = frame(mac, &message);
            assert_eq!(
                (&frame[..6], &frame[6..12], &frame[12..14]),
                (&[255; 6][..], &mac[..], &[8, 0][..])
            );
            let (ip, udp) = frame[14..].split_at(20);
            assert_eq!((&ip[12..16], &ip[16..20], ip[9]), (&[0; 4][..], &[255; 4][..], 17));
            assert_eq!(usize::from(u16::from_be_bytes([ip[2], ip[3]])), 20 + udp.len());
            assert_eq!((&udp[..4], &udp[8..]), (&[0, 68, 0, 67][..], &message[..]));
            // A checksum is right when all its words, with it, sum (ones' complement) to all ones.
            let ones = |bytes: &[u8]| {
                let mut total: u32 = bytes
                    .chunks(2)
                    .map(|w| u32::from(w[0]) << 8 | u32::from(*w.get(1).unwrap_or(&0)))
                    .sum();
                while total > 0xFFFF {
                    total = (total >> 16) + (total & 0xFFFF);
                }
                total
            };
            assert_eq!(ones(ip), 0xFFFF);
            let length = (udp.len() as u16).to_be_bytes();
            let pseudo = [&[0, 0, 0, 0, 255, 255, 255, 255, 0, 17][..], &length, udp].concat();
            assert_eq!(ones(&pseudo), 0xFFFF);
        }
    }

    /// Against a real server (dnsmasq) at the other end of a veth pair, in a network
    /// namespace of this test's own: the card is given an address of the server's range.
    #[tokio::test]
    async fn init_dhcp_takes_an_address_from_a_server() {
        use std::process::Command;
        let me = "dhcp::tests::init_dhcp_takes_an_address_from_a_server";
        if std::env::var_os("KITH_E2E").is_none() {
            return eprintln!("skipped: set KITH_E2E=1");
        }
        if std::env::var_os("KITH_IN_NAMESPACE").is_none() {
            let unshare = |args: &[&str]| Command::new("unshare").arg("-Urn").args(args).status();
            let dnsmasq = Command::new("dnsmasq").arg("--version").output();
            if !unshare(&["true"]).is_ok_and(|status| status.success()) || dnsmasq.is_err() {
                return eprintln!("skipped: needs unprivileged user namespaces (unshare -Urn) and dnsmasq");
            }
            let again = format!("KITH_IN_NAMESPACE=1 exec \"$0\" --exact {me} --nocapture");
            let exe = std::env::current_exe().unwrap();
            let status = unshare(&["sh", "-c", &again, exe.to_str().unwrap()]).unwrap();
            assert!(status.success(), "the test failed inside its namespace");
            return;
        }
        let ip = |args: &str| {
            let done = Command::new("ip").args(args.split(' ')).output().unwrap();
            assert!(
                done.status.success(),
                "ip {args}: {}",
                String::from_utf8_lossy(&done.stderr)
            );
            String::from_utf8_lossy(&done.stdout).into_owned()
        };
        ip("link add kc type veth peer name ks");
        ip("addr add 10.9.0.1/24 dev ks");
        ip("link set ks up");
        // (Both ends are in one namespace, so each sees packets from an address of this
        // machine's own come in from outside, which a machine does not otherwise take.)
        for of in ["all", "kc", "ks"] {
            std::fs::write(format!("/proc/sys/net/ipv4/conf/{of}/rp_filter"), "0").unwrap();
            std::fs::write(format!("/proc/sys/net/ipv4/conf/{of}/accept_local"), "1").unwrap();
        }
        // (Ended whatever happens below: it would hold this test's output open.)
        struct Ended(std::process::Child);
        impl Drop for Ended {
            fn drop(&mut self) {
                let _ = (self.0.kill(), self.0.wait());
            }
        }
        let server = Command::new("dnsmasq")
            .args([
                "--no-daemon",
                "--conf-file=/dev/null",
                "--port=0",
                "--user=root",
                "--pid-file=",
            ])
            .args(["--interface=ks", "--bind-interfaces", "--dhcp-authoritative"])
            .args([
                "--dhcp-range=10.9.0.50,10.9.0.60,255.255.255.0,1h",
                "--dhcp-option=6,10.9.0.1,9.9.9.9",
            ])
            .arg("--leasefile-ro")
            .spawn()
            .unwrap();
        let _server = Ended(server);
        let card = kith_mesh::cards()
            .unwrap()
            .0
            .into_iter()
            .find(|card| card.name == "kc")
            .unwrap();
        kith_mesh::up(card.index).unwrap();
        // (The server needs a moment to listen, the link one to carry.)
        // (And two cards may ask at once, each on port 68: the other end does too.)
        let other = kith_mesh::cards()
            .unwrap()
            .0
            .into_iter()
            .find(|card| card.name == "ks")
            .unwrap();
        // Every frame of this namespace's, seen: what a client asks goes from no address
        // (RFC 2131 4.1), though the other card has one.
        use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType};
        let flags = SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK;
        let seen = nix::sys::socket::socket(AddressFamily::Packet, SockType::Raw, flags, SockProtocol::EthAll).unwrap();
        let mut lease = None;
        for _ in 0..10 {
            let (ours, theirs) = tokio::join!(ask(&card, "tester"), ask(&other, "other"));
            assert!(!theirs.is_err_and(|e| e.kind() == ErrorKind::AddrInUse));
            lease = lease.or(ours.map_err(|e| eprintln!("{e}")).ok());
            if lease.is_some() {
                break;
            }
        }
        let lease = lease.expect("no lease in ten tries");
        let (mut frame, mut asked) = ([0; 1600], Vec::new());
        while let Ok(length) = nix::sys::socket::recv(
            std::os::fd::AsRawFd::as_raw_fd(&seen),
            &mut frame,
            nix::sys::socket::MsgFlags::empty(),
        ) {
            let (kind, ip) = (&frame[12..14], &frame[14..length]);
            let udp = &ip[usize::from(ip[0] & 15) * 4..];
            if kind == [8, 0] && ip[9] == 17 && udp[..4] == [0, 68, 0, 67] {
                asked.push(Ipv4Addr::from(<[u8; 4]>::try_from(&ip[12..16]).unwrap()));
            }
        }
        assert!(!asked.is_empty(), "no DHCP client's frame seen");
        assert!(asked.iter().all(Ipv4Addr::is_unspecified), "asked from: {asked:?}");
        let range = u32::from(Ipv4Addr::new(10, 9, 0, 50))..=u32::from(Ipv4Addr::new(10, 9, 0, 60));
        assert!(range.contains(&u32::from(lease.address)), "{lease:?}");
        assert_eq!(
            (lease.bits, lease.router, lease.secs),
            (24, Some([10, 9, 0, 1].into()), 3600)
        );
        assert_eq!(lease.dns, [Ipv4Addr::new(10, 9, 0, 1), Ipv4Addr::new(9, 9, 9, 9)]);
        kith_mesh::address4(card.index, lease.address, lease.bits, lease.router).unwrap();
        assert!(ip("-4 -o addr show kc").contains(&format!("inet {}/24 brd 10.9.0.255", lease.address)));
        assert!(ip("-4 route show default").contains("default via 10.9.0.1 dev kc"));
    }
}

#[cfg(test)]
mod ntp {
    use super::*;

    /// A server's OFFER for xid 7 to `mac`, with `options` after the mask and before the end.
    fn offer(mac: [u8; 6], options: &[u8]) -> Vec<u8> {
        let mut offer = vec![0; 236];
        offer[0] = 2;
        offer[4..8].copy_from_slice(&7u32.to_be_bytes());
        offer[16..20].copy_from_slice(&[10, 9, 0, 50]);
        offer[28..34].copy_from_slice(&mac);
        offer.extend(MAGIC);
        offer.extend([53, 1, OFFER, 1, 4, 255, 255, 255, 0]);
        offer.extend(options);
        offer.push(255);
        offer
    }

    #[test]
    fn dhcp_ntp_option_42_is_parsed_into_the_lease() {
        let mac = [0x52, 0x54, 0, 1, 2, 3];
        let (_, lease) = reply(&offer(mac, &[42, 8, 10, 9, 0, 7, 10, 9, 0, 8]), 7, mac).unwrap();
        assert_eq!(lease.ntp, [Ipv4Addr::new(10, 9, 0, 7), Ipv4Addr::new(10, 9, 0, 8)]);
        // None named: none (and the lease is as before); a ragged tail is not an address.
        let (_, none) = reply(&offer(mac, &[]), 7, mac).unwrap();
        assert!(none.ntp.is_empty());
        let (_, ragged) = reply(&offer(mac, &[42, 6, 10, 9, 0, 7, 1, 2]), 7, mac).unwrap();
        assert_eq!(ragged.ntp, [Ipv4Addr::new(10, 9, 0, 7)]);
        // A server that names a hundred is heard for four.
        let mut many = vec![42, 40];
        many.extend((1..=10).flat_map(|n| [10, 9, 0, n]));
        let (_, many) = reply(&offer(mac, &many), 7, mac).unwrap();
        assert_eq!(many.ntp.len(), 4);
    }

    #[test]
    fn dhcp_ntp_server_choice_is_the_one_told_and_the_lease_only_where_none_is() {
        let mac = [0x52, 0x54, 0, 1, 2, 3];
        let options = [3, 4, 10, 9, 0, 1, 42, 4, 10, 9, 0, 7];
        let (_, lease) = reply(&offer(mac, &options), 7, mac).unwrap();
        let told = Some("10.9.0.9:5123".parse().unwrap());
        let at = |address: &str| address.parse::<std::net::SocketAddr>().unwrap();
        // A rogue DHCP server's option 42 does not outrank the operator's word.
        assert_eq!(
            crate::clock::order(&lease.ntp, told, lease.router),
            [at("10.9.0.9:5123")]
        );
        // Nothing told: the lease's server, then the gateway.
        assert_eq!(
            crate::clock::order(&lease.ntp, None, lease.router),
            [at("10.9.0.7:123"), at("10.9.0.1:123")]
        );
        // A network that names none, and one told: the one told; with neither, none
        // (the cluster's leader is asked then, as `clock::ask` does).
        let (_, bare) = reply(&offer(mac, &options[..6]), 7, mac).unwrap();
        assert_eq!(crate::clock::order(&bare.ntp, told, bare.router), [at("10.9.0.9:5123")]);
        assert!(crate::clock::order(&bare.ntp, None, None).is_empty());
    }

    #[test]
    fn dhcp_ntp_is_asked_for_in_every_message() {
        let mac = [0x52, 0x54, 0, 1, 2, 3];
        for kind in [DISCOVER, REQUEST] {
            let message = message(kind, 7, mac, "", None);
            let at = message
                .windows(2)
                .position(|w| w == [55, 5])
                .expect("a parameter request list");
            assert_eq!(&message[at + 2..at + 8], &[1, 3, 6, 51, 42, 255]);
        }
    }
}
