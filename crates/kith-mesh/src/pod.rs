//! A pod's own network: a network namespace, and a pair of links between it and the node
//! (`eth0` in the pod, `kp<number>` on the node). The pod has an IPv4 address only its
//! node knows (what leaves the node from it leaves as the node: [`node`]), and an address
//! in its node's /80 of the mesh, which every node reaches. Made and set up over netlink
//! and by the kernel's own calls: no `ip`, no `nft`, no plugin.
//
// ponytail: the IPv4 range is fixed (100.88.0.0/16, of the range set aside for carriers'
// NAT): a node whose own network uses it needs this to be a flag. 65533 pods a node.

use crate::netlink::{ask_route, link, silent, up};
use netlink_packet_core::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE};
use netlink_packet_route::address::{AddressAttribute, AddressFlags, AddressMessage};
use netlink_packet_route::link::{InfoData, InfoKind, InfoVeth, LinkAttribute, LinkInfo};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use nix::sched::{CloneFlags, setns, unshare};
use std::fs::File;
use std::io::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

/// What every pod sends through, and where it asks for names: an address of the node's
/// that is on no wire.
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(100, 88, 0, 1);
const GATEWAY6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
/// The numbers a pod of a node may have (0 is the range's own, 1 the node's).
pub const NUMBERS: std::ops::RangeInclusive<u16> = 2..=65534;

/// The addresses of a node's pod `number`: the IPv4 one, and the one in the node's /80.
pub fn addresses(node_net: Option<Ipv6Addr>, number: u16) -> (Ipv4Addr, Option<Ipv6Addr>) {
    let [high, low] = number.to_be_bytes();
    let v6 = node_net.map(|net| {
        let mut bytes = net.octets();
        (bytes[13], bytes[14], bytes[15]) = (1, high, low);
        bytes.into()
    });
    (Ipv4Addr::new(100, 88, high, low), v6)
}

fn address(index: u32, address: IpAddr, bits: u8) -> Result<()> {
    let mut message = AddressMessage::default();
    message.header.family = match address {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    (message.header.prefix_len, message.header.index) = (bits, index);
    // (Nobody else is on the wire to have the address already: it is good at once.)
    let now = AddressAttribute::Flags(AddressFlags::Nodad);
    message.attributes.extend([
        AddressAttribute::Local(address),
        AddressAttribute::Address(address),
        now,
    ]);
    ask_route(
        RouteNetlinkMessage::NewAddress(message),
        NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
    )
    .map(drop)
}

/// A route out of link `index`: to `to` alone, or (`None`) to everywhere, through `via`.
fn route(index: u32, to: Option<IpAddr>, via: Option<IpAddr>) -> Result<()> {
    let mut route = RouteMessage::default();
    let v4 = matches!(to.or(via), Some(IpAddr::V4(_)));
    route.header.address_family = if v4 { AddressFamily::Inet } else { AddressFamily::Inet6 };
    route.header.table = 254; // main
    route.header.protocol = RouteProtocol::Boot;
    route.header.scope = if via.is_some() {
        RouteScope::Universe
    } else {
        RouteScope::Link
    };
    route.header.kind = RouteType::Unicast;
    let said = |address: IpAddr| match address {
        IpAddr::V4(address) => RouteAddress::Inet(address),
        IpAddr::V6(address) => RouteAddress::Inet6(address),
    };
    if let Some(to) = to {
        route.header.destination_prefix_length = if v4 { 32 } else { 128 };
        route.attributes.push(RouteAttribute::Destination(said(to)));
    }
    route
        .attributes
        .extend(via.map(|via| RouteAttribute::Gateway(said(via))));
    route.attributes.push(RouteAttribute::Oif(index));
    ask_route(
        RouteNetlinkMessage::NewRoute(route),
        NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
    )
    .map(drop)
}

fn index_of(name: &str) -> Result<u32> {
    let found = ask_route(RouteNetlinkMessage::GetLink(link(0, Some(name))), NLM_F_ACK)?;
    match found.into_iter().next() {
        Some(RouteNetlinkMessage::NewLink(found)) => Ok(found.header.index),
        _ => Err(Error::other(format!("no word from the kernel about {name}"))),
    }
}

fn enter(namespace: &impl AsFd) -> Result<()> {
    setns(namespace, CloneFlags::CLONE_NEWNET).map_err(Error::from)
}

/// Do `f` in the network namespace `namespace`: on a thread of its own, which ends there.
/// A socket made in it stays in it, whoever uses it afterwards.
pub fn within<T: Send>(namespace: &(impl AsFd + Sync), f: impl FnOnce() -> T + Send) -> Result<T> {
    let there = || enter(namespace).map(|()| f());
    std::thread::scope(|scope| scope.spawn(there).join())
        .unwrap_or_else(|_| Err(Error::other("the thread in the namespace panicked")))
}

/// Make the pod `number` its network namespace, with the addresses [`addresses`] gives
/// it, and give the namespace back: it lasts while this, or a process in it, does, and
/// the links go with it. Only root can ([`node`] comes first, once).
pub fn make(number: u16, v6: Option<Ipv6Addr>) -> Result<OwnedFd> {
    let (v4, _) = addresses(None, number);
    let host = format!("kp{number}");
    // (A thread of its own: it is in the pod's namespace for a while, and nothing else of
    // this process must find itself there.)
    let made = || -> Result<OwnedFd> {
        let ours = File::open("/proc/thread-self/ns/net")?;
        unshare(CloneFlags::CLONE_NEWNET)?;
        let pod = File::open("/proc/thread-self/ns/net")?;
        // Any port is the pod's own user's to listen on: nobody else is in here.
        std::fs::write("/proc/sys/net/ipv4/ip_unprivileged_port_start", "0")?;
        up(1)?; // (the loopback: the first link of a new namespace)

        enter(&ours)?;
        // (One left by a pod of this number that is gone is in the way: away with it.)
        let _ = ask_route(RouteNetlinkMessage::DelLink(link(0, Some(&host))), NLM_F_ACK);
        let mut peer = link(0, Some("eth0"));
        peer.attributes.push(LinkAttribute::NetNsFd(pod.as_raw_fd()));
        let mut pair = link(0, Some(&host));
        pair.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Veth),
            LinkInfo::Data(InfoData::Veth(InfoVeth::Peer(peer))),
        ]));
        ask_route(
            RouteNetlinkMessage::NewLink(pair),
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        )?;
        let node = index_of(&host)?;
        up(node)?;
        address(node, GATEWAY6.into(), 64)?;
        route(node, Some(v4.into()), None)?;
        v6.map_or(Ok(()), |v6| route(node, Some(v6.into()), None))?;

        enter(&pod)?;
        let eth0 = index_of("eth0")?;
        up(eth0)?;
        address(eth0, v4.into(), 32)?;
        route(eth0, Some(GATEWAY.into()), None)?;
        route(eth0, None, Some(GATEWAY.into()))?;
        if let Some(v6) = v6 {
            address(eth0, v6.into(), 128)?;
            route(eth0, None, Some(GATEWAY6.into()))?;
        }
        Ok(pod.into())
    };
    std::thread::scope(|scope| scope.spawn(made).join())
        .unwrap_or_else(|_| Err(Error::other("the thread making the namespace panicked")))
}

/// Make this machine the node its pods need, once before the first: [`GATEWAY`] on the
/// loopback, packets passed on between links, and what leaves from a pod's IPv4 address
/// sent as the node's own.
///
/// A machine that passed nothing on until now (or `guarded`: until this was done here
/// before) passes on only what comes from or goes to a pod: it is no more of a router for
/// anyone else than it was. Returns whether that is so, for the caller to say next time.
pub fn node(guarded: bool) -> Result<bool> {
    node_with(guarded, true)
}

fn node_with(guarded: bool, masquerade: bool) -> Result<bool> {
    crate::address4(1, GATEWAY, 32, None)?;
    let passes = "/proc/sys/net/ipv6/conf/all/forwarding";
    let guard = guarded || !std::fs::read_to_string(passes).is_ok_and(|said| said.trim() == "1");
    nat(guard, masquerade)?;
    // A machine that passes packets on stops listening to its router's advertisements,
    // unless told to go on (2): the node's own way out must not be lost to this.
    for link in std::fs::read_dir("/proc/sys/net/ipv6/conf")?.flatten() {
        let heard = link.path().join("accept_ra");
        if std::fs::read_to_string(&heard).is_ok_and(|said| said.trim() == "1") {
            std::fs::write(heard, "2")?;
        }
    }
    std::fs::write(passes, "1")?;
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    Ok(guard)
}

// ---- nftables, as the kernel takes it (nfnetlink): a few attributes by hand ----

const NESTED: u16 = 0x8000;

fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.len() + 8);
    bytes.extend((value.len() as u16 + 4).to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.extend(value);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

fn text(kind: u16, text: &str) -> Vec<u8> {
    attribute(kind, &[text.as_bytes(), &[0]].concat())
}

fn number(kind: u16, number: u32) -> Vec<u8> {
    attribute(kind, &number.to_be_bytes())
}

/// An expression of a rule: its name and what it is told.
fn expression(name: &str, told: &[Vec<u8>]) -> Vec<u8> {
    let told = attribute(2 | NESTED, &told.concat());
    attribute(1 | NESTED, &[text(1, name), told].concat())
}

/// Register 1 is what `bytes` are (the comparison every rule here ends its looking with).
fn is(bytes: &[u8]) -> Vec<u8> {
    let value = attribute(3 | NESTED, &attribute(1, bytes));
    expression("cmp", &[number(1, 1), number(2, 0), value])
}

/// The tables: `ip kith-pods` sends what comes from a pod's IPv4 address out as the
/// node's (masquerade); with `guard`, `inet kith-pods` lets nothing be passed on but what
/// comes in from or goes out to a pod's link.
fn nat(guard: bool, masquerade: bool) -> Result<()> {
    const TABLE: &str = "kith-pods";
    let (ip, inet) = (2u8, 1u8);
    // (New table, delete table, new chain, new rule: of the subsystem nftables, 10.)
    let (new_table, delete_table, new_chain, new_rule) = (0xa00u16, 0xa02u16, 0xa03u16, 0xa06u16);
    let mut batch = Vec::new();
    let mut sequence = 0u32;
    let mut say = |kind: u16, family: u8, subsystem: u16, attributes: &[Vec<u8>]| {
        let attributes = attributes.concat();
        sequence += 1;
        batch.extend((attributes.len() as u32 + 20).to_ne_bytes());
        batch.extend(kind.to_ne_bytes());
        // A request; what is not the batch's own beginning or end: acknowledged, and may create.
        batch.extend(if subsystem == 0 { 0x405u16 } else { 1 }.to_ne_bytes());
        batch.extend(sequence.to_ne_bytes());
        batch.extend(0u32.to_ne_bytes());
        batch.extend([family, 0]);
        batch.extend(subsystem.to_be_bytes());
        batch.extend(attributes);
    };
    let chain = |name: &str, kind: &str, hook: u32, priority: u32, policy: Option<u32>| {
        let hook = attribute(4 | NESTED, &[number(1, hook), number(2, priority)].concat());
        let mut chain = vec![text(1, TABLE), text(3, name), hook, text(7, kind)];
        chain.extend(policy.map(|policy| number(5, policy)));
        chain
    };
    let rule = |chain: &str, expressions: &[Vec<u8>]| {
        vec![
            text(1, TABLE),
            text(2, chain),
            attribute(4 | NESTED, &expressions.concat()),
        ]
    };
    say(0x10, 0, 10, &[]); // a batch begins
    for family in [ip, inet] {
        // (Made so that it is there to take away: what an earlier kithd left goes.)
        say(new_table, family, 0, &[text(1, TABLE)]);
        say(delete_table, family, 0, &[text(1, TABLE)]);
    }
    say(new_table, ip, 0, &[text(1, TABLE)]);
    // After routing (hook 4), where addresses are changed on the way out (priority 100).
    say(new_chain, ip, 0, &chain("out", "nat", 4, 100, None));
    // The first two bytes of where it comes from (12 into the IP header) are the range's.
    let from = expression("payload", &[number(1, 1), number(2, 1), number(3, 12), number(4, 2)]);
    let [first, second, ..] = GATEWAY.octets();
    if masquerade {
        say(
            new_rule,
            ip,
            0,
            &rule("out", &[from, is(&[first, second]), expression("masq", &[])]),
        );
    }
    if guard {
        say(new_table, inet, 0, &[text(1, TABLE)]);
        // What is passed on (hook 2): dropped (0) unless a rule lets it through.
        say(new_chain, inet, 0, &chain("passed", "filter", 2, 0, Some(0)));
        // (6 and 7: the names of the links it came in by and goes out by.)
        for link in [6, 7] {
            let name = expression("meta", &[number(2, link), number(1, 1)]);
            let verdict = attribute(2 | NESTED, &attribute(2 | NESTED, &number(1, 1)));
            let accept = expression("immediate", &[number(1, 0), verdict]);
            say(new_rule, inet, 0, &rule("passed", &[name, is(b"kp"), accept]));
        }
    }
    say(0x11, 0, 10, &[]); // and ends
    let last = sequence - 1;

    let socket = crate::netlink::socket(12)?; // netfilter's
    socket.send(&batch, 0)?;
    // The kernel answers each message in turn: a no is the answer, or the last one's yes.
    loop {
        let (bytes, _) = socket.recv_from_full().map_err(silent)?;
        let mut rest = &bytes[..];
        while let (Some(header), Some(code)) = (rest.get(..16), rest.get(16..20)) {
            let field = |at: usize| u32::from_ne_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]]);
            let code = i32::from_ne_bytes([code[0], code[1], code[2], code[3]]);
            // (2: an error, or with code 0 an acknowledgement.)
            if header[4..6] == 2u16.to_ne_bytes() && code != 0 {
                return Err(Error::from_raw_os_error(-code));
            }
            if field(8) == last {
                return Ok(());
            }
            rest = rest
                .get((field(0) as usize).next_multiple_of(4).max(16)..)
                .unwrap_or_default();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};

    #[test]
    fn a_pods_addresses_are_its_nodes() {
        let net = crate::node_net(crate::prefix(b"test"), "alpha");
        let (v4, v6) = addresses(Some(net), 0x0102);
        assert_eq!(v4, Ipv4Addr::new(100, 88, 1, 2));
        let (v6, net) = (v6.unwrap().octets(), net.octets());
        assert_eq!((&v6[..10], &v6[10..]), (&net[..10], &[0, 0, 0, 1, 1, 2][..]));
        assert_ne!(v6, crate::node_address(crate::prefix(b"test"), "alpha").octets());
    }

    /// Two pods of one node, as root of a network namespace (`unshare -Urn cargo test -p
    /// kith-mesh pods`): both listen on port 80, each is reached in its own namespace,
    /// at its own address from the node and from the other pod, and what one sends to the
    /// other's IPv4 address comes from the node.
    #[test]
    fn pods_have_a_network_each() {
        if !nix::unistd::getuid().is_root() || std::env::var_os("KITH_E2E").is_none() {
            return eprintln!("skipped: KITH_E2E=1 unshare -Urn cargo test -p kith-mesh pods");
        }
        up(1).unwrap();
        // (A kernel whose masquerade is a module nobody loaded has none in a namespace.)
        let masquerade = match node(false) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            guarded => guarded.unwrap(),
        };
        if !masquerade {
            eprintln!("this kernel has no masquerade here: without");
            assert!(node_with(false, false).unwrap());
        }
        let net = crate::node_net(crate::prefix(b"test"), "alpha");
        let pods: Vec<_> = [2, 3]
            .map(|number| {
                let (v4, v6) = addresses(Some(net), number);
                let namespace = make(number, v6).unwrap();
                let listener = within(&namespace, || TcpListener::bind("[::]:80")).unwrap().unwrap();
                (namespace, listener, v4, v6.unwrap())
            })
            .into();
        // Each says who it is to whoever connects, and who that was.
        let serve = |listener: &TcpListener, says: &str| {
            let (mut stream, from) = listener.accept().unwrap();
            stream.write_all(says.as_bytes()).unwrap();
            from
        };
        let read = |mut stream: TcpStream| {
            let mut said = String::new();
            stream.read_to_string(&mut said).unwrap();
            said
        };
        std::thread::scope(|scope| {
            let served = scope.spawn(|| {
                let mut from = Vec::new();
                for _ in 0..3 {
                    from.push(serve(&pods[0].1, "first"));
                }
                for _ in 0..2 {
                    from.push(serve(&pods[1].1, "second"));
                }
                from
            });
            // In its own namespace, on the loopback: where a Service's connection goes.
            let inside = |pod: usize| {
                within(&pods[pod].0, || TcpStream::connect("127.0.0.1:80"))
                    .unwrap()
                    .unwrap()
            };
            assert_eq!(read(inside(0)), "first");
            // From the node, at the pod's address on the mesh.
            assert_eq!(read(TcpStream::connect((pods[0].3, 80)).unwrap()), "first");
            // From the other pod: by the mesh address as itself, by IPv4 as the node.
            let other = |to: SocketAddr| within(&pods[1].0, || TcpStream::connect(to)).unwrap().unwrap();
            assert_eq!(read(other((pods[0].3, 80).into())), "first");
            assert_eq!(read(inside(1)), "second");
            let other = |to: SocketAddr| within(&pods[0].0, || TcpStream::connect(to)).unwrap().unwrap();
            assert_eq!(read(other((pods[1].2, 80).into())), "second");
            let from: Vec<IpAddr> = served
                .join()
                .unwrap()
                .iter()
                .map(|from| from.ip().to_canonical())
                .collect();
            let local = IpAddr::from(Ipv4Addr::LOCALHOST);
            assert_eq!((from[0], from[2], from[3]), (local, pods[1].3.into(), local));
            let node = if masquerade { GATEWAY } else { pods[0].2 };
            assert_eq!(
                from[4],
                IpAddr::from(node),
                "what leaves a pod by IPv4 leaves as the node"
            );
        });
        // A second time changes nothing (what the first left is taken away and made again).
        assert!(node_with(true, masquerade).unwrap());
    }
}
