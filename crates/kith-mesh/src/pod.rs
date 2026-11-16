//! A pod's own network: a network namespace, and a pair of links between it and the node
//! (`eth0` in the pod, `kp<number>` on the node). The pod has an IPv4 address only its
//! node knows (what leaves the node from it leaves as the node: [`node`]), and an address
//! in its node's /80 of the mesh, which every node reaches. Made and set up over netlink
//! and by the kernel's own calls: no `ip`, no `nft`, no plugin.
//
// ponytail: the IPv4 range is a flag of the node's kithd ([`Range`]; 100.88.0.0/16, of the
// range set aside for carriers' NAT, unless told). At most 65533 pods a node, whatever the
// range holds; a range's own network is read once, at start: one that comes up on this node
// later (a tailnet) and clashes is not noticed; the gateway of an earlier range stays on the
// loopback until reboot (nothing tells it from one an operator put there: it is only skipped).

use crate::netlink::{ask_route, link, silent, up};
use netlink_packet_core::{NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REPLACE};
use netlink_packet_route::address::{AddressAttribute, AddressFlags, AddressMessage};
use netlink_packet_route::link::{InfoData, InfoKind, InfoVeth, LinkAttribute, LinkInfo};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use nix::sched::{CloneFlags, setns, unshare};
use std::fs::File;
use std::io::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

const GATEWAY6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

/// The IPv4 range a node's pods get their addresses from (`kithd --pod-range`): an address
/// only that node knows. Its first address is what every pod sends through and where it
/// asks for names ([`Range::gateway`]: on no wire), pod `number` has the range's `number`th.
/// From /8 to /24 (a /24 holds 254 pods at most), whole networks, and none that is not a
/// private or public unicast one (no loopback, link-local, multicast or reserved).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    network: u32,
    bits: u8,
}

impl Default for Range {
    fn default() -> Self {
        Self::new(Ipv4Addr::new(100, 88, 0, 0), 16).expect("the default range is a good one")
    }
}

impl std::fmt::Display for Range {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.network), self.bits)
    }
}

impl std::str::FromStr for Range {
    type Err = String;
    fn from_str(text: &str) -> std::result::Result<Self, String> {
        let (address, bits) = text
            .split_once('/')
            .ok_or("not an IPv4 network: say ADDRESS/BITS, as 10.77.0.0/16")?;
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| format!("{address} is not an IPv4 address"))?;
        let bits: u8 = bits.parse().map_err(|_| format!("{bits} is not a number of bits"))?;
        Self::new(address, bits)
    }
}

impl Range {
    pub fn new(network: Ipv4Addr, bits: u8) -> std::result::Result<Self, String> {
        if bits > 24 {
            return Err(format!(
                "{network}/{bits} holds fewer than 254 addresses: /24 is the smallest range"
            ));
        }
        if bits < 8 {
            return Err(format!("{network}/{bits} is larger than /8"));
        }
        let range = Self {
            network: network.into(),
            bits,
        };
        if range.network & !range.mask() != 0 {
            return Err(format!(
                "{network}/{bits} is not a network (bits are set after the first {bits}): did you mean {}/{bits}?",
                Ipv4Addr::from(range.network & range.mask())
            ));
        }
        // 0.0.0.0/8, loopback, link-local, multicast and what is reserved after it.
        let nots = [
            (0, 8, "this network"),
            (127 << 24, 8, "loopback"),
            (169 << 24 | 254 << 16, 16, "link-local"),
            (224 << 24, 3, "multicast or reserved"),
        ];
        for (other, other_bits, what) in nots {
            if overlap((range.network, bits), (other, other_bits)) {
                return Err(format!("{range} is {what} (or holds it)"));
            }
        }
        Ok(range)
    }

    fn mask(&self) -> u32 {
        u32::MAX << (32 - self.bits)
    }

    /// The range as a network: its address and its length.
    pub fn network(&self) -> (Ipv4Addr, u8) {
        (self.network.into(), self.bits)
    }

    /// What every pod sends through, and where it asks for names: the range's first address,
    /// the node's own on no wire.
    pub fn gateway(&self) -> Ipv4Addr {
        (self.network + 1).into()
    }

    /// The numbers a pod of a node may have (0 is the range's own, 1 the node's, the last
    /// address is its broadcast); no more than a pod's number holds.
    pub fn numbers(&self) -> std::ops::RangeInclusive<u16> {
        2..=(!self.mask() - 1).min(65534) as u16
    }

    /// The IPv4 address of pod `number`.
    pub fn address(&self, number: u16) -> Ipv4Addr {
        (self.network + u32::from(number)).into()
    }

    /// Whether the range overlaps the network (or the address) of one this node has on a
    /// link other than the loopback, which holds the gateway of an earlier start. The
    /// complaint names the address and the link.
    pub fn refuse_held(&self, held: &[Held]) -> std::result::Result<(), String> {
        let clash = held
            .iter()
            .filter(|held| held.link != LOOPBACK)
            .find(|held| overlap((u32::from(held.address), held.bits), (self.network, self.bits)));
        clash.map_or(Ok(()), |Held { address, bits, name, .. }| {
            Err(format!(
                "this node has {address}/{bits} on {name}, which overlaps the pods' range {self}: name another with --pod-range"
            ))
        })
    }

    /// [`Range::refuse_held`] for the addresses this machine has now (read, not changed).
    pub fn refuse_if_in_use(&self) -> std::result::Result<(), String> {
        let held = held_addresses().map_err(|e| format!("reading this node's addresses: {e}"))?;
        self.refuse_held(&held)
    }
}

/// The loopback's index: the first link of a machine.
const LOOPBACK: u32 = 1;

/// An IPv4 address this machine has on a link: with its prefix length, the link's index
/// and its name.
#[derive(Clone, Debug)]
pub struct Held {
    pub address: Ipv4Addr,
    pub bits: u8,
    pub link: u32,
    pub name: String,
}

/// Whether two networks (address, bits) share an address.
fn overlap((a, a_bits): (u32, u8), (b, b_bits): (u32, u8)) -> bool {
    (a ^ b).checked_shr(32 - u32::from(a_bits.min(b_bits))).unwrap_or(0) == 0
}

/// The IPv4 addresses on this machine's links.
fn held_addresses() -> Result<Vec<Held>> {
    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet;
    let found = ask_route(RouteNetlinkMessage::GetAddress(message), NLM_F_DUMP)?;
    Ok(found
        .into_iter()
        .filter_map(|found| match found {
            RouteNetlinkMessage::NewAddress(found) => {
                // (Local is the link's own address; on a point-to-point one, Address is the peer's.)
                let (mut local, mut peer, mut name) = (None, None, None);
                for attribute in found.attributes {
                    match attribute {
                        AddressAttribute::Local(IpAddr::V4(a)) => local = local.or(Some(a)),
                        AddressAttribute::Address(IpAddr::V4(a)) => peer = peer.or(Some(a)),
                        AddressAttribute::Label(label) => name = Some(label),
                        _ => {}
                    }
                }
                Some(Held {
                    address: local.or(peer)?,
                    bits: found.header.prefix_len,
                    link: found.header.index,
                    name: name.unwrap_or_else(|| format!("link {}", found.header.index)),
                })
            }
            _ => None,
        })
        .collect())
}

/// The addresses of a node's pod `number`: the IPv4 one, and the one in the node's /80.
pub fn addresses(range: Range, node_net: Option<Ipv6Addr>, number: u16) -> (Ipv4Addr, Option<Ipv6Addr>) {
    let [high, low] = number.to_be_bytes();
    let v6 = node_net.map(|net| {
        let mut bytes = net.octets();
        (bytes[13], bytes[14], bytes[15]) = (1, high, low);
        bytes.into()
    });
    (range.address(number), v6)
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
    let bits = match to {
        Some(IpAddr::V4(_)) => 32,
        _ => 128,
    };
    route_to(index, to.map(|to| (to, bits)), via)
}

/// The same, to the network `to` (an address and its length).
fn route_to(index: u32, to: Option<(IpAddr, u8)>, via: Option<IpAddr>) -> Result<()> {
    let mut route = RouteMessage::default();
    let v4 = matches!(to.map(|to| to.0).or(via), Some(IpAddr::V4(_)));
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
    if let Some((to, bits)) = to {
        route.header.destination_prefix_length = bits;
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

/// The link of pod `number` on the node (an exit's pod's is [`crate::exit::link`]).
pub fn link_of(number: u16) -> String {
    format!("kp{number}")
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
///
/// With `exit` (a tunnel's number), it leaves by that tunnel only: its link is
/// [`crate::exit::link`]'s, its rules ([`crate::exit::hold`]) are made, and read back,
/// before its link is, and its IPv6 goes to the mesh and nowhere else.
pub fn make(range: Range, number: u16, v6: Option<Ipv6Addr>, exit: Option<u16>) -> Result<OwnedFd> {
    let (v4, _) = addresses(range, None, number);
    let gateway = range.gateway();
    let host = match exit {
        Some(_) => crate::exit::link(number),
        None => link_of(number),
    };
    // The mesh, where there is one: the /48 of the pod's address.
    let mesh = v6.map(|v6| {
        let mut bytes = v6.octets();
        bytes[6..].fill(0);
        (Ipv6Addr::from(bytes), crate::MESH_BITS)
    });
    if let Some(tunnel) = exit {
        crate::exit::hold(&host, tunnel, range, mesh)?;
    }
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
        // (One left by a pod of this number that is gone, of either kind, is in the way: it
        // has the address. Away with it.)
        for gone in [link_of(number), crate::exit::link(number)] {
            let _ = ask_route(RouteNetlinkMessage::DelLink(link(0, Some(&gone))), NLM_F_ACK);
        }
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
        route(eth0, Some(gateway.into()), None)?;
        route(eth0, None, Some(gateway.into()))?;
        if let Some(v6) = v6 {
            address(eth0, v6.into(), 128)?;
            match (exit, mesh) {
                (Some(_), Some((mesh, bits))) => route_to(eth0, Some((mesh.into(), bits)), Some(GATEWAY6.into()))?,
                _ => route(eth0, None, Some(GATEWAY6.into()))?,
            }
        }
        Ok(pod.into())
    };
    std::thread::scope(|scope| scope.spawn(made).join())
        .unwrap_or_else(|_| Err(Error::other("the thread making the namespace panicked")))
}

/// Make this machine the node its pods need, once before the first: the range's gateway on
/// the loopback, packets passed on between links, and what leaves from a pod's IPv4 address
/// sent as the node's own.
///
/// A machine that passed nothing on until now (or `guarded`: until this was done here
/// before) passes on only what comes from or goes to a pod: it is no more of a router for
/// anyone else than it was. Returns whether that is so, for the caller to say next time.
///
/// Whatever the guard, the pods of an exit (links `kpx`) pass on only to their tunnel
/// (`kx`), to another pod, and to the mesh (link `mesh`); what comes in by a tunnel
/// passes on, or to the node, only as an answer to what was sent out by it; and nothing
/// of theirs asks the node's own DNS.
pub fn node(range: Range, guarded: bool, mesh: &str) -> Result<bool> {
    node_with(range, guarded, true, mesh)
}

fn node_with(range: Range, guarded: bool, masquerade: bool, mesh: &str) -> Result<bool> {
    crate::address4(1, range.gateway(), 32, None)?;
    let passes = "/proc/sys/net/ipv6/conf/all/forwarding";
    let guard = guarded || !std::fs::read_to_string(passes).is_ok_and(|said| said.trim() == "1");
    nat(range, guard, masquerade, mesh)?;
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

pub(crate) fn number(kind: u16, number: u32) -> Vec<u8> {
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

/// The name of the link a packet came in by (6) or goes out by (7), in register 1.
fn link_name(which: u32) -> Vec<u8> {
    expression("meta", &[number(2, which), number(1, 1)])
}

/// A verdict: accept (1) or drop (0).
fn verdict(code: u32) -> Vec<u8> {
    let verdict = attribute(2 | NESTED, &attribute(2 | NESTED, &number(1, code)));
    expression("immediate", &[number(1, 0), verdict])
}

/// Its connection is one already seen both ways, or one such a connection made (state's
/// bits 2 and 4).
fn answering() -> Vec<u8> {
    let state = expression("ct", &[number(1, 1), number(2, 0)]);
    let (mask, nothing) = (6u32.to_ne_bytes(), 0u32.to_ne_bytes());
    let masked = expression(
        "bitwise",
        &[
            number(1, 1),
            number(2, 1),
            number(3, 4),
            attribute(4 | NESTED, &attribute(1, &mask)),
            attribute(5 | NESTED, &attribute(1, &nothing)),
        ],
    );
    let some = expression(
        "cmp",
        &[
            number(1, 1),
            number(2, 1),
            attribute(3 | NESTED, &attribute(1, &nothing)),
        ],
    );
    [state, masked, some].concat()
}

/// Its connection is marked as one a pod of an exit started ([`crate::exit::MARK`]).
fn marked() -> Vec<u8> {
    let value = attribute(2 | NESTED, &attribute(1, &crate::exit::MARK.to_ne_bytes()));
    let mark = expression("immediate", &[number(1, 1), value]);
    [mark, expression("ct", &[number(2, 3), number(4, 1)])].concat()
}

/// The tables: `ip kith-pods` sends what comes from a pod's IPv4 address out as the
/// node's (masquerade); with `guard`, `inet kith-pods` lets nothing be passed on but what
/// comes in from or goes out to a pod's link.
fn nat(range: Range, guard: bool, masquerade: bool, mesh: &str) -> Result<()> {
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
    // Where it comes from (4 bytes, 12 into the IP header), with all but the range's bits
    // cleared (bitwise: and with the mask, or with 0), is the range's network.
    let from = expression("payload", &[number(1, 1), number(2, 1), number(3, 12), number(4, 4)]);
    let value = |bytes: [u8; 4]| attribute(1, &bytes);
    let (mask, network) = (range.mask().to_be_bytes(), range.network.to_be_bytes());
    let masked = expression(
        "bitwise",
        &[
            number(1, 1),
            number(2, 1),
            number(3, 4),
            attribute(4 | NESTED, &value(mask)),
            attribute(5 | NESTED, &value([0; 4])),
        ],
    );
    if masquerade {
        say(
            new_rule,
            ip,
            0,
            &rule("out", &[from, masked, is(&network), expression("masq", &[])]),
        );
    }
    say(new_table, inet, 0, &[text(1, TABLE)]);
    // What is passed on (hook 2): with the guard, dropped (0) unless a rule lets it through.
    say(
        new_chain,
        inet,
        0,
        &chain("passed", "filter", 2, 0, Some(u32::from(!guard))),
    );
    // What comes to the node itself (hook 1).
    say(new_chain, inet, 0, &chain("in", "filter", 1, 0, Some(1)));
    // (6 and 7: the names of the links it came in by and goes out by.)
    let (from, to) = (
        |name: &[u8]| [link_name(6), is(name)].concat(),
        |name: &[u8]| [link_name(7), is(name)].concat(),
    );
    let mesh = [mesh.as_bytes(), &[0]].concat();
    for chain in ["passed", "in"] {
        say(new_rule, inet, 0, &rule(chain, &[from(b"kx"), answering(), verdict(1)]));
        say(new_rule, inet, 0, &rule(chain, &[from(b"kx"), verdict(0)]));
    }
    // (Of the transport header (2), the two bytes at 2: the port it goes to.)
    let port = expression("payload", &[number(1, 1), number(2, 2), number(3, 2), number(4, 2)]);
    say(
        new_rule,
        inet,
        0,
        &rule("in", &[from(b"kpx"), port, is(&53u16.to_be_bytes()), verdict(0)]),
    );
    say(new_rule, inet, 0, &rule("passed", &[from(b"kpx"), marked()]));
    for allowed in [&b"kx"[..], b"kp", &mesh] {
        say(
            new_rule,
            inet,
            0,
            &rule("passed", &[from(b"kpx"), to(allowed), verdict(1)]),
        );
    }
    say(new_rule, inet, 0, &rule("passed", &[from(b"kpx"), verdict(0)]));
    if guard {
        for link in [6, 7] {
            say(
                new_rule,
                inet,
                0,
                &rule("passed", &[link_name(link), is(b"kp"), verdict(1)]),
            );
        }
    }
    say(0x11, 0, 10, &[]); // and ends
    netfilter(&batch, sequence - 1)
}

/// Send netfilter `batch`, and take its answers: a no is the answer, or message `last`'s yes.
pub(crate) fn netfilter(batch: &[u8], last: u32) -> Result<()> {
    let socket = crate::netlink::socket(12)?; // netfilter's
    socket.send(batch, 0)?;
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

    fn range(text: &str) -> std::result::Result<Range, String> {
        text.parse()
    }

    #[test]
    fn the_range_gives_the_gateway_the_numbers_and_the_addresses() {
        let default = Range::default();
        assert_eq!(default.to_string(), "100.88.0.0/16");
        assert_eq!(
            (default.gateway(), default.numbers()),
            (Ipv4Addr::new(100, 88, 0, 1), 2..=65534)
        );
        let small = range("10.77.4.0/24").unwrap();
        assert_eq!(
            (small.gateway(), small.numbers()),
            (Ipv4Addr::new(10, 77, 4, 1), 2..=254)
        );
        assert_eq!(small.address(254), Ipv4Addr::new(10, 77, 4, 254));
        // A range larger than a pod's number holds is used as far as that goes.
        let large = range("10.0.0.0/8").unwrap();
        assert_eq!(
            (large.numbers(), large.address(0x0102)),
            (2..=65534, Ipv4Addr::new(10, 0, 1, 2))
        );
        let middle = range("198.18.16.0/20").unwrap();
        assert_eq!(
            (middle.numbers(), middle.address(0x0102)),
            (2..=4094, Ipv4Addr::new(198, 18, 17, 2))
        );
    }

    #[test]
    fn a_range_that_is_not_one_is_refused_with_its_reason() {
        let refused = |text: &str, why: &str| {
            let said = range(text).expect_err(text);
            assert!(said.contains(why), "{text}: {said}");
        };
        refused("10.77.0.0", "ADDRESS/BITS");
        refused("fd00::/64", "not an IPv4 address");
        refused("10.77.0.0/x", "not a number");
        refused("10.77.0.0/25", "fewer than 254");
        refused("10.77.0.0/32", "fewer than 254");
        refused("10.0.0.0/7", "larger than /8");
        refused("10.77.0.1/16", "did you mean 10.77.0.0/16");
        for (text, what) in [
            ("127.0.0.0/8", "loopback"),
            ("127.5.0.0/16", "loopback"),
            ("169.254.0.0/16", "link-local"),
            ("169.254.7.0/24", "link-local"),
            ("224.0.0.0/24", "multicast"),
            ("239.1.0.0/16", "multicast"),
            ("240.0.0.0/16", "reserved"),
            ("0.0.0.0/8", "this network"),
            ("0.9.0.0/16", "this network"),
        ] {
            refused(text, what);
        }
        // What is next to them is fine: 126, 128, 169.253, 169.255, and 223.
        for text in [
            "126.0.0.0/16",
            "128.0.0.0/16",
            "169.253.0.0/16",
            "169.255.0.0/16",
            "223.1.0.0/16",
            "100.64.0.0/10",
            "192.168.0.0/24",
        ] {
            range(text).expect(text);
        }
    }

    #[test]
    fn a_range_with_an_address_of_the_node_in_it_is_refused() {
        let ours = range("10.77.0.0/16").unwrap();
        // Each on link 2 (eth0), the loopback being link 1.
        let held = |list: &[(&str, u8)]| -> Vec<Held> {
            let on = |link, (a, bits): &(&str, u8)| Held {
                address: a.parse().unwrap(),
                bits: *bits,
                link,
                name: format!("link{link}"),
            };
            list.iter().map(|a| on(2, a)).collect()
        };
        // The node's own network (a LAN, a tailnet) and the loopback are not in it.
        ours.refuse_held(&held(&[("192.168.1.5", 24), ("100.101.1.2", 32), ("10.78.0.1", 16)]))
            .unwrap();
        // Whatever the loopback holds is no clash: the gateway an earlier start left there
        // (this range's too, after a restart onto the range of its pods), and 127/8.
        let mut on_lo = held(&[("10.77.0.1", 32), ("10.77.9.9", 24), ("127.0.0.1", 8)]);
        on_lo.iter_mut().for_each(|held| held.link = 1);
        ours.refuse_held(&on_lo).unwrap();
        // One that is, is (even at the range's ends, with another length, or its network
        // holding the range: 192.168.1.5/16 and a range of 192.168.77.0/24), naming the link.
        for (range, clash) in [
            ("10.77.0.0/16", ("10.77.0.9", 24)),
            ("10.77.0.0/16", ("10.77.255.254", 32)),
            ("10.77.0.0/16", ("10.77.0.0", 8)),
            ("10.77.0.0/16", ("10.77.0.1", 16)),
            ("192.168.77.0/24", ("192.168.1.5", 16)),
        ] {
            let said = range
                .parse::<Range>()
                .unwrap()
                .refuse_held(&held(&[("172.16.0.2", 24), clash]));
            let said = said.unwrap_err();
            assert!(
                said.contains(&format!("{}/{} on link2", clash.0, clash.1)) && said.contains("--pod-range"),
                "{said}"
            );
        }
        // And the machine this runs on can be asked (what it has is anyone's: only that it answers).
        assert!(held_addresses().is_ok_and(|held| held.iter().any(|held| held.address.is_loopback())));
    }

    #[test]
    fn a_pods_addresses_are_its_nodes() {
        let net = crate::node_net(crate::prefix(b"test"), "alpha");
        let (v4, v6) = addresses(Range::default(), Some(net), 0x0102);
        assert_eq!(v4, Ipv4Addr::new(100, 88, 1, 2));
        assert_eq!(
            addresses(range("10.77.0.0/20").unwrap(), None, 0x0102).0,
            Ipv4Addr::new(10, 77, 1, 2)
        );
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
        // (A range that is not the default, and not whole bytes: the masquerade matches its bits.)
        let range = range("198.18.16.0/20").unwrap();
        // (A kernel whose masquerade is a module nobody loaded has none in a namespace.)
        let masquerade = match node(range, false, "kith0") {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            guarded => guarded.unwrap(),
        };
        if !masquerade {
            eprintln!("this kernel has no masquerade here: without");
            assert!(node_with(range, false, false, "kith0").unwrap());
        }
        let net = crate::node_net(crate::prefix(b"test"), "alpha");
        let pods: Vec<_> = [2, 3]
            .map(|number| {
                let (v4, v6) = addresses(range, Some(net), number);
                let namespace = make(range, number, v6, None).unwrap();
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
            let node = if masquerade { range.gateway() } else { pods[0].2 };
            assert_eq!(
                from[4],
                IpAddr::from(node),
                "what leaves a pod by IPv4 leaves as the node"
            );
        });
        // A second time changes nothing (what the first left is taken away and made again).
        assert!(node_with(range, true, masquerade, "kith0").unwrap());
    }
}
