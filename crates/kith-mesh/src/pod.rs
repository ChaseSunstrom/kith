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
use std::io::{Error, ErrorKind, Result};
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

    /// With `--people`: this range may not overlap the people's `100.89.0.0/16` (condition 4).
    pub fn refuse_people(&self) -> std::result::Result<(), String> {
        if overlap((self.network, self.bits), PEOPLE) {
            return Err(format!(
                "the pods' range {self} overlaps the people's 100.89.0.0/16 (--people): name another with --pod-range"
            ));
        }
        Ok(())
    }

    /// With `--people`: no network this node has on a link may overlap `100.89.0.0/16`, except on the
    /// loopback and on kwg0, which holds its own address there.
    pub fn refuse_people_held(held: &[Held]) -> std::result::Result<(), String> {
        let clash = held
            .iter()
            .filter(|held| held.link != LOOPBACK && held.name != crate::people::DEVICE)
            .find(|held| overlap((u32::from(held.address), held.bits), PEOPLE));
        clash.map_or(
            Ok(()),
            |Held {
                 address, bits, name, ..
             }| {
                Err(format!(
                    "this node has {address}/{bits} on {name}, which overlaps the people's 100.89.0.0/16 (--people)"
                ))
            },
        )
    }

    /// [`Range::refuse_people_held`] for the addresses this machine has now.
    pub fn refuse_people_in_use() -> std::result::Result<(), String> {
        let held = held_addresses().map_err(|e| format!("reading this node's addresses: {e}"))?;
        Self::refuse_people_held(&held)
    }

    /// [`Range::refuse_held`] for the addresses this machine has now (read, not changed).
    pub fn refuse_if_in_use(&self) -> std::result::Result<(), String> {
        let held = held_addresses().map_err(|e| format!("reading this node's addresses: {e}"))?;
        self.refuse_held(&held)
    }

    /// Whether `ip` is in the range.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == self.network
    }

    /// The number of `ip` in the range ([`Range::address`] the other way round), if it is
    /// one of [`Range::numbers`]: not the range's own, the node's, nor its broadcast.
    pub fn number_of(&self, ip: Ipv4Addr) -> Option<u16> {
        let number = u16::try_from(u32::from(ip).checked_sub(self.network)?).ok();
        number.filter(|number| self.contains(ip) && self.numbers().contains(number))
    }

    /// What this range, as the Services', overlaps: the pods' range `pods`, the people's
    /// `100.89.0.0/16` (with `--people` or not: the people may come later), or a network on
    /// a link of `held` other than the loopback (which holds the Services' own addresses).
    /// The complaint names the clash.
    pub fn service_clash(&self, pods: &Range, held: &[Held]) -> Option<String> {
        let mine = (self.network, self.bits);
        if overlap(mine, (pods.network, pods.bits)) {
            return Some(format!("the Services' range {self} overlaps the pods' range {pods}"));
        }
        if overlap(mine, PEOPLE) {
            return Some(format!(
                "the Services' range {self} overlaps the people's 100.89.0.0/16"
            ));
        }
        let clash = held
            .iter()
            .filter(|held| held.link != LOOPBACK)
            .find(|held| overlap((u32::from(held.address), held.bits), mine))?;
        let Held {
            address, bits, name, ..
        } = clash;
        Some(format!(
            "this node has {address}/{bits} on {name}, which overlaps the Services' range {self}"
        ))
    }

    /// [`Range::service_clash`] for the addresses this machine has now (read, not changed).
    pub fn service_clash_in_use(&self, pods: &Range) -> std::result::Result<Option<String>, String> {
        let held = held_addresses().map_err(|e| format!("reading this node's addresses: {e}"))?;
        Ok(self.service_clash(pods, &held))
    }
}

/// The people's range, `100.89.0.0/16` (`--people`).
const PEOPLE: (u32, u8) = (100 << 24 | 89 << 16, 16);

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
/// (`kx`), to another pod, and to the mesh (link `mesh`), and nothing of theirs reaches
/// the node itself but answers to what it asked of them. (What comes in by a tunnel is
/// [`crate::exit::guard`]'s, made before the tunnel is.)
/// What comes by each of `pods`' links is passed only from that pod's own addresses; the
/// caller makes this again whenever the pods change.
///
/// `services` is the Services' (address, port) pairs this node listens on, IPv4 and IPv6: any
/// pod reaches TCP at those and nothing else of the node's own (a listener bound to every
/// address, the Service's address being one of the node's, is not reachable on another port).
pub fn node(range: Range, services: &[(IpAddr, u16)], guarded: bool, mesh: &str, pods: &[Served]) -> Result<bool> {
    node_with(range, services, guarded, true, mesh, pods)
}

/// A pod this node serves: its number, whether it leaves by an exit (its link is then
/// [`crate::exit::link`]'s, not [`link_of`]'s), and its address on the mesh, if it has one
/// (its IPv4 address is [`addresses`]'). `egress`, when it has rules (a NetworkPolicy
/// selects the pod): what the pod may reach, see [`Egress`]; `None` holds it to nothing.
pub struct Served {
    pub number: u16,
    pub exit: bool,
    pub v6: Option<Ipv6Addr>,
    pub egress: Option<Vec<Egress>>,
}

/// One egress rule of a pod, in the order given: the first that fits what the pod sends
/// says, an allow lets it be, a deny drops it, and when none fits it is dropped. It fits what
/// goes to one of the networks `to` (any, if none) at one of `ports` (any TCP or UDP port, or
/// no port, if none: a rule with ports fits TCP and UDP only). What answers what came to the
/// pod passes before any rule; nothing else does, DNS at the node's resolver included.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Egress {
    pub allow: bool,
    pub to: Vec<(IpAddr, u8)>,
    pub ports: Vec<u16>,
}

fn node_with(
    range: Range,
    services: &[(IpAddr, u16)],
    guarded: bool,
    masquerade: bool,
    mesh: &str,
    pods: &[Served],
) -> Result<bool> {
    crate::gateway4(1, range.gateway())?;
    let passes = "/proc/sys/net/ipv6/conf/all/forwarding";
    let guard = guard_wanted(guarded, std::fs::read_to_string(passes).ok().as_deref());
    nat(range, services, guard, masquerade, mesh, pods)?;
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

/// Whether the guard is wanted: when the node was `guarded` before, or when it did not pass
/// packets on until now (`forwarding` is what its IPv6 forwarding said, `None` if unread).
pub(crate) fn guard_wanted(guarded: bool, forwarding: Option<&str>) -> bool {
    guarded || !forwarding.is_some_and(|said| said.trim() == "1")
}

/// Whether the tables [`node`] makes are there (gone with `nft flush ruleset`, say).
pub fn tables() -> Result<bool> {
    has_table(INET, "kith-pods")
}

// ---- nftables, as the kernel takes it (nfnetlink): a few attributes by hand ----

pub(crate) const NESTED: u16 = 0x8000;

pub(crate) fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.len() + 8);
    bytes.extend((value.len() as u16 + 4).to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.extend(value);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

pub(crate) fn text(kind: u16, text: &str) -> Vec<u8> {
    attribute(kind, &[text.as_bytes(), &[0]].concat())
}

pub(crate) fn number(kind: u16, number: u32) -> Vec<u8> {
    attribute(kind, &number.to_be_bytes())
}

/// An expression of a rule: its name and what it is told.
pub(crate) fn expression(name: &str, told: &[Vec<u8>]) -> Vec<u8> {
    let told = attribute(2 | NESTED, &told.concat());
    attribute(1 | NESTED, &[text(1, name), told].concat())
}

/// Register 1 is what `bytes` are (the comparison every rule here ends its looking with).
pub(crate) fn is(bytes: &[u8]) -> Vec<u8> {
    let value = attribute(3 | NESTED, &attribute(1, bytes));
    expression("cmp", &[number(1, 1), number(2, 0), value])
}

/// The name of the link a packet came in by (6) or goes out by (7), in register 1.
pub(crate) fn link_name(which: u32) -> Vec<u8> {
    expression("meta", &[number(2, which), number(1, 1)])
}

/// A verdict: accept (1) or drop (0).
pub(crate) fn verdict(code: u32) -> Vec<u8> {
    let verdict = attribute(2 | NESTED, &attribute(2 | NESTED, &number(1, code)));
    expression("immediate", &[number(1, 0), verdict])
}

/// A jump to the chain `name` (NFT_JUMP, -3), which a rule of its own may return from.
pub(crate) fn jump(name: &str) -> Vec<u8> {
    let told = [number(1, (-3i32) as u32), text(2, name)].concat();
    expression(
        "immediate",
        &[number(1, 0), attribute(2 | NESTED, &attribute(2 | NESTED, &told))],
    )
}

/// A return (NFT_RETURN, -5) to the chain that jumped.
pub(crate) fn ret() -> Vec<u8> {
    verdict((-5i32) as u32)
}

/// It came in by a link whose name begins with `name`.
pub(crate) fn came_by(name: &[u8]) -> Vec<u8> {
    [link_name(6), is(name)].concat()
}

/// Its connection is one already seen both ways, or one such a connection made.
pub(crate) fn answering() -> Vec<u8> {
    state(2 | 4)
}

/// Its connection's state is one of `states`' bits: 2, seen both ways; 4, made by such a
/// connection (an ICMP error of it); 64, not tracked at all (IPv6's neighbour discovery).
fn state(states: u32) -> Vec<u8> {
    let state = expression("ct", &[number(1, 1), number(2, 0)]);
    let (mask, nothing) = (states.to_ne_bytes(), 0u32.to_ne_bytes());
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

/// The bytes `bytes` are at `offset` into the packet's header `base` (1: network, 2:
/// transport), compared in register 1.
pub(crate) fn at(base: u32, offset: u32, bytes: &[u8]) -> Vec<u8> {
    let load = expression(
        "payload",
        &[
            number(1, 1),
            number(2, base),
            number(3, offset),
            number(4, bytes.len() as u32),
        ],
    );
    [load, is(bytes)].concat()
}

/// The packet's family is `family` (meta nfproto: 2 IPv4, 10 IPv6).
pub(crate) fn nfproto(family: u8) -> Vec<u8> {
    [expression("meta", &[number(2, 15), number(1, 1)]), is(&[family])].concat()
}

/// The packet's transport protocol is `protocol` (meta l4proto: 6 TCP, 17 UDP).
pub(crate) fn l4proto(protocol: u8) -> Vec<u8> {
    [expression("meta", &[number(2, 16), number(1, 1)]), is(&[protocol])].concat()
}

/// The guard of the pod links (`kp*`, an exit's `kpx` among them), each rule as (chain,
/// expressions). `check` (prerouting, first): what comes by a pod's link is passed only from
/// that pod's own IPv4 or IPv6 address, the link's name whole; the rest of `kp*` is dropped.
/// `in` (what comes to the node): an answer to what the node asked is passed; an exit's pod
/// (`kpx`) gets nothing more, its DNS and Services among them; any pod gets DNS at the
/// gateway (UDP and TCP, port 53) and TCP to a Service, the address and the port both a pair
/// of `services` (IPv4 or IPv6); the rest is dropped. An answer is the state of a connection seen both ways or made by one, or
/// IPv6's neighbour discovery (not tracked). A pod with egress rules (see [`Egress`]) jumps
/// to its own chain from `passed` and, after the first rule, from `in`: so its DNS and
/// Services are held to its rules too.
fn pod_guard_rules(range: Range, services: &[(IpAddr, u16)], pods: &[Served]) -> Vec<(&'static str, Vec<Vec<u8>>)> {
    let gateway = range.gateway().octets();
    let dns = |protocol: u8| {
        vec![
            came_by(b"kp"),
            nfproto(2),
            l4proto(protocol),
            at(1, 16, &gateway),
            at(2, 2, &53u16.to_be_bytes()),
            verdict(1),
        ]
    };
    let mut rules = Vec::new();
    // Each held pod's jump to its chain, in what is passed on (first: before the kpx rules
    // that follow) and, but for an exit's pod (it has no more than answers), what comes to
    // the node, after the answers (made to pass by the first rule of `in`).
    let mut held_passed = Vec::new();
    let mut held_in = Vec::new();
    for served in pods {
        let link = link_for(served);
        // (Whole, with its end: `kp1` is not `kp10`.)
        let named = [link_name(6), is(&[link.as_bytes(), &[0]].concat())].concat();
        if served.egress.is_some() {
            let rule = vec![named.clone(), jump(&egress_chain(served))];
            held_passed.push(("passed", rule.clone()));
            if !served.exit {
                held_in.push(("in", rule));
            }
        }
        let (v4, _) = addresses(range, None, served.number);
        rules.push((
            "check",
            vec![named.clone(), nfproto(2), at(1, 12, &v4.octets()), verdict(1)],
        ));
        if let Some(v6) = served.v6 {
            rules.push(("check", vec![named, nfproto(10), at(1, 8, &v6.octets()), verdict(1)]));
        }
    }
    rules.push(("check", vec![came_by(b"kp"), verdict(0)]));
    rules.extend(held_passed);
    rules.push(("in", vec![came_by(b"kp"), state(2 | 4 | 64), verdict(1)]));
    rules.extend(held_in);
    rules.extend([
        ("in", vec![came_by(b"kpx"), verdict(0)]),
        ("in", dns(17)),
        ("in", dns(6)),
    ]);
    // A Service's address and port, TCP only, a rule for each: the Services' addresses are the
    // node's own (on its loopback or its mesh link), so a listener bound to every address is
    // there at them too, on ports that are no Service's.
    // ponytail: one rule each, so the "in" chain grows with the Services x their TCP ports, and each
    // make of the tables (on a change of the pairs) sends them all; an nft set of (address, port)
    // is the upgrade when a node holds thousands.
    for (address, port) in services {
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let mut rule = vec![came_by(b"kp")];
        rule.extend(towards(*address, bits));
        rule.extend([l4proto(6), at(2, 2, &port.to_be_bytes()), verdict(1)]);
        rules.push(("in", rule));
    }
    rules.push(("in", vec![came_by(b"kp"), verdict(0)]));
    rules
}

/// The name of a pod's link: `kpN`, or an exit's pod's `kpxN`.
fn link_for(served: &Served) -> String {
    if served.exit {
        crate::exit::link(served.number)
    } else {
        link_of(served.number)
    }
}

/// The chain of a held pod's egress rules.
fn egress_chain(served: &Served) -> String {
    format!("e-{}", link_for(served))
}

/// What goes to `address`'s first `prefix` bits (a prefix over the address's size is the
/// whole): its family, then its bytes, those of the whole bytes of the prefix compared as
/// they are and a part of a byte masked first. A prefix of 0 is any address of the family.
fn towards(address: IpAddr, prefix: u8) -> Vec<Vec<u8>> {
    let (family, offset, octets) = match address {
        IpAddr::V4(address) => (2, 16, address.octets().to_vec()),
        IpAddr::V6(address) => (10, 24, address.octets().to_vec()),
    };
    let bits = usize::from(prefix).min(octets.len() * 8);
    let (whole, part) = (bits / 8, bits % 8);
    let mut rule = vec![nfproto(family)];
    if part == 0 {
        if whole > 0 {
            rule.push(at(1, offset, &octets[..whole]));
        }
        return rule;
    }
    let length = whole + 1;
    let mut mask = vec![0xff; whole];
    mask.push(0xff << (8 - part));
    let network: Vec<u8> = octets.iter().zip(&mask).map(|(byte, mask)| byte & mask).collect();
    let load = expression(
        "payload",
        &[number(1, 1), number(2, 1), number(3, offset), number(4, length as u32)],
    );
    let masked = expression(
        "bitwise",
        &[
            number(1, 1),
            number(2, 1),
            number(3, length as u32),
            attribute(4 | NESTED, &attribute(1, &mask)),
            attribute(5 | NESTED, &attribute(1, &vec![0; length])),
        ],
    );
    rule.extend([load, masked, is(&network)]);
    rule
}

/// The chains of the held pods' egress rules (each as chain name and rules), one per pod
/// with `egress`: first what answers is returned (to the rules after the jump), then each
/// rule of the pod's own as it was given: an allow returns, a deny drops; what none fits is
/// dropped. A rule with several networks and ports is a rule for each of them (a network, a
/// port, then TCP and UDP).
// ponytail: that product is not bounded: a set per rule, if policies with many peers and ports come.
fn egress_rules(pods: &[Served]) -> Vec<(String, Vec<Vec<Vec<u8>>>)> {
    let mut chains = Vec::new();
    for served in pods {
        let Some(egress) = &served.egress else { continue };
        let mut rules = vec![vec![answering(), ret()]];
        for rule in egress {
            let end = if rule.allow { ret() } else { verdict(0) };
            // (No network: any, with no family said either.)
            let networks: Vec<Vec<Vec<u8>>> = if rule.to.is_empty() {
                vec![vec![]]
            } else {
                rule.to
                    .iter()
                    .map(|&(address, prefix)| towards(address, prefix))
                    .collect()
            };
            for network in networks {
                let ports: Vec<Option<(u8, u16)>> = if rule.ports.is_empty() {
                    vec![None]
                } else {
                    rule.ports
                        .iter()
                        .flat_map(|&port| [Some((6, port)), Some((17, port))])
                        .collect()
                };
                for port in ports {
                    let mut said = network.clone();
                    if let Some((protocol, port)) = port {
                        said.extend([l4proto(protocol), at(2, 2, &port.to_be_bytes())]);
                    }
                    said.push(end.clone());
                    rules.push(said);
                }
            }
        }
        rules.push(vec![verdict(0)]);
        chains.push((egress_chain(served), rules));
    }
    chains
}

/// The tables: `ip kith-pods` sends what comes from a pod's IPv4 address out as the
/// node's (masquerade); with `guard`, `inet kith-pods` lets nothing be passed on but what
/// comes in from or goes out to a pod's link. Whole, for `pods` as they are now.
fn nat(
    range: Range,
    services: &[(IpAddr, u16)],
    guard: bool,
    masquerade: bool,
    mesh: &str,
    pods: &[Served],
) -> Result<()> {
    let mut batch = Batch::new("kith-pods");
    batch.table(IP);
    // After routing (hook 4), where addresses are changed on the way out (priority 100).
    batch.chain(IP, "out", "nat", 4, 100, None);
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
        batch.rule(IP, "out", &[from, masked, is(&network), expression("masq", &[])]);
    }
    batch.table(INET);
    // What is passed on (hook 2): with the guard, dropped (0) unless a rule lets it through.
    batch.chain(INET, "passed", "filter", 2, 0, Some(u32::from(!guard)));
    // A pod link's guard, first: what comes by it from a source with no route back through it
    // is dropped (prerouting, priority -100: ahead of conntrack's own).
    batch.chain(INET, "check", "filter", 0, (-100i32) as u32, None);
    // What comes to the node itself (hook 1): the pods' rules, see `pod_guard_rules`.
    batch.chain(INET, "in", "filter", 1, 0, Some(1));
    // The held pods' chains, made before the rules that jump to them.
    let held = egress_rules(pods);
    for (name, _) in &held {
        batch.plain(INET, name);
    }
    for (chain, rule) in pod_guard_rules(range, services, pods) {
        batch.rule(INET, chain, &rule);
    }
    for (name, rules) in &held {
        for rule in rules {
            batch.rule(INET, name, rule);
        }
    }
    let to = |name: &[u8]| [link_name(7), is(name)].concat();
    let mesh = [mesh.as_bytes(), &[0]].concat();
    // (What comes in by a tunnel to be passed on is an answer, or the guard drops it; an
    // answer is passed whatever this table's policy.)
    batch.rule(INET, "passed", &[came_by(b"kx"), answering(), verdict(1)]);
    batch.rule(INET, "passed", &[came_by(b"kpx"), marked()]);
    for allowed in [&b"kx"[..], b"kp", &mesh] {
        batch.rule(INET, "passed", &[came_by(b"kpx"), to(allowed), verdict(1)]);
    }
    batch.rule(INET, "passed", &[came_by(b"kpx"), verdict(0)]);
    if guard {
        for link in [6, 7] {
            batch.rule(INET, "passed", &[link_name(link), is(b"kp"), verdict(1)]);
        }
        // The people's device, both ways: what its table (`inet kith-people`) lets through is
        // passed on here too (a level's exit, out by kx; the answers come back by the rule above).
        for rule in people_passed() {
            batch.rule(INET, "passed", &rule);
        }
    }
    batch.send()
}

/// The `passed` rules for the people's device: what comes in by it and what goes out by it, whole
/// link name (`is` compares a prefix, so the name ends with its NUL).
fn people_passed() -> [Vec<Vec<u8>>; 2] {
    let device = [crate::people::DEVICE.as_bytes(), &[0]].concat();
    [6, 7].map(|link| vec![link_name(link), is(&device), verdict(1)])
}

/// nftables' families of tables: IPv4's, and both IPv4's and IPv6's.
const IP: u8 = 2;
pub(crate) const INET: u8 = 1;

/// A netfilter batch, of the table `table`'s messages: sent whole, the kernel takes all of
/// it or none (a table made anew has no moment without its rules).
pub(crate) struct Batch {
    bytes: Vec<u8>,
    sequence: u32,
    table: &'static str,
    /// Where the last message said starts in `bytes`.
    last: usize,
}

impl Batch {
    pub(crate) fn new(table: &'static str) -> Batch {
        let mut batch = Batch {
            bytes: Vec::new(),
            sequence: 0,
            table,
            last: 0,
        };
        batch.say(0x10, 0, 10, &[]); // a batch begins
        batch
    }

    fn say(&mut self, kind: u16, family: u8, subsystem: u16, attributes: &[Vec<u8>]) {
        let attributes = attributes.concat();
        self.sequence += 1;
        self.last = self.bytes.len();
        let bytes = &mut self.bytes;
        bytes.extend((attributes.len() as u32 + 20).to_ne_bytes());
        bytes.extend(kind.to_ne_bytes());
        // A request; what is not the batch's own beginning or end: may create; a rule after
        // the chain's others (append: else the kernel puts it first, and a chain runs
        // backwards, its drop ahead of the accept meant to come before). Not acknowledged
        // here: `finish` asks for the one ack the batch needs, on its last message.
        let flags: u16 = match (subsystem, kind) {
            (0, 0xa06) => 0xc01,
            (0, _) => 0x401,
            _ => 1,
        };
        bytes.extend(flags.to_ne_bytes());
        bytes.extend(self.sequence.to_ne_bytes());
        bytes.extend(0u32.to_ne_bytes());
        bytes.extend([family, 0]);
        bytes.extend(subsystem.to_be_bytes());
        bytes.extend(attributes);
    }

    /// The table of `family` made anew: nothing an earlier one (an earlier kithd's) had stays.
    pub(crate) fn table(&mut self, family: u8) {
        // (New table, delete table, new table, of nftables' (10): made, so it is there to take away.)
        let name = [text(1, self.table)];
        for kind in [0xa00, 0xa02, 0xa00] {
            self.say(kind, family, 0, &name);
        }
    }

    /// The table of `family` taken away, with its chains and rules. The table must be there
    /// (see `has_table`): nftables says no to a delete of one that is not.
    pub(crate) fn drop_table(&mut self, family: u8) {
        self.say(0xa02, family, 0, &[text(1, self.table)]);
    }

    /// A chain of the table, at `hook` with `priority`, and `policy` (accept, 1, or drop,
    /// 0) for what no rule of it takes.
    pub(crate) fn chain(&mut self, family: u8, name: &str, kind: &str, hook: u32, priority: u32, policy: Option<u32>) {
        let hook = attribute(4 | NESTED, &[number(1, hook), number(2, priority)].concat());
        let mut chain = vec![text(1, self.table), text(3, name), hook, text(7, kind)];
        chain.extend(policy.map(|policy| number(5, policy)));
        self.say(0xa03, family, 0, &chain);
    }

    /// A chain of the table no hook reaches: a rule jumps to it.
    pub(crate) fn plain(&mut self, family: u8, name: &str) {
        self.say(0xa03, family, 0, &[text(1, self.table), text(3, name)]);
    }

    /// A rule at the end of `chain`, of `expressions`.
    pub(crate) fn rule(&mut self, family: u8, chain: &str, expressions: &[Vec<u8>]) {
        let rule = [
            text(1, self.table),
            text(2, chain),
            attribute(4 | NESTED, &expressions.concat()),
        ];
        self.say(0xa06, family, 0, &rule);
    }

    /// The batch's bytes, ended, and the sequence of the one message asked to be acknowledged:
    /// the batch's last. The kernel says no for any message that fails, so that yes is all a
    /// whole batch needs (one per message would flood the socket's receive buffer).
    pub(crate) fn finish(mut self) -> (Vec<u8>, u32) {
        let at = self.last + 6;
        let flags = u16::from_ne_bytes([self.bytes[at], self.bytes[at + 1]]) | 4;
        self.bytes[at..at + 2].copy_from_slice(&flags.to_ne_bytes());
        self.say(0x11, 0, 10, &[]); // and ends
        (self.bytes, self.sequence - 1)
    }

    pub(crate) fn send(self) -> Result<()> {
        let (bytes, last) = self.finish();
        netfilter(&bytes, last)
    }
}

/// Whether nftables has the table `name` of `family`.
pub(crate) fn has_table(family: u8, name: &str) -> Result<bool> {
    // (Get table, of nftables' (10): a request, acknowledged.)
    let attributes = text(1, name);
    let mut message = Vec::new();
    message.extend((attributes.len() as u32 + 20).to_ne_bytes());
    message.extend(0xa01u16.to_ne_bytes());
    message.extend(5u16.to_ne_bytes());
    message.extend(1u32.to_ne_bytes());
    message.extend(0u32.to_ne_bytes());
    message.extend([family, 0, 0, 0]);
    message.extend(attributes);
    match netfilter(&message, 1) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Send netfilter `batch`, and take its answers: a no is the answer, or message `last`'s yes.
pub(crate) fn netfilter(batch: &[u8], last: u32) -> Result<()> {
    let socket = crate::netlink::socket(12)?; // netfilter's
    // A whole table in one batch can be bigger than the default send buffer (EMSGSIZE).
    crate::netlink::raise_send_buffer(&socket, batch.len())?;
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
    use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::time::Duration;

    fn range(text: &str) -> std::result::Result<Range, String> {
        text.parse()
    }

    /// The guard is wanted when the node was guarded before, or when it did not pass packets
    /// on until now (forwarding read as not 1, or not read at all): a machine that already
    /// passed them on keeps doing so, and gets no guard.
    #[test]
    fn guard_wanted_is_true_when_guarded_before_or_forwarding_was_off() {
        assert!(guard_wanted(true, Some("1")));
        assert!(guard_wanted(false, Some("0")));
        assert!(guard_wanted(false, Some("0\n")));
        assert!(guard_wanted(false, None));
        assert!(!guard_wanted(false, Some("1")));
        assert!(!guard_wanted(false, Some("1\n")));
    }

    /// With the guard, what comes in by the people's device and what goes out by it is passed on, by
    /// the whole name (with its NUL: kwg0 and not a link that starts with it), both ways (T-0797).
    #[test]
    fn people_exit_the_guard_passes_kwg0_by_its_whole_name() {
        let [came, went] = people_passed();
        assert_eq!(came, vec![link_name(6), is(b"kwg0\0"), verdict(1)]);
        assert_eq!(went, vec![link_name(7), is(b"kwg0\0"), verdict(1)]);
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
        // And the machine this runs on can be asked (what it has is anyone's: only that it
        // answers, and that a loopback address it has comes back on link 1; in a network
        // namespace of its own, `unshare -Urn`, it has none).
        let machine = held_addresses().unwrap();
        assert!(
            machine
                .iter()
                .filter(|held| held.address.is_loopback())
                .all(|held| held.link == LOOPBACK),
            "{machine:?}"
        );
    }

    /// The Services' range (`--service-range`) is a `Range` too: what is in it, which
    /// number an address is, and what it may not overlap.
    #[test]
    fn service_range_knows_its_addresses_and_what_it_overlaps() {
        let services = range("100.87.0.0/16").unwrap();
        let addr = |text: &str| text.parse::<Ipv4Addr>().unwrap();
        assert!(services.contains(addr("100.87.4.9")) && !services.contains(addr("100.88.0.2")));
        assert_eq!(services.number_of(addr("100.87.0.2")), Some(2));
        assert_eq!(services.number_of(addr("100.87.255.254")), Some(65534));
        // (The network's own, the node's, the broadcast, and what is outside it, are no number.)
        for text in [
            "100.87.0.0",
            "100.87.0.1",
            "100.87.255.255",
            "100.86.255.255",
            "100.88.0.2",
        ] {
            assert_eq!(services.number_of(addr(text)), None, "{text}");
        }
        assert_eq!(services.address(7), addr("100.87.0.7"));
        let on = |address: &str, bits, link, name: &str| Held {
            address: address.parse().unwrap(),
            bits,
            link,
            name: name.into(),
        };
        let pods = Range::default();
        assert_eq!(services.service_clash(&pods, &[on("100.87.0.5", 32, 1, "lo")]), None);
        assert_eq!(services.service_clash(&pods, &[on("192.168.1.2", 24, 2, "eth0")]), None);
        let said = |range: &str, held: &[Held]| range.parse::<Range>().unwrap().service_clash(&pods, held);
        assert!(
            said("100.88.0.0/16", &[])
                .unwrap()
                .contains("overlaps the pods' range 100.88.0.0/16")
        );
        assert!(said("100.89.0.0/16", &[]).unwrap().contains("people's 100.89.0.0/16"));
        let on_eth = said("100.87.0.0/16", &[on("100.87.3.4", 24, 2, "eth0")]).unwrap();
        assert!(
            on_eth.contains("100.87.3.4/24 on eth0") && on_eth.contains("Services' range"),
            "{on_eth}"
        );
    }

    /// docs/adr-people.md, Review 4: with `--people`, neither the pods' range nor a network this
    /// node is on may overlap the people's 100.89.0.0/16 (kwg0's own address and the loopback aside).
    #[test]
    fn the_people_range_is_clear_of_the_pods_and_the_nodes_networks() {
        for text in ["100.89.0.0/16", "100.64.0.0/10", "100.89.8.0/24", "100.0.0.0/8"] {
            let said = range(text).unwrap().refuse_people().unwrap_err();
            assert!(said.contains(text) && said.contains("--pod-range"), "{said}");
        }
        for text in ["100.88.0.0/16", "10.77.0.0/16", "100.90.0.0/16", "100.96.0.0/11"] {
            range(text).unwrap().refuse_people().expect(text);
        }
        let on = |address: &str, bits, link, name: &str| Held {
            address: address.parse().unwrap(),
            bits,
            link,
            name: name.into(),
        };
        Range::refuse_people_held(&[
            on("192.168.1.5", 24, 2, "eth0"),
            on("100.88.0.1", 32, LOOPBACK, "lo"),
            on("100.89.0.1", 16, 7, crate::people::DEVICE),
            on("100.89.5.5", 32, LOOPBACK, "lo"),
        ])
        .unwrap();
        for (address, bits) in [("100.89.3.4", 24), ("100.64.0.9", 10), ("100.89.255.255", 32)] {
            let said =
                Range::refuse_people_held(&[on("192.168.1.5", 24, 2, "eth0"), on(address, bits, 3, "tailscale0")])
                    .unwrap_err();
            assert!(said.contains(&format!("{address}/{bits} on tailscale0")), "{said}");
        }
    }

    #[test]
    fn a_node_with_no_address_at_all_refuses_no_range() {
        let ours = range("10.77.0.0/16").unwrap();
        ours.refuse_held(&[]).unwrap();
        let lo = Held {
            address: "127.0.0.1".parse().unwrap(),
            bits: 8,
            link: LOOPBACK,
            name: "lo".into(),
        };
        ours.refuse_held(&[lo]).unwrap();
    }

    #[test]
    fn a_rule_goes_after_the_chains_others() {
        // (Without append, 0x800, the kernel puts each rule first: the guard's drop of
        // what comes by a tunnel ran ahead of its accept of the answers.)
        let mut batch = Batch::new("t");
        let start = batch.bytes.len();
        batch.rule(INET, "c", &[verdict(1)]);
        let flags = u16::from_ne_bytes([batch.bytes[start + 6], batch.bytes[start + 7]]);
        assert_eq!(flags, 0xc01);
    }

    #[test]
    fn a_batch_asks_for_one_acknowledgement_only_its_last_message() {
        // (An ack per rule queues a reply per rule in the socket's receive buffer: a table of
        // hundreds of peers overflowed it, ENOBUFS.)
        let mut batch = Batch::new("t");
        batch.table(INET);
        batch.rule(INET, "c", &[verdict(1)]);
        batch.rule(INET, "c", &[verdict(1)]);
        let (bytes, _) = batch.finish();
        let mut flags = Vec::new();
        let mut rest = &bytes[..];
        while rest.len() >= 16 {
            let length = u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            flags.push(u16::from_ne_bytes([rest[6], rest[7]]));
            rest = &rest[length.max(16)..];
        }
        // Begin, the three table messages, two rules, end.
        assert_eq!(flags.len(), 7);
        let acked: Vec<usize> = (0..flags.len()).filter(|&at| flags[at] & 4 != 0).collect();
        assert_eq!(acked, vec![5], "{flags:x?}");
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

    fn contains(bytes: &[u8], part: &[u8]) -> bool {
        bytes.windows(part.len()).any(|window| window == part)
    }

    /// What comes by a pod's link is passed at prerouting only from that pod's own addresses
    /// (its link's name whole, and its IPv4 or IPv6 source), and the rest of `kp*` (an exit's
    /// `kpx` among it) is dropped. A pod sends with its own addresses only, whatever the family.
    #[test]
    fn a_pod_link_has_a_reverse_path_check() {
        let range = range("198.18.16.0/20").unwrap();
        let net = crate::node_net(crate::prefix(b"test"), "alpha");
        let pods = [
            Served {
                number: 2,
                exit: false,
                v6: addresses(range, Some(net), 2).1,
                egress: None,
            },
            Served {
                number: 3,
                exit: true,
                v6: None,
                egress: None,
            },
        ];
        let check: Vec<Vec<u8>> = pod_guard_rules(range, &[], &pods)
            .iter()
            .filter(|(chain, _)| *chain == "check")
            .map(|(_, rule)| rule.concat())
            .collect();
        let [pod2_v4, pod2_v6, exit3_v4, rest] = check.as_slice() else {
            panic!("four rules in check, not {}", check.len())
        };
        let (v4, v6) = (
            addresses(range, None, 2).0.octets(),
            addresses(range, Some(net), 2).1.unwrap().octets(),
        );
        let kp2 = [link_name(6), is(b"kp2\0")].concat();
        assert_eq!(pod2_v4, &[kp2.clone(), nfproto(2), at(1, 12, &v4), verdict(1)].concat());
        assert_eq!(pod2_v6, &[kp2, nfproto(10), at(1, 8, &v6), verdict(1)].concat());
        let kpx3 = [link_name(6), is(b"kpx3\0")].concat();
        let v4_3 = addresses(range, None, 3).0.octets();
        assert_eq!(exit3_v4, &[kpx3, nfproto(2), at(1, 12, &v4_3), verdict(1)].concat());
        assert_eq!(
            rest,
            &[came_by(b"kp"), verdict(0)].concat(),
            "the rest of kp* is dropped"
        );
    }

    /// What answers the node is passed, an exit's pod gets nothing more, and any pod reaches
    /// its node only for DNS at the gateway (UDP and TCP, port 53) and TCP to a Service's address
    /// and port (a rule for each pair, IPv4 or IPv6: not the whole range, which a listener bound
    /// to every address would answer on any port). The rest of a pod's link is dropped.
    #[test]
    fn pods_reach_only_dns_and_the_services_of_their_node() {
        let range = range("198.18.16.0/20").unwrap();
        let (v4, v6): (IpAddr, IpAddr) = ("100.87.0.5".parse().unwrap(), "fd00::1:2".parse().unwrap());
        let input = |services: &[(IpAddr, u16)]| -> Vec<Vec<u8>> {
            pod_guard_rules(range, services, &[])
                .into_iter()
                .filter(|(chain, _)| *chain == "in")
                .map(|(_, rule)| rule.concat())
                .collect()
        };
        assert_eq!(input(&[]).len(), 5, "no Service, no rule for one");
        let input = input(&[(v4, 80), (v6, 443)]);
        let [answers, exit, dns_udp, dns_tcp, v4_rule, v6_rule, rest] = input.as_slice() else {
            panic!("seven rules in in, not {}", input.len())
        };
        assert_eq!(answers, &[came_by(b"kp"), state(2 | 4 | 64), verdict(1)].concat());
        assert_eq!(
            exit,
            &[came_by(b"kpx"), verdict(0)].concat(),
            "an exit's pod: nothing more"
        );
        for (dns, protocol) in [(dns_udp, 17u8), (dns_tcp, 6u8)] {
            assert!(dns.starts_with(&came_by(b"kp")) && dns.ends_with(&verdict(1)));
            assert!(contains(dns, &is(&range.gateway().octets())), "to the gateway");
            assert!(contains(dns, &is(&53u16.to_be_bytes())), "port 53");
            assert!(contains(dns, &is(&[protocol])), "UDP or TCP");
        }
        for (rule, family, address, port) in [
            (v4_rule, 2u8, &[100u8, 87, 0, 5][..], 80u16),
            (
                v6_rule,
                10u8,
                &"fd00::1:2".parse::<Ipv6Addr>().unwrap().octets()[..],
                443,
            ),
        ] {
            assert!(rule.starts_with(&came_by(b"kp")) && rule.ends_with(&verdict(1)));
            assert!(
                contains(rule, &is(&[family])) && contains(rule, &is(&[6])),
                "the family, and TCP"
            );
            assert!(contains(rule, &is(address)), "the Service's whole address");
            assert!(contains(rule, &is(&port.to_be_bytes())), "and its port");
        }
        assert_eq!(rest, &[came_by(b"kp"), verdict(0)].concat(), "and the rest is dropped");
    }

    fn served_with(number: u16, egress: Option<Vec<Egress>>) -> Served {
        Served {
            number,
            exit: false,
            v6: None,
            egress,
        }
    }

    /// A pod with egress rules is sent to a chain of its own, from what is passed on and from
    /// what comes to the node (where DNS and the Services are): the chain returns what
    /// answers, then each rule in turn (an allow returns, a deny drops), and drops what none
    /// takes. A pod with none has no chain and no jump.
    #[test]
    fn egress_rules_make_a_chain_per_pod_in_the_order_given() {
        let range = range("198.18.16.0/20").unwrap();
        let rules = vec![
            Egress {
                allow: false,
                to: vec![("10.1.2.3".parse().unwrap(), 32)],
                ports: vec![],
            },
            Egress {
                allow: true,
                to: vec![("10.0.0.0".parse().unwrap(), 8), ("fd00::".parse().unwrap(), 64)],
                ports: vec![443],
            },
        ];
        let pods = [served_with(2, Some(rules)), served_with(3, None)];
        let all = pod_guard_rules(range, &[], &pods);
        let chain = |name: &str| -> Vec<Vec<u8>> {
            let of = all.iter().filter(|(chain, _)| *chain == name);
            of.map(|(_, rule)| rule.concat()).collect()
        };
        let named = [link_name(6), is(b"kp2\0")].concat();
        for hook in ["passed", "in"] {
            let jumps = chain(hook);
            assert!(
                jumps
                    .iter()
                    .any(|rule| rule == &[named.clone(), jump("e-kp2")].concat()),
                "{hook}"
            );
            assert!(
                !jumps.iter().any(|rule| contains(rule, b"e-kp3")),
                "{hook}: a pod with none has no jump"
            );
        }
        // In `in`, the jump is ahead of the generic DNS accept, so a pod's policy gates it.
        let input = chain("in");
        let at = |part: &[u8]| input.iter().position(|rule| contains(rule, part)).unwrap();
        assert!(at(b"e-kp2") < at(&is(&53u16.to_be_bytes())));

        let own = egress_rules(&pods);
        let [(name, rules)] = own.as_slice() else {
            panic!("one chain, for the one pod with rules")
        };
        assert_eq!(name, "e-kp2");
        let rules: Vec<Vec<u8>> = rules.iter().map(|rule| rule.concat()).collect();
        // Answers, the deny, the allow for each of its two networks with the port in TCP and in
        // UDP, and the drop of the rest.
        assert_eq!(rules.len(), 1 + 1 + 2 * 2 + 1);
        assert_eq!(rules[0], [answering(), ret()].concat());
        assert!(contains(&rules[1], &is(&[10, 1, 2, 3])) && rules[1].ends_with(&verdict(0)));
        assert!(
            contains(&rules[2], &is(&[10])) && rules[2].ends_with(&ret()),
            "10.0.0.0/8: masked, then compared"
        );
        assert!(contains(&rules[2], &is(&443u16.to_be_bytes())) && contains(&rules[2], &is(&[6])));
        assert!(contains(&rules[3], &is(&[17])), "the same port by UDP");
        assert!(contains(&rules[4], &is(&[10])), "IPv6's");
        assert_eq!(rules.last().unwrap(), &verdict(0), "what no rule takes is dropped");
    }

    /// A pod with egress rules reaches the peers they allow and no other; one without them, and
    /// what comes to a pod, are not held (`KITH_E2E=1 unshare -Urn cargo test -p kith-mesh
    /// egress`).
    #[test]
    fn egress_reaches_only_the_peers_allowed() {
        if !nix::unistd::getuid().is_root() || std::env::var_os("KITH_E2E").is_none() {
            return eprintln!("skipped: KITH_E2E=1 unshare -Urn cargo test -p kith-mesh egress");
        }
        let _lo = crate::netlink::LO.lock().unwrap_or_else(|e| e.into_inner());
        // The namespace is left as found, a panic too: the other tests take forwarding off as a
        // sign of a node not yet guarded.
        struct Forwarding;
        impl Drop for Forwarding {
            fn drop(&mut self) {
                let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "0");
            }
        }
        let _forwarding = Forwarding;
        up(1).unwrap();
        let range = range("198.18.16.0/20").unwrap();
        let net = crate::node_net(crate::prefix(b"test"), "alpha");
        // The first pod is held; the others are not. Each listens on 80 and 81. (Numbers of
        // their own: the namespace is the other tests' too.)
        let pods: Vec<_> = [12u16, 13, 14]
            .map(|number| {
                let (v4, v6) = addresses(range, Some(net), number);
                let namespace = make(range, number, v6, None).unwrap();
                let listeners: Vec<_> = [80, 81]
                    .map(|port| within(&namespace, || TcpListener::bind(("::", port))).unwrap().unwrap())
                    .into();
                (namespace, listeners, v4, v6.unwrap())
            })
            .into();
        let host = |address: Ipv6Addr| IpAddr::from(address);
        let egress = vec![
            Egress {
                allow: false,
                to: vec![(host(pods[2].3), 128)],
                ports: vec![81],
            },
            Egress {
                allow: true,
                to: vec![(host(pods[1].3), 128), (host(pods[2].3), 128)],
                ports: vec![],
            },
        ];
        let served = |number: u16, egress: Option<Vec<Egress>>| Served {
            v6: addresses(range, Some(net), number).1,
            ..served_with(number, egress)
        };
        let served = [served(12, Some(egress)), served(13, None), served(14, None)];
        // (Without masquerade: a kernel may have none in a namespace.)
        assert!(node_with(range, &[], true, false, "kith0", &served).unwrap());
        let connect = |from: usize, to: IpAddr, port: u16| {
            let to = SocketAddr::from((to, port));
            within(&pods[from].0, || {
                TcpStream::connect_timeout(&to, Duration::from_secs(2))
            })
            .unwrap()
            .is_ok()
        };
        // The first rule that fits says: pod 4's port 81 is denied, its 80 and all of 3's allowed.
        let (second, third) = (host(pods[1].3), host(pods[2].3));
        assert!(connect(0, second, 80) && connect(0, second, 81));
        assert!(connect(0, third, 80), "an allow with no port: any");
        assert!(!connect(0, third, 81), "the deny is first");
        // Nothing fits: no (the other pod's IPv4 address is no rule's peer).
        assert!(!connect(0, pods[1].2.into(), 80));
        // Others are not held, and the held pod answers what comes to it.
        assert!(connect(1, host(pods[0].3), 80) && connect(1, third, 81));
        // A second time changes nothing.
        assert!(node_with(range, &[], true, false, "kith0", &served).unwrap());
        assert!(connect(0, second, 80) && !connect(0, third, 81));
    }

    /// Two pods of one node, as root of a network namespace (`unshare -Urn cargo test -p
    /// kith-mesh pods`): both listen on port 80, each is reached in its own namespace,
    /// at its own address from the node and from the other pod, and what one sends to the
    /// other's IPv4 address comes from the node. A pod sends with its own address only, and
    /// reaches its node only for DNS and Services.
    #[test]
    fn pods_have_a_network_each() {
        if !nix::unistd::getuid().is_root() || std::env::var_os("KITH_E2E").is_none() {
            return eprintln!("skipped: KITH_E2E=1 unshare -Urn cargo test -p kith-mesh pods");
        }
        let _lo = crate::netlink::LO.lock().unwrap_or_else(|e| e.into_inner());
        up(1).unwrap();
        // (A range that is not the default, and not whole bytes: the masquerade matches its bits.)
        let range = range("198.18.16.0/20").unwrap();
        // (A kernel whose masquerade is a module nobody loaded has none in a namespace.)
        let masquerade = match node(range, &[], false, "kith0", &[]) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            guarded => guarded.unwrap(),
        };
        if !masquerade {
            eprintln!("this kernel has no masquerade here: without");
            assert!(node_with(range, &[], false, false, "kith0", &[]).unwrap());
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
        // The pods' own addresses are the node's to pass by their links: made again with them.
        let served: Vec<Served> = [2, 3]
            .map(|number| Served {
                number,
                exit: false,
                v6: addresses(range, Some(net), number).1,
                egress: None,
            })
            .into();
        let service = crate::service_address(crate::prefix(b"test"), "default", "web");
        let services = [(IpAddr::from(service), 80)];
        assert!(node_with(range, &services, true, masquerade, "kith0", &served).unwrap());
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
        // A root pod sends with another pod's address (pod 1's, added to pod 0's interface):
        // the node hears nothing of it, and hears what pod 0 sends from its own address after
        // it (datagrams of one path keep their order, so a spoof that got through came first).
        let heard = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 53)).unwrap();
        heard.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        within(&pods[0].0, || -> Result<()> {
            address(index_of("eth0")?, pods[1].2.into(), 32)?;
            let spoof = UdpSocket::bind((pods[1].2, 0))?;
            spoof.send_to(b"spoofed", (range.gateway(), 53))?;
            let own = UdpSocket::bind((pods[0].2, 0))?;
            own.send_to(b"own", (range.gateway(), 53))?;
            Ok(())
        })
        .unwrap()
        .unwrap();
        let mut datagram = [0u8; 16];
        let (size, from) = heard.recv_from(&mut datagram).unwrap();
        assert_eq!(
            (&datagram[..size], from.ip()),
            (&b"own"[..], IpAddr::from(pods[0].2)),
            "a source that is not the pod's own is dropped"
        );
        // A pod reaches its node only for DNS at the gateway and a Service: another port of the
        // node's (open here, so it is the rule that refuses) does not connect; those do.
        let _open = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 8080)).unwrap();
        let _dns = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 53)).unwrap();
        address(1, service.into(), 128).unwrap();
        let _services = TcpListener::bind((service, 80)).unwrap();
        // A listener bound to every address (the Service's is the node's) on a port no Service
        // has: the Service's address does not reach it.
        let _every = TcpListener::bind("[::]:8081").unwrap();
        let connect = |pod: usize, to: SocketAddr| {
            within(&pods[pod].0, || TcpStream::connect_timeout(&to, Duration::from_secs(5))).unwrap()
        };
        assert!(
            connect(0, (range.gateway(), 8080).into()).is_err(),
            "a node's other port: dropped"
        );
        assert!(connect(0, (range.gateway(), 53).into()).is_ok(), "DNS at the gateway");
        assert!(connect(0, (service, 80).into()).is_ok(), "a Service's address");
        assert!(
            connect(0, (service, 8081).into()).is_err(),
            "a Service's address, a port that is no Service's: dropped"
        );
        // A second time changes nothing (what the first left is taken away and made again).
        assert!(node_with(range, &services, true, masquerade, "kith0", &served).unwrap());
        assert!(tables().unwrap());
    }

    /// A pod whose namespace has IPv6 off (no inet6 address at all) asks its node's resolver at
    /// the gateway and reaches a Service's IPv4 address and port (a /32 on the node's loopback) by
    /// TCP; another address of the loopback, the node's other ports, and a port that is no
    /// Service's at the Service's address (a listener bound to every address answers there), it
    /// does not (`KITH_E2E=1 unshare -Urn cargo test -p kith-mesh ipv6_off`).
    #[test]
    fn a_pod_with_ipv6_off_reaches_the_resolver_and_a_service_by_ipv4() {
        if !nix::unistd::getuid().is_root() || std::env::var_os("KITH_E2E").is_none() {
            return eprintln!("skipped: KITH_E2E=1 unshare -Urn cargo test -p kith-mesh ipv6_off");
        }
        let _lo = crate::netlink::LO.lock().unwrap_or_else(|e| e.into_inner());
        up(1).unwrap();
        let range = range("198.18.16.0/20").unwrap();
        let service = Ipv4Addr::new(100, 87, 0, 5);
        let elsewhere = Ipv4Addr::new(100, 86, 0, 5);
        let services = [(IpAddr::from(service), 80)];
        let net = crate::node_net(crate::prefix(b"test"), "alpha");
        let (v4, v6) = addresses(range, Some(net), 20);
        let namespace = make(range, 20, v6, None).unwrap();
        let (off, inet6) = within(&namespace, || {
            let sysctl = "/proc/sys/net/ipv6/conf/all/disable_ipv6";
            std::fs::write(sysctl, "1").unwrap();
            (
                std::fs::read_to_string(sysctl).unwrap(),
                // (This thread's view: /proc/net is the process's, not the thread's that joined.)
                std::fs::read_to_string("/proc/thread-self/net/if_inet6").unwrap(),
            )
        })
        .unwrap();
        assert_eq!(
            (off.trim(), inet6.as_str()),
            ("1", ""),
            "no inet6 address, the sysctl 1"
        );
        let served = [Served {
            v6,
            ..served_with(20, None)
        }];
        assert!(node_with(range, &services, true, false, "kith0", &served).is_ok());
        let within_pod = |f: fn(Ipv4Addr, Ipv4Addr) -> std::io::Result<String>, to: Ipv4Addr| {
            within(&namespace, move || f(v4, to)).unwrap()
        };
        // DNS at the gateway, by UDP: a question out and an answer back (the node's socket
        // answers where it was asked from).
        let resolver = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 53)).unwrap();
        resolver.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let answering = std::thread::spawn(move || {
            let mut asked = [0u8; 16];
            let (size, from) = resolver.recv_from(&mut asked).unwrap();
            resolver.send_to(&asked[..size], from).unwrap();
        });
        let said = within_pod(
            |own, to| {
                let socket = UdpSocket::bind((own, 0))?;
                socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                socket.send_to(b"question", (to, 53))?;
                let mut answer = [0u8; 16];
                let size = socket.recv(&mut answer)?;
                Ok(String::from_utf8_lossy(&answer[..size]).into_owned())
            },
            range.gateway(),
        );
        answering.join().unwrap();
        assert_eq!(said.unwrap(), "question", "the resolver at the gateway answers by IPv4");
        // A Service's IPv4 address: a /32 on the loopback, a listener on it.
        crate::netlink::address4(1, service, 32, None).unwrap();
        crate::netlink::address4(1, elsewhere, 32, None).unwrap();
        let listeners = [service, elsewhere].map(|at| TcpListener::bind((at, 80)).unwrap());
        let _open = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 8080)).unwrap();
        let connect = |to: Ipv4Addr, port: u16| {
            let to = SocketAddr::from((to, port));
            within(&namespace, move || {
                TcpStream::connect_timeout(&to, Duration::from_secs(3)).is_ok()
            })
            .unwrap()
        };
        assert!(connect(service, 80), "a Service's IPv4 address");
        assert!(
            !connect(elsewhere, 80),
            "an address outside the Services' range is dropped"
        );
        assert!(!connect(range.gateway(), 8080), "so is another port of the node");
        // `_open` is bound to every address, the Service's among them: its port is no Service's.
        assert!(
            !connect(service, 8080),
            "a Service's address on a port that is no Service's: dropped"
        );
        drop(listeners);
    }
}
