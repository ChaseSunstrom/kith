//! The kernel's side: a WireGuard link made and addressed over route netlink, its key and
//! peers set and read over generic netlink.

use crate::{Key, MESH_BITS, NODE_BITS, Peer};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST, NetlinkDeserializable,
    NetlinkMessage, NetlinkPayload, NetlinkSerializable,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_generic::ctrl::{GenlCtrl, GenlCtrlCmd, nlas::GenlCtrlAttrs};
use netlink_packet_route::address::{AddressAttribute, AddressMessage, CacheInfo};
use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute, WireguardCmd,
    WireguardMessage, WireguardPeer, WireguardPeerAttribute, WireguardPeerFlags,
};
use netlink_sys::{Socket, SocketAddr, protocols};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A peer as the kernel has it.
#[derive(Debug, Clone, PartialEq)]
pub struct Seen {
    pub key: Key,
    /// Where its packets last came from, or where it was said to be.
    pub endpoint: Option<std::net::SocketAddr>,
    /// How long ago the two last agreed on keys; `None`: never.
    pub handshake: Option<Duration>,
}

/// A WireGuard interface of this machine.
pub struct Device {
    index: u32,
    family: u16,
    /// The peers as last set, once they have been.
    had: Option<BTreeMap<Key, Peer>>,
    /// The further addresses (services') this has put on the interface.
    held: BTreeSet<Ipv6Addr>,
}

fn socket(protocol: isize) -> Result<Socket> {
    let mut socket = Socket::new(protocol)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;
    Ok(socket)
}

/// Send `message` and take the answers, up to the kernel's "done" or its yes or no. Each
/// question has a socket of its own, so what is left of an earlier one (after an answer
/// that could not be read) is never taken for this one's.
fn ask<T>(protocol: isize, message: T, flags: u16) -> Result<Vec<T>>
where
    T: NetlinkSerializable + NetlinkDeserializable + std::fmt::Debug,
    NetlinkMessage<T>: From<T>,
{
    let mut message = NetlinkMessage::from(message);
    message.header.flags = NLM_F_REQUEST | flags;
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    let socket = socket(protocol)?;
    socket.send(&bytes, 0)?;
    let mut answers = Vec::new();
    loop {
        let (bytes, _) = socket.recv_from_full()?;
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            let answer = NetlinkMessage::<T>::deserialize(rest);
            let answer = answer.map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
            // (Messages are padded to four bytes.)
            let length = (answer.header.length as usize).next_multiple_of(4);
            match answer.payload {
                NetlinkPayload::Error(e) if e.code.is_some() => return Err(e.to_io()),
                NetlinkPayload::Done(done) if done.code != 0 => {
                    return Err(Error::from_raw_os_error(done.code.abs()));
                }
                NetlinkPayload::Error(_) | NetlinkPayload::Done(_) => return Ok(answers),
                NetlinkPayload::InnerMessage(answer) => answers.push(answer),
                _ => {}
            }
            rest = rest.get(length.max(1)..).unwrap_or_default();
        }
    }
}

fn link(index: u32, name: Option<&str>) -> LinkMessage {
    let mut link = LinkMessage::default();
    link.header.index = index;
    link.attributes
        .extend(name.map(|name| LinkAttribute::IfName(name.into())));
    link
}

impl Device {
    /// The WireGuard interface `name`, made if it is not there, with this private key,
    /// UDP port and address (of a cluster's /48), and up. An interface of that name that
    /// is something else is left alone, and an error.
    pub fn ensure(name: &str, key: &Key, port: u16, address: Ipv6Addr) -> Result<Device> {
        let ask_route = |message, flags| ask(protocols::NETLINK_ROUTE, message, flags);
        let mut new = link(0, Some(name));
        let kind = LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Wireguard)]);
        new.attributes.push(kind.clone());
        let made = ask_route(RouteNetlinkMessage::NewLink(new), NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
        match made {
            Err(e) if e.kind() != ErrorKind::AlreadyExists => return Err(e),
            _ => {}
        }
        let found = ask_route(RouteNetlinkMessage::GetLink(link(0, Some(name))), NLM_F_ACK)?;
        let Some(RouteNetlinkMessage::NewLink(found)) = found.into_iter().next() else {
            return Err(Error::other(format!("no word from the kernel about {name}")));
        };
        let is_kind = |info: &LinkInfo| matches!(info, LinkInfo::Kind(InfoKind::Wireguard));
        let wireguard = found.attributes.iter().any(|attribute| match attribute {
            LinkAttribute::LinkInfo(infos) => infos.iter().any(is_kind),
            _ => false,
        });
        if !wireguard {
            let what = format!("there is an interface {name} already, and it is not a WireGuard one");
            return Err(Error::new(ErrorKind::AlreadyExists, what));
        }
        let index = found.header.index;

        let family = GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![GenlCtrlAttrs::FamilyName("wireguard".into())],
        };
        let families = ask(protocols::NETLINK_GENERIC, GenlMessage::from_payload(family), NLM_F_ACK)?;
        let ids = families.iter().flat_map(|family| &family.payload.nlas);
        let mut id = ids.filter_map(|attribute| match attribute {
            GenlCtrlAttrs::FamilyId(id) => Some(*id),
            _ => None,
        });
        let family = id.next().ok_or_else(|| Error::other("the kernel has no WireGuard"))?;
        let mut device = Device {
            index,
            family,
            had: None,
            held: BTreeSet::new(),
        };
        device.set(vec![
            WireguardAttribute::PrivateKey(*key),
            WireguardAttribute::ListenPort(port),
        ])?;

        // (The /48 on the interface is the route to every other node too.)
        device.address(address, MESH_BITS, true)?;
        let mut up = link(index, None);
        up.header.flags = LinkFlags::Up;
        up.header.change_mask = LinkFlags::Up;
        ask_route(RouteNetlinkMessage::SetLink(up), NLM_F_ACK)?;
        Ok(device)
    }

    /// Put `address` on the interface, or take it off.
    fn address(&self, address: Ipv6Addr, bits: u8, there: bool) -> Result<()> {
        let mut message = AddressMessage::default();
        message.header.family = AddressFamily::Inet6;
        message.header.prefix_len = bits;
        message.header.index = self.index;
        message.attributes.push(AddressAttribute::Address(address.into()));
        // A further address (every node has it) is never what this node's own traffic
        // comes from: the others would not take it for this node's. "Deprecated", to
        // the kernel: good to be reached at, not to be picked for calling out.
        if bits == 128 {
            let mut times = CacheInfo::default();
            (times.ifa_preferred, times.ifa_valid) = (0, u32::MAX);
            message.attributes.push(AddressAttribute::CacheInfo(times));
        }
        let (message, flags) = match there {
            true => (RouteNetlinkMessage::NewAddress(message), NLM_F_CREATE | NLM_F_REPLACE),
            false => (RouteNetlinkMessage::DelAddress(message), 0),
        };
        ask(protocols::NETLINK_ROUTE, message, NLM_F_ACK | flags).map(drop)
    }

    /// Make the further addresses of the interface (besides its own) `wanted`.
    //
    // ponytail: only what this Device added is taken off again: addresses left by a
    // kithd that was killed stay until the interface goes.
    pub fn set_addresses(&mut self, wanted: &BTreeSet<Ipv6Addr>) -> Result<()> {
        // All are tried; the first that failed is told. (One that would not go, because it
        // was gone already, say, is not tried again.)
        let mut failed = Ok(());
        for gone in self.held.clone().difference(wanted) {
            failed = failed.and(self.address(*gone, 128, false));
            self.held.remove(gone);
        }
        for new in wanted.difference(&self.held.clone()) {
            match self.address(*new, 128, true) {
                Ok(()) => drop(self.held.insert(*new)),
                Err(e) => failed = failed.and(Err(e)),
            }
        }
        failed
    }

    fn message(&self, cmd: WireguardCmd, mut attributes: Vec<WireguardAttribute>) -> GenlMessage<WireguardMessage> {
        attributes.insert(0, WireguardAttribute::IfIndex(self.index));
        let mut message = GenlMessage::from_payload(WireguardMessage { cmd, attributes });
        message.set_resolved_family_id(self.family);
        message
    }

    fn set(&mut self, attributes: Vec<WireguardAttribute>) -> Result<()> {
        let message = self.message(WireguardCmd::SetDevice, attributes);
        ask(protocols::NETLINK_GENERIC, message, NLM_F_ACK).map(drop)
    }

    fn get(&mut self) -> Result<Vec<WireguardAttribute>> {
        let message = self.message(WireguardCmd::GetDevice, Vec::new());
        let answers = ask(protocols::NETLINK_GENERIC, message, NLM_F_DUMP)?;
        Ok(answers
            .into_iter()
            .flat_map(|answer| answer.payload.attributes)
            .collect())
    }

    /// The public key that goes with the private one.
    pub fn public_key(&mut self) -> Result<Key> {
        let key = self.get()?.into_iter().find_map(|attribute| match attribute {
            WireguardAttribute::PublicKey(key) => Some(key),
            _ => None,
        });
        key.ok_or_else(|| Error::other("the interface has no key"))
    }

    /// The peers the interface has now.
    pub fn peers(&mut self) -> Result<Vec<Seen>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        // (A peer with many allowed addresses comes in parts; the first has what is read.)
        let mut peers: BTreeMap<Key, Seen> = BTreeMap::new();
        for attribute in self.get()? {
            let WireguardAttribute::Peers(some) = attribute else {
                continue;
            };
            for WireguardPeer(attributes) in some {
                let (mut key, mut endpoint, mut handshake) = (None, None, None);
                for attribute in attributes {
                    match attribute {
                        WireguardPeerAttribute::PublicKey(k) => key = Some(k),
                        WireguardPeerAttribute::Endpoint(e) => endpoint = Some(e),
                        WireguardPeerAttribute::LastHandshake(at) if at.seconds > 0 => {
                            let at = Duration::from_secs(at.seconds as u64);
                            handshake = Some(now.saturating_sub(at));
                        }
                        _ => {}
                    }
                }
                let Some(key) = key else { continue };
                let seen = Seen {
                    key,
                    endpoint,
                    handshake,
                };
                peers.entry(key).or_insert(seen);
            }
        }
        Ok(peers.into_values().collect())
    }

    /// Make the interface's peers `wanted`: the ones not wanted go, the others are added
    /// or changed. A peer that is as it was last time is not touched, so it keeps the
    /// endpoint the kernel has learnt from its packets.
    pub fn set_peers(&mut self, wanted: &[Peer]) -> Result<()> {
        let had = match self.had.take() {
            Some(had) => had,
            // First time: whatever is there is not ours to keep.
            None => {
                let there = self.peers()?.into_iter().map(|seen| Peer {
                    key: seen.key,
                    endpoint: None,
                    allowed: Vec::new(),
                    keepalive: 0,
                });
                there.map(|peer| (peer.key, peer)).collect()
            }
        };
        let wanted: BTreeMap<Key, Peer> = wanted.iter().map(|peer| (peer.key, peer.clone())).collect();
        let flags = |flags| WireguardPeerAttribute::Flags(flags);
        let mut changes = Vec::new();
        for key in had.keys().filter(|key| !wanted.contains_key(*key)) {
            let gone = vec![
                WireguardPeerAttribute::PublicKey(*key),
                flags(WireguardPeerFlags::RemoveMe),
            ];
            changes.push(WireguardPeer(gone));
        }
        for peer in wanted.values().filter(|peer| had.get(&peer.key) != Some(*peer)) {
            let allowed = |net: &Ipv6Addr| {
                WireguardAllowedIp(vec![
                    WireguardAllowedIpAttr::Family(WireguardAddressFamily::Ipv6),
                    WireguardAllowedIpAttr::IpAddr((*net).into()),
                    WireguardAllowedIpAttr::Cidr(NODE_BITS),
                ])
            };
            let mut new = vec![
                WireguardPeerAttribute::PublicKey(peer.key),
                flags(WireguardPeerFlags::ReplaceAllowedIps),
                WireguardPeerAttribute::PersistentKeepalive(peer.keepalive),
                WireguardPeerAttribute::AllowedIps(peer.allowed.iter().map(allowed).collect()),
            ];
            new.extend(peer.endpoint.map(WireguardPeerAttribute::Endpoint));
            changes.push(WireguardPeer(new));
        }
        // (A netlink message holds only so much: a few peers in each.)
        // One the kernel will not have does not keep the others out: all are tried, the
        // first refusal is the answer, and next time everything is set again.
        let mut refused = None;
        for some in changes.chunks(16) {
            let set = self.set(vec![WireguardAttribute::Peers(some.to_vec())]);
            refused = refused.or(set.err());
        }
        match refused {
            Some(e) => Err(e),
            None => {
                self.had = Some(wanted);
                Ok(())
            }
        }
    }

    /// Take the interface away.
    pub fn remove(self) -> Result<()> {
        let gone = RouteNetlinkMessage::DelLink(link(self.index, None));
        ask(protocols::NETLINK_ROUTE, gone, NLM_F_ACK).map(drop)
    }
}

fn ask_route(message: RouteNetlinkMessage, flags: u16) -> Result<Vec<RouteNetlinkMessage>> {
    ask(protocols::NETLINK_ROUTE, message, flags)
}

/// A network card of this machine (what the kernel calls Ethernet: wired, Wi-Fi, a veth).
#[derive(Debug, Clone, PartialEq)]
pub struct Card {
    pub index: u32,
    pub name: String,
    pub mac: [u8; 6],
}

/// The machine's network cards, in the kernel's order, and the loopback's index.
pub fn cards() -> Result<(Vec<Card>, Option<u32>)> {
    use netlink_packet_route::link::LinkLayerType;
    let links = ask_route(RouteNetlinkMessage::GetLink(LinkMessage::default()), NLM_F_DUMP)?;
    let (mut cards, mut loopback) = (Vec::new(), None);
    for link in links {
        let RouteNetlinkMessage::NewLink(link) = link else {
            continue;
        };
        let name = link.attributes.iter().find_map(|attribute| match attribute {
            LinkAttribute::IfName(name) => Some(name.clone()),
            _ => None,
        });
        let mac = link.attributes.iter().find_map(|attribute| match attribute {
            LinkAttribute::Address(mac) => <[u8; 6]>::try_from(&mac[..]).ok(),
            _ => None,
        });
        match (link.header.link_layer_type, name, mac) {
            (LinkLayerType::Loopback, ..) => loopback = Some(link.header.index),
            (LinkLayerType::Ether, Some(name), Some(mac)) => cards.push(Card {
                index: link.header.index,
                name,
                mac,
            }),
            _ => {}
        }
    }
    Ok((cards, loopback))
}

/// Bring a link up.
pub fn up(index: u32) -> Result<()> {
    let mut up = link(index, None);
    up.header.flags = LinkFlags::Up;
    up.header.change_mask = LinkFlags::Up;
    ask_route(RouteNetlinkMessage::SetLink(up), NLM_F_ACK).map(drop)
}

/// Give a link an IPv4 address (again does no harm), and send what is for elsewhere
/// through `gateway` if there is one.
pub fn address4(index: u32, address: std::net::Ipv4Addr, bits: u8, gateway: Option<std::net::Ipv4Addr>) -> Result<()> {
    use netlink_packet_route::route::{
        RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType,
    };
    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.prefix_len = bits;
    message.header.index = index;
    let mask = u32::MAX.checked_shl(32 - u32::from(bits.min(32))).unwrap_or(0);
    let broadcast = std::net::Ipv4Addr::from(u32::from(address) | !mask);
    message.attributes.extend([
        AddressAttribute::Local(address.into()),
        AddressAttribute::Address(address.into()),
        AddressAttribute::Broadcast(broadcast),
    ]);
    let flags = NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    ask_route(RouteNetlinkMessage::NewAddress(message), flags)?;
    let Some(gateway) = gateway else { return Ok(()) };
    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Inet;
    route.header.table = 254; // main
    route.header.protocol = RouteProtocol::Boot;
    route.header.scope = RouteScope::Universe;
    route.header.kind = RouteType::Unicast;
    route.attributes.extend([
        RouteAttribute::Gateway(RouteAddress::Inet(gateway)),
        RouteAttribute::Oif(index),
    ]);
    ask_route(RouteNetlinkMessage::NewRoute(route), flags).map(drop)
}
