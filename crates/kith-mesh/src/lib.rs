//! The mesh between a cluster's nodes: one kernel WireGuard interface per node, set up
//! over netlink (no `ip`, no `wg`). This crate works out who gets which address and which
//! peers a node should have ([`prefix`], [`node_address`], [`wanted`]), and makes an
//! interface so ([`Device`]). Who the nodes are, and telling them of each other, is the
//! caller's part.
//!
//! Addresses are IPv6 unique local ones: the cluster has a /48 (from something every node
//! of it knows, like its CA), every node an /80 of that (from its name) for itself (`::1`)
//! and for what runs on it.
//
// ponytail: direct paths and one relay hop through an edge node. No hole punching: two
// nodes that are both behind NAT talk through an edge node for good.

mod netlink;

pub use netlink::{Device, Seen};
use sha2::{Digest, Sha256};
use std::net::{Ipv6Addr, SocketAddr};

/// A WireGuard key, private or public.
pub type Key = [u8; 32];

/// How many bits of an address say which cluster, and which node of it.
pub const MESH_BITS: u8 = 48;
pub const NODE_BITS: u8 = 80;

/// Seconds between the packets that keep a path through a NAT open.
const KEEPALIVE: u16 = 25;

/// The cluster's /48: `fd`, then 40 bits of `seed`'s hash (RFC 4193 asks for 40 bits
/// nobody else is likely to have).
pub fn prefix(seed: &[u8]) -> Ipv6Addr {
    let mut bytes = [0; 16];
    bytes[0] = 0xfd;
    bytes[1..6].copy_from_slice(&Sha256::digest(seed)[..5]);
    bytes.into()
}

/// The /80 of the node called `name`: 32 bits of the name's hash after the cluster's 48.
/// Two names can land on one (likely from some 65 000 nodes on): whoever admits nodes
/// has to refuse the second.
pub fn node_net(prefix: Ipv6Addr, name: &str) -> Ipv6Addr {
    let mut bytes = prefix.octets();
    bytes[6..10].copy_from_slice(&Sha256::digest(name.as_bytes())[..4]);
    bytes.into()
}

/// The node's own address: the first of its /80.
pub fn node_address(prefix: Ipv6Addr, name: &str) -> Ipv6Addr {
    let mut bytes = node_net(prefix, name).octets();
    bytes[15] = 1;
    bytes.into()
}

/// What a node knows of another one.
#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    pub name: String,
    pub key: Key,
    /// Where it said it can be reached, if anywhere.
    pub endpoint: Option<SocketAddr>,
    /// It has a public address and passes traffic on between nodes that cannot reach
    /// each other.
    pub edge: bool,
    /// False once it should have answered directly and has not for some minutes.
    pub reached: bool,
}

/// A peer as the interface should have it.
#[derive(Debug, Clone, PartialEq)]
pub struct Peer {
    pub key: Key,
    pub endpoint: Option<SocketAddr>,
    /// The nodes (their /80s) whose traffic goes to and comes from this peer.
    pub allowed: Vec<Ipv6Addr>,
    pub keepalive: u16,
}

/// The peers the node `me` should have: every other member, each with its own /80. A
/// member that is not reached directly is reached through an edge node that is, if there
/// is one: its /80 goes to that peer. (It stays a peer, so it is tried directly all the
/// while, and gets its /80 back when it answers.)
//
// ponytail: the first edge node that this node reaches; whether that one reaches the
// other end is not known here. With several edge nodes of which the first does not reach
// the other end, the two ends can pick different ones and not hear each other: pick by
// what the edge nodes report. An edge node sees what it passes on (it is the end of both
// tunnels).
pub fn wanted(prefix: Ipv6Addr, me: &str, members: &[Member]) -> Vec<Peer> {
    let others = || members.iter().filter(|member| member.name != me);
    let relay = others().find(|member| member.edge && member.reached);
    let through = |member: &Member| relay.filter(|_| !member.reached);
    let peer = |member: &Member| {
        let mut allowed = Vec::new();
        if through(member).is_none() {
            allowed.push(node_net(prefix, &member.name));
        }
        if relay.is_some_and(|relay| relay.key == member.key) {
            let relayed = others().filter(|other| through(other).is_some());
            allowed.extend(relayed.map(|other| node_net(prefix, &other.name)));
        }
        Peer {
            key: member.key,
            endpoint: member.endpoint,
            allowed,
            keepalive: KEEPALIVE,
        }
    };
    others().map(peer).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_peers() {
        // One cluster, one /48; one node, one /80 in it; both the same whoever works it out.
        let mesh = prefix(b"some cluster's CA");
        assert_eq!(mesh.segments()[0] >> 8, 0xfd);
        assert_eq!(mesh.segments()[3..], [0; 5]);
        assert_ne!(mesh, prefix(b"another cluster's CA"));
        let (a, b) = (node_net(mesh, "a"), node_net(mesh, "b"));
        assert_ne!(a, b);
        assert_eq!(a.segments()[..3], mesh.segments()[..3]);
        assert_eq!(a.segments()[5..], [0; 3]);
        assert_eq!(node_address(mesh, "a").segments()[7], 1);
        assert_eq!(node_address(mesh, "a").segments()[..7], a.segments()[..7]);

        let member = |name: &str, edge, reached| Member {
            name: name.into(),
            key: [name.as_bytes()[0]; 32],
            endpoint: Some(([10, 0, 0, name.as_bytes()[0]], 51820).into()),
            edge,
            reached,
        };
        let nets = |peers: &[Peer]| -> Vec<(u8, Vec<Ipv6Addr>)> {
            let of = |peer: &Peer| (peer.key[0], peer.allowed.clone());
            peers.iter().map(of).collect()
        };
        // Everyone reached: every other node is a peer with its own /80, and not oneself.
        let all = [
            member("a", false, true),
            member("b", true, true),
            member("c", false, true),
        ];
        let peers = wanted(mesh, "a", &all);
        assert_eq!(nets(&peers), [(b'b', vec![b]), (b'c', vec![node_net(mesh, "c")])]);
        assert_eq!((peers[0].endpoint, peers[0].keepalive), (all[1].endpoint, 25));
        // c does not answer: it goes through the edge node b, and stays a peer.
        let lost = [all[0].clone(), all[1].clone(), member("c", false, false)];
        let peers = wanted(mesh, "a", &lost);
        assert_eq!(nets(&peers), [(b'b', vec![b, node_net(mesh, "c")]), (b'c', vec![])]);
        // The edge node itself has nobody to go through: everyone keeps their own.
        let peers = wanted(mesh, "b", &lost);
        assert_eq!(nets(&peers), [(b'a', vec![a]), (b'c', vec![node_net(mesh, "c")])]);
        // No edge node that answers: nothing to go through, c keeps its own.
        let alone = [all[0].clone(), member("b", true, false), member("c", false, false)];
        let peers = wanted(mesh, "a", &alone);
        assert_eq!(nets(&peers), [(b'b', vec![b]), (b'c', vec![node_net(mesh, "c")])]);
    }
}
