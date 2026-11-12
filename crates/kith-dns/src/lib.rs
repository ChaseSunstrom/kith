//! A small DNS server: it answers names from its zones and forwards the rest to upstream resolvers.
//!
//! The wire format is hand-written (RFC 1035) to keep the binary small. Records: A, AAAA, CNAME,
//! TXT, SRV, NS, SOA and PTR. A zone is any name that has an SOA record; names under one are
//! answered here (NXDOMAIN or NODATA with the SOA when missing), names under none go upstream.

mod server;
mod wire;
mod zones;

use std::net::IpAddr;
use wire::{FORMERR, Query, REFUSED, build, failure};

pub use server::serve;
pub use wire::SERVFAIL;
pub use zones::{Cidr, Rdata, Record, Records, View, Zones};

/// What to do with one incoming packet.
#[derive(Debug, PartialEq)]
pub enum Answer {
    /// Send these bytes back.
    Reply(Vec<u8>),
    /// Not ours: ask the upstream resolvers.
    Forward,
    /// Say nothing.
    Drop,
}

/// Decides what to do with `query` from `client`. `udp` limits the reply to the client's size
/// (512 bytes, or its EDNS size up to 1232) by truncating with TC set; TCP gets the whole reply.
pub fn answer(query: &[u8], client: IpAddr, zones: &Zones, udp: bool) -> Answer {
    // Too short to be a message, or a response: never answer those (no reply loops).
    if query.len() < 12 || query[2] & 0x80 != 0 {
        return Answer::Drop;
    }
    if query[2] & 0x78 != 0 {
        return Answer::Reply(failure(query, wire::NOTIMP));
    }
    let Some(q) = Query::parse(query) else {
        return Answer::Reply(failure(query, FORMERR));
    };
    if q.qclass != 1 {
        return Answer::Reply(failure(query, REFUSED));
    }
    let limit = if udp { q.udp_limit() } else { usize::from(u16::MAX) };
    match zones.lookup(client, &q.qname, q.qtype) {
        Some(f) => Answer::Reply(build(&q, f.rcode, &f.answers, &f.authority, limit)),
        None => Answer::Forward,
    }
}

/// A SERVFAIL reply to `query`, for when no upstream answered.
pub fn servfail(query: &[u8]) -> Vec<u8> {
    failure(query, SERVFAIL)
}

#[cfg(test)]
mod tests;
