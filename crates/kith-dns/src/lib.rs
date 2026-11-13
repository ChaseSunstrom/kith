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
use zones::{Found, key};

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
    /// Ours, but a CNAME leaves our zones: ask the upstreams for the rest (see `Chase`).
    Chase(Chase),
    /// Say nothing.
    Drop,
}

/// The most records one chase takes from the upstream.
const CHASE_MAX: usize = 100;

/// A zone answer that ends in a CNAME to a name outside our zones. A stub resolver does not
/// follow that CNAME, so the server asks the upstreams for the target and adds what belongs.
#[derive(Debug, PartialEq)]
pub struct Chase {
    q: Query,
    found: Found,
    limit: usize,
}

impl Chase {
    /// The question to put to the upstreams: the CNAME's target, with the type asked.
    pub(crate) fn ask(&self) -> Vec<u8> {
        wire::ask(&self.target(), self.q.qtype)
    }

    fn target(&self) -> String {
        match self.found.answers.last().map(|r| &r.data) {
            Some(Rdata::Cname(t)) => key(t),
            _ => unreachable!("a chase ends in a CNAME"),
        }
    }

    /// The answer as the zones give it, the CNAME alone: for when the upstreams cannot be asked.
    pub(crate) fn plain(&self) -> Vec<u8> {
        build(&self.q, 0, &self.found.answers, &[], self.limit)
    }

    /// The answer with the records from the upstreams' `reply` that belong: the target's CNAMEs
    /// and records of the asked type, following the chain of names. Anything else, and a reply
    /// that is an error or has nothing, leaves the answer as `plain`.
    // ponytail: records are taken in the order sent (resolvers send a chain in order), a name
    // in our own zones reached through the chain is not special-cased (the upstream is trusted).
    pub(crate) fn finish(&self, reply: &[u8]) -> Vec<u8> {
        let mut chain = vec![self.target()];
        let mut all = self.found.answers.clone();
        let mut room = CHASE_MAX;
        for r in wire::answers(reply) {
            if room == 0 || !chain.contains(&key(&r.name)) {
                continue;
            }
            match &r.data {
                Rdata::Cname(t) => chain.push(key(t)),
                d if d.rtype() == self.q.qtype => {}
                _ => continue,
            }
            all.push(r);
            room -= 1;
        }
        build(&self.q, 0, &all, &[], self.limit)
    }
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
        // NOERROR with no SOA and a CNAME last (and not asked for): the chain left our zones.
        Some(f)
            if f.rcode == 0
                && f.authority.is_empty()
                // (Of what the upstreams say, addresses and text are what is read.)
                && matches!(q.qtype, 1 | 16 | 28)
                && matches!(
                    f.answers.last(),
                    Some(Record {
                        data: Rdata::Cname(_),
                        ..
                    })
                ) =>
        {
            Answer::Chase(Chase { q, found: f, limit })
        }
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
