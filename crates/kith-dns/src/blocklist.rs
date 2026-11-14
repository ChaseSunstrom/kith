//! Block lists: names answered as not there, however a client got to them.
//!
//! A list is held as the 64-bit hashes of its names, sorted: 8 bytes a name, and nothing else (the
//! name text is dropped once read). The hash is SipHash with keys picked when the list is made, so
//! nobody who writes a list can make names collide on purpose. A collision of two different names
//! is as likely as one in 2^64 per pair, and its worst outcome is one name wrongly blocked.

use crate::wire::valid_name;
use crate::zones::{Cidr, key, suffixes};
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::Arc;

/// The names of one list.
#[derive(Debug)]
pub struct Names {
    state: RandomState,
    /// Sorted, without repeats.
    hashes: Box<[u64]>,
}

impl Names {
    fn hash(&self, name: &str) -> u64 {
        self.state.hash_one(name)
    }

    /// Whether `name`, or a name above it, is in the list (so `ads.example` blocks `x.ads.example`
    /// and not `example`).
    pub fn blocks(&self, name: &str) -> bool {
        let name = key(name);
        suffixes(&name).any(|s| self.hashes.binary_search(&self.hash(s)).is_ok())
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// The memory the names take.
    pub fn bytes(&self) -> usize {
        self.hashes.len() * size_of::<u64>()
    }
}

/// A list and who it is for.
#[derive(Debug, Clone)]
pub struct Block {
    /// The clients it applies to; empty for all of them.
    pub nets: Vec<Cidr>,
    pub names: Arc<Names>,
    /// Answer 0.0.0.0 and :: (and nothing for other types) instead of NXDOMAIN.
    pub null: bool,
}

/// What `parse_list` made of a text.
#[derive(Debug)]
pub struct Parsed {
    pub names: Names,
    /// Lines, or names on a hosts line, that were not names or addresses with names.
    pub skipped: usize,
    /// The text has more names than the bound given: `names` holds the first of them only.
    pub over: bool,
}

/// A name that goes in a list: it fits the wire, is plain letters, digits, `-` and `_`, and is
/// not an address.
fn listable(name: &str) -> bool {
    let name = name.trim_end_matches('.');
    valid_name(name)
        && !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        && name.parse::<IpAddr>().is_err()
}

/// The machine's own names a hosts file begins with: they are not for blocking.
const LOCAL_NAMES: [&str; 6] = [
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
];

/// Reads a list: a hosts file (`0.0.0.0 ads.example tracker.example`, `#` starts a comment), one
/// name a line, a filter list's plain rules (`||ads.example^`, `!` starts a comment), or a mix.
/// Any other line (a rule with a path, an option or an exception) is skipped and counted. At most
/// `max` names are kept.
pub fn parse_list(text: &str, max: usize) -> Parsed {
    let state = RandomState::new();
    let (mut hashes, mut skipped, mut over) = (Vec::new(), 0, false);
    // (A file saved with a byte-order mark begins with one; it is not part of the first name.)
    'lines: for line in text.trim_start_matches('\u{feff}').lines() {
        // (A `#` starts a comment at the start of a line or after a space: `site.example##.banner`,
        // a rule about a page's parts, is not the name before it.)
        let comment =
            |&(at, c): &(usize, char)| c == '#' && line[..at].chars().next_back().is_none_or(char::is_whitespace);
        let line = &line[..line.char_indices().find(comment).map_or(line.len(), |(at, _)| at)];
        if line.trim_start().starts_with(['!', '[']) {
            continue;
        }
        let rule = line.trim().strip_prefix("||").and_then(|rest| rest.strip_suffix('^'));
        let line = rule.unwrap_or(line);
        let mut words = line.split_whitespace().peekable();
        let Some(&first) = words.peek() else { continue };
        // A hosts line names an address first; anything else with several words is not a list line.
        let hosts = first.parse::<IpAddr>().is_ok();
        if hosts {
            words.next();
        } else if line.split_whitespace().count() > 1 {
            skipped += 1;
            continue;
        }
        if words.peek().is_none() {
            skipped += 1;
        }
        for name in words {
            if hosts && LOCAL_NAMES.iter().any(|local| local.eq_ignore_ascii_case(name)) {
                continue;
            }
            if !listable(name) {
                skipped += 1;
            } else if hashes.len() >= max {
                over = true;
                break 'lines;
            } else {
                hashes.push(state.hash_one(key(name)));
            }
        }
    }
    hashes.sort_unstable();
    hashes.dedup();
    Parsed {
        names: Names {
            state,
            hashes: hashes.into_boxed_slice(),
        },
        skipped,
        over,
    }
}
