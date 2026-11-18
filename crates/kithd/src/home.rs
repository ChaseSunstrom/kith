//! The house address: one IPv4 address on the LAN that a router can name once (DHCP option 6,
//! a port forward) and that is always answered by one node, the Raft leader.
//!
//! The leader puts it on its LAN card with a lifetime of at most three seconds, counted from
//! when the confirmation that allows it began, and renews it each time Raft confirms it still
//! leads (twice a second). It takes it off at once when a confirmation is missed. A leader that
//! hangs, or is cut off, keeps the address for no more than that lifetime past its last
//! confirmation: the kernel takes it off; and one that wakes from a pause adds or renews
//! nothing before a new confirmation has succeeded. A node that has just become leader waits
//! that lifetime and two seconds more, then asks the LAN (ARP probes, RFC 5227) whether
//! something else has the address and takes it only if not, and tells the LAN with three
//! announcements. Two MACs never answer for the address.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// The most the kernel keeps the address without being told again, from the start of the
/// confirmation that allowed it.
const LIFETIME: Duration = Duration::from_secs(3);
/// How long a new leader waits before it adds the address: the old holder's has gone (Raft
/// elects no one until the old leader's last heartbeat is a lease old), and a second for the
/// kernel to be late taking it off.
const WAIT: Duration = Duration::from_secs(4);
/// How often leadership is confirmed, and how long a confirmation is waited for.
const CONFIRM_EVERY: Duration = Duration::from_millis(500);
/// How many announcements, and how far apart.
const ANNOUNCEMENTS: u8 = 3;
const GAP: Duration = Duration::from_secs(1);
/// How many probes before the address is taken, how far apart, and how long the LAN is listened to.
const PROBES: u32 = 3;
const PROBE_GAP: Duration = Duration::from_millis(300);
const PROBE_FOR: Duration = Duration::from_secs(1);

/// Where this node is with the address.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum State {
    /// Not the leader (or has no card in the network): the address is not on it.
    Idle,
    /// The leader since a moment ago: waits until then to add it.
    Waiting(Instant),
    /// Has it on its card, and has told the LAN `announced` times, the last at `last`.
    Held { announced: u8, last: Instant },
}

/// What to do about the address now.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Action {
    Nothing,
    /// Put it on the card for `seconds`, or renew it so; and announce it if `announce`.
    Hold { announce: bool, seconds: u32 },
    /// Take it off, at once.
    Delete,
}

/// The whole seconds of the lifetime left for a confirmation that began at `started`, at `now`:
/// none when it began three seconds ago or more (the node was paused, or the answer was late).
fn left(started: Instant, now: Instant) -> u32 {
    LIFETIME.saturating_sub(now.saturating_duration_since(started)).as_secs() as u32
}

/// The next state and what to do at `now`. `confirmed` is when the confirmation began, if one has
/// just succeeded that Raft says this node leads (and a card of its is in the address's
/// network), else nothing. The address is added or renewed only for a confirmation with
/// lifetime left, and then for no more than that.
pub fn step(state: State, confirmed: Option<Instant>, now: Instant) -> (State, Action) {
    let seconds = confirmed.map_or(0, |started| left(started, now));
    match (state, seconds > 0) {
        (State::Idle, false) => (State::Idle, Action::Nothing),
        (State::Idle, true) => (State::Waiting(now + WAIT), Action::Nothing),
        // (Not confirmed while it waited: no address was added, and the wait is of no use.)
        (State::Waiting(_), false) => (State::Idle, Action::Nothing),
        (State::Waiting(until), true) if now < until => (state, Action::Nothing),
        (State::Waiting(_), true) => (State::Held { announced: 1, last: now }, Action::Hold { announce: true, seconds }),
        (State::Held { .. }, false) => (State::Idle, Action::Delete),
        (State::Held { announced, last }, true) => {
            if announced < ANNOUNCEMENTS && now.duration_since(last) >= GAP {
                (State::Held { announced: announced + 1, last: now }, Action::Hold { announce: true, seconds })
            } else {
                (state, Action::Hold { announce: false, seconds })
            }
        }
    }
}

/// An ARP request for `address` by `mac`, to everyone, from the IPv4 address `from`.
fn request(mac: [u8; 6], from: Ipv4Addr, address: Ipv4Addr) -> [u8; 42] {
    let mut frame = [0u8; 42];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&mac);
    frame[12..14].copy_from_slice(&[0x08, 0x06]);
    frame[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    frame[22..28].copy_from_slice(&mac);
    frame[28..32].copy_from_slice(&from.octets());
    // (The target MAC stays zero.)
    frame[38..42].copy_from_slice(&address.octets());
    frame
}

/// The ARP announcement of `address` by `mac` (RFC 5227, 2.3): a request, to everyone, for the
/// address itself from the address itself with no target; whoever has it cached has it from this
/// MAC now.
pub fn announcement(mac: [u8; 6], address: Ipv4Addr) -> [u8; 42] {
    request(mac, address, address)
}

/// The ARP probe for `address` by `mac` (RFC 5227, 2.1.1): a request for the address from
/// 0.0.0.0, which nobody caches and whoever has the address answers.
pub fn probe_frame(mac: [u8; 6], address: Ipv4Addr) -> [u8; 42] {
    request(mac, Ipv4Addr::UNSPECIFIED, address)
}

/// The MAC of whoever `frame` shows to have `address` besides `mac`: it answers for it (an ARP
/// reply from it, or a request from it), or it announces it, or probes for it.
pub fn conflict(frame: &[u8], mac: [u8; 6], address: Ipv4Addr) -> Option<[u8; 6]> {
    if frame.len() < 42 || frame[12..14] != [0x08, 0x06] || frame[14..20] != [0, 1, 8, 0, 6, 4] {
        return None;
    }
    let sender: [u8; 6] = frame[22..28].try_into().ok()?;
    let (from, to) = (&frame[28..32], &frame[38..42]);
    let named = match frame[21] {
        // A reply from the address, or any request from it (an announcement).
        1 | 2 if from == address.octets() => true,
        // Someone else's probe for it.
        1 => from == Ipv4Addr::UNSPECIFIED.octets() && to == address.octets(),
        _ => false,
    };
    (named && sender != mac).then_some(sender)
}

/// Ask the LAN through `card` whether any other has `address`: three probes in 0.9 s, and the
/// LAN listened to for a second. The MAC of one that does.
fn probe(card: &kith_mesh::Card, address: Ipv4Addr) -> std::io::Result<Option<[u8; 6]>> {
    use nix::errno::Errno;
    use nix::sys::socket::{MsgFlags, recv, send, setsockopt, sockopt::ReceiveTimeout};
    use std::os::fd::AsRawFd;
    // ponytail: the socket hears every frame of the card for a second and the ARP ones are
    // picked out here; a filter in the kernel when a LAN is busy enough for it to show.
    let fd = crate::dhcp::packet_socket(card, true)?;
    setsockopt(&fd, ReceiveTimeout, &nix::sys::time::TimeVal::new(0, 50_000))?;
    let frame = probe_frame(card.mac, address);
    let (started, mut sent, mut buffer) = (Instant::now(), 0, [0u8; 2048]);
    while started.elapsed() < PROBE_FOR {
        if sent < PROBES && started.elapsed() >= PROBE_GAP * sent {
            send(fd.as_raw_fd(), &frame, MsgFlags::empty())?;
            sent += 1;
        }
        match recv(fd.as_raw_fd(), &mut buffer, MsgFlags::empty()) {
            Ok(n) => {
                if let Some(other) = conflict(&buffer[..n], card.mac, address) {
                    return Ok(Some(other));
                }
            }
            Err(Errno::EAGAIN | Errno::EINTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(None)
}

fn mac_text(mac: [u8; 6]) -> String {
    mac.map(|byte| format!("{byte:02x}")).join(":")
}

/// The house address as the Cluster says it: `address` and the length of its network's prefix.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Home {
    pub address: Ipv4Addr,
    pub bits: u8,
}

impl Home {
    /// `192.168.1.250/24`; nothing else (no name, no address without a prefix, no network or
    /// broadcast address of the network, nothing a LAN cannot have).
    pub fn parse(text: &str) -> Option<Home> {
        let (address, bits) = text.split_once('/')?;
        let address: Ipv4Addr = address.parse().ok()?;
        let bits: u8 = bits.parse().ok().filter(|bits| (1..=30).contains(bits))?;
        let mask = mask(bits);
        let taken = address.is_loopback() || address.is_unspecified() || address.is_multicast();
        let (network, broadcast) = (u32::from(address) & !mask == 0, u32::from(address) | mask == u32::MAX);
        (!(taken || network || broadcast)).then_some(Home { address, bits })
    }
}

fn mask(bits: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0)
}

/// The card to hold `home` on: the first of `addresses` (card name, its address, its prefix
/// length) with `home`'s address in its network.
pub fn lan_card(home: Home, addresses: &[(String, Ipv4Addr, u8)]) -> Option<&str> {
    addresses
        .iter()
        .filter(|(_, address, bits)| *bits > 0 && !address.is_loopback())
        .find(|(_, address, bits)| u32::from(*address) & mask(*bits) == u32::from(home.address) & mask(*bits))
        .map(|(name, ..)| name.as_str())
}

/// The house address the Clusters say (the lowest of them, so that every node takes the same
/// when two disagree), or nothing.
pub fn configured(store: &kith_api::store::Store) -> Option<Home> {
    let said = store
        .list(Some("Cluster"))
        .filter_map(|cluster| cluster.spec["home"]["address"].as_str().and_then(Home::parse));
    said.min_by_key(|home| (home.address, home.bits))
}

/// Every IPv4 address of this machine's cards: the card's name, the address, its prefix length.
fn addresses() -> Vec<(String, Ipv4Addr, u8)> {
    let Ok(all) = nix::ifaddrs::getifaddrs() else {
        return Vec::new();
    };
    let found = |a: nix::ifaddrs::InterfaceAddress| {
        let address = a.address?.as_sockaddr_in().map(|a| a.ip())?;
        let mask = a.netmask?.as_sockaddr_in().map(|a| u32::from(a.ip()))?;
        Some((a.interface_name, address, mask.count_ones() as u8))
    };
    all.filter_map(found).collect()
}

/// Where the address is held now.
#[derive(Debug, Clone, PartialEq)]
struct Put {
    home: Home,
    card: kith_mesh::Card,
}

/// What the Clusters say about the address, as the reason this node holds nothing when it is not
/// in a Cluster.
const NO_CLUSTER: &str = "the house address is in no Cluster";

/// What this node should hold, and on which card: the house address, if a card of this node is in
/// its network; or why it holds nothing.
fn wanted(shared: &crate::Shared) -> Result<Put, String> {
    let home = {
        let state = shared.store.lock().expect("nothing panics holding the store");
        configured(&state.store).ok_or(NO_CLUSTER)?
    };
    let none = || format!("the house address {} is not held: no card of this node is in its network", home.address);
    let (cards, _) = kith_mesh::cards().map_err(|e| format!("the house address {} is not held: reading the cards: {e}", home.address))?;
    let name = lan_card(home, &addresses()).ok_or_else(none)?.to_owned();
    let card = cards.into_iter().find(|card| card.name == name).ok_or_else(none)?;
    Ok(Put { home, card })
}

/// When a confirmation that Raft says this node leads, a quorum having just said so, began: now,
/// before it was asked; or what Raft said (or that it said nothing in time) when it was not given.
async fn confirmed(shared: &crate::Shared) -> Result<Instant, String> {
    let started = Instant::now();
    let asked = tokio::time::timeout(CONFIRM_EVERY, shared.raft.ensure_linearizable());
    match asked.await {
        Ok(Ok(_)) => Ok(started),
        Ok(Err(e)) => {
            let m = shared.raft.metrics().borrow().clone();
            Err(format!("{e}; {:?} in term {}", m.state, m.current_term))
        }
        Err(_) => Err(format!("no quorum answered in {} ms", CONFIRM_EVERY.as_millis())),
    }
}

fn let_go(held: &mut Option<Put>) {
    if let Some(Put { home, card }) = held.take()
        && let Err(e) = kith_mesh::drop_address4(card.index, home.address, home.bits)
    {
        eprintln!("kithd: taking the house address {} off {}: {e}", home.address, card.name);
    }
}

/// Say why the address is held or not, when that has changed.
fn say(was: &mut String, now: String) {
    if *was != now {
        eprintln!("kithd: {now}");
        *was = now;
    }
}

/// Hold the house address while this node is the confirmed leader, until kithd stops.
pub async fn run(shared: std::sync::Arc<crate::Shared>, mut stopping: tokio::sync::watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(CONFIRM_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let (mut state, mut held, mut before) = (State::Idle, None::<Put>, None::<Put>);
    // Why nothing is held (the first reason is no one's news), and why it is not taken: a probe
    // that found it in use, kept until something else changes.
    let (mut reason, mut blocked) = (NO_CLUSTER.to_string(), None::<String>);
    // What Raft last said when it did not confirm this node as leader.
    let mut denied = String::new();
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stopping.changed() => break,
        }
        let want = wanted(&shared);
        // The address or its card changed (the Cluster was edited, a card came or went): what
        // was held is let go, and the new one is waited for as any.
        if want.as_ref().ok() != before.as_ref() {
            let_go(&mut held);
            (state, blocked, before) = (State::Idle, None, want.as_ref().ok().cloned());
        }
        let want = match want {
            Ok(want) => want,
            Err(why) => {
                say(&mut reason, why);
                continue;
            }
        };
        let Put { home, card } = &want;
        let confirm = confirmed(&shared).await;
        if let Err(why) = &confirm {
            denied.clone_from(why);
        }
        let (next, action) = step(state, confirm.ok(), Instant::now());
        state = next;
        match action {
            Action::Hold { announce, mut seconds } => {
                if held.is_none() {
                    // The first time, and every time after it was let go: is it anyone's?
                    let (asked, address) = (card.clone(), home.address);
                    let found = tokio::task::spawn_blocking(move || probe(&asked, address)).await;
                    let why = match found {
                        Ok(Ok(None)) => None,
                        Ok(Ok(Some(other))) => Some(format!(
                            "the house address {} is in use by MAC {}: not taken",
                            home.address,
                            mac_text(other)
                        )),
                        Ok(Err(e)) => Some(format!("the house address {} is not taken: asking the LAN: {e}", home.address)),
                        Err(e) => Some(format!("the house address {} is not taken: asking the LAN: {e}", home.address)),
                    };
                    blocked = why;
                    if blocked.is_none() {
                        // (A second the probe took: the confirmation is old, and a new one gives the lifetime.)
                        let again = confirmed(&shared).await;
                        seconds = again.map_or(0, |started| left(started, Instant::now()));
                        if seconds == 0 {
                            state = State::Idle;
                        }
                    } else {
                        state = State::Waiting(Instant::now() + WAIT);
                    }
                    if blocked.is_some() || seconds == 0 {
                        say(&mut reason, blocked.clone().unwrap_or_else(|| not_leader(home, &denied)));
                        continue;
                    }
                }
                if let Err(e) = kith_mesh::address4_for(card.index, home.address, home.bits, seconds) {
                    eprintln!("kithd: holding the house address {} on {}: {e}", home.address, card.name);
                    // (Not held: nothing is said, and the wait is begun again.)
                    let_go(&mut held);
                    state = State::Idle;
                    continue;
                }
                held = Some(want.clone());
                blocked = None;
                if announce {
                    let frame = announcement(card.mac, home.address);
                    if let Err(e) = crate::dhcp::send_frame(card, &frame) {
                        eprintln!("kithd: announcing the house address {} on {}: {e}", home.address, card.name);
                    }
                }
            }
            Action::Delete => let_go(&mut held),
            Action::Nothing => {}
        }
        let why = match (&held, state) {
            (Some(_), _) => format!(
                "the house address {} is held on {}, for up to {} s at a time",
                home.address,
                card.name,
                LIFETIME.as_secs()
            ),
            (None, State::Waiting(_)) => blocked
                .clone()
                .unwrap_or_else(|| format!("the house address {} is not held: this node leads, and waits for the old holder's to be gone", home.address)),
            (None, _) => not_leader(home, &denied),
        };
        if state == State::Idle {
            blocked = None;
        }
        say(&mut reason, why);
    }
    let_go(&mut held);
}

fn not_leader(home: &Home, why: &str) -> String {
    format!("the house address {} is not held: this node is not the confirmed leader ({why})", home.address)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x09, 0x01];
    const OTHER: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x09, 0x02];
    const HOME: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 100);

    #[test]
    fn the_announcement_is_the_42_bytes_of_rfc_5227() {
        let frame = announcement(MAC, HOME);
        assert_eq!(frame.len(), 42);
        // Ethernet: to everyone, from the MAC, ARP.
        assert_eq!(frame[..6], [0xff; 6]);
        assert_eq!(frame[6..12], MAC);
        assert_eq!(frame[12..14], [0x08, 0x06]);
        // ARP: Ethernet, IPv4, 6 and 4 long, a request.
        assert_eq!(frame[14..22], [0, 1, 8, 0, 6, 4, 0, 1]);
        // From the MAC and the address, to nobody's MAC and the address.
        assert_eq!(frame[22..28], MAC);
        assert_eq!(frame[28..32], [10, 9, 0, 100]);
        assert_eq!(frame[32..38], [0; 6]);
        assert_eq!(frame[38..42], [10, 9, 0, 100]);
    }

    #[test]
    fn the_probe_is_a_request_for_the_address_from_0_0_0_0() {
        let frame = probe_frame(MAC, HOME);
        assert_eq!(frame.len(), 42);
        assert_eq!(frame[..6], [0xff; 6]);
        assert_eq!(frame[6..12], MAC);
        assert_eq!(frame[12..22], [0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 1]);
        // From the MAC and no address, to nobody's MAC and the address.
        assert_eq!(frame[22..28], MAC);
        assert_eq!(frame[28..32], [0; 4]);
        assert_eq!(frame[32..38], [0; 6]);
        assert_eq!(frame[38..42], [10, 9, 0, 100]);
    }

    #[test]
    fn another_card_that_has_or_wants_the_address_is_a_conflict() {
        // A reply from the address by another card: the one that has it.
        let mut reply = request(OTHER, HOME, Ipv4Addr::new(10, 9, 0, 7));
        reply[21] = 2;
        assert_eq!(conflict(&reply, MAC, HOME), Some(OTHER));
        // Its announcement, and its probe.
        assert_eq!(conflict(&announcement(OTHER, HOME), MAC, HOME), Some(OTHER));
        assert_eq!(conflict(&probe_frame(OTHER, HOME), MAC, HOME), Some(OTHER));
        // Our own frames heard back, a machine asking who has the address, one probing for
        // another, a reply for another address, and what is not ARP, or too short: nothing.
        assert_eq!(conflict(&probe_frame(MAC, HOME), MAC, HOME), None);
        assert_eq!(conflict(&announcement(MAC, HOME), MAC, HOME), None);
        assert_eq!(conflict(&request(OTHER, Ipv4Addr::new(10, 9, 0, 7), HOME), MAC, HOME), None);
        assert_eq!(conflict(&probe_frame(OTHER, Ipv4Addr::new(10, 9, 0, 101)), MAC, HOME), None);
        assert_eq!(conflict(&announcement(OTHER, Ipv4Addr::new(10, 9, 0, 101)), MAC, HOME), None);
        let mut ip = announcement(OTHER, HOME);
        ip[12..14].copy_from_slice(&[0x08, 0x00]);
        assert_eq!(conflict(&ip, MAC, HOME), None);
        assert_eq!(conflict(&announcement(OTHER, HOME)[..41], MAC, HOME), None);
        assert_eq!(conflict(&[], MAC, HOME), None);
    }

    fn at(seconds: f64, from: Instant) -> Instant {
        from + Duration::from_secs_f64(seconds)
    }

    #[test]
    fn a_node_that_does_not_hold_has_nothing_and_does_nothing() {
        let now = Instant::now();
        assert_eq!(step(State::Idle, None, now), (State::Idle, Action::Nothing));
    }

    #[test]
    fn a_new_leader_waits_the_lifetime_and_a_second_before_it_adds() {
        assert_eq!(WAIT, LIFETIME + Duration::from_secs(1));
        let t0 = Instant::now();
        let (state, action) = step(State::Idle, Some(t0), t0);
        assert_eq!((state, action), (State::Waiting(t0 + WAIT), Action::Nothing));
        // Confirmed every half second: nothing is added until the wait is over.
        let mut state = state;
        for half in 1..=10 {
            let now = at(f64::from(half) * 0.5, t0);
            let (next, action) = step(state, Some(now), now);
            if now < t0 + WAIT {
                assert_eq!((next, action), (state, Action::Nothing), "at {half} halves of a second");
            } else {
                assert_eq!(action, Action::Hold { announce: true, seconds: 3 }, "at {half} halves of a second");
                assert_eq!(next, State::Held { announced: 1, last: now });
                return;
            }
            state = next;
        }
        panic!("the address was never added");
    }

    #[test]
    fn a_leader_that_lost_its_confirmation_while_it_waited_starts_the_wait_again() {
        let t0 = Instant::now();
        let (waiting, _) = step(State::Idle, Some(t0), t0);
        assert_eq!(step(waiting, None, at(3.0, t0)), (State::Idle, Action::Nothing));
        // (Leading again at 4 s: the wait is from then.)
        let (again, _) = step(State::Idle, Some(at(4.0, t0)), at(4.0, t0));
        assert_eq!(again, State::Waiting(at(4.0, t0) + WAIT));
    }

    #[test]
    fn a_missed_confirmation_takes_the_address_off_at_once() {
        let t0 = Instant::now();
        let held = State::Held { announced: 3, last: t0 };
        assert_eq!(step(held, None, at(0.5, t0)), (State::Idle, Action::Delete));
        // And it is waited for again, however soon it leads again.
        let (waiting, _) = step(State::Idle, Some(at(1.0, t0)), at(1.0, t0));
        assert_eq!(waiting, State::Waiting(at(1.0, t0) + WAIT));
    }

    #[test]
    fn the_lifetime_is_three_seconds_from_the_start_of_the_confirmation() {
        let t0 = Instant::now();
        let held = State::Held { announced: 3, last: t0 };
        for (took, seconds) in [(0.0, 3), (0.1, 2), (0.5, 2), (1.0, 2), (1.9, 1), (2.5, 0)] {
            let (_, action) = step(held, Some(t0), at(took, t0));
            let expected = if seconds == 0 { Action::Delete } else { Action::Hold { announce: false, seconds } };
            assert_eq!(action, expected, "a confirmation that took {took} s");
        }
    }

    #[test]
    fn a_holder_paused_for_ten_seconds_renews_nothing_until_a_new_confirmation() {
        let t0 = Instant::now();
        let held = State::Held { announced: 3, last: t0 };
        // The confirmation began at t0, and the node was paused inside it: it ends at 10 s.
        let (state, action) = step(held, Some(t0), at(10.0, t0));
        assert_eq!((state, action), (State::Idle, Action::Delete));
        // A node that was not holding yet, paused the same way, starts no wait either.
        assert_eq!(step(State::Idle, Some(t0), at(10.0, t0)), (State::Idle, Action::Nothing));
        assert_eq!(step(State::Waiting(t0), Some(t0), at(10.0, t0)), (State::Idle, Action::Nothing));
        // A new confirmation, begun after the pause, starts the wait: the address is not added
        // before it is over, and then for the lifetime of the confirmation that allowed it.
        let (state, action) = step(state, Some(at(10.0, t0)), at(10.2, t0));
        assert_eq!((state, action), (State::Waiting(at(10.2, t0) + WAIT), Action::Nothing));
        let (state, action) = step(state, Some(at(15.5, t0)), at(15.6, t0));
        assert_eq!(action, Action::Hold { announce: true, seconds: 2 });
        assert!(matches!(state, State::Held { .. }));
    }

    #[test]
    fn it_announces_three_times_a_second_apart_and_renews_in_between() {
        let t0 = Instant::now();
        let mut state = State::Waiting(t0);
        let mut said = Vec::new();
        for half in 0..40 {
            let now = at(f64::from(half) * 0.5, t0);
            let (next, action) = step(state, Some(now), now);
            assert!(matches!(action, Action::Hold { .. }), "renewed at every confirmation");
            if matches!(action, Action::Hold { announce: true, .. }) {
                said.push(half);
            }
            state = next;
        }
        // At 0 s (as it was added), 1 s and 2 s.
        assert_eq!(said, [0, 2, 4]);
    }

    #[test]
    fn the_house_address_is_an_address_with_a_prefix_a_lan_can_have() {
        let home = Home::parse("10.9.0.100/24").unwrap();
        assert_eq!((home.address, home.bits), (HOME, 24));
        for wrong in [
            "",
            "10.9.0.100",
            "10.9.0.100/33",
            "10.9.0.100/0",
            "10.9.0.0/24",
            "10.9.0.255/24",
            "127.0.0.1/8",
            "0.0.0.0/24",
            "224.0.0.1/24",
            "house.example.org/24",
            "fd00::1/64",
            " 10.9.0.100/24",
        ] {
            assert_eq!(Home::parse(wrong), None, "{wrong:?}");
        }
    }

    #[test]
    fn the_card_is_one_with_an_address_in_the_network_of_the_house_address() {
        let home = Home::parse("10.9.0.100/24").unwrap();
        let cards = [
            ("lo".to_string(), Ipv4Addr::LOCALHOST, 8),
            ("eth1".to_string(), Ipv4Addr::new(10, 0, 2, 15), 24),
            ("eth0".to_string(), Ipv4Addr::new(10, 9, 0, 2), 24),
        ];
        assert_eq!(lan_card(home, &cards), Some("eth0"));
        assert_eq!(lan_card(home, &cards[..2]), None);
        assert_eq!(lan_card(home, &[]), None);
        // A card's own prefix decides (a /16 card holds a /24 house address, which is in it).
        let wide = [("eth0".to_string(), Ipv4Addr::new(10, 9, 3, 2), 16)];
        assert_eq!(lan_card(home, &wide), Some("eth0"));
    }
}
