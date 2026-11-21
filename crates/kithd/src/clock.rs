//! The clock of a node that is its machine's first process (kith OS has no other to keep it: a
//! machine with no battery clock, or a flat one, starts in 1970 and every certificate is "not
//! yet valid"). SNTP, RFC 4330: one 48-byte UDP exchange with a server, the offset worked out
//! from its four time stamps, and the clock stepped with `clock_settime` when it is off by more
//! than two seconds. Asked again about every hour, never under a minute apart.
//!
//! Whose time: the server the operator told (`kith.ntp=ADDRESS[:PORT]` on the kernel command
//! line, or the installer's `ntp:`); where none is told, what the network says (a server its
//! DHCP names by option 42, then its gateway: anyone on the wire can say these, so they are
//! not asked while the operator's is); and the cluster's leader (`GET /v1/clock` on the
//! cluster port, a node asking another over mutual TLS: a closed network with one clock in
//! it still has one time), whose time outweighs a server that is over two seconds from it.
//! The operator's server is followed alone, by any step. Before the clock was ever set (it reads
//! before `FLOOR_US`) the first answer is enough; after, a network's word alone moves it by ten
//! seconds in all (`ONE_SOURCE_US`), and more takes the leader to agree (the servers of one
//! network do not vouch for each other: see `ask`). While the clock is
//! unset, `/v1/clock` answers 503: a node that reads 1970 is no one's time. What it found is
//! in this Node's status as `clock`: `{server, offsetMs, delayMs, stepped, checked}`, or
//! `{error, checked}` where no one answered. A step is written to the hardware clock too
//! (`/dev/rtc0`, in UTC: a node that reboots starts from the time it was given, not from the
//! firmware's hours off); a write that failed is `rtcError` beside it, and the step counts.
//!
//! Every timer of kithd is monotonic (tokio's `Instant`: Raft's elections and heartbeats, the
//! controllers' ticks, request timeouts), so a step breaks none of them: the store's own time
//! stamps are wall time and only read, and `controller/prune` measures what it prunes on
//! CLOCK_BOOTTIME for this reason. A node under the `hardened` policy does not set its clock:
//! the step is refused in `set_under` (the policy's cuts only trim the bounding set, so the
//! refusal is explicit), and the status says so, with the offset it found.

use nix::time::{ClockId, clock_settime};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, watch};

use crate::Shared;
use serde_json::{Value, json};
use std::sync::Arc;

/// Off by more than this, the clock is stepped (SNTP's own bound is 128 ms: below two seconds
/// nothing a node does notices, and a clock that jumps every hour for a few ms is worse).
const STEP_OVER_US: i64 = 2_000_000;
/// Two sources say the same time when their offsets are this near (see `ask`).
const AGREE_US: i64 = 1_000_000;
/// What one source that is not the operator's may step a set clock by, all steps together, until
/// the leader agrees (a clock without a battery drifts by seconds in days; a spoofed
/// server must not walk it by sub-hour steps, repeated).
const ONE_SOURCE_US: i64 = 10_000_000;
/// 2026-01-01: a clock before it was never set (a machine that starts in 1970), one after it
/// was, and a network's word alone does not move it by years. Stale in time, never wrong.
const FLOOR_US: i64 = 1_767_225_600_000_000;
/// Servers of a DHCP lease asked (a lease names few; more is a flood).
const NETWORK_SERVERS: usize = 4;

/// Set while this node keeps its clock and has not found the time yet: `serve` says nothing then
/// (a leader whose clock reads 1970 must not be the time the others set theirs to).
static UNSET: AtomicBool = AtomicBool::new(false);
/// Set while a time server's answer (or a leader's that a server set) is the time this clock was
/// set to or kept at: `serve` marks its answer so (`VOUCH`), and a member does not follow a leader
/// without the mark that is hours from its own clock (see `ask`).
static VOUCHED: AtomicBool = AtomicBool::new(false);
/// The header `/v1/clock` says `server` in beside the time, while `VOUCHED`. (Left out, the time is
/// taken as no server's: a node of the version before the mark says none.)
const VOUCH: &str = "kith-clock";
/// Between asks: after an answer, and after none (never under a minute).
const EVERY: Duration = Duration::from_secs(3600);
const RETRY: Duration = Duration::from_secs(60);
/// How long a server has to answer.
const WAIT: Duration = Duration::from_secs(3);
/// Seconds from 1900 (NTP's time) to 1970 (Unix's).
const UNIX_AT: i64 = 2_208_988_800;

/// Told when this node's status has a new `clock` to say (see `main::say_serves`).
pub static CHANGED: Notify = Notify::const_new();
/// Told when the network gave a server or a gateway.
static LEARNED: Notify = Notify::const_new();
static SOURCES: Mutex<Sources> = Mutex::new(Sources {
    dhcp: Vec::new(),
    told: None,
    gateway: None,
});
static STATUS: Mutex<Value> = Mutex::new(Value::Null);

/// Where time may come from, other than the cluster.
#[derive(Debug, Default, PartialEq)]
struct Sources {
    dhcp: Vec<Ipv4Addr>,
    told: Option<SocketAddr>,
    gateway: Option<Ipv4Addr>,
}

/// The server a `kith.ntp` word (or `ntp:` answer) names: an address, or an address and port.
pub fn server(word: &str) -> Option<SocketAddr> {
    kith_api::kinds::ntp_server(word)
}

/// The time server the Clusters name (`spec.ntp`): the lowest key's that names one, so that every
/// node takes the same.
fn cluster_ntp(store: &kith_api::store::Store) -> Option<SocketAddr> {
    let said = store.list(Some("Cluster")).filter_map(|cluster| {
        let ntp = cluster.spec["ntp"].as_str().and_then(server)?;
        Some((cluster.key(), ntp))
    });
    said.min().map(|(_, ntp)| ntp)
}

/// Who to ask, and whether that one is the operator's (followed alone, by any step): the node's
/// own `kith.ntp`, else the Cluster's `spec.ntp` (the node's word is the more specific), else
/// what the network says.
fn whose(sources: &Sources, cluster: Option<SocketAddr>) -> (Vec<SocketAddr>, bool) {
    let told = sources.told.or(cluster);
    (order(&sources.dhcp, told, sources.gateway), told.is_some())
}

/// What a network told: the time servers of its lease (kept as the last lease said: a lease
/// is the whole of what the network says), and the way out.
pub fn learn(ntp: &[Ipv4Addr], gateway: Option<Ipv4Addr>) {
    let mut sources = SOURCES.lock().expect("nothing panics holding the sources");
    if !ntp.is_empty() {
        sources.dhcp = ntp.to_vec();
    }
    sources.gateway = gateway.or(sources.gateway);
    drop(sources);
    LEARNED.notify_one();
}

/// The server the command line or the config names.
pub fn told(server: Option<SocketAddr>) {
    SOURCES.lock().expect("nothing panics holding the sources").told = server;
}

/// Who to ask: the one the operator told, and no other (what the network says, DHCP's option 42
/// and the gateway it names, is whatever any machine on the wire sent: it is used only where
/// nothing is told, the DHCP's first, then the gateway, a home router often being one).
/// No server twice.
pub(crate) fn order(dhcp: &[Ipv4Addr], told: Option<SocketAddr>, gateway: Option<Ipv4Addr>) -> Vec<SocketAddr> {
    let dhcp = dhcp
        .iter()
        .take(NETWORK_SERVERS)
        .map(|ip| SocketAddr::new((*ip).into(), 123));
    let gateway = gateway.map(|ip| SocketAddr::new(ip.into(), 123));
    let mut all: Vec<SocketAddr> = Vec::new();
    let network = dhcp.chain(gateway).filter(|_| told.is_none());
    for server in told.into_iter().chain(network) {
        if !all.contains(&server) {
            all.push(server);
        }
    }
    all
}

/// What one exchange found: how far the server's clock is ahead of ours (negative: behind),
/// and how long the exchange took, both in microseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Sample {
    offset_us: i64,
    delay_us: i64,
}

/// The wall clock, in microseconds since 1970.
pub fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or_else(|e| -(e.duration().as_micros() as i64), |d| d.as_micros() as i64)
}

/// Microseconds since 1970 as an NTP time stamp: seconds since 1900 (32 bits: it wraps in
/// 2036, which `from_ntp` undoes) and a fraction of a second in 2^-32.
fn to_ntp(us: i64) -> [u8; 8] {
    let seconds = us.div_euclid(1_000_000) + UNIX_AT;
    // (Rounded up, so that reading it back as microseconds, which rounds down, gives the same.)
    let fraction = ((us.rem_euclid(1_000_000) as u64) << 32).div_ceil(1_000_000);
    let mut stamp = [0; 8];
    stamp[..4].copy_from_slice(&(seconds as u32).to_be_bytes());
    stamp[4..].copy_from_slice(&(fraction as u32).to_be_bytes());
    stamp
}

/// An NTP time stamp as microseconds since 1970, in the era of 2^32 seconds that puts it
/// nearest `near` (our own clock: a server's time is never decades from it, and a machine
/// that starts in 1970 asks in the same era as one that has the year right).
fn from_ntp(stamp: &[u8], near: i64) -> i64 {
    let word = |at: usize| u64::from(u32::from_be_bytes(stamp[at..at + 4].try_into().expect("four bytes")));
    let era = 1i64 << 32;
    let mut seconds = word(0) as i64 - UNIX_AT;
    seconds += ((near.div_euclid(1_000_000) - seconds) + era / 2).div_euclid(era) * era;
    seconds * 1_000_000 + ((word(4) * 1_000_000) >> 32) as i64
}

/// The request: version 4, client mode, and our time as its one time stamp (the server
/// sends it back: how an answer is known to be to this question).
fn request(sent: [u8; 8]) -> [u8; 48] {
    let mut packet = [0; 48];
    packet[0] = 0x23;
    packet[40..].copy_from_slice(&sent);
    packet
}

/// What a server's `answer` to the request that was `sent` at `t1` says, read at `t4` (our
/// clock both times): or why it is not one to take time from.
fn decode(answer: &[u8], sent: [u8; 8], t1: i64, t4: i64) -> Result<Sample, String> {
    if answer.len() < 48 {
        return Err(format!("{} bytes are not an answer", answer.len()));
    }
    let (leap, version, mode, stratum) = (answer[0] >> 6, (answer[0] >> 3) & 7, answer[0] & 7, answer[1]);
    if mode != 4 || !(3..=4).contains(&version) {
        return Err("not an answer to a client".into());
    }
    if answer[24..32] != sent {
        return Err("an answer to another question".into());
    }
    // (Stratum 0 is a "kiss of the death": the server's code for why it will not answer; heard
    // only from an answer to this question, so that a forged one cannot end the wait.)
    if stratum == 0 {
        return Err(format!("{KISS}{}", String::from_utf8_lossy(&answer[12..16])));
    }
    if stratum > 15 || leap == 3 {
        return Err("the server's own clock is not set".into());
    }
    if answer[32..48].iter().all(|b| *b == 0) {
        return Err("no time in the answer".into());
    }
    // (A clock that was never set reads 1970: the era of the answer is the one of the floor.)
    let near = t1.max(FLOOR_US);
    let (t2, t3) = (from_ntp(&answer[32..], near), from_ntp(&answer[40..], near));
    let delay_us = (t4 - t1) - (t3 - t2);
    if t3 < t2 || delay_us < 0 {
        return Err("the answer's times are out of order".into());
    }
    Ok(Sample {
        offset_us: ((t2 - t1) + (t3 - t4)) / 2,
        delay_us,
    })
}

/// What `decode` says of a kiss of death: the wait for another answer is over.
const KISS: &str = "the server refuses: ";

fn failed(what: &'static str) -> impl FnOnce(std::io::Error) -> String {
    move |e| format!("{what}: {e}")
}

/// One exchange with `server`: what it says, within `wait`. An answer that is not to this
/// request (another's, or forged: the time stamp we sent is not in it) is left unread, and
/// the one that is may still come.
async fn exchange(server: SocketAddr, wait: Duration) -> Result<Sample, String> {
    let bind = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind).await.map_err(failed("opening a socket"))?;
    // (Connected: only the server's own address is heard, and an unreachable one is known at once.)
    socket.connect(server).await.map_err(failed("connecting"))?;
    let t1 = now_us();
    let sent = to_ntp(t1);
    socket.send(&request(sent)).await.map_err(failed("sending"))?;
    let mut bad = String::from("no answer");
    let answered = async {
        let mut packet = [0; 128];
        loop {
            let read = socket.recv(&mut packet).await.map_err(failed("reading"))?;
            match decode(&packet[..read], sent, t1, now_us()) {
                Ok(sample) => return Ok(sample),
                Err(e) if e.starts_with(KISS) => return Err(e),
                Err(e) => bad = e,
            }
        }
    };
    match tokio::time::timeout(wait, answered).await {
        Ok(result) => result,
        Err(_) => Err(bad),
    }
}

/// What a member said the time is, and whether a time server set its clock (its answer's mark).
#[derive(Debug, Clone, Copy)]
struct Said {
    sample: Sample,
    vouched: bool,
}

/// What the cluster says: its leader (or, for a worker, the control node it follows), the offsets
/// of the other voters that answered (not this node, not the leader), and how many voters there
/// are (0: the others were not asked, as on a worker).
struct Heard {
    leader: Result<Said, String>,
    others: Vec<i64>,
    voters: usize,
}

/// What the member at `address` says the time is (`GET /v1/clock`), within `WAIT`.
async fn time_of(address: &str, client: &reqwest::Client) -> Result<Said, String> {
    let t1 = now_us();
    let asked = client.get(format!("https://{address}/v1/clock")).timeout(WAIT);
    let said = asked.send().await.map_err(|e| format!("asking {address}: {e}"))?;
    let said = said.error_for_status().map_err(|e| format!("{address}: {e}"))?;
    let vouched = vouched_by(said.headers());
    let said = said.json::<i64>().await.map_err(|e| format!("{address}: {e}"))?;
    let t4 = now_us();
    // (The time said was read half way: one network trip each way, as with the server's own.)
    let sample = Sample {
        offset_us: said - (t1 + (t4 - t1) / 2),
        delay_us: t4 - t1,
    };
    Ok(Said { sample, vouched })
}

/// What the cluster says the time is: its leader, and the other voters, asked at once.
async fn heard(shared: &Shared) -> Heard {
    if shared.cluster.is_none() {
        let leader = Err("this node is not in a cluster".into());
        return Heard { leader, others: Vec::new(), voters: 0 };
    }
    let upstream = shared
        .upstream
        .lock()
        .expect("nothing panics holding the upstream")
        .clone();
    // (A worker asks the control node it follows, and no one else: it holds no voter's address.)
    if let Some((address, client)) = upstream {
        let leader = time_of(&address, &client).await;
        return Heard { leader, others: Vec::new(), voters: 0 };
    }
    let metrics = shared.raft.metrics().borrow().clone();
    let membership = metrics.membership_config.membership().clone();
    let leader = metrics.current_leader.filter(|leader| *leader != metrics.id);
    let leader = async {
        let leader = leader.ok_or("no other node leads")?;
        let address = membership
            .get_node(&leader)
            .ok_or("the leader's address is not known")?;
        time_of(&address.addr, &crate::raft::to_voter(shared, leader)?.0).await
    };
    // (Only a voter asks the others: a learner is not one of the cluster's time.)
    let me_votes = membership.voter_ids().any(|id| id == metrics.id);
    let voters = if me_votes { membership.voter_ids().count() } else { 0 };
    let asked = |id: &kith_store::NodeId| me_votes && *id != metrics.id && Some(*id) != metrics.current_leader;
    let others = membership.voter_ids().filter(asked).map(|id| {
        let membership = &membership;
        async move {
            let address = &membership.get_node(&id)?.addr;
            let (client, _) = crate::raft::to_voter(shared, id).ok()?;
            time_of(address, &client).await.ok().map(|said| said.sample.offset_us)
        }
    });
    let (leader, others) = tokio::join!(leader, futures_util::future::join_all(others));
    Heard {
        leader,
        others: others.into_iter().flatten().collect(),
        voters,
    }
}

/// Whether an answer of `/v1/clock` is marked as a time server's (`kith-clock: server`).
fn vouched_by(headers: &axum::http::HeaderMap) -> bool {
    headers.get(VOUCH).is_some_and(|mark| mark == "server")
}

/// What this node answers another that asks the time (`/v1/clock`, for members): its clock, as a
/// bare JSON number, marked `kith-clock: server` while a time server set it (`VOUCHED`).
/// Nothing (503) while this node has not found the time itself: its clock may read 1970.
pub async fn serve() -> axum::response::Response {
    use axum::response::IntoResponse;
    if UNSET.load(Ordering::Relaxed) {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let now = axum::Json(now_us());
    if VOUCHED.load(Ordering::Relaxed) {
        return ([(VOUCH, "server")], now).into_response();
    }
    now.into_response()
}

/// Set the wall clock to `us` microseconds since 1970, where this node's policy lets it.
fn set(us: i64) -> std::io::Result<()> {
    set_under(&crate::policy::get(), us)
}

/// A hardened node does not move its clock (certificates, update windows and CronJobs follow
/// it): the status says the offset it found and this.
fn set_under(policy: &crate::policy::Policy, us: i64) -> std::io::Result<()> {
    if *policy == crate::policy::Policy::hardened() {
        return Err(std::io::Error::other("this node's policy is hardened"));
    }
    let to = u64::try_from(us).map_err(|_| std::io::Error::other("a time before 1970"))?;
    let to = nix::sys::time::TimeSpec::from_duration(Duration::from_micros(to));
    clock_settime(ClockId::CLOCK_REALTIME, to).map_err(std::io::Error::from)
}

/// Set the hardware clock to `us` microseconds since 1970, where this node's policy lets it
/// (after `set` did: a node that reboots starts from it, not from the firmware's hours).
fn set_rtc(us: i64) -> std::io::Result<()> {
    set_rtc_under(&crate::policy::get(), us)
}

/// A hardened node does not move its clock, the hardware one no more than the system's.
fn set_rtc_under(policy: &crate::policy::Policy, us: i64) -> std::io::Result<()> {
    if *policy == crate::policy::Policy::hardened() {
        return Err(std::io::Error::other("this node's policy is hardened"));
    }
    kith_dm_sys::set_rtc(whole_seconds(us))
}

/// `us` microseconds as the nearest whole second (the hardware clock counts no less).
fn whole_seconds(us: i64) -> i64 {
    (us + 500_000).div_euclid(1_000_000)
}

/// The status of a check that found `sample` at `server` and `stepped` (or why it did not), and
/// `rtc_error`, why the hardware clock was not set to the time stepped to (the step counts).
fn render(
    server: &str,
    sample: Sample,
    stepped: Option<&Result<(), String>>,
    rtc_error: Option<&str>,
    at: i64,
) -> Value {
    let mut said = json!({
        "server": server,
        "offsetMs": (sample.offset_us as f64 / 1000.0).round() as i64,
        "delayMs": (sample.delay_us as f64 / 1000.0).round() as i64,
        "stepped": matches!(stepped, Some(Ok(()))),
        "checked": at / 1_000_000,
    });
    if let Some(Err(why)) = stepped {
        said["error"] = format!("the clock is not set: {why}").into();
    }
    if let Some(why) = rtc_error {
        said["rtcError"] = why.into();
    }
    said
}

/// The status of a check that found no time.
fn nothing(why: &str, at: i64) -> Value {
    json!({ "error": why, "checked": at / 1_000_000 })
}

/// One check: ask each server, then the leader; step the clock with `set_to` when the time found
/// is over two seconds from it; and the status that says so. Whose time, when they differ:
/// - the leader's (a member's, over the cluster's mutual TLS) when a server is over two seconds
///   from it, and when no server answered;
/// - else the first server's. Time from a network is unsigned: once the clock was set (`synced`:
///   by a check, or before kithd started), one source alone may step it only within a budget
///   (`ONE_SOURCE_US`, all its steps together, `spent` of it used since a step the leader
///   agreed with, or the leader or the operator's server made); past that the leader within a
///   second of the same time is needed (servers a network named do not count: one lease, or one
///   rogue DHCP server, names them all), and otherwise it is said in the status and not followed. The server the operator `told` is followed alone (that is
///   the operator's word). Before the clock was ever set, the first server answers.
///
/// The leader's word is a member's, not a server's: a leader whose clock no time server set (its
/// answer has no mark: it came up from a hardware clock hours off, on a network with no server)
/// is one source like a network's, within the same budget, once this node's clock was set and
/// either a server set it (`vouched`, this node's own mark) or most voters, this node with the
/// others that answered within two seconds of it, say this node's time. Otherwise (a cluster of
/// two with no server, a node in 1970) the leader is followed as before; a leader a server set
/// is followed by any step. `vouched` is kept: true once a server's answer (or a leader's with the
/// mark) is the time stepped to or kept, false when no one answered or the step failed.
#[allow(clippy::too_many_arguments)]
async fn ask(
    servers: &[SocketAddr],
    wait: Duration,
    heard: impl Future<Output = Heard>,
    set_to: impl Fn(i64) -> std::io::Result<()>,
    set_rtc: impl Fn(i64) -> std::io::Result<()>,
    synced: bool,
    told: bool,
    spent: &mut i64,
    vouched: &mut bool,
) -> Value {
    let (mut found, mut why) = (Vec::new(), Vec::new());
    for server in servers {
        match exchange(*server, wait).await {
            Ok(sample) => found.push((server.to_string(), sample)),
            Err(e) => why.push(format!("{server}: {e}")),
        }
        if !synced && !found.is_empty() {
            break;
        }
    }
    let heard = heard.await;
    let agree = 1 + heard.others.iter().filter(|o| o.abs() <= STEP_OVER_US).count();
    let majority = heard.voters > 0 && agree * 2 > heard.voters;
    let leader = heard.leader;
    // Why the leader is one source here, not the cluster's time (nothing: it is the time).
    let demoted = match &leader {
        Ok(said) if !said.vouched && synced && *vouched => Some("a time server set this node's".to_string()),
        Ok(said) if !said.vouched && synced && majority => {
            Some(format!("{agree} of {} voters agree with this node's", heard.voters))
        }
        _ => None,
    };
    let mut chosen = found.first().cloned();
    let mut from_leader = None;
    match &leader {
        // (A demoted leader is taken only where no server answered: it outweighs none.)
        Ok(said)
            if chosen.as_ref().is_none_or(|(_, s)| {
                demoted.is_none() && (s.offset_us - said.sample.offset_us).abs() > STEP_OVER_US
            }) =>
        {
            chosen = Some(("the cluster's leader".to_string(), said.sample));
            from_leader = Some(*said);
        }
        Err(e) if chosen.is_none() => why.push(format!("leader: {e}")),
        _ => {}
    }
    let Some((server, sample)) = chosen else {
        *vouched = false;
        return nothing(&format!("no time server answered ({})", why.join("; ")), now_us());
    };
    let trusted = from_leader.is_some() && demoted.is_none();
    // (Only the leader corroborates a server: the servers of a network all come from one lease,
    // and a rogue DHCP server names as many as it likes. The operator's server is its own word,
    // and says nothing of a leader's time when it did not answer.)
    let agrees = from_leader.is_none()
        && leader
            .iter()
            .any(|said| (said.sample.offset_us - sample.offset_us).abs() <= AGREE_US);
    let operators = from_leader.is_none() && told;
    // A server's time, or a vouched leader's: what `serve` marks.
    let a_servers = from_leader.is_none_or(|said| said.vouched);
    let off = sample.offset_us.abs();
    let corroborated = !synced || trusted || operators || agrees;
    let mut rtc_error = None;
    let step = if off <= STEP_OVER_US {
        *vouched |= a_servers;
        None
    } else if !corroborated && *spent + off > ONE_SOURCE_US {
        let seconds = sample.offset_us as f64 / 1e6;
        Some(Err(match &demoted {
            Some(whose) => format!(
                "{server} says the clock is {seconds:+.1} s off, and no time server set its clock: {whose}"
            ),
            None => format!("{server} says the clock is {seconds:+.1} s off and no second source agrees"),
        }))
    } else {
        let to = now_us() + sample.offset_us;
        let done = set_to(to).map_err(|e| e.to_string());
        if done.is_ok() {
            *vouched |= a_servers;
            *spent = if corroborated { 0 } else { *spent + off };
            // (The hardware clock follows a step that was vouched for, so the next boot starts from
            // it: the operator's server, the leader over mTLS, or a server the leader agrees with.
            // The first answer of an unsynced clock may be a plain-UDP network's alone, and a
            // reboot would take what was written for a clock that was set: that one is kept off
            // the hardware clock. A failed write is said beside the step, which counts.)
            if trusted || operators || agrees {
                rtc_error = set_rtc(to).err().map(|e| e.to_string());
            }
        } else {
            *vouched = false;
        }
        Some(done)
    };
    render(&server, sample, step.as_ref(), rtc_error.as_deref(), now_us())
}

/// What `ask` found, for this Node's status: null before the first check (and always on a node
/// that is not a machine's first process, which keeps no clock).
pub fn status() -> Value {
    STATUS.lock().expect("nothing panics holding the status").clone()
}

/// Whether the clock was set before kithd started (it reads after the floor); and `serve` says
/// nothing until it is.
fn begin_at(now: i64) -> bool {
    let synced = now > FLOOR_US;
    UNSET.store(!synced, Ordering::Relaxed);
    synced
}

/// What the log says of a check's `now` status (nothing: an empty line). `first`: no check was said yet,
/// and it says where it stands even when there was nothing to do. A step says when the hardware clock was
/// not set beside it: the next check's status replaces `rtcError`, the log keeps it.
fn log_line(now: &Value, first: bool) -> String {
    match (now["error"].as_str(), now["server"].as_str()) {
        (Some(why), _) => format!("kithd: clock: {why}"),
        (None, Some(server)) => {
            let seconds = now["offsetMs"].as_i64().unwrap_or_default() as f64 / 1000.0;
            if now["stepped"] == true {
                let line = format!("kithd: clock: stepped {seconds:+.3} s to the time of {server}");
                match now["rtcError"].as_str() {
                    Some(why) => format!("{line} (the hardware clock was not set: {why})"),
                    None => line,
                }
            } else if first {
                format!("kithd: clock: {seconds:+.3} s from the time of {server}: kept")
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

/// The wait between checks: `again`, or until `changed` (what the check asked changed), but never
/// under a minute from the check.
async fn rest(again: Duration, changed: impl Future<Output = ()>) {
    let started = tokio::time::Instant::now();
    tokio::select! {
        () = tokio::time::sleep(again) => {}
        () = changed => tokio::time::sleep_until(started + RETRY.min(again)).await,
    }
}

/// Keep the clock as long as kithd runs: once the network has said something (or a while
/// after, for one that says nothing: the cluster's leader may), then about every hour.
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let kept = async {
        // (Decided before the wait: a 1970 clock is not served for ten seconds.)
        let mut synced = begin_at(now_us());
        let _ = tokio::time::timeout(Duration::from_secs(10), LEARNED.notified()).await;
        let mut said = String::new();
        let mut spent = 0;
        let mut vouched = false;
        let mut generation = shared.generation.subscribe();
        loop {
            let ntp = cluster_ntp(&shared.store.lock().expect("nothing panics holding the store").store);
            let (servers, told) = whose(&SOURCES.lock().expect("nothing panics holding the sources"), ntp);
            let now = ask(
                &servers,
                WAIT,
                heard(&shared),
                set,
                set_rtc,
                synced,
                told,
                &mut spent,
                &mut vouched,
            )
            .await;
            VOUCHED.store(vouched, Ordering::Relaxed);
            if now["error"].is_null() && now["server"].is_string() {
                synced = true;
                UNSET.store(false, Ordering::Relaxed);
            }
            // (A server that answered and was not followed is asked again in an hour, not a minute.)
            let again = if now["server"].is_string() { EVERY } else { RETRY };
            // (Said in the log when it changes, so an hour of the same does not fill it.)
            let line = log_line(&now, said.is_empty());
            if !line.is_empty() && line != said {
                eprintln!("{line}");
                said = line;
            }
            *STATUS.lock().expect("nothing panics holding the status") = now;
            CHANGED.notify_one();
            // (A Cluster's `spec.ntp` that changes is asked within a minute, not at the next hour.)
            let changed = async {
                loop {
                    if generation.changed().await.is_err() {
                        std::future::pending::<()>().await;
                    }
                    let store = shared.store.lock().expect("nothing panics holding the store");
                    if cluster_ntp(&store.store) != ntp {
                        return;
                    }
                }
            };
            rest(again, changed).await;
        }
    };
    tokio::select! {
        () = kept => {}
        _ = stopping.changed() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An answer to `request`, as a server whose clock is `skew` microseconds ahead of ours
    /// writes it (stratum 2, version 4, server mode), `tweak`ed.
    fn answer(request: &[u8], skew: i64, tweak: &dyn Fn(&mut [u8; 48])) -> [u8; 48] {
        let mut packet = [0; 48];
        packet[0] = 0x24;
        packet[1] = 2;
        packet[24..32].copy_from_slice(&request[40..48]);
        let time = to_ntp(now_us() + skew);
        packet[32..40].copy_from_slice(&time);
        packet[40..48].copy_from_slice(&time);
        tweak(&mut packet);
        packet
    }

    /// A time server on 127.0.0.1 that answers every request once, as `answer` says.
    async fn fake(skew: i64, tweak: fn(&mut [u8; 48])) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let at = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut packet = [0; 128];
            while let Ok((read, from)) = socket.recv_from(&mut packet).await {
                if read == 48 && packet[0] & 7 == 3 {
                    let _ = socket.send_to(&answer(&packet, skew, &tweak), from).await;
                }
            }
        });
        at
    }

    /// The server's refusal: stratum 0, and the four letters that say why.
    fn kiss(packet: &mut [u8; 48], code: &[u8; 4]) {
        packet[1] = 0;
        packet[12..16].copy_from_slice(code);
    }

    /// An address nothing listens on: its port was a socket's, and is not now.
    async fn nobody() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.local_addr().unwrap()
    }

    const SOON: Duration = Duration::from_millis(400);

    /// `super::ask` with a budget of one source's steps that nothing has used, and a hardware
    /// clock that takes every write.
    async fn ask(
        servers: &[SocketAddr],
        wait: Duration,
        leader: impl Future<Output = Result<Sample, String>>,
        set_to: impl Fn(i64) -> std::io::Result<()>,
        synced: bool,
        told: bool,
    ) -> Value {
        let mark = &mut false;
        super::ask(servers, wait, alone(leader), set_to, |_| Ok(()), synced, told, &mut 0, mark).await
    }

    /// What the cluster says when its leader says `leader` with no mark (as one of before the mark
    /// did), and this node asks no other member (a worker, or a node no member answers).
    async fn alone(leader: impl Future<Output = Result<Sample, String>>) -> Heard {
        Heard {
            leader: leader.await.map(|sample| Said { sample, vouched: false }),
            others: Vec::new(),
            voters: 0,
        }
    }

    #[test]
    fn clock_time_stamps_go_both_ways_and_across_eras() {
        // 2026-11-19 12:00:00.5 UTC.
        let now = 1_795_089_600_500_000;
        let stamp = to_ntp(now);
        assert_eq!(
            u32::from_be_bytes(stamp[..4].try_into().unwrap()),
            (1_795_089_600u64 + 2_208_988_800) as u32
        );
        assert_eq!(u32::from_be_bytes(stamp[4..].try_into().unwrap()), 1 << 31);
        assert_eq!(from_ntp(&stamp, now), now);
        // A machine that starts in 1970 reads a server's time right (and so does one in 2040).
        assert_eq!(from_ntp(&stamp, 0), now);
        let later = 2_240_000_000_000_000;
        assert_eq!(from_ntp(&to_ntp(later), later), later);
        assert_eq!(from_ntp(&to_ntp(later), now), later);
        // Before 1970 as well, and to the microsecond.
        assert_eq!(from_ntp(&to_ntp(-1_234_567), 0), -1_234_567);
        assert_eq!(from_ntp(&to_ntp(now + 1), now), now + 1);
    }

    #[test]
    fn clock_request_is_a_client_packet_of_48_bytes_with_our_time() {
        let sent = to_ntp(1_795_089_600_000_000);
        let packet = request(sent);
        assert_eq!(packet.len(), 48);
        // Leap 0, version 4, mode 3; the transmit time stamp is the one the server returns.
        assert_eq!(packet[0], 0b00_100_011);
        assert_eq!(packet[40..], sent);
        assert!(packet[1..40].iter().all(|b| *b == 0));
    }

    #[test]
    fn clock_offset_and_delay_are_the_formulas_of_rfc_4330() {
        // We sent at 1000.00 and heard at 1000.20; the server (10 s ahead) got it at 1010.05 and
        // answered at 1010.07: so it was 9.96 s ahead, and the trip took 0.18 s.
        let (t1, t4) = (1_000_000_000, 1_000_200_000);
        let sent = to_ntp(t1);
        let mut packet = [0; 48];
        packet[0] = 0x24;
        packet[1] = 1;
        packet[24..32].copy_from_slice(&sent);
        packet[32..40].copy_from_slice(&to_ntp(1_010_050_000));
        packet[40..48].copy_from_slice(&to_ntp(1_010_070_000));
        let sample = decode(&packet, sent, t1, t4).unwrap();
        // (A time stamp's fraction is in 2^-32 of a second: a microsecond of rounding at most.)
        assert!((sample.offset_us - 9_960_000).abs() <= 2, "{sample:?}");
        assert!((sample.delay_us - 180_000).abs() <= 2, "{sample:?}");
        // The same, a clock behind: a negative offset.
        packet[32..40].copy_from_slice(&to_ntp(990_050_000));
        packet[40..48].copy_from_slice(&to_ntp(990_070_000));
        assert!((decode(&packet, sent, t1, t4).unwrap().offset_us + 10_040_000).abs() <= 2);
    }

    #[test]
    fn clock_answers_that_are_not_ours_or_not_good_are_refused() {
        let (t1, t4) = (1_795_089_600_000_000, 1_795_089_600_100_000);
        let sent = to_ntp(t1);
        let good = answer(&request(sent), 0, &|_| {});
        assert!(decode(&good, sent, t1, t4 + 1_000).is_ok());
        let refused = |tweak: &dyn Fn(&mut [u8; 48])| {
            let mut packet = good;
            tweak(&mut packet);
            decode(&packet, sent, t1, t4).unwrap_err()
        };
        // Another's, or forged: the time stamp we sent is not in it.
        assert!(refused(&|p| p[24] ^= 1).contains("another question"));
        // Not a server's: a client's (our own request, bounced), or version 2.
        assert!(refused(&|p| p[0] = 0x23).contains("not an answer"));
        assert!(refused(&|p| p[0] = 0x14).contains("not an answer"));
        // A kiss of death, with its code; a server that has no time itself.
        assert!(refused(&|p| kiss(p, b"RATE")).contains("RATE"));
        assert!(refused(&|p| p[1] = 16).contains("not set"));
        assert!(refused(&|p| p[0] |= 0xC0).contains("not set"));
        // No time, or the server's answer before its receipt.
        assert!(refused(&|p| p[32..48].fill(0)).contains("no time"));
        assert!(refused(&|p| p[32..40].copy_from_slice(&to_ntp(t1 + 5_000_000))).contains("out of order"));
        // Cut short: nothing, at any length, and no panic.
        for cut in 0..48 {
            assert!(decode(&good[..cut], sent, t1, t4).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn clock_server_words_are_an_address_with_or_without_a_port() {
        assert_eq!(server("10.0.0.7"), Some("10.0.0.7:123".parse().unwrap()));
        assert_eq!(server("10.0.2.2:5123"), Some("10.0.2.2:5123".parse().unwrap()));
        assert_eq!(server("fd00::7"), Some("[fd00::7]:123".parse().unwrap()));
        assert_eq!(server("[fd00::7]:99"), Some("[fd00::7]:99".parse().unwrap()));
        assert_eq!(server("pool.ntp.org"), None);
        assert_eq!(server(""), None);
        assert_eq!(server("10.0.0.7:"), None);
    }

    #[test]
    fn clock_servers_are_the_one_told_else_the_networks_each_once() {
        let at = |ip: &str| SocketAddr::new(ip.parse().unwrap(), 123);
        let told: SocketAddr = "10.0.0.9:5123".parse().unwrap();
        let dhcp = [[10, 0, 0, 7].into(), [10, 0, 0, 8].into()];
        // What the operator told is the only one asked: the network's words are not its to say.
        assert_eq!(order(&dhcp, Some(told), Some([10, 0, 0, 1].into())), [told]);
        assert_eq!(order(&[], Some(told), None), [told]);
        // Nothing told: DHCP's, then the gateway.
        assert_eq!(
            order(&dhcp, None, Some([10, 0, 0, 1].into())),
            [at("10.0.0.7"), at("10.0.0.8"), at("10.0.0.1")]
        );
        // The gateway named as a server too: asked once, where DHCP has it.
        assert_eq!(
            order(&[[10, 0, 0, 1].into()], None, Some([10, 0, 0, 1].into())),
            [at("10.0.0.1")]
        );
        assert!(order(&[], None, None).is_empty());
    }

    #[tokio::test]
    async fn clock_exchange_with_a_server_on_loopback_finds_its_skew() {
        let behind = exchange(fake(3_600_000_000, |_| {}).await, SOON).await.unwrap();
        // (An hour ahead: found within the time the exchange took, and that is little.)
        assert!((behind.offset_us - 3_600_000_000).abs() < 100_000, "{behind:?}");
        assert!(behind.delay_us < 100_000, "{behind:?}");
        let ahead = exchange(fake(-90_000_000, |_| {}).await, SOON).await.unwrap();
        assert!((ahead.offset_us + 90_000_000).abs() < 100_000, "{ahead:?}");
    }

    #[tokio::test]
    async fn clock_exchange_refuses_a_forged_answer_and_an_empty_port() {
        // The server sends back a time stamp that is not ours: left unread, and nothing else comes.
        let forged = exchange(fake(5_000_000, |p| p[24] ^= 1).await, SOON).await;
        assert!(forged.unwrap_err().contains("another question"));
        let refusing = exchange(fake(0, |p| kiss(p, b"DENY")).await, SOON).await;
        assert!(refusing.unwrap_err().contains("DENY"));
        // Where nothing listens the refusal comes back at once (no wait for the time out).
        let started = std::time::Instant::now();
        assert!(exchange(nobody().await, Duration::from_secs(30)).await.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn clock_steps_over_two_seconds_and_leaves_less_alone() {
        let set_to = std::cell::Cell::new(None);
        let record = |us: i64| {
            set_to.set(Some(us));
            Ok(())
        };
        let never = async { Err::<Sample, _>("not asked".to_string()) };
        // Eight hours behind: the clock is set to the server's time.
        let before = now_us();
        let said = ask(&[fake(28_800_000_000, |_| {}).await], SOON, never, record, false, false).await;
        let to = set_to.get().expect("the clock was set");
        assert!((to - before - 28_800_000_000).abs() < 200_000, "{to} from {before}");
        assert_eq!(
            (said["stepped"].clone(), said["error"].clone()),
            (true.into(), Value::Null)
        );
        assert!((said["offsetMs"].as_i64().unwrap() - 28_800_000).abs() < 200);
        // Ahead by five seconds: stepped back. Three-quarters of a second: left alone.
        set_to.set(None);
        let never = async { Err::<Sample, _>("not asked".to_string()) };
        let said = ask(&[fake(-5_000_000, |_| {}).await], SOON, never, record, false, false).await;
        assert!(set_to.get().is_some_and(|to| to < now_us() - 4_500_000));
        assert_eq!(said["stepped"], true);
        set_to.set(None);
        let never = async { Err::<Sample, _>("not asked".to_string()) };
        let said = ask(&[fake(750_000, |_| {}).await], SOON, never, record, true, false).await;
        assert_eq!(set_to.get(), None);
        assert_eq!(said["stepped"], false);
        assert!((said["offsetMs"].as_i64().unwrap() - 750).abs() < 100);
    }

    #[tokio::test]
    async fn clock_a_step_that_is_refused_is_said_with_the_offset_found() {
        let never = async { Err::<Sample, _>("not asked".to_string()) };
        let refuse = |_| Err(std::io::Error::from_raw_os_error(1));
        let said = ask(&[fake(7_200_000_000, |_| {}).await], SOON, never, refuse, false, false).await;
        assert_eq!(said["stepped"], false);
        assert!(said["error"].as_str().unwrap().contains("not set"), "{said}");
        assert!((said["offsetMs"].as_i64().unwrap() - 7_200_000).abs() < 200);
    }

    #[tokio::test]
    async fn clock_falls_to_the_next_server_then_to_the_leader_then_says_nothing() {
        let steps = std::cell::Cell::new(0);
        let record = |_| {
            steps.set(steps.get() + 1);
            Ok(())
        };
        // The first server is not there: the second's time is taken.
        let leader = async { Err::<Sample, _>("not asked".to_string()) };
        let said = ask(
            &[nobody().await, fake(4_000_000, |_| {}).await],
            SOON,
            leader,
            record,
            false,
            false,
        )
        .await;
        assert_eq!(said["stepped"], true);
        assert!(said["server"].as_str().unwrap().starts_with("127.0.0.1:"));
        // No server answers: the leader's time is, and said to be.
        let leader = async {
            Ok(Sample {
                offset_us: -9_000_000,
                delay_us: 2_000,
            })
        };
        let said = ask(&[nobody().await], SOON, leader, record, true, false).await;
        assert_eq!(
            (said["server"].as_str(), said["offsetMs"].as_i64()),
            (Some("the cluster's leader"), Some(-9000))
        );
        assert_eq!(steps.get(), 2);
        // None of them: the status is the reason, and the clock is not touched.
        let leader = async { Err::<Sample, _>("no other node leads".to_string()) };
        let said = ask(&[nobody().await], SOON, leader, record, false, false).await;
        let error = said["error"].as_str().unwrap();
        assert!(
            error.contains("no time server answered") && error.contains("no other node leads"),
            "{said}"
        );
        assert_eq!(steps.get(), 2);
        let none = ask(
            &[],
            SOON,
            async { Err::<Sample, _>("x".to_string()) },
            record,
            false,
            false,
        )
        .await;
        assert!(none["error"].as_str().unwrap().contains("(leader: x)"), "{none}");
    }

    /// `ask` once the clock has been set, with servers at these skews and a leader at `leader`
    /// (microseconds ahead; none: not in a cluster): what it stepped to (the offset), and the status.
    async fn after_first_sync(skews: &[i64], leader: Option<i64>) -> (Option<i64>, Value) {
        after_sync(skews, leader, false, &mut 0).await
    }

    /// The same, with the server the operator `told` (or not).
    async fn after_sync(skews: &[i64], leader: Option<i64>, told: bool, spent: &mut i64) -> (Option<i64>, Value) {
        let set_to = std::cell::Cell::new(None);
        let record = |us: i64| {
            set_to.set(Some(us));
            Ok(())
        };
        let mut servers = Vec::new();
        for skew in skews {
            servers.push(fake(*skew, |_| {}).await);
        }
        let leader = async move {
            leader
                .map(|offset_us| Sample {
                    offset_us,
                    delay_us: 1_000,
                })
                .ok_or("not in a cluster".to_string())
        };
        let before = now_us();
        let said = super::ask(&servers, SOON, alone(leader), record, |_| Ok(()), true, told, spent, &mut false).await;
        (set_to.get().map(|to| to - before), said)
    }

    #[tokio::test]
    async fn clock_after_the_first_sync_one_source_alone_does_not_step_it_hours() {
        // A rogue server alone: refused, and the status says why, with the offset it found.
        let (to, said) = after_first_sync(&[28_800_000_000], None).await;
        assert_eq!(to, None);
        assert_eq!(said["stepped"], false);
        assert!(
            said["error"].as_str().unwrap().contains("no second source agrees"),
            "{said}"
        );
        assert!((said["offsetMs"].as_i64().unwrap() - 28_800_000).abs() < 200);
        // Two that disagree (a second at another time): refused.
        let (to, _) = after_first_sync(&[28_800_000_000, -3_600_000_000], None).await;
        assert_eq!(to, None);
        // Two a network named that agree (one lease, one rogue DHCP server can name both): refused.
        let (to, said) = after_first_sync(&[28_800_000_000, 28_800_400_000], None).await;
        assert_eq!(to, None);
        assert_eq!(said["stepped"], false);
        // A server and a leader that agree: stepped. Under two seconds: left alone either way.
        let (to, _) = after_first_sync(&[-5_000_000], Some(-5_200_000)).await;
        assert!(to.is_some());
        let (to, said) = after_first_sync(&[900_000], None).await;
        assert_eq!((to, said["stepped"].clone()), (None, false.into()));
        // The first sync, with one source and no other: still stepped (it has no other way).
        let (to, _) = after_first_sync(&[], Some(7_200_000_000)).await;
        assert!(to.is_some(), "the leader's own time is followed");
    }

    #[tokio::test]
    async fn clock_the_leaders_time_wins_over_a_server_that_disagrees() {
        // The server says eight hours, the leader says the clock is right: nothing is stepped.
        let (to, said) = after_first_sync(&[28_800_000_000], Some(100_000)).await;
        assert_eq!(to, None);
        assert_eq!(said["server"], "the cluster's leader");
        // The server says it is right, the leader says three hours: the leader's time is followed.
        let (to, said) = after_first_sync(&[0], Some(10_800_000_000)).await;
        assert!(to.is_some_and(|to| (to - 10_800_000_000).abs() < 200_000), "{to:?}");
        assert_eq!(said["server"], "the cluster's leader");
    }

    #[tokio::test]
    async fn clock_the_server_told_is_followed_alone_the_others_to_an_hour() {
        const HOUR: i64 = 3_600_000_000;
        // The operator's server is the operator's word: five seconds, and eight hours, are stepped.
        let (to, _) = after_sync(&[5_000_000], None, true, &mut 0).await;
        assert!(to.is_some());
        let (to, said) = after_sync(&[8 * HOUR], None, true, &mut 0).await;
        assert!(to.is_some_and(|to| (to - 8 * HOUR).abs() < 200_000), "{to:?} {said}");
        // The network's: five seconds alone is followed; two hours alone is not.
        let (to, _) = after_sync(&[5_000_000], None, false, &mut 0).await;
        assert!(to.is_some());
        let (to, said) = after_sync(&[2 * HOUR], None, false, &mut 0).await;
        assert_eq!(to, None);
        assert!(
            said["error"].as_str().unwrap().contains("no second source agrees"),
            "{said}"
        );
    }

    #[tokio::test]
    async fn clock_one_source_cannot_walk_the_clock_by_steps_that_are_each_small() {
        const HALF_HOUR: i64 = 1_800_000_000;
        // Thirty minutes, again and again, from a source nothing agrees with: the budget is
        // over at the first (it is more than all of it), and stays over.
        let mut spent = 0;
        for _ in 0..3 {
            let (to, said) = after_sync(&[HALF_HOUR], None, false, &mut spent).await;
            assert_eq!(to, None);
            assert!(
                said["error"].as_str().unwrap().contains("no second source agrees"),
                "{said}"
            );
        }
        // Steps inside the budget are followed until it is spent: 4 s, 4 s, then 4 s is refused.
        let mut spent = 0;
        let steps = [4_000_000; 3];
        let mut stepped = Vec::new();
        for step in steps {
            stepped.push(after_sync(&[step], None, false, &mut spent).await.0.is_some());
        }
        assert_eq!(stepped, [true, true, false]);
        // Two servers of a lease that agree give nothing back; the leader that agrees does.
        let (to, _) = after_sync(&[4_000_000, 4_200_000], None, false, &mut spent).await;
        assert_eq!(to, None);
        let (to, _) = after_sync(&[4_000_000], Some(4_200_000), false, &mut spent).await;
        assert!(to.is_some());
        assert_eq!(spent, 0);
        let (to, _) = after_sync(&[4_000_000], None, false, &mut spent).await;
        assert!(to.is_some());
    }

    #[test]
    fn clock_a_hardened_node_does_not_set_its_clock() {
        let hardened = crate::policy::Policy::hardened();
        let said = set_under(&hardened, 1_795_089_600_000_000).unwrap_err().to_string();
        assert!(said.contains("this node's policy is hardened"), "{said}");
    }

    /// `ask` with a server `skew` microseconds ahead and a setter pair that records what each was
    /// given (`None`: not called): the system clock's, the hardware clock's, and the status.
    /// `rtc_fails` makes the hardware clock's write fail; `system_fails` the system clock's.
    /// `told`: the server is the operator's; `leader`: the cluster's leader says its offset.
    async fn written(
        skew: i64,
        system_fails: bool,
        rtc_fails: bool,
        told: bool,
        leader: Option<i64>,
    ) -> (Option<i64>, Option<i64>, Value) {
        let (system, rtc) = (std::cell::Cell::new(None), std::cell::Cell::new(None));
        let set_to = |us: i64| {
            system.set(Some(us));
            if system_fails {
                return Err(std::io::Error::from_raw_os_error(1));
            }
            Ok(())
        };
        let set_rtc = |us: i64| {
            rtc.set(Some(us));
            if rtc_fails {
                return Err(std::io::Error::other("no such device"));
            }
            Ok(())
        };
        let leader = async move {
            leader
                .map(|offset_us| Sample {
                    offset_us,
                    delay_us: 1_000,
                })
                .ok_or("not in a cluster".to_string())
        };
        let server = fake(skew, |_| {}).await;
        let said = super::ask(&[server], SOON, alone(leader), set_to, set_rtc, false, told, &mut 0, &mut false).await;
        (system.get(), rtc.get(), said)
    }

    #[tokio::test]
    async fn clock_a_network_named_first_answer_steps_but_writes_no_hardware_clock() {
        // Before the first sync one unvouched answer (DHCP's, the gateway's: plain UDP) is enough
        // for the system clock; a reboot would take it for a synced clock, so it is not kept.
        let (system, rtc, said) = written(28_800_000_000, false, false, false, None).await;
        assert!(system.is_some() && said["stepped"] == true, "{said}");
        assert_eq!(rtc, None, "{said}");
        assert!(said.get("rtcError").is_none(), "{said}");
    }

    #[tokio::test]
    async fn clock_a_step_the_leader_told_writes_the_hardware_clock() {
        // The leader alone (no server answers a leader this far off the server's time) ...
        let (system, rtc, said) = written(4_000_000, false, false, false, Some(28_800_000_000)).await;
        assert!(system.is_some(), "{said}");
        assert_eq!(rtc, system, "{said}");
        // ... or agreeing with the network's server.
        let (system, rtc, said) = written(28_800_000_000, false, false, false, Some(28_800_100_000)).await;
        assert!(system.is_some(), "{said}");
        assert_eq!(rtc, system, "{said}");
    }

    #[test]
    fn clock_the_hardware_clock_is_set_to_the_nearest_second() {
        assert_eq!(whole_seconds(1_500_000), 2);
        assert_eq!(whole_seconds(1_499_999), 1);
        assert_eq!(whole_seconds(0), 0);
    }

    #[tokio::test]
    async fn clock_a_step_writes_the_hardware_clock_with_the_same_time() {
        let (system, rtc, said) = written(28_800_000_000, false, false, true, None).await;
        assert!(system.is_some(), "{said}");
        assert_eq!(
            rtc, system,
            "the hardware clock is set to the time the system clock was"
        );
        assert_eq!(said["stepped"], true);
        assert!(said.get("rtcError").is_none() && said.get("error").is_none(), "{said}");
        // Under two seconds nothing is stepped, and nothing is written.
        let (system, rtc, said) = written(750_000, false, false, true, None).await;
        assert_eq!((system, rtc, said["stepped"].clone()), (None, None, false.into()));
    }

    #[tokio::test]
    async fn clock_a_failed_hardware_write_is_said_and_the_step_still_counts() {
        let (system, rtc, said) = written(28_800_000_000, false, true, true, None).await;
        assert_eq!(rtc, system);
        assert_eq!(said["stepped"], true);
        assert_eq!(said["rtcError"], "no such device");
        assert!(said.get("error").is_none(), "the step itself did not fail: {said}");
    }

    #[tokio::test]
    async fn clock_a_step_that_is_refused_writes_no_hardware_clock() {
        let (system, rtc, said) = written(28_800_000_000, true, false, true, None).await;
        assert!(system.is_some());
        assert_eq!(rtc, None);
        assert_eq!(said["stepped"], false);
        assert!(said.get("rtcError").is_none(), "{said}");
    }

    #[test]
    fn clock_the_log_line_of_a_step_says_when_the_hardware_clock_was_not_set() {
        let stepped = json!({ "server": "a:1", "offsetMs": 28_800_000, "stepped": true });
        assert_eq!(
            log_line(&stepped, true),
            "kithd: clock: stepped +28800.000 s to the time of a:1"
        );
        let failed = json!({ "server": "a:1", "offsetMs": 28_800_000, "stepped": true, "rtcError": "no rtc" });
        assert_eq!(
            log_line(&failed, true),
            "kithd: clock: stepped +28800.000 s to the time of a:1 (the hardware clock was not set: no rtc)"
        );
    }

    #[test]
    fn clock_a_hardened_node_writes_no_hardware_clock() {
        let hardened = crate::policy::Policy::hardened();
        let said = set_rtc_under(&hardened, 1_795_089_600_000_000).unwrap_err().to_string();
        assert!(said.contains("this node's policy is hardened"), "{said}");
    }

    #[tokio::test]
    async fn clock_serves_no_time_until_it_has_been_set() {
        // Decided at the start of `run`, before it waits for the network: a clock in 1970 is
        // not served, one after the floor is.
        let unavailable = axum::http::StatusCode::SERVICE_UNAVAILABLE;
        assert!(!begin_at(0));
        assert_eq!(serve().await.status(), unavailable);
        assert!(begin_at(FLOOR_US + 1));
        assert!(serve().await.status().is_success());
        UNSET.store(true, Ordering::Relaxed);
        assert_eq!(serve().await.status(), unavailable);
        UNSET.store(false, Ordering::Relaxed);
        assert!(serve().await.status().is_success());
        // (In this test, not one of its own: `UNSET` and `VOUCHED` are the process's.) The answer is
        // a bare JSON number, as before the mark (a node of the version before reads it the same),
        // and `kith-clock: server` beside it only while a time server set this clock.
        for vouched in [false, true] {
            VOUCHED.store(vouched, Ordering::Relaxed);
            let answer = serve().await;
            assert_eq!(vouched_by(answer.headers()), vouched);
            let mark = answer.headers().get(VOUCH).map(|v| v.to_str().unwrap().to_string());
            assert_eq!(mark, vouched.then(|| "server".to_string()));
            let body = axum::body::to_bytes(answer.into_body(), 64).await.unwrap();
            let said: i64 = serde_json::from_slice(&body).unwrap();
            assert!((said - now_us()).abs() < 5_000_000, "{said}");
        }
        VOUCHED.store(false, Ordering::Relaxed);
    }

    #[test]
    fn clock_a_leaders_answer_with_no_mark_is_read_as_unvouched() {
        // A leader of the version before says no mark: its clock is taken as one no server set.
        let mut headers = axum::http::HeaderMap::new();
        assert!(!vouched_by(&headers));
        headers.insert(VOUCH, "maybe".parse().unwrap());
        assert!(!vouched_by(&headers));
        headers.insert(VOUCH, "server".parse().unwrap());
        assert!(vouched_by(&headers));
    }

    const EIGHT_HOURS: i64 = 28_800_000_000;

    /// `super::ask` once the clock was set (or not: `synced`), with no server, the leader
    /// `leader` microseconds ahead (`vouched`: a time server set its clock), the other members at
    /// `others`, `voters` in all, and this node's own mark `mine`: what it stepped to (as an
    /// offset), the status, and the mark after.
    async fn from_cluster(
        leader: i64,
        vouched: bool,
        others: &[i64],
        voters: usize,
        mine: bool,
        synced: bool,
        spent: &mut i64,
    ) -> (Option<i64>, Value, bool) {
        let set_to = std::cell::Cell::new(None);
        let record = |us: i64| {
            set_to.set(Some(us));
            Ok(())
        };
        let heard = Heard {
            leader: Ok(Said {
                sample: Sample {
                    offset_us: leader,
                    delay_us: 1_000,
                },
                vouched,
            }),
            others: others.to_vec(),
            voters,
        };
        let mut mark = mine;
        let before = now_us();
        let said = super::ask(&[], SOON, async { heard }, record, |_| Ok(()), synced, false, spent, &mut mark).await;
        (set_to.get().map(|to| to - before), said, mark)
    }

    #[tokio::test]
    async fn clock_an_unvouched_leader_hours_off_does_not_move_a_node_a_server_set() {
        // The leader came up from a hardware clock eight hours ahead, and no server set it: a node
        // whose own clock a server set keeps its time, and says why.
        let (to, said, mark) = from_cluster(EIGHT_HOURS, false, &[], 3, true, true, &mut 0).await;
        assert_eq!(to, None, "{said}");
        assert_eq!((said["stepped"].clone(), said["server"].clone()), (false.into(), "the cluster's leader".into()));
        let why = said["error"].as_str().unwrap();
        assert!(why.contains("no time server set its clock") && why.contains("a time server set this node's"), "{said}");
        assert!((said["offsetMs"].as_i64().unwrap() - 28_800_000).abs() < 10, "{said}");
        assert!(mark, "a step not taken leaves the node's mark");
        // In a cluster of two as well: the node's own mark is enough.
        let (to, said, _) = from_cluster(EIGHT_HOURS, false, &[], 2, true, true, &mut 0).await;
        assert_eq!(to, None, "{said}");
        // It is one source then: its steps are followed to ten seconds in all.
        let mut spent = 0;
        let mut stepped = Vec::new();
        for _ in 0..3 {
            let (to, _, mark) = from_cluster(4_000_000, false, &[], 3, true, true, &mut spent).await;
            stepped.push((to.is_some(), mark));
        }
        assert_eq!(stepped, [(true, true), (true, true), (false, true)]);
        assert_eq!(spent, 8_000_000);
    }

    #[tokio::test]
    async fn clock_an_unvouched_leader_hours_off_does_not_move_a_node_the_members_agree_with() {
        // No server anywhere (the incident's network): the other member agrees with this node,
        // two of three voters, and the leader alone says eight hours.
        let (to, said, mark) = from_cluster(EIGHT_HOURS, false, &[300_000], 3, false, true, &mut 0).await;
        assert_eq!(to, None, "{said}");
        let why = said["error"].as_str().unwrap();
        assert!(why.contains("no time server set its clock") && why.contains("2 of 3 voters"), "{said}");
        assert!(!mark);
        // Five voters: two others agree, one is with the leader: three of five.
        let (to, said, _) = from_cluster(EIGHT_HOURS, false, &[0, -1_500_000, EIGHT_HOURS], 5, false, true, &mut 0).await;
        assert_eq!(to, None, "{said}");
        // One of four others agreeing is two of five: no majority, and the leader is followed.
        let (to, said, _) = from_cluster(EIGHT_HOURS, false, &[0, EIGHT_HOURS], 5, false, true, &mut 0).await;
        assert!(to.is_some_and(|to| (to - EIGHT_HOURS).abs() < 200_000), "{to:?} {said}");
    }

    #[tokio::test]
    async fn clock_with_neither_mark_nor_majority_the_unvouched_leader_is_followed_as_before() {
        // A cluster of two with no server: no majority without the leader.
        let (to, said, mark) = from_cluster(EIGHT_HOURS, false, &[], 2, false, true, &mut 0).await;
        assert!(to.is_some_and(|to| (to - EIGHT_HOURS).abs() < 200_000), "{to:?} {said}");
        assert_eq!(said["stepped"], true);
        assert!(!mark, "a leader no server set gives no mark");
        // The other member is with the leader.
        let (to, _, _) = from_cluster(EIGHT_HOURS, false, &[EIGHT_HOURS], 3, false, true, &mut 0).await;
        assert!(to.is_some());
        // A node in 1970: the others are decades from it, as the leader is.
        let decades = 1_795_000_000_000_000;
        let (to, said, _) = from_cluster(decades, false, &[decades], 3, false, false, &mut 0).await;
        assert!(to.is_some(), "{said}");
    }

    #[tokio::test]
    async fn clock_a_vouched_leader_is_followed_by_any_step() {
        let (to, said, mark) = from_cluster(EIGHT_HOURS, true, &[0], 3, true, true, &mut 0).await;
        assert!(to.is_some_and(|to| (to - EIGHT_HOURS).abs() < 200_000), "{to:?} {said}");
        assert!(said.get("error").is_none(), "{said}");
        assert!(mark, "the time of a leader a server set is a server's");
        // And kept within two seconds of it: the mark too.
        let (to, _, mark) = from_cluster(500_000, true, &[], 3, false, true, &mut 0).await;
        assert_eq!((to, mark), (None, true));
    }

    #[tokio::test]
    async fn clock_the_mark_is_a_servers_answer_followed_or_kept() {
        let mark = |servers: Vec<SocketAddr>, leader: Result<Sample, String>, mine: bool| async move {
            let mut mark = mine;
            let heard = async { alone(async { leader }).await };
            super::ask(&servers, SOON, heard, |_| Ok(()), |_| Ok(()), true, false, &mut 0, &mut mark).await;
            mark
        };
        let near = Sample {
            offset_us: 300_000,
            delay_us: 1_000,
        };
        // A server's time, kept or stepped to: a server set this clock.
        assert!(mark(vec![fake(0, |_| {}).await], Err("none".into()), false).await);
        assert!(mark(vec![fake(4_000_000, |_| {}).await], Err("none".into()), false).await);
        // No one answered: no one set it.
        assert!(!mark(vec![nobody().await], Err("none".into()), true).await);
        // A leader no server set, within two seconds: the mark stays as it was.
        assert!(mark(vec![], Ok(near), true).await);
        assert!(!mark(vec![], Ok(near), false).await);
        // A step that failed (a hardened node): the clock is not a server's.
        let mut mark = true;
        let refuse = |_| Err(std::io::Error::from_raw_os_error(1));
        let heard = alone(async { Err("none".to_string()) });
        let servers = [fake(EIGHT_HOURS, |_| {}).await];
        super::ask(&servers, SOON, heard, refuse, |_| Ok(()), true, true, &mut 0, &mut mark).await;
        assert!(!mark);
    }

    #[tokio::test]
    async fn clock_an_unvouched_leader_does_not_outweigh_a_server_or_borrow_the_operators_word() {
        let leader = |offset_us| Heard {
            leader: Ok(Said {
                sample: Sample {
                    offset_us,
                    delay_us: 1_000,
                },
                vouched: false,
            }),
            others: Vec::new(),
            voters: 3,
        };
        // A server that says this node's time, and an unvouched leader that says eight hours off:
        // the server's is taken, on a node a server set.
        let mut mark = true;
        let servers = [fake(0, |_| {}).await];
        let heard = async { leader(EIGHT_HOURS) };
        let said = super::ask(&servers, SOON, heard, |_| Ok(()), |_| Ok(()), true, false, &mut 0, &mut mark).await;
        assert_eq!(said["stepped"], false, "{said}");
        assert!(said["server"].as_str().unwrap().starts_with("127.0.0.1:"), "{said}");
        assert!(mark);
        // The operator's server is silent: its word does not carry the leader's eight hours.
        let stepped = std::cell::Cell::new(false);
        let record = |_| {
            stepped.set(true);
            Ok(())
        };
        let heard = async { leader(EIGHT_HOURS) };
        let said = super::ask(&[nobody().await], SOON, heard, record, |_| Ok(()), true, true, &mut 0, &mut mark).await;
        assert!(!stepped.get(), "{said}");
    }

    #[tokio::test]
    async fn clock_spec_ntp_is_the_operators_server_unless_kith_ntp_names_one() {
        let at = |text: &str| -> SocketAddr { text.parse().unwrap() };
        let network = Sources {
            dhcp: vec![[10, 0, 0, 8].into()],
            told: None,
            gateway: Some([10, 0, 0, 1].into()),
        };
        // The Cluster's server is the only one asked, and followed alone.
        assert_eq!(whose(&network, Some(at("10.0.0.7:123"))), (vec![at("10.0.0.7:123")], true));
        // The node's own `kith.ntp` (the more specific word) wins over it.
        let told = Sources {
            told: Some(at("10.0.0.9:5123")),
            ..network
        };
        assert_eq!(whose(&told, Some(at("10.0.0.7:123"))), (vec![at("10.0.0.9:5123")], true));
        // Neither: the network's, not followed alone.
        let network = Sources { told: None, ..told };
        assert_eq!(whose(&network, None), (vec![at("10.0.0.8:123"), at("10.0.0.1:123")], false));
        // What the Clusters say: the lowest key's, so every node takes the same.
        let mut store = kith_api::store::Store::default();
        assert_eq!(cluster_ntp(&store), None);
        for (name, spec) in [("b", "{ ntp: 10.0.0.8 }"), ("c", "{}"), ("a", "{ ntp: '10.0.0.7:5123' }")] {
            let text = format!("apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: {name} }}\nspec: {spec}\n");
            let resource = kith_api::Resource::from_source(&text).unwrap().remove(0);
            store.apply(resource.unwrap()).unwrap();
        }
        assert_eq!(cluster_ntp(&store), Some(at("10.0.0.7:5123")));
    }

    #[tokio::test(start_paused = true)]
    async fn clock_a_changed_spec_ntp_is_asked_within_a_minute_not_the_next_hour() {
        let rested = |changed_at: Option<u64>| async move {
            let started = tokio::time::Instant::now();
            let changed = async move {
                match changed_at {
                    Some(at) => tokio::time::sleep(Duration::from_secs(at)).await,
                    None => std::future::pending().await,
                }
            };
            rest(EVERY, changed).await;
            started.elapsed().as_secs()
        };
        // Nothing changed: the hour.
        assert_eq!(rested(None).await, EVERY.as_secs());
        // Changed five seconds after a check: asked a minute after it (never under a minute apart).
        assert_eq!(rested(Some(5)).await, RETRY.as_secs());
        // Changed ten minutes after: asked at once.
        assert_eq!(rested(Some(600)).await, 600);
    }

    #[tokio::test]
    async fn clock_before_the_first_sync_the_first_answer_is_enough() {
        // A server that never answers, bound and silent, after the one that does: not waited for.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let servers = [fake(4_000_000, |_| {}).await, silent.local_addr().unwrap()];
        let never = async { Err::<Sample, _>("not asked".to_string()) };
        let started = std::time::Instant::now();
        let said = ask(&servers, Duration::from_secs(30), never, |_| Ok(()), false, false).await;
        assert_eq!(said["stepped"], true);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn clock_a_clock_in_1970_reads_a_time_past_2038() {
        // The pivot is the floor, not the clock: 2040 is not read as 1904.
        let later = 2_240_000_000_000_000;
        let (t1, t4) = (0, 100_000);
        let sent = to_ntp(t1);
        let mut packet = [0; 48];
        packet[0] = 0x24;
        packet[1] = 2;
        packet[24..32].copy_from_slice(&sent);
        packet[32..40].copy_from_slice(&to_ntp(later));
        packet[40..48].copy_from_slice(&to_ntp(later));
        let sample = decode(&packet, sent, t1, t4).unwrap();
        assert!((sample.offset_us - (later - 50_000)).abs() < 1_000, "{sample:?}");
    }

    #[tokio::test]
    async fn clock_a_refusal_is_returned_at_once_not_after_the_wait() {
        let started = std::time::Instant::now();
        let said = exchange(fake(0, |p| kiss(p, b"DENY")).await, Duration::from_secs(30)).await;
        assert!(said.unwrap_err().contains("DENY"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn clock_no_more_than_four_of_the_networks_servers_are_asked() {
        let dhcp: Vec<Ipv4Addr> = (1..=9).map(|n| [10, 0, 0, n].into()).collect();
        assert_eq!(
            order(&dhcp, None, Some([10, 0, 0, 99].into())).len(),
            NETWORK_SERVERS + 1
        );
    }
}

#[cfg(test)]
mod status {
    use super::*;

    #[test]
    fn clock_status_has_the_offset_in_milliseconds_and_whether_it_was_stepped() {
        let sample = Sample {
            offset_us: -7_200_123_456,
            delay_us: 1_600,
        };
        let said = render("10.0.2.2:123", sample, Some(&Ok(())), None, 1_795_089_600_900_000);
        assert_eq!(
            said,
            json!({
                "server": "10.0.2.2:123",
                "offsetMs": -7_200_123,
                "delayMs": 2,
                "stepped": true,
                "checked": 1_795_089_600,
            })
        );
        // Under two seconds: not stepped, and the offset still said.
        let small = render(
            "10.0.2.2:123",
            Sample {
                offset_us: 750_400,
                delay_us: 100,
            },
            None,
            None,
            5_000_000,
        );
        assert_eq!(
            (small["offsetMs"].clone(), small["stepped"].clone()),
            (750.into(), false.into())
        );
        assert!(small.get("error").is_none());
    }

    #[test]
    fn clock_status_of_a_refused_step_and_of_no_answer_says_why() {
        let sample = Sample {
            offset_us: 3_000_000,
            delay_us: 0,
        };
        let refused = render("a:1", sample, Some(&Err("Operation not permitted".into())), None, 0);
        assert_eq!(refused["stepped"], false);
        // A step that counted, whose hardware clock write did not: said beside it, not as `error`.
        let kept = render("a:1", sample, Some(&Ok(())), Some("no such device"), 0);
        assert_eq!(
            (kept["stepped"].clone(), kept["rtcError"].clone()),
            (true.into(), "no such device".into())
        );
        assert!(kept.get("error").is_none());
        assert_eq!(refused["error"], "the clock is not set: Operation not permitted");
        assert_eq!(refused["offsetMs"], 3000);
        assert_eq!(
            nothing("no time server answered", 61_000_000),
            json!({"error": "no time server answered", "checked": 61})
        );
    }

    #[test]
    fn clock_status_is_null_until_a_check_has_run() {
        // (Where kithd is not a machine's first process, none runs: the Node says nothing of a clock.)
        assert_eq!(status(), Value::Null);
    }
}
