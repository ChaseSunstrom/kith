//! The clock of a node that is its machine's first process (kith OS has no other to keep it: a
//! machine with no battery clock, or a flat one, starts in 1970 and every certificate is "not
//! yet valid"). SNTP, RFC 4330: one 48-byte UDP exchange with a server, the offset worked out
//! from its four time stamps, and the clock stepped with `clock_settime` when it is off by more
//! than two seconds. Asked again about every hour, never under a minute apart.
//!
//! Whose time, in this order: a server the network's DHCP names (option 42), the one on the
//! kernel command line (`kith.ntp=ADDRESS[:PORT]`) or the installer's `ntp:`, the network's
//! gateway, and last the cluster's leader (`GET /v1/clock` on the cluster port, a node asking
//! another: a closed network with one clock in it still has one time). What it found is in this
//! Node's status as `clock`: `{server, offsetMs, delayMs, stepped, checked}`, or `{error,
//! checked}` where no one answered.
//!
//! Every timer of kithd is monotonic (tokio's `Instant`: Raft's elections and heartbeats, the
//! controllers' ticks, request timeouts), so a step breaks none of them: the store's own time
//! stamps are wall time and only read, and `controller/prune` measures what it prunes on
//! CLOCK_BOOTTIME for this reason. A node with `--node-policy hardened` has no CAP_SYS_TIME: the
//! step is refused there (and the status says so, with the offset it found).

use nix::time::{ClockId, clock_settime};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, watch};

use crate::Shared;
use serde_json::{Value, json};
use std::sync::Arc;

/// Off by more than this, the clock is stepped (SNTP's own bound is 128 ms: below two seconds
/// nothing a node does notices, and a clock that jumps every hour for a few ms is worse).
const STEP_OVER_US: i64 = 2_000_000;
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
    word.parse()
        .ok()
        .or_else(|| word.parse::<std::net::IpAddr>().ok().map(|ip| SocketAddr::new(ip, 123)))
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

/// Who to ask, in order: the DHCP's, the one told, the gateway (a home router often is one).
/// No server twice.
pub(crate) fn order(dhcp: &[Ipv4Addr], told: Option<SocketAddr>, gateway: Option<Ipv4Addr>) -> Vec<SocketAddr> {
    let dhcp = dhcp.iter().map(|ip| SocketAddr::new((*ip).into(), 123));
    let gateway = gateway.map(|ip| SocketAddr::new(ip.into(), 123));
    let mut all: Vec<SocketAddr> = Vec::new();
    for server in dhcp.chain(told).chain(gateway) {
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
    // (Stratum 0 is a "kiss of the death": the server's code for why it will not answer.)
    if stratum == 0 {
        return Err(format!(
            "the server refuses: {}",
            String::from_utf8_lossy(&answer[12..16])
        ));
    }
    if stratum > 15 || leap == 3 {
        return Err("the server's own clock is not set".into());
    }
    if answer[24..32] != sent {
        return Err("an answer to another question".into());
    }
    if answer[32..48].iter().all(|b| *b == 0) {
        return Err("no time in the answer".into());
    }
    let (t2, t3) = (from_ntp(&answer[32..], t1), from_ntp(&answer[40..], t1));
    let delay_us = (t4 - t1) - (t3 - t2);
    if t3 < t2 || delay_us < 0 {
        return Err("the answer's times are out of order".into());
    }
    Ok(Sample {
        offset_us: ((t2 - t1) + (t3 - t4)) / 2,
        delay_us,
    })
}

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
                Err(e) => bad = e,
            }
        }
    };
    match tokio::time::timeout(wait, answered).await {
        Ok(result) => result,
        Err(_) => Err(bad),
    }
}

/// What the cluster's leader (or, for a worker, the control node it follows) says the time is.
async fn leader_time(shared: &Shared) -> Result<Sample, String> {
    if shared.cluster.is_none() {
        return Err("this node is not in a cluster".into());
    }
    let upstream = shared
        .upstream
        .lock()
        .expect("nothing panics holding the upstream")
        .clone();
    let (address, client) = match upstream {
        Some(upstream) => upstream,
        None => {
            let metrics = shared.raft.metrics().borrow().clone();
            let leader = metrics.current_leader.filter(|leader| *leader != metrics.id);
            let leader = leader.ok_or("no other node leads")?;
            let membership = metrics.membership_config.membership().clone();
            let address = membership
                .get_node(&leader)
                .ok_or("the leader's address is not known")?;
            (address.addr.clone(), crate::raft::to_voter(shared, leader)?.0)
        }
    };
    let t1 = now_us();
    let asked = client.get(format!("https://{address}/v1/clock")).timeout(WAIT);
    let said = asked.send().await.map_err(|e| format!("asking {address}: {e}"))?;
    let said = said.error_for_status().map_err(|e| format!("{address}: {e}"))?;
    let said = said.json::<i64>().await.map_err(|e| format!("{address}: {e}"))?;
    let t4 = now_us();
    // (The time said was read half way: one network trip each way, as with the server's own.)
    Ok(Sample {
        offset_us: said - (t1 + (t4 - t1) / 2),
        delay_us: t4 - t1,
    })
}

/// What this node answers another that asks the time (`/v1/clock`, for members): its clock.
pub async fn serve() -> axum::Json<i64> {
    axum::Json(now_us())
}

/// Set the wall clock to `us` microseconds since 1970.
fn set(us: i64) -> std::io::Result<()> {
    let to = u64::try_from(us).map_err(|_| std::io::Error::other("a time before 1970"))?;
    let to = nix::sys::time::TimeSpec::from_duration(Duration::from_micros(to));
    clock_settime(ClockId::CLOCK_REALTIME, to).map_err(std::io::Error::from)
}

/// The status of a check that found `sample` at `server` and `stepped` (or why it did not).
fn render(server: &str, sample: Sample, stepped: Option<&Result<(), String>>, at: i64) -> Value {
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
    said
}

/// The status of a check that found no time.
fn nothing(why: &str, at: i64) -> Value {
    json!({ "error": why, "checked": at / 1_000_000 })
}

/// One check: ask each server in turn, then the leader; step the clock with `set_to` when the
/// time found is over two seconds from it; and the status that says so.
async fn ask(
    servers: &[SocketAddr],
    wait: Duration,
    leader: impl Future<Output = Result<Sample, String>>,
    set_to: impl Fn(i64) -> std::io::Result<()>,
) -> Value {
    let (mut found, mut why) = (None, Vec::new());
    for server in servers {
        match exchange(*server, wait).await {
            Ok(sample) => {
                found = Some((server.to_string(), sample));
                break;
            }
            Err(e) => why.push(format!("{server}: {e}")),
        }
    }
    if found.is_none() {
        match leader.await {
            Ok(sample) => found = Some(("the cluster's leader".to_string(), sample)),
            Err(e) => why.push(format!("leader: {e}")),
        }
    }
    let Some((server, sample)) = found else {
        return nothing(&format!("no time server answered ({})", why.join("; ")), now_us());
    };
    let step =
        (sample.offset_us.abs() > STEP_OVER_US).then(|| set_to(now_us() + sample.offset_us).map_err(|e| e.to_string()));
    render(&server, sample, step.as_ref(), now_us())
}

/// What `ask` found, for this Node's status: null before the first check (and always on a node
/// that is not a machine's first process, which keeps no clock).
pub fn status() -> Value {
    STATUS.lock().expect("nothing panics holding the status").clone()
}

/// Keep the clock as long as kithd runs: once the network has said something (or a while
/// after, for one that says nothing: the cluster's leader may), then about every hour.
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let kept = async {
        let _ = tokio::time::timeout(Duration::from_secs(10), LEARNED.notified()).await;
        let mut said = String::new();
        loop {
            let servers = {
                let sources = SOURCES.lock().expect("nothing panics holding the sources");
                order(&sources.dhcp, sources.told, sources.gateway)
            };
            let now = ask(&servers, WAIT, leader_time(&shared), set).await;
            let again = if now["error"].is_null() || now["stepped"] == true {
                EVERY
            } else {
                RETRY
            };
            // (Said in the log when it changes, so an hour of the same does not fill it.)
            let line = match (now["error"].as_str(), now["server"].as_str()) {
                (Some(why), _) => format!("kithd: clock: {why}"),
                (None, Some(server)) => {
                    let seconds = now["offsetMs"].as_i64().unwrap_or_default() as f64 / 1000.0;
                    if now["stepped"] == true {
                        format!("kithd: clock: stepped {seconds:+.3} s to the time of {server}")
                    } else if said.is_empty() {
                        // (The first check says where it stands even when there was nothing to do.)
                        format!("kithd: clock: {seconds:+.3} s from the time of {server}: kept")
                    } else {
                        String::new()
                    }
                }
                _ => String::new(),
            };
            if !line.is_empty() && line != said {
                eprintln!("{line}");
                said = line;
            }
            *STATUS.lock().expect("nothing panics holding the status") = now;
            CHANGED.notify_one();
            tokio::time::sleep(again).await;
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
    fn clock_servers_are_asked_dhcp_then_told_then_gateway_each_once() {
        let at = |ip: &str| SocketAddr::new(ip.parse().unwrap(), 123);
        let told: SocketAddr = "10.0.0.9:5123".parse().unwrap();
        let dhcp = [[10, 0, 0, 7].into(), [10, 0, 0, 8].into()];
        assert_eq!(
            order(&dhcp, Some(told), Some([10, 0, 0, 1].into())),
            [at("10.0.0.7"), at("10.0.0.8"), told, at("10.0.0.1")]
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
        let said = ask(&[fake(28_800_000_000, |_| {}).await], SOON, never, record).await;
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
        let said = ask(&[fake(-5_000_000, |_| {}).await], SOON, never, record).await;
        assert!(set_to.get().is_some_and(|to| to < now_us() - 4_500_000));
        assert_eq!(said["stepped"], true);
        set_to.set(None);
        let never = async { Err::<Sample, _>("not asked".to_string()) };
        let said = ask(&[fake(750_000, |_| {}).await], SOON, never, record).await;
        assert_eq!(set_to.get(), None);
        assert_eq!(said["stepped"], false);
        assert!((said["offsetMs"].as_i64().unwrap() - 750).abs() < 100);
    }

    #[tokio::test]
    async fn clock_a_step_that_is_refused_is_said_with_the_offset_found() {
        let never = async { Err::<Sample, _>("not asked".to_string()) };
        let refuse = |_| Err(std::io::Error::from_raw_os_error(1));
        let said = ask(&[fake(7_200_000_000, |_| {}).await], SOON, never, refuse).await;
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
        let said = ask(&[nobody().await, fake(4_000_000, |_| {}).await], SOON, leader, record).await;
        assert_eq!(said["stepped"], true);
        assert!(said["server"].as_str().unwrap().starts_with("127.0.0.1:"));
        // No server answers: the leader's time is, and said to be.
        let leader = async {
            Ok(Sample {
                offset_us: -9_000_000,
                delay_us: 2_000,
            })
        };
        let said = ask(&[nobody().await], SOON, leader, record).await;
        assert_eq!(
            (said["server"].as_str(), said["offsetMs"].as_i64()),
            (Some("the cluster's leader"), Some(-9000))
        );
        assert_eq!(steps.get(), 2);
        // None of them: the status is the reason, and the clock is not touched.
        let leader = async { Err::<Sample, _>("no other node leads".to_string()) };
        let said = ask(&[nobody().await], SOON, leader, record).await;
        let error = said["error"].as_str().unwrap();
        assert!(
            error.contains("no time server answered") && error.contains("no other node leads"),
            "{said}"
        );
        assert_eq!(steps.get(), 2);
        let none = ask(&[], SOON, async { Err::<Sample, _>("x".to_string()) }, record).await;
        assert!(none["error"].as_str().unwrap().contains("(leader: x)"), "{none}");
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
        let said = render("10.0.2.2:123", sample, Some(&Ok(())), 1_795_089_600_900_000);
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
        let refused = render("a:1", sample, Some(&Err("Operation not permitted".into())), 0);
        assert_eq!(refused["stepped"], false);
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
