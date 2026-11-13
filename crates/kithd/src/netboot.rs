//! Installing machines from the network (PLAN §4.9, "Network installs"). Off unless
//! someone turns it on (`PUT /v1/netboot`), for an hour at most, for machines named by
//! their network cards' addresses; off again after a restart. While on, this node
//!
//! - answers those machines when they ask the network what to start (PXE). It gives no
//!   addresses: the network's own DHCP server does, and this is the second answer the
//!   firmware waits for, "proxy DHCP": on port 67 to a broadcast, on 4011 when asked there;
//! - serves each of them one file over TFTP: the network boot file os/build.sh makes
//!   (kernel, installer and image), with that machine's answers written into the place
//!   the file keeps for them: install on the only disk, and join this cluster with a
//!   token made for that machine;
//! - serves each machine once: started again after the install, it finds no answer here
//!   and starts from its disk.
//!
//! Only machines that start by UEFI on x86-64 are answered: kith OS starts no other way.
//!
//! TFTP hides nothing: whoever can listen on that network during the hour reads the
//! token, and could join one node in the machine's place. It is good once.
//
// ponytail: the file (38 MB) is held in memory while this is on, and TFTP sends one block
// per answer: a minute on a slow network. UEFI HTTP boot would be faster (T-0114).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

pub type Mac = [u8; 6];

/// Where the boot file keeps room for a machine's answers, and how much (os/build.sh).
const MARKER: &[u8] = b"#kith-netboot-answers#";
const ROOM: usize = 4096;
/// A join token's life (pki.rs): netboot is not on for longer.
const MINUTES: u64 = 60;

/// The port this node serves other nodes on: where a machine installed from here joins.
pub static PORT: OnceLock<u16> = OnceLock::new();

struct Active {
    image: Arc<Vec<u8>>,
    /// Where in `image` the answers go.
    at: usize,
    disk: String,
    /// The machines keep their state encrypted (crypt.rs).
    encrypt: bool,
    machines: BTreeMap<Mac, Machine>,
    until: Instant,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

struct Machine {
    token: String,
    /// It has the whole file: it is not answered again.
    served: bool,
    /// The file on its way to it: one at a time, and none once netboot is off.
    transfer: Option<tokio::task::JoinHandle<()>>,
}

impl Active {
    /// Stop listening and sending. The tasks, for one who waits until their sockets are closed.
    fn stop(self) -> Vec<tokio::task::JoinHandle<()>> {
        let transfers = self.machines.into_values().filter_map(|machine| machine.transfer);
        let tasks: Vec<_> = self.tasks.into_iter().chain(transfers).collect();
        tasks.iter().for_each(|task| task.abort());
        tasks
    }
}

static ACTIVE: Mutex<Option<Active>> = Mutex::new(None);

fn active() -> std::sync::MutexGuard<'static, Option<Active>> {
    ACTIVE.lock().expect("nothing panics holding the netboot state")
}

/// `52:54:00:aa:bb:cc` (or with dashes).
pub fn mac(text: &str) -> Option<Mac> {
    let mut mac = [0; 6];
    let mut parts = text.trim().split([':', '-']);
    for byte in &mut mac {
        let hex = |part: &&str| part.len() == 2 && part.bytes().all(|digit| digit.is_ascii_hexdigit());
        let part = parts.next().filter(hex)?;
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

fn written(mac: &Mac) -> String {
    mac.map(|byte| format!("{byte:02x}")).join(":")
}

/// The file a machine is told to fetch: its name says whose it is, as TFTP does not.
fn file(mac: &Mac) -> String {
    format!("kith-netboot-{}.efi", mac.map(|byte| format!("{byte:02x}")).concat())
}

fn of(file: &str) -> Option<Mac> {
    let hex = file
        .trim_start_matches(['/', '\\'])
        .strip_prefix("kith-netboot-")?
        .strip_suffix(".efi")?;
    (hex.len() == 12 && hex.is_ascii()).then(|| {
        let pairs: Vec<&str> = (0..6).map(|i| &hex[i * 2..i * 2 + 2]).collect();
        mac(&pairs.join(":"))
    })?
}

/// What a machine's firmware asked the network (a DHCP DISCOVER or REQUEST from a PXE client).
#[derive(Debug, PartialEq)]
pub struct Asks {
    pub mac: Mac,
    xid: [u8; 4],
    ciaddr: [u8; 4],
    /// DISCOVER (1) or REQUEST (3).
    kind: u8,
    /// The machine's own id (option 97), to be said back.
    id: Option<Vec<u8>>,
}

/// Read `packet` as a PXE client's question, from a machine that starts by UEFI on x86-64.
pub fn asks(packet: &[u8]) -> Option<Asks> {
    if packet.len() < 240 || packet[0] != 1 || packet[1] != 1 || packet[2] != 6 || packet[236..240] != [99, 130, 83, 99]
    {
        return None;
    }
    let (mut kind, mut pxe, mut arch, mut id) = (0, false, None, None);
    let mut options = &packet[240..];
    while let [code, rest @ ..] = options {
        match (*code, rest) {
            (255, _) => break,
            (0, _) => options = rest,
            (code, [len, rest @ ..]) if rest.len() >= *len as usize => {
                let (value, rest) = rest.split_at(*len as usize);
                match (code, value) {
                    (53, [said]) => kind = *said,
                    (60, class) => pxe = class.starts_with(b"PXEClient"),
                    (93, [high, low, ..]) => arch = Some(u16::from_be_bytes([*high, *low])),
                    (97, own) => id = Some(own.to_vec()),
                    _ => {}
                }
                options = rest;
            }
            _ => return None,
        }
    }
    // (7 and 9: x86-64 UEFI, as the firmware's makers and the RFC number it.)
    (pxe && matches!(kind, 1 | 3) && matches!(arch, Some(7 | 9))).then(|| Asks {
        mac: packet[28..34].try_into().expect("six bytes"),
        xid: packet[4..8].try_into().expect("four bytes"),
        ciaddr: packet[12..16].try_into().expect("four bytes"),
        kind,
        id,
    })
}

/// The answer: no address (the network's server gives that), but where the file is (`us`)
/// and what it is called.
pub fn answer(asked: &Asks, us: Ipv4Addr) -> Vec<u8> {
    let mut packet = vec![0; 240];
    packet[..4].copy_from_slice(&[2, 1, 6, 0]);
    packet[4..8].copy_from_slice(&asked.xid);
    // (To be broadcast: the machine may not have its address yet.)
    packet[10] = 0x80;
    packet[12..16].copy_from_slice(&asked.ciaddr);
    packet[20..24].copy_from_slice(&us.octets());
    packet[28..34].copy_from_slice(&asked.mac);
    let name = file(&asked.mac);
    packet[108..108 + name.len()].copy_from_slice(name.as_bytes());
    packet[236..240].copy_from_slice(&[99, 130, 83, 99]);
    // OFFER to a DISCOVER, ACK to a REQUEST.
    packet.extend([53, 1, if asked.kind == 1 { 2 } else { 5 }]);
    packet.extend([54, 4]);
    packet.extend(us.octets());
    packet.extend([60, 9]);
    packet.extend(b"PXEClient");
    if let Some(id) = asked.id.as_ref().filter(|id| id.len() < 256) {
        packet.extend([97, id.len() as u8]);
        packet.extend(id);
    }
    // (Option 43, PXE's own: 6 = 8, "take the file named, ask no boot server, show no menu".)
    packet.extend([43, 4, 6, 1, 8, 255]);
    packet.push(255);
    packet
}

/// A machine's answers, as long as the room the file has for them.
fn answers(disk: &str, encrypt: bool, join: SocketAddr, token: &str) -> Option<Vec<u8>> {
    let encrypt = if encrypt { "encrypt: true\n" } else { "" };
    let mut text = format!("disk: {disk}\n{encrypt}join:\n  address: {join}\n  token: {token}\n").into_bytes();
    (text.len() <= ROOM).then(|| {
        text.resize(ROOM, b'\n');
        text
    })
}

/// `len` bytes of the file from `from`, with `answers` where the file keeps room for them.
fn read(image: &[u8], at: usize, answers: &[u8], from: usize, len: usize) -> Vec<u8> {
    let end = image.len().min(from.saturating_add(len));
    let mut bytes = image.get(from..end).unwrap_or_default().to_vec();
    for (i, byte) in bytes.iter_mut().enumerate() {
        if let Some(theirs) = (from + i).checked_sub(at).and_then(|i| answers.get(i)) {
            *byte = *theirs;
        }
    }
    bytes
}

/// A TFTP read request: the file, and the options asked for (RFC 1350, 2347).
fn request(packet: &[u8]) -> Option<(String, Vec<(String, String)>)> {
    let [0, 1, rest @ ..] = packet else {
        return None;
    };
    let mut words = rest
        .split(|byte| *byte == 0)
        .map(|word| String::from_utf8_lossy(word).into_owned());
    let (file, mode) = (words.next()?, words.next()?);
    let mut options = Vec::new();
    while let (Some(name), Some(value)) = (words.next(), words.next()) {
        options.push((name.to_ascii_lowercase(), value));
    }
    mode.eq_ignore_ascii_case("octet").then_some((file, options))
}

fn refusal(code: u8, why: &str) -> Vec<u8> {
    [&[0, 5, 0, code], why.as_bytes(), &[0]].concat()
}

/// Send `size` bytes, read through `read`, to the machine `socket` is connected to.
async fn send(
    socket: &UdpSocket,
    size: usize,
    options: &[(String, String)],
    read: impl Fn(usize, usize) -> Vec<u8>,
) -> std::io::Result<()> {
    /// One packet, sent again until `wanted` (a block's number) is acknowledged.
    async fn told(socket: &UdpSocket, packet: &[u8], wanted: u16) -> std::io::Result<()> {
        let mut heard = [0; 64];
        for _ in 0..8 {
            socket.send(packet).await?;
            let waited = tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    // (An acknowledgement of an earlier block is a late copy: answering
                    // those would send every block twice from then on.)
                    match socket.recv(&mut heard).await? {
                        4.. if heard[..4] == [0, 4, (wanted >> 8) as u8, wanted as u8] => return Ok(()),
                        2.. if heard[..2] == [0, 5] => return Err(std::io::Error::other("the machine gave up")),
                        _ => {}
                    }
                }
            });
            if let Ok(done) = waited.await {
                return done;
            }
        }
        Err(std::io::Error::other("the machine stopped answering"))
    }
    let mut block = 512;
    let mut agreed = Vec::new();
    for (name, value) in options {
        match name.as_str() {
            // (No more than fits a packet on any network: nothing here is put together again.)
            "blksize" => {
                block = value.parse::<usize>().unwrap_or(512).clamp(8, 1428);
                agreed.push(format!("blksize\0{block}\0"));
            }
            "tsize" => agreed.push(format!("tsize\0{size}\0")),
            _ => {}
        }
    }
    if !agreed.is_empty() {
        told(socket, &[&[0, 6], agreed.concat().as_bytes()].concat(), 0).await?;
    }
    // (To a block shorter than the rest, which ends it: an empty one if the size divides.)
    for number in 1..=size / block + 1 {
        let data = read((number - 1) * block, block);
        // (Block numbers are 16 bits and go round: both sides only compare the last one.)
        let number = number as u16;
        told(
            socket,
            &[&[0, 3, (number >> 8) as u8, number as u8], &data[..]].concat(),
            number,
        )
        .await?;
    }
    Ok(())
}

/// Answer read requests on `socket` (port 69) for as long as netboot is on.
async fn tftp(socket: UdpSocket) {
    let mut packet = [0; 1024];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut packet).await else {
            continue;
        };
        let Some((name, options)) = request(&packet[..len]) else {
            continue;
        };
        let wanted = of(&name).and_then(|mac| {
            let active = active();
            let active = active.as_ref()?;
            let machine = active.machines.get(&mac).filter(|machine| !machine.served)?;
            Some((
                mac,
                active.image.clone(),
                active.at,
                (active.disk.clone(), active.encrypt),
                machine.token.clone(),
            ))
        });
        let named = wanted.as_ref().map(|wanted| wanted.0);
        let transfer = tokio::spawn(async move {
            // Each transfer from a port of its own, as TFTP has it.
            let Ok(transfer) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else {
                return;
            };
            if transfer.connect(peer).await.is_err() {
                return;
            }
            let Some((mac, image, at, disk, token)) = wanted else {
                let _ = transfer.send(&refusal(1, "no such file here")).await;
                return;
            };
            // The node is joined at the address this machine reaches it by.
            let (Ok(us), Some(port)) = (transfer.local_addr(), PORT.get()) else {
                return;
            };
            let Some(answers) = answers(&disk.0, disk.1, SocketAddr::new(us.ip(), *port), &token) else {
                return;
            };
            let sent = send(&transfer, image.len(), &options, |from, len| {
                read(&image, at, &answers, from, len)
            });
            // (Firmware asks once for the size and gives up, then asks again: only a
            // transfer that ended is a machine that has the file.)
            match sent.await {
                Ok(()) => {
                    if let Some(machine) = active().as_mut().and_then(|active| active.machines.get_mut(&mac)) {
                        machine.served = true;
                    }
                    eprintln!(
                        "kithd: netboot: {} has the installer: it is not answered again",
                        written(&mac)
                    );
                }
                Err(why) => eprintln!("kithd: netboot: sending to {} ended: {why}", written(&mac)),
            }
        });
        // One at a time to a machine: firmware that asks again has given up on what it asked
        // before, and whoever asks in its name over and over gets one answer, not many.
        let machine = named.and_then(|mac| active().as_mut()?.machines.get_mut(&mac)?.transfer.replace(transfer));
        if let Some(before) = machine {
            before.abort();
        }
    }
}

/// Answer PXE questions heard on `socket`: broadcasts on port 67 (answered by broadcast),
/// or on port 4011, where firmware asks the one it heard from (answered there).
async fn dhcp(socket: UdpSocket, us: Option<Ipv4Addr>) {
    let mut packet = [0; 1500];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut packet).await else {
            continue;
        };
        let Some(asked) = asks(&packet[..len]) else {
            continue;
        };
        let wanted = active()
            .as_ref()
            .and_then(|active| active.machines.get(&asked.mac))
            .is_some_and(|machine| !machine.served);
        if !wanted {
            continue;
        }
        let (us, to) = match (us, peer) {
            (Some(us), _) => (us, SocketAddr::from((Ipv4Addr::BROADCAST, 68))),
            // Asked at this node's own address: which one is what a socket to there would use.
            (None, peer) => {
                let Ok(probe) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else {
                    continue;
                };
                match (probe.connect(peer).await, probe.local_addr()) {
                    (Ok(()), Ok(SocketAddr::V4(local))) => (*local.ip(), peer),
                    _ => continue,
                }
            }
        };
        let _ = socket.send_to(&answer(&asked, us), to).await;
    }
}

/// This machine's cards that have an IPv4 address, and it.
fn cards() -> Vec<(String, Ipv4Addr)> {
    let all = nix::ifaddrs::getifaddrs().into_iter().flatten();
    all.filter_map(|card| {
        let address = card.address?.as_sockaddr_in()?.ip();
        (!address.is_loopback()).then_some((card.interface_name, address))
    })
    .collect()
}

/// Turn it on: `image` is the network boot file, `machines` the cards' addresses with a
/// join token each. Says what is on, as `status` does.
///
/// `token` is asked for one per machine, once nothing else can refuse.
pub async fn on(
    image: Vec<u8>,
    machines: Vec<Mac>,
    minutes: u64,
    disk: &str,
    encrypt: bool,
    token: impl Fn() -> Result<String, String>,
) -> Result<serde_json::Value, String> {
    let places = image.windows(MARKER.len()).filter(|window| *window == MARKER);
    if places.count() != 1 {
        return Err("that is not kith's network boot file (os/build.sh makes kith-netboot.efi)".into());
    }
    let at = image.windows(MARKER.len()).position(|window| window == MARKER);
    let at = at.expect("counted above");
    if machines.is_empty() || !(1..=MINUTES).contains(&minutes) || PORT.get().is_none() {
        return Err(format!(
            "netboot needs a node that serves others (--listen), a machine's card address, and 1 to {MINUTES} minutes"
        ));
    }
    let plain = |c: char| c.is_ascii_alphanumeric();
    if disk.is_empty() || !disk.chars().all(plain) {
        return Err(format!("`{disk}` is not a disk's name, or `only`"));
    }
    // (Waited for: until a task is gone its socket holds the port.)
    for task in off() {
        let _ = task.await;
    }
    let failed = |what: &'static str| move |e: std::io::Error| format!("netboot cannot listen on {what}: {e}");
    let bound = |port: u16| {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    };
    // (Both before either is served: what fails here has started nothing to stop.)
    let (files, asked) = (
        bound(69).map_err(failed("port 69 (TFTP)"))?,
        bound(4011).map_err(failed("port 4011"))?,
    );
    let mut held = BTreeMap::new();
    for mac in machines {
        let (token, served, transfer) = (token()?, false, None);
        held.insert(
            mac,
            Machine {
                token,
                served,
                transfer,
            },
        );
    }
    let mut tasks = vec![tokio::spawn(tftp(files)), tokio::spawn(dhcp(asked, None))];
    for (card, address) in cards() {
        match crate::dhcp::socket(&card, 67) {
            Ok(socket) => tasks.push(tokio::spawn(dhcp(socket, Some(address)))),
            Err(e) => eprintln!("kithd: netboot: not answering on {card}: {e}"),
        }
    }
    tasks.push(tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(minutes * 60)).await;
        eprintln!("kithd: netboot: off again, {minutes} minutes after it was turned on");
        // (Not `off`: that would stop this task before it had let go of the rest.)
        if let Some(mut active) = active().take() {
            active.tasks.pop();
            active.stop();
        }
    }));
    *active() = Some(Active {
        image: Arc::new(image),
        at,
        disk: disk.to_string(),
        encrypt,
        machines: held,
        until: Instant::now() + Duration::from_secs(minutes * 60),
        tasks,
    });
    eprintln!("kithd: netboot: on for {minutes} minutes");
    Ok(status())
}

/// Turn it off: nothing is listened for, and the file and the tokens are let go.
pub fn off() -> Vec<tokio::task::JoinHandle<()>> {
    let Some(active) = active().take() else {
        return Vec::new();
    };
    eprintln!("kithd: netboot: off");
    active.stop()
}

/// Whether it is on, for how long, and which machines have had the file.
pub fn status() -> serde_json::Value {
    match active().as_ref() {
        None => serde_json::json!({ "on": false }),
        Some(active) => serde_json::json!({
            "on": true,
            "secondsLeft": active.until.saturating_duration_since(Instant::now()).as_secs(),
            "disk": active.disk,
            "encrypt": active.encrypt,
            "machines": active.machines.iter().map(|(mac, machine)| serde_json::json!({
                "mac": written(mac),
                "served": machine.served,
            })).collect::<Vec<_>>(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARD: Mac = [0x52, 0x54, 0, 0xaa, 0xbb, 0xcc];
    /// A machine asked for in small blocks.
    const SMALL: Mac = [0x52, 0x54, 0, 0xaa, 0xbb, 0xcd];

    /// What firmware sends: a DISCOVER from a PXE client of architecture `arch`.
    fn discover(class: &[u8], arch: u16, kind: u8) -> Vec<u8> {
        let mut packet = vec![0; 240];
        packet[..4].copy_from_slice(&[1, 1, 6, 0]);
        packet[4..8].copy_from_slice(&[1, 2, 3, 4]);
        packet[28..34].copy_from_slice(&CARD);
        packet[236..240].copy_from_slice(&[99, 130, 83, 99]);
        packet.extend([53, 1, kind, 0, 60, class.len() as u8]);
        packet.extend(class);
        packet.extend([93, 2]);
        packet.extend(arch.to_be_bytes());
        packet.extend([97, 3, 0, 7, 7, 255]);
        packet
    }

    #[test]
    fn netboot_answers_uefi_pxe_and_nothing_else() {
        let asked = asks(&discover(b"PXEClient:Arch:00007:UNDI:003016", 7, 1)).unwrap();
        assert_eq!(
            (asked.mac, asked.kind, asked.id.as_deref()),
            (CARD, 1, Some(&[0, 7, 7][..]))
        );
        assert!(asks(&discover(b"PXEClient", 9, 3)).is_some());
        // A machine that starts by BIOS, one that only wants an address, a reply, and noise.
        assert_eq!(asks(&discover(b"PXEClient", 0, 1)), None);
        assert_eq!(asks(&discover(b"MSFT 5.0", 7, 1)), None);
        let mut reply = discover(b"PXEClient", 7, 1);
        reply[0] = 2;
        assert_eq!(asks(&reply), None);
        assert_eq!(asks(&[1, 1, 6, 0, 9]), None);
        let mut cut = discover(b"PXEClient", 7, 1);
        cut.truncate(246);
        assert_eq!(asks(&cut), None);

        // The answer gives no address, says where the file is and whose it is.
        let us = Ipv4Addr::new(10, 0, 2, 15);
        let offer = answer(&asked, us);
        assert_eq!(offer[..4], [2, 1, 6, 0]);
        assert_eq!(offer[4..8], [1, 2, 3, 4]);
        assert_eq!((&offer[16..20], &offer[20..24]), (&[0; 4][..], &us.octets()[..]));
        assert_eq!(offer[28..34], CARD);
        assert!(offer[108..].starts_with(b"kith-netboot-525400aabbcc.efi\0"));
        let options = &offer[240..];
        assert!(options.starts_with(&[53, 1, 2, 54, 4, 10, 0, 2, 15, 60, 9]));
        assert!(options.ends_with(&[97, 3, 0, 7, 7, 43, 4, 6, 1, 8, 255, 255]));
        // To a REQUEST (as on port 4011), an ACK.
        let ack = answer(&asks(&discover(b"PXEClient", 9, 3)).unwrap(), us);
        assert_eq!(ack[240..243], [53, 1, 5]);
    }

    #[test]
    fn netboot_names_each_machine_its_file() {
        assert_eq!(mac("52:54:00:AA:bb:cc"), Some(CARD));
        assert_eq!(mac("52-54-00-aa-bb-cc"), Some(CARD));
        for bad in [
            "",
            "52:54:00:aa:bb",
            "52:54:00:aa:bb:cc:dd",
            "52:54:00:aa:bb:zz",
            "5254:00:aa:bb:cc:dd",
        ] {
            assert_eq!(mac(bad), None, "{bad}");
        }
        assert_eq!(file(&CARD), "kith-netboot-525400aabbcc.efi");
        assert_eq!(of("kith-netboot-525400aabbcc.efi"), Some(CARD));
        assert_eq!(of("/kith-netboot-525400aabbcc.efi"), Some(CARD));
        for other in [
            "kith-netboot.efi",
            "kith-netboot-525400aabbcc.efi.sig",
            "../etc/passwd",
            "kith-netboot-5254é0aabbc.efi",
        ] {
            assert_eq!(of(other), None, "{other}");
        }
    }

    #[test]
    fn netboot_writes_the_answers_where_the_file_keeps_room() {
        let mut image = vec![b'k'; 100];
        image.extend(MARKER);
        image.extend(vec![b'#'; ROOM - MARKER.len()]);
        image.extend(vec![b'z'; 50]);
        let join = "10.0.2.15:7443".parse().unwrap();
        let answers = answers("only", false, join, "kith1.ab.cd").unwrap(); // (made up) pragma: allowlist secret
        assert_eq!(answers.len(), ROOM);
        let text = String::from_utf8(answers.clone()).unwrap();
        let told = crate::install::answers(&text).unwrap();
        assert_eq!(told.disk, "only");
        assert_eq!(told.join.unwrap().address, "10.0.2.15:7443");
        // Read in pieces of any size, the file is itself with the answers in their place.
        for piece in [1, 7, 512, 1428, 5000] {
            let mut whole = Vec::new();
            while whole.len() < image.len() {
                whole.extend(read(&image, 100, &answers, whole.len(), piece));
            }
            assert_eq!(whole.len(), image.len());
            assert_eq!(whole[..100], image[..100]);
            assert_eq!(whole[100..100 + ROOM], answers[..]);
            assert_eq!(whole[100 + ROOM..], [b'z'; 50]);
        }
        assert!(read(&image, 100, &answers, image.len(), 512).is_empty());
        // Answers longer than the room are none.
        assert_eq!(super::answers(&"x".repeat(ROOM), true, join, "t"), None);
    }

    /// A TFTP client as firmware is one: asks with options, acknowledges each block.
    async fn fetch(server: SocketAddr, name: &str, block: usize, lose: usize) -> Result<Vec<u8>, String> {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ask = format!("\0\u{1}{name}\0octet\0blksize\0{block}\0tsize\00\0");
        client.send_to(ask.as_bytes(), server).await.unwrap();
        let (mut packet, mut whole, mut expected, mut seen) = (vec![0; 2000], Vec::new(), 1u16, 0);
        loop {
            let heard = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut packet));
            let (len, from) = heard.await.map_err(|_| "nothing heard")?.unwrap();
            seen += 1;
            // (A network that loses a packet now and then: the server sends it again.)
            if lose > 0 && seen % lose == 0 {
                continue;
            }
            match packet[..len] {
                [0, 6, ..] => {
                    let said = String::from_utf8_lossy(&packet[2..len]).into_owned();
                    assert!(said.contains(&format!("blksize\0{block}\0")), "{said:?}");
                    client.send_to(&[0, 4, 0, 0], from).await.unwrap();
                }
                [0, 3, high, low, ..] => {
                    let number = u16::from_be_bytes([high, low]);
                    if number == expected {
                        whole.extend(&packet[4..len]);
                        expected = expected.wrapping_add(1);
                    }
                    client.send_to(&[0, 4, high, low], from).await.unwrap();
                    if number == expected.wrapping_sub(1) && len - 4 < block {
                        return Ok(whole);
                    }
                }
                [0, 5, _, _, ..] => return Err(String::from_utf8_lossy(&packet[4..len - 1]).into_owned()),
                _ => return Err("something else".into()),
            }
        }
    }

    #[tokio::test]
    async fn netboot_serves_the_file_over_tftp_to_the_machines_named_once() {
        // More blocks of 8 bytes than a block number counts to, so the numbers go round.
        let mut image: Vec<u8> = (0..600_000u32).map(|i| (i % 251) as u8).collect();
        image[1000..1000 + MARKER.len()].copy_from_slice(MARKER);
        let _ = PORT.set(7443);
        *active() = Some(Active {
            image: Arc::new(image.clone()),
            at: 1000,
            disk: "only".into(),
            encrypt: false,
            machines: [CARD, SMALL]
                .map(|card| {
                    let token = "kith1.ab.cd".to_string(); // (made up) pragma: allowlist secret
                    let (served, transfer) = (false, None);
                    (
                        card,
                        Machine {
                            token,
                            served,
                            transfer,
                        },
                    )
                })
                .into(),
            until: Instant::now() + Duration::from_secs(60),
            tasks: vec![],
        });
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = socket.local_addr().unwrap();
        let serving = tokio::spawn(tftp(socket));

        // Another machine's file, and any other file, are not here.
        let other = fetch(server, "kith-netboot-525400000001.efi", 512, 0).await;
        assert_eq!(other.unwrap_err(), "no such file here");
        assert!(fetch(server, "/etc/passwd", 512, 0).await.is_err());
        assert_eq!(status()["machines"][0]["served"], false);

        let whole = fetch(server, &file(&CARD), 1428, 97).await.unwrap();
        assert_eq!(whole.len(), image.len());
        assert_eq!(whole[..1000], image[..1000]);
        assert!(whole[1000..].starts_with(b"disk: only\njoin:\n  address: 127.0.0.1:7443\n  token: kith1.ab.cd\n\n"));
        assert_eq!(whole[1000 + ROOM..], image[1000 + ROOM..]);
        // (The mark is made after the last acknowledgement is heard.)
        for _ in 0..50 {
            if status()["machines"][0]["served"] == true {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(status()["machines"][0]["served"], true);

        // It has the file: nobody is given that file, and its token, a second time.
        assert_eq!(
            fetch(server, &file(&CARD), 1428, 0).await.unwrap_err(),
            "no such file here"
        );

        let round = fetch(server, &file(&SMALL), 8, 0).await.unwrap();
        assert_eq!(round.len(), image.len());
        assert_eq!(round[round.len() - 100..], image[image.len() - 100..]);
        serving.abort();

        // Turned on twice, the second has the ports of the first; a file that is not the
        // boot file, or a card that is not one, costs no token.
        let token = || Ok("kith1.ab.cd".to_string()); // (made up) pragma: allowlist secret
        let none = || -> Result<String, String> { panic!("a token for a refusal") };
        assert!(on(vec![0; 64], vec![CARD], 5, "only", false, none).await.is_err());
        assert!(on(image.clone(), vec![CARD], 5, "../x", false, none).await.is_err());
        if on(image.clone(), vec![CARD], 5, "only", true, token).await.is_ok() {
            assert_eq!(on(image, vec![CARD], 5, "only", true, token).await.unwrap()["on"], true);
        }
        for task in off() {
            assert!(task.await.unwrap_err().is_cancelled());
        }
        assert_eq!(status()["on"], false);
        assert_eq!(mac("52:54:+0:aa:bb:cc"), None);
    }
}
