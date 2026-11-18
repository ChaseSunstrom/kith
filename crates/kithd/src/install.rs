//! Installing kith OS on a machine's disk (PLAN §4.9). The installer is kith OS started
//! with `kith.install` on its kernel command line (only the installer image's kernel image
//! has it, see os/build.sh): kithd, as the first process, serves nothing and instead
//!
//! 1. lists the machine's disks, never the one it was started from;
//! 2. takes answers: from the URL after `kith.install=` (over plain http only with its
//!    SHA-256 pinned in the fragment), else from `kith-install.yaml` on the installer's
//!    ESP, else from whoever sits at the console;
//! 3. copies the image the installer carries (its `payload` partition) to the chosen
//!    disk, reads it back, and writes what it was told of the node (hostname, address,
//!    kithd's arguments) into the new disk's `config` partition, which `init` reads at
//!    every start;
//! 4. powers the machine off.
//!
//! Where a machine cannot be started from a stick (a rented one), os/vps.sh starts the
//! same thing from the system that runs there, with the image and the answers in the
//! kernel's memory disk; the machine then restarts into what was installed.
//!
//! Everything on the chosen disk is lost. Without a person there, a disk is only chosen
//! by name, or as `only` when the machine has exactly one that is not removable.
//
// The image is copied as it is: its state partition is as small as the image's, and the
// spare partition table sits where the image ended, until the node's first start from
// the disk, which makes both right (`gpt`).

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;

/// A disk the machine has.
#[derive(Debug, Clone, PartialEq)]
pub struct Disk {
    pub name: String,
    pub bytes: u64,
    pub model: String,
    /// What the disk itself says it is (empty when it says nothing): the same at every
    /// start, where `name` is the order the kernel found the disks in.
    pub serial: String,
    /// A stick or a card reader (`removable` in sysfs): never the disk `only` means.
    pub removable: bool,
}

impl std::fmt::Display for Disk {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let size = self.bytes as f64 / 1e9;
        write!(f, "{} ({size:.1} GB", self.name)?;
        if !self.model.is_empty() {
            write!(f, ", {}", self.model)?;
        }
        if !self.serial.is_empty() {
            write!(f, ", serial {}", self.serial)?;
        }
        write!(f, ")")
    }
}

/// The disks under `sys` (`/sys/block`) that could be installed on: whole disks that can
/// be written, and not `booted`, the one this system runs from.
pub fn disks(sys: &Path, booted: Option<&str>) -> Vec<Disk> {
    let said = |disk: &Path, file: &str| {
        std::fs::read_to_string(disk.join(file))
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let mut found: Vec<Disk> = std::fs::read_dir(sys)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            // (Not disks: loop and RAM devices, device-mapper's, CD drives, floppies.)
            let other = ["loop", "ram", "zram", "dm-", "sr", "fd", "md", "nbd"];
            let bytes = said(&entry.path(), "size").parse::<u64>().ok()? * 512;
            let usable = bytes > 0 && said(&entry.path(), "ro") != "1";
            (usable && Some(&*name) != booted && !other.iter().any(|kind| name.starts_with(kind))).then(|| Disk {
                model: said(&entry.path(), "device/model"),
                serial: serial(&entry.path()),
                removable: said(&entry.path(), "removable") == "1",
                name,
                bytes,
            })
        })
        .collect();
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

/// The serial a disk under `/sys/block` says: an NVMe namespace's controller's, a VirtIO
/// block disk's own, or a SCSI or SATA disk's page 0x80 (four bytes of header, then the
/// serial). Only printable ASCII is kept: it is shown, and matched against what was typed.
fn serial(disk: &Path) -> String {
    let page = || {
        let page = std::fs::read(disk.join("device/vpd_pg80")).ok()?;
        let length = usize::from(*page.get(3)?);
        Some(String::from_utf8_lossy(page.get(4..4 + length).unwrap_or(&page[4..])).into_owned())
    };
    let said = ["device/serial", "serial"]
        .iter()
        .find_map(|file| std::fs::read_to_string(disk.join(file)).ok())
        .or_else(page)
        .unwrap_or_default();
    // (Kept bytes first, then trimmed: a page padded "ABC \0" is the serial "ABC".)
    let kept: String = said.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').collect();
    kept.trim().to_string()
}

/// The one disk that gives `serial` (after `serial:`), or why none is.
fn by_serial<'a>(serial: &str, disks: &'a [Disk]) -> Result<&'a Disk, String> {
    let serial = serial.trim();
    if serial.is_empty() {
        return Err("`disk: serial:` names no serial".into());
    }
    let listed = || disks.iter().map(Disk::to_string).collect::<Vec<_>>().join(", ");
    let found: Vec<&Disk> = disks.iter().filter(|disk| disk.serial == serial).collect();
    match found.as_slice() {
        [one] => Ok(one),
        [] if disks.is_empty() => Err("this machine has no disk to install on".into()),
        [] => Err(format!(
            "no disk with serial {serial} to install on; there is: {}",
            listed()
        )),
        // (Cheap USB bridges, and an NVMe drive's namespaces, give several disks one serial:
        // then it names none of them.)
        several => {
            let names: Vec<&str> = several.iter().map(|disk| disk.name.as_str()).collect();
            Err(format!(
                "{} disks give serial {serial}: {}. Name the disk",
                several.len(),
                names.join(", ")
            ))
        }
    }
}

/// Whether `disk` is still the size it was planned at, as `sys` (`/sys/block`) says now. A
/// disk swapped, or a card pulled, since the plan is not the one that was chosen.
pub fn size_unchanged(sys: &Path, disk: &Disk) -> Result<(), String> {
    let now = std::fs::read_to_string(sys.join(&disk.name).join("size"))
        .ok()
        .and_then(|sectors| sectors.trim().parse::<u64>().ok())
        .and_then(|sectors| sectors.checked_mul(512));
    // (A disk named by serial is asked for it again: another disk of its size could have
    // taken its name since.)
    if !disk.serial.is_empty() {
        let serial_now = serial(&sys.join(&disk.name));
        if serial_now != disk.serial {
            return Err(format!(
                "{disk} gives serial {serial_now:?} now, not {}: nothing was written",
                disk.serial
            ));
        }
    }
    match now {
        Some(bytes) if bytes == disk.bytes => Ok(()),
        Some(bytes) => Err(format!(
            "{disk} changed size since it was planned: it held {} bytes, and holds {bytes} now: nothing was written",
            disk.bytes
        )),
        None => Err(format!("{disk}'s size can no longer be read: nothing was written")),
    }
}

/// What the installer is told.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Answers {
    /// The disk's name (`sda`, `nvme0n1`); `serial:X`, the disk that says it is X, whatever
    /// the kernel named it; or `only`: the one disk the machine has that is not removable.
    pub disk: String,
    #[serde(default)]
    pub hostname: Option<String>,
    /// `10.0.0.5/24` or `10.0.0.5/24,10.0.0.1` (with the way out); without, the network is asked.
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub dns: Option<String>,
    /// How many bytes the disk holds, where its name was looked up under another kernel
    /// (os/vps.sh): a disk of that name and another size is not the one that was meant.
    #[serde(default)]
    pub size: Option<u64>,
    /// Join this cluster; without, the node starts a new one.
    #[serde(default)]
    pub join: Option<Join>,
    /// Keep the node's state encrypted, its key held by its cluster (see crypt.rs).
    #[serde(default)]
    pub encrypt: bool,
    /// The keys (hex, with commas between) the node takes kith OS releases from: over the
    /// ones its image was built with, and without either it takes the first release's.
    #[serde(default, rename = "releaseKey")]
    pub release_key: Option<String>,
    /// Fetch kith OS updates from the private ranges of the node's networks too (a release
    /// server on the LAN).
    #[serde(default, rename = "lanReleases")]
    pub lan_releases: bool,
    /// What the cluster may have this node do as its root: `hardened`, or the words of
    /// `--node-policy` with commas between (policy.rs). Without, everything, as before.
    #[serde(default, rename = "nodePolicy")]
    pub node_policy: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Join {
    pub address: String,
    pub token: String,
}

/// The image, where the installer runs from memory (os/build.sh puts it there).
const CARRIED: &str = "/payload";

static IN_MEMORY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The port a node's kithd serves other nodes and its admins on.
const PORT: u16 = 7443;

/// Which disk, and the node's config (more of its kernel command line, see `init`), or
/// why not. `room` is how long a config may be.
pub fn plan(answers: &Answers, disks: &[Disk], image: u64, room: u64) -> Result<(Disk, String), String> {
    let listed = || disks.iter().map(Disk::to_string).collect::<Vec<_>>().join(", ");
    let wanted = answers.disk.trim().trim_start_matches("/dev/");
    let disk = match wanted {
        // (A removable disk is never the one `only` means: a stick or a card reader that
        // enumerates before the machine's own disk is not that disk. Named, it is used.)
        "only" => {
            let fixed: Vec<&Disk> = disks.iter().filter(|disk| !disk.removable).collect();
            match fixed.as_slice() {
                [one] => *one,
                [] if disks.is_empty() => return Err("this machine has no disk to install on".into()),
                [] => {
                    return Err(format!(
                        "`disk: only` and this machine has no disk but removable ones: {}. Name the disk to use it",
                        listed()
                    ));
                }
                _ => return Err(format!("`disk: only` and this machine has several: {}", listed())),
            }
        }
        serial if serial.starts_with("serial:") => by_serial(&serial["serial:".len()..], disks)?,
        name => disks.iter().find(|disk| disk.name == name).ok_or_else(|| match disks {
            [] => format!("no disk {name}: this machine has no disk to install on"),
            _ => format!("no disk {name} to install on; there is: {}", listed()),
        })?,
    };
    if let Some(size) = answers.size.filter(|size| *size != disk.bytes) {
        return Err(format!(
            "{disk} is not the disk that was named: that one held {size} bytes. This kernel names the disks otherwise"
        ));
    }
    if disk.bytes < image {
        return Err(format!(
            "{disk} is smaller than kith OS ({} MB)",
            image.div_ceil(1 << 20)
        ));
    }
    // Each answer becomes a word of the node's command line: read back by the same
    // parser, so what it would not understand is refused here, where someone can see it.
    let mut words = Vec::new();
    for (key, value) in [
        ("kith.hostname", &answers.hostname),
        ("kith.ip", &answers.ip),
        ("kith.dns", &answers.dns),
    ] {
        let Some(value) = value.as_deref().map(str::trim).filter(|value| !value.is_empty()) else {
            continue;
        };
        let word = format!("{key}={value}");
        let (_, unknown) = crate::init::options(&word);
        if !unknown.is_empty() || word.contains(char::is_whitespace) {
            return Err(format!("`{value}` is not a {}", &key[5..]));
        }
        words.push(word);
    }
    words.push(format!("-- --listen 0.0.0.0:{PORT}"));
    // (An empty ip is none, not `--advertise :7443`.)
    let address = answers
        .ip
        .as_deref()
        .and_then(|ip| ip.trim().split('/').next())
        .filter(|a| !a.is_empty());
    if let Some(address) = address {
        let ip: std::net::Ipv4Addr = address
            .parse()
            .map_err(|_| format!("`{address}` in ip is not an IP address"))?;
        words.push(format!("--advertise {ip}:{PORT}"));
    }
    if let Some(keys) = &answers.release_key {
        let keys: Vec<&str> = keys.split(',').map(str::trim).collect();
        let key = |key: &&str| key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit());
        if keys.len() > 8 || !keys.iter().all(key) {
            return Err("`releaseKey` is 1 to 8 keys of 64 hex digits, with commas between".into());
        }
        words.push(format!("--release-key {}", keys.join(",")));
    }
    if answers.lan_releases {
        words.push("--lan-releases".into());
    }
    // (Read here by the parser kithd reads it with: a word it does not know is refused now,
    // not at the node's first start, where it would run hardened and say so to nobody.)
    let policy: String = answers
        .node_policy
        .iter()
        .flat_map(|policy| policy.split_whitespace())
        .collect();
    if !policy.is_empty() {
        let said = policy.parse::<crate::policy::Policy>();
        said.map_err(|e| e.replace("--node-policy", "`nodePolicy`"))?;
        words.push(format!("--node-policy {policy}"));
    }
    match &answers.join {
        Some(join) => {
            let plain = |text: &str, more: &str| {
                !text.is_empty() && text.chars().all(|c| c.is_ascii_alphanumeric() || more.contains(c))
            };
            let (address, token) = (join.address.trim(), join.token.trim());
            if !plain(address, ".-:[]") || !address.contains(':') || address.starts_with('-') {
                return Err(format!("`{address}` is not a node's address: ADDRESS:PORT"));
            }
            // A token ends in the name of the node that made it, which may hold `-`.
            if !plain(token, ".-") || token.starts_with('-') {
                return Err("the join token is not one: `kith node token` on the cluster makes them".into());
            }
            words.push(format!("--join {address} --token {token}"));
        }
        // (Nobody can log in to a kith OS node: its first admin is made over TLS.)
        None => words.push("--claim".into()),
    }
    let config = words.join(" ");
    if config.len() as u64 >= room {
        return Err("the answers are longer than the node's config partition".into());
    }
    Ok((disk.clone(), config))
}

/// Ask whoever is at the console. `ask` prints a question and reads a line.
pub fn interview(disks: &[Disk], mut ask: impl FnMut(&str) -> String) -> Result<Answers, String> {
    if disks.is_empty() {
        return Err("this machine has no disk to install on".into());
    }
    let listed: Vec<String> = disks.iter().map(|disk| format!("  {disk}\n")).collect();
    let some = |answer: String| Some(answer).filter(|answer| !answer.is_empty());
    let disk = ask(&format!(
        "This machine's disks:\n{}Install kith OS on which (its name, or serial:X)?",
        listed.concat()
    ));
    let chosen = match disk.strip_prefix("serial:") {
        Some(serial) => by_serial(serial, disks)?,
        None => disks
            .iter()
            .find(|found| found.name == disk)
            .ok_or(format!("there is no disk `{disk}` here"))?,
    };
    let hostname = some(ask(
        "The node's name (empty: one made from its network card's address)?",
    ));
    let ip = some(ask("Its address, as 10.0.0.5/24,10.0.0.1 (empty: ask the network)?"));
    let address = some(ask(
        "Join a cluster? The address of one of its nodes, as 10.0.0.7:7443 (empty: start a new cluster)",
    ));
    let join = address.map(|address| Join {
        address,
        token: ask("The join token (`kith node token` there)?"),
    });
    let encrypt = ask("Keep its state encrypted, the key held by its cluster (yes, or empty: no)?") == "yes";
    let again = ask(&format!(
        "Everything on {chosen} will be erased. Type its name again to go on:"
    ));
    if again != disk && again != chosen.name {
        return Err(format!("`{again}` is not `{disk}`: nothing was written"));
    }
    Ok(Answers {
        disk,
        hostname,
        ip,
        dns: None,
        size: None,
        join,
        encrypt,
        ..Answers::default()
    })
}

/// In the disk image `image` (GPT): how long it is, and where its partition named
/// `config` is and how long.
pub fn layout(image: &File) -> Result<(u64, u64, u64), String> {
    found(image, "config")
}

/// Where the image's partition `name` is, and how long.
pub fn named(image: &File, name: &str) -> Result<(u64, u64), String> {
    found(image, name).map(|(_, at, length)| (at, length))
}

fn found(image: &File, wanted: &str) -> Result<(u64, u64, u64), String> {
    let bad = |what: &str| format!("the image the installer carries is not one: {what}");
    let mut header = [0; 92];
    image.read_exact_at(&mut header, 512).map_err(|e| bad(&e.to_string()))?;
    let u64_at = |bytes: &[u8], at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"));
    let u32_at = |bytes: &[u8], at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"));
    if &header[..8] != b"EFI PART" {
        return Err(bad("no partition table"));
    }
    // (Its spare header is its last sector.)
    let length = (u64_at(&header, 32) + 1) * 512;
    let (entries, count, size) = (
        u64_at(&header, 72) * 512,
        u32_at(&header, 80),
        u32_at(&header, 84) as usize,
    );
    if !(128..=4096).contains(&size) || count > 1024 {
        return Err(bad("its partition table is damaged"));
    }
    let mut entry = vec![0; size];
    for index in 0..u64::from(count) {
        image
            .read_exact_at(&mut entry, entries + index * size as u64)
            .map_err(|e| bad(&e.to_string()))?;
        let name: Vec<u16> = entry[56..128]
            .chunks(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let name = String::from_utf16_lossy(&name);
        if name.trim_end_matches('\0') == wanted {
            let (first, last) = (u64_at(&entry, 32), u64_at(&entry, 40));
            if first == 0 || last < first || (last + 1) * 512 > length {
                return Err(bad(&format!("its {wanted} partition is not inside it")));
            }
            return Ok((length, first * 512, (last + 1 - first) * 512));
        }
    }
    Err(bad(&format!("no partition named {wanted}")))
}

/// Copy the image to the disk, read it back, and write the node's config. `said` is told
/// how far it is, in tenths.
pub fn write(image: &mut File, disk: &mut File, config: &str, mut said: impl FnMut(u64)) -> Result<(), String> {
    use ring::digest::{Context, SHA256};
    let (length, at, room) = layout(image)?;
    if config.len() as u64 >= room {
        return Err("the answers are longer than the node's config partition".into());
    }
    let io = |what: &'static str| move |e: std::io::Error| format!("{what}: {e}");
    image.seek(SeekFrom::Start(0)).map_err(io("reading the image"))?;
    disk.seek(SeekFrom::Start(0)).map_err(io("writing the disk"))?;
    let (mut block, mut copied, mut wrote) = (vec![0; 1 << 20], 0, Context::new(&SHA256));
    while copied < length {
        let some = block.len().min((length - copied) as usize);
        image.read_exact(&mut block[..some]).map_err(io("reading the image"))?;
        disk.write_all(&block[..some]).map_err(io("writing the disk"))?;
        wrote.update(&block[..some]);
        if (copied + some as u64) * 10 / length > copied * 10 / length {
            said((copied + some as u64) * 10 / length);
        }
        copied += some as u64;
    }
    disk.sync_all().map_err(io("writing the disk"))?;
    // Read back from the disk and not from memory: what the kernel still holds of it is let go first.
    let _ = nix::fcntl::posix_fadvise(
        std::os::fd::AsRawFd::as_raw_fd(&*disk),
        0,
        0,
        nix::fcntl::PosixFadviseAdvice::POSIX_FADV_DONTNEED,
    );
    disk.seek(SeekFrom::Start(0)).map_err(io("reading the disk back"))?;
    let (mut read, mut left) = (Context::new(&SHA256), length);
    while left > 0 {
        let some = block.len().min(left as usize);
        disk.read_exact(&mut block[..some])
            .map_err(io("reading the disk back"))?;
        read.update(&block[..some]);
        left -= some as u64;
    }
    if read.finish().as_ref() != wrote.finish().as_ref() {
        return Err(
            "what the disk gives back is not what was written to it: the disk is bad, or something else writes to it"
                .into(),
        );
    }
    zero_after(disk, length, &mut block).map_err(io("clearing the disk past kith OS"))?;
    // (To its end: a config from an install before this one would otherwise show through.)
    let mut text = config.as_bytes().to_vec();
    text.resize(room.min(64 << 10) as usize, 0);
    disk.write_all_at(&text, at).map_err(io("writing the node's config"))?;
    disk.sync_all().map_err(io("writing the node's config"))?;
    let mut back = vec![0; text.len()];
    disk.read_exact_at(&mut back, at)
        .map_err(io("reading the node's config back"))?;
    (back == text)
        .then_some(())
        .ok_or("the node's config did not stay on the disk as written".into())
}

/// What a reused disk held past `from` (an older install's state, someone's files) made to
/// read as zeros, so the state partition grown over it later shows none of it. The disk
/// clears the range itself where it can (unmapped, then zeroed in place); else it is written.
fn zero_after(disk: &mut File, from: u64, block: &mut [u8]) -> std::io::Result<()> {
    use nix::fcntl::{FallocateFlags as F, fallocate};
    let end = disk.seek(SeekFrom::End(0))?;
    let Some(len) = end.checked_sub(from).filter(|len| *len > 0) else {
        return Ok(());
    };
    let (at, len) = (from as i64, len as i64);
    let cleared = [
        F::FALLOC_FL_PUNCH_HOLE | F::FALLOC_FL_KEEP_SIZE,
        F::FALLOC_FL_ZERO_RANGE,
    ]
    .into_iter()
    .any(|how| fallocate(std::os::fd::AsRawFd::as_raw_fd(&*disk), how, at, len).is_ok());
    if !cleared {
        block.fill(0);
        let mut at = from;
        while at < end {
            let some = block.len().min((end - at) as usize);
            disk.write_all_at(&block[..some], at)?;
            at += some as u64;
        }
    }
    disk.sync_all()
}

/// The answers file as YAML.
pub fn answers(yaml: &str) -> Result<Answers, String> {
    kith_yaml::from_str(yaml).map_err(|e| e.render("kith-install.yaml", yaml))
}

/// One line from whoever types at any of the machine's consoles (a screen's keyboard, a
/// serial line): the kernel hands its first process only the last console named.
pub fn keyboard() -> std::sync::mpsc::Receiver<String> {
    let (lines, typed) = std::sync::mpsc::channel();
    let active = std::fs::read_to_string("/sys/class/tty/console/active").unwrap_or_default();
    for name in active.split_whitespace() {
        let (Ok(console), lines) = (File::open(format!("/dev/{name}")), lines.clone()) else {
            continue;
        };
        std::thread::spawn(move || lines_of(std::io::BufReader::new(console), &lines));
    }
    typed
}

/// Each line read from `console` to `lines`, until it ends or nobody listens. A line is read
/// 4 KiB at most at a time: one longer (a serial line's noise, no newline) comes in pieces.
fn lines_of(mut console: impl std::io::BufRead, lines: &std::sync::mpsc::Sender<String>) {
    use std::io::{BufRead, Read};
    let mut line = Vec::new();
    // (Bytes that are no text are typed too, on a serial line: they end nothing.)
    while (&mut console)
        .take(4096)
        .read_until(b'\n', &mut line)
        .is_ok_and(|read| read > 0)
    {
        if lines.send(String::from_utf8_lossy(&line).trim().to_string()).is_err() {
            return;
        }
        // (What was typed may be a PIN or a passphrase: no copy outlives its use.)
        zeroize::Zeroize::zeroize(&mut line);
    }
}

/// Nothing more is done, and the machine stays as it is for someone to read why.
async fn stop(why: &str) -> ! {
    eprintln!("kithd: install: nothing was installed: {why}");
    // Nobody sits at a machine installed from its own memory, and its way in went with the
    // system that ran: started again, that system is back if its disk was not written yet.
    if IN_MEMORY.load(std::sync::atomic::Ordering::Relaxed) {
        eprintln!(
            "kithd: install: starting the machine again: what its disk held starts, unless the disk was being written"
        );
        crate::init::end(true)
    }
    eprintln!("kithd: install: power the machine off, or press Ctrl-Alt-Del to start it again");
    std::future::pending().await
}

/// The disk opened for writing: refused while anything of it is mounted or held.
fn exclusive(device: &Path) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::fcntl::OFlag::O_EXCL.bits())
        .open(device)
        .map_err(|e| format!("{}: {e}", device.display()))
}

/// Clears both partition tables of an open disk, so nothing on it is found to boot from.
fn clear_table(disk: &mut File) -> Result<(), String> {
    // (The size of a block device is its end, which a file's length is not.)
    let sectors = disk.seek(SeekFrom::End(0)).map_err(|e| e.to_string())? / 512;
    crate::gpt::clear(disk, sectors)
}

/// Seals the written disk. A seal that fails leaves a disk that boots unencrypted, so its tables are cleared.
fn sealed(
    image: &File,
    device: &Path,
    seal: impl FnOnce(&File, &Path) -> Result<String, String>,
) -> Result<String, String> {
    seal(image, device).map_err(
        |e| match exclusive(device).and_then(|mut disk| clear_table(&mut disk)) {
            Ok(()) => format!("{e}: its partition table was cleared, so it boots nothing"),
            Err(c) => format!("{e}: clearing its partition table failed too ({c}), so it may boot unencrypted"),
        },
    )
}

/// Install mode, start to end. `source` is the URL of the answers, or empty.
pub async fn run(source: String) -> ! {
    eprintln!("kithd: install: this is the kith OS installer: it erases a disk of this machine and puts kith OS on it");
    // Started from a stick, the image is a partition of it. Started in place of a running
    // system (os/vps.sh), all there is is in memory: the image and the answers are files.
    let memory = Path::new(CARRIED).exists();
    IN_MEMORY.store(memory, std::sync::atomic::Ordering::Relaxed);
    let payload = match crate::init::labelled("payload").filter(|_| !memory) {
        Some(partition) => partition,
        None if memory => CARRIED.into(),
        None => stop("this installer carries no image (no partition named payload)").await,
    };
    let image = match File::open(&payload)
        .map_err(|e| e.to_string())
        .and_then(|image| Ok((layout(&image)?, image)))
    {
        Ok(image) => image,
        Err(e) => stop(&e).await,
    };
    let ((length, _, room), mut image) = image;
    // A machine's disks take a moment to be there, and one that is late must not make
    // another "the only one": the list is taken once it has stood still for two seconds.
    // ponytail: half a minute of looking at most, not an event from the kernel.
    let look = || disks(Path::new("/sys/block"), crate::init::booted().as_deref());
    let (mut found, mut still) = (look(), 0);
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let now = look();
        still = if now == found { still + 1 } else { 0 };
        found = now;
        if still == 4 {
            break;
        }
    }
    // Answers from a URL or from the stick mean nobody is asked anything.
    let file = match memory {
        // (A file of comments says nothing: the network boot file before a node has
        // written a machine's answers into it, see os/build.sh. Then someone is asked.)
        true => Ok(std::fs::read_to_string("/kith-install.yaml").ok().filter(|yaml| {
            yaml.lines()
                .any(|line| !line.trim_start().starts_with('#') && !line.trim().is_empty())
        })),
        false => crate::os::esp(|esp| std::fs::read_to_string(esp.join("../../kith-install.yaml")).ok()),
    };
    let given = if source.is_empty() {
        file.ok().flatten().map(Ok)
    } else {
        Some(fetched(&source).await)
    };
    let typed = std::sync::Arc::new(std::sync::Mutex::new(keyboard()));
    let ((disk, config), encrypt) = loop {
        let told = match &given {
            Some(Ok(yaml)) => answers(yaml),
            Some(Err(e)) => Err(e.clone()),
            None => {
                // Off the runtime's one thread: a signal is still heard while a question waits.
                let (disks, typed) = (found.clone(), typed.clone());
                let asked = tokio::task::spawn_blocking(move || {
                    let typed = typed.lock().expect("nothing panics holding the keyboard");
                    let mut gone = false;
                    let told = interview(&disks, |question| {
                        eprintln!("\n{question}");
                        typed.recv().unwrap_or_else(|_| {
                            gone = true;
                            String::new()
                        })
                    });
                    (told, gone)
                });
                match asked.await {
                    Ok((_, true)) | Err(_) => stop("no console here can be typed at, and no answers were given").await,
                    Ok((told, false)) => told,
                }
            }
        };
        match told.and_then(|told| Ok((plan(&told, &found, length, room)?, told.encrypt))) {
            Ok(planned) => break planned,
            Err(e) if given.is_some() || found.is_empty() => stop(&e).await,
            Err(e) => eprintln!("kithd: install: {e}\nkithd: install: once more."),
        }
    };
    // (Not the join token: a console is read by more people than a disk.)
    let shown = config.split(" --token ").next().unwrap_or_default();
    eprintln!("kithd: install: writing kith OS to {disk}; its node will start with: {shown}");
    let device = Path::new("/dev").join(&disk.name);
    let planned = disk.clone();
    let wrote = tokio::task::spawn_blocking(move || {
        // (Its size read again just before the open: a disk swapped since the plan is not the one chosen.)
        size_unchanged(Path::new("/sys/block"), &planned)?;
        let mut disk = exclusive(&device)?;
        if let Err(e) = write(&mut image, &mut disk, &config, |tenths| {
            eprintln!("kithd: install: {}%", tenths * 10)
        }) {
            // (Written from here on: the image may be partly on the disk, so its tables go too.)
            eprintln!("kithd: install: {planned} may hold part of kith OS now and nothing of what it held before");
            return Err(match clear_table(&mut disk) {
                Ok(()) => format!("{e}: its partition table was cleared"),
                Err(c) => format!("{e}; clearing its partition table failed too ({c})"),
            });
        }
        // (The disk let go of first: the kernel takes it for the mapping.)
        drop(disk);
        encrypt.then(|| sealed(&image, &device, crate::crypt::seal)).transpose()
    });
    // (A panic may come after the write began, so it is said the same way.)
    let wrote = match wrote.await {
        Ok(wrote) => wrote,
        Err(e) => {
            eprintln!("kithd: install: {disk} may hold part of kith OS now and nothing of what it held before");
            stop(&e.to_string()).await
        }
    };
    match wrote {
        Ok(recovery) => {
            if let Some(recovery) = recovery {
                eprintln!(
                    "kithd: install: the node's state is encrypted. Its recovery key opens it where no cluster answers, and is shown this once: {recovery}"
                );
            }
            // (Nothing to take out of a machine installed from its own memory: it starts at once.)
            let then = if memory {
                "Starting it."
            } else {
                "Take the installer out and start the machine."
            };
            eprintln!("kithd: install: kith OS is on {disk}. {then}");
            crate::init::POWER_OFF.store(!memory, std::sync::atomic::Ordering::Relaxed);
            crate::init::end(false)
        }
        Err(e) => stop(&e).await,
    }
}

/// The pin in a URL of answers: `#sha256=` and the SHA-256 of the answers, 64 hex digits in
/// either case. Returns the address to fetch (the URL before its fragment) and the pin in
/// lower case. Plain http needs a pin: anyone on its path could change the answers.
fn pinned(url: &str) -> Result<(&str, Option<String>), String> {
    let (address, fragment) = match url.split_once('#') {
        Some((address, fragment)) => (address, Some(fragment)),
        None => (url, None),
    };
    if !address.starts_with("http://") && !address.starts_with("https://") {
        return Err(format!("{address} is not an http or https address"));
    }
    let pin = match fragment {
        Some(fragment) => {
            let digest = fragment
                .strip_prefix("sha256=")
                .filter(|digest| digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()));
            Some(
                digest
                    .ok_or_else(|| format!("the pin of {address} is not `#sha256=` and 64 hex digits"))?
                    .to_ascii_lowercase(),
            )
        }
        None if address.starts_with("http://") => {
            return Err(format!(
                "{address} is plain http with no pin: add `#sha256=` and the answers' digest (`sha256sum FILE`), or use https"
            ));
        }
        None => None,
    };
    Ok((address, pin))
}

/// The answers must be the ones pinned: a refusal names both digests.
fn verified(pin: &str, answers: &[u8]) -> Result<(), String> {
    let got = crate::pki::hex(&Sha256::digest(answers));
    if got == pin {
        return Ok(());
    }
    Err(format!(
        "the answers hash to {got}, not the {pin} their URL pins: refused"
    ))
}

/// The answers at `url`. The network may take a moment to be there.
/// Whether a redirect to an address of `scheme`, after `hops` of them, is followed: to https
/// always, to plain http only for pinned answers (the pin covers what comes), and never past five.
fn followed(scheme: &str, hops: usize, pinned: bool) -> Result<(), &'static str> {
    match scheme {
        _ if hops >= 5 => Err("too many redirects"),
        "https" => Ok(()),
        "http" if pinned => Ok(()),
        _ => Err("an https address that sends its answers elsewhere than https: refused"),
    }
}

async fn fetched(url: &str) -> Result<String, String> {
    // (Refused before any connection: an unpinned http answer is never fetched.)
    let (address, pin) = pinned(url)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    // (A redirect is followed only where the answers stay as safe as asked: unpinned https
    // answers never come from plain http, and none come after more than a few hops.)
    let pinned_answers = pin.is_some();
    let redirect = reqwest::redirect::Policy::custom(move |attempt| {
        match followed(attempt.url().scheme(), attempt.previous().len(), pinned_answers) {
            Ok(()) => attempt.follow(),
            Err(why) => attempt.error(why),
        }
    });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .redirect(redirect)
        .build();
    let client = client.map_err(|e| e.to_string())?;
    let mut last = String::new();
    for _ in 0..12 {
        // (No more of it is taken than answers can be: this machine has only its memory.)
        let got = async {
            let mut from = client.get(address).send().await?.error_for_status()?;
            let mut text = Vec::new();
            while let Some(more) = from.chunk().await? {
                text.extend_from_slice(&more);
                if text.len() > 64 << 10 {
                    break;
                }
            }
            Ok::<_, reqwest::Error>(text)
        };
        match got.await {
            Ok(text) if text.len() <= 64 << 10 => {
                // (Checked as they came, before any text is made of them; a changed answer is refused, not asked for again.)
                if let Some(pin) = &pin {
                    verified(pin, &text)?;
                }
                return Ok(String::from_utf8_lossy(&text).into_owned());
            }
            Ok(_) => return Err(format!("{address} is too long to be answers")),
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    Err(format!("no answers from {address}: {last}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A console that sends no newline (a serial line's noise) comes in pieces of at most
    /// 4 KiB: what one line holds is bounded. A short line comes whole.
    #[test]
    fn install_keyboard_a_line_is_read_at_most_4_kib_at_a_time() {
        let mut sent = vec![b'x'; 10_000];
        sent.extend_from_slice(b"\n1234\n");
        let (lines, typed_in) = std::sync::mpsc::channel();
        lines_of(&sent[..], &lines);
        drop(lines);
        let got: Vec<String> = typed_in.iter().collect();
        assert!(
            got.iter().all(|piece| piece.len() <= 4096),
            "{:?}",
            got.iter().map(String::len).collect::<Vec<_>>()
        );
        assert_eq!(got.iter().map(String::len).sum::<usize>(), 10_004);
        assert_eq!(got.last().map(String::as_str), Some("1234"));
    }

    fn disk(name: &str, gigabytes: u64) -> Disk {
        Disk {
            name: name.into(),
            bytes: gigabytes * 1_000_000_000,
            model: "Test".into(),
            serial: String::new(),
            removable: false,
        }
    }

    #[test]
    fn install_lists_disks_but_never_the_one_it_runs_from() {
        let sys = std::env::temp_dir().join(format!("kith-install-sys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sys);
        for (name, size, ro) in [
            ("sda", "2048", "0"),
            ("vda", "4096", "0"),
            ("loop0", "8", "0"),
            ("sr0", "8", "0"),
        ] {
            std::fs::create_dir_all(sys.join(name).join("device")).unwrap();
            std::fs::write(sys.join(name).join("size"), size).unwrap();
            std::fs::write(sys.join(name).join("ro"), ro).unwrap();
        }
        std::fs::write(sys.join("sda/device/model"), "Stick \n").unwrap();
        for (name, size, ro) in [("sdb", "0", "0"), ("sdc", "64", "1")] {
            std::fs::create_dir_all(sys.join(name)).unwrap();
            std::fs::write(sys.join(name).join("size"), size).unwrap();
            std::fs::write(sys.join(name).join("ro"), ro).unwrap();
        }
        let names = |booted| {
            disks(&sys, booted)
                .into_iter()
                .map(|disk| disk.name)
                .collect::<Vec<_>>()
        };
        // Not loop devices or CD drives, not an empty card reader, not what cannot be written.
        assert_eq!(names(None), ["sda", "vda"]);
        assert_eq!(names(Some("sda")), ["vda"]);
        assert_eq!(disks(&sys, None)[0].to_string(), "sda (0.0 GB, Stick)");
        std::fs::remove_dir_all(&sys).unwrap();
    }

    #[test]
    fn serial_names_a_disk_whatever_the_kernel_calls_it() {
        let sys = std::env::temp_dir().join(format!("kith-install-serial-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sys);
        for name in ["nvme0n1", "vda", "sda", "sdb"] {
            std::fs::create_dir_all(sys.join(name).join("device")).unwrap();
            std::fs::write(sys.join(name).join("size"), "2048").unwrap();
        }
        // Where each says it: NVMe its controller, VirtIO's block disk itself, a SCSI or
        // SATA disk its page 0x80 (four bytes of header, then the serial, padded).
        std::fs::write(sys.join("nvme0n1/device/serial"), "S4EW0001      \n").unwrap();
        std::fs::write(sys.join("vda/serial"), "vd-two").unwrap();
        std::fs::write(sys.join("sda/device/vpd_pg80"), b"\0\x80\0\x0cSCSI-ONE  \0\0").unwrap();
        let found = disks(&sys, None);
        std::fs::remove_dir_all(&sys).unwrap();
        let serials: Vec<_> = found.iter().map(|d| (d.name.as_str(), d.serial.as_str())).collect();
        assert_eq!(
            serials,
            [
                ("nvme0n1", "S4EW0001"),
                ("sda", "SCSI-ONE"),
                ("sdb", ""),
                ("vda", "vd-two")
            ]
        );
        assert_eq!(found[1].to_string(), "sda (0.0 GB, serial SCSI-ONE)");
        assert_eq!(found[2].to_string(), "sdb (0.0 GB)");

        let pick = |wanted: &str, found: &[Disk]| {
            plan(
                &answers(&format!("disk: \"serial:{wanted}\"\n")).unwrap(),
                found,
                0,
                1 << 20,
            )
            .map(|(d, _)| d.name)
        };
        assert_eq!(pick("vd-two", &found).unwrap(), "vda");
        assert_eq!(pick("SCSI-ONE", &found).unwrap(), "sda");
        let none = pick("nope", &found).unwrap_err();
        assert!(
            none.contains("no disk with serial nope") && none.contains("vda (0.0 GB, serial vd-two)"),
            "{none}"
        );
        // A serial two disks give (cheap USB bridges do) names neither.
        let mut twice = found.clone();
        twice[2].serial = "SCSI-ONE".into();
        let both = pick("SCSI-ONE", &twice).unwrap_err();
        assert!(
            both.contains("2 disks give serial SCSI-ONE: sda") && both.contains("sdb"),
            "{both}"
        );
        assert!(pick("", &found).unwrap_err().contains("serial:"));
    }

    #[test]
    fn only_never_picks_a_removable_disk() {
        let sys = std::env::temp_dir().join(format!("kith-install-removable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sys);
        // A stick seen first (sda), then the machine's own disk (sdb), then a card reader (sdc).
        for (name, size, removable) in [
            ("sda", "2000000000", "1"),
            ("sdb", "4000000000", "0"),
            ("sdc", "128000000", "1"),
        ] {
            std::fs::create_dir_all(sys.join(name).join("device")).unwrap();
            std::fs::write(sys.join(name).join("size"), size).unwrap();
            std::fs::write(sys.join(name).join("ro"), "0").unwrap();
            std::fs::write(sys.join(name).join("removable"), removable).unwrap();
        }
        let only = |found: &[Disk]| plan(&answers("disk: only\n").unwrap(), found, 300 << 20, 1 << 20);
        // `only` is the one disk that is not removable, whichever of them enumerates first.
        let found = disks(&sys, None);
        assert_eq!(only(&found).unwrap().0.name, "sdb");
        // Named, a removable disk is still installed on: the name is the answer.
        let named = plan(&answers("disk: sda\n").unwrap(), &found, 300 << 20, 1 << 20).unwrap();
        assert_eq!(named.0.name, "sda");
        // A machine whose disks are all removable is refused, and the refusal names them.
        let removable_only = disks(&sys, Some("sdb"));
        let refused = only(&removable_only).unwrap_err();
        assert!(
            refused.contains("sda") && refused.contains("sdc") && refused.contains("removable"),
            "{refused}"
        );
        std::fs::remove_dir_all(&sys).unwrap();
    }

    #[test]
    fn a_disk_that_changed_size_is_not_written() {
        let sys = std::env::temp_dir().join(format!("kith-install-resized-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sys);
        std::fs::create_dir_all(sys.join("sdb")).unwrap();
        std::fs::write(sys.join("sdb/size"), "4000000000").unwrap();
        std::fs::write(sys.join("sdb/ro"), "0").unwrap();
        let planned = disks(&sys, None).remove(0);
        assert!(size_unchanged(&sys, &planned).is_ok());
        // Another disk under the same name (a card pulled, another put in): refused, both sizes said.
        std::fs::write(sys.join("sdb/size"), "30000000").unwrap();
        let why = size_unchanged(&sys, &planned).unwrap_err();
        assert!(
            why.contains(&planned.bytes.to_string()) && why.contains("15360000000"),
            "{why}"
        );
        assert!(why.contains("nothing was written"), "{why}");
        // A disk named by serial: another of the same size under its name is refused too.
        std::fs::write(sys.join("sdb/size"), "4000000000").unwrap();
        std::fs::write(sys.join("sdb/serial"), "ONE").unwrap();
        let planned = disks(&sys, None).remove(0);
        assert!(size_unchanged(&sys, &planned).is_ok());
        std::fs::write(sys.join("sdb/serial"), "TWO").unwrap();
        let why = size_unchanged(&sys, &planned).unwrap_err();
        assert!(why.contains("\"TWO\"") && why.contains("nothing was written"), "{why}");
        // A disk whose size can no longer be read is refused as well.
        std::fs::remove_dir_all(sys.join("sdb")).unwrap();
        assert!(size_unchanged(&sys, &planned).is_err());
        std::fs::remove_dir_all(&sys).unwrap();
    }

    /// An empty ip is no ip: no --advertise word (it was `--advertise :7443`); an ip whose
    /// address is not one is refused by name.
    #[test]
    fn an_empty_ip_gives_no_advertise_word_and_a_bad_one_is_refused() {
        let one = [disk("sda", 8)];
        let config = |yaml: &str| {
            let yaml = format!("disk: sda\n{yaml}");
            plan(&answers(&yaml).unwrap(), &one, 300 << 20, 1 << 20).map(|(_, c)| c)
        };
        for yaml in ["ip: \"\"\n", "ip: \"  \"\n", "hostname: alpha\n"] {
            let said = config(yaml).unwrap();
            assert!(!said.contains("--advertise"), "{yaml}: {said}");
        }
        let bad = config("ip: alpha/24\n").unwrap_err();
        assert!(bad.contains("ip"), "{bad}");
    }

    #[test]
    fn install_needs_a_disk_named_or_the_only_one() {
        let two = [disk("sda", 8), disk("nvme0n1", 256)];
        let told = |yaml: &str| answers(yaml).unwrap();
        let config = |yaml: &str, disks: &[Disk]| plan(&told(yaml), disks, 300 << 20, 1 << 20);
        let (on, config_new) = config(
            "disk: nvme0n1\nhostname: alpha\nip: 10.0.0.5/24,10.0.0.1\ndns: 9.9.9.9\n",
            &two,
        )
        .unwrap();
        assert_eq!(on.name, "nvme0n1");
        assert_eq!(
            config_new,
            "kith.hostname=alpha kith.ip=10.0.0.5/24,10.0.0.1 kith.dns=9.9.9.9 -- --listen 0.0.0.0:7443 --advertise 10.0.0.5:7443 --claim"
        );
        // The node reads it back as it was meant.
        let (read, args) = crate::init::configured(&config_new);
        assert_eq!(
            read,
            "kith.hostname=alpha kith.ip=10.0.0.5/24,10.0.0.1 kith.dns=9.9.9.9"
        );
        assert_eq!(
            args,
            ["--listen", "0.0.0.0:7443", "--advertise", "10.0.0.5:7443", "--claim"]
        );
        // A disk looked up under another kernel is the one of that size, or none.
        assert!(config("disk: sda\nsize: 8000000000\n", &two).is_ok());
        let other = config("disk: sda\nsize: 256000000000\n", &two).unwrap_err();
        assert!(other.contains("is not the disk that was named"), "{other}");
        let (_, joined) = config(
            "disk: /dev/sda\njoin: { address: 10.0.0.7:7443, token: kith1.ab.cd.ef.node-1 }\n", // pragma: allowlist secret
            &two,
        )
        .unwrap();
        assert_eq!(
            joined,
            "-- --listen 0.0.0.0:7443 --join 10.0.0.7:7443 --token kith1.ab.cd.ef.node-1" // pragma: allowlist secret
        );

        // `only` is for a machine with one disk; a name must be one that is there.
        assert_eq!(config("disk: only\n", &two[..1]).unwrap().0.name, "sda");
        assert!(config("disk: only\n", &two).unwrap_err().contains("several: sda (8.0"));
        assert!(
            config("disk: only\n", &[])
                .unwrap_err()
                .contains("no disk to install on")
        );
        assert!(
            config("disk: sdb\n", &two)
                .unwrap_err()
                .contains("no disk sdb to install on; there is: sda")
        );
        assert!(
            plan(&told("disk: sda\n"), &[disk("sda", 0)], 300 << 20, 1 << 20)
                .unwrap_err()
                .contains("smaller than kith OS (300 MB)")
        );
        // What the node could not read, or what would say more than it seems to, is refused.
        for bad in [
            "disk: sda\nhostname: Not A Name\n",
            "disk: sda\nhostname: a kith.slot=b\n",
            "disk: sda\nip: 10.0.0.5\n",
            "disk: sda\ndns: nine\n",
            "disk: sda\njoin: { address: 10.0.0.7, token: kith1.ab }\n",
            "disk: sda\njoin: { address: '10.0.0.7:7443 --claim', token: kith1.ab }\n",
            "disk: sda\njoin: { address: 10.0.0.7:7443, token: 'kith1.ab --state /tmp' }\n",
            "disk: sda\njoin: { address: 10.0.0.7:7443, token: --claim }\n",
            "disk: sda\njoin: { address: '--claim:7443', token: kith1.ab }\n",
        ] {
            assert!(config(bad, &two).is_err(), "{bad}");
        }
        assert!(answers("disk: sda\nwipe: everything\n").unwrap_err().contains("wipe"));
        assert!(answers("hostname: alpha\n").is_err(), "no disk named");
        assert!(
            plan(&told("disk: sda\nhostname: alpha\n"), &two, 1, 8)
                .unwrap_err()
                .contains("longer than")
        );
    }

    #[test]
    fn release_key_given_at_install_is_the_nodes() {
        let two = [disk("sda", 8)];
        let (a, b) = ("a".repeat(64), "0B".repeat(32));
        let yaml = format!("disk: sda\nip: 10.0.0.5/24\nreleaseKey: '{a}, {b}'\nlanReleases: true\n");
        let (_, config) = plan(&answers(&yaml).unwrap(), &two, 300 << 20, 1 << 20).unwrap();
        let (_, args) = crate::init::configured(&config);
        assert_eq!(
            args,
            [
                "--listen",
                "0.0.0.0:7443",
                "--advertise",
                "10.0.0.5:7443",
                "--release-key",
                &format!("{a},{b}"),
                "--lan-releases",
                "--claim"
            ]
        );
        // Only keys: nothing that would say more on the node's command line.
        for bad in [
            "''".to_string(),
            "abc".into(),
            format!("'{a} --claim'"),
            format!("'{a},'"),
            format!("'{}'", "g".repeat(64)),
            format!("'{}'", [a.as_str(); 9].join(",")),
        ] {
            let told = answers(&format!("disk: sda\nreleaseKey: {bad}\n")).unwrap();
            assert!(plan(&told, &two, 300 << 20, 1 << 20).is_err(), "{bad}");
        }
    }

    #[test]
    fn node_policy_given_at_install_is_on_the_nodes_line_and_a_wrong_word_installs_nothing() {
        let one = [disk("sda", 8)];
        let told = answers("disk: sda\nnodePolicy: 'hardened, node-network'\n").unwrap();
        let (_, config) = plan(&told, &one, 300 << 20, 1 << 20).unwrap();
        let (_, args) = crate::init::configured(&config);
        let policy = args.iter().position(|arg| arg == "--node-policy").unwrap();
        assert_eq!(args[policy + 1], "hardened,node-network");
        assert_eq!(args.last().unwrap(), "--claim");
        // None said: none on the line, and the node does everything, as before.
        let (_, config) = plan(&answers("disk: sda\n").unwrap(), &one, 300 << 20, 1 << 20).unwrap();
        assert!(!config.contains("node-policy"), "{config}");
        for bad in ["hardned", "'hardened --claim'", "devices=gpus"] {
            let told = answers(&format!("disk: sda\nnodePolicy: {bad}\n")).unwrap();
            let why = plan(&told, &one, 300 << 20, 1 << 20).unwrap_err();
            assert!(why.contains("`nodePolicy`"), "{bad}: {why}");
        }
    }

    #[test]
    fn install_asks_and_wants_the_disk_named_twice() {
        let two = [disk("sda", 8), disk("sdb", 16)];
        let ask = |lines: &[&str]| {
            let mut lines = lines.iter();
            let mut asked = Vec::new();
            let told = interview(&two, |question| {
                asked.push(question.to_string());
                (*lines.next().unwrap_or(&"")).to_string()
            });
            (told, asked)
        };
        let (told, asked) = ask(&["sdb", "alpha", "", "", "", "sdb"]);
        let expected = Answers {
            disk: "sdb".into(),
            hostname: Some("alpha".into()),
            ..Answers::default()
        };
        assert_eq!(told.unwrap(), expected);
        assert!(
            asked[0].contains("sda (8.0 GB, Test)") && asked[0].contains("sdb (16.0 GB, Test)"),
            "{asked:?}"
        );
        assert!(
            asked
                .last()
                .unwrap()
                .contains("Everything on sdb (16.0 GB, Test) will be erased")
        );
        let (told, asked) = ask(&["sda", "", "10.0.0.5/24", "10.0.0.7:7443", "kith1.ab.cd", "yes", "sda"]); // pragma: allowlist secret
        let join = Some(Join {
            address: "10.0.0.7:7443".into(),
            token: "kith1.ab.cd".into(), // (made up) pragma: allowlist secret
        });
        let told = told.unwrap();
        assert_eq!((told.join, told.encrypt), (join, true));
        assert_eq!(asked.len(), 7);
        // Not the same name twice, or a disk that is not there: nothing is chosen.
        assert!(
            ask(&["sda", "", "", "", "", "sdb"])
                .0
                .unwrap_err()
                .contains("nothing was written")
        );
        assert!(ask(&["sda", "", "", "", "", ""]).0.is_err());
        assert!(ask(&["sdz"]).0.unwrap_err().contains("no disk `sdz`"));
        assert!(interview(&[], |_| String::new()).is_err());
        // At the console a disk may be named by its serial, as in the answers file; the
        // second time, by its serial again or its name.
        let mut two = two;
        two[1].serial = "S4EW0001".into();
        for again in ["serial:S4EW0001", "sdb"] {
            let mut lines = ["serial:S4EW0001", "", "", "", "", again].into_iter();
            let told = interview(&two, |_| lines.next().unwrap().to_string()).unwrap();
            assert_eq!(told.disk, "serial:S4EW0001");
        }
        let mut lines = ["serial:S4EW0001", "", "", "", "", "sda"].into_iter();
        assert!(interview(&two, |_| lines.next().unwrap().to_string()).is_err());
        let refused = interview(&two, |_| "serial:NONE".into()).unwrap_err();
        assert!(refused.contains("no disk with serial NONE"), "{refused}");
    }

    /// A disk image of 64 sectors with a GPT whose third partition is `config`, 4 sectors at sector 40.
    fn image(named: &str) -> Vec<u8> {
        let mut image: Vec<u8> = (0..64 * 512).map(|at| (at % 251) as u8).collect();
        let header = &mut image[512..1024];
        header[..8].copy_from_slice(b"EFI PART");
        header[32..40].copy_from_slice(&63u64.to_le_bytes());
        header[72..80].copy_from_slice(&2u64.to_le_bytes());
        header[80..84].copy_from_slice(&4u32.to_le_bytes());
        header[84..88].copy_from_slice(&128u32.to_le_bytes());
        image[1024..1024 + 4 * 128].fill(0);
        let entry = &mut image[1024 + 2 * 128..1024 + 3 * 128];
        entry[32..40].copy_from_slice(&40u64.to_le_bytes());
        entry[40..48].copy_from_slice(&43u64.to_le_bytes());
        for (at, unit) in named.encode_utf16().enumerate() {
            entry[56 + at * 2..58 + at * 2].copy_from_slice(&unit.to_le_bytes());
        }
        image
    }

    /// A reused disk: what it held past the image (an older install's state, someone's
    /// files) reads as zeros once kith OS is written, so the state partition grown over
    /// it later shows none of it; the disk keeps its size.
    #[test]
    fn write_zeroes_what_a_reused_disk_held_past_the_image() {
        let dir = std::env::temp_dir().join(format!("kith-install-reused-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("image"), image("config")).unwrap();
        // (Not a multiple of the copy's block, nor of a sector: the end is zeroed to the byte.)
        std::fs::write(dir.join("disk"), vec![0x5a; (3 << 20) + 777]).unwrap();
        let open = |name: &str| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(dir.join(name))
                .unwrap()
        };
        write(&mut open("image"), &mut open("disk"), "kith.hostname=alpha", |_| ()).unwrap();
        let wrote = std::fs::read(dir.join("disk")).unwrap();
        assert_eq!(wrote.len(), (3 << 20) + 777);
        assert!(wrote[64 * 512..].iter().all(|byte| *byte == 0));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn install_copies_the_image_and_writes_the_config_where_its_table_says() {
        let dir = std::env::temp_dir().join(format!("kith-install-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let open = |name: &str, bytes: &[u8]| {
            std::fs::write(dir.join(name), bytes).unwrap();
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(dir.join(name))
                .unwrap()
        };
        let source = image("config");
        let mut from = open("image", &source);
        assert_eq!(layout(&from).unwrap(), (64 * 512, 40 * 512, 4 * 512));
        // A disk bigger than the image, with something on it, also where the config goes.
        let mut disk = open("disk", &vec![0xee; 100 * 512]);
        let mut tenths = Vec::new();
        write(&mut from, &mut disk, "kith.hostname=alpha -- --claim", |tenth| {
            tenths.push(tenth)
        })
        .unwrap();
        assert_eq!(tenths.last(), Some(&10));
        let wrote = std::fs::read(dir.join("disk")).unwrap();
        assert_eq!(wrote[..40 * 512], source[..40 * 512]);
        assert_eq!(wrote[44 * 512..64 * 512], source[44 * 512..]);
        assert!(
            wrote[64 * 512..].iter().all(|byte| *byte == 0),
            "past the image what the disk held is gone"
        );
        let config = &wrote[40 * 512..44 * 512];
        assert!(config.starts_with(b"kith.hostname=alpha -- --claim\0") && config[40..].iter().all(|byte| *byte == 0));
        assert_eq!(
            crate::init::configured(&String::from_utf8_lossy(config)).0,
            "kith.hostname=alpha"
        );

        // Answers too long for the partition, an image without one, a disk too small: said, not half done.
        let long = "x".repeat(4 * 512);
        assert!(
            write(&mut from, &mut disk, &long, |_| ())
                .unwrap_err()
                .contains("longer than")
        );
        assert!(
            layout(&open("other", &image("state")))
                .unwrap_err()
                .contains("no partition named config")
        );
        assert!(
            layout(&open("none", &[0; 4096]))
                .unwrap_err()
                .contains("no partition table")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_redirect_never_takes_unpinned_answers_off_https() {
        assert_eq!(followed("https", 0, false), Ok(()));
        assert!(followed("http", 0, false).is_err());
        assert!(followed("ftp", 0, true).is_err());
        assert_eq!(followed("http", 1, true), Ok(()));
        assert!(followed("https", 5, true).is_err());
    }

    #[test]
    fn answers_are_pinned_by_the_sha256_in_their_url() {
        let yaml = b"disk: sda\n";
        let hash = crate::pki::hex(&Sha256::digest(yaml));
        // What is fetched is the address before the fragment; the pin is the digest of the answers.
        let url = format!("http://10.0.2.2/alpha.yaml#sha256={hash}");
        let (address, pin) = pinned(&url).unwrap();
        assert_eq!(
            (address, pin.as_deref()),
            ("http://10.0.2.2/alpha.yaml", Some(hash.as_str()))
        );
        // Upper-case digits name the same digest; https needs no pin and is taken as it was.
        let (_, upper) = pinned(&format!("https://files.example/a.yaml#sha256={}", hash.to_uppercase())).unwrap();
        assert_eq!(upper.as_deref(), Some(hash.as_str()));
        assert_eq!(
            pinned("https://files.example/a.yaml").unwrap(),
            ("https://files.example/a.yaml", None)
        );
        // Plain http with no pin is refused, and the refusal says how to pin.
        assert!(pinned("http://10.0.2.2/alpha.yaml").unwrap_err().contains("#sha256="));
        // A pin that is not `sha256=` and 64 hex digits, and an address that is not http(s), are refused.
        for bad in [
            format!("https://files.example/a.yaml#sha256={}", &hash[..63]),
            format!("https://files.example/a.yaml#sha256={hash}0"),
            format!("https://files.example/a.yaml#sha256={}g", &hash[..63]),
            format!("https://files.example/a.yaml#md5={}", &hash[..32]),
            format!("https://files.example/a.yaml#{hash}"),
            "https://files.example/a.yaml#".to_string(),
            format!("https://files.example/a.yaml#sha256={hash}#more"),
            format!("ftp://files.example/a.yaml#sha256={hash}"),
        ] {
            assert!(pinned(&bad).is_err(), "{bad} is refused");
        }
        // The answers must hash to the pin; a refusal names both hashes.
        assert!(verified(&hash, yaml).is_ok());
        let other = b"disk: nvme0n1\n";
        let refused = verified(&hash, other).unwrap_err();
        assert!(refused.contains(&hash) && refused.contains(&crate::pki::hex(&Sha256::digest(other))));
    }

    #[tokio::test]
    async fn unpinned_http_answers_are_refused_before_any_fetch() {
        // Nothing listens on this port: a fetch would retry for a minute, not return at once.
        let started = std::time::Instant::now();
        let why = fetched("http://127.0.0.1:9/alpha.yaml").await.unwrap_err();
        assert!(why.contains("#sha256="), "{why}");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    /// A seal that fails after the image is written leaves no bootable disk: its partition
    /// tables are cleared, primary and spare, and the install says so.
    #[test]
    fn a_failed_seal_leaves_no_bootable_disk() {
        let dir = std::env::temp_dir().join(format!("kith-install-seal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // The image's backup table is in its last sector, as a partitioning tool writes one.
        let mut source = image("config");
        source[63 * 512..63 * 512 + 8].copy_from_slice(b"EFI PART");
        std::fs::write(dir.join("image"), &source).unwrap();
        std::fs::write(dir.join("disk"), vec![0xee; 64 * 512]).unwrap();
        let open = |name: &str| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(dir.join(name))
                .unwrap()
        };
        let (mut from, mut disk) = (open("image"), open("disk"));
        write(&mut from, &mut disk, "kith.hostname=alpha", |_| ()).unwrap();
        drop(disk);
        let device = dir.join("disk");
        let before = std::fs::read(&device).unwrap();
        assert!(before[512..520] == *b"EFI PART" && before[63 * 512..63 * 512 + 8] == *b"EFI PART");

        let said = sealed(&from, &device, |_, _| Err("the seal failed".into()));
        let now = std::fs::read(&device).unwrap();
        let gone = crate::gpt::guids(&open("disk"), 64);
        std::fs::remove_dir_all(&dir).unwrap();

        let why = said.unwrap_err();
        assert!(why.contains("the seal failed") && why.contains("cleared"), "{why}");
        assert!(
            now[..34 * 512].iter().all(|byte| *byte == 0),
            "the primary is not cleared"
        );
        assert!(
            now[31 * 512..].iter().all(|byte| *byte == 0),
            "the spare is not cleared"
        );
        assert!(gone.unwrap_err().contains("no partition table"));
    }

    /// A seal that fails and a clear that fails too: both are said, and the disk is not called clean.
    #[test]
    fn a_failed_clear_is_said_too() {
        let dir = std::env::temp_dir().join(format!("kith-install-clear-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("image"), b"").unwrap();
        let from = File::open(dir.join("image")).unwrap();
        let why = sealed(&from, &dir.join("no-disk"), |_, _| Err("the seal failed".into())).unwrap_err();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            why.contains("the seal failed") && why.contains("failed too") && why.contains("may boot unencrypted"),
            "{why}"
        );
    }

    /// docs/install.html makes this file in the browser; its two examples (the form as it
    /// starts, and the form filled in) are in the page as `<pre data-answers="...">`, and
    /// ci/site_shots.py checks that the page's script writes them. Here the installer
    /// reads them: its parser takes every field, and its plan accepts every value.
    #[test]
    fn the_install_page_examples_are_answers_the_installer_takes() {
        const PAGE: &str = include_str!("../../../docs/install.html");
        let example = |name: &str| {
            let from = PAGE
                .find(&format!("<pre data-answers=\"{name}\""))
                .unwrap_or_else(|| panic!("no {name} example"));
            let body = &PAGE[from..];
            let body = &body[body.find('>').unwrap() + 1..body.find("</pre>").unwrap()];
            let mut text = String::new();
            let mut in_tag = false;
            for c in body.chars() {
                match c {
                    '<' => in_tag = true,
                    '>' => in_tag = false,
                    c if !in_tag => text.push(c),
                    _ => {}
                }
            }
            text.replace("&quot;", "\"")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&")
        };
        let mut seen = Vec::new();
        for name in ["default", "example", "custom"] {
            let yaml = example(name);
            let told = answers(&yaml).unwrap_or_else(|e| panic!("{name}:\n{yaml}\n{e}"));
            let mut one = disk("nvme0n1", 256);
            one.serial = "S4EWNX0R123456".into();
            let (_, config) =
                plan(&told, &[one], 300 << 20, 1 << 20).unwrap_or_else(|e| panic!("{name}:\n{yaml}\n{e}"));
            seen.push((told, config));
        }
        // The default is the one disk and nothing else; the example fills in every field.
        assert_eq!(
            seen[0].0,
            Answers {
                disk: "only".into(),
                ..Answers::default()
            }
        );
        let full = &seen[1].0;
        assert!(full.disk.starts_with("serial:") && full.hostname.is_some() && full.ip.is_some() && full.dns.is_some());
        assert!(full.join.is_some() && full.encrypt && full.release_key.is_some() && full.lan_releases);
        assert!(full.node_policy.is_some());
        assert!(
            seen[1].1.contains("--join ")
                && seen[1].1.contains("--release-key ")
                && seen[1].1.contains("--lan-releases")
        );
        // The third is what the form writes for a fixed address with its way out, a join and a policy of its
        // own words (ci/site_shots.py fills the form from the block's data-fields and compares): the installer
        // takes the address, the join and the policy as the words the form joined.
        let custom = &seen[2].0;
        assert_eq!(custom.disk, "nvme0n1");
        assert_eq!(custom.ip.as_deref(), Some("10.0.0.6/24,10.0.0.1"));
        assert_eq!(custom.join.as_ref().map(|j| j.address.as_str()), Some("10.0.0.7:7443"));
        assert_eq!(custom.node_policy.as_deref(), Some("hardened,vms,devices=gpu+input"));
        assert!(!custom.encrypt && !custom.lan_releases && custom.release_key.is_none() && custom.dns.is_none());
        assert!(
            seen[2].1.contains("--advertise 10.0.0.6:")
                && seen[2].1.contains("--join 10.0.0.7:7443 --token ")
                && seen[2].1.contains("--node-policy hardened,vms,devices=gpu+input")
        );
    }
}
