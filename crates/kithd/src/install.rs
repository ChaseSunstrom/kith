//! Installing kith OS on a machine's disk (PLAN §4.9). The installer is kith OS started
//! with `kith.install` on its kernel command line (only the installer image's kernel image
//! has it, see os/build.sh): kithd, as the first process, serves nothing and instead
//!
//! 1. lists the machine's disks, never the one it was started from;
//! 2. takes answers: from the URL after `kith.install=`, else from `kith-install.yaml` on
//!    the installer's ESP, else from whoever sits at the console;
//! 3. copies the image the installer carries (its `payload` partition) to the chosen
//!    disk, reads it back, and writes what it was told of the node (hostname, address,
//!    kithd's arguments) into the new disk's `config` partition, which `init` reads at
//!    every start;
//! 4. powers the machine off.
//!
//! Everything on the chosen disk is lost. Without a person there, a disk is only chosen
//! by name, or as `only` when the machine has exactly one.
//
// ponytail: the image is copied as it is, so the state partition is as small as the
// image's (T-0094 grows it) and the spare partition table sits where the image ended,
// not at the disk's end (the kernel says so at each start and uses the first).

use serde::Deserialize;
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
}

impl std::fmt::Display for Disk {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let size = self.bytes as f64 / 1e9;
        write!(
            f,
            "{} ({size:.1} GB{}{})",
            self.name,
            if self.model.is_empty() { "" } else { ", " },
            self.model
        )
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
                name,
                bytes,
            })
        })
        .collect();
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

/// What the installer is told.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Answers {
    /// The disk's name (`sda`, `nvme0n1`), or `only`: the one disk the machine has.
    pub disk: String,
    #[serde(default)]
    pub hostname: Option<String>,
    /// `10.0.0.5/24` or `10.0.0.5/24,10.0.0.1` (with the way out); without, the network is asked.
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub dns: Option<String>,
    /// Join this cluster; without, the node starts a new one.
    #[serde(default)]
    pub join: Option<Join>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Join {
    pub address: String,
    pub token: String,
}

/// The port a node's kithd serves other nodes and its admins on.
const PORT: u16 = 7443;

/// Which disk, and the node's config (more of its kernel command line, see `init`), or
/// why not. `room` is how long a config may be.
pub fn plan(answers: &Answers, disks: &[Disk], image: u64, room: u64) -> Result<(Disk, String), String> {
    let listed = || disks.iter().map(Disk::to_string).collect::<Vec<_>>().join(", ");
    let wanted = answers.disk.trim().trim_start_matches("/dev/");
    let disk = match wanted {
        "only" => match disks {
            [one] => one,
            [] => return Err("this machine has no disk to install on".into()),
            _ => return Err(format!("`disk: only` and this machine has several: {}", listed())),
        },
        name => disks.iter().find(|disk| disk.name == name).ok_or_else(|| match disks {
            [] => format!("no disk {name}: this machine has no disk to install on"),
            _ => format!("no disk {name} to install on; there is: {}", listed()),
        })?,
    };
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
    let address = answers.ip.as_deref().and_then(|ip| ip.trim().split('/').next());
    if let Some(address) = address {
        words.push(format!("--advertise {address}:{PORT}"));
    }
    match &answers.join {
        Some(join) => {
            let plain = |text: &str, more: &str| {
                !text.is_empty() && text.chars().all(|c| c.is_ascii_alphanumeric() || more.contains(c))
            };
            let (address, token) = (join.address.trim(), join.token.trim());
            if !plain(address, ".-:[]") || !address.contains(':') {
                return Err(format!("`{address}` is not a node's address: ADDRESS:PORT"));
            }
            if !plain(token, ".") {
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
        "This machine's disks:\n{}Install kith OS on which (its name)?",
        listed.concat()
    ));
    let chosen = disks.iter().find(|found| found.name == disk);
    let chosen = chosen.ok_or(format!("there is no disk `{disk}` here"))?;
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
    let again = ask(&format!(
        "Everything on {chosen} will be erased. Type its name again to go on:"
    ));
    if again != disk {
        return Err(format!("`{again}` is not `{disk}`: nothing was written"));
    }
    Ok(Answers {
        disk,
        hostname,
        ip,
        dns: None,
        join,
    })
}

/// In the disk image `image` (GPT): how long it is, and where its partition named
/// `config` is and how long.
pub fn layout(image: &File) -> Result<(u64, u64, u64), String> {
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
        if name.trim_end_matches('\0') == "config" {
            let (first, last) = (u64_at(&entry, 32), u64_at(&entry, 40));
            if first == 0 || last < first || (last + 1) * 512 > length {
                return Err(bad("its config partition is not inside it"));
            }
            return Ok((length, first * 512, (last + 1 - first) * 512));
        }
    }
    Err(bad("no partition named config"))
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

/// The answers file as YAML.
pub fn answers(yaml: &str) -> Result<Answers, String> {
    kith_yaml::from_str(yaml).map_err(|e| e.render("kith-install.yaml", yaml))
}

/// One line from whoever types at any of the machine's consoles (a screen's keyboard, a
/// serial line): the kernel hands its first process only the last console named.
fn keyboard() -> std::sync::mpsc::Receiver<String> {
    use std::io::BufRead;
    let (lines, typed) = std::sync::mpsc::channel();
    let active = std::fs::read_to_string("/sys/class/tty/console/active").unwrap_or_default();
    for name in active.split_whitespace() {
        let (Ok(console), lines) = (File::open(format!("/dev/{name}")), lines.clone()) else {
            continue;
        };
        std::thread::spawn(move || {
            let (mut console, mut line) = (std::io::BufReader::new(console), Vec::new());
            // (Bytes that are no text are typed too, on a serial line: they end nothing.)
            while console.read_until(b'\n', &mut line).is_ok_and(|read| read > 0) {
                if lines.send(String::from_utf8_lossy(&line).trim().to_string()).is_err() {
                    return;
                }
                line.clear();
            }
        });
    }
    typed
}

/// Nothing more is done, and the machine stays as it is for someone to read why.
async fn stop(why: &str) -> ! {
    eprintln!("kithd: install: nothing was installed: {why}");
    eprintln!("kithd: install: power the machine off, or press Ctrl-Alt-Del to start it again");
    std::future::pending().await
}

/// Install mode, start to end. `source` is the URL of the answers, or empty.
pub async fn run(source: String) -> ! {
    eprintln!("kithd: install: this is the kith OS installer: it erases a disk of this machine and puts kith OS on it");
    let Some(payload) = crate::init::labelled("payload") else {
        stop("this installer carries no image (no partition named payload)").await
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
    let file = crate::os::esp(|esp| std::fs::read_to_string(esp.join("../../kith-install.yaml")).ok());
    let given = if source.is_empty() {
        file.ok().flatten().map(Ok)
    } else {
        Some(fetched(&source).await)
    };
    let typed = std::sync::Arc::new(std::sync::Mutex::new(keyboard()));
    let (disk, config) = loop {
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
        match told.and_then(|told| plan(&told, &found, length, room)) {
            Ok(planned) => break planned,
            Err(e) if given.is_some() || found.is_empty() => stop(&e).await,
            Err(e) => eprintln!("kithd: install: {e}\nkithd: install: once more."),
        }
    };
    // (Not the join token: a console is read by more people than a disk.)
    let shown = config.split(" --token ").next().unwrap_or_default();
    eprintln!("kithd: install: writing kith OS to {disk}; its node will start with: {shown}");
    let device = Path::new("/dev").join(&disk.name);
    let wrote = tokio::task::spawn_blocking(move || {
        use std::os::unix::fs::OpenOptionsExt;
        // (O_EXCL on a disk: refused while anything of it is mounted or held.)
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(nix::fcntl::OFlag::O_EXCL.bits());
        let mut disk = options
            .open(&device)
            .map_err(|e| format!("{}: {e}", device.display()))?;
        write(&mut image, &mut disk, &config, |tenths| {
            eprintln!("kithd: install: {}%", tenths * 10)
        })
    });
    match wrote.await.map_err(|e| e.to_string()).and_then(|wrote| wrote) {
        Ok(()) => {
            eprintln!("kithd: install: kith OS is on {disk}. Take the installer out and start the machine.");
            crate::init::POWER_OFF.store(true, std::sync::atomic::Ordering::Relaxed);
            crate::init::end(false)
        }
        Err(e) => {
            eprintln!("kithd: install: {disk} may hold part of kith OS now and nothing of what it held before");
            stop(&e).await
        }
    }
}

/// The answers at `url`. The network may take a moment to be there.
async fn fetched(url: &str) -> Result<String, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build();
    let client = client.map_err(|e| e.to_string())?;
    let mut last = String::new();
    for _ in 0..12 {
        // (No more of it is taken than answers can be: this machine has only its memory.)
        let got = async {
            let mut from = client.get(url).send().await?.error_for_status()?;
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
            Ok(text) if text.len() <= 64 << 10 => return Ok(String::from_utf8_lossy(&text).into_owned()),
            Ok(_) => return Err(format!("{url} is too long to be answers")),
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    Err(format!("no answers from {url}: {last}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(name: &str, gigabytes: u64) -> Disk {
        Disk {
            name: name.into(),
            bytes: gigabytes * 1_000_000_000,
            model: "Test".into(),
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
        let (_, joined) = config(
            "disk: /dev/sda\njoin: { address: 10.0.0.7:7443, token: kith1.ab.cd }\n",
            &two,
        )
        .unwrap();
        assert_eq!(
            joined,
            "-- --listen 0.0.0.0:7443 --join 10.0.0.7:7443 --token kith1.ab.cd"
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
        let (told, asked) = ask(&["sdb", "alpha", "", "", "sdb"]);
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
        let (told, asked) = ask(&["sda", "", "10.0.0.5/24", "10.0.0.7:7443", "kith1.ab.cd", "sda"]);
        let join = Some(Join {
            address: "10.0.0.7:7443".into(),
            token: "kith1.ab.cd".into(), // (made up) pragma: allowlist secret
        });
        assert_eq!(told.unwrap().join, join);
        assert_eq!(asked.len(), 6);
        // Not the same name twice, or a disk that is not there: nothing is chosen.
        assert!(
            ask(&["sda", "", "", "", "sdb"])
                .0
                .unwrap_err()
                .contains("nothing was written")
        );
        assert!(ask(&["sda", "", "", "", ""]).0.is_err());
        assert!(ask(&["sdz"]).0.unwrap_err().contains("no disk `sdz`"));
        assert!(interview(&[], |_| String::new()).is_err());
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
            wrote[64 * 512..].iter().all(|byte| *byte == 0xee),
            "past the image the disk is left alone"
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
}
