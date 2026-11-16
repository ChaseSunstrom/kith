//! What `sh ci/vm.sh --test pods` runs in its pods: one file, built static with rustc
//! alone, and put in the nodes as a container image (they reach no registry there).
//!
//!   pod serve [FILE]           make a file in the root, then answer every connection on
//!                              port 80 (as HTTP) with this pod's name, what GREETING and
//!                              PASSWORD say where it is told them, and, given a FILE it
//!                              adds a line to at each start, how many lines that has
//!   pod say                    answer every connection on port 80 (as HTTP) with what
//!                              PASSWORD says, writing nowhere (its root may take no file)
//!   pod ask HOST PORT [...]    ask each 40 times, and say each different answer's first
//!                              and last line once, to /dev/stdout opened by that name
//!   pod seen DIR [SOCKET]      for as long as it runs, say the names in DIR each time they
//!                              change: those it can open with a `+`, the others with a `-`;
//!                              and answer whoever connects to SOCKET (a path) with a line
//!   pod call SOCKET            say what whoever listens on SOCKET (a path) answers, waiting
//!                              a while for it to be there, and whether a file can be made
//!                              beside it
//!   pod self                   say which process it is and whose, where it finds itself
//!   pod node b|c NUMBERS PATH  make at PATH a node of the block or character device whose
//!                              MAJOR:MINOR the file NUMBERS holds (one of /sys), read from
//!                              it, and say how both went
//!   pod put FILE TEXT          after three seconds, write TEXT to FILE
//!   pod tell [PATH ...]        say whose it is, the capabilities it has and what it was
//!                              told (its environment); then of each PATH what is mounted
//!                              there, whether it can be written, and every file under it;
//!                              and, given a PATH, each file again when it changes
//!   pod echo                   on port 80, send back every byte each connection sends, and
//!                              when it ends say whether all of them came, in order (what
//!                              `pod check` sends: a length, a way to end, then the bytes)
//!   pod check HOST PORT        send `pod echo` there, over many connections, small and large,
//!                              one after another and side by side, closed at once, half
//!                              closed, reset by either end and kept for many small turns; say
//!                              the address a connection there reached, each byte that did
//!                              not come back in order, and how it went
//!   pod fill FILE BYTES [unlinked]
//!                              say whether FILE was there (its root is empty if not), then
//!                              write BYTES to it, 64 KiB each half second, saying if a write
//!                              fails (the disk is full), and wait; unlinked: removes FILE
//!                              first and writes to it held open, with no name
//!   pod probe                  what `vm.sh --test tunnel` runs behind an exit: answers on
//!                              port 8080 (TCP, as HTTP) and sends back what comes to UDP
//!                              8080; and each second asks 198.51.100.1:80 and a new name
//!                              (over UDP, and over TCP) where its resolv.conf says, asks its
//!                              node for a name, tries IPv6 out, sends `kithleak` to two
//!                              addresses outside, and says how each went
//!   pod init SCRIPT            as a machine's first process (that test's provider): mounts
//!                              /dev and /proc, runs each line of SCRIPT in turn (`NAME=VALUE`
//!                              words first are its environment; `&` first: left running),
//!                              then waits
//!   pod dns ADDRESS            on port 53, UDP and TCP, answers every name with ADDRESS and
//!                              says each it was asked
//!   pod shout TO WHAT          sends WHAT to TO (ADDRESS:PORT) over UDP, once a second, ten
//!                              times

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

/// The byte at `i` of what `pod check` sends: one no lost, doubled or swapped byte keeps in
/// place (251 is prime, and no buffer's size is a multiple of it).
fn byte(i: u64) -> u8 {
    (i % 251) as u8
}

/// One connection of `pod echo`: a length, how it is to end (1: by a reset, the rest of what
/// is sent left unread half way), then every byte sent back as it comes; at the end, what
/// it heard ("ok", or the first byte out of place, or how many came).
fn echo(mut stream: TcpStream) {
    let mut head = [0; 9];
    // (What only connects and sends nothing, as a readiness probe does, is not asked.)
    if stream.read_exact(&mut head).is_err() {
        return;
    }
    let length = u64::from_be_bytes(head[..8].try_into().expect("8 bytes"));
    let (mut at, mut buffer, mut bad) = (0u64, vec![0; 65536], None);
    loop {
        let read = match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        if let Some(i) = (0..read).find(|&i| buffer[i] != byte(at + i as u64)) {
            bad.get_or_insert(at + i as u64);
        }
        at += read as u64;
        if stream.write_all(&buffer[..read]).is_err() {
            break;
        }
        if head[8] == 1 && at >= length / 2 {
            // (Closed with bytes still coming unread: the kernel answers them with a reset.)
            return;
        }
    }
    let said = match bad {
        Some(i) => format!("bad at {i} of {length}\n"),
        None if at != length => format!("short {at} of {length}\n"),
        None => "ok\n".to_string(),
    };
    if bad.is_some() {
        println!("echo: {}", said.trim());
    }
    let _ = stream.write_all(said.as_bytes());
}

/// One connection to `pod echo` at `to`: `length` bytes sent in pieces of several sizes while
/// what comes back is read, and how it ends: 0, half closed at once when all is sent and
/// then everything back with "ok" after it; 1, reset by the far end half way, after which
/// what came back is in order up to where it stopped; 2, reset by this end half way.
fn exchange(to: (&str, u16), length: u64, mode: u8) -> Result<(), String> {
    let mut stream = TcpStream::connect(to).map_err(|e| format!("connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).map_err(|e| e.to_string())?;
    let mut sending = stream.try_clone().map_err(|e| e.to_string())?;
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        sending.write_all(&[&length.to_be_bytes()[..], &[mode]].concat())?;
        let (until, mut at, mut piece) = (if mode == 2 { length / 2 } else { length }, 0u64, 0);
        while at < until {
            let size = [1, 1448, 8192, 65536][piece % 4].min(until - at);
            let bytes: Vec<u8> = (at..at + size).map(byte).collect();
            sending.write_all(&bytes)?;
            (at, piece) = (at + size, piece + 1);
        }
        if mode != 2 {
            sending.shutdown(Shutdown::Write)?;
        }
        Ok(())
    });
    let (mut at, mut after, mut buffer) = (0u64, Vec::new(), vec![0; 65536]);
    let ended = loop {
        match stream.read(&mut buffer) {
            Ok(0) => break None,
            Ok(read) => {
                for &got in &buffer[..read] {
                    if at < length && got != byte(at) {
                        return Err(format!("byte {at} of {length} (mode {mode}) came back as {got}"));
                    } else if at >= length && after.len() < 64 {
                        after.push(got);
                    }
                    at += 1;
                }
                if mode == 2 && at > 0 {
                    // (Dropped with what is still coming unread: the kernel resets the connection.)
                    let _ = writer.join();
                    return Ok(());
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(format!("nothing for 30 s after {at} of {length} bytes back (mode {mode})"));
            }
            Err(e) => break Some(e),
        }
    };
    let wrote = writer.join().map_err(|_| "the writer panicked".to_string())?;
    let after = String::from_utf8_lossy(&after);
    match mode {
        1 if at <= length => Ok(()),
        1 => Err(format!("{at} bytes came back of {length} sent before a reset")),
        _ => match (ended, wrote) {
            (None, Ok(())) if at == length + 3 && after == "ok\n" => Ok(()),
            (ended, wrote) => Err(format!(
                "{at} bytes back of {length} (mode {mode}), then {:?}; it ended with {ended:?}, sending {wrote:?}",
                after.trim()
            )),
        },
    }
}

/// Many small turns on one connection, each waiting for the last: what a kept connection of
/// requests and answers asks of whatever passes its bytes. How many turns a second.
fn turns(to: (&str, u16), count: u64) -> Result<f64, String> {
    let mut stream = TcpStream::connect(to).map_err(|e| format!("connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).map_err(|e| e.to_string())?;
    let _ = stream.set_nodelay(true);
    let failed = |e: std::io::Error| format!("turns: {e}");
    stream.write_all(&[&(count * 100).to_be_bytes()[..], &[0]].concat()).map_err(failed)?;
    let started = Instant::now();
    for turn in 0..count {
        let sent: Vec<u8> = (turn * 100..turn * 100 + 100).map(byte).collect();
        stream.write_all(&sent).map_err(failed)?;
        let mut back = [0; 100];
        stream.read_exact(&mut back).map_err(failed)?;
        if back[..] != sent[..] {
            return Err(format!("turn {turn} came back as {back:?}"));
        }
    }
    let took = started.elapsed().as_secs_f64();
    stream.shutdown(Shutdown::Write).map_err(failed)?;
    let mut said = String::new();
    stream.read_to_string(&mut said).map_err(failed)?;
    if said != "ok\n" {
        return Err(format!("turns: the end said {said:?}"));
    }
    Ok(count as f64 / took)
}

fn asked(host: &str, port: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect((host, port.parse::<u16>().expect("a port")))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer)?;
    let (first, last) = (answer.lines().next().unwrap_or_default(), answer.lines().last().unwrap_or_default());
    Ok(format!("{first} {last}"))
}

/// A DNS question for `name`'s IPv4 address.
fn question(name: &str, id: u16) -> Vec<u8> {
    let mut asked = id.to_be_bytes().to_vec();
    asked.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        asked.push(label.len() as u8);
        asked.extend(label.as_bytes());
    }
    asked.extend([0, 0, 1, 0, 1]);
    asked
}

/// What `pod dns` answers `asked` with (every name: `address`), and the name asked.
fn answer(asked: &[u8], address: std::net::Ipv4Addr) -> Option<(Vec<u8>, String)> {
    let mut end = 12;
    let mut name = Vec::new();
    while *asked.get(end)? != 0 {
        let length = usize::from(asked[end]);
        name.push(String::from_utf8_lossy(asked.get(end + 1..end + 1 + length)?).into_owned());
        end += 1 + length;
    }
    let question = asked.get(12..end + 5)?;
    let a = question[question.len() - 4..question.len() - 2] == [0, 1];
    let mut said = asked[..2].to_vec();
    said.extend([0x81, 0x80, 0, 1, 0, u8::from(a), 0, 0, 0, 0]);
    said.extend(question);
    if a {
        said.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        said.extend(address.octets());
    }
    Some((said, name.join(".")))
}

/// Whether `server` answers a question for `name` (over TCP, or UDP) within two seconds:
/// "ok" with an address, "empty" without one, "silent" not at all.
fn asks(server: SocketAddr, name: &str, tcp: bool) -> &'static str {
    let id = (std::process::id() as u16) ^ (name.len() as u16);
    let asked = question(name, id);
    let mut said = [0; 512];
    let heard = if tcp {
        TcpStream::connect_timeout(&server, Duration::from_secs(2)).and_then(|mut stream| {
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream.write_all(&[&(asked.len() as u16).to_be_bytes()[..], &asked].concat())?;
            stream.read_exact(&mut said[..2])?;
            stream.read(&mut said)
        })
    } else {
        UdpSocket::bind("0.0.0.0:0").and_then(|socket| {
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;
            socket.send_to(&asked, server)?;
            socket.recv(&mut said)
        })
    };
    match heard {
        Ok(n) if n >= 8 && said[6..8] != [0, 0] => "ok",
        Ok(_) => "empty",
        Err(_) => "silent",
    }
}

/// Every file at or under `path` as "PATH MODE CONTENT", through links (as a mounted
/// ConfigMap has them) and past what such a mount keeps for itself (`..data` and the like).
fn files(path: &std::path::Path, found: &mut Vec<String>) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(has) = std::fs::metadata(path) else { return };
    if has.is_dir() {
        let mut inside: Vec<_> = std::fs::read_dir(path).into_iter().flatten().flatten().map(|e| e.path()).collect();
        inside.sort();
        for path in inside.iter().filter(|path| !path.file_name().is_some_and(|name| name.to_string_lossy().starts_with(".."))) {
            files(path, found);
        }
    } else {
        let content = std::fs::read_to_string(path).unwrap_or_else(|e| format!("failed: {:?}", e.kind()));
        found.push(format!("{} {:o} {}", path.display(), has.permissions().mode() & 0o777, content.trim()));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match &args[1..] {
        ["serve", keeps @ ..] if keeps.len() < 2 => {
            std::fs::write("/made-here", "a pod's root takes a file").expect("a file in the root");
            let mut name = std::fs::read_to_string("/proc/sys/kernel/hostname").expect("a name");
            name = format!("HTTP/1.0 200 OK\r\n\r\n{}", name.trim());
            for told in ["GREETING", "PASSWORD"] {
                name += &std::env::var(told).map(|told| format!(" {told}")).unwrap_or_default();
            }
            if let [file] = keeps {
                let mut kept = std::fs::OpenOptions::new().create(true).append(true).open(file).expect("the file it keeps");
                kept.write_all(b"started\n").expect("a line in the file it keeps");
                let lines = std::fs::read_to_string(file).expect("the file it keeps, read").lines().count();
                name += &format!(" started {lines}");
            }
            let listener = TcpListener::bind("0.0.0.0:80").expect("port 80");
            for mut stream in listener.incoming().flatten() {
                // (What asks is read first: closing on it unread would cut the answer off.)
                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                let _ = stream.read(&mut [0; 512]);
                let _ = stream.write_all(name.as_bytes());
            }
        }
        // A long task that keeps its place: the step it reached is in DIR/step, and run again
        // (after its node was drained, or started again) it goes on from there.
        ["count", dir] => {
            let file = format!("{dir}/step");
            let was: u32 = std::fs::read_to_string(&file).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            std::fs::write(&file, format!("{}\n", was + 1)).expect("its step, written down");
            match was {
                0 => println!("began: step 1"),
                _ => println!("went on from step {was}: step {}", was + 1),
            }
        }
        // What it was given (PASSWORD), to whoever asks on port 80: for a container on its
        // node's own network, whose root takes no file.
        ["say"] => {
            let said = format!("HTTP/1.0 200 OK\r\n\r\n{}", std::env::var("PASSWORD").unwrap_or_default());
            let listener = TcpListener::bind("0.0.0.0:80").expect("port 80");
            for mut stream in listener.incoming().flatten() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                let _ = stream.read(&mut [0; 512]);
                let _ = stream.write_all(said.as_bytes());
            }
        }
        ["ask", pairs @ ..] if !pairs.is_empty() && pairs.len() % 2 == 0 => {
            let mut heard = std::collections::BTreeSet::new();
            for pair in pairs.chunks(2) {
                for _ in 0..40 {
                    heard.insert(asked(pair[0], pair[1]).unwrap_or_else(|e| format!("failed: {}: {e}", pair[0])));
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            let out = std::fs::OpenOptions::new().write(true).open("/dev/stdout");
            let mut out = out.expect("/dev/stdout, by its name");
            for line in heard {
                writeln!(out, "{line}").expect("a line out");
            }
        }
        ["seen", dir, hears @ ..] if hears.len() < 2 => {
            if let [socket] = hears {
                let _ = std::fs::remove_file(socket);
                let listener = std::os::unix::net::UnixListener::bind(socket).expect("the socket it answers on");
                std::thread::spawn(move || {
                    for mut stream in listener.incoming().flatten() {
                        let _ = stream.write_all(b"a window\n");
                    }
                });
            }
            let mut said = String::new();
            loop {
                let names = std::fs::read_dir(dir).into_iter().flatten().flatten();
                let mut names: Vec<String> = names
                    .map(|entry| {
                        let opens = if std::fs::File::open(entry.path()).is_ok() { '+' } else { '-' };
                        format!("{}{opens}", entry.file_name().to_string_lossy())
                    })
                    .collect();
                names.sort();
                let now = format!("seen: {}", names.join(" "));
                if now != said {
                    println!("{now}");
                    said = now;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        ["call", socket] => {
            use std::io::ErrorKind::{ConnectionRefused, NotFound};
            let mut tries = 0;
            let answer = loop {
                match std::os::unix::net::UnixStream::connect(socket) {
                    Ok(mut stream) => {
                        let mut said = String::new();
                        let _ = stream.read_to_string(&mut said);
                        break said.trim().to_string();
                    }
                    // (Not there yet: whoever listens may still be starting.)
                    Err(e) if tries < 120 && matches!(e.kind(), NotFound | ConnectionRefused) => tries += 1,
                    Err(e) => break format!("failed: {:?}", e.kind()),
                }
                std::thread::sleep(Duration::from_millis(500));
            };
            let beside = std::path::Path::new(socket).with_file_name("made-by-a-caller");
            let wrote = std::fs::write(beside, "x").map_err(|e| e.kind());
            println!("called: {answer}, wrote {wrote:?}");
        }
        ["self"] => {
            let status = std::fs::read_to_string("/proc/self/status").expect("a /proc to read itself in");
            let uid = status.lines().find_map(|line| line.strip_prefix("Uid:")?.split_whitespace().next());
            println!("nested: pid {}, uid {}", std::process::id(), uid.unwrap_or("?"));
        }
        ["node", kind, numbers, path] => {
            let said = std::fs::read_to_string(numbers).expect("the device's numbers");
            let (major, minor) = said.trim().split_once(':').expect("MAJOR:MINOR");
            let (major, minor): (u64, u64) = (major.parse().expect("a major"), minor.parse().expect("a minor"));
            let device = (major & 0xfff) << 8 | minor & 0xff | (minor & !0xff) << 12 | (major & !0xfff) << 32;
            let mode: u64 = if *kind == "b" { 0o060600 } else { 0o020600 };
            let name = std::ffi::CString::new(*path).expect("a path");
            // mknod(2), by x86-64's number for it, asked of the kernel itself: this file has
            // only std, which makes no device nodes. What it answers: 0, or minus an errno.
            let mut made: i64 = 133;
            unsafe {
                std::arch::asm!(
                    "syscall",
                    inlateout("rax") made,
                    in("rdi") name.as_ptr(),
                    in("rsi") mode,
                    in("rdx") device,
                    lateout("rcx") _,
                    lateout("r11") _,
                );
            }
            let read = std::fs::File::open(path).and_then(|mut node| node.read(&mut [0; 512]));
            println!("node: made {made}, read {read:?}");
        }
        ["put", file, text] => {
            std::thread::sleep(Duration::from_secs(3));
            std::fs::write(file, text).expect("the file it was told to write");
            println!("put: {file}");
        }
        ["tell", paths @ ..] => {
            let status = std::fs::read_to_string("/proc/self/status").expect("a /proc to read itself in");
            let of = |key: &str| status.lines().find_map(|line| line.strip_prefix(key)?.split_whitespace().next()).unwrap_or("?");
            println!("tell: started uid {} caps eff {} bnd {}", of("Uid:"), of("CapEff:"), of("CapBnd:"));
            let mut told: Vec<String> = std::env::vars().map(|(name, value)| format!("{name}={value}")).collect();
            told.sort();
            told.iter().for_each(|told| println!("tell: env {told}"));
            let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
            for path in paths {
                // (mountinfo(5): ID PARENT MAJOR:MINOR ROOT WHERE OPTIONS ... - TYPE SOURCE ...)
                let mount = mounts.lines().rev().find_map(|line| {
                    let (before, after) = line.split_once(" - ")?;
                    let fields: Vec<&str> = before.split(' ').collect();
                    let read_only = fields.get(5)?.split(',').any(|option| option == "ro");
                    (fields.get(4) == Some(path)).then(|| format!("{} {} {}", after.split(' ').next().unwrap_or("?"), fields[3], if read_only { "ro" } else { "rw" }))
                });
                let is_dir = std::path::Path::new(path).is_dir();
                let probe = if is_dir { format!("{path}/written") } else { path.to_string() };
                let wrote = match is_dir {
                    true => std::fs::write(&probe, "x").and_then(|()| std::fs::remove_file(&probe)),
                    false => std::fs::OpenOptions::new().append(true).open(&probe).map(drop),
                };
                println!("tell: mount {path} {} write {:?}", mount.as_deref().unwrap_or("none"), wrote.map_err(|e| e.kind()));
            }
            let mut said = Vec::new();
            loop {
                let mut now = Vec::new();
                paths.iter().for_each(|path| files(std::path::Path::new(path), &mut now));
                now.iter().filter(|line| !said.contains(*line)).for_each(|line| println!("tell: file {line}"));
                if said.is_empty() {
                    println!("tell: watching");
                }
                if paths.is_empty() {
                    break;
                }
                said = now;
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        ["echo"] => {
            // (On IPv6 and IPv4 both, where the pod has IPv6: the kernel sends a connection
            // on the node's own network to a replica's IPv6 address only.)
            let listener = TcpListener::bind("[::]:80").or_else(|_| TcpListener::bind("0.0.0.0:80")).expect("port 80");
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || echo(stream));
            }
        }
        ["check", host, port] => {
            let to = (&*String::leak(host.to_string()), port.parse::<u16>().expect("a port"));
            // (Its pod may still be starting, and its name not yet known.)
            let mut tries = 0;
            while let Err(e) = exchange(to, 1000, 0) {
                tries += 1;
                assert!(tries < 120, "check: {host} {port} never answered: {e}");
                std::thread::sleep(Duration::from_millis(500));
            }
            // What a connection there is to, as the client sees it: the Service's address
            // where kithd passes it on, the replica's where the kernel sent it straight there.
            let reached = TcpStream::connect(to).and_then(|stream| stream.peer_addr());
            println!("check: reached {}", reached.map_or_else(|e| e.to_string(), |at| at.to_string()));
            let mut failed = Vec::new();
            let mut connections = 0;
            // One after another, each closed as soon as all is sent: nothing, a byte, less
            // than a segment, a window's worth, more than any buffer holds.
            for i in 0..300 {
                failed.extend(exchange(to, [0, 1, 1000, 65536, 1 << 20][i % 5], 0).err());
                connections += 1;
            }
            // Side by side.
            let side: Vec<_> = (0..8u64)
                .map(|thread| {
                    std::thread::spawn(move || {
                        let sizes = [1, 4096, 65536, 300_000];
                        (0..40).filter_map(|i| exchange(to, sizes[(thread as usize + i) % 4] + thread, 0).err()).collect::<Vec<_>>()
                    })
                })
                .collect();
            for thread in side {
                failed.extend(thread.join().unwrap_or_else(|_| vec!["a thread panicked".to_string()]));
                connections += 40;
            }
            // Reset by either end with bytes on their way, then plain ones again.
            for mode in [1, 2, 0] {
                for i in 0..20 {
                    failed.extend(exchange(to, (1 << 20) + i, mode).err());
                    connections += 1;
                }
            }
            let rate = turns(to, 5000);
            failed.extend(rate.as_ref().err().cloned());
            for failure in &failed {
                println!("failed: {failure}");
            }
            println!("check: {connections} connections and one of 5000 turns ({:.0} a second), {} failed", rate.unwrap_or(0.0), failed.len());
            std::process::exit(if failed.is_empty() { 0 } else { 1 });
        }
        ["fill", file, bytes, how @ ..] => {
            let bytes: u64 = bytes.parse().expect("how many bytes");
            match std::fs::metadata(file) {
                Ok(was) => println!("fill: {file} was there: {} bytes", was.len()),
                Err(_) => println!("fill: an empty root"),
            }
            let mut out = std::fs::File::create(file).expect("the file it fills");
            if how == ["unlinked"] {
                std::fs::remove_file(file).expect("the file it fills, removed");
                println!("fill: {file} removed, held open");
            }
            let chunk = vec![7u8; 64 << 10];
            let mut wrote = 0;
            while wrote < bytes {
                if let Err(e) = out.write_all(&chunk).and_then(|()| out.sync_data()) {
                    println!("fill: a write failed after {wrote} bytes: {e}");
                    break;
                }
                wrote += chunk.len() as u64;
                std::thread::sleep(Duration::from_millis(500));
            }
            println!("fill: wrote {wrote} bytes");
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        ["probe"] => {
            std::thread::spawn(|| {
                let listener = TcpListener::bind("0.0.0.0:8080").expect("port 8080");
                for mut stream in listener.incoming().flatten() {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                    let _ = stream.read(&mut [0; 512]);
                    let _ = stream.write_all(b"HTTP/1.0 200 OK\r\n\r\nthe web of a pod behind an exit");
                }
            });
            std::thread::spawn(|| {
                let socket = UdpSocket::bind("0.0.0.0:8080").expect("UDP port 8080");
                let mut got = [0; 1500];
                while let Ok((n, from)) = socket.recv_from(&mut got) {
                    let _ = socket.send_to(&got[..n], from);
                }
            });
            let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
            let server = resolv.lines().find_map(|line| line.strip_prefix("nameserver ")?.trim().parse::<std::net::IpAddr>().ok());
            let server = SocketAddr::from((server.expect("a nameserver in /etc/resolv.conf"), 53));
            // (Its node, where a pod not behind an exit asks for names: kith-mesh's GATEWAY.)
            let node = SocketAddr::from(([100, 88, 0, 1], 53));
            let outside = SocketAddr::from(([198, 51, 100, 1], 80));
            for round in 1.. {
                let fetched = TcpStream::connect_timeout(&outside, Duration::from_secs(3)).and_then(|mut stream| {
                    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                    stream.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
                    let mut said = String::new();
                    stream.read_to_string(&mut said).map(|_| said)
                });
                let web = if fetched.is_ok_and(|said| said.contains("outside")) { "ok" } else { "failed" };
                // (A name std asks as every program does: musl, from /etc/resolv.conf.)
                use std::net::ToSocketAddrs;
                let named = format!("kithleak-{round}.example:80").to_socket_addrs();
                let named = if named.is_ok_and(|mut found| found.any(|at| at == outside)) { "ok" } else { "failed" };
                let tcp = asks(server, &format!("kithleak-tcp-{round}.example"), true);
                let asked_node = asks(node, &format!("kithleak-node-{round}.example"), false);
                let v6 = TcpStream::connect_timeout(&"[2001:db8::7]:80".parse().expect("an address"), Duration::from_secs(2));
                let v6 = match v6 {
                    Ok(_) => "connected".to_string(),
                    Err(e) => format!("{:?}", e.kind()),
                };
                if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
                    for to in ["203.0.113.7:9", "10.0.2.2:9"] {
                        let _ = socket.send_to(format!("kithleak {round}").as_bytes(), to);
                    }
                }
                println!("probe {round}: web {web} dns {named} tcp-dns {tcp} node-dns {asked_node} ipv6 {v6}");
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        // WHAT to TO over UDP, once a second for ten seconds: what the tunnel test's count
        // of the node's packets must see from a pod not behind an exit.
        ["shout", to, what] => {
            let socket = UdpSocket::bind("0.0.0.0:0").expect("a UDP socket");
            for _ in 0..10 {
                if let Err(e) = socket.send_to(what.as_bytes(), to) {
                    eprintln!("shout: {e}");
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        ["init", script] => {
            for (kind, at) in [("devtmpfs", "/dev"), ("proc", "/proc")] {
                let _ = std::fs::create_dir_all(at);
                let (kind, at) = (std::ffi::CString::new(kind).expect("a name"), std::ffi::CString::new(at).expect("a path"));
                // mount(2), by x86-64's number for it (as `node` asks mknod).
                let mut mounted: i64 = 165;
                unsafe {
                    std::arch::asm!(
                        "syscall",
                        inlateout("rax") mounted,
                        in("rdi") kind.as_ptr(),
                        in("rsi") at.as_ptr(),
                        in("rdx") kind.as_ptr(),
                        in("r10") 0u64,
                        in("r8") 0u64,
                        lateout("rcx") _,
                        lateout("r11") _,
                    );
                }
                assert!(mounted == 0, "init: mounting {at:?}: {mounted}");
            }
            let console = std::fs::OpenOptions::new().read(true).write(true).open("/dev/console").expect("a console");
            let mut out = console.try_clone().expect("the console, again");
            for line in std::fs::read_to_string(script).expect("the script").lines() {
                let left = line.starts_with("& ");
                let words: Vec<&str> = line.trim_start_matches("& ").split_whitespace().collect();
                let told = words.iter().take_while(|word| word.contains('=')).count();
                let Some((program, rest)) = words[told..].split_first() else { continue };
                let mut command = std::process::Command::new(program);
                command.args(rest).envs(words[..told].iter().filter_map(|word| word.split_once('=')));
                command.stdout(console.try_clone().expect("the console")).stderr(console.try_clone().expect("the console"));
                let done = match command.spawn() {
                    Ok(_) if left => Ok(()),
                    Ok(mut child) => match child.wait() {
                        Ok(status) if status.success() => Ok(()),
                        Ok(status) => Err(status.to_string()),
                        Err(e) => Err(e.to_string()),
                    },
                    Err(e) => Err(e.to_string()),
                };
                let _ = match done {
                    Ok(()) => writeln!(out, "init: ok: {line}"),
                    Err(why) => writeln!(out, "init: failed: {line}: {why}"),
                };
            }
            let _ = writeln!(out, "init: ready");
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        ["dns", address] => {
            let address: std::net::Ipv4Addr = address.parse().expect("an IPv4 address");
            std::thread::spawn(move || {
                let socket = UdpSocket::bind("0.0.0.0:53").expect("UDP port 53");
                let mut asked = [0; 512];
                while let Ok((n, from)) = socket.recv_from(&mut asked) {
                    if let Some((said, name)) = answer(&asked[..n], address) {
                        println!("dns: udp {name}");
                        let _ = socket.send_to(&said, from);
                    }
                }
            });
            let listener = TcpListener::bind("0.0.0.0:53").expect("TCP port 53");
            for mut stream in listener.incoming().flatten() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut length = [0; 2];
                let mut asked = vec![0; 512];
                if stream.read_exact(&mut length).is_err() || usize::from(u16::from_be_bytes(length)) > asked.len() {
                    continue;
                }
                asked.truncate(usize::from(u16::from_be_bytes(length)));
                if stream.read_exact(&mut asked).is_ok()
                    && let Some((said, name)) = answer(&asked, address)
                {
                    println!("dns: tcp {name}");
                    let _ = stream.write_all(&[&(said.len() as u16).to_be_bytes()[..], &said].concat());
                }
            }
        }
        _ => panic!("pod serve [FILE] | pod ask HOST PORT [HOST PORT ...] | pod seen DIR [SOCKET] | pod call SOCKET | pod self | pod node b|c NUMBERS PATH | pod put FILE TEXT | pod tell [PATH ...] | pod echo | pod check HOST PORT | pod fill FILE BYTES [unlinked] | pod probe | pod init SCRIPT | pod dns ADDRESS | pod shout TO WHAT"),
    }
}
