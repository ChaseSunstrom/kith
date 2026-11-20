//! What `sh ci/vm.sh --test pods` runs in its pods: one file, built static with rustc
//! alone, and put in the nodes as a container image (they reach no registry there).
//!
//!   pod serve [FILE]           make a file in the root, then answer every connection on
//!                              port 80 (as HTTP) with this pod's name, what GREETING and
//!                              PASSWORD say where it is told them, and, given a FILE it
//!                              adds a line to at each start, how many lines that has; at
//!                              start it says `where: nameserver IP from IP` (its resolver,
//!                              and the address it reaches it from: its node's pod range)
//!   pod say                    answer every connection on port 80 (as HTTP) with what
//!                              PASSWORD says, writing nowhere (its root may take no file)
//!   pod ask HOST PORT [...]    ask each 40 times, and say each different answer's first
//!                              and last line once, to /dev/stdout opened by that name
//!   pod once HOST PORT [...]   knock each once (two seconds): say "HOST:PORT answered: FIRST
//!                              LAST" (then one request's first and last line), "refused" (a
//!                              reset), or "silent" (nothing back), one line each
//!   pod peer                   on port 80 (v4 and v6), answer each connection with this pod's
//!                              name and the address it came from: "NAME peer4 ADDRESS" for
//!                              IPv4 (also as a v6 socket shows it), "NAME peer6 ADDRESS"
//!   pod v4only NAME PORT       try to turn IPv6 off in this namespace (disable_ipv6 = 1: a
//!                              pod's /proc/sys is read-only) and say whether it is off
//!                              ("ipv6: off": no inet6 address, the sysctl reads 1) or "ipv6:
//!                              on"; then say the IPv4 addresses NAME resolves to (asked
//!                              for up to 30 seconds until it has one) and,
//!                              30 times each, asking `pod peer` at the first of them by the
//!                              A record of its name and by its address as a literal, each
//!                              different answer:
//!                              "name: ANSWER", "literal: ANSWER"
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
//!   pod link TARGET PATH       make PATH a link to TARGET, and say how it went
//!   pod tick [N]               say which process it is and when it started, then `tick N`
//!                              each second, for as long as it runs (or N times, then end)
//!   pod memory                 run on a node: process 1's and kithd's resident memory
//!                              ("memory: PID COMM VmRSS RssAnon", kB)
//!   pod kill N SECONDS         run on a node (an exec unit): N times, SECONDS apart, kill
//!                              (SIGKILL) the process named kithd that is not process 1,
//!                              saying each pid
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
//!   pod fill FILE BYTES [unlinked] [fast]
//!                              say whether FILE was there (its root is empty if not), then
//!                              write BYTES to it, 64 KiB each half second, saying if a write
//!                              fails (the disk is full), and wait; unlinked: removes FILE
//!                              first and writes to it held open, with no name; fast: with
//!                              no half second between
//!   pod free PATH              say how many bytes the disk PATH is on has free for anyone
//!   pod tests DEVICE           as a machine's first process: kithd's project-quota tests on DEVICE
//!                              (as kithd weighs its reserve: blocks available times their size)
//!   pod probe                what `vm.sh --test tunnel` runs behind an exit: answers on
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
//!   pod ids|stays [PATH ...]   say its uid_map (whose ids it has on the node), then of each
//!                              PATH its owner as seen here and whether it opens; `+PATH` is
//!                              a file it writes first; `root-only` is a file of a PCI
//!                              device's in /sys that only the node's root opens; `=PATH`
//!                              says what the file holds; `:80` says whether port 80 binds;
//!                              stays: then wait
//!   pod quota STEP ...         (`sh ci/vm.sh --test quota`) say `quota: STEP RESULT` for each
//!                              step, then `quota: done`, and wait: `+FILE:BYTES` writes BYTES
//!                              to FILE, held open after; `~FILE:BYTES` the same with FILE
//!                              removed first; `^FILE` adds a byte to it; `-FILE` removes it;
//!                              `>A:B` renames A to B; `&A:B` links B to A; `?FILE` says its
//!                              project; `0FILE` sets that to 0 by ioctl, `!FILE` by
//!                              file_setattr(2); `#DIR` says size, used and free bytes there
//!                              (statfs); `=FILE` says its size; `@` says the first line of
//!                              its uid_map; `sN` sleeps N seconds

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

/// The signals ignored when the program began (SigIgn of its status), as its parent left them.
/// Rust's runtime ignores SIGPIPE before `main`, so `main` reads a later SigIgn with that bit
/// always set: this is read earlier, from `.init_array`, which the C runtime runs first.
static INHERITED_SIGIGN: std::sync::OnceLock<String> = std::sync::OnceLock::new();

#[used]
#[unsafe(link_section = ".init_array")]
static READ_SIGIGN: extern "C" fn() = {
    extern "C" fn read_sigign() {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let found = status.lines().find_map(|l| l.strip_prefix("SigIgn:")).unwrap_or("?");
        let _ = INHERITED_SIGIGN.set(found.trim().to_string());
    }
    read_sigign
};

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
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
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
                return Err(format!(
                    "nothing for 30 s after {at} of {length} bytes back (mode {mode})"
                ));
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
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    let _ = stream.set_nodelay(true);
    let failed = |e: std::io::Error| format!("turns: {e}");
    stream
        .write_all(&[&(count * 100).to_be_bytes()[..], &[0]].concat())
        .map_err(failed)?;
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
    let (first, last) = (
        answer.lines().next().unwrap_or_default(),
        answer.lines().last().unwrap_or_default(),
    );
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

/// Whether `to` takes a TCP connection within two seconds: "answered", "refused" (a reset:
/// something there said no), or "silent" (nothing came back at all).
fn knocked(to: SocketAddr) -> &'static str {
    match TcpStream::connect_timeout(&to, Duration::from_secs(2)) {
        Ok(_) => "answered",
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => "refused",
        Err(_) => "silent",
    }
}

/// Every file at or under `path` as "PATH MODE CONTENT", through links (as a mounted
/// ConfigMap has them) and past what such a mount keeps for itself (`..data` and the like).
fn files(path: &std::path::Path, found: &mut Vec<String>) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(has) = std::fs::metadata(path) else { return };
    if has.is_dir() {
        let mut inside: Vec<_> = std::fs::read_dir(path)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect();
        inside.sort();
        for path in inside.iter().filter(|path| {
            !path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".."))
        }) {
            files(path, found);
        }
    } else {
        let content = std::fs::read_to_string(path).unwrap_or_else(|e| format!("failed: {:?}", e.kind()));
        found.push(format!(
            "{} {:o} {}",
            path.display(),
            has.permissions().mode() & 0o777,
            content.trim()
        ));
    }
}

/// A system call by x86-64's number, asked of the kernel itself: this file has only std.
/// What it answers: 0 or more, or minus an errno.
fn syscall(number: i64, args: [u64; 5]) -> i64 {
    let mut said = number;
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") said,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    said
}

/// `ok`, or what the errno a system call answered says.
fn how(said: i64) -> String {
    match said {
        0.. => "ok".to_string(),
        e => std::io::Error::from_raw_os_error(-e as i32).to_string(),
    }
}

/// `ok` or what failed.
fn went<T>(done: std::io::Result<T>) -> String {
    done.map_or_else(|e| e.to_string(), |_| "ok".to_string())
}

/// Write `bytes` to `out`, 64 KiB a write, then sync: `wrote N`, or `failed after N` and why.
fn fill(out: &mut std::fs::File, bytes: u64) -> String {
    let chunk = [7u8; 64 << 10];
    let mut wrote = 0;
    while wrote < bytes {
        match out.write(&chunk[..chunk.len().min((bytes - wrote) as usize)]) {
            Ok(0) => return format!("failed after {wrote}: it wrote nothing"),
            Ok(n) => wrote += n as u64,
            Err(e) => return format!("failed after {wrote}: {e}"),
        }
    }
    match out.sync_all() {
        Ok(()) => format!("wrote {wrote}"),
        Err(e) => format!("failed after {wrote} at the sync: {e}"),
    }
}

/// One step of `pod quota`, and what came of it.
fn quota(step: &str, held: &mut Vec<std::fs::File>) -> String {
    use std::os::fd::AsRawFd;
    let (op, rest) = step.split_at(1);
    let (a, b) = rest.split_once(':').unwrap_or((rest, ""));
    let name = std::ffi::CString::new(a).expect("a path");
    match op {
        "+" | "~" => {
            let mut out = match std::fs::OpenOptions::new().create(true).append(true).open(a) {
                Ok(out) => out,
                Err(e) => return e.to_string(),
            };
            if op == "~"
                && let Err(e) = std::fs::remove_file(a)
            {
                return format!("not removed: {e}");
            }
            let said = fill(&mut out, b.parse().expect("how many bytes"));
            held.push(out);
            said
        }
        "^" => went(
            std::fs::OpenOptions::new()
                .append(true)
                .open(a)
                .and_then(|mut f| f.write_all(b"x")),
        ),
        "-" => went(std::fs::remove_file(a).or_else(|_| std::fs::remove_dir_all(a))),
        ">" => went(std::fs::rename(a, b)),
        "&" => went(std::fs::hard_link(a, b)),
        // Its project, and setting it to 0: FS_IOC_FSGETXATTR and FS_IOC_FSSETXATTR (struct
        // fsxattr, its project at byte 12), or file_setattr(2) (struct file_attr, at 16).
        "?" | "0" => {
            let file = match std::fs::File::open(a) {
                Ok(file) => file,
                Err(e) => return e.to_string(),
            };
            let mut attr = [0u32; 7];
            let got = syscall(
                16,
                [file.as_raw_fd() as u64, 0x801c_581f, attr.as_mut_ptr() as u64, 0, 0],
            );
            if got < 0 || op == "?" {
                return if got < 0 {
                    how(got)
                } else {
                    format!("project {}", attr[3])
                };
            }
            attr[3] = 0;
            how(syscall(
                16,
                [file.as_raw_fd() as u64, 0x401c_5820, attr.as_ptr() as u64, 0, 0],
            ))
        }
        "!" => {
            let attr = [0u32; 6];
            let at_fdcwd = -100i64 as u64;
            how(syscall(
                469,
                [at_fdcwd, name.as_ptr() as u64, attr.as_ptr() as u64, 24, 0],
            ))
        }
        // statfs(2): of a project's directory, its limit and what it holds, in bytes ("#") or
        // in files ("%").
        "#" | "%" => {
            let mut fs = [0u64; 15];
            let got = syscall(137, [name.as_ptr() as u64, fs.as_mut_ptr() as u64, 0, 0, 0]);
            if got < 0 {
                return how(got);
            }
            let block = fs[1];
            match op {
                "#" => format!(
                    "size {} used {} free {}",
                    fs[2] * block,
                    (fs[2] - fs[3]) * block,
                    fs[3] * block
                ),
                _ => format!("files {} held {}", fs[5], fs[5] - fs[6]),
            }
        }
        // Empty files in a directory (made first), up to that many: how many, and why no more.
        "*" => {
            if let Err(e) = std::fs::create_dir_all(a) {
                return e.to_string();
            }
            let most: u64 = b.parse().expect("how many files");
            for made in 0..most {
                if let Err(e) = std::fs::File::create(format!("{a}/{made}")) {
                    return format!("made {made}, then: {e}");
                }
            }
            format!("made {most}")
        }
        "s" => {
            std::thread::sleep(Duration::from_secs(a.parse().expect("seconds")));
            "ok".to_string()
        }
        "=" => std::fs::metadata(a).map_or_else(|e| e.to_string(), |meta| format!("size {}", meta.len())),
        // Whose users it has: the first line of its uid_map ("0 0 4294967295", the node's).
        "@" => match std::fs::read_to_string("/proc/self/uid_map") {
            Ok(map) => map
                .lines()
                .next()
                .unwrap_or("")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
            Err(e) => e.to_string(),
        },
        _ => panic!("pod quota: no step {step}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match &args[1..] {
        ["serve", keeps @ ..] if keeps.len() < 2 => {
            std::fs::write("/made-here", "a pod's root takes a file").expect("a file in the root");
            // Where it is told to ask for names, and the address it asks from (a UDP socket
            // connected sends nothing): both in its node's pod range.
            let resolv = std::fs::read_to_string("/etc/resolv.conf").expect("a resolv.conf");
            let ns = resolv
                .lines()
                .find_map(|line| line.strip_prefix("nameserver "))
                .expect("a nameserver")
                .trim();
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("a UDP socket");
            socket.connect(format!("{ns}:53")).expect("a way to the nameserver");
            println!(
                "where: nameserver {ns} from {}",
                socket.local_addr().expect("a local address").ip()
            );
            let mut name = std::fs::read_to_string("/proc/sys/kernel/hostname").expect("a name");
            name = format!("HTTP/1.0 200 OK\r\n\r\n{}", name.trim());
            for told in ["GREETING", "PASSWORD"] {
                name += &std::env::var(told).map(|told| format!(" {told}")).unwrap_or_default();
            }
            if let [file] = keeps {
                let mut kept = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(file)
                    .expect("the file it keeps");
                kept.write_all(b"started\n").expect("a line in the file it keeps");
                let lines = std::fs::read_to_string(file)
                    .expect("the file it keeps, read")
                    .lines()
                    .count();
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
            let was: u32 = std::fs::read_to_string(&file)
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            std::fs::write(&file, format!("{}\n", was + 1)).expect("its step, written down");
            match was {
                0 => println!("began: step 1"),
                _ => println!("went on from step {was}: step {}", was + 1),
            }
        }
        // What it was given (PASSWORD), to whoever asks on port 80: for a container on its
        // node's own network, whose root takes no file.
        ["say"] => {
            let said = format!(
                "HTTP/1.0 200 OK\r\n\r\n{}",
                std::env::var("PASSWORD").unwrap_or_default()
            );
            let listener = TcpListener::bind("0.0.0.0:80").expect("port 80");
            for mut stream in listener.incoming().flatten() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                let _ = stream.read(&mut [0; 512]);
                let _ = stream.write_all(said.as_bytes());
            }
        }
        // HOST PORT SECONDS: asks it ten times a second for that long and says how many
        // answers came, how many failed (the first, with why) and what the rest said: a
        // rolling update's check that something always answered.
        ["hammer", host, port, seconds] => {
            let until = std::time::Instant::now() + Duration::from_secs(seconds.parse().expect("seconds"));
            let (mut asked_n, mut failed, mut heard) = (0, Vec::new(), std::collections::BTreeSet::new());
            while std::time::Instant::now() < until {
                asked_n += 1;
                match asked(host, port) {
                    Ok(said) if said.starts_with("HTTP/1.0 200") => drop(heard.insert(said)),
                    Ok(said) => failed.push(format!("said {said:?}")),
                    Err(e) => failed.push(e.to_string()),
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            println!(
                "hammer: {asked_n} asked, {} failed ({}), heard {heard:?}",
                failed.len(),
                failed.first().map_or("none", String::as_str)
            );
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
        // Once each, two seconds at most (knocked): the egress cases, where a denied packet
        // hangs and asking forty times would take minutes.
        ["once", pairs @ ..] if !pairs.is_empty() && pairs.len() % 2 == 0 => {
            let out = std::fs::OpenOptions::new().write(true).open("/dev/stdout");
            let mut out = out.expect("/dev/stdout, by its name");
            for pair in pairs.chunks(2) {
                let resolved = std::net::ToSocketAddrs::to_socket_addrs(&(pair[0], pair[1].parse::<u16>().expect("a port")))
                    .ok()
                    .and_then(|mut found| found.next());
                let said = match resolved {
                    None => "unresolved".to_string(),
                    Some(addr) => match knocked(addr) {
                        "answered" => match asked(pair[0], pair[1]) {
                            Ok(first_last) => format!("answered: {first_last}"),
                            Err(e) => format!("answered, then failed: {e}"),
                        },
                        state => state.to_string(),
                    },
                };
                writeln!(out, "{}:{} {said}", pair[0], pair[1]).expect("a line out");
            }
        }
        // NAME...: the addresses this container's resolver gives each (what /etc/resolv.conf
        // says), on stdout, sorted; what it says when it gives none.
        ["lookup", names @ ..] if !names.is_empty() => {
            for name in names {
                match std::net::ToSocketAddrs::to_socket_addrs(&(*name, 0)) {
                    Ok(found) => {
                        let mut ips: Vec<String> = found.map(|addr| addr.ip().to_string()).collect();
                        ips.sort();
                        ips.dedup();
                        println!("{name}: {ips:?}");
                    }
                    Err(e) => println!("{name}: failed: {e}"),
                }
            }
        }
        ["peer"] => {
            let name = std::fs::read_to_string("/proc/sys/kernel/hostname").expect("a name");
            let listener = TcpListener::bind("[::]:80").expect("port 80");
            for mut stream in listener.incoming().flatten() {
                let from = stream.peer_addr().map(|a| a.ip().to_canonical());
                let said = match from {
                    Ok(std::net::IpAddr::V4(ip)) => format!("{} peer4 {ip}", name.trim()),
                    Ok(ip) => format!("{} peer6 {ip}", name.trim()),
                    Err(e) => format!("{} peer failed {e}", name.trim()),
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                let _ = stream.read(&mut [0; 512]);
                let _ = stream.write_all(format!("HTTP/1.0 200 OK\r\n\r\n{said}").as_bytes());
            }
        }
        ["v4only", name, port] => {
            let out = std::fs::OpenOptions::new().write(true).open("/dev/stdout");
            let mut out = out.expect("/dev/stdout, by its name");
            let sysctl = "/proc/sys/net/ipv6/conf/all/disable_ipv6";
            let wrote = std::fs::write(sysctl, "1");
            let inet6 = std::fs::read_to_string("/proc/net/if_inet6").unwrap_or_default();
            let reads = std::fs::read_to_string(sysctl).unwrap_or_default();
            // (A pod's /proc/sys is read-only, so in a pod this stays "on": the Service's IPv4
            // address is still asked for, by the A record and as a literal, which a v6 fallback
            // cannot do. The no-IPv6 namespace itself is proved in kith-mesh's pod tests.)
            if inet6.trim().is_empty() && reads.trim() == "1" {
                writeln!(out, "ipv6: off").expect("a line out");
            } else {
                writeln!(out, "ipv6: on: wrote {wrote:?}, sysctl {:?}", reads.trim()).expect("a line out");
            }
            let port: u16 = port.parse().expect("a port");
            // (The Service's address comes a moment after the Service: asked for up to 30 s.)
            let mut v4: Vec<std::net::Ipv4Addr> = Vec::new();
            for _ in 0..30 {
                let found = std::net::ToSocketAddrs::to_socket_addrs(&(*name, port));
                v4 = found
                    .into_iter()
                    .flatten()
                    .filter_map(|addr| match addr.ip() {
                        std::net::IpAddr::V4(ip) => Some(ip),
                        std::net::IpAddr::V6(_) => None,
                    })
                    .collect();
                if !v4.is_empty() {
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            writeln!(out, "addresses: {v4:?}").expect("a line out");
            let Some(first) = v4.first() else { return };
            let mut heard = std::collections::BTreeSet::new();
            for _ in 0..30 {
                // (By name: the A record, asked again each time, and its address connected to.)
                let named = std::net::ToSocketAddrs::to_socket_addrs(&(*name, port))
                    .into_iter()
                    .flatten()
                    .find(|addr| addr.is_ipv4())
                    .map_or_else(|| name.to_string(), |addr| addr.ip().to_string());
                for (how, host) in [("name", named), ("literal", first.to_string())] {
                    heard.insert(format!(
                        "{how}: {}",
                        asked(&host, &port.to_string()).unwrap_or_else(|e| format!("failed: {host}: {e}"))
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
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
                        let opens = if std::fs::File::open(entry.path()).is_ok() {
                            '+'
                        } else {
                            '-'
                        };
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
            let uid = status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:")?.split_whitespace().next());
            println!("nested: pid {}, uid {}", std::process::id(), uid.unwrap_or("?"));
        }
        ["node", kind, numbers, path] => {
            let said = std::fs::read_to_string(numbers).expect("the device's numbers");
            let (major, minor) = said.trim().split_once(':').expect("MAJOR:MINOR");
            let (major, minor): (u64, u64) = (major.parse().expect("a major"), minor.parse().expect("a minor"));
            let device = (major & 0xfff) << 8 | minor & 0xff | (minor & !0xff) << 12 | (major & !0xfff) << 32;
            let mode: u64 = if *kind == "b" { 0o060600 } else { 0o020600 };
            let name = std::ffi::CString::new(*path).expect("a path");
            // mknod(2): std makes no device nodes.
            let made = syscall(133, [name.as_ptr() as u64, mode, device, 0, 0]);
            let read = std::fs::File::open(path).and_then(|mut node| node.read(&mut [0; 512]));
            let status = std::fs::read_to_string("/proc/self/status").expect("a /proc to read itself in");
            let eff = status.lines().find_map(|line| line.strip_prefix("CapEff:")).map_or("?", str::trim);
            println!("node: made {made}, read {read:?}, caps eff {eff}");
        }
        [how @ ("ids" | "stays"), paths @ ..] => {
            use std::os::unix::fs::MetadataExt;
            let map = std::fs::read_to_string("/proc/self/uid_map").expect("its uid_map");
            println!("ids: map {}", map.split_whitespace().collect::<Vec<_>>().join(" "));
            for path in paths {
                if let Some(read) = path.strip_prefix('=') {
                    let holds = std::fs::read_to_string(read)
                        .map(|text| text.trim().to_string())
                        .map_err(|e| e.kind());
                    println!("ids: {path} holds {holds:?}");
                    continue;
                }
                if *path == ":80" {
                    println!(
                        "ids: :80 binds {:?}",
                        TcpListener::bind("[::]:80")
                            .or_else(|_| TcpListener::bind("0.0.0.0:80"))
                            .map(drop)
                            .map_err(|e| e.kind())
                    );
                    continue;
                }
                let found = if *path == "root-only" {
                    // (A BAR of a device: 0600 and the node's root's, as sysfs makes it.)
                    let devices = std::fs::read_dir("/sys/bus/pci/devices")
                        .into_iter()
                        .flatten()
                        .flatten();
                    let files =
                        devices.flat_map(|device| std::fs::read_dir(device.path()).into_iter().flatten().flatten());
                    let named = |name: &str| name.strip_prefix("resource").is_some_and(|n| n.parse::<u8>().is_ok());
                    let found = files
                        .map(|file| file.path())
                        .find(|path| path.file_name().is_some_and(|n| named(&n.to_string_lossy())));
                    found.unwrap_or_default()
                } else if let Some(made) = path.strip_prefix('+') {
                    if let Err(e) = std::fs::write(made, "made") {
                        println!("ids: {path} not written: {e}");
                    }
                    made.into()
                } else {
                    path.into()
                };
                let owner =
                    std::fs::metadata(&found).map_or_else(|e| format!("{:?}", e.kind()), |has| has.uid().to_string());
                let opens = std::fs::File::open(&found).map(drop).map_err(|e| e.kind());
                println!("ids: {path} {} owner {owner} opens {opens:?}", found.display());
            }
            while *how == "stays" {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        ["link", target, path] => {
            let made = std::os::unix::fs::symlink(target, path).map_err(|e| e.kind());
            println!("link: {path} -> {target}: {made:?}");
        }
        ["tick", times @ ..] => {
            // Field 22 of its stat: when it started, in clock ticks since the machine did.
            let stat = std::fs::read_to_string("/proc/self/stat").expect("its stat");
            let start = stat.rsplit(") ").next().and_then(|rest| rest.split(' ').nth(19)).unwrap_or("?");
            println!("tick: process {} started at {start}", std::process::id());
            // The signals it has blocked (SigBlk of its status): kithd's own mask is not its pods'.
            let status = std::fs::read_to_string("/proc/self/status").expect("its status");
            let blocked = status.lines().find_map(|l| l.strip_prefix("SigBlk:")).unwrap_or("?").trim();
            println!("tick: blocked {blocked}");
            println!("tick: ignored {}", INHERITED_SIGIGN.get().map_or("?", |s| s.as_str()));
            let last: u64 = times.first().map_or(u64::MAX, |n| n.parse().expect("N"));
            for n in 1..=last {
                println!("tick {n}");
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        ["bootid"] => {
            // This boot of the machine (the kernel's, the same for every container on it).
            let id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
            println!("bootid: {}", id.trim());
        }
        ["memory"] => {
            // Process 1 and kithd: "memory: PID COMM VmRSS RssAnon" (kB).
            for entry in std::fs::read_dir("/proc").expect("/proc").flatten() {
                let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
                let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
                if pid != 1 && comm.trim() != "kithd" {
                    continue;
                }
                let status = std::fs::read_to_string(entry.path().join("status")).unwrap_or_default();
                let kb = |field: &str| status.lines().find_map(|l| l.strip_prefix(field)?.split_whitespace().next()).unwrap_or("?").to_string();
                println!("memory: {pid} {} {} {}", comm.trim(), kb("VmRSS:"), kb("RssAnon:"));
            }
        }
        ["kill", times, gap] => {
            let (times, gap): (u32, u64) = (times.parse().expect("N"), gap.parse().expect("SECONDS"));
            for _ in 0..times {
                let kithd = std::fs::read_dir("/proc").expect("/proc").flatten().find_map(|entry| {
                    let pid: i64 = entry.file_name().to_str()?.parse().ok()?;
                    let comm = std::fs::read_to_string(entry.path().join("comm")).ok()?;
                    (pid != 1 && comm.trim() == "kithd").then_some(pid)
                });
                match kithd {
                    // (62: kill, 9: SIGKILL.)
                    Some(pid) => println!("kill: kithd {pid}: {}", syscall(62, [pid as u64, 9, 0, 0, 0])),
                    None => println!("kill: no kithd"),
                }
                std::thread::sleep(Duration::from_secs(gap));
            }
        }
        ["put", file, text] => {
            std::thread::sleep(Duration::from_secs(3));
            std::fs::write(file, text).expect("the file it was told to write");
            println!("put: {file}");
        }
        ["tell", paths @ ..] => {
            let status = std::fs::read_to_string("/proc/self/status").expect("a /proc to read itself in");
            let of = |key: &str| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix(key)?.split_whitespace().next())
                    .unwrap_or("?")
            };
            println!(
                "tell: started uid {} caps eff {} bnd {}",
                of("Uid:"),
                of("CapEff:"),
                of("CapBnd:")
            );
            let mut told: Vec<String> = std::env::vars()
                .map(|(name, value)| format!("{name}={value}"))
                .collect();
            told.sort();
            told.iter().for_each(|told| println!("tell: env {told}"));
            let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
            for path in paths {
                // (mountinfo(5): ID PARENT MAJOR:MINOR ROOT WHERE OPTIONS ... - TYPE SOURCE ...)
                let mount = mounts.lines().rev().find_map(|line| {
                    let (before, after) = line.split_once(" - ")?;
                    let fields: Vec<&str> = before.split(' ').collect();
                    let read_only = fields.get(5)?.split(',').any(|option| option == "ro");
                    (fields.get(4) == Some(path)).then(|| {
                        format!(
                            "{} {} {}",
                            after.split(' ').next().unwrap_or("?"),
                            fields[3],
                            if read_only { "ro" } else { "rw" }
                        )
                    })
                });
                let is_dir = std::path::Path::new(path).is_dir();
                let probe = if is_dir {
                    format!("{path}/written")
                } else {
                    path.to_string()
                };
                let wrote = match is_dir {
                    true => std::fs::write(&probe, "x").and_then(|()| std::fs::remove_file(&probe)),
                    false => std::fs::OpenOptions::new().append(true).open(&probe).map(drop),
                };
                println!(
                    "tell: mount {path} {} write {:?}",
                    mount.as_deref().unwrap_or("none"),
                    wrote.map_err(|e| e.kind())
                );
            }
            let mut said = Vec::new();
            loop {
                let mut now = Vec::new();
                paths
                    .iter()
                    .for_each(|path| files(std::path::Path::new(path), &mut now));
                now.iter()
                    .filter(|line| !said.contains(*line))
                    .for_each(|line| println!("tell: file {line}"));
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
            let listener = TcpListener::bind("[::]:80")
                .or_else(|_| TcpListener::bind("0.0.0.0:80"))
                .expect("port 80");
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
            println!(
                "check: reached {}",
                reached.map_or_else(|e| e.to_string(), |at| at.to_string())
            );
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
                        (0..40)
                            .filter_map(|i| exchange(to, sizes[(thread as usize + i) % 4] + thread, 0).err())
                            .collect::<Vec<_>>()
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
            println!(
                "check: {connections} connections and one of 5000 turns ({:.0} a second), {} failed",
                rate.unwrap_or(0.0),
                failed.len()
            );
            std::process::exit(if failed.is_empty() { 0 } else { 1 });
        }
        ["fill", file, bytes, how @ ..] => {
            let bytes: u64 = bytes.parse().expect("how many bytes");
            match std::fs::metadata(file) {
                Ok(was) => println!("fill: {file} was there: {} bytes", was.len()),
                Err(_) => println!("fill: an empty root"),
            }
            let mut out = std::fs::File::create(file).expect("the file it fills");
            if how.contains(&"unlinked") {
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
                if !how.contains(&"fast") {
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
            println!("fill: wrote {wrote} bytes");
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        ["tests", device] => {
            // The first process of a machine of its own (ci/vm/quota.sh): kithd's tests of the
            // project-quota path, which set a project's limit (CAP_SYS_ADMIN, which no pod has),
            // run as root in `device`, a state partition made with projects, mounted as kithd
            // mounts it. Then the machine is powered off.
            let c = |text: &str| std::ffi::CString::new(text).expect("no NUL");
            let mount = |source: &str, target: &str, kind: &str, data: &str| {
                let _ = std::fs::create_dir_all(target);
                let (source, target, kind, data) = (c(source), c(target), c(kind), c(data));
                let at = [source.as_ptr(), target.as_ptr(), kind.as_ptr()].map(|p| p as u64);
                syscall(165, [at[0], at[1], at[2], 0, data.as_ptr() as u64])
            };
            mount("dev", "/dev", "devtmpfs", "");
            // (Its own stdout and stderr, and its tests': the kernel found no /dev/console to
            // give it, which the memory disk has not.)
            let console = std::fs::OpenOptions::new().write(true).open("/dev/console").expect("a console");
            for fd in [1, 2] {
                syscall(33, [std::os::fd::AsRawFd::as_raw_fd(&console) as u64, fd, 0, 0, 0]);
            }
            mount("proc", "/proc", "proc", "");
            let said = mount(device, "/state", "ext4", "prjquota");
            println!("tests: {device} mounted: {said}");
            std::fs::create_dir_all("/state/unit-tests").expect("a directory for them");
            let ran = std::process::Command::new("/kithd-tests")
                .args(["storage_projects_", "--test-threads=1", "--nocapture"])
                .env("TMPDIR", "/state/unit-tests")
                .status();
            println!("tests: {ran:?}");
            let _ = std::fs::remove_dir_all("/state/unit-tests");
            syscall(162, [0; 5]);
            // reboot(2): LINUX_REBOOT_CMD_POWER_OFF.
            syscall(169, [0xfee1dead, 672274793, 0x4321fedc, 0, 0]);
        }
        // Its open-file limits as the kernel keeps them (/proc/self/limits: soft, then hard).
        ["nofile"] => {
            let limits = std::fs::read_to_string("/proc/self/limits").expect("its limits");
            let line = limits.lines().find(|l| l.starts_with("Max open files")).expect("a limit of files");
            let mut words = line.split_whitespace().skip(3);
            println!("nofile: {} {}", words.next().expect("soft"), words.next().expect("hard"));
        }
        ["free", path] => {
            // statfs(2): struct statfs is 15 words on x86-64; f_bavail the 5th, f_frsize the 10th.
            let name = std::ffi::CString::new(*path).expect("a path");
            let mut found = [0u64; 15];
            let said = syscall(137, [name.as_ptr() as u64, found.as_mut_ptr() as u64, 0, 0, 0]);
            assert!(said == 0, "statfs {path}: errno {}", -said);
            println!("free: {path} {}", found[4] * found[9]);
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
            let server = resolv.lines().find_map(|line| {
                line.strip_prefix("nameserver ")?
                    .trim()
                    .parse::<std::net::IpAddr>()
                    .ok()
            });
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
                let web = if fetched.is_ok_and(|said| said.contains("outside")) {
                    "ok"
                } else {
                    "failed"
                };
                // (A name std asks as every program does: musl, from /etc/resolv.conf.)
                use std::net::ToSocketAddrs;
                let named = format!("kithleak-{round}.example:80").to_socket_addrs();
                let named = if named.is_ok_and(|mut found| found.any(|at| at == outside)) {
                    "ok"
                } else {
                    "failed"
                };
                let tcp = asks(server, &format!("kithleak-tcp-{round}.example"), true);
                let asked_node = asks(node, &format!("kithleak-node-{round}.example"), false);
                // (kithd's own API on its node, as any service of the node's: not for it.)
                let api = knocked(SocketAddr::from(([100, 88, 0, 1], 7443)));
                let v6 = TcpStream::connect_timeout(
                    &"[2001:db8::7]:80".parse().expect("an address"),
                    Duration::from_secs(2),
                );
                let v6 = match v6 {
                    Ok(_) => "connected".to_string(),
                    Err(e) => format!("{:?}", e.kind()),
                };
                if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
                    for to in ["203.0.113.7:9", "10.0.2.2:9"] {
                        let _ = socket.send_to(format!("kithleak {round}").as_bytes(), to);
                    }
                }
                println!(
                    "probe {round}: web {web} dns {named} tcp-dns {tcp} node-dns {asked_node} node-api {api} ipv6 {v6}"
                );
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        // Whether TO takes a TCP connection, once a second, said when it changes: from the
        // provider's end of a tunnel, what the tunnel's node must never answer.
        ["knock", to] => {
            let to: SocketAddr = to.parse().expect("an address and port");
            let mut was = "";
            loop {
                let now = knocked(to);
                if now != was {
                    println!("knock: {to} {now}");
                    was = now;
                }
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
                let (kind, at) = (
                    std::ffi::CString::new(kind).expect("a name"),
                    std::ffi::CString::new(at).expect("a path"),
                );
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
            let console = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/console")
                .expect("a console");
            let mut out = console.try_clone().expect("the console, again");
            for line in std::fs::read_to_string(script).expect("the script").lines() {
                let left = line.starts_with("& ");
                let words: Vec<&str> = line.trim_start_matches("& ").split_whitespace().collect();
                let told = words.iter().take_while(|word| word.contains('=')).count();
                let Some((program, rest)) = words[told..].split_first() else {
                    continue;
                };
                let mut command = std::process::Command::new(program);
                command
                    .args(rest)
                    .envs(words[..told].iter().filter_map(|word| word.split_once('=')));
                command
                    .stdout(console.try_clone().expect("the console"))
                    .stderr(console.try_clone().expect("the console"));
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
        ["quota", steps @ ..] => {
            let mut held = Vec::new();
            for step in steps {
                println!("quota: {step} {}", quota(step, &mut held));
            }
            println!("quota: done");
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
                        println!("dns: udp {name} from {from}");
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
        _ => panic!(
            "pod serve [FILE] | pod ask HOST PORT [HOST PORT ...] | pod lookup NAME... | pod seen DIR [SOCKET] | pod call SOCKET | pod self | pod node b|c NUMBERS PATH | pod put FILE TEXT | pod tell [PATH ...] | pod echo | pod check HOST PORT | pod fill FILE BYTES [unlinked] | pod quota STEP... | pod probe | pod knock TO | pod init SCRIPT | pod dns ADDRESS | pod shout TO WHAT"
        ),
    }
}
