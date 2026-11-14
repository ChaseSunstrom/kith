//! What `sh ci/vm.sh --test pods` runs in its pods: one file, built static with rustc
//! alone, and put in the nodes as a container image (they reach no registry there).
//!
//!   pod serve [FILE]           make a file in the root, then answer every connection on
//!                              port 80 (as HTTP) with this pod's name, what GREETING and
//!                              PASSWORD say where it is told them, and, given a FILE it
//!                              adds a line to at each start, how many lines that has
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

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

fn asked(host: &str, port: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect((host, port.parse::<u16>().expect("a port")))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer)?;
    let (first, last) = (answer.lines().next().unwrap_or_default(), answer.lines().last().unwrap_or_default());
    Ok(format!("{first} {last}"))
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
        _ => panic!("pod serve [FILE] | pod ask HOST PORT [HOST PORT ...] | pod seen DIR [SOCKET] | pod call SOCKET | pod self | pod node b|c NUMBERS PATH | pod put FILE TEXT | pod tell [PATH ...]"),
    }
}
