//! What `sh ci/vm.sh --test pods` runs in its pods: one file, built static with rustc
//! alone, and put in the nodes as a container image (they reach no registry there).
//!
//!   pod serve [FILE]           make a file in the root, then answer every connection on
//!                              port 80 (as HTTP) with this pod's name, what GREETING and
//!                              PASSWORD say where it is told them, and, given a FILE it
//!                              adds a line to at each start, how many lines that has
//!   pod ask HOST PORT [...]    ask each 40 times, and say each different answer's first
//!                              and last line once, to /dev/stdout opened by that name
//!   pod seen DIR               for as long as it runs, say the names in DIR each time they
//!                              change: those it can open with a `+`, the others with a `-`
//!   pod self                   say which process it is and whose, where it finds itself
//!   pod node b|c NUMBERS PATH  make at PATH a node of the block or character device whose
//!                              MAJOR:MINOR the file NUMBERS holds (one of /sys), read from
//!                              it, and say how both went

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
        ["seen", dir] => {
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
        _ => panic!("pod serve [FILE] | pod ask HOST PORT [HOST PORT ...] | pod seen DIR | pod self | pod node b|c NUMBERS PATH"),
    }
}
