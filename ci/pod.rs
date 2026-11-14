//! What `sh ci/vm.sh --test pods` runs in its pods: one file, built static with rustc
//! alone, and put in the nodes as a container image (they reach no registry there).
//!
//!   pod serve                  make a file in the root, then answer every connection on
//!                              port 80 with this pod's name
//!   pod ask HOST PORT [...]    ask each 40 times, and say each different answer's first
//!                              line once, to /dev/stdout opened by that name

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

fn asked(host: &str, port: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect((host, port.parse::<u16>().expect("a port")))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer)?;
    Ok(answer.lines().next().unwrap_or_default().to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match &args[1..] {
        ["serve"] => {
            std::fs::write("/made-here", "a pod's root takes a file").expect("a file in the root");
            let name = std::fs::read_to_string("/proc/sys/kernel/hostname").expect("a name");
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
        _ => panic!("pod serve | pod ask HOST PORT [HOST PORT ...]"),
    }
}
