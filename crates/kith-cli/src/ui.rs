//! `kith ui`: kithd's web UI for a browser on this machine.
//!
//! kithd serves the page on its socket, where whoever can open it is the admin; a
//! browser cannot open a socket, so this listens on a loopback port and passes requests
//! on. That port is then as good as the socket, and every program on the machine (and
//! every web page in its browsers) can reach it, so a request passes only if it
//! - is for a path under a secret this run made up and printed (the address to open),
//! - names this machine as its `Host` (a page that points its own name here does not), and
//! - comes from the page itself, when the browser says where from (`Origin`).

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

/// The most a request's head may be.
const HEAD: usize = 64 << 10;

/// The head of a request (without its last blank line) as kithd is to get it: the secret
/// taken off the path, one request to the connection. Or why it does not pass.
fn admit(head: &str, secret: &str) -> Result<String, &'static str> {
    const ODD: &str = "not an HTTP request";
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().splitn(3, ' ');
    let (Some(method), Some(target), Some(version)) = (first.next(), first.next(), first.next()) else {
        return Err(ODD);
    };
    let inside = target.strip_prefix('/').and_then(|target| target.strip_prefix(secret));
    let Some(path) = inside.filter(|path| path.starts_with('/')) else {
        return Err("this is not the address `kith ui` gave");
    };
    let mut passed = format!("{method} {path} {version}\r\n");
    let (mut host, mut origin) = (None, None);
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(ODD)?;
        // (Said once each: of two, kithd and this could each believe another. No line ends within a line.)
        if line.contains('\n') || line.contains('\r') {
            return Err(ODD);
        }
        match name.to_ascii_lowercase().as_str() {
            "host" if host.is_none() => host = Some(value.trim()),
            "origin" if origin.is_none() => origin = Some(value.trim()),
            "host" | "origin" => return Err(ODD),
            "connection" => continue,
            _ => {}
        }
        passed.push_str(line);
        passed.push_str("\r\n");
    }
    let host = host.ok_or(ODD)?;
    // (Any port: the browser may be at the other end of an `ssh -L`.)
    let name = host.rsplit_once(':').map_or(host, |(name, _port)| name);
    if !["127.0.0.1", "localhost", "[::1]"].contains(&name) {
        return Err("asked for under a name that is not this machine's own");
    }
    if origin.is_some_and(|origin| origin.strip_prefix("http://") != Some(host)) {
        return Err("asked for by another site's page");
    }
    passed.push_str("Connection: close\r\n\r\n");
    Ok(passed)
}

fn forward(mut browser: TcpStream, socket: &Path, secret: &str) -> io::Result<()> {
    // (Its head, promptly; after that a watch may wait as long as kithd lets it.)
    let by = Instant::now() + Duration::from_secs(10);
    let (mut read, mut some) = (Vec::new(), [0; 4096]);
    let end = loop {
        if let Some(end) = read.windows(4).position(|four| four == b"\r\n\r\n") {
            break end;
        }
        // (Ten seconds for all of it, however slowly it trickles in.)
        let Some(left) = by.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()) else {
            return Ok(());
        };
        browser.set_read_timeout(Some(left))?;
        let more = browser.read(&mut some)?;
        if more == 0 || read.len() > HEAD {
            return Ok(());
        }
        read.extend_from_slice(&some[..more]);
    };
    let refuse = |mut browser: TcpStream, status: &str, why: &str| {
        let length = why.len() + 1;
        write!(
            browser,
            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{why}\n"
        )
    };
    let head = match admit(&String::from_utf8_lossy(&read[..end]), secret) {
        Ok(head) => head,
        Err(why) => return refuse(browser, "403 Forbidden", why),
    };
    let mut kithd = match UnixStream::connect(socket) {
        Ok(kithd) => kithd,
        Err(e) => return refuse(browser, "502 Bad Gateway", &format!("kithd is not there: {e}")),
    };
    kithd.write_all(head.as_bytes())?;
    kithd.write_all(&read[end + 4..])?;
    browser.set_read_timeout(None)?;
    // The rest of what the browser sends (a body) goes on while the answer comes back.
    let (mut sending, mut taking) = (browser.try_clone()?, kithd.try_clone()?);
    std::thread::spawn(move || {
        let _ = io::copy(&mut sending, &mut taking);
        let _ = taking.shutdown(Shutdown::Write);
    });
    io::copy(&mut kithd, &mut browser)?;
    browser.shutdown(Shutdown::Both)
}

/// Serve until interrupted. The address to open is the one line on stdout.
pub fn serve(socket: &Path, port: u16) -> Result<(), String> {
    let listener =
        TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("error: listening on 127.0.0.1:{port}: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut random = [0u8; 16];
    let read = std::fs::File::open("/dev/urandom").and_then(|mut file| file.read_exact(&mut random));
    read.map_err(|e| format!("error: no randomness for the address: {e}"))?;
    let secret: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    eprintln!("kithd's web UI, as this machine's administrator, until this is stopped (ctrl-c).");
    eprintln!("The address is the key: anyone who has it and can reach this machine's loopback is that administrator.");
    println!("http://127.0.0.1:{port}/{secret}/ui/");
    io::stdout().flush().map_err(|e| e.to_string())?;
    // ponytail: a thread per connection, as many as come; it is one person's browser. A pool if that changes.
    for browser in listener.incoming().flatten() {
        let (socket, secret) = (socket.to_path_buf(), secret.clone());
        std::thread::spawn(move || drop(forward(browser, &socket, &secret)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::admit;

    #[test]
    fn ui_requests_pass_only_with_the_secret_from_this_machines_own_page() {
        let head =
            |target: &str, more: &str| format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:7000\r\nAccept: */*{more}");
        // The secret comes off the path; the connection is for this one request.
        let passed = admit(
            &head("/s3cret/v1/watch?after=4", "\r\nConnection: keep-alive"),
            "s3cret",
        )
        .unwrap();
        assert_eq!(
            passed,
            "GET /v1/watch?after=4 HTTP/1.1\r\nHost: 127.0.0.1:7000\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        let own = "\r\nOrigin: http://127.0.0.1:7000";
        assert!(admit(&head("/s3cret/v1/apply", own), "s3cret").is_ok());
        assert!(admit("GET /s3cret/ui/ HTTP/1.1\r\nhost: localhost:9000", "s3cret").is_ok());
        assert!(admit("GET /s3cret/ui/ HTTP/1.1\r\nHost: [::1]:9000", "s3cret").is_ok());
        // Without it, or with only its beginning: no.
        for target in [
            "/v1/apply",
            "/",
            "/s3cre/v1/apply",
            "/s3cretly/v1/apply",
            "/s3cret",
            "s3cret/v1/apply",
            "/x/s3cret/ui/",
        ] {
            assert!(admit(&head(target, ""), "s3cret").is_err(), "{target}");
        }
        // Another site's page, even one that knows the address; a name pointed at this machine.
        let said = admit(&head("/s3cret/v1/apply", "\r\nOrigin: http://evil.example"), "s3cret");
        assert_eq!(said, Err("asked for by another site's page"));
        assert!(admit(&head("/s3cret/v1/apply", "\r\nOrigin: null"), "s3cret").is_err());
        let rebound = "POST /s3cret/v1/apply HTTP/1.1\r\nHost: evil.example:7000";
        assert_eq!(
            admit(rebound, "s3cret"),
            Err("asked for under a name that is not this machine's own")
        );
        assert!(admit("GET /s3cret/ui/ HTTP/1.1\r\nAccept: */*", "s3cret").is_err());
        assert!(admit("nonsense", "s3cret").is_err());
        // Two Hosts, two Origins, or a line end inside a line: kithd might read them another way.
        let twice = "GET /s3cret/ui/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\nHost: evil.example";
        assert!(admit(twice, "s3cret").is_err());
        assert!(admit(&head("/s3cret/ui/", &format!("{own}{own}")), "s3cret").is_err());
        assert!(admit(&head("/s3cret/ui/", "\r\nX: a\nHost: evil.example"), "s3cret").is_err());
    }
}
