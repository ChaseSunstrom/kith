//! `--resolver`: this machine's own programs get the cluster's `.kith` names. kithd serves its DNS on
//! 127.0.0.87:53 (127/8 is martian on every other link, so it answers this machine only), and while
//! the mesh interface is up systemd-resolved is told, for that link alone, to send the routing domain
//! `~kith` there and nothing else (default route off). The entry is on the link and in resolved's
//! memory: no file is written, and it goes with the link or `resolvectl revert`.
//!
//! The root part runs `resolvectl` ([`apply`]): what it may register is fixed here, so a request names
//! an interface and nothing else.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Where kithd serves `.kith` for this machine's resolver.
pub const SERVER: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 87)), 53);
/// The only domain sent there: a routing domain (`~`), so no other name goes to it.
const DOMAIN: &str = "~kith";
/// systemd-resolved's runtime directory: where it is, it runs.
const RESOLVED: &str = "/run/systemd/resolve";
const RESOLVECTL: &str = "/usr/bin/resolvectl";

/// Whether `status` (`resolvectl status IF`) shows the link as this module sets it: DNS server
/// 127.0.0.87 alone, the domain `~kith` alone, and no default route.
fn is_set(status: &str) -> bool {
    // A line that starts a field ("DNS Servers: ..."), not one that goes on (a second server, which an
    // IPv6 address with its colons is not: a field starts with a capital and has a space or end after the colon).
    let field = |line: &str| {
        line.trim().split_once(':').is_some_and(|(name, rest)| {
            name.starts_with(|c: char| c.is_ascii_uppercase())
                && name.chars().all(|c| c.is_ascii_alphabetic() || c == ' ')
                && (rest.is_empty() || rest.starts_with(' '))
        })
    };
    // The values of a field: the rest of its line and the lines that go on under it.
    let value = |key: &str| {
        let mut lines = status.lines().skip_while(|line| !line.trim().starts_with(key));
        let first = lines.next()?.trim().strip_prefix(key)?;
        let more = lines.take_while(|line| !line.trim().is_empty() && !field(line));
        Some(
            first
                .split_whitespace()
                .chain(more.flat_map(str::split_whitespace))
                .collect::<Vec<_>>(),
        )
    };
    value("DNS Servers:") == Some(vec![SERVER.ip().to_string().as_str()])
        && value("DNS Domain:") == Some(vec![DOMAIN])
        && value("Default Route:") == Some(vec!["no"])
}

/// Register kithd's DNS for `~kith` on `interface` (`on`), or take it back. `dir` is resolved's
/// runtime directory and `run` runs `resolvectl` with these arguments and returns what it printed.
/// Without `dir` nothing is run. On, the link is read first and set only when it is not as wanted:
/// resolved logs each change, and this is asked every half minute.
pub fn register(
    dir: &Path,
    interface: &str,
    on: bool,
    run: &mut dyn FnMut(&[&str]) -> Result<String, String>,
) -> Result<(), String> {
    if !dir.is_dir() {
        return Err(format!(
            "no systemd-resolved ({} is not there): this machine's programs do not get .kith names; nothing written",
            dir.display()
        ));
    }
    if !on {
        return run(&["revert", interface]).map(drop);
    }
    if is_set(&run(&["status", interface])?) {
        return Ok(());
    }
    // The server goes last: a link with a server and no routing domain is a default-route link, and a
    // failure between the calls would send every name to kithd, which asks resolved: a loop.
    let ip = SERVER.ip().to_string();
    run(&["default-route", interface, "false"])?;
    run(&["domain", interface, DOMAIN])?;
    run(&["dns", interface, &ip]).map(drop)
}

/// How long one `resolvectl` may take: it runs while the meshing lock is held, and a hung resolved must not hold it.
const LIMIT: Duration = Duration::from_secs(5);

/// What `command` printed, killed (and an error) if it is still running after `limit`. The output is
/// read after it ends: resolvectl's is far under a pipe's size, so it never blocks on a full one.
fn output_within(command: &mut Command, limit: Duration) -> Result<Output, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let start = Instant::now();
    while child.try_wait().map_err(|e| e.to_string())?.is_none() {
        if start.elapsed() >= limit {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("no answer in {} s, killed", limit.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().map_err(|e| e.to_string())
}

/// [`register`] on this machine: the real directory and `resolvectl`.
pub fn apply(interface: &str, on: bool) -> Result<(), String> {
    let mut run = |args: &[&str]| {
        let mut command = std::process::Command::new(RESOLVECTL);
        command.args(args).env("LC_ALL", "C");
        let out = output_within(&mut command, LIMIT).map_err(|e| format!("resolvectl {}: {e}", args.join(" ")))?;
        match out.status.success() {
            true => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
            false => Err(format!(
                "resolvectl {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        }
    };
    register(Path::new(RESOLVED), interface, on, &mut run)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SET: &str = "Link 3 (kith0)\n    Current Scopes: DNS\n         Protocols: -DefaultRoute\n\
        Current DNS Server: 127.0.0.87\n       DNS Servers: 127.0.0.87\n        DNS Domain: ~kith\n     Default Route: no\n";

    /// What the root part runs, for a link: only 127.0.0.87 and `~kith`, whatever the interface is
    /// called, and `resolvectl revert` to take it back.
    #[test]
    fn resolver_registers_only_the_loopback_server_for_kith() {
        let mut ran: Vec<String> = Vec::new();
        let mut run = |args: &[&str]| {
            ran.push(args.join(" "));
            Ok(String::new())
        };
        register(Path::new("/"), "kith0", true, &mut run).unwrap();
        assert_eq!(
            ran,
            [
                "status kith0",
                "default-route kith0 false",
                "domain kith0 ~kith",
                "dns kith0 127.0.0.87"
            ]
        );
        ran.clear();
        let mut run = |args: &[&str]| {
            ran.push(args.join(" "));
            Ok(String::new())
        };
        register(Path::new("/"), "kith0", false, &mut run).unwrap();
        assert_eq!(ran, ["revert kith0"]);
        assert_eq!(SERVER, "127.0.0.87:53".parse().unwrap());
    }

    /// A link that is as wanted is read and not set again (resolved's journal is not filled); one
    /// that lost any of the three is set.
    #[test]
    fn resolver_sets_again_only_when_the_link_lost_it() {
        let mut ran = 0;
        let mut run = |args: &[&str]| {
            ran += 1;
            Ok(if args[0] == "status" {
                SET.to_string()
            } else {
                String::new()
            })
        };
        register(Path::new("/"), "kith0", true, &mut run).unwrap();
        assert_eq!(ran, 1);
        for lost in ["DNS Servers: 127.0.0.87", "DNS Domain: ~kith", "Default Route: no"] {
            assert!(!is_set(&SET.replace(lost, "")), "{lost}");
        }
        assert!(!is_set(
            &SET.replace("DNS Servers: 127.0.0.87", "DNS Servers: 127.0.0.87 192.0.2.1")
        ));
        assert!(!is_set(&SET.replace("Default Route: no", "Default Route: yes")));
    }

    /// resolvectl prints a second server or domain on the line below the first, with no key: the link
    /// is not as wanted then, though the first line is.
    #[test]
    fn resolver_reads_the_lines_that_go_on_under_a_field() {
        let more = |key: &str, value: &str, extra: &str| {
            let line = format!("{key} {value}\n");
            SET.replace(&line, &format!("{line}                    {extra}\n"))
        };
        assert!(is_set(SET));
        for extra in ["192.0.2.1", "fe80::1%2", "abcd::1"] {
            assert!(!is_set(&more("DNS Servers:", "127.0.0.87", extra)), "{extra}");
        }
        assert!(!is_set(&more("DNS Domain:", "~kith", "example.test")));
    }

    /// A resolvectl that does not answer is killed after the limit, and one that does is read.
    #[test]
    fn resolver_command_that_hangs_is_killed() {
        let started = Instant::now();
        let err = output_within(Command::new("sleep").arg("30"), Duration::from_millis(200)).unwrap_err();
        assert!(err.contains("killed"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
        let out = output_within(Command::new("echo").arg("up"), Duration::from_secs(10)).unwrap();
        assert_eq!(out.stdout, b"up\n");
    }

    /// Without systemd-resolved's directory nothing is run and nothing is written; the error says so.
    #[test]
    fn resolver_without_systemd_resolved_runs_nothing() {
        let gone = std::env::temp_dir().join(format!("kith-no-resolved-{}", std::process::id()));
        let mut run = |_: &[&str]| -> Result<String, String> { panic!("resolvectl run with no resolved") };
        for on in [true, false] {
            let said = register(&gone, "kith0", on, &mut run).unwrap_err();
            assert!(
                said.contains("no systemd-resolved") && said.contains("nothing written"),
                "{said}"
            );
        }
        assert!(!gone.exists());
    }
}
