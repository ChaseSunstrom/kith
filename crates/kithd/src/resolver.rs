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
    let value = |key: &str| {
        let line = status.lines().find_map(|line| line.trim().strip_prefix(key));
        line.map(|rest| rest.split_whitespace().collect::<Vec<_>>())
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
    let ip = SERVER.ip().to_string();
    run(&["dns", interface, &ip])?;
    run(&["domain", interface, DOMAIN])?;
    run(&["default-route", interface, "false"]).map(drop)
}

/// [`register`] on this machine: the real directory and `resolvectl`.
pub fn apply(interface: &str, on: bool) -> Result<(), String> {
    let mut run = |args: &[&str]| {
        // ponytail: no time limit of its own: resolvectl's own D-Bus timeout (25 s) ends a hung resolved.
        let out = std::process::Command::new(RESOLVECTL)
            .args(args)
            .env("LC_ALL", "C")
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("resolvectl: {e}"))?;
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
                "dns kith0 127.0.0.87",
                "domain kith0 ~kith",
                "default-route kith0 false"
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
