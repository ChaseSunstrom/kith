//! Three network namespaces as three nodes, on a line: a and c each have a wire to b and
//! none to each other. Run with `KITH_E2E=1`; needs unprivileged user namespaces and the
//! `unshare`, `ip` and `ping` programs, and says so when it skips.
//!
//! `e2e.sh` builds the namespaces and runs this same program in them as its tool: the
//! arguments `up`, `peers`, `show`, `address` and `down` below.

use kith_mesh::{Device, Member, node_address, prefix, wanted};
use std::process::Command;

const INTERFACE: &str = "kith0";
const PORT: u16 = 51820;

fn hex(key: &[u8]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key(hex: &str) -> [u8; 32] {
    let byte = |at| u8::from_str_radix(&hex[2 * at..2 * at + 2], 16).unwrap();
    std::array::from_fn(byte)
}

/// The interface as `up` left it (the key is not looked at again: `private` is the node's).
fn device(seed: &str, name: &str, private: &str) -> Device {
    let address = node_address(prefix(seed.as_bytes()), name);
    Device::ensure(INTERFACE, &key(private), PORT, address).expect("the interface")
}

fn tool(args: &[&str]) {
    match args {
        ["address", seed, name] => println!("{}", node_address(prefix(seed.as_bytes()), name)),
        ["up", seed, name, private] => {
            println!("{}", hex(&device(seed, name, private).public_key().unwrap()));
        }
        // Each member: name,public key,endpoint or -,edge (0 or 1),reached (0 or 1).
        ["peers", seed, name, private, members @ ..] => {
            let member = |text: &&str| {
                let part: Vec<&str> = text.split(',').collect();
                Member {
                    name: part[0].into(),
                    key: key(part[1]),
                    endpoint: part[2].parse().ok(),
                    edge: part[3] == "1",
                    reached: part[4] == "1",
                }
            };
            let members: Vec<Member> = members.iter().map(member).collect();
            let peers = wanted(prefix(seed.as_bytes()), name, &members);
            device(seed, name, private).set_peers(&peers).unwrap();
        }
        ["show", seed, name, private] => {
            for peer in device(seed, name, private).peers().unwrap() {
                println!("{} {:?} {:?}", hex(&peer.key), peer.endpoint, peer.handshake);
            }
        }
        ["down", seed, name, private] => device(seed, name, private).remove().unwrap(),
        _ => panic!("what is {args:?}?"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    if matches!(args.first(), Some(&("address" | "up" | "peers" | "show" | "down"))) {
        return tool(&args);
    }
    if std::env::var_os("KITH_E2E").is_none() {
        return println!("skipped: set KITH_E2E=1 to run it");
    }
    let unshare = |args: &[&str]| Command::new("unshare").arg("-Urnm").args(args).status();
    if !unshare(&["true"]).is_ok_and(|status| status.success()) {
        return println!("skipped: no unprivileged user namespaces here (unshare -Urnm)");
    }
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e.sh");
    let me = std::env::current_exe().unwrap();
    let status = unshare(&["sh", script, me.to_str().unwrap()]).unwrap();
    assert!(status.success(), "{script} failed");
    println!("ok: three namespaces meshed, one pair through the edge node");
}
