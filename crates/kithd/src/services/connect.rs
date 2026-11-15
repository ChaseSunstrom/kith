//! A connection to a Service's address made on this node by a container on its network
//! goes straight to a replica here: a program on the containers' cgroup that the kernel
//! asks at each connect() writes the replica's address in place of the Service's, before
//! the kernel looks at it. kithd then never sees the connection. The program is the table
//! itself, its entries written in as numbers, and made again when they change.

use std::fs::File;
use std::net::{Ipv6Addr, SocketAddrV6};

/// Where the containers' cgroups are, where kithd is root (as `kith_runtime` puts them):
/// never kithd's own, nor the host's processes.
pub const CGROUP: &str = "/sys/fs/cgroup/kith";

/// One Service port the kernel passes on: of all its backends (`all`), those it may send
/// a connection to itself (`here`), and where a pick of one of the others goes instead:
/// kithd's listener on the same address for the other nodes' backends only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub service: (Ipv6Addr, u16),
    pub here: Vec<SocketAddrV6>,
    pub all: u32,
    pub elsewhere: Option<u16>,
}

/// The fields of `struct bpf_sock_addr` the program reads and writes.
const IP6: i16 = 8;
const PORT: i16 = 24;
const PROTOCOL: i16 = 36;
/// The kernel's helpers it calls.
const PRANDOM: i32 = 7;
const NETNS_COOKIE: i32 = 122;

/// One BPF instruction, as the kernel reads it (see `kith_runtime`'s device filter).
fn instruction(code: u8, to: u8, from: u8, offset: i16, number: i32) -> [u8; 8] {
    let mut bytes = [code, from << 4 | to, 0, 0, 0, 0, 0, 0];
    bytes[2..4].copy_from_slice(&offset.to_ne_bytes());
    bytes[4..8].copy_from_slice(&number.to_ne_bytes());
    bytes
}

/// A port as the program reads it from `user_port`: in the network's order, in a word.
fn port_word(port: u16) -> i32 {
    i32::from(u16::from_ne_bytes(port.to_be_bytes()))
}

/// The four words of an address as the program reads them from `user_ip6`.
fn address_words(address: Ipv6Addr) -> [i32; 4] {
    let octets = address.octets();
    std::array::from_fn(|at| i32::from_ne_bytes(octets[at * 4..at * 4 + 4].try_into().expect("four")))
}

/// `r0 = 1; exit`: the connect goes on, to whatever address is written by now.
fn done() -> [[u8; 8]; 2] {
    [instruction(0xb7, 0, 0, 0, 1), instruction(0x95, 0, 0, 0, 0)]
}

/// Write `port` (and `address`, if any) where the connect goes.
fn write(made: &mut Vec<[u8; 8]>, address: Option<Ipv6Addr>, port: u16) {
    for (at, word) in address.map(address_words).into_iter().flatten().enumerate() {
        made.push(instruction(0xb4, 2, 0, 0, word)); // w2 = the word
        made.push(instruction(0x63, 6, 2, IP6 + at as i16 * 4, 0)); // into user_ip6[at]
    }
    made.push(instruction(0xb4, 2, 0, 0, port_word(port)));
    made.push(instruction(0x63, 6, 2, PORT, 0));
}

/// The program for `entries`, asked only for connects from sockets made in the network
/// namespace whose cookie is `netns` (a pod's loopback is not the node's).
pub fn program(entries: &[Entry], netns: u64) -> Vec<u8> {
    let mut made = vec![
        instruction(0xbf, 6, 1, 0, 0),        // r6 = what the program is handed
        instruction(0x61, 2, 6, PROTOCOL, 0), // w2 = the protocol
        instruction(0x16, 2, 0, 2, 6),        // TCP, or:
    ];
    made.extend(done());
    made.extend([
        instruction(0x85, 0, 0, 0, NETNS_COOKIE), // r0 = the socket's namespace's cookie
        instruction(0x18, 2, 0, 0, netns as u32 as i32),
        instruction(0x00, 0, 0, 0, (netns >> 32) as u32 as i32), // r2 = this node's
        instruction(0x1d, 0, 2, 2, 0),                           // the same, or:
    ]);
    made.extend(done());
    for entry in entries {
        // Each test jumps to the entry's end (`NEXT`, made right below) where it fails.
        const NEXT: i16 = i16::MAX;
        let mut block = vec![
            instruction(0x61, 2, 6, PORT, 0),
            instruction(0x56, 2, 0, NEXT, port_word(entry.service.1)),
        ];
        for (at, word) in address_words(entry.service.0).into_iter().enumerate() {
            block.push(instruction(0x61, 2, 6, IP6 + at as i16 * 4, 0));
            block.push(instruction(0x56, 2, 0, NEXT, word));
        }
        // One of all the backends, each as likely: r7 = which.
        if entry.all > 1 {
            block.push(instruction(0x85, 0, 0, 0, PRANDOM));
            block.push(instruction(0x94, 0, 0, 0, entry.all as i32)); // w0 %= all
            block.push(instruction(0xbc, 7, 0, 0, 0)); // w7 = w0
        } else {
            block.push(instruction(0xb4, 7, 0, 0, 0));
        }
        for (which, target) in entry.here.iter().enumerate() {
            let mut then = Vec::new();
            write(&mut then, Some(*target.ip()), target.port());
            then.extend(done());
            block.push(instruction(0x56, 7, 0, then.len() as i16, which as i32));
            block.extend(then);
        }
        // One elsewhere: to kithd, for the other nodes'.
        if let Some(port) = entry.elsewhere {
            write(&mut block, None, port);
        }
        block.extend(done());
        let end = block.len();
        for (at, now) in block.iter_mut().enumerate() {
            if now[0] == 0x56 && i16::from_ne_bytes([now[2], now[3]]) == NEXT {
                now[2..4].copy_from_slice(&((end - at - 1) as i16).to_ne_bytes());
            }
        }
        made.extend(block);
    }
    made.extend(done());
    made.concat()
}

/// Put the program for `entries` on the containers' cgroup, in place of the one there.
pub fn attach(entries: &[Entry], netns: u64) -> std::io::Result<()> {
    if let Err(e) = std::fs::create_dir(CGROUP)
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(e);
    }
    kith_dm_sys::connect_filter(&File::open(CGROUP)?, &program(entries, netns))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a connect() to `to` over `protocol` from the namespace `netns` becomes, as
    /// the kernel would run `program` on it, with `random` what bpf_get_prandom_u32 says;
    /// and whether it goes on at all.
    fn run(program: &[u8], netns: u64, protocol: u32, to: SocketAddrV6, random: u32) -> (bool, SocketAddrV6) {
        // struct bpf_sock_addr, by words: family, user_ip4, user_ip6[4], user_port, ..., protocol.
        let mut context = [0u32; 10];
        context[0] = 10;
        let words = address_words(*to.ip());
        for at in 0..4 {
            context[2 + at] = words[at] as u32;
        }
        context[6] = port_word(to.port()) as u32;
        context[8] = 1;
        context[9] = protocol;
        let mut registers = [0u64; 11];
        let mut at = 0;
        for _ in 0..program.len() {
            let now: [u8; 8] = program[at * 8..at * 8 + 8].try_into().unwrap();
            let (to, from) = ((now[1] & 15) as usize, (now[1] >> 4) as usize);
            let offset = i16::from_ne_bytes([now[2], now[3]]);
            let number = i32::from_ne_bytes([now[4], now[5], now[6], now[7]]);
            let low = |register: u64| register & 0xffff_ffff;
            at += 1;
            let mut jump = |taken: bool| {
                if taken {
                    at = at.checked_add_signed(offset as isize).unwrap();
                }
            };
            match now[0] {
                0xbf => registers[to] = registers[from],
                0xbc => registers[to] = low(registers[from]),
                0xb4 => registers[to] = u64::from(number as u32),
                0xb7 => registers[to] = number as i64 as u64,
                0x94 => registers[to] = low(registers[to]) % u64::from(number as u32),
                0x61 => {
                    assert_eq!((from, offset % 4), (6, 0), "a field of the context, through r6");
                    registers[to] = u64::from(context[offset as usize / 4]);
                }
                0x63 => {
                    assert!(
                        to == 6 && (offset == PORT || (IP6..IP6 + 16).contains(&offset)),
                        "a field it may write"
                    );
                    context[offset as usize / 4] = low(registers[from]) as u32;
                }
                0x18 => {
                    let high: [u8; 8] = program[at * 8..at * 8 + 8].try_into().unwrap();
                    let high = u32::from_ne_bytes([high[4], high[5], high[6], high[7]]);
                    registers[to] = u64::from(high) << 32 | u64::from(number as u32);
                    at += 1;
                }
                0x85 => {
                    registers[0] = match number {
                        PRANDOM => u64::from(random),
                        NETNS_COOKIE => netns,
                        other => panic!("a helper this does not call: {other}"),
                    };
                    registers[1..6].fill(0xdead);
                }
                0x16 => jump(low(registers[to]) == u64::from(number as u32)),
                0x56 => jump(low(registers[to]) != u64::from(number as u32)),
                0x1d => jump(registers[to] == registers[from]),
                0x95 => {
                    let mut octets = [0u8; 16];
                    for word in 0..4 {
                        octets[word * 4..word * 4 + 4].copy_from_slice(&context[2 + word].to_ne_bytes());
                    }
                    let port = u16::from_be_bytes((context[6] as u16).to_ne_bytes());
                    return (registers[0] == 1, SocketAddrV6::new(octets.into(), port, 0, 0));
                }
                other => panic!("an instruction this does not write: {other:#x}"),
            }
        }
        panic!("the program does not end");
    }

    #[test]
    fn the_kernel_sends_a_connect_to_a_service_on_to_a_replica_here() {
        let service: Ipv6Addr = "fd5e:1::80".parse().unwrap();
        let other: Ipv6Addr = "fd5e:1::81".parse().unwrap();
        let mapped = std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        let at = |ip, port| SocketAddrV6::new(ip, port, 0, 0);
        let entries = [
            Entry {
                service: (service, 80),
                here: vec![at(mapped, 8080)],
                all: 1,
                elsewhere: None,
            },
            // Three backends, one of them here: two picks in three go to kithd's other listener.
            Entry {
                service: (service, 443),
                here: vec![at(Ipv6Addr::LOCALHOST, 8443)],
                all: 3,
                elsewhere: Some(40001),
            },
        ];
        let made = program(&entries, 0x1234_5678_9abc_def0);
        let node = 0x1234_5678_9abc_def0;
        let run = |netns, protocol, to, random| run(&made, netns, protocol, to, random);
        assert_eq!(run(node, 6, at(service, 80), 0), (true, at(mapped, 8080)));
        // Another port, another address, UDP, a pod's own namespace: left as they are.
        for (netns, protocol, to) in [
            (node, 6, at(service, 81)),
            (node, 6, at(other, 80)),
            (node, 17, at(service, 80)),
            (7, 6, at(service, 80)),
        ] {
            assert_eq!(run(netns, protocol, to, 0), (true, to));
        }
        // The shares: each backend's pick as likely, over every number the kernel may say.
        assert_eq!(run(node, 6, at(service, 443), 3), (true, at(Ipv6Addr::LOCALHOST, 8443)));
        assert_eq!(run(node, 6, at(service, 443), 4), (true, at(service, 40001)));
        assert_eq!(run(node, 6, at(service, 443), 5), (true, at(service, 40001)));
        let here = (0..3000)
            .filter(|random| run(node, 6, at(service, 443), *random).1.port() == 8443)
            .count();
        assert_eq!(here, 1000);
        // With nothing in it, it changes nothing.
        let empty = program(&[], node);
        assert_eq!(
            super::tests::run(&empty, node, 6, at(service, 80), 0),
            (true, at(service, 80))
        );
    }
}
