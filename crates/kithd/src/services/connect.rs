//! A connection to a Service's address made on this node by a container on its network
//! goes straight to a replica here: a program on the containers' cgroup that the kernel
//! asks at each connect() writes the replica's address in place of the Service's, before
//! the kernel looks at it. kithd then never sees the connection. The program is the table
//! itself, its entries written in as numbers, and made again when they change.

use std::fs::File;
use std::net::{IpAddr, SocketAddr};

/// Where the containers' cgroups are, where kithd is root (as `kith_runtime` puts them):
/// never kithd's own, nor the host's processes.
pub const CGROUP: &str = "/sys/fs/cgroup/kith";

/// One Service port the kernel passes on: of all its backends (`all`), those it may send
/// a connection to itself (`here`), and where a pick of one of the others goes instead:
/// kithd's listener on the same address for the other nodes' backends only. An entry of
/// an IPv4 address is for the IPv4 program and holds only IPv4 addresses, one of an IPv6
/// address only IPv6 ones ([`program`], [`program4`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub service: (IpAddr, u16),
    pub here: Vec<SocketAddr>,
    pub all: u32,
    pub elsewhere: Option<u16>,
}

/// Is the entry one for the IPv4 program (`v4`) or the IPv6 one? One that has the other
/// family's address anywhere (a bug upstream) is for neither: its port is left to kithd.
fn is_for(entry: &Entry, v4: bool) -> bool {
    entry.service.0.is_ipv4() == v4 && entry.here.iter().all(|at| at.is_ipv4() == v4)
}

/// The fields of `struct bpf_sock_addr` the program reads and writes.
const IP4: i16 = 4;
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

/// The words of an address as the program reads them from `user_ip4` (one) or `user_ip6` (four).
fn address_words(address: IpAddr) -> Vec<i32> {
    let octets = match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    let word = |octets: &[u8]| i32::from_ne_bytes(octets.try_into().expect("four"));
    octets.chunks(4).map(word).collect()
}

/// `r0 = 1; exit`: the connect goes on, to whatever address is written by now.
fn done() -> [[u8; 8]; 2] {
    [instruction(0xb7, 0, 0, 0, 1), instruction(0x95, 0, 0, 0, 0)]
}

/// Write `port` (and `address`, if any) where the connect goes.
fn write(made: &mut Vec<[u8; 8]>, address: Option<IpAddr>, port: u16) {
    let first = if address.is_some_and(|address| address.is_ipv4()) {
        IP4
    } else {
        IP6
    };
    for (at, word) in address.map(address_words).into_iter().flatten().enumerate() {
        made.push(instruction(0xb4, 2, 0, 0, word)); // w2 = the word
        made.push(instruction(0x63, 6, 2, first + at as i16 * 4, 0)); // into user_ip4 or user_ip6[at]
    }
    made.push(instruction(0xb4, 2, 0, 0, port_word(port)));
    made.push(instruction(0x63, 6, 2, PORT, 0));
}

/// The program of the connects of IPv6 sockets, for the IPv6 `entries` among `entries`,
/// asked only for connects from sockets made in the network namespace whose cookie is
/// `netns` (a pod's loopback is not the node's).
pub fn program(entries: &[Entry], netns: u64) -> Vec<u8> {
    program_of(entries, netns, false)
}

/// [`program`] for the connects of IPv4 sockets and the IPv4 entries: it reads and writes
/// `user_ip4` and never holds an IPv6 address.
pub fn program4(entries: &[Entry], netns: u64) -> Vec<u8> {
    program_of(entries, netns, true)
}

fn program_of(entries: &[Entry], netns: u64, v4: bool) -> Vec<u8> {
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
    for entry in entries.iter().filter(|entry| is_for(entry, v4)) {
        // Each test jumps to the entry's end (`NEXT`, made right below) where it fails.
        const NEXT: i16 = i16::MAX;
        let mut block = vec![
            instruction(0x61, 2, 6, PORT, 0),
            instruction(0x56, 2, 0, NEXT, port_word(entry.service.1)),
        ];
        let first = if v4 { IP4 } else { IP6 };
        for (at, word) in address_words(entry.service.0).into_iter().enumerate() {
            block.push(instruction(0x61, 2, 6, first + at as i16 * 4, 0));
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
            write(&mut then, Some(target.ip()), target.port());
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

/// What the two programs' attaching came to: each is put apart from the other, so one
/// refused leaves the other where it was put.
pub struct Attached {
    pub v6: std::io::Result<()>,
    pub v4: std::io::Result<()>,
}

impl Attached {
    /// Both, or the first error.
    pub fn all(self) -> std::io::Result<()> {
        self.v6.and(self.v4)
    }
}

/// Put the programs for `entries` on the containers' cgroup, in place of the ones there.
pub fn attach(entries: &[Entry], netns: u64) -> Attached {
    attach_with(entries, netns, put)
}

/// Put one program (`true`: the IPv4 one) on the containers' cgroup.
pub fn put(v4: bool, program: &[u8]) -> std::io::Result<()> {
    if let Err(e) = std::fs::create_dir(CGROUP)
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(e);
    }
    let cgroup = File::open(CGROUP)?;
    match v4 {
        true => kith_dm_sys::connect_filter4(&cgroup, program),
        false => kith_dm_sys::connect_filter(&cgroup, program),
    }
}

/// [`attach`] with `put` (`true` for the IPv4 program) to put each, so a test can have one refused.
pub fn attach_with(entries: &[Entry], netns: u64, put: impl Fn(bool, &[u8]) -> std::io::Result<()>) -> Attached {
    Attached {
        v6: put(false, &program(entries, netns)),
        v4: put(true, &program4(entries, netns)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    /// What a connect() to `to` over `protocol` from the namespace `netns` becomes, as
    /// the kernel would run `program` on it, with `random` what bpf_get_prandom_u32 says;
    /// and whether it goes on at all.
    fn run(program: &[u8], netns: u64, protocol: u32, to: SocketAddr, random: u32) -> (bool, SocketAddr) {
        // struct bpf_sock_addr, by words: family, user_ip4, user_ip6[4], user_port, ..., protocol.
        let mut context = [0u32; 10];
        context[0] = if to.is_ipv4() { 2 } else { 10 };
        let first = if to.is_ipv4() { 1 } else { 2 };
        for (at, word) in address_words(to.ip()).into_iter().enumerate() {
            context[first + at] = word as u32;
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
                    // (A program for IPv4 sockets writes user_ip4 and never user_ip6, as the kernel's verifier has it.)
                    let wrote = if to == 6 && context[0] == 2 {
                        offset == PORT || offset == IP4
                    } else {
                        to == 6 && (offset == PORT || (IP6..IP6 + 16).contains(&offset))
                    };
                    assert!(wrote, "a field it may write");
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
                    let port = u16::from_be_bytes((context[6] as u16).to_ne_bytes());
                    if context[0] == 2 {
                        return (
                            registers[0] == 1,
                            SocketAddr::new(context[1].to_ne_bytes().into(), port),
                        );
                    }
                    let mut octets = [0u8; 16];
                    for word in 0..4 {
                        octets[word * 4..word * 4 + 4].copy_from_slice(&context[2 + word].to_ne_bytes());
                    }
                    return (registers[0] == 1, SocketAddr::new(octets.into(), port));
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
        let at = |ip, port| SocketAddr::new(IpAddr::V6(ip), port);
        let entries = [
            Entry {
                service: (service.into(), 80),
                here: vec![at(mapped, 8080)],
                all: 1,
                elsewhere: None,
            },
            // Three backends, one of them here: two picks in three go to kithd's other listener.
            Entry {
                service: (service.into(), 443),
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

    /// The IPv4 program is the IPv6 one's twin: the same picks and shares, on `user_ip4`.
    #[test]
    fn service_v4_table_the_kernel_sends_an_ipv4_connect_on_to_a_replica_here() {
        let node = 0x1234_5678_9abc_def0;
        let at = |ip: [u8; 4], port| SocketAddr::new(IpAddr::V4(ip.into()), port);
        let service = [100, 87, 0, 5];
        let entries = [
            Entry {
                service: (at(service, 0).ip(), 80),
                here: vec![at([100, 88, 0, 7], 8080)],
                all: 1,
                elsewhere: None,
            },
            // Three backends, one here: two picks in three change only the port, to kithd's.
            Entry {
                service: (at(service, 0).ip(), 443),
                here: vec![at([100, 88, 0, 8], 8443)],
                all: 3,
                elsewhere: Some(40001),
            },
        ];
        let made = program4(&entries, node);
        let run = |netns, protocol, to, random| run(&made, netns, protocol, to, random);
        assert_eq!(run(node, 6, at(service, 80), 0), (true, at([100, 88, 0, 7], 8080)));
        for (netns, protocol, to) in [
            (node, 6, at(service, 81)),
            (node, 6, at([100, 87, 0, 6], 80)),
            (node, 17, at(service, 80)),
            (7, 6, at(service, 80)),
        ] {
            assert_eq!(run(netns, protocol, to, 0), (true, to));
        }
        assert_eq!(run(node, 6, at(service, 443), 3), (true, at([100, 88, 0, 8], 8443)));
        assert_eq!(run(node, 6, at(service, 443), 4), (true, at(service, 40001)));
        let here = (0..3000)
            .filter(|random| run(node, 6, at(service, 443), *random).1.port() == 8443)
            .count();
        assert_eq!(here, 1000);
        // The IPv6 program has none of these: an IPv4 entry is never in it, nor an IPv6 one here.
        assert_eq!(program(&entries, node), program(&[], node));
    }

    /// An entry of an IPv4 address with an IPv6 backend in it (a bug upstream) is in neither program.
    #[test]
    fn service_v4_table_an_ipv4_entry_never_holds_an_ipv6_address() {
        let node = 7;
        let v4 = IpAddr::V4([100, 87, 0, 5].into());
        let v6 = IpAddr::V6("fd5e:1::80".parse().unwrap());
        let mixed = Entry {
            service: (v4, 80),
            here: vec![SocketAddr::new(v6, 8080)],
            all: 1,
            elsewhere: None,
        };
        let ipv6_with_ipv4 = Entry {
            service: (v6, 80),
            here: vec![SocketAddr::new(v4, 8080)],
            all: 1,
            elsewhere: None,
        };
        let entries = [mixed, ipv6_with_ipv4];
        assert_eq!(program4(&entries, node), program4(&[], node));
        assert_eq!(program(&entries, node), program(&[], node));
    }

    /// A refused IPv4 attach leaves the IPv6 program as it was put, and the other way about.
    #[test]
    fn service_v4_table_a_refused_ipv4_attach_leaves_the_ipv6_hook_working() {
        let put = std::cell::RefCell::new(Vec::new());
        let refuse_v4 = |v4: bool, program: &[u8]| {
            if v4 {
                return Err(std::io::Error::other("injected: no INET4_CONNECT"));
            }
            put.borrow_mut().push(program.to_vec());
            Ok(())
        };
        let entry = Entry {
            service: (IpAddr::V6("fd5e:1::80".parse().unwrap()), 80),
            here: vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080)],
            all: 1,
            elsewhere: None,
        };
        let attached = attach_with(std::slice::from_ref(&entry), 7, refuse_v4);
        assert!(attached.v6.is_ok());
        assert!(attached.v4.as_ref().unwrap_err().to_string().contains("injected"));
        assert_eq!(*put.borrow(), [program(std::slice::from_ref(&entry), 7)]);
        assert!(attached.all().is_err());
    }
}
