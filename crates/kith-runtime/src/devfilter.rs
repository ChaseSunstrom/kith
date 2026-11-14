//! What holds a container to the devices it was given, where kithd is root: a program on
//! its cgroup that the kernel asks at every open and every mknod of a device node by a
//! process in it. (Where kithd is not root a container is a user namespace, and the kernel
//! lets none make a device node at all.)
//!
//! The program is made here, from the same rules as are in the container's spec, and
//! handed to the kernel by `kith_dm_sys::device_filter`: the runtime library has a filter
//! of its own, behind a feature that brings a C library with it.

use crate::{Context, Result, err};
use oci_spec::runtime::{LinuxDeviceCgroup, LinuxDeviceType};
use std::path::Path;

/// To make a node of it, to read it, to write it: as the kernel numbers them.
const MAKE: u32 = 1;
const READ: u32 = 2;
const WRITE: u32 = 4;

/// One device, or every one of a major, that a container may reach, and how.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rule {
    block: bool,
    major: u32,
    minor: Option<u32>,
    access: u32,
}

const fn every(major: u32, minor: Option<u32>) -> Rule {
    Rule {
        block: false,
        major,
        minor,
        access: MAKE | READ | WRITE,
    }
}

/// What every container has: the nodes the runtime makes in its `/dev` (null, zero, full,
/// random, urandom, tty), and the terminals of its own `/dev/pts` (which a node made
/// elsewhere does not open).
const EVERY: [Rule; 8] = [
    every(1, Some(3)),
    every(1, Some(5)),
    every(1, Some(7)),
    every(1, Some(8)),
    every(1, Some(9)),
    every(5, Some(0)),
    every(5, Some(2)),
    every(136, None),
];

/// The rules of a container whose spec allows `allowed` (each one device: `device_nodes`
/// writes them), after those of every container.
pub(crate) fn rules(allowed: &[LinuxDeviceCgroup]) -> Result<Vec<Rule>> {
    let mut rules = EVERY.to_vec();
    for rule in allowed {
        let block = match rule.typ() {
            Some(LinuxDeviceType::C | LinuxDeviceType::U) => false,
            Some(LinuxDeviceType::B) => true,
            _ => return err("a device rule for no one kind of device"),
        };
        // (A device number has twelve bits of major and twenty of minor.)
        let part = |part: Option<i64>, most: i64| part.filter(|part| (0..=most).contains(part)).map(|part| part as u32);
        let (Some(major), Some(minor), true) = (part(rule.major(), 0xfff), part(rule.minor(), 0xf_ffff), rule.allow())
        else {
            return err("a device rule that is not one device allowed");
        };
        let access = rule.access().as_deref().unwrap_or_default().chars();
        let access = access.fold(0, |all, how| {
            all | match how {
                'm' => MAKE,
                'r' => READ,
                'w' => WRITE,
                _ => 0,
            }
        });
        rules.push(Rule {
            block,
            major,
            minor: Some(minor),
            access,
        });
    }
    Ok(rules)
}

/// One BPF instruction, as the kernel reads it: what to do, to which register (the low
/// half) from which (the high), a jump's length or a field's offset, and a number.
fn instruction(code: u8, to: u8, from: u8, offset: i16, number: i32) -> [u8; 8] {
    let mut bytes = [code, from << 4 | to, 0, 0, 0, 0, 0, 0];
    bytes[2..4].copy_from_slice(&offset.to_ne_bytes());
    bytes[4..8].copy_from_slice(&number.to_ne_bytes());
    bytes
}

/// The program that answers 1 for what one of `rules` allows and 0 for all else. It is
/// handed `struct bpf_cgroup_dev_ctx`: the kind of device (1 block, 2 character) in the
/// low half of its first word and the access in the high, then the major, then the minor.
pub(crate) fn program(rules: &[Rule]) -> Vec<u8> {
    let mut made = vec![
        instruction(0x61, 2, 1, 0, 0),      // r2 = the first word
        instruction(0x61, 3, 1, 4, 0),      // r3 = the major
        instruction(0x61, 4, 1, 8, 0),      // r4 = the minor
        instruction(0xbc, 5, 2, 0, 0),      // r5 = r2
        instruction(0x54, 5, 0, 0, 0xffff), // r5 &= 0xffff: the kind
        instruction(0x74, 2, 0, 0, 16),     // r2 >>= 16: the access
    ];
    for rule in rules {
        // Each test jumps past the rule's end where it does not hold.
        let mut tests = vec![
            (0x55, 5, if rule.block { 1 } else { 2 }), // the kind is not this one
            (0xbc, 6, 0),                              // r6 = r2
            (0x54, 6, !rule.access as i32),            // r6 &= what the rule does not give
            (0x55, 6, 0),                              // some of what is asked is left
            (0x55, 3, rule.major as i32),              // the major is another
        ];
        tests.extend(rule.minor.map(|minor| (0x55, 4, minor as i32)));
        let end = tests.len() + 2;
        for (at, (code, register, number)) in tests.into_iter().enumerate() {
            let jump = if code == 0x55 { (end - at - 1) as i16 } else { 0 };
            let from = if code == 0xbc { 2 } else { 0 };
            made.push(instruction(code, register, from, jump, number));
        }
        made.push(instruction(0xb7, 0, 0, 0, 1)); // r0 = 1: it may
        made.push(instruction(0x95, 0, 0, 0, 0)); // and that is the answer
    }
    made.push(instruction(0xb7, 0, 0, 0, 0)); // r0 = 0: no rule gives it
    made.push(instruction(0x95, 0, 0, 0, 0));
    made.concat()
}

/// Put the filter for `allowed` on the cgroup at `cgroup`, in place of the one there.
pub(crate) fn attach(cgroup: &Path, allowed: &[LinuxDeviceCgroup]) -> Result<()> {
    let what = format!("the device filter of {}", cgroup.display());
    let program = program(&rules(allowed).ctx(&what)?);
    let cgroup = std::fs::File::open(cgroup).ctx(&what)?;
    kith_dm_sys::device_filter(&cgroup, &program).ctx(&what)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::LinuxDeviceCgroupBuilder;

    /// What the kernel would answer: the program run on one question, by the few
    /// instructions `program` writes.
    fn asks(program: &[u8], block: bool, access: u32, major: u32, minor: u32) -> bool {
        let asked = [access << 16 | if block { 1 } else { 2 }, major, minor];
        let mut registers = [0i64; 11];
        let mut at = 0;
        for _ in 0..program.len() {
            let now: [u8; 8] = program[at * 8..at * 8 + 8].try_into().unwrap();
            let (to, from) = ((now[1] & 15) as usize, (now[1] >> 4) as usize);
            let jump = i16::from_ne_bytes([now[2], now[3]]) as isize;
            let number = i64::from(i32::from_ne_bytes([now[4], now[5], now[6], now[7]]));
            at += 1;
            match now[0] {
                0x61 => {
                    assert_eq!(
                        (from, jump % 4, jump < 12),
                        (1, 0, true),
                        "a field of what it is handed"
                    );
                    registers[to] = i64::from(asked[jump as usize / 4]);
                }
                0xbc => registers[to] = registers[from] & 0xffff_ffff,
                0x54 => registers[to] = registers[to] & number & 0xffff_ffff,
                0x74 => registers[to] = (registers[to] & 0xffff_ffff) >> number,
                0xb7 => registers[to] = number,
                0x55 if registers[to] != number => at = at.checked_add_signed(jump).unwrap(),
                0x55 => {}
                0x95 => return registers[0] == 1,
                other => panic!("an instruction this does not write: {other:#x}"),
            }
        }
        panic!("the program does not end");
    }

    #[test]
    fn the_filter_gives_what_the_rules_give_and_no_more() {
        let given = |major: i64, minor: i64, access: &str| {
            let rule = LinuxDeviceCgroupBuilder::default().allow(true).typ(LinuxDeviceType::C);
            rule.major(major).minor(minor).access(access).build().unwrap()
        };
        // A keyboard and a card's render node, as a claim gives them.
        let made = program(&rules(&[given(13, 69, "rw"), given(226, 128, "rw")]).unwrap());
        assert_eq!(made.len() % 8, 0);
        let asks = |block, access, major, minor| asks(&made, block, access, major, minor);
        let both = READ | WRITE;
        // What every container has: /dev/null to read, write and make; any terminal of its own.
        assert!(asks(false, both, 1, 3) && asks(false, MAKE, 1, 3) && asks(false, READ, 5, 0));
        assert!(asks(false, both, 136, 0) && asks(false, both, 136, 4000));
        // What it was given, to read and write and not to make; and not the one beside it.
        assert!(asks(false, both, 13, 69) && asks(false, READ, 226, 128));
        assert!(!asks(false, MAKE, 13, 69) && !asks(false, both | MAKE, 13, 69));
        assert!(!asks(false, READ, 13, 70) && !asks(false, READ, 226, 0));
        // A disk of the node (and a block device with the numbers of /dev/null), memory, a console.
        assert!(!asks(true, READ, 254, 0) && !asks(true, MAKE, 254, 0) && !asks(true, READ, 1, 3));
        assert!(!asks(false, READ, 1, 1) && !asks(false, WRITE, 4, 0) && !asks(false, READ, 1, 4));
        // With nothing given: the same few, and nothing else.
        let bare = program(&rules(&[]).unwrap());
        assert!(super::tests::asks(&bare, false, both, 1, 9) && !super::tests::asks(&bare, false, READ, 13, 69));

        // A rule that is not one device allowed is not guessed at.
        let deny = LinuxDeviceCgroupBuilder::default()
            .allow(false)
            .access("rwm")
            .build()
            .unwrap();
        let wide = LinuxDeviceCgroupBuilder::default().allow(true).typ(LinuxDeviceType::C);
        let wide = wide.major(13).access("rw").build().unwrap();
        assert!(rules(&[deny]).is_err() && rules(&[wide]).is_err());
        assert!(rules(&[given(4096, 0, "rw")]).is_err() && rules(&[given(1, -1, "rw")]).is_err());
    }
}
