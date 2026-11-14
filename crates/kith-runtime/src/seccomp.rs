//! The filter on a container's system calls.
//!
//! Everything is let through but the calls named here: the ones that administer the
//! machine (no container has the capability for them; here a mistake of the kernel's in
//! one is out of reach too), and the ones that open the most of the kernel to a program
//! with no privilege at all (new namespaces, bpf, perf, io_uring, userfaultfd, keyrings,
//! another process's memory).
//
// ponytail: a list of what is refused, not of what is allowed: a call the kernel grows
// next year is let through until it is named here. A list of what is allowed (Docker's
// is some 350 names) when someone keeps one; an untrusted program belongs in a VM anyway.

use nix::libc;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    sock_filter,
};

/// The calls refused, by the names a template allows them back by. `clone` is refused only
/// when it makes a namespace; `clone3`, whose flags a filter cannot read, is answered as
/// if the kernel had none (a C library then calls `clone`).
pub const REFUSED: &[(&str, libc::c_long)] = &[
    // Mounting, and leaving the root.
    ("mount", libc::SYS_mount),
    ("umount2", libc::SYS_umount2),
    ("pivot_root", libc::SYS_pivot_root),
    ("open_tree", libc::SYS_open_tree),
    ("move_mount", libc::SYS_move_mount),
    ("fsopen", libc::SYS_fsopen),
    ("fsconfig", libc::SYS_fsconfig),
    ("fsmount", libc::SYS_fsmount),
    ("fspick", libc::SYS_fspick),
    ("mount_setattr", libc::SYS_mount_setattr),
    ("open_by_handle_at", libc::SYS_open_by_handle_at),
    // New namespaces: in one of its own a program has every capability over it, and with
    // them most of the kernel to call.
    ("unshare", libc::SYS_unshare),
    ("setns", libc::SYS_setns),
    ("clone", libc::SYS_clone),
    ("clone3", libc::SYS_clone3),
    // The machine itself.
    ("init_module", libc::SYS_init_module),
    ("finit_module", libc::SYS_finit_module),
    ("delete_module", libc::SYS_delete_module),
    ("kexec_load", libc::SYS_kexec_load),
    ("kexec_file_load", libc::SYS_kexec_file_load),
    ("reboot", libc::SYS_reboot),
    ("swapon", libc::SYS_swapon),
    ("swapoff", libc::SYS_swapoff),
    ("acct", libc::SYS_acct),
    ("settimeofday", libc::SYS_settimeofday),
    ("clock_settime", libc::SYS_clock_settime),
    // Much of the kernel, for no privilege.
    ("bpf", libc::SYS_bpf),
    ("perf_event_open", libc::SYS_perf_event_open),
    ("userfaultfd", libc::SYS_userfaultfd),
    ("io_uring_setup", libc::SYS_io_uring_setup),
    ("io_uring_enter", libc::SYS_io_uring_enter),
    ("io_uring_register", libc::SYS_io_uring_register),
    ("add_key", libc::SYS_add_key),
    ("request_key", libc::SYS_request_key),
    ("keyctl", libc::SYS_keyctl),
    // Another process, from the inside.
    ("ptrace", libc::SYS_ptrace),
    ("process_vm_readv", libc::SYS_process_vm_readv),
    ("process_vm_writev", libc::SYS_process_vm_writev),
    ("kcmp", libc::SYS_kcmp),
    ("pidfd_getfd", libc::SYS_pidfd_getfd),
];

/// `clone`'s flags that make a namespace.
const NAMESPACES: [libc::c_int; 8] = [
    libc::CLONE_NEWNS,
    libc::CLONE_NEWCGROUP,
    libc::CLONE_NEWUTS,
    libc::CLONE_NEWIPC,
    libc::CLONE_NEWUSER,
    libc::CLONE_NEWPID,
    libc::CLONE_NEWNET,
    0x80, // CLONE_NEWTIME
];

/// The filters of a container that allows `allowed` back: each is installed, and a call
/// goes through when every one lets it.
pub fn filters(allowed: &[String]) -> Result<Vec<BpfProgram>, String> {
    if let Some(unknown) = allowed
        .iter()
        .find(|name| !REFUSED.iter().any(|(refused, _)| refused == name))
    {
        let known: Vec<&str> = REFUSED.iter().map(|(name, _)| *name).collect();
        return Err(format!(
            "seccomp: `{unknown}` is not a call the filter refuses (it refuses: {})",
            known.join(", ")
        ));
    }
    let refused = |name: &str| !allowed.iter().any(|allowed| allowed == name);
    let failed = |e: seccompiler::BackendError| format!("seccomp: {e}");
    let arch = std::env::consts::ARCH.try_into().map_err(failed)?;
    let mut rules = std::collections::BTreeMap::new();
    for (name, number) in REFUSED.iter().filter(|(name, _)| refused(name) && *name != "clone3") {
        let mut when = Vec::new();
        if *name == "clone" {
            for flag in NAMESPACES {
                let set = SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Qword,
                    SeccompCmpOp::MaskedEq(flag as u64),
                    flag as u64,
                );
                when.push(SeccompRule::new(vec![set.map_err(failed)?]).map_err(failed)?);
            }
        }
        rules.insert(*number, when);
    }
    let answer = |rules, errno: i32| -> Result<BpfProgram, String> {
        SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Errno(errno as u32), arch)
            .and_then(|filter| filter.try_into())
            .map_err(failed)
    };
    let mut filters = vec![answer(rules, libc::EPERM)?];
    if refused("clone3") {
        let clone3 = [(libc::SYS_clone3, Vec::new())].into_iter().collect();
        filters.push(answer(clone3, libc::ENOSYS)?);
    }
    // x86-64 has a second set of numbers for the same calls (x32, from 0x40000000 up) that
    // a list by number does not see: no such call, for a container. (A 32-bit program on
    // a 64-bit kernel has a third, and seccompiler's filter stops the program that uses it.)
    if cfg!(target_arch = "x86_64") {
        let step = |code, jt, jf, k| sock_filter { code, jt, jf, k };
        filters.push(vec![
            step(0x20, 0, 0, 0),                                 // A = the call's number
            step(0x35, 0, 1, 0x4000_0000),                       // A >= x32's first: the next; else the one after
            step(0x06, 0, 0, 0x0005_0000 | libc::ENOSYS as u32), // answer: no such call
            step(0x06, 0, 0, 0x7fff_0000),                       // let it through
        ]);
    }
    Ok(filters)
}

/// Installs them on this process, for good: on it and on whatever it becomes or starts.
pub fn install(filters: &[BpfProgram]) -> Result<(), String> {
    filters
        .iter()
        .try_for_each(|filter| seccompiler::apply_filter(filter).map_err(|e| format!("seccomp: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW: u32 = 0x7fff_0000;
    const ERRNO: u32 = 0x0005_0000;
    const KILL: u32 = 0x8000_0000;

    /// What a filter answers a call: the kernel's own reading of the few instructions a
    /// seccomp filter is made of, over a call's number, architecture and arguments.
    fn answer(filter: &[sock_filter], arch: u32, number: u32, args: [u64; 6]) -> u32 {
        let mut data = Vec::new();
        data.extend(number.to_ne_bytes());
        data.extend(arch.to_ne_bytes());
        data.extend(0u64.to_ne_bytes());
        args.iter().for_each(|arg| data.extend(arg.to_ne_bytes()));
        let (mut a, mut at) = (0u32, 0usize);
        loop {
            let sock_filter { code, jt, jf, k } = filter[at];
            at += 1;
            let jump = |yes: bool| if yes { jt as usize } else { jf as usize };
            match code {
                0x20 => a = u32::from_ne_bytes(data[k as usize..k as usize + 4].try_into().unwrap()),
                0x54 => a &= k,
                0x05 => at += k as usize,
                0x15 => at += jump(a == k),
                0x25 => at += jump(a > k),
                0x35 => at += jump(a >= k),
                0x45 => at += jump(a & k != 0),
                0x06 => return k,
                other => panic!("an instruction this test does not read: {other:#x}"),
            }
        }
    }

    /// The first answer that is not "let it through", as the kernel takes the strictest.
    fn said(allowed: &[&str], arch: u32, number: i64, arg0: u64) -> u32 {
        let allowed: Vec<String> = allowed.iter().map(|name| name.to_string()).collect();
        let filters = filters(&allowed).unwrap();
        let answers = filters
            .iter()
            .map(|filter| answer(filter, arch, number as u32, [arg0, 0, 0, 0, 0, 0]));
        answers.min_by_key(|said| (said & 0xffff_0000) as i32).unwrap()
    }

    #[cfg(target_arch = "x86_64")]
    const NATIVE: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const NATIVE: u32 = 0xc000_00b7;

    #[test]
    fn seccomp_refuses_what_is_named_and_lets_the_rest_through() {
        let (eperm, enosys) = (ERRNO | libc::EPERM as u32, ERRNO | libc::ENOSYS as u32);
        for (name, number) in REFUSED {
            let made = said(&[], NATIVE, *number, libc::CLONE_NEWUSER as u64);
            let wanted = if *name == "clone3" { enosys } else { eperm };
            assert_eq!(made, wanted, "{name}");
            // Allowed back by name, and nothing else with it.
            assert_eq!(
                said(&[name], NATIVE, *number, libc::CLONE_NEWUSER as u64),
                ALLOW,
                "{name}"
            );
            let other = if *name == "bpf" { libc::SYS_mount } else { libc::SYS_bpf };
            assert_eq!(said(&[name], NATIVE, other, 0), eperm, "{name} allowed back");
        }
        for through in [
            libc::SYS_read,
            libc::SYS_execve,
            libc::SYS_openat,
            libc::SYS_exit_group,
            libc::SYS_socket,
        ] {
            assert_eq!(said(&[], NATIVE, through, 0), ALLOW, "{through}");
        }
        // A thread or a fork is a clone that makes no namespace; each namespace's flag,
        // alone or among others, is refused.
        let thread =
            (libc::CLONE_VM | libc::CLONE_FS | libc::CLONE_FILES | libc::CLONE_SIGHAND | libc::CLONE_THREAD) as u64;
        assert_eq!(said(&[], NATIVE, libc::SYS_clone, thread), ALLOW);
        assert_eq!(said(&[], NATIVE, libc::SYS_clone, libc::SIGCHLD as u64), ALLOW);
        for flag in NAMESPACES {
            assert_eq!(said(&[], NATIVE, libc::SYS_clone, flag as u64), eperm, "{flag:#x}");
            assert_eq!(
                said(&[], NATIVE, libc::SYS_clone, thread | flag as u64),
                eperm,
                "{flag:#x}"
            );
        }
        // The other numbers the same kernel takes: x32's are no call at all, and a 32-bit
        // program's stop it.
        if cfg!(target_arch = "x86_64") {
            assert_eq!(said(&[], NATIVE, 0x4000_0000 + libc::SYS_mount, 0), enosys);
            assert_eq!(said(&[], NATIVE, 0x4000_0000, 0), enosys);
            assert_eq!(said(&["mount"], NATIVE, 0x4000_0000 + libc::SYS_mount, 0), enosys);
            assert_eq!(
                said(&[], 0x4000_0003, 21, 0) & 0xffff_0000,
                KILL,
                "mount, as a 32-bit program calls it"
            );
        }
        // A name that is not one of them is a mistake, and says what the names are.
        let said = filters(&["mounts".to_string()]).unwrap_err();
        assert!(
            said.contains("`mounts` is not a call the filter refuses") && said.contains("mount, umount2"),
            "{said}"
        );
    }
}
