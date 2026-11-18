//! The first process of a kith OS machine: the kithd binary started as process 1 keeps kithd,
//! and nothing else. It mounts what every process needs, makes the consoles one, starts kithd
//! (this same file, as a process of its own) and starts it again when it ends, so what kithd
//! started outlives it (kithd takes it back: controller.rs, `Runtime::adopt`). It reaps every
//! process left to it and writes down how each ended ([`kith_runtime::EXITS`]) for the next
//! kithd. Ten ends of kithd in a minute restart the machine, as one did before.
//!
//! What it acts on: its own arguments (passed on to kithd), the exits of its children and the
//! signals that stop a machine (sent on to kithd). It reads nothing from the network, the
//! disk or kithd: a kithd that is taken can make it do no more than start kithd again.

use nix::sys::signal::{SigSet, Signal, kill};
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid, waitpid};
use nix::unistd::Pid;
use std::time::{Duration, Instant};

/// Set in kithd's environment by the keeper: how many times it was started (1 the first time).
const KEPT: &str = "KITH_KEPT";
/// Set as well for the last start after ten failures: kithd counts the failed start (os.rs) and
/// restarts the machine, as a first process that failed did.
const END: &str = "KITH_END";
/// How many ends of kithd within [`WINDOW`] restart the machine.
const FAILURES: usize = 10;
const WINDOW: Duration = Duration::from_secs(60);

/// Under the keeper: which start of kithd this is, and whether it is the last (it is to end
/// at once, counted as a failed start).
// ponytail: left in the environment (taking it out is unsafe code): what kithd starts is told
// its own start number, and a container's environment is its spec's alone.
pub fn kept() -> Option<(u32, bool)> {
    let start = std::env::var(KEPT).ok()?.parse().ok()?;
    Some((start, std::env::var_os(END).is_some()))
}

/// Process 1's life. Never returns: when it must end, the machine restarts.
pub fn keep() -> ! {
    // Blocked before first_things starts a thread: each thread inherits the mask, and process 1
    // drops a SIGINT (Ctrl-Alt-Del) that a thread without it takes (no handler), so kithd is never told.
    let heard = block_heard();
    crate::init::first_things();
    let _ = std::fs::create_dir_all(kith_runtime::EXITS);
    let (mut starts, mut ends) = (0u32, Vec::<Instant>::new());
    let mut kithd = start(&mut starts, &mut ends);
    loop {
        let Ok(signal) = heard.wait() else { continue };
        if signal != Signal::SIGCHLD {
            if let Some(pid) = kithd {
                let _ = kill(pid, signal);
            }
            continue;
        }
        // Looked at first and reaped after (WNOWAIT): how a unit ended is written down while its
        // pid still names it, so kithd, seeing it gone, finds the file there.
        let peek = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
        while let Ok(status) = waitid(Id::All, peek) {
            let (pid, code) = match status {
                WaitStatus::Exited(pid, code) => (pid, code),
                WaitStatus::Signaled(pid, signal, _) => (pid, 128 + signal as i32),
                _ => break,
            };
            if Some(pid) != kithd {
                // (For kithd to find, if the process was one of its units: it removes what it read.
                // Its start time with it, read while it is a zombie, tells it from a later pid.)
                // ponytail: an orphan that was no unit leaves its file: a few bytes in /run each.
                let start = kith_runtime::started(pid).unwrap_or(0);
                let _ = std::fs::write(format!("{}/{pid}", kith_runtime::EXITS), format!("{code} {start}"));
            }
            let _ = waitpid(pid, None);
            if Some(pid) != kithd {
                continue;
            }
            // (However it ended: a kithd that stops as asked restarts or powers off the machine
            // itself, so an end of 0 here is one more that it did not mean.)
            ends.retain(|at| at.elapsed() < WINDOW);
            ends.push(Instant::now());
            eprintln!("kithd: init: kithd ended ({code}): starting it again");
            kithd = start(&mut starts, &mut ends);
        }
    }
}

/// Blocks the signals process 1 waits for (waited for below, not handled: SIGTERM and SIGINT
/// (Ctrl-Alt-Del) are kithd's to act on) in this thread, and so in every thread started after.
fn block_heard() -> SigSet {
    let heard = heard_set();
    let _ = heard.thread_block();
    heard
}

/// Unblocked by kithd once its own handlers are set (main.rs `stops`): kithd is started with the
/// mask process 1 holds, and a signal blocked with no one to take it is never heard.
pub fn unblock_heard() {
    let _ = heard_set().thread_unblock();
}

fn heard_set() -> SigSet {
    let mut heard = SigSet::empty();
    for signal in [Signal::SIGCHLD, Signal::SIGTERM, Signal::SIGINT] {
        heard.add(signal);
    }
    heard
}

/// Start kithd: this file again (an update of kithd alone, T-0709, is not yet). The start
/// after ten failures in a minute is told to end (and restart the machine); a failure past
/// that restarts it here.
fn start(starts: &mut u32, ends: &mut Vec<Instant>) -> Option<Pid> {
    loop {
        if ends.len() > FAILURES {
            restart();
        }
        *starts += 1;
        let mut command = std::process::Command::new("/proc/self/exe");
        command.args(std::env::args_os().skip(1)).env(KEPT, starts.to_string());
        if ends.len() == FAILURES {
            command.env(END, "1");
        }
        match command.spawn() {
            Ok(child) => return Some(Pid::from_raw(child.id() as i32)),
            Err(e) => {
                // (No end of it will be heard: counted here.)
                eprintln!("kithd: init: starting kithd: {e}");
                ends.retain(|at| at.elapsed() < WINDOW);
                ends.push(Instant::now());
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

/// kithd failed and could not even say so: the machine restarts.
fn restart() -> ! {
    eprintln!("kithd: init: kithd failed {FAILURES} times in a minute: restarting");
    std::thread::sleep(Duration::from_millis(200));
    nix::unistd::sync();
    let _ = nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_AUTOBOOT);
    // (Process 1 of a container: ending is how it stops.)
    std::process::exit(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SigBlk mask of a thread started now (bit N-1 is signal N), read from its own status.
    fn blocked_in_new_thread() -> u64 {
        std::thread::spawn(|| {
            let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
            let line = status.lines().find_map(|line| line.strip_prefix("SigBlk:")).unwrap();
            u64::from_str_radix(line.trim(), 16).unwrap()
        })
        .join()
        .unwrap()
    }

    #[test]
    fn keeper_blocks_what_it_waits_for_before_a_thread_starts() {
        let before = SigSet::thread_get_mask().unwrap();
        let _ = block_heard();
        let blocked = blocked_in_new_thread();
        // (This test's own thread is put back as it was: the other tests run on it or after it.)
        before.thread_set_mask().unwrap();
        for signal in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGCHLD] {
            assert_eq!(blocked >> (signal as u32 - 1) & 1, 1, "{signal} is not blocked");
        }
    }

    #[test]
    fn keeper_unblocks_what_a_kept_kithd_handles() {
        let before = SigSet::thread_get_mask().unwrap();
        let _ = block_heard();
        unblock_heard();
        let blocked = blocked_in_new_thread();
        before.thread_set_mask().unwrap();
        for signal in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGCHLD] {
            assert_eq!(blocked >> (signal as u32 - 1) & 1, 0, "{signal} is still blocked");
        }
    }
}
