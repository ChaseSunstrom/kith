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
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How kithd says it is handing over to a kithd it staged (update.rs `stage`): it ends with
/// this code (EX_TEMPFAIL, no failure's own) and the staged file is there. Nothing else is read.
pub const HANDOVER: i32 = 75;
/// Where a staged kithd is: a tmpfs of its own, mounted exec and root-only (init.rs `mounts`).
pub const STAGED_DIR: &str = "/run/kith/bin";
pub const STAGED: &str = "/run/kith/bin/kithd";
/// A kithd that lived less than this has handed nothing over: its end counts as any other.
pub const HANDOVER_AFTER: Duration = Duration::from_secs(5);

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
    let mut kept = Kept::new(
        "/proc/self/exe".into(),
        STAGED.into(),
        std::env::args_os().skip(1).collect(),
    );
    let mut kithd = kept.start();
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
            eprintln!("kithd: init: kithd ended ({code}): starting it again");
            kept.ended(code);
            kithd = kept.start();
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

/// What the keeper knows of how kithd runs: which program starts it (its own file, or the one a
/// kithd staged and handed over to) and the ends of it that count as failures.
struct Kept {
    /// What starts kithd when nothing was handed over (and after a staged one failed).
    own: PathBuf,
    staged: PathBuf,
    args: Vec<OsString>,
    starts: u32,
    ends: Vec<Instant>,
    /// kithd ended handing over: the next start is of the staged file.
    handed: bool,
    began: Instant,
    /// How long a kithd must have run for its [`HANDOVER`] to be one.
    after: Duration,
}

impl Kept {
    fn new(own: PathBuf, staged: PathBuf, args: Vec<OsString>) -> Kept {
        Kept {
            own,
            staged,
            args,
            starts: 0,
            ends: Vec::new(),
            handed: false,
            began: Instant::now(),
            after: HANDOVER_AFTER,
        }
    }

    /// kithd ended with `code`. A hand-over (its code, the staged file there, and a kithd that
    /// ran for more than a moment) is no failure: the next start is of the staged file. Any other
    /// end counts toward the ten, and a staged kithd that ends so within the window is given up:
    /// the next start is of the keeper's own file again.
    fn ended(&mut self, code: i32) {
        let lived = self.began.elapsed();
        if code == HANDOVER && lived >= self.after && self.staged.is_file() {
            self.handed = true;
            return;
        }
        if self.handed && lived < WINDOW {
            eprintln!("kithd: init: the staged kithd failed within a minute: back to the one that started it");
            self.handed = false;
        }
        self.ends.retain(|at| at.elapsed() < WINDOW);
        self.ends.push(Instant::now());
    }

    /// Start kithd: the staged one after a hand-over, else this file again. The start
    /// after ten failures in a minute is told to end (and restart the machine); a failure past
    /// that restarts it here. A staged file that cannot be started is given up at once.
    fn start(&mut self) -> Option<Pid> {
        loop {
            if self.ends.len() > FAILURES {
                restart();
            }
            self.starts += 1;
            let program = if self.handed { &self.staged } else { &self.own };
            let mut command = std::process::Command::new(program);
            command.args(&self.args).env(KEPT, self.starts.to_string());
            if self.ends.len() == FAILURES {
                command.env(END, "1");
            }
            self.began = Instant::now();
            match command.spawn() {
                Ok(child) => return Some(Pid::from_raw(child.id() as i32)),
                Err(e) if self.handed => {
                    eprintln!("kithd: init: starting the staged kithd: {e}: back to the one that started it");
                    self.handed = false;
                }
                Err(e) => {
                    // (No end of it will be heard: counted here.)
                    eprintln!("kithd: init: starting kithd: {e}");
                    self.ends.retain(|at| at.elapsed() < WINDOW);
                    self.ends.push(Instant::now());
                    std::thread::sleep(Duration::from_secs(1));
                }
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

/// The keeper's hand-over: a kithd that ended handing over is followed by the file it staged, a
/// staged one that fails by the keeper's own, and a hand-over is no failure.
#[cfg(test)]
mod handover {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A folder with two programs, `own` and `staged`, each of which writes its name to `log`.
    fn folder(name: &str, staged_mode: u32) -> (PathBuf, Kept) {
        let dir = std::env::temp_dir().join(format!("kith-keeper-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (which, mode) in [("own", 0o755), ("staged", staged_mode)] {
            let file = dir.join(which);
            std::fs::write(&file, format!("#!/bin/sh\necho {which} >> {}/log\n", dir.display())).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let mut kept = Kept::new(dir.join("own"), dir.join("staged"), Vec::new());
        kept.after = Duration::ZERO;
        (dir, kept)
    }

    /// Starts kithd and waits for it, then what it wrote to the log.
    fn ran(kept: &mut Kept, dir: &std::path::Path) -> Vec<String> {
        let pid = kept.start().expect("a start");
        waitpid(pid, None).unwrap();
        let log = std::fs::read_to_string(dir.join("log")).unwrap_or_default();
        let _ = std::fs::remove_file(dir.join("log"));
        log.lines().map(str::to_string).collect()
    }

    #[test]
    fn starts_the_staged_binary_after_a_handover_mark_and_only_then() {
        let (dir, mut kept) = folder("mark", 0o755);
        assert_eq!(ran(&mut kept, &dir), ["own"]);
        kept.ended(HANDOVER);
        assert_eq!(ran(&mut kept, &dir), ["staged"], "after the mark: the staged file");
        // (The staged one handing over again is followed again: a newer kithd staged over it.)
        kept.ended(HANDOVER);
        assert_eq!(ran(&mut kept, &dir), ["staged"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_mark_with_nothing_staged_is_an_end_like_any_other() {
        let (dir, mut kept) = folder("none", 0o755);
        std::fs::remove_file(dir.join("staged")).unwrap();
        kept.ended(HANDOVER);
        assert_eq!((kept.handed, kept.ends.len()), (false, 1));
        assert_eq!(ran(&mut kept, &dir), ["own"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn falls_back_to_its_own_after_a_failed_start_of_the_staged_one() {
        // One that cannot be started (no execute bit): the next start is of the keeper's own.
        let (dir, mut kept) = folder("fails", 0o644);
        kept.ended(HANDOVER);
        assert!(kept.handed);
        assert_eq!(ran(&mut kept, &dir), ["own"]);
        assert!(!kept.handed, "given up: it is not tried again");
        // One that starts and ends at once: the end counts, and the next start is of its own.
        let (dir2, mut kept) = folder("dies", 0o755);
        kept.ended(HANDOVER);
        kept.ended(1);
        assert_eq!((kept.handed, kept.ends.len()), (false, 1));
        assert_eq!(ran(&mut kept, &dir2), ["own"]);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn a_handover_end_does_not_count_toward_the_ten_failures() {
        let (dir, mut kept) = folder("count", 0o755);
        for _ in 0..(FAILURES * 3) {
            kept.ended(HANDOVER);
        }
        assert!(kept.ends.is_empty(), "{} counted", kept.ends.len());
        // The same end of a kithd that had not run for long enough counts (a loop of them restarts the machine).
        kept.after = Duration::from_secs(3600);
        kept.handed = false;
        kept.ended(HANDOVER);
        assert_eq!(kept.ends.len(), 1);
        // And any other end counts, as before.
        kept.after = Duration::ZERO;
        for _ in 0..(FAILURES - 1) {
            kept.ended(1);
        }
        assert_eq!(kept.ends.len(), FAILURES);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A unit started before a hand-over, taken back by the kithd that is started after it: the
/// same process, known by its pid, its start time and its cgroup.
#[cfg(test)]
mod container {
    mod adopt {
        use kith_runtime::{Runtime, started};
        use nix::unistd::Pid;

        #[test]
        fn a_unit_started_before_a_handover_is_adopted_with_the_same_pid_and_start_time() {
            let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
            let own = own
                .lines()
                .find_map(|l| l.strip_prefix("0::"))
                .unwrap_or("/")
                .to_string();
            let Some(parent) = std::path::Path::new(&own)
                .parent()
                .filter(|p| *p != std::path::Path::new("/"))
            else {
                eprintln!("no delegated cgroup here: not run");
                return;
            };
            let id = format!("handover-{}", std::process::id());
            let group = std::path::Path::new("/sys/fs/cgroup")
                .join(parent.strip_prefix("/").unwrap())
                .join(format!("kith-{id}"));
            if std::fs::create_dir(&group).is_err() {
                eprintln!("cannot make a cgroup in {}: not run", group.display());
                return;
            }
            // The unit the first kithd started: a process in its own cgroup, written down as it does.
            let mut unit = std::process::Command::new("sleep").arg("60").spawn().unwrap();
            let pid = Pid::from_raw(unit.id() as i32);
            let moved = std::fs::write(group.join("cgroup.procs"), unit.id().to_string());
            let root = std::env::temp_dir().join(format!("kith-adopt-handover-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let records = root.join("units");
            std::fs::create_dir_all(&records).unwrap();
            let start = started(pid).expect("its start time");
            std::fs::write(records.join(&id), format!("{pid} {start} the-mark\n")).unwrap();
            // The kithd the keeper starts after the hand-over: a runtime of its own over the same records.
            let staged = Runtime::new(root.join("runtime")).map(|mut rt| {
                rt.records = Some(records.clone());
                rt
            });
            let taken = staged.as_ref().map(|rt| rt.adopt());
            let held = taken.map(|mut taken| (taken.remove(&id), taken.len()));
            let (alive, same_start) = (unit.try_wait().is_ok_and(|ended| ended.is_none()), started(pid));
            let ran = held.map(|(held, others)| {
                held.map(|(mut handle, mark)| (handle.try_wait().ok(), handle.pid(), mark, others))
            });
            let _ = unit.kill();
            let _ = unit.wait();
            let _ = std::fs::remove_dir(&group);
            let _ = std::fs::remove_dir_all(&root);
            moved.expect("moving the unit into its cgroup");
            let (still, taken_pid, mark, others) = ran.expect("a runtime").expect("the unit is taken back");
            assert_eq!(
                (taken_pid, mark.as_str(), others),
                (pid.as_raw(), "the-mark", 0),
                "the same pid"
            );
            // The same process, by its start time too: it was not started again, and runs on.
            assert_eq!((alive, same_start), (true, Some(start)));
            assert_eq!(still, Some(None), "taken back as running");
        }
    }
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
