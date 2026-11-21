//! Where the time of one path goes (`ci/budgets.py --phases`): with `KITH_TIMELINE` set, [`mark`]
//! writes one line, `kith-timeline NAME NANOS`, to stderr (kithd's log), NANOS being CLOCK_MONOTONIC,
//! the clock Python's `time.monotonic_ns` reads. Off, a mark is one load and a branch.
//! A mark may be made in the child of a `fork` (the container's helper): it takes no lock of stderr.

use std::sync::OnceLock;

/// The line a mark writes.
pub fn line(name: &str, nanos: u64) -> String {
    format!("kith-timeline {name} {nanos}\n")
}

pub fn mark(name: &str) {
    static ON: OnceLock<bool> = OnceLock::new();
    if !*ON.get_or_init(|| std::env::var_os("KITH_TIMELINE").is_some()) {
        return;
    }
    let now = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC);
    let nanos = now.map_or(0, |t| t.tv_sec() as u64 * 1_000_000_000 + t.tv_nsec() as u64);
    let _ = nix::unistd::write(std::io::stderr(), line(name, nanos).as_bytes());
}
