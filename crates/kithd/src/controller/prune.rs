//! Removing the images no unit on this node uses: once unused for `--image-grace`, and sooner,
//! oldest first, while the state disk is under its reserve. What goes and what stays of an
//! image's files is `ImageStore::remove_image`'s; this is which, and what is said of it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

/// How often the images are looked over, at most.
pub const EVERY: Duration = Duration::from_secs(60);

/// However short the disk, an image used later than this before a pass stays. Its last use
/// is the last look that found it in use, so this is at least one whole look unused: a unit
/// that stopped a moment ago and starts again (a retry, a drain taken off) still has it.
pub const LEAST: Duration = Duration::from_secs(2 * EVERY.as_secs());

/// Removes, of the `unused` images (oldest first, each with when it was last used), those
/// unused for `grace` by `began`, and while `low` says the state disk is under its reserve
/// the others unused for `LEAST`, oldest first; `remove(digest, before)` removes one unless
/// it was used after `before`. Gives up as `stop` is set. A grace of 0 removes nothing.
/// What is said of each, a line for the log.
pub fn prune(
    unused: &[(String, SystemTime)],
    began: SystemTime,
    grace: Duration,
    mut low: impl FnMut() -> bool,
    mut remove: impl FnMut(&str, SystemTime) -> Result<Option<u64>, String>,
    stop: &AtomicBool,
) -> Vec<String> {
    let mut said = Vec::new();
    if grace.is_zero() {
        return said;
    }
    let (cut, least) = (began.checked_sub(grace), began.checked_sub(LEAST));
    for (digest, since) in unused {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let (before, why) = match (cut, least) {
            (Some(cut), _) if *since <= cut => (cut, "past its grace"),
            (_, Some(least)) if *since <= least && low() => (least, "the state disk is under its reserve"),
            // The rest were used later still.
            _ => break,
        };
        let idle = began.duration_since(*since).unwrap_or_default().as_secs();
        match remove(digest, before) {
            Ok(Some(bytes)) => said.push(format!(
                "kithd: removed image {digest}, unused for {idle} s ({why}): {bytes} bytes freed"
            )),
            // Used since, or a pull holds the store: it stays this time.
            Ok(None) => {}
            Err(e) => said.push(format!("kithd: removing image {digest}: {e}")),
        }
    }
    said
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const HOUR: Duration = Duration::from_secs(3600);

    /// `unused` as images last used `ago` before `began`, oldest first.
    fn images(began: SystemTime, ago: &[u64]) -> Vec<(String, SystemTime)> {
        ago.iter()
            .map(|h| (format!("sha256:{h}"), began - HOUR * *h as u32))
            .collect()
    }

    /// The digests `prune` removed (with the `before` each was asked with), and what it said.
    fn run(
        unused: &[(String, SystemTime)],
        began: SystemTime,
        grace: Duration,
        low: impl FnMut() -> bool,
    ) -> (Vec<(String, SystemTime)>, Vec<String>) {
        let removed = RefCell::new(Vec::new());
        let said = prune(
            unused,
            began,
            grace,
            low,
            |digest, before| {
                removed.borrow_mut().push((digest.to_string(), before));
                Ok(Some(1000))
            },
            &AtomicBool::new(false),
        );
        (removed.into_inner(), said)
    }

    #[test]
    fn image_removal_takes_what_is_past_its_grace_and_keeps_the_rest() {
        let began = SystemTime::now();
        let (removed, said) = run(&images(began, &[30, 25, 2, 1]), began, 24 * HOUR, || false);
        let digests: Vec<&str> = removed.iter().map(|(d, _)| d.as_str()).collect();
        assert_eq!(digests, ["sha256:30", "sha256:25"]);
        // Each is removed only if it was not used since its grace began.
        assert!(removed.iter().all(|(_, before)| *before == began - 24 * HOUR));
        assert_eq!(said.len(), 2);
        assert!(
            said[0]
                .starts_with("kithd: removed image sha256:30, unused for 108000 s (past its grace): 1000 bytes freed"),
            "{said:?}"
        );
    }

    #[test]
    fn image_removal_grace_zero_is_off() {
        let began = SystemTime::now();
        let (removed, said) = run(&images(began, &[1000, 1]), began, Duration::ZERO, || true);
        assert!(removed.is_empty() && said.is_empty());
    }

    #[test]
    fn image_removal_under_reserve_goes_oldest_first_and_stops_once_free() {
        let began = SystemTime::now();
        // Under the reserve until two are gone.
        let asked = Cell::new(0);
        let low = || {
            asked.set(asked.get() + 1);
            asked.get() <= 2
        };
        let (removed, said) = run(&images(began, &[5, 3, 2, 1]), began, 24 * HOUR, low);
        let digests: Vec<&str> = removed.iter().map(|(d, _)| d.as_str()).collect();
        assert_eq!(digests, ["sha256:5", "sha256:3"]);
        // Within its grace, an image used within `LEAST` of the pass stays.
        assert!(removed.iter().all(|(_, before)| *before == began - LEAST));
        assert!(said[1].contains("(the state disk is under its reserve)"), "{said:?}");
        // However short the disk, one stopped a moment ago (seen in use at the last look) stays.
        let stopped = [("sha256:just".to_string(), began - EVERY)];
        let (removed, said) = run(&stopped, began, 24 * HOUR, || true);
        assert!(removed.is_empty() && said.is_empty(), "{said:?}");
        // Past grace ones go first and need no shortage.
        let asked = Cell::new(0);
        let low = || {
            asked.set(asked.get() + 1);
            false
        };
        let (removed, _) = run(&images(began, &[48, 3]), began, 24 * HOUR, low);
        assert_eq!(removed.len(), 1);
        assert_eq!(asked.get(), 1, "the disk was asked about an image past its grace");
    }

    #[test]
    fn image_removal_keeps_one_used_since_and_says_a_failure_and_stops_when_told() {
        let began = SystemTime::now();
        let unused = images(began, &[50, 40]);
        let mut calls = 0;
        let said = prune(
            &unused,
            began,
            HOUR,
            || false,
            |digest, _| {
                calls += 1;
                match digest {
                    "sha256:50" => Ok(None),
                    _ => Err("Permission denied".into()),
                }
            },
            &AtomicBool::new(false),
        );
        assert_eq!(calls, 2);
        assert_eq!(said, ["kithd: removing image sha256:40: Permission denied"]);
        let said = prune(
            &unused,
            began,
            HOUR,
            || true,
            |_, _| panic!("removed"),
            &AtomicBool::new(true),
        );
        assert!(said.is_empty());
    }
}
