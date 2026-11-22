//! A test's own directory in the temp dir, removed when its guard drops (also when the test
//! panics: unwinding drops it). Tests that made `temp_dir().join(..)` by hand left one per
//! test per run, 25,000 in five days.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// An empty directory, `<temp dir>/<prefix>-<pid>-<n>`, removed with this value.
/// Keep it in the test's scope: a task that outlives it writes into a directory that is gone.
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(prefix: &str) -> Scratch {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::Scratch;

    #[test]
    fn scratch_guard_removes_its_dir_on_drop() {
        let guard = Scratch::new("kithd-scratch-drop");
        let dir = guard.to_path_buf();
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("a/b/c"), b"x").unwrap();
        assert!(dir.is_dir());
        drop(guard);
        assert!(!dir.exists());
    }

    #[test]
    fn scratch_guard_removes_its_dir_when_the_test_panics() {
        let seen = std::sync::Mutex::new(None);
        let result = std::panic::catch_unwind(|| {
            let guard = Scratch::new("kithd-scratch-panic");
            *seen.lock().unwrap() = Some(guard.to_path_buf());
            std::fs::write(guard.join("f"), b"x").unwrap();
            panic!("the test failed");
        });
        assert!(result.is_err());
        let dir = seen.lock().unwrap().take().unwrap();
        assert!(!dir.exists(), "{dir:?} was left behind");
    }

    #[test]
    fn scratch_guard_hands_out_a_dir_of_its_own_each_time() {
        let (a, b) = (Scratch::new("kithd-scratch-same"), Scratch::new("kithd-scratch-same"));
        assert_ne!(a.to_path_buf(), b.to_path_buf());
    }
}
