//! What a pod writes outside its Volumes: its containers' writable roots and its disk scratch,
//! counted together, and which pod is replaced for it.

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// One pod as it was counted.
pub struct Pod {
    /// Its id (`pod_of`).
    pub id: String,
    /// The sum of what its containers state in `resources.storage`; `None` when none does.
    pub limit: Option<u64>,
    /// Bytes on disk under its roots; past its limit, where the count stopped.
    pub bytes: u64,
}

/// How the message of a unit replaced for what its pod wrote begins.
pub const REPLACED: &str = "replaced: ";

/// The reserve a node keeps when its flag does not say: 5% of its state disk, at most 1 GiB.
pub fn default_reserve(total: u64) -> u64 {
    (total / 20).min(1 << 30)
}

/// Whether a pod is counted at all: one with a limit always, one without only while the state
/// disk has less than twice its reserve free (it is counted for the reserve alone).
pub fn walked(limit: Option<u64>, free: u64, reserve: u64) -> bool {
    limit.is_some() || free < reserve.saturating_mul(2)
}

/// Bytes on disk under `roots`. Follows no symlink, counts a file with several links once and
/// leaves out what another filesystem holds. Stops as soon as it is past `stop`. What cannot be
/// read is passed over.
//
// ponytail: the files a pod made are walked one by one, so millions of small ones make a slow
// count; an ext4 project quota on each root would hold the line at the write instead.
pub fn count(roots: &[PathBuf], stop: u64) -> u64 {
    let mut linked = BTreeSet::new();
    let mut bytes = 0u64;
    for root in roots {
        let Ok(top) = std::fs::symlink_metadata(root) else {
            continue;
        };
        let device = top.dev();
        bytes = bytes.saturating_add(top.blocks() * 512);
        let mut dirs = match top.is_dir() {
            true => vec![root.clone()],
            false => Vec::new(),
        };
        while let Some(dir) = dirs.pop() {
            if bytes > stop {
                return bytes;
            }
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                // (Not followed: a symlink is the link itself.)
                let Ok(meta) = entry.metadata() else { continue };
                if meta.dev() != device || (meta.nlink() > 1 && !meta.is_dir() && !linked.insert((device, meta.ino())))
                {
                    continue;
                }
                bytes = bytes.saturating_add(meta.blocks() * 512);
                if bytes > stop {
                    return bytes;
                }
                if meta.is_dir() {
                    dirs.push(entry.path());
                }
            }
        }
    }
    bytes
}

/// Moves the directory `scratch` aside, to a new name beside it, and returns that: what is
/// made at `scratch` next is empty. `None` when there is none.
pub fn aside(scratch: &Path) -> Option<PathBuf> {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    let gone = scratch.with_file_name(format!("scratch.{}", nanos.unwrap_or_default().as_nanos()));
    std::fs::rename(scratch, &gone).ok().map(|()| gone)
}

/// The pods to replace, by index into `pods`, and why. Every pod past its limit; while
/// `free` is under `reserve` and none is, the one that wrote the most (one a count), if what it
/// wrote is a tenth of the reserve or more: replacing a pod that wrote less frees nothing much.
pub fn choose(pods: &[Pod], free: u64, reserve: u64) -> Vec<(usize, String)> {
    let over: Vec<(usize, String)> = pods
        .iter()
        .enumerate()
        .filter_map(|(i, pod)| {
            let limit = pod.limit.filter(|limit| pod.bytes > *limit)?;
            let why = format!(
                "replaced: its pod wrote {} bytes outside its volumes, over its limit of {limit}",
                pod.bytes
            );
            Some((i, why))
        })
        .collect();
    if !over.is_empty() || free >= reserve {
        return over;
    }
    let most = pods.iter().enumerate().max_by_key(|(_, pod)| pod.bytes);
    let most = most.filter(|(_, pod)| pod.bytes.saturating_mul(10) >= reserve);
    most.map(|(i, pod)| {
        let why = format!(
            "replaced: the node's state disk has {free} bytes free, under its reserve of {reserve}, and its pod wrote the most outside its volumes, {} bytes",
            pod.bytes
        );
        (i, why)
    })
    .into_iter()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kithd-storage-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pod(id: &str, limit: Option<u64>, bytes: u64) -> Pod {
        Pod {
            id: id.into(),
            limit,
            bytes,
        }
    }

    const MIB: u64 = 1 << 20;

    #[test]
    fn storage_limit_count_stops_past_its_limit_and_counts_blocks() {
        let root = dir("stop");
        for n in 0..8 {
            std::fs::write(root.join(n.to_string()), vec![1u8; MIB as usize]).unwrap();
        }
        let all = count(std::slice::from_ref(&root), u64::MAX);
        assert!((8 * MIB..9 * MIB).contains(&all), "{all}");
        // Past 2 MiB it stops: a file or two more at most, never the whole.
        let stopped = count(std::slice::from_ref(&root), 2 * MIB);
        assert!(stopped > 2 * MIB && stopped < 4 * MIB, "{stopped}");
        // A sparse file is what it holds on disk, not its length.
        let sparse = dir("sparse");
        std::fs::File::create(sparse.join("hole"))
            .unwrap()
            .set_len(1 << 30)
            .unwrap();
        assert!(count(std::slice::from_ref(&sparse), u64::MAX) < MIB);
        // A root that is not there is nothing.
        assert_eq!(count(&[root.join("gone")], u64::MAX), 0);
        for d in [root, sparse] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn storage_limit_a_hard_linked_file_is_counted_once_and_no_symlink_is_followed() {
        let root = dir("links");
        let (a, b) = (root.join("a"), root.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("file"), vec![1u8; 4 * MIB as usize]).unwrap();
        let alone = count(&[a.clone(), b.clone()], u64::MAX);
        // Linked again in the same root and in another root of the pod: no more bytes.
        std::fs::hard_link(a.join("file"), a.join("again")).unwrap();
        std::fs::hard_link(a.join("file"), b.join("again")).unwrap();
        assert_eq!(count(&[a.clone(), b.clone()], u64::MAX), alone);
        // A symlink to what is outside, a file or a directory, adds nothing of what it names.
        let outside = dir("outside");
        std::fs::write(outside.join("big"), vec![1u8; 4 * MIB as usize]).unwrap();
        std::os::unix::fs::symlink(&outside, b.join("dir")).unwrap();
        std::os::unix::fs::symlink(outside.join("big"), b.join("file")).unwrap();
        std::os::unix::fs::symlink(&b, b.join("loop")).unwrap();
        assert!(count(&[a.clone(), b.clone()], u64::MAX) < alone + MIB);
        for d in [root, outside] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn storage_limit_a_pod_over_its_limit_is_replaced_and_says_by_how_much() {
        let pods = [
            pod("a", Some(10 * MIB), 12 * MIB),
            pod("b", Some(10 * MIB), 9 * MIB),
            pod("c", None, 0),
        ];
        let chosen = choose(&pods, u64::MAX, MIB);
        assert_eq!(chosen.len(), 1);
        let (which, why) = &chosen[0];
        assert_eq!(*which, 0);
        assert!(why.starts_with(REPLACED), "{why}");
        assert!(
            why.contains(&(12 * MIB).to_string()) && why.contains(&(10 * MIB).to_string()),
            "{why}"
        );
        // Under its limit, or at it, it is left alone.
        let under = [pod("a", Some(10 * MIB), 10 * MIB)];
        assert!(choose(&under, u64::MAX, MIB).is_empty());
        // Two past their limits: both go.
        let two = [pod("a", Some(MIB), 2 * MIB), pod("b", Some(MIB), 3 * MIB)];
        assert_eq!(choose(&two, u64::MAX, MIB).len(), 2);
    }

    #[test]
    fn storage_limit_a_replaced_pods_scratch_is_set_aside_whole() {
        let replica = dir("aside");
        let scratch = replica.join("scratch");
        std::fs::create_dir_all(scratch.join("cache")).unwrap();
        std::fs::write(scratch.join("cache").join("file"), "written").unwrap();
        let gone = aside(&scratch).unwrap();
        assert!(!scratch.exists() && gone.join("cache").join("file").exists());
        assert_eq!(gone.parent(), Some(replica.as_path()));
        // Nothing there: nothing to set aside.
        assert_eq!(aside(&scratch), None);
        std::fs::remove_dir_all(replica).unwrap();
    }

    #[test]
    fn storage_reserve_the_pod_that_wrote_most_is_replaced_one_a_count() {
        let reserve = 100 * MIB;
        let pods = [
            pod("small", None, 20 * MIB),
            pod("big", None, 50 * MIB),
            pod("limited", Some(80 * MIB), 30 * MIB),
        ];
        // Free above the reserve: nothing.
        assert!(choose(&pods, reserve, reserve).is_empty());
        // Under it: the biggest writer, alone, and it says why.
        let chosen = choose(&pods, reserve - 1, reserve);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].0, 1);
        assert!(chosen[0].1.contains("reserve"), "{}", chosen[0].1);
        // One past its limit goes before the biggest writer, which is left for a later count.
        let over = [pod("big", None, 50 * MIB), pod("over", Some(MIB), 2 * MIB)];
        let chosen = choose(&over, 0, reserve);
        assert_eq!(chosen.iter().map(|c| c.0).collect::<Vec<_>>(), [1]);
        // A pod that wrote too little to free anything is not replaced for the reserve.
        assert!(choose(&[pod("tiny", None, 4096)], 0, reserve).is_empty());
        // A reserve of 0 is none.
        assert!(choose(&pods, 0, 0).is_empty());
    }

    #[test]
    fn storage_reserve_a_pod_without_a_limit_is_counted_only_when_the_disk_is_low() {
        let reserve = 100 * MIB;
        assert!(walked(Some(MIB), u64::MAX, reserve));
        assert!(!walked(None, 2 * reserve, reserve));
        assert!(walked(None, 2 * reserve - 1, reserve));
        assert!(!walked(None, 0, 0));
        assert_eq!(default_reserve(10 * MIB * 20), 10 * MIB);
        assert_eq!(default_reserve(1 << 40), 1 << 30);
    }
}
