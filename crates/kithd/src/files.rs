//! What a replica mounts that is no Volume: the keys of a ConfigMap or a Secret as files,
//! and empty directories of its own. Each replica has one directory for them on the state
//! disk and one in memory (a Secret's files, and a scratch that asks), and both go when
//! the replica does.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Under which every replica's directory is, in `state` and in [`memory`].
pub(crate) const REPLICAS: &str = "replicas";
/// The link the files of a mounted map are read through: renamed over, so they change at once.
const DATA: &str = "..data";

/// A directory of this machine's memory for kithd, or why there is none: `/run/kith` where
/// kithd is root, the user's runtime directory where it is not. Not taken on its word: it
/// is asked what file system it is, and a Secret is not written to one with a disk under it.
pub fn memory() -> Result<PathBuf, String> {
    let dir = memory_dir().ok_or("no directory in memory here (XDG_RUNTIME_DIR is not set)")?;
    in_memory(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(dir)
}

/// Where [`memory`] is, made or not.
pub fn memory_dir() -> Option<PathBuf> {
    let base = match nix::unistd::getuid().is_root() {
        true => Some(PathBuf::from("/run")),
        false => std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
    };
    Some(base?.join("kith"))
}

fn in_memory(dir: &Path) -> io::Result<()> {
    use nix::sys::statfs::{FsType, TMPFS_MAGIC, statfs};
    // (What a system that runs from its initramfs has `/run` on, where it has no tmpfs.)
    const RAMFS_MAGIC: FsType = FsType(0x8584_58f6);
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, PermissionsExt::from_mode(0o700))?;
    let kind = statfs(dir)?.filesystem_type();
    match kind == TMPFS_MAGIC || kind == RAMFS_MAGIC {
        true => Ok(()),
        false => Err(io::Error::other(
            "not in memory: a Secret's files are not written to a disk",
        )),
    }
}

/// The directory of the replica `replica` (its pod's id) under `base`, kithd's alone.
pub fn of(base: &Path, replica: &str) -> io::Result<PathBuf> {
    let dir = base.join(REPLICAS).join(replica);
    std::fs::create_dir_all(&dir)?;
    for dir in [dir.parent().unwrap_or(&dir), &dir] {
        std::fs::set_permissions(dir, PermissionsExt::from_mode(0o700))?;
    }
    Ok(dir)
}

/// An empty directory any user of the replica's containers may write, made if it is not there.
pub fn scratch(base: &Path, replica: &str, name: &str) -> io::Result<PathBuf> {
    let dir = of(base, replica)?.join("scratch").join(name);
    std::fs::create_dir_all(&dir)?;
    // (Whoever its containers are: nobody else reaches it, under directories that are kithd's alone.)
    std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o1777))?;
    Ok(dir)
}

/// Write `files` (a path inside to its content) into `dir`, as the whole of what it
/// holds: into a new directory beside the last, which a link (`..data`) is then renamed
/// to name, so whoever reads sees all of the old or all of the new. They are made the
/// user's that `dir` is (the container's, once it was given to it).
pub fn write(dir: &Path, files: &BTreeMap<String, String>, mode: u32) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let (uid, gid) = std::fs::metadata(dir).map(|has| (has.uid(), has.gid()))?;
    let own = |path: &Path| match std::os::unix::fs::lchown(path, Some(uid), Some(gid)) {
        // (Where kithd is not root everything is its user's, the container's one user.)
        Err(e) if e.kind() != io::ErrorKind::PermissionDenied => Err(e),
        _ => Ok(()),
    };
    // Asked again here, where it is written: a key is a name anyone may have given.
    for path in files.keys() {
        kith_api::kinds::inside("a file", path).map_err(io::Error::other)?;
    }
    let last = std::fs::read_link(dir.join(DATA)).ok();
    let number = |name: &PathBuf| name.to_str()?.strip_prefix("..")?.parse::<u64>().ok();
    let new = format!("..{}", last.as_ref().and_then(number).unwrap_or(0) + 1);
    let data = dir.join(&new);
    // (Left by a write that was cut short.)
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir(&data)?;
    own(&data)?;
    for (path, content) in files {
        let file = data.join(path);
        for parent in file.ancestors().skip(1).take_while(|parent| *parent != data) {
            std::fs::create_dir_all(parent)?;
            own(parent)?;
        }
        std::fs::write(&file, content)?;
        std::fs::set_permissions(&file, PermissionsExt::from_mode(mode))?;
        own(&file)?;
    }
    let link = dir.join("..new");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&new, &link)?;
    own(&link)?;
    std::fs::rename(&link, dir.join(DATA))?;
    // What is at the top: a link per file or directory there, through `..data`.
    let tops: BTreeSet<&str> = files.keys().filter_map(|path| path.split('/').next()).collect();
    for entry in std::fs::read_dir(dir)?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == DATA || name == new.as_str() {
            continue;
        }
        if name.starts_with("..") {
            let _ = std::fs::remove_dir_all(entry.path());
        } else if !tops.contains(&*name) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    for top in tops {
        let link = dir.join(top);
        if std::fs::symlink_metadata(&link).is_err() {
            std::os::unix::fs::symlink(Path::new(DATA).join(top), &link)?;
            own(&link)?;
        }
    }
    Ok(())
}

/// The file `path` of what [`write`] put in `dir`, as it is now: for mounting it alone.
pub fn one(dir: &Path, path: &str) -> io::Result<PathBuf> {
    kith_api::kinds::inside("subPath", path).map_err(io::Error::other)?;
    let file = dir.join(std::fs::read_link(dir.join(DATA))?).join(path);
    match std::fs::symlink_metadata(&file)?.is_file() {
        true => Ok(file),
        false => Err(io::Error::other("not a file")),
    }
}

/// Remove the directory of every replica that is not in `keep`, under each of `bases`.
pub fn sweep(bases: &[&Path], keep: &BTreeSet<String>) {
    for base in bases {
        for entry in std::fs::read_dir(base.join(REPLICAS)).into_iter().flatten().flatten() {
            if !keep.contains(&*entry.file_name().to_string_lossy())
                && let Err(e) = std::fs::remove_dir_all(entry.path())
            {
                eprintln!("kithd: removing {}: {e}", entry.path().display());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(files: &[(&str, &str)]) -> BTreeMap<String, String> {
        files
            .iter()
            .map(|(path, content)| (path.to_string(), content.to_string()))
            .collect()
    }

    /// A mounted map is replaced whole: its files are read through one link, what is no
    /// longer in it is gone, and nothing of the directory before is left behind.
    #[test]
    fn a_maps_files_are_replaced_whole_and_never_written_outside() {
        let base = std::env::temp_dir().join(format!("kith-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dir = of(&base, "w_default_web_0").unwrap().join("files/web/0");
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).ok();
        write(
            &dir,
            &map(&[("index", "one"), ("conf.d/site", "a"), ("gone", "x")]),
            0o440,
        )
        .unwrap();
        assert_eq!(
            (read("index"), read("conf.d/site")),
            (Some("one".into()), Some("a".into()))
        );
        let mode = |name: &str| std::fs::metadata(dir.join(name)).unwrap().mode() & 0o7777;
        assert_eq!(mode("index"), 0o440);
        assert!(std::fs::symlink_metadata(dir.join("index")).unwrap().is_symlink());
        assert_eq!(one(&dir, "conf.d/site").unwrap(), dir.join("..1/conf.d/site"));
        assert!(one(&dir, "conf.d").is_err() && one(&dir, "../x").is_err() && one(&dir, "none").is_err());

        write(&dir, &map(&[("index", "two"), ("new", "n")]), 0o444).unwrap();
        assert_eq!(
            (read("index"), read("new"), read("gone"), read("conf.d/site")),
            (Some("two".into()), Some("n".into()), None, None)
        );
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["..2", "..data", "index", "new"]);

        // A key is not a way out of the directory, and what was there stays.
        for bad in ["../out", "/etc/out", "a/../../out", "..data"] {
            assert!(write(&dir, &map(&[(bad, "x")]), 0o444).is_err(), "{bad}");
        }
        assert!(!base.join("out").exists() && !dir.join("../out").exists());
        assert_eq!(read("index"), Some("two".into()));

        // A scratch is anyone's to write, under directories that are kithd's alone; and
        // all of a replica's goes with it.
        let made = scratch(&base, "w_default_web_0", "cache").unwrap();
        assert_eq!(std::fs::metadata(&made).unwrap().mode() & 0o7777, 0o1777);
        assert_eq!(std::fs::metadata(base.join(REPLICAS)).unwrap().mode() & 0o777, 0o700);
        scratch(&base, "w_default_web_1", "cache").unwrap();
        sweep(&[&base], &BTreeSet::from(["w_default_web_1".to_string()]));
        assert!(
            !base.join(REPLICAS).join("w_default_web_0").exists()
                && base.join(REPLICAS).join("w_default_web_1").exists()
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// A Secret's files are written where the kernel says there is no disk, or not at all.
    #[test]
    fn a_directory_on_a_disk_is_not_memory() {
        // (Where this was built: a disk, unless someone builds in memory.)
        let disk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp/kith-not-memory");
        let kind = |dir: &Path| nix::sys::statfs::statfs(dir).map(|fs| fs.filesystem_type());
        std::fs::create_dir_all(&disk).unwrap();
        if kind(&disk).unwrap() != nix::sys::statfs::TMPFS_MAGIC {
            let refused = in_memory(&disk).unwrap_err().to_string();
            assert!(refused.starts_with("not in memory"), "{refused}");
        }
        let Ok(dir) = memory() else {
            return eprintln!("no directory in memory on this machine: not checked here");
        };
        assert!(in_memory(&dir).is_ok());
    }
}
