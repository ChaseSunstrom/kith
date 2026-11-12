//! Pulling images and unpacking them.
//!
//! ```text
//! <root>/blobs/sha256/<hex>          layers, exactly as the registry serves them
//! <root>/images/<manifest hex>/      one unpacked image
//!     rootfs/                        shared read-only by its containers
//!     config.json                    written last: its presence means "complete"
//! ```

use crate::{Context, Result, err};
use oci_client::client::ClientConfig;
use oci_client::config::ConfigFile;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

pub struct ImageStore {
    root: PathBuf,
}

/// A pulled, unpacked image.
#[derive(Debug, Clone, Default)]
pub struct Image {
    /// The manifest digest, `sha256:<hex>`.
    pub digest: String,
    pub rootfs: PathBuf,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    /// `NAME=value` entries.
    pub env: Vec<String>,
    pub working_dir: Option<String>,
    /// Layers this pull had to download; 0 when everything was already stored.
    pub downloaded: usize,
}

/// The hex part of a `sha256:<64 hex>` digest. Digests come from the registry
/// and become file names, so anything else is refused.
fn sha256_hex(digest: &str) -> Result<&str> {
    match digest.strip_prefix("sha256:") {
        Some(hex) if hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) => Ok(hex),
        _ => err(format!(
            "unsupported digest `{digest}`: expected sha256:<64 hex digits>"
        )),
    }
}

impl ImageStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<ImageStore> {
        let root = root.into();
        // Errors only if a provider is already installed, which is just as good.
        let _ = rustls::crypto::ring::default_provider().install_default();
        fs::create_dir_all(root.join("blobs/sha256")).ctx(format!("creating {}", root.display()))?;
        fs::create_dir_all(root.join("images")).ctx(format!("creating {}", root.display()))?;
        // Images keep their setuid bits; nobody else on this machine gets to run them.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).ctx(format!("securing {}", root.display()))?;
        Ok(ImageStore { root })
    }

    /// Pull `reference` (e.g. `docker.io/library/busybox:1.36`) for this machine's
    /// platform. Always asks the registry which manifest the tag points at;
    /// layers and unpacked images already in the store are reused.
    // ponytail: anonymous pulls only; registry credentials arrive with Secrets in the controller.
    pub async fn pull(&self, reference: &str) -> Result<Image> {
        let reference: Reference = reference.parse().ctx(format!("image reference `{reference}`"))?;
        let client = Client::new(ClientConfig::default());
        let auth = RegistryAuth::Anonymous;
        let (manifest, digest, config) = client
            .pull_manifest_and_config(&reference, &auth)
            .await
            .ctx(format!("pulling {reference}"))?;
        let config: ConfigFile =
            serde_json::from_str(&config).ctx(format!("reading the image config of {reference}"))?;

        let mut layers = Vec::new();
        let mut downloaded = 0;
        for layer in &manifest.layers {
            let blob = self.root.join("blobs/sha256").join(sha256_hex(&layer.digest)?);
            if !blob.exists() {
                // oci-client checks the bytes against the layer digest as they stream.
                let partial = blob.with_extension(scratch_name("partial"));
                let mut file = tokio::fs::File::create(&partial).await.ctx("storing a layer")?;
                let mut pulled = client
                    .pull_blob(&reference, layer, &mut file)
                    .await
                    .ctx(format!("pulling layer {} of {reference}", layer.digest));
                if pulled.is_ok() {
                    // On disk before it gets its final name: a crash must not leave half a layer there.
                    pulled = file.sync_all().await.ctx("storing a layer");
                }
                if pulled.is_err() {
                    let _ = fs::remove_file(&partial);
                }
                pulled?;
                fs::rename(&partial, &blob).ctx("storing a layer")?;
                downloaded += 1;
            }
            layers.push((blob, layer.media_type.clone()));
        }

        let dir = self.root.join("images").join(sha256_hex(&digest)?);
        if !dir.join("config.json").exists() {
            let staging = dir.with_extension(scratch_name("unpacking"));
            let target = dir.clone();
            let unpacked = tokio::task::spawn_blocking(move || -> Result<()> {
                let _ = fs::remove_dir_all(&staging);
                fs::create_dir_all(staging.join("rootfs")).ctx("unpacking")?;
                for (blob, media_type) in &layers {
                    unpack_layer(blob, media_type, &staging.join("rootfs"))?;
                }
                // The marker that the image is complete, so it is written last.
                fs::write(staging.join("config.json"), "{}").ctx("unpacking")?;
                match fs::rename(&staging, &target) {
                    // Another pull of the same image finished first; theirs is as good as ours.
                    Err(_) if target.join("config.json").exists() => fs::remove_dir_all(&staging).ctx("unpacking"),
                    other => other.ctx("unpacking"),
                }
            });
            unpacked.await.ctx("unpacking")??;
        }

        let cfg = config.config.unwrap_or_default();
        Ok(Image {
            digest,
            rootfs: dir.join("rootfs"),
            entrypoint: cfg.entrypoint.unwrap_or_default(),
            cmd: cfg.cmd.unwrap_or_default(),
            env: cfg.env.unwrap_or_default(),
            working_dir: cfg.working_dir.filter(|d| !d.is_empty()),
            downloaded,
        })
    }
}

/// A name no other pull has, in this process or another: two pulls of one image
/// may run at once, and each needs its own files until the final rename.
// ponytail: a crash leaves its `.partial-*`/`.unpacking-*` behind; sweep them at startup if it shows.
fn scratch_name(what: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{what}-{}-{n}", std::process::id())
}

/// `rootfs/path`, provided that stays inside `rootfs` even through symlinks an
/// earlier layer may have planted.
fn inside(rootfs: &Path, path: &Path) -> Result<PathBuf> {
    let mut clean = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(p) => clean.push(p),
            Component::CurDir => {}
            _ => return err(format!("layer entry `{}` escapes the image", path.display())),
        }
    }
    if clean.as_os_str().is_empty() {
        return Ok(rootfs.into()); // `./`, the root itself
    }
    let target = rootfs.join(&clean);
    if let Some(parent) = target.parent().filter(|p| p.exists()) {
        let real = parent.canonicalize().ctx("unpacking")?;
        if !real.starts_with(rootfs.canonicalize().ctx("unpacking")?) {
            return err(format!(
                "layer entry `{}` escapes the image through a symlink",
                path.display()
            ));
        }
    }
    Ok(target)
}

fn remove(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(_) => Ok(()),
    }
}

/// Apply one layer on top of `rootfs`, as an unprivileged user: ownership is
/// not kept (everything belongs to us, which is root inside the container) and
/// device nodes are skipped (the runtime provides /dev).
pub(crate) fn unpack_layer(blob: &Path, media_type: &str, rootfs: &Path) -> Result<()> {
    let file = File::open(blob).ctx(format!("opening {}", blob.display()))?;
    let reader: Box<dyn Read> = match media_type.rsplit(['+', '.']).next() {
        Some("gzip") => Box::new(flate2::read::GzDecoder::new(std::io::BufReader::new(file))),
        Some("tar") => Box::new(file),
        _ => {
            return err(format!(
                "unsupported layer type `{media_type}` (gzip and plain tar are supported)"
            ));
        }
    };
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    for entry in archive.entries().ctx("reading a layer")? {
        let mut entry = entry.ctx("reading a layer")?;
        let path = entry.path().ctx("reading a layer")?.into_owned();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();

        // Whiteouts: this layer deletes something from the layers below.
        if name == ".wh..wh..opq" {
            // Check the marker's own path, so the directory it sits in is the one verified.
            let marker = inside(rootfs, &path)?;
            for child in fs::read_dir(marker.parent().unwrap_or(rootfs))
                .into_iter()
                .flatten()
                .flatten()
            {
                remove(&child.path()).ctx("applying a whiteout")?;
            }
            continue;
        }
        if let Some(deleted) = name.strip_prefix(".wh.") {
            if deleted.is_empty() {
                return err(format!("layer entry `{}` is a whiteout of nothing", path.display()));
            }
            remove(&inside(rootfs, &path.with_file_name(deleted))?).ctx("applying a whiteout")?;
            continue;
        }

        let kind = entry.header().entry_type();
        if kind.is_character_special() || kind.is_block_special() || kind.is_fifo() {
            continue;
        }
        // A layer may turn a directory into a file or the other way round.
        let target = inside(rootfs, &path)?;
        if target == rootfs && !kind.is_dir() {
            return err("a layer replaces the image root with something that is not a directory");
        }
        if let Ok(existing) = fs::symlink_metadata(&target)
            && existing.is_dir() != kind.is_dir()
        {
            remove(&target).ctx("unpacking")?;
        }
        if !entry.unpack_in(rootfs).ctx(format!("unpacking `{}`", path.display()))? {
            return err(format!("layer entry `{}` escapes the image", path.display()));
        }
        // Keep directories writable for us, or later entries and cleanup would fail.
        if kind.is_dir() {
            let mode = fs::metadata(&target).ctx("unpacking")?.permissions().mode();
            fs::set_permissions(&target, fs::Permissions::from_mode(mode | 0o700)).ctx("unpacking")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tar::{Builder, EntryType, Header};

    enum E<'a> {
        File(&'a str, &'a str),
        Dir(&'a str, u32),
        Link(&'a str, &'a str),
        /// A name written into the header as-is, the way a hostile layer would.
        Raw(&'a str),
    }

    fn layer(dir: &Path, name: &str, entries: &[E]) -> PathBuf {
        let mut tar = Builder::new(Vec::new());
        for entry in entries {
            let mut h = Header::new_gnu();
            match entry {
                E::File(path, body) => {
                    h.set_size(body.len() as u64);
                    h.set_mode(0o644);
                    tar.append_data(&mut h, path, body.as_bytes()).unwrap();
                }
                E::Dir(path, mode) => {
                    h.set_entry_type(EntryType::Directory);
                    h.set_size(0);
                    h.set_mode(*mode);
                    tar.append_data(&mut h, path, &[][..]).unwrap();
                }
                E::Link(path, to) => {
                    h.set_entry_type(EntryType::Symlink);
                    h.set_size(0);
                    tar.append_link(&mut h, path, to).unwrap();
                }
                E::Raw(path) => {
                    h.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
                    h.set_size(1);
                    h.set_mode(0o644);
                    h.set_cksum();
                    tar.append(&h, &b"x"[..]).unwrap();
                }
            }
        }
        let path = dir.join(name);
        fs::write(&path, tar.into_inner().unwrap()).unwrap();
        path
    }

    fn sandbox(name: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("kith-runtime-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("rootfs")).unwrap();
        (dir.clone(), dir.join("rootfs"))
    }

    const TAR: &str = "application/vnd.oci.image.layer.v1.tar";

    #[test]
    fn layers_stack_with_whiteouts() {
        let (dir, rootfs) = sandbox("stack");
        let base = [
            E::Dir("./", 0o755),
            E::Dir("etc", 0o755),
            E::File("etc/keep", "1"),
            E::File("etc/gone", "2"),
            E::Dir("cache", 0o555),
            E::File("cache/a", "a"),
            E::File("cache/b", "b"),
            E::Dir("was-dir", 0o755),
            E::File("was-dir/x", "x"),
            E::File("was-file", "f"),
        ];
        unpack_layer(&layer(&dir, "1.tar", &base), TAR, &rootfs).unwrap();
        // A read-only directory from the image is still writable for us.
        assert_eq!(fs::read_to_string(rootfs.join("cache/a")).unwrap(), "a");

        let top = [
            E::File("etc/.wh.gone", ""),
            E::File("cache/.wh..wh..opq", ""),
            E::File("cache/c", "c"),
            E::File("was-dir", "now a file"),
            E::Dir("was-file", 0o755),
            E::File("was-file/y", "y"),
            E::File("etc/keep", "updated"),
        ];
        unpack_layer(&layer(&dir, "2.tar", &top), TAR, &rootfs).unwrap();
        assert_eq!(fs::read_to_string(rootfs.join("etc/keep")).unwrap(), "updated");
        assert!(!rootfs.join("etc/gone").exists());
        let cache: Vec<_> = fs::read_dir(rootfs.join("cache"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(cache, ["c"], "the opaque whiteout cleared what was below");
        assert_eq!(fs::read_to_string(rootfs.join("was-dir")).unwrap(), "now a file");
        assert_eq!(fs::read_to_string(rootfs.join("was-file/y")).unwrap(), "y");

        // gzip layers, by OCI and by Docker media type; anything else is refused.
        let plain = fs::read(layer(&dir, "3.tar", &[E::File("zipped", "z")])).unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &plain).unwrap();
        fs::write(dir.join("3.tgz"), gz.finish().unwrap()).unwrap();
        unpack_layer(
            &dir.join("3.tgz"),
            "application/vnd.docker.image.rootfs.diff.tar.gzip",
            &rootfs,
        )
        .unwrap();
        assert_eq!(fs::read_to_string(rootfs.join("zipped")).unwrap(), "z");
        let e = unpack_layer(
            &dir.join("3.tgz"),
            "application/vnd.oci.image.layer.v1.tar+zstd",
            &rootfs,
        )
        .unwrap_err();
        assert!(e.to_string().contains("unsupported layer type"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hostile_layers_cannot_leave_the_rootfs() {
        let (dir, rootfs) = sandbox("hostile");
        let outside = dir.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("victim"), "safe").unwrap();

        // `..` in a name.
        let e = unpack_layer(&layer(&dir, "dots.tar", &[E::Raw("../outside/victim")]), TAR, &rootfs).unwrap_err();
        assert!(e.to_string().contains("escapes the image"), "{e}");
        let e = unpack_layer(&layer(&dir, "wh.tar", &[E::Raw("../outside/.wh.victim")]), TAR, &rootfs).unwrap_err();
        assert!(e.to_string().contains("escapes the image"), "{e}");

        // A symlink planted by one layer, then used by the next to write, delete or clear outside.
        let out = outside.to_str().unwrap();
        unpack_layer(&layer(&dir, "link.tar", &[E::Link("evil", out)]), TAR, &rootfs).unwrap();
        for attack in [
            E::Raw("evil/victim"),
            E::Raw("evil/.wh.victim"),
            E::Raw("evil/.wh..wh..opq"),
        ] {
            let result = unpack_layer(&layer(&dir, "attack.tar", &[attack]), TAR, &rootfs);
            assert!(
                result.is_err(),
                "an entry under a symlink that leaves the image was accepted"
            );
            assert_eq!(fs::read_to_string(outside.join("victim")).unwrap(), "safe");
        }

        // Entries that would delete or replace the rootfs itself, lower layers included.
        for attack in [E::Raw(".wh."), E::Raw("./")] {
            assert!(unpack_layer(&layer(&dir, "root.tar", &[attack]), TAR, &rootfs).is_err());
            assert!(rootfs.join("evil").is_symlink(), "the lower layer is still there");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn digests_are_checked_before_becoming_file_names() {
        let good = format!("sha256:{}", "a1".repeat(32));
        assert_eq!(sha256_hex(&good).unwrap().len(), 64);
        for bad in [
            "sha256:../../etc/passwd",
            "sha256:abc",
            "sha512:00",
            &good.to_uppercase(),
            "",
        ] {
            assert!(sha256_hex(bad).is_err(), "{bad}");
        }
    }
}
