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
    /// Answered from the store alone: the registry was not asked anything.
    pub from_cache: bool,
}

/// When to ask the registry what a reference points at.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum PullPolicy {
    /// Only if this reference was never pulled here. A tag that moved at the
    /// registry is not noticed; use `Always`, or a digest, where that matters.
    #[default]
    IfNotPresent,
    Always,
    /// Use what is here or fail: no network at all.
    Never,
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
        fs::create_dir_all(root.join("refs")).ctx(format!("creating {}", root.display()))?;
        // What a crashed pull left half-done. One owner per store (kithd holds the
        // state lock), so nothing here is still being written.
        for (dir, marker) in [
            ("blobs/sha256", ".partial-"),
            ("images", ".unpacking-"),
            ("refs", ".ref-"),
        ] {
            for entry in fs::read_dir(root.join(dir)).into_iter().flatten().flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                // Blob and image names are hex; a ref name never starts with a dot.
                if name.contains(marker) && (dir != "refs" || name.starts_with(marker)) {
                    let _ = remove(&entry.path());
                }
            }
        }
        // Images keep their setuid bits; nobody else on this machine gets to run them.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).ctx(format!("securing {}", root.display()))?;
        Ok(ImageStore { root })
    }

    /// Where the store remembers what `reference` resolved to.
    fn ref_file(&self, reference: &Reference) -> Result<PathBuf> {
        // The whole reference as one file name: `/` and anything unusual become `%xx`.
        let plain = |b: u8| b.is_ascii_alphanumeric() || b"-._:@".contains(&b);
        let escape = |b: u8| {
            if plain(b) {
                (b as char).to_string()
            } else {
                format!("%{b:02x}")
            }
        };
        let name: String = reference.whole().bytes().map(escape).collect();
        if name.len() > 250 || name.starts_with('.') {
            return err(format!("image reference `{reference}` is too long"));
        }
        Ok(self.root.join("refs").join(name))
    }

    /// The image `reference` resolved to last time, if it is still unpacked here.
    fn cached(&self, reference: &Reference) -> Option<Image> {
        let saved = fs::read(self.ref_file(reference).ok()?).ok()?;
        let saved: serde_json::Value = serde_json::from_slice(&saved).ok()?;
        let strings = |key: &str| -> Option<Vec<String>> { serde_json::from_value(saved[key].clone()).ok() };
        let digest = saved["digest"].as_str()?;
        let dir = self.root.join("images").join(sha256_hex(digest).ok()?);
        dir.join("config.json").exists().then_some(())?;
        Some(Image {
            digest: digest.into(),
            rootfs: dir.join("rootfs"),
            entrypoint: strings("entrypoint")?,
            cmd: strings("cmd")?,
            env: strings("env")?,
            working_dir: saved["workingDir"].as_str().map(String::from),
            downloaded: 0,
            from_cache: true,
        })
    }

    /// Pull `reference` (e.g. `docker.io/library/busybox:1.36`) for this machine's
    /// platform. Under the default policy a reference pulled before is answered
    /// from the store with no network; otherwise the registry says which manifest
    /// it points at, and layers and unpacked images already stored are reused.
    // ponytail: anonymous pulls only; registry credentials arrive with Secrets in the controller.
    pub async fn pull(&self, reference: &str, policy: PullPolicy) -> Result<Image> {
        let reference: Reference = reference.parse().ctx(format!("image reference `{reference}`"))?;
        if policy != PullPolicy::Always
            && let Some(image) = self.cached(&reference)
        {
            return Ok(image);
        }
        if policy == PullPolicy::Never {
            return err(format!(
                "image `{reference}` is not here and its pull policy is `never`"
            ));
        }
        let client = Client::new(ClientConfig {
            protocol: protocol(reference.registry()),
            ..ClientConfig::default()
        });
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
            let unpacked = tokio::task::spawn_blocking(move || unpack_image(&layers, &staging, &target, Budget::IMAGE));
            unpacked.await.ctx("unpacking")??;
        }

        let cfg = config.config.unwrap_or_default();
        let image = Image {
            digest,
            rootfs: dir.join("rootfs"),
            entrypoint: cfg.entrypoint.unwrap_or_default(),
            cmd: cfg.cmd.unwrap_or_default(),
            env: cfg.env.unwrap_or_default(),
            working_dir: cfg.working_dir.filter(|d| !d.is_empty()),
            downloaded,
            from_cache: false,
        };
        // Remember the answer. Written whole, then renamed: a reader sees the old one or the new one.
        let saved = serde_json::json!({
            "digest": image.digest, "entrypoint": image.entrypoint, "cmd": image.cmd,
            "env": image.env, "workingDir": image.working_dir,
        });
        // Best effort: the image is here either way, and without the note the next pull just asks again.
        if let Ok(file) = self.ref_file(&reference) {
            let scratch = file.with_file_name(format!(".{}", scratch_name("ref")));
            if fs::write(&scratch, saved.to_string())
                .and_then(|()| fs::rename(&scratch, &file))
                .is_err()
            {
                let _ = fs::remove_file(&scratch);
            }
        }
        Ok(image)
    }
}

/// How `registry` (`host[:port]`) is asked: with TLS, but for one on this very machine (as
/// container tools do), which is where a node serves the cluster's own Images.
fn protocol(registry: &str) -> oci_client::client::ClientProtocol {
    let host = match registry.strip_prefix('[').and_then(|rest| rest.split_once(']')) {
        Some((v6, _)) => v6,
        None => registry.rsplit_once(':').map_or(registry, |(host, _)| host),
    };
    match ["localhost", "127.0.0.1", "::1"].contains(&host) {
        true => oci_client::client::ClientProtocol::Http,
        false => oci_client::client::ClientProtocol::Https,
    }
}

/// A name no other pull has, in this process or another: two pulls of one image
/// may run at once, and each needs its own files until the final rename.
fn scratch_name(what: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{what}-{}-{n}", std::process::id())
}

/// Where `path` from a layer lands under `rootfs`. Symlinks on the way are
/// followed the way the container will see them, with `rootfs` as `/`: an
/// absolute link (`/var/run -> /run`) or a run of `..` stays inside. The last
/// component is not followed: it is the thing being created or removed.
fn inside(rootfs: &Path, path: &Path) -> Result<PathBuf> {
    let mut todo = std::collections::VecDeque::new();
    for part in path.components() {
        match part {
            Component::Normal(p) => todo.push_back(Component::Normal(p).as_os_str().to_owned()),
            Component::CurDir => {}
            _ => return err(format!("layer entry `{}` escapes the image", path.display())),
        }
    }
    let Some(name) = todo.pop_back() else {
        return Ok(rootfs.into()); // `./`, the root itself
    };
    let mut real = PathBuf::new(); // relative to rootfs
    let mut hops = 0;
    while let Some(part) = todo.pop_front() {
        if part == ".." {
            real.pop(); // at the root this stays at the root, as in a chroot
            continue;
        }
        let Ok(link) = fs::read_link(rootfs.join(&real).join(&part)) else {
            real.push(part);
            continue;
        };
        hops += 1;
        if hops > 40 {
            return err(format!(
                "layer entry `{}` goes through a loop of symlinks",
                path.display()
            ));
        }
        if link.is_absolute() {
            real = PathBuf::new();
        }
        for piece in link.components().rev() {
            match piece {
                Component::Normal(p) => todo.push_front(p.to_owned()),
                Component::ParentDir => todo.push_front("..".into()),
                _ => {}
            }
        }
    }
    Ok(rootfs.join(real).join(name))
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
/// What one image may unpack to, all layers together. Far above any real
/// image; one built to fill the disk or the memory (a few megabytes of gzip can
/// hold terabytes) stops here.
#[derive(Clone, Copy)]
struct Budget {
    bytes: u64,
    entries: usize,
}

impl Budget {
    const IMAGE: Budget = Budget {
        bytes: 32 << 30,
        entries: 4_000_000,
    };
}

/// Lets `left` bytes through and then fails, so nothing downstream (tar reads long
/// names and pax headers whole, into memory) ever sees more than the budget.
struct Metered<'a, R> {
    inner: R,
    left: &'a mut u64,
}

impl<R: Read> Read for Metered<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if *self.left == 0 {
            return Err(std::io::Error::other("the image is larger than kith unpacks"));
        }
        let most = buf.len().min(usize::try_from(*self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..most])?;
        *self.left -= n as u64;
        Ok(n)
    }
}

/// tar wraps the real reason (disk full, over the budget) in its own error; say both.
fn because(what: &str, e: std::io::Error) -> crate::Error {
    let mut text = format!("{what}: {e}");
    let mut cause = std::error::Error::source(&e);
    while let Some(inner) = cause {
        text.push_str(&format!(": {inner}"));
        cause = inner.source();
    }
    crate::Error(text)
}

/// Unpack `layers` in order into `staging`, then publish it as `target`.
/// However it fails, `staging` does not stay behind.
fn unpack_image(layers: &[(PathBuf, String)], staging: &Path, target: &Path, mut budget: Budget) -> Result<()> {
    let _ = fs::remove_dir_all(staging);
    let unpacked = (|| {
        fs::create_dir_all(staging.join("rootfs")).ctx("unpacking")?;
        for (blob, media_type) in layers {
            unpack_layer_capped(blob, media_type, &staging.join("rootfs"), &mut budget)?;
        }
        // The marker that the image is complete, so it is written last.
        fs::write(staging.join("config.json"), "{}").ctx("unpacking")?;
        match fs::rename(staging, target) {
            // Another pull of the same image finished first; theirs is as good as ours.
            Err(_) if target.join("config.json").exists() => Ok(()),
            other => other.ctx("unpacking"),
        }
    })();
    let _ = fs::remove_dir_all(staging); // already renamed away when all went well
    unpacked
}

#[cfg(test)]
fn unpack_layer(blob: &Path, media_type: &str, rootfs: &Path) -> Result<()> {
    unpack_layer_capped(blob, media_type, rootfs, &mut Budget::IMAGE.clone())
}

fn unpack_layer_capped(blob: &Path, media_type: &str, rootfs: &Path, budget: &mut Budget) -> Result<()> {
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
    let metered = Metered {
        inner: reader,
        left: &mut budget.bytes,
    };
    let mut archive = tar::Archive::new(metered);
    archive.set_preserve_permissions(true);
    for entry in archive.entries().ctx("reading a layer")? {
        let mut entry = entry.map_err(|e| because("reading a layer", e))?;
        if budget.entries == 0 {
            return err("the image has more files than kith unpacks");
        }
        budget.entries -= 1;
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
            if deleted.is_empty() || deleted == "." || deleted == ".." {
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
        let what = format!("unpacking `{}`", path.display());
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).ctx(&what)?;
        }
        if kind.is_hard_link() {
            // The link's source is a path in the image too, and gets the same treatment.
            let source = entry
                .link_name()
                .ctx(&what)?
                .ok_or_else(|| crate::Error(format!("{what}: a link to nothing")))?;
            remove(&target).ctx(&what)?;
            fs::hard_link(inside(rootfs, &source)?, &target).ctx(&what)?;
            continue;
        }
        // `target` is ours down to its last component, which `unpack` replaces rather than follows.
        entry.unpack(&target).map_err(|e| because(&what, e))?;
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
    fn remembered_references() {
        let (dir, _) = sandbox("refs");
        let store = ImageStore::new(dir.join("store")).unwrap();
        let reference: Reference = "busybox".parse().unwrap();
        let file = store.ref_file(&reference).unwrap();
        // One file per reference, inside refs/, whatever the reference looks like.
        assert_eq!(file, dir.join("store/refs/docker.io%2flibrary%2fbusybox:latest"));
        assert_eq!(
            file,
            store
                .ref_file(&"docker.io/library/busybox:latest".parse().unwrap())
                .unwrap()
        );
        let long: Reference = format!("example.com/{}:1", "a/".repeat(100) + "b").parse().unwrap();
        assert!(store.ref_file(&long).is_err());

        // Nothing remembered, a damaged note, or a note about an image that is gone: ask the registry.
        assert!(store.cached(&reference).is_none());
        fs::write(&file, "{ not json").unwrap();
        assert!(store.cached(&reference).is_none());
        let digest = format!("sha256:{}", "a".repeat(64));
        let note = serde_json::json!({ "digest": digest, "entrypoint": ["sh"], "cmd": [], "env": ["A=1"], "workingDir": null });
        fs::write(&file, note.to_string()).unwrap();
        assert!(store.cached(&reference).is_none());
        fs::write(&file, note.to_string().replace("sha256:", "sha256:../")).unwrap();
        assert!(store.cached(&reference).is_none());

        // The image is unpacked: the note is enough.
        fs::write(&file, note.to_string()).unwrap();
        let image_dir = dir.join("store/images").join("a".repeat(64));
        fs::create_dir_all(&image_dir).unwrap();
        fs::write(image_dir.join("config.json"), "{}").unwrap();
        let image = store.cached(&reference).unwrap();
        assert!(image.from_cache);
        assert_eq!(
            (image.entrypoint, image.env, image.rootfs),
            (
                vec!["sh".to_string()],
                vec!["A=1".to_string()],
                image_dir.join("rootfs")
            )
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn absolute_links_and_caps() {
        let (dir, rootfs) = sandbox("links");
        // Debian-style: /var/run is an absolute link, and a later layer writes through it.
        let base = [
            E::Dir("run", 0o755),
            E::Dir("var", 0o755),
            E::Link("var/run", "/run"),
            E::File("bin-sh", "sh"),
        ];
        unpack_layer(&layer(&dir, "1.tar", &base), TAR, &rootfs).unwrap();
        unpack_layer(&layer(&dir, "2.tar", &[E::File("var/run/pid", "1")]), TAR, &rootfs).unwrap();
        assert_eq!(fs::read_to_string(rootfs.join("run/pid")).unwrap(), "1");
        assert!(rootfs.join("var/run").is_symlink());

        // A loop of links is an error, not a hang.
        let looped = [E::Link("a", "b"), E::Link("b", "a"), E::File("a/x", "")];
        assert!(unpack_layer(&layer(&dir, "loop.tar", &looped), TAR, &rootfs).is_err());

        // The budget, in bytes and in entries, is for the whole image: at it is fine,
        // over it is refused, and a refused image leaves nothing behind.
        let big = layer(
            &dir,
            "big.tar",
            &[E::File("one", "12345678"), E::File("two", "12345678")],
        );
        let size = fs::metadata(&big).unwrap().len();
        let layers = [(big.clone(), TAR.to_string()), (big, TAR.to_string())];
        let (staging, target) = (dir.join("staging"), dir.join("image"));
        let refused = [
            (size + 1024, 4, "larger than kith unpacks"),
            (2 * size, 3, "more files than kith unpacks"),
        ];
        for (bytes, entries, message) in refused {
            let e = unpack_image(&layers, &staging, &target, Budget { bytes, entries }).unwrap_err();
            assert!(e.to_string().contains(message), "{e}");
            assert!(!staging.exists() && !target.exists());
        }
        let enough = Budget {
            bytes: 2 * size,
            entries: 4,
        };
        unpack_image(&layers, &staging, &target, enough).unwrap();
        assert!(!staging.exists() && target.join("config.json").exists() && target.join("rootfs/two").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

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

    /// Only a registry on this machine is asked without TLS.
    #[test]
    fn image_pulls_use_plain_http_for_this_machine_only() {
        use oci_client::client::ClientProtocol::{Http, Https};
        for local in ["localhost:5000", "127.0.0.1:5000", "localhost", "[::1]:5000", "[::1]"] {
            assert!(matches!(protocol(local), Http), "{local}");
        }
        for far in [
            "registry.example:5000",
            "docker.io",
            "localhost.example.org",
            "127.0.0.1.example:80",
            "10.0.0.1:5000",
        ] {
            assert!(matches!(protocol(far), Https), "{far}");
        }
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

        // A symlink planted by one layer, then used by the next to write, delete or clear
        // outside. The link is followed as the container would follow it, with the
        // rootfs as `/`, so all of it happens inside and the real target is untouched.
        let out = outside.to_str().unwrap();
        unpack_layer(
            &layer(&dir, "link.tar", &[E::Link("evil", out), E::Link("up", "../../../..")]),
            TAR,
            &rootfs,
        )
        .unwrap();
        for attack in [
            E::Raw("evil/victim"),
            E::Raw("evil/.wh.victim"),
            E::Raw("evil/.wh..wh..opq"),
            E::Raw("up/planted"),
            E::Raw("evil"), // replaces the link itself; never writes through it
        ] {
            unpack_layer(&layer(&dir, "attack.tar", &[attack]), TAR, &rootfs).unwrap();
            assert_eq!(fs::read_to_string(outside.join("victim")).unwrap(), "safe");
            let around: Vec<_> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
            assert!(!around.iter().any(|n| n == "planted"), "{around:?}");
        }
        assert_eq!(
            fs::read_to_string(rootfs.join("planted")).unwrap(),
            "x",
            "`..` stops at the root"
        );
        assert!(rootfs.join("evil").is_file());
        fs::write(rootfs.join("evil"), "").unwrap();
        fs::remove_file(rootfs.join("evil")).unwrap();
        std::os::unix::fs::symlink(out, rootfs.join("evil")).unwrap();

        // Entries that would delete or replace the rootfs itself, lower layers included.
        for attack in [E::Raw(".wh."), E::Raw(".wh.."), E::Raw("./")] {
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
