//! Pulling images and unpacking them.
//!
//! ```text
//! <root>/blobs/sha256/<hex>          layers, exactly as the registry serves them
//! <root>/images/<manifest hex>/      one unpacked image
//!     rootfs/                        shared read-only by its containers
//!     config.json                    written last: its presence means "complete"
//! <root>/shared/<hex>-<mode>-<uid>-<gid>-<mtime>
//!                                    a file equal in all of these in several images: one
//!                                    inode, which each of them and this name link to
//! ```

use crate::{Context, Result, err};
use oci_client::client::ClientConfig;
use oci_client::config::ConfigFile;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub struct ImageStore {
    root: PathBuf,
    /// This node's own registry, where it serves one.
    pub local: Option<Local>,
    /// How long the own registry may take to accept a connection, and to answer one read
    /// ([`OWN_CONNECT`], [`OWN_READ`]). Tests shorten them.
    pub own_timeouts: (Duration, Duration),
}

/// Waiting for the node's own registry to accept a connection. It is on this machine: a
/// connection that takes longer than this is a registry that is not there.
const OWN_CONNECT: Duration = Duration::from_secs(10);
/// Waiting for the node's own registry to answer a read. A start awaits its pull inside the
/// controller's pass, so a registry that accepts and then stalls would hold every unit's start
/// with it; past this, the start fails with its reason instead.
const OWN_READ: Duration = Duration::from_secs(30);

/// This node's own registry of the cluster's Images, as its kithd made it at this start.
/// It is asked over TLS, trusting the one certificate it was started with and no other,
/// with a password nothing else on the node is told.
#[derive(Clone)]
pub struct Local {
    pub port: u16,
    pub password: String,
    /// The registry's certificate (DER), made when it is first asked for (a node that
    /// serves no Image makes no key), or why there is none.
    pub certificate: Arc<dyn Fn() -> std::result::Result<Vec<u8>, String> + Send + Sync>,
}

/// The registry and the repository `reference` names, as a pull reads it (`nginx` is
/// `docker.io/library/nginx`), with no tag or digest: what a rule for a prefix of images is
/// matched against. The registry is in lower case, without the port a pull would use anyway
/// (`ghcr.io:443` is `ghcr.io`), and Docker Hub by its one name. Another name that only
/// happens to reach the same machine (an address, an alias in DNS) stays another registry.
/// None for what is no reference.
pub fn repository(reference: &str) -> Option<String> {
    let reference: Reference = reference.parse().ok()?;
    Some(format!("{}/{}", registry(reference.registry()), reference.repository()))
}

/// A registry's one name, of the ones it is written by (see [`repository`]).
pub fn registry(registry: &str) -> String {
    let registry = registry.to_ascii_lowercase();
    let usual = match protocol(&registry) {
        oci_client::client::ClientProtocol::Http => ":80",
        _ => ":443",
    };
    match registry.strip_suffix(usual).unwrap_or(&registry) {
        "index.docker.io" | "registry-1.docker.io" => "docker.io".to_string(),
        registry => registry.to_string(),
    }
}

impl Local {
    /// Whether `registry` (the `host:port` of a reference) is that registry: one of its
    /// two names at its very port, said just so. Nothing else is sent the password.
    pub fn is(&self, registry: &str) -> bool {
        ["localhost", "127.0.0.1"]
            .iter()
            .any(|host| registry == format!("{host}:{}", self.port))
    }

    /// The namespace of the cluster Image `reference` names, if it names one of this
    /// registry's (`localhost:PORT/NAMESPACE/NAME`).
    pub fn namespace(&self, reference: &str) -> Option<String> {
        let reference: Reference = reference.parse().ok()?;
        let (namespace, _) = reference.repository().split_once('/')?;
        self.is(reference.registry()).then(|| namespace.to_string())
    }
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
    /// The user its programs are meant to run as, as the image says it: a number or a
    /// name of its `/etc/passwd`, with `:group` or without.
    pub user: Option<String>,
    /// The keys this node has found a signature of this image by (see [`ImageStore::pull_signed`]).
    pub signed_by: Vec<String>,
    /// Layers this pull had to download; 0 when everything was already stored.
    pub downloaded: usize,
    /// Answered from the store alone: the registry was not asked anything.
    pub from_cache: bool,
}

/// When to ask the registry what a reference points at. A reference of this node's own
/// registry is always asked, whatever the policy.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum PullPolicy {
    /// Only if this reference was never pulled here. A tag that moved at the
    /// registry is not noticed; use `Always`, or a digest, where that matters.
    #[default]
    IfNotPresent,
    Always,
    /// Use what is here or fail: no network at all (but for this node's own registry,
    /// which is asked).
    Never,
}

/// The hex part of a `sha256:<64 hex>` digest. Digests come from the registry
/// and become file names, so anything else is refused.
pub(crate) fn sha256_hex(digest: &str) -> Result<&str> {
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
            (SHARED, ".shared-"),
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
        Ok(ImageStore {
            root,
            local: None,
            own_timeouts: (OWN_CONNECT, OWN_READ),
        })
    }

    /// Removes the shared files no image links any more, and says how many. Waits for an
    /// unpack that is sharing. (For the removal of unused images, T-0414.)
    pub fn sweep_shared(&self) -> Result<usize> {
        sweep(&self.root.join(SHARED)).ctx("sweeping the shared files")
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
            // (A note with no `user` at all is from before this was kept: not an image
            // that names none. It is asked for again, and its layers are here already.)
            user: saved.get("user")?.as_str().map(String::from),
            signed_by: strings("signedBy").unwrap_or_default(),
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
        self.pull_signed(reference, policy, &[]).await
    }

    /// [`pull`](Self::pull), for an image that must be signed by one of the keys `signed_by`
    /// where any is named (see [`crate::signed`]). The signature is of the manifest's
    /// digest, found before a layer is fetched, and every layer is fetched by the digest
    /// that manifest gives it: what is unpacked is what was signed, whatever the tag is
    /// made to name meanwhile. An image that is here counts as signed only by the keys a
    /// signature of it was found by, here, before.
    pub async fn pull_signed(&self, reference: &str, policy: PullPolicy, signed_by: &[String]) -> Result<Image> {
        let reference: Reference = reference.parse().ctx(format!("image reference `{reference}`"))?;
        let keys: Vec<crate::signed::Key> = signed_by
            .iter()
            .map(|key| crate::signed::key(key))
            .collect::<Result<_>>()?;
        // The node's own registry is always asked, whatever the policy: an Image of it that is
        // here may have been deleted with its namespace, or made again under the same name, since.
        let own = self.local.as_ref().filter(|local| local.is(reference.registry()));
        let here = self.cached(&reference);
        let signed = |image: &Image| keys.is_empty() || keys.iter().any(|key| image.signed_by.contains(&key.id));
        if own.is_none()
            && policy != PullPolicy::Always
            && let Some(image) = here.clone().filter(signed)
        {
            return Ok(image);
        }
        if own.is_none() && policy == PullPolicy::Never {
            return err(match here {
                None => format!("image `{reference}` is not here and its pull policy is `never`"),
                Some(_) => format!(
                    "image `{reference}` is here, but has not been checked for a signature by a key its template or the Cluster's rule for it names, and its pull policy is `never`"
                ),
            });
        }
        // The node's own registry is shown its password only once it has shown the
        // certificate it was started with: whatever else listens on that port is not it.
        let (config, auth) = match own {
            Some(local) => (
                ClientConfig {
                    protocol: oci_client::client::ClientProtocol::Https,
                    tls_certs_only: vec![oci_client::client::Certificate {
                        encoding: oci_client::client::CertificateEncoding::Der,
                        data: (local.certificate)().ctx("the node's registry")?,
                    }],
                    connect_timeout: Some(self.own_timeouts.0),
                    read_timeout: Some(self.own_timeouts.1),
                    ..ClientConfig::default()
                },
                RegistryAuth::Basic("kithd".into(), local.password.clone()),
            ),
            None => (
                ClientConfig {
                    protocol: protocol(reference.registry()),
                    ..ClientConfig::default()
                },
                RegistryAuth::Anonymous,
            ),
        };
        // (Not `Client::new`: it falls back to a client with every usual root when it is
        // given a certificate it cannot read.)
        let client = Client::try_from(config).ctx("setting up the registry client")?;
        let (manifest, digest, config, list) = client
            .pull_manifest_and_config_and_list_digest(&reference, &auth)
            .await
            .ctx(format!("pulling {reference}"))?;
        // Whose it is, before anything of it but its manifest and its config is here. (A
        // signature of an image for several machines is of the list this one was in.)
        let mut signed_by = here
            .filter(|image| image.digest == digest)
            .map(|image| image.signed_by)
            .unwrap_or_default();
        if !keys.is_empty() {
            let digests: Vec<&str> = list.iter().map(String::as_str).chain([digest.as_str()]).collect();
            let by = crate::signed::signer(&client, &reference, &digests, &keys).await?;
            signed_by.retain(|key| *key != by);
            signed_by.push(by);
        }
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
            let index = self.root.join(SHARED);
            let unpacked = tokio::task::spawn_blocking(move || {
                unpack_image(&layers, &staging, &target, Some(&index), Budget::IMAGE)
            });
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
            user: cfg.user.filter(|user| !user.is_empty()),
            signed_by,
            downloaded,
            from_cache: false,
        };
        // Remember the answer. Written whole, then renamed: a reader sees the old one or the new one.
        let saved = serde_json::json!({
            "digest": image.digest, "entrypoint": image.entrypoint, "cmd": image.cmd,
            "env": image.env, "workingDir": image.working_dir, "user": image.user, "signedBy": image.signed_by,
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
/// However it fails, `staging` does not stay behind. With an `index`, the finished tree's
/// files that other images hold too become one with theirs before it is published.
fn unpack_image(
    layers: &[(PathBuf, String)],
    staging: &Path,
    target: &Path,
    index: Option<&Path>,
    mut budget: Budget,
) -> Result<()> {
    let _ = fs::remove_dir_all(staging);
    let unpacked = (|| {
        fs::create_dir_all(staging.join("rootfs")).ctx("unpacking")?;
        for (blob, media_type) in layers {
            unpack_layer_capped(blob, media_type, &staging.join("rootfs"), &mut budget)?;
        }
        // Once, over the whole tree: a file a later layer replaces was never worth sharing.
        if let Some(index) = index {
            share(&staging.join("rootfs"), index, |from, to| fs::hard_link(from, to));
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

/// The store's index of shared files (see the module's head).
const SHARED: &str = "shared";

/// What, beside their bytes, two files must have alike to be one: the whole mode (setuid,
/// setgid and sticky with it), owner, group, last change to the second's billionth, length.
type Same = (u32, u32, u32, i64, i64, u64);

fn same(meta: &fs::Metadata) -> Same {
    let mode = meta.mode() & 0o7777;
    (
        mode,
        meta.uid(),
        meta.gid(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.len(),
    )
}

/// A file's name in the index: its SHA-256 and all of [`Same`] but the length, which the
/// hash holds.
fn shared_name(hex: &str, (mode, uid, gid, secs, nanos, _): Same) -> String {
    format!("{hex}-{mode:o}-{uid}-{gid}-{secs}.{nanos:09}")
}

/// The index's lock, held by an unpack while it shares and by the sweep: no entry is
/// swept between an unpack finding it and linking to it.
fn lock(index: &Path) -> std::io::Result<File> {
    fs::create_dir_all(index)?;
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(index.join(".lock"))?;
    file.lock()?;
    Ok(file)
}

/// How a hard link is made: `fs::hard_link`, but for tests of a link that fails.
type Link = fn(&Path, &Path) -> std::io::Result<()>;

/// Makes each regular file of the finished tree `rootfs` one inode with the equal file of
/// other images, through `index`. Best effort: a file that cannot be (a link fails, there
/// are too many, the index is elsewhere) stays as it was. Nothing is written into a file:
/// a shared one is replaced whole, by a rename. A hard link shares the inode, so what
/// changes one image's copy on disk changes every image's; nothing does (containers see an
/// image read-only, or through an overlay), and the store is root's alone.
fn share(rootfs: &Path, index: &Path, link: Link) {
    let Ok(_held) = lock(index) else { return };
    let mut buf = vec![0; 64 << 10];
    let mut todo = vec![rootfs.to_path_buf()];
    while let Some(dir) = todo.pop() {
        // Read whole before any rename in it, so a name is seen once.
        let entries: Vec<_> = fs::read_dir(&dir).into_iter().flatten().flatten().collect();
        for entry in entries {
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => todo.push(entry.path()),
                Ok(kind) if kind.is_file() => share_one(&entry.path(), index, link, &mut buf),
                _ => {}
            }
        }
    }
}

fn share_one(path: &Path, index: &Path, link: Link, buf: &mut [u8]) {
    let Ok((ours, hex)) = fingerprint(path, buf) else {
        return;
    };
    let entry = index.join(shared_name(&hex, same(&ours)));
    match link(path, &entry) {
        Ok(()) => return, // the first of its kind
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return,
    }
    let Ok(held) = fs::symlink_metadata(&entry) else { return };
    if (held.dev(), held.ino()) == (ours.dev(), ours.ino()) {
        return; // one already
    }
    // Checked, not trusted. An entry is only ever made by linking a finished file, so one
    // whose length, mode, owner or time are not what its name says (cut short, written
    // since) is not used. Its bytes are not read again: that cost a tenth of the unpack.
    let plain = || {
        matches!(
            rustix::fs::llistxattr_query(&entry),
            Ok(0) | Err(rustix::io::Errno::OPNOTSUPP)
        )
    };
    let scratch = |dir: &Path| dir.join(format!(".{}", scratch_name("shared")));
    let (from, scratch, to): (&Path, _, &Path) = match held.is_file() && same(&held) == same(&ours) && plain() {
        true => (&entry, scratch(path.parent().unwrap_or(path)), path),
        // Ours takes its place, for the images that come after.
        false => (path, scratch(index), &*entry),
    };
    if link(from, &scratch).is_ok() && fs::rename(&scratch, to).is_err() {
        let _ = fs::remove_file(&scratch);
    }
}

/// A regular file's metadata and the SHA-256 of its bytes. An error for anything else, and
/// for a file with an extended attribute (a file capability, a label): never shared.
fn fingerprint(path: &Path, buf: &mut [u8]) -> std::io::Result<(fs::Metadata, String)> {
    let flags = nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK;
    let mut file = File::options().read(true).custom_flags(flags).open(path)?;
    let meta = file.metadata()?;
    match rustix::fs::flistxattr_query(&file) {
        Ok(0) | Err(rustix::io::Errno::OPNOTSUPP) if meta.is_file() => {}
        _ => return Err(std::io::Error::other("not a plain file")),
    }
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    loop {
        match file.read(buf)? {
            0 => break,
            n => hash.update(&buf[..n]),
        }
    }
    let mut hex = String::with_capacity(64);
    for b in hash.finish().as_ref() {
        hex.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(b & 15), 16).unwrap_or('0'));
    }
    Ok((meta, hex))
}

/// Removes the index's entries no image links any more; how many.
fn sweep(index: &Path) -> std::io::Result<usize> {
    let _held = lock(index)?;
    let mut swept = 0;
    for entry in fs::read_dir(index)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with('.') && entry.metadata()?.nlink() == 1 {
            fs::remove_file(entry.path())?;
            swept += 1;
        }
    }
    Ok(swept)
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
    // Where kithd is root every file is its image's user's, as the image says: a container
    // that may write its root, as that user, writes where the image means it to.
    archive.set_preserve_ownerships(nix::unistd::getuid().is_root());
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
    use std::io::Write;
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
    fn a_note_that_does_not_say_the_images_user_is_asked_again() {
        let (dir, _) = sandbox("old-note");
        let store = ImageStore::new(dir.join("store")).unwrap();
        let reference: Reference = "busybox".parse().unwrap();
        let hex = "a".repeat(64);
        fs::create_dir_all(dir.join("store/images").join(&hex)).unwrap();
        fs::write(dir.join("store/images").join(&hex).join("config.json"), "{}").unwrap();
        let noted = |user: &str| {
            let text = format!(r#"{{"digest":"sha256:{hex}","entrypoint":[],"cmd":[],"env":[]{user}}}"#);
            fs::write(store.ref_file(&reference).unwrap(), text).unwrap();
            store.cached(&reference).map(|image| image.user)
        };
        assert_eq!(noted(r#","user":"app""#), Some(Some("app".to_string())));
        assert_eq!(noted(r#","user":null"#), Some(None));
        // Written by a kithd from before a container ran as its image's user: taking it
        // for an image that names none would run it as nobody.
        assert_eq!(noted(""), None);
    }

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
        let note = serde_json::json!({ "digest": digest, "entrypoint": ["sh"], "cmd": [], "env": ["A=1"], "workingDir": null, "user": null });
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
            let e = unpack_image(&layers, &staging, &target, None, Budget { bytes, entries }).unwrap_err();
            assert!(e.to_string().contains(message), "{e}");
            assert!(!staging.exists() && !target.exists());
        }
        let enough = Budget {
            bytes: 2 * size,
            entries: 4,
        };
        unpack_image(&layers, &staging, &target, None, enough).unwrap();
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

    /// The node's own registry is two names at one port and nothing that looks like them:
    /// the password goes nowhere else, and an Image's namespace is read from no other.
    #[test]
    fn the_nodes_own_registry_is_its_two_names_at_its_port_and_nothing_else() {
        let local = Local {
            port: 5000,
            password: "p".into(),
            certificate: Arc::new(|| Ok(Vec::new())),
        };
        for own in ["localhost:5000", "127.0.0.1:5000"] {
            assert!(local.is(own), "{own}");
            let of = local.namespace(&format!("{own}/team/hello:1"));
            assert_eq!(of.as_deref(), Some("team"), "{own}");
        }
        for other in [
            "localhost",
            "localhost:5001",
            "localhost:50000",
            "127.0.0.1",
            "127.0.0.2:5000",
            "[::1]:5000",
            "localhost.example.org:5000",
            "localhost:5000.example.org",
            "example.org",
            "LOCALHOST:5000",
            "0.0.0.0:5000",
        ] {
            assert!(!local.is(other), "{other}");
            assert_eq!(local.namespace(&format!("{other}/team/hello:1")), None, "{other}");
        }
        // (Not an Image's name: the registry has nothing there, and the pull says so.)
        assert_eq!(local.namespace("localhost:5000/hello:1"), None);
        assert_eq!(local.namespace("docker.io/team/hello:1"), None);
    }

    /// Whatever listens on the node's registry port without its certificate is shown a
    /// TLS handshake and no password; and a registry that is not the node's own is asked
    /// as before, with none.
    #[tokio::test]
    async fn the_registry_password_is_shown_to_the_nodes_own_registry_only() {
        use std::io::Write;
        let (dir, _) = sandbox("local-password");
        let heard = |listener: std::net::TcpListener| {
            let heard = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let into = heard.clone();
            std::thread::spawn(move || {
                for mut stream in listener.incoming().flatten() {
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(300)));
                    let mut said = vec![0; 4096];
                    let n = stream.read(&mut said).unwrap_or(0);
                    into.lock().unwrap().extend_from_slice(&said[..n]);
                    let _ = stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"x\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                }
            });
            heard
        };
        let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (port, far) = (
            squatter.local_addr().unwrap().port(),
            other.local_addr().unwrap().port(),
        );
        let (squatted, asked) = (heard(squatter), heard(other));
        let mut store = ImageStore::new(dir.join("store")).unwrap();
        // (Somebody's certificate for `localhost`, made for this test and its key thrown
        // away: what the node's registry would have shown, and the squatter cannot.)
        let certificate = "MIIBejCCASCgAwIBAgIUeB0Ob+IUKMsyzojHgFVmKdxIbzgwCgYIKoZIzj0EAwIw\
            FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTExNDEzMTAwMVoYDzIxMjYxMDIx\
            MTMxMDAxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO\
            PQMBBwNCAASemNdrUoBlAEh3pDAfln2GeFxSD58qyJsodvGQwHokep/TNITm0gEc\
            JQ2HJ/9ADMuLuqsXxCNIi28RTHguK4xuo04wTDAdBgNVHQ4EFgQUBVWGeBlQwQFA\
            EPE2hy5k7nDZ8X4wDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhv\
            c3SHBH8AAAEwCgYIKoZIzj0EAwIDSAAwRQIgJ7+DxgUL05UX018RauiWDrv57XiZ\
            kSKcG5ltxXmnZxMCIQDVSGK947WkxHyq5NIweKHgaf2GQNp8BU3fWPQ44u+doA==";
        let certificate = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, certificate).unwrap();
        store.local = Some(Local {
            port,
            password: "open-sesame".into(), // pragma: allowlist secret
            certificate: Arc::new(move || Ok(certificate.clone())),
        });
        let secret = |heard: &std::sync::Mutex<Vec<u8>>| {
            let heard = String::from_utf8_lossy(&heard.lock().unwrap()).to_lowercase();
            // (`kithd:open-sesame`, as Basic sends it.)
            heard.contains("authorization") || heard.contains("a2l0aGQ6b3Blbi1zZXNhbWU")
        };
        for name in ["localhost", "127.0.0.1"] {
            let pulled = store
                .pull(&format!("{name}:{port}/team/hello:1"), PullPolicy::Always)
                .await;
            assert!(pulled.is_err(), "{name}: nothing there shows the node's certificate");
        }
        // (A TLS hello and nothing after it: 0x16 is a handshake record.)
        assert_eq!(
            squatted.lock().unwrap().first(),
            Some(&0x16),
            "it was asked for its certificate"
        );
        assert!(!secret(&squatted), "whoever took the port was told the password");
        // Another registry on this machine, which asks for a password: it is not given this one.
        let pulled = store
            .pull(&format!("127.0.0.1:{far}/team/hello:1"), PullPolicy::Always)
            .await;
        assert!(pulled.is_err());
        assert!(!asked.lock().unwrap().is_empty(), "it was asked");
        assert!(!secret(&asked), "another registry was told the password");
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

    type Files = Arc<std::sync::Mutex<std::collections::HashMap<String, (String, Vec<u8>)>>>;

    // (A test-only certificate for `localhost` and 127.0.0.1, valid for a hundred years and not
    // a CA, with its key below, made with openssl: nothing trusts it but these tests' clients,
    // which are told it by hand.)
    const REGISTRY_CERTIFICATE: &str = "MIIBhDCCASqgAwIBAgIUQSHn5qa3SOvSNwHc/zDY+GlIP7MwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTExNTA2MzI0M1oYDzIxMjYxMDIyMDYzMjQzWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATpxnpqkmfgCLaqxTLOdv1xxDiweTwOFG3jF2FaCkR4hVGagoDe3hu/JTJD806s3Y9/9PDt6EiF7SrPOnBnNFjAo1gwVjAdBgNVHQ4EFgQUQpZJwqh1DYSEgKBb1HmdJg9Lg1YwGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgeAMAoGCCqGSM49BAMCA0gAMEUCIEPXA9/RZwGM8VCZN/nY7RqxkR7HEDQUvV//jVG/rfSVAiEAwx4OjM7eaEMMDJmppsbKbm+yo1pXs9+RNuTT7RbpMfU="; // pragma: allowlist secret
    const REGISTRY_KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpDvOyGoDPU2RfuNInjEEFAnwdX1/8mIVbtEL4zcvi2WhRANCAATpxnpqkmfgCLaqxTLOdv1xxDiweTwOFG3jF2FaCkR4hVGagoDe3hu/JTJD806s3Y9/9PDt6EiF7SrPOnBnNFjA"; // pragma: allowlist secret

    /// A registry for these tests, over TLS with the certificate above (as the node's own
    /// registry has one) or over plain HTTP. It serves `/v2/` and whatever `files` holds; any
    /// other path is a 404, as an Image deleted with its namespace is. `asked` counts the
    /// requests it answered (a handshake that fails answers none).
    struct Registry {
        port: u16,
        certificate: Vec<u8>,
        files: Files,
        asked: Arc<std::sync::atomic::AtomicUsize>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Registry {
        fn start(tls: bool) -> Registry {
            use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let decode = |text: &str| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text).unwrap();
            let certificate = decode(REGISTRY_CERTIFICATE);
            let config = tls.then(|| {
                let key = rustls::pki_types::PrivatePkcs8KeyDer::from(decode(REGISTRY_KEY));
                let config =
                    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                        .with_safe_default_protocol_versions()
                        .unwrap()
                        .with_no_client_auth()
                        .with_single_cert(
                            vec![rustls::pki_types::CertificateDer::from(decode(REGISTRY_CERTIFICATE))],
                            key.into(),
                        )
                        .unwrap();
                Arc::new(config)
            });
            let files: Files = Arc::default();
            let asked = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let (serve_files, serve_asked, serve_stop) = (files.clone(), asked.clone(), stop.clone());
            let thread = std::thread::spawn(move || {
                while !serve_stop.load(Ordering::SeqCst) {
                    let Ok((mut tcp, _)) = listener.accept() else {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    };
                    let _ = tcp.set_nonblocking(false);
                    let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                    match &config {
                        Some(config) => {
                            if let Ok(conn) = rustls::ServerConnection::new(config.clone()) {
                                let mut tls = rustls::StreamOwned::new(conn, tcp);
                                serve_one(&mut tls, &serve_files, &serve_asked);
                            }
                        }
                        None => serve_one(&mut tcp, &serve_files, &serve_asked),
                    }
                }
            });
            Registry {
                port,
                certificate,
                files,
                asked,
                stop,
                thread: Some(thread),
            }
        }

        /// The node's own registry as its kithd would have made it: this certificate, this password.
        fn local(&self) -> Local {
            let certificate = self.certificate.clone();
            Local {
                port: self.port,
                password: "open-sesame".into(), // pragma: allowlist secret
                certificate: Arc::new(move || Ok(certificate.clone())),
            }
        }

        fn asked(&self) -> usize {
            self.asked.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Publishes `team/hello` at `tag` with this entrypoint, and returns its manifest digest.
        /// Its one layer holds `bin/hello`, so an Image pulled again unchanged has a layer to not fetch.
        fn publish(&self, tag: &str, entrypoint: &str) -> String {
            let mut tar = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            h.set_size(5);
            h.set_mode(0o755);
            tar.append_data(&mut h, "bin/hello", &b"hello"[..]).unwrap();
            let layer = tar.into_inner().unwrap();
            let layer_digest = sha(&layer);
            let config = serde_json::json!({
                "architecture": "amd64", "os": "linux",
                "config": { "Entrypoint": [entrypoint] },
                "rootfs": { "type": "layers", "diff_ids": [] },
            })
            .to_string()
            .into_bytes();
            let config_digest = sha(&config);
            let manifest = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": config_digest, "size": config.len(),
                },
                "layers": [{ "mediaType": TAR, "digest": layer_digest, "size": layer.len() }],
            })
            .to_string()
            .into_bytes();
            let digest = sha(&manifest);
            let json = "application/vnd.oci.image.manifest.v1+json";
            let mut files = self.files.lock().unwrap();
            files.insert(
                format!("/v2/team/hello/blobs/{config_digest}"),
                ("application/octet-stream".into(), config),
            );
            files.insert(
                format!("/v2/team/hello/blobs/{layer_digest}"),
                ("application/octet-stream".into(), layer),
            );
            files.insert(
                format!("/v2/team/hello/manifests/{tag}"),
                (json.into(), manifest.clone()),
            );
            files.insert(format!("/v2/team/hello/manifests/{digest}"), (json.into(), manifest));
            digest
        }

        /// The namespace `team` is deleted: nothing under it is served any more.
        fn delete_namespace(&self) {
            self.files
                .lock()
                .unwrap()
                .retain(|path, _| !path.starts_with("/v2/team/"));
        }

        /// The registry is down: it answers nothing, and its port refuses.
        fn stop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    impl Drop for Registry {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn sha(bytes: &[u8]) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
        let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        format!("sha256:{hex}")
    }

    /// Answers one request on `conn`, then closes it.
    fn serve_one<S: Read + Write>(conn: &mut S, files: &Files, asked: &std::sync::atomic::AtomicUsize) {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
            match conn.read(&mut byte) {
                Ok(1) => head.push(byte[0]),
                _ => return,
            }
        }
        asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let head = String::from_utf8_lossy(&head).into_owned();
        let target = head.split_whitespace().nth(1).unwrap_or("");
        let path = target.split('?').next().unwrap_or("").to_string();
        let found = files.lock().unwrap().get(&path).cloned();
        let (status, kind, body, digest) = if path == "/v2/" {
            ("200 OK", "application/json".to_string(), b"{}".to_vec(), None)
        } else if let Some((kind, body)) = found {
            let digest = sha(&body);
            ("200 OK", kind, body, Some(digest))
        } else {
            let body = br#"{"errors":[{"code":"MANIFEST_UNKNOWN","message":"gone"}]}"#.to_vec();
            ("404 Not Found", "application/json".to_string(), body, None)
        };
        let mut reply = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if let Some(digest) = digest {
            reply.push_str(&format!("Docker-Content-Digest: {digest}\r\n"));
        }
        reply.push_str("\r\n");
        let _ = conn.write_all(reply.as_bytes());
        let _ = conn.write_all(&body);
        let _ = conn.flush();
    }

    const POLICIES: [PullPolicy; 3] = [PullPolicy::IfNotPresent, PullPolicy::Always, PullPolicy::Never];

    /// A cached reference of the node's own registry is asked for its manifest on every
    /// pull, whatever the policy, and an unchanged Image is not unpacked again.
    #[tokio::test]
    async fn own_registry_is_asked_on_every_pull_and_an_unchanged_image_is_not_unpacked_again() {
        use std::os::unix::fs::MetadataExt;
        let (dir, _) = sandbox("own-registry-unchanged");
        let registry = Registry::start(true);
        let digest = registry.publish("1", "/bin/one");
        let mut store = ImageStore::new(dir.join("store")).unwrap();
        store.local = Some(registry.local());
        let reference = format!("localhost:{}/team/hello:1", registry.port);
        let first = store.pull(&reference, PullPolicy::IfNotPresent).await.unwrap();
        assert_eq!(first.digest, digest);
        assert_eq!(first.downloaded, 1, "the first pull did not fetch its layer");
        let unpacked = fs::metadata(&first.rootfs).unwrap().ino();
        for policy in POLICIES {
            let before = registry.asked();
            let again = store
                .pull(&reference, policy)
                .await
                .unwrap_or_else(|e| panic!("{policy:?}: {e}"));
            assert!(
                !again.from_cache,
                "{policy:?}: answered from the store, not the registry"
            );
            assert_eq!(again.digest, digest, "{policy:?}");
            assert_eq!(again.downloaded, 0, "{policy:?}: a layer was downloaded again");
            assert!(registry.asked() > before, "{policy:?}: the registry was not asked");
            assert_eq!(
                fs::metadata(&again.rootfs).unwrap().ino(),
                unpacked,
                "{policy:?}: unpacked again"
            );
        }
        drop(registry);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// An Image deleted with its namespace, and made again, is not started from the store's copy.
    #[tokio::test]
    async fn own_registry_fails_a_start_whose_image_it_no_longer_has() {
        let (dir, _) = sandbox("own-registry-deleted");
        let registry = Registry::start(true);
        registry.publish("1", "/bin/one");
        let mut store = ImageStore::new(dir.join("store")).unwrap();
        store.local = Some(registry.local());
        let reference = format!("localhost:{}/team/hello:1", registry.port);
        store.pull(&reference, PullPolicy::IfNotPresent).await.unwrap();
        registry.delete_namespace();
        for policy in POLICIES {
            let before = registry.asked();
            let failed = store.pull(&reference, policy).await;
            let Err(reason) = failed else {
                panic!("{policy:?}: started a deleted Image from the store");
            };
            assert!(registry.asked() > before, "{policy:?}: the registry was not asked");
            assert!(reason.to_string().contains("team/hello:1"), "{policy:?}: {reason}");
            // The registry's refusal, in the words its 404 gave (the envelope is read, not a bare status).
            assert!(
                reason.to_string().contains("OCI API error: gone"),
                "{policy:?}: {reason}"
            );
        }
        drop(registry);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A tag that moved under the node's own registry starts as the new Image, whatever the policy.
    #[tokio::test]
    async fn own_registry_starts_a_changed_tag_as_the_new_image() {
        let (dir, _) = sandbox("own-registry-changed");
        let registry = Registry::start(true);
        let old = registry.publish("1", "/bin/one");
        let mut store = ImageStore::new(dir.join("store")).unwrap();
        store.local = Some(registry.local());
        let reference = format!("localhost:{}/team/hello:1", registry.port);
        store.pull(&reference, PullPolicy::IfNotPresent).await.unwrap();
        let new = registry.publish("1", "/bin/two");
        assert_ne!(old, new);
        for policy in POLICIES {
            let image = store
                .pull(&reference, policy)
                .await
                .unwrap_or_else(|e| panic!("{policy:?}: {e}"));
            assert_eq!(image.digest, new, "{policy:?}");
            assert_eq!(image.entrypoint, ["/bin/two"], "{policy:?}");
        }
        drop(registry);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The node's own registry being down fails the start with the reason, not with the cached copy.
    #[tokio::test]
    async fn own_registry_being_down_fails_the_start_with_its_reason() {
        let (dir, _) = sandbox("own-registry-down");
        let mut registry = Registry::start(true);
        registry.publish("1", "/bin/one");
        let mut store = ImageStore::new(dir.join("store")).unwrap();
        store.local = Some(registry.local());
        let reference = format!("localhost:{}/team/hello:1", registry.port);
        store.pull(&reference, PullPolicy::IfNotPresent).await.unwrap();
        registry.stop();
        for policy in POLICIES {
            let failed = store.pull(&reference, policy).await;
            let Err(reason) = failed else {
                panic!("{policy:?}: started with the registry down");
            };
            assert!(reason.to_string().contains(&reference), "{policy:?}: {reason}");
            assert!(
                reason.to_string().contains("error sending request"),
                "{policy:?}: {reason}"
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Another registry's reference keeps its policy: IfNotPresent answers from the store
    /// without asking, and only Always asks.
    #[tokio::test]
    async fn own_registry_leaves_another_registrys_policy_as_it_was() {
        let (dir, _) = sandbox("own-registry-other");
        let own = Registry::start(true);
        let other = Registry::start(false);
        other.publish("1", "/bin/one");
        let mut store = ImageStore::new(dir.join("store")).unwrap();
        store.local = Some(own.local());
        let reference = format!("127.0.0.1:{}/team/hello:1", other.port);
        store.pull(&reference, PullPolicy::Always).await.unwrap();
        let before = other.asked();
        let cached = store.pull(&reference, PullPolicy::IfNotPresent).await.unwrap();
        assert!(cached.from_cache, "another registry was asked under IfNotPresent");
        assert_eq!(other.asked(), before, "another registry was asked under IfNotPresent");
        store.pull(&reference, PullPolicy::Always).await.unwrap();
        assert!(other.asked() > before, "Always did not ask");
        drop((own, other));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Other names for the node's registry's port are not it: they are sent no request at all
    /// (no password either), and leave nothing in the store.
    #[tokio::test]
    async fn own_registry_names_at_its_port_that_are_not_its_own_pull_nothing() {
        let (dir, _) = sandbox("own-registry-names");
        let registry = Registry::start(true);
        registry.publish("1", "/bin/one");
        let mut store = ImageStore::new(dir.join("store")).unwrap();
        store.local = Some(registry.local());
        for name in ["[::1]", "LOCALHOST", "localhost.", "127.1"] {
            let reference = format!("{name}:{}/team/hello:1", registry.port);
            for policy in POLICIES {
                assert!(store.pull(&reference, policy).await.is_err(), "{reference} {policy:?}");
            }
        }
        assert_eq!(
            registry.asked(),
            0,
            "a name that is not the node's own was sent a request"
        );
        assert_eq!(
            fs::read_dir(dir.join("store/refs")).unwrap().count(),
            0,
            "a ref file was left"
        );
        drop(registry);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A registry that accepts a connection and never answers fails the start with its reason
    /// within the own registry's timeouts, rather than holding the start for as long as it stalls.
    #[tokio::test]
    async fn own_registry_that_accepts_and_never_answers_fails_the_start_in_time() {
        let (dir, _) = sandbox("own-registry-stalls");
        // The kernel accepts a connection to it; nothing ever reads it or answers.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = silent.local_addr().unwrap().port();
        let certificate =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, REGISTRY_CERTIFICATE).unwrap();
        let mut store = ImageStore::new(dir.join("store")).unwrap();
        store.local = Some(Local {
            port,
            password: "open-sesame".into(), // pragma: allowlist secret
            certificate: Arc::new(move || Ok(certificate.clone())),
        });
        store.own_timeouts = (Duration::from_millis(200), Duration::from_millis(200));
        let reference = format!("localhost:{port}/team/hello:1");
        let started = std::time::Instant::now();
        let Ok(result) =
            tokio::time::timeout(Duration::from_secs(20), store.pull(&reference, PullPolicy::Always)).await
        else {
            panic!("the start was still waiting on a registry that never answers after 20 s");
        };
        let Err(reason) = result else {
            panic!("started from a registry that never answered");
        };
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "took {:?}",
            started.elapsed()
        );
        assert!(reason.to_string().contains(&reference), "{reason}");
        drop(silent);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A file of a finished tree, as unpacking leaves one.
    fn put(root: &Path, path: &str, bytes: &str, mode: u32, mtime: u64) -> PathBuf {
        let file = root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, bytes).unwrap();
        let opened = File::options().write(true).open(&file).unwrap();
        opened
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(mtime))
            .unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
        file
    }

    fn ino(path: &Path) -> u64 {
        fs::symlink_metadata(path).unwrap().ino()
    }

    fn links(path: &Path) -> u64 {
        fs::symlink_metadata(path).unwrap().nlink()
    }

    /// What the index holds, but for its lock.
    fn entries(index: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(index)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| !name.starts_with('.'))
            .collect();
        names.sort();
        names
    }

    fn hard_link(from: &Path, to: &Path) -> std::io::Result<()> {
        fs::hard_link(from, to)
    }

    /// Sets `name` on `file` as this process can: directly, or as root of a user namespace
    /// of its own (a capability may be set on a file only by someone who could hold it).
    fn set_xattr(file: &Path, name: &str, value: &[u8]) -> bool {
        if rustix::fs::setxattr(file, name, value, rustix::fs::XattrFlags::empty()).is_ok() {
            return true;
        }
        let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
        std::process::Command::new("unshare")
            .args(["-Ur", "setfattr", "-n", name, "-v"])
            .arg(format!("0x{hex}"))
            .arg(file)
            .status()
            .is_ok_and(|status| status.success())
    }

    /// Equal files of two images are one inode; a file that differs in anything that
    /// matters, or that has an extended attribute, is its own; nothing's bytes or mode change.
    #[test]
    fn shared_files_are_one_where_everything_matches() {
        let (dir, _) = sandbox("shared-same");
        let (a, b, index) = (dir.join("a"), dir.join("b"), dir.join("shared"));
        let both = [
            ("bin/tool", "tool", 0o755, 100),
            ("etc/conf", "conf", 0o644, 100),
            ("empty", "", 0o644, 100),
            ("setuid", "s", 0o4755, 100),
            ("all-bits", "s", 0o7755, 100),
        ];
        for (path, bytes, mode, mtime) in both {
            put(&a, path, bytes, mode, mtime);
            put(&b, path, bytes, mode, mtime);
        }
        // The same within one image too.
        put(&a, "bin/tool-too", "tool", 0o755, 100);
        // One thing apart, each.
        let apart = [
            ("bytes", ("one", 0o644, 100), ("two", 0o644, 100)),
            ("mode", ("m", 0o644, 100), ("m", 0o640, 100)),
            ("setuid-bit", ("s", 0o4755, 100), ("s", 0o755, 100)),
            ("setgid-bit", ("s", 0o2755, 100), ("s", 0o755, 100)),
            ("sticky-bit", ("s", 0o1755, 100), ("s", 0o755, 100)),
            ("changed", ("t", 0o644, 100), ("t", 0o644, 200)),
        ];
        for (path, (x, xm, xt), (y, ym, yt)) in apart {
            put(&a, path, x, xm, xt);
            put(&b, path, y, ym, yt);
        }
        // Equal in all of it, but for an extended attribute: never shared, not even with each other.
        let mut capable = true;
        for root in [&a, &b] {
            assert!(set_xattr(&put(root, "user-x", "x", 0o644, 100), "user.x", b"1"));
            // VFS_CAP_REVISION_2, effective, CAP_NET_RAW permitted.
            let cap = [1, 0, 0, 2, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            capable &= set_xattr(&put(root, "capable", "c", 0o755, 100), "security.capability", &cap);
        }
        if !capable {
            eprintln!("could not set security.capability here; user.x was tried");
        }
        fs::create_dir_all(a.join("dir")).unwrap();
        std::os::unix::fs::symlink("bin/tool", a.join("link")).unwrap();
        std::os::unix::fs::symlink("bin/tool", b.join("link")).unwrap();
        let look = |root: &Path| -> Vec<_> {
            let mut all = Vec::new();
            for path in ["bin/tool", "etc/conf", "empty", "setuid", "all-bits", "bytes", "mode"] {
                let meta = fs::symlink_metadata(root.join(path)).unwrap();
                all.push((path, fs::read(root.join(path)).unwrap(), meta.mode(), meta.mtime()));
            }
            all
        };
        let before = (look(&a), look(&b));

        share(&a, &index, hard_link);
        share(&b, &index, hard_link);

        assert_eq!((look(&a), look(&b)), before, "a shared file changed");
        for (path, ..) in both {
            assert_eq!(ino(&a.join(path)), ino(&b.join(path)), "{path} is two files");
        }
        assert_eq!(ino(&a.join("bin/tool")), ino(&a.join("bin/tool-too")));
        assert_eq!(links(&a.join("bin/tool")), 4, "two images, one index entry");
        for (path, ..) in apart {
            assert_ne!(ino(&a.join(path)), ino(&b.join(path)), "{path} is one file");
        }
        for path in ["user-x", "capable"] {
            assert_ne!(ino(&a.join(path)), ino(&b.join(path)), "{path} is one file");
            assert_eq!(links(&a.join(path)), 1, "{path} went into the index");
        }
        assert!(a.join("link").is_symlink() && a.join("dir").is_dir());
        // Two files apart in owner are two names in the index: their own files.
        let differ = |uid, gid| shared_name("ab", (0o644, uid, gid, 100, 0, 1));
        assert!(differ(0, 0) != differ(1, 0) && differ(0, 0) != differ(0, 1));
        if nix::unistd::getuid().is_root() {
            let (x, y) = (put(&a, "owner", "o", 0o644, 100), put(&b, "owner", "o", 0o644, 100));
            std::os::unix::fs::chown(&y, Some(1), None).unwrap();
            let (u, v) = (put(&a, "group", "g", 0o644, 100), put(&b, "group", "g", 0o644, 100));
            std::os::unix::fs::chown(&v, None, Some(1)).unwrap();
            share(&a, &index, hard_link);
            share(&b, &index, hard_link);
            assert!(ino(&x) != ino(&y) && ino(&u) != ino(&v));
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A link that cannot be made (too many links already, another file system) leaves the
    /// file as it was, and nothing of the attempt behind.
    #[test]
    fn shared_files_stay_plain_where_no_link_can_be_made() {
        fn too_many(_: &Path, _: &Path) -> std::io::Result<()> {
            Err(std::io::Error::from_raw_os_error(nix::libc::EMLINK))
        }
        fn elsewhere(_: &Path, _: &Path) -> std::io::Result<()> {
            Err(std::io::Error::from_raw_os_error(nix::libc::EXDEV))
        }
        /// Into the index, yes; out of it, no.
        fn not_out(from: &Path, to: &Path) -> std::io::Result<()> {
            match to
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with('.'))
            {
                true => too_many(from, to),
                false => fs::hard_link(from, to),
            }
        }
        let (dir, _) = sandbox("shared-plain");
        for (n, link) in [too_many as fn(&Path, &Path) -> _, elsewhere, not_out]
            .into_iter()
            .enumerate()
        {
            let (a, b, index) = (
                dir.join(format!("a{n}")),
                dir.join(format!("b{n}")),
                dir.join(format!("i{n}")),
            );
            let files = [put(&a, "f", "same", 0o755, 1), put(&b, "f", "same", 0o755, 1)];
            share(&a, &index, link);
            share(&b, &index, link);
            assert_ne!(ino(&files[0]), ino(&files[1]), "{n}");
            for file in &files {
                assert_eq!(fs::read_to_string(file).unwrap(), "same", "{n}");
                assert_eq!(fs::symlink_metadata(file).unwrap().mode() & 0o7777, 0o755);
            }
            assert_eq!(
                fs::read_dir(&b).unwrap().count(),
                1,
                "{n}: a scratch name was left behind"
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Sharing runs on the finished tree: what a lower layer had and a later one replaced
    /// never reaches the index, and an image unpacked later shares what is left.
    #[test]
    fn shared_files_are_shared_once_the_tree_is_finished() {
        let (dir, _) = sandbox("shared-finished");
        let index = dir.join("shared");
        let lower = layer(&dir, "1.tar", &[E::File("a", "first"), E::File("b", "kept")]);
        let upper = layer(&dir, "2.tar", &[E::File("a", "second")]);
        let one = [(lower, TAR.to_string()), (upper, TAR.to_string())];
        unpack_image(&one, &dir.join("s1"), &dir.join("one"), Some(&index), Budget::IMAGE).unwrap();
        assert_eq!(entries(&index).len(), 2, "{:?}", entries(&index));
        for name in entries(&index) {
            assert_ne!(fs::read_to_string(index.join(name)).unwrap(), "first");
        }
        let again = layer(&dir, "3.tar", &[E::File("a", "second"), E::File("b", "kept")]);
        let two = [(again, TAR.to_string())];
        unpack_image(&two, &dir.join("s2"), &dir.join("two"), Some(&index), Budget::IMAGE).unwrap();
        for file in ["rootfs/a", "rootfs/b"] {
            assert_eq!(ino(&dir.join("one").join(file)), ino(&dir.join("two").join(file)));
        }
        assert_eq!(fs::read_to_string(dir.join("two/rootfs/a")).unwrap(), "second");
        assert_eq!(entries(&index).len(), 2);
        // Unpacked with no index, nothing is shared.
        unpack_image(&two, &dir.join("s3"), &dir.join("three"), None, Budget::IMAGE).unwrap();
        assert_eq!(links(&dir.join("three/rootfs/a")), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Removing an image leaves the other's files whole; the sweep then removes what only the
    /// index still holds, and waits for an unpack that is sharing.
    #[test]
    fn shared_files_outlive_an_image_and_the_sweep_takes_what_is_left() {
        let (dir, _) = sandbox("shared-sweep");
        let store = ImageStore::new(dir.join("store")).unwrap();
        let index = dir.join("store/shared");
        let images = dir.join("store/images");
        let common = layer(
            &dir,
            "common.tar",
            &[E::File("lib", "library"), E::File("etc", "settings")],
        );
        let own = layer(&dir, "own.tar", &[E::File("only-a", "mine")]);
        let a = [(common.clone(), TAR.to_string()), (own, TAR.to_string())];
        let b = [(common, TAR.to_string())];
        unpack_image(&a, &images.join("sa"), &images.join("a"), Some(&index), Budget::IMAGE).unwrap();
        unpack_image(&b, &images.join("sb"), &images.join("b"), Some(&index), Budget::IMAGE).unwrap();
        assert_eq!(entries(&index).len(), 3);
        assert_eq!(store.sweep_shared().unwrap(), 0, "the sweep took what images still use");

        fs::remove_dir_all(images.join("a")).unwrap();
        assert_eq!(fs::read_to_string(images.join("b/rootfs/lib")).unwrap(), "library");
        assert_eq!(fs::read_to_string(images.join("b/rootfs/etc")).unwrap(), "settings");
        assert_eq!(links(&images.join("b/rootfs/lib")), 2);
        assert_eq!(store.sweep_shared().unwrap(), 1, "only-a's entry was kept");
        assert_eq!(entries(&index).len(), 2);
        assert_eq!(fs::read_to_string(images.join("b/rootfs/lib")).unwrap(), "library");

        // The sweep waits for the lock an unpack holds while it shares.
        let held = lock(&index).unwrap();
        let sweeping = std::thread::spawn({
            let index = index.clone();
            move || sweep(&index)
        });
        std::thread::sleep(Duration::from_millis(300));
        assert!(!sweeping.is_finished(), "the sweep ran while an unpack was sharing");
        drop(held);
        assert_eq!(sweeping.join().unwrap().unwrap(), 0);

        fs::remove_dir_all(images.join("b")).unwrap();
        assert_eq!(store.sweep_shared().unwrap(), 2);
        assert!(entries(&index).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Two unpacks at once into one index, which an earlier stop left an entry in that nothing
    /// links and one that is not whole: every file is whole, and equal files are one.
    #[test]
    fn shared_files_two_unpacks_at_once_and_stray_entries() {
        let (dir, _) = sandbox("shared-at-once");
        let index = dir.join("shared");
        // What a stop left: the entry for `f0`, nothing else linking it; and `f1`'s, cut short.
        let seed = dir.join("seed");
        unpack_image(
            &[(
                layer(&dir, "seed.tar", &[E::File("f0", "file 0"), E::File("f1", "file 1")]),
                TAR.to_string(),
            )],
            &dir.join("seed-staging"),
            &seed,
            Some(&index),
            Budget::IMAGE,
        )
        .unwrap();
        let stray = ino(&seed.join("rootfs/f0"));
        let cut = index.join(
            entries(&index)
                .into_iter()
                .find(|name| ino(&index.join(name)) == ino(&seed.join("rootfs/f1")))
                .unwrap(),
        );
        fs::remove_dir_all(&seed).unwrap();
        File::options().write(true).open(&cut).unwrap().set_len(3).unwrap();
        let short = ino(&cut);

        let bodies: Vec<String> = (0..300).map(|n| format!("file {}", n % 150)).collect();
        let files: Vec<(String, &str)> = bodies
            .iter()
            .enumerate()
            .map(|(n, b)| (format!("f{n}"), b.as_str()))
            .collect();
        let tar: Vec<E> = files.iter().map(|(name, body)| E::File(name, body)).collect();
        let blob = layer(&dir, "many.tar", &tar);
        let unpacks: Vec<_> = ["x", "y"]
            .map(|name| {
                let (blob, dir, index) = (blob.clone(), dir.clone(), index.clone());
                std::thread::spawn(move || {
                    let layers = [(blob, TAR.to_string())];
                    let staging = dir.join(format!("staging-{name}"));
                    unpack_image(&layers, &staging, &dir.join(name), Some(&index), Budget::IMAGE)
                })
            })
            .into();
        for unpack in unpacks {
            unpack.join().unwrap().unwrap();
        }
        let (x, y) = (dir.join("x/rootfs"), dir.join("y/rootfs"));
        for (name, body) in &files {
            for root in [&x, &y] {
                assert_eq!(&fs::read_to_string(root.join(name)).unwrap(), body, "{name}");
            }
        }
        assert_eq!(ino(&x.join("f0")), stray, "the stray entry was not used");
        assert_eq!(ino(&y.join("f150")), stray);
        for root in [&x, &y] {
            assert_ne!(ino(&root.join("f1")), short, "linked to an entry cut short");
        }
        // The first unpack's whole file took its place, and the rest share it.
        assert_eq!(fs::read_to_string(&cut).unwrap(), "file 1");
        for n in 1..150 {
            let one = ino(&x.join(format!("f{n}")));
            for other in [
                x.join(format!("f{}", n + 150)),
                y.join(format!("f{n}")),
                y.join(format!("f{}", n + 150)),
            ] {
                assert_eq!(ino(&other), one, "f{n}");
            }
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    /// T-0175's trial, on this machine: three images of one base, unpacked as they would be
    /// with and without sharing. Prints the disk they take (each inode counted once), the
    /// middle of three unpack times, and the machine's load; fails if the disk falls by less
    /// than a tenth. Pulls from mirror.gcr.io; nothing else is asked.
    #[tokio::test]
    async fn shared_files_measured() {
        if std::env::var_os("KITH_E2E").is_none() {
            eprintln!("skipped: set KITH_E2E=1 to run");
            return;
        }
        let references = [
            "mirror.gcr.io/library/nginx:1.27-alpine",
            "mirror.gcr.io/library/nginx:1.27-alpine-perl",
            "mirror.gcr.io/library/nginx:1.27-alpine-otel",
        ];
        let (dir, _) = sandbox("shared-measured");
        let store = ImageStore::new(dir.join("store")).unwrap();
        let client = Client::try_from(ClientConfig::default()).unwrap();
        let mut images = Vec::new();
        for reference in references {
            store.pull(reference, PullPolicy::Always).await.unwrap();
            let (manifest, _) = client
                .pull_image_manifest(&reference.parse().unwrap(), &RegistryAuth::Anonymous)
                .await
                .unwrap();
            let layers: Vec<(PathBuf, String)> = manifest
                .layers
                .iter()
                .map(|l| {
                    (
                        dir.join("store/blobs/sha256").join(sha256_hex(&l.digest).unwrap()),
                        l.media_type.clone(),
                    )
                })
                .collect();
            images.push(layers);
        }
        let load = || {
            fs::read_to_string("/proc/loadavg")
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        eprintln!(
            "load before: {} ({} cores)",
            load(),
            std::thread::available_parallelism().map_or(0, |n| n.get())
        );
        let mut times: [Vec<Duration>; 2] = [Vec::new(), Vec::new()];
        let mut disk = [0u64; 2];
        // Taken in turns, so a change in the machine's load falls on both alike.
        for round in 0..3 {
            for (shared, time) in times.iter_mut().enumerate() {
                let at = dir.join(format!("run-{round}-{shared}"));
                let index = at.join("shared");
                let started = std::time::Instant::now();
                for (n, layers) in images.iter().enumerate() {
                    let target = at.join(format!("image-{n}"));
                    let staging = at.join(format!("staging-{n}"));
                    unpack_image(
                        layers,
                        &staging,
                        &target,
                        (shared == 1).then_some(&*index),
                        Budget::IMAGE,
                    )
                    .unwrap();
                }
                time.push(started.elapsed());
                let mut seen = std::collections::HashSet::new();
                let mut bytes = 0;
                let mut todo = vec![at.clone()];
                while let Some(path) = todo.pop() {
                    let meta = fs::symlink_metadata(&path).unwrap();
                    if seen.insert((meta.dev(), meta.ino())) {
                        bytes += meta.blocks() * 512;
                    }
                    if meta.is_dir() {
                        todo.extend(fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
                    }
                }
                disk[shared] = bytes;
                fs::remove_dir_all(&at).unwrap();
            }
        }
        eprintln!("load after: {}", load());
        for time in &mut times {
            time.sort();
        }
        let (before, after) = (times[0][1], times[1][1]);
        let mb = |bytes: u64| bytes as f64 / 1e6;
        eprintln!(
            "disk: {:.1} MB -> {:.1} MB ({:+.1}%)",
            mb(disk[0]),
            mb(disk[1]),
            100.0 * (disk[1] as f64 / disk[0] as f64 - 1.0)
        );
        eprintln!(
            "unpack, middle of three: {before:?} -> {after:?} ({:+.1}%); all: {:?}",
            100.0 * (after.as_secs_f64() / before.as_secs_f64() - 1.0),
            times
        );
        assert!(disk[1] * 10 <= disk[0] * 9, "the disk fell by less than a tenth");
        fs::remove_dir_all(&dir).unwrap();
    }
}
