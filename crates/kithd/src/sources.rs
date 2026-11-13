//! Sources (PLAN.md §4.9): the node that leads the store keeps what a `Source` points
//! at (a path in a git repository, or an OCI artifact) applied. What a Source applied
//! is marked and kept to itself like a Release's: a Source applies into its own
//! namespace, and one in `kith-system` anywhere (that is the cluster's own).
//!
//! `approval: manual` holds a new revision in `status.pending` until `spec.approve`
//! names it. What a Source applied and someone changed since is put back, and listed in
//! `status.drift`: the source is what is true.
//
// ponytail: git is the node's `git`, run as a program (a git inside kithd is several MB
// for what the program does); nothing is ever checked out, so no link in a repository
// is followed and no hook runs. No signed-commit check yet.

use crate::Shared;
use crate::releases::{OWNER, Step, carry_out, owner, reconcile, recorded};
use kith_api::Resource;
use kith_api::kinds::{Approval, SourceSpec};
use kith_api::store::Store;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::sync::watch;

type Fallible<T> = Result<T, String>;

/// The most files a source may hold under its path, and the most bytes in them.
const FILES_LIMIT: usize = 2000;
const BYTES_LIMIT: u64 = 4 << 20;
/// How long git gets for one thing.
const PATIENCE: Duration = Duration::from_secs(120);
/// The most git may say in one go (the list of a big repository's files fits).
const OUTPUT_LIMIT: u64 = 16 << 20;
/// The most a git repository of a Source may take on disk, and the most of it git may
/// write to one file (a pack).
const DISK_LIMIT: u64 = 256 << 20;
/// How many Sources are fetched at once.
const FETCHES_AT_ONCE: usize = 4;
/// The longest a Source that keeps failing is left alone.
const BACKOFF_LIMIT: Duration = Duration::from_secs(3600);

/// What a source holds, at one revision.
#[derive(Debug, Clone, PartialEq)]
pub struct Fetched {
    pub revision: String,
    /// The YAML and JSON files under the path, by their path in the source.
    pub files: BTreeMap<String, String>,
    /// What is there and was not read, and why.
    pub skipped: Vec<String>,
    /// The resources in the files, once worked out (see `desired`).
    pub resources: OnceLock<Fallible<Vec<Resource>>>,
}

/// May a Source name this git URL? Over the network only (`file://` for tests, when
/// kithd is told so): never a path on the node, never a transport that runs a program.
pub fn url_allowed(url: &str, local: bool) -> Fallible<()> {
    let fine = ["https://", "ssh://"].iter().any(|scheme| url.starts_with(scheme));
    match fine || (local && url.starts_with("file://")) {
        true => Ok(()),
        false => Err(format!("{url}: a git URL is https:// or ssh://")),
    }
}

/// The host a git or OCI URL names (`scheme://[user@]HOST[:port]/...`).
fn host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let rest = rest.split('/').next().unwrap_or_default();
    let rest = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    match rest.strip_prefix('[').and_then(|v6| v6.split_once(']')) {
        Some((v6, _)) => v6,
        None => rest.rsplit_once(':').map_or(rest, |(host, _)| host),
    }
}

/// Is this an address of this node or of the networks around it (loopback, private,
/// link-local, shared, unspecified), in whatever form it is written?
fn inward(ip: std::net::IpAddr) -> bool {
    let v4 = |ip: std::net::Ipv4Addr| {
        let shared = ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64;
        ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified() || shared || ip.is_broadcast()
    };
    match ip {
        std::net::IpAddr::V4(ip) => v4(ip),
        std::net::IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            // (Unique-local, link-local, the old site-local; and the forms that carry an
            // IPv4 address inside: mapped, compatible, 6to4, NAT64.)
            let local = (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 || (first & 0xffc0) == 0xfec0;
            let [a, b, c, d] = [ip.octets()[2], ip.octets()[3], ip.octets()[4], ip.octets()[5]];
            let sixtofour = first == 0x2002 && v4(std::net::Ipv4Addr::new(a, b, c, d));
            let [a, b, c, d] = [ip.octets()[12], ip.octets()[13], ip.octets()[14], ip.octets()[15]];
            let nat64 = ip.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0] && v4(std::net::Ipv4Addr::new(a, b, c, d));
            let ours = ip.is_loopback() || local || sixtofour || nat64;
            ours || ip.to_ipv4_mapped().or(ip.to_ipv4()).is_some_and(v4)
        }
    }
}

/// May a Source that is not the cluster's own (not in `kith-system`) be fetched from
/// `url`? Not with the node's own ssh keys, and not from this node or the networks
/// around it, whatever name they go by: whoever may write a Source in a namespace does
/// not get to have kithd ask them.
///
/// Says where it is, as git's `http.curloptResolve` takes it (`HOST:PORT:ADDRESS`): the
/// fetch connects there and nowhere else, so a name that changes its answer after this
/// look gets nothing by it.
pub async fn outward(url: &str) -> Fallible<Vec<String>> {
    let (host, port, found) = vetted(url).await?;
    // (One entry for the name: curl keeps only the last it is given for a host and port.)
    let all: Vec<String> = found.iter().map(|address| at(address.ip())).collect();
    Ok(vec![format!("{host}:{port}:{}", all.join(","))])
}

/// The addresses the cluster's Nodes say they are at (`status.address`), as [`run`] last
/// read them.
static NODES: std::sync::Mutex<Vec<std::net::IpAddr>> = std::sync::Mutex::new(Vec::new());

/// Is this an address one of this machine's cards has, or one a Node of the cluster
/// says it is at, public ones included?
//
// ponytail: neither set is seen through 6to4 or NAT64, a public address that a NAT in
// front of this machine holds for it is known only if a Node advertises it, and a Node
// that joins during a round of fetches is known from the next round on.
fn ours(ip: std::net::IpAddr) -> bool {
    let ip = ip.to_canonical();
    let has = |card: nix::ifaddrs::InterfaceAddress| {
        let address = card.address?;
        let v4 = address.as_sockaddr_in().map(|at| std::net::IpAddr::from(at.ip()));
        let v6 = address
            .as_sockaddr_in6()
            .map(|at| std::net::IpAddr::from(at.ip()).to_canonical());
        Some(v4.or(v6)? == ip)
    };
    let mut cards = nix::ifaddrs::getifaddrs().into_iter().flatten();
    cards.any(|card| has(card) == Some(true))
        || NODES
            .lock()
            .expect("nothing panics holding the Nodes' addresses")
            .contains(&ip)
}

/// Read where the Nodes say they are (a name is looked up) for [`ours`].
async fn nodes(shared: &Shared) {
    let said: Vec<String> = {
        let state = shared.store.lock().expect("nothing panics holding the store");
        let at = |node: &Resource| Some(node.status.as_ref()?["address"].as_str()?.to_string());
        state.store.list(Some("Node")).filter_map(at).collect()
    };
    let mut found = Vec::new();
    for at in said {
        if let Ok(Ok(all)) = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(at)).await {
            found.extend(all.map(|at| at.ip().to_canonical()));
        }
    }
    *NODES.lock().expect("nothing panics holding the Nodes' addresses") = found;
}

#[cfg(test)]
thread_local! {
    /// For a test whose "outside" server is on this machine: its own thread takes loopback for outside.
    pub static LOOPBACK_IS_OUTSIDE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The host and port `url` names and the addresses it is at, if none of them is this
/// node or its networks.
pub async fn vetted(url: &str) -> Fallible<(String, u16, Vec<std::net::SocketAddr>)> {
    let host = host(url);
    let authority = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = authority.split('/').next().unwrap_or_default();
    // What is vetted must be what whoever fetches connects to: nothing that one reader
    // of a URL takes for the host's end and another does not.
    if url.contains(['?', '#', '\\']) || authority.contains(['@', '%']) || url.chars().any(char::is_whitespace) {
        return Err(format!(
            "{url}: a Source's address is scheme://host[:port]/path, and no more"
        ));
    }
    let after = authority.rsplit_once(']').map_or(authority, |(_, after)| after);
    let port: u16 = match after.rsplit_once(':') {
        Some((_, port)) => port.parse().map_err(|_| format!("{url}: {port:?} is not a port"))?,
        None => 443,
    };
    if url.starts_with("ssh://") {
        return Err(format!(
            "{host}: only a Source in kith-system is fetched over ssh (with this node's keys)"
        ));
    }
    let found: Vec<_> = match tokio::net::lookup_host((host, port)).await {
        Ok(found) => found.collect(),
        Err(e) => return Err(format!("{host}: {e}")),
    };
    let inward = |ip: std::net::IpAddr| inward(ip) || ours(ip);
    #[cfg(test)]
    let inward = |ip: std::net::IpAddr| inward(ip) && !(ip.is_loopback() && LOOPBACK_IS_OUTSIDE.get());
    match found.is_empty() || found.iter().any(|address| inward(address.ip())) {
        true => Err(format!(
            "{host}: only a Source in kith-system is fetched from this node or its own networks"
        )),
        false => Ok((host.to_string(), port, found)),
    }
}

/// Does the git that says this of its version know `http.curloptResolve` (2.37 on)?
fn pinnable(version: &str) -> bool {
    let mut numbers = version.split_whitespace().nth(2).unwrap_or_default().split('.');
    let mut number = || numbers.next().and_then(|number| number.parse::<u32>().ok());
    matches!((number(), number()), (Some(major), Some(minor)) if (major, minor) >= (2, 37))
}

/// An address as curl's `--resolve` takes it.
fn at(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    }
}

/// May a Source name this branch, tag or commit? (Nothing git could take for an option
/// or a range.)
pub fn rev_allowed(rev: &str) -> Fallible<()> {
    let plain = |c: char| c.is_ascii_alphanumeric() || "._/-".contains(c);
    match !rev.is_empty() && !rev.starts_with('-') && !rev.contains("..") && rev.chars().all(plain) {
        true => Ok(()),
        false => Err(format!("{rev:?}: not a branch, tag or commit")),
    }
}

/// A plain path inside a source: no way up or out of it.
pub fn path_allowed(path: &str) -> Fallible<()> {
    let part = |part: &str| !matches!(part, "" | "." | "..") && !part.starts_with('-');
    match path.split('/').all(part) && !path.contains(['\\', '\0', ':']) {
        true => Ok(()),
        false => Err(format!("{path:?}: not a path inside the source")),
    }
}

/// Run git in the bare repository `dir`: with no configuration but ours, nothing to
/// ask anyone, and only the transports a Source may use. With `pins` (see [`outward`]) it
/// connects only where they say and follows no redirect to anywhere else. It may write no
/// file bigger than `limit` bytes (run under `ulimit -f`, in 512-byte blocks; the program
/// that is stopped for it is said so).
async fn git(limit: u64, dir: &Path, local: bool, pins: &[String], args: &[&str]) -> Fallible<Vec<u8>> {
    let mut command = tokio::process::Command::new("sh");
    command
        .args([
            "-c",
            &format!("ulimit -f {} && exec git \"$@\"", limit.div_ceil(512)),
            "git",
        ])
        .arg("-C")
        .arg(dir);
    let file = if local { "always" } else { "never" };
    for setting in [
        "protocol.allow=never",
        "protocol.https.allow=always",
        "protocol.ssh.allow=always",
        &format!("protocol.file.allow={file}"),
        "core.hooksPath=/dev/null",
        "credential.helper=",
    ] {
        command.args(["-c", setting]);
    }
    // (Every fetch into one pack file, which the file limit bounds: left to itself git
    // unpacks a small pack into as many loose files as it has objects.)
    command.args(["-c", "fetch.unpackLimit=1", "-c", "transfer.unpackLimit=1"]);
    for pin in pins {
        command.args(["-c", &format!("http.curloptResolve={pin}")]);
    }
    if !pins.is_empty() {
        // (And through no proxy, which would look the name up again itself.)
        command.args(["-c", "http.followRedirects=false", "-c", "http.proxy="]);
        for proxy in [
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
        ] {
            command.env_remove(proxy);
        }
    }
    command
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_SSH_COMMAND", "ssh -oBatchMode=yes")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // (kithd collects the children nobody waits for: this one is waited for.)
    let child = match kith_runtime::spawn_awaited(|| command.spawn(), tokio::process::Child::id) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err("this node has no git or no sh: a Source from a git repository needs both".into());
        }
        Err(e) => return Err(format!("running git: {e}")),
        Ok(child) => child,
    };
    let (mut child, _awaited) = child;
    // (No more of what it says is kept than a source may hold; the rest ends it.)
    let (stdout, stderr) = (child.stdout.take().expect("piped"), child.stderr.take().expect("piped"));
    let (mut out, mut said) = (Vec::new(), Vec::new());
    let ran = async {
        let mut stderr = stderr.take(64 << 10);
        let said = async {
            let _ = stderr.read_to_end(&mut said).await;
            let _ = tokio::io::copy(&mut stderr.into_inner(), &mut tokio::io::sink()).await;
        };
        let mut stdout = stdout.take(OUTPUT_LIMIT + 1);
        let _ = tokio::join!(stdout.read_to_end(&mut out), said);
        child.wait().await
    };
    let ran = match tokio::time::timeout(PATIENCE, ran).await {
        Err(_) => return Err(format!("git {}: not done in {} s", args[0], PATIENCE.as_secs())),
        Ok(Err(e)) => return Err(format!("running git: {e}")),
        Ok(Ok(ran)) => ran,
    };
    if out.len() as u64 > OUTPUT_LIMIT {
        return Err(format!("git {}: more than {OUTPUT_LIMIT} bytes to say", args[0]));
    }
    // (SIGXFSZ: it tried to write a file past the limit.)
    if std::os::unix::process::ExitStatusExt::signal(&ran) == Some(25) {
        return Err(format!("git {}: more than {limit} bytes in a file", args[0]));
    }
    match ran.success() {
        true => Ok(out),
        false => {
            let said = String::from_utf8_lossy(&said);
            Err(format!(
                "git {}: {}",
                args[0],
                said.trim().lines().last().unwrap_or("failed")
            ))
        }
    }
}

/// Fetch `rev` of the repository at `url` into the bare repository `dir` (made if it
/// is not there) and read the files under `path`.
pub async fn fetch_git(
    dir: &Path,
    url: &str,
    rev: Option<&str>,
    path: Option<&str>,
    local: bool,
    pins: &[String],
) -> Fallible<Fetched> {
    fetch_within(DISK_LIMIT, dir, url, rev, path, local, pins).await
}

/// What `dir` holds, in bytes (links are not followed).
fn disk_used(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut used = 0;
    for entry in entries.flatten() {
        match entry.metadata() {
            Ok(meta) if meta.is_dir() => used += disk_used(&entry.path()),
            Ok(meta) => used += meta.len(),
            Err(_) => {}
        }
    }
    used
}

/// [`fetch_git`] with a bound on the disk: git writes no file past `limit`, and a
/// repository that holds more than that after the fetch is dropped.
async fn fetch_within(
    limit: u64,
    dir: &Path,
    url: &str,
    rev: Option<&str>,
    path: Option<&str>,
    local: bool,
    pins: &[String],
) -> Fallible<Fetched> {
    url_allowed(url, local)?;
    if !pins.is_empty() {
        // (An older git takes the setting that pins it for nothing, and says nothing.)
        // (Asked from a directory that is there: the clone's may not be yet.)
        let version = git(limit, Path::new("/"), local, &[], &["version"]).await?;
        if !pinnable(&String::from_utf8_lossy(&version)) {
            return Err("this node's git is older than 2.37: it cannot be held to the address that was checked".into());
        }
    }
    let rev = rev.unwrap_or("HEAD");
    rev_allowed(rev)?;
    let path = path.map(|path| path.trim_matches('/')).filter(|path| !path.is_empty());
    path.map_or(Ok(()), path_allowed)?;
    if !dir.join("HEAD").exists() {
        let failed = |e: std::io::Error| format!("{}: {e}", dir.display());
        tokio::fs::create_dir_all(dir).await.map_err(failed)?;
        git(limit, dir, local, pins, &["init", "--quiet", "--bare", "."]).await?;
    }
    let fetch = [
        "fetch",
        "--quiet",
        "--depth=1",
        "--no-tags",
        "--no-recurse-submodules",
        "--",
        url,
        rev,
    ];
    let fetched = git(limit, dir, local, pins, &fetch).await;
    // (A file is held to `limit`, the repository as a whole is counted here. A fetch that
    // failed may leave half a pack: start again from nothing.)
    // ponytail: the whole is only counted once git is done, in its 120 s: many files each
    // under the limit can fill the disk that far; a quota on the state disk is the upgrade.
    let dir_ = dir.to_path_buf();
    let used = tokio::task::spawn_blocking(move || disk_used(&dir_)).await.unwrap_or(0);
    if fetched.is_err() || used > limit {
        let _ = tokio::fs::remove_dir_all(dir).await;
        return Err(fetched
            .err()
            .unwrap_or_else(|| format!("the repository takes more than {limit} bytes on disk")));
    }
    let text = |bytes: Vec<u8>| String::from_utf8(bytes).map_err(|_| "git said something that is not text".to_string());
    let revision = text(git(limit, dir, local, pins, &["rev-parse", "FETCH_HEAD"]).await?)?
        .trim()
        .to_string();

    // What is there, and how big, before any of it is read.
    let mut list = vec!["ls-tree", "-r", "-l", "-z", "FETCH_HEAD"];
    list.extend(path.iter().flat_map(|path| ["--", *path]));
    // (A name that is not text is no reason to refuse the rest.)
    let listed = git(limit, dir, local, pins, &list).await?;
    let listed = String::from_utf8_lossy(&listed);
    let (mut wanted, mut skipped, mut bytes) = (Vec::new(), Vec::new(), 0u64);
    for entry in listed.split('\0').filter(|entry| !entry.is_empty()) {
        // `<mode> <type> <object> <size>\t<path>`
        let Some((about, name)) = entry.split_once('\t') else {
            continue;
        };
        let about: Vec<&str> = about.split_whitespace().collect();
        let [mode, _, object, size] = about.as_slice() else {
            continue;
        };
        if ![".yaml", ".yml", ".json"].iter().any(|suffix| name.ends_with(suffix)) {
            continue;
        }
        if !mode.starts_with("100") {
            skipped.push(format!("{name}: a link or a repository in the repository, not a file"));
            continue;
        }
        bytes += size.parse::<u64>().unwrap_or(BYTES_LIMIT + 1);
        wanted.push((name.to_string(), object.to_string()));
        if wanted.len() > FILES_LIMIT || bytes > BYTES_LIMIT {
            return Err(format!(
                "more than {FILES_LIMIT} files, or more than {BYTES_LIMIT} bytes in them"
            ));
        }
    }
    let mut files = BTreeMap::new();
    for (name, object) in wanted {
        match String::from_utf8(git(limit, dir, local, pins, &["cat-file", "blob", &object]).await?) {
            Ok(file) => drop(files.insert(name, file)),
            Err(_) => skipped.push(format!("{name}: not text")),
        }
    }
    Ok(Fetched {
        revision,
        files,
        skipped,
        resources: OnceLock::new(),
    })
}

/// The files of the OCI artifact `oci://HOST/PATH/NAME[:TAG]` (as `kith source push`
/// makes one), under `path`. Its revision is the blob's digest.
///
/// `outward`: of a Source that is not the cluster's own, so every connection made for it
/// (the registry, where its tokens come from, where a redirect leads) goes only to an
/// address that was just seen to be outside this node and its networks.
pub async fn fetch_oci(reference: &str, path: Option<&str>, outward: bool) -> Fallible<Fetched> {
    let (url, name) = reference
        .rsplit_once('/')
        .ok_or(format!("{reference}: not oci://HOST/PATH/NAME[:TAG]"))?;
    let (name, tag) = name.split_once(':').unwrap_or((name, "latest"));
    let (blob, _) = crate::registry::pull(url, name, tag, outward).await?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &blob);
    let revision: String = digest.as_ref()[..16].iter().map(|byte| format!("{byte:02x}")).collect();
    let files = kith_packages::artifact::files(&blob)?;
    let path = path
        .map(|path| format!("{}/", path.trim_matches('/')))
        .filter(|path| path != "/");
    let under = |name: &String| path.as_ref().is_none_or(|path| name.starts_with(path.as_str()));
    let wanted = |name: &String| [".yaml", ".yml", ".json"].iter().any(|suffix| name.ends_with(suffix));
    Ok(Fetched {
        revision,
        files: files
            .into_iter()
            .filter(|(name, _)| under(name) && wanted(name))
            .collect(),
        skipped: Vec::new(),
        resources: OnceLock::new(),
    })
}

/// Where the Source `source` keeps its copy of a git repository, under `state`.
fn clone_of(state: &Path, source: &str) -> PathBuf {
    let name = source.strip_prefix("Source/").unwrap_or(source).replace('/', "_");
    state.join("sources").join(format!("{name}.git"))
}

/// The resources in what was fetched for `source`: each in the Source's namespace
/// unless it names one, marked as the Source's, and where a Source may put things.
fn desired(key: &str, fetched: &Fetched) -> Fallible<Vec<Resource>> {
    let home = key.split('/').nth(1).unwrap_or_default();
    let mut resources: Vec<Resource> = Vec::new();
    for (path, text) in &fetched.files {
        let shown = |e: kith_yaml::Error| e.render(path, text);
        for document in kith_yaml::parse(text).map_err(shown)? {
            let placed = document
                .get("metadata")
                .is_some_and(|metadata| metadata.get("namespace").is_some());
            let mut resource = Resource::from_node(&document).map_err(shown)?;
            // (A kind some KindDefinition makes is placed when the store is at hand: `settled`.)
            let own = kith_api::kind(&resource.kind);
            let scoped = own.is_some_and(|kind| kind.namespaced);
            if !placed && scoped {
                resource.metadata.namespace = Some(home.to_string());
            }
            let at = resource.key();
            if home != "kith-system" && own.is_some() {
                if !scoped || resource.kind == "Source" {
                    return Err(format!(
                        "{path}: {at}: only a Source in kith-system gets to make a {}",
                        resource.kind
                    ));
                }
                if resource.metadata.namespace.as_deref() != Some(home) {
                    return Err(format!(
                        "{path}: {at}: a Source stays in its own namespace ({home}) unless it is in kith-system"
                    ));
                }
            }
            if at == key {
                return Err(format!("{path}: {at}: a Source does not apply itself"));
            }
            if resources.iter().any(|other| other.key() == at) {
                return Err(format!("{path}: {at} is in the source twice"));
            }
            (resource.metadata.revision, resource.status) = (None, None);
            resource.metadata.annotations.insert(OWNER.into(), key.to_string());
            resources.push(resource);
        }
    }
    Ok(resources)
}

/// A message with nothing in it for a terminal to act on (it may quote a file's name
/// or what a server said).
fn plain(message: &str) -> String {
    message.chars().filter(|c| !c.is_control() || *c == '\n').collect()
}

/// `resources` (see `desired`) with those of kinds a `KindDefinition` makes put where
/// such a kind lives, and kept where a Source may put things. The definition is the
/// store's, or one the source brings along.
fn settled<'a>(store: &Store, key: &str, resources: &'a [Resource]) -> Fallible<std::borrow::Cow<'a, [Resource]>> {
    let custom = |resource: &Resource| kith_api::kind(&resource.kind).is_none();
    if !resources.iter().any(custom) {
        return Ok(resources.into());
    }
    let home = key.split('/').nth(1).unwrap_or_default();
    let mut kinds = crate::releases::custom_kinds(store);
    let brought = resources.iter().filter(|resource| resource.kind == "KindDefinition");
    kinds.extend(brought.map(|definition| {
        let kind = definition.spec["kind"].as_str().unwrap_or_default();
        (kind.to_string(), definition.spec["namespaced"] != false)
    }));
    let mut resources = resources.to_vec();
    let mut seen = BTreeSet::new();
    for resource in &mut resources {
        // (A kind nothing makes is for the store to refuse, in its words.)
        let scoped = match kinds.get(&resource.kind) {
            Some(scoped) if custom(resource) => *scoped,
            _ => {
                seen.insert(resource.key());
                continue;
            }
        };
        if scoped && resource.metadata.namespace.is_none() {
            resource.metadata.namespace = Some(home.to_string());
        }
        let at = resource.key();
        if home != "kith-system" && !scoped {
            return Err(format!(
                "{at}: only a Source in kith-system gets to make a {}",
                resource.kind
            ));
        }
        if home != "kith-system" && resource.metadata.namespace.as_deref() != Some(home) {
            return Err(format!(
                "{at}: a Source stays in its own namespace ({home}) unless it is in kith-system"
            ));
        }
        if !seen.insert(at.clone()) {
            return Err(format!("{at} is in the source twice"));
        }
    }
    Ok(resources.into())
}

/// What was fetched for each Source, or why it could not be.
type Fetches = BTreeMap<String, Result<Fetched, String>>;

/// What the store needs done for its Sources, given what was fetched.
fn plan(store: &Store, fetches: &Fetches) -> Vec<Step> {
    let mut steps = Vec::new();
    // What the Sources before this one (by key) keep: a resource is one Source's.
    let mut claimed = BTreeSet::new();
    for source in store.list(Some("Source")) {
        let key = source.key();
        let Some(fetched) = fetches.get(&key) else {
            continue;
        };
        let Ok(spec) = serde_json::from_value::<SourceSpec>(source.spec.clone()) else {
            continue;
        };
        let live = source.status.as_ref();
        let mut step = Step {
            release: key.clone(),
            apply: Vec::new(),
            delete: Vec::new(),
            status: None,
        };
        // (Worked out once for each fetch, not each time the store changes.)
        let done = fetched.as_ref().map_err(String::clone).and_then(|fetched| {
            let resources = fetched.resources.get_or_init(|| desired(&key, fetched));
            let resources = settled(store, &key, resources.as_ref().map_err(String::clone)?)?;
            // (What another owns now is no longer ours, whatever we recorded: else two
            // Sources that named one resource take it back from each other for ever.)
            let ours = |at: &&str| {
                store
                    .get(at)
                    .is_none_or(|live| owner(live).is_none_or(|owner| owner == key))
            };
            let before: BTreeSet<&str> = recorded(source).into_iter().filter(ours).collect();
            let done = reconcile(store, &key, &before, &resources, spec.prune == Some(true))?;
            // (And one that an earlier Source in this very pass took is that Source's.)
            if let Some(at) = done.kept.iter().find(|at| claimed.contains(at.as_str())) {
                return Err(format!("{at} is there already and is not {key}'s"));
            }
            Ok((fetched, done))
        });
        let status = match done {
            // (What was applied before stays as it is.)
            Err(e) => json!({ "state": "error", "message": plain(&e), "observedRevision": source.metadata.revision }),
            Ok((fetched, done)) => {
                claimed.extend(done.kept.iter().cloned());
                let synced = live.is_some_and(|live| live["revision"] == fetched.revision.as_str());
                let held =
                    matches!(spec.approval, Some(Approval::Manual)) && spec.approve.as_ref() != Some(&fetched.revision);
                if held && !synced {
                    // A revision nobody approved: what it would do, and nothing done.
                    let removed = done.delete.iter().map(|key| format!("-{key}"));
                    let changes: Vec<String> = done.apply.iter().map(Resource::key).chain(removed).collect();
                    json!({
                        "state": "pending", "message": null, "skipped": fetched.skipped,
                        "pending": { "revision": fetched.revision, "changes": changes },
                        "observedRevision": source.metadata.revision,
                    })
                } else {
                    let mut status = json!({
                        "state": "synced", "message": null, "revision": fetched.revision, "pending": null,
                        "resources": done.kept, "skipped": fetched.skipped, "observedRevision": source.metadata.revision,
                    });
                    // Changed since this very revision was applied: someone's doing,
                    // undone. (The list stays until a new revision or more drift.)
                    if synced && !done.differ.is_empty() {
                        status["drift"] = json!(done.differ);
                    } else if !synced {
                        status["drift"] = json!([]);
                    }
                    (step.apply, step.delete) = (done.apply, done.delete);
                    status
                }
            }
        };
        let Value::Object(status) = status else {
            unreachable!("an object")
        };
        if !status
            .iter()
            .all(|(field, value)| live.is_some_and(|live| &live[field] == value))
        {
            step.status = Some(status);
        }
        if !step.apply.is_empty() || !step.delete.is_empty() || step.status.is_some() {
            steps.push(step);
        }
    }
    steps
}

/// How often a Source is fetched when it does not say, and the least it may say.
const INTERVAL: u64 = 60;
const LEAST_INTERVAL: u64 = 5;

/// How often `source` asks to be fetched.
fn interval(source: &SourceSpec) -> Duration {
    Duration::from_secs(u64::from(source.interval_seconds.unwrap_or(INTERVAL as u32)).max(LEAST_INTERVAL))
}

/// How long to leave a Source that failed `failed` times in a row: its interval, doubled
/// for each, up to an hour (never less than the interval).
fn backed_off(every: Duration, failed: u32) -> Duration {
    every.saturating_mul(1 << failed.min(10)).min(BACKOFF_LIMIT).max(every)
}

/// Fetch what `source` (the Source `key`, of the spec `about`) points at.
async fn fetch_one(
    state: PathBuf,
    local: bool,
    key: String,
    source: SourceSpec,
    about: Value,
) -> (String, Value, Fallible<Fetched>) {
    let named = source.git.as_ref().map(|git| &git.url).or(source.oci.as_ref());
    let own = key.starts_with("Source/kith-system/") || (local && source.git.is_some());
    let allowed = match named.filter(|_| !own) {
        Some(url) => outward(url).await,
        None => Ok(Vec::new()),
    };
    let outward = named.is_some() && !own;
    let got = match (&source.git, &source.oci, allowed) {
        (_, _, Err(refused)) => Err(refused),
        (Some(git), _, Ok(pins)) => {
            let dir = clone_of(&state, &key);
            fetch_git(&dir, &git.url, git.rev.as_deref(), source.path.as_deref(), local, &pins).await
        }
        (None, Some(oci), _) => fetch_oci(oci, source.path.as_deref(), outward).await,
        (None, None, _) => Err("neither git nor oci".into()),
    };
    // (Read here, not while the store is held.)
    if let Ok(fetched) = &got {
        fetched.resources.get_or_init(|| desired(&key, fetched));
    }
    (key, about, got)
}

/// Keep the Sources synced, as long as this node leads the store, until told to stop.
/// Git repositories are kept under `state`; `local` lets a Source name a `file://` one.
pub async fn run(shared: Arc<Shared>, state: PathBuf, local: bool, mut stopping: watch::Receiver<bool>) {
    let mut generation = shared.generation.subscribe();
    let mut fetches = Fetches::new();
    // (When each was fetched, and from what spec: a changed Source is fetched at once.)
    // (And how many fetches in a row failed: see `backed_off`.)
    let mut fetched: BTreeMap<String, (Value, tokio::time::Instant, u32)> = BTreeMap::new();
    loop {
        let metrics = shared.raft.metrics().borrow().clone();
        let mut next = Duration::from_secs(INTERVAL);
        nodes(&shared).await;
        if metrics.current_leader == Some(metrics.id) {
            let sources: Vec<(String, Value)> = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                let sources = state.store.list(Some("Source"));
                sources.map(|source| (source.key(), source.spec.clone())).collect()
            };
            let there: BTreeSet<&String> = sources.iter().map(|(key, _)| key).collect();
            for gone in fetched.keys().filter(|key| !there.contains(key)) {
                let _ = tokio::fs::remove_dir_all(clone_of(&state, gone)).await;
            }
            fetched.retain(|key, _| there.contains(key));
            fetches.retain(|key, _| there.contains(key));
            let mut due = Vec::new();
            for (key, spec) in &sources {
                let Ok(source) = serde_json::from_value::<SourceSpec>(spec.clone()) else {
                    continue;
                };
                // (`approve` is no reason to fetch again: it is about what was fetched.)
                let mut about = spec.clone();
                about.as_object_mut().map(|about| about.remove("approve"));
                let ready = fetched.get(key).is_none_or(|(was, at, failed)| {
                    *was != about || at.elapsed() >= backed_off(interval(&source), *failed)
                });
                if ready {
                    due.push((key.clone(), source, about));
                }
            }
            // (Several at once: a slow or dead one holds the rest no longer than its own
            // time. A fetch that panicked is not in `done`, and is tried again next time.)
            let (mut waiting, mut running, mut done) = (due.into_iter(), tokio::task::JoinSet::new(), Vec::new());
            loop {
                while running.len() < FETCHES_AT_ONCE
                    && let Some((key, source, about)) = waiting.next()
                {
                    running.spawn(fetch_one(state.clone(), local, key, source, about));
                }
                match running.join_next().await {
                    None => break,
                    Some(finished) => done.extend(finished),
                }
            }
            for (key, about, got) in done {
                // (A changed Source starts again: what failed was another spec.)
                let was = fetched
                    .get(&key)
                    .filter(|(was, ..)| *was == about)
                    .map_or(0, |(.., n)| *n);
                let failed = if got.is_err() { was.saturating_add(1) } else { 0 };
                fetches.insert(key.clone(), got);
                fetched.insert(key, (about, tokio::time::Instant::now(), failed));
            }
            for (key, spec) in &sources {
                let Ok(source) = serde_json::from_value::<SourceSpec>(spec.clone()) else {
                    continue;
                };
                let every = interval(&source);
                let left = fetched.get(key).map_or(every, |(_, at, failed)| {
                    backed_off(every, *failed).saturating_sub(at.elapsed())
                });
                next = next.min(left.max(Duration::from_secs(1)));
            }
            let steps = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                plan(&state.store, &fetches)
            };
            carry_out(&shared, steps, Vec::new()).await;
        }
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(next) => {}
            _ = stopping.changed() => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_a_source_may_name() {
        assert!(url_allowed("https://example.org/a.git", false).is_ok());
        assert!(url_allowed("ssh://git@example.org/a.git", false).is_ok());
        for url in [
            "file:///etc",
            "/etc",
            "ext::sh -c id",
            "git@example.org:a.git",
            "--upload-pack=id",
            "http://x",
        ] {
            assert!(url_allowed(url, false).is_err(), "{url}");
        }
        assert!(url_allowed("file:///tmp/a", true).is_ok() && url_allowed("ext::sh", true).is_err());
        assert!(rev_allowed("main").is_ok() && rev_allowed("v1.2").is_ok() && rev_allowed("release/1").is_ok());
        for rev in ["", "-x", "--upload-pack=id", "a..b", "a b", "a:b", "a^{}"] {
            assert!(rev_allowed(rev).is_err(), "{rev}");
        }
        for (url, at) in [
            ("https://example.org/a.git", "example.org"),
            ("ssh://git@example.org:22/a", "example.org"),
            ("oci://[::1]:5000/x/y", "::1"),
            ("https://user:pass@10.0.0.1:8080/a", "10.0.0.1"),
            ("https:///a", ""),
        ] {
            assert_eq!(host(url), at);
        }
        for ip in ["8.8.8.8", "2606:4700::1111", "100.128.0.1"] {
            assert!(!inward(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:7f00:1",
            "::127.0.0.1",
        ] {
            assert!(inward(ip.parse().unwrap()), "{ip}");
        }
        assert!(path_allowed("clusters/prod").is_ok());
        for path in ["../x", "a/../b", "/abs", "a//b", "-x", ":(top)"] {
            assert!(path_allowed(path).is_err(), "{path}");
        }
    }

    /// However this node or its networks are spelt, a namespace's Source is not fetched
    /// from them, nor over ssh.
    #[tokio::test]
    async fn a_namespaces_source_is_fetched_from_outside_only() {
        for url in [
            "https://localhost/a",
            "https://127.0.0.1:8080/a",
            "oci://[::1]:5000/x/y",
            "https://[::ffff:7f00:1]/x",
            "https://2130706433/a",
            "https://0x7f.1/a",
            "https://user@10.1.2.3/a",
            "https:///a",
            "ssh://git@8.8.8.8/a",
            // What one reader of a URL ends the host at and another does not.
            "https://127.0.0.1#@8.8.8.8/a",
            "https://127.0.0.1:8080#@8.8.8.8/a", // pragma: allowlist secret
            "https://8.8.8.8/a?b",
            "https://127.0.0.1\\@8.8.8.8/a",
            "https://8.8.8.8:x/a",
            "https://user@8.8.8.8/a",
            "https://[2002:7f00:1::1]/a",
            "https://[64:ff9b::a00:1]/a",
            "https://[fec0::1]/a",
        ] {
            assert!(outward(url).await.is_err(), "{url}");
        }
        assert_eq!(
            outward("https://8.8.8.8/x").await,
            Ok(vec!["8.8.8.8:443:8.8.8.8".to_string()])
        );
        assert_eq!(
            outward("https://8.8.8.8:8443/x").await,
            Ok(vec!["8.8.8.8:8443:8.8.8.8".to_string()])
        );
        // A Node's public address, and this machine's own (whatever a socket binds to).
        assert!(outward("https://8.8.4.4/x").await.is_ok());
        NODES.lock().unwrap().push("8.8.4.4".parse().unwrap());
        assert!(outward("https://8.8.4.4/x").await.is_err());
        assert!(outward("https://[::ffff:8.8.4.4]/x").await.is_err());
        NODES.lock().unwrap().clear();
        assert!(ours("127.0.0.1".parse().unwrap()) && !ours("8.8.8.8".parse().unwrap()));
        assert_eq!(super::at("2001:db8::1".parse().unwrap()), "[2001:db8::1]");
        assert!(
            pinnable("git version 2.37.0") && pinnable("git version 3.0.1") && pinnable("git version 2.56.0.windows.1")
        );
        assert!(!pinnable("git version 2.36.9") && !pinnable("git version 1.99") && !pinnable("nonsense"));
        assert_eq!(plain("a\x1b[2Jb\nc"), "a[2Jb\nc");
    }

    /// git goes to the address it was told, whatever the name would answer (this one answers nothing).
    #[tokio::test]
    async fn pinned_git_connects_where_it_was_vetted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = std::env::temp_dir().join(format!("kith-pinned-{}", std::process::id()));
        let url = format!("https://kith-pinned.invalid:{port}/x.git");
        let pins = [format!("kith-pinned.invalid:{port}:127.0.0.1")];
        let fetch = fetch_git(&dir, &url, None, None, false, &pins);
        let reached = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::select! {
                accepted = listener.accept() => accepted.is_ok(),
                _ = fetch => false,
            }
        });
        let reached = reached.await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(reached, Ok(true), "git did not connect to the pinned address");
    }

    fn apply(store: &mut Store, source: &str) {
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
    }

    /// Carry the plan out until there is nothing to do.
    fn settle(store: &mut Store, fetches: &Fetches) {
        for _ in 0..10 {
            let mut steps = plan(store, fetches);
            let orphans: Vec<String> = {
                let gone = |resource: &&Resource| {
                    crate::releases::owner(resource).is_some_and(|owner| store.get(owner).is_none())
                };
                store.list(None).filter(gone).map(Resource::key).collect()
            };
            if steps.is_empty() && orphans.is_empty() {
                return;
            }
            for step in steps.drain(..) {
                store.apply_all(step.apply).unwrap();
                for key in step.delete {
                    store.delete(&key).unwrap();
                }
                if let Some(fields) = step.status {
                    let live = store.get(&step.release).and_then(|r| r.status.clone());
                    let mut status = live.unwrap_or(json!({}));
                    status.as_object_mut().unwrap().extend(fields);
                    store.set_status(&step.release, Some(status)).unwrap();
                }
            }
            for key in orphans {
                store.delete(&key).unwrap();
            }
        }
        panic!("the sources never settle");
    }

    fn map(name: &str, colour: &str) -> String {
        format!(
            "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: {{ name: {name} }}\nspec: {{ data: {{ colour: {colour} }} }}\n"
        )
    }

    fn at(revision: &str, files: &[(&str, String)]) -> Fetches {
        let fetched = Fetched {
            revision: revision.into(),
            files: files
                .iter()
                .map(|(path, text)| (path.to_string(), text.clone()))
                .collect(),
            skipped: Vec::new(),
            resources: OnceLock::new(),
        };
        Fetches::from([("Source/shop/repo".to_string(), Ok(fetched))])
    }

    const SOURCE: &str = "apiVersion: kith.dev/v1\nkind: Source\nmetadata: { name: repo, namespace: shop }\n\
                          spec: { git: { url: 'https://example.org/a.git' }, prune: true }\n";

    #[test]
    fn a_source_is_applied_pruned_and_put_back() {
        let mut store = Store::default();
        let status = |store: &Store| store.get("Source/shop/repo").unwrap().status.clone().unwrap();
        let colour = |store: &Store, name: &str| {
            store
                .get(&format!("ConfigMap/shop/{name}"))
                .map(|map| map.spec["data"]["colour"].clone())
        };
        apply(&mut store, SOURCE);
        // Two files, three maps: in the Source's namespace, marked as its own.
        let both = format!("{}---\n{}", map("a", "red"), map("b", "red"));
        settle(
            &mut store,
            &at("r1", &[("x/one.yaml", both.clone()), ("x/two.yaml", map("c", "red"))]),
        );
        assert_eq!(
            (&status(&store)["state"], &status(&store)["revision"]),
            (&json!("synced"), &json!("r1"))
        );
        assert_eq!(status(&store)["resources"].as_array().unwrap().len(), 3);
        assert_eq!(
            crate::releases::owner(store.get("ConfigMap/shop/c").unwrap()),
            Some("Source/shop/repo")
        );

        // The source moves on: one map changes, one is gone from it and from here.
        let next = at(
            "r2",
            &[("x/one.yaml", format!("{}---\n{}", map("a", "blue"), map("b", "red")))],
        );
        settle(&mut store, &next);
        assert_eq!((colour(&store, "a"), colour(&store, "c")), (Some(json!("blue")), None));
        assert_eq!(status(&store)["drift"], json!([]));

        // Someone changes what the source says: put back, and said.
        let mut edited = store.get("ConfigMap/shop/b").unwrap().clone();
        (edited.spec["data"]["colour"], edited.metadata.revision) = (json!("pink"), None);
        store.apply(edited).unwrap();
        settle(&mut store, &next);
        assert_eq!(colour(&store, "b"), Some(json!("red")));
        assert_eq!(status(&store)["drift"], json!(["ConfigMap/shop/b"]));

        // A file that is no resource: said, and what is applied stays.
        let broken = at("r3", &[("x/one.yaml", "kind: ConfigMap\nmetadata: [".to_string())]);
        settle(&mut store, &broken);
        assert_eq!(status(&store)["state"], "error");
        assert!(status(&store)["message"].as_str().unwrap().contains("x/one.yaml"));
        assert_eq!(colour(&store, "a"), Some(json!("blue")));
        // The repository cannot be reached: the same.
        let unreachable = Fetches::from([("Source/shop/repo".to_string(), Err("git fetch: no route".to_string()))]);
        settle(&mut store, &unreachable);
        assert_eq!(status(&store)["message"], "git fetch: no route");

        // Without prune, what the source drops stays; the Source gone, all of it goes.
        apply(&mut store, &SOURCE.replace("prune: true", "prune: false"));
        settle(&mut store, &at("r4", &[("y.yaml", map("b", "red"))]));
        assert_eq!(colour(&store, "a"), Some(json!("blue")));
        store.delete("Source/shop/repo").unwrap();
        settle(&mut store, &Fetches::new());
        assert_eq!((colour(&store, "a"), colour(&store, "b")), (None, None));
    }

    #[test]
    fn a_source_waits_to_be_approved() {
        let mut store = Store::default();
        let status = |store: &Store| store.get("Source/shop/repo").unwrap().status.clone().unwrap();
        let manual = |approve: &str| SOURCE.replace("prune: true", &format!("prune: true, approval: manual{approve}"));
        apply(&mut store, &manual(""));
        let first = at("r1", &[("a.yaml", map("a", "red"))]);
        settle(&mut store, &first);
        assert_eq!(status(&store)["state"], "pending");
        assert_eq!(
            status(&store)["pending"],
            json!({ "revision": "r1", "changes": ["ConfigMap/shop/a"] })
        );
        assert!(store.get("ConfigMap/shop/a").is_none());
        // Approved: applied. Another revision was approved: not this one.
        apply(&mut store, &manual(", approve: r0"));
        settle(&mut store, &first);
        assert!(store.get("ConfigMap/shop/a").is_none());
        apply(&mut store, &manual(", approve: r1"));
        settle(&mut store, &first);
        assert_eq!(
            (&status(&store)["state"], &status(&store)["pending"]),
            (&json!("synced"), &Value::Null)
        );
        // The source moves on: held again, with what it would do; what runs is r1 still.
        let second = at("r2", &[("b.yaml", map("b", "red"))]);
        settle(&mut store, &second);
        let now = status(&store);
        assert_eq!((&now["state"], &now["revision"]), (&json!("pending"), &json!("r1")));
        assert_eq!(
            now["pending"]["changes"],
            json!(["ConfigMap/shop/b", "-ConfigMap/shop/a"])
        );
        assert!(store.get("ConfigMap/shop/a").is_some() && store.get("ConfigMap/shop/b").is_none());
    }

    #[test]
    fn a_source_keeps_to_its_namespace() {
        let mut store = Store::default();
        let message = |store: &Store, key: &str| store.get(key).unwrap().status.clone().unwrap()["message"].to_string();
        apply(&mut store, SOURCE);
        // Someone else's map of that name; another namespace; a kind in no namespace; a Source.
        apply(
            &mut store,
            &map("a", "theirs").replace("name: a", "name: a, namespace: shop"),
        );
        settle(&mut store, &at("r1", &[("a.yaml", map("a", "red"))]));
        assert!(message(&store, "Source/shop/repo").contains("ConfigMap/shop/a is there already"));
        assert_eq!(store.get("ConfigMap/shop/a").unwrap().spec["data"]["colour"], "theirs");
        let elsewhere = map("z", "red").replace("name: z", "name: z, namespace: kith-system");
        settle(&mut store, &at("r1", &[("z.yaml", elsewhere.clone())]));
        assert!(message(&store, "Source/shop/repo").contains("a Source stays in its own namespace (shop)"));
        let repository = "apiVersion: kith.dev/v1\nkind: Repository\nmetadata: { name: theirs }\nspec: { url: 'oci://example.org/x' }\n";
        settle(&mut store, &at("r1", &[("r.yaml", repository.to_string())]));
        assert!(message(&store, "Source/shop/repo").contains("only a Source in kith-system gets to make a Repository"));
        settle(
            &mut store,
            &at("r1", &[("s.yaml", SOURCE.replace("name: repo", "name: more"))]),
        );
        assert!(message(&store, "Source/shop/repo").contains("only a Source in kith-system gets to make a Source"));
        settle(
            &mut store,
            &at("r1", &[("a.yaml", map("q", "red")), ("b.yaml", map("q", "blue"))]),
        );
        assert!(message(&store, "Source/shop/repo").contains("ConfigMap/shop/q is in the source twice"));

        // The cluster's own Source: anywhere, anything but itself.
        apply(&mut store, &SOURCE.replace("namespace: shop", "namespace: kith-system"));
        let system = Fetches::from([(
            "Source/kith-system/repo".to_string(),
            at("r1", &[("z.yaml", elsewhere), ("r.yaml", repository.to_string())])
                .remove("Source/shop/repo")
                .unwrap(),
        )]);
        settle(&mut store, &system);
        assert!(store.get("Repository/theirs").is_some() && store.get("ConfigMap/kith-system/z").is_some());
        let itself = SOURCE.replace("namespace: shop", "namespace: kith-system");
        let system = Fetches::from([(
            "Source/kith-system/repo".to_string(),
            at("r2", &[("s.yaml", itself)]).remove("Source/shop/repo").unwrap(),
        )]);
        settle(&mut store, &system);
        assert!(message(&store, "Source/kith-system/repo").contains("a Source does not apply itself"));
    }

    /// Kinds a KindDefinition makes go where such a kind lives, and no further than a
    /// Source may reach; a source may bring the definition along.
    #[test]
    fn a_source_applies_kinds_that_are_defined() {
        let mut store = Store::default();
        let message = |store: &Store, key: &str| store.get(key).unwrap().status.clone().unwrap()["message"].to_string();
        let definition = |kind: &str, scoped: bool| {
            format!(
                "apiVersion: kith.dev/v1\nkind: KindDefinition\nmetadata: {{ name: {} }}\n\
                 spec: {{ group: games.example.com, version: v1, kind: {kind}, namespaced: {scoped}, schema: {{ type: object }} }}\n",
                kind.to_lowercase()
            )
        };
        let of = |kind: &str, name: &str| {
            format!("apiVersion: games.example.com/v1\nkind: {kind}\nmetadata: {{ name: {name} }}\n")
        };
        apply(&mut store, &SOURCE.replace("namespace: shop", "namespace: kith-system"));
        let brought = [
            definition("GameServer", true),
            definition("Realm", false),
            of("GameServer", "one"),
            of("Realm", "north"),
        ];
        let system = Fetches::from([(
            "Source/kith-system/repo".to_string(),
            at("r1", &[("all.yaml", brought.join("---\n"))])
                .remove("Source/shop/repo")
                .unwrap(),
        )]);
        settle(&mut store, &system);
        assert!(store.get("GameServer/kith-system/one").is_some() && store.get("Realm/north").is_some());

        apply(&mut store, SOURCE);
        let mut both = system.clone();
        both.extend(at("r1", &[("two.yaml", of("GameServer", "two"))]));
        settle(&mut store, &both);
        assert!(store.get("GameServer/shop/two").is_some());
        both.extend(at("r2", &[("two.yaml", of("Realm", "south"))]));
        settle(&mut store, &both);
        assert!(message(&store, "Source/shop/repo").contains("only a Source in kith-system gets to make a Realm"));
        both.extend(at("r3", &[("two.yaml", of("Nothing", "x"))]));
        assert!(
            plan(&store, &both)
                .iter()
                .any(|step| step.apply.iter().any(|resource| resource.kind == "Nothing"))
        );
    }

    /// Two Sources that name one resource end with one owner, the same one however
    /// they came to the store and however often it settles.
    #[test]
    fn two_sources_claiming_one_resource_settle_the_same_way() {
        let owner = |store: &Store| crate::releases::owner(store.get("ConfigMap/shop/a").unwrap()).map(str::to_string);
        let status = |store: &Store, key: &str| store.get(key).unwrap().status.clone().unwrap();
        for names in [["one", "two"], ["two", "one"]] {
            let mut store = Store::default();
            let mut fetches = Fetches::new();
            for name in names {
                apply(&mut store, &SOURCE.replace("name: repo", &format!("name: {name}")));
                let fetched = at("r1", &[("a.yaml", map("a", name))])
                    .remove("Source/shop/repo")
                    .unwrap();
                fetches.insert(format!("Source/shop/{name}"), fetched);
            }
            settle(&mut store, &fetches);
            let first = owner(&store);
            assert!(first.is_some());
            for _ in 0..3 {
                settle(&mut store, &fetches);
                assert_eq!(owner(&store), first);
            }
            // (The one that sorts first, however they were applied; the other is told.)
            assert_eq!(first.as_deref(), Some("Source/shop/one"));
            assert_eq!(status(&store, "Source/shop/one")["state"], "synced");
            assert_eq!(status(&store, "Source/shop/two")["state"], "error");
        }
    }

    /// A Source that keeps failing is left longer each time, up to an hour, and no
    /// less than its own interval.
    #[test]
    fn a_failing_source_is_fetched_less_and_less() {
        let every = Duration::from_secs(60);
        let waits: Vec<u64> = (0..8).map(|failed| backed_off(every, failed).as_secs()).collect();
        assert_eq!(waits, [60, 120, 240, 480, 960, 1920, 3600, 3600]);
        assert_eq!(backed_off(every, u32::MAX), BACKOFF_LIMIT);
        let long = Duration::from_secs(7200);
        assert_eq!(backed_off(long, 0), long);
        assert_eq!(backed_off(long, 5), long);
    }

    fn sh(dir: &Path, script: &str) {
        let done = std::process::Command::new("sh")
            .current_dir(dir)
            .args(["-c", script])
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap();
        assert!(done.success(), "{script}");
    }

    /// A repository with a file git cannot make small is not fetched past the bound; a
    /// small one is; and what a directory holds is counted.
    #[tokio::test]
    async fn a_fetch_over_the_disk_bound_is_refused() {
        let root = std::env::temp_dir().join(format!("kith-bound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let origin = root.join("origin");
        std::fs::create_dir_all(&origin).unwrap();
        // (A million bytes that do not compress.)
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let noise: Vec<u8> = (0..1 << 20)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect();
        std::fs::write(origin.join("noise.bin"), noise).unwrap();
        std::fs::write(origin.join("a.yaml"), map("a", "red")).unwrap();
        let commit = "git init -q . && git add . && git -c user.name=t -c user.email=t@t commit -qm x";
        sh(&origin, commit);
        let url = format!("file://{}", origin.display());

        let big = fetch_within(256 << 10, &root.join("big.git"), &url, None, None, true, &[]).await;
        assert!(big.is_err(), "{big:?}");
        // (What was fetched is not kept.)
        assert!(!root.join("big.git").exists());
        let fine = fetch_within(64 << 20, &root.join("fine.git"), &url, None, None, true, &[]).await;
        assert!(fine.unwrap().files.contains_key("a.yaml"));

        let held = root.join("held");
        std::fs::create_dir_all(held.join("in")).unwrap();
        std::fs::write(held.join("x"), [0; 3000]).unwrap();
        std::fs::write(held.join("in/y"), [0; 5000]).unwrap();
        assert_eq!(disk_used(&held), 8000);
        let _ = std::fs::remove_dir_all(&root);
    }
}
