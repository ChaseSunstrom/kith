//! A vulnerability scan of an image, on request (`GET /v1/scan/{node}?image=REF`, `kith image scan`).
//!
//! The node reads the package list of the image as it is unpacked here (dpkg's `var/lib/dpkg/status`,
//! apk's `lib/apk/db/installed`, the distribution from `etc/os-release`), sends it to OSV
//! (`https://api.osv.dev/v1/querybatch`: ecosystem, package name and version of each package, and
//! nothing else) and answers each package with the OSV ids that name it. Nothing is pulled (an image
//! the node does not have is not scanned), nothing is kept, and no scan runs but when someone asks.
//!
//! The root part reads the image ([`read`], through `root_part::packages_of`): the store is its own.
//! What it reads is the image's, which anyone who can have an image pulled wrote: a link in it is
//! followed as the container would see it (the image's root is `/`), what is not a regular file is
//! not opened, and what is read is bounded.

use crate::api::{ApiError, Reply, permit_key};
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use kith_api::kinds::Verb;
use kith_api::store::Error;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// One package, as OSV names it: the source package's name, and the version it was built as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
}

/// An image's packages, and the OSV ecosystem they are of (`Debian:12`, `Alpine:v3.19`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Found {
    pub ecosystem: String,
    pub packages: Vec<Package>,
}

/// A package OSV has ids for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hit {
    pub name: String,
    pub version: String,
    pub ids: Vec<String>,
}

/// The most of a package list that is read (a Debian image's is a megabyte or two).
const MOST_LIST: u64 = 16 << 20;
/// The most of `os-release` that is read.
const MOST_OS_RELEASE: u64 = 64 << 10;
/// The links followed in one path: the kernel's own limit is 40.
const MOST_LINKS: usize = 40;
/// The most bytes of packages (names, versions) one answer carries: the root part's reply is one
/// datagram of at most `root_part::socket::MAX_REQUEST` (256 KiB), whatever the image holds.
const MOST_PACKAGES: usize = 200_000;
/// The longest name or version of a package that is taken (Debian's longest are a few dozen).
const MOST_FIELD: usize = 200;
/// OSV's limit of queries in one batch.
const MOST_BATCH: usize = 1000;
/// The most of one OSV answer that is read.
const MOST_ANSWER: usize = 16 << 20;
/// Where OSV is. (The one address: a node asks no other for a scan.)
const OSV: &str = "https://api.osv.dev";

/// The text of the file at `path` in the image whose root is `root`, as a process in the image would
/// open it (the root is `/`: an absolute link is to the image's own, and `..` stops at the root), or
/// `None` where there is no such file, or it is not a regular file. At most `most` bytes.
fn slurp(root: &Path, path: &str, most: u64) -> Result<Option<String>, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut at: Vec<std::ffi::OsString> = Vec::new();
    let mut todo: std::collections::VecDeque<std::ffi::OsString> = path.split('/').map(Into::into).collect();
    let mut links = 0;
    let whole = |at: &[std::ffi::OsString]| root.join(at.iter().collect::<PathBuf>());
    while let Some(part) = todo.pop_front() {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            at.pop();
            continue;
        }
        at.push(part);
        let here = whole(&at);
        let Ok(meta) = std::fs::symlink_metadata(&here) else {
            return Ok(None);
        };
        if meta.file_type().is_symlink() {
            links += 1;
            let target = std::fs::read_link(&here)
                .ok()
                .and_then(|t| t.to_str().map(String::from));
            let (true, Some(target)) = (links <= MOST_LINKS, target) else {
                return Ok(None);
            };
            at.pop();
            if target.starts_with('/') {
                at.clear();
            }
            for part in target.split('/').rev() {
                todo.push_front(part.into());
            }
        }
    }
    // (A pipe is not waited on, and a link swapped in since is not followed.)
    let flags = nix::fcntl::OFlag::O_NONBLOCK | nix::fcntl::OFlag::O_NOFOLLOW;
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits())
        .open(whole(&at));
    let Ok(file) = opened else {
        return Ok(None);
    };
    if !file.metadata().is_ok_and(|meta| meta.is_file()) {
        return Ok(None);
    }
    let mut text = Vec::new();
    file.take(most + 1)
        .read_to_end(&mut text)
        .map_err(|e| format!("reading /{path}: {e}"))?;
    if text.len() as u64 > most {
        return Err(format!("/{path} is larger than {most} bytes"));
    }
    Ok(Some(String::from_utf8_lossy(&text).into_owned()))
}

/// The value of `key` in the lines of an `os-release` (`KEY=value`, `KEY="value"`).
fn os_release(text: &str, key: &str) -> Option<String> {
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))?;
    Some(value.trim().trim_matches(['"', '\'']).to_string())
}

/// The OSV ecosystem of the distribution `id` of `version`, and whether its packages are dpkg's.
fn ecosystem(id: &str, version: &str) -> Result<(String, bool), String> {
    let number = |text: &str| !text.is_empty() && text.len() <= 4 && text.bytes().all(|b| b.is_ascii_digit());
    let mut parts = version.split('.');
    let (major, minor) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    match id {
        "debian" if number(major) => Ok((format!("Debian:{major}"), true)),
        "ubuntu" if number(major) && number(minor) => {
            // (Every April of an even year is a long-term release, which OSV names so.)
            let lts = major.parse::<u32>().is_ok_and(|year| year % 2 == 0) && minor == "04";
            Ok((format!("Ubuntu:{major}.{minor}{}", if lts { ":LTS" } else { "" }), true))
        }
        "alpine" if number(major) && number(minor) => Ok((format!("Alpine:v{major}.{minor}"), false)),
        "debian" | "ubuntu" | "alpine" => Err(format!(
            "this image is `{id}` of no release OSV has (VERSION_ID `{}`)",
            version.escape_debug()
        )),
        _ => Err(format!(
            "this image's distribution, `{}`, is not one a scan knows (Debian, Ubuntu and Alpine are)",
            id.chars().take(40).collect::<String>().escape_debug()
        )),
    }
}

/// A package's name or version, if it is one: what OSV and a terminal can be given as it is.
fn plain(what: &str, text: &str) -> Result<String, String> {
    let fine = |c: char| c.is_ascii_alphanumeric() || ".+-_:~".contains(c);
    match !text.is_empty() && text.len() <= MOST_FIELD && text.chars().all(fine) {
        true => Ok(text.to_string()),
        false => Err(format!(
            "a package {what} that is not one: `{}`",
            text.chars().take(60).collect::<String>().escape_debug()
        )),
    }
}

/// The paragraphs of dpkg's or apk's database, as lists of `(key, value)` (dpkg's `Key: value`, apk's
/// `K:value`; a continuation line of dpkg's, which starts with a blank, is not a key).
fn paragraphs(text: &str, dpkg: bool) -> impl Iterator<Item = Vec<(&str, &str)>> {
    text.split("\n\n").map(move |paragraph| {
        paragraph
            .lines()
            .filter(|line| !line.starts_with([' ', '\t']))
            .filter_map(|line| line.split_once(if dpkg { ": " } else { ":" }))
            .map(|(key, value)| (key, value.trim()))
            .collect()
    })
}

/// The packages of the unpacked image at `rootfs`: its source packages (OSV's advisories are of
/// those), each as many times as it has versions, in the ecosystem of its distribution.
pub fn read(rootfs: &Path) -> Result<Found, String> {
    let dpkg = slurp(rootfs, "var/lib/dpkg/status", MOST_LIST)?;
    let apk = slurp(rootfs, "lib/apk/db/installed", MOST_LIST)?;
    if dpkg.is_none() && apk.is_none() {
        return Err(
            "no package list in this image (dpkg's or apk's): a scan reads those of Debian, Ubuntu and Alpine".into(),
        );
    }
    let release = ["etc/os-release", "usr/lib/os-release"]
        .iter()
        .find_map(|path| slurp(rootfs, path, MOST_OS_RELEASE).transpose())
        .transpose()?
        .ok_or("this image has no /etc/os-release: its distribution is not known")?;
    let (ecosystem, is_dpkg) = ecosystem(
        &os_release(&release, "ID").unwrap_or_default(),
        &os_release(&release, "VERSION_ID").unwrap_or_default(),
    )?;
    let list = if is_dpkg { dpkg } else { apk };
    let Some(list) = list else {
        return Err(format!("no package list in this image for {ecosystem}"));
    };
    let mut found = std::collections::BTreeSet::new();
    for fields in paragraphs(&list, is_dpkg) {
        let get = |key: &str| fields.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
        let (name, version) = if is_dpkg {
            // (Only what is installed: a package removed with its settings kept is not.)
            let installed = get("Status").is_some_and(|status| {
                status
                    .split(' ')
                    .next_back()
                    .is_some_and(|last| !["config-files", "not-installed"].contains(&last))
            });
            let (Some(package), Some(version), true) = (get("Package"), get("Version"), installed) else {
                continue;
            };
            // (`Source: name` or `Source: name (version)`: the version of the source, where it is not the binary's.)
            match get("Source").filter(|source| !source.is_empty()) {
                Some(source) => match source.split_once(' ') {
                    Some((name, rest)) => (name, rest.trim().trim_start_matches('(').trim_end_matches(')')),
                    None => (source, version),
                },
                None => (package, version),
            }
        } else {
            let (Some(package), Some(version)) = (get("P"), get("V")) else {
                continue;
            };
            (get("o").filter(|origin| !origin.is_empty()).unwrap_or(package), version)
        };
        found.insert((plain("name", name)?, plain("version", version)?));
    }
    if found
        .iter()
        .map(|(name, version)| name.len() + version.len() + 40)
        .sum::<usize>()
        > MOST_PACKAGES
    {
        return Err(format!(
            "more packages than a scan takes ({} of them): at most about {MOST_PACKAGES} bytes of names and versions",
            found.len()
        ));
    }
    Ok(Found {
        ecosystem,
        packages: found
            .into_iter()
            .map(|(name, version)| Package { name, version })
            .collect(),
    })
}

/// An OSV id as OSV gives them (`CVE-2023-5678`, `DSA-5532-1`, `GHSA-…`, `USN-…`): what is printed and linked.
fn is_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:".contains(c))
}

/// Each package of `found` that OSV at `base` has ids for (`POST /v1/querybatch`, a thousand at a
/// time: the ecosystem, name and version of each, and nothing more of the node or the image), in the
/// order of `found`, each with its ids sorted. What is not an id is dropped.
pub async fn osv(base: &str, found: &Found) -> Result<Vec<Hit>, String> {
    let url = format!("{base}/v1/querybatch");
    let failed = |e: &dyn std::error::Error| format!("OSV ({url}): {}", crate::cluster::why(e));
    // (A second install is refused, and is no matter.)
    let _ = rustls::crypto::ring::default_provider().install_default();
    // (No proxy, and no redirect: OSV's answer comes from the address that was asked.)
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(60))
        .connect_timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| failed(&e))?;
    let mut hits = Vec::new();
    for batch in found.packages.chunks(MOST_BATCH) {
        let queries: Vec<_> = batch
            .iter()
            .map(|package| {
                serde_json::json!({
                    "package": { "name": package.name, "ecosystem": found.ecosystem },
                    "version": package.version,
                })
            })
            .collect();
        let reply = client
            .post(&url)
            .json(&serde_json::json!({ "queries": queries }))
            .send()
            .await
            .map_err(|e| failed(&e))?;
        if !reply.status().is_success() {
            return Err(format!("OSV ({url}) answered {}", reply.status()));
        }
        let body = crate::acme::capped(reply, &url, MOST_ANSWER)
            .await
            .map_err(|e| format!("OSV: {e}"))?;
        let said: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| format!("OSV ({url}) answered what is not JSON: {e}"))?;
        let results = said["results"]
            .as_array()
            .filter(|results| results.len() == batch.len())
            .ok_or_else(|| {
                format!(
                    "OSV ({url}) did not answer with a result for each of the {} packages",
                    batch.len()
                )
            })?;
        for (package, result) in batch.iter().zip(results) {
            let mut ids: Vec<String> = result["vulns"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|vuln| vuln["id"].as_str())
                .filter(|id| is_id(id))
                .map(String::from)
                .collect();
            ids.sort();
            ids.dedup();
            if !ids.is_empty() {
                hits.push(Hit {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    ids,
                });
            }
        }
    }
    Ok(hits)
}

/// What `GET /v1/scan/{node}?image=REF` is asked: `here` is what a node that passed it on says
/// (it is asked of the one node named, and passed on no further).
#[derive(Deserialize)]
pub struct Asked {
    image: String,
    #[serde(default)]
    here: bool,
}

/// `GET /v1/scan/{node}?image=REF` (`kith image scan`): the packages of the image `REF` as `node`
/// has it unpacked, and the OSV ids of each that OSV has any for. For who may Get the Node; the
/// node named does it (passed on to it, like a unit's logs, from any other), the image is not
/// pulled, and what is asked of OSV is each package's ecosystem, name and version.
pub async fn scan(
    State(shared): State<Arc<crate::Shared>>,
    Extension(caller): Extension<crate::access::Caller>,
    UrlPath(node): UrlPath<String>,
    Query(asked): Query<Asked>,
) -> Reply<serde_json::Value> {
    crate::root_part::label("node", &node).map_err(|e| ApiError::Store(Error::Invalid(e)))?;
    permit_key(&shared, &caller, Verb::Get, &format!("Node/{node}"))?;
    let done = scanned(&shared, &caller, &node, &asked).await;
    // (A scan sends names to a third party: it is in the audit log, whoever asked and whatever came of it.)
    let said = done.as_ref().map(drop).map_err(|e| match e {
        ApiError::Store(e) => e.to_string(),
        ApiError::Refused(why) | ApiError::Unauthorized(why) => why.clone(),
    });
    shared.audit.record(&caller, "scan", vec![format!("Node/{node}")], said);
    done.map(Json)
}

async fn scanned(
    shared: &Arc<crate::Shared>,
    caller: &crate::access::Caller,
    node: &str,
    asked: &Asked,
) -> Result<serde_json::Value, ApiError> {
    let io = |why: String| ApiError::Store(Error::Io(why));
    // (With no cluster there is one node, whatever it is called.)
    let there = match shared.cluster.as_ref() {
        Some(cluster) if cluster.me.name != node => {
            let there = {
                let state = shared.store.lock().expect("a handler panicked holding the store");
                state
                    .store
                    .get(&format!("Node/{node}"))
                    .and_then(crate::view::Upstream::of)
            };
            match (asked.here, there) {
                (true, _) => return Err(ApiError::Refused(format!("{node} is not this node"))),
                (false, None) => {
                    return Err(ApiError::Refused(format!(
                        "{node} is not a node known here with an address"
                    )));
                }
                (false, Some(there)) => Some((cluster, there)),
            }
        }
        _ => None,
    };
    if let Some((cluster, there)) = there {
        let mut url =
            reqwest::Url::parse(&format!("https://{}/v1/scan/", there.address)).map_err(|e| io(e.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| io("an address with no path".into()))?
            .push(node);
        url.query_pairs_mut()
            .append_pair("image", &asked.image)
            .append_pair("here", "true");
        let client = cluster.to(&there).map_err(io)?;
        let answer = crate::access_sign::pass_on(client.get(url))
            .header(crate::access::FOR, caller.to_string())
            .timeout(std::time::Duration::from_secs(300))
            .send()
            .await
            .map_err(|e| io(format!("asking node {node} for a scan: {}", crate::cluster::why(&e))))?;
        let status = answer.status();
        let said: serde_json::Value = answer
            .json()
            .await
            .map_err(|e| io(format!("node {node}'s answer to a scan: {}", crate::cluster::why(&e))))?;
        if status.is_success() {
            return Ok(said);
        }
        let why = said["error"]
            .as_str()
            .map_or(format!("{node} answered {status}"), String::from);
        return Err(match status {
            StatusCode::FORBIDDEN => ApiError::Refused(why),
            StatusCode::UNPROCESSABLE_ENTITY => ApiError::Store(Error::Invalid(why)),
            _ => io(why),
        });
    }
    let image = asked.image.clone();
    image.parse::<oci_client::Reference>().map_err(|_| {
        ApiError::Store(Error::Invalid(format!(
            "`{}` is not an image reference",
            image.escape_debug()
        )))
    })?;
    let named = image.clone();
    let found = tokio::task::spawn_blocking(move || crate::root_part::packages_of(&named))
        .await
        .map_err(|e| io(e.to_string()))?
        .map_err(|why| {
            ApiError::Store(Error::Invalid(why.replacen(
                "is not on this node",
                &format!("is not on node {node}"),
                1,
            )))
        })?;
    let hits = osv(OSV, &found).await.map_err(io)?;
    Ok(serde_json::json!({
        "node": node,
        "image": image,
        "ecosystem": found.ecosystem,
        "packages": found.packages.len(),
        "vulnerable": hits,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn put(root: &Path, path: &str, text: &str) {
        let file = root.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, text).unwrap();
    }

    fn pkg(name: &str, version: &str) -> Package {
        Package {
            name: name.into(),
            version: version.into(),
        }
    }

    const DPKG: &str = "Package: libssl3\nStatus: install ok installed\nVersion: 3.0.11-1~deb12u2\nSource: openssl\n\n\
Package: openssl\nStatus: install ok installed\nVersion: 3.0.11-1~deb12u2\nSource: openssl\n\n\
Package: libc6\nStatus: install ok installed\nVersion: 2.36-9+deb12u4\nSource: glibc (2.36-9+deb12u4)\n\n\
Package: bash\nStatus: install ok installed\nVersion: 5.2.15-2+b2\nSource: bash (5.2.15-2)\n\n\
Package: gone\nStatus: deinstall ok config-files\nVersion: 1.0\n\n\
Package: tzdata\nStatus: install ok installed\nVersion: 2024a-0+deb12u1\n";

    const APK: &str = "C:Q1abc=\nP:libcrypto3\nV:3.1.4-r5\nA:x86_64\no:openssl\nT:Crypto library\n\n\
C:Q1def=\nP:openssl\nV:3.1.4-r5\no:openssl\n\n\
C:Q1ghi=\nP:busybox\nV:1.36.1-r15\no:busybox\n\n\
C:Q1jkl=\nP:alpine-baselayout-data\nV:3.4.3-r2\n\n";

    #[test]
    fn scan_packages_of_a_debian_root_are_its_source_packages_in_the_ecosystem_of_its_release() {
        let root = Scratch::new("scan-deb");
        put(
            &root,
            "etc/os-release",
            "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
        );
        put(&root, "var/lib/dpkg/status", DPKG);
        let found = read(&root).unwrap();
        assert_eq!(found.ecosystem, "Debian:12");
        // (The source package's name, and its version: the binary's own where none is said; once for a source of many binaries; none for what is not installed.)
        assert_eq!(
            found.packages,
            [
                pkg("bash", "5.2.15-2"),
                pkg("glibc", "2.36-9+deb12u4"),
                pkg("openssl", "3.0.11-1~deb12u2"),
                pkg("tzdata", "2024a-0+deb12u1"),
            ]
        );
    }

    #[test]
    fn scan_packages_of_an_alpine_root_are_its_origins_in_its_minor_release() {
        let root = Scratch::new("scan-apk");
        put(
            &root,
            "etc/os-release",
            "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.19.1\n",
        );
        put(&root, "lib/apk/db/installed", APK);
        let found = read(&root).unwrap();
        assert_eq!(found.ecosystem, "Alpine:v3.19");
        assert_eq!(
            found.packages,
            [
                pkg("alpine-baselayout-data", "3.4.3-r2"),
                pkg("busybox", "1.36.1-r15"),
                pkg("openssl", "3.1.4-r5"),
            ]
        );
    }

    #[test]
    fn scan_packages_of_a_ubuntu_lts_root_are_of_its_lts_ecosystem() {
        let root = Scratch::new("scan-ubuntu");
        put(&root, "usr/lib/os-release", "ID=ubuntu\nVERSION_ID=\"22.04\"\n");
        // (As the images have it: `/etc/os-release` is a relative link, and the list is under a link too.)
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::os::unix::fs::symlink("../usr/lib/os-release", root.join("etc/os-release")).unwrap();
        put(
            &root,
            "var/lib/dpkg/status",
            "Package: zlib1g\nStatus: install ok installed\nVersion: 1:1.2.11.dfsg-2ubuntu9.2\nSource: zlib\n",
        );
        let found = read(&root).unwrap();
        assert_eq!(found.ecosystem, "Ubuntu:22.04:LTS");
        assert_eq!(found.packages, [pkg("zlib", "1:1.2.11.dfsg-2ubuntu9.2")]);
    }

    #[test]
    fn scan_packages_never_leave_the_image_for_what_a_link_in_it_names() {
        let outside = Scratch::new("scan-outside");
        put(
            &outside,
            "status",
            "Package: host\nStatus: install ok installed\nVersion: 9\n",
        );
        let root = Scratch::new("scan-link");
        put(&root, "etc/os-release", "ID=debian\nVERSION_ID=12\n");
        // An absolute link is the image's own `/`, not the host's: with no such file there, there is no list.
        std::fs::create_dir_all(root.join("var/lib/dpkg")).unwrap();
        std::os::unix::fs::symlink(outside.join("status"), root.join("var/lib/dpkg/status")).unwrap();
        let why = read(&root).unwrap_err();
        assert!(why.contains("no package list"), "{why}");
        // ..., and a `..` past the root stays at the root.
        std::fs::remove_file(root.join("var/lib/dpkg/status")).unwrap();
        put(
            &root,
            "status",
            "Package: inside\nStatus: install ok installed\nVersion: 1\n",
        );
        std::os::unix::fs::symlink("../../../../../../status", root.join("var/lib/dpkg/status")).unwrap();
        assert_eq!(read(&root).unwrap().packages, [pkg("inside", "1")]);
    }

    #[test]
    fn scan_packages_say_what_they_cannot_read() {
        let root = Scratch::new("scan-none");
        assert!(read(&root).unwrap_err().contains("no package list"));
        // A distribution this does not know, with a list it does.
        put(&root, "etc/os-release", "ID=arch\n");
        put(&root, "var/lib/dpkg/status", DPKG);
        let why = read(&root).unwrap_err();
        assert!(why.contains("arch"), "{why}");
        // A list that is a pipe is not opened (it would wait for a writer).
        let root = Scratch::new("scan-pipe");
        put(&root, "etc/os-release", "ID=debian\nVERSION_ID=12\n");
        std::fs::create_dir_all(root.join("var/lib/dpkg")).unwrap();
        // (`mkfifo` the program: no unsafe here.)
        assert!(
            std::process::Command::new("mkfifo")
                .arg(root.join("var/lib/dpkg/status"))
                .status()
                .unwrap()
                .success()
        );
        assert!(read(&root).unwrap_err().contains("no package list"));
    }

    /// An OSV that answers each query with what `answer` says of its package; the bodies it was asked with come back.
    async fn osv_standin(
        answer: impl Fn(&serde_json::Value) -> serde_json::Value + Send + Sync + 'static,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (seen, answer) = (asked.clone(), std::sync::Arc::new(answer));
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let (seen, answer) = (seen.clone(), answer.clone());
                tokio::spawn(async move {
                    let mut got = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let body = loop {
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        got.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&got).into_owned();
                        if let Some((head, body)) = text.split_once("\r\n\r\n") {
                            let length = head
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|v| v.trim().parse::<usize>().unwrap())
                                })
                                .unwrap_or(0);
                            if body.len() >= length || n == 0 {
                                assert!(head.starts_with("POST /v1/querybatch "), "{head}");
                                break body.to_string();
                            }
                        }
                        if n == 0 {
                            return;
                        }
                    };
                    let asked: serde_json::Value = serde_json::from_str(&body).unwrap();
                    let results: Vec<_> = asked["queries"].as_array().unwrap().iter().map(|q| answer(q)).collect();
                    seen.lock().unwrap().push(asked);
                    let reply = serde_json::json!({ "results": results }).to_string();
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        reply.len()
                    );
                    let _ = socket.write_all(head.as_bytes()).await;
                    let _ = socket.write_all(reply.as_bytes()).await;
                });
            }
        });
        (base, asked)
    }

    fn found(packages: &[(&str, &str)]) -> Found {
        Found {
            ecosystem: "Debian:12".into(),
            packages: packages.iter().map(|(n, v)| pkg(n, v)).collect(),
        }
    }

    #[tokio::test]
    async fn scan_osv_sends_ecosystem_name_and_version_and_returns_each_package_with_its_ids() {
        let (base, asked) = osv_standin(|q| match q["package"]["name"].as_str().unwrap() {
            "openssl" => serde_json::json!({ "vulns": [{ "id": "DSA-5532-1", "modified": "2024-01-01T00:00:00Z" }, { "id": "CVE-2023-5678", "modified": "x" }] }),
            _ => serde_json::json!({}),
        })
        .await;
        let hits = osv(&base, &found(&[("bash", "5.2.15-2"), ("openssl", "3.0.11-1")]))
            .await
            .unwrap();
        assert_eq!(
            hits,
            [Hit {
                name: "openssl".into(),
                version: "3.0.11-1".into(),
                ids: vec!["CVE-2023-5678".into(), "DSA-5532-1".into()]
            }]
        );
        let asked = asked.lock().unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(
            asked[0],
            serde_json::json!({ "queries": [
                { "package": { "name": "bash", "ecosystem": "Debian:12" }, "version": "5.2.15-2" },
                { "package": { "name": "openssl", "ecosystem": "Debian:12" }, "version": "3.0.11-1" },
            ] })
        );
    }

    #[tokio::test]
    async fn scan_osv_asks_in_batches_of_a_thousand_and_keeps_only_ids_that_are_ids() {
        let (base, asked) = osv_standin(|q| match q["package"]["name"].as_str().unwrap() {
            "p0" => serde_json::json!({ "vulns": [{ "id": "<script>" }, { "id": "USN-1-1" }] }),
            "p2500" => serde_json::json!({ "vulns": [{ "id": "CVE-1-1" }] }),
            _ => serde_json::json!({}),
        })
        .await;
        let many: Vec<(String, String)> = (0..2501).map(|n| (format!("p{n}"), "1".to_string())).collect();
        let many: Vec<(&str, &str)> = many.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
        let hits = osv(&base, &found(&many)).await.unwrap();
        assert_eq!(
            hits.iter()
                .map(|h| (h.name.as_str(), h.ids.clone()))
                .collect::<Vec<_>>(),
            [
                ("p0", vec!["USN-1-1".to_string()]),
                ("p2500", vec!["CVE-1-1".to_string()])
            ]
        );
        assert_eq!(
            asked
                .lock()
                .unwrap()
                .iter()
                .map(|b| b["queries"].as_array().unwrap().len())
                .collect::<Vec<_>>(),
            [1000, 1000, 501]
        );
    }

    #[tokio::test]
    async fn scan_osv_says_what_went_wrong_when_osv_does_not_answer_as_it_should() {
        // Nothing listens there.
        let why = osv("http://127.0.0.1:9", &found(&[("a", "1")])).await.unwrap_err();
        assert!(why.contains("OSV"), "{why}");
        // An answer for a different number of packages is no answer.
        let (base, _) = osv_standin(|_| serde_json::json!({})).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let short = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut chunk = [0u8; 4096];
            let _ = socket.read(&mut chunk).await;
            let reply = "{\"results\":[]}";
            let _ = socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                        reply.len()
                    )
                    .as_bytes(),
                )
                .await;
        });
        let why = osv(&short, &found(&[("a", "1")])).await.unwrap_err();
        assert!(why.contains("OSV"), "{why}");
        let _ = base;
    }
}
