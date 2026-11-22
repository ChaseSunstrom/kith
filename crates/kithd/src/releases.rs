//! Releases (PLAN.md §4.8): the node that leads the store installs every `Release`. It
//! renders the release's package (a `Package` in the store, put there by
//! `kith package push`) with the release's values, applies what comes out, and deletes
//! what it applied before and no longer renders. A resource is a release's when it is
//! annotated [`OWNER`] with the Release's key: only those are ever deleted, and they
//! all are once the Release is gone.
//!
//! Values, later over earlier: the package's defaults, `values` (YAML) in the
//! ConfigMap `kith-system/kith-values`, the same in the release's namespace, the
//! release's own.
//
// ponytail: hooks run on install and upgrade only (no delete hooks, weights or delete policies:
// a hook Job is kept until its version or spec changes, or the Release goes); no values per
// node; a version is one version, not a range.
// A render is remembered by the revisions of what went in, so every Release is looked at
// on every change to the store but rendered once. `lookup(kind, namespace, name)` in a
// template reads the live spec (an empty map when there is none) of a resource in the
// release's own namespace that its writer, and a pushed Package's pusher, may `get`: the
// render has no store, so it is handed a snapshot (at most 1 MB), and is made again when a
// resource it looked up changes. Other namespaces and the `.kith` language see no `lookup`.

use crate::Shared;
use kith_api::Resource;
use kith_api::kinds::{ConfigMapSpec, ReleaseSpec};
use kith_api::store::Store;
use kith_packages::Package;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// The annotation on what a release applied: the Release's key.
pub const OWNER: &str = "kith.dev/owned-by";
/// The annotation on a Release or a Source: who applied it, as the audit log names them,
/// written by the API server (a client's word for it is replaced) and, on what a Source
/// makes, the Source's own. What it renders is made with that one's rights.
pub const WRITER: &str = "kith.dev/written-by";
/// The annotation on a Job a package renders that makes it a hook: `pre-install`,
/// `post-install`, `pre-upgrade` or `post-upgrade`. A hook is applied at its point and the
/// Release waits for it to succeed; it is not one of the Release's recorded resources.
pub const HOOK: &str = "kith.dev/hook";
/// The annotation on a hook Job kithd applied: the version and the hook as rendered when it
/// ran. A Job with another is of an older version or spec, and is deleted before the new one.
const RAN: &str = "kith.dev/hook-ran";
const POINTS: [&str; 4] = ["pre-install", "post-install", "pre-upgrade", "post-upgrade"];
/// The annotation beside [`WRITER`] when that is an Identity: the print of its `publicKey`
/// (`pki::key_print`) when it applied. An Identity made again under the name has another
/// key, so what the old one applied is not acted on as the new one. None for the local socket.
pub const KEY: &str = "kith.dev/written-key";

/// The print of the key the Identity `name` has in `store`, if it is there with one.
pub fn print_of(store: &Store, name: &str) -> Option<String> {
    let identity = store.get(&format!("Identity/{name}"))?;
    crate::pki::print_of_key(identity.spec["publicKey"].as_str()?)
}

/// Whether `owner` (a Release or a Source) was applied by the Identity `caller` is now:
/// one with the key it had then. One written down with no key, or another key (an Identity
/// made again under that name, or given a new certificate), is not acted on. One that is
/// not there is for the rights to say (it has none); the local socket has no key.
fn same_writer(store: &Store, owner: &Resource, caller: &crate::access::Caller) -> Result<(), String> {
    let crate::access::Caller::Identity(name) = caller else {
        return Ok(());
    };
    if store.get(&format!("Identity/{name}")).is_none() {
        return Ok(());
    }
    let written = owner.metadata.annotations.get(KEY);
    if written.is_some() && written == print_of(store, name).as_ref() {
        return Ok(());
    }
    Err(format!(
        "{} was applied by an earlier Identity named {name}, or by {name} before it had the key it has now, \
         so it makes nothing new: {}",
        owner.key(),
        again(owner)
    ))
}

/// How `owner`'s writer mends what is said of it: a Package is pushed, the rest applied.
fn again(owner: &Resource) -> &'static str {
    match owner.kind.as_str() {
        "Package" => "push it again",
        _ => "apply it again",
    }
}

/// For tests: the key `nth` (of two, made once) of the Identity bob, as a PEM and its print.
#[cfg(test)]
pub(crate) fn bobs_key(nth: usize) -> (String, String) {
    static KEYS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        let ca = crate::pki::Ca::create().unwrap();
        (0..2).map(|_| ca.issue_user("bob").unwrap().2).collect()
    });
    (keys[nth].clone(), crate::pki::print_of_key(&keys[nth]).unwrap())
}

/// For tests: the Identity bob in `store`, with his key `nth`.
#[cfg(test)]
pub(crate) fn bob_is(store: &mut Store, nth: usize) {
    let identity = json!({
        "apiVersion": kith_api::API_VERSION, "kind": "Identity",
        "metadata": { "name": "bob" }, "spec": { "publicKey": bobs_key(nth).0 },
    });
    store.apply(serde_json::from_value(identity).unwrap()).unwrap();
}

/// For tests: `bob`'s mark on what he applied with his key `nth`, as the API writes it
/// (what the local socket writes is `"annotations: { 'kith.dev/written-by': 'local socket' }"`).
#[cfg(test)]
pub(crate) fn bobs_note(nth: usize) -> String {
    format!(
        "annotations: {{ 'kith.dev/written-by': 'bob', 'kith.dev/written-key': '{}' }}",
        bobs_key(nth).1
    )
}

/// For tests: `source` (applied through the local socket) as bob applied it with his key `nth`.
#[cfg(test)]
pub(crate) fn by_bob(source: &str, nth: usize) -> String {
    source.replace(
        "annotations: { 'kith.dev/written-by': 'local socket' }",
        &bobs_note(nth),
    )
}
/// What no package gets to make, besides anything that is in no namespace (nodes,
/// packages, repositories): what installs things.
const KEPT: [&str; 2] = ["Release", "Source"];
/// The annotation on a Package fetched from a Repository: the Repository's name. A
/// Release that names a Repository installs only those, and one that names none only
/// what was pushed here.
pub const REPOSITORY: &str = "kith.dev/repository";
/// What a Package fetched from the Repository `name` is annotated with: the name, and
/// a print of where the Repository points and the key it checks with, so that what
/// was fetched under another key or from elsewhere is no longer taken for its.
pub fn origin(store: &Store, name: &str) -> Option<String> {
    let repository = store.get(&format!("Repository/{name}"))?;
    let about = format!("{}\n{}", repository.spec["url"], repository.spec["publicKey"]);
    let print = ring::digest::digest(&ring::digest::SHA256, about.as_bytes());
    let print: String = print.as_ref()[..8].iter().map(|byte| format!("{byte:02x}")).collect();
    Some(format!("{name}@{print}"))
}

/// The kinds `KindDefinition`s make, and whether each is namespaced.
pub fn custom_kinds(store: &Store) -> BTreeMap<String, bool> {
    let made = |definition: &Resource| {
        let kind = definition.spec["kind"].as_str().unwrap_or_default();
        (kind.to_string(), definition.spec["namespaced"] != false)
    };
    store.list(Some("KindDefinition")).map(made).collect()
}

/// The ConfigMap (in `kith-system`, in a namespace) whose `values` releases are given.
pub const SHARED: &str = "kith-values";

/// What a render was made from: it stands until one of these changes. (A revision and
/// when it was applied: a resource deleted and made again starts at revision 1 again.)
#[derive(Debug, Clone, PartialEq)]
struct Inputs {
    release: Stamp,
    package: (String, Stamp),
    cluster: Stamp,
    namespace: Stamp,
    /// (A kind made since is a reason to render again what failed for want of it.)
    kinds: BTreeMap<String, bool>,
    /// What a render looked up (`lookup` in a template), as it was when the render began: it
    /// stands until one of these changes ([`fresh`]). Empty until [`pending`] makes the job.
    looked: BTreeMap<String, Stamp>,
    /// The rights `lookup` read by, as one number ([`lookup_rights`]); none for a
    /// package that looks nothing up.
    rights: Option<u64>,
}

/// Is a render made from `had` still what `now` (what [`inputs`] says) asks for, with
/// `store` as it is: nothing it was made from, nor looked up, nor read by, has changed?
fn fresh(store: &Store, release: &Resource, had: &Inputs, now: &Inputs) -> bool {
    let looked = |(key, stamped): (&String, &Stamp)| {
        let live = store.get(key).and_then(|resource| stamp(store, resource));
        live == *stamped
    };
    let alike = Inputs {
        looked: BTreeMap::new(),
        rights: None,
        ..had.clone()
    };
    alike == *now
        && had.looked.iter().all(looked)
        && had.rights.is_none_or(|rights| {
            let package = store.get(&now.package.0);
            package.is_some_and(|package| rights == lookup_rights(store, release, package))
        })
}

/// What a finished render stands on: of the stamps its job was made with, those of what it
/// looked up (a render that failed may have stopped before it looked: all of them stay), and
/// what it looked up that the job did not have (absent then).
fn learned(mut inputs: Inputs, result: Result<Output, String>) -> (Inputs, Result<Output, String>) {
    if let Ok(output) = &result {
        inputs.looked.retain(|key, _| output.looked.contains(key));
        for key in &output.looked {
            inputs.looked.entry(key.clone()).or_insert(None);
        }
    }
    (inputs, result)
}

pub type Stamp = Option<(Option<u64>, u64)>;

pub fn stamp(store: &Store, resource: &Resource) -> Stamp {
    let applied = store.history(&resource.key()).ok().and_then(|history| history.last());
    Some((resource.metadata.revision, applied.map_or(0, |revision| revision.at)))
}

/// A render to do.
#[derive(serde::Serialize, serde::Deserialize)]
struct Job {
    files: BTreeMap<String, String>,
    layers: Vec<Value>,
    name: String,
    namespace: String,
    owner: String,
    kinds: BTreeMap<String, bool>,
    /// What `lookup` sees ([`live`]).
    live: kith_packages::Live,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Output {
    version: String,
    resources: Vec<Resource>,
    notes: Option<String>,
    /// The keys `lookup` was asked for.
    looked: BTreeSet<String>,
}

type Renders = BTreeMap<String, (Inputs, Result<Output, String>)>;

/// What to do for one Release, in this order; the status only if the rest went well.
#[derive(Debug, PartialEq)]
pub struct Step {
    /// The Release (or the Source: they are carried out alike).
    pub release: String,
    pub apply: Vec<Resource>,
    pub delete: Vec<String>,
    pub status: Option<Map<String, Value>>,
}

/// What to do to the store.
#[derive(Debug, Default, PartialEq)]
struct Plan {
    steps: Vec<Step>,
    /// What a Release that is gone left behind.
    orphans: Vec<String>,
}

fn namespace(resource: &Resource) -> String {
    resource.key().split('/').nth(1).unwrap_or_default().to_string()
}

/// Does `version` fit what a Release asks for? One version asked for is that one; a
/// range (`^1.2`, `>=1, <3`, `*`) is any in it; nothing asked for is any that is not a
/// pre-release.
pub fn fits(asked: Option<&str>, version: &str) -> bool {
    let asked = asked.unwrap_or("*");
    let Ok(version) = semver::Version::parse(version) else {
        return asked == version;
    };
    match semver::Version::parse(asked) {
        Ok(exactly) => exactly == version,
        Err(_) => semver::VersionReq::parse(asked).is_ok_and(|range| range.matches(&version)),
    }
}

/// The Package a release is on: of those that fit what it asks for (and came from the
/// Repository it names, if it names one), the one it has installed, or the newest when
/// it has none or `follow`s the newest (`autoUpgrade`; an upgrade's preview follows too).
/// `1.0.0-rc1` is older than `1.0.0`.
/// With `pin` (the version a rolled-back spec had, [`pinned`]), that one and no other, and
/// an error when it is gone: a rollback never moves to a version it did not have.
fn package<'a>(
    store: &'a Store,
    release: &Resource,
    spec: &ReleaseSpec,
    follow: bool,
    pin: Option<&str>,
) -> Result<&'a Resource, String> {
    let (name, asked) = (&spec.package.name, spec.package.version.as_deref());
    let version = |package: &Resource| package.spec["version"].as_str().unwrap_or_default().to_string();
    let from = spec
        .package
        .repo
        .as_ref()
        .map(|repo| origin(store, repo).unwrap_or_default());
    let fitting = |package: &&Resource| {
        package.metadata.name == format!("{name}-{}", version(package))
            && package.metadata.annotations.get(REPOSITORY) == from.as_ref()
            && fits(asked, &version(package))
    };
    let installed = release.status.as_ref().and_then(|status| status["version"].as_str());
    let kept = pin.or(installed.filter(|_| !follow));
    let kept = kept.and_then(|installed| store.get(&format!("Package/{name}-{installed}")));
    if let Some(pin) = pin {
        return kept
            .filter(fitting)
            .ok_or(format!("there is no Package {name} {pin}, the version this spec installed before: push it again, or change the spec to follow the newest"));
    }
    let newest = || {
        let packages = store.list(Some("Package")).filter(fitting);
        packages.max_by_key(|package| semver::Version::parse(&version(package)).ok())
    };
    let wanted = asked.map_or(String::new(), |version| format!(" {version}"));
    kept.filter(fitting).or_else(newest).ok_or(match &spec.package.repo {
        None => format!("there is no Package {name}{wanted}: `kith package push` puts one here"),
        Some(repo) if store.get(&format!("Repository/{repo}")).is_none() => format!("there is no Repository/{repo}"),
        Some(repo) if let Err(why) = supplied(store, release) => {
            format!("there is no Package {name}{wanted} from Repository/{repo}: {why}")
        }
        Some(repo) => format!(
            "there is no Package {name}{wanted} from Repository/{repo} (yet): its status says if it cannot be asked"
        ),
    })
}

/// The `values` of the ConfigMap `key`, if there is one: its stamp too.
fn shared_values(store: &Store, key: &str) -> Result<(Stamp, Option<Value>), String> {
    let Some(map) = store.get(key) else {
        return Ok((None, None));
    };
    let spec = serde_json::from_value::<ConfigMapSpec>(map.spec.clone()).map_err(|e| format!("{key}: {e}"))?;
    let values = match spec.data.get("values") {
        None => None,
        Some(source) => {
            let values: Value = kith_yaml::from_str(source).map_err(|e| e.render(&format!("{key}: values"), source))?;
            if !values.is_object() {
                return Err(format!("{key}: values is not a map"));
            }
            Some(values)
        }
    };
    Ok((stamp(store, map), values))
}

/// What the Release `release` is to be rendered from, now: the package and the values
/// over its defaults. (Nothing big is copied here: this runs for every Release on
/// every change to the store.) With `preview`, the newest fitting Package, as if it followed.
fn inputs<'a>(
    store: &'a Store,
    release: &Resource,
    preview: bool,
) -> Result<(Inputs, &'a Resource, Vec<Value>), String> {
    let spec: ReleaseSpec = serde_json::from_value(release.spec.clone()).map_err(|e| e.to_string())?;
    // (An upgrade's preview is what moving would do: it is not held back.)
    let pin = pinned(store, release).filter(|_| !preview);
    let package = package(
        store,
        release,
        &spec,
        preview || spec.auto_upgrade == Some(true),
        pin.as_deref(),
    )?;
    let (cluster, everywhere) = shared_values(store, "ConfigMap/kith-system/kith-values")?;
    let (local, here) = shared_values(store, &format!("ConfigMap/{}/{SHARED}", namespace(release)))?;
    let inputs = Inputs {
        release: stamp(store, release),
        package: (package.key(), stamp(store, package)),
        cluster,
        namespace: local,
        kinds: custom_kinds(store),
        looked: BTreeMap::new(),
        rights: None,
    };
    let own = Value::Object(spec.values);
    Ok((
        inputs,
        package,
        everywhere.into_iter().chain(here).chain([own]).collect(),
    ))
}

/// Render: the package's resources for the release, each marked as the release's. A
/// release stays in its namespace, away from the kinds in [`KEPT`] and from the values
/// it is itself rendered from.
fn render(job: &Job) -> Result<Output, String> {
    let package = Package::from_files(job.files.clone())?;
    // (From the files themselves, which are what is rendered: a Package resource's own
    // spec is only what its pusher wrote there.)
    if let Some(why) = package.meta.kith_mismatch(env!("CARGO_PKG_VERSION")) {
        return Err(why);
    }
    let release = kith_packages::Release {
        name: &job.name,
        namespace: &job.namespace,
    };
    let mut rendered = package.render_live(release, &job.layers, &job.live)?;
    for resource in &mut rendered.resources {
        let scoped = match kith_api::kind(&resource.kind) {
            Some(kind) => kind.namespaced,
            // A kind a KindDefinition makes: in the release's namespace when it names none.
            None => {
                let Some(scoped) = job.kinds.get(&resource.kind).copied() else {
                    return Err(format!(
                        "{}: no KindDefinition makes a {}",
                        resource.key(),
                        resource.kind
                    ));
                };
                if scoped && resource.metadata.namespace.is_none() {
                    resource.metadata.namespace = Some(job.namespace.clone());
                }
                scoped
            }
        };
        let key = resource.key();
        if !scoped || KEPT.contains(&resource.kind.as_str()) {
            return Err(format!("{key}: a package does not get to make a {}", resource.kind));
        }
        if resource.metadata.namespace.as_deref() != Some(job.namespace.as_str()) {
            return Err(format!(
                "{key}: a release stays in its own namespace ({})",
                job.namespace
            ));
        }
        if (resource.kind.as_str(), resource.metadata.name.as_str()) == ("ConfigMap", SHARED) {
            return Err(format!(
                "{key}: a package does not get to set the values releases are given"
            ));
        }
        // (What a template says of these is not for a template to say.)
        (resource.metadata.revision, resource.status) = (None, None);
        resource.metadata.annotations.insert(OWNER.into(), job.owner.clone());
    }
    Ok(Output {
        version: package.meta.version,
        resources: rendered.resources,
        notes: rendered.notes,
        looked: rendered.looked,
    })
}

/// The first argument kithd is started again with to render one Release ([`render_shim`]).
pub const RENDER: &str = "--kith-render";
/// What a render may have: the address space of the kithd it runs in, its CPU time, the
/// time it takes, and how much it answers.
const RENDER_MEMORY: u64 = 256 << 20;
const RENDER_CPU: u64 = 20;
/// The files a render may hold open.
const RENDER_FILES: u64 = 256;
const RENDER_TIME: Duration = Duration::from_secs(30);
const RENDER_ANSWER: u64 = 32 << 20;

/// Started again to render ([`RENDER`])? Then a [`Job`] is read on stdin, its [`Output`]
/// or why not written on stdout, and this never returns. A package is someone else's
/// code: what it grows to, a panic, a stack it overflows end only this kithd.
pub fn render_shim() {
    use nix::sys::resource::{Resource, setrlimit};
    if std::env::args_os().nth(1).as_deref() != Some(std::ffi::OsStr::new(RENDER)) {
        return;
    }
    // (Held before anything of the package is read; one that cannot be held renders nothing.)
    let held = [
        (Resource::RLIMIT_AS, RENDER_MEMORY),
        (Resource::RLIMIT_CPU, RENDER_CPU),
        (Resource::RLIMIT_CORE, 0),
        // (Not the raised 65536 kithd runs with, [`crate::raise_nofile`].)
        (Resource::RLIMIT_NOFILE, RENDER_FILES),
    ];
    if held
        .into_iter()
        .any(|(what, most)| setrlimit(what, most, most).is_err())
    {
        std::process::exit(2);
    }
    let job: Result<Job, String> = serde_json::from_reader(std::io::stdin().lock()).map_err(|e| e.to_string());
    let answer = job.and_then(|job| render(&job));
    let written = serde_json::to_writer(std::io::stdout().lock(), &answer);
    std::process::exit(i32::from(written.is_err()));
}

/// Render `job` in a kithd started again for it ([`render_shim`]), held to
/// [`RENDER_MEMORY`], [`RENDER_CPU`] and [`RENDER_TIME`].
async fn apart(job: &Job) -> Result<Output, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let sent = serde_json::to_vec(job).map_err(|e| e.to_string())?;
    let mut command = tokio::process::Command::new("/proc/self/exe");
    command
        .arg(RENDER)
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    // (Its exit is this one's to collect, not the orphan reaper's.)
    let spawned = kith_runtime::spawn_awaited(|| command.spawn(), tokio::process::Child::id);
    let (mut child, _awaited) = spawned.map_err(|e| format!("rendering: {e}"))?;
    let (mut input, output) = (child.stdin.take(), child.stdout.take());
    let talk = async {
        if let Some(mut input) = input.take() {
            // (One that stops reading has stopped: what it says next is why.)
            let _ = input.write_all(&sent).await;
        }
        let mut answer = Vec::new();
        if let Some(output) = output {
            output.take(RENDER_ANSWER + 1).read_to_end(&mut answer).await?;
        }
        Ok::<_, std::io::Error>((answer, child.wait().await?))
    };
    let (answer, ended) = match tokio::time::timeout(RENDER_TIME, talk).await {
        Err(_) => return Err(format!("rendering took more than {} s", RENDER_TIME.as_secs())),
        Ok(talked) => talked.map_err(|e| format!("rendering: {e}"))?,
    };
    if answer.len() as u64 > RENDER_ANSWER {
        return Err(format!("rendering gave more than {} MB", RENDER_ANSWER >> 20));
    }
    match serde_json::from_slice::<Result<Output, String>>(&answer) {
        Ok(rendered) if ended.success() => rendered,
        _ => Err(match std::os::unix::process::ExitStatusExt::signal(&ended) {
            Some(nix::libc::SIGXCPU) => format!("rendering took more than {RENDER_CPU} s of CPU"),
            Some(_) => format!(
                "rendering stopped ({ended}): it wanted more memory than the {} MB it has, \
                 a deeper stack, or it panicked",
                RENDER_MEMORY >> 20
            ),
            None => format!("rendering stopped ({ended})"),
        }),
    }
}

/// The most that `lookup` is handed: the specs of a namespace, as JSON.
const LIVE_LIMIT: usize = 1 << 20;

/// What `lookup` is to see for `release`: the specs of the resources in its namespace that
/// whoever applied it may read (a template is no way round a right) and, unless `package` is
/// one its Repository supplied ([`fetched`]), that its pusher may read too: the template is
/// the pusher's, and its output is held to both ([`plan`]), so with the writer's rights alone
/// it could read through them (a Secret rendered into a ConfigMap the pusher may read). A
/// pusher nobody wrote down, or one kithd does not act as, may read nothing. With the stamp
/// of each, taken together with them. Nothing for a package that does not say `lookup` anywhere.
// ponytail: a scan of the store per render that looks things up; an index by namespace if
// that is ever dear.
fn live(
    store: &Store,
    release: &Resource,
    package: &Resource,
    files: &BTreeMap<String, String>,
) -> (kith_packages::Live, BTreeMap<String, Stamp>, Option<u64>) {
    use crate::access::{Caller, Grants};
    use kith_api::kinds::Verb;
    let mut live = kith_packages::Live::default();
    let mut stamps = BTreeMap::new();
    // (Any file: the NOTES are rendered with `lookup` too.)
    if !files.values().any(|text| text.contains("lookup")) {
        return (live, stamps, None);
    }
    // Whoever applied `owner` (the Release, or the Package), as it was when they did.
    let grants = |owner: &Resource| {
        let writer = owner.metadata.annotations.get(WRITER);
        let caller = writer.and_then(|writer| Caller::named(writer));
        let caller = caller.filter(|caller| same_writer(store, owner, caller).is_ok());
        caller.map(|caller| Grants::of(&caller, store))
    };
    // (None for a fetched Package: no pusher to ask.)
    let (writer, pusher) = (
        grants(release),
        (!fetched(store, release, package)).then(|| grants(package)),
    );
    let home = namespace(release);
    let get = |grants: &Option<Grants>, kind: &str| {
        grants
            .as_ref()
            .is_some_and(|grants| grants.may(&Verb::Get, kind, Some(&home), None))
    };
    let mut size = 0;
    for resource in store.list(None) {
        if resource.metadata.namespace.as_deref() != Some(home.as_str()) {
            continue;
        }
        // (Stamped whether or not it is handed over: one that is hidden is there all the same,
        // and a render that asks for it would otherwise never be taken for current.)
        let key = resource.key();
        stamps.insert(key.clone(), stamp(store, resource));
        // (Past the cap nothing more is copied: the snapshot is refused below.)
        if size <= LIVE_LIMIT
            && get(&writer, &resource.kind)
            && pusher.as_ref().is_none_or(|pusher| get(pusher, &resource.kind))
        {
            size += resource.spec.to_string().len();
            live.specs.insert(key, resource.spec.clone());
        }
    }
    if size > LIVE_LIMIT {
        live.specs.clear();
        live.refused = Some(format!(
            "the resources of namespace {home} are more than {} MB, more than a render is handed",
            LIVE_LIMIT >> 20
        ));
    }
    (live, stamps, Some(lookup_rights(store, release, package)))
}

/// What `lookup` reads by, as one number: the rights of the Release's writer
/// ([`crate::controllers::rights`]) and, for a Package its Repository did not supply, of its
/// pusher too, so a pusher narrowed, gone or made again renders it again.
fn lookup_rights(store: &Store, release: &Resource, package: &Resource) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::hash::DefaultHasher::new();
    crate::controllers::rights(store, release).hash(&mut hasher);
    if !fetched(store, release, package) {
        crate::controllers::rights(store, package).hash(&mut hasher);
    }
    hasher.finish()
}

/// Is `package` the one the Repository `release` names supplied, as its origin says
/// ([`origin`])? That Repository's key (or, with none, its address) is its trust, and it has
/// no pusher. Any other, annotated or not, is its pusher's.
fn fetched(store: &Store, release: &Resource, package: &Resource) -> bool {
    let origin = release.spec["package"]["repo"]
        .as_str()
        .and_then(|repo| origin(store, repo));
    origin.is_some() && package.metadata.annotations.get(REPOSITORY) == origin.as_ref()
}

/// What the upgrade of each Release is rendered from, by its key: those that do not follow,
/// have something installed, and have a newer Package that fits. Worked out once a pass (it
/// reads the store, under its lock) and handed to [`prune`], [`upgrading`] and [`plan`].
type Newer<'a> = BTreeMap<String, (Inputs, &'a Resource, Vec<Value>)>;

fn newers(store: &Store) -> Newer<'_> {
    let upgrade = |release: &Resource| {
        let installed = release.status.as_ref()?["version"].as_str()?;
        if release.spec["autoUpgrade"] == true {
            return None;
        }
        let found = inputs(store, release, true).ok()?;
        (found.1.spec["version"] != installed).then(|| (release.key(), found))
    };
    store.list(Some("Release")).filter_map(upgrade).collect()
}

/// Drop the renders of what is gone, and the upgrade of each Release that has none to preview.
fn prune(store: &Store, renders: &mut Renders, upgrades: &mut Renders, newer: &Newer) {
    renders.retain(|key, _| store.get(key).is_some());
    upgrades.retain(|key, _| newer.contains_key(key));
}

/// The Releases whose render is missing or out of date.
fn pending(store: &Store, renders: &Renders) -> Vec<(String, Inputs, Job)> {
    jobs(store, renders, None)
}

/// The Releases whose upgrade has no render, or one out of date ([`Newer`]).
fn upgrading(store: &Store, upgrades: &Renders, newer: &Newer) -> Vec<(String, Inputs, Job)> {
    jobs(store, upgrades, Some(newer))
}

fn jobs(store: &Store, renders: &Renders, upgrade: Option<&Newer>) -> Vec<(String, Inputs, Job)> {
    let mut jobs = Vec::new();
    for release in store.list(Some("Release")) {
        let key = release.key();
        // (One that cannot be started says why in `plan`.)
        let built;
        let (inputs, package, layers) = match upgrade {
            Some(newer) => match newer.get(&key) {
                Some(found) => found,
                None => continue,
            },
            None => match inputs(store, release, false) {
                Ok(found) => {
                    built = found;
                    &built
                }
                Err(_) => continue,
            },
        };
        if renders
            .get(&key)
            .is_some_and(|(had, _)| fresh(store, release, had, inputs))
        {
            continue;
        }
        let files: BTreeMap<String, String> = package.spec["files"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(path, text)| (path.clone(), text.as_str().unwrap_or_default().to_string()))
            .collect();
        let (live, stamps, rights) = live(store, release, package, &files);
        let job = Job {
            files,
            layers: layers.clone(),
            name: release.metadata.name.clone(),
            namespace: namespace(release),
            owner: key.clone(),
            kinds: inputs.kinds.clone(),
            live,
        };
        jobs.push((
            key,
            Inputs {
                looked: stamps,
                rights,
                ..inputs.clone()
            },
            job,
        ));
    }
    jobs
}

pub fn owner(resource: &Resource) -> Option<&str> {
    resource.metadata.annotations.get(OWNER).map(String::as_str)
}

/// May `resources` be applied by hand? Not one that says it is of a Release that is
/// not there (nor comes with it): it would be deleted as that Release's leftovers.
pub fn claims(store: &Store, resources: &[Resource]) -> Result<(), String> {
    for resource in resources {
        if resource.metadata.annotations.contains_key(REPOSITORY) {
            let key = resource.key();
            return Err(format!(
                "{key} is annotated {REPOSITORY}, which says kithd fetched and checked it: apply it without"
            ));
        }
        let coming = |owner: &str| {
            resources
                .iter()
                .any(|other| other.kind == "Release" && other.key() == owner)
        };
        if let Some(owner) = owner(resource).filter(|owner| store.get(owner).is_none() && !coming(owner)) {
            let key = resource.key();
            return Err(format!(
                "{key} is annotated {OWNER}: {owner}, and there is no {owner}: apply it without the annotation"
            ));
        }
    }
    Ok(())
}

/// What it takes to make `resources` (marked as `key`'s) what `key` has in the store.
pub struct Reconciled {
    pub apply: Vec<Resource>,
    pub delete: Vec<String>,
    /// The keys of `resources`.
    pub kept: BTreeSet<String>,
    /// Those that are there and its own, and not as `resources` has them.
    pub differ: Vec<String>,
}

/// What the owner `key` (a Release, a Source) put in the store, by its own account in
/// its status: only that is pruned (not a copy someone made, annotation and all), and
/// that is still its own when someone applied over it and the annotation went.
pub fn recorded(owner: &Resource) -> BTreeSet<&str> {
    let listed = owner.status.as_ref().and_then(|status| status["resources"].as_array());
    listed.into_iter().flatten().filter_map(Value::as_str).collect()
}

/// Are `live` and `wanted` the same, as far as applying one over the other would change it?
fn same(live: &Resource, wanted: &Resource) -> bool {
    (&live.spec, &live.metadata.labels, &live.metadata.annotations)
        == (&wanted.spec, &wanted.metadata.labels, &wanted.metadata.annotations)
}

/// What moving `release` to the Package its upgrade is rendered from would change, by what
/// `installed` and that render make: the keys to apply (new or changed) and to delete. Taken
/// from the two renders, not the store, so a hand edit or another Release's churn does not
/// move it. Null when there is no newer Package; None when its render is not made yet.
fn upgrade_of<'a>(
    store: &Store,
    release: &Resource,
    installed: &'a Output,
    upgrades: &'a Renders,
    newer: &Newer,
) -> Option<Value> {
    let Some((now, package, _)) = newer.get(&release.key()) else {
        return Some(Value::Null);
    };
    let (had, rendered) = upgrades.get(&release.key())?;
    if !fresh(store, release, had, now) {
        return None;
    }
    let version = &package.spec["version"];
    Some(match rendered {
        Err(error) => json!({ "version": version, "error": error }),
        Ok(upgraded) => {
            let keyed = |output: &'a Output| -> BTreeMap<String, &'a Resource> {
                output
                    .resources
                    .iter()
                    .filter(|r| !is_hook(r))
                    .map(|r| (r.key(), r))
                    .collect()
            };
            let (had, next) = (keyed(installed), keyed(upgraded));
            let apply: Vec<&String> = next
                .iter()
                .filter(|(key, wanted)| !had.get(*key).is_some_and(|live| same(live, wanted)))
                .map(|(key, _)| key)
                .collect();
            let delete: Vec<&String> = had.keys().filter(|key| !next.contains_key(*key)).collect();
            json!({ "version": version, "apply": apply, "delete": delete })
        }
    })
}

/// How many installed versions a Release's status remembers.
const HISTORY: usize = 10;

/// The Release's `history` with `version` added, when it is not the one last installed: a
/// spec edit at one version adds nothing, a move back to an older one adds an entry. None
/// when there is nothing to add.
fn history_of(release: &Resource, version: &str, now: u64) -> Option<Value> {
    let mut seen: Vec<Value> = release
        .status
        .as_ref()
        .and_then(|status| status["history"].as_array().cloned())
        .unwrap_or_default();
    if seen.last().is_some_and(|last| last["version"] == version) {
        return None;
    }
    seen.push(json!({ "version": version, "revision": release.metadata.revision, "at": now }));
    seen.drain(..seen.len().saturating_sub(HISTORY));
    Some(Value::Array(seen))
}

/// The version a Release that follows the newest (`autoUpgrade`) is held to, when its spec is
/// again what it was before: the spec is compared with the revisions before the run of equal
/// ones it is in (a metadata edit is not a return), newest first, and the version is the last
/// `history` entry at or before the revision found. None when there is none, or the history
/// no longer reaches back so far. (One that stays on its version keeps it already, and turning
/// `autoUpgrade` off to freeze it must not bring back an older one.)
fn pinned(store: &Store, release: &Resource) -> Option<String> {
    if release.spec["autoUpgrade"] != true {
        return None;
    }
    let seen = release.status.as_ref()?["history"].as_array()?;
    let revisions = store.history(&release.key()).ok()?.iter().rev();
    let mut earlier = revisions.skip_while(|revision| revision.resource.spec == release.spec);
    earlier
        .find(|revision| revision.resource.spec == release.spec)
        .and_then(|revision| {
            let at = revision.resource.metadata.revision?;
            let entry = seen
                .iter()
                .rev()
                .find(|entry| entry["revision"].as_u64().is_some_and(|r| r <= at));
            // (Installing the oldest entry's version drops it from the ten: the pin it made, said in
            // the status, is the version then.)
            let status = release.status.as_ref()?;
            let held = (status["pinned"] == true).then(|| &status["version"]);
            entry
                .map(|entry| &entry["version"])
                .or(held)?
                .as_str()
                .map(str::to_string)
        })
}

/// Compare `resources` with the store for the owner `key`. Nothing of someone else's
/// is taken over: one resource that is there already and not `key`'s refuses them all.
pub fn reconcile(
    store: &Store,
    key: &str,
    recorded: &BTreeSet<&str>,
    resources: &[Resource],
    prune: bool,
) -> Result<Reconciled, String> {
    // (Recorded and unmarked is still its own; recorded and marked another's is the
    // other's now: two owners of one resource do not take it from each other for ever.)
    let mine = |live: &Resource| match owner(live) {
        Some(owner) => owner == key,
        None => recorded.contains(live.key().as_str()),
    };
    let others = resources.iter().map(Resource::key);
    let others: Vec<String> = others
        .filter(|resource| store.get(resource).is_some_and(|live| !mine(live)))
        .collect();
    if !others.is_empty() {
        return Err(format!("{} is there already and is not {key}'s", others.join(", ")));
    }
    let mut done = Reconciled {
        apply: Vec::new(),
        delete: Vec::new(),
        kept: BTreeSet::new(),
        differ: Vec::new(),
    };
    for resource in resources {
        done.kept.insert(resource.key());
        let live = store.get(&resource.key());
        if !live.is_some_and(|live| same(live, resource)) {
            done.apply.push(resource.clone());
            done.differ.extend(live.map(Resource::key));
        }
    }
    if prune {
        let gone = recorded.iter().filter(|resource| !done.kept.contains(**resource));
        let gone = gone.filter(|resource| store.get(resource).is_some_and(|live| owner(live) == Some(key)));
        done.delete.extend(gone.map(|resource| resource.to_string()));
    }
    Ok(done)
}

fn is_hook(resource: &Resource) -> bool {
    resource.metadata.annotations.contains_key(HOOK)
}

/// What the hooks at one point ask of the store: Jobs to apply, old ones to delete first, and
/// the key of the first Job still to be waited for, and why one failed.
#[derive(Default)]
struct Gate {
    apply: Vec<Resource>,
    delete: Vec<String>,
    waiting: Option<String>,
    failed: Option<String>,
}

/// The hooks of `release` at `point`, at `version`: a Job there is not run again while the version
/// and its spec are as it ran for; one for another is deleted (the new one is applied once it
/// is gone, the next pass). Err when one is a Job that is there and not the release's; a failed
/// one is `failed` (the caller says when).
fn gate(store: &Store, release: &str, version: &str, hooks: &[&Resource], point: &str) -> Result<Gate, String> {
    let mut gate = Gate::default();
    for hook in hooks
        .iter()
        .filter(|hook| hook.metadata.annotations.get(HOOK).is_some_and(|at| at == point))
    {
        let at = hook.key();
        let ran = crate::pki::hex(&Sha256::digest(format!("{version} {}", hook.spec)));
        let Some(live) = store.get(&at) else {
            let mut hook = (*hook).clone();
            hook.metadata.annotations.insert(RAN.into(), ran);
            gate.apply.push(hook);
            gate.waiting.get_or_insert(at);
            continue;
        };
        if owner(live) != Some(release) {
            return Err(format!("{at} is there already and is not {release}'s"));
        }
        if live.metadata.annotations.get(RAN) != Some(&ran) {
            gate.delete.push(at.clone());
        } else {
            let status = live.status.as_ref();
            match status.and_then(|status| status["state"].as_str()) {
                Some("succeeded") => continue,
                Some("failed") => {
                    let said = status
                        .and_then(|status| status["message"].as_str())
                        .map_or(String::new(), |m| format!(": {m}"));
                    gate.failed
                        .get_or_insert(format!("the hook {at} failed{said}; delete it to run it again"));
                    continue;
                }
                _ => {}
            }
        }
        gate.waiting.get_or_insert(at);
    }
    Ok(gate)
}

/// What the store needs done for its Releases, given the renders there are and the upgrades
/// previewed; `now` (unix seconds) is when a version newly installed is written down.
fn plan(store: &Store, renders: &Renders, upgrades: &Renders, newer: &Newer, now: u64) -> Plan {
    let mut plan = Plan::default();
    for release in store.list(Some("Release")) {
        let key = release.key();
        let (output, package) = match inputs(store, release, false) {
            Err(e) => (Err(e), None),
            Ok((now, package, _)) => match renders.get(&key) {
                Some((had, output)) if fresh(store, release, had, &now) => (output.clone(), Some(package)),
                // (Not rendered yet: next time.)
                _ => continue,
            },
        };
        let live = release.status.as_ref();
        let done = output.and_then(|output| {
            let hooks: Vec<&Resource> = output.resources.iter().filter(|r| is_hook(r)).collect();
            fn point(hook: &Resource) -> &str {
                hook.metadata.annotations.get(HOOK).map_or("", String::as_str)
            }
            if let Some(odd) = hooks
                .iter()
                .find(|hook| hook.kind != "Job" || !POINTS.contains(&point(hook)))
            {
                return Err(format!(
                    "{} is annotated {HOOK}: {}, but only a Job can be a hook, at one of {}",
                    odd.key(),
                    point(odd),
                    POINTS.join(", ")
                ));
            }
            let rest: Vec<Resource> = output.resources.iter().filter(|r| !is_hook(r)).cloned().collect();
            let mut done = reconcile(store, &key, &recorded(release), &rest, true)?;
            // A hook Job this render no longer names (one of another version) goes, so that coming
            // back to that version runs it again.
            let stale: Vec<String> = store
                .list(Some("Job"))
                .filter(|job| is_hook(job) && owner(job) == Some(key.as_str()))
                .map(Resource::key)
                .filter(|at| !hooks.iter().any(|hook| hook.key() == *at))
                .collect();
            done.delete.extend(stale.iter().cloned());
            // Install when nothing was installed (or it is the first version still); else an upgrade.
            // The pre hooks go before the rest is moved to this version, the post hooks after.
            let installed = live.and_then(|status| status["version"].as_str());
            let seen = live.and_then(|status| status["history"].as_array()).map_or(0, Vec::len);
            let event = match installed {
                Some(version) if version != output.version => "upgrade",
                _ if seen > 1 => "upgrade",
                _ => "install",
            };
            let mut before = match installed == Some(&output.version) {
                true => Gate::default(),
                false => gate(store, &key, &output.version, &hooks, &format!("pre-{event}"))?,
            };
            // (Both points are asked before anything is applied: a Job that is not the release's is its error at once.)
            let after = gate(store, &key, &output.version, &hooks, &format!("post-{event}"))?;
            if let Some(why) = before.failed.take() {
                return Err(why);
            }
            before.delete.extend(stale);
            let mut gone = done.delete.clone();
            gone.extend(before.delete.iter().chain(&after.delete).cloned());
            // (Asked on every pass: a writer that loses a right is told at once.)
            writer_may(store, release, &output.resources, &gone)?;
            // And of whoever pushed the Package it came from: no more than its pusher, besides
            // the Release's writer. One the Repository the Release names supplied has none: that
            // Repository's key (or, with none, its address) is its trust. Any other, annotated
            // or not, is asked of its writer, and refused when none is written down.
            if let Some(package) = package.filter(|package| !fetched(store, release, package)) {
                writer_may(store, package, &output.resources, &gone)?;
            }
            Ok((output, done, before, after))
        });
        let mut step = Step {
            release: key.clone(),
            apply: Vec::new(),
            delete: Vec::new(),
            status: None,
        };
        let status = match done {
            // The pre hooks are still to succeed: only they are made, and the rest waits (what was
            // installed before stays as it is, as for an error).
            Ok((
                _,
                _,
                Gate {
                    apply,
                    delete,
                    waiting: Some(job),
                    ..
                },
                _,
            )) => {
                (step.apply, step.delete) = (apply, delete);
                json!({
                    "state": "hooks", "message": format!("waiting for {job}"),
                    "observedRevision": release.metadata.revision, "pinned": pinned(store, release).is_some(),
                })
            }
            Ok((output, done, _, after)) => {
                // The post hooks are made once the rest is there (and waited for from the start).
                let there = done.apply.is_empty() && done.delete.is_empty();
                (step.apply, step.delete) = (done.apply, done.delete);
                if there {
                    step.apply.extend(after.apply);
                    step.delete.extend(after.delete);
                }
                let (waiting, broken) = (after.waiting, after.failed.filter(|_| there));
                // (Following the newest from a Repository its writer may not fetch from: said on
                // every pass, or it would be said only once a Package is missing.)
                let following = release.spec["autoUpgrade"] == true && release.spec["package"]["repo"].is_string();
                let unlooked = following.then(|| supplied(store, release).err()).flatten();
                let message = unlooked.map(|why| format!("no newer Package is looked for: {why}"));
                let mut status = json!({
                    "state": "installed", "message": message, "version": output.version,
                    "resources": done.kept, "notes": output.notes, "observedRevision": release.metadata.revision,
                    "pinned": pinned(store, release).is_some(),
                });
                // (Left out when not known yet or unchanged: the status is written when a field differs.)
                if let Some(pending) = upgrade_of(store, release, &output, upgrades, newer) {
                    status["pending"] = pending;
                }
                if let Some(history) = history_of(release, &output.version, now) {
                    status["history"] = history;
                }
                if let Some(why) = broken {
                    (status["state"], status["message"]) = (json!("error"), json!(why));
                } else if let Some(job) = waiting {
                    (status["state"], status["message"]) = (json!("hooks"), json!(format!("waiting for {job}")));
                }
                status
            }
            // (What was installed before stays as it is.)
            // (And whether it is pinned: a patch merges, so it would else keep the last pass's.)
            Err(e) => json!({
                "state": "error", "message": e, "observedRevision": release.metadata.revision,
                "pinned": pinned(store, release).is_some(),
            }),
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
            plan.steps.push(step);
        }
    }
    // What belonged to a Release or a Source that is gone goes too.
    let orphans = store
        .list(None)
        .filter(|resource| owner(resource).is_some_and(|owner| store.get(owner).is_none()));
    plan.orphans.extend(orphans.map(Resource::key));
    plan
}

/// Why `owner` (a Release or a Source) may not make `resources` and delete `gone`, if so:
/// each is asked of whoever applied it ([`WRITER`]), as the API asks it of whoever applies
/// a resource directly. One with nobody written down, or one kithd does not act as, makes
/// nothing: never more than the cluster's least.
pub fn writer_may(store: &Store, owner: &Resource, resources: &[Resource], gone: &[String]) -> Result<(), String> {
    use crate::access::{Caller, Grants};
    use kith_api::kinds::Verb;
    let key = owner.key();
    let Some(writer) = owner.metadata.annotations.get(WRITER) else {
        return Err(format!(
            "nobody is written down as having applied {key} (it was applied before kithd wrote that down), \
             so it makes nothing new: {}",
            again(owner)
        ));
    };
    let Some(caller) = Caller::named(writer) else {
        return Err(format!(
            "{key} was applied by {writer}, as whom kithd makes nothing: {}",
            again(owner)
        ));
    };
    same_writer(store, owner, &caller)?;
    let grants = Grants::of(&caller, store);
    let short = |(at, (verb, kind, namespace, _)): (String, crate::api::Right)| {
        let place = namespace.map_or(String::new(), |namespace| format!(" in namespace {namespace}"));
        let why = match &caller {
            Caller::Identity(name) if store.get(&format!("Identity/{name}")).is_none() => {
                format!("there is no Identity {name}")
            }
            _ => "no Role bound to it allows that".to_string(),
        };
        let verb = crate::api::word(&verb);
        format!("{at}: {key} was applied by {writer}, and {writer} may not {verb} {kind}{place}: {why}")
    };
    let made = resources.iter().flat_map(|resource| {
        let rights = crate::api::takes(store, std::slice::from_ref(resource));
        rights.into_iter().map(|right| (resource.key(), right))
    });
    let taken = gone
        .iter()
        .map(|at| (at.clone(), crate::api::right_of(Verb::Delete, at)));
    let mut asked = made.chain(taken);
    match asked
        .find(|(_, (verb, kind, namespace, name))| !grants.may(verb, kind, namespace.as_deref(), name.as_deref()))
    {
        Some(refused) => Err(short(refused)),
        None => Ok(()),
    }
}

/// Why kithd asks no Repository for `release`'s Package, if so: reaching a registry
/// through kithd takes `apply` on `Package` (as a pull or a push by hand does, `api.rs`),
/// and it is asked of whoever applied the Release. Else one who may write Releases alone
/// would have kithd ask any Repository there is and store what it answers.
pub fn supplied(store: &Store, release: &Resource) -> Result<(), String> {
    use crate::access::{Caller, Grants};
    let key = release.key();
    let Some(writer) = release.metadata.annotations.get(WRITER) else {
        return Err(format!(
            "nobody is written down as having applied {key}, so nothing is fetched for it: apply it again"
        ));
    };
    let Some(caller) = Caller::named(writer) else {
        return Err(format!(
            "{key} was applied by {writer}, for whom kithd fetches nothing: apply it again"
        ));
    };
    same_writer(store, release, &caller)?;
    if Grants::of(&caller, store).may(&kith_api::kinds::Verb::Apply, "Package", None, None) {
        return Ok(());
    }
    Err(format!(
        "{key} was applied by {writer}, and {writer} may not apply Package (in every namespace: a Package is in none), \
         so nothing is fetched for it"
    ))
}

fn failed(why: &str, revision: Option<u64>) -> Value {
    json!({ "state": "error", "message": why, "observedRevision": revision })
}

/// Plan from the store as it is now, and carry the plan out.
async fn carry_out_plan(shared: &Shared, renders: &Renders, upgrades: &Renders) {
    let plan = {
        let state = shared.store.lock().expect("nothing panics holding the store");
        let newer = newers(&state.store);
        plan(&state.store, renders, upgrades, &newer, kith_api::store::now())
    };
    carry_out(shared, plan.steps, plan.orphans).await;
}

/// Install the Releases, as long as this node leads the store, until told to stop.
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let (mut renders, mut upgrades) = (Renders::new(), Renders::new());
    let mut generation = shared.generation.subscribe();
    loop {
        let metrics = shared.raft.metrics().borrow().clone();
        if metrics.current_leader == Some(metrics.id) {
            let jobs = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                renders.retain(|key, _| state.store.get(key).is_some());
                pending(&state.store, &renders)
            };
            // (Each in a kithd of its own, one at a time: a package is someone else's code, and
            // what it grows to, a panic or a stack it overflows ends only that one.)
            for (key, inputs, job) in jobs {
                let rendered = apart(&job).await;
                renders.insert(key, learned(inputs, rendered));
            }
            carry_out_plan(&shared, &renders, &upgrades).await;
            // The previews come after what installs: a package that spins delays only what
            // it says about itself. When one is made, what it says is written now.
            let previews = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                let newer = newers(&state.store);
                prune(&state.store, &mut renders, &mut upgrades, &newer);
                upgrading(&state.store, &upgrades, &newer)
            };
            let made = !previews.is_empty();
            for (key, inputs, job) in previews {
                let rendered = apart(&job).await;
                upgrades.insert(key, learned(inputs, rendered));
            }
            if made {
                carry_out_plan(&shared, &renders, &upgrades).await;
            }
        }
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(30)) => {}
            _ = stopping.changed() => break,
        }
    }
}

/// Each Release for itself: one that cannot be applied says so and stops no other.
pub async fn carry_out(shared: &Shared, steps: Vec<Step>, orphans: Vec<String>) {
    use kith_api::store::Error;
    use kith_store::Command;
    // (Signed by this node under `spec.signing: required`: every node holds each to what its owner's
    // writer may, `own_writes`.)
    let delete = async |key: String| match shared.submit_node(Command::Delete { key }).await {
        Ok(_) | Err(Error::NotFound(_)) => Ok(()),
        Err(e) => Err(e),
    };
    let mut statuses = Vec::new();
    for mut step in steps {
        let mut done = Ok(());
        // (A kind is made before what is of it, and unmade after.)
        step.apply.sort_by_key(|resource| resource.kind != "KindDefinition");
        step.delete.sort_by_key(|key| key.starts_with("KindDefinition/"));
        if !step.apply.is_empty() {
            let at = kith_api::store::now();
            let applied = shared
                .submit_node(Command::Apply {
                    resources: step.apply,
                    at,
                })
                .await;
            if let Err(Error::Invalid(e) | Error::Conflict(e)) = &applied {
                let Value::Object(status) = failed(e, None) else {
                    unreachable!("an object")
                };
                // (`observedRevision` stays: that revision is the one that fails.)
                step.status = Some(
                    status
                        .into_iter()
                        .filter(|(field, _)| field != "observedRevision")
                        .collect(),
                );
                step.delete.clear();
            } else {
                done = applied.map(|_| ());
            }
        }
        for key in step.delete {
            done = done.and(delete(key).await);
        }
        match (done, step.status) {
            (Ok(()), Some(status)) => statuses.push((step.release, status)),
            (Ok(()), None) => {}
            (Err(e), _) => eprintln!("kithd: releases: {}: {e}", step.release),
        }
    }
    for key in orphans {
        if let Err(e) = delete(key).await {
            eprintln!("kithd: releases: {e}");
        }
    }
    if !statuses.is_empty()
        && let Err(e) = shared.submit(Command::Patch { statuses }).await
    {
        eprintln!("kithd: releases: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(store: &mut Store, source: &str) {
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
    }

    fn package(version: &str, templates: &[(&str, &str)]) -> Resource {
        package_asking(version, "", templates)
    }

    /// `package(..)` with `kith` as its package.yaml lines (a `kithVersion`, say).
    fn package_asking(version: &str, kith: &str, templates: &[(&str, &str)]) -> Resource {
        let mut files = BTreeMap::from([
            (
                "package.yaml".to_string(),
                format!("name: maps\nversion: {version}\n{kith}"),
            ),
            ("values.yaml".to_string(), "colour: red\nextra: false\n".to_string()),
            ("NOTES".to_string(), "{{ name }} is {{ values.colour }}".to_string()),
        ]);
        for (path, source) in templates {
            files.insert(format!("templates/{path}"), (*source).to_string());
        }
        // (Pushed through the local socket: the API server writes down who pushes one.)
        let mut package = Package::from_files(files).unwrap().resource().unwrap();
        package
            .metadata
            .annotations
            .insert(WRITER.into(), "local socket".into());
        package
    }

    /// `package(..)` as bob pushed it with his key `nth`.
    fn pushed_by_bob(mut package: Resource, nth: usize) -> Resource {
        let notes = &mut package.metadata.annotations;
        notes.insert(WRITER.into(), "bob".into());
        notes.insert(KEY.into(), bobs_key(nth).1);
        package
    }

    const MAP: &str = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: {{ name }} }\n\
                       spec: { data: { colour: {{ values.colour }} } }\n\
                       {% if values.extra %}---\napiVersion: kith.dev/v1\nkind: ConfigMap\n\
                       metadata: { name: {{ name }}-extra }\nspec: { data: { a: b } }\n{% endif %}";
    /// (Applied through the local socket: the API server writes down who applies one.)
    const RELEASE: &str = "apiVersion: kith.dev/v1\nkind: Release\n\
                           metadata: { name: mine, namespace: shop, annotations: { 'kith.dev/written-by': 'local socket' } }\n\
                           spec: { package: { name: maps }, autoUpgrade: true, values: { extra: true } }\n";

    /// Render what is pending and carry the plan out, until there is nothing to do.
    fn settle(store: &mut Store, renders: &mut Renders) -> usize {
        settle_at(store, renders, &mut Renders::new(), 1000)
    }

    /// `settle`, with the upgrades kept between calls and the clock at `now`.
    fn settle_at(store: &mut Store, renders: &mut Renders, upgrades: &mut Renders, now: u64) -> usize {
        for turn in 0..10 {
            let newer = newers(store);
            prune(store, renders, upgrades, &newer);
            for (key, inputs, job) in pending(store, renders) {
                renders.insert(key, learned(inputs, render(&job)));
            }
            for (key, inputs, job) in upgrading(store, upgrades, &newer) {
                upgrades.insert(key, learned(inputs, render(&job)));
            }
            let plan = plan(store, renders, upgrades, &newer, now);
            if plan == Plan::default() {
                return turn;
            }
            for step in plan.steps {
                store.apply_all(step.apply).unwrap();
                for key in step.delete.into_iter() {
                    store.delete(&key).unwrap();
                }
                // (As `carry_out` writes it.)
                if let Some(fields) = step.status {
                    let statuses = vec![(step.release, fields)];
                    kith_store::run(store, kith_store::Command::Patch { statuses }).unwrap();
                }
            }
            for key in plan.orphans {
                store.delete(&key).unwrap();
            }
        }
        panic!("the releases never settle");
    }

    /// What an owner once recorded and another has since marked as its own is the
    /// other's: neither takes it back from the other, round after round.
    #[test]
    fn a_recorded_resource_another_owns_now_is_not_taken_back() {
        let map = |owner: Option<&str>| -> Resource {
            let marks = owner.map_or(serde_json::json!({}), |owner| serde_json::json!({ OWNER: owner }));
            let map = serde_json::json!({
                "apiVersion": kith_api::API_VERSION, "kind": "ConfigMap",
                "metadata": { "name": "a", "namespace": "shop", "annotations": marks },
                "spec": { "data": { "k": "v" } },
            });
            serde_json::from_value(map).unwrap()
        };
        let recorded = BTreeSet::from(["ConfigMap/shop/a"]);
        let mut store = Store::default();
        store.apply(map(Some("Release/shop/two"))).unwrap();
        let wanted = [map(Some("Release/shop/one"))];
        let said = reconcile(&store, "Release/shop/one", &recorded, &wanted, true).map(|_| ());
        assert!(said.unwrap_err().contains("is not Release/shop/one's"));
        // One that lost its mark (someone applied it bare) and is recorded is still its own.
        let mut store = Store::default();
        store.apply(map(None)).unwrap();
        assert!(reconcile(&store, "Release/shop/one", &recorded, &wanted, true).is_ok());
    }

    #[test]
    fn a_release_installs_upgrades_and_goes() {
        let (mut store, mut renders) = (Store::default(), Renders::new());
        // No package yet: the release says so, and nothing else happens.
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        let status = |store: &Store| store.get("Release/shop/mine").unwrap().status.clone().unwrap();
        assert_eq!(status(&store)["state"], "error");
        assert!(
            status(&store)["message"]
                .as_str()
                .unwrap()
                .contains("there is no Package maps")
        );

        // The package comes: both maps, in the release's namespace, marked as its own.
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        assert_eq!(
            settle(&mut store, &mut renders),
            1,
            "one turn to do it, one to see it done"
        );
        let keys = |store: &Store| -> Vec<String> {
            let owned = store.list(None).filter(|resource| owner(resource).is_some());
            owned.map(Resource::key).collect()
        };
        assert_eq!(
            keys(&store),
            ["ConfigMap/shop/mine-maps", "ConfigMap/shop/mine-maps-extra"]
        );
        let now = status(&store);
        assert_eq!(
            (&now["state"], &now["version"], &now["message"]),
            (&json!("installed"), &json!("1.0.0"), &Value::Null)
        );
        assert_eq!(now["notes"], "mine-maps is red");
        assert_eq!(
            store.get("ConfigMap/shop/mine-maps").unwrap().spec["data"]["colour"],
            "red"
        );

        // Values for the whole cluster and for the namespace; the release's own win.
        let values = |namespace: &str, values: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: {{ name: kith-values, namespace: {namespace} }}\nspec: {{ data: {{ values: '{values}' }} }}\n"
            )
        };
        apply(&mut store, &values("kith-system", "{ colour: blue, extra: false }"));
        settle(&mut store, &mut renders);
        assert_eq!(
            store.get("ConfigMap/shop/mine-maps").unwrap().spec["data"]["colour"],
            "blue"
        );
        assert_eq!(keys(&store).len(), 2, "the release says extra: true");
        apply(&mut store, &values("shop", "colour: green"));
        settle(&mut store, &mut renders);
        assert_eq!(
            store.get("ConfigMap/shop/mine-maps").unwrap().spec["data"]["colour"],
            "green"
        );

        // A newer package is taken (no version asked for); what it no longer renders goes.
        store
            .apply(package(
                "1.1.0",
                &[("map.yaml", &MAP.replace("{% if values.extra %}", "{% if false %}"))],
            ))
            .unwrap();
        settle(&mut store, &mut renders);
        assert_eq!(
            (keys(&store), status(&store)["version"].clone()),
            (vec!["ConfigMap/shop/mine-maps".to_string()], json!("1.1.0"))
        );
        // Asked for by version, the older one comes back.
        apply(
            &mut store,
            &RELEASE.replace("name: maps }", "name: maps, version: 1.0.0 }"),
        );
        settle(&mut store, &mut renders);
        assert_eq!(keys(&store).len(), 2);

        // Someone deletes one of its resources: it is put back.
        store.delete("ConfigMap/shop/mine-maps-extra").unwrap();
        settle(&mut store, &mut renders);
        assert_eq!(keys(&store).len(), 2);

        // The release goes: so does everything of its, and nothing else.
        store.delete("Release/shop/mine").unwrap();
        settle(&mut store, &mut renders);
        assert_eq!(keys(&store), Vec::<String>::new());
        assert!(store.get("ConfigMap/shop/kith-values").is_some());
    }

    /// A package written in kith's own language is installed as one in YAML is: the
    /// same resources, marked the release's own, and a mistake in it is the release's
    /// error, said with its place in the package's file.
    #[test]
    fn kith_template_is_installed_as_a_yaml_one_is() {
        const KITH: &str = "[\n    ConfigMap { metadata: { name }, spec: { data: { colour: values.colour } } },\n    \
                            if values.extra then ConfigMap { metadata: { name: \"${name}-extra\" }, spec: { data: { a: \"b\" } } } else null,\n]\n";
        let installed = |template: (&str, &str)| {
            let (mut store, mut renders) = (Store::default(), Renders::new());
            apply(&mut store, RELEASE);
            store.apply(package("1.0.0", &[template])).unwrap();
            settle(&mut store, &mut renders);
            store
        };
        let owned = |store: &Store| -> Vec<serde_json::Value> {
            let owned = store.list(None).filter(|resource| owner(resource).is_some());
            owned
                .map(|resource| json!([resource.key(), resource.metadata.annotations, resource.spec]))
                .collect()
        };
        let (kith, yaml) = (installed(("map.kith", KITH)), installed(("map.yaml", MAP)));
        assert_eq!(owned(&kith).len(), 2);
        assert_eq!(owned(&kith), owned(&yaml));

        let wrong = installed(("map.kith", &KITH.replace("{ a: \"b\" }", "[\"b\"]")));
        let status = wrong.get("Release/shop/mine").unwrap().status.clone().unwrap();
        assert_eq!(status["state"], "error");
        let message = status["message"].as_str().unwrap();
        assert!(
            message.contains("templates/map.kith:3:") && message.contains("ConfigMap.spec.data"),
            "{message}"
        );
        assert_eq!(owned(&wrong), Vec::<serde_json::Value>::new());
    }

    #[test]
    fn a_release_keeps_to_itself() {
        let (mut store, mut renders) = (Store::default(), Renders::new());
        let state = |store: &Store| store.get("Release/shop/mine").unwrap().status.clone().unwrap();
        // A map of that name is there already and nobody's: it is not taken over.
        apply(
            &mut store,
            "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: mine-maps, namespace: shop }\nspec: { data: { mine: yes } }\n",
        );
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        assert!(
            state(&store)["message"]
                .as_str()
                .unwrap()
                .contains("ConfigMap/shop/mine-maps is there already")
        );
        assert_eq!(
            store.get("ConfigMap/shop/mine-maps").unwrap().spec["data"]["mine"],
            "yes"
        );
        assert!(
            store.get("ConfigMap/shop/mine-maps-extra").is_none(),
            "all of a release or none of it"
        );

        // Another namespace, and kinds no package makes.
        let elsewhere = MAP.replace("name: {{ name }} }", "name: {{ name }}, namespace: kith-system }");
        store.apply(package("2.0.0", &[("map.yaml", &elsewhere)])).unwrap();
        settle(&mut store, &mut renders);
        assert!(
            state(&store)["message"]
                .as_str()
                .unwrap()
                .contains("a release stays in its own namespace (shop)")
        );
        let more =
            "apiVersion: kith.dev/v1\nkind: Release\nmetadata: { name: more }\nspec: { package: { name: maps } }\n";
        store.apply(package("3.0.0", &[("release.yaml", more)])).unwrap();
        settle(&mut store, &mut renders);
        assert!(
            state(&store)["message"]
                .as_str()
                .unwrap()
                .contains("a package does not get to make a Release")
        );
        // ...nor anything that is in no namespace: here, a newer package for everyone.
        let newer =
            "apiVersion: kith.dev/v1\nkind: Package\nmetadata: { name: maps-9.0.0 }\nspec: { version: 9.0.0 }\n";
        store.apply(package("4.0.0", &[("package.yaml", newer)])).unwrap();
        settle(&mut store, &mut renders);
        assert!(
            state(&store)["message"]
                .as_str()
                .unwrap()
                .contains("a package does not get to make a Package")
        );
        assert!(store.get("Package/maps-9.0.0").is_none());
        assert_eq!(store.list(None).filter(|resource| owner(resource).is_some()).count(), 0);
    }

    #[test]
    fn a_release_and_what_people_do() {
        let (mut store, mut renders) = (Store::default(), Renders::new());
        // A release candidate is older than what it is a candidate for.
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        store.apply(package("1.0.0-rc1", &[("map.yaml", MAP)])).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        let status = |store: &Store| store.get("Release/shop/mine").unwrap().status.clone().unwrap();
        assert_eq!(status(&store)["version"], "1.0.0");

        // Someone copies one of its maps, annotation and all: the copy is theirs to keep.
        let mut copy = store.get("ConfigMap/shop/mine-maps").unwrap().clone();
        (copy.metadata.name, copy.metadata.revision) = ("copy".into(), None);
        assert_eq!(claims(&store, std::slice::from_ref(&copy)), Ok(()));
        store.apply(copy.clone()).unwrap();
        // Someone applies over one, and the annotation goes: it is still the release's.
        let mut over = store.get("ConfigMap/shop/mine-maps-extra").unwrap().clone();
        (over.metadata.annotations, over.metadata.revision) = (BTreeMap::new(), None);
        store.apply(over).unwrap();
        settle(&mut store, &mut renders);
        assert_eq!(status(&store)["state"], "installed");
        assert_eq!(
            owner(store.get("ConfigMap/shop/mine-maps-extra").unwrap()),
            Some("Release/shop/mine")
        );
        assert!(store.get("ConfigMap/shop/copy").is_some());

        // What a template says of revisions and statuses is dropped; the values releases
        // are given are not a package's to set.
        let stamped = MAP.replace("name: {{ name }} }", "name: {{ name }}, revision: 7 }");
        store.apply(package("1.1.0", &[("map.yaml", &stamped)])).unwrap();
        settle(&mut store, &mut renders);
        assert_eq!(
            (&status(&store)["state"], &status(&store)["version"]),
            (&json!("installed"), &json!("1.1.0"))
        );
        let shared = MAP.replace("name: {{ name }} }", "name: kith-values }");
        store.apply(package("1.2.0", &[("map.yaml", &shared)])).unwrap();
        settle(&mut store, &mut renders);
        assert!(
            status(&store)["message"]
                .as_str()
                .unwrap()
                .contains("the values releases are given")
        );

        // The release goes: the copy, which says it is the release's, goes with it; and
        // nobody applies by hand what says it belongs to a release that is not there.
        store.delete("Release/shop/mine").unwrap();
        settle(&mut store, &mut renders);
        assert!(store.get("ConfigMap/shop/copy").is_none());
        let refused = claims(&store, std::slice::from_ref(&copy)).unwrap_err();
        assert!(refused.contains("there is no Release/shop/mine"), "{refused}");
        let release = Resource::from_source(RELEASE).unwrap().remove(0).unwrap();
        assert_eq!(claims(&store, &[copy, release]), Ok(()));
    }

    /// A Package that asks for a newer kithd than runs is the Release's error, naming
    /// both, and installs nothing; one that fits, or asks for nothing, installs (T-0990).
    #[test]
    fn releases_kith_version_a_package_for_a_newer_kithd_is_not_installed() {
        let running = env!("CARGO_PKG_VERSION");
        let owned = |store: &Store| store.list(None).filter(|resource| owner(resource).is_some()).count();
        for (asked, installs) in [
            ("kithVersion: '>=99'\n", false),
            ("kithVersion: nonsense\n", false),
            ("kithVersion: '>=0.1'\n", true),
            ("", true),
        ] {
            let (mut store, mut renders) = (Store::default(), Renders::new());
            store
                .apply(package_asking("1.0.0", asked, &[("map.yaml", MAP)]))
                .unwrap();
            apply(&mut store, RELEASE);
            settle(&mut store, &mut renders);
            let (state, message) = said(&store);
            if installs {
                assert_eq!((state, owned(&store)), (json!("installed"), 2), "{asked}: {message}");
            } else {
                assert_eq!((&state, owned(&store)), (&json!("error"), 0), "{asked}");
                assert!(
                    message.contains(&format!("this kith is {running}")) && message.contains("maps 1.0.0"),
                    "{message}"
                );
            }
        }
    }

    #[test]
    fn a_release_stays_on_its_version_unless_it_follows() {
        assert!(fits(None, "1.0.0") && !fits(None, "1.0.0-rc1") && fits(Some("1.0.0-rc1"), "1.0.0-rc1"));
        assert!(
            fits(Some("1.2.0"), "1.2.0") && !fits(Some("1.2.0"), "1.2.1"),
            "one version is that one"
        );
        assert!(fits(Some("^1.2"), "1.9.0") && !fits(Some("^1.2"), "2.0.0") && fits(Some(">=1, <3"), "2.5.0"));
        assert!(!fits(Some("nonsense"), "1.0.0") && fits(Some("nightly"), "nightly"));

        let (mut store, mut renders) = (Store::default(), Renders::new());
        let version =
            |store: &Store| store.get("Release/shop/mine").unwrap().status.clone().unwrap()["version"].clone();
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        let pinned = RELEASE.replace("autoUpgrade: true", "autoUpgrade: false");
        apply(&mut store, &pinned.replace("name: maps }", "name: maps, version: ^1 }"));
        settle(&mut store, &mut renders);
        // Newer ones come: it stays; told to follow, it goes to the newest in its range.
        store.apply(package("1.5.0", &[("map.yaml", MAP)])).unwrap();
        store.apply(package("2.0.0", &[("map.yaml", MAP)])).unwrap();
        settle(&mut store, &mut renders);
        assert_eq!(version(&store), "1.0.0");
        apply(
            &mut store,
            &RELEASE.replace("name: maps }", "name: maps, version: ^1 }"),
        );
        settle(&mut store, &mut renders);
        assert_eq!(version(&store), "1.5.0");
        // A range the installed one is outside of moves it, following or not.
        apply(
            &mut store,
            &pinned.replace("name: maps }", "name: maps, version: '>=2' }"),
        );
        settle(&mut store, &mut renders);
        assert_eq!(version(&store), "2.0.0");
        // What was pushed here is not what a Repository supplied.
        apply(&mut store, &pinned.replace("name: maps }", "name: maps, repo: ours }"));
        settle(&mut store, &mut renders);
        let status = store.get("Release/shop/mine").unwrap().status.clone().unwrap();
        assert_eq!(
            (&status["state"], &status["message"]),
            (&json!("error"), &json!("there is no Repository/ours"))
        );
    }

    const SELF: &str = "Release/shop/mine";

    fn status_of(store: &Store) -> Value {
        store.get(SELF).unwrap().status.clone().unwrap()
    }

    /// A Release that is not following says in `status.pending` which resources moving to the
    /// newest fitting Package would apply and delete, from the two renders alone.
    #[test]
    fn a_release_says_what_an_upgrade_would_change() {
        let (mut store, mut renders, mut upgrades) = (Store::default(), Renders::new(), Renders::new());
        let old =
            "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: {{ name }}-old }\nspec: { data: { a: b } }\n";
        let new = old.replace("-old", "-new");
        let changed = MAP.replace("colour: {{", "colour: v2-{{");
        let pinned = RELEASE.replace("autoUpgrade: true", "autoUpgrade: false");
        let pending = |store: &Store| status_of(store)["pending"].clone();

        store
            .apply(package("1.0.0", &[("map.yaml", MAP), ("old.yaml", old)]))
            .unwrap();
        apply(&mut store, &pinned);
        settle_at(&mut store, &mut renders, &mut upgrades, 10);
        assert_eq!(pending(&store), Value::Null);
        assert!(upgrades.is_empty());

        // 1.5.0 changes `mine-maps`, adds `-new`, drops `-old`, and leaves `-extra` be.
        store
            .apply(package("1.5.0", &[("map.yaml", &changed), ("new.yaml", &new)]))
            .unwrap();
        settle_at(&mut store, &mut renders, &mut upgrades, 20);
        let expected = json!({
            "version": "1.5.0",
            "apply": ["ConfigMap/shop/mine-maps", "ConfigMap/shop/mine-maps-new"],
            "delete": ["ConfigMap/shop/mine-maps-old"],
        });
        assert_eq!(pending(&store), expected);
        assert_eq!(status_of(&store)["version"], "1.0.0");
        assert_eq!(settle_at(&mut store, &mut renders, &mut upgrades, 30), 0);

        // A hand edit to a live resource is not what an upgrade changes.
        // (`-extra` is the same in 1.5.0; planned, not carried out, so the edit is live
        // in the store when `pending` is worked out, and not yet healed.)
        let mut live = store.get("ConfigMap/shop/mine-maps-extra").unwrap().clone();
        live.spec["data"]["colour"] = json!("blue");
        store.apply(live).unwrap();
        let newer = newers(&store);
        let plan = plan(&store, &renders, &upgrades, &newer, 40);
        let step = plan.steps.iter().find(|step| step.release == SELF).unwrap();
        let healed: Vec<String> = step.apply.iter().map(|resource| resource.key()).collect();
        assert_eq!(
            healed,
            ["ConfigMap/shop/mine-maps-extra"],
            "the edit is live, and would be put back"
        );
        assert!(
            step.status
                .as_ref()
                .is_none_or(|fields| !fields.contains_key("pending")),
            "the edit moved pending: {:?}",
            step.status
        );
        assert_eq!(pending(&store), expected);
        settle_at(&mut store, &mut renders, &mut upgrades, 40);
        assert_eq!(pending(&store), expected);

        // Following, it goes there and has nothing pending; so has one that is current.
        apply(&mut store, RELEASE);
        settle_at(&mut store, &mut renders, &mut upgrades, 50);
        assert_eq!(
            (status_of(&store)["version"].clone(), pending(&store)),
            (json!("1.5.0"), Value::Null)
        );
        assert!(upgrades.is_empty());
        apply(&mut store, &pinned);
        settle_at(&mut store, &mut renders, &mut upgrades, 60);
        assert_eq!(pending(&store), Value::Null);
        assert_eq!(settle_at(&mut store, &mut renders, &mut upgrades, 61), 0);

        // A newer one whose render fails says so, and nothing else.
        store.apply(package("1.6.0", &[("map.yaml", "{% if %}")])).unwrap();
        settle_at(&mut store, &mut renders, &mut upgrades, 70);
        let failed = pending(&store);
        let mut fields: Vec<&String> = failed.as_object().unwrap().keys().collect();
        fields.sort();
        assert_eq!(
            (fields, &failed["version"]),
            (vec![&"error".to_string(), &"version".to_string()], &json!("1.6.0"))
        );
        assert!(!failed["error"].as_str().unwrap().is_empty());
        assert_eq!(settle_at(&mut store, &mut renders, &mut upgrades, 80), 0);
    }

    /// A Release whose spec is again what an earlier revision held (a `kith rollback`) goes
    /// back to the version it had then, even following the newest; what a later version made
    /// is pruned, a spec that matches no earlier one follows again, and a Package that is gone
    /// is an error that tears nothing down.
    #[test]
    fn a_rollback_brings_back_the_version_it_installed() {
        let (mut store, mut renders, mut upgrades) = (Store::default(), Renders::new(), Renders::new());
        let revision = |store: &Store| store.get(SELF).unwrap().metadata.revision.unwrap();
        let mut at = 100;
        let mut settled = |store: &mut Store| {
            at += 100;
            settle_at(store, &mut renders, &mut upgrades, at);
            assert_eq!(settle_at(store, &mut renders, &mut upgrades, at + 1), 0);
        };
        let plain = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: {{ name }} }\n\
                     spec: { data: { colour: {{ values.colour }} } }\n";
        store.apply(package("1.0.0", &[("map.yaml", plain)])).unwrap();
        apply(&mut store, RELEASE);
        settled(&mut store);
        let first = revision(&store);
        // An edit, then 2.0.0 (which makes an extra map) comes and is followed.
        apply(&mut store, &RELEASE.replace("extra: true", "extra: true, colour: blue"));
        settled(&mut store);
        store.apply(package("2.0.0", &[("map.yaml", MAP)])).unwrap();
        settled(&mut store);
        assert_eq!(status_of(&store)["version"], "2.0.0");
        assert!(store.get("ConfigMap/shop/mine-maps-extra").is_some());
        // Rolled back to the first revision: 1.0.0 again, the extra map pruned.
        store.rollback(SELF, first).unwrap();
        settled(&mut store);
        assert_eq!(status_of(&store)["version"], "1.0.0");
        assert!(store.get("ConfigMap/shop/mine-maps-extra").is_none());
        // A newer Package does not move it.
        store.apply(package("3.0.0", &[("map.yaml", MAP)])).unwrap();
        settled(&mut store);
        assert_eq!(status_of(&store)["version"], "1.0.0");
        assert_eq!(status_of(&store)["pinned"], true);
        // A spec equal to no earlier revision follows again.
        apply(
            &mut store,
            &RELEASE.replace("extra: true", "extra: true, colour: green"),
        );
        settled(&mut store);
        assert_eq!(status_of(&store)["version"], "3.0.0");
        assert_eq!(status_of(&store)["pinned"], false);
        assert!(store.get("ConfigMap/shop/mine-maps-extra").is_some());
        // Back again with 1.0.0 gone: an error, and nothing is torn down.
        store.rollback(SELF, first).unwrap();
        store.delete("Package/maps-1.0.0").unwrap();
        settled(&mut store);
        let status = status_of(&store);
        assert_eq!(status["state"], "error");
        let message = status["message"].as_str().unwrap();
        assert!(
            message.contains("no Package maps 1.0.0") && message.contains("push it again"),
            "{message}"
        );
        // (Said in the error too: a patch merges, so it would else keep the last pass's.)
        assert_eq!(status["pinned"], true);
        assert!(store.get("ConfigMap/shop/mine-maps-extra").is_some());
        assert!(store.get("ConfigMap/shop/mine-maps").is_some());
    }

    /// A rollback to the oldest version the history remembers stays: installing it pushes the
    /// eleventh entry and drops the one the pin was read from.
    #[test]
    fn a_rollback_to_the_oldest_remembered_version_stays() {
        let (mut store, mut renders, mut upgrades) = (Store::default(), Renders::new(), Renders::new());
        let mut at = 100;
        let mut settled = |store: &mut Store| {
            at += 100;
            settle_at(store, &mut renders, &mut upgrades, at);
            assert_eq!(settle_at(store, &mut renders, &mut upgrades, at + 1), 0);
        };
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        apply(&mut store, RELEASE);
        settled(&mut store);
        let first = store.get(SELF).unwrap().metadata.revision.unwrap();
        apply(&mut store, &RELEASE.replace("extra: true", "extra: true, colour: blue"));
        for major in 2..=10 {
            store
                .apply(package(&format!("{major}.0.0"), &[("map.yaml", MAP)]))
                .unwrap();
            settled(&mut store);
        }
        assert_eq!(status_of(&store)["history"].as_array().unwrap().len(), 10);
        store.rollback(SELF, first).unwrap();
        settled(&mut store);
        assert_eq!(status_of(&store)["version"], "1.0.0");
        assert_eq!(status_of(&store)["pinned"], true);
        // (Still, with the entry it came from gone, and after one more pass.)
        settled(&mut store);
        assert_eq!(status_of(&store)["version"], "1.0.0");
        assert_eq!(status_of(&store)["history"].as_array().unwrap().len(), 10);
    }

    /// An edit back to an earlier spec pins like a rollback, whatever it was made by: the
    /// toggle of `autoUpgrade` off and on again does; a change to the metadata alone is not
    /// one; and a Release that does not follow is never pinned.
    #[test]
    fn an_edit_back_to_an_earlier_spec_pins_and_a_new_field_follows() {
        let (mut store, mut renders, mut upgrades) = (Store::default(), Renders::new(), Renders::new());
        let mut at = 100;
        let mut settled = |store: &mut Store| {
            at += 100;
            settle_at(store, &mut renders, &mut upgrades, at);
            assert_eq!(settle_at(store, &mut renders, &mut upgrades, at + 1), 0);
        };
        let version = |store: &Store| status_of(store)["version"].clone();
        let pinned = |store: &Store| status_of(store)["pinned"].clone();
        let push = |store: &mut Store, version: &str| store.apply(package(version, &[("map.yaml", MAP)])).unwrap();
        push(&mut store, "1.0.0");
        apply(&mut store, RELEASE);
        settled(&mut store);
        push(&mut store, "2.0.0");
        settled(&mut store);
        // A freeze (autoUpgrade off) stays; on again it is the first spec: pinned, not following.
        apply(&mut store, &RELEASE.replace("autoUpgrade: true", "autoUpgrade: false"));
        push(&mut store, "3.0.0");
        settled(&mut store);
        assert_eq!((version(&store), pinned(&store)), (json!("2.0.0"), json!(false)));
        apply(&mut store, RELEASE);
        push(&mut store, "4.0.0");
        settled(&mut store);
        assert_eq!((version(&store), pinned(&store)), (json!("2.0.0"), json!(true)));
        // Any field that is new follows again.
        apply(&mut store, &RELEASE.replace("extra: true", "extra: true, colour: blue"));
        settled(&mut store);
        assert_eq!((version(&store), pinned(&store)), (json!("4.0.0"), json!(false)));
        // A change to the annotations alone is not a return to anything.
        let noted = RELEASE.replace("extra: true", "extra: true, colour: blue");
        apply(
            &mut store,
            &noted.replace("'local socket' }", "'local socket', note: x }"),
        );
        push(&mut store, "5.0.0");
        settled(&mut store);
        assert_eq!((version(&store), pinned(&store)), (json!("5.0.0"), json!(false)));
    }

    #[test]
    fn a_release_that_stays_is_never_pinned() {
        let (mut store, mut renders, mut upgrades) = (Store::default(), Renders::new(), Renders::new());
        let stays = RELEASE.replace("autoUpgrade: true", "autoUpgrade: false");
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        apply(&mut store, &stays);
        settle_at(&mut store, &mut renders, &mut upgrades, 10);
        let first = store.get(SELF).unwrap().metadata.revision.unwrap();
        apply(&mut store, &stays.replace("extra: true", "extra: false"));
        settle_at(&mut store, &mut renders, &mut upgrades, 20);
        store.apply(package("2.0.0", &[("map.yaml", MAP)])).unwrap();
        store.rollback(SELF, first).unwrap();
        settle_at(&mut store, &mut renders, &mut upgrades, 30);
        assert_eq!(status_of(&store)["pinned"], false);
        assert_eq!(status_of(&store)["version"], "1.0.0");
    }

    /// `status.history` has one entry per version installed (newest last, the last ten), so
    /// writing it never makes another turn.
    #[test]
    fn a_release_keeps_a_history_without_a_write_loop() {
        let (mut store, mut renders, mut upgrades) = (Store::default(), Renders::new(), Renders::new());
        let revision = |store: &Store| store.get(SELF).unwrap().metadata.revision;
        let history = |store: &Store| status_of(store)["history"].clone();
        let mut at = 100;
        let mut settled = |store: &mut Store| {
            at += 100;
            settle_at(store, &mut renders, &mut upgrades, at);
            assert_eq!(settle_at(store, &mut renders, &mut upgrades, at + 1), 0);
            at
        };
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        apply(&mut store, RELEASE);
        let first = revision(&store);
        let at1 = settled(&mut store);
        assert_eq!(
            history(&store),
            json!([{ "version": "1.0.0", "revision": first, "at": at1 }])
        );

        store.apply(package("2.0.0", &[("map.yaml", MAP)])).unwrap();
        let at2 = settled(&mut store);
        let both = json!([
            { "version": "1.0.0", "revision": first, "at": at1 },
            { "version": "2.0.0", "revision": first, "at": at2 },
        ]);
        assert_eq!(history(&store), both);

        // A spec edit at the same version adds nothing.
        apply(&mut store, &RELEASE.replace("extra: true", "extra: false"));
        assert_ne!(revision(&store), first);
        settled(&mut store);
        assert_eq!(history(&store), both);

        // A move back to an older version is another entry.
        let back = RELEASE.replace("autoUpgrade: true", "autoUpgrade: false");
        apply(
            &mut store,
            &back.replace("name: maps }", "name: maps, version: 1.0.0 }"),
        );
        let at3 = settled(&mut store);
        assert_eq!(status_of(&store)["version"], "1.0.0");
        let entries = history(&store);
        assert_eq!(
            entries.as_array().unwrap()[2],
            json!({ "version": "1.0.0", "revision": revision(&store), "at": at3 })
        );
        assert_eq!(entries.as_array().unwrap().len(), 3);

        // Eleven more installs keep the last ten. (A spec that is new: one equal to an earlier
        // one is a rollback, and holds its version.)
        apply(&mut store, &RELEASE.replace("extra: true", "extra: true, colour: teal"));
        for minor in 3..=13 {
            store
                .apply(package(&format!("{minor}.0.0"), &[("map.yaml", MAP)]))
                .unwrap();
            settled(&mut store);
        }
        let entries = history(&store);
        let versions: Vec<&str> = entries
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["version"].as_str().unwrap())
            .collect();
        assert_eq!(
            versions,
            [
                "4.0.0", "5.0.0", "6.0.0", "7.0.0", "8.0.0", "9.0.0", "10.0.0", "11.0.0", "12.0.0", "13.0.0"
            ]
        );
    }

    /// The Identity bob, who may apply and delete `kinds` (a YAML list's insides) in shop.
    fn bob(store: &mut Store, kinds: &str) {
        apply(
            store,
            &format!(
                "apiVersion: kith.dev/v1\nkind: Role\nmetadata: {{ name: shop }}\n\
                 spec: {{ rules: [{{ kinds: [{kinds}], verbs: [apply, delete], namespaces: [shop] }}] }}\n---\n\
                 apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {{ name: bob-shop }}\nspec: {{ role: shop, subjects: [bob] }}\n"
            ),
        );
        bob_is(store, 0);
    }

    fn said(store: &Store) -> (Value, String) {
        let status = store.get("Release/shop/mine").unwrap().status.clone().unwrap();
        let message = status["message"].as_str().unwrap_or_default().to_string();
        (status["state"].clone(), message)
    }

    /// A Release makes what whoever applied it may make, and nothing more: one who may
    /// write Releases and no Secret gets no Secret by way of a package.
    #[test]
    fn release_rights_a_release_makes_nothing_its_writer_may_not() {
        let as_bob = by_bob(RELEASE, 0);
        let kinds = [
            ("Secret", "spec: { data: { k: v } }"),
            ("Backup", "spec: { volume: v, every: 1d }"),
            ("Share", "spec: { volume: v, users: [bob] }"),
            (
                "Workload",
                "spec: { template: { exec: [{ name: run, command: [sleep, inf] }] } }",
            ),
        ];
        for (kind, spec) in kinds {
            let (mut store, mut renders) = (Store::default(), Renders::new());
            bob(&mut store, "Release, ConfigMap");
            let template = format!("apiVersion: kith.dev/v1\nkind: {kind}\nmetadata: {{ name: x }}\n{spec}\n");
            store
                .apply(package("1.0.0", &[("map.yaml", MAP), ("x.yaml", &template)]))
                .unwrap();
            apply(&mut store, &as_bob);
            settle(&mut store, &mut renders);
            let (state, message) = said(&store);
            assert_eq!(state, "error", "{message}");
            assert!(
                message.contains(&format!("{kind}/shop/x: "))
                    && message.contains(&format!("bob may not apply {kind} in namespace shop")),
                "{message}"
            );
            let owned = store.list(None).filter(|resource| owner(resource).is_some());
            assert_eq!(owned.count(), 0, "all of a release or none of it");
        }
        // What a resource reaches into is the writer's to reach too: a Share is a Volume's files.
        let (mut store, mut renders) = (Store::default(), Renders::new());
        bob(&mut store, "Release, ConfigMap, Share");
        let share = "apiVersion: kith.dev/v1\nkind: Share\nmetadata: { name: x }\nspec: { volume: v, users: [bob] }\n";
        store
            .apply(package("1.0.0", &[("map.yaml", MAP), ("x.yaml", share)]))
            .unwrap();
        apply(&mut store, &as_bob);
        settle(&mut store, &mut renders);
        let (_, message) = said(&store);
        assert!(
            message.contains("Share/shop/x: ") && message.contains("bob may not apply Volume in namespace shop"),
            "{message}"
        );
        // Who may make all of it: installed. So is what the local socket applied.
        let (mut store, mut renders) = (Store::default(), Renders::new());
        bob(&mut store, "Release, ConfigMap");
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        apply(&mut store, &as_bob);
        settle(&mut store, &mut renders);
        assert_eq!(said(&store).0, "installed", "{}", said(&store).1);
        let secret = "apiVersion: kith.dev/v1\nkind: Secret\nmetadata: { name: x }\nspec: { data: { k: v } }\n";
        store
            .apply(package("2.0.0", &[("map.yaml", MAP), ("x.yaml", secret)]))
            .unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        assert_eq!(said(&store).0, "installed", "{}", said(&store).1);
        assert!(store.get("Secret/shop/x").is_some());
    }

    /// A writer that loses its rights, or is gone: what was installed stays, nothing new is
    /// made or taken away, and the Release says whose rights fell short. One with no writer
    /// written down acts as nobody, not as the cluster.
    #[test]
    fn rights_later_a_release_whose_writer_may_no_longer_installs_nothing_new() {
        let as_bob = by_bob(RELEASE, 0);
        let keys = |store: &Store| -> Vec<String> {
            let owned = store.list(None).filter(|resource| owner(resource).is_some());
            owned.map(Resource::key).collect()
        };
        let (mut store, mut renders) = (Store::default(), Renders::new());
        bob(&mut store, "Release, ConfigMap");
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        apply(&mut store, &as_bob);
        settle(&mut store, &mut renders);
        assert_eq!(keys(&store).len(), 2);
        // The status written does not touch who wrote it.
        let writer = |store: &Store| {
            let release = store.get("Release/shop/mine").unwrap();
            release.metadata.annotations.get("kith.dev/written-by").cloned()
        };
        assert_eq!(writer(&store).as_deref(), Some("bob"));

        // bob may write ConfigMaps no more; the release asks for one map fewer.
        store.delete("RoleBinding/bob-shop").unwrap();
        apply(&mut store, &as_bob.replace("extra: true", "extra: false"));
        settle(&mut store, &mut renders);
        let (state, message) = said(&store);
        assert_eq!(state, "error");
        assert!(
            message.contains("ConfigMap/shop/mine-maps: ")
                && message.contains("bob may not apply ConfigMap in namespace shop"),
            "{message}"
        );
        assert_eq!(keys(&store).len(), 2, "a refused render takes nothing away");
        assert_eq!(writer(&store).as_deref(), Some("bob"));

        // The rights back, and the Identity gone: the same, said so.
        bob(&mut store, "Release, ConfigMap");
        store.delete("Identity/bob").unwrap();
        settle(&mut store, &mut renders);
        let (_, message) = said(&store);
        assert!(message.contains("there is no Identity bob"), "{message}");
        assert_eq!(keys(&store).len(), 2);
        // Back: the extra map goes, as asked.
        bob(&mut store, "Release, ConfigMap");
        settle(&mut store, &mut renders);
        assert_eq!((said(&store).0, keys(&store).len()), (json!("installed"), 1));

        // Applied before anyone wrote the writer down, or by one kithd does not act as:
        // nothing new, and how to mend it.
        for written in ["", ", annotations: { 'kith.dev/written-by': 'node n1' }"] {
            let release = as_bob.replace(&format!(", {}", bobs_note(0)), written);
            apply(&mut store, &release.replace("extra: false", "extra: true"));
            settle(&mut store, &mut renders);
            let (state, message) = said(&store);
            assert_eq!(state, "error");
            assert!(message.contains("apply it again"), "{message}");
            assert_eq!(keys(&store).len(), 1);
        }
    }

    /// A Release that names a Repository is supplied from it only when whoever applied it
    /// may apply Packages, the right a pull by hand takes (T-0546). Without it the status
    /// says whose right fell short; a Package that is here already installs as before.
    #[test]
    fn fetch_rights_a_release_is_supplied_only_when_its_writer_may_apply_packages() {
        const HUB: &str = "apiVersion: kith.dev/v1\nkind: Repository\nmetadata: { name: hub }\n\
                           spec: { url: 'oci://127.0.0.1:1/kith' }\n";
        let from_hub = RELEASE.replace("name: maps }", "name: maps, repo: hub }");
        let as_bob = by_bob(&from_hub, 0);
        let (mut store, mut renders) = (Store::default(), Renders::new());
        apply(&mut store, HUB);
        // A Role in one namespace reaches no Package, whatever kinds it lists: Packages are
        // in no namespace.
        bob(&mut store, "Release, ConfigMap, Package");
        apply(&mut store, &as_bob);
        let release = |store: &Store| store.get("Release/shop/mine").unwrap().clone();
        let refused = supplied(&store, &release(&store)).unwrap_err();
        assert!(refused.contains("bob may not apply Package"), "{refused}");
        settle(&mut store, &mut renders);
        let (state, message) = said(&store);
        assert_eq!(state, "error");
        assert!(
            message.contains("Repository/hub") && message.contains("bob may not apply Package"),
            "{message}"
        );

        // With the right, in every namespace: asked for, and said to be on its way.
        apply(
            &mut store,
            "apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: packages }\n\
             spec: { rules: [{ kinds: [Package], verbs: [apply] }] }\n---\n\
             apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: bob-packages }\n\
             spec: { role: packages, subjects: [bob] }\n",
        );
        assert_eq!(supplied(&store, &release(&store)), Ok(()));
        // The local socket's; and nobody's, or a node's, for whom nothing is fetched.
        apply(&mut store, &from_hub);
        assert_eq!(supplied(&store, &release(&store)), Ok(()));
        for written in ["", ", annotations: { 'kith.dev/written-by': 'node n1' }"] {
            apply(&mut store, &as_bob.replace(&format!(", {}", bobs_note(0)), written));
            let refused = supplied(&store, &release(&store)).unwrap_err();
            assert!(refused.contains("apply it again"), "{refused}");
        }

        // The right gone again, and the Package here already (from that Repository): it
        // installs, since what it makes is asked of bob as ever.
        store.delete("RoleBinding/bob-packages").unwrap();
        apply(&mut store, &as_bob);
        let mut here = package("1.0.0", &[("map.yaml", MAP)]);
        here.metadata
            .annotations
            .insert(REPOSITORY.into(), origin(&store, "hub").unwrap());
        store.apply(here).unwrap();
        settle(&mut store, &mut renders);
        let (state, message) = said(&store);
        assert_eq!(state, json!("installed"), "{message}");
        // Following the newest, it says no newer one is looked for, and why (T-0575).
        assert!(
            message.contains("no newer Package is looked for") && message.contains("bob may not apply Package"),
            "{message}"
        );
        // Not following the newest, there is nothing to look for, and nothing said.
        apply(&mut store, &as_bob.replace("autoUpgrade: true", "autoUpgrade: false"));
        settle(&mut store, &mut renders);
        assert_eq!(said(&store), (json!("installed"), String::new()));
    }

    /// What a Release installs by its writer's rights is for that Identity's key: one made
    /// again under the name (another key, wider Roles) gets nothing of the old one's Release,
    /// not a Package fetched for it either; applied again by the new one it goes on (T-0551).
    #[test]
    fn writer_key_a_release_is_not_acted_on_for_an_identity_made_again_under_its_name() {
        let from_hub = RELEASE.replace("name: maps }", "name: maps, repo: hub }");
        let owned = |store: &Store| store.list(None).filter(|resource| owner(resource).is_some()).count();
        let (mut store, mut renders) = (Store::default(), Renders::new());
        bob(&mut store, "Release, ConfigMap");
        apply(
            &mut store,
            "apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: packages }\n\
             spec: { rules: [{ kinds: [Package], verbs: [apply] }] }\n---\n\
             apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: bob-packages }\n\
             spec: { role: packages, subjects: [bob] }\n",
        );
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        apply(&mut store, &by_bob(RELEASE, 0));
        settle(&mut store, &mut renders);
        assert_eq!((said(&store).0, owned(&store)), (json!("installed"), 2));
        apply(&mut store, &by_bob(&from_hub, 0));
        let release = |store: &Store| store.get("Release/shop/mine").unwrap().clone();
        assert_eq!(supplied(&store, &release(&store)), Ok(()));

        // bob removed and made again with another key, whose Roles allow more.
        store.delete("Identity/bob").unwrap();
        bob_is(&mut store, 1);
        let refused = supplied(&store, &release(&store)).unwrap_err();
        assert!(
            refused.contains("an earlier Identity named bob") && refused.contains("apply it again"),
            "{refused}"
        );
        apply(&mut store, &by_bob(&RELEASE.replace("extra: true", "extra: false"), 0));
        settle(&mut store, &mut renders);
        let (state, message) = said(&store);
        assert_eq!(state, "error");
        assert!(
            message.contains("an earlier Identity named bob") && message.contains("apply it again"),
            "{message}"
        );
        assert_eq!(
            owned(&store),
            2,
            "what was installed stays, and nothing new is made or taken"
        );

        // Applied again by the new one: it goes on.
        apply(&mut store, &by_bob(&RELEASE.replace("extra: true", "extra: false"), 1));
        settle(&mut store, &mut renders);
        assert_eq!((said(&store).0, owned(&store)), (json!("installed"), 1));
        apply(&mut store, &by_bob(&from_hub, 1));
        assert_eq!(supplied(&store, &release(&store)), Ok(()));
    }

    /// A Release's writer is its name and its key's print: the local socket's has no print
    /// and works; a name with no print (written before), or the print of a key the Identity
    /// no longer has (a new certificate), makes nothing new and says to apply it again.
    #[test]
    fn writer_print_a_release_needs_the_key_its_writer_has_now() {
        let owned = |store: &Store| store.list(None).filter(|resource| owner(resource).is_some()).count();
        let (mut store, mut renders) = (Store::default(), Renders::new());
        bob(&mut store, "Release, ConfigMap");
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        assert_eq!((said(&store).0, owned(&store)), (json!("installed"), 2));

        let more = RELEASE.replace("extra: true", "extra: false");
        let name_only = more.replace("'local socket'", "'bob'");
        let mut again = |store: &mut Store, release: &str| {
            apply(store, release);
            settle(store, &mut renders);
            said(store)
        };
        let (state, message) = again(&mut store, &name_only);
        assert_eq!(state, "error");
        assert!(message.contains("apply it again"), "{message}");
        // A new certificate: the Identity has a key the Release's print is not.
        bob_is(&mut store, 1);
        let (state, message) = again(&mut store, &by_bob(&more, 0));
        assert_eq!(state, "error");
        assert!(message.contains("apply it again"), "{message}");
        assert_eq!(owned(&store), 2, "nothing is taken away or made");
        let (state, message) = again(&mut store, &by_bob(&more, 1));
        assert_eq!((state, owned(&store)), (json!("installed"), 1), "{message}");
    }

    /// A Package is rendered with no more than its pusher's rights, besides its Release
    /// writer's: one who may push Packages and nothing else cannot publish a version an
    /// admin's autoUpgrade Release then renders with the admin's rights (T-0550).
    #[test]
    fn package_rights_a_package_makes_nothing_its_pusher_may_not() {
        let secret = "apiVersion: kith.dev/v1\nkind: Secret\nmetadata: { name: x }\nspec: { data: { k: v } }\n";
        let owned = |store: &Store| store.list(None).filter(|resource| owner(resource).is_some()).count();
        let (mut store, mut renders) = (Store::default(), Renders::new());
        bob(&mut store, "ConfigMap");
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        assert_eq!((said(&store).0, owned(&store)), (json!("installed"), 2));

        // bob pushes 2.0.0, which makes a Secret: the Release (the local socket's, which
        // may) follows the newest, and gets none of it.
        let two = package("2.0.0", &[("map.yaml", MAP), ("x.yaml", secret)]);
        store.apply(pushed_by_bob(two, 0)).unwrap();
        settle(&mut store, &mut renders);
        let (state, message) = said(&store);
        assert_eq!(state, "error", "{message}");
        assert!(
            message.contains("Package/maps-2.0.0")
                && message.contains("Secret/shop/x")
                && message.contains("bob may not apply Secret in namespace shop"),
            "{message}"
        );
        assert_eq!(owned(&store), 2, "what was installed stays, nothing new");
        assert!(store.get("Secret/shop/x").is_none());

        // The same for a version the Release names, pushed again by one without rights.
        let pinned = RELEASE
            .replace("autoUpgrade: true, ", "")
            .replace("name: maps }", "name: maps, version: 3.0.0 }");
        store.apply(package("3.0.0", &[("map.yaml", MAP)])).unwrap();
        apply(&mut store, &pinned);
        settle(&mut store, &mut renders);
        assert_eq!(said(&store).0, "installed", "{}", said(&store).1);
        let three = package("3.0.0", &[("map.yaml", MAP), ("x.yaml", secret)]);
        store.apply(pushed_by_bob(three, 0)).unwrap();
        settle(&mut store, &mut renders);
        let (state, message) = said(&store);
        assert_eq!(state, "error", "{message}");
        assert!(message.contains("Package/maps-3.0.0"), "{message}");
        assert!(store.get("Secret/shop/x").is_none());

        // What a Package's pusher may not delete stays as well: bob may apply, not delete.
        let (mut store, mut renders) = (Store::default(), Renders::new());
        apply(
            &mut store,
            "apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: shop }\n\
             spec: { rules: [{ kinds: [ConfigMap], verbs: [apply], namespaces: [shop] }] }\n---\n\
             apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: bob-shop }\nspec: { role: shop, subjects: [bob] }\n",
        );
        bob_is(&mut store, 0);
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        assert_eq!(owned(&store), 2);
        let fewer = RELEASE.replace("extra: true", "extra: false");
        store
            .apply(pushed_by_bob(package("1.0.0", &[("map.yaml", MAP)]), 0))
            .unwrap();
        apply(&mut store, &fewer);
        settle(&mut store, &mut renders);
        let (state, message) = said(&store);
        assert_eq!(state, "error", "{message}");
        assert!(
            message.contains("bob may not delete ConfigMap in namespace shop"),
            "{message}"
        );
        assert_eq!(owned(&store), 2);
        // Pushed again through the local socket: it goes on.
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        settle(&mut store, &mut renders);
        assert_eq!((said(&store).0, owned(&store)), (json!("installed"), 1));
    }

    /// The pusher check is skipped only for a Package that carries the origin of the
    /// Repository its Release names: a Package annotated for another Repository, or for
    /// one that is not there, or met by a Release that names none, is no fetched one, and
    /// is asked of its pusher (T-0550).
    #[test]
    fn package_origin_only_the_named_repositorys_own_is_taken_as_fetched() {
        const HUB: &str = "apiVersion: kith.dev/v1\nkind: Repository\nmetadata: { name: hub }\n\
                           spec: { url: 'oci://127.0.0.1:1/kith' }\n";
        let secret = "apiVersion: kith.dev/v1\nkind: Secret\nmetadata: { name: x }\nspec: { data: { k: v } }\n";
        let annotated = |origin: String| {
            let mut package = pushed_by_bob(package("1.0.0", &[("map.yaml", MAP), ("x.yaml", secret)]), 0);
            package.metadata.annotations.insert(REPOSITORY.into(), origin);
            package
        };
        let (mut store, mut renders) = (Store::default(), Renders::new());
        apply(&mut store, HUB);
        bob(&mut store, "ConfigMap");
        let hubs = origin(&store, "hub").unwrap();

        // A Release that names no Repository does not take one a Repository supplied.
        store.apply(annotated(hubs.clone())).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        let (state, message) = said(&store);
        assert_eq!(state, "error", "{message}");
        assert!(message.contains("there is no Package maps"), "{message}");
        assert!(store.get("Secret/shop/x").is_none());

        // One that names a Repository that is not there takes an annotation it cannot
        // match, and is asked of the pusher.
        store.apply(annotated(String::new())).unwrap();
        apply(
            &mut store,
            &RELEASE.replace("name: maps }", "name: maps, repo: ghost }"),
        );
        settle(&mut store, &mut renders);
        let (state, message) = said(&store);
        assert_eq!(state, "error", "{message}");
        assert!(store.get("Secret/shop/x").is_none(), "{message}");

        // The Repository it names, and its own origin: a fetched one, not asked of a pusher.
        store.apply(annotated(hubs)).unwrap();
        apply(&mut store, &RELEASE.replace("name: maps }", "name: maps, repo: hub }"));
        settle(&mut store, &mut renders);
        assert_eq!(said(&store).0, "installed", "{}", said(&store).1);
        assert!(store.get("Secret/shop/x").is_some());
    }

    /// A Package's writer is its name and its key's print: the local socket's renders as
    /// before; nobody written down, a node, one gone or made again under the name, makes
    /// nothing new and says to push it again; one fetched from a Repository has no pusher,
    /// the Repository's key is what it is trusted by.
    #[test]
    fn package_writer_a_package_is_acted_on_for_the_pusher_it_had() {
        let owned = |store: &Store| store.list(None).filter(|resource| owner(resource).is_some()).count();
        let plain = || package("1.0.0", &[("map.yaml", MAP)]);
        let fewer = RELEASE.replace("extra: true", "extra: false");
        let (mut store, mut renders) = (Store::default(), Renders::new());
        bob(&mut store, "ConfigMap");
        store.apply(plain()).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        assert_eq!((said(&store).0, owned(&store)), (json!("installed"), 2));

        let mut again = |store: &mut Store, package: Resource, release: &str| {
            store.apply(package).unwrap();
            apply(store, release);
            settle(store, &mut renders);
            said(store)
        };
        // Nobody written down, or a node: nothing new, and how to mend it.
        for written in [None, Some("node n1")] {
            let mut package = plain();
            package.metadata.annotations.remove(WRITER);
            if let Some(written) = written {
                package.metadata.annotations.insert(WRITER.into(), written.into());
            }
            let (state, message) = again(&mut store, package, &fewer);
            assert_eq!(state, "error", "{message}");
            assert!(
                message.contains("Package/maps-1.0.0") && message.contains("push it again"),
                "{message}"
            );
            assert_eq!(owned(&store), 2);
        }
        // bob, with the key he had: as he may.
        let (state, message) = again(&mut store, pushed_by_bob(plain(), 0), &fewer);
        assert_eq!((state, owned(&store)), (json!("installed"), 1), "{message}");

        // bob made again under the name, or gone.
        bob_is(&mut store, 1);
        let (state, message) = again(&mut store, pushed_by_bob(plain(), 0), RELEASE);
        assert_eq!(state, "error", "{message}");
        assert!(
            message.contains("an earlier Identity named bob") && message.contains("push it again"),
            "{message}"
        );
        assert_eq!(owned(&store), 1);
        store.delete("Identity/bob").unwrap();
        let (_, message) = again(&mut store, pushed_by_bob(plain(), 0), RELEASE);
        assert!(message.contains("there is no Identity bob"), "{message}");
        assert_eq!(owned(&store), 1);
        // Pushed again by the new bob: it goes on.
        bob_is(&mut store, 1);
        let (state, message) = again(&mut store, pushed_by_bob(plain(), 1), RELEASE);
        assert_eq!((state, owned(&store)), (json!("installed"), 2), "{message}");

        // A Package a Repository supplied has no pusher: the Repository's key is its trust.
        let (mut store, mut renders) = (Store::default(), Renders::new());
        apply(
            &mut store,
            "apiVersion: kith.dev/v1\nkind: Repository\nmetadata: { name: hub }\nspec: { url: 'oci://127.0.0.1:1/kith' }\n",
        );
        let mut here = plain();
        here.metadata.annotations.remove(WRITER);
        here.metadata
            .annotations
            .insert(REPOSITORY.into(), origin(&store, "hub").unwrap());
        store.apply(here).unwrap();
        apply(&mut store, &RELEASE.replace("name: maps }", "name: maps, repo: hub }"));
        settle(&mut store, &mut renders);
        assert_eq!(said(&store).0, json!("installed"), "{}", said(&store).1);
    }

    /// `lookup` in a template reads a live resource of the release's namespace, and the
    /// release is rendered again when one it looked up changes (not for any other change),
    /// by what its writer may read, and not without end when it looks up what it makes.
    #[test]
    fn lookup_a_release_renders_again_when_what_it_looked_up_changes() {
        const PEEK: &str = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: {{ name }}-peek }\n\
                            spec: { data: { peer: \"{{ (lookup('ConfigMap', release.namespace, 'upstream').data | default({})).addr | default('none') }}\" } }\n---\n\
                            apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: {{ name }}-self }\n\
                            spec: { data: { seen: \"{{ 'yes' if lookup('ConfigMap', release.namespace, name ~ '-self') else 'no' }}\" } }\n";
        let upstream = |addr: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: {{ name: upstream, namespace: shop }}\nspec: {{ data: {{ addr: {addr} }} }}\n"
            )
        };
        let data = |store: &Store, name: &str, field: &str| {
            store.get(&format!("ConfigMap/shop/{name}")).unwrap().spec["data"][field].clone()
        };
        let (mut store, mut renders) = (Store::default(), Renders::new());
        store.apply(package("1.0.0", &[("peek.yaml", PEEK)])).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        assert_eq!(said(&store).0, json!("installed"), "{}", said(&store).1);
        assert_eq!(data(&store, "mine-maps-peek", "peer"), "none", "absent: an empty map");
        assert_eq!(
            data(&store, "mine-maps-self", "seen"),
            "yes",
            "what it made is seen, and it settles"
        );

        // The resource comes, then changes: each renders the release again.
        apply(&mut store, &upstream("a"));
        settle(&mut store, &mut renders);
        assert_eq!(data(&store, "mine-maps-peek", "peer"), "a");
        apply(&mut store, &upstream("b"));
        settle(&mut store, &mut renders);
        assert_eq!(data(&store, "mine-maps-peek", "peer"), "b");

        // One it never looked up changes: nothing is rendered again.
        apply(
            &mut store,
            "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: other, namespace: shop }\nspec: { data: { a: b } }\n",
        );
        assert!(pending(&store, &renders).is_empty());
        // And gone is a change too.
        store.delete("ConfigMap/shop/upstream").unwrap();
        settle(&mut store, &mut renders);
        assert_eq!(data(&store, "mine-maps-peek", "peer"), "none");

        // A writer that may apply ConfigMaps and not read them looks at nothing.
        let (mut store, mut renders) = (Store::default(), Renders::new());
        bob(&mut store, "ConfigMap");
        store
            .apply(pushed_by_bob(package("1.0.0", &[("peek.yaml", PEEK)]), 0))
            .unwrap();
        apply(&mut store, &upstream("a"));
        apply(&mut store, &by_bob(RELEASE, 0));
        settle(&mut store, &mut renders);
        assert_eq!(said(&store).0, json!("installed"), "{}", said(&store).1);
        assert_eq!(data(&store, "mine-maps-peek", "peer"), "none");
    }

    /// What it may read is capped: past the cap, `lookup` says so, and the rest renders.
    #[test]
    fn lookup_a_namespace_too_big_to_hand_over_fails_the_lookup_alone() {
        let (mut store, mut renders) = (Store::default(), Renders::new());
        let big = "x".repeat(LIVE_LIMIT + 1);
        apply(
            &mut store,
            &format!(
                "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: {{ name: big, namespace: shop }}\nspec: {{ data: {{ a: {big} }} }}\n"
            ),
        );
        let peek = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: {{ name }}-peek }\nspec: { data: { a: \"{{ lookup('ConfigMap', release.namespace, 'big') | length }}\" } }\n";
        store.apply(package("1.0.0", &[("peek.yaml", peek)])).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        let (state, message) = said(&store);
        assert_eq!(state, "error", "{message}");
        assert!(message.contains("more than 1 MB"), "{message}");
        // A package that never looks anything up is not asked for the snapshot.
        store.apply(package("2.0.0", &[("map.yaml", MAP)])).unwrap();
        settle(&mut store, &mut renders);
        assert_eq!(said(&store).0, json!("installed"), "{}", said(&store).1);
    }

    const UPSTREAM: &str = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: upstream, namespace: shop }\n\
                            spec: { data: { addr: {addr} } }\n";
    const PEEKS: &str = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: {{ name }}-peek }\n\
                         spec: { data: { peer: \"{{ (lookup('ConfigMap', release.namespace, 'upstream').data | default({})).addr | default('none') }}\" } }\n";

    /// The NOTES file looks things up too, and a package that does so in NOTES alone is
    /// rendered again when what it looked up changes.
    #[test]
    fn lookup_in_the_notes_alone_is_rendered_again_on_a_change() {
        let (mut store, mut renders) = (Store::default(), Renders::new());
        let files = BTreeMap::from([
            ("package.yaml".to_string(), "name: maps\nversion: 1.0.0\n".to_string()),
            ("templates/map.yaml".to_string(), MAP.to_string()),
            (
                "NOTES".to_string(),
                "peer {{ (lookup('ConfigMap', release.namespace, 'upstream').data | default({})).addr | default('none') }}"
                    .to_string(),
            ),
            ("values.yaml".to_string(), "colour: red\n".to_string()),
        ]);
        let mut notes = Package::from_files(files).unwrap().resource().unwrap();
        notes.metadata.annotations.insert(WRITER.into(), "local socket".into());
        store.apply(notes).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        let notes = |store: &Store| store.get("Release/shop/mine").unwrap().status.clone().unwrap()["notes"].clone();
        assert_eq!(notes(&store), "peer none");
        apply(&mut store, &UPSTREAM.replace("{addr}", "a"));
        settle(&mut store, &mut renders);
        assert_eq!(notes(&store), "peer a");
    }

    /// What `lookup` reads depends on its writer's rights: narrowing a Role renders the
    /// Release again, and the rest of the lookup then finds nothing.
    #[test]
    fn lookup_a_release_renders_again_when_its_writers_rights_change() {
        let role = |verbs: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: Role\nmetadata: {{ name: shop }}\n\
                 spec: {{ rules: [{{ kinds: [ConfigMap], verbs: [{verbs}], namespaces: [shop] }}] }}\n"
            )
        };
        let (mut store, mut renders) = (Store::default(), Renders::new());
        bob(&mut store, "ConfigMap");
        apply(&mut store, &role("apply, delete, get"));
        store
            .apply(pushed_by_bob(package("1.0.0", &[("peek.yaml", PEEKS)]), 0))
            .unwrap();
        apply(&mut store, &UPSTREAM.replace("{addr}", "a"));
        apply(&mut store, &by_bob(RELEASE, 0));
        settle(&mut store, &mut renders);
        assert_eq!(said(&store).0, json!("installed"), "{}", said(&store).1);
        let peer = |store: &Store| store.get("ConfigMap/shop/mine-maps-peek").unwrap().spec["data"]["peer"].clone();
        assert_eq!(peer(&store), "a");
        apply(&mut store, &role("apply, delete"));
        settle(&mut store, &mut renders);
        assert_eq!(peer(&store), "none", "{}", said(&store).1);
        apply(&mut store, &role("apply, delete, get"));
        settle(&mut store, &mut renders);
        assert_eq!(peer(&store), "a");
    }

    /// What the render of the Release `mine` is handed for `lookup`: the keys.
    fn handed(store: &Store) -> Vec<String> {
        let jobs = pending(store, &Renders::new());
        jobs.into_iter()
            .flat_map(|(_, _, job)| job.live.specs.into_keys())
            .collect()
    }

    /// `lookup` in a Package someone pushed reads no more than that pusher may get, besides
    /// the Release's writer: the template is the pusher's, so the writer's rights alone would
    /// let it read through them (a Secret rendered into a ConfigMap the pusher may read). A
    /// pusher without get on Secret is handed no Secret though the writer may read it, and a
    /// ConfigMap both may get is still handed over (T-0922).
    #[test]
    fn lookup_pusher_a_pushed_package_is_handed_only_what_both_may_get() {
        const TOKEN: &str = "apiVersion: kith.dev/v1\nkind: Secret\nmetadata: { name: token, namespace: shop }\n\
                             spec: { data: { k: hidden } }\n";
        let mut store = Store::default();
        bob(&mut store, "ConfigMap");
        apply(
            &mut store,
            "apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: shop }\n\
             spec: { rules: [{ kinds: [ConfigMap], verbs: [apply, delete, get], namespaces: [shop] }] }\n",
        );
        apply(&mut store, TOKEN);
        apply(&mut store, &UPSTREAM.replace("{addr}", "a"));
        store
            .apply(pushed_by_bob(package("1.0.0", &[("peek.yaml", PEEKS)]), 0))
            .unwrap();
        // The local socket applied the Release: it may get both.
        apply(&mut store, RELEASE);
        assert_eq!(handed(&store), ["ConfigMap/shop/upstream"]);
        // Rendered so, it stands; with bob's Identity gone it is rendered again (what it read
        // by is the pusher's as well as the writer's).
        let mut renders = Renders::new();
        settle(&mut store, &mut renders);
        assert_eq!(said(&store).0, json!("installed"), "{}", said(&store).1);
        assert!(pending(&store, &renders).is_empty());
        store.delete("Identity/bob").unwrap();
        assert_eq!(pending(&store, &renders).len(), 1);
        // Made again under the name with another key: not the bob who pushed it, nothing.
        bob_is(&mut store, 1);
        assert_eq!(handed(&store), Vec::<String>::new());
        // Pushed again through the local socket: both are handed over.
        store.apply(package("1.0.0", &[("peek.yaml", PEEKS)])).unwrap();
        let all = [
            "ConfigMap/shop/mine-maps-peek",
            "ConfigMap/shop/upstream",
            "Release/shop/mine",
            "Secret/shop/token",
        ];
        assert_eq!(handed(&store), all);
    }

    /// A Package fetched from the Repository its Release names has no pusher: its `lookup`
    /// reads by the writer's rights alone, as its output is checked. One not fetched with
    /// nobody written down as its pusher is handed nothing (T-0922).
    #[test]
    fn lookup_pusher_a_fetched_package_reads_by_the_writer_and_one_with_no_pusher_by_nobody() {
        const HUB: &str = "apiVersion: kith.dev/v1\nkind: Repository\nmetadata: { name: hub }\n\
                           spec: { url: 'oci://127.0.0.1:1/kith' }\n";
        let mut store = Store::default();
        apply(&mut store, HUB);
        apply(&mut store, &UPSTREAM.replace("{addr}", "a"));
        let mut fetched = package("1.0.0", &[("peek.yaml", PEEKS)]);
        fetched.metadata.annotations.remove(WRITER);
        let hubs = origin(&store, "hub").unwrap();
        fetched.metadata.annotations.insert(REPOSITORY.into(), hubs);
        store.apply(fetched).unwrap();
        apply(&mut store, &RELEASE.replace("name: maps }", "name: maps, repo: hub }"));
        assert_eq!(handed(&store), ["ConfigMap/shop/upstream", "Release/shop/mine"]);

        // Pushed here with nobody written down, for a Release that names no Repository.
        let mut unknown = package("1.0.0", &[("peek.yaml", PEEKS)]);
        unknown.metadata.annotations.remove(WRITER);
        store.apply(unknown).unwrap();
        apply(&mut store, RELEASE);
        assert_eq!(handed(&store), Vec::<String>::new());
    }

    /// A job with what `lookup` sees goes to the render child as JSON on its stdin and its
    /// answer comes back the same way ([`apart`] and [`render_shim`], less the process).
    #[test]
    fn lookup_a_job_with_a_snapshot_crosses_to_the_render_child_and_back() {
        let (mut store, renders) = (Store::default(), Renders::new());
        store.apply(package("1.0.0", &[("peek.yaml", PEEKS)])).unwrap();
        apply(&mut store, &UPSTREAM.replace("{addr}", "a"));
        apply(&mut store, RELEASE);
        let (_, inputs, job) = pending(&store, &renders).pop().unwrap();
        assert!(job.live.specs.contains_key("ConfigMap/shop/upstream"));
        assert!(inputs.looked.contains_key("ConfigMap/shop/upstream"));
        let sent = serde_json::to_vec(&job).unwrap();
        let job: Job = serde_json::from_slice(&sent).unwrap();
        let answer = serde_json::to_vec(&render(&job)).unwrap();
        let output = serde_json::from_slice::<Result<Output, String>>(&answer)
            .unwrap()
            .unwrap();
        let peek = output
            .resources
            .iter()
            .find(|resource| resource.metadata.name == "mine-maps-peek");
        assert_eq!(peek.unwrap().spec["data"]["peer"], "a");
        assert!(output.looked.contains("ConfigMap/shop/upstream"));
    }

    /// A package of one ConfigMap and a hook Job for each point; a Job's command says the colour.
    fn hooked(version: &str) -> Resource {
        let job = |point: &str| {
            format!(
                "---\napiVersion: kith.dev/v1\nkind: Job\nmetadata: {{ name: {{{{ name }}}}-{point}, annotations: {{ 'kith.dev/hook': {point} }} }}\n\
                 spec: {{ template: {{ exec: [{{ name: run, command: ['{{{{ values.colour }}}}'] }}] }} }}\n"
            )
        };
        let jobs: Vec<String> = ["pre-install", "post-install", "pre-upgrade", "post-upgrade"]
            .map(job)
            .into();
        package(version, &[("map.yaml", &format!("{MAP}{}", jobs.concat()))])
    }

    /// What a node would write when a Job ends.
    fn end(store: &mut Store, job: &str, state: &str) {
        let fields = json!({ "state": state }).as_object().unwrap().clone();
        let statuses = vec![(format!("Job/shop/mine-maps-{job}"), fields)];
        kith_store::run(store, kith_store::Command::Patch { statuses }).unwrap();
    }

    fn jobs(store: &Store) -> Vec<String> {
        store.list(Some("Job")).map(|job| job.metadata.name.clone()).collect()
    }

    fn maps(store: &Store) -> usize {
        store.list(Some("ConfigMap")).count()
    }

    /// A pre hook runs alone and the rest waits for it; a post hook runs once the rest is there
    /// and the Release is installed when it has succeeded.
    #[test]
    fn hooks_install_runs_pre_then_the_rest_then_post() {
        let (mut store, mut renders) = (Store::default(), Renders::new());
        store.apply(hooked("1.0.0")).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        assert_eq!(
            (jobs(&store), maps(&store)),
            (vec!["mine-maps-pre-install".to_string()], 0)
        );
        let said = status_of(&store);
        assert_eq!(said["state"], "hooks");
        assert!(
            said["message"]
                .as_str()
                .unwrap()
                .contains("Job/shop/mine-maps-pre-install")
        );
        // (Running is not done: it still waits.)
        end(&mut store, "pre-install", "running");
        settle(&mut store, &mut renders);
        assert_eq!(maps(&store), 0);
        end(&mut store, "pre-install", "succeeded");
        settle(&mut store, &mut renders);
        assert_eq!(maps(&store), 2);
        assert_eq!(jobs(&store), ["mine-maps-post-install", "mine-maps-pre-install"]);
        assert_eq!(status_of(&store)["state"], "hooks");
        end(&mut store, "post-install", "succeeded");
        settle(&mut store, &mut renders);
        let said = status_of(&store);
        assert_eq!(
            (&said["state"], &said["version"], &said["message"]),
            (&json!("installed"), &json!("1.0.0"), &Value::Null)
        );
        // A hook is not one of the release's resources, so it is not pruned as one.
        assert_eq!(
            said["resources"],
            json!(["ConfigMap/shop/mine-maps", "ConfigMap/shop/mine-maps-extra"])
        );
        // The same again runs nothing again.
        let before: Vec<_> = store.list(Some("Job")).map(|job| job.metadata.revision).collect();
        assert_eq!(settle(&mut store, &mut renders), 0);
        let after: Vec<_> = store.list(Some("Job")).map(|job| job.metadata.revision).collect();
        assert_eq!(before, after);
        // The Release goes, and its hook Jobs with it.
        store.delete("Release/shop/mine").unwrap();
        settle(&mut store, &mut renders);
        assert_eq!((jobs(&store), maps(&store)), (Vec::<String>::new(), 0));
    }

    /// A hook that fails leaves the Release in error naming the Job, and nothing else is made.
    #[test]
    fn hooks_a_failed_hook_stops_the_release_and_changes_nothing() {
        let (mut store, mut renders) = (Store::default(), Renders::new());
        store.apply(hooked("1.0.0")).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        end(&mut store, "pre-install", "failed");
        settle(&mut store, &mut renders);
        let said = status_of(&store);
        assert_eq!(said["state"], "error");
        assert!(
            said["message"]
                .as_str()
                .unwrap()
                .contains("Job/shop/mine-maps-pre-install")
        );
        assert!(said["message"].as_str().unwrap().contains("delete it to run it again"));
        assert_eq!((jobs(&store).len(), maps(&store)), (1, 0));
        assert_eq!(said["version"], Value::Null);
        // One that fails after: the rest is there, and the Release says so.
        let (mut store, mut renders) = (Store::default(), Renders::new());
        store.apply(hooked("1.0.0")).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        end(&mut store, "pre-install", "succeeded");
        settle(&mut store, &mut renders);
        end(&mut store, "post-install", "failed");
        settle(&mut store, &mut renders);
        let said = status_of(&store);
        assert_eq!((&said["state"], maps(&store)), (&json!("error"), 2));
        assert!(
            said["message"]
                .as_str()
                .unwrap()
                .contains("Job/shop/mine-maps-post-install")
        );
    }

    /// An upgrade runs the upgrade hooks, not the install ones; a hook as it was is not run
    /// again, and one for a new version is, the old Job deleted first.
    #[test]
    fn hooks_upgrade_runs_its_own_and_reruns_only_what_changed() {
        let (mut store, mut renders) = (Store::default(), Renders::new());
        store.apply(hooked("1.0.0")).unwrap();
        apply(&mut store, RELEASE);
        for job in ["pre-install", "post-install"] {
            settle(&mut store, &mut renders);
            end(&mut store, job, "succeeded");
        }
        settle(&mut store, &mut renders);
        assert_eq!(status_of(&store)["state"], "installed");
        store.apply(hooked("1.1.0")).unwrap();
        settle(&mut store, &mut renders);
        assert_eq!(status_of(&store)["state"], "hooks");
        assert_eq!(
            jobs(&store),
            [
                "mine-maps-post-install",
                "mine-maps-pre-install",
                "mine-maps-pre-upgrade"
            ]
        );
        end(&mut store, "pre-upgrade", "succeeded");
        settle(&mut store, &mut renders);
        assert_eq!(status_of(&store)["version"], "1.1.0");
        assert_eq!(jobs(&store).last().unwrap(), "mine-maps-pre-upgrade");
        assert!(jobs(&store).contains(&"mine-maps-post-upgrade".to_string()));
        end(&mut store, "post-upgrade", "succeeded");
        settle(&mut store, &mut renders);
        assert_eq!(status_of(&store)["state"], "installed");
        let revisions =
            |store: &Store| -> Vec<_> { store.list(Some("Job")).map(|job| job.metadata.revision).collect() };
        let before = revisions(&store);
        assert_eq!(settle(&mut store, &mut renders), 0);
        assert_eq!(before, revisions(&store), "nothing run again");
        // A new version: the hooks that run for it are made again, from nothing.
        store.apply(hooked("1.2.0")).unwrap();
        settle(&mut store, &mut renders);
        let job = store.get("Job/shop/mine-maps-pre-upgrade").unwrap();
        assert_eq!(job.status, None, "the old Job is gone and this is a new one");
        assert_eq!((status_of(&store)["state"].clone(), maps(&store)), (json!("hooks"), 2));
        assert_eq!(status_of(&store)["version"], "1.1.0");
    }

    /// A hook of another kind, or at a point there is none of, is an error; so is a Job there
    /// already that is not the Release's.
    #[test]
    fn hooks_a_mistake_in_one_is_the_releases_error() {
        let (mut store, mut renders) = (Store::default(), Renders::new());
        let odd = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: x, annotations: { 'kith.dev/hook': pre-install } }\nspec: { data: {} }\n";
        store.apply(package("1.0.0", &[("odd.yaml", odd)])).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        let said = status_of(&store);
        assert_eq!(said["state"], "error");
        assert!(said["message"].as_str().unwrap().contains("only a Job"));
        let wrong = odd
            .replace("ConfigMap", "Job")
            .replace("pre-install", "sometimes")
            .replace("data: {}", "template: { exec: [{ name: a, command: ['true'] }] }");
        store.apply(package("1.0.1", &[("odd.yaml", &wrong)])).unwrap();
        settle(&mut store, &mut renders);
        assert!(status_of(&store)["message"].as_str().unwrap().contains("sometimes"));
        let (mut store, mut renders) = (Store::default(), Renders::new());
        apply(
            &mut store,
            "apiVersion: kith.dev/v1\nkind: Job\nmetadata: { name: mine-maps-pre-install, namespace: shop }\nspec: { template: { exec: [{ name: a, command: ['true'] }] } }\n",
        );
        store.apply(hooked("1.0.0")).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        assert!(
            status_of(&store)["message"]
                .as_str()
                .unwrap()
                .contains("not Release/shop/mine's")
        );
        assert_eq!(maps(&store), 0);
        // One at the post point is asked at once too: no pre Job is made first.
        let (mut store, mut renders) = (Store::default(), Renders::new());
        apply(
            &mut store,
            "apiVersion: kith.dev/v1\nkind: Job\nmetadata: { name: mine-maps-post-install, namespace: shop }\nspec: { template: { exec: [{ name: a, command: ['true'] }] } }\n",
        );
        store.apply(hooked("1.0.0")).unwrap();
        apply(&mut store, RELEASE);
        settle(&mut store, &mut renders);
        assert!(
            status_of(&store)["message"]
                .as_str()
                .unwrap()
                .contains("not Release/shop/mine's")
        );
        assert_eq!(
            (jobs(&store), maps(&store)),
            (vec!["mine-maps-post-install".to_string()], 0)
        );
    }

    /// A hook Job the render of the version now there no longer names is deleted, so a way
    /// back to the version that had it (A, B, A, B) runs it again.
    #[test]
    fn hooks_one_the_render_no_longer_names_goes_so_coming_back_runs_it_again() {
        let (mut store, mut renders) = (Store::default(), Renders::new());
        let job = "---\napiVersion: kith.dev/v1\nkind: Job\nmetadata: { name: {{ name }}-pre-upgrade, annotations: { 'kith.dev/hook': pre-upgrade } }\n\
                   spec: { template: { exec: [{ name: run, command: ['migrate'] }] } }\n";
        store.apply(package("1.0.0", &[("map.yaml", MAP)])).unwrap();
        store
            .apply(package("1.1.0", &[("map.yaml", &format!("{MAP}{job}"))]))
            .unwrap();
        let at = |version: &str| {
            RELEASE
                .replace("autoUpgrade: true", "autoUpgrade: false")
                .replace("name: maps }", &format!("name: maps, version: '={version}' }}"))
        };
        apply(&mut store, &at("1.0.0"));
        settle(&mut store, &mut renders);
        apply(&mut store, &at("1.1.0"));
        settle(&mut store, &mut renders);
        end(&mut store, "pre-upgrade", "succeeded");
        settle(&mut store, &mut renders);
        assert_eq!(
            (status_of(&store)["version"].clone(), jobs(&store)),
            (json!("1.1.0"), vec!["mine-maps-pre-upgrade".to_string()])
        );
        apply(&mut store, &at("1.0.0"));
        settle(&mut store, &mut renders);
        assert_eq!(
            (status_of(&store)["version"].clone(), jobs(&store)),
            (json!("1.0.0"), Vec::<String>::new())
        );
        apply(&mut store, &at("1.1.0"));
        settle(&mut store, &mut renders);
        assert_eq!(status_of(&store)["state"], "hooks");
        assert_eq!(
            store.get("Job/shop/mine-maps-pre-upgrade").unwrap().status,
            None,
            "made again"
        );
    }
}
