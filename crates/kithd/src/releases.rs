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
// ponytail: no hooks, no `lookup` of what is in the cluster, no values per node; a
// version is one version, not a range. A render is remembered by the revisions of what
// went in, so every Release is looked at on every change to the store but rendered
// once.

use crate::Shared;
use kith_api::Resource;
use kith_api::kinds::{ConfigMapSpec, ReleaseSpec};
use kith_api::store::Store;
use kith_packages::Package;
use serde_json::{Map, Value, json};
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
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Output {
    version: String,
    resources: Vec<Resource>,
    notes: Option<String>,
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
/// it has none or follows the newest (`autoUpgrade`). `1.0.0-rc1` is older than `1.0.0`.
fn package<'a>(store: &'a Store, release: &Resource, spec: &ReleaseSpec) -> Result<&'a Resource, String> {
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
    let kept = installed.filter(|_| spec.auto_upgrade != Some(true));
    let kept = kept.and_then(|installed| store.get(&format!("Package/{name}-{installed}")));
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
/// every change to the store.)
fn inputs<'a>(store: &'a Store, release: &Resource) -> Result<(Inputs, &'a Resource, Vec<Value>), String> {
    let spec: ReleaseSpec = serde_json::from_value(release.spec.clone()).map_err(|e| e.to_string())?;
    let package = package(store, release, &spec)?;
    let (cluster, everywhere) = shared_values(store, "ConfigMap/kith-system/kith-values")?;
    let (local, here) = shared_values(store, &format!("ConfigMap/{}/{SHARED}", namespace(release)))?;
    let inputs = Inputs {
        release: stamp(store, release),
        package: (package.key(), stamp(store, package)),
        cluster,
        namespace: local,
        kinds: custom_kinds(store),
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
    let release = kith_packages::Release {
        name: &job.name,
        namespace: &job.namespace,
    };
    let mut rendered = package.render(release, &job.layers)?;
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
    })
}

/// The first argument kithd is started again with to render one Release ([`render_shim`]).
pub const RENDER: &str = "--kith-render";
/// What a render may have: the address space of the kithd it runs in, its CPU time, the
/// time it takes, and how much it answers.
const RENDER_MEMORY: u64 = 256 << 20;
const RENDER_CPU: u64 = 20;
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

/// The Releases whose render is missing or out of date.
fn pending(store: &Store, renders: &Renders) -> Vec<(String, Inputs, Job)> {
    let mut jobs = Vec::new();
    for release in store.list(Some("Release")) {
        // (One that cannot be started says why in `plan`.)
        let Ok((inputs, package, layers)) = inputs(store, release) else {
            continue;
        };
        let key = release.key();
        if renders.get(&key).is_some_and(|(had, _)| *had == inputs) {
            continue;
        }
        let files = package.spec["files"].as_object().into_iter().flatten();
        let job = Job {
            files: files
                .map(|(path, text)| (path.clone(), text.as_str().unwrap_or_default().to_string()))
                .collect(),
            layers,
            name: release.metadata.name.clone(),
            namespace: namespace(release),
            owner: key.clone(),
            kinds: inputs.kinds.clone(),
        };
        jobs.push((key, inputs, job));
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
        let same = live.is_some_and(|live| {
            (&live.spec, &live.metadata.labels, &live.metadata.annotations)
                == (
                    &resource.spec,
                    &resource.metadata.labels,
                    &resource.metadata.annotations,
                )
        });
        if !same {
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

/// What the store needs done for its Releases, given the renders there are.
fn plan(store: &Store, renders: &Renders) -> Plan {
    let mut plan = Plan::default();
    for release in store.list(Some("Release")) {
        let key = release.key();
        let (output, package) = match inputs(store, release) {
            Err(e) => (Err(e), None),
            Ok((now, package, _)) => match renders.get(&key) {
                Some((had, output)) if *had == now => (output.clone(), Some(package)),
                // (Not rendered yet: next time.)
                _ => continue,
            },
        };
        let live = release.status.as_ref();
        let done = output.and_then(|output| {
            let done = reconcile(store, &key, &recorded(release), &output.resources, true)?;
            // (Asked on every pass: a writer that loses a right is told at once.)
            writer_may(store, release, &output.resources, &done.delete)?;
            // And of whoever pushed the Package it came from: no more than its pusher, besides
            // the Release's writer. One the Repository the Release names supplied has none: that
            // Repository's key (or, with none, its address) is its trust. Any other, annotated
            // or not, is asked of its writer, and refused when none is written down.
            let origin = release.spec["package"]["repo"]
                .as_str()
                .and_then(|repo| origin(store, repo));
            let fetched = |package: &Resource| {
                origin.is_some() && package.metadata.annotations.get(REPOSITORY) == origin.as_ref()
            };
            if let Some(package) = package.filter(|package| !fetched(package)) {
                writer_may(store, package, &output.resources, &done.delete)?;
            }
            Ok((output, done))
        });
        let mut step = Step {
            release: key.clone(),
            apply: Vec::new(),
            delete: Vec::new(),
            status: None,
        };
        let status = match done {
            Ok((output, done)) => {
                (step.apply, step.delete) = (done.apply, done.delete);
                // (Following the newest from a Repository its writer may not fetch from: said on
                // every pass, or it would be said only once a Package is missing.)
                let following = release.spec["autoUpgrade"] == true && release.spec["package"]["repo"].is_string();
                let unlooked = following.then(|| supplied(store, release).err()).flatten();
                let message = unlooked.map(|why| format!("no newer Package is looked for: {why}"));
                json!({
                    "state": "installed", "message": message, "version": output.version,
                    "resources": done.kept, "notes": output.notes, "observedRevision": release.metadata.revision,
                })
            }
            // (What was installed before stays as it is.)
            Err(e) => failed(&e, release.metadata.revision),
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
    let short = |(at, (verb, kind, namespace)): (String, crate::api::Right)| {
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
    let taken = gone.iter().map(|at| {
        let (kind, namespace) = crate::api::place_of(at);
        (at.clone(), (Verb::Delete, kind, namespace))
    });
    let mut asked = made.chain(taken);
    match asked.find(|(_, (verb, kind, namespace))| !grants.may(verb, kind, namespace.as_deref())) {
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
    if Grants::of(&caller, store).may(&kith_api::kinds::Verb::Apply, "Package", None) {
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

/// Install the Releases, as long as this node leads the store, until told to stop.
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let mut renders = Renders::new();
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
                renders.insert(key, (inputs, apart(&job).await));
            }
            let plan = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                plan(&state.store, &renders)
            };
            carry_out(&shared, plan.steps, plan.orphans).await;
        }
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(30)) => {}
            _ = stopping.changed() => break,
        }
    }
}

/// Under `spec.signing: required` every node refuses, at apply, a bare write that changes access
/// ([`crate::access_sign::refuses_render`]) and a Release's or a Source's is bare until slice 6
/// (T-0850). So a step that makes or prunes a Role, RoleBinding, Identity or KindDefinition
/// proposes nothing: it says so in the Release's (or Source's) status, once, not in an entry
/// every node audits again every round. Returns whether it did.
fn refuse_access(store: &Store, step: &mut Step) -> bool {
    use kith_store::Command;
    let apply = Command::Apply {
        resources: std::mem::take(&mut step.apply),
        at: 0,
    };
    let mut why = crate::access_sign::refuses_render(store, &apply);
    if let Command::Apply { resources, .. } = apply {
        step.apply = resources;
    }
    why = why.or_else(|| {
        let delete = |key: &String| Command::Delete { key: key.clone() };
        step.delete
            .iter()
            .find_map(|key| crate::access_sign::refuses_render(store, &delete(key)))
    });
    let Some(why) = why else { return false };
    let message = format!(
        "{} makes or removes a Role, RoleBinding, Identity or KindDefinition, which a Release or Source \
         may not yet under spec.signing: required ({why}); apply it signed, or set signing open",
        step.release
    );
    let Value::Object(status) = failed(&message, None) else {
        unreachable!("an object")
    };
    let status: Map<String, Value> = status.into_iter().filter(|(field, _)| field != "observedRevision").collect();
    let live = store.get(&step.release).and_then(|release| release.status.as_ref());
    let said = live.is_some_and(|live| status.iter().all(|(field, value)| &live[field] == value));
    (step.apply, step.delete) = (Vec::new(), Vec::new());
    step.status = (!said).then_some(status);
    true
}

/// Each Release for itself: one that cannot be applied says so and stops no other.
pub async fn carry_out(shared: &Shared, steps: Vec<Step>, orphans: Vec<String>) {
    use kith_api::store::Error;
    use kith_store::Command;
    // (Decided once, from the store as it stands; every node decides alike again at apply.)
    let (steps, orphans) = {
        let state = shared.store.lock().expect("nothing panics holding the store");
        let mut steps = steps;
        for step in &mut steps {
            refuse_access(&state.store, step);
        }
        let orphans: Vec<String> = orphans
            .into_iter()
            .filter(|key| {
                crate::access_sign::refuses_render(&state.store, &Command::Delete { key: key.clone() }).is_none()
            })
            .collect();
        (steps, orphans)
    };
    let delete = async |key: String| match shared.submit(Command::Delete { key }).await {
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
                .submit(Command::Apply {
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
        let mut files = BTreeMap::from([
            ("package.yaml".to_string(), format!("name: maps\nversion: {version}\n")),
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
        for turn in 0..10 {
            for (key, inputs, job) in pending(store, renders) {
                renders.insert(key, (inputs, render(&job)));
            }
            let plan = plan(store, renders);
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

    /// Under `spec.signing: required` a step that makes a Role (a Source's: a Release's render
    /// may not hold one, but a Source's may) or prunes one proposes nothing and says why, once:
    /// every node would refuse the bare write at apply, and audit it, every round.
    #[test]
    fn a_step_making_a_role_under_required_proposes_nothing_and_says_so() {
        const ROLE: &str = "apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: shop }\nspec: { rules: [] }\n";
        let mut store = Store::default();
        apply(&mut store, RELEASE);
        let step = |apply: Vec<Resource>, delete: Vec<String>| Step {
            release: "Release/shop/mine".into(),
            apply,
            delete,
            status: Some(Map::new()),
        };
        let role = || Resource::from_source(ROLE).unwrap().remove(0).unwrap();
        apply(
            &mut store,
            &format!(
                "apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: c }}\nspec: {{ adminKey: {}, signing: required }}\n",
                "11".repeat(32)
            ),
        );
        // Open, or below format 4: the step stands.
        let mut made = step(vec![role()], Vec::new());
        assert!(!refuse_access(&store, &mut made));
        assert_eq!(made.apply.len(), 1);
        kith_store::run(&mut store, kith_store::Command::MarkChecked).unwrap();
        // What is not access stands; a Role made, or a RoleBinding pruned, does not.
        let mut plain = step(Vec::new(), vec!["ConfigMap/shop/a".into()]);
        assert!(!refuse_access(&store, &mut plain));
        let mut pruned = step(Vec::new(), vec!["RoleBinding/bob-shop".into()]);
        assert!(refuse_access(&store, &mut pruned));
        assert!(refuse_access(&store, &mut made));
        assert!(made.apply.is_empty() && made.delete.is_empty());
        let status = made.status.clone().expect("a status that says why");
        assert_eq!(status["state"], "error");
        assert!(status["message"].as_str().unwrap().contains("spec.signing: required"));
        // Once it says so, the next round writes nothing at all.
        kith_store::run(
            &mut store,
            kith_store::Command::Patch {
                statuses: vec![("Release/shop/mine".into(), status)],
            },
        )
        .unwrap();
        let mut again = step(vec![role()], Vec::new());
        assert!(refuse_access(&store, &mut again));
        assert_eq!(again.status, None);
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
}
