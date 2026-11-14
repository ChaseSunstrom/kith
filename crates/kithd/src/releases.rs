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
struct Job {
    files: BTreeMap<String, String>,
    layers: Vec<Value>,
    name: String,
    namespace: String,
    owner: String,
    kinds: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, PartialEq)]
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
        let output = match inputs(store, release) {
            Err(e) => Err(e),
            Ok((now, ..)) => match renders.get(&key) {
                Some((had, output)) if *had == now => output.clone(),
                // (Not rendered yet: next time.)
                _ => continue,
            },
        };
        let live = release.status.as_ref();
        let done = output.and_then(|output| {
            let done = reconcile(store, &key, &recorded(release), &output.resources, true)?;
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
                json!({
                    "state": "installed", "message": null, "version": output.version,
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
            // (Off the threads everything else waits on: a package is someone else's code.
            // One at a time, so that one that panics takes only its own render with it.)
            for (key, inputs, job) in jobs {
                let rendered = tokio::task::spawn_blocking(move || render(&job)).await;
                let rendered = rendered.unwrap_or_else(|e| Err(format!("rendering stopped: {e}")));
                renders.insert(key, (inputs, rendered));
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

/// Each Release for itself: one that cannot be applied says so and stops no other.
pub async fn carry_out(shared: &Shared, steps: Vec<Step>, orphans: Vec<String>) {
    use kith_api::store::Error;
    use kith_store::Command;
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
        Package::from_files(files).unwrap().resource().unwrap()
    }

    const MAP: &str = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: {{ name }} }\n\
                       spec: { data: { colour: {{ values.colour }} } }\n\
                       {% if values.extra %}---\napiVersion: kith.dev/v1\nkind: ConfigMap\n\
                       metadata: { name: {{ name }}-extra }\nspec: { data: { a: b } }\n{% endif %}";
    const RELEASE: &str = "apiVersion: kith.dev/v1\nkind: Release\nmetadata: { name: mine, namespace: shop }\n\
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
                if let Some(fields) = step.status {
                    let live = store.get(&step.release).and_then(|r| r.status.clone());
                    let mut status = live.unwrap_or(json!({}));
                    status.as_object_mut().unwrap().extend(fields);
                    store.set_status(&step.release, Some(status)).unwrap();
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
}
