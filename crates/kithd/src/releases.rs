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
/// The ConfigMap (in `kith-system`, in a namespace) whose `values` releases are given.
const SHARED: &str = "kith-values";

/// What a render was made from: it stands until one of these changes. (A revision and
/// when it was applied: a resource deleted and made again starts at revision 1 again.)
#[derive(Debug, Clone, PartialEq)]
struct Inputs {
    release: Stamp,
    package: (String, Stamp),
    cluster: Stamp,
    namespace: Stamp,
}

type Stamp = Option<(Option<u64>, u64)>;

fn stamp(store: &Store, resource: &Resource) -> Stamp {
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
struct Step {
    release: String,
    apply: Vec<Resource>,
    delete: Vec<String>,
    status: Option<Map<String, Value>>,
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

/// The Package a release asks for: that version, or the newest there is (a version
/// that is no semver is older than any that is; `1.0.0-rc1` is older than `1.0.0`).
fn package<'a>(store: &'a Store, spec: &ReleaseSpec) -> Result<&'a Resource, String> {
    let name = &spec.package.name;
    let version = |package: &Resource| package.spec["version"].as_str().unwrap_or_default().to_string();
    let found = match &spec.package.version {
        Some(version) => store.get(&format!("Package/{name}-{version}")),
        None => {
            let named = |package: &&Resource| package.metadata.name == format!("{name}-{}", version(package));
            let packages = store.list(Some("Package")).filter(named);
            packages.max_by_key(|package| semver::Version::parse(&version(package)).ok())
        }
    };
    let wanted = spec.package.version.as_deref();
    let wanted = wanted.map_or(String::new(), |version| format!("-{version}"));
    found.ok_or(format!(
        "there is no Package {name}{wanted}: `kith package push` puts one here"
    ))
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
    let package = package(store, &spec)?;
    let (cluster, everywhere) = shared_values(store, "ConfigMap/kith-system/kith-values")?;
    let (local, here) = shared_values(store, &format!("ConfigMap/{}/{SHARED}", namespace(release)))?;
    let inputs = Inputs {
        release: stamp(store, release),
        package: (package.key(), stamp(store, package)),
        cluster,
        namespace: local,
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
        let key = resource.key();
        let scoped = kith_api::kind(&resource.kind).is_some_and(|kind| kind.namespaced);
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
        };
        jobs.push((key, inputs, job));
    }
    jobs
}

fn owner(resource: &Resource) -> Option<&str> {
    resource.metadata.annotations.get(OWNER).map(String::as_str)
}

/// May `resources` be applied by hand? Not one that says it is of a Release that is
/// not there (nor comes with it): it would be deleted as that Release's leftovers.
pub fn claims(store: &Store, resources: &[Resource]) -> Result<(), String> {
    for resource in resources {
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

/// What the store needs done for its Releases, given the renders there are.
fn plan(store: &Store, renders: &Renders) -> Plan {
    let mut plan = Plan::default();
    let mut releases = BTreeSet::new();
    for release in store.list(Some("Release")) {
        let key = release.key();
        releases.insert(key.clone());
        let output = match inputs(store, release) {
            Err(e) => Err(e),
            Ok((now, ..)) => match renders.get(&key) {
                Some((had, output)) if *had == now => output.clone(),
                // (Not rendered yet: next time.)
                _ => continue,
            },
        };
        // What the release put there, by its own account: only that is pruned (not a
        // copy someone made, annotation and all), and that is still its own when
        // someone applied over it and the annotation went.
        let live = release.status.as_ref();
        let recorded = live.and_then(|status| status["resources"].as_array());
        let recorded: BTreeSet<&str> = recorded.into_iter().flatten().filter_map(Value::as_str).collect();
        // Nothing of someone else's is taken over.
        let taken = |output: &Output| {
            let others = output.resources.iter().map(Resource::key).filter(|resource| {
                let mine = |live: &Resource| owner(live) == Some(&key) || recorded.contains(resource.as_str());
                store.get(resource).is_some_and(|live| !mine(live))
            });
            let others: Vec<String> = others.collect();
            match others.is_empty() {
                true => Ok(()),
                false => Err(format!(
                    "{} is there already and is not this release's",
                    others.join(", ")
                )),
            }
        };
        let output = output.and_then(|output| taken(&output).map(|()| output));
        let mut step = Step {
            release: key.clone(),
            apply: Vec::new(),
            delete: Vec::new(),
            status: None,
        };
        let status = match output {
            Ok(output) => {
                let mut kept = BTreeSet::new();
                for resource in &output.resources {
                    kept.insert(resource.key());
                    let same = store.get(&resource.key()).is_some_and(|live| {
                        (&live.spec, &live.metadata.labels, &live.metadata.annotations)
                            == (
                                &resource.spec,
                                &resource.metadata.labels,
                                &resource.metadata.annotations,
                            )
                    });
                    if !same {
                        step.apply.push(resource.clone());
                    }
                }
                let gone = recorded.iter().filter(|resource| !kept.contains(**resource));
                let gone = gone.filter(|resource| store.get(resource).is_some_and(|live| owner(live) == Some(&key)));
                step.delete.extend(gone.map(|resource| resource.to_string()));
                json!({
                    "state": "installed", "message": null, "version": output.version,
                    "resources": kept, "notes": output.notes, "observedRevision": release.metadata.revision,
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
    // What belonged to a Release that is gone goes too.
    let orphans = store
        .list(None)
        .filter(|resource| owner(resource).is_some_and(|owner| !releases.contains(owner)));
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
            carry_out(&shared, plan).await;
        }
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(30)) => {}
            _ = stopping.changed() => break,
        }
    }
}

/// Each Release for itself: one that cannot be applied says so and stops no other.
async fn carry_out(shared: &Shared, plan: Plan) {
    use kith_api::store::Error;
    use kith_store::Command;
    let delete = async |key: String| match shared.submit(Command::Delete { key }).await {
        Ok(_) | Err(Error::NotFound(_)) => Ok(()),
        Err(e) => Err(e),
    };
    let mut statuses = Vec::new();
    for mut step in plan.steps {
        let mut done = Ok(());
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
    for key in plan.orphans {
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
                           spec: { package: { name: maps }, values: { extra: true } }\n";

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
}
