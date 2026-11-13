//! What a container's `volumeMounts` come to: which `Volume` each names, the one node they are
//! on, where on that node the data lives, and which `Volume` each `VolumeClaim` is bound to. Pure
//! (but for `host_dir`, which makes the directory): it reads a store and answers, so the
//! scheduler (to place a replica and to write each status) and the node's controller (to mount
//! what the replica names) get the same answer from the same store.
//
// ponytail: no dynamic provisioning: a VolumeClaim binds a Volume somebody made, and says so when
// there is none. A `shared: true` Volume in `kith-system` is refused (see `volumes`). `subvolume: true` is a plain directory (a btrfs subvolume would
// need the `btrfs` tool or its ioctls). A claim stays bound until its Volume goes; a Volume whose
// claim goes is free again with its data kept.

use kith_api::kinds::{VolumeClaimSpec, VolumeSpec};
use kith_api::{Resource, store::Store};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The one namespace whose volumes may be anywhere on the host: the system's own.
///
/// What keeps another namespace's workload from mounting them is access control, not this
/// module: reading and writing `Volume`s of `kith-system` is a rule an `Identity` has to be given.
pub const SYSTEM: &str = "kith-system";

/// Where a volume's data is, as the Volume says: its namespace and name, its `spec.path`, and
/// the node that is on. A node other than that one mounts it only if it is `shared`
/// (`crate::share`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Dir {
    pub namespace: String,
    pub name: String,
    pub path: String,
    pub node: String,
    /// Kept under dm-crypt on that node ([`crate::encrypted`]): no directory until it is open.
    pub encrypted: bool,
}

/// What a workload's mounts come to: the one node those that are not `shared` are on (none: it
/// may run anywhere), and for each name a container mounts (a Volume's, or a VolumeClaim's) the
/// directory it is.
#[derive(Debug, Clone, PartialEq)]
pub struct Held {
    pub node: Option<String>,
    pub volumes: BTreeMap<String, Dir>,
}

/// The answer for every workload that mounts something (its key), and the status each
/// `Volume` and `VolumeClaim` should have (its key; none when there is nothing to say).
#[derive(Debug, Default)]
pub struct Volumes {
    pub owners: BTreeMap<String, Result<Held, String>>,
    pub status: BTreeMap<String, Option<Value>>,
}

/// A Volume as read: what binding needs to know and whether its path is allowed.
struct Vol {
    dir: Dir,
    /// More than one: kept on other nodes too ([`crate::replicas`]).
    replicas: u32,
    size: Option<f64>,
    shared: bool,
    refused: Option<String>,
}

/// Whether `path` is one the namespace may use: any absolute path in `kith-system`, else a
/// relative one with no `.`, `..` or empty part (so it stays inside the namespace's own directory).
fn check_path(namespace: &str, path: &str) -> Result<(), String> {
    if path.contains('\0') {
        return Err(format!("path `{path:?}` must be relative, with no NUL"));
    }
    if namespace == SYSTEM {
        let absolute = path.starts_with('/');
        return absolute
            .then_some(())
            .ok_or(format!("path `{path}` must be absolute in {SYSTEM}"));
    }
    let plain = path.split('/').all(|part| !matches!(part, "" | "." | ".."));
    plain.then_some(()).ok_or(format!(
        "path `{path}` must be relative to the namespace's own directory, with no `..`, `.` or empty part"
    ))
}

/// A key's namespace and name (`Volume/shop/data` is `shop` and `data`).
fn parts(key: &str) -> (&str, &str) {
    let mut parts = key.split('/').skip(1);
    (parts.next().unwrap_or_default(), parts.next().unwrap_or_default())
}

fn volumes(store: &Store) -> BTreeMap<String, Vol> {
    let read = |volume: &Resource| {
        let key = volume.key();
        let (namespace, name) = parts(&key);
        let mut dir = Dir {
            namespace: namespace.into(),
            name: name.into(),
            path: String::new(),
            node: String::new(),
            encrypted: false,
        };
        let vol = match serde_json::from_value::<VolumeSpec>(volume.spec.clone()) {
            Ok(spec) => {
                dir.path = spec.path;
                dir.encrypted = spec.encrypted == Some(true);
                let replicas = spec.replicas.unwrap_or(1);
                // A volume that had replicas is where its status says: on the node that took
                // over when the one it was made on was lost (and stays there with `replicas`
                // lowered again, until `node` names that node: never back to the old copy).
                let primary = volume.status.as_ref().and_then(|status| status["primary"].as_str());
                dir.node = primary.map_or(spec.node, String::from);
                let shared = spec.shared == Some(true);
                // ponytail: what a node serves to the others is under its state directory only
                // (`crate::share`); a path anywhere on the host is not. Lift it by serving each
                // such path from a root of its own.
                let anywhere = (shared && namespace == SYSTEM)
                    .then(|| format!("a shared volume cannot be in {SYSTEM}: its path is anywhere on the host"));
                // ponytail: one served to the others, or anywhere on a host, has no copies yet:
                // the nodes that mount it would have to follow it, and a host path is one node's.
                let alone = (replicas > 1 && (shared || namespace == SYSTEM))
                    .then(|| format!("a volume with replicas cannot be shared or in {SYSTEM} yet"));
                // (A path anywhere on the host is not a file of this node's state.)
                let sealed = (dir.encrypted && namespace == SYSTEM)
                    .then(|| format!("an encrypted volume cannot be in {SYSTEM}: its path is anywhere on the host"));
                Vol {
                    refused: check_path(namespace, &dir.path).err().or(anywhere).or(alone).or(sealed),
                    replicas,
                    dir,
                    size: spec.size.map(|size| size.value()),
                    shared,
                }
            }
            Err(e) => Vol {
                dir,
                replicas: 1,
                size: None,
                shared: false,
                refused: Some(e.to_string()),
            },
        };
        (key.clone(), vol)
    };
    store.list(Some("Volume")).map(read).collect()
}

/// What each claim is bound to (a Volume's name, or why it is bound to none), and for each
/// bound Volume the claim that has it.
type Bound = (BTreeMap<String, Result<String, String>>, BTreeMap<String, String>);

/// A claim that is bound stays bound while its Volume exists. One that is not takes the first
/// Volume (by key) of its namespace that no claim has, that is not refused, is at least as big,
/// is on a node with the labels it selects, and is `shared` when it asks for that.
fn bind(store: &Store, vols: &BTreeMap<String, Vol>) -> Bound {
    let mut claims: Vec<&Resource> = store.list(Some("VolumeClaim")).collect();
    claims.sort_by_key(|claim| claim.key());
    let (mut bound, mut taken) = (BTreeMap::new(), BTreeMap::new());
    for claim in &claims {
        let key = claim.key();
        let name = parts(&key).1.to_string();
        let (namespace, _) = parts(&key);
        let recorded = claim.status.as_ref().and_then(|status| status["volume"].as_str());
        let Some(volume) = recorded else { continue };
        let volume_key = format!("Volume/{namespace}/{volume}");
        if vols.contains_key(&volume_key) && !taken.contains_key(&volume_key) {
            taken.insert(volume_key, name);
            bound.insert(key, Ok(volume.to_string()));
        } else {
            // It does not quietly take another: the workload would start on empty data.
            let why = format!("its Volume {volume} is gone: make it again, or delete this claim to bind another");
            bound.insert(key, Err(why));
        }
    }
    for claim in claims {
        let key = claim.key();
        if bound.contains_key(&key) {
            continue;
        }
        let (namespace, name) = parts(&key);
        let spec: VolumeClaimSpec = match serde_json::from_value(claim.spec.clone()) {
            Ok(spec) => spec,
            Err(e) => {
                bound.insert(key, Err(e.to_string()));
                continue;
            }
        };
        let (want, shared) = (spec.size.value(), spec.shared == Some(true));
        let labels = |node: &str| {
            store
                .get(&format!("Node/{node}"))
                .map(|node| node.metadata.labels.clone())
        };
        // (A Volume on a node that is not there fits nothing: its claim could never run.)
        let on_node =
            |node: &str| labels(node).is_some_and(|have| spec.selector.iter().all(|(k, v)| have.get(k) == Some(v)));
        let prefix = format!("Volume/{namespace}/");
        let fits = |(volume_key, vol): &(&String, &Vol)| {
            vol.refused.is_none()
                && !taken.contains_key(*volume_key)
                && vol.size.is_none_or(|size| size >= want)
                && (!shared || vol.shared)
                && on_node(&vol.dir.node)
        };
        let found = vols.iter().filter(|(k, _)| k.starts_with(&prefix)).find(fits);
        if let Some((volume_key, vol)) = found {
            taken.insert(volume_key.clone(), name.to_string());
            bound.insert(key, Ok(vol.dir.name.clone()));
            continue;
        }
        let mut needs = vec![format!("at least {}", String::from(spec.size.clone()))];
        if !spec.selector.is_empty() {
            let labels: Vec<String> = spec.selector.iter().map(|(k, v)| format!("{k}={v}")).collect();
            needs.push(format!("on a node labelled {}", labels.join(", ")));
        }
        if shared {
            needs.push("shared".into());
        }
        let message = format!("no free Volume of this namespace is {}", needs.join(" and "));
        bound.insert(key, Err(message));
    }
    (bound, taken)
}

/// The names of the volumes a workload's containers mount.
fn mount_names(owner: &Resource) -> BTreeSet<String> {
    let containers = owner.spec["template"]["containers"].as_array().into_iter().flatten();
    let mounts = containers
        .filter_map(|container| container["volumeMounts"].as_array())
        .flatten();
    mounts
        .filter_map(|mount| Some(mount["volume"].as_str()?.to_string()))
        .collect()
}

/// The Volumes `names` come to in `namespace`, and the one node they are on, or why they are not.
fn held(
    namespace: &str,
    names: BTreeSet<String>,
    vols: &BTreeMap<String, Vol>,
    bound: &BTreeMap<String, Result<String, String>>,
) -> Result<Held, String> {
    let (mut volumes, mut nodes) = (BTreeMap::new(), BTreeSet::new());
    for name in names {
        // A Volume of the name is mounted before a VolumeClaim of it.
        let volume = if vols.contains_key(&format!("Volume/{namespace}/{name}")) {
            name.clone()
        } else {
            match bound.get(&format!("VolumeClaim/{namespace}/{name}")) {
                Some(Ok(volume)) => volume.clone(),
                Some(Err(why)) => return Err(format!("VolumeClaim {name}: {why}")),
                None => return Err(format!("there is no Volume or VolumeClaim {name}")),
            }
        };
        let vol = &vols[&format!("Volume/{namespace}/{volume}")];
        if let Some(why) = &vol.refused {
            return Err(format!("Volume {volume}: {why}"));
        }
        // (A shared one is served to whichever node the workload is on.)
        if !vol.shared {
            nodes.insert(vol.dir.node.clone());
        }
        volumes.insert(name, vol.dir.clone());
    }
    if nodes.len() > 1 {
        let nodes: Vec<String> = nodes.into_iter().collect();
        return Err(format!("its volumes are on different nodes: {}", nodes.join(", ")));
    }
    Ok(Held {
        node: nodes.into_iter().next(),
        volumes,
    })
}

/// Work out every claim, every volume and every workload that mounts some.
pub fn resolve(store: &Store) -> Volumes {
    let vols = volumes(store);
    let (bound, taken) = bind(store, &vols);
    let mut found = Volumes::default();
    for (key, vol) in &vols {
        let status = match (&vol.refused, taken.get(key)) {
            (Some(why), _) => Some(json!({ "message": why })),
            (None, Some(claim)) => Some(json!({ "claim": claim })),
            (None, None) => None,
        };
        // (What is said of its copies is the replicas' and the leader's to say: it stays.)
        let was = store.get(key).and_then(|volume| volume.status.as_ref()?.as_object());
        let copies = was
            .into_iter()
            .flatten()
            .filter(|(field, _)| crate::replicas::FIELDS.contains(&field.as_str()));
        let copies: serde_json::Map<String, Value> =
            copies.map(|(field, value)| (field.clone(), value.clone())).collect();
        // (Without replicas any more, only where it is, while that is not where `node` says.)
        let home = store.get(key).and_then(|volume| volume.spec["node"].as_str());
        let mut copies = copies;
        if vol.replicas < 2 {
            copies.retain(|field, node| field == "primary" && node.as_str() != home);
        }
        let status = match (status, copies.is_empty()) {
            (status, true) => status,
            (status, false) => {
                let mut all = copies;
                all.extend(status.as_ref().and_then(Value::as_object).cloned().unwrap_or_default());
                Some(all.into())
            }
        };
        found.status.insert(key.clone(), status);
    }
    for (key, outcome) in &bound {
        let status = match outcome {
            Ok(volume) => json!({ "volume": volume }),
            Err(message) => {
                // (What it was bound to stays written: that is what keeps it from another.)
                let recorded = store
                    .get(key)
                    .and_then(|claim| claim.status.as_ref()?["volume"].as_str());
                match recorded {
                    Some(volume) => json!({ "volume": volume, "message": message }),
                    None => json!({ "message": message }),
                }
            }
        };
        found.status.insert(key.clone(), Some(status));
    }
    let owners = ["Workload", "Job"].into_iter().flat_map(|kind| store.list(Some(kind)));
    // (A Job that is over holds nothing.)
    for owner in owners.filter(|owner| crate::sched::wants(owner).is_some()) {
        let names = mount_names(owner);
        if !names.is_empty() {
            let key = owner.key();
            let outcome = held(parts(&key).0, names, &vols, &bound);
            found.owners.insert(key, outcome);
        }
    }
    found
}

/// The Volumes and VolumeClaims whose status is not what it should be: key and new status.
pub fn writes(store: &Store) -> Vec<(String, Option<Value>)> {
    let differs = |(key, new): &(String, Option<Value>)| store.get(key).is_some_and(|found| found.status != *new);
    resolve(store).status.into_iter().filter(differs).collect()
}

/// The one node a workload goes on when it has claimed devices (`devices`) and mounts volumes
/// (`volumes`): none if it has neither or its volumes are all shared, why not if the two are
/// not on one node.
pub fn together(
    devices: Option<&Result<crate::claims::Held, String>>,
    volumes: Option<&Result<Held, String>>,
) -> Result<Option<String>, String> {
    let devices = devices.map(|d| d.as_ref().map(|held| held.node.as_str()).map_err(Clone::clone));
    let volumes = volumes.map(|v| v.as_ref().map(|held| held.node.as_deref()).map_err(Clone::clone));
    match (devices.transpose()?, volumes.transpose()?.flatten()) {
        (Some(d), Some(v)) if d != v => Err(format!("its DeviceClaims are on node {d} but its volumes on node {v}")),
        (d, v) => Ok(d.or(v).map(str::to_string)),
    }
}

/// What each workload that may be placed on `me` mounts: its key, and each name a container
/// mounts with the directory that is. A Volume of another node is in it only if it is shared.
pub fn mounts(store: &Store, me: &str) -> BTreeMap<String, BTreeMap<String, Dir>> {
    let owners = resolve(store).owners;
    // A claim counts once the scheduler has written what it is bound to: this node's own first
    // fit, worked out from a store that is a write behind, could be another Volume.
    let recorded = |namespace: &str, name: &str, dir: &Dir| {
        let claim = store.get(&format!("VolumeClaim/{namespace}/{name}"));
        name == dir.name || claim.and_then(|c| c.status.as_ref()?["volume"].as_str()) == Some(&dir.name)
    };
    let mine = owners.into_iter().filter_map(|(key, outcome)| {
        let held = outcome
            .ok()
            .filter(|held| held.node.as_deref().is_none_or(|node| node == me))?;
        let namespace = parts(&key).0;
        let settled = held.volumes.iter().all(|(name, dir)| recorded(namespace, name, dir));
        settled.then_some((key, held.volumes))
    });
    mine.collect()
}

/// The Volumes kept on more than one node: key, where each is now, and how many copies in all.
pub fn replicated(store: &Store) -> Vec<(String, Dir, u32)> {
    let kept =
        |(key, vol): (String, Vol)| (vol.replicas > 1 && vol.refused.is_none()).then_some((key, vol.dir, vol.replicas));
    volumes(store).into_iter().filter_map(kept).collect()
}

/// Where the Volume `name` of `namespace` is, if there is one that is not refused.
pub fn dir(store: &Store, namespace: &str, name: &str) -> Option<Dir> {
    let vol = volumes(store).remove(&format!("Volume/{namespace}/{name}"))?;
    vol.refused.is_none().then_some(vol.dir)
}

/// The encrypted Volumes whose data is on `me`, and how big each is to be (bytes).
pub fn encrypted(store: &Store, me: &str) -> Vec<(Dir, u64)> {
    let mine = |vol: Vol| {
        let kept = vol.dir.encrypted && vol.refused.is_none() && vol.dir.node == me;
        kept.then(|| (vol.dir, vol.size.unwrap_or(0.0) as u64))
    };
    volumes(store).into_values().filter_map(mine).collect()
}

/// The shared Volumes whose data is on `me`: what it serves to the other nodes.
pub fn served(store: &Store, me: &str) -> Vec<Dir> {
    let mine = |vol: Vol| (vol.shared && vol.refused.is_none() && vol.dir.node == me).then_some(vol.dir);
    volumes(store).into_values().filter_map(mine).collect()
}

/// Make the directory a volume is on this node, and say where it is. In `kith-system` it is the
/// path as written; anywhere else it is `<state>/volumes/<namespace>/<name>/<path>`.
///
/// Nothing is made or followed outside that root: each part is made one at a time, one that is
/// a symbolic link (a container with the volume mounted can make one) or a file is refused, and
/// the result is checked to be inside the root once more.
//
// ponytail: between this check and the container's mount, something that can write the directory
// could swap a part for a link; the mount follows the final path. A kernel that has openat2
// with RESOLVE_BENEATH would close it: bind from a file descriptor.
pub fn host_dir(state: &Path, dir: &Dir) -> Result<PathBuf, String> {
    check_path(&dir.namespace, &dir.path)?;
    let made = |path: &Path, e: std::io::Error| format!("cannot make {}: {e}", path.display());
    if dir.namespace == SYSTEM {
        let path = PathBuf::from(&dir.path);
        std::fs::create_dir_all(&path).map_err(|e| made(&path, e))?;
        return Ok(path);
    }
    let state = state.canonicalize().map_err(|e| made(state, e))?;
    let root = state.join("volumes").join(&dir.namespace).join(&dir.name);
    // (Nothing is made under a closed one: what a workload wrote there would be in the clear.)
    if dir.encrypted && !crate::encrypted::open(&root) {
        return Err(
            "it is encrypted and not open: its key comes from the cluster's other nodes, \
                    and this node's log says what it waits for"
                .into(),
        );
    }
    // (Nor beside one that was made encrypted: what is in its file would seem to be gone.)
    if !dir.encrypted && crate::encrypted::made(&state, &dir.namespace, &dir.name) {
        return Err("it was made encrypted and its file is still on this node: say `encrypted: true` again".into());
    }
    let mut path = state;
    let inside = ["volumes", &dir.namespace, &dir.name]
        .into_iter()
        .chain(dir.path.split('/'));
    for part in inside {
        path.push(part);
        match std::fs::symlink_metadata(&path) {
            Ok(found) if found.is_symlink() => return Err(format!("{} is a symbolic link", path.display())),
            Ok(found) if !found.is_dir() => return Err(format!("{} is not a directory", path.display())),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&path).map_err(|e| made(&path, e))?;
            }
            Err(e) => return Err(made(&path, e)),
        }
    }
    let real = path.canonicalize().map_err(|e| made(&path, e))?;
    if !real.starts_with(&root) {
        return Err(format!("{} is outside {}", real.display(), root.display()));
    }
    Ok(real)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_store::Command;

    /// Two nodes with different disks and three volumes of the `default` namespace.
    const CLUSTER: &str = "
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a, labels: { disk: ssd } }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: b, labels: { disk: hdd } }
spec: {}
---
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: fast }
spec: { node: a, path: fast, size: 100Gi }
---
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: slow }
spec: { node: b, path: slow, size: 1Ti, shared: true }
---
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: tiny }
spec: { node: a, path: tiny, size: 1Gi }
";

    fn store(extra: &str) -> Store {
        let mut store = Store::default();
        for resource in Resource::from_source(&format!("{CLUSTER}---\n{extra}")).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        store
    }

    fn res(kind: &str, namespace: &str, name: &str, spec: &str) -> String {
        format!(
            "---\napiVersion: kith.dev/v1\nkind: {kind}\nmetadata: {{ name: {name}, namespace: {namespace} }}\nspec: {spec}\n"
        )
    }

    /// A Workload of `namespace` whose one container mounts each of `volumes` at `/mnt/<volume>`.
    fn workload(namespace: &str, name: &str, volumes: &[&str]) -> String {
        let mounts: Vec<String> = volumes
            .iter()
            .map(|v| format!("{{ volume: {v}, path: /mnt/{v} }}"))
            .collect();
        let spec = format!(
            "{{ template: {{ containers: [{{ name: run, image: img, volumeMounts: [{}] }}] }} }}",
            mounts.join(", ")
        );
        res("Workload", namespace, name, &spec)
    }

    /// What the scheduler does: write what `writes` says, and a second look writes nothing.
    fn settle(store: &mut Store) -> Volumes {
        let found = resolve(store);
        kith_store::run(
            store,
            Command::Status {
                statuses: writes(store),
            },
        )
        .unwrap();
        assert!(writes(store).is_empty(), "a second look writes nothing");
        found
    }

    fn status(store: &Store, key: &str) -> Value {
        store.get(key).unwrap().status.clone().unwrap_or(json!({}))
    }

    #[test]
    fn a_mounted_volume_places_the_workload_on_its_node_and_a_bad_mount_says_why() {
        let source = [
            res("Volume", "default", "far", "{ node: b, path: far }"),
            workload("default", "db", &["fast"]),
            workload("default", "both", &["fast", "far"]),
            workload("default", "lost", &["nowhere"]),
            workload("ops", "other", &["fast"]),
            res(
                "Workload",
                "default",
                "plain",
                "{ template: { containers: [{ name: run, image: img }] } }",
            ),
        ]
        .concat();
        let store = store(&source);
        let found = resolve(&store);
        let db = found.owners["Workload/default/db"].clone().unwrap();
        assert_eq!(db.node.as_deref(), Some("a"));
        let fast = Dir {
            namespace: "default".into(),
            name: "fast".into(),
            path: "fast".into(),
            node: "a".into(),
            encrypted: false,
        };
        assert_eq!(db.volumes, BTreeMap::from([("fast".to_string(), fast)]));
        assert_eq!(
            found.owners["Workload/default/both"],
            Err("its volumes are on different nodes: a, b".into())
        );
        assert_eq!(
            found.owners["Workload/default/lost"],
            Err("there is no Volume or VolumeClaim nowhere".into())
        );
        // A volume is read in the workload's own namespace; a workload with no mounts is not in it.
        assert!(found.owners["Workload/ops/other"].is_err());
        assert!(!found.owners.contains_key("Workload/default/plain"));
        // Only the volume's node is given the mounts.
        assert!(mounts(&store, "a").contains_key("Workload/default/db"));
        assert!(mounts(&store, "b").is_empty());
        // A claimed device on another node than the volume: not placed, and the reason says so.
        let device = Ok(crate::claims::Held {
            node: "b".into(),
            devices: vec!["b-gpu".into()],
        });
        let on_a = found.owners.get("Workload/default/db");
        assert_eq!(
            together(Some(&device), on_a),
            Err("its DeviceClaims are on node b but its volumes on node a".into())
        );
        assert_eq!(together(None, on_a), Ok(Some("a".into())));
        assert_eq!(together(Some(&device), None), Ok(Some("b".into())));
        assert_eq!(together(None, None), Ok(None));
        assert_eq!(
            together(None, found.owners.get("Workload/default/both")).unwrap_err(),
            "its volumes are on different nodes: a, b"
        );
    }

    #[test]
    fn a_volume_claim_binds_a_free_fitting_volume_and_stays_bound() {
        let source = [
            res(
                "VolumeClaim",
                "default",
                "db",
                "{ size: 10Gi, selector: { disk: ssd } }",
            ),
            res(
                "VolumeClaim",
                "default",
                "second",
                "{ size: 10Gi, selector: { disk: ssd } }",
            ),
            res("VolumeClaim", "default", "huge", "{ size: 10Ti }"),
            res("VolumeClaim", "default", "mesh", "{ size: 1Gi, shared: true }"),
            workload("default", "app", &["db"]),
            workload("default", "waits", &["second"]),
        ]
        .concat();
        let mut store = store(&source);
        let found = settle(&mut store);
        // `fast` is the first that is big enough, on an ssd node, and free; `tiny` is too small.
        assert_eq!(status(&store, "VolumeClaim/default/db"), json!({ "volume": "fast" }));
        assert_eq!(status(&store, "Volume/default/fast"), json!({ "claim": "db" }));
        assert_eq!(status(&store, "Volume/default/tiny"), json!({}));
        assert_eq!(
            found.owners["Workload/default/app"].clone().unwrap().node.as_deref(),
            Some("a")
        );
        // Nothing else fits `second`: it says what it needs, and its workload waits with that said.
        let said = status(&store, "VolumeClaim/default/second");
        assert_eq!(
            said["message"],
            "no free Volume of this namespace is at least 10Gi and on a node labelled disk=ssd"
        );
        assert_eq!(
            found.owners["Workload/default/waits"],
            Err(format!("VolumeClaim second: {}", said["message"].as_str().unwrap()))
        );
        assert!(status(&store, "VolumeClaim/default/huge")["message"].is_string());
        // A claim that asks for shared gets a shared volume only.
        assert_eq!(status(&store, "VolumeClaim/default/mesh"), json!({ "volume": "slow" }));
        // A new volume that sorts before `fast` and fits does not take the claim from it.
        store
            .apply(
                Resource::from_source(&res("Volume", "default", "aaa", "{ node: a, path: aaa, size: 50Gi }"))
                    .unwrap()
                    .remove(0)
                    .unwrap(),
            )
            .unwrap();
        settle(&mut store);
        assert_eq!(status(&store, "VolumeClaim/default/db"), json!({ "volume": "fast" }));
        // ... and it is `second`'s now, which was waiting.
        assert_eq!(status(&store, "VolumeClaim/default/second"), json!({ "volume": "aaa" }));
        assert_eq!(status(&store, "Volume/default/aaa"), json!({ "claim": "second" }));
        // The volume goes: its claim says so and takes no other (`aaa` would fit once `second` goes):
        // the workload would start on empty data.
        store.delete("Volume/default/fast").unwrap();
        store.delete("VolumeClaim/default/second").unwrap();
        let again = settle(&mut store);
        let gone = status(&store, "VolumeClaim/default/db");
        assert_eq!(gone["volume"], "fast");
        assert!(gone["message"].as_str().unwrap().contains("is gone"), "{gone}");
        assert!(again.owners["Workload/default/app"].is_err());
        assert!(mounts(&store, "a").is_empty());
    }

    #[test]
    fn a_volume_of_the_name_is_mounted_before_a_claim_of_it() {
        let source = [
            res(
                "VolumeClaim",
                "default",
                "slow",
                "{ size: 1Gi, selector: { disk: ssd } }",
            ),
            workload("default", "app", &["slow"]),
        ]
        .concat();
        let found = resolve(&store(&source));
        // `slow` is both a Volume (on b) and a claim (that binds `fast`, on a): the Volume is mounted.
        let held = found.owners["Workload/default/app"].clone().unwrap();
        // (It is shared, so it pins the workload to no node; its data is on b.)
        let slow = &held.volumes["slow"];
        assert_eq!((held.node, slow.name.as_str(), slow.node.as_str()), (None, "slow", "b"));
    }

    #[test]
    fn a_volume_path_outside_the_namespaces_root_is_refused_in_the_status_and_places_nothing() {
        let source = [
            res("Volume", "default", "abs", "{ node: a, path: /etc }"),
            res("Volume", "default", "up", "{ node: a, path: ../x }"),
            res("Volume", "default", "gap", "{ node: a, path: a//b }"),
            res("Volume", "kith-system", "host", "{ node: a, path: /srv/shared }"),
            res("Volume", "kith-system", "rel", "{ node: a, path: srv }"),
            res("VolumeClaim", "default", "c", "{ size: 1 }"),
            workload("default", "w1", &["abs"]),
            workload("kith-system", "w2", &["host"]),
        ]
        .concat();
        let mut store = store(&source);
        let found = settle(&mut store);
        let refused = found.owners["Workload/default/w1"].clone().unwrap_err();
        assert!(
            refused.starts_with("Volume abs: path `/etc` must be relative"),
            "{refused}"
        );
        assert!(status(&store, "Volume/default/abs")["message"].is_string());
        assert!(status(&store, "Volume/default/up")["message"].is_string());
        assert!(status(&store, "Volume/default/gap")["message"].is_string());
        // Only kith-system may name a host path, and an absolute one.
        assert!(found.owners["Workload/kith-system/w2"].is_ok());
        assert_eq!(status(&store, "Volume/kith-system/host"), json!({}));
        assert!(
            status(&store, "Volume/kith-system/rel")["message"]
                .as_str()
                .unwrap()
                .contains("absolute")
        );
        // A claim never binds a volume that is refused (it has no size, so anything it asks fits).
        assert_ne!(status(&store, "VolumeClaim/default/c")["volume"], "abs");
    }

    /// A made-up state directory.
    fn state(name: &str) -> PathBuf {
        let state = std::env::temp_dir().join(format!("kith-volumes-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        std::fs::create_dir_all(&state).unwrap();
        state.canonicalize().unwrap()
    }

    fn dir(namespace: &str, path: &str) -> Dir {
        Dir {
            namespace: namespace.into(),
            name: "data".into(),
            path: path.into(),
            node: "a".into(),
            encrypted: false,
        }
    }

    #[test]
    fn a_namespaces_volume_directory_is_made_under_its_own_root_and_nowhere_else() {
        let state = state("root");
        let made = host_dir(&state, &dir("shop", "db/files")).unwrap();
        assert_eq!(made, state.join("volumes/shop/data/db/files"));
        assert!(made.is_dir());
        // A second time finds it as it is.
        assert_eq!(host_dir(&state, &dir("shop", "db/files")).unwrap(), made);
        std::fs::write(made.join("kept"), "x").unwrap();
        assert!(
            host_dir(&state, &dir("shop", "db/files"))
                .unwrap()
                .join("kept")
                .exists()
        );
        for bad in ["/etc", "../x", "a/../../x", "a//b", "", ".", "a/", "a/./b", "x\0y"] {
            let why = host_dir(&state, &dir("shop", bad)).unwrap_err();
            assert!(why.contains("must be relative"), "{bad:?}: {why}");
        }
        // Nothing outside the root was made by any of that.
        assert!(!state.join("volumes/shop/x").exists() && !state.join("x").exists());
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn a_volume_path_through_a_symlink_planted_in_the_root_is_refused() {
        let state = state("link");
        let outside = state.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        // A container with the volume mounted made a link in it that points out of it.
        let root = host_dir(&state, &dir("shop", "base")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let why = host_dir(&state, &dir("shop", "base/link/sub")).unwrap_err();
        assert!(why.contains("symbolic link"), "{why}");
        assert!(!outside.join("sub").exists(), "nothing was made through the link");
        // The link itself as the whole path is refused too, and so is a link to a file.
        assert!(host_dir(&state, &dir("shop", "base/link")).is_err());
        let file = state.join("file");
        std::fs::write(&file, "x").unwrap();
        std::os::unix::fs::symlink(&file, root.join("f")).unwrap();
        assert!(host_dir(&state, &dir("shop", "base/f")).is_err());
        // A plain file where a directory is wanted is refused as well.
        std::fs::write(root.join("plain"), "x").unwrap();
        assert!(
            host_dir(&state, &dir("shop", "base/plain/x"))
                .unwrap_err()
                .contains("not a directory")
        );
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn a_kith_system_volume_is_the_path_as_written() {
        let state = state("system");
        let at = state.join("somewhere/else");
        let made = host_dir(&state, &dir(SYSTEM, at.to_str().unwrap())).unwrap();
        assert_eq!(made, at);
        assert!(at.is_dir());
        assert!(
            host_dir(&state, &dir(SYSTEM, "relative"))
                .unwrap_err()
                .contains("absolute")
        );
        let _ = std::fs::remove_dir_all(&state);
    }

    /// A workload whose volumes are all shared goes on any node, and every node may mount them;
    /// one that also mounts a volume that is not goes where that one is. Only the volume's own
    /// node serves it, and a shared volume with a path anywhere on the host is refused.
    #[test]
    fn a_shared_volume_pins_nothing_and_is_served_by_its_node_only() {
        let source = [
            CLUSTER.to_string(),
            workload("default", "anywhere", &["slow"]),
            workload("default", "pinned", &["slow", "fast"]),
            res(
                "Volume",
                "kith-system",
                "host",
                "{ node: a, path: /srv/all, shared: true }",
            ),
            workload("kith-system", "system", &["host"]),
        ]
        .concat();
        let store = store(&source);
        let found = resolve(&store);
        assert_eq!(found.owners["Workload/default/anywhere"].clone().unwrap().node, None);
        assert_eq!(together(None, found.owners.get("Workload/default/anywhere")), Ok(None));
        assert_eq!(
            found.owners["Workload/default/pinned"].clone().unwrap().node.as_deref(),
            Some("a")
        );
        for node in ["a", "b"] {
            let mounted = mounts(&store, node);
            assert_eq!(mounted["Workload/default/anywhere"]["slow"].node, "b", "{node}");
            assert_eq!(mounted.contains_key("Workload/default/pinned"), node == "a");
        }
        let names = |node: &str| served(&store, node).into_iter().map(|dir| dir.name).collect::<Vec<_>>();
        assert_eq!((names("a"), names("b")), (vec![], vec!["slow".to_string()]));
        let refused = found.owners["Workload/kith-system/system"].clone().unwrap_err();
        assert!(
            refused.contains("a shared volume cannot be in kith-system"),
            "{refused}"
        );
    }

    /// The example in the README's Storage section is a real one: it applies, binds and places.
    #[test]
    fn the_readme_volume_example_applies_binds_and_places() {
        let readme = include_str!("../../../README.md");
        let section = readme.split("\n## Storage\n").nth(1).expect("a Storage section");
        let example = section.split("```yaml\n").nth(1).and_then(|s| s.split("```").next());
        let mut store = Store::default();
        let nodes = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: { name: n1 }\nspec: {}\n---\n";
        let source = format!("{nodes}{}", example.expect("a yaml example"));
        for resource in Resource::from_source(&source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let found = settle(&mut store);
        let held = found.owners.values().next().expect("a workload that mounts").clone();
        assert_eq!(held.unwrap().node.as_deref(), Some("n1"));
        assert_eq!(status(&store, "VolumeClaim/default/db-data")["volume"], "db-disk");
    }
}
