//! What a worker (`spec.trust: worker`) may write to the store.
//!
//! A node sends its writes to the node that leads (`/v1/raft/write`), which gives them to
//! Raft as they come. From a worker each one is held to the list here first, against the
//! store of the control node that was asked: what a node says about itself, and nothing
//! of anyone else's (docs/adr-workers.md, "Writes"). A control node's own writes (no caller
//! named) are held to the list in `own_writes.rs` instead, which reuses these checks for
//! the kinds a control node holds and refuses the rest.

use kith_api::Resource;
use kith_api::store::Store;
use kith_store::Command;
use serde_json::{Map, Value};
use std::net::Ipv6Addr;

/// The annotation a control node puts on a Blob a worker made: the worker's name.
pub const MADE_ON: &str = "kith.dev/made-on";
/// What `images` and `backups` put on the Blobs they make.
const MADE_BY: &str = "kith.dev/made-by";
const DISCOVERED: &str = "kith.dev/discovered";

/// Who sent the write, as the node that checks it knows them.
pub struct Worker<'a> {
    /// The name in its certificate.
    pub name: &'a str,
    /// The mesh's prefix, where there is one: a unit's address has to be in the worker's part.
    pub prefix: Option<Ipv6Addr>,
    /// Does this node have a blob's file of that name? (Bytes a Blob may not be made for.)
    pub held: &'a dyn Fn(&str) -> bool,
}

type Fields = Map<String, Value>;

fn refused(what: impl std::fmt::Display, why: impl std::fmt::Display) -> String {
    format!("{what}: {why}: a worker writes only what it says of itself")
}

/// Are all of `fields`' names among `allowed`?
fn only(key: &str, fields: &Fields, allowed: &[&str]) -> Result<(), String> {
    match fields.keys().find(|field| !allowed.contains(&field.as_str())) {
        Some(field) => Err(refused(key, format!("the field `{field}` is not a worker's to write"))),
        None => Ok(()),
    }
}

fn namespace(resource: &Resource) -> &str {
    resource.metadata.namespace.as_deref().unwrap_or("default")
}

/// Is the Volume `volume` of `namespace` on the node `node`, as the store has it?
fn has_volume(store: &Store, namespace: &str, volume: &str, node: &str) -> bool {
    crate::volumes::dir(store, namespace, volume).is_some_and(|dir| dir.node == node)
}

/// Is `resource` an Image or a Backup of a Volume that is on `node`?
pub(crate) fn of_its_volume(store: &Store, resource: &Resource, node: &str) -> bool {
    let volume = resource.spec["volume"].as_str();
    volume.is_some_and(|volume| has_volume(store, namespace(resource), volume, node))
}

/// May `node` name the blob `blob` of `namespace` in a status that named `before`? One it
/// made, or one that status named already.
fn its_blob(store: &Store, namespace: &str, blob: &str, node: &str, before: &[&str]) -> bool {
    let made = store.get(&format!("Blob/{namespace}/{blob}"));
    before.contains(&blob)
        || made.is_some_and(|made| made.metadata.annotations.get(MADE_ON).is_some_and(|on| on == node))
}

/// Is a replica (or a copy, or the run) of the template `template` placed on `node`?
pub(crate) fn on(template: &Resource, node: &str) -> bool {
    let placed = template.status.as_ref().and_then(|status| status["nodes"].as_object());
    placed.is_some_and(|placed| placed.values().any(|on| on == node))
}

/// Does the reference `image` of a template name the cluster's Image `wanted` (`NAMESPACE/NAME`)
/// at a node's own registry (`localhost:PORT/NAMESPACE/NAME`, a tag or a digest after it)?
fn names_image(image: &str, wanted: &str) -> bool {
    let Some((registry, rest)) = image.split_once('/') else {
        return false;
    };
    let local = ["localhost:", "127.0.0.1:"]
        .iter()
        .any(|host| registry.starts_with(host));
    let repository = rest.split('@').next().unwrap_or_default();
    // (A tag is after the last `/`: a `:` before it would be a port, and there is none here.)
    let repository = match repository.rsplit_once(':') {
        Some((repository, tag)) if !tag.contains('/') => repository,
        _ => repository,
    };
    local && repository == wanted
}

/// Does a template of the Image's namespace that is placed on `node` run the Image `image`?
fn runs(store: &Store, image: &Resource, node: &str) -> bool {
    let wanted = format!("{}/{}", namespace(image), image.metadata.name);
    let kinds = ["Workload", "NodeWorkload", "Job"];
    let mut templates = kinds.iter().flat_map(|kind| store.list(Some(kind)));
    templates.any(|template| {
        let units = |list: &str| template.spec["template"][list].as_array().cloned().unwrap_or_default();
        let mut units = units("containers").into_iter().chain(units("initContainers"));
        namespace(template) == namespace(image)
            && on(template, node)
            && units.any(|unit| unit["image"].as_str().is_some_and(|image| names_image(image, &wanted)))
    })
}

/// May the worker `node` be sent the bytes of the blob `name`? Where the status of an Image
/// or a Backup names it, and that one's Volume is on the worker or it is an Image that a
/// template placed on the worker runs. Not every blob of a namespace the worker has something
/// in: one small unit on a worker would then be the backups of every Volume beside it.
pub fn may_fetch(store: &Store, node: &str, name: &str) -> bool {
    let mut of = store.list(Some("Image")).chain(store.list(Some("Backup")));
    of.any(|of| {
        named(of.status.as_ref()).contains(&name)
            && (of_its_volume(store, of, node) || (of.kind == "Image" && runs(store, of, node)))
    })
}

/// The blobs an Image's or a Backup's status names.
fn named(status: Option<&Value>) -> Vec<&str> {
    let Some(status) = status else { return Vec::new() };
    let image = status["blobs"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(_, blob)| blob.as_str());
    let backups = status["backups"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|backup| backup["blob"].as_str());
    image.chain(backups).collect()
}

/// What a node says it serves (`status.serves`): null, or `dns` a port and `ingress` true, and nothing else.
fn serving_shape(key: &str, serves: &Value) -> Result<(), String> {
    let fields = match serves {
        Value::Null => return Ok(()),
        Value::Object(fields) => fields,
        _ => return Err(refused(key, "`serves` is null or an object of dns and ingress")),
    };
    if let Some(other) = fields.keys().find(|key| !matches!(key.as_str(), "dns" | "ingress")) {
        return Err(refused(key, format!("serves has no {other}")));
    }
    let port = fields
        .get("dns")
        .map(|dns| dns.as_u64().filter(|port| (1..=65535).contains(port)));
    if port == Some(None) {
        return Err(refused(key, "`dns` is a port from 1 to 65535"));
    }
    if fields
        .get("ingress")
        .is_some_and(|ingress| *ingress != Value::Bool(true))
    {
        return Err(refused(key, "`ingress` is true or not said"));
    }
    Ok(())
}

/// Refused where the mesh key `fields` say is another node's: two nodes that say one key are both
/// left out of the mesh, so saying another's cuts it off. (A Node's own patch, by a worker or a
/// control node alike: `own_writes` calls it too.)
pub(crate) fn mesh_key_elsewhere(store: &Store, node: &str, key: &str, fields: &Fields) -> Result<(), String> {
    let said = fields.get("mesh").and_then(|mesh| mesh["key"].as_str());
    let theirs = |other: &Resource| {
        let has = other.status.as_ref().and_then(|status| status["mesh"]["key"].as_str());
        other.metadata.name != node && has.is_some() && has == said
    };
    match store.list(Some("Node")).find(|other| theirs(other)) {
        Some(other) => Err(refused(key, format!("the mesh key is node {}'s", other.metadata.name))),
        None => Ok(()),
    }
}

/// What a node says of its people's device (`status.people`): null, or the device's public key
/// (32 bytes, base64), its port and its endpoint (a string or null), and nothing else.
fn people_shape(key: &str, people: &Value) -> Result<(), String> {
    use base64::Engine as _;
    let fields = match people {
        Value::Null => return Ok(()),
        Value::Object(fields) => fields,
        _ => {
            return Err(refused(
                key,
                "`people` is null or the people's device: publicKey, port, endpoint",
            ));
        }
    };
    if let Some(other) = fields
        .keys()
        .find(|key| !matches!(key.as_str(), "publicKey" | "port" | "endpoint"))
    {
        return Err(refused(key, format!("people has no {other}")));
    }
    let public = fields.get("publicKey").and_then(Value::as_str);
    let public = public.and_then(|public| base64::engine::general_purpose::STANDARD.decode(public).ok());
    if public.is_none_or(|public| public.len() != 32) {
        return Err(refused(key, "`publicKey` is a 32-byte key in base64"));
    }
    if !fields
        .get("port")
        .and_then(Value::as_u64)
        .is_some_and(|port| (1..=65535).contains(&port))
    {
        return Err(refused(key, "`port` is a port from 1 to 65535"));
    }
    if !fields
        .get("endpoint")
        .is_some_and(|endpoint| endpoint.is_null() || endpoint.is_string())
    {
        return Err(refused(key, "`endpoint` is a string or null"));
    }
    Ok(())
}

/// What a node says of what its levels could not give (`status.peopleNotes`): null, or a few short
/// lines of text.
fn notes_shape(key: &str, notes: &Value) -> Result<(), String> {
    let few = match notes {
        Value::Null => true,
        Value::Array(lines) => {
            lines.len() <= 16
                && lines
                    .iter()
                    .all(|line| line.as_str().is_some_and(|line| line.chars().count() <= 200))
        }
        _ => false,
    };
    if few {
        Ok(())
    } else {
        Err(refused(key, "`peopleNotes` is null or up to 16 lines of text"))
    }
}

pub(crate) fn patch(store: &Store, who: &Worker, key: &str, fields: &Fields) -> Result<(), String> {
    let node = who.name;
    let Some(live) = store.get(key) else {
        // (A key that is gone is skipped by the store: nothing to refuse.)
        return Ok(());
    };
    match live.kind.as_str() {
        "Node" if live.metadata.name == node => {
            only(
                key,
                fields,
                &["os", "mesh", "serves", "policy", "thumbprint", "people", "peopleNotes"],
            )?;
            if let Some(people) = fields.get("people") {
                people_shape(key, people)?;
            }
            if let Some(notes) = fields.get("peopleNotes") {
                notes_shape(key, notes)?;
            }
            // (Its own policy, as it says it: null, or a small object of yes and no and the classes of Device.)
            let small = |policy: &Value| match policy {
                Value::Null => true,
                Value::Object(keys) => {
                    keys.len() <= 16
                        && keys.iter().all(|(key, value)| match value {
                            Value::Bool(_) => key.len() <= 32,
                            // (The classes of Device, or the capabilities it holds, by name.)
                            Value::Array(names) => {
                                let most = match key.as_str() {
                                    "devices" => 8,
                                    "capabilities" => 64,
                                    _ => 0,
                                };
                                names.len() <= most && names.iter().all(|c| c.as_str().is_some_and(|c| c.len() <= 24))
                            }
                            _ => false,
                        })
                }
                _ => false,
            };
            if !fields.get("policy").is_none_or(small) {
                return Err(refused(key, "`policy` is null or a node's own policy as it says it"));
            }
            // The ACME account's thumbprint its view holds: the leader orders once each ingress
            // worker says it has it. (Wrong, it holds up orders, as a wrong answer to the
            // authority's challenge would.)
            let print = fields.get("thumbprint");
            if print.is_some_and(|print| {
                !print.is_null()
                    && !print
                        .as_str()
                        .is_some_and(|print| print.len() <= 64 && crate::acme::token_like(print))
            }) {
                return Err(refused(key, "`thumbprint` is a thumbprint or null"));
            }
            if let Some(serves) = fields.get("serves") {
                serving_shape(key, serves)?;
                // A worker that joined to run from a view answers ingress only when its token let
                // it: the node that admitted it wrote `spec.ingress` (its view holds the certificates).
                let viewed = live.status.as_ref().is_some_and(|status| status["view"] == true);
                if viewed && serves.get("ingress").is_some() && live.spec["ingress"] != true {
                    return Err(refused(
                        key,
                        "ingress is served by a worker that joined with a token from `kith node token --worker --ingress`",
                    ));
                }
            }
            mesh_key_elsewhere(store, node, key, fields)
        }
        "Blob" => {
            only(key, fields, &["nodes"])?;
            let names = |nodes: Option<&Value>| -> Option<std::collections::BTreeSet<String>> {
                let nodes = nodes.map_or(Some(Vec::new()), |nodes| nodes.as_array().cloned())?;
                nodes.iter().map(|node| node.as_str().map(str::to_string)).collect()
            };
            let was = names(
                live.status
                    .as_ref()
                    .map(|status| &status["nodes"])
                    .filter(|nodes| !nodes.is_null()),
            );
            let (Some(was), Some(now)) = (was, names(fields.get("nodes"))) else {
                return Err(refused(key, "`nodes` is a list of names"));
            };
            match was.symmetric_difference(&now).find(|changed| *changed != node) {
                Some(other) => Err(refused(
                    key,
                    format!("whether node {other} holds it is for that node to say"),
                )),
                None => Ok(()),
            }
        }
        "Image" | "Backup" if of_its_volume(store, live, node) => {
            only(
                key,
                fields,
                &["digest", "size", "blobs", "of", "backups", "message", "tried"],
            )?;
            let before = named(live.status.as_ref());
            let said = Value::Object(fields.clone());
            match named(Some(&said))
                .into_iter()
                .find(|blob| !its_blob(store, namespace(live), blob, node, &before))
            {
                Some(blob) => Err(refused(key, format!("the blob {blob} is not one this node made"))),
                None => Ok(()),
            }
        }
        "Volume" => {
            only(key, fields, &["synced"])?;
            let status = live.status.as_ref();
            let replica = status.and_then(|status| status["replicas"].as_array());
            if !replica.is_some_and(|replicas| replicas.iter().any(|replica| replica == node)) {
                return Err(refused(key, "this node is no replica of it"));
            }
            let empty = Map::new();
            let was = status.and_then(|status| status["synced"].as_object()).unwrap_or(&empty);
            let Some(now) = fields.get("synced").and_then(Value::as_object) else {
                return Err(refused(key, "`synced` is a time for each replica"));
            };
            let others = |synced: &Fields| -> Vec<(String, Value)> {
                let rest = synced.iter().filter(|(replica, _)| *replica != node);
                rest.map(|(replica, at)| (replica.clone(), at.clone())).collect()
            };
            match (others(was) == others(now), now.get(node).is_none_or(Value::is_u64)) {
                (true, true) => Ok(()),
                _ => Err(refused(key, "when another replica synced is for that replica to say")),
            }
        }
        _ => Err(refused(key, "its status is not this node's")),
    }
}

pub(crate) fn status(store: &Store, who: &Worker, key: &str, said: Option<&Value>) -> Result<(), String> {
    let Some(live) = store.get(key) else { return Ok(()) };
    let fields = match said {
        Some(Value::Object(fields)) => fields.clone(),
        None => Map::new(),
        Some(_) => return Err(refused(key, "a status is an object")),
    };
    match live.kind.as_str() {
        "NodeKey" if live.metadata.name == who.name => only(
            key,
            &fields,
            &["sealed", "message", "passphrase", "recoverySeen", "duress", "duressAll"],
        ),
        // What its session does (`activity`), and nothing else of the status.
        "Seat" if live.spec["node"] == who.name => {
            let rest = |status: &Fields| -> Vec<(String, Value)> {
                let rest = status.iter().filter(|(field, _)| *field != "activity");
                rest.map(|(field, value)| (field.clone(), value.clone())).collect()
            };
            let empty = Map::new();
            let was = live.status.as_ref().and_then(Value::as_object).unwrap_or(&empty);
            match rest(was) == rest(&fields) {
                true => Ok(()),
                false => Err(refused(key, "only what its session does is this node's to say")),
            }
        }
        _ => Err(refused(key, "its status is not this node's")),
    }
}

/// What is taken of what the worker says of the units of `key`: `Err` when none of it is
/// its to say, and the units of replicas the scheduler gave another node are left out.
pub(crate) fn report(store: &Store, who: &Worker, key: &str, said: Option<Value>) -> Result<Option<Value>, String> {
    let (Some(live), Some(said)) = (store.get(key), said) else {
        // (Gone: skipped by the store. Nothing said: its own units are taken out.)
        return Ok(None);
    };
    if !["Workload", "NodeWorkload", "Job"].contains(&live.kind.as_str()) {
        return Err(refused(key, "it runs no units"));
    }
    let Value::Object(mut said) = said else {
        return Err(refused(key, "a report is an object"));
    };
    // What a report has today: a Job's is the word of the one node that runs it.
    match live.kind.as_str() {
        "Job" => only(
            key,
            &said,
            &[
                "state",
                "succeeded",
                "failed",
                "observedRevision",
                "containers",
                "message",
            ],
        )?,
        _ => only(key, &said, &["replicas", "containers", "notes"])?,
    }
    // (A NodeWorkload's copies too: the scheduler gives each node it selects a number.)
    let placed = live.status.as_ref().and_then(|status| status["nodes"].as_object());
    let given = |unit: &Value| {
        let replica = unit["replica"].as_u64().map(|replica| replica.to_string());
        replica.is_some_and(|replica| {
            placed.is_some_and(|placed| placed.get(&replica).is_some_and(|node| node == who.name))
        })
    };
    let within = |unit: &Value| match (unit.get("address"), who.prefix) {
        (None, _) => true,
        (Some(address), Some(prefix)) => {
            let address = address.as_str().and_then(|address| address.parse::<Ipv6Addr>().ok());
            let net = kith_mesh::node_net(prefix, who.name).segments();
            address.is_some_and(|address| address.segments()[..5] == net[..5])
        }
        (Some(_), None) => false,
    };
    let units = said.remove("containers");
    let units: Vec<Value> = units.as_ref().and_then(Value::as_array).cloned().unwrap_or_default();
    // (`hostUsers`: whether a container keeps the node's users, which the node says of its own unit.)
    const UNIT: [&str; 10] = [
        "name",
        "replica",
        "state",
        "ready",
        "restarts",
        "revision",
        "exitCode",
        "message",
        "address",
        "hostUsers",
    ];
    for unit in &units {
        match unit.as_object() {
            Some(unit) => only(key, unit, &UNIT)?,
            None => return Err(refused(key, "a unit is an object")),
        }
    }
    if let Some(unit) = units.iter().find(|unit| given(unit) && !within(unit)) {
        return Err(refused(
            key,
            format!("the address {} is not in this node's part of the mesh", unit["address"]),
        ));
    }
    let units: Vec<Value> = units.into_iter().filter(given).collect();
    // Nothing of it is placed here: the rest of a report (a Job's state, the notes) is the
    // word of a node that runs it, so all that is taken is that this one runs none.
    if !on(live, who.name) {
        return Ok(None);
    }
    // How many replicas there are follows from the spec, as this node reads it: where only
    // workers run a Workload, theirs is the one word on it.
    if said.contains_key("replicas") {
        let replicas = crate::controller::template_of(live).map_or(0, |(_, replicas)| replicas);
        said.insert("replicas".into(), replicas.into());
    }
    said.insert("containers".into(), units.into());
    Ok(Some(said.into()))
}

pub(crate) fn apply(store: &Store, who: &Worker, resource: &mut Resource) -> Result<(), String> {
    let (key, node) = (resource.key(), who.name);
    let live = store.get(&key);
    let spec = resource.spec.as_object().cloned().unwrap_or_default();
    match resource.kind.as_str() {
        // The key of its encrypted state, given to the cluster to hold: once. What is
        // changed on it after (locked, wiped, sealed) is the owner's word, not the node's.
        "NodeKey" if resource.metadata.name == node && live.is_none() => only(&key, &spec, &["id", "wrapped"]),
        "Device" | "Seat" => {
            let own = |resource: &Resource| {
                resource.spec["node"] == node
                    && resource
                        .metadata
                        .labels
                        .get(DISCOVERED)
                        .is_some_and(|made| made == "true")
            };
            // The labels discovery writes and no other, a claim's selector reads them: with
            // one of its own choosing, this node's Device would be one more that a claim made
            // for another node's comes to. And a name that is its own (`devices::whose`): one
            // that starts as its own do, and as no other node's with a longer name does (`w`
            // does not make `w-b-gpu-card0`: node `w-b` would then leave its own out).
            let class = resource.spec["class"].as_str();
            let plain = resource
                .metadata
                .labels
                .iter()
                .all(|(label, value)| match label.as_str() {
                    "kith.dev/node" => value == node,
                    "class" => Some(value.as_str()) == class,
                    // (Checked below: the label is an admin's, not this node's to write.)
                    crate::claims::NAMESPACES => true,
                    other => crate::devices::LABELS.contains(&other),
                });
            if !(own(resource) && live.is_none_or(own) && plain) {
                return Err(refused(&key, "it is not one this node's hardware made"));
            }
            // The namespaces a Device or Seat is given to are set by an admin, and kept as the store has
            // them: a worker neither adds, changes nor takes that label away.
            let namespaces = |resource: &Resource| resource.metadata.labels.get(crate::claims::NAMESPACES).cloned();
            if namespaces(resource) != live.and_then(namespaces) {
                return Err(refused(&key, "its kith.dev/namespaces label is an admin's to set"));
            }
            // A Device's class is what its hardware was found to be: a live one keeps the class it has.
            if live.is_some_and(|live| live.spec["class"] != resource.spec["class"]) {
                return Err(refused(&key, "its class is the one its hardware was found with"));
            }
            match crate::devices::whose(store, &resource.metadata.name) {
                theirs if theirs.contains(&node) => Ok(()),
                theirs if theirs.is_empty() => Err(refused(&key, "it is not one this node's hardware made")),
                theirs => {
                    let theirs = theirs.join(", ");
                    let why = format!("its name is node {theirs}'s (the longest name that starts it), not {node}'s");
                    Err(refused(&key, why))
                }
            }
        }
        "Blob" => {
            only(&key, &spec, &["size", "copies"])?;
            let (namespace, name) = (namespace(resource).to_string(), resource.metadata.name.clone());
            if !crate::blobs::named(&name) {
                return Err(refused(&key, "that is no name a blob can have"));
            }
            let wanted = |kind: &'static str| store.list(Some(kind)).filter(|of| self::namespace(of) == namespace);
            let mut volumes = wanted("Image").chain(wanted("Backup"));
            if !resource.metadata.annotations.contains_key(MADE_BY) || !volumes.any(|of| of_its_volume(store, of, node))
            {
                return Err(refused(
                    &key,
                    "no Image or Backup of that namespace is of a Volume on this node",
                ));
            }
            // The same bytes are one blob under one name everywhere: a Blob for a name a
            // worker has only heard of would be a way to be sent those bytes.
            let there = store.list(Some("Blob")).any(|blob| blob.metadata.name == name);
            if there || (who.held)(&name) {
                return Err(refused(&key, "a blob of that name is there already"));
            }
            resource.metadata.annotations.insert(MADE_ON.into(), node.into());
            Ok(())
        }
        _ => Err(refused(&key, "it is not a worker's to apply: ask a control node")),
    }
}

pub(crate) fn delete(store: &Store, who: &Worker, key: &str) -> Result<(), String> {
    let Some(live) = store.get(key) else { return Ok(()) };
    let discovered = live.metadata.labels.get(DISCOVERED).is_some_and(|made| made == "true");
    let made_here = live.metadata.annotations.get(MADE_ON).is_some_and(|on| on == who.name);
    match live.kind.as_str() {
        // (A Device or Seat an admin gave namespaces is kept while its hardware is gone: a worker does not delete it.)
        "Device" | "Seat" if live.metadata.labels.contains_key(crate::claims::NAMESPACES) => {
            Err(refused(key, "its kith.dev/namespaces label is an admin's: it is kept"))
        }
        "Device" | "Seat" if discovered && live.spec["node"] == who.name => Ok(()),
        "Blob" if made_here => Ok(()),
        _ => Err(refused(key, "it is not this node's to delete")),
    }
}

/// `command` as it is given to Raft for the worker `who`, or why none of it is.
pub fn checked(store: &Store, who: &Worker, command: Command) -> Result<Command, String> {
    match command {
        Command::Patch { statuses } => {
            statuses
                .iter()
                .try_for_each(|(key, fields)| patch(store, who, key, fields))?;
            Ok(Command::Patch { statuses })
        }
        Command::Status { statuses } => {
            statuses
                .iter()
                .try_for_each(|(key, said)| status(store, who, key, said.as_ref()))?;
            Ok(Command::Status { statuses })
        }
        Command::Report { node, statuses } if node == who.name => {
            let taken = statuses
                .into_iter()
                .map(|(key, said)| report(store, who, &key, said).map(|said| (key, said)));
            let statuses = taken.collect::<Result<_, _>>()?;
            Ok(Command::Report { node, statuses })
        }
        Command::Report { node, .. } => Err(refused(
            format!("a report in node {node}'s name"),
            "it is not this node",
        )),
        Command::Apply { mut resources, at } => {
            resources
                .iter_mut()
                .try_for_each(|resource| apply(store, who, resource))?;
            Ok(Command::Apply { resources, at })
        }
        Command::Delete { key } => delete(store, who, &key).map(|()| Command::Delete { key }),
        Command::Rollback { key, .. } => Err(refused(key, "a rollback is asked of a control node")),
        Command::Import { .. } => Err(refused("a whole store", "only a control node brings one in")),
        Command::Mark => Err(refused("the store's format", "only the leader changes it")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Control node `a`, workers `w` and `w-b`. A Workload with replica 0 on `w` and 1 on `a`,
    /// a Job on `a`, a Volume on `w` with an Image and a Backup of it, a Volume on `a` with a
    /// Backup, and a Volume with replicas whose primary is `a` and whose replica is `w`.
    const CLUSTER: &str = "\
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: w }
spec: { trust: worker }
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: w-b }
spec: { trust: worker }
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: web }
spec: { replicas: 2, template: { containers: [{ name: run, image: img }] } }
---
apiVersion: kith.dev/v1
kind: Job
metadata: { name: once }
spec: { template: { containers: [{ name: run, image: img }] } }
---
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: here }
spec: { node: w, path: here }
---
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: there }
spec: { node: a, path: there }
---
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: kept }
spec: { node: a, path: kept, replicas: 2 }
---
apiVersion: kith.dev/v1
kind: Image
metadata: { name: packed }
spec: { volume: here }
---
apiVersion: kith.dev/v1
kind: Backup
metadata: { name: nightly }
spec: { volume: here, every: 1d }
---
apiVersion: kith.dev/v1
kind: Backup
metadata: { name: theirs }
spec: { volume: there, every: 1d }
";

    const OTHERS: &str = "1111111111111111111111111111111111111111111111111111111111111a";
    const OWN: &str = "2222222222222222222222222222222222222222222222222222222222222b";

    fn store() -> Store {
        let mut store = Store::default();
        for resource in Resource::from_source(CLUSTER).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let mut set = |key: &str, status: Value| store.set_status(key, Some(status)).unwrap();
        set(
            "Node/a",
            json!({ "address": "10.0.0.1:7443", "raftId": "1", "mesh": { "key": "QUFB", "port": 51820 } }),
        );
        set(
            "Node/w",
            json!({ "address": "10.0.0.2:7443", "raftId": "2", "mesh": { "key": "V1dX", "port": 51820 } }),
        );
        set(
            "Workload/default/web",
            json!({ "nodes": { "0": "w", "1": "a" }, "replicas": 2 }),
        );
        set("Job/default/once", json!({ "nodes": { "0": "a" }, "state": "running" }));
        set(
            "Volume/default/kept",
            json!({ "primary": "a", "replicas": ["w"], "synced": { "w": 100 } }),
        );
        set(
            "Backup/default/theirs",
            json!({ "backups": [{ "at": 1, "size": 9, "blob": OTHERS }] }),
        );
        store
    }

    fn blob(namespace: &str, name: &str, on: Option<&str>) -> Resource {
        let mut annotations = json!({ MADE_BY: "backup" });
        if let Some(on) = on {
            annotations[MADE_ON] = on.into();
        }
        let blob = json!({
            "apiVersion": "kith.dev/v1", "kind": "Blob",
            "metadata": { "name": name, "namespace": namespace, "annotations": annotations },
            "spec": { "size": 9 },
        });
        serde_json::from_value(blob).unwrap()
    }

    fn try_as(store: &Store, name: &str, command: Command) -> Result<Command, String> {
        let nothing = |_: &str| false;
        let who = Worker {
            name,
            prefix: Some(kith_mesh::prefix(b"a cluster")),
            held: &nothing,
        };
        checked(store, &who, command)
    }

    fn patch_of(key: &str, fields: Value) -> Command {
        let Value::Object(fields) = fields else {
            panic!("an object")
        };
        Command::Patch {
            statuses: vec![(key.to_string(), fields)],
        }
    }

    #[test]
    fn a_worker_says_its_people_device_in_its_shape() {
        use base64::Engine as _;
        let store = store();
        let people = |said: Value| patch_of("Node/w", json!({ "people": said }));
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let device = |public: Value, port: Value, endpoint: Value| json!({ "publicKey": public, "port": port, "endpoint": endpoint });
        // Its device, with or without an endpoint; null when the device is taken away.
        for said in [
            device(json!(key), json!(51821), Value::Null),
            device(json!(key), json!(65535), json!("203.0.113.5:51821")),
            Value::Null,
        ] {
            assert!(try_as(&store, "w", people(said.clone())).is_ok(), "{said}");
        }
        // Outside its shape: a key that is not 32 bytes in base64, a port out of range or not a
        // number, an endpoint that is neither a string nor null, another field, a field missing.
        let short = base64::engine::general_purpose::STANDARD.encode([7u8; 31]);
        let outside = [
            device(json!(short), json!(51821), Value::Null),
            device(json!("not base64!"), json!(51821), Value::Null),
            device(json!(7), json!(51821), Value::Null),
            device(json!(key), json!(0), Value::Null),
            device(json!(key), json!(65536), Value::Null),
            device(json!(key), json!("51821"), Value::Null),
            device(json!(key), json!(51821), json!(5)),
            json!({ "publicKey": key, "port": 51821, "endpoint": null, "lan": "192.0.2.5" }),
            json!({ "publicKey": key, "port": 51821 }),
            json!("yes"),
        ];
        for said in outside {
            assert!(try_as(&store, "w", people(said.clone())).is_err(), "{said}");
        }
        // Another node's device.
        let theirs = patch_of(
            "Node/w",
            json!({ "people": device(json!(key), json!(51821), Value::Null) }),
        );
        assert!(try_as(&store, "w-b", theirs).is_err());
    }

    #[test]
    fn a_worker_says_what_its_levels_left_out_in_a_few_lines() {
        let store = store();
        let notes = |said: Value| patch_of("Node/w", json!({ "peopleNotes": said }));
        let long = "x".repeat(201);
        let many: Vec<String> = (0..17).map(|n| n.to_string()).collect();
        for said in [
            json!(["peer a: refused"]),
            json!([]),
            Value::Null,
            json!(["é".repeat(200)]),
        ] {
            assert!(try_as(&store, "w", notes(said.clone())).is_ok(), "{said}");
        }
        for said in [
            json!([long]),
            json!(many),
            json!("text"),
            json!([1]),
            json!({ "a": "b" }),
        ] {
            assert!(try_as(&store, "w", notes(said.clone())).is_err(), "{said}");
        }
        assert!(try_as(&store, "w-b", notes(json!(["x"]))).is_err(), "another node's");
    }

    #[test]
    fn the_barrier_and_what_a_node_says_of_itself_pass() {
        let store = store();
        assert!(try_as(&store, "w", Command::Patch { statuses: Vec::new() }).is_ok());
        assert!(try_as(&store, "w", patch_of("Node/w", json!({ "os": { "version": "1.0.1" } }))).is_ok());
        let mesh = json!({ "mesh": { "key": "TkVX", "port": 51820, "reaches": ["a"] } });
        assert!(try_as(&store, "w", patch_of("Node/w", mesh)).is_ok());
    }

    #[test]
    fn another_nodes_status_and_the_fields_a_join_wrote_are_refused() {
        let store = store();
        // The same write in another node's name.
        let os = json!({ "os": { "version": "1.0.1" } });
        assert!(try_as(&store, "w", patch_of("Node/a", os.clone())).is_err());
        assert!(try_as(&store, "w-b", patch_of("Node/w", os)).is_err());
        // Which key stands for it, where it is, that it holds the CA key, that it is there.
        for forged in ["certificate", "address", "raftId", "ca", "state"] {
            let said = try_as(&store, "w", patch_of("Node/w", json!({ forged: "x" })));
            assert!(said.unwrap_err().contains(forged), "{forged}");
        }
        // Another node's mesh key: both would be left out of the mesh.
        let copied = json!({ "mesh": { "key": "QUFB", "port": 51820 } });
        assert!(
            try_as(&store, "w", patch_of("Node/w", copied))
                .unwrap_err()
                .contains("node a's")
        );
        // Nothing of a spec: a worker cannot make itself a control node.
        let node: Resource = serde_json::from_value(json!({
            "apiVersion": "kith.dev/v1", "kind": "Node", "metadata": { "name": "w" }, "spec": {},
        }))
        .unwrap();
        let apply = Command::Apply {
            resources: vec![node],
            at: 0,
        };
        assert!(try_as(&store, "w", apply).is_err());
        assert!(try_as(&store, "w", Command::Delete { key: "Node/a".into() }).is_err());
        let rollback = Command::Rollback {
            key: "Workload/default/web".into(),
            to: 1,
            at: 0,
        };
        assert!(try_as(&store, "w", rollback).is_err());
        assert!(
            try_as(
                &store,
                "w",
                Command::Import {
                    store: Store::default()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn a_worker_says_what_it_serves_of_its_own_node_in_its_shape() {
        let mut store = store();
        let serves = |fields: Value| patch_of("Node/w", json!({ "serves": fields }));
        // What it serves on its own Node, and null to take it off.
        let fine = [
            json!({ "dns": 53 }),
            json!({ "dns": 65535, "ingress": true }),
            json!({ "ingress": true }),
            Value::Null,
        ];
        for said in fine {
            assert!(try_as(&store, "w", serves(said.clone())).is_ok(), "{said}");
        }
        // Outside its shape: a port out of range or not a number, ingress that is not true, another key.
        let outside = [
            json!({ "dns": 0 }),
            json!({ "dns": 65536 }),
            json!({ "dns": "53" }),
            json!({ "ingress": false }),
            json!({ "dns": 53, "lan": "192.0.2.5" }),
            json!("yes"),
        ];
        for said in outside {
            assert!(try_as(&store, "w", serves(said.clone())).is_err(), "{said}");
        }
        // Another node's serves.
        let theirs = patch_of("Node/w", json!({ "serves": { "dns": 53 } }));
        assert!(try_as(&store, "w-b", theirs).is_err());
        // Its own policy, as a node says it; nothing else under that name, and not another node's.
        let policy = |said: Value| patch_of("Node/w", json!({ "policy": said }));
        for said in [
            json!({ "run": false, "vms": true, "devices": ["gpu"] }),
            json!({ "run": false, "capabilities": ["CHOWN", "SYS_ADMIN"] }),
            Value::Null,
        ] {
            assert!(try_as(&store, "w", policy(said.clone())).is_ok(), "{said}");
        }
        for said in [
            json!({ "run": "no" }),
            json!({ "devices": [1] }),
            json!({ "devices": vec!["gpu"; 9] }),
            json!({ "capabilities": [1] }),
            json!({ "other": ["gpu"] }),
            json!("hardened"),
        ] {
            assert!(try_as(&store, "w", policy(said.clone())).is_err(), "{said}");
        }
        assert!(try_as(&store, "w-b", policy(json!({ "run": false }))).is_err());
        // A viewed worker: the control node that let it join to view did not let it serve ingress.
        store
            .set_status(
                "Node/w-b",
                Some(json!({ "address": "192.0.2.9:7443", "raftId": "3", "view": true })),
            )
            .unwrap();
        let ingress = patch_of("Node/w-b", json!({ "serves": { "ingress": true } }));
        assert!(try_as(&store, "w-b", ingress.clone()).unwrap_err().contains("ingress"));
        let dns = patch_of("Node/w-b", json!({ "serves": { "dns": 53 } }));
        assert!(try_as(&store, "w-b", dns).is_ok());
        // Unless it joined with a token for an ingress worker: its Node says so.
        ingress_worker(&mut store, "w-b");
        assert!(try_as(&store, "w-b", ingress).is_ok());
        // `view` is a control node's to write, as its address is.
        let view = patch_of("Node/w", json!({ "view": true }));
        assert!(try_as(&store, "w", view).unwrap_err().contains("view"));
        // The store's format is the leader's to change.
        assert!(
            try_as(&store, "w", Command::Mark)
                .unwrap_err()
                .contains("only the leader")
        );
        // The ACME account's thumbprint its view holds (the leader orders once each ingress
        // worker says it has it): a thumbprint's shape, or null; on its own Node only.
        let print = |said: Value| patch_of("Node/w", json!({ "thumbprint": said }));
        let thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
        assert!(try_as(&store, "w", print(thumbprint.into())).is_ok());
        assert!(try_as(&store, "w", print(Value::Null)).is_ok());
        for said in [
            json!(7),
            json!("a b"),
            json!("a.b"),
            json!(""),
            json!("x".repeat(65)),
            json!({}),
        ] {
            assert!(try_as(&store, "w", print(said.clone())).is_err(), "{said}");
        }
        assert!(try_as(&store, "w-b", print(thumbprint.into())).is_err());
    }

    /// Make `node` a worker that joined to serve ingress from a view, as its join writes it.
    fn ingress_worker(store: &mut Store, node: &str) {
        let mut live = store.get(&format!("Node/{node}")).unwrap().clone();
        live.spec["ingress"] = true.into();
        store.put(live);
    }

    fn resource(of: Value) -> Resource {
        serde_json::from_value(of).unwrap()
    }

    /// Every write the ingress loop makes (`crate::ingress`): an ACME account key, a host's
    /// certificate, the thumbprint a worker answers challenges with, and a Service's `tls` status.
    /// Each is a control node's: a worker, even one that serves ingress, makes none of them. It
    /// says of its own Node that it serves ingress, and that alone.
    #[test]
    fn ingress_writes_are_a_control_nodes_and_an_ingress_worker_says_only_that_it_serves() {
        let mut store = store();
        let service = resource(json!({
            "apiVersion": "kith.dev/v1", "kind": "Service", "metadata": { "name": "web" },
            "spec": { "selector": { "app": "web" }, "ports": [{ "port": 80 }], "expose": { "host": "web.example.test", "via": "edge" } },
        }));
        store.apply(service).unwrap();
        ingress_worker(&mut store, "w");
        store
            .set_status(
                "Node/w",
                Some(json!({ "address": "10.0.0.2:7443", "raftId": "2", "view": true })),
            )
            .unwrap();
        let secret = |name: &str, namespace: &str, data: Value| {
            resource(json!({
                "apiVersion": "kith.dev/v1", "kind": "Secret",
                "metadata": { "name": name, "namespace": namespace }, "spec": { "data": data },
            }))
        };
        // A certificate already ordered, which the control node renews or replaces.
        let ordered = secret(
            "tls-web.example.test",
            "default",
            json!({ "tls.crt": "c", "tls.key": "k" }),
        );
        store.apply(ordered).unwrap();
        let apply = |resource: Resource| Command::Apply {
            resources: vec![resource],
            at: 0,
        };
        let writes = [
            (
                "the ACME account key",
                apply(secret("acme-account", "kith-system", json!({ "key": "k" }))),
            ),
            (
                "a host's certificate",
                apply(secret(
                    "tls-web.example.test",
                    "default",
                    json!({ "tls.crt": "c", "tls.key": "k" }),
                )),
            ),
            (
                "the thumbprint",
                apply(resource(json!({
                    "apiVersion": "kith.dev/v1", "kind": "ConfigMap",
                    "metadata": { "name": "acme", "namespace": "kith-system" }, "spec": { "data": { "thumbprint": "t" } },
                }))),
            ),
            (
                "a Service's tls status",
                patch_of(
                    "Service/default/web",
                    json!({ "tls": { "state": "ordering", "by": "w" } }),
                ),
            ),
            (
                "a certificate's deletion",
                Command::Delete {
                    key: "Secret/default/tls-web.example.test".into(),
                },
            ),
        ];
        for (what, write) in writes {
            assert!(
                try_as(&store, "w", write).is_err(),
                "{what} is a control node's to write"
            );
        }
        // What it serves, on its own Node; not on another worker's that joined without ingress.
        let serves = |node: &str| patch_of(&format!("Node/{node}"), json!({ "serves": { "ingress": true } }));
        assert!(try_as(&store, "w", serves("w")).is_ok());
        store
            .set_status("Node/w-b", Some(json!({ "address": "10.0.0.3:7443", "view": true })))
            .unwrap();
        assert!(try_as(&store, "w-b", serves("w-b")).is_err());
        assert!(try_as(&store, "w", serves("w-b")).is_err());
        // And the one write the ingress loop makes on a worker: the thumbprint its view holds,
        // on its own Node (the leader orders once each ingress worker has it), on no other.
        let holds = |node: &str| patch_of(&format!("Node/{node}"), json!({ "thumbprint": "t" }));
        assert!(try_as(&store, "w", holds("w")).is_ok());
        assert!(try_as(&store, "w", holds("w-b")).is_err());
    }

    fn unit(replica: u64, more: Value) -> Value {
        let mut unit = json!({ "name": "run", "replica": replica, "state": "running", "ready": true });
        unit.as_object_mut().unwrap().extend(more.as_object().cloned().unwrap());
        unit
    }

    fn report_of(node: &str, key: &str, said: Value) -> Command {
        Command::Report {
            node: node.into(),
            statuses: vec![(key.to_string(), Some(said))],
        }
    }

    fn reported(command: Command) -> Option<Value> {
        let Command::Report { mut statuses, .. } = command else {
            panic!("a report")
        };
        statuses.pop().unwrap().1
    }

    #[test]
    fn a_report_is_taken_for_the_replicas_the_node_was_given() {
        let store = store();
        // One replica saying it is both: only its own is taken, and the replicas stay 2.
        let said = json!({ "replicas": 9, "containers": [unit(0, json!({})), unit(1, json!({}))] });
        let taken = reported(try_as(&store, "w", report_of("w", "Workload/default/web", said)).unwrap()).unwrap();
        assert_eq!(taken["containers"].as_array().unwrap().len(), 1);
        assert_eq!(
            (&taken["containers"][0]["replica"], &taken["replicas"]),
            (&json!(0), &json!(2))
        );
        // In another node's name.
        let said = json!({ "containers": [unit(1, json!({}))] });
        assert!(try_as(&store, "w", report_of("a", "Workload/default/web", said.clone())).is_err());
        // By a worker nothing of it is on: all that is taken is that it runs none.
        assert_eq!(
            reported(try_as(&store, "w-b", report_of("w-b", "Workload/default/web", said)).unwrap()),
            None
        );
        // A Job on another node: its state is not this node's to say.
        let over = json!({ "state": "succeeded", "succeeded": 1, "failed": 0, "containers": [] });
        assert_eq!(
            reported(try_as(&store, "w", report_of("w", "Job/default/once", over)).unwrap()),
            None
        );
        // A field no report has, and a resource that runs nothing.
        let more = json!({ "containers": [], "nodes": { "1": "w" } });
        assert!(try_as(&store, "w", report_of("w", "Workload/default/web", more)).is_err());
        assert!(
            try_as(
                &store,
                "w",
                report_of("w", "Volume/default/here", json!({ "containers": [] }))
            )
            .is_err()
        );
        // A NodeWorkload's copies are numbered by the scheduler: its own number, not another's.
        let every: Resource = serde_json::from_value(json!({
            "apiVersion": "kith.dev/v1", "kind": "NodeWorkload", "metadata": { "name": "every" },
            "spec": { "template": { "containers": [{ "name": "run", "image": "img" }] } },
        }))
        .unwrap();
        let mut store = store;
        store.apply(every).unwrap();
        store
            .set_status(
                "NodeWorkload/default/every",
                Some(json!({ "nodes": { "0": "a", "3": "w" } })),
            )
            .unwrap();
        let said = json!({ "containers": [unit(0, json!({})), unit(3, json!({}))] });
        let taken = reported(try_as(&store, "w", report_of("w", "NodeWorkload/default/every", said)).unwrap()).unwrap();
        assert_eq!(taken["containers"], json!([unit(3, json!({}))]));
        // A Workload that says a `state` would have its ready replicas counted by no one.
        let stated = json!({ "state": "succeeded", "containers": [unit(0, json!({}))] });
        assert!(try_as(&store, "w", report_of("w", "Workload/default/web", stated)).is_err());
        // A unit that says which node runs it, or anything else a unit does not say today.
        let elsewhere = json!({ "containers": [unit(0, json!({ "node": "a" }))] });
        assert!(try_as(&store, "w", report_of("w", "Workload/default/web", elsewhere)).is_err());
    }

    /// Whether a unit keeps the node's users (`hostUsers`, where kithd is root) is the node's to say.
    #[test]
    fn a_unit_says_whether_it_keeps_the_nodes_users() {
        let store = store();
        let said = json!({ "containers": [unit(0, json!({ "hostUsers": false }))] });
        let taken = reported(try_as(&store, "w", report_of("w", "Workload/default/web", said)).unwrap()).unwrap();
        assert_eq!(taken["containers"], json!([unit(0, json!({ "hostUsers": false }))]));
    }

    #[test]
    fn a_blobs_bytes_go_to_a_worker_only_where_something_on_it_names_them() {
        let mut store = store();
        let image = json!({ "digest": "sha256:0", "blobs": { "0": OWN } });
        store.set_status("Image/default/packed", Some(image)).unwrap();
        // The Image of a Volume that is on it; the backup of one that is not.
        assert!(may_fetch(&store, "w", OWN));
        assert!(!may_fetch(&store, "w", OTHERS));
        assert!(!may_fetch(&store, "w-b", OWN));
        // Run by a template placed on it: by that worker, and by no other.
        let runs: Resource = serde_json::from_value(json!({
            "apiVersion": "kith.dev/v1", "kind": "Workload", "metadata": { "name": "runs" },
            "spec": { "template": { "containers": [{ "name": "run", "image": "localhost:5000/default/packed:1" }] } },
        }))
        .unwrap();
        store.apply(runs).unwrap();
        assert!(!may_fetch(&store, "w-b", OWN));
        store
            .set_status("Workload/default/runs", Some(json!({ "nodes": { "0": "w-b" } })))
            .unwrap();
        assert!(may_fetch(&store, "w-b", OWN));
        // A name it has only heard: no status names it.
        assert!(!may_fetch(&store, "w", &"3".repeat(62)));
        for (image, named) in [
            ("localhost:5000/default/packed", true),
            ("127.0.0.1:5000/default/packed@sha256:00", true),
            ("localhost:5000/default/packed:1", true),
            ("localhost:5000/other/packed:1", false),
            ("localhost:5000/default/packed-more:1", false),
            ("registry.example:5000/default/packed:1", false),
            ("default/packed", false),
        ] {
            assert_eq!(names_image(image, "default/packed"), named, "{image}");
        }
    }

    #[test]
    fn a_units_address_is_in_its_nodes_part_of_the_mesh() {
        let store = store();
        let prefix = kith_mesh::prefix(b"a cluster");
        let mut own = kith_mesh::node_net(prefix, "w").segments();
        own[7] = 5;
        let own = Ipv6Addr::from(own).to_string();
        let said = |address: &str| json!({ "containers": [unit(0, json!({ "address": address }))] });
        assert!(try_as(&store, "w", report_of("w", "Workload/default/web", said(&own))).is_ok());
        let others = kith_mesh::node_address(prefix, "a").to_string();
        for forged in [others.as_str(), "::1", "10.0.0.1", "not an address"] {
            let refused = try_as(&store, "w", report_of("w", "Workload/default/web", said(forged)));
            assert!(refused.is_err(), "{forged}");
        }
    }

    #[test]
    fn a_namespaces_label_is_an_admins_and_a_worker_keeps_the_one_it_has() {
        let mut store = store();
        let device = |name: &str, namespaces: Option<&str>| -> Resource {
            let mut labels = json!({ DISCOVERED: "true", "kith.dev/node": "w" });
            if let Some(namespaces) = namespaces {
                labels["kith.dev/namespaces"] = namespaces.into();
            }
            serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": "Device",
                "metadata": { "name": name, "labels": labels },
                "spec": { "node": "w", "class": "gpu", "path": "/dev/dri/card0" },
            }))
            .unwrap()
        };
        let seat = |name: &str, namespaces: Option<&str>| -> Resource {
            let mut labels = json!({ DISCOVERED: "true", "kith.dev/node": "w" });
            if let Some(namespaces) = namespaces {
                labels["kith.dev/namespaces"] = namespaces.into();
            }
            serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": "Seat",
                "metadata": { "name": name, "labels": labels },
                "spec": { "node": "w", "devices": ["w-gpu-card0"] },
            }))
            .unwrap()
        };
        let apply = |resource: Resource| Command::Apply {
            resources: vec![resource],
            at: 0,
        };
        // An admin gave the GPU and the Seat the label: the store holds it.
        store.apply(device("w-gpu-card0", Some("ops"))).unwrap();
        store.apply(seat("w-seat0", Some("ops"))).unwrap();
        // This node's discovery writes them back with the label they have: kept.
        assert!(try_as(&store, "w", apply(device("w-gpu-card0", Some("ops")))).is_ok());
        assert!(try_as(&store, "w", apply(seat("w-seat0", Some("ops")))).is_ok());
        // Changed, or taken away, by the worker: refused.
        assert!(try_as(&store, "w", apply(device("w-gpu-card0", Some("dev")))).is_err());
        assert!(try_as(&store, "w", apply(device("w-gpu-card0", None))).is_err());
        assert!(try_as(&store, "w", apply(seat("w-seat0", None))).is_err());
        // Added by the worker, to a Device or Seat that has none: refused, too.
        assert!(try_as(&store, "w", apply(device("w-gpu-card1", Some("ops")))).is_err());
        assert!(try_as(&store, "w", apply(seat("w-seat1", Some("ops")))).is_err());
        // Without the label, a worker's own Device is as it was.
        assert!(try_as(&store, "w", apply(device("w-gpu-card1", None))).is_ok());
    }

    /// A worker deletes none of its Devices that carry the label, and changes the class of none
    /// of its live Devices: what an admin gave a Device, and what a claim's selector reads, is kept.
    #[test]
    fn a_worker_neither_deletes_a_labelled_device_nor_changes_a_live_devices_class() {
        let mut store = store();
        let device = |name: &str, class: &str, labelled: bool| -> Resource {
            let mut labels = json!({ DISCOVERED: "true", "kith.dev/node": "w", "class": class });
            if labelled {
                labels["kith.dev/namespaces"] = "ops".into();
            }
            serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": "Device",
                "metadata": { "name": name, "labels": labels },
                "spec": { "node": "w", "class": class, "path": "/dev/dri/card0" },
            }))
            .unwrap()
        };
        let apply = |resource: Resource| Command::Apply {
            resources: vec![resource],
            at: 0,
        };
        let delete = |key: &str| Command::Delete { key: key.into() };
        store.apply(device("w-gpu-card0", "gpu", true)).unwrap();
        store.apply(device("w-gpu-card1", "gpu", false)).unwrap();
        // Its labelled Device is not the worker's to delete; its unlabelled one is.
        assert!(try_as(&store, "w", delete("Device/w-gpu-card0")).is_err());
        assert!(try_as(&store, "w", delete("Device/w-gpu-card1")).is_ok());
        // A live Device keeps its class, whatever its label says (the two are written together).
        assert!(try_as(&store, "w", apply(device("w-gpu-card1", "display", false))).is_err());
        assert!(try_as(&store, "w", apply(device("w-gpu-card0", "display", true))).is_err());
        assert!(try_as(&store, "w", apply(device("w-gpu-card1", "gpu", false))).is_ok());
        // A Device the store does not have yet may be of any class its node finds.
        assert!(try_as(&store, "w", apply(device("w-gpu-card2", "display", false))).is_ok());
    }

    #[test]
    fn devices_and_seats_are_held_to_their_node_not_their_name() {
        let mut store = store();
        let device = |name: &str, node: &str| -> Resource {
            serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": "Device",
                "metadata": { "name": name, "labels": { DISCOVERED: "true", "kith.dev/node": node } },
                "spec": { "node": node, "class": "gpu", "path": "/dev/dri/card0" },
            }))
            .unwrap()
        };
        let apply = |device: Resource| Command::Apply {
            resources: vec![device],
            at: 0,
        };
        assert!(try_as(&store, "w", apply(device("w-gpu-card0", "w"))).is_ok());
        // Another node's name in the spec, whatever the Device is called.
        assert!(try_as(&store, "w", apply(device("w-gpu-card0", "w-b"))).is_err());
        // Over another node's Device: `w` is the start of `w-b`'s name.
        store.apply(device("w-b-gpu-card0", "w-b")).unwrap();
        assert!(try_as(&store, "w", apply(device("w-b-gpu-card0", "w"))).is_err());
        // Under a name another node's discovery would give: node `a` would then leave its own out.
        assert!(try_as(&store, "w", apply(device("a-gpu-card0", "w"))).is_err());
        // With a label discovery does not write, or one that says another node or class: a
        // claim's selector would then come to this node's Device beside the one it was for.
        let labelled = |label: &str, value: &str| {
            let mut device = device("w-gpu-card1", "w");
            device.metadata.labels.insert(label.into(), value.into());
            apply(device)
        };
        assert!(try_as(&store, "w", labelled("vram", "17163091968")).is_ok());
        assert!(try_as(&store, "w", labelled("class", "gpu")).is_ok());
        assert!(try_as(&store, "w", labelled("room", "office")).is_err());
        assert!(try_as(&store, "w", labelled("kith.dev/node", "a")).is_err());
        assert!(try_as(&store, "w", labelled("class", "display")).is_err());
        let seat = |name: &str| -> Resource {
            serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": "Seat",
                "metadata": { "name": name, "labels": { DISCOVERED: "true", "kith.dev/node": "w" } },
                "spec": { "node": "w", "devices": ["w-gpu-card0"] },
            }))
            .unwrap()
        };
        assert!(try_as(&store, "w", apply(seat("w-seat0"))).is_ok());
        assert!(try_as(&store, "w", apply(seat("a-seat0"))).is_err());
        // (A node whose name is long has its Devices' names cut: they start as its name does.)
        let long = "n".repeat(60);
        let cut = format!("{long}-gp");
        store.apply(serde_json::from_value(json!({
            "apiVersion": "kith.dev/v1", "kind": "Node", "metadata": { "name": long }, "spec": { "trust": "worker" },
        })).unwrap()).unwrap();
        assert!(try_as(&store, &long, apply(device(&cut, &long))).is_ok());
        assert!(
            try_as(
                &store,
                "w",
                Command::Delete {
                    key: "Device/w-b-gpu-card0".into()
                }
            )
            .is_err()
        );
        assert!(
            try_as(
                &store,
                "w-b",
                Command::Delete {
                    key: "Device/w-b-gpu-card0".into()
                }
            )
            .is_ok()
        );
    }

    /// A discovered name is the node's with the longest name that starts it: `w` cannot make
    /// `w-b`'s Device or Seat before `w-b` does (it would then skip its own).
    #[test]
    fn longest_name_has_a_discovered_name_and_a_shorter_one_is_refused() {
        let mut store = store();
        let node = |name: &str| -> Resource {
            serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": "Node", "metadata": { "name": name }, "spec": { "trust": "worker" },
            }))
            .unwrap()
        };
        let made = |kind: &str, name: &str, by: &str| -> Command {
            let spec = match kind {
                "Seat" => json!({ "node": by, "devices": [] }),
                _ => json!({ "node": by, "class": "gpu", "path": "/dev/dri/card0" }),
            };
            let resource = json!({
                "apiVersion": "kith.dev/v1", "kind": kind,
                "metadata": { "name": name, "labels": { DISCOVERED: "true", "kith.dev/node": by } },
                "spec": spec,
            });
            Command::Apply {
                resources: vec![serde_json::from_value(resource).unwrap()],
                at: 0,
            }
        };
        let (long_a, long_b) = (format!("{}aaa", "n".repeat(57)), format!("{}bbb", "n".repeat(57)));
        for name in ["w-b", "w-b-x", "w-b-x-y", &long_a, &long_b] {
            store.apply(node(name)).unwrap();
        }
        // Its own, as before.
        assert!(try_as(&store, "w", made("Device", "w-gpu-card0", "w")).is_ok());
        assert!(try_as(&store, "w-b", made("Device", "w-b-gpu-card0", "w-b")).is_ok());
        // Another node's, though it starts as this node's do: refused, naming both.
        for (kind, name) in [("Device", "w-b-gpu-card0"), ("Seat", "w-b-seat0")] {
            let why = try_as(&store, "w", made(kind, name, "w")).unwrap_err();
            assert!(why.contains("w-b") && why.contains("longest name"), "{why}");
        }
        assert!(try_as(&store, "w-b-x", made("Device", "w-b-x-y-gpu-card0", "w-b-x")).is_err());
        assert!(try_as(&store, "w-b-x-y", made("Device", "w-b-x-y-gpu-card0", "w-b-x-y")).is_ok());
        assert!(try_as(&store, "w-b", made("Seat", "w-b-x-seat0", "w-b")).is_err());
        // Two long names cut to one stem: the name is both's (the first to make it keeps it).
        let seat = format!("{}-seat0", "n".repeat(57));
        assert!(try_as(&store, &long_a, made("Seat", &seat, &long_a)).is_ok());
        assert!(try_as(&store, &long_b, made("Seat", &seat, &long_b)).is_ok());
        // (Not where the whole of one's name starts it.)
        let cut = format!("{long_a}-gp");
        assert!(try_as(&store, &long_a, made("Device", &cut, &long_a)).is_ok());
        assert!(try_as(&store, &long_b, made("Device", &cut, &long_b)).is_err());
    }

    #[test]
    fn a_blob_is_one_the_worker_made_and_no_one_elses() {
        let mut store = store();
        store.apply(blob("default", OTHERS, None)).unwrap();
        let apply = |blob: Resource| Command::Apply {
            resources: vec![blob],
            at: 0,
        };
        // A new one, for a backup of its own Volume: the control node writes whose it is.
        let Command::Apply { resources, .. } = try_as(&store, "w", apply(blob("default", OWN, Some("a")))).unwrap()
        else {
            panic!("an apply")
        };
        assert_eq!(resources[0].metadata.annotations[MADE_ON], "w");
        // For a name a Blob has already, here or in any namespace; where it has no Volume.
        assert!(try_as(&store, "w", apply(blob("default", OTHERS, None))).is_err());
        assert!(try_as(&store, "w", apply(blob("other", OTHERS, None))).is_err());
        assert!(try_as(&store, "w-b", apply(blob("default", OWN, None))).is_err());
        // For a name the node that is asked still has a file of.
        let lingers = |name: &str| name == OWN;
        let who = Worker {
            name: "w",
            prefix: None,
            held: &lingers,
        };
        assert!(checked(&store, &who, apply(blob("default", OWN, None))).is_err());
        // Naming a Blob in its Backup's status: its own, not one it has heard of.
        store.apply(blob("default", OWN, Some("w"))).unwrap();
        let names =
            |blob: &str| json!({ "backups": [{ "at": 2, "size": 9, "blob": blob }], "message": null, "tried": null });
        assert!(try_as(&store, "w", patch_of("Backup/default/nightly", names(OWN))).is_ok());
        assert!(try_as(&store, "w", patch_of("Backup/default/nightly", names(OTHERS))).is_err());
        let image = json!({ "digest": "sha256:0", "size": 9, "blobs": { "0": OTHERS }, "of": "x", "message": null, "tried": null });
        assert!(try_as(&store, "w", patch_of("Image/default/packed", image)).is_err());
        // (That it failed is said on it all the same, so it is tried again later and not each round.)
        let failed = json!({ "message": "the blob is not one this node made", "tried": 9 });
        assert!(try_as(&store, "w", patch_of("Image/default/packed", failed)).is_ok());
        // The Backup of a Volume that is on another node.
        assert!(try_as(&store, "w", patch_of("Backup/default/theirs", names(OWN))).is_err());
        // Deleting: only one it made.
        assert!(
            try_as(
                &store,
                "w",
                Command::Delete {
                    key: format!("Blob/default/{OWN}")
                }
            )
            .is_ok()
        );
        assert!(
            try_as(
                &store,
                "w",
                Command::Delete {
                    key: format!("Blob/default/{OTHERS}")
                }
            )
            .is_err()
        );
        assert!(
            try_as(
                &store,
                "w-b",
                Command::Delete {
                    key: format!("Blob/default/{OWN}")
                }
            )
            .is_err()
        );
    }

    #[test]
    fn who_holds_a_blob_and_when_a_replica_synced_is_each_nodes_own_word() {
        let mut store = store();
        store.apply(blob("default", OTHERS, None)).unwrap();
        let key = format!("Blob/default/{OTHERS}");
        store.set_status(&key, Some(json!({ "nodes": ["a"] }))).unwrap();
        assert!(try_as(&store, "w", patch_of(&key, json!({ "nodes": ["a", "w"] }))).is_ok());
        // Taking a control node's name out (it would be fetched again), or putting one in
        // (a node that should hold it would be believed to).
        assert!(try_as(&store, "w", patch_of(&key, json!({ "nodes": ["w"] }))).is_err());
        assert!(try_as(&store, "w", patch_of(&key, json!({ "nodes": ["a", "w", "w-b"] }))).is_err());
        assert!(try_as(&store, "w", patch_of(&key, json!({ "nodes": ["a"], "size": 1 }))).is_err());
        // Its own time as a replica; not another's, and not of a Volume it is no replica of.
        let kept = "Volume/default/kept";
        assert!(try_as(&store, "w", patch_of(kept, json!({ "synced": { "w": 200 } }))).is_ok());
        assert!(try_as(&store, "w", patch_of(kept, json!({ "synced": { "w": 200, "a": 900 } }))).is_err());
        assert!(try_as(&store, "w", patch_of(kept, json!({ "primary": "w" }))).is_err());
        assert!(
            try_as(
                &store,
                "w-b",
                patch_of(kept, json!({ "synced": { "w": 100, "w-b": 200 } }))
            )
            .is_err()
        );
    }

    #[test]
    fn a_node_key_is_given_once_and_its_lock_is_not_the_nodes_to_lift() {
        let mut store = store();
        let key = |name: &str, spec: Value| -> Resource {
            serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": "NodeKey", "metadata": { "name": name }, "spec": spec,
            }))
            .unwrap()
        };
        let apply = |key: Resource| Command::Apply {
            resources: vec![key],
            at: 0,
        };
        let held = json!({ "id": "00", "wrapped": "11" });
        assert!(try_as(&store, "w", apply(key("w", held.clone()))).is_ok());
        assert!(try_as(&store, "w", apply(key("a", held.clone()))).is_err());
        // Locked by its owner: the node cannot put a key that is not locked in its place.
        let mut locked = held.clone();
        locked["locked"] = true.into();
        store.apply(key("w", locked)).unwrap();
        assert!(try_as(&store, "w", apply(key("w", held))).is_err());
        let sealed = Command::Status {
            statuses: vec![("NodeKey/w".into(), Some(json!({ "sealed": true })))],
        };
        assert!(try_as(&store, "w", sealed.clone()).is_ok());
        assert!(try_as(&store, "w-b", sealed).is_err());
    }
}
