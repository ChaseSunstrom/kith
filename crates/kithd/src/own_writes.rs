//! What a control node may write as itself (`raft.rs` `write`, a write that names no caller):
//! its own Node's status, its units' status, the Devices, Blobs, NodeKey and Volume syncs it
//! holds. (A Cluster's `status.home` is the leader's, written locally, never through here.)
//! Default-deny: a kind that is not in [`CLASSES`] is refused, and a refusal is audited
//! by the node's name and said on the console (`refused a control node's own write`).

use crate::access_sign::Asked;
use crate::worker::{self, Worker};
use base64::Engine;
use kith_api::Resource;
use kith_api::store::Store;
use kith_store::Command;
use serde_json::{Map, Value};
use std::net::Ipv6Addr;

/// Every kind kith knows, and whether a control node may write one of its own as itself. A kind
/// marked no is refused whatever it names; one marked yes is still checked field by field.
pub const CLASSES: &[(&str, bool)] = &[
    ("Cluster", false),
    ("Node", true),
    ("Namespace", false),
    ("Workload", true),
    ("NodeWorkload", true),
    ("Job", true),
    ("CronJob", false),
    ("Service", false),
    ("DNSZone", false),
    ("DNSBlockList", false),
    ("DNSRecord", false),
    ("NetworkPolicy", false),
    ("Exit", false),
    ("AccessLevel", false),
    ("RemotePeer", false),
    ("Volume", true),
    ("VolumeClaim", false),
    ("Blob", true),
    ("Backup", true),
    ("Image", true),
    ("Share", false),
    ("Secret", false),
    ("ConfigMap", false),
    ("Seat", true),
    ("Device", true),
    ("DeviceClaim", false),
    ("Package", false),
    ("Release", false),
    ("Repository", false),
    ("Source", false),
    ("OSRelease", false),
    ("UpdatePlan", false),
    ("NodeKey", true),
    ("KindDefinition", false),
    ("Role", false),
    ("RoleBinding", false),
    ("Identity", false),
    ("KubeObject", false),
];

type Fields = Map<String, Value>;

fn refused(what: impl std::fmt::Display, why: impl std::fmt::Display) -> String {
    format!("{what}: {why}: a control node writes as itself only what it holds")
}

/// Is `kind` one a control node may write as itself? Unknown kinds are not.
fn class(kind: &str) -> Result<(), String> {
    match CLASSES.iter().find(|(known, _)| *known == kind) {
        Some((_, true)) => Ok(()),
        _ => Err(refused(kind, "a control node does not write this kind as itself")),
    }
}

/// The kind of a store key (`Kind/namespace/name`, or `Kind/name`).
fn kind_of(key: &str) -> &str {
    key.split('/').next().unwrap_or(key)
}

/// A control node's own Node: any status field, its raft id only as its name gives it (the boot
/// writes that id again, and a follower forwards the write to the leader, which would otherwise
/// hold it as the node's own write), and no mesh key another node holds (as a worker's may not).
fn own_node(store: &Store, name: &str, key: &str, fields: &Fields) -> Result<(), String> {
    raft_id(name, key, fields)?;
    // Which node holds the CA ([`holds_ca`]) is what the CA node's first start wrote, as the one
    // node, leading: said again the same, never changed by a node of itself.
    if let Some(said) = fields.get("ca") {
        let held = store
            .get(key)
            .and_then(|node| node.status.as_ref())
            .map(|status| &status["ca"]);
        if held != Some(said) {
            return Err(refused(key, "which node holds the CA is not a node's own to say"));
        }
    }
    worker::mesh_key_elsewhere(store, name, key, fields)
}

/// A Node's raft id, if it says one, is the one its name gives (`kith_store::node_id`).
fn raft_id(name: &str, key: &str, fields: &Fields) -> Result<(), String> {
    let id = kith_store::node_id(name).to_string();
    match fields.get("raftId") {
        Some(said) if said.as_str() != Some(id.as_str()) => Err(refused(key, "the raft id is the one its name gives")),
        _ => Ok(()),
    }
}

/// Whether `who` holds the CA: its own Node's status says so (`ca`, which the node that makes
/// the CA writes at its start, `main.rs`). The store records which node that is.
fn holds_ca(store: &Store, who: &Worker) -> bool {
    let status = store
        .get(&format!("Node/{}", who.name))
        .and_then(|node| node.status.as_ref());
    status.is_some_and(|status| status["ca"] == true)
}

/// A Node the CA-holding control node `who` admits by its join (`cluster.rs` `join`): a new name,
/// with the spec the join gives it and no other field. Admitting a node by a signed write is
/// layer 3's (`docs/adr-taken-node.md`, "What stays open").
fn admits(store: &Store, who: &Worker, resource: &Resource) -> bool {
    let spec = resource.spec.as_object().is_some_and(|spec| {
        spec.iter().all(|(field, value)| match field.as_str() {
            "roaming" | "ingress" => value.as_bool() == Some(true),
            "trust" => value.as_str() == Some("worker"),
            _ => false,
        })
    });
    let new = store.get(&format!("Node/{}", resource.metadata.name)).is_none();
    holds_ca(store, who) && new && resource.metadata.name != who.name && spec
}

/// What `cluster.rs` `register` says of a Node the CA-holding control node `who` admits: its
/// address, its raft id, its certificate's print, its mesh key and whether it is a view. Once only:
/// a Node that has a certificate is not changed this way.
fn registers(store: &Store, who: &Worker, name: &str, key: &str, fields: &Fields) -> Result<(), String> {
    let node = store.get(key);
    let registered = node
        .and_then(|node| node.status.as_ref())
        .is_some_and(|status| status.get("certificate").is_some());
    if !holds_ca(store, who) || node.is_none() || registered {
        return Err(refused(
            key,
            "a Node is registered by its join, once, by the control node that holds the CA",
        ));
    }
    let fields_ok = fields
        .keys()
        .all(|field| ["address", "raftId", "certificate", "mesh", "view"].contains(&field.as_str()));
    if !fields_ok {
        return Err(refused(
            key,
            "a join gives a Node its address, raft id, certificate, mesh and view alone",
        ));
    }
    raft_id(name, key, fields)?;
    worker::mesh_key_elsewhere(store, name, key, fields)
}

/// A resource the control node `who` applies as its own: its own Node only where it has none
/// yet (and no spec), or a Node it admits by its join; else what a worker may apply of its own.
fn applied(store: &Store, who: &Worker, resource: &mut Resource) -> Result<(), String> {
    class(&resource.kind)?;
    if resource.kind == "Node" {
        let none = store.get(&format!("Node/{}", who.name)).is_none();
        let empty = resource.spec.as_object().is_some_and(|spec| spec.is_empty());
        let own = resource.metadata.name == who.name && none && empty;
        return match own || admits(store, who, resource) {
            true => Ok(()),
            false => Err(refused(
                "a Node",
                "a control node makes its own Node only where it has none, or admits a new one by its join",
            )),
        };
    }
    worker::apply(store, who, resource)
}

/// `command` as it is given to Raft for the control node `name`, which names no caller, or why not.
/// What a control node writes as itself is held to the same rules a worker's own writes are, with
/// its own Node's status open to any field (its raft id only as its name gives it), and the kinds
/// of [`CLASSES`] only.
///
/// A function of `store`, `prefix` (the mesh's), `held` (which blobs' bytes this node has: only a
/// node's own edge knows) and the entry alone, so any node decides it alike. A bare entry is also
/// held to [`bare`](crate::access_sign::bare): a bare Patch of a Node's certificate or raft id
/// is refused under `spec.signing: required`.
pub fn checked(
    store: &Store,
    prefix: Option<Ipv6Addr>,
    held: &dyn Fn(&str) -> bool,
    name: &str,
    command: Command,
) -> Result<Command, String> {
    crate::access_sign::bare(store, &command)?;
    rules(store, prefix, held, name, command)
}

/// [`checked`] for a write that reached this node's edge (`raft.rs` `write`): its store, its mesh
/// prefix and the blobs it has.
pub fn edge(shared: &crate::Shared, name: &str, command: Command) -> Result<Command, String> {
    let blobs = crate::blobs::dir(shared);
    let held = |blob: &str| blobs.join(blob).exists();
    let prefix = shared
        .cluster
        .as_ref()
        .map(|cluster| crate::mesh::prefix(&cluster.me.ca));
    let state = shared.store.lock().expect("a handler panicked holding the store");
    checked(&state.store, prefix, &held, name, command)
}

fn rules(
    store: &Store,
    prefix: Option<Ipv6Addr>,
    held: &dyn Fn(&str) -> bool,
    name: &str,
    command: Command,
) -> Result<Command, String> {
    let who = Worker { name, prefix, held };
    let mine = format!("Node/{name}");
    match command {
        Command::Patch { statuses } => {
            for (key, fields) in &statuses {
                if *key == mine {
                    own_node(store, name, key, fields)?;
                } else if let Some(joined) = key.strip_prefix("Node/") {
                    registers(store, &who, joined, key, fields)?;
                } else {
                    class(kind_of(key))?;
                    worker::patch(store, &who, key, fields)?;
                }
            }
            Ok(Command::Patch { statuses })
        }
        Command::Status { statuses } => {
            for (key, said) in &statuses {
                class(kind_of(key))?;
                worker::status(store, &who, key, said.as_ref())?;
            }
            Ok(Command::Status { statuses })
        }
        Command::Report { node, statuses } if node == name => {
            let mut taken = Vec::with_capacity(statuses.len());
            for (key, said) in statuses {
                class(kind_of(&key))?;
                let said = worker::report(store, &who, &key, said)?;
                taken.push((key, said));
            }
            Ok(Command::Report { node, statuses: taken })
        }
        Command::Report { node, .. } => Err(refused(
            format!("a report in node {node}'s name"),
            "it is not this node",
        )),
        Command::Apply { mut resources, at } => {
            for resource in &mut resources {
                applied(store, &who, resource)?;
            }
            Ok(Command::Apply { resources, at })
        }
        Command::Delete { key } => {
            class(kind_of(&key))?;
            worker::delete(store, &who, &key)?;
            Ok(Command::Delete { key })
        }
        Command::Rollback { key, .. } => Err(refused(key, "a rollback is not a control node's own write")),
        Command::Import { .. } => Err(refused("a whole store", "only an admin brings one in")),
        // The store's format is the leader's to change: a mark it has made already is the barrier
        // an older follower's relayed write ends with, a no-op, and taken (this build's is an
        // empty Patch). A signed entry is the leader's to write from the request it checked:
        // never another node's own write.
        Command::Mark | Command::MarkSigned | Command::MarkChecked => {
            let made = match command {
                Command::Mark => 2,
                Command::MarkSigned => 3,
                _ => 4,
            };
            match kith_store::format_of(store) >= made {
                true => Ok(command),
                false => Err(refused("the store's format", "only the leader changes it")),
            }
        }
        Command::Signed { .. } => Err(refused("a signed change", "only the leader writes them")),
    }
}

// A control node's own write that makes something new, signed by its node key: a Volume for a
// claim that says `provision` (`sched.rs`), a Job for a CronJob (`cron.rs`) and a certificate or
// the account of ACME (`ingress.rs`). Its entry is the node's POST of its command's JSON to
// `OWN` for every node (`*`): the node's key is the one its Node's `status.certificate` is the
// print of, so no other node's key makes it.
const OWN: &str = "/v1/own";

/// `command` as the control node `me` signs it for the cluster `cluster`: valid 300 s, with a
/// nonce of its own, and its key's point in the header for [`admit`] to find the Node's by.
pub fn sign(me: &crate::pki::Identity, cluster: &str, command: &Command) -> Option<Command> {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    use rustls::pki_types::{PrivatePkcs8KeyDer, pem::PemObject};
    let rng = ring::rand::SystemRandom::new();
    let der = PrivatePkcs8KeyDer::from_pem_slice(me.key.as_bytes()).ok()?;
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der.secret_pkcs8_der(), &rng).ok()?;
    let body = serde_json::to_vec(command).ok()?;
    let mut nonce = [0; 16];
    ring::rand::SecureRandom::fill(&rng, &mut nonce).ok()?;
    {
        let (who, expires, nonce) = (
            format!("node:{}", me.name),
            kith_api::store::now() + 300,
            crate::pki::hex(&nonce),
        );
        let asked = Asked {
            method: "POST",
            path: OWN,
            body: &body,
        };
        let message = crate::access_sign::bytes(cluster, "*", &asked, &who, expires, &nonce);
        let sig = pair.sign(&rng, message.as_bytes()).ok()?;
        let base64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let (sig, key) = (base64(sig.as_ref()), base64(pair.public_key().as_ref()));
        Some(Command::Signed {
            header: format!("v1; who={who}; target=*; expires={expires}; nonce={nonce}; sig={sig}; key={key}"),
            method: "POST".into(),
            path: OWN.into(),
            body: base64(&body),
            command: Box::new(command.clone()),
        })
    }
}

/// May a node apply `command`, which the signed entry `header` (`who=node:NAME`, over `asked`)
/// carries, to `store`? Only where all hold: the key it names is the one Node `node`'s certificate
/// is of; its signature holds; its body is `command`; `command` is something `node` makes
/// ([`signed`]); and `node`'s nonce book takes its nonce. A function of the entry and `store`.
pub fn admit(
    store: &Store,
    cluster: &str,
    node: &str,
    leader: kith_store::NodeId,
    header: &str,
    asked: &Asked,
    command: &Command,
) -> Result<(), String> {
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    let (read, sig) = crate::access_sign::parse(header)?;
    let not = |why: &str| format!("node:{node}: {why}");
    // A header with no (or a bad) key reads as an empty point, whose print is no Node's.
    let point = read
        .key
        .and_then(|key| base64::engine::general_purpose::STANDARD.decode(key).ok());
    let point = point.unwrap_or_default();
    let print = crate::pki::key_print(&[&crate::pki::P256_SPKI[..], &point].concat());
    let status = store.get(&format!("Node/{node}")).and_then(|node| node.status.as_ref());
    if status.is_none_or(|status| status["certificate"] != print.as_str()) {
        return Err(not("its key is not its Node's"));
    }
    if crate::access::is_worker(store, node) {
        return Err(not("it is not a control node"));
    }
    let message = crate::access_sign::bytes(cluster, read.target, asked, read.who, read.expires, read.nonce);
    let holds = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point).verify(message.as_bytes(), &sig);
    // (The body parsed is this command: compared as values, not as the bytes this or another
    // build writes, where a key's order or a number's spelling may differ.)
    let value = |bytes: &[u8]| serde_json::from_slice::<serde_json::Value>(bytes).ok();
    let made = serde_json::to_vec(command).ok();
    if holds.is_err() || !value(asked.body).is_some_and(|sent| made.as_deref().and_then(value) == Some(sent)) {
        return Err(not("its signature or body is not this entry's"));
    }
    let leads = kith_store::node_id(node) == leader;
    signed(store, kith_mesh::prefix(cluster.as_bytes()), (node, leads), command)?;
    let taken = store.takes_nonce(read.who, read.expires, read.nonce);
    taken.map_err(|e| e.to_string())
}

/// What `node`, a control node, may write signed: an Apply of what [`mine`] says it makes (a
/// Volume, Job or Secret [`made`] allows; what a Release, Source or controller makes, held to its
/// owner's writer, [`owned`]; a Package a Repository sent; a Node's [`cordon`]), or a
/// Delete of what [`takes_away`] allows; else what it writes as itself bare, but for the blobs it
/// holds (a signed entry is decided by the store alone: no blob is held).
fn signed(store: &Store, prefix: Ipv6Addr, by: (&str, bool), command: &Command) -> Result<(), String> {
    // Whatever the owner it names, a node never signs a write that changes access (a Role, a
    // RoleBinding, an Identity, a KindDefinition or the Cluster): a Release's writer may be allowed
    // one, and `writer_may` asks only that, not that the Release renders it. People sign those.
    if crate::raft::changes_access(command) {
        return Err(not_made(
            "a node's own write",
            "it changes access, and only a person signs that",
        ));
    }
    match command {
        Command::Apply { resources, .. } => {
            let decided: Vec<_> = resources.iter().map(|r| mine(store, prefix, by, r)).collect();
            // (A thing refused here is refused whatever the rest: not left to what a node holds.)
            decided.iter().flatten().cloned().collect::<Result<(), _>>()?;
            if decided.iter().all(Option::is_some) {
                return Ok(());
            }
        }
        Command::Delete { key } => {
            if let Some(decided) = takes_away(store, by.1, key) {
                return decided;
            }
        }
        _ => {}
    }
    rules(store, Some(prefix), &|_| false, by.0, command.clone()).map(drop)
}

/// Is `resource` what the leader writes for what it is derived from, and may it? `None`: it is not
/// of these, and what a node writes as itself decides it.
fn mine(store: &Store, prefix: Ipv6Addr, by: (&str, bool), resource: &Resource) -> Option<Result<(), String>> {
    use crate::releases::{REPOSITORY, owner};
    // (What a CronJob makes is a Job of it: [`made`] holds it to the CronJob, not to a writer.)
    let of = owner(resource).filter(|of| !of.starts_with("CronJob/"));
    match (of, resource.kind.as_str()) {
        (Some(of), _) => Some(owned(store, by.1, of, resource)),
        (None, "Volume" | "Job" | "Secret") => Some(made(store, prefix, by, resource)),
        (None, "Package") if resource.metadata.annotations.contains_key(REPOSITORY) => {
            Some(fetched(store, by.1, resource))
        }
        (None, "Node") => cordon(store, by.1, resource),
        _ => None,
    }
}

fn not_made(key: impl std::fmt::Display, why: impl std::fmt::Display) -> String {
    format!("{key}: {why}")
}

/// The resource whose writer's rights hold what the owner `owner` makes: a Release's or a Source's
/// own, or the KindDefinition of a kind a controller makes things of ([`crate::controllers`]).
fn writer_of<'a>(store: &'a Store, owner: &str) -> Result<&'a Resource, String> {
    let owner = store.get(owner).ok_or_else(|| format!("{owner} is not there"))?;
    match owner.kind.as_str() {
        "Release" | "Source" => Ok(owner),
        kind => store
            .definition(kind)
            .ok_or_else(|| format!("no KindDefinition makes a {kind}")),
    }
}

/// May the leader write `resource`, which says it is made for `of` (a Release, a Source or a
/// controller's resource)? As `writer_may` decides it, as it does where the controller proposes it
/// (so one that has lost its rights writes nothing new): on every node. And not over what is
/// another owner's, or no one's.
fn owned(store: &Store, leads: bool, of: &str, resource: &Resource) -> Result<(), String> {
    let key = resource.key();
    if !leads {
        return Err(not_made(
            key,
            "only the leader writes what a Release, a Source or a controller makes",
        ));
    }
    if store
        .get(&key)
        .is_some_and(|held| crate::releases::owner(held) != Some(of))
    {
        return Err(not_made(key, format!("it is there, and not what {of} made")));
    }
    let writer = writer_of(store, of).map_err(|why| not_made(&key, why))?;
    crate::releases::writer_may(store, writer, std::slice::from_ref(resource), &[])
}

/// May the leader take away `key`? What a Release, a Source or a controller made, where the writer
/// of its owner may delete it (the leftovers of an owner that is gone go too: nobody's rights are
/// left to ask); the Jobs of a CronJob, and a Volume made for a claim that is gone. `None`: none
/// of these, and what a node writes as itself decides it.
fn takes_away(store: &Store, leads: bool, key: &str) -> Option<Result<(), String>> {
    let held = store.get(key)?;
    let of = crate::releases::owner(held);
    let for_claim = held.kind == "Volume" && held.metadata.annotations.contains_key(crate::volumes::MADE_FOR_CLAIM);
    let decided: Result<(), String> = match of {
        _ if for_claim => match store.get(&key.replacen("Volume", "VolumeClaim", 1)) {
            None => Ok(()),
            Some(_) => Err("its claim is there".into()),
        },
        Some(of) if of.starts_with("CronJob/") && held.kind == "Job" => Ok(()),
        // (An owner that is not there leaves no rights to ask; one that is and has no writer, does.
        // And only of a kind a controller makes things of: what merely carries the annotation of
        // another stays. Nobody applies one by hand, `releases::claims`: it is the reaper's to take.)
        Some(of) if store.get(of).is_none() => {
            let kind = kind_of(of);
            match matches!(kind, "Release" | "Source") || store.definition(kind).is_some() {
                true => Ok(()),
                false => Err(format!("{of} is gone, and no controller makes things of a {kind}")),
            }
        }
        Some(of) => {
            writer_of(store, of).and_then(|writer| crate::releases::writer_may(store, writer, &[], &[key.to_string()]))
        }
        None => return None,
    };
    Some(match (leads, decided) {
        (false, _) => Err(not_made(
            key,
            "only the leader takes away what Releases, Sources, CronJobs and claims made",
        )),
        (true, decided) => decided.map_err(|why| not_made(key, why)),
    })
}

/// May the leader write the Package `package`, which says a Repository sent it? One of a
/// Repository that is there and says what it said when it was fetched (`releases::origin`: its
/// url and key), for a Release that names that Repository and whose writer may apply Packages
/// (`releases::supplied`, as the registry asks it before it fetches): a taken leader names no
/// other, nor stores what no Release wants.
fn fetched(store: &Store, leads: bool, package: &Resource) -> Result<(), String> {
    let key = package.key();
    let said = package.metadata.annotations.get(crate::releases::REPOSITORY);
    let name = said.and_then(|said| said.split('@').next()).unwrap_or_default();
    // (The registry names a Package `NAME-VERSION`, its `spec.version` the version: the name and
    // version a Release asks of that Repository, and that its `version` fits.)
    let wanted = |release: &&Resource| {
        let asks = &release.spec["package"];
        let version = package.spec["version"].as_str().unwrap_or_default();
        asks["repo"] == name
            && asks["name"]
                .as_str()
                .is_some_and(|asked| package.metadata.name == format!("{asked}-{version}"))
            && crate::releases::fits(asks["version"].as_str(), version)
            && crate::releases::supplied(store, release).is_ok()
    };
    // (Over a Package that is there: only the same Repository's, as the registry does it. One no
    // one fetched, or another Repository's, is not for a fetch to overwrite.)
    let overwrites_another = store.get(&key).is_some_and(|held| {
        let from = held.metadata.annotations.get(crate::releases::REPOSITORY);
        from.and_then(|from| from.split('@').next()) != Some(name)
    });
    match (leads, crate::releases::origin(store, name)) {
        (false, _) => Err(not_made(key, "only the leader writes what a Repository sent")),
        _ if overwrites_another => Err(not_made(key, "it is there, and not what that Repository sent")),
        (_, origin) if origin.as_ref() == said && store.list(Some("Release")).any(|r| wanted(&r)) => Ok(()),
        _ => Err(not_made(
            key,
            "no Release of one who may apply Packages asks that Repository for it",
        )),
    }
}

/// May the leader write the Node `node` as an update's cordon of one that is there: its spec the
/// cordon's, put on or lifted, and nothing else of it? `None`: it is not that (a join's Node is
/// `admits`' to decide), and what a node writes as itself decides it.
fn cordon(store: &Store, leads: bool, node: &Resource) -> Option<Result<(), String>> {
    let key = node.key();
    let held = store.get(&key)?;
    let moved = |on| crate::update::cordoned_spec(&held.spec, on);
    if ![moved(true), moved(false)].contains(&Some(node.spec.clone())) {
        return None;
    }
    let mut was = held.clone();
    (was.spec, was.status, was.metadata.revision) = (node.spec.clone(), node.status.clone(), node.metadata.revision);
    Some(match (leads, was == *node) {
        (false, _) => Err(not_made(key, "only the leader writes a Node's cordon")),
        (_, false) => Err(not_made(key, "an update writes a Node's cordon and nothing else of it")),
        _ => Ok(()),
    })
}

/// May the control node `by` (its name, and whether it leads) make `resource`? Each is the work of
/// the node that does it: the leader's scheduler makes a Volume and its cron a Job; a Secret is the
/// leader's, or a node's that serves ingress (it orders its own certificates). A Volume: new, for a
/// claim that says `provision`, on a Node, and all of what `volumes::made_for` makes of them. A Job:
/// new, of a CronJob that is there, and all of what `cron::job_for` makes of it. A Secret: the
/// account of ACME, or the certificate of a host the Services expose; a node that is not the leader
/// orders only where the admin set its `spec.ingress` as well as its own status says it serves
/// ingress (the status is its own to say), and never overwrites the account.
fn made(store: &Store, prefix: Ipv6Addr, by: (&str, bool), resource: &Resource) -> Result<(), String> {
    let key = resource.key();
    let there = |key: &str| store.get(key).is_some();
    let allowed = match resource.kind.as_str() {
        "Volume" => {
            let claim = store.get(&key.replacen("Volume", "VolumeClaim", 1));
            let node = resource.spec["node"]
                .as_str()
                .filter(|node| there(&format!("Node/{node}")));
            let asked = claim.zip(node).is_some_and(|(claim, node)| {
                let system = claim.metadata.namespace.as_deref() == Some(crate::volumes::SYSTEM);
                claim.spec["provision"] == true && !system && *resource == crate::volumes::made_for(claim, node)
            });
            by.1 && !there(&key) && asked
        }
        "Job" => {
            let cron = crate::releases::owner(resource).filter(|owner| owner.starts_with("CronJob/"));
            let cron = cron.and_then(|owner| store.get(owner));
            // (A CronJob sent here stamps its Job with when it was made, `kube::MADE`: not compared.)
            let untimed = |job: &Resource| {
                let mut job = job.clone();
                job.metadata.annotations.remove("kube.kith.dev/made");
                job
            };
            let same = |cron: &Resource| {
                let named = resource.metadata.name.strip_prefix(&format!("{}-", cron.metadata.name));
                let minute =
                    named.is_some_and(|minute| !minute.is_empty() && minute.bytes().all(|b| b.is_ascii_digit()));
                let job = crate::cron::job_for(cron, resource.metadata.name.clone());
                minute && untimed(&job) == untimed(resource)
            };
            by.1 && !there(&key) && cron.is_some_and(same)
        }
        _ => {
            let node = store.get(&format!("Node/{}", by.0));
            let serves = node
                .and_then(|node| node.status.as_ref())
                .is_some_and(|status| status["serves"]["ingress"] == true);
            let said = node.is_some_and(|node| node.spec["ingress"] == true);
            let account = key == crate::ingress::ACCOUNT;
            let orders = by.1 || (serves && said && !(account && there(&key)));
            let (hosts, _) = crate::ingress::exposed(store, prefix);
            orders && (account || hosts.iter().any(|(host, e)| crate::ingress::tls_secret(host, e) == key))
        }
    };
    match allowed {
        true => Ok(()),
        false => Err(refused(key, "no claim, CronJob or exposed host asks for it")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Shared;
    use crate::cluster::Peer;
    use crate::cluster::pinned_peer::{at, node, shared_with};
    use crate::cluster::{Cluster, listen, node_router};
    use crate::pki;
    use kith_store::Command;
    use kith_store::openraft::BasicNode;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    /// [`edge`], as the tests before the store was a parameter called it.
    fn checked(shared: &Shared, name: &str, command: Command) -> Result<Command, String> {
        super::edge(shared, name, command)
    }

    /// Each kind kith knows is classified once: a new kind fails here until it is.
    #[test]
    fn every_kind_is_classified() {
        for info in kith_api::KINDS {
            let said = CLASSES.iter().filter(|(kind, _)| *kind == info.kind).count();
            assert_eq!(
                said, 1,
                "{} is classified {said} times: say whether a control node writes it as itself",
                info.kind
            );
        }
        assert_eq!(
            CLASSES.len(),
            kith_api::KINDS.len(),
            "a classified kind kith does not know"
        );
    }

    /// Through the write route: a control node's own write, naming no caller, is let through for
    /// what it holds, and refused and audited by its name for what only an admin may write; a
    /// worker is still held to what it may write, and no control node's kind.
    #[tokio::test]
    async fn own_writes_let_a_control_node_write_what_it_holds_and_refuse_the_rest() {
        let ca = pki::Ca::create().unwrap();
        let (c, w, k) = (node(&ca, "own-c"), node(&ca, "own-w"), node(&ca, "own-k"));
        let shared: Arc<Shared> = shared_with("own", c.clone(), &[]).await;
        for (name, spec) in [("own-w", "{trust: worker}"), ("own-k", "{}")] {
            let text = format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{name: {name}}}\nspec: {spec}\n");
            let node = kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap();
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(node).unwrap();
            // Joined: a Node made by hand is not let in.
            let joined = serde_json::json!({ "raftId": kith_store::node_id(name).to_string() });
            store.set_status(&format!("Node/{name}"), Some(joined)).unwrap();
        }
        let volume = "apiVersion: kith.dev/v1\nkind: Volume\nmetadata: {name: data, namespace: default}\nspec: {node: own-c, path: d}\n";
        let volume = kith_api::Resource::from_source(volume).unwrap().remove(0).unwrap();
        {
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(volume).unwrap();
            let replicas = serde_json::json!({ "replicas": ["own-k"] });
            store.set_status("Volume/default/data", Some(replicas)).unwrap();
        }
        let id = shared.raft.metrics().borrow().id;
        shared
            .raft
            .initialize(BTreeMap::from([(id, BasicNode::new(""))]))
            .await
            .unwrap();
        let leads = shared.raft.wait(Some(Duration::from_secs(30)));
        leads.current_leader(id, "leads").await.unwrap();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap().to_string();
        let listener = listen(tcp, pki::server_config(&c).unwrap()).unwrap();
        let app = node_router(shared.clone()).into_make_service_with_connect_info::<Peer>();
        tokio::spawn(async move { drop(axum::serve(listener, app).await) });
        let client = |who: &pki::Identity| {
            let cluster = Cluster::new(who.clone(), None).unwrap();
            cluster.to(&at("own-c", &address, None)).unwrap()
        };
        let (to_w, to_k) = (client(&w), client(&k));
        let url = format!("https://{address}/v1/raft/write");
        let patch = |key: &str, fields: serde_json::Value| Command::Patch {
            statuses: vec![(key.to_string(), fields.as_object().unwrap().clone())],
        };

        // Its own Node's status, a Volume it is a replica of, and its units (none here).
        let own_id = kith_store::node_id("own-k").to_string();
        let allowed = [
            patch("Node/own-k", serde_json::json!({ "os": "x" })),
            // Its boot writes its raft id again: the id its name gives, forwarded to the leader.
            patch("Node/own-k", serde_json::json!({ "raftId": own_id })),
            patch("Volume/default/data", serde_json::json!({ "synced": { "own-k": 5 } })),
            Command::Report {
                node: "own-k".into(),
                statuses: Vec::new(),
            },
        ];
        for command in &allowed {
            let said = to_k
                .post(&url)
                .json(command)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert!(said.contains("Ok"), "{said}");
        }

        // What only an admin may write, and another node's Node: refused, each one audited by name.
        let refused = [
            Command::Delete {
                key: "Cluster/cluster".into(),
            },
            Command::Delete {
                key: "Secret/default/s".into(),
            },
            Command::Delete {
                key: "Deployment/default/d".into(),
            },
            patch("Node/own-w", serde_json::json!({ "os": "x" })),
            patch("Node/own-k", serde_json::json!({ "raftId": "1" })),
        ];
        for command in &refused {
            let said = to_k
                .post(&url)
                .json(command)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert!(said.contains("Err"), "{said}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let of_k = shared
            .audit
            .tail(200)
            .unwrap()
            .iter()
            .filter(|e| e["who"] == "node own-k" && e["ok"] == false)
            .count();
        assert_eq!(of_k, refused.len(), "each refusal is in the audit log by its name");

        // A worker: no Cluster, whatever it names.
        let theirs = Command::Delete {
            key: "Cluster/cluster".into(),
        };
        let said = to_w
            .post(&url)
            .json(&theirs)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(said.contains("Err"), "{said}");
    }

    /// The store's format is the leader's to change, and a signed entry the leader's to write: a
    /// Signed is never a control node's own write, and a mark only once the store has made it
    /// (the barrier an older follower's relayed write ends with; this build's is an empty Patch).
    #[tokio::test]
    async fn raft_write_refuses_a_format_or_signed_entry_as_a_control_nodes_own_write() {
        let ca = pki::Ca::create().unwrap();
        let shared: Arc<Shared> = shared_with("own-signed", node(&ca, "sign-c"), &[]).await;
        let signed = || Command::Signed {
            header: String::new(),
            method: "POST".into(),
            path: "/v1/apply".into(),
            body: String::new(),
            command: Box::new(Command::Patch { statuses: vec![] }),
        };
        for format in 1..=4 {
            match format {
                2 => shared.store.lock().unwrap().store.mark(),
                3 => shared.store.lock().unwrap().store.sign(),
                4 => shared.store.lock().unwrap().store.check(),
                _ => {}
            }
            // A mark the store has made already is an older follower's barrier: taken, a no-op.
            for (made, command) in [(2, Command::Mark), (3, Command::MarkSigned), (4, Command::MarkChecked)] {
                match checked(&shared, "sign-c", command) {
                    Ok(_) => assert!(format >= made, "format {format}: format {made}'s mark taken"),
                    Err(said) => assert!(format < made && said.contains("only the leader changes it"), "{said}"),
                }
            }
            let said = checked(&shared, "sign-c", signed()).unwrap_err();
            assert!(said.contains("only the leader writes"), "{said}");
            assert!(checked(&shared, "sign-c", Command::Patch { statuses: vec![] }).is_ok());
        }
    }

    /// Another node's mesh key, said in a control node's own Node, is refused as a worker's is:
    /// two nodes that say one key are both left out of the mesh.
    #[tokio::test]
    async fn own_writes_refuse_a_mesh_key_another_node_holds() {
        let ca = pki::Ca::create().unwrap();
        let shared: Arc<Shared> = shared_with("own-mesh", node(&ca, "mesh-c"), &[]).await;
        {
            let text = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: {name: mesh-o}\nspec: {}\n";
            let other = kith_api::Resource::from_source(text).unwrap().remove(0).unwrap();
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(other).unwrap();
            let mesh = serde_json::json!({ "mesh": { "key": "QUFB", "port": 51820 } });
            store.set_status("Node/mesh-o", Some(mesh)).unwrap();
        }
        let own = |key: &str| Command::Patch {
            statuses: vec![(
                "Node/mesh-c".to_string(),
                serde_json::json!({ "mesh": { "key": key, "port": 51820 } })
                    .as_object()
                    .unwrap()
                    .clone(),
            )],
        };
        assert!(checked(&shared, "mesh-c", own("QUFB")).is_err());
        assert!(checked(&shared, "mesh-c", own("TkVX")).is_ok());
    }

    /// The join a control node that holds the CA makes (`cluster.rs` `join` and `register`), not
    /// the leader: a new name's Node and its status pass; a Node already there is not made again
    /// or patched once registered; a node that holds no CA, and any other field, are refused.
    #[tokio::test]
    async fn own_writes_let_the_ca_node_join_a_new_node_and_not_change_a_registered_one() {
        let ca = pki::Ca::create().unwrap();
        let shared: Arc<Shared> = shared_with("own-join", node(&ca, "join-c"), &[]).await;
        let resource = |name: &str, spec: serde_json::Value| {
            let node = serde_json::json!({
                "apiVersion": kith_api::API_VERSION, "kind": "Node", "metadata": { "name": name }, "spec": spec,
            });
            serde_json::from_value::<kith_api::Resource>(node).unwrap()
        };
        let apply = |name: &str, spec: serde_json::Value| Command::Apply {
            resources: vec![resource(name, spec)],
            at: kith_api::store::now(),
        };
        let patch = |name: &str, fields: serde_json::Value| Command::Patch {
            statuses: vec![(format!("Node/{name}"), fields.as_object().unwrap().clone())],
        };
        let register = |print: &str| {
            serde_json::json!({
                "address": "10.0.0.7:7", "raftId": kith_store::node_id("join-n").to_string(), "certificate": print,
            })
        };
        {
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(resource("join-c", serde_json::json!({}))).unwrap();
            store
                .set_status("Node/join-c", Some(serde_json::json!({ "ca": true })))
                .unwrap();
            store.apply(resource("join-o", serde_json::json!({}))).unwrap();
        }

        // `join`: the Node with the spec it gives, then `register`'s Node when it is not there yet.
        assert!(
            checked(
                &shared,
                "join-c",
                apply("join-n", serde_json::json!({ "roaming": true }))
            )
            .is_ok()
        );
        assert!(checked(&shared, "join-c", apply("join-n", serde_json::json!({}))).is_ok());
        assert!(
            checked(
                &shared,
                "join-c",
                apply("join-x", serde_json::json!({ "trust": "admin" }))
            )
            .is_err()
        );
        assert!(
            checked(&shared, "join-c", apply("join-o", serde_json::json!({}))).is_err(),
            "a Node there is not made again"
        );
        // Its status, once: the address, the raft id its name gives, and the certificate's print.
        shared
            .store
            .lock()
            .unwrap()
            .store
            .apply(resource("join-n", serde_json::json!({ "roaming": true })))
            .unwrap();
        assert!(checked(&shared, "join-c", patch("join-n", register("PRINT"))).is_ok());
        assert!(checked(&shared, "join-c", patch("join-o", serde_json::json!({ "os": "x" }))).is_err());
        let other_id = serde_json::json!({ "address": "10.0.0.7:7", "raftId": "1", "certificate": "PRINT" });
        assert!(
            checked(&shared, "join-c", patch("join-n", other_id)).is_err(),
            "a raft id its name does not give"
        );
        shared
            .store
            .lock()
            .unwrap()
            .store
            .set_status("Node/join-n", Some(register("PRINT")))
            .unwrap();
        assert!(
            checked(&shared, "join-c", patch("join-n", register("OTHER"))).is_err(),
            "a registered Node is not changed this way"
        );

        // Held to the CA: a control node that holds none admits no node.
        shared
            .store
            .lock()
            .unwrap()
            .store
            .apply(resource("join-f", serde_json::json!({})))
            .unwrap();
        assert!(checked(&shared, "join-f", apply("join-m", serde_json::json!({}))).is_err());
    }

    /// Through the write route: a write a node passes on for an admin (`x-kith-for: local
    /// socket`, the local socket's) is checked as the admin's and not as the node's own, so an
    /// Identity, or another node's NodeKey, that a control node could not write as itself goes
    /// through when the admin asked for it (`certificate`, `claim`, the lock and duress routes).
    #[tokio::test]
    async fn own_writes_let_an_admin_write_a_node_passes_on_go_through_as_the_admin() {
        let ca = pki::Ca::create().unwrap();
        let (c, k) = (node(&ca, "fwd-c"), node(&ca, "fwd-k"));
        let shared: Arc<Shared> = shared_with("own-fwd", c.clone(), &[]).await;
        {
            let store = &mut shared.store.lock().unwrap().store;
            for (name, spec) in [("fwd-k", "{}"), ("fwd-w", "{trust: worker}")] {
                let text = format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{name: {name}}}\nspec: {spec}\n");
                store
                    .apply(kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap())
                    .unwrap();
                let joined = serde_json::json!({ "raftId": kith_store::node_id(name).to_string() });
                store.set_status(&format!("Node/{name}"), Some(joined)).unwrap();
            }
            let key = "apiVersion: kith.dev/v1\nkind: NodeKey\nmetadata: {name: fwd-w}\nspec: {id: QUFB}\n";
            store
                .apply(kith_api::Resource::from_source(key).unwrap().remove(0).unwrap())
                .unwrap();
        }
        let id = shared.raft.metrics().borrow().id;
        shared
            .raft
            .initialize(BTreeMap::from([(id, BasicNode::new(""))]))
            .await
            .unwrap();
        let leads = shared.raft.wait(Some(Duration::from_secs(30)));
        leads.current_leader(id, "leads").await.unwrap();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap().to_string();
        let listener = listen(tcp, pki::server_config(&c).unwrap()).unwrap();
        let app = node_router(shared.clone()).into_make_service_with_connect_info::<Peer>();
        tokio::spawn(async move { drop(axum::serve(listener, app).await) });
        let to_k = Cluster::new(k.clone(), None)
            .unwrap()
            .to(&at("fwd-c", &address, None))
            .unwrap();
        let url = format!("https://{address}/v1/raft/write");
        let own = |command: &Command| to_k.post(&url).json(command);
        let forwarded = |command: &Command| own(command).header(crate::access::FOR, "local socket");
        let said = |call: reqwest::RequestBuilder| async move { call.send().await.unwrap().text().await.unwrap() };

        let identity = "apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: fwd-user}\nspec: {}\n";
        let identity = Command::Apply {
            resources: vec![kith_api::Resource::from_source(identity).unwrap().remove(0).unwrap()],
            at: kith_api::store::now(),
        };
        assert!(
            said(own(&identity)).await.contains("Err"),
            "a node's own Identity is refused"
        );
        assert!(
            said(forwarded(&identity)).await.contains("Ok"),
            "an admin's, passed on, is let through"
        );

        let key = "apiVersion: kith.dev/v1\nkind: NodeKey\nmetadata: {name: fwd-w}\nspec: {id: QUFB, locked: true}\n";
        let key = Command::Apply {
            resources: vec![kith_api::Resource::from_source(key).unwrap().remove(0).unwrap()],
            at: kith_api::store::now(),
        };
        assert!(
            said(own(&key)).await.contains("Err"),
            "a node's own write of another node's NodeKey is refused"
        );
        assert!(
            said(forwarded(&key)).await.contains("Ok"),
            "an admin's lock of it, passed on, is let through"
        );
    }

    /// The holder of the house address is the leader, and its own writes never come through here
    /// (they are not forwarded): a write of a Cluster that is forwarded, status.home as the
    /// holder's own included, is a taken control node's and is refused.
    #[tokio::test]
    async fn own_writes_refuse_a_forwarded_home_status_and_every_other_write_of_a_cluster() {
        let ca = pki::Ca::create().unwrap();
        let shared: Arc<Shared> = shared_with("own-home", node(&ca, "home-c"), &[]).await;
        for (name, spec) in [("house", "{home: {address: 10.9.0.100/24}}"), ("bare", "{}")] {
            let text = format!("apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{name: {name}}}\nspec: {spec}\n");
            let cluster = kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap();
            shared.store.lock().unwrap().store.apply(cluster).unwrap();
        }
        let patch = |key: &str, fields: serde_json::Value| Command::Patch {
            statuses: vec![(key.to_string(), fields.as_object().unwrap().clone())],
        };
        let since = "2026-11-18T10:00:00Z";
        let holder = |who: &str| serde_json::json!({ "home": { "holder": who, "since": since } });
        let refused = [
            patch("Cluster/house", holder("home-c")),
            patch("Cluster/house", holder("home-o")),
            patch("Cluster/bare", holder("home-c")),
            patch("Cluster/house", serde_json::json!({ "home": { "holder": "home-c" } })),
            patch(
                "Cluster/house",
                serde_json::json!({ "home": { "holder": "home-c", "since": 5 } }),
            ),
            patch(
                "Cluster/house",
                serde_json::json!({ "home": { "holder": "home-c", "since": since, "x": 1 } }),
            ),
            patch(
                "Cluster/house",
                serde_json::json!({ "home": holder("home-c")["home"], "signing": "open" }),
            ),
            patch("Cluster/house", serde_json::json!({ "adminKey": "x" })),
            Command::Status {
                statuses: vec![("Cluster/house".into(), Some(holder("home-c")))],
            },
            Command::Delete {
                key: "Cluster/house".into(),
            },
        ];
        for command in refused {
            assert!(checked(&shared, "home-c", command.clone()).is_err(), "{command:?}");
        }
    }

    /// Which node holds the CA is what its first start wrote (it led alone then): a control node
    /// does not say so of itself after, or it would admit nodes by a join it cannot sign.
    #[tokio::test]
    async fn own_writes_refuse_a_control_node_saying_it_holds_the_ca() {
        let ca = pki::Ca::create().unwrap();
        let shared: Arc<Shared> = shared_with("own-ca", node(&ca, "ca-c"), &[]).await;
        let node = |name: &str| {
            let node = serde_json::json!({
                "apiVersion": kith_api::API_VERSION, "kind": "Node", "metadata": { "name": name }, "spec": {},
            });
            serde_json::from_value::<kith_api::Resource>(node).unwrap()
        };
        {
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(node("ca-c")).unwrap();
            store
                .set_status("Node/ca-c", Some(serde_json::json!({ "ca": true })))
                .unwrap();
            store.apply(node("ca-o")).unwrap();
        }
        let patch = |name: &str, fields: serde_json::Value| Command::Patch {
            statuses: vec![(format!("Node/{name}"), fields.as_object().unwrap().clone())],
        };
        assert!(checked(&shared, "ca-o", patch("ca-o", serde_json::json!({ "ca": true }))).is_err());
        assert!(checked(&shared, "ca-c", patch("ca-c", serde_json::json!({ "ca": false }))).is_err());
        // (The CA node's start says it again: the same, and let through.)
        assert!(checked(&shared, "ca-c", patch("ca-c", serde_json::json!({ "ca": true }))).is_ok());
    }

    fn resource(value: serde_json::Value) -> kith_api::Resource {
        serde_json::from_value(value).unwrap()
    }

    fn named(kind: &str, name: &str, spec: serde_json::Value) -> kith_api::Resource {
        let metadata = if kind == "Node" || kind == "Cluster" {
            serde_json::json!({ "name": name })
        } else {
            serde_json::json!({ "name": name, "namespace": "default" })
        };
        resource(
            serde_json::json!({ "apiVersion": kith_api::API_VERSION, "kind": kind, "metadata": metadata, "spec": spec }),
        )
    }

    /// A store in format 4 that says `spec.signing: required`, with the control nodes `names` of
    /// `ca`, each with the print of its key as its certificate, and `a` holding the CA.
    fn required(ca: &pki::Ca, names: &[&str]) -> (Store, Vec<pki::Identity>) {
        let mut store = Store::default();
        let spec = serde_json::json!({ "adminKey": "a".repeat(64), "signing": "required" });
        store.apply(named("Cluster", "home", spec)).unwrap();
        kith_store::run(&mut store, Command::MarkChecked).unwrap();
        let nodes: Vec<pki::Identity> = names.iter().map(|name| node(ca, name)).collect();
        for me in &nodes {
            store.apply(named("Node", &me.name, serde_json::json!({}))).unwrap();
            let status = serde_json::json!({ "certificate": pki::print_of(&me.cert).unwrap(), "ca": me.name == "a" });
            store.set_status(&format!("Node/{}", me.name), Some(status)).unwrap();
        }
        (store, nodes)
    }

    fn apply(resources: Vec<kith_api::Resource>) -> Command {
        Command::Apply { resources, at: 0 }
    }

    /// A function of the store and the entry: the same where the store is the same, and a bare
    /// Patch of a Node's certificate or raft id is refused under `required`, in format 4 (other
    /// fields, and a store that does not require signing, are as they were).
    #[test]
    fn own_writes_checked_is_pure_and_refuses_a_bare_node_certificate_or_raft_id() {
        let ca = pki::Ca::create().unwrap();
        let (store, _) = required(&ca, &["a"]);
        let patch = |field: &str, value: &str| Command::Patch {
            statuses: vec![(
                "Node/a".into(),
                serde_json::Map::from_iter([(field.into(), value.into())]),
            )],
        };
        let id = kith_store::node_id("a").to_string();
        let decide = |store: &Store, command: Command| super::checked(store, None, &|_| false, "a", command);
        for command in [patch("certificate", "00"), patch("raftId", &id)] {
            let said = decide(&store, command.clone()).unwrap_err();
            assert!(said.contains("certificate or raft id"), "{command:?}");
            assert_eq!(
                said,
                decide(&store, command).unwrap_err(),
                "the same entry and store decide alike"
            );
        }
        assert!(decide(&store, patch("os", "x")).is_ok());
        let mut open = Store::default();
        open.apply(named("Node", "a", serde_json::json!({}))).unwrap();
        assert!(decide(&open, patch("raftId", &id)).is_ok());
    }

    /// A node's Volume, Job and Secret writes, signed by its key, are applied where a claim, a
    /// CronJob or an exposed host asks for them; another node's key makes none of them its own.
    #[test]
    fn own_writes_signed_by_a_node_apply_only_as_that_node_for_what_is_asked() {
        let ca = pki::Ca::create().unwrap();
        let (mut store, nodes) = required(&ca, &["a", "b"]);
        let (a, b) = (&nodes[0], &nodes[1]);
        let id = pki::fingerprint(&ca.cert).unwrap();
        let claim = serde_json::json!({ "size": "1Gi", "provision": true });
        store.apply(named("VolumeClaim", "db", claim)).unwrap();
        let cron = named(
            "CronJob",
            "tick",
            serde_json::json!({
                "schedule": "* * * * *", "job": { "template": { "exec": [{ "name": "tick", "command": ["true"] }] } },
            }),
        );
        store.apply(cron.clone()).unwrap();
        let volume = |name: &str, node: &str, path: &str| {
            let claim = named(
                "VolumeClaim",
                name,
                serde_json::json!({ "size": "1Gi", "provision": true }),
            );
            let mut volume = crate::volumes::made_for(&claim, node);
            volume.spec["path"] = path.into();
            volume
        };
        let job = crate::cron::job_for(&cron, "tick-1".into());
        let mut orphan = job.clone();
        orphan.metadata.name = "other-1".into();
        orphan
            .metadata
            .annotations
            .insert(crate::releases::OWNER.into(), "CronJob/default/none".into());
        let account = resource(serde_json::json!({
            "apiVersion": kith_api::API_VERSION, "kind": "Secret",
            "metadata": { "name": "acme-account", "namespace": "kith-system" }, "spec": { "data": {} },
        }));
        let admitted =
            |store: &Store, entry: &Command| crate::access_sign::admit(store, &id, entry, kith_store::node_id("a"));
        let by = |me: &pki::Identity, command: Command| sign(me, &id, &command).unwrap();

        // What is asked: applied, signed by the leader that does the work, and once (its nonce is taken).
        for (me, command) in [
            (a, apply(vec![volume("db", "b", "data")])),
            (a, apply(vec![job.clone()])),
            (a, apply(vec![account.clone()])),
        ] {
            let entry = by(me, command);
            assert_eq!(admitted(&store, &entry), Ok(()), "{entry:?}");
            kith_store::run(&mut store, entry.clone()).unwrap();
            // (Refused as made already, whatever its nonce says.)
            assert!(admitted(&store, &entry).is_err(), "{entry:?}");
        }

        // What is not: a Volume of no claim, on no Node or somewhere on the host; a Job of no
        // CronJob or one that is there; a Secret of no host.
        let secret = |name: &str| {
            let mut secret = account.clone();
            secret.metadata.name = name.into();
            secret
        };
        for command in [
            apply(vec![volume("none", "a", "data")]),
            apply(vec![volume("db2", "nowhere", "data")]),
            apply(vec![volume("db3", "a", "/etc")]),
            apply(vec![orphan]),
            apply(vec![job]),
            apply(vec![secret("kube-system")]),
            apply(vec![secret("x"), named("Service", "web", serde_json::json!({}))]),
        ] {
            let said = admitted(&store, &by(a, command.clone()));
            assert!(said.is_err(), "{command:?}");
        }

        // Another node's key, said as node a's; a command that is not the body's; no key.
        let as_a = pki::Identity {
            name: "a".into(),
            ..b.clone()
        };
        let command = apply(vec![volume("db", "a", "data")]);
        let forged = admitted(&store, &sign(&as_a, &id, &command).unwrap());
        assert!(forged.unwrap_err().contains("its key is not its Node's"));
        let Command::Signed {
            header,
            method,
            path,
            body,
            ..
        } = by(a, command.clone())
        else {
            unreachable!()
        };
        let swapped = apply(vec![volume("db", "b", "data")]);
        let entry = Command::Signed {
            header: header.clone(),
            method: method.clone(),
            path: path.clone(),
            body: body.clone(),
            command: Box::new(swapped),
        };
        assert!(admitted(&store, &entry).unwrap_err().contains("signature or body"));
        let bare_key = header.split("; key=").next().unwrap().to_string();
        let entry = Command::Signed {
            header: bare_key,
            method,
            path,
            body,
            command: Box::new(command),
        };
        assert!(admitted(&store, &entry).unwrap_err().contains("not its Node's"));
    }

    /// A write is the work of the node that does it: the leader's scheduler makes a Volume and its
    /// cron a Job, and a Secret is the leader's or a serving node's. Another control node's key (a
    /// Node's own, so it passes the key check) makes none of them, nor does a worker's; and what the
    /// CronJob's template or the claim's size does not say is refused from the leader too.
    #[test]
    fn own_writes_signed_are_the_work_of_the_node_that_does_it() {
        let ca = pki::Ca::create().unwrap();
        let (mut store, nodes) = required(&ca, &["a", "b", "w"]);
        let (a, b, w) = (&nodes[0], &nodes[1], &nodes[2]);
        let id = pki::fingerprint(&ca.cert).unwrap();
        store
            .apply(named("Node", "w", serde_json::json!({ "trust": "worker" })))
            .unwrap();
        let template = serde_json::json!({ "template": { "exec": [{ "name": "tick", "command": ["true"] }] } });
        let claim = named(
            "VolumeClaim",
            "db",
            serde_json::json!({ "size": "1Gi", "provision": true }),
        );
        let cron = named(
            "CronJob",
            "tick",
            serde_json::json!({ "schedule": "* * * * *", "job": template }),
        );
        store.apply(claim.clone()).unwrap();
        store.apply(cron.clone()).unwrap();
        let volume = |size: &str| {
            let mut volume = crate::volumes::made_for(&claim, "b");
            volume.spec["size"] = size.into();
            volume
        };
        let job = |spec: serde_json::Value| {
            let mut job = crate::cron::job_for(&cron, "tick-1".into());
            job.spec = spec;
            job
        };
        let secret = || {
            resource(serde_json::json!({
                "apiVersion": kith_api::API_VERSION, "kind": "Secret",
                "metadata": { "name": "acme-account", "namespace": "kith-system" }, "spec": { "data": {} },
            }))
        };
        let admitted = |store: &Store, me: &pki::Identity, command: Command| {
            let entry = sign(me, &id, &command).unwrap();
            crate::access_sign::admit(store, &id, &entry, kith_store::node_id("a"))
        };
        let writes = [
            apply(vec![volume("1Gi")]),
            apply(vec![job(template.clone())]),
            apply(vec![secret()]),
        ];
        for command in &writes {
            assert_eq!(admitted(&store, a, command.clone()), Ok(()), "{command:?}");
            let said = admitted(&store, b, command.clone()).unwrap_err();
            assert!(
                said.contains("asks for it"),
                "another control node: {command:?}: {said}"
            );
            let said = admitted(&store, w, command.clone()).unwrap_err();
            assert!(said.contains("not a control node"), "a worker: {command:?}: {said}");
        }
        // The leader's Job is its CronJob's template, and its Volume the claim's size.
        let other = serde_json::json!({ "template": { "exec": [{ "name": "x", "command": ["rm"] }] } });
        assert!(admitted(&store, a, apply(vec![job(other)])).is_err());
        assert!(admitted(&store, a, apply(vec![volume("9Gi")])).is_err());
        // A Secret that is there is overwritten by the leader (it renews), never by another node ...
        store.apply(secret()).unwrap();
        assert_eq!(admitted(&store, a, apply(vec![secret()])), Ok(()));
        assert!(admitted(&store, b, apply(vec![secret()])).is_err());
        // ... unless that one serves ingress, and orders its own certificates.
        let status =
            serde_json::json!({ "certificate": pki::print_of(&b.cert).unwrap(), "serves": { "ingress": true } });
        store.set_status("Node/b", Some(status)).unwrap();
        assert!(
            admitted(&store, b, apply(vec![secret()])).is_err(),
            "its own status says it: the admin did not"
        );
        store
            .apply(named("Node", "b", serde_json::json!({ "ingress": true })))
            .unwrap();
        assert!(
            admitted(&store, b, apply(vec![secret()])).is_err(),
            "the account that is there is the leader's"
        );
        assert!(admitted(&store, b, apply(vec![volume("1Gi")])).is_err());
    }

    /// Asked as each entry of the log is (`access_sign::hook`, with the id of the node that wrote
    /// the entry), the work is the leader's whoever leads: after a change of leader the new one's
    /// Volume is let in and the old one's is not. And what is there is never made again, a fresh
    /// signature or not; a Volume or Job that is more than what the leader would make is refused.
    #[test]
    fn own_writes_signed_are_asked_of_the_node_that_wrote_the_entry() {
        let ca = pki::Ca::create().unwrap();
        let (mut store, nodes) = required(&ca, &["a", "b"]);
        let (a, b) = (&nodes[0], &nodes[1]);
        let id = pki::fingerprint(&ca.cert).unwrap();
        let audit = std::sync::Arc::new(crate::audit::Audit::new(
            std::env::temp_dir().join(format!("kith-own-writes-{}.log", std::process::id())),
        ));
        let hook = crate::access_sign::hook(Some(id.clone()), audit);
        let claim = named(
            "VolumeClaim",
            "db",
            serde_json::json!({ "size": "1Gi", "provision": true, "shared": true }),
        );
        store.apply(claim.clone()).unwrap();
        let template = serde_json::json!({ "template": { "exec": [{ "name": "tick", "command": ["true"] }] } });
        let cron = named(
            "CronJob",
            "tick",
            serde_json::json!({ "schedule": "* * * * *", "job": template }),
        );
        store.apply(cron.clone()).unwrap();
        let (a_id, b_id) = (kith_store::node_id("a"), kith_store::node_id("b"));
        let volume = crate::volumes::made_for(&claim, "b");
        let job = crate::cron::job_for(&cron, "tick-1".into());
        let entry = |me: &pki::Identity, resource: &Resource| sign(me, &id, &apply(vec![resource.clone()])).unwrap();

        // Led by a: a's is let in, b's is not (b is a control node, and its key is its own).
        assert!(hook(&store, &entry(b, &volume), a_id).is_err());
        assert!(hook(&store, &entry(b, &job), a_id).is_err());
        assert!(hook(&store, &entry(a, &volume), a_id).is_ok());
        // Led by b since: the other way about.
        assert!(hook(&store, &entry(a, &volume), b_id).is_err());
        assert!(hook(&store, &entry(a, &job), b_id).is_err());
        assert!(hook(&store, &entry(b, &volume), b_id).is_ok());

        // More than the leader makes: a label, an annotation, a size or a name the claim does not say.
        let mut more = vec![volume.clone(), volume.clone(), volume.clone(), job.clone(), job.clone()];
        more[0].metadata.labels.insert("x".into(), "y".into());
        more[1].metadata.annotations.insert("x".into(), "y".into());
        more[2].spec["shared"] = false.into();
        more[3].metadata.labels.insert("x".into(), "y".into());
        more[4].metadata.name = "tick-soon".into();
        for resource in &more {
            assert!(hook(&store, &entry(a, resource), a_id).is_err(), "{resource:?}");
        }

        // What is there is not made again: its claim's or CronJob's Volume or Job, signed afresh.
        for resource in [&volume, &job] {
            kith_store::run(&mut store, apply(vec![resource.clone()])).unwrap();
            let said = hook(&store, &entry(a, resource), a_id).unwrap_err().to_string();
            assert!(said.contains("asks for it"), "{said}");
        }
    }

    /// A node that is not the leader orders its own certificates only where its own Node says it
    /// serves ingress and the admin's `spec.ingress` says so too, and the ACME account that is there
    /// is the leader's to overwrite alone.
    #[test]
    fn own_writes_signed_secrets_of_a_node_that_serves_ingress_need_the_admins_word() {
        let ca = pki::Ca::create().unwrap();
        let (mut store, nodes) = required(&ca, &["a", "b"]);
        let (a, b) = (&nodes[0], &nodes[1]);
        let id = pki::fingerprint(&ca.cert).unwrap();
        let account = resource(serde_json::json!({
            "apiVersion": kith_api::API_VERSION, "kind": "Secret",
            "metadata": { "name": "acme-account", "namespace": "kith-system" }, "spec": { "data": {} },
        }));
        let admitted = |store: &Store, me: &pki::Identity| {
            let entry = sign(me, &id, &apply(vec![account.clone()])).unwrap();
            crate::access_sign::admit(store, &id, &entry, kith_store::node_id("a"))
        };
        let status =
            serde_json::json!({ "certificate": pki::print_of(&b.cert).unwrap(), "serves": { "ingress": true } });
        store.set_status("Node/b", Some(status)).unwrap();
        // Its own status says it serves ingress: not enough.
        assert!(admitted(&store, b).unwrap_err().contains("asks for it"));
        // The admin says so too: the account it has none of is made.
        store
            .apply(named("Node", "b", serde_json::json!({ "ingress": true })))
            .unwrap();
        assert_eq!(admitted(&store, b), Ok(()));
        // Made: from then on the leader's to overwrite alone.
        kith_store::run(&mut store, apply(vec![account.clone()])).unwrap();
        assert!(admitted(&store, b).unwrap_err().contains("asks for it"));
        assert_eq!(admitted(&store, a), Ok(()));
    }

    /// A node-signed write never changes access, whatever owner it names (T-1084): a Release, a
    /// Source or a controller's resource is held to what its writer may, and a writer who may write
    /// a Role may not have a taken leader write one for it. Nor does a node-signed Delete take one away.
    #[test]
    fn own_writes_signed_owned_writes_never_change_access_whatever_the_owner() {
        use crate::releases::{OWNER, bob_is, bobs_note};
        let ca = pki::Ca::create().unwrap();
        let (mut store, nodes) = required(&ca, &["a"]);
        let id = pki::fingerprint(&ca.cert).unwrap();
        let note = bobs_note(0);
        for resource in kith_api::Resource::from_source(&format!(
            "apiVersion: kith.dev/v1\nkind: Role\nmetadata: {{ name: bob }}\nspec: {{ rules: [\
             {{ kinds: [ConfigMap], verbs: [apply, delete], namespaces: [shop] }}, \
             {{ kinds: [Role, RoleBinding, Identity, KindDefinition, Cluster], verbs: [apply, delete] }}] }}\n---\n\
             apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {{ name: bob }}\nspec: {{ role: bob, subjects: [bob] }}\n"
        ))
        .unwrap()
        {
            store.apply(resource.unwrap()).unwrap();
        }
        bob_is(&mut store, 0);
        for resource in kith_api::Resource::from_source(&format!(
            "apiVersion: kith.dev/v1\nkind: Release\nmetadata: {{ name: mine, namespace: shop, {note} }}\n\
             spec: {{ package: {{ name: maps }} }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Source\nmetadata: {{ name: repo, namespace: shop, {note} }}\n\
             spec: {{ git: {{ url: 'https://example.org/a.git' }} }}\n---\n\
             apiVersion: kith.dev/v1\nkind: KindDefinition\nmetadata: {{ name: gameserver, {note} }}\n\
             spec: {{ group: games.example.com, version: v1, kind: GameServer, schema: {{ type: object }} }}\n"
        ))
        .unwrap()
        {
            store.apply(resource.unwrap()).unwrap();
        }
        let leader = kith_store::node_id("a");
        let admitted = |store: &Store, command: &Command| {
            let entry = sign(&nodes[0], &id, command).unwrap();
            crate::access_sign::admit(store, &id, &entry, leader)
        };
        let made = |owner: &str, kind: &str, name: &str| {
            let mut made = named(kind, name, serde_json::json!({ "data": {} }));
            made.metadata.namespace = (!["Cluster", "Role", "RoleBinding", "Identity", "KindDefinition"]
                .contains(&kind))
            .then(|| "shop".to_string());
            made.metadata.annotations.insert(OWNER.into(), owner.into());
            made
        };
        // (The same write of a ConfigMap is what the owner's writer may: the control.)
        for owner in ["Release/shop/mine", "Source/shop/repo", "GameServer/play/one"] {
            let ok = apply(vec![made(owner, "ConfigMap", "c")]);
            if owner != "GameServer/play/one" {
                assert_eq!(admitted(&store, &ok), Ok(()), "{owner}");
            }
            for kind in ["Role", "RoleBinding", "Identity", "KindDefinition", "Cluster"] {
                let access = made(owner, kind, "x");
                let said = admitted(&store, &apply(vec![access.clone()])).unwrap_err();
                assert!(said.contains("changes access"), "{owner} {kind}: {said}");
                // Mixed with what it may write, still refused: one thing refused is the entry refused.
                let mixed = apply(vec![made(owner, "ConfigMap", "c"), access.clone()]);
                assert!(admitted(&store, &mixed).is_err(), "{owner} {kind}");
                // Nor taken away, there or not (whoever owns it, or its owner is gone).
                let said = admitted(&store, &Command::Delete { key: access.key() }).unwrap_err();
                assert!(said.contains("changes access"), "{owner} {kind}: {said}");
            }
        }
    }

    /// A Package the registry fetched is of the name and version a qualifying Release asks for, and
    /// does not overwrite one that is another Repository's, or that nobody fetched (T-1084).
    #[test]
    fn own_writes_signed_fetched_package_is_the_one_a_release_asks_for_and_no_ones_else() {
        use crate::releases::{REPOSITORY, bob_is, bobs_note};
        let ca = pki::Ca::create().unwrap();
        let (mut store, nodes) = required(&ca, &["a"]);
        let id = pki::fingerprint(&ca.cert).unwrap();
        for resource in kith_api::Resource::from_source(&format!(
            "apiVersion: kith.dev/v1\nkind: Role\nmetadata: {{ name: bob }}\nspec: {{ rules: [\
             {{ kinds: [Package], verbs: [apply] }}] }}\n---\n\
             apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {{ name: bob }}\nspec: {{ role: bob, subjects: [bob] }}\n"
        ))
        .unwrap()
        {
            store.apply(resource.unwrap()).unwrap();
        }
        bob_is(&mut store, 0);
        let note = bobs_note(0);
        for resource in kith_api::Resource::from_source(&format!(
            "apiVersion: kith.dev/v1\nkind: Release\nmetadata: {{ name: mine, namespace: shop, {note} }}\n\
             spec: {{ package: {{ name: maps, repo: hub, version: '1.0.0' }} }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Repository\nmetadata: {{ name: hub }}\n\
             spec: {{ url: 'https://example.org/r' }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Repository\nmetadata: {{ name: other }}\n\
             spec: {{ url: 'https://example.org/o' }}\n"
        ))
        .unwrap()
        {
            store.apply(resource.unwrap()).unwrap();
        }
        let leader = kith_store::node_id("a");
        let admitted = |store: &Store, package: &kith_api::Resource| {
            let entry = sign(&nodes[0], &id, &apply(vec![package.clone()])).unwrap();
            crate::access_sign::admit(store, &id, &entry, leader)
        };
        let origin = crate::releases::origin(&store, "hub").unwrap();
        let package = |name: &str, version: &str, origin: &str| {
            let mut package = named("Package", name, serde_json::json!({ "version": version, "files": {} }));
            package.metadata.namespace = None;
            package.metadata.annotations.insert(REPOSITORY.into(), origin.into());
            package
        };
        // The control: what the Release asks of the Repository it names.
        assert_eq!(admitted(&store, &package("maps-1.0.0", "1.0.0", &origin)), Ok(()));
        // Another name, or a version the Release does not ask for, is nothing it wants.
        for (name, version) in [
            ("other-1.0.0", "1.0.0"),
            ("maps-2.0.0", "2.0.0"),
            ("maps-1.0.0", "9.9.9"),
        ] {
            let said = admitted(&store, &package(name, version, &origin)).unwrap_err();
            assert!(said.contains("asks that Repository"), "{name} {version}: {said}");
        }
        // Over a Package that is there: its own Repository's, again, is the registry's re-fetch;
        // nobody's, or another Repository's, is not its to overwrite.
        let mut held = package("maps-1.0.0", "1.0.0", "hub@old");
        store.apply(held.clone()).unwrap();
        assert_eq!(admitted(&store, &package("maps-1.0.0", "1.0.0", &origin)), Ok(()));
        held.metadata.annotations.insert(REPOSITORY.into(), "other@old".into());
        store.apply(held.clone()).unwrap();
        let said = admitted(&store, &package("maps-1.0.0", "1.0.0", &origin)).unwrap_err();
        assert!(said.contains("not what"), "{said}");
        held.metadata.annotations.remove(REPOSITORY);
        store.apply(held).unwrap();
        let said = admitted(&store, &package("maps-1.0.0", "1.0.0", &origin)).unwrap_err();
        assert!(said.contains("not what"), "{said}");
    }

    /// A node-signed Delete of what names an owner that is not there takes it away only where a
    /// controller could have left it: an owner of a kind a Release, a Source or a KindDefinition
    /// makes things of. A resource that merely carries the annotation of anything else stays (T-1084).
    #[test]
    fn own_writes_signed_deletes_of_a_missing_owners_leftovers_are_a_controllers_kinds_only() {
        use crate::releases::OWNER;
        let ca = pki::Ca::create().unwrap();
        let (mut store, nodes) = required(&ca, &["a"]);
        let id = pki::fingerprint(&ca.cert).unwrap();
        for resource in kith_api::Resource::from_source(
            "apiVersion: kith.dev/v1\nkind: KindDefinition\nmetadata: { name: gameserver }\n\
             spec: { group: games.example.com, version: v1, kind: GameServer, schema: { type: object } }\n",
        )
        .unwrap()
        {
            store.apply(resource.unwrap()).unwrap();
        }
        let leader = kith_store::node_id("a");
        let mut deleted = |owner: &str| {
            let mut held = named("ConfigMap", "c", serde_json::json!({ "data": {} }));
            held.metadata.annotations.insert(OWNER.into(), owner.into());
            store.apply(held.clone()).unwrap();
            let entry = sign(&nodes[0], &id, &Command::Delete { key: held.key() }).unwrap();
            let said = crate::access_sign::admit(&store, &id, &entry, leader);
            store.delete(&held.key()).unwrap();
            said
        };
        for owner in ["Release/shop/gone", "Source/shop/gone", "GameServer/play/gone"] {
            assert_eq!(deleted(owner), Ok(()), "{owner}");
        }
        for owner in [
            "ConfigMap/default/gone",
            "Workload/default/web",
            "Node/gone",
            "Secret/kith-system/acme-account",
        ] {
            assert!(deleted(owner).is_err(), "{owner}");
        }
    }

    /// A try again of a write whose answer was lost (`raft.rs` `write_as` signs at each try) is
    /// signed with a nonce of its own: the first try's is taken, and the second is not refused for it.
    #[test]
    fn own_writes_signed_again_take_a_nonce_of_their_own() {
        let ca = pki::Ca::create().unwrap();
        let (mut store, nodes) = required(&ca, &["a"]);
        let id = pki::fingerprint(&ca.cert).unwrap();
        let secret = resource(serde_json::json!({
            "apiVersion": kith_api::API_VERSION, "kind": "Secret",
            "metadata": { "name": "acme-account", "namespace": "kith-system" }, "spec": { "data": {} },
        }));
        let command = apply(vec![secret]);
        let (first, again) = (
            sign(&nodes[0], &id, &command).unwrap(),
            sign(&nodes[0], &id, &command).unwrap(),
        );
        let leader = kith_store::node_id("a");
        for entry in [&first, &again] {
            assert_eq!(crate::access_sign::admit(&store, &id, entry, leader), Ok(()));
            kith_store::run(&mut store, entry.clone()).unwrap();
        }
        assert!(
            crate::access_sign::admit(&store, &id, &first, leader).is_err(),
            "the same nonce twice"
        );
    }

    /// The CA node registers a joiner, signed: its address, raft id and certificate, once. Another
    /// control node's key is no more than its own: it holds no CA.
    #[test]
    fn own_writes_signed_register_of_a_joiner_is_the_ca_nodes_alone() {
        let ca = pki::Ca::create().unwrap();
        let (mut store, nodes) = required(&ca, &["a", "b"]);
        let id = pki::fingerprint(&ca.cert).unwrap();
        store
            .apply(named("Node", "j", serde_json::json!({ "trust": "worker" })))
            .unwrap();
        let joined = serde_json::json!({
            "address": "[::1]:1", "raftId": kith_store::node_id("j").to_string(), "certificate": "00",
        });
        let register = Command::Patch {
            statuses: vec![("Node/j".into(), joined.as_object().unwrap().clone())],
        };
        let leader = kith_store::node_id("a");
        let admitted = |me: &pki::Identity| {
            let entry = sign(me, &id, &register).unwrap();
            crate::access_sign::admit(&store, &id, &entry, leader)
        };
        assert_eq!(admitted(&nodes[0]), Ok(()));
        assert!(admitted(&nodes[1]).is_err());
        assert!(crate::access_sign::admit(&store, &id, &register, leader).is_err());
    }

    /// What a Release, a Source, a wasm controller, the registry and an update write, signed by the
    /// leader, is held at apply to what its owner's writer may (`releases::writer_may`): on every
    /// node alike, a write of one who has no right is refused, and a node that does not lead
    /// writes none of it. One table: each kind of owner, what is made, and what is taken away.
    #[test]
    fn own_writes_signed_owned_writes_are_held_to_writer_may_at_apply() {
        use crate::releases::{OWNER, REPOSITORY, bob_is, bobs_note};
        let ca = pki::Ca::create().unwrap();
        let (mut store, nodes) = required(&ca, &["a", "b"]);
        let id = pki::fingerprint(&ca.cert).unwrap();
        let note = bobs_note(0);
        fn source(store: &mut Store, yaml: String) {
            for resource in kith_api::Resource::from_source(&yaml).unwrap() {
                store.apply(resource.unwrap()).unwrap();
            }
        }
        // bob may apply and delete a ConfigMap in shop and play, a Package anywhere, and nothing else.
        source(
            &mut store,
            "apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: bob }\nspec: { rules: [\
             { kinds: [ConfigMap], verbs: [apply, delete], namespaces: [shop, play] },\
             { kinds: [Package], verbs: [apply] }] }\n---\n\
             apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: bob }\nspec: { role: bob, subjects: [bob] }\n"
                .into(),
        );
        bob_is(&mut store, 0);
        source(
            &mut store,
            format!(
                "apiVersion: kith.dev/v1\nkind: Release\nmetadata: {{ name: mine, namespace: shop, {note} }}\n\
             spec: {{ package: {{ name: maps, repo: hub }} }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Release\nmetadata: {{ name: nobody, namespace: shop }}\n\
             spec: {{ package: {{ name: maps, repo: cold }} }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Source\nmetadata: {{ name: repo, namespace: shop, {note} }}\n\
             spec: {{ git: {{ url: 'https://example.org/a.git' }} }}\n---\n\
             apiVersion: kith.dev/v1\nkind: KindDefinition\nmetadata: {{ name: gameserver, {note} }}\n\
             spec: {{ group: games.example.com, version: v1, kind: GameServer, schema: {{ type: object }} }}\n---\n\
             apiVersion: games.example.com/v1\nkind: GameServer\nmetadata: {{ name: one, namespace: play }}\n\
             spec: {{ map: dust }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Repository\nmetadata: {{ name: hub }}\n\
             spec: {{ url: 'https://example.org/r' }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Repository\nmetadata: {{ name: cold }}\n\
             spec: {{ url: 'https://example.org/c' }}\n"
            ),
        );
        let made = |owner: &str, kind: &str, namespace: &str, name: &str| {
            let mut made = named(kind, name, serde_json::json!({ "data": {} }));
            made.metadata.namespace = Some(namespace.into());
            made.metadata.annotations.insert(OWNER.into(), owner.into());
            made
        };
        let leader = kith_store::node_id("a");
        let admitted = |store: &Store, me: &pki::Identity, command: &Command| {
            let entry = sign(me, &id, command).unwrap();
            crate::access_sign::admit(store, &id, &entry, leader)
        };
        let (a, b) = (&nodes[0], &nodes[1]);
        let owners = [
            ("Release/shop/mine", "shop"),
            ("Source/shop/repo", "shop"),
            ("GameServer/play/one", "play"),
        ];
        for (owner, namespace) in owners {
            // What its writer may make, the leader writes; another control node does not.
            let config = made(owner, "ConfigMap", namespace, "c");
            let ok = apply(vec![config.clone()]);
            assert_eq!(admitted(&store, a, &ok), Ok(()), "{owner}");
            assert!(admitted(&store, b, &ok).unwrap_err().contains("leader"), "{owner}");
            // What it may not (no Secret, no Workload; a Role is no node's to sign at all, below).
            for kind in ["Secret", "Workload"] {
                let said = admitted(&store, a, &apply(vec![made(owner, kind, namespace, "x")])).unwrap_err();
                assert!(said.contains("bob may not apply"), "{owner} {kind}: {said}");
            }
            // All or nothing: one thing it may not spoils the rest.
            let mixed = apply(vec![config.clone(), made(owner, "Secret", namespace, "x")]);
            assert!(admitted(&store, a, &mixed).is_err(), "{owner}");
            // Taking away: of what it made, where its writer may delete; the stray of an owner that
            // is gone goes too (the leftovers of a Release deleted), and no other is taken.
            store.apply(config.clone()).unwrap();
            let delete = |key: &str| Command::Delete { key: key.into() };
            let key = format!("ConfigMap/{namespace}/c");
            assert_eq!(admitted(&store, a, &delete(&key)), Ok(()), "{owner}");
            assert!(admitted(&store, b, &delete(&key)).is_err(), "{owner}");
            let mut secret = made(owner, "Secret", namespace, "s");
            secret.metadata.annotations.insert(OWNER.into(), owner.into());
            store.apply(secret).unwrap();
            let said = admitted(&store, a, &delete(&format!("Secret/{namespace}/s"))).unwrap_err();
            assert!(said.contains("bob may not delete Secret"), "{owner}: {said}");
            // Over another's: a resource that is there and not this owner's is not its to overwrite.
            let mut other = config.clone();
            other
                .metadata
                .annotations
                .insert(OWNER.into(), "Release/shop/nobody".into());
            store.apply(other).unwrap();
            let said = admitted(&store, a, &ok).unwrap_err();
            assert!(said.contains("not what"), "{owner}: {said}");
            store.delete(&key).unwrap();
            store.delete(&format!("Secret/{namespace}/s")).unwrap();
        }
        // An owner with nobody written down as its writer makes nothing; one that is not there either.
        for owner in ["Release/shop/nobody", "Release/shop/gone"] {
            let said = admitted(&store, a, &apply(vec![made(owner, "ConfigMap", "shop", "c")])).unwrap_err();
            assert!(
                said.contains("nobody is written down") || said.contains("not there"),
                "{owner}: {said}"
            );
        }
        let stray = made("Release/shop/gone", "ConfigMap", "shop", "old");
        store.apply(stray.clone()).unwrap();
        assert_eq!(admitted(&store, a, &Command::Delete { key: stray.key() }), Ok(()));
        // What the registry fetched: a Package of a Repository that a Release whose writer may apply
        // Packages names. (One only a Release with nobody written down names, is not fetched.)
        let origin = crate::releases::origin(&store, "hub").unwrap();
        let mut package = named(
            "Package",
            "maps-1.0.0",
            serde_json::json!({ "version": "1.0.0", "files": {} }),
        );
        package.metadata.namespace = None;
        package.metadata.annotations.insert(REPOSITORY.into(), origin);
        let ok = apply(vec![package.clone()]);
        assert_eq!(admitted(&store, a, &ok), Ok(()));
        assert!(admitted(&store, b, &ok).is_err());
        let cold = crate::releases::origin(&store, "cold").unwrap();
        package.metadata.annotations.insert(REPOSITORY.into(), cold);
        assert!(
            admitted(&store, a, &apply(vec![package.clone()])).is_err(),
            "no Release that may asks for it"
        );
        package.metadata.annotations.insert(REPOSITORY.into(), "hub@00".into());
        assert!(
            admitted(&store, a, &apply(vec![package.clone()])).is_err(),
            "not the Repository's own"
        );
        package
            .metadata
            .annotations
            .insert(REPOSITORY.into(), "nowhere@00".into());
        assert!(
            admitted(&store, a, &apply(vec![package])).is_err(),
            "no such Repository"
        );
        // What an update writes: a Node's cordon and nothing else of it.
        source(
            &mut store,
            "apiVersion: kith.dev/v1\nkind: Node\nmetadata: { name: w }\nspec: { trust: worker }\n".into(),
        );
        let mut node = store.get("Node/w").unwrap().clone();
        let cordoned = crate::update::cordoned_spec(&node.spec, true).unwrap();
        node.spec = cordoned;
        let ok = apply(vec![node.clone()]);
        assert_eq!(admitted(&store, a, &ok), Ok(()));
        assert!(admitted(&store, b, &ok).is_err());
        node.spec["trust"] = "control".into();
        assert!(admitted(&store, a, &apply(vec![node])).is_err(), "more than a cordon");
    }
}
