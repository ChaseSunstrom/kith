//! A Workload that runs as an Identity (`spec.identity`): the node that runs it makes a key
//! for the pod's life, and the node that holds the cluster CA key signs a certificate for
//! its public half, good for calling the API for two hours ([`crate::pki::WORKLOAD_LIFE`]).
//!
//! The CA holder checks, in its own store, each time it signs (the first time and at every
//! renewal alike): the node that asks is the one its certificate on the link says (never one
//! the request names) and its Node is there; the Workload is placed on that node and says the
//! Identity; the Identity names the Workload's namespace (and it, where it names any) and has
//! no key of its own. It signs one a minute at most for one replica on one node, and writes
//! each in the audit log. It is sent a public key and never makes a private one.
//!
//! On the node that runs the pod the files are in memory ([`MOUNTED_AT`] in each container,
//! a copy of its own, its user's alone): `ca.crt`, `tls.crt`, `tls.key` and `address`, the
//! API's. They are made before the first container starts, or it does not start; the
//! certificate is made again at half its life, by a rename, with the same key; where the CA
//! holder says the pod may no longer have one, the certificate is taken out of the files and
//! asked for again in ten minutes.

use crate::Shared;
use crate::cluster::Peer;
use axum::extract::{ConnectInfo, Path as Named, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kith_api::store::Store;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

/// One certificate in so many seconds, at most, for one replica of a Workload on one node.
const AT_MOST_EVERY: u64 = 60;

/// When each (node, Workload, replica) was last given one, for a minute.
// ponytail: in the CA holder's memory: a restart lets each ask once more.
static GIVEN: Mutex<BTreeMap<(String, String), u64>> = Mutex::new(BTreeMap::new());

/// Where a pod's files are in each of its containers.
pub const MOUNTED_AT: &str = "/run/kith/identity";
/// How often the files are looked at, to be made again or taken away.
const ROUND: Duration = Duration::from_secs(60);
/// How long a pod the CA holder refused waits before it is asked for again.
const REFUSED_FOR: Duration = Duration::from_secs(600);

/// The Identity the Workload `namespace`/`name` runs as, if the node `node` may have a
/// certificate for it now (for its replica `replica`, where one is named); else why not.
pub fn may_have(
    store: &Store,
    node: &str,
    (namespace, name): (&str, &str),
    replica: Option<&str>,
) -> Result<String, String> {
    if store.get(&format!("Node/{node}")).is_none() {
        return Err(format!("{node} is no node of this cluster"));
    }
    let key = format!("Workload/{namespace}/{name}");
    let workload = store.get(&key).ok_or(format!("there is no {key}"))?;
    let nodes = workload.status.as_ref().and_then(|status| status["nodes"].as_object());
    let placed = nodes.is_some_and(|nodes| match replica {
        Some(replica) => nodes.get(replica).is_some_and(|placed| placed == node),
        None => nodes.values().any(|placed| placed == node),
    });
    if !placed {
        let which = replica
            .map(|replica| format!(" (replica {replica})"))
            .unwrap_or_default();
        return Err(format!("{key}{which} is not placed on node {node}"));
    }
    let identity = workload.spec["identity"].as_str();
    let identity = identity.ok_or(format!("{key} runs as no Identity"))?;
    crate::access::runs_as(store, std::slice::from_ref(workload))?;
    // (The store refuses an Identity with both; one kept from before is not believed either.)
    let held = store.get(&format!("Identity/{identity}"));
    if held.is_some_and(|held| !held.spec["publicKey"].is_null()) {
        return Err(format!("Identity {identity} has a publicKey: no Workload runs as it"));
    }
    Ok(identity.into())
}

/// Whether a Workload's certificate (its Identity, Workload and node) stands now: checked
/// on each request, so it stops the moment the Identity's word is withdrawn, the Workload is
/// gone, moved or runs as another, or the Identity or the Node is gone.
pub fn stands(store: &Store, identity: &str, namespace: &str, name: &str, node: &str) -> Result<(), String> {
    let now = may_have(store, node, (namespace, name), None);
    let now = now.map_err(|why| format!("this certificate stands for nothing now: {why}"))?;
    match now == identity {
        true => Ok(()),
        false => Err(format!(
            "this certificate stands for nothing now: Workload/{namespace}/{name} runs as {now}, not {identity}"
        )),
    }
}

/// Whether `node` may be given one more for `what` (a Workload's replica) at `now` (seconds).
/// A taken node can neither fill the audit log nor mint without end.
fn due(node: &str, what: &str, now: u64) -> bool {
    let mut given = GIVEN.lock().expect("nothing panics holding this");
    given.retain(|_, at| now < *at + AT_MOST_EVERY);
    !given.contains_key(&(node.to_string(), what.to_string()))
}

/// One was given: no more for a minute.
fn spend(node: &str, what: &str, now: u64) {
    let mut given = GIVEN.lock().expect("nothing panics holding this");
    given.insert((node.to_string(), what.to_string()), now);
}

/// `POST /v1/workload-certificate/NS/NAME/REPLICA` (members only): on the node that holds
/// the CA key, a certificate (PEM) for the public key sent (P-256, SubjectPublicKeyInfo DER),
/// for that replica of the Workload NS/NAME on the node that asks, as the Identity it runs as.
pub async fn issue(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    Named((namespace, name, replica)): Named<(String, String, String)>,
    key: axum::body::Bytes,
) -> Response {
    let Some(crate::pki::Subject::Node(node, ..)) = &peer.subject else {
        return (StatusCode::FORBIDDEN, "this is for the cluster's nodes").into_response();
    };
    let Some(ca) = shared.cluster.as_ref().and_then(|cluster| cluster.ca.as_ref()) else {
        return (StatusCode::CONFLICT, crate::cluster::CA_ELSEWHERE).into_response();
    };
    let now = kith_api::store::now();
    let checked = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        may_have(&state.store, node, (&namespace, &name), Some(&replica))
    };
    let workload = format!("Workload/{namespace}/{name}");
    let what = format!("{workload}#{replica}");
    // (Not written down: a node that asks too often is not given the audit log to fill.)
    if checked.is_ok() && !due(node, &what, now) {
        let why = "one certificate a minute for one replica on one node";
        return (StatusCode::TOO_MANY_REQUESTS, why).into_response();
    }
    let signed = checked.and_then(|identity| {
        let cert = ca.issue_workload(&identity, (&namespace, &name), node, &key, now)?;
        Ok((identity, cert))
    });
    let who = crate::access::Caller::Node(node.clone());
    match signed {
        Ok((identity, cert)) => {
            spend(node, &what, now);
            shared
                .audit
                .record(&who, "certificate", vec![what, format!("Identity/{identity}")], Ok(()));
            cert.into_response()
        }
        Err(why) => {
            shared.audit.record(&who, "certificate", vec![what], Err(why.clone()));
            (StatusCode::FORBIDDEN, why).into_response()
        }
    }
}

// ---- On the node that runs the pod ----
//
// Under the pod's directory in memory: `identity.key` (its key, made here, kithd's alone),
// `identity.crt` and `identity.address` (the last certificate, and where it was asked), and
// `identity/UNIT/` for each container: the four files, that container's user's.

/// Why a node was not given a certificate: the CA holder refused (the pod may not have one),
/// or it could not be asked or did not sign this time.
#[derive(Debug)]
enum Unmade {
    Refused(String),
    Failed(String),
}

/// The Workload a pod (`w_NS_NAME_REPLICA`, `controller::pod_of`) is of, and its replica.
/// Names have no `_`.
fn workload_of(pod: &str) -> Option<(&str, &str, &str)> {
    let (rest, replica) = pod.strip_prefix("w_")?.rsplit_once('_')?;
    let (namespace, name) = rest.split_once('_')?;
    Some((namespace, name, replica))
}

/// Whether the pod's certificate (in `pod`, its directory) was made less than half its life
/// ago, for the Identity `identity`.
fn fresh(pod: &Path, identity: &str) -> bool {
    let crt = pod.join("identity.crt");
    let made = std::fs::metadata(&crt).and_then(|file| file.modified());
    let young = made.is_ok_and(|made| made.elapsed().unwrap_or_default() < crate::pki::WORKLOAD_LIFE / 2);
    let pem = std::fs::read(&crt).unwrap_or_default();
    let der = rustls::pki_types::pem::PemObject::from_pem_slice(&pem);
    let named = der
        .ok()
        .and_then(|der: rustls::pki_types::CertificateDer| crate::pki::subject_of(&der));
    young && matches!(named, Some(crate::pki::Subject::Workload { identity: was, .. }) if was == identity)
}

/// Ask the CA holder to sign for `public` as `replica` of the Workload `namespace`/`name`
/// on this node: the certificate, and the address it was asked at (the API's, for the pod).
async fn signed(
    shared: &Shared,
    (namespace, name, replica): (&str, &str, &str),
    public: &[u8],
) -> Result<(String, String), Unmade> {
    let failed = |why: String| Unmade::Failed(why);
    let cluster = shared.cluster.as_ref();
    let cluster = cluster.ok_or(failed("this kithd is not part of a cluster".into()))?;
    let holder = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let holds = |node: &&kith_api::Resource| node.status.as_ref().is_some_and(|status| status["ca"] == true);
        let mut nodes = state.store.list(Some("Node"));
        nodes.find(holds).and_then(crate::view::Upstream::of)
    };
    let holder = holder.ok_or(failed("no node that holds the CA key is known".into()))?;
    let client = cluster.to(&holder).map_err(failed)?;
    let url = format!(
        "https://{}/v1/workload-certificate/{namespace}/{name}/{replica}",
        holder.address
    );
    let sent = client
        .post(url)
        .body(public.to_vec())
        .timeout(Duration::from_secs(10))
        .send();
    let answer = sent.await.map_err(|e| failed(format!("asking {}: {e}", holder.name)))?;
    let status = answer.status();
    let text = answer.text().await;
    let text = text.map_err(|e| failed(format!("reading {}: {e}", holder.name)))?;
    match status {
        StatusCode::OK => Ok((text, holder.address)),
        StatusCode::FORBIDDEN => Err(Unmade::Refused(text)),
        _ => Err(failed(format!("{} said {status}: {text}", holder.name))),
    }
}

/// The pod's key: the one it has, else one made now and kept (one key for the pod's life,
/// made here and never sent).
fn key_of(pod: &Path) -> Result<rcgen::KeyPair, String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = pod.join("identity.key");
    if let Ok(pem) = std::fs::read_to_string(&path) {
        return rcgen::KeyPair::from_pem(&pem).map_err(|e| format!("the pod's key: {e}"));
    }
    let key = rcgen::KeyPair::generate().map_err(|e| format!("making the pod's key: {e}"))?;
    let file = std::fs::File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path);
    let written = file.and_then(|mut file| file.write_all(key.serialize_pem().as_bytes()));
    written.map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(key)
}

/// Have the pod (`pod`, its directory) given a certificate again, with its key.
async fn make(shared: &Shared, pod: &Path, workload: (&str, &str, &str)) -> Result<(), Unmade> {
    let failed = |why: String| Unmade::Failed(why);
    let key = key_of(pod).map_err(failed)?;
    let public = rcgen::PublicKeyData::subject_public_key_info(&key);
    let (cert, address) = signed(shared, workload, &public).await?;
    // (The address first: a certificate there with no address would be taken as made.)
    let kept = crate::pki::write_whole(&pod.join("identity.address"), address.as_bytes())
        .and_then(|()| crate::pki::write_whole(&pod.join("identity.crt"), cert.as_bytes()));
    kept.map_err(|e| failed(format!("{}: {e}", pod.display())))
}

/// Write the container `unit`'s files of the pod `pod` (its directory) from what the pod has;
/// none where it has no certificate.
fn give(shared: &Shared, pod: &Path, unit: &str) -> std::io::Result<PathBuf> {
    let dir = pod.join("identity").join(unit);
    let read = |name: &str| std::fs::read_to_string(pod.join(name));
    let files = match (read("identity.crt"), read("identity.key"), read("identity.address")) {
        (Ok(cert), Ok(key), Ok(address)) => {
            let ca = shared
                .cluster
                .as_ref()
                .map(|cluster| cluster.me.ca.clone())
                .unwrap_or_default();
            BTreeMap::from([
                ("ca.crt".to_string(), ca),
                ("tls.crt".to_string(), cert),
                ("tls.key".to_string(), key),
                ("address".to_string(), address),
            ])
        }
        _ => BTreeMap::new(),
    };
    crate::files::write(&dir, &files, 0o400)?;
    Ok(dir)
}

/// The directory to mount at [`MOUNTED_AT`] in the container `unit` of the pod `pod`, a
/// replica of the Workload `namespace`/`name` that runs as `identity`: its files made if the
/// pod has no young certificate. Why not, if none could be made (the container is then not
/// started).
pub async fn files(shared: &Shared, pod: &str, unit: &str, identity: &str) -> Result<PathBuf, String> {
    let dir = crate::files::of(&crate::files::memory()?, pod).map_err(|e| e.to_string())?;
    let workload = workload_of(pod).ok_or(format!("{pod} is no Workload's pod"))?;
    if !fresh(&dir, identity) {
        let made = make(shared, &dir, workload).await;
        made.map_err(|(Unmade::Refused(why) | Unmade::Failed(why))| format!("no certificate for its Identity: {why}"))?;
    }
    give(shared, &dir, unit).map_err(|e| e.to_string())
}

/// Takes the certificate away from the pod (`pod`, its directory) and its containers: the
/// key stays, for when it may have one again.
fn take_away(shared: &Shared, pod: &Path) -> std::io::Result<()> {
    let _ = std::fs::remove_file(pod.join("identity.crt"));
    take_units(shared, pod)
}

/// Makes each pod's certificate again at half its life, or at once when its Workload runs as
/// another Identity now; takes it away when the CA holder refuses, and asks again in
/// [`REFUSED_FOR`].
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let mut refused: BTreeMap<String, std::time::Instant> = BTreeMap::new();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(ROUND) => {}
            _ = stopping.changed() => return,
        }
        let Some(memory) = crate::files::memory_dir() else {
            continue;
        };
        let pods = std::fs::read_dir(memory.join(crate::files::REPLICAS))
            .into_iter()
            .flatten()
            .flatten();
        let mut seen = std::collections::BTreeSet::new();
        for pod in pods {
            let (dir, pod) = (pod.path(), pod.file_name().to_string_lossy().into_owned());
            let Some(workload) = workload_of(&pod).filter(|_| dir.join("identity.key").exists()) else {
                continue;
            };
            seen.insert(pod.clone());
            let identity = {
                let state = shared.store.lock().expect("a handler panicked holding the store");
                let held = state.store.get(&format!("Workload/{}/{}", workload.0, workload.1));
                held.and_then(|held| held.spec["identity"].as_str().map(str::to_string))
            };
            if identity.as_deref().is_some_and(|identity| fresh(&dir, identity))
                || refused.get(&pod).is_some_and(|at| at.elapsed() < REFUSED_FOR)
            {
                continue;
            }
            match make(&shared, &dir, workload).await {
                Ok(()) => {
                    refused.remove(&pod);
                    if let Err(e) = take_units(&shared, &dir) {
                        eprintln!("kithd: {pod}: its containers' certificate files: {e}");
                    }
                }
                Err(Unmade::Refused(why)) => {
                    refused.insert(pod.clone(), std::time::Instant::now());
                    let gone = take_away(&shared, &dir).map_err(|e| e.to_string());
                    let gone = gone.err().map(|e| format!(" ({e})")).unwrap_or_default();
                    eprintln!("kithd: {pod}: its Identity's certificate is taken away{gone}: {why}");
                }
                Err(Unmade::Failed(why)) => eprintln!("kithd: {pod}: its certificate is not made again yet: {why}"),
            }
        }
        refused.retain(|pod, _| seen.contains(pod));
    }
}

/// Write each container's files of the pod (`pod`, its directory) again from what it has.
fn take_units(shared: &Shared, pod: &Path) -> std::io::Result<()> {
    for unit in std::fs::read_dir(pod.join("identity"))?.flatten() {
        give(shared, pod, &unit.file_name().to_string_lossy())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_api::Resource;

    fn store(yaml: &str) -> Store {
        let mut store = Store::default();
        for resource in Resource::from_source(yaml).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        store
    }

    const CLUSTER: &str = "
apiVersion: kith.dev/v1
kind: Node
metadata: {name: beta}
spec: {trust: worker}
---
apiVersion: kith.dev/v1
kind: Identity
metadata: {name: gateway}
spec: {workloads: [{namespace: web, names: [proxy]}]}
---
apiVersion: kith.dev/v1
kind: Workload
metadata: {name: proxy, namespace: web}
spec: {identity: gateway, template: {containers: [{name: c, image: i}]}}
";

    fn placed(mut store: Store, key: &str, node: &str) -> Store {
        let status = serde_json::json!({ "nodes": { "0": node } });
        store.set_status(key, Some(status)).unwrap();
        store
    }

    #[test]
    fn identity_issue_only_to_the_node_a_named_workload_is_placed_on() {
        let cluster = placed(store(CLUSTER), "Workload/web/proxy", "beta");
        assert_eq!(
            may_have(&cluster, "beta", ("web", "proxy"), Some("0")).unwrap(),
            "gateway"
        );
        // Only for the replica placed there.
        let said = may_have(&cluster, "beta", ("web", "proxy"), Some("1")).unwrap_err();
        assert!(said.contains("(replica 1) is not placed on node beta"), "{said}");

        let refused = |store: &Store, node: &str, name: &str, why: &str| {
            let said = may_have(store, node, ("web", name), Some("0")).unwrap_err();
            assert!(said.contains(why), "{said}");
        };
        // Another node, a node that is not there, a Workload that is not there.
        refused(&cluster, "alpha", "proxy", "alpha is no node");
        let mut other = placed(store(CLUSTER), "Workload/web/proxy", "beta");
        other
            .apply(
                Resource::from_source("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {name: gamma}\n")
                    .unwrap()
                    .remove(0)
                    .unwrap(),
            )
            .unwrap();
        refused(&other, "gamma", "proxy", "not placed on node gamma");
        refused(&cluster, "beta", "other", "there is no Workload/web/other");
        // Not placed yet.
        refused(&store(CLUSTER), "beta", "proxy", "not placed on node beta");
        // The Identity's word withdrawn, or the Identity gone.
        let mut withdrawn = cluster.clone();
        let mut identity = withdrawn.get("Identity/gateway").unwrap().clone();
        identity.spec = serde_json::json!({ "workloads": [{ "namespace": "shop" }] });
        withdrawn.apply(identity).unwrap();
        refused(&withdrawn, "beta", "proxy", "does not name namespace web");
        let mut gone = cluster.clone();
        gone.delete("Identity/gateway").unwrap();
        refused(&gone, "beta", "proxy", "there is no Identity gateway");
        // The Workload no longer says it.
        let mut unsaid = cluster.clone();
        let mut workload = unsaid.get("Workload/web/proxy").unwrap().clone();
        workload.spec.as_object_mut().unwrap().remove("identity");
        unsaid.apply(workload).unwrap();
        let unsaid = placed(unsaid, "Workload/web/proxy", "beta");
        refused(&unsaid, "beta", "proxy", "runs as no Identity");
    }

    #[test]
    fn workload_identity_stands_only_while_the_store_says_so() {
        let cluster = placed(store(CLUSTER), "Workload/web/proxy", "beta");
        stands(&cluster, "gateway", "web", "proxy", "beta").unwrap();
        let refused = |store: &Store, identity: &str, why: &str| {
            let said = stands(store, identity, "web", "proxy", "beta").unwrap_err();
            assert!(said.contains(why), "{said}");
        };
        // Taken somewhere and shown as another Identity's: the names are the CA's, but asked anyway.
        refused(&cluster, "admin", "runs as gateway, not admin");
        for (gone, why) in [
            ("Workload/web/proxy", "there is no Workload/web/proxy"),
            ("Identity/gateway", "there is no Identity gateway"),
            ("Node/beta", "beta is no node"),
        ] {
            let mut less = cluster.clone();
            less.delete(gone).unwrap();
            refused(&less, "gateway", why);
        }
        // Moved to another node: what was made for the first stands no more.
        refused(
            &placed(cluster.clone(), "Workload/web/proxy", "gamma"),
            "gateway",
            "not placed on node beta",
        );
        // The word withdrawn, then given back.
        let mut withdrawn = cluster.clone();
        let mut identity = withdrawn.get("Identity/gateway").unwrap().clone();
        let given = identity.spec.clone();
        identity.spec = serde_json::json!({ "workloads": [{ "namespace": "web", "names": ["other"] }] });
        withdrawn.apply(identity.clone()).unwrap();
        refused(&withdrawn, "gateway", "does not name Workload/web/proxy");
        (identity.spec, identity.metadata.revision) = (given, None);
        withdrawn.apply(identity).unwrap();
        stands(&withdrawn, "gateway", "web", "proxy", "beta").unwrap();
        // A key of its own cannot be added to it: the store refuses that.
        let mut keyed = withdrawn.get("Identity/gateway").unwrap().clone();
        keyed.spec["publicKey"] = "abc".into();
        assert!(withdrawn.apply(keyed).is_err());
    }

    #[test]
    fn workload_identity_files_are_found_by_their_pod() {
        assert_eq!(workload_of("w_web_proxy_0"), Some(("web", "proxy", "0")));
        assert_eq!(workload_of("w_web_my-proxy_12"), Some(("web", "my-proxy", "12")));
        assert_eq!(workload_of("j_web_once_0"), None);
        assert_eq!(workload_of("n_web_agent_3"), None);

        // A young certificate for the Identity the Workload runs as now is kept; none, an
        // old one, or one for another Identity is made again.
        let pod = std::env::temp_dir().join(format!("kith-identity-{}", std::process::id()));
        std::fs::create_dir_all(&pod).unwrap();
        assert!(!fresh(&pod, "reader"));
        let ca = crate::pki::Ca::create().unwrap();
        let key = key_of(&pod).unwrap();
        // (The same key every time it is asked for.)
        assert_eq!(key_of(&pod).unwrap().serialize_pem(), key.serialize_pem());
        let public = rcgen::PublicKeyData::subject_public_key_info(&key);
        let cert = ca.issue_workload("reader", ("web", "proxy"), "beta", &public, kith_api::store::now());
        std::fs::write(pod.join("identity.crt"), cert.unwrap()).unwrap();
        std::fs::write(pod.join("identity.address"), "10.0.0.7:7443").unwrap();
        assert!(fresh(&pod, "reader") && !fresh(&pod, "writer"));
        let file = std::fs::File::options()
            .write(true)
            .open(pod.join("identity.crt"))
            .unwrap();
        file.set_modified(std::time::SystemTime::now() - crate::pki::WORKLOAD_LIFE / 2)
            .unwrap();
        assert!(!fresh(&pod, "reader"));
        std::fs::remove_dir_all(&pod).unwrap();
    }

    #[test]
    fn identity_issue_once_a_minute_for_one_workload_on_one_node() {
        // Spent only once one is given.
        assert!(due("n1", "Workload/a/b#0", 1000) && due("n1", "Workload/a/b#0", 1000));
        spend("n1", "Workload/a/b#0", 1000);
        assert!(!due("n1", "Workload/a/b#0", 1059));
        // Another replica, another node: each its own.
        assert!(due("n1", "Workload/a/b#1", 1059) && due("n2", "Workload/a/b#0", 1059));
        assert!(due("n1", "Workload/a/b#0", 1060));
    }
}
