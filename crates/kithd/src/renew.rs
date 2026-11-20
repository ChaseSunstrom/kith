//! A node's certificate is made again before it ends. A node with under a third of its
//! certificate's life left ([`crate::pki::renewal_due`]) asks a node that holds the CA key for a
//! new one, over the one it has (`POST /v1/renew-certificate`, members only), writes it down
//! and shows it from the next handshake on ([`crate::pki::Live`]): no restart. The new one is
//! for the same key and the same names, so everything the cluster keeps of the node's key (its
//! Node's `status.certificate`, join tokens, pins) still holds.
//!
//! The CA holder signs for the node that asks, never for one the request names (the key and the
//! birth index are the ones of the certificate on the link), only while its Node stands (the
//! link was refused before this otherwise), one a minute at most, and writes each in the audit
//! log. A certificate that has ended cannot ask: that node is joined again.
//!
//! The CA's own certificate (twenty years) is not renewed here.

use crate::Shared;
use crate::cluster::Peer;
use crate::pki::{self, Subject};
use crate::workload_identity::{Unmade, due, holders, spend, walk};
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

/// How often a node looks at how long its certificate has left.
const ROUND: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 3600 });
/// What the rate limit of [`due`] files a node's asking under.
const WHAT: &str = "node certificate";

/// The CA holder (its Node's name) that last renewed one: asked first next time.
// ponytail: in memory: a restart asks the holders in the store's order once.
static ANSWERED: Mutex<Option<String>> = Mutex::new(None);

/// `POST /v1/renew-certificate` (members only), on the node that holds the CA key: the
/// certificate (PEM) of the node that asks, made again for its key for [`pki::NODE_LIFE`].
pub async fn issue(State(shared): State<Arc<Shared>>, ConnectInfo(peer): ConnectInfo<Peer>) -> Response {
    let Some(Subject::Node(node, key, born)) = &peer.subject else {
        return (StatusCode::FORBIDDEN, "this is for the cluster's nodes").into_response();
    };
    let Some(ca) = shared.cluster.as_ref().and_then(|cluster| cluster.ca.as_ref()) else {
        return (StatusCode::CONFLICT, crate::cluster::CA_ELSEWHERE).into_response();
    };
    let now = kith_api::store::now();
    if !due(node, WHAT, now) {
        return (StatusCode::TOO_MANY_REQUESTS, "one certificate a minute for one node").into_response();
    }
    let who = crate::access::Caller::Node(node.clone());
    let target = vec![format!("Node/{node}")];
    match ca.renew_node(node, *born, key, now, pki::NODE_LIFE) {
        Ok(cert) => {
            spend(node, WHAT, now);
            shared.audit.record(&who, "renew-certificate", target, Ok(()));
            cert.into_response()
        }
        Err(why) => {
            shared.audit.record(&who, "renew-certificate", target, Err(why.clone()));
            (StatusCode::FORBIDDEN, why).into_response()
        }
    }
}

/// What a round of [`renew_if_due`] did.
#[derive(Debug, PartialEq)]
pub enum Renewed {
    /// More than a third of its life is left (or it says none): nothing was asked.
    NotYet,
    /// Shown from now on, and written down.
    Done,
}

/// Make the certificate `live` shows again, if less than a third of its life is left at `now`
/// (seconds since 1970): `ask` gives the new one (PEM). The new one is checked to be for the key
/// held and is written to `node.crt` in `dir` before it is shown, so a failure at any step
/// leaves the old one shown and written, and a restart reads the one that was shown.
pub async fn renew_if_due<F, Fut>(live: &pki::Live, dir: &Path, now: u64, ask: F) -> Result<Renewed, String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    let shown = live.current();
    let ends = shown.cert.first().and_then(|cert| pki::validity(cert));
    let Some((from, to)) = ends else {
        return Ok(Renewed::NotYet);
    };
    if !pki::renewal_due(from, to, now) {
        return Ok(Renewed::NotYet);
    }
    let pem = ask().await?;
    let new = live.parse(&pem)?;
    // (Only one that ends later: a CA holder that answers with an older one does no harm.)
    let later = new.cert.first().and_then(|cert| pki::validity(cert)).map(|(_, to)| to);
    if later.is_none_or(|later| later <= to) {
        return Err("the certificate it was sent does not end later than this one".into());
    }
    pki::write_whole(&dir.join("node.crt"), pem.as_bytes()).map_err(|e| format!("{}: {e}", dir.display()))?;
    live.show(new);
    Ok(Renewed::Done)
}

/// Ask the node that holds the CA key (this one, if it does) for this node's certificate.
async fn ask(shared: &Shared, now: u64) -> Result<String, String> {
    let cluster = shared.cluster.as_ref().ok_or("this kithd is not part of a cluster")?;
    let shown = cluster.live.current();
    if let Some(ca) = &cluster.ca {
        // (Its own: no one else signs for it, and the CA key is here.)
        let der = shown.cert.first().ok_or("no certificate")?;
        let Some(Subject::Node(name, key, born)) = pki::subject_of(der) else {
            return Err("this node's certificate is not a node's".into());
        };
        return ca.renew_node(&name, born, &key, now, pki::NODE_LIFE);
    }
    let holders = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        holders(&state.store)
    };
    let failed = |why: String| Unmade::Failed(why);
    let heard = walk(holders, &ANSWERED, |holder| async move {
        let client = cluster.to(&holder).map_err(failed)?;
        let url = format!("https://{}/v1/renew-certificate", holder.address);
        let sent = client.post(url).timeout(Duration::from_secs(10)).send();
        let answer = sent.await.map_err(|e| failed(format!("asking {}: {e}", holder.name)))?;
        let status = answer.status();
        let text = answer.text().await;
        let text = text.map_err(|e| failed(format!("reading {}: {e}", holder.name)))?;
        match status {
            StatusCode::OK => Ok(text),
            StatusCode::FORBIDDEN => Err(Unmade::Refused(text)),
            _ => Err(failed(format!("{} said {status}: {text}", holder.name))),
        }
    })
    .await;
    heard
        .map(|(pem, _)| pem)
        .map_err(|(Unmade::Refused(why) | Unmade::Failed(why))| why)
}

/// Once an hour (and at the start), make this node's certificate again if it is due.
pub async fn run(shared: Arc<Shared>, dir: std::path::PathBuf, mut stopping: watch::Receiver<bool>) {
    let Some(cluster) = shared.cluster.as_ref() else {
        return;
    };
    loop {
        let now = kith_api::store::now();
        match renew_if_due(&cluster.live, &dir, now, || ask(&shared, now)).await {
            Ok(Renewed::Done) => eprintln!("kithd: this node's certificate was made again"),
            Ok(Renewed::NotYet) => {}
            Err(why) => eprintln!("kithd: this node's certificate is not made again yet: {why}"),
        }
        tokio::select! {
            _ = tokio::time::sleep(ROUND) => {}
            _ = stopping.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::{Ca, Identity};

    /// A node `b` whose certificate ended in `left` seconds, from an hour ago, in a directory.
    fn node(ca: &Ca, left: u64) -> (Identity, Vec<u8>, std::path::PathBuf) {
        let (cert, key) = ca.issue("b").unwrap();
        let der = rustls::pki_types::CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
        let Some(Subject::Node(_, public, _)) = pki::subject_of(&der) else {
            panic!("a node's certificate");
        };
        let now = kith_api::store::now();
        let short = ca
            .renew_node("b", None, &public, now - 3600, Duration::from_secs(3600 + left))
            .unwrap();
        let dir = std::env::temp_dir().join(format!("kith-renew-{}-{left}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        pki::write_whole(&dir.join("node.crt"), short.as_bytes()).unwrap();
        let me = Identity {
            name: "b".into(),
            ca: ca.cert.clone(),
            cert: short,
            key,
        };
        (me, public, dir)
    }

    use rustls::pki_types::pem::PemObject;

    #[tokio::test]
    async fn a_certificate_with_under_a_third_left_is_made_again_and_kept() {
        let ca = Ca::create().unwrap();
        let now = kith_api::store::now();
        // Ten minutes left of the hour and ten minutes, with a third of that gone.
        let (me, public, dir) = node(&ca, 600);
        let live = pki::Live::new(&me).unwrap();
        let ends = |live: &pki::Live| pki::validity(&live.current().cert[0]).unwrap().1;
        assert_eq!(ends(&live), now + 600);

        // A third of its life left or more: nothing is asked.
        let (young, _, early) = node(&ca, 6000);
        let fresh = pki::Live::new(&young).unwrap();
        let asked = renew_if_due(&fresh, &early, now, || async { panic!("asked too early") }).await;
        assert_eq!(asked, Ok(Renewed::NotYet));

        // A holder that fails, or sends what it should not: the old one stays, shown and written.
        let old = std::fs::read_to_string(dir.join("node.crt")).unwrap();
        let failing = renew_if_due(&live, &dir, now, || async { Err("down".to_string()) }).await;
        assert_eq!(failing, Err("down".to_string()));
        let other = ca.issue("b").unwrap().0;
        let wrong = renew_if_due(&live, &dir, now, || async { Ok(other) }).await;
        assert!(wrong.is_err());
        let same = renew_if_due(&live, &dir, now, || async { Ok(old.clone()) }).await;
        assert!(same.is_err(), "one that does not end later is not taken");
        assert_eq!(ends(&live), now + 600);
        assert_eq!(std::fs::read_to_string(dir.join("node.crt")).unwrap(), old);

        // Made again: shown at once, written down, for the same key.
        let signing = ca.renew_node("b", None, &public, now, pki::NODE_LIFE).unwrap();
        let done = renew_if_due(&live, &dir, now, || async { Ok(signing.clone()) }).await;
        assert_eq!(done, Ok(Renewed::Done));
        assert_eq!(ends(&live), now + pki::NODE_LIFE.as_secs());
        assert_eq!(std::fs::read_to_string(dir.join("node.crt")).unwrap(), signing);
        // (A second round has nothing to do.)
        let again = renew_if_due(&live, &dir, now, || async { panic!("asked again") }).await;
        assert_eq!(again, Ok(Renewed::NotYet));
    }
}
