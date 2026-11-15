//! Which nodes are there, without a word of it in the store: every node tells every
//! other one, every two seconds, how long ago anyone heard from each node, and what each
//! has to give. News passed on counts, so a node that one node cannot reach but another
//! can is still there. Nothing here is agreed on; the leader writes down only the outcome
//! (`ready` or `unreachable` in the Node's status, see `raft::tend_once`).
//
// ponytail: every node calls every node (n squared small requests each period), fine to
// about 50 nodes. Past that, SWIM (the foca crate) over the mesh, which brings the
// message authentication that the node API's mutual TLS gives here.

use crate::Shared;
use crate::cluster::Peer;
use crate::view::Upstream;
use axum::Json;
use axum::extract::{ConnectInfo, State};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

const PERIOD: Duration = Duration::from_secs(2);
/// A node nobody has heard from for this long is called unreachable.
pub const GRACE: Duration = Duration::from_secs(10);

/// What one node says of another.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Seen {
    /// Milliseconds since anyone heard from the node itself.
    pub ago: u64,
    /// CPUs.
    pub cpu: f64,
    /// Memory, in bytes.
    pub memory: f64,
}

/// What a node knows, by node name. Its own entry has `ago` 0.
pub type View = BTreeMap<String, Seen>;

pub struct Members {
    me: String,
    mine: (f64, f64),
    /// When each node was last heard from and what it has; for one never heard from,
    /// since when this kithd has known of it.
    heard: Mutex<Heard>,
}

type Heard = BTreeMap<String, (Instant, Option<Seen>)>;

/// Take `theirs` into `mine`: of two reports about a node, the more recent one.
fn merge(mine: &mut Heard, theirs: View, now: Instant) {
    for (name, seen) in theirs {
        // An age the clock cannot go back by is no news.
        let Some(at) = now.checked_sub(Duration::from_millis(seen.ago)) else {
            continue;
        };
        // (News as old as knowing of the node is news all the same.)
        if mine
            .get(&name)
            .is_none_or(|(known, heard)| *known < at || (*known == at && heard.is_none()))
        {
            mine.insert(name, (at, Some(seen)));
        }
    }
}

impl Members {
    pub fn new(me: &str) -> Members {
        let cpu = std::thread::available_parallelism().map_or(1.0, |n| n.get() as f64);
        let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let total = meminfo.lines().find_map(|line| line.strip_prefix("MemTotal:"));
        let kib = total.and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse::<f64>().ok());
        Members {
            me: me.to_string(),
            mine: (cpu, kib.unwrap_or(0.0) * 1024.0),
            heard: Mutex::default(),
        }
    }

    /// This node's name.
    pub fn me(&self) -> &str {
        &self.me
    }

    fn heard(&self) -> std::sync::MutexGuard<'_, Heard> {
        self.heard.lock().expect("nothing panics holding the members")
    }

    /// What to tell the others.
    fn view(&self, now: Instant) -> View {
        let ago = |at: &Instant| now.saturating_duration_since(*at).as_millis() as u64;
        let heard = self.heard();
        let told = |(name, (at, seen)): (&String, &(Instant, Option<Seen>))| {
            Some((
                name.clone(),
                Seen {
                    ago: ago(at),
                    ..(*seen)?
                },
            ))
        };
        let mut view: View = heard.iter().filter_map(told).collect();
        let (cpu, memory) = self.mine;
        view.insert(self.me.clone(), Seen { ago: 0, cpu, memory });
        view
    }

    /// How long `name` has been out of contact, or `None` while that cannot be said: a
    /// node this kithd has not heard from yet (it just joined, or this kithd just started)
    /// is not called lost before it has had the grace, nor called there.
    pub fn lost_for(&self, name: &str, now: Instant) -> Option<Duration> {
        if name == self.me {
            return Some(Duration::ZERO);
        }
        let (since, seen) = *self.heard().get(name)?;
        let gone = now.saturating_duration_since(since);
        (seen.is_some() || gone >= GRACE).then_some(gone)
    }

    /// CPUs and bytes of memory `name` said it has, once it has been heard from.
    pub fn capacity(&self, name: &str) -> Option<(f64, f64)> {
        if name == self.me {
            return Some(self.mine);
        }
        let seen = self.heard().get(name)?.1?;
        Some((seen.cpu, seen.memory))
    }
}

/// What is taken of the view the node `from` sent: all of a control node's, and of a
/// worker's only its word about itself (it cannot keep a node that is gone looking there,
/// or say what another has free).
fn taken(shared: &Shared, from: Option<&str>, theirs: View) -> View {
    match from.filter(|from| crate::access::worker(shared, from)) {
        Some(worker) => own_word(worker, theirs),
        None => theirs,
    }
}

fn own_word(from: &str, mut theirs: View) -> View {
    theirs.retain(|name, _| name == from);
    theirs
}

/// `POST /v1/ping` (members only): take the caller's view, answer with ours.
pub async fn ping(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    Json(theirs): Json<View>,
) -> Json<View> {
    let now = Instant::now();
    let from = match &peer.subject {
        Some(crate::pki::Subject::Node(name, ..)) => Some(name.as_str()),
        _ => None,
    };
    let theirs = taken(&shared, from, theirs);
    merge(&mut shared.members.heard(), theirs, now);
    Json(shared.members.view(now))
}

/// What `client` is told of the nodes by the one at `address`, for this node's view of them.
async fn ask(client: &reqwest::Client, address: &str, view: &View) -> Option<View> {
    let call = client.post(format!("https://{address}/v1/ping"));
    let mut answer = call
        .timeout(Duration::from_secs(1))
        .json(view)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?;
    let mut body = Vec::new();
    while let Some(chunk) = answer.chunk().await.ok()? {
        body.extend_from_slice(&chunk);
        if body.len() > 64 << 10 {
            return None;
        }
    }
    serde_json::from_slice(&body).ok()
}

/// Tell every other node what this one knows, and take in what they know, until stopped.
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let Some(cluster) = &shared.cluster else { return };
    loop {
        tokio::select! {
            () = tokio::time::sleep(PERIOD) => {}
            _ = stopping.changed() => return,
        }
        let peers: BTreeMap<String, Upstream> = {
            let store = shared.store.lock().expect("nothing panics holding the store");
            let at = |node: &kith_api::Resource| Some((node.metadata.name.clone(), Upstream::of(node)?));
            store.store.list(Some("Node")).filter_map(at).collect()
        };
        // Only Nodes are remembered, so what a member can make this node hold is bounded;
        // a new one is known of from now.
        let sent = Instant::now();
        {
            let mut heard = shared.members.heard();
            heard.retain(|name, _| peers.contains_key(name));
            cluster.forget_but(|name| peers.contains_key(name));
            for name in peers.keys() {
                heard.entry(name.clone()).or_insert((sent, None));
            }
        }
        let view = shared.members.view(sent);
        let mut calls = tokio::task::JoinSet::new();
        for (name, there) in peers.iter().filter(|(name, _)| **name != cluster.me.name) {
            // (That node and no other: what answers is taken for what that node says.)
            let Ok(client) = cluster.to(there) else { continue };
            let (name, address, view) = (name.clone(), there.address.clone(), view.clone());
            calls.spawn(async move { Some((name, ask(&client, &address, &view).await?)) });
        }
        while let Some(answer) = calls.join_next().await {
            // Ages count from when the call was made: time on the way is not news.
            if let Ok(Some((name, theirs))) = answer {
                let theirs = taken(&shared, Some(&name), theirs);
                merge(&mut shared.members.heard(), theirs, sent);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pinned_peer_is_pinged_and_what_another_node_says_is_not_its_word() {
        use crate::cluster::pinned_peer::{answering_as, at, node};
        use std::sync::atomic::Ordering;
        let ca = crate::pki::Ca::create().unwrap();
        let (a, b, x) = (node(&ca, "a"), node(&ca, "b"), node(&ca, "x"));
        let cluster = crate::cluster::Cluster::new(a, None).unwrap();
        let (stolen, to_x) = answering_as(&x).await;
        // x answers at the address of b, and says what a view says (`{}`: nobody).
        let there = at("b", &stolen, Some(crate::pki::print_of(&b.cert).unwrap()));
        let client = cluster.to(&there).unwrap();
        assert_eq!(ask(&client, &stolen, &View::new()).await, None);
        assert_eq!(
            to_x.load(Ordering::SeqCst),
            0,
            "x was pinged, and its answer is taken for b's"
        );
        // Where b answers, and where its Node names no key yet, the answer is taken.
        let (home, to_b) = answering_as(&b).await;
        for print in [None, Some(crate::pki::print_of(&b.cert).unwrap())] {
            let client = cluster.to(&at("b", &home, print)).unwrap();
            assert_eq!(ask(&client, &home, &View::new()).await, Some(View::new()));
        }
        assert_eq!(to_b.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn news_is_passed_on_and_grows_old() {
        let members = Members::new("a");
        let start = Instant::now() + Duration::from_secs(3600);
        let seen = |ago| Seen {
            ago,
            cpu: 4.0,
            memory: 8e9,
        };
        let told = |name: &str, ago| View::from([(name.to_string(), seen(ago))]);
        // Of a worker's view only its word about itself is taken.
        let mut both = told("w", 0);
        both.extend(told("gone", 0));
        assert_eq!(own_word("w", both).into_keys().collect::<Vec<_>>(), ["w"]);
        let lost = |name: &str, after: u64| {
            let gone = members.lost_for(name, start + Duration::from_secs(after));
            gone.map(|gone| gone.as_secs())
        };

        // Itself: always there. Not known of: nothing to say.
        assert_eq!((lost("a", 100), lost("b", 0)), (Some(0), None));
        assert_eq!(members.capacity("b"), None);
        // Known of but never heard from: nothing to say until the grace is over, then lost.
        members.heard().insert("b".into(), (start, None));
        assert_eq!((lost("b", 9), lost("b", 10)), (None, Some(10)));
        assert!(!members.view(start).contains_key("b"));
        // b calls: there now, and less so as time passes.
        merge(&mut members.heard(), told("b", 0), start);
        assert_eq!((lost("b", 0), lost("b", 12)), (Some(0), Some(12)));
        assert_eq!(members.capacity("b"), Some((4.0, 8e9)));
        // c says it heard from b 3 s ago: that is news at 12 s, and none at 14 s.
        merge(&mut members.heard(), told("b", 3000), start + Duration::from_secs(12));
        assert_eq!(lost("b", 12), Some(3));
        merge(&mut members.heard(), told("b", 9000), start + Duration::from_secs(14));
        assert_eq!(lost("b", 14), Some(5));
        // What is passed on keeps its age, so stale news cannot keep a dead node alive.
        let view = members.view(start + Duration::from_secs(14));
        assert_eq!((view["b"].ago, view["a"].ago), (5000, 0));
        // An absurd age is no news and no panic.
        merge(
            &mut members.heard(),
            told("b", u64::MAX),
            start + Duration::from_secs(14),
        );
        assert_eq!(lost("b", 14), Some(5));
    }
}
