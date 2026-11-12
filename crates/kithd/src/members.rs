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
use axum::Json;
use axum::extract::State;
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
    // The scheduler's input (T-0027).
    #[allow(dead_code)]
    pub fn capacity(&self, name: &str) -> Option<(f64, f64)> {
        if name == self.me {
            return Some(self.mine);
        }
        let seen = self.heard().get(name)?.1?;
        Some((seen.cpu, seen.memory))
    }
}

/// `POST /v1/ping` (members only): take the caller's view, answer with ours.
pub async fn ping(State(shared): State<Arc<Shared>>, Json(theirs): Json<View>) -> Json<View> {
    let now = Instant::now();
    merge(&mut shared.members.heard(), theirs, now);
    Json(shared.members.view(now))
}

/// Tell every other node what this one knows, and take in what they know, until stopped.
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let Some(cluster) = &shared.cluster else { return };
    loop {
        tokio::select! {
            () = tokio::time::sleep(PERIOD) => {}
            _ = stopping.changed() => return,
        }
        let peers: BTreeMap<String, String> = {
            let store = shared.store.lock().expect("nothing panics holding the store");
            let at = |node: &kith_api::Resource| {
                let address = node.status.as_ref()?["address"].as_str()?;
                Some((node.metadata.name.clone(), address.to_string()))
            };
            store.store.list(Some("Node")).filter_map(at).collect()
        };
        // Only Nodes are remembered, so what a member can make this node hold is bounded;
        // a new one is known of from now.
        let sent = Instant::now();
        {
            let mut heard = shared.members.heard();
            heard.retain(|name, _| peers.contains_key(name));
            for name in peers.keys() {
                heard.entry(name.clone()).or_insert((sent, None));
            }
        }
        let view = shared.members.view(sent);
        let mut calls = tokio::task::JoinSet::new();
        for (_, address) in peers.iter().filter(|(name, _)| **name != cluster.me.name) {
            let call = cluster.client.post(format!("https://{address}/v1/ping"));
            let call = call.timeout(Duration::from_secs(1)).json(&view);
            calls.spawn(async move {
                let mut answer = call.send().await.ok()?.error_for_status().ok()?;
                let mut body = Vec::new();
                while let Some(chunk) = answer.chunk().await.ok()? {
                    body.extend_from_slice(&chunk);
                    if body.len() > 64 << 10 {
                        return None;
                    }
                }
                serde_json::from_slice::<View>(&body).ok()
            });
        }
        while let Some(answer) = calls.join_next().await {
            // Ages count from when the call was made: time on the way is not news.
            if let Ok(Some(theirs)) = answer {
                merge(&mut shared.members.heard(), theirs, sent);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
