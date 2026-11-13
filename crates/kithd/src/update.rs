//! OS updates rolled through the cluster (PLAN §4.9). An `OSRelease` names a version of
//! kith OS, where its update file is and the key that signed it; an `UpdatePlan` says
//! which nodes get it and how fast.
//!
//! The leader decides who goes next ([`step`], in the plan's status: `nodes.NAME` is
//! `updating`, `done` or `failed`). A node that finds itself `updating` fetches the file,
//! checks the signature, writes its other slot (`os`) and restarts; every kith OS node
//! says in its Node's status what it runs (`os.version`, `os.slot`) and, when an update
//! did not take, which (`os.failed`, `os.why`). A node that fails pauses the plan: it is
//! back on the system it had, and nobody else is sent the release that did that.
//!
//! A plan paused that way stays so until its release is changed (signed anew, another
//! address), or it is given another release.

use crate::Shared;
use kith_api::Resource;
use kith_store::Command;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// A node told to update that has said nothing of the new version for this long has
/// failed: it is not coming back by itself.
const PATIENCE: u64 = 15 * 60;

/// What the leader knows of a node when it decides.
#[derive(Debug, Clone, Default)]
pub struct Node {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    /// The kith OS version it runs; `None` for a node that is not kith OS.
    pub version: Option<String>,
    /// The version it tried and did not come up as, and why.
    pub failed: Option<(String, String)>,
    pub voter: bool,
    pub leader: bool,
    /// Heard from, and not called unreachable.
    pub up: bool,
}

/// What [`step`] wants written.
#[derive(Debug, PartialEq)]
pub struct Decided {
    pub status: Map<String, Value>,
    /// Nodes to stop placing workloads on (true) or to place them on again (false).
    pub cordon: Vec<(String, bool)>,
}

/// Is `now` (minutes since Monday 00:00 UTC) inside `window`: `HH:MM-HH:MM`, every day,
/// or `Sat,Sun HH:MM-HH:MM`? A window may run past midnight, into the next day.
fn within(window: &str, now: u32) -> Result<bool, String> {
    let bad = || format!("the window `{window}` is not understood: HH:MM-HH:MM, or Sat,Sun HH:MM-HH:MM");
    let (days, hours) = match window.trim().rsplit_once(' ') {
        Some((days, hours)) => (Some(days), hours),
        None => (None, window.trim()),
    };
    let minute = |text: &str| {
        let (hour, minute) = text.split_once(':')?;
        let (hour, minute): (u32, u32) = (hour.parse().ok()?, minute.parse().ok()?);
        (hour < 24 && minute < 60 && text.len() == 5).then_some(hour * 60 + minute)
    };
    let (from, to) = hours.split_once('-').ok_or_else(bad)?;
    let (from, to) = (minute(from).ok_or_else(bad)?, minute(to).ok_or_else(bad)?);
    const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    let mut on = [days.is_none(); 7];
    for day in days.into_iter().flat_map(|days| days.split(',')) {
        let day = DAYS.iter().position(|known| day.eq_ignore_ascii_case(known));
        on[day.ok_or_else(bad)?] = true;
    }
    let (day, at) = ((now / 1440 % 7) as usize, now % 1440);
    Ok(if from <= to {
        on[day] && (from..to).contains(&at)
    } else {
        // Past midnight: the evening of a day it is on, or the morning after one.
        (on[day] && at >= from) || (on[(day + 6) % 7] && at < to)
    })
}

/// What the plan's status should now say, and which nodes to cordon. `release` is the
/// OSRelease the plan names, if there is one: its version, and what tells it from every
/// other release and from itself before it was changed (`NAME@REVISION`). `now` is
/// seconds since 1970.
pub fn step(plan: &Resource, release: Option<(&str, &str)>, nodes: &[Node], now: u64) -> Decided {
    let spec = &plan.spec;
    let old = plan.status.as_ref();
    let text = |value: Option<&Value>| value.and_then(Value::as_str).map(str::to_string);
    let mut states: BTreeMap<String, String> = old
        .and_then(|status| status["nodes"].as_object())
        .into_iter()
        .flatten()
        .filter_map(|(name, state)| Some((name.clone(), state.as_str()?.to_string())))
        .collect();
    let mut since: BTreeMap<String, u64> = old
        .and_then(|status| status["since"].as_object())
        .into_iter()
        .flatten()
        .filter_map(|(name, at)| Some((name.clone(), at.as_u64()?)))
        .collect();
    let mut cordoned: Vec<String> = old
        .and_then(|status| status["cordoned"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|name| text(Some(name)))
        .collect();
    let mut reason = text(old.map(|status| &status["reason"])).unwrap_or_default();
    let mut cordon = Vec::new();
    let done = |phase: &str, reason: String, states, since, cordoned: Vec<String>, cordon| Decided {
        status: Map::from_iter([
            ("phase".to_string(), json!(phase)),
            ("reason".to_string(), json!(reason)),
            ("release".to_string(), json!(release.map(|(version, _)| version))),
            ("of".to_string(), json!(release.map(|(_, of)| of))),
            ("nodes".to_string(), json!(states)),
            ("since".to_string(), json!(since)),
            ("cordoned".to_string(), json!(cordoned)),
        ]),
        cordon,
    };
    let Some((target, of)) = release else {
        let why = format!("there is no OSRelease {}", spec["release"].as_str().unwrap_or_default());
        return done("Waiting", why, states, since, cordoned, cordon);
    };
    // Another release than the one this status is about, or that one changed (signed
    // anew, say): a new rollout, from nothing.
    if old.is_some_and(|status| status["of"].as_str() != Some(of)) {
        states.clear();
        since.clear();
        reason.clear();
        // (Nobody is updating now: whoever was kept free of workloads for it is not.)
        cordon.extend(cordoned.drain(..).map(|name| (name, false)));
    }
    let selected = |node: &&Node| {
        let wanted = spec["selector"].as_object();
        let has = |(label, value): (&String, &Value)| node.labels.get(label).map(String::as_str) == value.as_str();
        node.version.is_some() && wanted.is_none_or(|wanted| wanted.iter().all(has))
    };
    let targets: Vec<&Node> = nodes.iter().filter(selected).collect();

    // What became of the nodes that were told to go.
    for node in &targets {
        let state = states.get(&node.name).map(String::as_str);
        let failed = node.failed.as_ref().filter(|(version, _)| version == target);
        let late = since
            .get(&node.name)
            .is_some_and(|at| now.saturating_sub(*at) > PATIENCE);
        let (next, why) = match state {
            // (Also one given up on that came back as the release after all.)
            Some("updating" | "failed") | None if node.version.as_deref() == Some(target) => ("done", None),
            Some("updating") if failed.is_some() => ("failed", failed.map(|(_, why)| why.clone())),
            Some("updating") if late => ("failed", Some("it did not come back as the new version".into())),
            _ => continue,
        };
        if state == Some("updating") {
            since.remove(&node.name);
            if let Some(at) = cordoned.iter().position(|name| name == &node.name) {
                cordoned.remove(at);
                cordon.push((node.name.clone(), false));
            }
        }
        if let Some(why) = why {
            reason = format!("{} did not take {target}: {why}", node.name);
        }
        states.insert(node.name.clone(), next.into());
    }
    let count = |state: &str, states: &BTreeMap<String, String>| states.values().filter(|s| *s == state).count();
    if count("failed", &states) > 0 {
        return done("Paused", reason, states, since, cordoned, cordon);
    }
    if spec["paused"].as_bool() == Some(true) {
        return done("Paused", "the plan says paused".into(), states, since, cordoned, cordon);
    }
    if targets
        .iter()
        .all(|node| states.get(&node.name).is_some_and(|state| state == "done"))
    {
        let why = if targets.is_empty() {
            "no kith OS node matches the selector"
        } else {
            ""
        };
        return done("Done", why.into(), states, since, cordoned, cordon);
    }
    let windows: Vec<&str> = spec["windows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    // (1970 began on a Thursday; a week here begins on Monday.)
    let minute = ((now / 60 + 3 * 1440) % (7 * 1440)) as u32;
    let open: Result<Vec<bool>, String> = windows.iter().map(|window| within(window, minute)).collect();
    match open {
        Err(why) => return done("Waiting", why, states, since, cordoned, cordon),
        Ok(open) if !open.is_empty() && !open.contains(&true) => {
            return done(
                "Waiting",
                "outside the plan's windows".into(),
                states,
                since,
                cordoned,
                cordon,
            );
        }
        Ok(_) => {}
    }

    // Who goes next: those that do not vote first, the leader last; a voter goes alone,
    // and only while every other voter is up, so the store keeps its majority.
    let most = spec["maxUnavailable"].as_u64().unwrap_or(1).max(1) as usize;
    let going = |states: &BTreeMap<String, String>| -> Vec<&Node> {
        let updating = |node: &&&Node| states.get(&node.name).is_some_and(|state| state == "updating");
        targets.iter().filter(updating).copied().collect()
    };
    let mut waiting: Vec<&Node> = targets
        .iter()
        .filter(|node| !states.contains_key(&node.name))
        // (One that still says it failed this version has not heard of the new try yet.)
        .filter(|node| node.up && node.failed.as_ref().is_none_or(|(version, _)| version != target))
        .copied()
        .collect();
    waiting.sort_by_key(|node| (node.voter, node.leader, node.name.clone()));
    let voters_up = nodes.iter().filter(|node| node.voter).all(|node| node.up);
    for node in waiting {
        let now_going = going(&states);
        let alone = now_going.is_empty();
        let fits = now_going.len() < most && !now_going.iter().any(|other| other.voter);
        if !(if node.voter { alone && voters_up } else { fits }) {
            continue;
        }
        states.insert(node.name.clone(), "updating".into());
        since.insert(node.name.clone(), now);
        if spec["drain"].as_bool() == Some(true) {
            cordoned.push(node.name.clone());
            cordon.push((node.name.clone(), true));
        }
    }
    let stuck = going(&states).is_empty() && !voters_up;
    let why = if stuck {
        "waiting for every voting node to be up before another restarts"
    } else {
        ""
    };
    done("Progressing", why.into(), states, since, cordoned, cordon)
}

/// The leader's part: every plan's next step, written down.
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let mut generation = shared.generation.subscribe();
    loop {
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(5)) => {}
            _ = stopping.changed() => return,
        }
        let metrics = shared.raft.metrics().borrow().clone();
        if metrics.current_leader != Some(metrics.id) {
            continue;
        }
        let voters: Vec<u64> = metrics.membership_config.membership().voter_ids().collect();
        let now = std::time::Instant::now();
        let mut commands = Vec::new();
        {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let store = &state.store;
            let node = |node: &Resource| {
                let status = node.status.as_ref();
                let text = |value: Option<&Value>| value.and_then(Value::as_str).map(str::to_string);
                let os = status.map(|status| &status["os"]);
                let id: Option<u64> = status.and_then(|status| status["raftId"].as_str()?.parse().ok());
                let name = node.metadata.name.clone();
                let lost = shared.members.lost_for(&name, now);
                let unreachable = status.is_some_and(|status| status["state"] == "unreachable");
                Node {
                    labels: node.metadata.labels.clone(),
                    version: text(os.map(|os| &os["version"])),
                    failed: text(os.map(|os| &os["failed"]))
                        .map(|version| (version, text(os.map(|os| &os["why"])).unwrap_or_default())),
                    voter: id.is_some_and(|id| voters.contains(&id)),
                    leader: id == Some(metrics.id),
                    up: !unreachable && lost.is_none_or(|lost| lost < crate::members::GRACE),
                    name,
                }
            };
            let nodes: Vec<Node> = store.list(Some("Node")).map(node).collect();
            let at = kith_api::store::now();
            let seconds = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_secs());
            for plan in store.list(Some("UpdatePlan")) {
                let release = store.get(&format!(
                    "OSRelease/{}",
                    plan.spec["release"].as_str().unwrap_or_default()
                ));
                let release = release.and_then(|release| {
                    let of = format!("{}@{}", release.metadata.name, release.metadata.revision.unwrap_or(0));
                    Some((release.spec["version"].as_str()?, of))
                });
                let release = release.as_ref().map(|(version, of)| (*version, of.as_str()));
                let decided = step(plan, release, &nodes, seconds);
                if plan.status.as_ref().and_then(Value::as_object) != Some(&decided.status) {
                    let statuses = vec![(plan.key(), decided.status)];
                    commands.push(Command::Patch { statuses });
                }
                for (name, cordoned) in decided.cordon {
                    let Some(mut node) = store.get(&format!("Node/{name}")).cloned() else {
                        continue;
                    };
                    node.spec["unschedulable"] = if cordoned { json!(true) } else { Value::Null };
                    if !cordoned && let Some(spec) = node.spec.as_object_mut() {
                        spec.remove("unschedulable");
                    }
                    commands.push(Command::Apply {
                        resources: vec![node],
                        at,
                    });
                }
            }
        }
        for command in commands {
            if let Err(e) = shared.submit(command).await {
                eprintln!("kithd: writing down an update plan's step: {e}");
            }
        }
    }
}

/// What this node tried to become, kept on its state partition across the restart: if it
/// comes back as something else, the update did not take.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone)]
struct Tried {
    version: String,
    #[serde(default)]
    why: String,
}

fn tried(state: &Path) -> PathBuf {
    state.join("os-update.json")
}

/// What this node's status says of its system: what it runs, and an update that did not
/// take. An update that did is forgotten here.
fn report(state: &Path, version: &str, slot: char) -> Value {
    let was: Option<Tried> = std::fs::read(tried(state))
        .ok()
        .and_then(|text| serde_json::from_slice(&text).ok());
    match was {
        Some(tried) if tried.version == version => {
            let _ = std::fs::remove_file(self::tried(state));
            json!({ "version": version, "slot": slot.to_string() })
        }
        Some(tried) => {
            let why = match tried.why.as_str() {
                "" => format!("it did not come up; the node is back on {version}"),
                why => why.to_string(),
            };
            json!({ "version": version, "slot": slot.to_string(), "failed": tried.version, "why": why })
        }
        None => json!({ "version": version, "slot": slot.to_string() }),
    }
}

/// The version in an os-release file (`VERSION_ID=`).
fn version_in(os_release: &str) -> Option<String> {
    let value = os_release.lines().find_map(|line| line.strip_prefix("VERSION_ID="))?;
    Some(value.trim_matches('"').to_string()).filter(|version| !version.is_empty())
}

/// The update file at `url`, into this node's other slot, if it is the release's: signed
/// by its key, and the version it says.
async fn fetch(url: &str, wanted: String, release: &Value, slot: char) -> Result<String, String> {
    let text = |field: &str| release[field].as_str().map(str::to_string);
    let (signature, public) = (text("signature"), text("publicKey"));
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        // (A server that goes quiet is a download that broke, not one to wait out.)
        .read_timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())?;
    let failed = |e: reqwest::Error| format!("fetching {url}: {e}");
    let mut response = client
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(failed)?;
    // What arrives is written as it arrives: an update is tens of megabytes, a node may
    // have little memory, and the writer checks every piece against the signed header.
    let (send, mut pieces) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    struct Arriving<'a>(&'a mut tokio::sync::mpsc::Receiver<Vec<u8>>, Vec<u8>, usize);
    impl std::io::Read for Arriving<'_> {
        fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
            if self.2 == self.1.len() {
                match self.0.blocking_recv() {
                    Some(more) => (self.1, self.2) = (more, 0),
                    None => return Ok(0),
                }
            }
            let some = into.len().min(self.1.len() - self.2);
            into[..some].copy_from_slice(&self.1[self.2..self.2 + some]);
            self.2 += some;
            Ok(some)
        }
    }
    let writer = tokio::task::spawn_blocking(move || {
        let running = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        let signed = crate::os::signed(signature.as_deref(), public.as_deref());
        let vouched = |header: &[u8]| {
            signed(header)?;
            let named: Value = serde_json::from_slice(header).map_err(|e| format!("the update's header: {e}"))?;
            match named["version"].as_str() {
                Some(version) if version == wanted => Ok(()),
                version => Err(format!(
                    "the update at that address is kith OS {}",
                    version.unwrap_or("?")
                )),
            }
        };
        crate::os::into_other_slot(&mut Arriving(&mut pieces, Vec::new(), 0), slot, &running, vouched)
    });
    let mut cut = None;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                // (The writer has stopped reading: it has what it needs, or has refused.)
                if send.send(chunk.to_vec()).await.is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                cut = Some(failed(e));
                break;
            }
        }
    }
    drop(send);
    let wrote = writer.await.map_err(|e| e.to_string())?;
    match (wrote, cut) {
        (Ok(Some(version)), _) => Ok(version),
        (Ok(None), _) => Err("that release is what this node runs already, under another version".into()),
        (Err(_), Some(cut)) => Err(cut),
        (Err(e), None) => Err(e),
    }
}

/// A kith OS node's part: say what it runs, and when a plan says so, become the release.
pub async fn node(shared: Arc<Shared>, state: PathBuf, mut stopping: watch::Receiver<bool>) {
    let line = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let version = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| version_in(&text));
    let (Some(slot), Some(version), Some(cluster)) = (crate::init::options(&line).0.slot, version, &shared.cluster)
    else {
        return;
    };
    let me = format!("Node/{}", cluster.me.name);
    let mut generation = shared.generation.subscribe();
    loop {
        let said = report(&state, &version, slot);
        // What the store has of this node, and a plan that says it is this node's turn.
        let (known, turn, named) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let store = &state.store;
            let known = store
                .get(&me)
                .map(|node| node.status.as_ref().map(|status| status["os"].clone()));
            let mine = |plan: &&Resource| {
                plan.status
                    .as_ref()
                    .map(|status| status["nodes"][&cluster.me.name].clone())
            };
            let plans: Vec<&Resource> = store.list(Some("UpdatePlan")).collect();
            let named = plans
                .iter()
                .any(|plan| mine(plan).is_some_and(|state| state == "updating" || state == "failed"));
            let turn = plans
                .iter()
                .find(|plan| mine(plan).is_some_and(|state| state == "updating"));
            let release = turn.and_then(|plan| store.get(&format!("OSRelease/{}", plan.spec["release"].as_str()?)));
            (known, release.map(|release| release.spec.clone()), named)
        };
        // (No plan speaks of this node any more: what failed before may be tried again.)
        if said["failed"].is_string() && !named && std::fs::remove_file(tried(&state)).is_ok() {
            continue;
        }
        if known.is_some_and(|known| known != Some(said.clone())) {
            let Value::Object(status) = json!({ "os": said }) else {
                unreachable!("an object")
            };
            if let Err(e) = shared
                .submit(Command::Patch {
                    statuses: vec![(me.clone(), status)],
                })
                .await
            {
                eprintln!("kithd: telling the cluster what this node runs: {e}");
            }
        }
        let text = |spec: &Value, field: &str| spec[field].as_str().map(str::to_string);
        if let Some(release) = turn
            && let (Some(wanted), Some(url)) = (text(&release, "version"), text(&release, "image"))
            && wanted != version
            && said["failed"].as_str() != Some(&wanted)
        {
            eprintln!("kithd: this node's turn in an update plan: kith OS {wanted} from {url}");
            let mut trying = Tried {
                version: wanted.clone(),
                why: String::new(),
            };
            let write =
                |trying: &Tried| crate::pki::write_whole(&tried(&state), &serde_json::to_vec(trying).expect("text"));
            let wrote = match write(&trying) {
                Ok(()) => fetch(&url, wanted.clone(), &release, slot).await,
                Err(e) => Err(format!("keeping a note of the update: {e}")),
            };
            match wrote {
                Ok(_) => {
                    eprintln!("kithd: kith OS {wanted} is in the other slot: restarting into it");
                    shared.stop.send_replace(true);
                    return;
                }
                // (It started moments ago and has not called its own slot good yet: soon.)
                Err(why) if why == crate::os::TOO_EARLY => {
                    let _ = std::fs::remove_file(tried(&state));
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                Err(why) => {
                    eprintln!("kithd: no update to kith OS {wanted}: {why}");
                    trying.why = why;
                    // (A note that cannot be kept is an update tried again: not at once.)
                    if write(&trying).is_err() {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    }
                    continue;
                }
            }
        }
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(5)) => {}
            _ = stopping.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(spec: Value, status: Option<&Decided>) -> Resource {
        let mut spec = spec;
        spec["release"] = json!("next");
        let plan =
            json!({ "apiVersion": "kith.dev/v1", "kind": "UpdatePlan", "metadata": { "name": "p" }, "spec": spec });
        let mut plan: Resource = serde_json::from_value(plan).unwrap();
        plan.status = status.map(|decided| Value::Object(decided.status.clone()));
        plan
    }

    fn node(name: &str, version: &str, voter: bool) -> Node {
        Node {
            name: name.into(),
            version: Some(version.into()),
            voter,
            up: true,
            ..Node::default()
        }
    }

    fn states(decided: &Decided) -> Vec<(String, String)> {
        let nodes = decided.status["nodes"].as_object().unwrap();
        nodes
            .iter()
            .map(|(name, state)| (name.clone(), state.as_str().unwrap().to_string()))
            .collect()
    }

    fn told(decided: &Decided) -> Vec<String> {
        let updating = |(name, state): (String, String)| (state == "updating").then_some(name);
        states(decided).into_iter().filter_map(updating).collect()
    }

    /// Run the plan to its end: whoever is told to go comes back as the new version.
    fn rounds(spec: Value, mut nodes: Vec<Node>) -> Vec<Vec<String>> {
        let (mut order, mut last) = (Vec::new(), None);
        for round in 0..20 {
            let decided = step(
                &plan(spec.clone(), last.as_ref()),
                Some(("2", "next@1")),
                &nodes,
                1000 + round,
            );
            let going = told(&decided);
            if decided.status["phase"] == "Done" {
                return order;
            }
            for node in nodes.iter_mut().filter(|node| going.contains(&node.name)) {
                node.version = Some("2".into());
            }
            order.push(going);
            last = Some(decided);
        }
        panic!("the plan did not end: {order:?}");
    }

    #[test]
    fn update_takes_voters_one_at_a_time_and_the_rest_as_many_as_allowed() {
        let mut nodes = vec![node("v1", "1", true), node("v2", "1", true), node("v3", "1", true)];
        nodes[0].leader = true;
        nodes.extend([node("w1", "1", false), node("w2", "1", false), node("w3", "1", false)]);
        nodes.push(Node {
            name: "other".into(),
            up: true,
            ..Node::default()
        });
        // Those that do not vote first, two at a time; then each voter alone, the leader last.
        let order = rounds(json!({ "maxUnavailable": 2 }), nodes.clone());
        assert_eq!(
            order,
            [vec!["w1", "w2"], vec!["w3"], vec!["v2"], vec!["v3"], vec!["v1"]]
        );
        // One at a time unless the plan says more; a node that is not kith OS is left alone.
        let order = rounds(json!({}), nodes.clone());
        assert_eq!(order.len(), 6);
        assert!(order.iter().all(|going| going.len() == 1 && going[0] != "other"));

        // No voter goes while another voter is away: two of three must stay.
        nodes[2].up = false;
        let only_voters: Vec<Node> = nodes[..3].to_vec();
        let decided = step(&plan(json!({}), None), Some(("2", "next@1")), &only_voters, 0);
        assert_eq!(
            (told(&decided), &decided.status["phase"]),
            (vec![], &json!("Progressing"))
        );
        assert!(decided.status["reason"].as_str().unwrap().contains("every voting node"));
        // A node already there is done without being told; one that is away is not told.
        let mut some = vec![node("a", "2", false), node("b", "1", false)];
        some[1].up = false;
        let decided = step(&plan(json!({}), None), Some(("2", "next@1")), &some, 0);
        assert_eq!(states(&decided), [("a".to_string(), "done".to_string())]);
    }

    #[test]
    fn update_picks_by_label_cordons_when_draining_and_waits_for_its_windows() {
        let mut nodes = vec![node("a", "1", false), node("b", "1", false)];
        nodes[1].labels.insert("ring".into(), "canary".into());
        let spec = json!({ "selector": { "ring": "canary" }, "drain": true });
        let first = step(&plan(spec.clone(), None), Some(("2", "next@1")), &nodes, 0);
        assert_eq!(
            (told(&first), &first.cordon),
            (vec!["b".to_string()], &vec![("b".to_string(), true)])
        );
        nodes[1].version = Some("2".into());
        let second = step(&plan(spec, Some(&first)), Some(("2", "next@1")), &nodes, 60);
        assert_eq!(second.cordon, [("b".to_string(), false)]);
        assert_eq!(
            (&second.status["phase"], &second.status["cordoned"]),
            (&json!("Done"), &json!([]))
        );

        // 1970-01-05 was a Monday: `at` is minutes into that week.
        let at = |minutes: u64| (4 * 1440 + minutes) * 60;
        let phase = |windows: Value, minutes: u64| {
            let decided = step(
                &plan(json!({ "windows": windows }), None),
                Some(("2", "next@1")),
                &nodes[..1],
                at(minutes),
            );
            (
                decided.status["phase"].as_str().unwrap().to_string(),
                told(&decided).len(),
            )
        };
        assert_eq!(phase(json!(["02:00-04:00"]), 3 * 60), ("Progressing".into(), 1));
        assert_eq!(phase(json!(["02:00-04:00"]), 4 * 60), ("Waiting".into(), 0));
        assert_eq!(
            phase(json!(["Sat,Sun 00:00-23:59", "Tue 01:00-02:00"]), 1440 + 90),
            ("Progressing".into(), 1)
        );
        assert_eq!(phase(json!(["Sat,Sun 00:00-23:59"]), 1440 + 90), ("Waiting".into(), 0));
        // Past midnight: Monday's window is still open early on Tuesday, and not on Monday morning.
        assert_eq!(phase(json!(["Mon 23:00-01:00"]), 1440 + 30), ("Progressing".into(), 1));
        assert_eq!(phase(json!(["Mon 23:00-01:00"]), 30), ("Waiting".into(), 0));
        // A window nobody can read opens never, and the status says which.
        for bad in ["2-4", "25:00-26:00", "Someday 01:00-02:00", ""] {
            let decided = step(
                &plan(json!({ "windows": [bad] }), None),
                Some(("2", "next@1")),
                &nodes[..1],
                0,
            );
            assert_eq!(decided.status["phase"], "Waiting", "{bad}");
            assert!(
                decided.status["reason"].as_str().unwrap().contains("not understood"),
                "{bad}"
            );
        }
        let paused = step(&plan(json!({ "paused": true }), None), Some(("2", "next@1")), &nodes, 0);
        assert_eq!(
            (paused.status["phase"].as_str(), told(&paused).len()),
            (Some("Paused"), 0)
        );
        let none = step(&plan(json!({}), None), None, &nodes, 0);
        assert_eq!(none.status["reason"], "there is no OSRelease next");
    }

    #[test]
    fn update_pauses_when_a_node_comes_back_on_its_old_system() {
        let mut nodes = vec![node("a", "1", false), node("b", "1", false)];
        let spec = json!({ "drain": true });
        let first = step(&plan(spec.clone(), None), Some(("2", "next@1")), &nodes, 0);
        assert_eq!(told(&first), ["a"]);
        // Still away, or back and not yet saying: nothing changes.
        let waiting = step(&plan(spec.clone(), Some(&first)), Some(("2", "next@1")), &nodes, 60);
        assert_eq!(waiting.status, first.status);
        nodes[0].failed = Some(("2".into(), "it did not come up; the node is back on 1".into()));
        let paused = step(&plan(spec.clone(), Some(&first)), Some(("2", "next@1")), &nodes, 120);
        assert_eq!(paused.status["phase"], "Paused");
        assert_eq!(
            paused.status["reason"],
            "a did not take 2: it did not come up; the node is back on 1"
        );
        assert_eq!(states(&paused), [("a".to_string(), "failed".to_string())]);
        // It is back and whole: workloads may be placed on it again. Nobody else is told.
        assert_eq!(paused.cordon, [("a".to_string(), false)]);
        let still = step(&plan(spec.clone(), Some(&paused)), Some(("2", "next@1")), &nodes, 180);
        assert_eq!(
            (still.status["phase"].as_str(), told(&still).len()),
            (Some("Paused"), 0)
        );

        // The same release changed (signed anew, say) is another try, though not for a
        // node that still says it failed that version: it has not heard yet.
        let again = step(&plan(spec.clone(), Some(&paused)), Some(("2", "next@2")), &nodes, 200);
        assert_eq!(
            (again.status["phase"].as_str(), told(&again)),
            (Some("Progressing"), vec!["b".to_string()])
        );
        // Changed while a node was out for it: that node is not left without workloads.
        let reset = step(
            &plan(spec.clone(), Some(&first)),
            Some(("2", "next@2")),
            &nodes[1..],
            200,
        );
        assert!(reset.cordon.contains(&("a".to_string(), false)), "{:?}", reset.cordon);
        // One given up on that turns up as the release after all is done, and the plan goes on.
        let mut back = nodes.clone();
        (back[0].version, back[0].failed) = (Some("2".into()), None);
        let on = step(&plan(spec.clone(), Some(&paused)), Some(("2", "next@1")), &back, 200);
        assert_eq!(
            (on.status["phase"].as_str(), told(&on)),
            (Some("Progressing"), vec!["b".to_string()])
        );
        // Another release is another rollout, from nothing.
        let next = step(&plan(spec.clone(), Some(&paused)), Some(("3", "newer@1")), &nodes, 240);
        assert_eq!(told(&next), ["a"]);
        // One that never comes back fails after a while, and that pauses the plan too.
        nodes[0].failed = None;
        let late = step(&plan(spec, Some(&first)), Some(("2", "next@1")), &nodes, PATIENCE + 1);
        assert_eq!(late.status["phase"], "Paused");
        assert!(late.status["reason"].as_str().unwrap().contains("did not come back"));
    }

    #[test]
    fn update_reports_what_a_node_runs_and_what_it_failed_to_become() {
        let state = std::env::temp_dir().join(format!("kith-update-{}", std::process::id()));
        std::fs::create_dir_all(&state).unwrap();
        assert_eq!(report(&state, "1", 'a'), json!({ "version": "1", "slot": "a" }));
        // It became what it tried: nothing to say, and the note is gone.
        std::fs::write(tried(&state), r#"{"version":"2"}"#).unwrap();
        assert_eq!(report(&state, "2", 'b'), json!({ "version": "2", "slot": "b" }));
        assert!(!tried(&state).exists());
        // It is back as what it was: said at every start, until a plan lets go of it.
        std::fs::write(tried(&state), r#"{"version":"2"}"#).unwrap();
        let said = report(&state, "1", 'a');
        assert_eq!(
            (&said["failed"], &said["why"]),
            (&json!("2"), &json!("it did not come up; the node is back on 1"))
        );
        std::fs::write(tried(&state), r#"{"version":"2","why":"the release is not signed"}"#).unwrap();
        assert_eq!(report(&state, "1", 'a')["why"], "the release is not signed");
        assert!(tried(&state).exists());
        assert_eq!(
            version_in("NAME=\"kith OS\"\nVERSION_ID=0.0.1\n").as_deref(),
            Some("0.0.1")
        );
        assert_eq!(version_in("NAME=x\n"), None);
    }

    #[test]
    fn whole_torn_or_empty_marker_is_read_as_none() {
        let state = std::env::temp_dir().join(format!("kith-whole-update-{}", std::process::id()));
        std::fs::create_dir_all(&state).unwrap();
        for torn in ["", "{", r#"{"version":"2","why":"the rel"#] {
            crate::pki::write_whole(&tried(&state), torn.as_bytes()).unwrap();
            assert_eq!(
                report(&state, "1", 'a'),
                json!({ "version": "1", "slot": "a" }),
                "{torn:?}"
            );
        }
        std::fs::remove_dir_all(&state).unwrap();
    }
}
