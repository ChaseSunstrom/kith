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

/// Forget the update that was tried: the note is removed, and the directory written out,
/// so a power cut does not bring it back (a stale "failed" in the node's status).
fn forget(state: &Path) -> std::io::Result<()> {
    std::fs::remove_file(tried(state))?;
    std::fs::File::open(state)?.sync_all()
}

/// What this node's status says of its system: what it runs, and an update that did not
/// take. An update that did is forgotten here.
fn report(state: &Path, version: &str, slot: char) -> Value {
    let was: Option<Tried> = std::fs::read(tried(state))
        .ok()
        .and_then(|text| serde_json::from_slice(&text).ok());
    match was {
        Some(tried) if tried.version == version => {
            let _ = forget(state);
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

/// Whose releases this node becomes: the keys it was started with (`--release-key`), or
/// else the key of the first release it took, kept in its state. An OSRelease names its
/// own `publicKey`, and whoever may apply one may name any: the node is who must know.
#[derive(Clone)]
pub struct Keys {
    given: Vec<String>,
    kept: PathBuf,
    /// Where the floor is kept: see `floor`.
    floor: PathBuf,
}

impl Keys {
    pub fn new(given: Vec<String>, state: &Path) -> Keys {
        let (kept, floor) = (state.join("os-release-keys"), state.join("os-release-floor"));
        Keys { given, kept, floor }
    }

    /// Refuses a release whose key is not one of this node's. `Ok(true)`: it has none
    /// yet, and this key is to be kept once it has signed an update.
    fn refused(&self, public: Option<&str>) -> Result<bool, String> {
        // (Only a file that is not there is no key yet: one that cannot be read is not.)
        let kept = match std::fs::read_to_string(&self.kept) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            kept => kept.map_err(|e| format!("reading this node's release keys ({}): {e}", self.kept.display()))?,
        };
        let kept = kept.lines().map(str::trim);
        let kept = kept.filter(|key| !key.is_empty() && !key.starts_with('#'));
        let mine: Vec<&str> = match self.given.is_empty() {
            true => kept.collect(),
            false => self.given.iter().map(|key| key.trim()).collect(),
        };
        match public {
            _ if mine.is_empty() => Ok(true),
            Some(public) if mine.iter().any(|key| key.eq_ignore_ascii_case(public.trim())) => Ok(false),
            _ => Err(format!(
                "the release is not signed by a key this node takes releases from: start kithd with \
                 --release-key for a new one (on kith OS: `-- --release-key KEY` in the config \
                 partition); the key it holds is in {}",
                self.kept.display()
            )),
        }
    }

    /// Where keys a release hands over wait until this node runs that release.
    fn next(&self) -> PathBuf {
        self.kept.with_extension("next")
    }

    /// The keys `release` hands over to, as this node keeps them once it runs it. None: it
    /// hands nothing over, or this node was started with its keys, or its keys were handed
    /// over at that version or a later one already (an old release, shown again to bring a
    /// key back). A handover that is not whole is the release refused: whoever made it
    /// believes the nodes have new keys.
    fn handed(&self, release: &Value, version: &str, header: &[u8]) -> Result<Option<String>, String> {
        let handover = &release["handover"];
        if handover.is_null() || !self.given.is_empty() {
            return Ok(None);
        }
        let named: Vec<String> = serde_json::from_value(handover["keys"].clone()).unwrap_or_default();
        let key = |key: &String| key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit());
        if named.is_empty() || named.len() > 8 || !named.iter().all(key) {
            return Err("the release's handover names 1 to 8 keys (64 hex digits each), and this one does not".into());
        }
        let kept = std::fs::read_to_string(&self.kept).unwrap_or_default();
        if let Some(since) = kept.lines().find_map(|line| line.strip_prefix(SINCE)) {
            let since = since.trim();
            if since == version || before(version, since) {
                return Ok(None);
            }
            if !before(since, version) {
                return Err(format!(
                    "the release hands keys over as kith OS {version}, and this node's keys came with {since}: it \
                     cannot tell which of the two is the later (they differ after their numbers). Hand keys \
                     over in a release with a higher number"
                ));
            }
        }
        let text = handover_text(version, header, &named);
        let by = |field: &str, key: &str| {
            let signature = handover[field].as_str().unwrap_or_default();
            kith_packages::artifact::signed_by(&text, signature, key).unwrap_or(false)
        };
        if !release["publicKey"]
            .as_str()
            .is_some_and(|public| by("signature", public))
        {
            return Err(
                "the release's handover is not signed by the release's key over these keys, this \
                        version and this update (`handover.signature`)"
                    .into(),
            );
        }
        if !named.iter().any(|key| by("proof", key)) {
            return Err(
                "the release's handover is signed by none of the keys it names (`handover.proof`): \
                        keys nobody has shown they hold are not taken"
                    .into(),
            );
        }
        let mut named: Vec<String> = named.iter().map(|key| key.to_ascii_lowercase()).collect();
        named.sort();
        Ok(Some(format!("{SINCE}{version}\n{}\n", named.join("\n"))))
    }

    /// For an update this node, which runs `runs`, is about to write: what its release
    /// hands over is put aside, and what an update that never ran had put aside is taken
    /// away. Not what the release this node runs put aside: those keys are waiting for
    /// its slot to be called good, and the update waits with them.
    fn pend(&self, release: &Value, version: &str, header: &[u8], runs: &str) -> Result<(), String> {
        let next = self.next();
        let failed = |e: std::io::Error| format!("keeping the keys the release hands over ({}): {e}", next.display());
        let handed = self.handed(release, version, header)?;
        let waiting = std::fs::read_to_string(&next).unwrap_or_default();
        if waiting.lines().next() == Some(&format!("{SINCE}{runs}")) {
            return Err(crate::os::TOO_EARLY.into());
        }
        match handed {
            Some(text) => crate::pki::write_whole(&next, text.as_bytes()).map_err(failed),
            None => match std::fs::remove_file(&next) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(failed(e)),
                _ => Ok(()),
            },
        }
    }

    /// This node runs `version` well: keys the release of that version handed over are its
    /// keys from now on (`true`), and the ones it had are left beside them (`.before`).
    /// Not before: an update that does not come up is tried again, under the keys it had.
    fn taken(&self, version: &str) -> Result<bool, String> {
        let failed = |e: std::io::Error| format!("taking the keys handed over ({}): {e}", self.kept.display());
        let next = match std::fs::read_to_string(self.next()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            next => next.map_err(failed)?,
        };
        if next.lines().next() != Some(&format!("{SINCE}{version}")) {
            return Ok(false);
        }
        // (Stopped after the keys were written and before the note was removed: only that is left.)
        if std::fs::read_to_string(&self.kept).ok().as_deref() != Some(&next) {
            match std::fs::copy(&self.kept, self.kept.with_extension("before")) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(failed(e)),
                _ => {}
            }
            crate::pki::write_whole(&self.kept, next.as_bytes()).map_err(failed)?;
        }
        std::fs::remove_file(self.next()).map_err(failed)?;
        Ok(true)
    }
}

/// In a node's kept keys: the version of the release that handed them over.
const SINCE: &str = "# since ";

/// What a handover's two signatures are over: the keys, and the release they come with
/// (its version, and the hash of its update's signed header), under a first line no
/// other signed text of kith's begins with. `sh os/update.sh --handover` writes the same.
fn handover_text(version: &str, header: &[u8], keys: &[String]) -> Vec<u8> {
    let mut keys: Vec<String> = keys.iter().map(|key| key.trim().to_ascii_lowercase()).collect();
    keys.sort();
    let sum = crate::pki::hex(ring::digest::digest(&ring::digest::SHA256, header).as_ref());
    format!("kith os-release keys v1\n{version}\n{sum}\n{}\n", keys.join("\n")).into_bytes()
}

/// Is version `a` before `b`? Their numbers compare as numbers (1.9 is before 1.10), and
/// one with a word after them (`1.0-rc1`) is before the same numbers without.
// ponytail: two words after the same numbers compare alike (1.0-rc1 is not before
// 1.0-rc2). Give them semver's order when releases use them.
fn before(a: &str, b: &str) -> bool {
    let parts = |version: &str| -> (Vec<u64>, bool) {
        let mut parts = version
            .split(|c: char| !c.is_ascii_alphanumeric())
            .map(str::parse::<u64>);
        let numbers: Vec<u64> = parts.by_ref().map_while(Result::ok).collect();
        let whole = numbers.len() == version.split(|c: char| !c.is_ascii_alphanumeric()).count();
        (numbers, whole)
    };
    parts(a) < parts(b)
}

/// Refuses a release older than `floor`, what this node runs (no floor: the plan allows it).
fn not_back(version: &str, floor: Option<&str>) -> Result<(), String> {
    match floor {
        Some(floor) if before(version, floor) => Err(format!(
            "kith OS {version} is older than the {floor} this node runs: a plan with \
             `allowDowngrade: true` takes it back"
        )),
        _ => Ok(()),
    }
}

/// The floor: the newest version this node ever ran well (its slot was marked good), kept
/// in its state beside its keys. No release under it is taken, whatever slot the node
/// runs from now and whatever a plan allows: a node that fell back to its older slot, or
/// whose cluster was taken, is not walked down to a release with a hole that was since
/// mended. It is taken away by removing the file at the node, and by nothing else.
fn floor(file: &Path) -> Result<Option<String>, String> {
    let unread = |why: String| {
        let file = file.display();
        format!("this node's floor ({file}) {why}: no update is taken until it says a version, or is removed")
    };
    match std::fs::read_to_string(file) {
        // (Only a file that is not there is no floor: one that cannot be read is not.)
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(unread(format!("cannot be read ({e})"))),
        Ok(text) if text.trim().starts_with(|c: char| c.is_ascii_digit()) => Ok(Some(text.trim().to_string())),
        Ok(_) => Err(unread("says no version".into())),
    }
}

/// Refuses a release under the floor.
fn above(file: &Path, version: &str) -> Result<(), String> {
    match floor(file)? {
        Some(floor) if before(version, &floor) => Err(format!(
            "kith OS {version} is older than {floor}, the newest this node has run well: it takes nothing under \
             that, whatever a plan allows (to go back, release the older system again under a newer version; \
             the floor is {})",
            file.display()
        )),
        _ => Ok(()),
    }
}

/// This node runs `version` well: that is the floor, if the floor was lower.
fn raise(file: &Path, version: &str) -> Result<(), String> {
    match floor(file)? {
        Some(floor) if !before(&floor, version) => Ok(()),
        // (A version that is no number is no floor: `above` could not compare with it.)
        _ if !version.starts_with(|c: char| c.is_ascii_digit()) => Ok(()),
        _ => crate::pki::write_whole(file, format!("{version}\n").as_bytes())
            .map_err(|e| format!("keeping this node's floor ({}): {e}", file.display())),
    }
}

/// The update file at `url`, into this node's other slot, if it is the release's: signed
/// by its key, and the version it says.
async fn fetch(
    url: &str,
    wanted: String,
    release: &Value,
    slot: char,
    keys: &Keys,
    runs: &str,
    back: bool,
) -> Result<String, String> {
    let text = |field: &str| release[field].as_str().map(str::to_string);
    let (signature, public) = (text("signature"), text("publicKey"));
    above(&keys.floor, &wanted)?;
    let first = keys.refused(public.as_deref())?;
    let (kept, runs, keys, release) = (keys.kept.clone(), runs.to_string(), keys.clone(), release.clone());
    let client = reqwest::Client::builder()
        // (The address is the release's, and the release is what was applied: nowhere else.)
        .redirect(reqwest::redirect::Policy::none())
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
    if !response.status().is_success() {
        return Err(format!(
            "fetching {url}: it answers {}, and a redirect is not followed",
            response.status()
        ));
    }
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
        let public = public.clone();
        let signed = crate::os::signed(signature.as_deref(), public.as_deref());
        let vouched = |header: &[u8]| {
            signed(header)?;
            let named: Value = serde_json::from_slice(header).map_err(|e| format!("the update's header: {e}"))?;
            match named["version"].as_str() {
                // (The version is the signed header's: what the store says is not asked.)
                Some(version) if version == wanted => {
                    not_back(version, (!back).then_some(runs.as_str()))?;
                    // (The first release this node takes, signed and the version asked
                    // for: its key is the one it takes from now on.)
                    if let (true, Some(public)) = (first, &public) {
                        let keep = crate::pki::write_whole(&kept, format!("{public}\n").as_bytes());
                        keep.map_err(|e| format!("keeping the release's key ({}): {e}", kept.display()))?;
                    }
                    keys.pend(&release, version, header, &runs)
                }
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
pub async fn node(shared: Arc<Shared>, state: PathBuf, keys: Vec<String>, mut stopping: watch::Receiver<bool>) {
    let keys = Keys::new(keys, &state);
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
    let (mut raised, mut unraised) = (false, String::new());
    loop {
        // (Its slot is marked good a little after the start, and no update is taken before.)
        if !raised && crate::os::GOOD.load(std::sync::atomic::Ordering::Relaxed) {
            match raise(&keys.floor, &version).and_then(|()| keys.taken(&version)) {
                Ok(taken) => {
                    if taken {
                        let kept = keys.kept.display();
                        eprintln!(
                            "kithd: kith OS {version} handed over its release keys: this node takes releases from those in {kept} now (the ones before: {kept}.before)"
                        );
                    }
                    raised = true;
                }
                Err(e) if e != unraised => {
                    eprintln!("kithd: {e}");
                    unraised = e;
                }
                Err(_) => {}
            }
        }
        let said = report(&state, &version, slot);
        // What the store has of this node, and a plan that says it is this node's turn.
        let (known, turn, named, back) = {
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
            let back = turn.is_some_and(|plan| plan.spec["allowDowngrade"] == true);
            (known, release.map(|release| release.spec.clone()), named, back)
        };
        // (No plan speaks of this node any more: what failed before may be tried again.)
        if said["failed"].is_string() && !named && forget(&state).is_ok() {
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
                Ok(()) => fetch(&url, wanted.clone(), &release, slot, &keys, &version, back).await,
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
                    let _ = forget(&state);
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

    /// An empty directory of this test's own.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kithd-release-keys-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn release_key_is_the_given_ones_or_the_first_kept() {
        let dir = scratch("given");
        let (ours, theirs) = ("aa11", "bb22");
        // Started with keys: those, however they are cased, and no other; none is kept.
        let given = Keys::new(vec!["AA11".into(), "cc33".into()], &dir);
        assert_eq!(given.refused(Some(ours)), Ok(false));
        let said = given.refused(Some(theirs)).unwrap_err();
        assert!(said.contains("--release-key"), "{said}");
        assert!(given.refused(None).is_err());
        // Started with none: the first is to be kept...
        let first = Keys::new(Vec::new(), &dir);
        assert_eq!(first.refused(Some(ours)), Ok(true));
        // ...and once kept (as an update signed by it does), it is the only one.
        crate::pki::write_whole(&first.kept, format!("{ours}\n").as_bytes()).unwrap();
        assert_eq!(first.refused(Some(ours)), Ok(false));
        assert!(first.refused(Some(theirs)).is_err() && first.refused(None).is_err());
        // The arguments are over what was kept.
        let moved = Keys::new(vec![theirs.into()], &dir);
        assert!(moved.refused(Some(theirs)).is_ok() && moved.refused(Some(ours)).is_err());
        // A file of keys that cannot be read is not "no key yet".
        let unread = Keys::new(Vec::new(), &dir.join("unread"));
        std::fs::create_dir_all(&unread.kept).unwrap();
        assert!(unread.refused(Some(theirs)).is_err());
    }

    #[tokio::test]
    async fn release_key_not_this_nodes_is_refused_before_anything_is_fetched() {
        let dir = scratch("refused");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/kith-os.update", listener.local_addr().unwrap());
        let release = json!({ "publicKey": "bb22", "signature": "00" });
        let keys = Keys::new(vec!["aa11".into()], &dir);
        let said = fetch(&url, "2".into(), &release, 'a', &keys, "1", true)
            .await
            .unwrap_err();
        assert!(said.contains("not signed by a key this node takes"), "{said}");
        let asked = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(asked.is_err(), "nothing was to be fetched");
    }

    /// A release key: what signs with it, and its public half as an OSRelease names it.
    fn pair() -> (impl Fn(&[u8]) -> String, String) {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let made = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(made.as_ref()).unwrap();
        let public = crate::pki::hex(pair.public_key().as_ref());
        (move |text: &[u8]| crate::pki::hex(pair.sign(text).as_ref()), public)
    }

    #[test]
    fn handover_makes_the_named_keys_this_nodes_once_it_runs_the_release() {
        let keys = Keys::new(Vec::new(), &scratch("handover"));
        let ((old, old_public), (new, new_public), (_, spare_public)) = (pair(), pair(), pair());
        crate::pki::write_whole(&keys.kept, format!("{old_public}\n").as_bytes()).unwrap();
        let header = [b' '; 64];
        let named = [spare_public.to_uppercase(), new_public.clone()];
        let text = handover_text("1.6", &header, &named);
        let release = |by: &str, named: Value, signature: String, proof: String| json!({ "publicKey": by, "handover": { "keys": named, "signature": signature, "proof": proof } });
        let good = release(&old_public, json!(named), old(&text), new(&text));

        // Signed by another than the release's key (which is the kept one), or by none of
        // the keys it names (keys nobody holds); for another version, or another update.
        let said = keys.handed(
            &release(&old_public, json!(named), new(&text), new(&text)),
            "1.6",
            &header,
        );
        assert!(
            said.clone().unwrap_err().contains("not signed by the release's key"),
            "{said:?}"
        );
        let said = keys.handed(
            &release(&old_public, json!(named), old(&text), old(&text)),
            "1.6",
            &header,
        );
        assert!(
            said.clone().unwrap_err().contains("none of the keys it names"),
            "{said:?}"
        );
        assert!(keys.handed(&good, "1.7", &header).is_err() && keys.handed(&good, "1.6", b"another").is_err());
        // No keys, more than eight, or what is no key.
        let nine: Vec<String> = (0..9).map(|_| pair().1).collect();
        for wrong in [json!([]), json!(nine), json!(["aa11"]), json!("all")] {
            let text = handover_text("1.6", &header, &[]);
            let said = keys.handed(&release(&old_public, wrong, old(&text), new(&text)), "1.6", &header);
            assert!(said.clone().unwrap_err().contains("1 to 8 keys"), "{said:?}");
        }
        // Each of those is a release refused, and none changed anything.
        for refused in [json!([]), json!(["aa11"])] {
            assert!(
                keys.pend(
                    &release(&old_public, refused, String::new(), String::new()),
                    "1.6",
                    &header,
                    "1.5"
                )
                .is_err()
            );
        }
        assert!(!keys.next().exists());
        assert!(keys.refused(Some(&new_public)).is_err() && keys.refused(Some(&old_public)) == Ok(false));

        // Signed by both: kept aside until this node runs that release well...
        keys.pend(&good, "1.6", &header, "1.5").unwrap();
        assert!(keys.refused(Some(&new_public)).is_err() && keys.refused(Some(&old_public)) == Ok(false));
        // It has started on 1.6 and is shown 1.7 before it called its slot good: the keys
        // 1.6 handed over are still waiting, and an update that would put others in their
        // place (or none) waits for them to be taken, as it waits for the slot.
        let waiting = std::fs::read_to_string(keys.next()).unwrap();
        let later = handover_text("1.7", &header, &named);
        let later = release(&old_public, json!(named), old(&later), new(&later));
        for next in [json!({ "publicKey": old_public }), later] {
            assert_eq!(
                keys.pend(&next, "1.7", &header, "1.6"),
                Err(crate::os::TOO_EARLY.to_string())
            );
            assert_eq!(std::fs::read_to_string(keys.next()).unwrap(), waiting);
        }
        // ...which it does not, back on the system it had: the update is tried again, and
        // its release is still one this node takes.
        assert_eq!(keys.taken("1.5"), Ok(false));
        assert_eq!(keys.refused(Some(&old_public)), Ok(false));
        // It does: the keys named are this node's, and the one left out signs nothing more.
        assert_eq!(keys.taken("1.6"), Ok(true));
        assert_eq!(keys.refused(Some(&new_public)), Ok(false));
        assert_eq!(keys.refused(Some(&spare_public)), Ok(false));
        assert!(keys.refused(Some(&old_public)).is_err());
        assert_eq!(
            std::fs::read_to_string(keys.kept.with_extension("before")).unwrap(),
            format!("{old_public}\n")
        );
        assert!(!keys.next().exists() && keys.taken("1.6") == Ok(false));

        // A handover of the version these keys were written at, or of one before (an old
        // release shown again, to bring a key back): the release may be taken, its keys not.
        let back = [old_public.clone()];
        for version in ["1.6", "1.5"] {
            let text = handover_text(version, &header, &back);
            let again = release(&new_public, json!(back), new(&text), old(&text));
            assert_eq!(keys.handed(&again, version, &header), Ok(None));
        }
        // One at a version this node cannot place after the one its keys came with (a
        // word after the same numbers) is refused aloud: taken in silence, the release
        // would run and its keys would not count.
        let text = handover_text("1.6-b", &header, &back);
        let worded = release(&new_public, json!(back), new(&text), old(&text));
        assert_eq!(keys.handed(&worded, "1.6-b", &header), Ok(None), "1.6-b is before 1.6");
        let kept = std::fs::read_to_string(&keys.kept).unwrap();
        std::fs::write(&keys.kept, kept.replace("# since 1.6\n", "# since 1.6-a\n")).unwrap();
        let said = keys.handed(&worded, "1.6-b", &header);
        assert!(said.clone().unwrap_err().contains("cannot tell"), "{said:?}");
        std::fs::write(&keys.kept, kept).unwrap();
        // A later one is taken as the first was, and a release that hands nothing over
        // takes away what an update that never ran had put aside.
        let text = handover_text("1.7", &header, &back);
        keys.pend(
            &release(&new_public, json!(back), new(&text), old(&text)),
            "1.7",
            &header,
            "1.6",
        )
        .unwrap();
        assert!(keys.next().exists());
        keys.pend(&json!({ "publicKey": new_public }), "1.7", &header, "1.6")
            .unwrap();
        assert!(!keys.next().exists() && keys.taken("1.7") == Ok(false));

        // A node started with its keys takes them from nobody else.
        let given = Keys::new(vec![old_public.clone()], &scratch("handover-given"));
        let text = handover_text("1.6", &header, &named);
        assert_eq!(given.handed(&good, "1.6", &header), Ok(None));
        assert!(text.starts_with(b"kith os-release keys v1\n1.6\n"));
    }

    /// What `sh os/update.sh --handover` signs is what a node checks. (Where openssl and
    /// xxd are, as for a release's own signature: skipped elsewhere.)
    #[test]
    fn handover_signed_by_the_script_is_one_a_node_takes() {
        let sh = |script: &str| std::process::Command::new("sh").args(["-c", script]).output().unwrap();
        if !sh("command -v openssl && command -v xxd").status.success() {
            eprintln!("skipped: no openssl or no xxd here");
            return;
        }
        let dir = scratch("handover-script");
        let key = |name: &str| {
            let (secret, public) = kith_packages::artifact::keygen().unwrap();
            std::fs::write(dir.join(name), secret).unwrap();
            public
        };
        let (old, new) = (key("old.key"), key("new.key"));
        let header = format!("{:<4095}\n", r#"{"format":1,"version":"1.6","hash":"00","pieces":[]}"#);
        std::fs::write(dir.join("update"), format!("{header}the pieces")).unwrap();
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../os/update.sh");
        let sign = |by: &str| {
            let (dir, new) = (dir.display(), new.to_uppercase());
            let made = sh(&format!("sh {script} --handover {dir}/{by} {dir}/update {old} {new}"));
            assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
            String::from_utf8(made.stdout)
                .unwrap()
                .split_whitespace()
                .collect::<String>()
        };
        let keys = Keys::new(Vec::new(), &dir);
        let handover = json!({ "keys": [new, old], "signature": sign("old.key"), "proof": sign("new.key") });
        let release = json!({ "publicKey": old, "handover": handover });
        let said = keys.handed(&release, "1.6", header.as_bytes());
        assert!(said.clone().is_ok_and(|keys| keys.is_some()), "{said:?}");
        // What is no public key (the key file's name, say) is not signed for.
        let made = sh(&format!(
            "sh {script} --handover {0}/old.key {0}/update {0}/new.key",
            dir.display()
        ));
        let said = String::from_utf8_lossy(&made.stderr);
        assert!(!made.status.success() && said.contains("is not a public key"), "{said}");
    }

    #[test]
    fn floor_is_the_newest_version_called_good_and_is_never_lowered() {
        let keys = Keys::new(Vec::new(), &scratch("floor"));
        let kept = || std::fs::read_to_string(&keys.floor).unwrap();
        // None yet: anything is above it.
        assert!(above(&keys.floor, "0.1").is_ok());
        raise(&keys.floor, "1.10").unwrap();
        assert_eq!(kept(), "1.10\n");
        // Back on an older slot, which is called good again: the floor stays.
        raise(&keys.floor, "1.9").unwrap();
        assert_eq!(kept(), "1.10\n");
        let said = above(&keys.floor, "1.9").unwrap_err();
        assert!(said.contains("1.10") && said.contains("os-release-floor"), "{said}");
        assert!(above(&keys.floor, "1.10").is_ok() && above(&keys.floor, "1.11").is_ok());
        raise(&keys.floor, "1.11").unwrap();
        assert_eq!(kept(), "1.11\n");
        assert!(above(&keys.floor, "1.10").is_err());
        // A floor that cannot be read, or says no version, is not "no floor": nothing is
        // taken, and nothing is written over it.
        for unread in ["", "newest\n"] {
            std::fs::write(&keys.floor, unread).unwrap();
            let said = above(&keys.floor, "99").unwrap_err();
            assert!(
                said.contains("os-release-floor") && said.contains("no update is taken"),
                "{said}"
            );
            assert!(raise(&keys.floor, "99").is_err());
            assert_eq!(kept(), unread);
        }
        std::fs::remove_file(&keys.floor).unwrap();
        std::fs::create_dir(&keys.floor).unwrap();
        assert!(above(&keys.floor, "99").is_err() && raise(&keys.floor, "99").is_err());
        // Taken away at the node: there is none.
        std::fs::remove_dir(&keys.floor).unwrap();
        assert!(above(&keys.floor, "0.1").is_ok());
    }

    #[tokio::test]
    async fn floor_holds_on_an_older_slot_and_under_a_plan_that_allows_going_back() {
        let keys = Keys::new(vec!["aa11".into()], &scratch("floor-held"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/kith-os.update", listener.local_addr().unwrap());
        let release = json!({ "publicKey": "aa11", "signature": "00" });
        raise(&keys.floor, "1.10").unwrap();
        // The node is back on the slot of 1.8 and its plan allows a downgrade (so what it
        // runs is no limit): 1.9 is still under what it once ran well.
        let said = fetch(&url, "1.9".into(), &release, 'a', &keys, "1", true)
            .await
            .unwrap_err();
        assert!(said.contains("1.10") && said.contains("os-release-floor"), "{said}");
        std::fs::write(&keys.floor, "?").unwrap();
        let said = fetch(&url, "2.0".into(), &release, 'a', &keys, "1", true)
            .await
            .unwrap_err();
        assert!(said.contains("no update is taken"), "{said}");
        let asked = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(asked.is_err(), "nothing was to be fetched");
    }

    #[test]
    fn downgrade_is_an_older_version() {
        for (a, b) in [
            ("1.9", "1.10"),
            ("0.1.0", "0.1.1"),
            ("2026.11.1", "2026.11.13"),
            ("1", "1.0"),
        ] {
            assert!(before(a, b) && !before(b, a), "{a} {b}");
        }
        assert!(!before("1.2.3", "1.2.3"));
        // Refused, unless the plan allows it (then there is no floor).
        let said = not_back("1.9", Some("1.10")).unwrap_err();
        assert!(said.contains("allowDowngrade"), "{said}");
        assert!(not_back("1.10", Some("1.10")).is_ok() && not_back("1.9", None).is_ok());
        assert!(!before("0.0.0-broken", "0.0.0-next") && !before("0.0.0-next", "0.0.0-broken"));
        // A word after the numbers is before the numbers alone, and before greater ones.
        assert!(before("1.0-rc1", "1.0") && !before("1.0", "1.0-rc1"));
        assert!(before("0.0.0-next", "0.0.1") && before("1.0", "1.1-rc1"));
    }

    #[tokio::test]
    async fn no_redirect_is_followed_for_an_update() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = scratch("redirect");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let elsewhere = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let to = elsewhere.local_addr().unwrap();
        let url = format!("http://{}/kith-os.update", listener.local_addr().unwrap());
        let answering = tokio::spawn(async move {
            let (mut asked, _) = listener.accept().await.unwrap();
            let _ = asked.read(&mut [0; 1024]).await;
            let moved = format!("HTTP/1.1 302 Found\r\nLocation: http://{to}/x\r\nContent-Length: 0\r\n\r\n");
            asked.write_all(moved.as_bytes()).await.unwrap();
        });
        let release = json!({ "publicKey": "aa11", "signature": "00" });
        let keys = Keys::new(Vec::new(), &dir);
        let said = fetch(&url, "2".into(), &release, 'a', &keys, "1", true)
            .await
            .unwrap_err();
        assert!(said.contains("302") && said.contains("redirect"), "{said}");
        answering.await.unwrap();
        let asked = tokio::time::timeout(Duration::from_millis(200), elsewhere.accept()).await;
        assert!(asked.is_err(), "the redirect was followed");
        // (And a key is kept only once it has signed the update asked for.)
        assert!(!keys.kept.exists());
    }

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
