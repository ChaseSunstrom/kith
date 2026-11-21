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
    /// It carries the `kith.dev/drain` taint now.
    pub drained: bool,
    /// That drain is stamped by an UpdatePlan that is gone: a plan that picks the node takes it over.
    pub stale: bool,
    /// What the drain plan says moves off it and is not running elsewhere yet
    /// (`sched::drain_waits`); read only for a node the plan is draining.
    pub waits: Vec<String>,
    /// A seat of it that last said `active` or `fullscreen` (its name, and which); none for a node
    /// whose seats are idle, say nothing or are not there.
    pub seat: Option<(String, String)>,
}

/// What [`step`] wants written.
#[derive(Debug, PartialEq)]
pub struct Decided {
    pub status: Map<String, Value>,
    /// Nodes to stop placing workloads on (true) or to place them on again (false).
    pub cordon: Vec<(String, bool)>,
    /// Nodes to drain (true) or undrain (false): only those the plan drained itself.
    pub drain: Vec<(String, bool)>,
}

/// What the plan holds on nodes besides their cordon, and what it said of them.
#[derive(Default)]
struct Held {
    /// Nodes it put the drain on (not one an operator had put there).
    drained: Vec<String>,
    /// Nodes let go of before their drain ended, and why, until each is done.
    gave: BTreeMap<String, String>,
    drain: Vec<(String, bool)>,
    /// Nodes whose drain was lifted, until a Node shows none: a lift that was lost is made up.
    lifting: Vec<String>,
    /// Nodes held back for a seat that is not idle, and since when (`waitForIdleSeats`).
    idle: BTreeMap<String, u64>,
}

/// Seconds a drain waits for what moves, unless the plan says (`drainSeconds`).
const DRAIN_SECONDS: u64 = 300;
/// The most a plan may ask a drain to wait: a node is not held off its update for longer.
const DRAIN_CEILING: u64 = 3600;
/// Seconds a node waits for its seat to be idle, unless the plan says (`idleWaitSeconds`), and the
/// most it may ask: the update never hangs on a machine in daily use.
const IDLE_SECONDS: u64 = 3600;
const IDLE_CEILING: u64 = 86_400;

/// How many replicas, as words. The plan's status says how many, never which: an UpdatePlan is
/// read by whoever may read UpdatePlans, and a replica's name is its namespace's.
fn replicas(count: usize) -> String {
    format!("{count} replica{}", if count == 1 { "" } else { "s" })
}

/// Lets go of what the plan put on `name`: its cordon, its drain, what it said of it.
fn let_go(name: &str, cordoned: &mut Vec<String>, held: &mut Held, cordon: &mut Vec<(String, bool)>) {
    if let Some(at) = cordoned.iter().position(|cordoned| cordoned == name) {
        cordoned.remove(at);
        cordon.push((name.to_string(), false));
    }
    if let Some(at) = held.drained.iter().position(|drained| drained == name) {
        held.drained.remove(at);
        held.drain.push((name.to_string(), false));
        held.lifting.push(name.to_string());
    }
    held.gave.remove(name);
}

/// Lets go of each node the plan is draining but `keep` does not name: it left the selector, the
/// release is gone, or the plan stopped or no longer drains.
fn let_go_draining(
    states: &mut BTreeMap<String, String>,
    since: &mut BTreeMap<String, u64>,
    cordoned: &mut Vec<String>,
    held: &mut Held,
    cordon: &mut Vec<(String, bool)>,
    keep: impl Fn(&str) -> bool,
) {
    let gone: Vec<String> = states
        .iter()
        .filter(|(name, state)| *state == "draining" && !keep(name))
        .map(|(name, _)| name.clone())
        .collect();
    for name in gone {
        states.remove(&name);
        since.remove(&name);
        let_go(&name, cordoned, held, cordon);
    }
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
    let names = |key: &str| -> Vec<String> {
        let names = old.and_then(|status| status[key].as_array());
        names
            .into_iter()
            .flatten()
            .filter_map(|name| text(Some(name)))
            .collect()
    };
    let gave = old
        .and_then(|status| status["gaveUp"].as_object())
        .into_iter()
        .flatten()
        .filter_map(|(name, why)| Some((name.clone(), why.as_str()?.to_string())))
        .collect();
    // The wait for a seat counts continuous picking: it is kept only by the pass that picks, so any
    // other (paused, a closed window, no release) writes none and the clock starts again.
    let mut idle_before: BTreeMap<String, u64> = old
        .and_then(|status| status["idleSince"].as_object())
        .into_iter()
        .flatten()
        .filter_map(|(name, at)| Some((name.clone(), at.as_u64()?)))
        .collect();
    let mut held = Held {
        drained: names("drained"),
        gave,
        drain: Vec::new(),
        lifting: Vec::new(),
        idle: BTreeMap::new(),
    };
    // A lift that was lost (the Node still shows the drain) is asked for again.
    for name in names("undraining") {
        if nodes.iter().any(|node| node.name == name && node.drained) {
            held.drain.push((name.clone(), false));
            held.lifting.push(name);
        }
    }
    let done = |phase: &str, reason: String, states, since, cordoned: Vec<String>, cordon, held: Held| Decided {
        status: Map::from_iter([
            ("phase".to_string(), json!(phase)),
            ("reason".to_string(), json!(reason)),
            ("release".to_string(), json!(release.map(|(version, _)| version))),
            ("of".to_string(), json!(release.map(|(_, of)| of))),
            ("nodes".to_string(), json!(states)),
            ("since".to_string(), json!(since)),
            ("cordoned".to_string(), json!(cordoned)),
            ("drained".to_string(), json!(held.drained)),
            ("undraining".to_string(), json!(held.lifting)),
            ("gaveUp".to_string(), json!(held.gave)),
            ("idleSince".to_string(), json!(held.idle)),
        ]),
        cordon,
        drain: held.drain,
    };
    let Some((target, of)) = release else {
        let why = format!("there is no OSRelease {}", spec["release"].as_str().unwrap_or_default());
        // (Nothing is being drained for a release that is not there.)
        let_go_draining(&mut states, &mut since, &mut cordoned, &mut held, &mut cordon, |_| {
            false
        });
        return done("Waiting", why, states, since, cordoned, cordon, held);
    };
    // Another release than the one this status is about, or that one changed (signed
    // anew, say): a new rollout, from nothing.
    if old.is_some_and(|status| status["of"].as_str() != Some(of)) {
        states.clear();
        since.clear();
        reason.clear();
        // (Nobody is updating now: whoever was kept free of workloads for it is not, nor drained.)
        for name in cordoned.clone().into_iter().chain(held.drained.clone()) {
            let_go(&name, &mut cordoned, &mut held, &mut cordon);
        }
        held.gave.clear();
        idle_before.clear();
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
            Some("updating" | "failed" | "draining") | None if node.version.as_deref() == Some(target) => {
                ("done", None)
            }
            Some("updating") if failed.is_some() => ("failed", failed.map(|(_, why)| why.clone())),
            Some("updating") if late => ("failed", Some("it did not come back as the new version".into())),
            _ => continue,
        };
        if matches!(state, Some("updating" | "draining")) {
            since.remove(&node.name);
            let_go(&node.name, &mut cordoned, &mut held, &mut cordon);
        }
        if let Some(why) = why {
            reason = format!("{} did not take {target}: {why}", node.name);
        }
        states.insert(node.name.clone(), next.into());
    }
    let count = |state: &str, states: &BTreeMap<String, String>| states.values().filter(|s| *s == state).count();
    let paused = spec["paused"].as_bool() == Some(true);
    // A plan that stops, or that no longer drains, lets go of the nodes it was draining, as does
    // a node that left the selector: each goes again when the plan does.
    let stops = paused || count("failed", &states) > 0 || spec["drain"].as_bool() != Some(true);
    let keep = |name: &str| !stops && targets.iter().any(|node| node.name == name);
    let_go_draining(&mut states, &mut since, &mut cordoned, &mut held, &mut cordon, keep);
    if count("failed", &states) > 0 {
        return done("Paused", reason, states, since, cordoned, cordon, held);
    }
    if paused {
        return done(
            "Paused",
            "the plan says paused".into(),
            states,
            since,
            cordoned,
            cordon,
            held,
        );
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
        return done("Done", why.into(), states, since, cordoned, cordon, held);
    }
    // A node whose drain has nothing left to move is told to restart; one whose movable replicas
    // are not running elsewhere after `drainSeconds` is let go, with the reason.
    let patience = spec["drainSeconds"]
        .as_u64()
        .unwrap_or(DRAIN_SECONDS)
        .min(DRAIN_CEILING);
    for node in &targets {
        if states.get(&node.name).map(String::as_str) != Some("draining") {
            continue;
        }
        let began = since.get(&node.name).copied().unwrap_or(now);
        if node.waits.is_empty() || now.saturating_sub(began) >= patience {
            if !node.waits.is_empty() {
                let why = format!(
                    "{} was let go after {patience} seconds: {} still not running on another node \
                     (`kith node drain {} --dry-run` names those you may read)",
                    node.name,
                    replicas(node.waits.len()),
                    node.name
                );
                held.gave.insert(node.name.clone(), why);
            }
            states.insert(node.name.clone(), "updating".into());
            since.insert(node.name.clone(), now);
        } else if held.drained.contains(&node.name) {
            // (Asked for again: a write that was lost is made up.)
            held.drain.push((node.name.clone(), true));
        }
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
        Err(why) => return done("Waiting", why, states, since, cordoned, cordon, held),
        Ok(open) if !open.is_empty() && !open.contains(&true) => {
            return done(
                "Waiting",
                "outside the plan's windows".into(),
                states,
                since,
                cordoned,
                cordon,
                held,
            );
        }
        Ok(_) => {}
    }

    // Who goes next: those that do not vote first, the leader last; a voter goes alone,
    // and only while every other voter is up, so the store keeps its majority.
    let most = spec["maxUnavailable"].as_u64().unwrap_or(1).max(1) as usize;
    let going = |states: &BTreeMap<String, String>| -> Vec<&Node> {
        let going = |node: &&&Node| {
            matches!(
                states.get(&node.name).map(String::as_str),
                Some("updating" | "draining")
            )
        };
        targets.iter().filter(going).copied().collect()
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
    // With `waitForIdleSeats` a node whose seat is busy is not picked, until `idleWaitSeconds` from
    // when it was first held back (a seat that says idle, or none, ends the wait).
    let idle_patience = spec["idleWaitSeconds"]
        .as_u64()
        .unwrap_or(IDLE_SECONDS)
        .min(IDLE_CEILING);
    let idle_wait = spec["waitForIdleSeats"].as_bool() == Some(true);
    let mut idle = BTreeMap::new();
    let mut seat_waits = Vec::new();
    for node in waiting {
        let now_going = going(&states);
        let alone = now_going.is_empty();
        let fits = now_going.len() < most && !now_going.iter().any(|other| other.voter);
        let busy = node.seat.as_ref().filter(|_| idle_wait);
        // (The count runs while it waits for its turn too.)
        let began = idle_before.get(&node.name).copied().unwrap_or(now);
        if busy.is_some() {
            idle.insert(node.name.clone(), began);
        }
        if !(if node.voter { alone && voters_up } else { fits }) {
            continue;
        }
        if let Some((seat, says)) = busy {
            if now.saturating_sub(began) < idle_patience {
                seat_waits.push(format!(
                    "waiting for seat {seat} of {} to be idle (it says {says})",
                    node.name
                ));
                continue;
            }
            let why = format!(
                "{} was let go after {idle_patience} seconds: seat {seat} still said {says}",
                node.name
            );
            held.gave.insert(node.name.clone(), why);
            idle.remove(&node.name);
        }
        since.insert(node.name.clone(), now);
        if spec["drain"].as_bool() == Some(true) {
            // Cordoned and drained, then restarted once what moves is running elsewhere.
            states.insert(node.name.clone(), "draining".into());
            cordoned.push(node.name.clone());
            cordon.push((node.name.clone(), true));
            // A drain on the Node is an operator's, unless this plan's own lift of it is still
            // pending (a release changed under a drain: the node is picked again at once).
            let lifting = held.lifting.iter().position(|name| *name == node.name);
            if let Some(at) = lifting {
                held.lifting.remove(at);
                held.drain.retain(|(name, on)| *name != node.name || *on);
            }
            if !node.drained || node.stale || lifting.is_some() {
                held.drained.push(node.name.clone());
                held.drain.push((node.name.clone(), true));
            }
        } else {
            states.insert(node.name.clone(), "updating".into());
        }
    }
    held.idle = idle;
    let stuck = going(&states).is_empty() && !voters_up;
    let draining: Vec<&Node> = going(&states)
        .into_iter()
        .filter(|node| states.get(&node.name).is_some_and(|state| state == "draining"))
        .collect();
    let (phase, why) = if !draining.is_empty() {
        let waits = match draining.iter().map(|node| node.waits.len()).sum() {
            0 => "nothing left to move".to_string(),
            n => format!("waiting for {} to run on another node", replicas(n)),
        };
        let names: Vec<&str> = draining.iter().map(|node| node.name.as_str()).collect();
        ("Draining", format!("draining {}: {waits}", names.join(", ")))
    } else if stuck {
        (
            "Progressing",
            "waiting for every voting node to be up before another restarts".to_string(),
        )
    } else {
        (
            "Progressing",
            held.gave
                .values()
                .cloned()
                .chain(seat_waits)
                .collect::<Vec<_>>()
                .join("; "),
        )
    };
    done(phase, why, states, since, cordoned, cordon, held)
}

/// Puts (`on`) or takes off the OS update's cordon of a Node's spec, as its `kith.dev/update`
/// record says it put one on. A node an older kithd cordoned for an update has no record:
/// its cordon is lifted as before, unless a drain holds the node.
fn apply_cordon(spec: &mut Value, on: bool) {
    if on {
        crate::sched::cordon_on(spec, crate::sched::UPDATE_CORDON, "noSchedule");
    } else if crate::sched::has_record(spec, crate::sched::UPDATE_CORDON) {
        crate::sched::cordon_off(spec, crate::sched::UPDATE_CORDON);
    } else if !crate::sched::has_record(spec, kith_sched::DRAIN)
        && let Some(spec) = spec.as_object_mut()
    {
        spec.remove("unschedulable");
    }
}

/// The spec a Node should have for the update's cordon, given the spec it has now: `None`
/// when it has that already.
pub(crate) fn cordoned_spec(spec: &Value, on: bool) -> Option<Value> {
    let mut next = spec.clone();
    apply_cordon(&mut next, on);
    (next != *spec).then_some(next)
}

/// Puts (`on`) or takes off the drain the update put on a Node's spec. The drain's record says
/// whether an owner cordoned the node first, so lifting it leaves an operator's cordon as it
/// was; a node with no drain record has none to lift.
fn apply_drain(spec: &mut Value, on: bool) {
    if on {
        crate::sched::drain_on(spec);
    } else {
        crate::sched::drain_off(spec);
    }
}

/// The spec a Node should have for the update's drain, given the spec it has now: `None` when
/// it has that already.
fn drained_spec(spec: &Value, on: bool) -> Option<Value> {
    let mut next = spec.clone();
    apply_drain(&mut next, on);
    (next != *spec).then_some(next)
}

/// Stamps the plan on the record under `key`, in its taint's value (`plan:NAME`, after `owner;`
/// when an owner cordoned the node first): the Taint has no other field to name it in. A record
/// an operator put on has no stamp, so no plan's end lifts it.
fn stamp(spec: &mut Value, key: &str, plan: &str) {
    let Some(taint) = spec["taints"]
        .as_array_mut()
        .and_then(|taints| taints.iter_mut().find(|taint| taint["key"] == key))
    else {
        return;
    };
    let owner = taint["value"]
        .as_str()
        .is_some_and(|v| v == "owner" || v.starts_with("owner;"));
    taint["value"] = format!("{}plan:{plan}", if owner { "owner;" } else { "" }).into();
}

/// The spec `what` makes of `spec`, with the record stamped by `plan` when this write puts it
/// on, or when it is one a plan that is no longer `live` left (taken over, not left to the
/// sweep). A record that was there with no stamp, or another live plan's, is not the plan's:
/// it is left as it is. `None` when nothing changes.
fn written(
    spec: &Value,
    on: bool,
    what: fn(&Value, bool) -> Option<Value>,
    record: &str,
    plan: &str,
    live: &dyn Fn(&str) -> bool,
) -> Option<Value> {
    if !on && crate::sched::has_record(spec, record) {
        // Only the plan's own record is lifted by it; the sweep (`plan` empty) lifts a gone plan's.
        let by = stamped_by(spec, record);
        if !(if plan.is_empty() {
            by.is_some_and(|by| !live(by))
        } else {
            by == Some(plan)
        }) {
            return None;
        }
    }
    let mut next = what(spec, on).unwrap_or_else(|| spec.clone());
    let ours = !crate::sched::has_record(spec, record) || stamped_by(spec, record).is_some_and(|by| !live(by));
    if on && ours {
        stamp(&mut next, record, plan);
    }
    (next != *spec).then_some(next)
}

/// The plan whose stamp the record under `key` carries, if it has one.
fn stamped_by<'a>(spec: &'a Value, key: &str) -> Option<&'a str> {
    let taint = spec["taints"].as_array()?.iter().find(|taint| taint["key"] == key)?;
    let value = taint["value"].as_str()?;
    value.strip_prefix("owner;").unwrap_or(value).strip_prefix("plan:")
}

/// The cordon records on Nodes that an UpdatePlan which is gone put on: (node, record key).
/// `live` says whether a plan of that name exists.
fn orphans<'a>(
    nodes: impl Iterator<Item = (&'a str, &'a Value)>,
    live: impl Fn(&str) -> bool,
) -> Vec<(String, &'static str)> {
    let mut found = Vec::new();
    for (name, spec) in nodes {
        for key in [kith_sched::DRAIN, crate::sched::UPDATE_CORDON] {
            if stamped_by(spec, key).is_some_and(|plan| !live(plan)) {
                found.push((name.to_string(), key));
            }
        }
    }
    found
}

/// Set or lift the update's cordon (`what` is `cordoned_spec`) or drain (`drained_spec`) on
/// `name`; `record` is its taint's key, and a record put on is stamped with `plan`. Each try
/// re-reads the Node, so a try that lost a race to another write (a Conflict)
/// is finished by the next one; a bounded number of tries.
async fn write_cordon(
    shared: &Shared,
    name: &str,
    on: bool,
    what: fn(&Value, bool) -> Option<Value>,
    record: &str,
    plan: &str,
) {
    const TRIES: usize = 3;
    let key = format!("Node/{name}");
    for _ in 0..TRIES {
        let (found, gone) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let found = state.store.get(&key).cloned();
            // (Is the plan that stamped the record on the Node gone? `written` asks only of that one.)
            let gone = found
                .as_ref()
                .and_then(|node| stamped_by(&node.spec, record))
                .map(|by| state.store.get(&format!("UpdatePlan/{by}")).is_none());
            (found, gone.unwrap_or(false))
        };
        let Some(mut node) = found else { return };
        let Some(spec) = written(&node.spec, on, what, record, plan, &|_| !gone) else {
            return;
        };
        node.spec = spec;
        let at = kith_api::store::now();
        let sent = shared
            .submit_node(Command::Apply {
                resources: vec![node],
                at,
            })
            .await;
        match sent {
            Ok(_) => return,
            Err(kith_api::store::Error::Conflict(_)) => {}
            Err(e) => {
                eprintln!("kithd: writing an update's cordon on {name}: {e}");
                return;
            }
        }
    }
    eprintln!("kithd: {name}'s update cordon was not written in {TRIES} tries");
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
        let mut cordons = Vec::new();
        let mut drains = Vec::new();
        {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let store = &state.store;
            let seen = crate::sched::seen_at(&shared, now);
            let grace = shared.lost_after;
            // The nodes a plan has told to drain: only those are asked what they wait for.
            let draining: Vec<String> = store
                .list(Some("UpdatePlan"))
                .filter_map(|plan| plan.status.as_ref()?["nodes"].as_object())
                .flat_map(|nodes| {
                    nodes
                        .iter()
                        .filter(|(_, state)| *state == "draining")
                        .map(|(name, _)| name.clone())
                })
                .collect();
            let live = |plan: &str| store.get(&format!("UpdatePlan/{plan}")).is_some();
            let node = |node: &Resource| {
                let status = node.status.as_ref();
                let text = |value: Option<&Value>| value.and_then(Value::as_str).map(str::to_string);
                let os = status.map(|status| &status["os"]);
                let id: Option<u64> = status.and_then(|status| status["raftId"].as_str()?.parse().ok());
                let name = node.metadata.name.clone();
                let lost = shared.members.lost_for(&name, now);
                let unreachable = status.is_some_and(|status| status["state"] == "unreachable");
                Node {
                    seat: crate::seats::busy(store, &name),
                    drained: crate::sched::has_record(&node.spec, kith_sched::DRAIN),
                    stale: orphans([(name.as_str(), &node.spec)].into_iter(), live)
                        .iter()
                        .any(|(_, record)| *record == kith_sched::DRAIN),
                    waits: if draining.contains(&name) {
                        crate::sched::drain_waits(store, &seen, grace, &name)
                    } else {
                        Vec::new()
                    },
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
                let by = |(name, on)| (name, on, plan.metadata.name.clone());
                cordons.extend(decided.cordon.into_iter().map(by));
                drains.extend(decided.drain.into_iter().map(by));
            }
            // What a plan that is gone put on is lifted (written again each round until it is),
            // except on a node a live plan has or is just now taking: it takes the record over.
            let mut busy: Vec<String> = (cordons.iter().chain(&drains))
                .filter(|(_, on, _)| *on)
                .map(|(name, _, _)| name.clone())
                .collect();
            for plan in store.list(Some("UpdatePlan")) {
                let nodes = plan.status.as_ref().and_then(|status| status["nodes"].as_object());
                let going = nodes
                    .into_iter()
                    .flatten()
                    .filter(|(_, state)| *state == "draining" || *state == "updating");
                busy.extend(going.map(|(name, _)| name.clone()));
            }
            let nodes = store
                .list(Some("Node"))
                .map(|node| (node.metadata.name.as_str(), &node.spec));
            for (name, record) in orphans(nodes, live)
                .into_iter()
                .filter(|(name, _)| !busy.contains(name))
            {
                if record == kith_sched::DRAIN {
                    drains.push((name, false, String::new()));
                } else {
                    cordons.push((name, false, String::new()));
                }
            }
        }
        for command in commands {
            if let Err(e) = shared.submit(command).await {
                eprintln!("kithd: writing down an update plan's step: {e}");
            }
        }
        for (name, cordoned, plan) in cordons {
            write_cordon(
                &shared,
                &name,
                cordoned,
                cordoned_spec,
                crate::sched::UPDATE_CORDON,
                &plan,
            )
            .await;
        }
        for (name, drained, plan) in drains {
            write_cordon(&shared, &name, drained, drained_spec, kith_sched::DRAIN, &plan).await;
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

/// What this node's status says of its system: what it runs, whose releases it takes
/// (`Keys::whose`), and an update that did not take. An update that did is forgotten here.
fn report(state: &Path, version: &str, slot: char, whose: &str) -> Value {
    let was: Option<Tried> = std::fs::read(tried(state))
        .ok()
        .and_then(|text| serde_json::from_slice(&text).ok());
    let runs = json!({ "version": version, "slot": slot.to_string(), "releaseKeys": whose });
    match was {
        Some(tried) if tried.version == version => {
            let _ = forget(state);
            runs
        }
        Some(tried) => {
            let why = match tried.why.as_str() {
                "" => format!("it did not come up; the node is back on {version}"),
                why => why.to_string(),
            };
            let mut runs = runs;
            runs["failed"] = json!(tried.version);
            runs["why"] = json!(why);
            runs
        }
        None => runs,
    }
}

/// The version in an os-release file (`VERSION_ID=`).
fn version_in(os_release: &str) -> Option<String> {
    let value = os_release.lines().find_map(|line| line.strip_prefix("VERSION_ID="))?;
    Some(value.trim_matches('"').to_string()).filter(|version| !version.is_empty())
}

/// Whose releases this node becomes: the keys it was started with (`--release-key`), or
/// else the ones kept in its state (handed over, or the first it took), or else the ones
/// its system was built or installed with (`/etc/kith/release-keys`), and only with none of
/// those the key of the first release it takes. An OSRelease names its own `publicKey`, and
/// whoever may apply one may name any: the node is who must know.
#[derive(Clone)]
pub struct Keys {
    given: Vec<String>,
    /// This node's state directory: where its kept keys, floor and kept headers are.
    state: PathBuf,
    kept: PathBuf,
    /// Where the floor is kept: see `floor`.
    floor: PathBuf,
    /// The keys in the system it runs (`KITH_RELEASE_KEY` when the image was built): none
    /// off kith OS.
    image: Option<PathBuf>,
}

/// The keys in a file of them, one a line (`#` lines are notes). Only a file that is not
/// there is no keys: one that cannot be read is an error, not a node that takes any key.
pub(crate) fn keys_in(file: &Path) -> Result<Vec<String>, String> {
    let text = match std::fs::read_to_string(file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        text => text.map_err(|e| format!("reading this node's release keys ({}): {e}", file.display()))?,
    };
    let keys = text.lines().map(str::trim);
    Ok(keys
        .filter(|key| !key.is_empty() && !key.starts_with('#'))
        .map(str::to_string)
        .collect())
}

/// This node's keys for releases: the given ones, else kept, else the system's own.
pub fn keys(given: Vec<String>, state: &Path) -> Keys {
    Keys {
        image: Some(PathBuf::from("/etc/kith/release-keys")),
        ..Keys::new(given, state)
    }
}

impl Keys {
    pub fn new(given: Vec<String>, state: &Path) -> Keys {
        let (kept, floor) = (state.join("os-release-keys"), state.join("os-release-floor"));
        Keys {
            given,
            state: state.to_path_buf(),
            kept,
            floor,
            image: None,
        }
    }

    /// Check 3 of docs/adr-unlock.md for the system in `slot`, which runs the image `running`:
    /// its header, as kept, is signed by a key this node takes releases from, is not under the
    /// floor, and is the piece of the image that runs. Says which of those does not hold.
    pub fn signed_system(&self, slot: char, running: &[u8]) -> Result<(), String> {
        let (signature, public, block) = crate::os::kept_signed(&self.state, slot)?;
        let (mine, _) = self.mine()?;
        if !mine.iter().any(|key| key.eq_ignore_ascii_case(public.trim())) {
            return Err("the system's release is signed by a key this node does not take releases from".into());
        }
        crate::os::signed(Some(&signature), Some(&public))(&block)?;
        let version = crate::os::piece_of(&block, slot, running)?;
        above(&self.floor, &version)
    }

    /// How the update with header `block` is taken, against the system in `slot` that runs the
    /// image `running`: kithd alone only when the header kept for that system is its own
    /// (`signed_system`) and says the kernel and the rest of the root are the same. A missing,
    /// unsigned, stale or older-style kept header is a full update. Says why it is a full
    /// update where it is. (`Keys::way`, in the tests at the foot of this file, is the same as a `Way`.)
    pub fn kithd_only(&self, slot: char, running: &[u8], block: &[u8]) -> Result<(), String> {
        let (_, _, kept) = self
            .signed_system(slot, running)
            .and_then(|()| crate::os::kept_signed(&self.state, slot))
            .map_err(|e| format!("the running system's own release is not proven: {e}"))?;
        crate::os::why_full(block, &kept).map_or(Ok(()), |why| Err(why.to_string()))
    }

    /// The keys this node takes releases from, and whose they are: `given`, `kept`,
    /// `image`, or `none` (no keys: the first release's is taken).
    pub(crate) fn mine(&self) -> Result<(Vec<String>, &'static str), String> {
        if !self.given.is_empty() {
            return Ok((self.given.iter().map(|key| key.trim().to_string()).collect(), "given"));
        }
        let kept = keys_in(&self.kept)?;
        if !kept.is_empty() {
            return Ok((kept, "kept"));
        }
        match &self.image {
            Some(image) => match keys_in(image)? {
                keys if keys.is_empty() => Ok((keys, "none")),
                keys => Ok((keys, "image")),
            },
            None => Ok((Vec::new(), "none")),
        }
    }

    /// Whose keys this node takes releases from, for its status (`os.releaseKeys`). One
    /// it cannot read says `unread`: it takes nothing then.
    fn whose(&self) -> &'static str {
        self.mine().map_or("unread", |(_, whose)| whose)
    }

    /// What a node that takes releases from no key (or from keys it cannot read) says at
    /// its start, every start.
    fn unkeyed(&self) -> Option<String> {
        match self.mine() {
            Ok((_, "none")) => Some(
                "kithd: this node has no release key: the first kith OS release it takes sets it, \
                 whoever applies that one (give it with --release-key, or KITH_RELEASE_KEY when \
                 building the image, or `releaseKey` when installing)"
                    .to_string(),
            ),
            Err(e) => Some(format!(
                "kithd: this node's release keys could not be read ({e}): it takes no release"
            )),
            Ok(_) => None,
        }
    }

    /// What the first update this node takes keeps in its state: the keys of its system if
    /// it has any (the next system may have none), or the release's own.
    fn first_kept(&self, public: &str) -> String {
        match self.mine() {
            Ok((keys, "image")) => format!("{}\n", keys.join("\n")),
            _ => format!("{public}\n"),
        }
    }

    /// Refuses a release whose key is not one of this node's. `Ok(true)`: none is kept in
    /// its state yet, and what `first_kept` says is to be kept once it has signed an update.
    fn refused(&self, public: Option<&str>) -> Result<bool, String> {
        let (mine, whose) = self.mine()?;
        match public {
            _ if mine.is_empty() => Ok(true),
            Some(public) if mine.iter().any(|key| key.eq_ignore_ascii_case(public.trim())) => Ok(whose == "image"),
            _ => Err(format!(
                "the release is not signed by a key this node takes releases from: start kithd with \
                 --release-key for a new one (on kith OS: `-- --release-key KEY` in the config \
                 partition); the key it holds is in {}",
                self.kept.display()
            )),
        }
    }

    /// Whether a TPM seal is made ahead for the system a release signed by `public` puts in
    /// the other slot (docs/adr-unlock.md): only for a release signed by a key this node held
    /// before it (given, kept, or its image's: not the first release's, which it takes on
    /// trust, nor one a release hands over, which it holds only once it runs that release),
    /// and never under `allowDowngrade` (`back`): a node that may go back is sealed for the
    /// system it runs. (The floor is `above`'s, asked before anything is fetched.)
    fn seals_ahead(&self, public: Option<&str>, back: bool) -> bool {
        let Ok((mine, _)) = self.mine() else { return false };
        let held = public.is_some_and(|public| mine.iter().any(|key| key.eq_ignore_ascii_case(public.trim())));
        held && !back
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

/// What a kithd-only hand-over leaves for the kithd it starts (tmpfs: a reboot clears it, and
/// then the slot that boots has the new release whole): the version, a space, and the sha256
/// of the kithd that is that release's.
const HANDED_OVER: &str = "/run/kith/handed-over";
/// Where the new slot's root is mounted, for as long as the kithd in it is copied out.
const NEW_ROOT: &str = "/run/kith/new-root";
/// The most a staged kithd may be (its place is a 64 MB tmpfs: init.rs `mounts`).
const STAGE_MOST: u64 = 48 << 20;

/// Stages the kithd at `from` in `dir` (the root-only tmpfs of init.rs `mounts`): only a file whose
/// sha256 is `digest` (the signed header's), taken whole into memory so what is checked is what is
/// written, to a file of its own that only its owner may run, put in place by a rename (a kithd
/// that runs from the old one is not written into). `dir` must be there and be nobody else's
/// to use. Says the file staged.
fn stage(from: &Path, digest: &str, dir: &Path) -> Result<PathBuf, String> {
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let place = std::fs::metadata(dir).map_err(|e| format!("the place for a staged kithd ({}): {e}", dir.display()))?;
    if !place.is_dir() || place.mode() & 0o077 != 0 || place.uid() != nix::unistd::geteuid().as_raw() {
        return Err(format!(
            "{} is not a directory only this node may use: no kithd is staged there",
            dir.display()
        ));
    }
    let (new, file) = (dir.join("kithd.new"), dir.join("kithd"));
    let _ = std::fs::remove_file(&new);
    // Streamed: each chunk goes through the hasher and into `kithd.new` (at most STAGE_MOST of
    // them), and the file is put in place only when the digest comes out as the signed one.
    let wrote = (|| -> Result<(), String> {
        let mut src = std::fs::File::open(from)
            .map_err(|e| format!("reading the new kithd ({}): {e}", from.display()))?
            .take(STAGE_MOST + 1);
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&new)
            .map_err(|e| format!("staging the new kithd in {}: {e}", dir.display()))?;
        let (mut hash, mut buf, mut size) = (ring::digest::Context::new(&ring::digest::SHA256), [0u8; 65536], 0u64);
        loop {
            let n = src
                .read(&mut buf)
                .map_err(|e| format!("reading the new kithd ({}): {e}", from.display()))?;
            if n == 0 {
                break;
            }
            size += n as u64;
            if size > STAGE_MOST {
                return Err(format!(
                    "the new kithd ({}) is larger than {STAGE_MOST} bytes",
                    from.display()
                ));
            }
            hash.update(&buf[..n]);
            out.write_all(&buf[..n])
                .map_err(|e| format!("staging the new kithd in {}: {e}", dir.display()))?;
        }
        let got = crate::pki::hex(hash.finish().as_ref());
        if !got.eq_ignore_ascii_case(digest) {
            return Err(format!(
                "the new kithd's sha256 is {got}, and the release's signed header names {digest}"
            ));
        }
        out.sync_all()
            .and_then(|()| std::fs::rename(&new, &file))
            .map_err(|e| format!("staging the new kithd in {}: {e}", dir.display()))
    })();
    if let Err(e) = wrote {
        let _ = std::fs::remove_file(&new);
        return Err(e);
    }
    Ok(file)
}

/// Stages the kithd of the release just written into slot `into`, as `digest` (the signed header's)
/// has it: the slot's root is mounted read-only for as long as `/sbin/init` is read from it.
fn stage_release(into: char, digest: &str) -> Result<PathBuf, String> {
    use nix::mount::{MntFlags, MsFlags, mount, umount2};
    let device =
        crate::init::labelled(&format!("root-{into}")).ok_or(format!("no partition is labelled root-{into}"))?;
    let at = Path::new(NEW_ROOT);
    std::fs::create_dir_all(at).map_err(|e| format!("making {NEW_ROOT}: {e}"))?;
    let flags = MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    mount(Some(&device), at, Some("squashfs"), flags, None::<&str>)
        .map_err(|e| format!("mounting {}: {e}", device.display()))?;
    let staged = stage(&at.join("sbin/init"), digest, Path::new(crate::keeper::STAGED_DIR));
    // (Detached: a umount that fails with EBUSY must not leave the next hand-over's mount to fail.)
    if let Err(e) = umount2(at, MntFlags::MNT_DETACH) {
        eprintln!("kithd: update: unmounting {NEW_ROOT}: {e}");
    }
    staged
}

/// Writes down that the kithd that is the sha256 `digest` is `version`'s (see [`effective`]),
/// the node running `running` now: only a newer version is one a hand-over moves to.
fn hand_over(record: &Path, running: &str, version: &str, digest: &str) -> Result<(), String> {
    if version.is_empty() || version.contains(char::is_whitespace) || !before(running, version) {
        return Err(format!(
            "kith OS {version:?} is not a version a hand-over from {running} can write down"
        ));
    }
    crate::pki::write_whole(record, format!("{version} {digest}\n").as_bytes())
        .map_err(|e| format!("keeping a note of the hand-over ({}): {e}", record.display()))
}

/// What the hand-over note in `record` says: the version it names, if that is newer than
/// `os_release`, and whether `exe`'s sha256 is the kithd it names (so it is this one that runs).
fn handed_over(os_release: &str, record: &Path, exe: &Path) -> Option<(String, bool)> {
    let handed = std::fs::read_to_string(record).ok()?;
    let (version, digest) = handed.trim().split_once(' ')?;
    if !before(os_release, version) {
        return None;
    }
    let runs = std::fs::read(exe).map(|bytes| crate::os::sha256(&bytes));
    Some((
        version.to_string(),
        runs.is_ok_and(|runs| runs.eq_ignore_ascii_case(digest)),
    ))
}

/// The version this node runs: `os_release`'s (the root is read-only, and a kithd-only
/// hand-over leaves it as it was), or the newer one a hand-over wrote in `record`, but only for
/// the kithd it names (`exe`'s sha256): a keeper that fell back to its own kithd runs the old
/// release again, and a reboot has the new root, whose os-release says so.
fn effective(os_release: String, record: &Path, exe: &Path) -> String {
    match handed_over(&os_release, record, exe) {
        Some((version, true)) => version,
        _ => os_release,
    }
}

/// A hand-over whose kithd is not the one that runs (it crashed, and the keeper went back to
/// this one) is a try that failed: written as `Tried`, so [`node`] does not fetch and hand over
/// to that version again at every poll.
fn forgo_failed_hand_over(state: &Path, os_release: &str, record: &Path, exe: &Path) {
    let Some((version, false)) = handed_over(os_release, record, exe) else {
        return;
    };
    let tried = Tried {
        version,
        why: "the kithd handed over to failed".into(),
    };
    if let Err(e) = crate::pki::write_whole(&self::tried(state), &serde_json::to_vec(&tried).expect("text")) {
        eprintln!("kithd: update: noting the failed hand-over: {e}");
    }
}

/// The client an update is fetched with: `host`'s vetted addresses are the ones connected
/// to, through no proxy (which would look the name up again itself), and no redirect is
/// followed by it (a redirect's target is vetted, and gets a client of its own: [`get`]).
fn client(host: &str, addresses: &[std::net::SocketAddr]) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .resolve_to_addrs(host, addresses)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(30))
        // (A server that goes quiet is a download that broke, not one to wait out.)
        .read_timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())
}

/// The cluster's own /48 on the mesh (`crate::mesh::prefix`), once [`node`] knows it: the
/// nodes' and the pods' addresses, which `--lan-releases` does not open.
static MESH: std::sync::OnceLock<std::net::Ipv6Addr> = std::sync::OnceLock::new();

/// Is one of `addresses` in the cluster's /48 `mesh`?
fn on_the_mesh(mesh: Option<&std::net::Ipv6Addr>, addresses: &[std::net::SocketAddr]) -> bool {
    let within = |mesh: &std::net::Ipv6Addr, ip: std::net::IpAddr| match ip {
        std::net::IpAddr::V6(ip) => ip.octets()[..6] == mesh.octets()[..6],
        std::net::IpAddr::V4(_) => false,
    };
    mesh.is_some_and(|mesh| addresses.iter().any(|at| within(mesh, at.ip())))
}

/// The host of a release's image and the addresses it may be fetched from: outside this
/// node and its networks, or with `lan` (`--lan-releases`) in their private ranges too,
/// but for the cluster's own mesh.
async fn pinned(url: &reqwest::Url, lan: bool) -> Result<(String, Vec<std::net::SocketAddr>), String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("the release's image, {url}: it is fetched over http or https"));
    }
    match crate::sources::vetted(&url.origin().ascii_serialization(), lan).await {
        Ok((_, _, addresses)) if on_the_mesh(MESH.get(), &addresses) => Err(format!(
            "the release's image, {url}: an update is not fetched from the cluster's own mesh"
        )),
        Ok((host, _, addresses)) => Ok((host, addresses)),
        Err(crate::sources::Refused::Inward(_)) if lan => Err(format!(
            "the release's image, {url}: an update is not fetched from this node, nor from its \
             networks but for their private ranges"
        )),
        Err(crate::sources::Refused::Inward(_)) => Err(format!(
            "the release's image, {url}: an update is not fetched from this node or its own \
             networks (start kithd with --lan-releases for a release server on their private ranges)"
        )),
        Err(crate::sources::Refused::Address(why)) => Err(format!("the release's image: {why}")),
    }
}

/// Redirects an image's address may lead through before it answers.
const HOPS: usize = 5;

/// `url` as an error may say it: with no user or password, and no query (often a signature).
fn shown(url: &reqwest::Url) -> reqwest::Url {
    let mut url = url.clone();
    url.set_query(None);
    url.set_fragment(None);
    // (Only a URL that cannot have a host refuses these, and none here is one.)
    url.set_username("").ok();
    url.set_password(None).ok();
    url
}

/// The longest [`pinned`] may take: a name that is not answered is not waited for.
const VET: Duration = Duration::from_secs(30);

/// The longest the image's address takes to answer, through its redirects (what it sends
/// after the answer starts is the body's: each read of it has its own limit, `client`).
const ANSWER: Duration = Duration::from_secs(300);

/// Where a redirect from `from` goes, by its `Location`: an address of its own (a relative
/// one is read against `from`), with no user or password in it, and not a lower scheme.
/// What it is vetted as is for [`get`].
fn hop(from: &reqwest::Url, location: Option<&reqwest::header::HeaderValue>) -> Result<reqwest::Url, String> {
    let refused = |why: &str| format!("fetching {}: its redirect {why}", shown(from));
    let location = location.ok_or_else(|| refused("names no Location"))?;
    if location.len() > 2048 {
        return Err(refused("has a Location over 2048 bytes"));
    }
    let location = location
        .to_str()
        .map_err(|_| refused("has a Location that is not text"))?;
    // (Read against the address with no user or password: none is carried to another.)
    let mut to = shown(from)
        .join(location)
        .map_err(|e| refused(&format!("has a Location that is no address ({e})")))?;
    to.set_fragment(None);
    if !to.username().is_empty() || to.password().is_some() {
        return Err(refused(
            "names a userinfo (a user or password in the address): none is sent",
        ));
    }
    match (from.scheme(), to.scheme()) {
        ("https", "https") | ("http", _) => Ok(to),
        (from, to) => Err(refused(&format!("goes from {from} to {to}: a scheme is not lowered"))),
    }
}

/// The answer of the image at `url`, after at most [`HOPS`] redirects. Each address, the first
/// and every redirect's, is vetted by [`pinned`] and fetched from through a client of its own
/// holding the addresses vetted (a client that followed would look the name up again): so
/// an address that the first may not be is not a redirect's either. Says the address it
/// came from too, for what is said of the body. All of it takes [`ANSWER`] at most.
async fn get(first: reqwest::Url, lan: bool) -> Result<(reqwest::Response, reqwest::Url), String> {
    let at = shown(&first);
    let all = tokio::time::timeout(ANSWER, hops(first, lan));
    all.await
        .map_err(|_| format!("fetching {at}: no answer in {} seconds", ANSWER.as_secs()))?
}

async fn hops(first: reqwest::Url, lan: bool) -> Result<(reqwest::Response, reqwest::Url), String> {
    let (mut url, mut seen) = (first.clone(), vec![first]);
    loop {
        let at = shown(&url);
        let vetted = tokio::time::timeout(VET, pinned(&at, lan));
        let vetted = vetted
            .await
            .map_err(|_| format!("looking up {at}: no answer in {} seconds", VET.as_secs()));
        let (host, addresses) = vetted?.map_err(|why| match seen.len() {
            1 => why,
            _ => format!("after a redirect, {why}"),
        })?;
        let failed = |e: reqwest::Error| format!("fetching {at}: {}", e.without_url());
        let response = client(&host, &addresses)?.get(url.clone()).send().await;
        let response = response.and_then(|r| r.error_for_status()).map_err(failed)?;
        if !response.status().is_redirection() {
            return match response.status().is_success() {
                true => Ok((response, url)),
                false => Err(format!("fetching {at}: it answers {}", response.status())),
            };
        }
        if seen.len() > HOPS {
            return Err(format!("fetching {at}: more than {HOPS} redirects: the hop limit"));
        }
        url = hop(&url, response.headers().get(reqwest::header::LOCATION))?;
        if seen.contains(&url) {
            return Err(format!("fetching {at}: its redirects loop (to {})", shown(&url)));
        }
        seen.push(url.clone());
    }
}

/// The update file at `url`, into this node's other slot, if it is the release's: signed
/// by its key, and the version it says. Not from this node or its own networks (their
/// private ranges only with `lan`, `--lan-releases`): an OSRelease is written by whoever
/// may write one, and kithd fetches as root.
#[allow(clippy::too_many_arguments)]
async fn fetch(
    url: &str,
    wanted: String,
    release: &Value,
    slot: char,
    keys: &Keys,
    runs: &str,
    back: bool,
    lan: bool,
) -> Result<(String, Option<String>), String> {
    let text = |field: &str| release[field].as_str().map(str::to_string);
    let (signature, public) = (text("signature"), text("publicKey"));
    above(&keys.floor, &wanted)?;
    let first = keys.refused(public.as_deref())?;
    let ahead = keys.seals_ahead(public.as_deref(), back);
    let (kept, runs, keys, release) = (keys.kept.clone(), runs.to_string(), keys.clone(), release.clone());
    // (Said without the address: it may hold a password or a signed query.)
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("the release's image address: {e}"))?;
    let (mut response, came_from) = get(parsed, lan).await?;
    let failed = |e: reqwest::Error| format!("fetching {}: {}", shown(&came_from), e.without_url());
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
    // The signed digest of the new kithd, when the header says kithd alone differs.
    let only = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let said = only.clone();
    let writer = tokio::task::spawn_blocking(move || {
        let only = said;
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
                        let keep = crate::pki::write_whole(&kept, keys.first_kept(public).as_bytes());
                        keep.map_err(|e| format!("keeping the release's key ({}): {e}", kept.display()))?;
                    }
                    // (Decided here, before a slot is written, on the signed header: the slot is
                    // written whichever way it is, and a reboot into it is the way back.)
                    let running_image = crate::os::running_image_here(slot).unwrap_or_default();
                    match keys.kithd_only(slot, &running_image, header) {
                        Ok(()) => {
                            eprintln!("kithd: update: {version} differs from this system in kithd alone");
                            *only.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                                crate::os::digests(header).map(|[kithd, ..]| kithd);
                        }
                        Err(why) => eprintln!("kithd: update: {version} is a full update (a restart): {why}"),
                    }
                    keys.pend(&release, version, header, &runs)?;
                    // (The header is kept for the slot it writes, with its signature: check 3 of
                    // docs/adr-unlock.md reads it there.)
                    let into = crate::os::other(slot);
                    crate::os::keep_signed(&keys.state, into, signature.as_deref(), public.as_deref(), header)
                }
                version => Err(format!(
                    "the update at that address is kith OS {}",
                    version.unwrap_or("?")
                )),
            }
        };
        crate::os::into_slot(
            &mut Arriving(&mut pieces, Vec::new(), 0),
            slot,
            &running,
            vouched,
            ahead,
        )
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
        (Ok((Some(version), boots)), _) => {
            // (The update is in the other slot whatever comes of this: a key not sealed ahead
            // is a node that asks the cluster for it at its next start, as before.)
            match boots {
                Some(Ok(boots)) => match crate::crypt::ahead(boots).await {
                    Ok(Some(_)) => {
                        eprintln!("kithd: update: the key of this node's state is sealed ahead for {version}")
                    }
                    Ok(None) => {}
                    Err(why) => eprintln!("kithd: update: no key is sealed ahead for {version}: {why}"),
                },
                Some(Err(why)) => eprintln!("kithd: update: no key is sealed ahead for {version}: {why}"),
                None => {}
            }
            let only = only.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
            Ok((version, only))
        }
        (Ok((None, _)), _) => Err("that release is what this node runs already, under another version".into()),
        (Err(_), Some(cut)) => Err(cut),
        (Err(e), None) => Err(e),
    }
}

/// A kith OS node's part: say what it runs, and when a plan says so, become the release.
pub async fn node(
    shared: Arc<Shared>,
    state: PathBuf,
    keys: Vec<String>,
    lan: bool,
    mut stopping: watch::Receiver<bool>,
) {
    let keys = crate::update::keys(keys, &state);
    if let Some(cluster) = &shared.cluster {
        let _ = MESH.set(crate::mesh::prefix(&cluster.me.ca));
    }
    let line = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    // (After a kithd-only hand-over the root still says the old version: see `effective`.)
    let os_release = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| version_in(&text));
    let (record, exe) = (Path::new(HANDED_OVER), Path::new("/proc/self/exe"));
    if let Some(os_release) = &os_release {
        forgo_failed_hand_over(&state, os_release, record, exe);
    }
    let version = os_release.map(|version| effective(version, record, exe));
    let (Some(slot), Some(version), Some(cluster)) = (crate::init::options(&line).0.slot, version, &shared.cluster)
    else {
        return;
    };
    if let Some(unkeyed) = keys.unkeyed() {
        eprintln!("{unkeyed}");
    }
    let me = format!("Node/{}", cluster.me.name);
    let mut generation = shared.generation.subscribe();
    let (mut raised, mut unraised) = (false, String::new());
    // How its pods' storage limits hold, for whoever looks at the node.
    let storage = crate::controller::storage::how(crate::controller::storage::held_at_write(&state));
    // The os/features its PCI cards want, read once: a card put in later is seen at the next start.
    let wants = crate::devices::wants(Path::new("/sys"));
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
        let mut said = report(&state, &version, slot, keys.whose());
        said["storage"] = json!(storage);
        said["wants"] = json!(wants);
        // The data disks it looked at at the start (none before it has, and on a node that is not init).
        if let Some(disks) = crate::data_disk::boot::said() {
            said["disks"] = disks;
        }
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
                Ok(()) => fetch(&url, wanted.clone(), &release, slot, &keys, &version, back, lan).await,
                Err(e) => Err(format!("keeping a note of the update: {e}")),
            };
            match wrote {
                // (Kithd alone differs, and this kithd has a keeper to start the next: it is
                // staged and started with no unit stopped. Else, or if that fails, the restart.)
                Ok((_, Some(kithd))) if crate::keeper::kept().is_some() => {
                    let staged = stage_release(crate::os::other(slot), &kithd)
                        .and_then(|_| hand_over(Path::new(HANDED_OVER), &version, &wanted, &kithd));
                    match staged {
                        Ok(()) => {
                            eprintln!(
                                "kithd: kith OS {wanted} differs in kithd alone: handing over to the kithd staged"
                            );
                            // (The keeper counts a kithd that ends sooner than this as a failure.)
                            // (A stop asked for in the wait, the power button or SIGTERM, is that stop's: no hand-over.)
                            tokio::select! {
                                _ = tokio::time::sleep(crate::keeper::HANDOVER_AFTER + Duration::from_secs(1)) => {}
                                _ = stopping.changed() => return,
                            }
                            // (Set only now: a power-button stop during the wait is not a hand-over.)
                            crate::init::HANDING_OVER.store(true, std::sync::atomic::Ordering::Relaxed);
                            shared.stop.send_replace(true);
                            return;
                        }
                        Err(why) => {
                            eprintln!("kithd: no hand-over to kith OS {wanted} ({why}): restarting into it instead");
                            shared.stop.send_replace(true);
                            return;
                        }
                    }
                }
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
    pub(super) fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kithd-release-keys-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Check 3 of docs/adr-unlock.md: the running system's header, kept for its slot, is signed
    /// by a key this node takes releases from, is not under the floor, and vouches for the image
    /// that runs. Each of those failing is a node that does not seal again.
    #[test]
    fn seals_again_the_running_system_is_signed_by_a_key_this_node_takes() {
        let state = scratch("seals-again");
        let (sign, public) = pair();
        let running = b"the kernel image that runs".to_vec();
        let sum = |bytes: &[u8]| crate::pki::hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
        let header = serde_json::json!({
            "format": 1, "version": "9.9", "hash": "0".repeat(64),
            "pieces": [
                {"name": "root", "size": 0, "sha256": sum(&[])},
                {"name": "verity", "size": 0, "sha256": sum(&[])},
                {"name": "a", "size": 0, "sha256": sum(&[])},
                {"name": "b", "size": running.len(), "sha256": sum(&running)},
            ],
        })
        .to_string();
        let mut block = header.into_bytes();
        block.resize(4096, b' ');
        let signature = sign(&block);
        crate::os::keep_signed(&state, 'b', Some(&signature), Some(&public), &block).unwrap();
        let keys = Keys::new(vec![public.clone()], &state);
        assert_eq!(keys.signed_system('b', &running), Ok(()));
        // A key this node does not take, or no key at all: refused.
        let (_, stranger) = pair();
        assert!(Keys::new(vec![stranger], &state).signed_system('b', &running).is_err());
        assert!(Keys::new(Vec::new(), &state).signed_system('b', &running).is_err());
        // An image that is not the piece the header names: refused.
        assert!(keys.signed_system('b', b"another image").is_err());
        // A signature that is not the header's: refused.
        let (forge, _) = pair();
        let forged = forge(&block);
        crate::os::keep_signed(&state, 'b', Some(&forged), Some(&public), &block).unwrap();
        assert!(keys.signed_system('b', &running).is_err());
        // A floor above the header's version: refused.
        crate::os::keep_signed(&state, 'b', Some(&signature), Some(&public), &block).unwrap();
        crate::pki::write_whole(&keys.floor, b"10\n").unwrap();
        assert!(keys.signed_system('b', &running).is_err());
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

    #[test]
    fn tpm_next_update_gate() {
        let dir = scratch("tpm-next-gate");
        // A key given, however cased: sealed ahead; another's, or none shown, not; nor under
        // allowDowngrade.
        let given = Keys::new(vec!["AA11".into()], &dir);
        assert!(given.seals_ahead(Some("aa11"), false) && given.seals_ahead(Some(" AA11 "), false));
        assert!(!given.seals_ahead(Some("aa11"), true));
        assert!(!given.seals_ahead(Some("bb22"), false) && !given.seals_ahead(None, false));
        // No key yet: the first release's is taken on trust, and nothing is sealed ahead for it.
        let first = Keys::new(Vec::new(), &dir);
        assert!(!first.seals_ahead(Some("aa11"), false));
        // Once kept (a release it took signed it), it is held before the next one.
        crate::pki::write_whole(&first.kept, b"aa11\n").unwrap();
        assert!(first.seals_ahead(Some("aa11"), false) && !first.seals_ahead(Some("bb22"), false));
        // The keys a release hands over are held only once it runs: they sign nothing sealed ahead.
        crate::pki::write_whole(&first.next(), b"bb22\n").unwrap();
        assert!(!first.seals_ahead(Some("bb22"), false));
        // The key of the node's image: held before any release.
        let image = dir.join("image-keys");
        std::fs::write(&image, "cc33\n").unwrap();
        let imaged = Keys {
            image: Some(image),
            ..Keys::new(Vec::new(), &dir.join("elsewhere"))
        };
        assert!(imaged.seals_ahead(Some("cc33"), false) && !imaged.seals_ahead(Some("aa11"), false));
        // Keys that cannot be read: nothing is sealed.
        let unread = Keys::new(Vec::new(), &dir.join("unread"));
        std::fs::create_dir_all(&unread.kept).unwrap();
        assert!(!unread.seals_ahead(Some("aa11"), false));
    }

    #[tokio::test]
    async fn release_key_not_this_nodes_is_refused_before_anything_is_fetched() {
        let dir = scratch("refused");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/kith-os.update", listener.local_addr().unwrap());
        let release = json!({ "publicKey": "bb22", "signature": "00" });
        let keys = Keys::new(vec!["aa11".into()], &dir);
        let said = fetch(&url, "2".into(), &release, 'a', &keys, "1", true, true)
            .await
            .unwrap_err();
        assert!(said.contains("not signed by a key this node takes"), "{said}");
        let asked = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(asked.is_err(), "nothing was to be fetched");
    }

    #[test]
    fn release_key_none_given_says_so() {
        let dir = scratch("none");
        let image = dir.join("image-keys");
        let keys = Keys {
            image: Some(image.clone()),
            ..Keys::new(Vec::new(), &dir)
        };
        // No key anywhere: said at the start and in the node's status.
        let said = keys.unkeyed().expect("a node with no key says so");
        assert!(
            said.contains("--release-key") && said.contains("KITH_RELEASE_KEY"),
            "{said}"
        );
        assert_eq!(keys.whose(), "none");
        // An empty file of keys (or one of notes only) is no key either.
        std::fs::write(&image, "# none\n\n").unwrap();
        assert_eq!((keys.whose(), keys.unkeyed().is_some()), ("none", true));
        // Built with a key, given one, or keeping one: nothing to say.
        std::fs::write(&image, "aa11\n").unwrap();
        assert_eq!((keys.whose(), keys.unkeyed()), ("image", None));
        let given = Keys::new(vec!["aa11".into()], &dir);
        assert_eq!((given.whose(), given.unkeyed()), ("given", None));
        crate::pki::write_whole(&keys.kept, b"bb22\n").unwrap();
        assert_eq!((keys.whose(), keys.unkeyed()), ("kept", None));
        // Keys that cannot be read are not none: such a node takes no release at all, and
        // says so at every start too.
        std::fs::remove_file(&keys.kept).unwrap();
        std::fs::create_dir(&keys.kept).unwrap();
        assert_eq!(keys.whose(), "unread");
        let said = keys.unkeyed().expect("a node whose keys cannot be read says so");
        assert!(
            said.contains("could not be read") && said.contains("takes no release"),
            "{said}"
        );
        assert!(keys.refused(Some("aa11")).is_err());
    }

    #[test]
    fn release_key_none_given_is_in_the_nodes_status() {
        let dir = scratch("status");
        let keys = Keys::new(Vec::new(), &dir);
        assert_eq!(report(&dir, "1", 'a', keys.whose())["releaseKeys"], "none");
        crate::pki::write_whole(&keys.kept, b"aa11\n").unwrap();
        assert_eq!(report(&dir, "1", 'a', keys.whose())["releaseKeys"], "kept");
    }

    #[test]
    fn release_key_of_the_install_is_the_only_one() {
        let dir = scratch("image");
        let image = dir.join("image-keys");
        std::fs::write(&image, "# the keys this system was built with\nAA11\ncc33\n").unwrap();
        let keys = Keys {
            image: Some(image.clone()),
            ..Keys::new(Vec::new(), &dir)
        };
        // Whoever applies the first release does not choose the key: the system says it.
        let said = keys.refused(Some("bb22")).unwrap_err();
        assert!(said.contains("not signed by a key this node takes"), "{said}");
        assert!(keys.refused(None).is_err());
        // Its own key is taken, and what is kept then is the system's keys, not the release's
        // (the next system may have been built with none).
        assert_eq!(keys.refused(Some("aa11")), Ok(true));
        assert_eq!(keys.first_kept("aa11"), "AA11\ncc33\n");
        // Once kept (or handed over), the kept keys are the node's; given ones are over all.
        crate::pki::write_whole(&keys.kept, b"bb22\n").unwrap();
        assert_eq!(keys.refused(Some("bb22")), Ok(false));
        assert!(keys.refused(Some("aa11")).is_err());
        let given = Keys {
            image: Some(image.clone()),
            ..Keys::new(vec!["dd44".into()], &dir)
        };
        assert!(given.refused(Some("dd44")).is_ok() && given.refused(Some("aa11")).is_err());
        // A file of the system's keys that cannot be read takes nothing.
        let unread = Keys {
            image: Some(dir.clone()),
            ..Keys::new(Vec::new(), &dir.join("elsewhere"))
        };
        assert!(unread.refused(Some("aa11")).is_err());
        // No system file (off kith OS): the first release's key, as before.
        let first = Keys::new(Vec::new(), &dir.join("elsewhere"));
        assert_eq!(first.first_kept("aa11"), "aa11\n");
    }

    /// The cluster's own /48 (its nodes and pods on the mesh) is not fetched from, though
    /// `--lan-releases` lets the unique-local range through.
    #[test]
    fn os_image_vetted_refuses_the_clusters_mesh() {
        let mesh = kith_mesh::prefix(b"a cluster");
        let pod = kith_mesh::node_net(mesh, "n2");
        let at = |ip: &str| vec![std::net::SocketAddr::new(ip.parse().unwrap(), 7443)];
        assert!(on_the_mesh(Some(&mesh), &at(&pod.to_string())));
        let both = [at("192.168.1.9"), at(&pod.to_string())].concat();
        assert!(on_the_mesh(Some(&mesh), &both), "one address there refuses the host");
        // Another unique-local network, the LAN's, and a node with no cluster.
        assert!(!on_the_mesh(Some(&mesh), &at("fd00::1")) && !on_the_mesh(Some(&mesh), &at("192.168.1.9")));
        assert!(!on_the_mesh(None, &at(&pod.to_string())));
    }

    #[tokio::test]
    async fn os_image_vetted_refuses_loopback() {
        let dir = scratch("vetted");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let release = json!({ "publicKey": "aa11", "signature": "00" });
        let keys = Keys::new(vec!["aa11".into()], &dir);
        let at = listener.local_addr().unwrap();
        for url in [
            format!("http://{at}/kith-os.update"),
            format!("http://localhost:{}/kith-os.update", at.port()),
        ] {
            let said = fetch(&url, "2".into(), &release, 'a', &keys, "1", true, false)
                .await
                .unwrap_err();
            assert!(said.contains("--lan-releases"), "{said}");
            // Allowing the LAN does not allow this node itself.
            let said = fetch(&url, "2".into(), &release, 'a', &keys, "1", true, true)
                .await
                .unwrap_err();
            assert!(said.contains("not fetched from this node"), "{said}");
        }
        // Nor what a cloud answers on at its link-local address (looked at, never asked).
        for lan in [false, true] {
            let url = "http://169.254.169.254/kith-os.update";
            let said = fetch(url, "2".into(), &release, 'a', &keys, "1", true, lan)
                .await
                .unwrap_err();
            assert!(said.contains("not fetched from this node"), "{said}");
            assert!(!said.contains("Source"), "an OS update's words: {said}");
        }
        let asked = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(asked.is_err(), "nothing was to be fetched");
    }

    /// `--lan-releases` lets the private ranges of the node's networks through: a release
    /// server on the LAN. (Looked up, not asked: an address literal needs no lookup.)
    #[tokio::test]
    async fn os_image_vetted_lan_lets_private_ranges_through() {
        for url in [
            "http://10.254.253.252/kith-os.update",
            "http://[fd12:3456:789a::1]/kith-os.update",
        ] {
            let url = reqwest::Url::parse(url).unwrap();
            let said = pinned(&url, false).await.unwrap_err();
            assert!(said.contains("--lan-releases"), "{said}");
            let (_, addresses) = pinned(&url, true).await.unwrap();
            assert_eq!(addresses.len(), 1, "{url}");
        }
    }

    /// A URL with no port is fetched from its scheme's: the addresses held carry it, and
    /// what is connected to is one of them, at that port (port 80 cannot be listened on
    /// here, so this is the address the fetch is given, through the name it looks up).
    #[tokio::test]
    async fn os_image_vetted_portless_url_holds_its_schemes_port() {
        crate::sources::LOOPBACK_IS_OUTSIDE.set(true);
        let mut ports = Vec::new();
        for url in ["http://localhost/kith-os.update", "https://localhost/kith-os.update"] {
            let (host, addresses) = pinned(&reqwest::Url::parse(url).unwrap(), false).await.unwrap();
            assert_eq!(host, "localhost");
            ports.push(
                addresses
                    .iter()
                    .map(|at| at.port())
                    .collect::<std::collections::BTreeSet<_>>(),
            );
        }
        crate::sources::LOOPBACK_IS_OUTSIDE.set(false);
        assert_eq!(ports, [[80].into(), [443].into()]);
        // Neither ssh nor anything else but HTTP.
        let said = pinned(&reqwest::Url::parse("ssh://8.8.8.8/x").unwrap(), false)
            .await
            .unwrap_err();
        assert!(said.contains("http") && !said.contains("Source"), "{said}");
    }

    #[tokio::test]
    async fn os_image_vetted_address_is_the_one_connected_to() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let answering = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut asked, _) = listener.accept().await.unwrap();
                let _ = asked.read(&mut [0; 1024]).await;
                let said = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                asked.write_all(said.as_bytes()).await.unwrap();
            }
        });
        // A name nobody can look up reaches the address it was vetted at, and only that.
        let held = client("releases.example", &[at]).unwrap();
        let url = format!("http://releases.example:{}/kith-os.update", at.port());
        assert_eq!(held.get(url).send().await.unwrap().status(), 404);
        // And the fetch, by a name it looks up, goes on to the address that was vetted.
        // (This thread takes loopback for outside: it stands for a server elsewhere.)
        crate::sources::LOOPBACK_IS_OUTSIDE.set(true);
        let keys = Keys::new(vec!["aa11".into()], &scratch("vetted-out"));
        let release = json!({ "publicKey": "aa11", "signature": "00" });
        let url = format!("http://localhost:{}/kith-os.update", at.port());
        let said = fetch(&url, "2".into(), &release, 'a', &keys, "1", true, false).await;
        crate::sources::LOOPBACK_IS_OUTSIDE.set(false);
        let said = said.unwrap_err();
        assert!(said.contains("404"), "{said}");
        answering.await.unwrap();
    }

    /// A release key: what signs with it, and its public half as an OSRelease names it.
    pub(super) fn pair() -> (impl Fn(&[u8]) -> String, String) {
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
        let said = fetch(&url, "1.9".into(), &release, 'a', &keys, "1", true, true)
            .await
            .unwrap_err();
        assert!(said.contains("1.10") && said.contains("os-release-floor"), "{said}");
        std::fs::write(&keys.floor, "?").unwrap();
        let said = fetch(&url, "2.0".into(), &release, 'a', &keys, "1", true, true)
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

    /// A server on `listener` (an unbounded number of asks) that logs each request's path
    /// and answers it with what `answer` says for that path.
    fn serving(
        listener: tokio::net::TcpListener,
        answer: impl Fn(&str) -> String + 'static,
    ) -> std::rc::Rc<std::cell::RefCell<Vec<String>>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let seen = log.clone();
        // (Local to this test's thread, where the loopback-is-outside switch is too.)
        tokio::task::spawn_local(async move {
            loop {
                let (mut asked, _) = listener.accept().await.unwrap();
                let mut line = [0; 4096];
                let got = asked.read(&mut line).await.unwrap_or(0);
                let text = String::from_utf8_lossy(&line[..got]).to_string();
                let path = text.split_whitespace().nth(1).unwrap_or_default().to_string();
                let said = answer(&path);
                seen.borrow_mut().push(path);
                let _ = asked.write_all(said.as_bytes()).await;
            }
        });
        log
    }

    fn moved(to: &str) -> String {
        format!("HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    }

    const IMAGE: &str = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd";

    /// `fetch` as a node with `lan` does it, from a server that stands for one elsewhere
    /// (this thread takes loopback for outside). The image never gets further than the
    /// writer, which finds no slot here: that is what "followed to the image" says.
    async fn fetched(url: &str, lan: bool) -> Result<String, String> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let keys = Keys::new(vec!["aa11".into()], &scratch("redirect"));
        let release = json!({ "publicKey": "aa11", "signature": "00" });
        crate::sources::LOOPBACK_IS_OUTSIDE.set(true);
        let said = fetch(url, "2".into(), &release, 'a', &keys, "1", true, lan).await;
        crate::sources::LOOPBACK_IS_OUTSIDE.set(false);
        // (And a key is kept only once it has signed the update asked for.)
        assert!(!keys.kept.exists());
        said.map(|(text, _)| text)
    }

    /// Runs `test` where [`serving`] can spawn.
    async fn locally<F: std::future::Future<Output = ()>>(test: F) {
        tokio::task::LocalSet::new().run_until(test).await;
    }

    const NO_SLOT: &str = "no partition is labelled";

    #[tokio::test]
    async fn redirect_is_followed_to_the_image() {
        locally(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = listener.local_addr().unwrap();
            let log = serving(listener, move |path| match path {
                "/kith-os.update" => moved("/second"),
                "/second" => moved(&format!("http://{at}/image")),
                _ => IMAGE.to_string(),
            });
            let said = fetched(&format!("http://{at}/kith-os.update"), false).await;
            assert!(said.unwrap_err().contains(NO_SLOT));
            assert_eq!(*log.borrow(), ["/kith-os.update", "/second", "/image"]);
        })
        .await;
    }

    /// GitHub's way: the file's address answers 302 to another host's, with a signed query.
    #[tokio::test]
    async fn redirect_to_another_host_with_a_query() {
        locally(async {
            let (first, second) = (
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
            );
            let (a, b) = (first.local_addr().unwrap(), second.local_addr().unwrap());
            let to = format!("http://localhost:{}/asset/1?sig=ab%2Bc&exp=9", b.port());
            let one = serving(first, move |_| moved(&to));
            let two = serving(second, |_| IMAGE.to_string());
            let said = fetched(&format!("http://{a}/releases/download/v1/kith-os.update"), false).await;
            assert!(said.unwrap_err().contains(NO_SLOT));
            assert_eq!(*one.borrow(), ["/releases/download/v1/kith-os.update"]);
            // (The query goes to the second host as it was written.)
            assert_eq!(*two.borrow(), ["/asset/1?sig=ab%2Bc&exp=9"]);
        })
        .await;
    }

    #[tokio::test]
    async fn redirect_five_hops_are_followed_and_the_sixth_is_refused() {
        locally(async {
            for (hops, followed) in [(5, true), (6, false)] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let at = listener.local_addr().unwrap();
                let log = serving(listener, move |path| {
                    match path.trim_start_matches('/').parse::<usize>() {
                        Ok(n) if n < hops => moved(&format!("/{}", n + 1)),
                        _ => IMAGE.to_string(),
                    }
                });
                // (Every answer, but the last, is a redirect to the next number.)
                let said = fetched(&format!("http://{at}/0"), false).await.unwrap_err();
                match followed {
                    true => assert!(said.contains(NO_SLOT), "{said}"),
                    false => assert!(said.contains("5 redirects") && said.contains("hop"), "{said}"),
                }
                // (Six asks either way: the sixth redirect is refused, not asked for.)
                assert_eq!(log.borrow().len(), 6, "{:?}", log.borrow());
            }
        })
        .await;
    }

    #[tokio::test]
    async fn redirect_loop_is_refused() {
        locally(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = listener.local_addr().unwrap();
            let log = serving(listener, |path| moved(if path == "/a" { "/b#again" } else { "/a" }));
            let said = fetched(&format!("http://{at}/a"), false).await.unwrap_err();
            assert!(said.contains("loop"), "{said}");
            assert_eq!(*log.borrow(), ["/a", "/b"]);
        })
        .await;
    }

    #[tokio::test]
    async fn redirect_with_userinfo_or_no_location_is_refused() {
        locally(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = listener.local_addr().unwrap();
            let none = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let log = serving(listener, move |path| match path {
                "/user" => moved(&format!("http://me:secret@{at}/image")),
                "/name" => moved(&format!("http://me@{at}/image")),
                "/none" => none.to_string(),
                _ => IMAGE.to_string(),
            });
            for (path, words) in [("/user", "userinfo"), ("/name", "userinfo"), ("/none", "no Location")] {
                let said = fetched(&format!("http://{at}{path}"), false).await.unwrap_err();
                assert!(said.contains(words) && !said.contains("secret"), "{said}");
            }
            assert_eq!(*log.borrow(), ["/user", "/name", "/none"], "nothing was followed");
        })
        .await;
    }

    /// What an error says of an address is the address with no user, password, query or
    /// fragment: a signed query and a password are secrets, and a status shows the error.
    #[tokio::test]
    async fn redirect_errors_say_no_userinfo_and_no_query() {
        locally(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = listener.local_addr().unwrap();
            let log = serving(listener, move |path| match path.split('?').next().unwrap() {
                "/gone" => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
                _ => moved("/gone?sig=secret"),
            });
            for path in ["/gone?sig=secret#secret", "/moved?sig=secret"] {
                let said = fetched(&format!("http://me:hunter2@{at}{path}"), false)
                    .await
                    .unwrap_err();
                assert!(said.contains("404") && said.contains(&at.to_string()), "{said}");
                assert!(!said.contains("hunter2") && !said.contains("secret"), "{said}");
            }
            assert_eq!(log.borrow().len(), 3);
        })
        .await;
    }

    /// What a redirect may name is what the first address may: http or https, outside this
    /// node, however it is written (a scheme-less `//host`, an IPv4 in an IPv6 address).
    #[tokio::test]
    async fn os_image_redirect_to_another_scheme_or_a_loopback_in_disguise_is_refused() {
        locally(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = listener.local_addr().unwrap();
            let log = serving(listener, |path| {
                crate::sources::LOOPBACK_IS_OUTSIDE.set(false);
                moved(&path.trim_start_matches('/').replace("%2F", "/"))
            });
            for (target, words) in [
                ("ftp:%2F%2Fx.example%2Fa", "fetched over http or https"),
                ("file:%2F%2F%2Fx", "fetched over http or https"),
                ("http:%2F%2F[::ffff:127.0.0.1]%2Fa", "not fetched from this node"),
                ("%2F%2F127.0.0.1%2Fa", "not fetched from this node"),
            ] {
                let said = fetched(&format!("http://{at}/{target}"), false).await.unwrap_err();
                assert!(
                    said.starts_with("after a redirect, ") && said.contains(words),
                    "{target}: {said}"
                );
            }
            assert_eq!(log.borrow().len(), 4, "only the first address was asked");
        })
        .await;
    }

    /// Where a redirect goes is decided apart from the network: a scheme is never lowered.
    #[test]
    fn redirect_hop_never_lowers_the_scheme_and_reads_the_location_whole() {
        let value = |text: &str| reqwest::header::HeaderValue::from_str(text).unwrap();
        let at = |from: &str, location: &str| hop(&reqwest::Url::parse(from).unwrap(), Some(&value(location)));
        let said = at("https://a.example/x", "http://b.example/y").unwrap_err();
        assert!(said.contains("https") && said.contains("http"), "{said}");
        assert!(at("https://a.example/x", "//b.example/y").unwrap().as_str() == "https://b.example/y");
        assert_eq!(
            at("http://a.example/x/y", "https://b.example/z?q=1#f")
                .unwrap()
                .as_str(),
            "https://b.example/z?q=1"
        );
        assert_eq!(
            at("http://a.example/x/y", "z").unwrap().as_str(),
            "http://a.example/x/z"
        );
        assert!(at("https://a.example/x", "ftp://b.example/y").is_err());
        let long = format!("/{}", "a".repeat(2048));
        assert!(at("http://a.example/", &long).unwrap_err().contains("2048"));
        assert!(hop(&reqwest::Url::parse("http://a.example/").unwrap(), None).is_err());
    }

    /// Each hop is vetted as the first address is: the redirect's target is named in the
    /// refusal (and its query, which may be a signature, is not).
    #[tokio::test]
    async fn os_image_redirect_to_loopback_or_a_private_range_is_refused_with_lan_off() {
        locally(async {
            let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (a, b) = (first.local_addr().unwrap(), second.local_addr().unwrap());
            let one = serving(first, move |path| {
                // (The first answer is from "outside"; what it names is looked at as itself.)
                crate::sources::LOOPBACK_IS_OUTSIDE.set(false);
                moved(&match path {
                    "/loopback" => format!("http://{b}/x?sig=secret"),
                    _ => "http://10.254.253.252/x?sig=secret".into(),
                })
            });
            let two = serving(second, |_| IMAGE.to_string());
            for (path, target, words) in [
                ("/loopback", format!("{b}"), "not fetched from this node"),
                ("/private", "10.254.253.252".into(), "--lan-releases"),
            ] {
                let said = fetched(&format!("http://{a}{path}"), false).await.unwrap_err();
                assert!(said.contains(&target) && said.contains(words), "{said}");
                assert!(said.contains("redirect") && !said.contains("secret"), "{said}");
            }
            // And with the LAN allowed, loopback is this node still.
            let said = fetched(&format!("http://{a}/loopback"), true).await.unwrap_err();
            assert!(said.contains("not fetched from this node"), "{said}");
            assert!(two.borrow().is_empty(), "nothing was asked of it");
            assert_eq!(one.borrow().len(), 3);
        })
        .await;
    }

    /// With `--lan-releases` a private range is followed to (the connection is tried: there
    /// is no such host here, so it is not answered), but never the cluster's own mesh.
    #[tokio::test]
    async fn os_image_redirect_to_a_private_range_is_followed_with_lan_on_but_not_the_mesh() {
        locally(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = listener.local_addr().unwrap();
            let mesh = *MESH.get_or_init(|| kith_mesh::prefix(b"a cluster"));
            let pod = kith_mesh::node_net(mesh, "n2");
            let log = serving(listener, move |path| {
                moved(&match path {
                    "/mesh" => format!("http://[{pod}]/x"),
                    _ => "http://10.254.253.252/x".into(),
                })
            });
            let said = fetched(&format!("http://{at}/mesh"), true).await.unwrap_err();
            assert!(said.contains("cluster's own mesh"), "{said}");
            let tried = tokio::time::timeout(Duration::from_secs(2), fetched(&format!("http://{at}/lan"), true)).await;
            crate::sources::LOOPBACK_IS_OUTSIDE.set(false);
            match tried {
                // (No route, or refused: said of the address, never of the vetting.)
                Ok(said) => {
                    let said = said.unwrap_err();
                    assert!(
                        said.contains("10.254.253.252") && !said.contains("not fetched from"),
                        "{said}"
                    );
                }
                // (Or the connection is still being made, as on a host that routes it: the
                // vetting passed, and the redirect was served once, as the log says.)
                Err(_) => assert_eq!(log.borrow().iter().filter(|p| *p == "/lan").count(), 1),
            }
            assert_eq!(*log.borrow(), ["/mesh", "/lan"]);
        })
        .await;
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
        let picked = step(&plan(spec.clone(), None), Some(("2", "next@1")), &nodes, 0);
        assert_eq!(picked.cordon, [("b".to_string(), true)]);
        // (Nothing to move off it: it restarts at the next step.)
        let first = step(&plan(spec.clone(), Some(&picked)), Some(("2", "next@1")), &nodes, 0);
        assert_eq!(told(&first), ["b"]);
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

    const WEB: &str = "Workload/default/web#0";

    #[test]
    fn update_drain_moves_before_the_restart() {
        let spec = json!({ "drain": true });
        let mut nodes = vec![node("a", "1", false), node("b", "1", false)];
        let first = step(&plan(spec.clone(), None), Some(("2", "next@1")), &nodes, 0);
        // Picked: drained (and cordoned), not yet told to restart.
        assert_eq!(states(&first), [("a".to_string(), "draining".to_string())]);
        assert_eq!(first.drain, [("a".to_string(), true)]);
        assert_eq!(first.cordon, [("a".to_string(), true)]);
        assert_eq!(first.status["drained"], json!(["a"]));
        assert_eq!(first.status["phase"], "Draining");
        // A replica the drain plan says moves is not running elsewhere yet: it waits, and the
        // drain is asked for again (a write that was lost is made up).
        nodes[0].waits = vec![WEB.into()];
        let waiting = step(&plan(spec.clone(), Some(&first)), Some(("2", "next@1")), &nodes, 60);
        assert_eq!(states(&waiting), states(&first));
        assert_eq!(waiting.drain, [("a".to_string(), true)]);
        assert!(told(&waiting).is_empty());
        // It runs elsewhere (or a replica that stays does not count: `waits` has only movers):
        // the node is told to restart, still drained.
        nodes[0].waits.clear();
        let told_now = step(&plan(spec.clone(), Some(&waiting)), Some(("2", "next@1")), &nodes, 90);
        assert_eq!(told(&told_now), ["a"]);
        assert_eq!(
            (
                &told_now.status["phase"],
                &told_now.status["drained"],
                &told_now.status["since"]["a"]
            ),
            (&json!("Progressing"), &json!(["a"]), &json!(90))
        );
        assert!(told_now.drain.is_empty() && told_now.cordon.is_empty());
        // It is back as the release: the drain is lifted with the cordon.
        nodes[0].version = Some("2".into());
        let done = step(&plan(spec, Some(&told_now)), Some(("2", "next@1")), &nodes[..1], 120);
        assert_eq!(done.drain, [("a".to_string(), false)]);
        assert_eq!(done.cordon, [("a".to_string(), false)]);
        assert_eq!(done.status["drained"], json!([]));
    }

    /// A node as the plan leaves it: the drain (and the update's cordon) it put on, stamped with it.
    fn put_on_by(spec: &Value, plan: &str, drain: bool) -> Value {
        let mut next = if drain {
            drained_spec(spec, true)
        } else {
            cordoned_spec(spec, true)
        }
        .expect("a record to put on");
        stamp(
            &mut next,
            if drain {
                kith_sched::DRAIN
            } else {
                crate::sched::UPDATE_CORDON
            },
            plan,
        );
        next
    }

    /// What the sweep would lift from these nodes when only the plans in `live` exist.
    fn swept(nodes: &[(&str, &Value)], live: &[&str]) -> Vec<(String, &'static str)> {
        orphans(nodes.iter().map(|(name, spec)| (*name, *spec)), |plan| {
            live.contains(&plan)
        })
    }

    #[test]
    fn update_delete_lifts_the_drain_and_cordon_the_plan_put_on_and_no_operators() {
        let (drain, cordon) = (kith_sched::DRAIN, crate::sched::UPDATE_CORDON);
        // The plan's own drain, its own cordon, a drain on a node an owner had cordoned first.
        let drained = put_on_by(&json!({}), "p", true);
        let cordoned = put_on_by(&json!({}), "p", false);
        let owned = put_on_by(&json!({ "unschedulable": true }), "p", true);
        // The operator's: a drain with no stamp, one an owner cordoned over, a cordon of theirs,
        // and a drain the operator re-put after the plan's was lifted.
        let mut theirs = json!({});
        crate::sched::drain_on(&mut theirs);
        let mut theirs_owned = json!({ "unschedulable": true });
        crate::sched::drain_on(&mut theirs_owned);
        let cordon_only = json!({ "unschedulable": true });
        let nodes = [
            ("drained", &drained),
            ("cordoned", &cordoned),
            ("owned", &owned),
            ("theirs", &theirs),
            ("theirs-owned", &theirs_owned),
            ("cordon-only", &cordon_only),
        ];
        // The plan is there: nothing is lifted.
        assert!(swept(&nodes, &["p"]).is_empty());
        // The plan is deleted: its records, and only those.
        let lifted = swept(&nodes, &[]);
        assert_eq!(
            lifted,
            [
                ("drained".to_string(), drain),
                ("cordoned".to_string(), cordon),
                ("owned".to_string(), drain)
            ]
        );
        // Another plan's records stay while that plan is there.
        assert_eq!(swept(&nodes, &["q"]), lifted);
        // Lifting leaves no taint and no cordon, except the owner's cordon.
        assert_eq!(drained_spec(&drained, false).expect("a lift")["taints"], json!([]));
        assert!(drained_spec(&drained, false).unwrap().get("unschedulable").is_none());
        assert!(cordoned_spec(&cordoned, false).unwrap().get("unschedulable").is_none());
        let kept = drained_spec(&owned, false).expect("a lift");
        assert_eq!(
            (kept["taints"].clone(), kept["unschedulable"].clone()),
            (json!([]), json!(true))
        );
        // A lift that was lost is asked for again: the nodes are the same, so is the sweep.
        assert_eq!(swept(&nodes, &[]), lifted);
        // The plan's stamp survives the drain and the update cordon on one node, and an owner
        // record gone from under it.
        let both = put_on_by(&drained, "p", false);
        assert_eq!(
            swept(&[("n", &both)], &[]),
            [("n".to_string(), drain), ("n".to_string(), cordon)]
        );
        let after_drain = drained_spec(&both, false).expect("a lift");
        assert_eq!(swept(&[("n", &after_drain)], &[]), [("n".to_string(), cordon)]);
        assert_eq!(after_drain["unschedulable"], true);
    }

    /// A plan picks a node that carries a record of a plan deleted in the same snapshot (a
    /// rename, or two plans on one selector): the new plan takes the record over, and the sweep
    /// leaves the node alone, so it keeps its drain and cordon.
    #[test]
    fn update_delete_lifts_not_what_a_plan_picking_the_node_takes_over() {
        let (drain, cordon) = (kith_sched::DRAIN, crate::sched::UPDATE_CORDON);
        for owner in [false, true] {
            let base = if owner {
                json!({ "unschedulable": true })
            } else {
                json!({})
            };
            let mut spec = put_on_by(&put_on_by(&base, "q", true), "q", false);
            let live = |plan: &str| plan == "p";
            assert_eq!(
                orphans([("a", &spec)].into_iter(), live),
                [("a".to_string(), drain), ("a".to_string(), cordon)]
            );
            // The plan sees a drain that is a gone plan's, and holds it as its own.
            let mut nodes = vec![node("a", "1", false)];
            nodes[0].drained = true;
            nodes[0].stale = true;
            let picked = step(&plan(json!({ "drain": true }), None), Some(("2", "next@1")), &nodes, 0);
            assert_eq!(picked.drain, [("a".to_string(), true)]);
            assert_eq!(picked.status["drained"], json!(["a"]));
            // Written with its stamp over the old one, the sweep finds nothing; a second write is no change.
            for (record, what) in [
                (drain, drained_spec as fn(&Value, bool) -> Option<Value>),
                (cordon, cordoned_spec),
            ] {
                spec = written(&spec, true, what, record, "p", &live).expect("a stamp to take over");
                assert_eq!(written(&spec, true, what, record, "p", &live), None);
            }
            assert!(orphans([("a", &spec)].into_iter(), live).is_empty(), "{spec}");
            // The owner's cordon is still said to be an owner's.
            assert_eq!(
                spec["taints"][0]["value"].as_str().unwrap().starts_with("owner;"),
                owner,
                "{spec}"
            );
        }
    }

    /// A record that was there before the plan's write, with no stamp or another live plan's, is
    /// not the plan's: it is not stamped, so no end or deletion of the plan lifts it.
    #[test]
    fn update_delete_lifts_not_an_operators_record_a_plan_writes_over() {
        let (drain, cordon) = (kith_sched::DRAIN, crate::sched::UPDATE_CORDON);
        let live = |plan: &str| plan == "p" || plan == "q";
        let mut drained = json!({});
        crate::sched::drain_on(&mut drained);
        let mut drained_over_owner = json!({ "unschedulable": true });
        crate::sched::drain_on(&mut drained_over_owner);
        let mut cordoned = json!({});
        crate::sched::cordon_on(&mut cordoned, crate::sched::UPDATE_CORDON, "noSchedule");
        let theirs_live = put_on_by(&json!({}), "q", true);
        let drains = [&drained, &drained_over_owner, &theirs_live];
        for spec in drains {
            assert_eq!(written(spec, true, drained_spec, drain, "p", &live), None, "{spec}");
        }
        assert_eq!(written(&cordoned, true, cordoned_spec, cordon, "p", &live), None);
        // Deleted plans: only the stamped one is the plan's.
        let none = |_: &str| false;
        assert!(
            orphans(
                [("a", &drained), ("b", &drained_over_owner), ("c", &cordoned)].into_iter(),
                none
            )
            .is_empty()
        );
        // A record the write creates is stamped.
        let made = written(&json!({}), true, drained_spec, drain, "p", &live).expect("a drain");
        assert_eq!(made["taints"][0]["value"], "plan:p");
    }

    /// A lift takes off only a record that is the plan's own (its stamp), or, for the sweep (plan
    /// `""`), one a gone plan left: not an operator's drain put on after the plan's.
    #[test]
    fn update_delete_lifts_not_a_record_put_on_after_the_plans() {
        let (drain, cordon) = (kith_sched::DRAIN, crate::sched::UPDATE_CORDON);
        let live = |plan: &str| plan == "p" || plan == "q";
        // The plan drained and cordoned `a`; the operator undrained and drained again: a new,
        // unstamped record. The plan's end, and the sweep, leave it.
        let mut spec = put_on_by(&json!({}), "p", true);
        let mut redone = spec.clone();
        apply_drain(&mut redone, false);
        apply_drain(&mut redone, true);
        assert_eq!(stamped_by(&redone, drain), None);
        assert_eq!(written(&redone, false, drained_spec, drain, "p", &live), None);
        assert_eq!(written(&redone, false, drained_spec, drain, "", &|_| false), None);
        // The same for the update's cordon.
        let mut cordoned = json!({});
        crate::sched::cordon_on(&mut cordoned, cordon, "noSchedule");
        assert_eq!(written(&cordoned, false, cordoned_spec, cordon, "p", &live), None);
        assert_eq!(written(&cordoned, false, cordoned_spec, cordon, "", &|_| false), None);
        // Its own stamp is lifted by it, and by no other live plan; the sweep lifts it only
        // once the plan is gone.
        assert_eq!(written(&spec, false, drained_spec, drain, "q", &live), None);
        assert_eq!(written(&spec, false, drained_spec, drain, "", &live), None);
        let lifted = written(&spec, false, drained_spec, drain, "p", &live).expect("its own drain");
        assert!(!crate::sched::has_record(&lifted, drain), "{lifted}");
        let gone = written(&spec, false, drained_spec, drain, "", &|plan| plan != "p").expect("a gone plan's");
        assert!(!crate::sched::has_record(&gone, drain), "{gone}");
        // With nothing recorded there is nothing to lift (an older kithd's update cordon is
        // still taken off as before).
        spec = json!({ "unschedulable": true });
        assert!(written(&spec, false, cordoned_spec, cordon, "p", &live).is_some());
    }

    #[test]
    fn update_drain_leaves_the_operators() {
        let spec = json!({ "drain": true });
        let mut nodes = vec![node("a", "1", false)];
        // The operator drained `a` first: the update waits for what moves, but never puts the
        // drain on nor takes it off.
        nodes[0].drained = true;
        let first = step(&plan(spec.clone(), None), Some(("2", "next@1")), &nodes, 0);
        assert_eq!(states(&first), [("a".to_string(), "draining".to_string())]);
        assert!(first.drain.is_empty(), "{:?}", first.drain);
        assert_eq!(first.status["drained"], json!([]));
        nodes[0].waits = vec![WEB.into()];
        let waiting = step(&plan(spec.clone(), Some(&first)), Some(("2", "next@1")), &nodes, 60);
        assert!(waiting.drain.is_empty());
        nodes[0].version = Some("2".into());
        let done = step(&plan(spec.clone(), Some(&waiting)), Some(("2", "next@1")), &nodes, 120);
        assert!(done.drain.is_empty(), "{:?}", done.drain);

        // On the Node: a cordon its owner set stays after the update's drain; the operator's own
        // drain is not put on again, and a lost one is not taken off by a node that has none.
        let mut owned = json!({ "unschedulable": true });
        let on = drained_spec(&owned, true).expect("a drain to put on");
        assert!(crate::sched::has_record(&on, kith_sched::DRAIN), "{on}");
        owned = on;
        apply_drain(&mut owned, false);
        assert_eq!(owned["unschedulable"], true, "an owner's cordon: {owned}");
        let theirs = json!({ "unschedulable": true, "taints": [{ "key": "kith.dev/drain", "effect": "noExecute" }] });
        assert_eq!(drained_spec(&theirs, true), None);
        assert_eq!(drained_spec(&json!({}), false), None);

        // The plan paused, its release changed, or `drain` taken off its spec: the update's
        // drain is lifted and the node goes again when the plan does.
        nodes[0].drained = false;
        nodes[0].version = Some("1".into());
        nodes[0].waits.clear();
        let first = step(&plan(spec.clone(), None), Some(("2", "next@1")), &nodes, 0);
        let lifted = |decided: &Decided| {
            (
                decided.drain.clone(),
                decided.cordon.clone(),
                decided.status["nodes"].as_object().unwrap().len(),
            )
        };
        let gone = (vec![("a".to_string(), false)], vec![("a".to_string(), false)], 0);
        let paused = json!({ "drain": true, "paused": true });
        let held = step(&plan(paused, Some(&first)), Some(("2", "next@1")), &nodes, 60);
        assert_eq!(
            (held.status["phase"].as_str(), lifted(&held)),
            (Some("Paused"), gone.clone())
        );
        let changed = step(&plan(spec.clone(), Some(&first)), Some(("2", "next@2")), &nodes, 60);
        // (Held for the new rollout: the lift is not written, the drain is asked for again.)
        assert_eq!(changed.drain, [("a".to_string(), true)]);
        let not_now = step(&plan(json!({}), Some(&first)), Some(("2", "next@1")), &nodes, 60);
        assert_eq!(lifted(&not_now).0, [("a".to_string(), false)]);
        assert_eq!(told(&not_now), ["a"], "no longer drains: told at once");
        assert_eq!(not_now.status["drained"], json!([]));
    }

    #[test]
    fn update_drain_is_let_go_when_the_plan_stops_caring() {
        let spec = json!({ "drain": true, "selector": { "pool": "web" } });
        let mut nodes = vec![node("a", "1", false)];
        nodes[0].labels.insert("pool".into(), "web".into());
        let go = |spec: &Value, last: Option<&Decided>, release: Option<(&str, &str)>, nodes: &[Node], at: u64| {
            step(&plan(spec.clone(), last), release, nodes, at)
        };
        let rel = Some(("2", "next@1"));
        let first = go(&spec, None, rel, &nodes, 0);
        assert_eq!(first.status["drained"], json!(["a"]));
        // (The drain is on the Node now, as the first step asked.)
        nodes[0].drained = true;
        nodes[0].waits = vec![WEB.into()];
        let off = vec![("a".to_string(), false)];
        let none = |decided: &Decided| {
            assert_eq!(decided.status["nodes"], json!({}));
            assert_eq!(
                (&decided.status["drained"], &decided.status["cordoned"]),
                (&json!([]), &json!([]))
            );
        };

        // A release changed while the node holds the drain: its drain is the update's still, put
        // on again for the new rollout, not read as an operator's.
        let changed = go(&spec, Some(&first), Some(("2", "next@2")), &nodes, 60);
        assert_eq!(changed.drain, [("a".to_string(), true)], "{:?}", changed.drain);
        assert_eq!(changed.status["drained"], json!(["a"]));
        assert_eq!(changed.status["undraining"], json!([]));

        // The release is gone, or the plan names none that exists: nothing is updating.
        let missing = go(&spec, Some(&first), None, &nodes, 60);
        assert_eq!(
            (missing.status["phase"].as_str(), missing.drain.clone()),
            (Some("Waiting"), off.clone())
        );
        assert_eq!(missing.cordon, off);
        none(&missing);

        // The node leaves the selector (a label removed) while draining.
        let mut moved = nodes.clone();
        moved[0].labels.clear();
        let out = go(&spec, Some(&first), rel, &moved, 60);
        assert_eq!((out.drain.clone(), out.cordon.clone()), (off.clone(), off.clone()));
        none(&out);

        // A lift whose write was lost is made up while the node still shows the drain, and
        // forgotten once it does not.
        assert_eq!(out.status["undraining"], json!(["a"]));
        let again = go(&spec, Some(&out), None, &moved, 65);
        assert_eq!(again.drain, off);
        assert_eq!(again.status["undraining"], json!(["a"]));
        moved[0].drained = false;
        let after = go(&spec, Some(&again), None, &moved, 70);
        assert!(after.drain.is_empty(), "{:?}", after.drain);
        assert_eq!(after.status["undraining"], json!([]));
    }

    #[test]
    fn update_drain_seconds_has_a_ceiling() {
        let spec = json!({ "drain": true, "drainSeconds": 1_000_000 });
        let mut nodes = vec![node("a", "1", false)];
        let first = step(&plan(spec.clone(), None), Some(("2", "next@1")), &nodes, 0);
        nodes[0].waits = vec![WEB.into()];
        let late = step(&plan(spec.clone(), Some(&first)), Some(("2", "next@1")), &nodes, 3599);
        assert!(told(&late).is_empty());
        let gave = step(&plan(spec, Some(&late)), Some(("2", "next@1")), &nodes, 3600);
        assert_eq!(told(&gave), ["a"]);
        assert!(gave.status["reason"].as_str().unwrap().contains("3600"));
    }

    #[test]
    fn update_drain_says_and_gives_up() {
        let mut nodes = vec![node("a", "1", false)];
        let go = |spec: &Value, last: Option<&Decided>, nodes: &[Node], at: u64| {
            step(&plan(spec.clone(), last), Some(("2", "next@1")), nodes, at)
        };
        let spec = json!({ "drain": true });
        let first = go(&spec, None, &nodes, 0);
        // The plan is for anyone who may read UpdatePlans: it says how many wait, never which
        // (a namespace's names are for those who may read that namespace: `kith node drain`).
        nodes[0].waits = vec![WEB.into(), "Workload/secret/db#0".into(), "Workload/secret/db#1".into()];
        let waiting = go(&spec, Some(&first), &nodes, 100);
        let reason = waiting.status["reason"].as_str().unwrap();
        assert_eq!(waiting.status["phase"], "Draining");
        assert!(
            reason.contains("draining a") && reason.contains("3 replicas"),
            "{reason}"
        );
        let nameless = |decided: &Decided| {
            let said = serde_json::to_string(&decided.status).unwrap();
            assert!(
                !said.contains("default") && !said.contains("secret") && !said.contains("web"),
                "{said}"
            );
        };
        nameless(&waiting);
        // Not yet: the default is 300 seconds from when the drain began.
        let late = go(&spec, Some(&waiting), &nodes, 299);
        assert_eq!((told(&late).len(), &late.status["phase"]), (0, &json!("Draining")));
        // Then it is let go, with the reason in the plan's message, which stays until it is done.
        let gave = go(&spec, Some(&late), &nodes, 300);
        assert_eq!(
            (told(&gave), &gave.status["phase"]),
            (vec!["a".to_string()], &json!("Progressing"))
        );
        let reason = gave.status["reason"].as_str().unwrap();
        assert!(
            reason.contains("a") && reason.contains("300") && reason.contains("3 replicas"),
            "{reason}"
        );
        nameless(&gave);
        let after = go(&spec, Some(&gave), &nodes, 400);
        assert_eq!(after.status["reason"], gave.status["reason"]);
        // The plan's own seconds count, and a node that is back is done with the message cleared.
        let quick = json!({ "drain": true, "drainSeconds": 30 });
        let first = go(&quick, None, &nodes, 1000);
        assert_eq!(told(&go(&quick, Some(&first), &nodes, 1029)).len(), 0);
        let gave = go(&quick, Some(&first), &nodes, 1030);
        assert_eq!(told(&gave), ["a"]);
        assert!(gave.status["reason"].as_str().unwrap().contains("30"));
        nodes[0].version = Some("2".into());
        let done = go(&quick, Some(&gave), &nodes, 1100);
        assert_eq!(
            (&done.status["phase"], &done.status["reason"]),
            (&json!("Done"), &json!(""))
        );
        assert_eq!(done.drain, [("a".to_string(), false)]);
    }

    fn seated(name: &str, says: &str) -> Node {
        Node {
            seat: Some((format!("{name}-seat0"), says.into())),
            ..node(name, "1", false)
        }
    }

    #[test]
    fn update_waits_for_idle_seats() {
        let spec = json!({ "waitForIdleSeats": true, "maxUnavailable": 3 });
        let go = |spec: &Value, last: Option<&Decided>, nodes: &[Node], at: u64| {
            step(&plan(spec.clone(), last), Some(("2", "next@1")), nodes, at)
        };
        let mut nodes = vec![seated("a", "active"), seated("b", "fullscreen"), node("c", "1", false)];
        // Active and fullscreen wait, and the message names the seat and that it waits; a node with
        // no seat goes.
        let first = go(&spec, None, &nodes, 0);
        assert_eq!(told(&first), ["c"]);
        let reason = first.status["reason"].as_str().unwrap();
        assert!(
            reason.contains("a-seat0") && reason.contains("b-seat0") && reason.contains("idle"),
            "{reason}"
        );
        // One seat says idle (or its report is anything else but active or fullscreen): that node goes.
        nodes[0].seat = None;
        nodes[1].seat = None;
        let second = go(&spec, Some(&first), &nodes, 10);
        assert_eq!(told(&second), ["a", "b", "c"]);
        assert!(
            second.status["reason"].as_str().unwrap().is_empty(),
            "{:?}",
            second.status["reason"]
        );
    }

    #[test]
    fn update_idle_seats_off_and_gives_up() {
        let go = |spec: &Value, last: Option<&Decided>, nodes: &[Node], at: u64| {
            step(&plan(spec.clone(), last), Some(("2", "next@1")), nodes, at)
        };
        let nodes = vec![seated("a", "active")];
        // Unset or false: the seat is not looked at.
        for spec in [json!({}), json!({ "waitForIdleSeats": false })] {
            let decided = go(&spec, None, &nodes, 0);
            assert_eq!(told(&decided), ["a"], "{spec}");
            assert_eq!(decided.status["reason"], "");
        }
        // A seat that stays active lets the node go after 3600 seconds, with the reason.
        let spec = json!({ "waitForIdleSeats": true });
        let first = go(&spec, None, &nodes, 1000);
        assert!(told(&first).is_empty());
        let late = go(&spec, Some(&first), &nodes, 1000 + 3599);
        assert!(told(&late).is_empty());
        let gave = go(&spec, Some(&late), &nodes, 1000 + 3600);
        assert_eq!(told(&gave), ["a"]);
        let reason = gave.status["reason"].as_str().unwrap();
        assert!(reason.contains("a-seat0") && reason.contains("3600"), "{reason}");
        // The plan's own seconds count, with a ceiling.
        let quick = json!({ "waitForIdleSeats": true, "idleWaitSeconds": 60 });
        let first = go(&quick, None, &nodes, 0);
        assert!(told(&go(&quick, Some(&first), &nodes, 59)).is_empty());
        assert_eq!(told(&go(&quick, Some(&first), &nodes, 60)), ["a"]);
        let long = json!({ "waitForIdleSeats": true, "idleWaitSeconds": 10_000_000 });
        let first = go(&long, None, &nodes, 0);
        assert!(told(&go(&long, Some(&first), &nodes, 86_399)).is_empty());
        assert_eq!(told(&go(&long, Some(&first), &nodes, 86_400)), ["a"]);
    }

    /// The wait for a seat counts continuous picking: a pause or a closed window restarts it.
    #[test]
    fn update_idle_wait_restarts_after_a_pause_or_a_closed_window() {
        let go = |spec: &Value, last: Option<&Decided>, nodes: &[Node], at: u64| {
            step(&plan(spec.clone(), last), Some(("2", "next@1")), nodes, at)
        };
        let nodes = vec![seated("a", "active")];
        let open = json!({ "waitForIdleSeats": true });
        let first = go(&open, None, &nodes, 1000);
        assert!(told(&first).is_empty());
        // Paused for a day: the next pass picks again, and the clock starts there.
        let paused = go(
            &json!({ "waitForIdleSeats": true, "paused": true }),
            Some(&first),
            &nodes,
            1000 + 86_400,
        );
        assert_eq!(paused.status["idleSince"], json!({}));
        let again = go(&open, Some(&paused), &nodes, 1000 + 86_400);
        assert!(told(&again).is_empty(), "{:?}", again.status);
        assert_eq!(told(&go(&open, Some(&again), &nodes, 1000 + 86_400 + 3600)), ["a"]);
        // A closed window (1970-01-01 is a Thursday; 00:00 UTC is minute 0 of that day) does too.
        let spec = json!({ "waitForIdleSeats": true, "windows": ["00:00-00:30"] });
        let first = go(&spec, None, &nodes, 0);
        assert!(told(&first).is_empty());
        let closed = go(&spec, Some(&first), &nodes, 3600 * 12);
        assert_eq!(closed.status["phase"], "Waiting");
        assert_eq!(closed.status["idleSince"], json!({}));
        let next_night = go(&spec, Some(&closed), &nodes, 86_400);
        assert!(told(&next_night).is_empty(), "{:?}", next_night.status);
    }

    /// An update ends only the cordon it put on: one its owner set first stays, a drained node
    /// stays cordoned when the update ends, and a drain ending leaves the cordon the update holds.
    #[test]
    fn update_ending_uncordons_only_what_it_cordoned() {
        let cordoned = |spec: &Value| spec["unschedulable"] == true;
        let mut owned = json!({ "unschedulable": true });
        apply_cordon(&mut owned, true);
        apply_cordon(&mut owned, false);
        assert!(cordoned(&owned), "an owner's cordon: {owned}");
        let mut drained = json!({});
        apply_cordon(&mut drained, true);
        crate::sched::drain_on(&mut drained);
        apply_cordon(&mut drained, false);
        assert!(cordoned(&drained), "a drained node: {drained}");
        crate::sched::drain_off(&mut drained);
        assert!(!cordoned(&drained), "{drained}");
        let mut held = json!({});
        crate::sched::drain_on(&mut held);
        apply_cordon(&mut held, true);
        crate::sched::drain_off(&mut held);
        assert!(cordoned(&held), "a drain ending on an update's node: {held}");
        apply_cordon(&mut held, false);
        assert!(!cordoned(&held), "{held}");
        // A cordon an older kithd set with no record: the update's end lifts it, as it did.
        let mut legacy = json!({ "unschedulable": true });
        apply_cordon(&mut legacy, false);
        assert!(!cordoned(&legacy), "{legacy}");
    }

    /// A cordon write asks what the Node should be now, so a try that lost a race (Conflict)
    /// is finished by the next try: a spec already in the state asked for is `None`.
    #[test]
    fn cordon_write_is_none_once_the_node_is_in_the_state_asked_for() {
        let on = cordoned_spec(&json!({}), true).expect("a cordon to set");
        assert_eq!(cordoned_spec(&on, true), None, "{on}");
        let off = cordoned_spec(&on, false).expect("a cordon to lift");
        assert!(off.get("unschedulable").is_none(), "{off}");
        assert_eq!(cordoned_spec(&off, false), None, "{off}");
        // A lost cordon-off: the record and the cordon are still there, and the next try lifts them.
        let stranded =
            json!({ "unschedulable": true, "taints": [{ "key": "kith.dev/update", "effect": "noSchedule" }] });
        let lifted = cordoned_spec(&stranded, false).expect("the retry lifts a stranded cordon");
        assert!(
            lifted.get("unschedulable").is_none() && lifted["taints"] == json!([]),
            "{lifted}"
        );
        assert_eq!(cordoned_spec(&lifted, false), None, "{lifted}");
    }

    #[test]
    fn update_pauses_when_a_node_comes_back_on_its_old_system() {
        let mut nodes = vec![node("a", "1", false), node("b", "1", false)];
        let spec = json!({ "drain": true });
        let picked = step(&plan(spec.clone(), None), Some(("2", "next@1")), &nodes, 0);
        let first = step(&plan(spec.clone(), Some(&picked)), Some(("2", "next@1")), &nodes, 0);
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
        // (It drains first: told once what moves runs elsewhere.)
        assert_eq!(
            (again.status["phase"].as_str(), &again.status["nodes"]["b"]),
            (Some("Draining"), &json!("draining"))
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
            (on.status["phase"].as_str(), &on.status["nodes"]["b"]),
            (Some("Draining"), &json!("draining"))
        );
        // Another release is another rollout, from nothing.
        let next = step(&plan(spec.clone(), Some(&paused)), Some(("3", "newer@1")), &nodes, 240);
        assert_eq!(next.status["nodes"]["a"], "draining");
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
        let runs = |version: &str, slot: &str| json!({ "version": version, "slot": slot, "releaseKeys": "kept" });
        assert_eq!(report(&state, "1", 'a', "kept"), runs("1", "a"));
        // It became what it tried: nothing to say, and the note is gone.
        std::fs::write(tried(&state), r#"{"version":"2"}"#).unwrap();
        assert_eq!(report(&state, "2", 'b', "kept"), runs("2", "b"));
        assert!(!tried(&state).exists());
        // It is back as what it was: said at every start, until a plan lets go of it.
        std::fs::write(tried(&state), r#"{"version":"2"}"#).unwrap();
        let said = report(&state, "1", 'a', "kept");
        assert_eq!(
            (&said["failed"], &said["why"], &said["releaseKeys"]),
            (
                &json!("2"),
                &json!("it did not come up; the node is back on 1"),
                &json!("kept")
            )
        );
        std::fs::write(tried(&state), r#"{"version":"2","why":"the release is not signed"}"#).unwrap();
        assert_eq!(report(&state, "1", 'a', "kept")["why"], "the release is not signed");
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
                report(&state, "1", 'a', "given"),
                json!({ "version": "1", "slot": "a", "releaseKeys": "given" }),
                "{torn:?}"
            );
        }
        std::fs::remove_dir_all(&state).unwrap();
    }
}

/// An update's header for the tests of the `kithd` object: version `version`, the piece for
/// slot b the image `IMAGE`, and `kithd` (kithd, kernel, rest) as given, or not there.
#[cfg(test)]
mod kithd_made {
    pub const IMAGE: &[u8] = b"the kernel image that runs";

    pub fn block(version: &str, kithd: Option<[&str; 3]>) -> Vec<u8> {
        let sum = |bytes: &[u8]| crate::pki::hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
        let mut header = serde_json::json!({
            "format": 1, "version": version, "hash": "0".repeat(64),
            "pieces": [
                {"name": "root", "size": 0, "sha256": sum(&[])},
                {"name": "verity", "size": 0, "sha256": sum(&[])},
                {"name": "a", "size": 0, "sha256": sum(&[])},
                {"name": "b", "size": IMAGE.len(), "sha256": sum(IMAGE)},
            ],
        });
        if let Some([sha256, kernel, rest]) = kithd {
            header["kithd"] = serde_json::json!({ "sha256": sha256, "kernel": kernel, "rest": rest });
        }
        let mut block = header.to_string().into_bytes();
        block.resize(4096, b' ');
        block
    }

    pub fn digest(c: char) -> String {
        c.to_string().repeat(64)
    }
}

#[cfg(test)]
mod kithd_header {
    use super::kithd_made::{block, digest};

    #[test]
    fn parses_with_the_object_and_without_it() {
        let (a, b, c) = (digest('a'), digest('B'), digest('c'));
        let with = block("2", Some([&a, &b, &c]));
        assert_eq!(crate::os::digests(&with), Some([a, digest('b'), c]));
        // An older-style header is still a header, and says nothing of its parts.
        let without = block("1", None);
        assert_eq!(crate::os::digests(&without), None);
        assert_eq!(crate::os::way(&with, &without), crate::os::Way::Full);
    }

    #[test]
    fn a_malformed_object_is_none_not_a_refused_update() {
        for bad in [
            serde_json::json!("x"),
            serde_json::json!({"sha256": digest('a')}),
            serde_json::json!({"sha256": "short", "kernel": digest('a'), "rest": digest('a')}),
            serde_json::json!({"sha256": 1, "kernel": digest('a'), "rest": digest('a')}),
        ] {
            let mut header: serde_json::Value = serde_json::from_slice(&block("2", None)).unwrap();
            header["kithd"] = bad;
            let mut text = header.to_string().into_bytes();
            text.resize(4096, b' ');
            assert_eq!(crate::os::digests(&text), None);
        }
    }

    #[test]
    fn a_tampered_field_fails_the_signature() {
        let (sign, public) = super::tests::pair();
        let (a, b, c) = (digest('a'), digest('b'), digest('c'));
        let signed = block("2", Some([&a, &b, &c]));
        let signature = sign(&signed);
        let check = |block: &[u8]| crate::os::signed(Some(&signature), Some(&public))(block);
        assert_eq!(check(&signed), Ok(()));
        // The kernel's digest made the running system's: not the one that was signed.
        let tampered = block("2", Some([&a, &digest('d'), &c]));
        assert!(check(&tampered).is_err());
        assert!(check(&block("2", None)).is_err());
    }
}

#[cfg(test)]
mod kithd_only {
    use super::kithd_made::{block, digest};
    use crate::os::{Way, way};

    #[test]
    fn only_kithd_differing_is_kithd_only() {
        let now = block("1", Some([&digest('a'), &digest('b'), &digest('c')]));
        // Another kithd, the same kernel and the same rest of the root.
        assert_eq!(
            way(&block("2", Some([&digest('f'), &digest('b'), &digest('c')])), &now),
            Way::KithdOnly
        );
    }

    #[test]
    fn a_kernel_or_the_rest_differing_is_full() {
        let now = block("1", Some([&digest('a'), &digest('b'), &digest('c')]));
        for next in [
            [digest('a'), digest('d'), digest('c')],
            [digest('a'), digest('b'), digest('d')],
            [digest('f'), digest('d'), digest('d')],
        ] {
            assert_eq!(way(&block("2", Some([&next[0], &next[1], &next[2]])), &now), Way::Full);
        }
    }

    #[test]
    fn a_header_without_the_object_on_either_side_is_full() {
        let some = block("1", Some([&digest('a'), &digest('b'), &digest('c')]));
        let none = block("1", None);
        assert_eq!(way(&some, &none), Way::Full);
        assert_eq!(way(&none, &some), Way::Full);
        assert_eq!(way(&none, &none), Way::Full);
        assert_eq!(way(&some, b"not a header"), Way::Full);
    }
}

#[cfg(test)]
mod kithd_vouched {
    use super::kithd_made::{IMAGE, block, digest};
    use super::{Keys, tests::pair, tests::scratch};
    use crate::os::Way;

    /// A node whose slot b runs `IMAGE`, written by the update `kept` signed by its key.
    fn node(name: &str, kept: &[u8]) -> (Keys, String) {
        let state = scratch(name);
        let (sign, public) = pair();
        let signature = sign(kept);
        crate::os::keep_signed(&state, 'b', Some(&signature), Some(&public), kept).unwrap();
        (Keys::new(vec![public.clone()], &state), public)
    }

    #[test]
    fn decides_by_the_kept_header_of_the_running_slot() {
        let now = block("1", Some([&digest('a'), &digest('b'), &digest('c')]));
        let (keys, _) = node("kithd-vouched", &now);
        // (The kept header of the running slot is signed by a key the node takes.)
        let same = block("2", Some([&digest('f'), &digest('b'), &digest('c')]));
        let kernel = block("2", Some([&digest('f'), &digest('d'), &digest('c')]));
        assert_eq!(keys.way('b', IMAGE, &same), Way::KithdOnly);
        assert_eq!(keys.way('b', IMAGE, &kernel), Way::Full);
        // Not the image the kept header names: the kept header is not the system's own.
        assert_eq!(keys.way('b', b"another image", &same), Way::Full);
        // No header kept for that slot (an older node).
        assert_eq!(keys.way('a', IMAGE, &same), Way::Full);
    }

    #[test]
    fn a_kept_header_without_the_object_or_not_signed_is_full() {
        let old = block("1", None);
        let (keys, _) = node("kithd-vouched-old", &old);
        let next = block("2", Some([&digest('f'), &digest('b'), &digest('c')]));
        assert_eq!(keys.way('b', IMAGE, &next), Way::Full);
        // A signature that is not the kept header's.
        let now = block("1", Some([&digest('a'), &digest('b'), &digest('c')]));
        let (keys, public) = node("kithd-vouched-forged", &now);
        let (forge, _) = pair();
        crate::os::keep_signed(&keys.state, 'b', Some(&forge(&now)), Some(&public), &now).unwrap();
        assert_eq!(keys.way('b', IMAGE, &next), Way::Full);
    }

    #[test]
    fn says_why_it_is_a_full_update() {
        let now = block("1", Some([&digest('a'), &digest('b'), &digest('c')]));
        let (keys, _) = node("kithd-vouched-why", &now);
        let same = block("2", Some([&digest('f'), &digest('b'), &digest('c')]));
        let kernel = block("2", Some([&digest('f'), &digest('d'), &digest('c')]));
        let rest = block("2", Some([&digest('f'), &digest('b'), &digest('e')]));
        assert_eq!(keys.kithd_only('b', IMAGE, &same), Ok(()));
        assert!(keys.kithd_only('b', IMAGE, &kernel).unwrap_err().contains("kernel"));
        assert!(
            keys.kithd_only('b', IMAGE, &rest)
                .unwrap_err()
                .contains("rest of the root")
        );
        assert!(
            keys.kithd_only('b', IMAGE, &block("2", None))
                .unwrap_err()
                .contains("no kithd object")
        );
        // (The running system's own release is not proven: no header kept for that slot.)
        assert!(keys.kithd_only('a', IMAGE, &same).unwrap_err().contains("not proven"));
    }
}

/// Staging a kithd (T-0709): the new kithd is put in a root-only place of its own, and only
/// after its sha256 is the one the signed header names.
#[cfg(test)]
mod stage {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const KITHD: &[u8] = b"#!/bin/sh\nexit 0\n";

    /// A staging folder (mode 0700, as the mount is) and a file holding `KITHD` beside it.
    fn folders(name: &str) -> (PathBuf, PathBuf) {
        let root = tests::scratch(&format!("stage-{name}"));
        let (dir, from) = (root.join("bin"), root.join("sbin-init"));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&from, KITHD).unwrap();
        (dir, from)
    }

    fn sum(bytes: &[u8]) -> String {
        crate::os::sha256(bytes)
    }

    #[test]
    fn refuses_a_binary_whose_sha256_differs_from_the_signed_digest_and_leaves_the_mount_root_only() {
        let (dir, from) = folders("differs");
        // An older staged file stays what it was (it may be the one that runs).
        std::fs::write(dir.join("kithd"), b"older").unwrap();
        let why = stage(&from, &sum(b"another kithd"), &dir).unwrap_err();
        assert!(why.contains("sha256"), "{why}");
        assert_eq!(std::fs::read(dir.join("kithd")).unwrap(), b"older");
        assert!(!dir.join("kithd.new").exists(), "no half-staged file is left");
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "still root-only");
    }

    #[test]
    fn stages_what_the_digest_names_as_an_executable_only_its_owner_has() {
        let (dir, from) = folders("matches");
        std::fs::write(dir.join("kithd"), b"older").unwrap();
        // (Upper case, as a header may write it.)
        let staged = stage(&from, &sum(KITHD).to_ascii_uppercase(), &dir).unwrap();
        assert_eq!(staged, dir.join("kithd"));
        assert_eq!(std::fs::read(&staged).unwrap(), KITHD);
        assert_eq!(std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(!dir.join("kithd.new").exists());
        // Twice: the same file again.
        stage(&from, &sum(KITHD), &dir).unwrap();
        assert_eq!(std::fs::read(&staged).unwrap(), KITHD);
    }

    #[test]
    fn refuses_a_place_that_others_could_write_or_that_is_not_there() {
        let (dir, from) = folders("open");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let why = stage(&from, &sum(KITHD), &dir).unwrap_err();
        assert!(why.contains("only"), "{why}");
        assert!(!dir.join("kithd").exists());
        assert!(stage(&from, &sum(KITHD), &dir.join("nowhere")).is_err());
        let (dir, _) = folders("no-file");
        assert!(stage(&dir.join("not-there"), &sum(KITHD), &dir).is_err());
    }

    #[test]
    fn a_hand_over_counts_for_the_kithd_it_names_and_for_no_other() {
        let root = tests::scratch("stage-effective");
        let (record, exe) = (root.join("handed-over"), root.join("exe"));
        std::fs::write(&exe, KITHD).unwrap();
        let says = |os: &str| effective(os.to_string(), &record, &exe);
        // No record: what the system says.
        assert_eq!(says("1.0"), "1.0");
        hand_over(&record, "1.0", "1.1", &sum(KITHD)).unwrap();
        assert_eq!(says("1.0"), "1.1");
        // The system itself has caught up (a reboot into the new slot): its own word.
        assert_eq!(says("1.1"), "1.1");
        assert_eq!(says("1.2"), "1.2");
        // Not the kithd that runs (the keeper fell back to its own): the system's.
        std::fs::write(&exe, b"the old kithd").unwrap();
        assert_eq!(says("1.0"), "1.0");
        // A record that is not what was written.
        std::fs::write(&record, "nonsense").unwrap();
        assert_eq!(says("1.0"), "1.0");
        // A version that could not be read back is not recorded.
        assert!(hand_over(&record, "1.0", "1.1 x", &sum(KITHD)).is_err());
        // Nor is a version that is not newer than the one that runs.
        std::fs::remove_file(&record).unwrap();
        assert!(hand_over(&record, "1.1", "1.1", &sum(KITHD)).is_err());
        assert!(hand_over(&record, "1.1", "1.0", &sum(KITHD)).is_err());
        assert!(!record.exists());
    }

    #[test]
    fn a_kithd_handed_over_to_that_was_not_the_one_that_runs_is_noted_as_a_try_that_failed() {
        let root = tests::scratch("stage-failed");
        let (record, exe, state) = (root.join("handed-over"), root.join("exe"), root.join("state"));
        std::fs::create_dir(&state).unwrap();
        std::fs::write(&exe, KITHD).unwrap();
        hand_over(&record, "1.0", "1.1", &sum(KITHD)).unwrap();
        // The staged kithd runs: nothing failed.
        forgo_failed_hand_over(&state, "1.0", &record, &exe);
        assert!(!tried(&state).exists());
        // It crashed and the keeper went back to the old one: 1.1 is a try that failed.
        std::fs::write(&exe, b"the old kithd").unwrap();
        forgo_failed_hand_over(&state, "1.0", &record, &exe);
        let said = report(&state, "1.0", 'a', "");
        assert_eq!(said["failed"], "1.1");
        assert!(
            said["why"].as_str().unwrap().contains("handed over to failed"),
            "{said}"
        );
        // A system that has caught up (a reboot into the new slot) has nothing to note.
        std::fs::remove_file(tried(&state)).unwrap();
        forgo_failed_hand_over(&state, "1.1", &record, &exe);
        assert!(!tried(&state).exists());
    }

    #[test]
    fn refuses_a_file_larger_than_most_and_leaves_nothing_staged() {
        let (dir, from) = folders("large");
        let big = vec![7u8; STAGE_MOST as usize + 1];
        std::fs::write(&from, &big).unwrap();
        let why = stage(&from, &sum(&big), &dir).unwrap_err();
        assert!(why.contains("larger"), "{why}");
        assert!(!dir.join("kithd").exists() && !dir.join("kithd.new").exists());
    }
}

/// (Here, at the foot, so that `#[cfg(test)]` comes after the code the cluster's `pinned_peer`
/// test counts clients in: it reads each file up to the first one.)
#[cfg(test)]
impl Keys {
    /// [`Keys::kithd_only`] as a [`crate::os::Way`].
    pub fn way(&self, slot: char, running: &[u8], block: &[u8]) -> crate::os::Way {
        match self.kithd_only(slot, running, block) {
            Ok(()) => crate::os::Way::KithdOnly,
            Err(_) => crate::os::Way::Full,
        }
    }
}
