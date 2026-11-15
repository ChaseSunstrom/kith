//! CronJobs: at each minute a CronJob's schedule names (in UTC), the node that leads the
//! store makes a Job of it, named after the CronJob and the minute. A CronJob that says
//! `concurrency: forbid` waits for its Job that has not finished, one that says `replace`
//! has it removed first. The last [`KEPT`] finished Jobs of a CronJob that succeeded and
//! as many that failed are kept (`successfulJobsHistoryLimit`, `failedJobsHistoryLimit`
//! say otherwise); each is marked as the CronJob's own ([`OWNER`]), so all of them go
//! when it does.
//!
//! A minute in which no node led (or kithd was not running) is made up for when the
//! CronJob says `startingDeadlineSeconds`: of the minutes its schedule named since
//! `status.last` that are no older than that, the latest is run, once. One that has
//! never run (no `status.last`) has nothing to catch up from.
//!
//! A CronJob whose schedule cannot be read, or that names a time zone other than UTC, is
//! not run, and its status says why (`message`).
//!
//! ponytail: no table of time zones: measured, the zones' rules are 207 kB as compiled
//! (`zic -b slim`, 345 distinct zones; 407 kB as the host keeps them, 105 kB as source
//! with a parser to write), over the 150 kB this was given out of what kithd has left
//! under its 13.00 MB, and kith OS ships none. Take a zone's name if that room is made. A catch-up looks back
//! at most [`LOOKBACK`] minutes: one more `due` per minute per CronJob that is idle.

use crate::Shared;
use crate::releases::{OWNER, owner};
use kith_api::cron::Schedule;
use kith_api::store::{Store, now, rfc3339};
use kith_api::{Metadata, Resource};
use kith_store::Command;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// Finished Jobs of a CronJob that are kept of each, unless it says.
const KEPT: usize = 3;

/// The most minutes a catch-up looks back, whatever the deadline (a week).
const LOOKBACK: u64 = 7 * 24 * 60;

/// Seconds since the epoch of `2026-11-12T09:30:00Z` (what [`rfc3339`] writes).
fn unrfc3339(text: &str) -> Option<u64> {
    let n = |from: usize, len: usize| text.get(from..from + len)?.parse::<i64>().ok();
    if text.len() != 20 || !text.ends_with('Z') {
        return None;
    }
    let (m, d) = (n(5, 2)?, n(8, 2)?);
    let y = n(0, 4)? - i64::from(m <= 2);
    let (era, yoe) = (y.div_euclid(400), y.rem_euclid(400));
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    u64::try_from(days * 86400 + n(11, 2)? * 3600 + n(14, 2)? * 60 + n(17, 2)?).ok()
}

/// The minute (since the epoch, in minutes) to make a Job for at `at`: the latest the
/// schedule names, of this one and, where the CronJob has a deadline, the ones since its
/// last run that the deadline allows.
fn minute(cron: &Resource, schedule: &Schedule, at: u64) -> Option<u64> {
    let this = at / 60;
    let last = cron
        .status
        .as_ref()
        .and_then(|status| status["last"].as_str())
        .and_then(unrfc3339);
    // (Never the minute of its last run again, nor one before it: a Job that ran and went,
    // kept by no history limit, is not made a second time by a look in the same minute.)
    let after = last.map_or(0, |last| last / 60 + 1);
    let from = match (cron.spec["startingDeadlineSeconds"].as_u64(), last) {
        (Some(deadline), Some(_)) => (at.saturating_sub(deadline))
            .div_ceil(60)
            .max(this.saturating_sub(LOOKBACK)),
        _ => this,
    };
    // (This minute is run on time whatever the deadline.)
    (from.min(this).max(after)..=this)
        .rev()
        .find(|minute| schedule.due(minute * 60))
}

/// What the minute `at` is in asks for.
#[derive(Default)]
struct Step {
    make: Vec<Resource>,
    delete: Vec<String>,
    /// Each CronJob a Job was made for, and when.
    last: Vec<(String, Map<String, Value>)>,
}

/// When a CronJob runs, or why it is not run.
fn schedule(cron: &Resource) -> Result<Schedule, String> {
    match cron.spec["timezone"].as_str() {
        None | Some("UTC" | "Etc/UTC") => {}
        // ponytail: no table of time zones (it is bigger than kith); one is what this needs.
        Some(zone) => {
            return Err(format!(
                "not run: its timezone is {zone}, and a schedule is read in UTC only"
            ));
        }
    }
    // (A Job is called `<name>-<minute>`, and a name has 63 characters.)
    if cron.metadata.name.len() > 54 {
        return Err("not run: its name is longer than 54 characters, and a Job's name is its and the minute".into());
    }
    let said = cron.spec["schedule"].as_str().unwrap_or_default();
    Schedule::parse(said).map_err(|e| format!("not run: its schedule {e}"))
}

fn plan(store: &Store, at: u64) -> Step {
    let mut step = Step::default();
    // The Jobs that were made for something, by its key.
    let mut jobs: BTreeMap<&str, Vec<&Resource>> = BTreeMap::new();
    for job in store.list(Some("Job")) {
        if let Some(of) = owner(job) {
            jobs.entry(of).or_default().push(job);
        }
    }
    for cron in store.list(Some("CronJob")) {
        let (key, meta) = (cron.key(), &cron.metadata);
        let mine = jobs.remove(key.as_str()).unwrap_or_default();
        let finished = |job: &&Resource| matches!(job.status.as_ref().map(|status| &status["state"]), Some(state) if state == "succeeded" || state == "failed");
        // (A Job's name ends in its minute: by name is by age.)
        let (done, running): (Vec<&Resource>, Vec<&Resource>) = mine.into_iter().partition(finished);
        let (good, bad): (Vec<&Resource>, Vec<&Resource>) = done
            .iter()
            .partition(|job| job.status.as_ref().is_some_and(|status| status["state"] == "succeeded"));
        for (jobs, field) in [(good, "successfulJobsHistoryLimit"), (bad, "failedJobsHistoryLimit")] {
            let kept = cron.spec[field]
                .as_u64()
                .map_or(KEPT, |kept| usize::try_from(kept).unwrap_or(KEPT));
            step.delete
                .extend(jobs[..jobs.len().saturating_sub(kept)].iter().map(|job| job.key()));
        }
        let due = schedule(cron);
        // What it says of that, where it does not say it already (nothing, where it runs).
        let why = due.as_ref().err().map_or(Value::Null, |why| json!(why));
        let says = cron.status.as_ref().map_or(&Value::Null, |status| &status["message"]);
        if *says != why {
            step.last
                .push((key.clone(), Map::from_iter([("message".to_string(), why)])));
        }
        let Some(minute) = due.ok().and_then(|schedule| minute(cron, &schedule, at)) else {
            continue;
        };
        let name = format!("{}-{minute}", meta.name);
        if running.iter().chain(&done).any(|job| job.metadata.name == name) {
            continue;
        }
        match cron.spec["concurrency"].as_str() {
            Some("forbid") if !running.is_empty() => continue,
            Some("replace") => step.delete.extend(running.iter().map(|job| job.key())),
            _ => {}
        }
        let mut annotations = crate::kube::job_of(cron, &name);
        annotations.insert(OWNER.into(), key.clone());
        step.make.push(Resource {
            api_version: kith_api::API_VERSION.into(),
            kind: "Job".into(),
            metadata: Metadata {
                name,
                namespace: meta.namespace.clone(),
                labels: meta.labels.clone(),
                annotations,
                // (Made, never changed: two nodes that both think they lead make one.)
                revision: Some(0),
            },
            spec: cron.spec["job"].clone(),
            status: None,
        });
        let last = json!({ "last": rfc3339(minute * 60) });
        step.last.extend(last.as_object().map(|last| (key, last.clone())));
    }
    step
}

/// Once a minute, while this node leads: what [`plan`] says.
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    // The minute last looked at: each is looked at once.
    let mut looked = 0;
    loop {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(60 - now() % 60)) => {}
            _ = stopping.changed() => return,
        }
        let at = now();
        let metrics = shared.raft.metrics().borrow().clone();
        if metrics.current_leader != Some(metrics.id) || at / 60 == looked {
            continue;
        }
        looked = at / 60;
        let step = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            plan(&state.store, at)
        };
        let deletes = step.delete.into_iter().map(|key| Command::Delete { key });
        let makes = step.make.into_iter().map(|job| Command::Apply {
            resources: vec![job],
            at,
        });
        let last = (!step.last.is_empty()).then_some(Command::Patch { statuses: step.last });
        for command in deletes.chain(makes).chain(last) {
            if let Err(e) = shared.submit(command).await {
                eprintln!("kithd: a CronJob's Jobs: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource(kind: &str, name: &str, spec: Value) -> Resource {
        let text = json!({ "apiVersion": "kith.dev/v1", "kind": kind, "metadata": { "name": name }, "spec": spec });
        serde_json::from_value(text).unwrap()
    }

    #[test]
    fn a_due_cronjob_gets_a_job_and_keeps_its_last_three() {
        // Friday 2026-11-13 09:30:10.
        let (at, minute) = (1_794_562_210, 1_794_562_200 / 60);
        let job = json!({ "template": { "exec": [{ "name": "tick", "command": ["true"] }] } });
        let cron = |name: &str, schedule: &str, concurrency: &str| {
            let spec = json!({ "schedule": schedule, "concurrency": concurrency, "job": job });
            resource("CronJob", name, spec)
        };
        let mut store = Store::default();
        for cron in [
            cron("often", "30 9 * * *", "allow"),
            cron("waits", "* * * * *", "forbid"),
            cron("anew", "* * * * *", "replace"),
            cron("later", "31 9 * * *", "allow"),
        ] {
            store.apply(cron).unwrap();
        }
        let step = plan(&store, at);
        let made: Vec<&str> = step.make.iter().map(|job| job.metadata.name.as_str()).collect();
        let name = |of: &str| format!("{of}-{minute}");
        assert_eq!(made, [name("anew"), name("often"), name("waits")]);
        assert!(step.delete.is_empty());
        assert_eq!(step.last[0].1["last"], "2026-11-13T09:30:00Z");
        // One that cannot be run is not, and says why once.
        let mut wrong = Store::default();
        let mut berlin = cron("berlin", "* * * * *", "allow");
        berlin.spec["timezone"] = "Europe/Berlin".into();
        for cron in [
            berlin,
            cron("never", "61 * * * *", "allow"),
            cron(&"n".repeat(55), "* * * * *", "allow"),
            cron("utc", "* * * * *", "allow"),
        ] {
            wrong.apply(cron).unwrap();
        }
        let unread = plan(&wrong, at);
        assert_eq!(unread.make.len(), 1, "the one that can be read");
        let said: Vec<String> = unread
            .last
            .iter()
            .filter(|(_, says)| says.contains_key("message"))
            .map(|(key, says)| format!("{key}: {}", says["message"]))
            .collect();
        assert!(
            said[0].starts_with("CronJob/default/berlin: \"not run: its timezone is Europe/Berlin"),
            "{said:?}"
        );
        assert!(
            said[1].contains("never: \"not run: its schedule `61` is not a minute"),
            "{said:?}"
        );
        assert!(said[2].contains("not run: its name is longer than 54"), "{said:?}");
        wrong
            .set_status(
                "CronJob/default/berlin",
                Some(json!({ "message": unread.last[0].1["message"] })),
            )
            .unwrap();
        assert!(
            plan(&wrong, at).last.iter().all(|(key, _)| !key.ends_with("berlin")),
            "said once"
        );
        let made = &step.make[1];
        assert_eq!(made.spec, job);
        assert_eq!(
            owner(made),
            Some("CronJob/default/often"),
            "it goes when the CronJob does"
        );
        assert_eq!(made.metadata.revision, Some(0), "made once, by whichever node");
        // Applied, the same minute asks for nothing more.
        for job in step.make {
            store.apply(job).unwrap();
        }
        let step = plan(&store, at + 20);
        assert!(step.make.is_empty() && step.delete.is_empty());
        // The next minute: the one that waits has a Job still running, the one that
        // replaces has its own removed, and `often` is not due.
        let step = plan(&store, at + 60);
        let made: Vec<&str> = step.make.iter().map(|job| job.metadata.name.as_str()).collect();
        assert_eq!(made, [format!("anew-{}", minute + 1), format!("later-{}", minute + 1)]);
        assert_eq!(step.delete, [format!("Job/default/{}", name("anew"))]);
        // Of the finished ones the last three that succeeded and the last three that failed are kept.
        let mut store = Store::default();
        store.apply(cron("often", "30 9 * * *", "allow")).unwrap();
        for n in 1..=5 {
            let mut done = resource("Job", &format!("often-{n}"), job.clone());
            let own = "CronJob/default/often".to_string();
            done.metadata.annotations.insert(OWNER.into(), own);
            let state = json!({ "state": if n == 2 { "failed" } else { "succeeded" } });
            let done = store.apply(done).unwrap().after.key();
            store.set_status(&done, Some(state)).unwrap();
        }
        let key = |name: &str| format!("Job/default/{name}");
        let step = plan(&store, at + 3600);
        assert_eq!(step.delete, [key("often-1")]);
        // A CronJob that says how many of each are kept keeps that many: one that succeeded,
        // none that failed.
        let mut few = cron("often", "30 9 * * *", "allow");
        few.spec["successfulJobsHistoryLimit"] = 1.into();
        few.spec["failedJobsHistoryLimit"] = 0.into();
        store.apply(few).unwrap();
        let mut deleted = plan(&store, at + 3600).delete;
        deleted.sort();
        assert_eq!(
            deleted,
            [key("often-1"), key("often-2"), key("often-3"), key("often-4")]
        );
    }

    #[test]
    fn a_missed_minute_is_made_up_once_within_its_deadline() {
        // Friday 2026-11-13 09:34:10; `*/10 * * * *` named 09:10, 09:20 and 09:30 since 09:00.
        let (at, nine_thirty) = (1_794_562_450, 1_794_562_200);
        let job = json!({ "template": { "exec": [{ "name": "tick", "command": ["true"] }] } });
        let mut store = Store::default();
        let nine = nine_thirty - 1800;
        for (name, deadline, last) in [
            ("late", Some(300), Some(nine)),
            ("too-late", Some(200), Some(nine)),
            ("unsaid", None, Some(nine)),
            ("new", Some(3600), None),
            ("zero", Some(0), Some(nine)),
            ("done", Some(3600), Some(nine_thirty)),
        ] {
            let spec = json!({ "schedule": "*/10 * * * *", "job": job, "startingDeadlineSeconds": deadline });
            let key = store.apply(resource("CronJob", name, spec)).unwrap().after.key();
            if let Some(last) = last {
                store.set_status(&key, Some(json!({ "last": rfc3339(last) }))).unwrap();
            }
        }
        let minute = nine_thirty / 60;
        let step = plan(&store, at);
        let made: Vec<&str> = step.make.iter().map(|job| job.metadata.name.as_str()).collect();
        assert_eq!(
            made,
            [format!("late-{minute}")],
            "the latest missed one, once, in its deadline"
        );
        assert_eq!(step.last[0].1["last"], "2026-11-13T09:30:00Z");
        // Made, it is not made again; a minute the schedule names is run on time as before.
        let mut store = store;
        for job in step.make {
            store.apply(job).unwrap();
        }
        store
            .set_status("CronJob/default/late", Some(json!({ "last": rfc3339(nine_thirty) })))
            .unwrap();
        assert!(plan(&store, at + 60).make.is_empty());
        // Nor is the minute of a last run made again in that same minute, its Job gone
        // already (a history limit of 0): `done` ran at 09:30 and has no Job. (The four that
        // last ran at 09:00, or never, run at 09:30 on time.)
        let again = plan(&store, nine_thirty + 5);
        let again: Vec<&str> = again.make.iter().map(|job| job.metadata.name.as_str()).collect();
        assert_eq!(again.len(), 4, "{again:?}");
        assert!(!again.contains(&format!("done-{minute}").as_str()), "{again:?}");
        let on_time = plan(&store, nine_thirty + 600 + 5);
        assert_eq!(
            on_time.make.len(),
            6,
            "09:40 is named by all six, and is run on time as before"
        );
    }

    #[test]
    fn a_status_time_is_read_back() {
        for secs in [0, 951_782_400, 1_794_476_096] {
            assert_eq!(unrfc3339(&rfc3339(secs)), Some(secs));
        }
        assert_eq!(unrfc3339("yesterday"), None);
    }
}
