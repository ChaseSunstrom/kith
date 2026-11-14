//! CronJobs: at each minute a CronJob's schedule names (in UTC), the node that leads the
//! store makes a Job of it, named after the CronJob and the minute. A CronJob that says
//! `concurrency: forbid` waits for its Job that has not finished, one that says `replace`
//! has it removed first. The last [`KEPT`] finished Jobs of a CronJob are kept; each is
//! marked as the CronJob's own ([`OWNER`]), so all of them go when it does.
//!
//! A CronJob whose schedule cannot be read, or that names a time zone other than UTC, is
//! not run, and its status says why (`message`).
//!
//! ponytail: a minute in which no node led (or kithd was not running) is not made up for,
//! and Kubernetes's `startingDeadlineSeconds` would say how late a run may still start:
//! read `status.last` and catch up from it if a missed run comes to matter.

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

/// Finished Jobs of a CronJob that are kept.
const KEPT: usize = 3;

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
        let old = done.len().saturating_sub(KEPT);
        step.delete.extend(done[..old].iter().map(|job| job.key()));
        let due = schedule(cron);
        // What it says of that, where it does not say it already (nothing, where it runs).
        let why = due.as_ref().err().map_or(Value::Null, |why| json!(why));
        let says = cron.status.as_ref().map_or(&Value::Null, |status| &status["message"]);
        if *says != why {
            step.last
                .push((key.clone(), Map::from_iter([("message".to_string(), why)])));
        }
        let name = format!("{}-{}", meta.name, at / 60);
        let made = running.iter().chain(&done).any(|job| job.metadata.name == name);
        if !due.is_ok_and(|schedule| schedule.due(at)) || made {
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
        let last = json!({ "last": rfc3339(at - at % 60) });
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
        // Of the finished ones the last three are kept.
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
        assert_eq!(step.delete, [key("often-1"), key("often-2")]);
    }
}
