//! The store `kith docker serve` answers container calls from (T-1258): the same `Backend` as
//! `kith apply`, `kith get` and `kith delete`, so a container is a resource kith shows and deletes
//! like any other. Kith keys are `Kind/namespace/name`.

use crate::Backend;
use kith_api::Resource;
use kith_docker::{LogChunk, LogFrom, Session, Store};
use serde_json::Value;

pub struct DockerStore(pub Backend);

impl Store for DockerStore {
    fn get(&self, key: &str) -> Result<Option<Value>, String> {
        // One read of the one key; "not found" (local or kithd's refusal) is no resource, not a failure.
        match self.0.get(key) {
            Ok(resource) => to_value(&resource).map(Some),
            Err(e) if e.ends_with(" not found") => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn list(&self, kind: &str, namespace: &str) -> Result<Vec<Value>, String> {
        self.0
            .list(Some(kind))?
            .iter()
            .filter(|r| r.metadata.namespace.as_deref() == Some(namespace))
            .map(to_value)
            .collect()
    }

    fn apply(&self, doc: Value) -> Result<(), String> {
        let resource: Resource = serde_json::from_value(doc).map_err(|e| e.to_string())?;
        self.0.apply(vec![resource], false).map(|_| ())
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        self.0.delete(key).map(|_| ())
    }

    /// kithd's `/v1/logs` of the container's first unit (a stopped Workload has none to read).
    fn logs(&self, key: &str, stderr: bool, from: LogFrom) -> Result<LogChunk, String> {
        let Backend::Daemon(kithd) = &self.0 else {
            return Err("logs are read from kithd: leave out --store".into());
        };
        let place = match from {
            LogFrom::Start => "&offset=0".to_string(),
            LogFrom::Tail(lines) => format!("&tail={lines}"),
            LogFrom::Offset(at) => format!("&offset={at}"),
        };
        let which = if stderr { "&stderr=true" } else { "" };
        let reply: Value = crate::request(
            kithd,
            "GET",
            &format!("/v1/logs/{}?replica=0{which}{place}", crate::escape(key)),
            b"",
        )?;
        Ok(LogChunk {
            data: reply["data"].as_str().unwrap_or_default().as_bytes().to_vec(),
            next: reply["next"].as_u64().unwrap_or(0),
        })
    }

    fn exec(&self, pod: &str, command: &[String], tty: bool, stdin: bool) -> Result<Session, String> {
        let Backend::Daemon(kithd) = &self.0 else {
            return Err("exec is a connection to kithd: leave out --store".into());
        };
        crate::machine::shell::session(kithd, pod, command, tty, stdin)
    }
}

fn to_value(resource: &Resource) -> Result<Value, String> {
    serde_json::to_value(resource).map_err(|e| e.to_string())
}
