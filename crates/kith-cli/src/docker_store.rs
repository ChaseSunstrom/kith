//! The store `kith docker serve` answers container calls from (T-1258): the same `Backend` as
//! `kith apply`, `kith get` and `kith delete`, so a container is a resource kith shows and deletes
//! like any other. Kith keys are `Kind/namespace/name`.

use crate::Backend;
use kith_api::Resource;
use kith_docker::Store;
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
}

fn to_value(resource: &Resource) -> Result<Value, String> {
    serde_json::to_value(resource).map_err(|e| e.to_string())
}
