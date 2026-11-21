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
        let Some((kind, _)) = key.split_once('/') else {
            return Ok(None);
        };
        let found = self.0.list(Some(kind))?.into_iter().find(|r| r.key() == key);
        found.map(|r| to_value(&r)).transpose()
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
