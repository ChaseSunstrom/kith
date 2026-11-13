//! The controller and admission hook of two kinds: a `GameServer` gets a ConfigMap of
//! its settings, a `Match` gets a GameServer. Build:
//!
//! ```sh
//! cargo build --release --target wasm32-unknown-unknown
//! kith controller set GameServer --controller target/wasm32-unknown-unknown/release/gameserver_controller.wasm \
//!                                --admission  target/wasm32-unknown-unknown/release/gameserver_controller.wasm
//! ```

use kith_controller::{Admit, Reconcile, Reconciled, Value, json};

fn reconcile(input: Reconcile) -> Result<Reconciled, String> {
    let resource = &input.resource;
    let name = resource["metadata"]["name"].as_str().ok_or("a resource has a name")?;
    let map = &resource["spec"]["map"];
    match resource["kind"].as_str() {
        Some("GameServer") => Ok(Reconciled {
            status: json!({ "state": "ready", "config": format!("{name}-config") }),
            resources: vec![json!({
                "apiVersion": "kith.dev/v1", "kind": "ConfigMap",
                "metadata": { "name": format!("{name}-config") },
                "spec": { "data": { "map": map, "players": resource["spec"]["players"].to_string() } },
            })],
        }),
        // A match is played on a server of its own. (How many play is the server's admission's to say.)
        Some("Match") => Ok(Reconciled {
            status: json!({ "state": "scheduled", "servers": input.owned.len() }),
            resources: vec![json!({
                "apiVersion": "games.example.com/v1", "kind": "GameServer",
                "metadata": { "name": format!("{name}-server") },
                "spec": { "map": map },
            })],
        }),
        other => Err(format!("this controller does not know the kind {other:?}")),
    }
}

fn admit(input: Admit) -> Result<Option<Value>, String> {
    let mut resource = input.resource;
    if resource["spec"]["map"] == "lava" {
        return Err("the map lava is closed".into());
    }
    if resource["spec"]["players"].is_null() {
        resource["spec"]["players"] = 8.into();
        return Ok(Some(resource));
    }
    Ok(None)
}

kith_controller::controller!(reconcile);
kith_controller::admission!(admit);
