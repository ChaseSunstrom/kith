//! Write a kith controller or admission hook in Rust.
//!
//! kithd runs the WebAssembly module a `KindDefinition` carries: a **controller** for
//! each resource of the kind (what should exist because of it, and its status) and an
//! **admission** hook before one is written (let it be, change it, or refuse it). Both
//! are plain functions: they get JSON and answer JSON, and can reach nothing else.
//!
//! ```ignore
//! use kith_controller::{Reconcile, Reconciled, json};
//!
//! fn reconcile(input: Reconcile) -> Result<Reconciled, String> {
//!     let name = input.resource["metadata"]["name"].as_str().ok_or("a resource has a name")?;
//!     Ok(Reconciled {
//!         status: json!({ "state": "ready" }),
//!         resources: vec![json!({
//!             "apiVersion": "kith.dev/v1", "kind": "ConfigMap",
//!             "metadata": { "name": format!("{name}-config") },
//!             "spec": { "data": { "map": input.resource["spec"]["map"] } },
//!         })],
//!     })
//! }
//! kith_controller::controller!(reconcile);
//! ```
//!
//! Build it as a `cdylib` for `wasm32-unknown-unknown` (`opt-level = "z"`, `lto`,
//! `panic = "abort"` keep it small), then `kith controller set KIND --controller FILE`.
//!
//! The contract, for other languages: the module exports `memory`,
//! `kith_alloc(len: u32) -> ptr`, and `kith_reconcile` / `kith_admit`
//! `(ptr: u32, len: u32) -> u64`: JSON in at `ptr`, and the answer's `ptr << 32 | len`
//! out, which is `{"ok": …}` or `{"error": "why"}`. It imports nothing.

use serde::{Deserialize, Serialize};
pub use serde_json::{Value, json};

/// What a controller is asked: the resource, and what it made before that is still there.
#[derive(Deserialize)]
pub struct Reconcile {
    pub resource: Value,
    #[serde(default)]
    pub owned: Vec<Value>,
}

/// What a controller answers: fields for the resource's status, and every resource that
/// should exist because of it. kithd makes them so, in the resource's namespace, and
/// removes what is no longer answered.
#[derive(Serialize, Default)]
pub struct Reconciled {
    pub status: Value,
    pub resources: Vec<Value>,
}

/// What an admission hook is asked: the resource about to be written, and what is there now.
#[derive(Deserialize)]
pub struct Admit {
    pub resource: Value,
    #[serde(default)]
    pub old: Option<Value>,
}

/// Room for kithd to put the input in.
#[unsafe(no_mangle)]
pub extern "C" fn kith_alloc(len: u32) -> u32 {
    let mut room = Vec::<u8>::with_capacity(len as usize);
    let at = room.as_mut_ptr();
    std::mem::forget(room);
    at as u32
}

#[doc(hidden)]
pub fn call<I: for<'a> Deserialize<'a>, O: Serialize>(at: u32, len: u32, f: impl FnOnce(I) -> Result<O, String>) -> u64 {
    // Safety: kithd wrote `len` bytes where `kith_alloc(len)` said, and hands them back once.
    let input = unsafe { Vec::from_raw_parts(at as *mut u8, len as usize, len as usize) };
    let answer = serde_json::from_slice(&input).map_err(|e| format!("the input: {e}")).and_then(f);
    let answer = match answer {
        Ok(answer) => json!({ "ok": answer }),
        Err(why) => json!({ "error": why }),
    };
    let answer = serde_json::to_vec(&answer).unwrap_or_default().into_boxed_slice();
    let said = (answer.as_ptr() as u64) << 32 | answer.len() as u64;
    std::mem::forget(answer);
    said
}

/// Make `fn(Reconcile) -> Result<Reconciled, String>` the module's controller.
#[macro_export]
macro_rules! controller {
    ($f:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn kith_reconcile(at: u32, len: u32) -> u64 {
            $crate::call(at, len, $f)
        }
    };
}

/// Make `fn(Admit) -> Result<Option<Value>, String>` the module's admission hook:
/// `Ok(None)` lets the resource be, `Ok(Some(resource))` is the resource changed (its
/// spec, labels and annotations), `Err(why)` refuses the write.
#[macro_export]
macro_rules! admission {
    ($f:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn kith_admit(at: u32, len: u32) -> u64 {
            $crate::call(at, len, $f)
        }
    };
}
