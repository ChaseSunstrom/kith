//! Runs other people's code inside kithd: a WASM module (a controller, an admission
//! hook) as a function from JSON to JSON, in an interpreter.
//!
//! A module exports its `memory`, `kith_alloc(len) -> ptr` and the function asked for,
//! `(ptr, len) -> (ptr << 32 | len)`: it is given JSON at a place it allocated, and
//! says where its answer is, `{"ok": …}` or `{"error": "why"}`. It imports nothing:
//! it sees its input and no more, and each call starts from a fresh instance.
//!
//! What it cannot do: run on (a budget of instructions, [`FUEL`]), grow without end
//! ([`MEMORY`]), be huge ([`MODULE_LIMIT`]) or answer at length ([`OUTPUT`]). Any of
//! these fails that one call, with the reason.

use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Mutex;
use wasmi::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

/// The largest module taken, in bytes.
pub const MODULE_LIMIT: usize = kith_api::kinds::WASM_LIMIT;
/// What one call may spend: tens of milliseconds of interpreting on an ordinary machine.
const FUEL: u64 = 50_000_000;
/// The most memory an instance may have.
const MEMORY: usize = 16 << 20;
/// The longest input given and answer read.
const OUTPUT: usize = 1 << 20;
/// Compiled modules kept. (More than that in use at once: they are compiled again in turn.)
const KEPT: usize = 16;
/// Modules run at once; more wait their turn.
const RUNNING: usize = 4;

type Digest = [u8; 32];

pub struct Modules {
    engine: Engine,
    compiled: Mutex<BTreeMap<Digest, Module>>,
    /// Calls at once: each may take its whole fuel and memory, and kithd has other work.
    running: std::sync::Arc<tokio::sync::Semaphore>,
}

impl Default for Modules {
    fn default() -> Modules {
        let mut config = Config::default();
        config.consume_fuel(true);
        Modules {
            engine: Engine::new(&config),
            compiled: Mutex::default(),
            running: std::sync::Arc::new(tokio::sync::Semaphore::new(RUNNING)),
        }
    }
}

pub fn digest(wasm: &[u8]) -> Digest {
    let digest = ring::digest::digest(&ring::digest::SHA256, wasm);
    digest.as_ref().try_into().expect("SHA-256 is 32 bytes")
}

impl Modules {
    /// Do `work` (calls of modules) on a thread that may be kept busy, when there is a turn free.
    pub async fn run<T: Send + 'static>(
        self: &std::sync::Arc<Self>,
        work: impl FnOnce(&Modules) -> T + Send + 'static,
    ) -> Result<T, String> {
        let modules = self.clone();
        let turn = self.running.clone().acquire_owned().await.map_err(|e| e.to_string())?;
        // (The turn goes with the work: a caller that stops waiting does not free it early.)
        let done = tokio::task::spawn_blocking(move || {
            let _turn = turn;
            work(&modules)
        });
        let done = done.await;
        done.map_err(|e| format!("the module's run stopped: {e}"))
    }

    /// The module compiled, if it is one that can run.
    pub fn module(&self, wasm: &[u8]) -> Result<Module, String> {
        if wasm.len() > MODULE_LIMIT {
            return Err(format!("the module is {} bytes: {MODULE_LIMIT} at most", wasm.len()));
        }
        let digest = digest(wasm);
        let mut compiled = self.compiled.lock().expect("nothing panics holding the modules");
        if let Some(module) = compiled.get(&digest) {
            return Ok(module.clone());
        }
        // (Checked as it is read: what is not valid WebAssembly never runs.)
        let module = Module::new(&self.engine, wasm).map_err(|e| format!("not a module that can run: {e}"))?;
        if compiled.len() >= KEPT {
            compiled.clear();
        }
        compiled.insert(digest, module.clone());
        Ok(module)
    }

    /// Call `export` of the module with `input`; what it answers under `ok`, or why not.
    /// This interprets: call it off the threads everything else waits on.
    pub fn call(&self, wasm: &[u8], export: &str, input: &Value) -> Result<Value, String> {
        let module = self.module(wasm)?;
        let input = serde_json::to_vec(input).map_err(|e| e.to_string())?;
        if input.len() > OUTPUT {
            return Err(format!(
                "{} bytes are too many to give a module: {OUTPUT} at most",
                input.len()
            ));
        }
        let failed = |what: &str, e: &dyn std::fmt::Display| format!("{what}: {e}");
        let limits = StoreLimitsBuilder::new()
            .memory_size(MEMORY)
            .memories(1)
            .tables(4)
            .table_elements(1 << 16)
            .instances(1)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(&self.engine, limits);
        store.limiter(|limits: &mut StoreLimits| limits);
        store.set_fuel(FUEL).map_err(|e| failed("setting it up", &e))?;
        // Nothing is linked: a module that imports anything does not start.
        let linker = <Linker<StoreLimits>>::new(&self.engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|e| failed("starting the module", &e))?;
        let memory = instance
            .get_memory(&store, "memory")
            .ok_or("the module exports no `memory`")?;
        let alloc = instance
            .get_typed_func::<u32, u32>(&store, "kith_alloc")
            .map_err(|e| failed("the module's `kith_alloc`", &e))?;
        let function = instance
            .get_typed_func::<(u32, u32), u64>(&store, export)
            .map_err(|e| failed(&format!("the module's `{export}`"), &e))?;
        let len = input.len() as u32;
        let at = alloc.call(&mut store, len).map_err(|e| failed("in `kith_alloc`", &e))?;
        memory
            .write(&mut store, at as usize, &input)
            .map_err(|e| failed("`kith_alloc` gave no room for the input", &e))?;
        let answer = function
            .call(&mut store, (at, len))
            .map_err(|e| failed(&format!("in `{export}`"), &e))?;
        let (at, len) = ((answer >> 32) as usize, (answer & 0xffff_ffff) as usize);
        if len > OUTPUT {
            return Err(format!("its answer is {len} bytes: {OUTPUT} at most"));
        }
        let answer = memory
            .data(&store)
            .get(at..at + len)
            .ok_or("its answer is not in its memory")?;
        let answer: Value = serde_json::from_slice(answer).map_err(|e| failed("its answer is not JSON", &e))?;
        match answer {
            Value::Object(mut answer) if answer.contains_key("ok") => Ok(answer.remove("ok").unwrap_or_default()),
            Value::Object(answer) if answer.contains_key("error") => {
                Err(answer["error"].as_str().unwrap_or("it gave no reason").to_string())
            }
            _ => Err("its answer is neither {\"ok\": …} nor {\"error\": …}".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A module whose `run` is `body`, with a `kith_alloc` that hands out the memory after
    /// the first 1024 bytes, where `data` is.
    fn module(data: &str, body: &str) -> Vec<u8> {
        let text = format!(
            r#"(module
                (memory (export "memory") 1)
                (data (i32.const 0) "{data}")
                (func (export "kith_alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "run") (param $at i32) (param $len i32) (result i64) {body}))"#
        );
        wat::parse_str(text).unwrap()
    }

    /// The answer at `at`, `len` bytes long.
    fn answer(at: u64, len: u64) -> String {
        format!("(i64.const {})", at << 32 | len)
    }

    #[test]
    fn wasm_modules_are_functions_over_json() {
        let modules = Modules::default();
        // The input comes back: it was written where `kith_alloc` said, and read from there.
        let echo = "(i64.or (i64.shl (i64.extend_i32_u (local.get $at)) (i64.const 32)) \
                    (i64.extend_i32_u (local.get $len)))";
        let echo = module("", echo);
        let input = serde_json::json!({ "ok": { "map": "dust", "players": [1, 2] } });
        assert_eq!(modules.call(&echo, "run", &input), Ok(input["ok"].clone()));
        assert_eq!(modules.call(&echo, "run", &input), Ok(input["ok"].clone()));
        // Its own refusal is the error; anything else it says is not an answer.
        let refusing = serde_json::json!({ "error": "not on a Sunday" });
        assert_eq!(modules.call(&echo, "run", &refusing), Err("not on a Sunday".into()));
        let said = modules.call(&echo, "run", &serde_json::json!([1])).unwrap_err();
        assert!(said.contains("neither"), "{said}");
        let said = modules
            .call(&module("nonsense", &answer(0, 8)), "run", &input)
            .unwrap_err();
        assert!(said.contains("not JSON"), "{said}");
    }

    #[test]
    fn wasm_modules_are_held_to_their_limits() {
        let modules = Modules::default();
        let input = serde_json::json!({});
        let fails = |wasm: &[u8], with: &str| {
            let said = modules.call(wasm, "run", &input).unwrap_err();
            assert!(said.contains(with), "`{with}` is not in: {said}");
        };
        // Runs on: out of fuel.
        fails(&module("", "(loop $again (br $again)) (i64.const 0)"), "fuel");
        // Grows without end: stopped at the limit (a trap, not a quiet -1 it could ignore).
        let greedy = "(loop $again (drop (memory.grow (i32.const 16))) (br $again)) (i64.const 0)";
        let said = modules.call(&module("", greedy), "run", &input).unwrap_err();
        assert!(said.contains("in `run`") && !said.contains("fuel"), "{said}");
        // Recurses without end.
        let deep = wat::parse_str(
            r#"(module (memory (export "memory") 1)
                (func (export "kith_alloc") (param i32) (result i32) (i32.const 0))
                (func $run (export "run") (param i32 i32) (result i64)
                    (call $run (local.get 0) (local.get 1))))"#,
        );
        fails(&deep.unwrap(), "in `run`");
        // An answer that is not in its memory, or too long.
        fails(&module("", &answer(70_000, 16)), "not in its memory");
        fails(&module("", &answer(0, 2 << 20)), "at most");
        fails(&module("", "(i64.const -1)"), "at most");
        // Traps.
        fails(&module("", "(unreachable)"), "in `run`");
        // No room for the input where it said.
        let nowhere = wat::parse_str(
            r#"(module (memory (export "memory") 1)
                (func (export "kith_alloc") (param i32) (result i32) (i32.const -8))
                (func (export "run") (param i32 i32) (result i64) (i64.const 0)))"#,
        );
        fails(&nowhere.unwrap(), "no room");
        // Lacks what is asked of it.
        let said = modules.call(&module("", "(i64.const 0)"), "other", &input).unwrap_err();
        assert!(said.contains("`other`"), "{said}");
        let bare = r#"(module (func (export "run") (param i32 i32) (result i64) (i64.const 0)))"#;
        fails(&wat::parse_str(bare).unwrap(), "no `memory`");
        // Wants something of its host: there is nothing to have.
        let asking = r#"(module (import "env" "open" (func (param i32) (result i32)))
            (memory (export "memory") 1))"#;
        fails(&wat::parse_str(asking).unwrap(), "starting the module");
        // Not WebAssembly, and too much of it.
        fails(b"\0asm but not really", "not a module");
        fails(&vec![0; MODULE_LIMIT + 1], "at most");
    }
}
