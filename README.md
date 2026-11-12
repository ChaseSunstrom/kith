<p align="center"><img src="logo-wordmark.svg" alt="kith" width="300"></p>

> **kith** *(n.)* one's close circle; the people you trust.

A tiny, immutable operating system that turns all of your machines into one
cluster, configured entirely through declarative resources. The design is in
[PLAN.md](PLAN.md).

## Status: Phase 0 done, Phase 1 started

There is no daemon yet. What works today is the resource model, the `kith`
command against a local store file, and a container runtime library that
nothing drives yet:

```sh
cargo build --release
alias kith=target/release/kith
export KITH_STORE=/tmp/kith-demo/store.json   # default: ~/.local/share/kith/store.json

kith lint -f examples/           # validate without touching the store
kith diff -f examples/           # what apply would change; exits 1 if anything
kith apply -f examples/
kith get                         # or: kith get workload/jellyfin -n media -o yaml
kith history workload/jellyfin -n media
kith rollback workload/jellyfin -n media --to 1
kith schema                      # the 26 built-in kinds; `kith schema workload` prints its JSON Schema
```

Mistakes are reported with the file, line and column:

```
web.yaml:7:13: invalid type: string "yes", expected u32
  |   replicas: yes
  |             ^
```

## Containers

`kith-runtime` pulls an OCI image into a content-addressed store and runs it in
its own cgroup, with youki's `libcontainer` linked in: no containerd, no shim,
no root. `kithd` will drive it; until then its end-to-end test is the demo:

```sh
KITH_E2E=1 cargo test -p kith-runtime --test e2e    # needs a registry, user namespaces and a systemd user session
```

Limits for now: the image is shared read-only (with tmpfs on `/tmp` and `/run`),
containers use the host's network, pulls are anonymous, layers must be gzip or
plain tar, and there is no seccomp filter yet.

## YAML, strictly

kith reads a strict subset of YAML (and JSON, which is a subset of that):

- duplicate keys are an error;
- anchors, aliases and tags are errors;
- `no`, `on`, `Yes`, `0x10` and `012` are strings; only `true`/`false`, `null`/`~`, and decimal numbers are special;
- where a field is a string, the text is taken as written, so `version: 1.0` is `"1.0"`;
- unknown fields are errors.

## Layout

| Crate | What it is |
|---|---|
| `crates/kith-yaml` | The strict parser, a serde deserializer that keeps source positions, and a YAML writer |
| `crates/kith-api` | The resource envelope, the built-in kinds, JSON Schemas, and the store (apply, diff, revisions) |
| `crates/kith-cli` | The `kith` command |
| `crates/kith-runtime` | Image pulls and containers |

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
python3 ci/budgets.py            # binary-size and memory budgets, enforced in CI
```

Release binaries are static musl builds. `kith-runtime` pulls in `ring`, which
has C in it, so linking it for musl needs a musl C compiler: `musl-tools` on
Debian/Ubuntu, or point `CC_x86_64_unknown_linux_musl` at a `zig cc -target
x86_64-linux-musl` wrapper.
