# Security review 2: what the 1.0 review left out

Read on 2026-11-16, at main 0f81e83, by six independent read-only reviewers (one per area,
adversary lens, whole files rather than a diff). Each finding below was checked against the
code at its line before it was written here. "Read" means found by reading the code;
"test" means a test reproduces it. HIGH findings are fixed (by the named test) or have a
task of their own. MEDIUM and LOW findings each have a task, or are queued to be filed
("queued"). This review fixes none of them itself.

The six areas are the ones the 1.0 review named as not read (SECURITY.md, "Not reviewed").
Two other checks were done alongside:

- The dependency advisory check is in SECURITY.md under "Dependencies".
- kith-yaml now has a test that feeds it damaged files at random:
  `a_file_taken_apart_at_random` in `crates/kith-yaml/src/tests.rs`.

## Summary

| Area | HIGH | MEDIUM | LOW |
|---|---|---|---|
| The mesh: WireGuard keys and peers | 0 | 3 | 2 |
| The installer and the first process | 0 | 4 | 7 |
| A Source's apply against what a Package may write | 0 | 1 | 2 |
| Package templates: memory and time | 1 | 4 | 2 |
| Devices and seats | 1 | 2 | 2 |
| kith-lang and kith-lsp | 1 | 2 | 2 |

## Findings with their status

- H1 Templates: a lazily repeated list is expanded by a serializing filter or output before fuel is charged, and a panic or stack overflow in a render ends kithd. task: T-0645
- H2 Devices: no grant ties a Device or a Seat to a namespace, so any namespace's applier claims an unheld Seat or a keyboard. task: T-0646
- H3 kith-lang: the walk from a file's value to its resources charged no steps (2^60 for a shared list sixty deep). fixed: limits_hold_a_file_that_gives_a_list_shared_many_times

In detail:

- **H1** (`crates/kith-packages/src/lib.rs`, line 243; read). The constructs are `[s] * 100000`
  and a doubled merge. They are expanded by `toYaml`, `tojson`, `string`, `~` and
  `{{ }}` output before any fuel is charged. A 1 MB string becomes 100 GB, and kithd is
  killed for running out of memory. The author of a Package can do this, and so can a
  Release's writer through `values`. Release builds abort on panic, so a panic or a native
  stack overflow during a render ends kithd too.
- **H2** (`crates/kithd/src/claims.rs`, lines 85, 282 and 307; read).
  - What can be claimed: a Seat nobody holds, a keyboard, a sound card or a vfio GPU.
  - The per-namespace exclusion that SECURITY.md describes holds only while a holder is
    recorded.
  - While the session is gone, a `shared` claim also takes the seat's directory.
- **H3** (`crates/kith-lang/src/lib.rs`, line 181; test). A list that holds itself twice per
  level takes a few steps to make. Walking it, kithd pinned a core for a Source, and
  kith-lsp hung the editor.

## The mesh

- M1 Two Services whose 48-bit hashed addresses are equal merge their backends
  (`kith-mesh/src/lib.rs:60`, `kithd/src/services.rs` `table`). Someone who may apply in a
  namespace can search names until one lands on another namespace's Service. (Read.)
  task: T-0649
- M2 A pod running as root can send with another pod's or the node's mesh source address:
  nothing checks the source address per veth (`kith-mesh/src/pod.rs:538`). (Read.)
  task: T-0650
- M3 Pods other than exits reach every port of their node: the `in` chain accepts
  (`kith-mesh/src/pod.rs:525`). (Read.) task: T-0651
- L1 A mesh key held by two Nodes drops both from every peer list, not only the later one
  (`kithd/src/mesh.rs:171`). (Read; queued.)
- L2 A node's own `mesh.address` and endpoint are taken as it says. It can point only its
  own name elsewhere (`kithd/src/dns.rs:133`). (Read; queued.)
- Examined and sound:
  - private key files (0600, written by rename);
  - allowed-IPs, which come from node names only;
  - the join's refusal of a clash;
  - what a worker may patch;
  - peer removal;
  - netlink parsing;
  - the exit's rules.

## The installer and the first process

- M1 The verity table names `root-a`/`verity-a` by PARTLABEL, which the kernel finds on any
  disk, and init takes the disk `dm-0` sits on as the boot disk (`os/build.sh`, line 210;
  `kithd/src/init.rs:274`). A stick holding a copy of the public root and verity
  partitions, plus its own config and state, boots as the node. The node then joins the
  stick's cluster, unencrypted. Doing this takes hands on the machine and a restart. (Read.)
  task: T-0647
- M2 Install answers fetched over `http://` can be changed by anyone on the LAN: the
  disk, the join address and token, and `releaseKey` (`kithd/src/install.rs:557`). (Read.)
  task: T-0648
- M3 If an install with `encrypt` fails after the image is written, the disk is left
  bootable and unencrypted, while the installer says nothing was installed
  (`install.rs:530`). (Read; queued.)
- M4 `disk: only` can pick a removable drive when the internal disk shows up late
  (`install.rs:68`). (Read; queued.)
- L1 The disk is chosen by name and not checked again when it is opened (`install.rs:138`).
  (Read; queued.)
- L2 `ip: ''` writes `--advertise :7443` (`install.rs:180`). (Read; queued.)
- L3 The boot loader's editor is not turned off: with Secure Boot off, someone at the
  console can add `kith.update=` (`os/build.sh`, line 235). (Read; queued.)
- L4 `labelled()` takes any disk when `dm-0` has no slaves (`init.rs:274`). (Read; queued.)
- L5 `/run`, `/tmp` and `/dev/shm` are mounted without `noexec` (`init.rs:560`). (Read;
  queued.)
- L6 Only the image's length is written, so the rest of a reused disk is not erased
  (`install.rs:338`). (Read; queued.)
- L7 Until the cluster takes the key over, a sealed install keeps the disk key in the
  config partition's lock record. This was already in SECURITY.md. (Read.)
- Examined and sound:
  - answers are checked again before use, with no command or path built from them;
  - the installer refuses its own stick, opens the disk with O_EXCL and has the disk's
    name typed twice;
  - the written disk is read back and its hash compared;
  - the GPT, ext4 and DHCP readers check their bounds;
  - mount flags, and no shared propagation.

## A Source's apply against what a Package may write

- M1 The duplicate check is quadratic and builds a key string for every comparison, and
  nothing caps how many resources one Source gives (`kithd/src/sources.rs:613`; the same
  holds for a Package, `kith-packages/src/lib.rs:307`). (Read; queued.)
- L1 Between the plan and the apply a resource can appear: the apply is kithd's own, and
  is bounded by the writer's rights as decided at plan time (`sources.rs:931`). (Read;
  queued.)
- L2 What a Source fetches carries no signature. Only `spec.approve` pins a revision. This
  was already in the sources.rs header. (Read.)
- Examined and sound:
  - every resource, and every prune, goes through `writer_may` as the Source's writer;
  - a Source stays in its namespace (outside kith-system);
  - no other owner's resources are taken over;
  - annotations are stamped by kithd;
  - git is read as objects, with no symlinks and with size and file limits;
  - addresses are checked before they are fetched;
  - an approval is bound to the revision it approved.

## Package templates: memory and time

- M1 Fuel lets a template hold about 32 MB of strings, and the 1 MiB output limit is
  checked only after the whole output exists (`kith-packages/src/lib.rs:36`, `:292`).
  (Read; part of T-0645.)
- M2 Nothing caps the number of resources, or the total size, a Package renders to
  (`lib.rs:299`). (Read; queued with the Source's M1.)
- M3 Renders run on threads with the default 2 MiB stack, and 500 levels of macro
  recursion may not fit. A stack overflow ends kithd (`kithd/src/releases.rs:644`). (Read;
  part of T-0645.)
- M4 The JoinError handling around a render never runs in release builds, because they
  abort on panic (`releases.rs:645`). (Read; part of T-0645.)
- L1 minijinja's `range` with a negative step overflows. It panics in debug builds only.
  (Read.)
- L2 The `debug()` global writes out the whole context without charging fuel. (Read;
  queued.)
- Examined and sound:
  - string repeat and `range` are capped;
  - `join`, `replace`, `format` and `indent` are fueled;
  - `namespace()` is removed;
  - macro and include depth are capped;
  - rendered YAML is capped at 128 levels deep.

## Devices and seats

- M1 An input Device is named by its event index, which the kernel hands to the next
  device straight away. A claim on a gamepad gets a keyboard plugged in its place
  (`kithd/src/devices.rs:149`, `controller.rs:509`). (Read.) task: T-0652
- M2 A USB Device is known only by its vendor and product, both of which the stick
  reports itself (`devices.rs:168`). (Read.) task: T-0653
- L1 A selector with no node fails when a matching stick is plugged into another node
  (`claims.rs:116`). (Read; queued.)
- L2 A Device's `path` is checked only for being a character device under `/dev`, so
  `/dev/mem` and `/dev/tpm*` pass. Who may write Devices bounds this (`kith-runtime`
  `container.rs:1660`). (Read; queued.)
- Examined and sound:
  - device cgroup rules give one device each, `rw` without `m`;
  - plug and unplug do not follow links;
  - device node names are made from numbers;
  - `holder:` stays in its own namespace;
  - seat clients get render nodes only, and the seat's directory read-only;
  - status cannot be forged;
  - a worker writes only its own node's Devices.

## kith-lang and kith-lsp

- M1 `node_at` charged nothing for the nulls it leaves out of a list: the same class of
  bug as H3, on the way into a resource (`kith-lang/src/eval.rs:993`). (Test.) fixed:
  limits_hold_a_file_that_gives_a_list_shared_many_times
- M2 An error's column is counted from the line's start, on every error, and kith-lsp
  does this on every keystroke (`eval.rs:963`). (Read; queued.)
- L1 Chains of closures are dropped by recursion (`eval.rs:99`). (Read; queued.)
- L2 An import is read whole before its size is checked, with no total across imports.
  This affects kith and kith-lsp only, not kithd (`kith-lang/src/lib.rs:284`). (Read;
  queued.)
- Examined and sound:
  - the parser's nesting is capped, and the evaluator runs on a 64 MB stack with a depth
    limit;
  - arithmetic is checked;
  - builtins charge before they allocate;
  - UTF-8 is stepped by characters;
  - imports are confined to the directory;
  - kith-lsp caps Content-Length, converts UTF-16 positions safely, and never runs or
    fetches anything.
