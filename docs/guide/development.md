# Working on kith

## Layout

| Where | What it is |
|---|---|
| `crates/kith-yaml` | The strict parser, a serde deserializer that keeps source positions, and a YAML writer |
| `crates/kith-api` | The resource envelope, the built-in kinds, JSON Schemas, and the store (apply, diff, revisions) |
| `crates/kith-cli` | The `kith` command |
| `crates/kith-runtime` | Image pulls and containers |
| `crates/kith-store` | The replicated store: Raft (`openraft`) with its log in `redb` |
| `crates/kith-dns` | The DNS server: wire format, zones, split horizon, forwarding |
| `crates/kith-sched` | The scheduler, as a pure function from nodes and replicas to a plan |
| `crates/kith-packages` | Packages: templates and values rendered into resources |
| `crates/kith-lang` | kith's own language: its parser and its evaluator, from a `.kith` file to resources |
| `crates/kith-lsp` | `kith-lsp`, the language server for `.kith` files |
| `crates/kith-dm-sys` | The one crate of the workspace with `unsafe`: device-mapper, loop devices, growing a file system and a partition's new length, by ioctl, for encrypted volumes and kith OS's state |
| `crates/kith-mesh` | The mesh: addresses and peers worked out from the nodes, and the kernel's WireGuard set up over netlink |
| `crates/kith-kube` | Kubernetes objects read as the kith resources they mean, with a table of what becomes of every field: carried over, taken and said to change nothing, or refused |
| `crates/kithd` | The daemon: API server, store replica, scheduler, mesh, DNS and Workload controller |
| `sdk/kith-controller` | The SDK for controllers and admission hooks in WebAssembly, with an example (its own workspace: it builds for wasm32) |
| `os/` | kith OS: what builds its image (`build.sh`), an update (`update.sh`) and the installer for a rented machine (`vps.sh`), and the kernel's configuration |
| `packages/` | Packages that come with kith: `web`, `nas`, `kith-build`, `kith-panel`, and the desktops (`gnome`, `hyprland`, `kiosk`) |
| `examples/` | Resources to apply as they are; `examples/session/` is a set of files (a Containerfile, a script, a manifest), and `-f examples/` does not read it |
| `ci/` | The budgets, the benchmark, the VM tests (`vm.sh`), and what measures and photographs the website (`site_numbers.py`, `site_shots.py`) |
| `dist/` | A systemd user unit for agent mode |
| `docs/` | The website (GitHub Pages serves this folder), the pictures the README shows, and `adr-workers.md`, the design for worker nodes that is not built yet |

## Development

```sh
cargo test --workspace
KITH_E2E=1 cargo test -p kithd -p kith-runtime --test e2e   # pulls an image and runs containers
cargo clippy --workspace --all-targets -- -D warnings
rustup target add wasm32-unknown-unknown   # once: without it the WASM end-to-end tests skip themselves
python3 ci/budgets.py            # binary-size and memory budgets, enforced in CI
python3 ci/bench.py              # the plan's numbers for one node: cached start < 150 ms, 20+ containers under 30 MB of kithd
```

The workspace's tests can run on a kith cluster instead, spread over all its nodes, from a commit
that is not pushed:
`KITH_REMOTE=ADDR KITH_REMOTE_CREDS=DIR sh ci/remote.sh --fan [COMMIT [CARGO TEST ARGS]]`
(`COMMIT` is `HEAD` unless named; the arguments are `cargo test`'s and `--workspace` unless
given), with DIR holding the cluster's `ca.crt` and a client's `root.crt` and `root.key`.

- **What is sent.** Only what GitHub lacks: a `git bundle` of `origin/main..COMMIT`, put into the
  node's Volume `ci-NODE` (made if it is not there). The node fetches the commits the bundle
  builds on from GitHub, shallow, so a push is never needed.
- **The cache.** The same Volume keeps the node's cargo registry, its target folder and the
  checkout, so only what changed builds on a second run. A node whose target folder is over
  `KITH_REMOTE_CACHE_MB` (30000) drops it at the start of a run. The Volume stays; its folder
  `volumes/ci/ci-NODE` in the node's state is what to remove to free the disk.
- **The namespace.** CI runs in namespace `ci`, and /dev/kvm is granted only there: every
  Volume, Job and claim the script applies is in `ci`.
- **The split.** Each node lists the workspace's tests (`cargo test -- --list`), keeps the names
  whose hash is its place among the nodes' and runs them (`-- --exact NAMES`, `--no-fail-fast`)
  as a user who is not root, in a pod. Every node builds all of it, so a cold node takes as long
  as one alone; the run time is the longest share's.
- **The result.** One merged report: each node's summary line (tests passed and failed, the
  seconds, whether its cache was warm) and `FAILED: NODE: TEST` for each failure. The exit is 0,
  101 when a test or a build failed, or 2 when a node's Job did not run to its end. A second run
  of the same user waits for the first on each node (a lock in the Volume).
- **No cluster.** With `KITH_REMOTE` unset, or no node answering, `cargo test` runs here with
  the same arguments and exit status, on the working tree.
- **Check it.** `sh ci/remote.sh --self-test` runs offline: the bundle of a commit GitHub lacks,
  shares of 1 to 5 nodes covering each test once, a Job of three nodes against a folder for a
  GitHub, the merged report and the fallback.

Not yet: a Job has no low priority, so a run uses the nodes' CPUs as any Job does.

The VM tests (`sh ci/vm.sh --test NAME`) can go to the same cluster:
`KITH_REMOTE=ADDR KITH_REMOTE_CREDS=DIR sh ci/remote.sh --vm TEST[,TEST...] [COMMIT]`.

- **The KVM.** Per node it applies, unchanged on a second run, a Device `ci-kvm-NODE` of the
  node's /dev/kvm (class `other`), granted to namespace `ci` alone, and a shared DeviceClaim
  `ci-kvm-NODE` in `ci` that each Job names. The Job is not privileged: it runs as 1000 in a
  user namespace.
- **The tools.** The Job copies the image's root into the Volume and installs ci/vm.sh's tools
  there with apt (its archives and lists in the Volume too), then runs the test chrooted in it,
  as root of a user namespace of its own. That copy is kept until the image or the list of
  tools changes. `KITH_OS_CACHE`, cargo's registry and its target folder are in the Volume, so
  the kernel builds once per node. Two things differ from a machine of your own: a pod's
  seccomp answers `FS_IOC_SETFLAGS` with "not permitted", which systemd-repart gives up on, so a
  small preloaded library answers "not supported" as tmpfs would; and tar runs with
  `--no-same-owner`, as the user namespace maps one uid only.
- **The split.** The tests are dealt to the nodes in turn, in the order given, and each node
  runs its own one at a time. One merged report names `FAILED: NODE: TEST` for each failure; a test
  that ci/vm.sh skips (no KVM, a tool missing) counts as failed, with its reason.
- **What runs there.** On a cluster of three nodes, 21 of the 29 tests pass: alone, image,
  update, modules, disk, rollout, install, vps, access, pods, poddns, nested, outlive, services,
  compose, quota, worker, chaos, home, policy and tunnel (from 30 s warm to 17 minutes for the
  first kernel and image a node builds). rollout gets the checkout's `kith` built first; kube
  goes by `sh ci/kube.sh --vm`, which fetches kubectl and helm. The rest, and why:
  - `init` skips: it boots the host's kernel, and a Job has none in /boot.
  - `netboot`, `crypt`, `tpm` and `duress`: the machine installed from the network starts
    again into the firmware's UEFI shell, not its disk. Debian's OVMF has a built-in shell,
    and that second start gives the disk no boot index.
  - `blackout`: the guests find no TPM event log
    (`/sys/kernel/security/tpm0/binary_bios_measurements`) with Debian's OVMF and swtpm, so
    no node seals its key.
  - `share` ("the Share mine does not say where it is") and `kube` ("the claim was refused")
    fail there, on more than one node, and are not explained yet.

Time budgets are medians of five runs on one machine, no VM. `python3 ci/budgets.py --times`
prints them; `python3 ci/budgets.py` holds each to twice the slowest of three medians on main on
the CI runner, rounded up: a ceiling for a regression, not a claim of speed. On a busy machine
each budget is multiplied by its 1-minute load over its CPU count (at least 1, measured once
before the timed runs), so a host shared with other builds does not fail on noise; the CI
runner is quiet, so it holds the budgets as written. A busy machine is also judged on the
fastest of the five runs, not their median (the line says so and prints the median beside it):
each hop waits for a CPU, which slows a run more than the load scales, and the fastest run
waited least, while a regression in kith slows every run. A line reads `ok one DNS answer from
kithd: 2.4 ms (budget 7.0 ms x 1.00 for load = 7.0 ms)`, or `FAIL` and exit 1; a path that
cannot run here (no cgroup of its own for a container, say) is a `FAIL` too, since it has a
budget.

| Time | On the CI runner: the median of five, on three runs on main | Budget |
|---|---|---|
| apply to a running container | 85.3, 88.1, 78.3 ms (before T-1207; not retaken since) | 160 ms |
| a status change reaching a second kithd | 4.7, 4.8, 4.8 ms | 10 ms |
| one DNS answer from kithd | 2.9, 3.1, 3.5 ms | 7 ms |
| boot to ready | 2.5 to 3.7 s to `kithd` answering, in a VM (`boot` in [ci/compare.txt](../../ci/compare.txt)) | not budgeted: no VM runs in CI |

Where the apply to a running container goes: `python3 ci/budgets.py --phases` starts a kithd with
`KITH_TIMELINE` set (off otherwise: no mark is written), applies a Workload whose image is on the
node 20 times, and prints the median of each phase, the time since the mark before it. Each mark
is a line `kith-timeline NAME NANOS` (CLOCK_MONOTONIC) on kithd's log. On the dev PC (16 CPUs,
load 6.4, the median of 20):

| Step | Time |
|---|---|
| the CLI and the request reaching the handler | 5.8 ms |
| store write (a raft commit, one fsync) | 7.7 ms |
| schedule (the controller wakes, begins the start) | 0.5 ms |
| the unit made ready, its image reference parsed (waits for the regex compile, below) | 28.4 ms |
| the image found on the node | 0.2 ms |
| runtime create: the bundle and spec written and synced (two fsyncs) | 10.4 ms |
| fork of the build helper | 0.4 ms |
| clone3, cgroup and mounts (libcontainer's build in the forked helper; its steps cannot be marked from outside, so one phase) | 15.1 ms |
| the parent collecting the helper, the container loaded, its cgroup set | 5.1 ms |
| start (the init process released) | 0.6 ms |
| its status committed (a second raft commit) | 7.8 ms |
| `kith get` polling (every 5 ms) seeing it | 0.6 ms |
| total | 83.6 ms (90.5 ms before T-1207, the same load) |

The largest phase is not the runtime's: oci-spec compiles a large regex at the first image
reference it parses, about 35 ms and 8 MB of heap, and a kithd paid it at its first start.
`kith_runtime::warm_reference` now parses one on a thread of its own when a Workload,
NodeWorkload or Job is applied, so the compile overlaps the store write; most of it is still
waited for. Parsing at start-up hid all of it (150 to 64 ms at load 29) but took kithd's idle
RSS from 5.4 to 16.2 MB, over its 9 MB budget, so it was not kept. What is left is mostly disk
and the kernel: four fsyncs (two raft commits, and two for the spec, which stay: a config.json
torn by a power cut gives no range to any container) and libcontainer's build. The goal is
under 20 ms on a quiet run; it was not reached or measurable here (the quietest load was 6). The
160 ms budget is twice the CI median expected after the change (about 81 ms, from the dev PC's
ratio, not three CI medians): retake three on main and tighten it (T-0269).

Release binaries are static musl builds: `ring` (C) needs `musl-tools` (Debian/Ubuntu) or
`CC_x86_64_unknown_linux_musl` set to a `zig cc -target x86_64-linux-musl` wrapper.

kithd is linked by the toolchain's own lld with the functions it runs from its start until it
has idled a while first, in the order `crates/kithd/kithd.order` lists. The kernel keeps the
pages around each one a process touches, so kithd idle held 10.50 MB without the order and 4.62
MB with it (`python3 ci/budgets.py`; budget 9.00 MB).

| | |
|---|---|
| **Measured** | Of the binary read from disk, as a node has it: `ci/budgets.py` drops the file's cache and reads it back before starting kithd, so the number is the same right after a build and an hour later. Right after a build, with the file in the page cache as the linker wrote it, the kernel maps fewer pages around each one touched: 8.75 MB without the order, 3.75 with it. On tmpfs the cache cannot be dropped, so the number is that of the file as it is there. The binary is 11.35 MB, as without the order. |
| **Writing it** | `python3 ci/order.py` (x86_64 Linux) writes the file from a run of the kithd it builds: a breakpoint on every function, taken off when first hit, so each one that runs is seen once, in order. Each name is a pattern without what an ordinary change alters: the letters Rust writes before each crate's name (`cargo update` or a new compiler changes them), an `impl`'s number in its module, and the number a copy of a function ends with. So the file outlives most changes, but code written since is not in it, and each start-up function left where the compiler put it keeps up to 64 kB around it in memory. `python3 ci/order.py --check`, which CI runs, fails once under 95 in 100 of its names are still in kithd, or under four fifths of those are together where its code starts. |
| **Toolchain** | The order is of the one compiler `rust-toolchain.toml` names (rustup installs it): Rust 1.100.0 gave a tenth of these functions other names, and kithd built with it held 5.96 MB, measured right after the build. After naming another, run `python3 ci/order.py` again. With no lld, kithd is linked in the compiler's order with a warning and holds 10.50 MB again (the check then fails, saying there is no lld). |
| **As init** | As the first process of kith OS, kithd does more before it serves (mounts, the state partition, DHCP), none of it in the order file, which is traced from a kithd that is not first and needs no root. What a node does in its first minute is traced: `ci/order.py` asks the traced kithd, on 127.0.0.1, for a TLS request on the node listener, a join token, an apply of a small Workload, a DNS answer and a write through Raft. It says on its console what it holds when told to stop (`kithd: init: told to stop: 10248 kB resident, 8996 kB of it files`), and the VM tests print it: `sh ci/vm.sh --test image`, from the image's own root after one TLS request, 9.3 MB, 8.0 of them files (three runs: 9564, 8924 and 9432 kB; 10.2 to 10.7 MB before the first minute was traced); `sh ci/vm.sh --test init`, from a memory disk and told to stop as soon as it serves, 6.4 MB, 5.4 of them files. No budget holds the VM's number (no VM runs in CI); the 9.00 MB budget is of the build machine's. |
| **Tried, not kept** | Telling the kernel the code is read at random (`MADV_RANDOM`) changed nothing (10.3 to 10.6 MB): the pages it maps around a fault are not read-ahead. Mapping one page a fault where it maps 64 kB (a setting of the whole node, which kith OS leaves) gave 7.7 MB, 5.4 of them code, so most of what kithd holds is code it ran, a page here and there, not the pages around it. Not tried: dropping the pages once it serves, which lowers the number until each is used again. These pages are the kernel's copy of a file, taken back when memory is short; what would lower them is that code linked together too, which the order file does not do yet. |

### Testing on several nodes

```sh
KITH_E2E=1 cargo test -q -p kithd --test cluster rig_   # 3 nodes: one behind a NAT, a partition, a heal
sh ci/vm.sh                                             # the host's kernel, booted with kithd as init
sh ci/vm.sh --test init                                 # and: it serves, then restarts when told
sh ci/vm.sh --test image                                # kith OS's image: UEFI, verity root, DHCP, state, tampering
sh ci/vm.sh --test update                               # and its two slots: an update, marked good; a broken one, gone back from
sh ci/vm.sh --test chaos                                # three nodes: each cut off in turn, each reset in turn, all reset at once, while writes go on
sh ci/vm.sh --test access                               # three nodes: a RoleBinding deleted while one is cut off; no write after it is kept
sh ci/vm.sh --test fido2                                # a test-build kithd's FIDO2 client against its software key (uhid, hidraw): the hmac-secret each seed says, a withheld touch timed out
sh ci/vm.sh --test pods                                 # two nodes: pods with a network, an address and a root each
sh ci/vm.sh --test quota                                # pods' storage limits held at the write, across a restart
sh ci/kube.sh                                           # the real kubectl and helm (fetched once, by hash) against kithd
sh ci/kube.sh --vm                                      # and against two nodes, where what they make runs (sh ci/vm.sh --test kube)
KITH_E2E=1 cargo test -q -p kithd init_dhcp             # an address from a real DHCP server (dnsmasq)
sh ci/vm.sh --help                                      # any kernel, initramfs and disk image
```

The `rig_` tests in `crates/kithd/tests/cluster.rs` run again inside `unshare -Urnm` (rootless),
each kithd in its own network namespace with a veth pair to the test's, the router. A node can
sit behind a NAT (SNAT out, only its API port forwarded in, TCP only), its link can be cut and
healed, and `tc netem` latency is added when the kernel has `sch_netem`. Without `KITH_E2E=1`,
user namespaces, `ip`, `iptables` or `nsenter`, a test prints `skipped: ...` and passes. The
edge relay (after 180 s of silence, `QUIET` in `crates/kithd/src/mesh.rs`) is not covered.

`ci/vm.sh`, the launcher the image, installer, update and cluster tests reuse, builds the static
kithd, makes an initramfs whose `/init` is it, boots the host's kernel with it under QEMU and
KVM, and prints the console. `--kernel`, `--initrd` and `--disk` take any other (a disk is
attached `-snapshot`, never written; a `/dev` path is refused). Without QEMU, KVM or a readable
kernel it prints `skipped: ...`, exit 0.
