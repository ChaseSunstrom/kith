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
| `examples/` | Resources to apply as they are |
| `ci/` | The budgets, the benchmark, the VM tests (`vm.sh`), and what measures and photographs the website (`site_numbers.py`, `site_shots.py`) |
| `dist/` | A systemd user unit for agent mode |
| `docs/` | The website (GitHub Pages serves this folder: `index.html`, `site.css`, `site.js`, its numbers and typeface), the pictures this file shows, and `adr-workers.md`, the design for worker nodes that is not built yet |

## Development

```sh
cargo test --workspace
KITH_E2E=1 cargo test -p kithd -p kith-runtime --test e2e   # pulls an image and runs containers
cargo clippy --workspace --all-targets -- -D warnings
rustup target add wasm32-unknown-unknown   # once: without it the WASM end-to-end tests skip themselves
python3 ci/budgets.py            # binary-size and memory budgets, enforced in CI
python3 ci/bench.py              # the plan's numbers for one node: cached start < 150 ms, 20+ containers under 30 MB of kithd
```

Time budgets sit beside the size and memory ones. Three times are measured on one
machine with no VM: `kith apply` until a container of a local image runs, a status
change written on one of two kithds until the other has it, and one DNS answer from
kithd. Each time is the median of five runs: `python3 ci/budgets.py --times` prints
them, and the build's `python3 ci/budgets.py` holds each to its budget. Each budget is
twice the slowest of three such medians on main on the CI runner, rounded up: a ceiling for a
regression, not a claim of speed. Each is printed as `ok   one DNS answer from kithd:
2.4 ms (budget 7.0 ms)`, or `FAIL` and exit 1. A machine where a path cannot be run (no
cgroup of its own for a container, say) fails that path, since it has a budget.

| Time | On the CI runner: the median of five, on three runs on main | Budget |
|---|---|---|
| apply to a running container | 85.3, 88.1, 78.3 ms | 180 ms |
| a status change reaching a second kithd | 4.7, 4.8, 4.8 ms | 10 ms |
| one DNS answer from kithd | 2.9, 3.1, 3.5 ms | 7 ms |
| boot to ready | 2.5 to 3.7 s to `kithd` answering, in a VM (`boot` in [ci/compare.txt](../../ci/compare.txt)) | not budgeted: no VM runs in CI |

Release binaries are static musl builds. `kith-runtime` pulls in `ring`, which
has C in it, so linking it for musl needs a musl C compiler: `musl-tools` on
Debian/Ubuntu, or point `CC_x86_64_unknown_linux_musl` at a `zig cc -target
x86_64-linux-musl` wrapper.

kithd is linked by the Rust toolchain's own lld, with the functions it runs from its
start until it has idled a while first in its code, in the order
`crates/kithd/kithd.order` lists them. The kernel keeps in memory the pages around each
one a process touches: with that code where the compiler put it, all over the binary,
kithd with nothing to do held 10.50 MB without the order and 4.62 MB with it
(`python3 ci/budgets.py`; the budget stays 9.00 MB). Those are of the binary read from
disk, as a node has it: `ci/budgets.py` drops the file's cache and reads it back before it
starts kithd, so the number is the same right after a build and an hour later. Right
after a build, with the file in the page cache as the linker wrote it, the kernel maps
fewer pages around each one touched, and kithd held 8.75 MB without the order and 3.75 MB
with it (an earlier version of this paragraph told those: 8.91 and 3.81). On tmpfs the
cache cannot be dropped and the number is that of the file as it is there. The binary is
11.35 MB, as it was without the order. `python3 ci/order.py` writes the file again from a run of the kithd it
builds: a breakpoint on every function, taken off the first time it is hit, so each one
that runs is seen once and in order (x86_64 Linux). The file holds each name as a
pattern, without what an ordinary change gives another value: the letters Rust writes
before each crate's name (a `cargo update` or a new compiler changes them), the number
of an `impl` in its module (one more for every `impl` written above it) and the number
the compiler ends a copy of a function with. So the file outlives most changes; code
written since is not in it, and each function kithd runs at start that is left where
the compiler put it keeps up to 64 kB around it in memory. `python3 ci/order.py
--check`, which CI runs, fails once under 95 in 100 of its names are still in kithd,
or under four fifths of those are together where its code starts. The order is of
one compiler, the one `rust-toolchain.toml` names (rustup installs it by itself):
Rust 1.100.0 gave a tenth of these functions other names, and kithd built with it held
5.96 MB (measured right after the build). After naming another there, run `python3
ci/order.py` again. A toolchain with no lld links kithd in the compiler's order, with a
warning, and it holds the 10.50 MB again (the check then fails, saying there is no lld).

That number is of a kithd with nothing to do on the machine that built it. As the first
process of kith OS it does more before it serves (its mounts, the state partition, DHCP,
its node's TLS), and none of that code is in the order file, which is traced from a kithd
that is not the first process. kithd as the first process says on its console what it
holds when it is told to stop (`kithd: init: told to stop: 10248 kB resident, 8996 kB of
it files`), and the VM tests print it: `sh ci/vm.sh --test image`, from the image's own
root after one TLS request, 10.2 MB, 9.0 of them files, which is its own program (7.7 MB
of its 9.8 MB of code); `sh ci/vm.sh --test init`, from a memory disk and told to stop as
soon as it serves, 6.4 MB, 5.4 of them files. Tried in that VM, and not kept: telling the
kernel the code is read at random (`MADV_RANDOM`) changed nothing (10.3 to 10.6 MB: the
pages the kernel maps around a fault are not read-ahead); with the kernel mapping one
page a fault where it maps 64 kB (a setting of the whole node, which kith OS leaves as it
is) kithd held 7.7 MB, 5.4 of them code, so most of what it holds is code it ran, a page
here and a page there, and not the pages around it. (Not tried: dropping the pages once
it serves, which lowers the number until each is used again.) What would lower it is that code linked together
too, which the order file does not do yet. These pages are the kernel's copy of a file:
it takes them back when memory is short. No budget holds the VM's number (no VM runs in
CI); the 9.00 MB budget is of the build machine's.

### Testing on several nodes

```sh
KITH_E2E=1 cargo test -q -p kithd --test cluster rig_   # 3 nodes: one behind a NAT, a partition, a heal
sh ci/vm.sh                                             # the host's kernel, booted with kithd as init
sh ci/vm.sh --test init                                 # and: it serves, then restarts when told
sh ci/vm.sh --test image                                # kith OS's image: UEFI, verity root, DHCP, state, tampering
sh ci/vm.sh --test update                               # and its two slots: an update, marked good; a broken one, gone back from
sh ci/vm.sh --test chaos                                # three nodes: each cut off in turn, each reset in turn, all reset at once, while writes go on
sh ci/vm.sh --test access                               # three nodes: a RoleBinding deleted while one is cut off; no write after it is kept
sh ci/vm.sh --test pods                                 # two nodes: pods with a network, an address and a root each
sh ci/vm.sh --test quota                                # pods' storage limits held at the write, across a restart
sh ci/kube.sh                                           # the real kubectl and helm (fetched once, by hash) against kithd
sh ci/kube.sh --vm                                      # and against two nodes, where what they make runs (sh ci/vm.sh --test kube)
KITH_E2E=1 cargo test -q -p kithd init_dhcp             # an address from a real DHCP server (dnsmasq)
sh ci/vm.sh --help                                      # any kernel, initramfs and disk image
```

The `rig_` tests in `crates/kithd/tests/cluster.rs` run the test again inside
`unshare -Urnm` (rootless; nothing outside it changes) and put each kithd in its own
network namespace, a veth pair to the test's own namespace, which is the router.
A node can sit behind a NAT (SNAT out, and only its API port forwarded in, TCP
only, so UDP and every other inbound connection are dropped like a home router
would), a node's link can be cut and healed, and `tc netem` latency is added when
the kernel has `sch_netem`. Without `KITH_E2E=1`, user namespaces, `ip`,
`iptables` or `nsenter`, a test prints `skipped: ...` and passes; without netem
it prints `skipped: no netem` and goes on without the latency. The relay through an
edge node is not covered here: kithd falls back to it only after 180 s of
silence (`QUIET` in `crates/kithd/src/mesh.rs`), and `kith-mesh` has unit tests
for the choice.

`ci/vm.sh` is the launcher the image, installer, update and cluster tests reuse. It
builds the static kithd, makes an initramfs whose `/init` is that kithd, boots the
host's kernel with it under QEMU and KVM, and prints the console. `--kernel`,
`--initrd` and `--disk` take any other; a disk image is attached with `-snapshot`
(it is never written, and a `/dev` path is refused). Where there is no QEMU, KVM or
readable kernel it prints `skipped: ...` and exits 0.
