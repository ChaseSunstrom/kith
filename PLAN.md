# kith — implementation plan

> **kith** *(n.)* one's close circle; the people you trust.
> A tiny, immutable operating system that turns all of your machines — desktops, home servers, cloud VPSs — into one cluster that is configured entirely through declarative resources.

---

## 1. Vision

kith is installed **as the OS** on every machine you own, or runs as an agent on machines where you can't replace the OS. Each node runs one small Rust supervisor, `kithd`, which is init, orchestrator, network mesh and API server at once. Together the nodes form a cluster that:

- is configured like Kubernetes, with **declarative YAML resources**, **templated packages** (Helm-style) and **custom resource kinds with their own controllers**;
- runs workloads (containers, processes, VMs, WASM) on whichever machine fits;
- connects every node over an encrypted, low-latency mesh, whether it's on the LAN or a VPS across the world;
- can give any node **native local hardware access** (display, input, GPU, audio). A desktop environment is just a package you choose to deploy, or don't;
- **manages and upgrades itself from inside the cluster**: OS updates, kithd updates, packages and config are all resources reconciled by the cluster;
- keeps the platform's footprint at **< 256 MB RAM per node (target: < 100 MB)** and the base OS image at **< 300 MB on disk**.

### Non-goals
- **No transparent pooling of CPU/RAM** across machines (single-system-image). Network latency makes remote RAM unusable as local RAM. kith makes it trivial to *place* work on the right machine and to *use* remote resources at the service level instead.
- **No built-in or default desktop environment.** The OS is headless. Desktops, shells, compositors and login managers are packages.
- **No host package manager.** All software runs as workloads.
- **Not wire-compatible with the Kubernetes API** in v1. kith resources look familiar, and the plan includes an import path for existing manifests and Helm charts (§4.8).

---

## 2. Core principles

1. **Everything is a resource.** Nodes, workloads, volumes, network policies, hardware seats, OS versions and the cluster itself are typed resources with `apiVersion`, `kind`, `metadata`, `spec` and `status`.
2. **Desired state + reconciliation.** Controllers continuously move actual state toward the declared spec. The CLI, web UI and any settings app only write resources; nothing changes state behind the API's back.
3. **Extensible.** Users and packages can add new kinds (like CRDs) along with controllers that implement them.
4. **Self-hosting.** The cluster deploys, configures and upgrades itself, including the OS beneath it.
5. **One binary per node.** `kithd` is PID 1 on kith OS, or a systemd service in agent mode.
6. **Immutable host, atomic updates.** Read-only root, A/B slots, automatic rollback.
7. **Masterless.** Any node can be a voter. A single node is a valid cluster.
8. **Fast and small.** No garbage collector, no etcd, no Docker/containerd daemons, no sidecars.
9. **Secure by default.** mTLS between nodes, an encrypted mesh, signed images, packages and OS updates, and least-privilege workloads.

---

## 3. Architecture

```
┌───────────────────────────── node ──────────────────────────────┐
│ Linux kernel (minimal config: cgroups v2, WireGuard, KVM, DRM)  │
│                                                                 │
│ kithd (PID 1, single static Rust binary)                        │
│  ├─ init          mounts, devices, reaping, shutdown            │
│  ├─ api           resource API (gRPC + HTTP/JSON), watch, RBAC  │
│  ├─ store         embedded Raft (openraft) + redb               │
│  ├─ members       SWIM gossip (foca), failure detection         │
│  ├─ mesh          WireGuard peers, NAT traversal, relay, DNS    │
│  ├─ scheduler     constraint + scoring placement                │
│  ├─ runtime       containers / processes / microVMs / WASM      │
│  ├─ devices       seats, GPUs, USB, device claims               │
│  ├─ storage       volumes, content-addressed blobs, sharing     │
│  ├─ controllers   built-in reconcilers (workloads, updates, …)  │
│  ├─ packages      template engine, package releases             │
│  └─ ui            embedded web dashboard (static assets)        │
│                                                                 │
│ workloads ... (each in its own cgroup)                          │
│ user controllers ... (workloads that watch the API)             │
└─────────────────────────────────────────────────────────────────┘
```

### 3.1 Node roles
Roles are set on the `Node` resource. A node can have any combination.
| Role | Meaning |
|---|---|
| `voter` | Takes part in Raft (1, 3 or 5 per cluster; a lightweight witness voter is also supported) |
| `worker` | Runs scheduled workloads (default) |
| `edge` | Has a public IP. Acts as a mesh relay and ingress (usually a VPS) |

There is no `desktop` role. Local hardware is exposed through **Seat** and **Device** resources (§4.6), and anything can claim it.

### 3.2 Memory budget (per node, steady state)
| Component | Target |
|---|---|
| kithd core (init, api, store, gossip, scheduler, controllers) | ≤ 30 MB |
| Mesh control (data path is kernel WireGuard) | ≤ 5 MB |
| Runtime overhead per container (no shim process) | ≤ 1 MB |
| Web UI (static, served by kithd) | ≤ 5 MB |
| Kernel + base userspace | ≤ 60 MB |
| **Total platform overhead** | **≤ 100 MB (hard cap 256 MB)** |

CI fails if the idle RSS of kithd exceeds 40 MB on a 3-node test cluster.

---

## 4. Components

### 4.1 Base OS image (`kith-os`)
- Reproducible build of a **minimal kernel + musl userspace**. Optional kernel modules (GPU drivers, ZFS, etc.) are signed **system extensions** layered on at boot, chosen per node in config.
- Partitions: `ESP` · `root-A` · `root-B` (read-only erofs + dm-verity) · `state` (config, Raft, volumes).
- Boot through a UKI (Unified Kernel Image) with Secure Boot support. Automatic rollback if the new slot fails its health check.
- **Installer:** bootable USB/ISO with a small TUI. Asks for the disk and hostname, then whether to create a new cluster or join one (token or QR code). An unattended install can read a YAML file from the USB stick or a URL.
- **VPS:** an in-place `kexec` installer, plus raw/qcow2 cloud images.
- **Agent mode:** the same `kithd` as a systemd service on an existing distro. Everything works except PID-1 duties and OS updates.

### 4.2 Resource model & config format
**YAML is the primary format.** JSON is accepted anywhere YAML is, because the API speaks JSON. Files can contain several documents separated by `---`.
To avoid YAML's well-known pitfalls, kith parses a **strict YAML subset**:
- no implicit type coercion (`no`, `on` and `1.0` are not silently turned into booleans or floats where the schema expects a string);
- no anchors across documents;
- duplicate keys are an error.

All values are validated against generated JSON Schemas, and errors report the file and line.

Every resource has the same shape:

```yaml
apiVersion: kith.dev/v1
kind: Workload
metadata:
  name: jellyfin
  namespace: media
  labels: { app: jellyfin }
spec:
  replicas: 1
  template:
    containers:
      - name: jellyfin
        image: docker.io/jellyfin/jellyfin:10
        resources: { cpu: "2", memory: 2Gi }
        ports: [{ name: http, port: 8096 }]
        volumeMounts: [{ volume: media, path: /media }]
  placement:
    require: { node.labels.disks: hdd }
    prefer:  [{ weight: 50, node.labels.room: closet }]
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: jellyfin, namespace: media }
spec:
  selector: { app: jellyfin }
  ports: [{ name: http, port: 80, targetPort: http }]
  expose: { host: media.example.com, via: edge }   # public HTTPS through an edge node
```

**Built-in kinds (v1):**
| Kind | Purpose |
|---|---|
| `Cluster` | Cluster-wide settings: domain, voter set, update policy, mesh settings |
| `Node` | One machine: roles, labels, taints, OS version, system extensions, resource reservations |
| `Namespace` | Grouping, quotas, default policies |
| `Workload` | Long-running replicas. Strategy: rolling, recreate or blue/green. Kind of unit: container, exec, vm or wasm. |
| `NodeWorkload` | Runs on every node matching a selector (like a DaemonSet) |
| `Job` / `CronJob` | Run-to-completion and scheduled tasks |
| `Service` | Stable name, load balancing and optional public exposure |
| `NetworkPolicy` | Allow/deny traffic between workloads, namespaces and nodes |
| `Volume` / `VolumeClaim` | Local, shared-over-mesh or backed-up storage |
| `Secret` / `ConfigMap` | Configuration and secrets, delivered as files or env vars |
| `Seat` / `Device` / `DeviceClaim` | Local hardware access (§4.6) |
| `Package` / `Release` / `Repository` | Templated packages (§4.8) |
| `Source` | GitOps: sync resources from a git repo or OCI artifact (§4.9) |
| `OSRelease` / `UpdatePlan` | OS and kithd self-updates (§4.9) |
| `KindDefinition` | Define a new resource kind (§4.10) |
| `Role` / `RoleBinding` / `Identity` | Access control |

Every change to a resource is stored as a revision, so you can run `kith history <kind>/<name>` and `kith rollback <kind>/<name> --to N`.

### 4.3 State, API & membership
- **Store:** `openraft` + `redb`, holding all resources and their revisions. Secrets are encrypted at rest with the cluster key.
- **API:** CRUD, server-side apply (field ownership, like Kubernetes), **watch streams** (the basis for all controllers and the UI), admission validation, RBAC. Served as gRPC plus an HTTP/JSON gateway over mTLS.
- **Gossip:** `foca` (SWIM) for liveness and live metrics. Metrics never go into Raft.
- 1-node and 2-node clusters are supported, with clear warnings about what they can and can't survive.

### 4.4 Mesh networking
- **Kernel WireGuard**, configured over netlink. Each node and each workload gets a stable mesh address (IPv6 ULA, IPv4 optional).
- **NAT traversal:** endpoint discovery through gossip and UDP hole punching, falling back to relaying through `edge` nodes.
- **Same-LAN detection** sends traffic directly over the local network. Target: ≤ 0.3 ms added latency on a LAN.
- **DNS:** `<service>.<namespace>.kith`, `<node>.node.kith`.
- **Load balancing and NetworkPolicy** are enforced with eBPF (`aya`), with nftables as a fallback.
- **Ingress:** ACME TLS on edge nodes, forwarded over the mesh.

### 4.5 Workload runtime
| Unit | Implementation |
|---|---|
| `container` | Built-in OCI image pulling into a content-addressed store. Runs through `youki` used as a library (cgroups v2 + namespaces). No containerd, no shim process. |
| `exec` | Plain supervised process in a cgroup (for host-level tools) |
| `vm` | `cloud-hypervisor` / Firecracker microVMs. QEMU/KVM with VFIO passthrough for full VMs (e.g. a Windows VM with a GPU) |
| `wasm` | `wasmtime`, feature-gated |

Health and readiness probes, restart policies, rolling updates, resource limits, priority classes and preemption are all set on the resource. Logs go into a ring buffer per workload and can be streamed from anywhere in the cluster.

### 4.6 Hardware access: Seats & Devices
This is how a machine gets a **native, local desktop (or kiosk, game console, media centre…) without kith forcing one**.

- `Device`: discovered automatically per node (GPUs, DRM cards, input devices, audio, USB, cameras), with labels such as `vendor`, `model` and `vram`.
- `Seat`: a named group of local display + input + audio devices on a node (multi-seat support comes for free).
- `DeviceClaim`: a workload claims a seat or a device, either exclusively or shared. kithd grants the device nodes, cgroup device permissions and udev forwarding.
- **Resource guarantees:** a workload holding a seat can be given a reserved CPU/memory/IO slice and the highest priority, so cluster jobs can never make the local session stutter.
- **Activity signals:** the session can publish `seat.active` / `seat.idle` / `seat.fullscreen` to the API. Other workloads can use these in placement and throttling rules (e.g. "yield the GPU while the seat is fullscreen").

**Desktop environments are packages.** A seat on its own does nothing. The user deploys whatever they want into it: GNOME, KDE, Hyprland, niri, Sway, a single-app kiosk, Steam Big Picture, or nothing at all. Example:

```yaml
apiVersion: kith.dev/v1
kind: Release
metadata: { name: workstation, namespace: desktop }
spec:
  package: { repo: kith-community, name: hyprland, version: ^1.2 }
  values:
    seat: office-pc/seat0
    user: casun
    reserve: { cpu: "4", memory: 8Gi }
    apps: [firefox, code, steam]
    dotfiles: { git: https://github.com/me/dotfiles }
```

The session runs at native speed: the compositor talks to DRM/KMS and the GPU directly, and nothing is streamed or virtualised.

**Using other machines from a session.** These are ordinary kith features, available to any workload:
- `kith run --on <node|selector> -- <app>`: start a remote GUI app that appears as a local window (through `waypipe` over the mesh);
- send jobs to other nodes, and reach remote GPU-backed services by DNS name;
- mount shared volumes into the session (e.g. under `~/kith/<volume>`);
- an optional `kith-panel` package (tray/launcher integration) for whichever environment you choose.

### 4.7 Scheduler
- Pipeline: filter (requirements, taints, device availability, quotas) → score (configurable plugins: bin-pack, spread, affinity, latency to dependencies) → bind through Raft.
- Supports priority classes, preemption, topology spread and anti-affinity.
- Conditions based on seat activity (§4.6) and time windows let work fit around people using the machines.
- Rescheduling after node failure waits for a configurable grace period, so a reboot doesn't cause churn.
- **Pluggable:** extra filter/score plugins can be WASM modules referenced from the `Cluster` resource.

### 4.8 Packages (Helm-style)
- A **package** is a versioned bundle containing:
  - `package.yaml` (metadata, dependencies, required kith version);
  - `values.yaml` (defaults) plus `values.schema.json`;
  - `templates/` (resource templates);
  - an optional `README` and `NOTES`.
- **Templating:** `minijinja` (Jinja2 syntax, sandboxed, fast). It provides helpers for names and labels, `toYaml`, `required`, `lookup` (read-only access to existing resources), includes and partials.
- **Releases** are resources (`kind: Release`). kithd renders the templates in the cluster, diffs the result against what's running, applies it, tracks which resources belong to the release, prunes resources that are no longer rendered, and keeps release history for rollback. Hooks run as `Job`s (pre/post install, upgrade, delete).
- **Distribution:** packages are signed OCI artifacts in any OCI registry. A `Repository` resource points at one. A small community index ships with the project.
- **Layered values:** package defaults → cluster-wide values → namespace values → release values → per-node overrides.
- **Kubernetes/Helm import:** `kith import helm <chart>` and `kith import k8s <manifests>` translate the supported Kubernetes kinds (Deployment, StatefulSet, DaemonSet, Service, ConfigMap, Secret, PVC, Job, CronJob, Ingress) into kith resources, and report anything they can't translate.
- Packages can depend on other packages and can include `KindDefinition`s and their controllers (operators).

### 4.9 Self-management: deploy & update from inside the cluster
The cluster runs itself through its own resources.
- **GitOps (`Source`):** points at a git repo or OCI artifact plus a path. A built-in controller syncs it continuously. Options: auto or manual approval, pruning, drift detection and alerts, signed-commit verification.
- **Operator workflow:** edit YAML locally → `kith diff` → `kith apply`, or push to git and let the `Source` reconcile. The web UI uses the same API, shows the diff and asks for confirmation.
- **OS and kithd updates (`OSRelease` + `UpdatePlan`):**
  - `OSRelease` names a signed image version.
  - `UpdatePlan` picks the nodes (by selector) and the strategy:
    - how many nodes at a time;
    - maintenance windows;
    - drain behaviour;
    - whether to hold back nodes with an active seat until they're idle.
  - Rollout per node: drain → write the inactive A/B slot → reboot → health check → mark good, or roll back automatically and pause the plan.
  - Raft voters are upgraded one at a time to keep quorum.
- **Package updates:** a `Release` can follow a semver range and auto-upgrade, with the same window and approval controls.
- **Building in the cluster (optional package):** a `kith-build` package provides rootless OCI image builds and a local registry, so the cluster can build and deploy its own images, including custom kith OS images, entirely inside itself.
- **Bootstrapping:** the first node's installer can take a `Source` URL. The new cluster then pulls its entire configuration from git on first boot.

### 4.10 Extensibility: custom kinds & controllers
- `KindDefinition` registers a new kind: its group, version, schema, printer columns and validation rules.
- **Controllers** are ordinary workloads that use the watch API, with Rust and Go client libraries. Small ones can run as **WASM controllers inside kithd's sandbox**, with no separate process and very little memory.
- **Admission hooks** (validate or mutate) can also be WASM modules.
- Examples:
  - a `Backup` kind;
  - a `GameServer` kind;
  - a `DesktopProfile` kind that a desktop package uses to manage dotfiles and apps.

### 4.11 Storage
- **Volumes:** a local path or a btrfs subvolume on a node.
- **Shared volumes:** exported over the mesh (NFSv4 over WireGuard to start, virtiofs for VMs) and mountable on any node.
- **Blob store:** content-addressed (BLAKE3) and deduplicated across nodes. Holds images, packages, revisions and backups.
- **Snapshots and backups:** btrfs snapshots, plus `Backup` resources targeting S3-compatible storage or another node.
- Storage drivers are pluggable (CSI-like interface) for later integrations such as ZFS, Ceph or SeaweedFS.

### 4.12 Interfaces
- **CLI `kith`:**
  - resources: `get`, `describe`, `apply`, `diff`, `delete`, `edit`, `history`, `rollback`, `logs`, `exec`, `port-forward`, `run --on`;
  - packages: `package` / `release` (`install`, `upgrade`, `template`, `lint`);
  - other: `import`, `node join|drain|cordon`, `update`, `backup`.
- **Web UI:** built into kithd and served at `https://<any-node>.node.kith`. Built with Leptos (WASM) or SolidJS, about 1 MB gzipped.
  - Forms are generated automatically from each kind's schema, including custom kinds.
  - The YAML editor validates as you type.
  - Every change shows a diff before it's applied.
  - Includes a package browser, release history, update plans and live logs and metrics.
  - Themeable and customisable (CSS variables, layout config, custom panels contributed by packages).
- **API:** stable and versioned, with generated OpenAPI and protobuf definitions. The CLI and UI use only the public API.

### 4.13 Security
- A cluster CA is created at init. Each node and identity gets a certificate. Joining uses a short-lived token or QR code.
- All control traffic uses mTLS over WireGuard. RBAC applies to every API call. Every write is recorded in an audit log.
- Secrets are encrypted in Raft and mounted as tmpfs files.
- OS images, packages, and optionally workload images (cosign) are signed and verified.
- Workloads get no Linux capabilities by default. Hardware access only comes through explicit `DeviceClaim`s.

### 4.14 Additions (2026-11-12)
Requested after the first draft. Each is placed in an existing phase; none changes Phase 0–1.

- **Redundancy.** Workloads already have `replicas` and topology spread (§4.7). Add replicated volumes: `Volume.spec.replicas: N` keeps N copies on different nodes and fails over with the workload. Edge nodes are redundant by running ingress on every `edge` node behind the same DNS name. *(Workloads: Phase 2. Volumes: Phase 7.)*
- **NAS.** A `Share` kind exports a volume to devices that are not kith nodes, over SMB and NFS on the LAN, with users mapped from `Identity`. It ships as an official package (the file server runs as a container), built on shared volumes (§4.11). *(Phase 7.)*
- **Network installs.** Any node can serve the installer to PCs on its LAN: proxy-DHCP + TFTP/HTTP boot (PXE and UEFI HTTP boot) into the same installer as the USB stick, with a join token baked in. `kith node netboot --on <node>` turns it on for a limited time; it is off by default. *(Phase 5.)*
- **Encryption controlled from other nodes.**
  - *Storage:* the `state` partition and any `Volume` with `encrypted: true` use dm-crypt. Keys are not kept on the node: at boot it asks the voters for them over the mesh (network-bound disk encryption), optionally sealed to the TPM as well.
  - *Remote lock:* `kith node lock <node>` makes the voters refuse the keys and tells the node to drop them and stop its workloads. A stolen or seized machine is unreadable; `kith node unlock` reverses it. `kith node wipe` destroys the keys for good.
  - *Processes:* workloads marked `confidential: true` run as microVMs with encrypted memory (AMD SEV-SNP / Intel TDX) where the hardware has it, and are refused elsewhere rather than silently run in the clear.
  *(Storage and lock: Phase 5 and 7. Confidential workloads: Phase 7, after microVMs.)*
- **DNS.** The mesh DNS server (§4.4) is native to kithd and grows into a general one: `DNSZone` and `DNSRecord` kinds for custom names, upstream forwarders, split-horizon answers, and optionally serving the LAN on port 53 so every device in the house uses it. Filtering resolvers (AdGuard Home, Pi-hole, Unbound) and full custom DNS servers run as packages and can be set as the upstream. *(Native: Phase 2. Packages: Phase 3.)*
- **Reverse proxy.** `Service.expose` with the built-in ingress (§4.4) stays the simple path. Caddy, Traefik and nginx are official packages for people who want their own proxy config; they claim ports 80/443 on a node through the ordinary `Service` mechanism. *(Phase 3.)*

### 4.15 Additions (2026-11-13)

- **A language of its own.** YAML stays the format, and every YAML file stays valid. Beside it, a file named `*.kith` works the same resources out: values with names, functions, `if`, lists and records built from others, and imports of files beside it. It is checked against the kinds' own schemas by the code that checks YAML (a mistake is refused at its line and column, with the path into the resource), reads nothing of the machine it runs on, and is held to a number of steps and a size, so kithd can evaluate a package's `templates/*.kith` from a registry. Packages may be written in it instead of in templates. `kith-lsp`, an optional program, serves editors (what is wrong, completion from the schemas, hover). No dependency is added for it: an existing language would outweigh the `kith` binary.


---

## 5. Tech stack

| Area | Choice |
|---|---|
| Language | Rust (stable), `#![forbid(unsafe_code)]` except the `sys` crates |
| Async | `tokio` (current-thread runtimes where possible, to save memory) |
| Store | `openraft`, `redb` |
| Gossip | `foca` |
| Networking | `rtnetlink`, WireGuard netlink, `hickory-dns`, `aya` (eBPF) |
| Containers | `youki` (libcontainer), `oci-spec`, `oci-client` |
| VMs | `cloud-hypervisor` / Firecracker, QEMU for passthrough |
| WASM | `wasmtime` (controllers, scheduler plugins, admission, workloads) |
| API | `tonic`, `axum`, `rustls` |
| Config | `serde`, a strict YAML parser (`saphyr`-based, or a vetted `serde_yaml` fork), `schemars` |
| Templating | `minijinja` |
| UI | Leptos or SolidJS, embedded with `rust-embed` |
| OS build | `mkosi` or a custom Rust builder, erofs, dm-verity, UKI, system extensions |
| Zig | Optional, only for tiny static helpers if it helps. Not required. |

Build settings: LTO, `panic=abort` and musl static linking. Size-critical crates use `opt-level="z"`. VMs, WASM workloads and the UI are feature-gated, so minimal nodes don't carry them.

---

## 6. Repository layout

```
kith/
├─ crates/
│  ├─ kithd/             # binary: wires everything together
│  ├─ kith-init/         # PID 1 duties
│  ├─ kith-api/          # resource types, schemas, server, watch, RBAC
│  ├─ kith-store/        # raft + redb + revisions
│  ├─ kith-yaml/         # strict YAML parsing with source positions
│  ├─ kith-members/      # gossip
│  ├─ kith-mesh/         # wireguard, NAT traversal, DNS, eBPF policy
│  ├─ kith-sched/        # scheduler + plugin host
│  ├─ kith-runtime/      # container / exec / vm / wasm
│  ├─ kith-devices/      # seats, devices, claims
│  ├─ kith-storage/      # volumes, blobs, sharing, backups
│  ├─ kith-packages/     # templating, releases, repositories, import
│  ├─ kith-lang/         # kith's own language (.kith), and kith-lsp beside it
│  ├─ kith-controllers/  # built-in reconcilers (workloads, sources, updates…)
│  ├─ kith-client/       # Rust client library
│  └─ kith-cli/          # `kith` command
├─ sdk/                  # controller SDKs (Rust, Go), WASM plugin SDK
├─ ui/                   # web dashboard
├─ os/                   # image build, kernel config, sysexts, installer
├─ packages/             # official packages (desktops, panel, build, …)
├─ proto/
├─ docs/
└─ tests/                # integration + multi-node QEMU tests
```

---

## 7. Phases

Each phase ends with a demo, and its acceptance criteria must pass in CI before the next phase starts.

### Phase 0 — Foundations
- Workspace and CI (fmt, clippy, tests, binary-size and RSS budgets).
- `kith-yaml` strict parser.
- Core resource types and schema generation.
- In-memory API with apply/diff/revisions.
- ✅ `kith diff` and `kith apply` work against a local store. Bad YAML produces errors that point at the right file and line.

### Phase 1 — Single node, agent mode
- kithd as a systemd service.
- `Workload`, `Job`, `Service` and `ConfigMap`/`Secret` with containers and exec units.
- Probes, rolling updates, logs, watch API.
- ✅ 20 containers running. kithd idle RSS < 30 MB. Container start < 150 ms with a cached image.

### Phase 2 — Multi-node cluster & mesh
- Join, Raft, gossip, WireGuard mesh, DNS.
- Scheduler v1, `NodeWorkload`, failover, `NetworkPolicy`, ingress on edge nodes.
- ✅ 3 nodes (2 LAN + 1 VPS behind NAT) form a cluster. A workload is rescheduled after its node is killed. Mesh RTT on a LAN ≤ base RTT + 0.3 ms.

### Phase 3 — Packages & GitOps
- Packages, templating, `Release` lifecycle, OCI repositories, signing.
- `Source` sync, Helm/Kubernetes import.
- ✅ A multi-resource package installs, upgrades and rolls back. A git push changes what's running. A sample Helm chart imports with a translation report.

### Phase 4 — Extensibility & UI
- `KindDefinition`, controller SDK, WASM controllers and admission, RBAC, audit log.
- Web UI with schema-driven forms and diff-before-apply.
- ✅ A custom kind and its WASM controller work end to end. Every UI action is a normal API write.

### Phase 5 — kith OS & self-updates
- Minimal image, A/B updates, UKI, system extensions, installer (interactive and unattended), kexec VPS install, kithd as PID 1.
- `OSRelease` / `UpdatePlan` rolling upgrades.
- ✅ Bare-metal install from USB. A cluster-wide OS update rolls through every node with automatic rollback on a failed health check. Image < 300 MB. Boot to ready < 10 s on NVMe.

### Phase 6 — Hardware access & desktop packages
- Device discovery, `Seat` and `DeviceClaim`, reserved slices, seat activity signals.
- `kith run --on` (waypipe).
- Official example packages for a few environments (e.g. Hyprland, GNOME, a kiosk) and `kith-panel`.
- ✅ A desktop package deployed from YAML runs within 2% of a stock distro on a GPU benchmark, while other nodes run 10+ workloads. A node with no desktop package stays headless. A remote app opens as a local window.

### Phase 7 — Storage, VMs, in-cluster builds
- Shared volumes, blob store, backups.
- microVMs and VFIO passthrough VMs.
- `kith-build` package.
- ✅ A shared volume is mounted across nodes. A GPU-passthrough VM is defined in YAML and boots. The cluster builds and deploys one of its own images.

### Phase 8 — Hardening & 1.0
- Security review, chaos tests (partitions, power loss), upgrade-compatibility guarantees, documentation, a stable API version.

---

## 8. Testing strategy
- **Unit and property tests:**
  - YAML parsing;
  - apply/merge/field ownership;
  - template rendering;
  - the scheduler.
- **Golden tests** for packages: rendered output is compared to snapshots.
- **Multi-node integration tests** in QEMU (3–5 nodes) with simulated NAT, latency and partitions (`tc netem`).
- **Budgets enforced in CI:** binary size, idle RSS, container start time, boot time, mesh latency.
- **Hardware matrix** for seats and GPUs: AMD, Intel and NVIDIA.

---

## 9. Key risks & mitigations
| Risk | Mitigation |
|---|---|
| YAML ambiguity and user mistakes | Strict parser, schema validation, errors with line numbers, `kith lint` |
| Template complexity (Helm's main pain point) | Typed values schemas, `required`, sandboxed engine, `kith package template` for local preview, golden tests |
| NVIDIA and other out-of-tree drivers on an immutable OS | Signed system extensions built for each OS release |
| Breaking the cluster with a bad self-update | Upgrade one voter at a time, health-gated rollout, automatic A/B rollback, pause on failure |
| NAT traversal edge cases | Always keep a relay path through edge nodes |
| Scope creep | Agent mode (Phases 0–4) is useful before kith OS exists. Every phase ships usable software. |

---

## 10. First tasks for the implementer
1. Create the workspace and CI with RSS and binary-size budget checks from the start.
2. Build `kith-yaml`: a strict YAML subset parsed into typed values, keeping source positions for errors.
3. Build `kith-api`: the resource envelope, the built-in kinds, JSON Schema generation, apply/diff and revision history in an in-memory store.
4. Build `kith-runtime` for containers only: run one OCI image in a cgroup without containerd.
5. Wire up `kithd` agent mode with `kith apply` / `diff` / `get` for a single node, then start Phase 2.

---

## 11. Brand
- **Name:** `kith`, always lower case.
- **Logo:** `logo.svg` (icon) and `logo-wordmark.svg`. A lowercase "k" drawn as a small network: three nodes connected through a central hub.
- **Colours:** ink `#16181d`, accent `#5b8cff`, paper `#f6f5f1`.
