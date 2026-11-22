# What kithd does today

kithd keeps the store and runs what the resources say: containers, host processes, Jobs and
CronJobs. `kith` talks to it over a unix socket only you can open. A second kithd on one state
directory is refused.

| Setting | Flag, env | Default |
|---|---|---|
| Socket | `--socket`, `KITH_SOCKET` | `$XDG_RUNTIME_DIR/kith/kithd.sock` |
| State directory | `--state`, `KITH_STATE` | `~/.local/state/kith/raft` |
| How long `kith` waits (a change that timed out may still have been applied) | `--timeout`, `KITH_TIMEOUT` (s) | 30 |
| How long an unused image is kept | `--image-grace` (s) | a day |
| State disk kept free | `--storage-reserve` (bytes) | as root: 5% of the disk, at most 1 GiB; else 0 |
| Log file size before it is moved aside | `--log-cap` (bytes) | 10 MiB |

- **The store** is a log synced to disk before a change is answered, plus a snapshot now and then:
  the store a cluster uses, with this node as its only member. `kith --store FILE` edits a plain
  file with no daemon, for trying things out.
- **Containers.** Each `Workload` container runs in its own cgroup with youki's `libcontainer`
  linked in: no containerd, no shim, no root. Memory and CPU limits, `resources.storage`
  ([below](#a-replica-as-a-pod)), `command`/`args` and `env` from values, `ConfigMap`s and
  `Secret`s are honoured. A container that exits is restarted per `restartPolicy`, after a wait
  that doubles from a second to a minute. **Exec units** are plain processes of the host (its
  files, network, your user) with the same cgroup, limits and restart policy.
- **Jobs.** A `Job` runs `completions` runs of its template, `parallelism` at a time (1). A failed
  run is tried again after a backoff; `retries` failures are forgiven (3), one more fails the Job,
  and so does passing `timeoutSeconds`. `kith get job` shows `running`, `succeeded` or
  `failed: <why>`. A finished Job runs again only when you change it.
- **Logs.** `kith logs KIND/NAME` prints a unit's output; `--unit`, `--replica`, `--stderr`,
  `--tail LINES`, `--previous` (the one old copy) and `-f` narrow it. Deleting the Workload or Job
  deletes its logs.
- **Probes.** `readiness` decides whether a replica counts as ready. A `liveness` probe that fails
  `failureThreshold` times in a row (3) restarts the container. `tcp` and `http` probes go to
  `localhost` every `intervalSeconds` (10), and once a second until the first success. A liveness
  probe's `startSeconds` (0, none) is how long a container may take to pass its first check: after
  it, a failure counts like any other. (Kubernetes' `initialDelaySeconds` on a liveness probe is
  imported as `startSeconds`; on a readiness probe it is said and left out.) An `exec` probe runs
  its command in the container's own namespaces, as `kubectl exec` does, with the same interval
  and thresholds: exit 0 passes, anything else fails, and a command that outlasts
  `timeoutSeconds` (1) is killed and fails. A container whose only probe is `exec` readiness is
  not ready (and a rolling update does not move on, nor `kubectl rollout status` return) until
  the command has passed once. Its output is not read: keep it small.
- **Updates.** A changed Workload (or a changed `ConfigMap` or `Secret` value in a unit's `env`) is
  replaced one replica at a time, the next once the others are ready: an update that does not come
  up stops at its first replica and the status says where. `strategy: recreate` replaces all at once.
  A rolling update surges: the replacement starts beside the old replica, and the old one stops
  only after the new one is ready (and its Service address has moved, 3 seconds), so a
  `replicas: 1` Workload behind a Service is never without a ready replica. A replica that holds
  one of something (a volume, a claimed device, the node's network, or a second copy's worth of
  CPU or memory the node does not have) stops first instead, and the status says why
  ([Rolling updates](cluster.md#rolling-updates): a replacement that does not come up, a kithd restarted in the middle).
- **Shutdown.** On SIGTERM kithd stops what it started, answering requests for 3 seconds at most.
  A second signal ends it at once and its next start stops what was left.

### Images

Images are pulled into a content-addressed store. One already pulled starts without asking the
registry, so `pullPolicy: always` is how you follow a tag that moves. A file several unpacked
images hold alike is one file on the node, hard-linked into each: three nginx images of one Alpine
base took 44% less disk. An image no unit uses is removed (kithd's log says so), with its layers
no other image has.

- **When.** After `--image-grace` seconds unused; or, while the state disk is under
  `--storage-reserve`, oldest first, after two minutes. kithd looks once a minute.
- **What stays.** An image a unit has a slot for or a container is made from, and every image
  while a pull is under way. Time between a Job's or CronJob's runs counts as unused.
- **After removal** the image is pulled again when a unit needs it (`pullPolicy: never` fails).
  A node off its network (a laptop) wants `--image-grace 0`, which keeps every image.

#### An image from a Nix closure

A node has no Nix, and needs none: build the image elsewhere with one layer for each store
path (nixpkgs' `dockerTools.buildLayeredImage`, as in
[examples/nix-images.nix](../../examples/nix-images.nix)), push it to a registry, and name it
in a template like any other image.

```sh
nix-build examples/nix-images.nix -A hello -o hello.tar
docker load -i hello.tar && docker tag hello:1 registry.example/hello:1
docker push registry.example/hello:1
```

```yaml
apiVersion: kith.dev/v1
kind: Job
metadata: { name: hello }
spec:
  template:
    containers: [{ name: run, image: "registry.example/hello:1" }]
```

Two such images share the layers of the store paths they share. The example's two, pulled by
one node: `hello` has 6 layers and `figlet` 7, 4 of them the same (glibc, libgcc, libidn2,
libunistring), so the node keeps 9 layers; unpacked, `hello` alone is 33 MB, `figlet` 42 MB,
and both together 42 MB. A layer's entries are named from `/` (`/nix/store/…`) and land in
the image's root, as Docker takes them.

### CronJobs

At each minute its `schedule` names (cron's five fields, or `@hourly` and the like; UTC), the node
that leads makes a Job of the CronJob's `job`, called `<name>-<minute>`. Whoever applies a CronJob
must be allowed to apply a Job.

| Field | Meaning |
|---|---|
| `concurrency: forbid` / `replace` | Wait for a Job still running / remove it first. |
| `successfulJobsHistoryLimit`, `failedJobsHistoryLimit` | Finished Jobs kept (3 each); all go with the CronJob. |
| `startingDeadlineSeconds` | Run, once, the latest minute missed since `status.last` no older than this (a week at most). Without it a missed minute is skipped. |
| `timezone` not `UTC`, a schedule that cannot be read, a name over 54 characters | The CronJob does not run, and its status says why. |

### Idle work

A template that says `priority: idle` (a Workload's, a Job's or a CronJob's `job`; `normal` is the
default and changes nothing) runs on what the node does not use. Each of its units gets:

| File of its cgroup | Value | Effect |
|---|---|---|
| `cpu.idle` | `1` | The kernel's idle scheduling for the whole unit: it runs only on CPU nothing else wants. |
| `io.weight` | `default 1` | The lowest disk weight. |
| `memory.high` | the unit's `resources.memory`, if it states one | Its memory is reclaimed first; without an amount none is set. |

```yaml
apiVersion: kith.dev/v1
kind: Job
metadata: { name: build-all }
spec:
  parallelism: 8                 # eight at a time, all on the one node the Job runs on
  completions: 64
  template:
    priority: idle               # only spare cycles beside whatever else runs there
    containers:
      - name: build
        image: registry.example/ci/build:1
        resources: { memory: 2Gi }
```

- Nothing is made idle unless it says so: a Job or a Workload without `priority` runs as before.
  A value other than `normal` or `idle` is refused (422).
- Beside a seat's desktop, idle work takes what the desktop leaves and no more. The seat's
  `reserve` still comes off the node, and `yieldTo` still holds a unit to a twentieth of a CPU
  while the seat is busy: `priority: idle` goes under both (see
  [what a seat keeps for itself](hardware.md#what-a-seat-keeps-for-itself)). A unit that is both
  idle and held by a seat keeps the lowest weights.
- Changing `priority` replaces the replica (its cgroup is made again), as changing its image does.
- To run batch work across the cluster beside people's desktops, give it `priority: idle` and a
  `resources.memory`, and no `yieldTo` is needed. A Job runs on one node, so spread the work over
  several Jobs (one per slice of it), or run it as a Workload with `replicas`, which the leader
  spreads over the nodes with room. Idle is not preemption: the scheduler places it as any unit
  and nothing is evicted for a busier one.

### Not yet

- A container's `ports` only name them for probes and Services; nothing is opened or mapped.
- A replica that holds a volume, a device or the node's network is stopped before its replacement
  starts, so `replicas: 1` of one is down for a moment during an update. `blueGreen` is treated as
  rolling. A readiness probe's `initialDelaySeconds` is not kept: kith asks at once.
- Pulls are anonymous; layers must be gzip or plain tar.
- [`dist/kithd.service`](../../dist/kithd.service) is a systemd user unit; `sh ci/systemd.sh` runs
  it under your user's systemd and checks its cgroups and its stop. In a Debian guest (systemd
  254 or newer, cgroup v2) install it as that user unit and run `loginctl enable-linger "$USER"`
  so it outlives a login. A root service on a distro is untested.

### What a container is kept from

Every container is started the same way, whatever it is for, with nothing to say:

```yaml
apiVersion: kith.dev/v1
kind: Workload
metadata:
  name: web
spec:
  template:
    containers:
      - name: web
        image: registry.example/shop/web:1
        signedBy:                  # run only if signed by one of these keys [whoever made it]
          - |
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERhDxn4VReZhiLBr2unWdvMY/ZNKC
            MGaYlOciQKQ+hYdtBvtUrt5fB1yFOSdyVJyZGQsBVEz8puMa+EcnvEXHIg==
            -----END PUBLIC KEY-----
        runAsUser: 1000            # [the image's User; 65534 if it names none, or root]
        seccomp:
          allow: [ptrace]          # refused calls it may make after all [none]
        userNamespaces: true       # it may start a sandbox of its own inside [false]
```

- **Who it is.** `runAsUser` (a number; the group the same), else the image's `User`, else nobody
  (65534). An image naming root gets nobody: only `runAsUser: 0` makes a container root.
- **Nothing more than that user.** No capabilities (on kith OS the one for ports below 1024 is
  kept) and `no_new_privs`, so a setuid program in the image is an ordinary program. Its image is
  read-only, with a tmpfs on `/tmp` and `/run`. Where kithd is root, a volume it mounts to write is
  given to its user: two workloads that write one volume should be one user.
- **Its users** depend on where it runs (its status says: `hostUsers: false` is a namespace of its
  own):

  | Where | Its users |
  |---|---|
  | kithd is your service | A user namespace where its user is the only one (its files are yours on the node); root is root of that namespace alone. |
  | kith OS, a pod's container ([a pod](#a-replica-as-a-pod)) | A namespace of its own: users 0 to 65535 are 65536 users of the node that no other container has, so `runAsUser: 0` is root of that namespace alone and 65536 or more is refused. Image and volumes are mounted id-mapped (Linux 5.12; a kernel or file system that refuses one fails the start). |
  | kith OS, the rest | The node's users: `runAsUser: 0` is the node's root with three capabilities (signals, ports below 1024, the audit log). That is a container on the node's network, one whose image or volume is on a file system without id-mapped mounts (ext4, xfs, btrfs and tmpfs have them; NFS does not), one given devices, and a NodeWorkload. |
- **A filter on its system calls** (seccomp) refuses the calls below and lets the rest through.
  `seccomp: { allow: [NAMES] }` lets some of them through again; `seccomp: { unconfined: true }`
  is no filter, and a 32-bit program on a 64-bit node needs it.

  | Kind | Calls |
  |---|---|
  | mounts | `mount`, `umount2`, `pivot_root`, `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`, `open_by_handle_at` |
  | namespaces | `unshare`, `setns`, `clone` when it makes a namespace, `clone3` |
  | machine and kernel | `init_module`, `finit_module`, `delete_module`, `kexec_load`, `kexec_file_load`, `reboot`, `swapon`, `swapoff`, `acct`, `settimeofday`, `clock_settime`, `bpf`, `perf_event_open`, `userfaultfd`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `add_key`, `request_key`, `keyctl` |
  | other processes | `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, `pidfd_getfd` |
- **A sandbox of its own inside** (Steam, Flatpak, browsers: bubblewrap) needs `userNamespaces:
  true`. It lets the namespace and mount calls through (not `open_by_handle_at`), leaves `/proc`
  and `/sys/firmware` uncovered, and on kith OS drops the capability for ports below 1024. The
  cost: inside a user namespace a program reaches kernel code a plain user never calls, where much
  of what has made a user the node's root was found. The node's root is not started with it.
- **Whose image it is.** With `signedBy`, the image runs only if one of those keys signed it, as
  `cosign sign --key` does: the signature (the tag `sha256-DIGEST.sig` in the image's repository)
  is checked against the manifest's digest before any layer is fetched. Keys are ECDSA P-256 or
  Ed25519: the `.pub` file's text, or the base64 in it. With no `signedBy` and no cluster rule
  (below), an image runs whoever made it.
- **Signed without a kept key** (`cosign sign IMAGE`): `signedBy` may name an identity instead.
  You give the roots you trust (for the public Sigstore instance, from `cosign trusted-root
  create`):

  ```yaml
  signedBy:
    - issuer: https://token.actions.githubusercontent.com
      subject: https://github.com/acme/tool/.github/workflows/release.yml@refs/heads/main
      authority: [ "-----BEGIN CERTIFICATE-----\n…", "-----BEGIN CERTIFICATE-----\n…" ]
      log: "-----BEGIN PUBLIC KEY-----\n…"
  ```

  The image runs only if a certificate from that authority names exactly that subject and issuer
  and was valid when the log (under its key) saw the signature. A signature in a log of Rekor v2
  (a time from a timestamp authority, no promise) is refused unless the identity also gives
  `tsa: [ "-----BEGIN CERTIFICATE-----\n…" ]`, the authority's root (1 to 4), whose RFC 3161
  timestamp then times it; with `tsa`, every signature of that identity needs the timestamp.
  What this proves and what it
  does not: [SECURITY.md](../../SECURITY.md#what-is-not-defended) and
  [docs/adr-keyless.md](../../docs/adr-keyless.md).
- **Keys named once, for the cluster.** A `Cluster`'s `spec.images` says which keys sign the
  images under a registry or a path of one, whatever a template says:

  ```yaml
  apiVersion: kith.dev/v1
  kind: Cluster
  metadata: { name: home }
  spec:
    images:
      - prefix: ghcr.io/acme        # ghcr.io/acme/tool, not ghcr.io/acmex
        signedBy: [MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=]
      - signedBy:                   # no prefix: every other image a node pulls
          - MCowBQYDK2VwAyEAPN3lqZV4Lw1d2sZ0c3gW5vQy8Tn6uJ7kR9xB1mD4hFA=
  ```

  An image is held to the rule with the longest prefix it is under (`nginx` is
  `docker.io/library/nginx`) and runs only if one of that rule's keys signed it. A template's own
  `signedBy` can then only narrow: a key both name must have signed. An image under no rule runs
  as before, so to cover every image give a rule with no prefix. A rule may name identities too.
  - Only someone with rights over the whole cluster can apply a `Cluster`. Every node must run a
    build that reads rules: an older one runs an image as before.
  - At most 32 rules, 16 keys each. A rule by mistake stops new containers under it from starting
    (the refusal names it); take it out of the `Cluster` to go back. `spec.images`, `spec.home`
    (the [house address](cluster.md#one-address-for-the-house)) and `spec.ntp` (the [time
    server](cluster.md#one-time-for-the-cluster)) are all kithd reads of a `Cluster` today;
    `kith lint`, `diff` and `apply` say so of its other fields.
- **What it still reaches.** The node's network, the kernel through every call the filter lets by,
  and the devices it claims (a GPU's render node is a wide door into a kernel driver). Untrusted
  programs belong in a VM ([Virtual machines](hardware.md#virtual-machines)), which is what a
  `vms` unit is for.
- **Not yet.** No AppArmor or SELinux profile. On kith OS, no user namespace for a container on
  the node's network, one given devices or one with a volume of another node. A call the kernel
  gains later is let through until it is named in the filter. A log of Rekor v2 is not read: its signatures are taken only by a timestamp (an identity's `tsa`). An
  `exec` unit is none of this: it is a process of the host.

### A replica as a pod

`pod: true` on a template runs each replica as Kubernetes runs a pod. A Deployment sent through
[the Kubernetes API](kubernetes.md#kubectl-and-helm-as-they-are) says it, and a kith file can too:

```yaml
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: web, labels: { app: web } }
spec:
  replicas: 3
  template:
    pod: true
    containers:
      - name: web
        image: nginx:1.27-alpine
        ports: [{ port: 80 }]
```

- **A network of its own.** The replica's containers share one: any port is theirs (three replicas
  on one node each listen on port 80), and `localhost` is each other. The replica has an address
  of its own, on the cluster's mesh where there is one (`--mesh`), so every node reaches it and
  Services send to it. Its DNS is this node's; outside names go to the node's resolvers, so the
  node needs one in `/etc/resolv.conf` or `--dns-upstream`.
- **Its address range** is `100.88.0.0/16` unless the node's kithd is given another (when its own
  network or tailnet is in it) with `--pod-range ADDRESS/BITS` or `KITH_POD_RANGE`; on kith OS
  after ` -- ` on the kernel command line, or in `boot.args` of the config partition. It is the
  node's own, from `/8` to `/24`, a whole network (`10.77.0.0/20`, not `10.77.0.1/20`), never
  loopback, link-local, multicast or reserved space, and should be private. A node address inside
  it makes kithd refuse `--pod-range` and otherwise warn on stderr.
- **A root file system to write.** Each container may write its own (what it writes goes when it
  does), unless it says `readOnlyRoot: true`. It is the user its image names, root included, with
  the capabilities a container runtime gives root, behind the same system call filter. On kith OS
  each container of a pod is a user namespace of its own, so its root is not the node's root
  ([what a container is kept from](#what-a-container-is-kept-from)).
- **What it may write.** `resources: { storage: 1Gi }` on a container bounds what its replica
  writes outside its Volumes (its roots and scratch on the state disk, summed against the sum of
  the limits). A limit under 64Ki is refused, and a Node's `reserved`, a seat's `reserve` and a
  Namespace's `quota` refuse `storage`. The Node's status says which way a node holds limits:
  - On a kith OS state disk made with project quotas, at the write: each pod is a project, and a
    write past its limit fails (`EDQUOT`). A pod also gets a share of the disk's files (4096 at
    least): a unit with very many small files needs a larger `storage`.
  - Elsewhere, by counting about every 10 seconds: a replica past its limit is replaced, started
    again from an empty root and scratch, and its status says how much it wrote. A fast writer can
    pass the limit between counts, and a kithd that is not root counts only what it can read.
    Under `--storage-reserve`, the replica that wrote the most is replaced, limit or none, one per
    count.

### A pod behind a VPN exit

An app that must reach the internet only through a VPN needs no VPN container with `NET_ADMIN`,
`/dev/net/tun` and a killswitch. The node holds the WireGuard tunnel; the pod gets a network that
leads into it:

```yaml
apiVersion: kith.dev/v1
kind: Secret
metadata: { name: vpn, namespace: kith-system }
spec:
  data:
    wg0.conf: |              # the file your provider gives you, as it gives it
      [Interface]
      PrivateKey = ...
      Address = 10.2.0.2/32
      DNS = 10.2.0.1
      [Peer]
      PublicKey = ...
      AllowedIPs = 0.0.0.0/0
      Endpoint = 192.0.2.10:51820
---
apiVersion: kith.dev/v1
kind: Exit
metadata: { name: vpn }
spec:
  node: n1                   # the node that holds the tunnel; the pods run there
  secret: vpn                # in kith-system: kithd reads it, no container mounts it
  namespaces: [media]        # whose pods may leave by it
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: downloads, namespace: media }
spec:
  template:
    pod: true
    exit: vpn
    containers:
      - name: app
        image: example/downloads:1
        ports: [{ port: 8080, publish: true }]
```

- **Through the tunnel, or nowhere.** Before the pod's link is made, kithd writes rules that send
  everything the pod sends outside the cluster into the tunnel, or, with no tunnel, nowhere; the
  firewall drops whatever would leave by any other link, whether kithd runs or not. With the
  provider silent, or the tunnel or the Exit deleted, the pod reaches nothing outside: it never
  falls back to the node's own way out. IPv6 never leaves. Nothing comes in from the tunnel that
  was not started from this side, so the provider reaches none of the node's services.
- **Names.** The pod asks the exit's DNS (`DNS` in the file, or the Exit's `dns`) through the
  tunnel, never the node's resolver, so it has no cluster DNS names.
- **Only where the tunnel is.** An exit's pods are placed on its node; a node with no tunnel for
  it, or a kithd that is not root, does not start them. A Workload in a namespace the Exit does
  not list is refused. Only a Workload's pods leave by an exit, not a Job's, NodeWorkload's or exec
  unit's.
- **Its web UI from the LAN.** `publish: true` on a port (TCP, or `protocol: udp`) makes kithd
  listen on that port of each of the node's IPv4 addresses and pass each connection or datagram to
  the pod; replies go back the same way, not through the tunnel. `publish` works for any pod. The
  app must listen on `0.0.0.0`, not 127.0.0.1 alone, and sees each client as the pod's own address.
  - A port belongs to the first pod of a namespace that has it; another of the same namespace
    waits, one of another namespace is refused. At most 8 ports a pod and 64 a node, none below
    1024 or one kithd serves on (5000, 7443 and 51820).
  - A connection ends after 10 seconds with nothing sent, or 10 minutes once something has been.
- **An Exit** is cluster-wide: whoever may write one decides which namespaces' pods leave through
  it, so a Role scoped to a namespace cannot. Only its node is sent it and its Secret. `Endpoint`
  has to be an address; the tunnel carries IPv4 only. Changing an Exit's namespaces or `dns`
  leaves its tunnel up, and a tunnel, rule or route taken away is made again within a minute.
- **Not yet:** OpenVPN, port forwarding, one key on two nodes, an exit's traffic from a pod on
  another node, and phones or laptops through an exit.

### A workload that outlives its node

A dev session, a desktop app, a game server or a database is one process that holds state and runs
for weeks. Kith keeps it going across a node's restarts with three kinds it has already: a
Workload of one replica, its home on a replicated Volume, its key in a Secret, and each long
command as a Job of its own.

```yaml
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: home }
spec:
  node: alpha            # where it is first made: the files are in state/volumes/default/home/home
  path: home
  replicas: 2            # copies in all: this one, and one on another node
  sync: 10s              # the other is brought up to date every 10 seconds (10s is the least)
---
apiVersion: kith.dev/v1
kind: Secret
metadata: { name: session-key }
spec:
  data:
    API_KEY: replace-with-the-key
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: session }
spec:
  replicas: 1            # one: it is a process with one home, not a service to spread
  template:
    containers:
      - name: dev
        image: ghcr.io/example/devbox:1
        volumeMounts: [{ volume: home, path: /home/dev }]
        env:
          - { name: API_KEY, secret: { name: session-key, key: API_KEY } }
```

The long commands are Jobs, so that the session itself is only what you type into, and a build,
an index or a training run is a thing kith can see end, fail and run again:

```yaml
apiVersion: kith.dev/v1
kind: Job
metadata: { name: reindex }
spec:
  template:
    containers:
      - name: run
        image: ghcr.io/example/devbox:1
        command: [sh, -c, "cd /home/dev/project && make index"]
        volumeMounts: [{ volume: home, path: /home/dev }]
---
apiVersion: kith.dev/v1
kind: Job
metadata: { name: nightly-build }
spec:
  template:
    containers:
      - name: run
        image: ghcr.io/example/devbox:1
        command: [sh, -c, "cd /home/dev/project && make release"]
        volumeMounts: [{ volume: home, path: /home/dev }]
```

A Workload or Job that mounts a Volume runs on the node that has it (the Volume's `primary`), so
the session and its Jobs share one home. Put the key in the Secret and not in the image or the
Volume. A worker is sent the Secrets of what is placed on it and no others, but a control node
holds every Secret of the cluster (`docs/adr-workers.md`), so a key in a Secret is as safe as the
cluster's control nodes are.
Clients find the session after a move by a Service that selects the Workload, not by a node's
address ([Services across nodes](cluster.md#services-across-nodes)).

What each restart of the node costs:

| What happens | The Volume | The Workload | What is lost |
|---|---|---|---|
| A planned drain, or an OS update by an `UpdatePlan` with `drain: true` ([restarting a node on purpose](cluster.md#restarting-a-node-on-purpose)) | The copy that synced last is asked to sync now and is handed over once it is current | Starts on that node in seconds, plus the image pull if that node does not have the image yet (`pullPolicy: ifNotPresent`) | Nothing is lost of what was written before the drain asked for the sync; a write in the seconds between that sync and the Workload's stop stays on the old node as `.PATH.was-TIME` |
| A crash or a lost node, which is also an OS update without `drain: true`: the reboot is a loss | The copy that synced last becomes the primary once the node has been silent for `--lost-after`: about 5 minutes on a default cluster, and about 15 seconds with `--lost-after 10` (10 seconds is the least) | Starts on that node within one reconcile (5 seconds) of that, plus the image pull if needed | Writes of up to 10 seconds (the sync), those since the last sync; the old node keeps them as `.PATH.was-TIME` |
| A Job that was running when its node went | A drain holds the Volume back until the Job ends | A planned drain waits for the Job and nothing is lost. After a loss, a Job on a replicated Volume starts over on the new primary from its first command; a Job on a Volume with no `replicas` waits for its node ([checkpointing a long GPU Job](cluster.md#checkpointing-a-long-gpu-job)) | The Job's progress: it is in memory, so a Job that must not start over writes its own checkpoints into the home and reads the last at its start |

- **Set `--lost-after` where kithd starts.** `kithd --lost-after 10` (or `KITH_LOST_AFTER=10`) on
  every node; a node is lost after 10 seconds at the least, whatever smaller number is given.
  Left at its default, a crash is 5 minutes of nothing before the move.
- **Seconds, not a lost-after, for a planned move.** A drain is told the Workload's node is going,
  so nothing waits for a silence; the session is down for the time the container takes to start.
  After a loss the cost is what was written since the last sync: shorten `sync` to shrink it
  (10 seconds is the least), or save a file that must not be lost and wait out one sync.
- **A process in memory is not kept.** The session starts again from its home: a shell, an editor's
  buffers and a running server do not move, and a program that keeps its state in files (a game
  server's world, a database's data directory) comes back from the last sync of them. A database
  wants its own log or replication besides, as a copy 10 seconds old is a crash-consistent
  one, not a point it chose.
- **No Kubernetes and no VM.** Kith runs no Kubernetes and no virtual machine for this: the session
  is a container kithd starts, in the cluster's own scheduler, and a restart is the container
  started again on another node. Live migration of a VM workload (the memory, devices and the
  running process of a `vms` unit carried to another node) is a later, separate feature, and the
  costs above are for a container, not a VM.

#### Dev machines

`kith machine` writes [that recipe](#a-workload-that-outlives-its-node) for you: one Workload of
one replica and a replicated home Volume, applied through the same call as `kith apply`. Nothing is
new on kithd's side; `kith get workload/dev` shows the machine as it shows any Workload.

```sh
kith machine create dev --distro debian --node alpha   # debian, alpine, ubuntu or REGISTRY/NAME:TAG
kith machine shell dev          # a shell in the running machine, on a terminal
kith machine shell dev -- make -C project index   # or one command there; its exit code is kith's
kith machine shell dev --root   # root of the machine's own user namespace, where it has one
kith machine run dev -- sh -c 'cd project && make index'   # a Job in its image, as its user, on its home
kith machine list
kith machine rm dev              # its Jobs and the Workload; the home Volume stays unless --purge
```

- **Your user.** The container runs as your numeric user, read from the process and never 0: kith
  as root is refused, and so is a `$HOME` that is not yours. Where kithd is your service that user
  is yours on the node, and [its users](#what-a-container-is-kept-from) say what it is elsewhere.
  Its `$HOME` is `/home/$USER` there; `$USER` falls back to `dev` when it is unset, has an
  uppercase letter or is longer than 32 characters.
- **Its home** is the Volume `NAME-home` with `replicas: 2` (`--replicas`, 2 or more, `sync: 10s`),
  mounted at `/home/$USER`: the machine's own replicated Volume, not your host home. The node that
  holds it first is `--node`, or the cluster's only node. When that node is lost the Volume's other
  copy takes over and the Workload follows it, as above.
- **Yours stays yours.** `create` refuses a Workload or Volume of that name that is not a machine's,
  and a machine that exists with other settings (`rm` it first); the same settings are `unchanged`.
  `rm --purge` leaves the home when another Workload or Job mounts it. `rm` can be run again
  to finish what stopped midway.
- **A shell** is `kith machine shell NAME`: a process in the running machine (bash where the image
  has it, else `sh`; or the command after `--`) on a terminal of its own when kith's input and
  output are terminals, so a full-screen program and `^C` work. The terminal is raw while it
  runs and put back when it ends, also on a hangup or a kill; the window follows yours; the
  command's exit code is kith's. With a pipe on either end it runs on pipes, with the standard
  error apart. It is the same call as `kubectl exec -it`, so `--server` reaches a node as every
  other kith command does, and the right it asks is `exec` on the machine's Workload.
- **`--root`** is root of the machine's own user namespace and nothing more: it is refused, with
  the reason, where uid 0 there would be the node's root or the user kithd runs as (a container
  with no user namespace of its own, or a rootless kithd's). `--root` needs a machine with a user
  namespace of its own (`userNamespaces: true`), and `kith machine create` does not make one
  (that setting lets the calls a container is refused back), so today `--root` is refused with
  that reason on every machine; it is not `sudo`.
- **A command in a Job** is `kith machine run`, which runs a Job of its own with the machine's
  container and mount; read it with `kith logs job NAME-run-N -f`. The machine's own container
  only sleeps.
- **Not yet.** `sudo` does not work, since a container has `no_new_privs` and a setuid program is
  an ordinary program; `userNamespaces: true` is not set on a machine (so no `--root`). Your real home is not mounted: an absolute host path is a
  `kith-system` Volume, which cannot be replicated, so the machine's home is its own. No images
  built from a spec, no dotfile sync, no ports opened, no snapshots.

### What a container is given

Files from a ConfigMap or a Secret, directories of its replica's own, what it is told from maps
and of itself, and containers that run before it. A Deployment sent through
[the Kubernetes API](kubernetes.md#kubectl-and-helm-as-they-are) says them as Kubernetes does:

```yaml
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: web }
spec:
  template:
    initContainers:                # run first, in this order, each to its end [none]
      - name: migrate
        image: registry.example/shop/migrate:1
        volumeMounts: [{ scratch: work, path: /work }]
    containers:
      - name: web
        image: registry.example/shop/web:1
        envFrom:
          - configMap: web-env     # every key of it is a variable
          - secret: web-keys
            prefix: KEY_           # put before each name [nothing]
        env:
          - name: POD_NAME
            field: name            # this replica's name | namespace | node | address
        runAsNonRoot: true         # do not start it as root [false]
        dropCapabilities: [all]    # start without these, or without `all` [none]
        volumeMounts:
          - configMap: web-conf    # each key a file, changed when the ConfigMap is
            path: /etc/web
          - configMap: web-conf
            path: /etc/nginx/nginx.conf
            subPath: nginx.conf    # one of them alone, at a file's path
          - secret: web-tls
            path: /etc/tls
            items: { tls.key: private/key.pem }   # only these keys, at these paths [every key, by its name]
            mode: "0400"           # [0444]
          - scratch: work          # an empty directory of this replica's
            path: /work
          - volume: data
            path: /var/lib/postgresql/data
            subPath: pg/15         # this directory of it alone, made if it is not there
          - scratch: cache
            path: /var/cache
            memory: true           # kept in memory [on the node's state disk]
```

- **Files.** A mounted ConfigMap or Secret is read-only. When it changes, its files change in the
  running container, all at once, and nothing is restarted (a `subPath` file stays as it was until
  its container starts again). A ConfigMap or key that is not there keeps the replica from
  starting, and its status says which. A Secret's files are in memory, never on a disk (`/run/kith`
  on kith OS, your runtime directory where kithd is your service).
- **A scratch** is an empty directory the containers of one replica that name it share. It
  outlives a restarted container and goes with its replica. On the state disk it counts toward
  `resources.storage`; in memory, as the memory of the container that wrote it.
- **`envFrom`** gives every key of a ConfigMap or a Secret as a variable; a variable in `env` of
  the same name wins, and a changed value replaces the container. **`field`** is the replica's
  own: `name` (`web-0`), `namespace`, `node`, or `address` (a pod's own; otherwise its node's on
  the mesh, or `127.0.0.1`).
- **`initContainers`** run one after the other before the template's containers, each until it
  ends well (with `restartPolicy: never` a failed one is not run again and nothing after it
  starts). They take no probes and run again when their replica is replaced.
- **`runAsNonRoot`** does not start a container that would be root: `runAsUser: 0` is refused when
  applied, and an image that names root, or (in a pod) no user, when it starts.
  **`dropCapabilities`** takes capabilities (`NET_RAW`, without `CAP_`) from what the container
  would have had: a pod's root has fourteen, root on kith OS three, anyone else none or one.
- **`subPath` of a volume or a scratch** mounts that directory (or file) of it alone, made where
  it is not there, its parent's user's. What is in a volume is its containers' to write, links
  included, so no step of the path may be a link (wherever it points: the container does not
  start, and its status says which step), and the part is mounted as it was opened, never looked
  up again. It is mounted only for a container with users of its own: a NodeWorkload's, one on
  the host's network or given devices, or one where kithd is not root does not start with one.
- **Not yet:** a mode for one file among the others.
