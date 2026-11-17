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
  `localhost` every `intervalSeconds` (10), and once a second until the first success.
- **Updates.** A changed Workload (or a changed `ConfigMap` or `Secret` value in a unit's `env`) is
  replaced one replica at a time, the next once the others are ready: an update that does not come
  up stops at its first replica and the status says where. `strategy: recreate` replaces all at once.
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

### Not yet

- `exec` probes are accepted and do nothing (the status says so). A container's `ports` only name
  them for probes and Services; nothing is opened or mapped.
- A replica is stopped before its replacement starts, so `replicas: 1` is down for a moment during
  an update. `blueGreen` is treated as rolling.
- Pulls are anonymous; layers must be gzip or plain tar.
- [`dist/kithd.service`](../../dist/kithd.service) is a systemd user unit, not yet run under
  systemd; a root service on a distro is untested.

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
  and was valid when the log (under its key) saw the signature. What this proves and what it
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
    (the refusal names it); take it out of the `Cluster` to go back. `spec.images` is all kithd
    reads of a `Cluster` today; `kith lint`, `diff` and `apply` say so of its other fields.
- **What it still reaches.** The node's network, the kernel through every call the filter lets by,
  and the devices it claims (a GPU's render node is a wide door into a kernel driver). Untrusted
  programs belong in a VM ([Virtual machines](hardware.md#virtual-machines)), which is what a
  `vms` unit is for.
- **Not yet.** No AppArmor or SELinux profile. On kith OS, no user namespace for a container on
  the node's network, one given devices or one with a volume of another node. A call the kernel
  gains later is let through until it is named in the filter. A log of Rekor v2 is not read. An
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
- **Not yet:** `subPath` of a volume or of a scratch, and a mode for one file among the others.
