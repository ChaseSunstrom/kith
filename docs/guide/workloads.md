# What kithd does today

- Serves the resource API as HTTP/JSON on a unix socket only you can open
  (`$XDG_RUNTIME_DIR/kith/kithd.sock`; `--socket` or `KITH_SOCKET` to move it).
  `kith` gives up on a kithd that has not answered for 30 s (`--timeout` or
  `KITH_TIMEOUT`, in seconds); a change that timed out may still have been applied.
- One kithd per state directory: a second one is refused instead of left waiting.
- Keeps resources and their revision history under `~/.local/state/kith/raft`
  (`--state` or `KITH_STATE`): a log of changes that is synced to disk before a
  change is answered, and a snapshot of the store now and then. It is the same
  replicated store a cluster uses, with this node as its only member. A
  `store.json` left there by an older kithd is brought in on the first start.
  `kith --store FILE` reads or edits a store kept in a plain file, with no
  daemon: for trying things out, not for looking into a kithd's state.
- Runs each `Workload` container in its own cgroup with youki's `libcontainer`
  linked in: no containerd, no shim, no root. Images are pulled into a
  content-addressed store; one pulled before starts without asking the registry (but
  one of this node's own registry, below; about 25 ms from `kith apply` to first output
  here), so `pullPolicy: always` is
  how you follow a tag that moves. A cluster Image of this node's own registry is
  always asked, whatever its policy: one deleted, or made again under its name, is
  not started from the copy kept here (asking for an unchanged one takes about 22 ms
  here). A file that several unpacked images hold alike (bytes, mode, owner, time, and
  no extended attribute) is one file on the node, hard-linked into each: three nginx
  images of one Alpine base took 44% less disk here, and unpacked 4 to 6% slower (each
  file is read once more to find its equals, on up to four threads; on one thread it
  was a quarter slower). An image no unit on the node uses goes once it has gone unused
  for `--image-grace` seconds (a day by default; kithd looks once a minute, and counts
  from the last look that found it in use, and never from before kithd's start: only
  time kithd has been up counts, so a node down or restarted keeps its images longer),
  and sooner, oldest first, while the state disk
  is under its `--storage-reserve`, once unused for two minutes (so a unit started
  again a moment later still has it; no grace is shorter): its unpacked tree, the
  layers no image is made of any more, and the shared files nothing else links, each
  said in kithd's log with the bytes it freed. An image a unit has a slot for, or a
  container is made from, stays; while a pull is under way (one that hangs too) none
  is removed. The time between a Job's or CronJob's runs counts as unused: an image
  used less often than its grace is pulled again each time. A unit that needs a
  removed image pulls it again, checked for its signature again; one with
  `pullPolicy: never` fails until it is pulled, so a node off its network (a laptop)
  wants `--image-grace 0`. That keeps every image and layer; kithd then only finishes
  deleting what a removal it was stopped in left. A wall clock set forward between two
  looks removes nothing that look, and counts every image from then; an image used
  while the clock was far ahead is kept (under the reserve too) until the clock passes
  that time again. A layer no image names goes once it is as old as an unused image
  must be (a pull cut short is likely tried again), and none goes while an image
  unpacked by a kithd from before this version is on the node: remove that image by
  hand, or let it go past its grace, for layers to go.
  Memory and CPU limits, a limit on what a replica writes (`resources.storage`,
  [below](#a-replica-as-a-pod)), `command`/`args`, and `env`
  from values, `ConfigMap`s and `Secret`s are honoured; containers that exit are
  restarted according to `restartPolicy`: at once the first time (and whenever it
  had run for a minute), then after a wait that doubles from a second up to a
  minute for one that keeps exiting.
- Runs `exec` units next to containers: a plain process of the host (its files,
  its network, your user) in its own cgroup with the same limits and restart
  policy, for host-level tools. Whatever it forks is stopped with it.
- Runs each `Job` to completion: `completions` runs of its template,
  `parallelism` at a time (1 unless you say). A run fails as soon as one of its
  units exits non-zero or cannot start, and is tried again after a backoff;
  `retries` failed runs are forgiven (3 unless you say), one more fails the Job,
  and so does taking longer than `timeoutSeconds`. `kith get job` shows
  `running`, `succeeded` or `failed: <why>`. A finished Job runs again only when
  you change it; one that kithd was restarted under starts over.
- Makes a `CronJob`'s Jobs by the clock: at each minute its `schedule` names
  (cron's five fields, or a name such as `@hourly`; read in UTC), the node that
  leads makes a Job of its `job`,
  called `<name>-<minute>`. `concurrency: forbid` waits for one that is still
  running, `replace` removes it first. The last three Jobs that succeeded and the
  last three that failed are kept (`successfulJobsHistoryLimit` and
  `failedJobsHistoryLimit` say how many instead), and all of them go when the
  CronJob does. A minute in which no node led (or kithd was down) is skipped,
  unless the CronJob says `startingDeadlineSeconds`: then the latest minute its
  schedule named since its last run (`status.last`) that is no older than that is
  run, once (never more than a week back; a CronJob that has not run yet has
  nothing to catch up from). A CronJob that names a `timezone` other than
  `UTC` (kith has no table of time zones: their rules measure 207 kB as compiled,
  more than the 150 kB kithd's size budget was to give them, and kith OS ships
  none), whose schedule cannot be read, or whose name is longer than 54 characters
  (a Job's name is its and the minute) is not run, and its status says why.
  Whoever applies a CronJob must be allowed to apply a Job.
- Keeps each unit's output: `kith logs KIND/NAME` prints it, with `--unit`,
  `--replica` (or the run of a Job), `--stderr`, `--tail LINES` and `-f` to
  follow until the unit is done. A log file that passes 10 MiB (`kithd
  --log-cap BYTES`) is moved aside, one old copy is kept (`kith logs
  --previous`), and deleting the Workload or Job deletes its logs.
- Probes containers: `readiness` decides whether a replica counts as ready, and
  a `liveness` probe that fails `failureThreshold` times in a row (3 unless you
  say) gets the container restarted, once it has passed for the first time
  (there is no start deadline yet). `tcp` and `http` probes are made against
  `localhost`, every `intervalSeconds` (10) and once a second until the first
  success.
- Updates a changed Workload one replica at a time: the next one is replaced
  only once the others are ready, so an update that does not come up stops at
  its first replica and the status says where. `strategy: recreate` replaces
  everything at once. A container or exec unit is replaced the same way when a
  `ConfigMap` or `Secret` value in its `env` changes.
- On SIGTERM it stops everything it started, and goes on answering the
  requests it has for 3 seconds at most: a longer one (a large `kith volume
  put`, a followed log) is cut there. Told a second time while it
  stops, it ends at once and its next start stops what was left (on kith OS
  the second signal changes nothing: the node still unmounts its disks).

Not yet: `exec` probes are accepted but do nothing (the status says so), a
container's `ports` only name them for probes and Services (nothing is opened or
mapped: containers share the host's network), a replica is stopped before
its replacement starts (so `replicas: 1` is down for a moment during an update;
`blueGreen` is treated as rolling), containers share the host's
network and a read-only image (tmpfs on `/tmp` and `/run`), pulls are anonymous, and layers
must be gzip or plain tar. The log cap
is checked every 10 s, so a file can pass it by what its unit writes in that
time, and output written in the instant a file is moved aside is lost. As a service on a
distro, running as root is untested (on kith OS kithd is root: it is the first
process).

[`dist/kithd.service`](../../dist/kithd.service) is a systemd user unit for it; it has
not been run under systemd yet.

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

- **Who it is.** The user its template names (`runAsUser`, a number, the group the same),
  else the image's `User` (a name is looked up in the image's own `/etc/passwd`), else
  nobody (65534). An image cannot make its container root by saying so: one that names
  root, or 0, gets nobody too (and one that names root's group, the user's own number
  as its group), and `runAsUser: 0` is how a container is root. Where kithd
  is your own service the container is a user namespace in which that user is the only
  one there is (on the node, its files are yours), and root, when asked for, is root of
  that namespace alone. It is still in your groups there (a namespace made without
  privileges cannot leave them), for what that is worth to it: the files it can reach
  are its image, its volumes and the devices it claims. On kith OS, where kithd is root,
  a pod's container (one with a network of its own: [a pod](#a-replica-as-a-pod)) is a
  user namespace of its own too: its users 0 to 65535 are 65536 users of the node that no
  other container has (taken as it starts, given back once it is gone; which are taken is
  read from the containers' bundles on the disk, and one left behind whose processes
  outlive its kill keeps its range until they are gone), so `runAsUser: 0` is root of that
  namespace alone, and a `runAsUser` of 65536 or more is refused. Its image and its
  volumes are mounted id-mapped: a file its user 1000 makes is user 1000's on the disk, as
  before, and no owner on the disk is changed to fit its range. Id-mapped mounts are
  Linux 5.12's (btrfs's 5.15, tmpfs's 6.3; kith OS's own kernel, 6.18, has them all); a
  kernel or file system that refuses one fails the container's start rather than run it as
  the node's users. Any port of the pod's own network is anyone's in it, so its root still
  serves port 80. The rest keep the node's
  users, so that `runAsUser: 0` is the node's root with three capabilities (to send
  signals, to take a port below 1024, to write the audit log): a container on the node's
  network (a port it serves is below 1024 as often as not, and no capability of a user
  namespace reaches the node's network; the node's ports below 1024 stay its root's), one
  whose image or a volume is on a file system that takes no id-mapped mount (ext4, xfs,
  btrfs and tmpfs take one; a volume of another node is NFS, which does not), one given
  devices (theirs are the node's users) and a NodeWorkload's (the node's own). A
  container's status says which it is: `hostUsers: false` for a namespace of its own; a
  pod's container kept so by a file system also says which path on kithd's log.
- **Nothing more than that user.** No capabilities (on kith OS the one for ports below
  1024 is kept), and no way to any: `no_new_privs` is set, so a setuid program in the
  image is an ordinary program.
- **Its image is read-only**, with a tmpfs on `/tmp` and on `/run`. A volume it mounts to
  write is given to its user where kithd is root: all of it, the first time and whenever
  the volume's directory is someone else's (a volume from before containers had users,
  a restored one, a workload whose user changed), walked without following a link. Two
  workloads that write one volume should be one user: each start would take it back. A
  directory of the host's that you named (a `kith-system` Volume) is left as you made it,
  and so is a volume mounted `readOnly`.
- **A filter on its system calls** (seccomp) refuses these, as if it were not allowed
  them: `mount`, `umount2`, `pivot_root`, `open_tree`, `move_mount`, `fsopen`,
  `fsconfig`, `fsmount`, `fspick`, `mount_setattr`, `open_by_handle_at`; `unshare`,
  `setns`, `clone` when it makes a namespace, `clone3` (answered as a kernel without it
  answers, so a C library falls back on `clone`); `init_module`, `finit_module`,
  `delete_module`, `kexec_load`, `kexec_file_load`, `reboot`, `swapon`, `swapoff`,
  `acct`, `settimeofday`, `clock_settime`; `bpf`, `perf_event_open`, `userfaultfd`,
  `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `add_key`, `request_key`,
  `keyctl`; `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, `pidfd_getfd`.
  Everything else goes through. `seccomp: { allow: [NAMES] }` lets some of them through again (a
  debugger wants `ptrace`; a browser's own sandbox wants `unshare`, `clone` and
  `clone3`), and `seccomp: { unconfined: true }` is no filter. A 32-bit program on a
  64-bit node is stopped at its first call, the filter knowing only the node's own
  numbers: it needs `unconfined`.
- **No sandbox of its own inside, unless it asks.** Steam's runtime, Flatpak and a
  browser start what they run in a user namespace they make themselves (bubblewrap), and
  do not start without (bubblewrap's own words for it:
  `bwrap: Unexpected capabilities but not setuid, old file caps config?`).
  `userNamespaces: true` lets the calls for namespaces (`unshare`,
  `setns`, `clone`, `clone3`) and those that mount (`mount` to `mount_setattr` in the
  list above; not `open_by_handle_at`) through the filter and covers nothing in the
  container's `/proc` and `/sys/firmware` (the kernel gives a namespace made inside no
  `/proc` of its own while the one around it is covered in places), so it reads there
  what its user could read on the node. On kith OS it also starts without the capability
  for ports below 1024 (bubblewrap refuses to start as a user who holds one). The rest of
  the filter holds, for what the
  sandbox starts too, and so does `no_new_privs`. What it costs: inside a user namespace
  a program is that namespace's root, and reaches kernel code a plain user never calls
  (mounting, more of the network); much of what has let a user become the node's root was
  found there. A container that is the node's root (on kith OS where it keeps the node's
  users: `runAsUser: 0`, or a pod whose image is root's) is not started with it, and
  says so.
- **Whose image it is.** With `signedBy`, the image is run only if one of those keys
  signed it, as `cosign sign --key` does: the signature is looked for in the image's own
  repository (the tag `sha256-DIGEST.sig`) and checked against the manifest's digest
  before any layer is fetched; an image for several machines may be signed as the list
  or as this machine's own. Keys are ECDSA P-256 (what `cosign generate-key-pair` makes)
  or Ed25519: the text of the `.pub` file, or the base64 in it. An image already on the
  node counts as signed only by the keys a signature of it was found by; `pullPolicy:
  never` with a key the node has not checked it against does not start. With no
  `signedBy` and no rule of the cluster's (next), an image is run whoever made it.
- **Signed without a kept key** (cosign's default: `cosign sign IMAGE`, no `--key`).
  `signedBy` may name an identity in place of a key: whom the authority certified and
  where they signed in, with the authority's certificates and the transparency log's
  key. Nothing of these is built in or fetched: you give the roots you trust, as below
  for the public Sigstore instance (its trusted root's Fulcio certificates and Rekor key,
  e.g. from `cosign trusted-root create`, or the files Sigstore publishes):

  ```yaml
  signedBy:
    - issuer: https://token.actions.githubusercontent.com
      subject: https://github.com/acme/tool/.github/workflows/release.yml@refs/heads/main
      authority: [ "-----BEGIN CERTIFICATE-----\n…", "-----BEGIN CERTIFICATE-----\n…" ]
      log: "-----BEGIN PUBLIC KEY-----\n…"
  ```

  The signature is looked for as a bundle among the image's referrers (cosign 3) and
  under the tag `sha256-DIGEST.sig` (older cosigns). It is run only if the signature is
  by a certificate from that authority, for code signing, naming exactly that subject
  and issuer, valid when the log promised (under its key) that it saw the signature,
  and the log's entry is of that very signature. What this proves and what it does not:
  [SECURITY.md](../../SECURITY.md#what-is-not-defended) and [docs/adr-keyless.md](../../docs/adr-keyless.md).
  Whatever its `pullPolicy`, a cluster Image of this node's own registry is asked for
  again before it starts (see above).
- **Keys named once, for the cluster.** A `Cluster`'s `spec.images` says which keys
  sign the images under a registry or a path of one, whatever a template says:

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

  An image is held to the rule with the longest prefix it is under, read as a pull
  reads it (`nginx` is `docker.io/library/nginx`, so Docker Hub's official images are
  under `docker.io/library`; `ghcr.io:443` is `ghcr.io`), and is run only if one of
  that rule's keys signed it. A template's own `signedBy` can then only narrow: the image
  must be signed by a key both name, and where they name none in common it is not
  run. An image under no rule runs as before, so a rule for a prefix holds that name
  and not what a workload's writer may choose to run instead: for that, give a rule
  with no prefix. Only someone with rights over the whole cluster can apply a
  `Cluster` (a Role that names namespaces gives none), or who may write a Source in
  `kith-system`, whose files are applied cluster-wide. Every node must run a build
  that reads rules: an older one runs an image as before. Up to 32 rules, 16 keys each;
  a rule by mistake stops new containers under it from starting (the refusal names
  the rule), and taking it out of the `Cluster` is the way back. Not under any rule:
  a cluster Image (packed from a Volume on a node, signed by no one). A rule may name
  identities as a template may (above); an older kithd refuses such a rule, or keeps
  only its keys and runs nothing a rule of identities alone covers. Not read yet: a log
  of Rekor v2 (no promise, a time from a timestamp authority). `spec.images` is all kithd reads of a `Cluster` today: its `domain`, `voters`,
  `updatePolicy`, `mesh` and `values` are kept and not acted on, and `kith lint`, `kith
  diff` and `kith apply` say so of each one a file sets.
- **What it still reaches.** The node's network (and so every port on its loopback, and
  the sockets programs of the node listen on by name alone, without a file), the
  kernel through every call the filter lets by, and the devices it claims: a GPU's render
  node is a wide door into a kernel driver, and no filter here narrows it. All of this is
  for keeping an honest program's mistakes small. Untrusted programs belong in a VM
  ([Virtual machines](hardware.md#virtual-machines)), which is what a `vms` unit is for.
- Not yet: no AppArmor or SELinux profile; no user namespace on kith OS for a container
  on the node's network, one given devices or one with a volume of another node, and a
  pod's `/sys` is the node's, bound in (a user namespace may mount no other); the filter is a
  list of what is refused, not of what is allowed, so a call the kernel gains later is let
  through until it is named here; a log of Rekor v2 is not read (its signatures are
  refused, naming it); an `exec` unit is none of this: it is a process
  of the host. The user namespace of the first kind (kithd as your service) has been run;
  the kith OS kind has been run in VMs for pods as root, serving port 80, and its
  id-mapped volumes beside one of another node.

### A replica as a pod

`pod: true` on a template runs each replica as Kubernetes runs a pod. It is what
a Deployment sent through [the Kubernetes API](kubernetes.md#kubectl-and-helm-as-they-are)
says, and a kith file can say it too:

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

- **A network of its own.** The replica's containers share one: any port is theirs
  (three replicas on one node each listen on port 80), `localhost` is each other, and
  the replica has an address of its own, on the cluster's mesh where there is one
  (`--mesh`), so every node reaches it and Services send to it. What it asks outside
  the cluster leaves from behind its node's address. It is told this node's DNS, with
  the search list Kubernetes gives: `web` and `web.default.svc.cluster.local` are the Service.
  A pod's names outside the cluster are asked of its node's resolvers: they need a resolver
  on the node (in `/etc/resolv.conf`) or `--dns-upstream`, and `--dns` is not needed for them.
  The IPv4 address only its node knows is taken from `100.88.0.0/16` unless that node's
  kithd is told another with `--pod-range ADDRESS/BITS` (or `KITH_POD_RANGE`; on kith OS
  after ` -- ` on the kernel command line or in `boot.args` of the config partition), for a
  node whose own network or tailnet is in it. It is the node's own to name (nodes of one
  cluster may differ: no pod reaches another by it), from `/8` to `/24` (a `/24` holds 254
  pods) and a whole network (`10.77.0.0/20`, not `10.77.0.1/20`); never loopback,
  link-local (169.254.0.0/16), multicast or reserved space. At start, as root, kithd reads the
  addresses its node has on its links (not the loopback's) and finds one that is inside the
  range or whose network (`192.168.1.5/16`) holds it; it changes nothing, and a range that comes
  up on the node later is not noticed. When the range was named with `--pod-range` and
  kithd is not the first process of a kith OS node, kithd then refuses to start, naming the
  address and the link; on the default range, and on kith OS (a refusal there restarts the
  machine, and a lease that lands in the range one day would make it loop), it says so on stderr
  and goes on. The node's DNS answers names outside the cluster for any address in the
  range, so a range that is not private lets whoever can reach its listener from such an
  address use it: choose a private one. Pods of the old range go when kithd restarts.
- **A root file system to write.** Each container may write its own (what it writes
  goes when it does), unless it says `readOnlyRoot: true`.
- **What it may write.** `resources: { storage: 1Gi }` on a container bounds what its
  replica writes outside its Volumes: its containers' roots and its scratch on the state
  disk, counted together against the sum of their limits, with a file it removed that
  one of its processes still holds open. kithd counts about every 10 seconds, and a
  replica past it is replaced: each container is started again from an empty root and
  an empty scratch, and its status says how much it wrote. A limited replica whose files
  cannot all be counted in 5 seconds, or that nests directories 128 deep, two counts in
  a row, is replaced too, and says so. A node keeps part of its state disk free
  (`--storage-reserve BYTES`; where kithd is root, 5% of the disk and at most 1 GiB
  unless said; 0 for none, and where it is not): under it, the replica that wrote the
  most (a tenth of the reserve at least) is replaced, limit or none, one a count, once
  what the last one replaced wrote is gone, even when what filled the disk is no
  replica's root: kithd's own store, logs and Images, and Volumes, count against no
  replica. On a kith OS state disk made since this was added (project quotas, kithd
  root) the limit is held at the write instead: each pod is a project of its own, a write
  past its limit fails (EDQUOT), in its root (a copy-up of an image's file too) and its
  scratch, with the node's users or its own; only what kithd itself writes there is
  counted (SECURITY.md); with its bytes a pod gets its share of the disk's files (the
  share its limit is of the disk's bytes, 4096 at least), and a new file past it fails
  the same way: one of very many small files needs a larger `storage`; its units say it
  reached it, and kithd says at start and
  in the Node's status which way it holds limits. Elsewhere it is counted, not held at
  the write: between two counts a fast writer
  can pass it, a removed file held only by a descriptor in flight on a socket counts
  nothing, and a kithd that is not root counts only what it can read (SECURITY.md). A
  limit under 64Ki is refused. (`storage` limits a container only:
  a Node's `reserved`, a seat's `reserve` and a Namespace's `quota` refuse it.)
- **The image's user.** Each container is the user its image names, root included,
  with the capabilities a container runtime gives root and no more, in namespaces
  and a root of its own and behind the same filter on system calls as every container.
- Where kithd is not root (a service of your user) a pod shares the node's network
  like any replica, and its root is root of a user namespace only.
- On kith OS, where kithd is root, each container of a pod is a user namespace of its
  own, with users of the node no other container has: its root is not the node's root,
  and a root-only file of the node it is handed stays shut to it
  ([what a container is kept from](#what-a-container-is-kept-from); `sh ci/vm.sh --test share`
  shows it). A pod on the node's network, one given devices or one with a volume of
  another node keeps the node's users.

### A pod behind a VPN exit

An app that must reach the internet only through a VPN (a download client, say) needs no
VPN container beside it with `NET_ADMIN`, `/dev/net/tun`, sysctls and a killswitch. The
node holds the WireGuard tunnel itself, and the pod is given nothing but a network that
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

- **Through the tunnel, or nowhere.** Before the pod's link is made, kithd writes rules
  that send everything the pod sends outside the cluster to the tunnel's own routing
  table, or, with no tunnel, to nowhere; and the firewall drops whatever of an exit's pod
  would leave by any other link, whether kithd runs or not. With the provider silent, the
  tunnel deleted or the Exit deleted, the pod reaches nothing outside; it does not fall
  back to the node's own way out. IPv6 never leaves (only the mesh's range is routed),
  and nothing from the tunnel comes in, to the pod or to the node, that was not started
  from this side: the provider reaches none of the node's services (kithd's API among
  them), from the moment the tunnel is made. Nor does an exit's pod, on any port.
- **Names through the tunnel.** The pod asks the exit's DNS (`DNS` in the file, or the
  Exit's `dns`), over UDP and TCP, through the tunnel: never the node's resolver or its
  cache. So an exit's pod has no cluster DNS names, and a Service that sends to it may not
  reach it.
- **Only where the tunnel is.** An exit's pods are placed on its node; a node that holds
  no tunnel for it, or a kithd that is not root, does not start them; and deleting the
  Exit stops them. A Workload in a namespace the Exit does not list is refused when
  applied (`Exit vpn does not list namespace other`), and again by the node. Only a
  Workload's pods leave by an exit (not a Job's, a NodeWorkload's or an exec unit's).
- **Its web UI from the LAN.** `publish: true` on a port (TCP, or `protocol: udp`) makes
  kithd listen on that port of each of the node's IPv4 addresses and pass each connection
  or datagram to the pod; the replies go back the same way, not through the tunnel. The
  pod of a node that has a port keeps it; another of the same namespace waits for it to
  go (kithd's log says so), and one of another namespace is refused when written, whoever writes it; the
  node remembers whose each port is, kithd started again or not. A pod
  publishes 8 ports at most, a node 64. `publish` works for any pod, not only an exit's. The app is reached at the
  pod's own address, so it must listen on all of them (`0.0.0.0`), not on 127.0.0.1
  alone, and sees each client as that address, not the client's. No port below 1024 is
  published, nor one kithd serves on (5000, 7443 and 51820 are refused when applied, and
  the node's DNS, ingress and other ports by the node, in its log). A connection ends
  after 10 seconds if nothing is sent either way, after 10 minutes with nothing sent once
  something has been; each port has 2 connections or UDP senders of its own and the
  node's ports share 64 more, and past that a new UDP sender takes the place of the one
  heard from longest ago.
- **What an Exit is.** It is cluster-wide: whoever may write one decides which namespaces'
  pods leave through it, so a Role scoped to a namespace cannot. Only the Exit's node is
  sent the Exit and its Secret. `Endpoint` has to be an address, not a name (a name would
  be asked outside the tunnel). The tunnel carries IPv4 only. A node holds several, even
  two whose provider gave each the same address; changing an Exit's namespaces or `dns`
  leaves its tunnel up (pods started after ask the new `dns`), and a tunnel, rule or route of one taken away is made again within
  a minute.
- Not yet: OpenVPN, the provider's port forwarding, one key on two nodes, an exit's
  traffic from a pod on another node, and phones or laptops through an exit.

### What a container is given

Files from a ConfigMap or a Secret, directories of its replica's own, what it is told
from maps and of itself, and containers that run before it. They are what a Deployment
sent through [the Kubernetes API](kubernetes.md#kubectl-and-helm-as-they-are) says with `volumes`,
`envFrom`, `fieldRef` and `initContainers`; in a kith file:

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

- **Files.** A mounted ConfigMap or Secret is read-only. When it changes, its files
  change in the running container, all at once, and nothing is restarted (they are
  read through one link that is moved, as Kubernetes does it). A file mounted alone
  (`subPath`) stays as it was until its container starts again. A ConfigMap or a key
  that is not there keeps the replica from starting, and its status says which.
- **A Secret's files are in memory**, never on a disk: under `/run/kith` on kith OS, in
  your runtime directory where kithd is a service of your user. kithd asks the kernel
  what that directory is on, and does not write them where the answer is a disk. A
  ConfigMap's are in the node's state. Both are in directories only kithd opens, belong
  to the container's user, and go when the replica does.
- **A scratch** is an empty directory that the containers of one replica which name
  it share. It outlives a container that is restarted and goes with its replica. On
  the state disk it counts toward its replica's `resources.storage` (and the reserve);
  in memory, what is written counts as the memory of the container that wrote it. (A
  disk `emptyDir`'s `sizeLimit` is added to the storage of the first container that
  mounts it, raised to 64Ki where it is less; a memory one's limits nothing.)
- **`envFrom`** gives every key of a ConfigMap or a Secret as a variable (one that
  cannot name a variable, with a `=` in it, is passed over); a variable in `env` of the
  same name wins. As with `env`, a changed value replaces the container.
  **`field`** is the replica's own: its `name` (`web-0`), its `namespace`, its `node`,
  its `address` (a pod's own; otherwise its node's on the mesh, or `127.0.0.1` where
  there is no mesh).
- **`initContainers`** run one after the other before the template's containers, each
  until it ends well (where `restartPolicy` is `never` one that fails is not run again,
  and what waits for it does not start). They take no probes. They run again when
  their replica is replaced (a new revision, another node), not when one of its
  containers is restarted.
- **`runAsNonRoot`** does not start a container that would be root: `runAsUser: 0` is
  refused when applied, and an image that names root, or (in a pod) no user, when it
  starts, with the reason in its status. **`dropCapabilities`** takes capabilities
  (`NET_RAW`, without `CAP_`) from whatever the container would have had: a pod's root
  has fourteen, root on kith OS three, anyone else none or one.
- Not yet: `subPath` of a volume or of a scratch; a mode
  for one file among the others. Where kithd is not root, the files of a map are your
  user's, which is the one user its containers have.

What it costs: 0.09 MB of kithd (10.86 to 10.95 MB) and 0.05 MB of `kith`, which knows
the fields to check a file before it is sent (2.90 to 2.95 MB of its 3 MB).
