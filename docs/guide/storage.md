# Storage

A `Volume` is a directory on one node. A container mounts one by naming it, or a
`VolumeClaim` bound to one, in its `volumeMounts`:

```yaml
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: db-disk }
spec: { node: n1, path: db, size: 20Gi }
---
apiVersion: kith.dev/v1
kind: VolumeClaim
metadata: { name: db-data }
spec: { size: 10Gi }
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: db }
spec:
  template:
    containers:
      - name: run
        image: example/db
        volumeMounts: [{ volume: db-data, path: /var/lib/db }]
```

- The workload runs on the volume's node, and only there, unless the volume is `shared`
  (below). Volumes on two nodes, or a `DeviceClaim` on another node than the volume, leave
  it unplaced: its `unschedulable` says why. A name that is both a Volume and a VolumeClaim
  is the Volume.
- A claim with no volume yet takes the first Volume (by name) of its namespace that no
  claim has, is at least as big, is on a node with the labels in its `selector`, and is
  `shared` if the claim asks for that. `kith get volumeclaim db-data -o yaml` shows
  `status.volume`, the Volume shows `status.claim`, and it stays so while both exist; a claim
  that finds none says so in `status.message`. A claim whose Volume is deleted says so and
  takes no other (the workload would start on empty data): make the Volume again, or delete
  the claim and apply it again. Every replica of a workload shares the one directory. Deleting a claim frees its Volume, data
  kept.
- A claim that says `provision: true` and finds no Volume gets one made for it: of its
  name and size, a directory of its own in the node's state, on the ready node (of those its
  `selector` picks) that has the fewest Volumes. That Volume fits no other claim and is
  removed with the claim; the directory stays on the node, as every Volume's does, and
  a claim of the same name made later finds what was written. Whoever applies such a
  claim must be allowed to apply a Volume. (It is how a PersistentVolumeClaim sent by
  `kubectl` gets its volume.)
- The container sees the directory as a bind mount (`readOnly: true` makes it read-only).
  The directory is made on the node when the unit starts. In a namespace other than
  `kith-system` it is `<state>/volumes/<namespace>/<name>/<path>`: `path` must be relative,
  with no `..`, and no part of it may be a symbolic link, so a container cannot reach out of
  its namespace's directory by planting one. A `path` that breaks this is refused in the
  Volume's `status.message`. In `kith-system`, `path` is an absolute host path as written;
  what keeps others out of it is access control (nobody may apply a Volume there without the
  rule to do so).
- A container path that is not absolute, has `..`, or is `/`, `/proc`, `/sys` or `/dev`
  (or under them) stops the unit from starting, and says so.
- Not yet (ponytail): no dynamic provisioning (a claim binds a Volume somebody made);
  `subvolume: true` makes a plain directory, not a btrfs subvolume; `size` is a
  promise for binding, not a quota; an `exec` unit and a NodeWorkload mount nothing.

### Shared volumes

`shared: true` on a Volume lets a workload that mounts it run on any node:

```yaml
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: media }
spec: { node: n1, path: media, shared: true }
```

- The data stays on the volume's node (`n1`). A replica on `n1` mounts the directory as
  any volume; a replica on another node mounts it from `n1` over the mesh (NFS 4.2 over
  WireGuard) under `<state>/remote/n1/<namespace>/<name>`, when its unit starts, and that is
  what its container sees. It is unmounted when no unit on the node mounts it any more.
- A workload whose volumes are all shared is placed like one with none. One that also mounts
  a volume that is not shared goes to that volume's node.
- **Who can reach it:** the cluster's nodes, and nothing else. The node serves it on its mesh
  address only, to the mesh addresses of the cluster's nodes only (a container has another
  address, and gets nothing), and serves nothing but shared volumes and the names of the
  directories leading to them. Every node is trusted with a shared volume as root is, as
  every node is trusted with the cluster today.
- **What it takes:** the mesh (`--mesh`), and a kernel with the NFS server and the NFS 4.2
  client built in or loaded, as kith OS's has. kithd drives the kernel itself: there is no
  `rpc.mountd`, `exportfs`, `rpcbind` or `mount.nfs` to install, and no `/etc/exports`. On a
  machine that already runs an NFS server of its own, kithd leaves it alone and serves
  nothing (it says so in its log).
- While the volume's node is away, a container using the volume from another node waits
  (the mount is `hard`: it carries on when the node is back, and does not fail a write
  meanwhile); a unit that would start meanwhile says the node does not serve the volume, and is
  tried again.
- Not yet: a shared volume in `kith-system` (an absolute host path) is refused; the data is
  on one node, not copied to others; a volume that stops being `shared` is still served for
  up to two minutes; locks held when the volume's node restarts must be taken again within
  30 seconds; VMs (virtiofs) and machines that are not nodes cannot mount one.

### Shares: a volume for machines that are not nodes

A `Share` gives a Volume to the laptops, televisions and phones on your network:

```yaml
apiVersion: kith.dev/v1
kind: Share
metadata: { name: films }
spec:
  volume: media          # in this namespace
  readOnly: false        # [false]
  uid: 1000              # whoever uses the share is this user on the files [65534, nobody]
  gid: 1000
  nfs:
    clients: [192.168.1.0/24, 192.168.2.7]   # who may mount it over NFS
  users: [ada, grace]    # the Identities that may use it over SMB
```

- **NFS** is served by the volume's node itself, with the kernel server it already drives
  for shared volumes: NFS 4.2 on port 2049 of the node's IPv4 addresses, to the addresses
  `nfs.clients` names and nobody else. `kith get share films -o yaml` says the `node` and the
  `path`; on a client, `mount -t nfs4 NODE:PATH /mnt`. Every client is the Share's `uid` and
  `gid` on the files, whoever it says it is; a client sees its Shares' volumes and nothing
  beside them. The cluster's own nodes are never a Share's clients, whatever range it
  names: a container has its node's address, and mounts volumes the cluster's way. One
  Share gives a volume over NFS (the first by name; a second says so in its `status`).
- **SMB** is served by a Samba container that the `nas` package runs on the volume's node,
  port 445:

  ```sh
  kith apply -f passwords.yaml    # a Secret with a password under each user's name
  kith package render packages/nas --name films \
      --set volume=media --set 'users=[ada,grace]' --set passwords=nas-passwords \
      --set image=registry.example/nas/samba:1 | kith apply -f -
  ```

  The package makes the Share too (`--set 'nfs.clients=[192.168.1.0/24]'` for NFS beside
  it, or alone with no `users`). kith ships no Samba image: name one you built or trust, with
  Samba 4.15 or later and `nss_wrapper` in it (on Alpine: `samba-server`,
  `samba-common-tools`, `nss_wrapper`).
- The `status` of a Share says why it is given to nobody: no such Volume, an Identity in
  `users` that does not exist, or nobody named. Whoever applies a Share (or rolls one
  back) must be allowed to apply the Volume it gives; so must whoever applied a Release or a
  Source that renders one.
- `uid` is who writes: nobody (65534) unless you say, which is also who a container is
  with nothing said, so the two write each other's files. Where a container on the volume
  is another user (`runAsUser`, or its image's), name that user here.
- Not yet: NFS trusts an address to be who it says (no Kerberos), so name single addresses
  or a network you trust; a range wider than a /8 is refused; IPv6 clients that are not
  nodes are not served; once a node has served a Share over NFS it keeps listening on port
  2049 of its IPv4 addresses until it restarts (answering nobody when no Share names them);
  SMB users all write as the Share's one user; the SMB server listens on port 445 of every
  address of its node, so a node runs one `nas` release; an NFS client that moves a file
  between directories while another has it open may see that one's handle go stale; a
  Volume in `kith-system` cannot be given;
  the SMB server is not announced on the network (name the node in your file manager); and
  **the Samba half has been rendered and its start script run against stand-ins, not run
  with a real Samba here** (no image to run it from yet).

### Replicas

A Volume can be kept on more than one node, and move when its node is lost:

```yaml
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: data }
spec:
  node: alpha     # where it is to begin with
  path: d
  replicas: 2     # copies in all: this one, and one on another node
  sync: 5m        # how often the others are brought up to date (5m unless said)
```

- The cluster picks the other nodes (`status.replicas`). Every `sync`, each of them asks the
  node that has the volume (`status.primary`) for its directory over the cluster's mutual
  TLS, and puts what it gets in the place of its own copy; `status.synced` says when each
  last did. Nothing is sent when nothing changed.
- When the primary is not heard from for as long as a lost node's workloads wait
  (`--lost-after`), the replica that synced last becomes the primary. Workloads that mount
  the volume are placed there, and another node is picked to hold a copy.
- **A failover loses what was written after the last sync.** The copies are not written
  together: for data that must not lose a second, this is not yet the tool. A copy is the
  directory as it was read while in use, file by file: a database caught in the middle of a
  write may need its own recovery, as after a power cut. The replica that takes over is the
  one that synced last, however long ago that was: `status.synced` says when.
- With `replicas` lowered to 1 after a failover, the volume stays where it took over
  (`status.primary`) until `node` names that node; it never goes back by itself to the old
  copy. `sync` is at least `10s`.
- A node that comes back after its volume moved is not given it back. If it is later picked
  to hold a copy, what it still had is kept beside the copy as `PATH.was-TIME`, not deleted.
- Not yet: each sync reads the whole volume and sends all of it when anything changed, so
  this is for data of modest size; a volume with replicas cannot be `shared` or in
  `kith-system`; a node sends one copy at a time; `PATH.was-TIME` directories are yours to
  delete; a replica that never synced takes nothing over (the volume waits for its
  node); moving a volume back is done by hand.
- A restore of a Backup and a replica's first copy and each sync unpack no more than the
  Volume's `size`, and stop with an error (the Volume left empty, or the replica's old copy
  as it was) when what arrives passes it: each file, directory and link is counted at the
  blocks it takes (4 KiB at least, so a Volume of very many small files counts as more than
  the sum of their lengths), a sparse file at its whole length, and what is downloaded stops
  at twice the `size` and 1 MiB. A Volume with no `size` is not capped, and nothing limits
  the directory itself (no quota, no count of inodes): a Volume that takes more than its
  `size` this way cannot be restored from its own Backup.

### Encrypted volumes

A Volume can be kept encrypted on its node's disk, with its key held by the other nodes:

```yaml
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: vault }
spec:
  node: alpha
  path: data
  size: 20Gi        # needed: the volume has all of it from the start (8Mi at least)
  encrypted: true   # said when the Volume is made
```

- On its node the volume is one file of that size, opened through dm-crypt (aes-xts, a
  512-bit key) and mounted where the volume's directory would be. Workloads mount it like
  any volume.
- **The key is never on the volume's node's disk.** That node makes it; every other node
  keeps a copy in its own state and hands it to the volume's node alone, over the cluster's
  mutual TLS, whenever that node has to open the volume (each start). A disk taken from the
  node has the file and no key. **When a node's disk is lost, delete its Node** (`kith
  delete node/NAME`), or `kith node lock NAME` if its state is encrypted: the others then
  hand its volumes' keys to nobody. Until then, whoever has the disk and can reach the
  cluster with it could ask as that node. Nodes that join later are given the key
  within a few minutes, so the volume outlives the nodes that kept it first.
- Until it is open, a workload that mounts it does not start and says so (`volume vault: it
  is encrypted and not open`); the node's log says what it waits for. Nothing is ever
  written in its place in the clear.
- A key is made only for a volume that has no file yet, and only once another node keeps
  it. **A cluster of one node cannot have an encrypted volume**: nobody else would hold
  the key. If every node that keeps the key is gone, so is the volume.
- What it does not do (ponytail): the other nodes keep the key as it is, so someone with
  the volume's node's disk *and* another node's disk can open it, unless that other node's
  state is [encrypted too](os.md#encrypted-state). A Backup or an Image of the
  volume is what was in it, not encrypted by this (a Share of one is untried). An encrypted volume cannot be
  `shared`, have `replicas`, or be in `kith-system`; it is not resized after it is made,
  and a directory that already has files is not encrypted in place (move them away, make
  the volume, copy them in). Taking `encrypted: true` away again does not decrypt it: the
  node refuses the volume while its encrypted file is there. Its file and the others' copies of its key stay when the
  Volume is deleted. It needs kith OS (which carries the file system a volume starts as:
  a node has no mkfs). Why one is not open is in the node's log, not yet in the Volume's
  status. Tested in VMs (`sh ci/vm.sh --test share`): made on one node with its key on the
  other, no file system to be seen on the node's disk, opened again after a restart with
  what was written still in it.

### Blobs

Bytes the cluster keeps by what they are, on more than one node:

```sh
kith blob put backup.tar          # prints the name the bytes are kept under
kith blob get NAME -o backup.tar  # from any node, whichever nodes hold them
```

- A blob's name is the first 62 hex digits of the BLAKE3 hash of its bytes (what `b3sum`
  prints, less its last two digits: a resource's name is at most 63 long). The same bytes
  put twice, by anyone and in any namespace, are one file on a node.
- `put` makes a `Blob` resource (`spec.size`, `spec.copies`: on how many nodes, 2 unless
  `--copies` says). Every node works out the same holders from the name and the nodes it
  hears from, fetches what it should hold from a node that has it over the cluster's mutual
  TLS, and writes itself into the Blob's `status.nodes`. A copy whose bytes do not hash to
  its name is thrown away, and so is an upload that ends early.
- `get` on a node that holds none of it passes on the bytes of one that does. Reading needs
  `get` on `Blob` in its namespace, putting needs `apply`.
  A Blob cannot be made with `kith apply`: only putting the bytes makes one, so knowing a
  blob's name does not let another namespace read it.
- When a holder is not heard from for a minute, another node takes its place and fetches a
  copy. The node a blob was put on keeps it until the holders say they have it.
- `kith delete blob NAME` forgets it; a node removes a file that no Blob names once it is
  ten minutes old.
- `put` answers once the bytes are on the node it was asked on; the other copies follow
  within seconds. Until a second node is in `status.nodes`, that node's disk is the only
  place they are.
- Not yet: only Backups and Images keep what they hold as blobs (pulled images, packages
  and revisions are kept as before); a
  blob passes through the CLI's memory whole; no size limit or quota but the disk; a holder
  does not read its copies again to find one the disk has spoiled.

### Files in and out of a volume

```sh
kith volume put data ./nextcloud-data    # what is in the directory, into the Volume `data`
kith volume put data ./config.php        # or one file, under its name
kith volume get data ./copy              # what is in the Volume, into a directory
tar -cf - -C /srv/app . | kith volume put data -   # a tar you make yourself (`get … -` writes one)
```

- Any node is asked; the node that has the Volume does it, and the files cross as one tar
  stream, never held whole in memory or on a second disk. `-n NAMESPACE` as elsewhere.
  `kith` runs the machine's own `tar` to pack and unpack (with `-` as the path it needs
  none).
- A put adds to what is there: a file takes the place of one with its name, a directory
  is gone into, nothing else is touched. It all arrives first in a directory `.kith-put`
  inside the Volume and is moved in when the whole stream was good, so a put that is
  refused or cut short leaves the Volume as it was. A running container that mounts the
  Volume sees the files appear, and one that changes the Volume's directories at that
  moment can leave a put half moved in (the put says so): stop it first.
- Files, directories, links and hard links go in, with their modes (less setuid and
  setgid) and times. Their owner is not carried: they are made the user's that the
  Volume's directory is, which is the user of the container that mounts it (see
  [What a container is kept from](workloads.md#what-a-container-is-kept-from)), so the app reads what
  you put.
- Refused, with the name of the entry: a path that leaves the Volume (`..`, or one that
  starts at the root), a path through a link, a device, a pipe, a sparse file (pack
  without `--sparse`), a file where the Volume has a directory of that name or the other
  way round, more bytes than the Volume's `size` when it says one, and whatever would
  leave the node's disk with less than 64 MiB free. A link that points out of the Volume
  (`/etc/localtime`, `../../elsewhere`), or that goes up after it has gone down
  (`a/../b`), is left out, and the reply names each.
- Both need `apply` on `Volume` and on `Workload` in the namespace: whoever may run a
  workload that mounts the Volume reads and writes the same files. Each put, and each get
  as it starts, is in the audit log with who asked. A Volume in `kith-system` is a
  directory of the host's and is neither read nor written this way.
- A get gives the files as the Volume has them, written by whatever ran there: unpack it
  as an ordinary user, not as root, which would keep their owners and setuid bits.
- Not yet: no path inside the Volume to put into or get from (it is the whole Volume);
  one put at a time on a node; a get is of the directory as it is while it is read, like a
  backup.

### Backups

A `Backup` archives a Volume every so often and keeps the last few:

```yaml
apiVersion: kith.dev/v1
kind: Backup
metadata: { name: nightly }
spec:
  volume: data      # a Volume in this namespace
  every: 24h        # a number and s, m, h or d
  keep: 7           # how many are kept (7 unless said)
```

- The node the volume is on makes a tar of its directory when one is due and keeps it as a
  blob, so it is on other nodes too (`copies`, 2 unless said). `status.backups` lists them,
  oldest first: `at` (seconds since 1970), `size`, and the `blob`. Two backups with nothing
  changed between them are one blob.
- To an S3-compatible bucket instead:

  ```yaml
  spec:
    volume: data
    every: 24h
    s3:
      endpoint: https://s3.example.org   # objects are endpoint/bucket/prefix…
      bucket: backups
      prefix: kith/                      # optional
      region: us-east-1                  # optional
      secret: s3-keys                    # a Secret here with accessKey and secretKey
  ```

  Requests are signed (AWS Signature Version 4) and go over `https://` only. The endpoint
  may be on the internet or the LAN (a NAS), not on the node itself, a link-local address
  or the cluster's mesh; redirects are not followed. Whoever may apply a Backup in a
  namespace chooses where that namespace's volumes are sent. Each backup is the object `PREFIX NAMESPACE/NAME-TIME.tar`.
- `kith backup restore NAME [--at SECONDS]` unpacks one (the last unless said) into the
  volume, on the volume's node, whichever node is asked. The volume must be empty: nothing
  is written over. It needs `apply` on `Backup` and on `Volume` in the namespace.
- Applying a Backup needs `get` on `Volume` and `Secret` in the namespace as well as
  `apply` on `Backup`: it sends the one where it says, with the other's keys.
- Restored files keep their owner, mode and times, less setuid and setgid.
- An archive holds the volume's files, directories and links. A link is kept as a link
  and never followed, also when a program in the volume puts one where a file was while
  the archive is made. Pipes, sockets and device files are left out. A volume more than
  128 directories deep, or with a file kithd cannot read, is not archived: the Backup's
  status says which.
- A backup that fails says why in `status.message` and is tried again in ten minutes.
- Not yet: the archive is of the directory as it is while it is read (what a crash at that
  moment would leave), not of a snapshot: stop what writes to it for a backup that must be
  exact. Each backup is whole, not what changed. It is not encrypted beyond TLS to the
  bucket and the cluster's own TLS. Stop the workloads that use a volume before restoring it. An
  archive goes to a bucket in one request (5 GiB at most on Amazon's S3). Deleting a Backup
  leaves the blobs and objects it made.

### Images made in the cluster

The cluster can build a container image and run it without asking any registry outside it.
A build is an ordinary Job that leaves the image's files in a Volume; an `Image` is that
volume, packed:

```yaml
apiVersion: kith.dev/v1
kind: Image
metadata: { name: hello }
spec:
  volume: hello-root          # its directory is the image's root
  job: hello-build            # made when this Job has succeeded (leave out: made at once)
  tag: "1"                    # latest, unless said
  entrypoint: [/bin/hello]    # and cmd, env (NAME=value), workingDir
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: hello }
spec:
  template:
    containers: [{ name: run, image: "localhost:5000/default/hello:1" }]
```

- The volume's node packs the directory as the image's one layer and keeps the layer, the
  image's config and its manifest as Blobs (`copies` nodes hold them, 2 unless said).
  `kith get image hello -o yaml` has the `digest` when it is made, or a `message` saying why
  it was not (tried again every minute).
- **The registry.** Every node's kithd serves the cluster's Images to itself, on
  `127.0.0.1:5000` (`--registry-port`; 0 turns it off), as an OCI registry that can only be
  read: `localhost:5000/NAMESPACE/NAME:TAG` (or `127.0.0.1:5000/…`) is the Image `NAME` of
  `NAMESPACE` on whichever node runs it, fetched from a node that holds its Blobs. It
  answers kithd's own pull and nothing else on the node: it speaks TLS under a certificate
  kithd makes for each start and wants that start's password, and both stay in kithd's
  memory. So `docker pull localhost:5000/default/hello:1` on a node gets nothing (the
  Image's status names its Blobs, and `kith blob get` reads one, for who may). Another
  registry on `localhost`, at another port, is still asked without TLS, as container
  tools do.
- **The `kith-build` package** renders the three pieces from a few values: a Volume on the
  node you name, a Job that runs your script in a builder image with the volume at `/out`
  (as root, `runAsUser: 0`: an image's files belong to whoever its build gives them to),
  and the Image.

  ```sh
  kith package render packages/kith-build --name hello --set node=n1 \
      --set builder=registry.example/tools:1 --set tag=2 --set 'entrypoint=[/hello]' \
      --set 'script=cc -static -o /out/hello /src/hello.c' | kith apply -f -
  ```

  The builder can be an image built this way before, so a cluster that has one image with
  tools in it needs nothing from outside for the next.
- Nothing privileged builds: no daemon, no nested containers. The steps are a Job's
  containers, sandboxed like any other, and packing is reading a directory (a link in it
  stays a link).
- An Image is made once for its spec and for a run of its Job: change the Job and it is
  made again when the Job has succeeded again. A node keeps a tag it has pulled, so give
  what should roll out a new tag (the tag it had is then served no more). A Job deleted
  and applied again just as it was is not seen as a new run: change the tag.
- Who may: writing an Image takes leave to read its Volume (checked on `kith apply` and a
  rollback; an Image a Release renders is written by the release, as a Backup is). What
  runs in a namespace runs that namespace's Images only: a template in `web` that names
  `localhost:5000/default/hello:1` is not started, and its status says whose Image that
  is (make the Image in the namespace that runs it). Nothing else on a node is given an
  Image: not its other processes, nor its containers (see the registry, above).
- Not yet (ponytail): a base image under the layer (`FROM`): the volume holds the whole
  root, programs with their libraries or static ones; Dockerfiles; pushing into the
  registry with `docker push`; a registry other machines can reach; deleting an Image
  leaves its Blobs (`kith delete blob`); an Image that waits for its Volume or its Job says
  nothing in its status. Tested: a Job fills a Volume, the Image is made, the registry
  serves it and a Job whose container is that image runs it, on one node; not tested: a
  pull on another node than the one that built (the Blobs travel as any Blob does), and
  building kith OS this way.

### Remote apps

`kith run --on NODE|SELECTOR [--via PROGRAM] -- APP [ARGS…]` runs a
graphical app on another node and opens its window on this machine, through
[waypipe](https://gitlab.freedesktop.org/mstoeckl/waypipe) over the mesh.
`--on` is a node's name, or labels (`role=display,zone=lab`) for the first ready Node,
by name, that has them. `--via` names the program that carries the window (default
`waypipe`). The app's command line is passed as it is written, never through a shell.

- **waypipe must be installed on both ends** (here, and on the node that runs the app):
  kith does not ship it. A missing program is refused with its name and the node's.
- **The windows are tagged for your compositor as a sandboxed program's** (`waypipe
  --secctx dev.kith.run`, Wayland's security-context-v1), so that it keeps them from what
  it keeps such a program from: reading the screen, typing as you. A waypipe before 0.9,
  a compositor without that protocol or another `--via` program does not take the tag:
  the app is then started without it, and `kith run` says so and why. What was seen,
  in a container: with waypipe 0.11 under sway 1.12 the app's window has
  `sandbox_engine` `waypipe` and `sandbox_app_id` `dev.kith.run` in `swaymsg -t
  get_tree` (a window carried without the tag has neither), and sway offers that
  program, through waypipe, 35 of the 53 interfaces it offers another: not screen capture, the clipboard
  managers, virtual keyboards and pointers, input methods, the layer shell or the
  session lock. Under cage 0.3, which has no such protocol, and with waypipe 0.8, which
  has no such option, waypipe stops before it listens: that is what `kith run` takes
  for "no tag". What is kept from a tagged program is each compositor's own to decide
  (sway 1.10 has the protocol, and its tree does not show the tag).
- **Who may:** only who may run the node itself: a Role rule with `verbs: [exec]` on
  `kinds: [Node]` and no `namespaces` (`admin` has it). The app runs as kithd's user on
  the node, outside any container, so a right in one namespace is never enough. It is
  checked on the node you ask, before anything starts or is forwarded. The other node
  accepts the hop only from a cluster node, never from a client token, asks its own
  store whether the caller that node names may, and writes its own audit entry
  (`GET /v1/audit`) with both names (`alice via node a`). It takes the first node's word
  for who asked (see SECURITY.md).
- **How:** the `kith` command asks its kithd for a tunnel (`POST /v1/run`); kithd runs the app
  there with `waypipe --socket S server -- APP…`, S in a private (0700) directory with a name
  nobody can guess, and joins it to the tunnel; `kith` runs `waypipe --socket L client` and
  joins L to the other end. Either end closing kills the carrier, the app
  and what the app started (their process group).
- The command line is written to the audit log as it is: do not pass a secret on it.
  A node of the cluster is trusted by the others: the node you ask tells the other who
  asked, and the other runs it.
- Not yet: a node that vanishes without a word (powered off) leaves an idle app running
  on the other until something is written to it; one `kith run` carries one connection of the app; the app's exit status is not
  returned; an interrupt (Ctrl-C) leaves an empty directory in the temp dir.
