# Storage

A `Volume` is a directory on one node. A container mounts one by naming it, or a `VolumeClaim`
bound to one, in its `volumeMounts`:

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

- The workload runs on the volume's node only, unless the volume is `shared` (below). Volumes on
  two nodes, or a `DeviceClaim` on another node, leave it unplaced (`unschedulable` says why).
- A claim takes the first Volume (by name) of its namespace that is free, big enough, on a node
  matching its `selector`, and `shared` if the claim asks (`status.volume` and `status.message`
  show the pairing). If its Volume is deleted it takes no other: make the Volume again, or
  delete the claim and apply it again.
- `provision: true` on a claim with no Volume makes one of its name and size on the ready node
  with the fewest Volumes. Whoever applies such a claim must be allowed to apply a Volume.
- Deleting a claim that provisioned its Volume deletes the Volume and its data on its node
  (only the directory kithd made for it; a link inside that points elsewhere is removed, not
  followed), as Kubernetes does by default. To keep the data, put the annotation
  `kith.dev/reclaim: retain` on the claim: the Volume goes and its directory stays, and a later
  claim of the same name that provisions finds that data in its place. A Volume you applied
  yourself is never deleted with a claim, nor is its data: it is free again for another claim.
- The container sees a bind mount (`readOnly: true` for read-only) of
  `<state>/volumes/<namespace>/<name>/<path>`. `path` must be relative, with no `..` or symbolic
  link in it (in `kith-system`, an absolute host path). A container path that is relative, has
  `..`, or is `/`, `/proc`, `/sys` or `/dev` (or under them) stops the unit.
- Not yet: `subvolume: true` makes a plain directory; `size` is no quota; an `exec` unit and a
  NodeWorkload mount nothing.

### A claim for each replica

A mount with `perReplica: true` names the *base* of a claim, and replica `i` mounts the claim
(or Volume) `<volume>-<i>`: the claim of a StatefulSet's `volumeClaimTemplates`, which the
Kubernetes layer makes for each replica (`data-db-0`, `data-db-1`, ...).

```yaml
volumeMounts: [{ volume: data-db, perReplica: true, path: /var/lib/db }]
```

- Each replica is placed on the node of its own Volume, so three replicas can be on three nodes.
  A plain mount beside it still puts all of them on its one node.
- A replica whose claim has no Volume, or whose Volume's node is gone, waits (`unschedulable`
  says why) and is never started on an empty directory elsewhere. The others go on.
- Scaling down removes no claim and no data; scaling up again finds them. Deleting a claim is
  what removes its Volume, as above. A claim deleted while its replica is still there is not
  made again until the StatefulSet is applied again, so that replica waits until then. Moving a
  Volume's data to another node is not done.

### Shared volumes

`shared: true` on a Volume lets a workload that mounts it run on any node:

```yaml
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: media }
spec: { node: n1, path: media, shared: true }
```

- The data stays on `n1`; a replica elsewhere mounts it over the mesh (NFS 4.2 over WireGuard)
  under `<state>/remote/n1/<namespace>/<name>`. A workload that also mounts an unshared volume
  goes to that volume's node. Only the cluster's nodes can reach it; a container gets nothing,
  and every node is trusted with it as root.
- It takes the mesh (`--mesh`) and a kernel with the NFS server and NFS 4.2 client (kith OS has
  them); kithd drives the kernel itself and leaves a machine's own NFS server alone. While the
  volume's node is away, a container using it from another node waits (a `hard` mount).
- Not yet: `kith-system`, VMs and non-node machines cannot use one; the data is not copied.

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

- **NFS** is served by the volume's node (NFS 4.2, port 2049 of its IPv4 addresses) to the
  addresses in `nfs.clients` only, never the cluster's nodes. `kith get share films -o yaml`
  says the `node` and `path`; on a client, `mount -t nfs4 NODE:PATH /mnt`. Every client is the
  Share's `uid` and `gid` on the files (nobody, 65534, unless you say: name the user a container
  on the volume runs as). One Share gives a volume over NFS (the first by name).
- **SMB** is a Samba container the `nas` package runs on the volume's node (port 445):

  ```sh
  kith apply -f passwords.yaml    # a Secret with a password under each user's name
  kith package render packages/nas --name films \
      --set volume=media --set 'users=[ada,grace]' --set passwords=nas-passwords \
      --set image=registry.example/nas/samba:1 | kith apply -f -
  ```

  The package makes the Share too (`--set 'nfs.clients=[192.168.1.0/24]'` for NFS beside it).
  kith ships no Samba image: name one you trust, with Samba 4.15 or later and `nss_wrapper`.
- A Share's `status` says why it is given to nobody. Applying one takes leave to apply its
  Volume.
- Not yet: NFS trusts an address (no Kerberos), so name single addresses or a network you trust
  (wider than a /8 is refused); IPv6 clients are not served; SMB users all write as one user, on
  port 445 of every address (one `nas` release a node); a `kith-system` Volume cannot be given;
  **the Samba half has been rendered and its start script run against stand-ins, not run with a
  real Samba here**.

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

- The cluster picks the other nodes (`status.replicas`). Every `sync` (at least `10s`), each
  fetches the directory from the node that has the volume (`status.primary`) over the cluster's
  mutual TLS and replaces its own copy; `status.synced` says when.
- When the primary is not heard from for `--lost-after`, the replica that synced last becomes
  primary and workloads that mount the volume are placed there. A node that comes back is not
  given the volume back; what it had is kept beside it as `.PATH.was-TIME`, a hidden name (yours to
  delete).
- **A failover loses what was written after the last sync**, and a copy is the directory as read
  while in use: a database caught mid-write may need its own recovery.
- A restore, a replica's first copy and each sync unpack no more than the Volume's `size` and
  stop with an error when more arrives (no `size`, no cap: a Volume that outgrows it cannot be
  restored from its own Backup).
- Not yet: each sync sends the whole volume, so this is for modest data; it cannot be `shared`
  or in `kith-system`; moving a volume back is by hand.

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

- On its node the volume is one file of that size, opened through dm-crypt (aes-xts, a 512-bit
  key) and mounted where the volume's directory would be.
- **The key is never on the volume's node's disk.** Every other node keeps a copy and hands it
  to the volume's node alone, over the cluster's mutual TLS, each time that node opens the
  volume. A disk taken from the node has the file and no key. **When a node's disk is lost,
  delete its Node** (`kith delete node/NAME`), or `kith node lock NAME` if its state is
  encrypted: the others then hand its keys to nobody.
- Until it is open, a workload that mounts it does not start and says so. **A cluster of one
  node cannot have an encrypted volume**; if every node that keeps the key is gone, so is the
  volume.
- Not yet: someone with the volume's node's disk *and* another node's disk can open it, unless
  that node's state is [encrypted too](os.md#encrypted-state). A Backup or an Image of it is not
  encrypted. It cannot be `shared`, have `replicas`, or be in `kith-system`; it is not resized;
  it needs kith OS. Tested in VMs (`sh ci/vm.sh --test share`).

### Blobs

Bytes the cluster keeps by what they are, on more than one node:

```sh
kith blob put backup.tar          # prints the name the bytes are kept under
kith blob get NAME -o backup.tar  # from any node, whichever nodes hold them
```

- A blob's name is the first 62 hex digits of the BLAKE3 hash of its bytes, so the same bytes
  put twice are one file. `put` makes a `Blob` resource (`spec.copies`: 2 unless `--copies`
  says) and answers once the bytes are on the node asked; the other holders fetch them within
  seconds over the cluster's mutual TLS and write themselves into `status.nodes`. A copy that
  does not hash to its name is thrown away; a holder not heard from for a minute is replaced.
- Reading needs `get` on `Blob` in its namespace, putting needs `apply`; a Blob cannot be made
  with `kith apply`, so knowing a name lets no other namespace read it.
- Not yet: a blob passes through the CLI's memory whole; no size limit but the disk.

### Files in and out of a volume

```sh
kith volume put data ./nextcloud-data    # what is in the directory, into the Volume `data`
kith volume put data ./config.php        # or one file, under its name
kith volume get data ./copy              # what is in the Volume, into a directory
tar -cf - -C /srv/app . | kith volume put data -   # a tar you make yourself (`get … -` writes one)
```

- The node that has the Volume does it, whichever node is asked, as one tar stream (`kith` runs
  the machine's own `tar`). A put adds to what is there: a file replaces one of its name,
  nothing else is touched. It arrives first in `.kith-put` and is moved in when the whole stream
  was good, so a refused or cut-short put leaves the Volume as it was. A running container that
  changes the Volume's directories meanwhile can leave a put half moved in: stop it first.
- Files, directories, links and hard links go in, with modes (less setuid and setgid) and times.
  The owner is not carried: they are the user's that the Volume's directory is, the user of the
  container that mounts it (see [What a container is kept
  from](workloads.md#what-a-container-is-kept-from)).
- Refused, with the entry's name: a path that leaves the Volume or goes through a link, a
  device, a pipe, a sparse file, a file where the Volume has a directory or the other way round,
  more bytes than the Volume's `size`, and whatever would leave the node's disk under 64 MiB
  free. A link that points out of the Volume is left out, and the reply names each.
- Both need `apply` on `Volume` and on `Workload` in the namespace: whoever may run a workload
  that mounts the Volume reads and writes the same files. Each is in the audit log. A
  `kith-system` Volume is neither read nor written this way. Unpack a get as an ordinary user,
  not root, which would keep the owners and setuid bits of whatever ran there.
- Not yet: no path inside the Volume to put into or get from.

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

- The node the volume is on makes a tar of its directory when one is due and keeps it as a blob
  (`copies`, 2 unless said). `status.backups` lists them, oldest first (`at`, `size`, `blob`).
  One that fails says why in `status.message` and is tried again in ten minutes.
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

  Requests are signed (AWS Signature Version 4) and go over `https://` only, to the internet or
  the LAN, not to the node itself, a link-local address or the mesh; redirects are not followed.
  Whoever may apply a Backup chooses where the volumes go, so it needs `get` on `Volume` and
  `Secret` as well as `apply` on `Backup`.
- `kith backup restore NAME [--at SECONDS]` unpacks one (the last unless said) into the volume,
  on its node, whichever node is asked. The volume must be empty. It needs `apply` on `Backup`
  and `Volume`. Files keep their owner, mode and times, less setuid and setgid.
- An archive holds files, directories and links (never followed); pipes, sockets and devices are
  left out. A volume more than 128 directories deep, or with a file kithd cannot read, is not
  archived: the Backup's status says which.
- Not yet: the archive is of the directory as it is while read, not a snapshot: stop what writes
  to it for an exact backup, and the workloads that use a volume before restoring it. Each
  backup is whole, and not encrypted beyond TLS. Deleting a Backup leaves what it made.

### Images made in the cluster

The cluster can build a container image and run it with no registry outside it. A build is a Job
that leaves the image's files in a Volume; an `Image` is that volume, packed:

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

- The volume's node packs the directory as the image's one layer and keeps it as Blobs. `kith
  get image hello -o yaml` has the `digest` when it is made, or a `message` saying why not.
- **The registry** is on `127.0.0.1:5000` of every node (`--registry-port`; 0 turns it off), a
  read-only OCI registry: `localhost:5000/NAMESPACE/NAME:TAG` is the Image `NAME` of
  `NAMESPACE`. It answers kithd's own pull and nothing else on the node: it speaks TLS under a
  certificate and a password that kithd makes for each start, so `docker pull` on a node gets
  nothing.
- **The `kith-build` package** renders a Volume on the node you name, a Job that runs your
  script in a builder image with the volume at `/out` (as root), and the Image. Nothing
  privileged builds: no daemon, no nested containers.

  ```sh
  kith package render packages/kith-build --name hello --set node=n1 \
      --set builder=registry.example/tools:1 --set tag=2 --set 'entrypoint=[/hello]' \
      --set 'script=cc -static -o /out/hello /src/hello.c' | kith apply -f -
  ```

- An Image is made once per spec and Job run; a node keeps a tag it has pulled, so give what
  should roll out a new tag.
- What runs in a namespace runs that namespace's Images only: a template in `web` naming
  `localhost:5000/default/hello:1` is not started, and says why. Writing an Image takes leave to
  read its Volume.
- Not yet: a base image under the layer (`FROM`); Dockerfiles; `docker push`; a registry other
  machines can reach; deleting an Image leaves its Blobs. Not tested: a pull on another node.

### Remote apps

`kith run --on NODE|SELECTOR [--via PROGRAM] -- APP [ARGS…]` runs a graphical app on another
node and opens its window on this machine, through
[waypipe](https://gitlab.freedesktop.org/mstoeckl/waypipe) over the mesh. `--on` is a node's
name, or labels (`role=display,zone=lab`) for the first ready Node, by name, that has them;
`--via` names the program that carries the window (default `waypipe`). The command line is
passed as written, never through a shell.

- **waypipe must be installed on both ends** (kith does not ship it). The windows are tagged for
  your compositor as a sandboxed program's (`waypipe --secctx dev.kith.run`, Wayland's
  security-context-v1), so that it keeps them from reading the screen or typing as you. A
  waypipe before 0.9, a compositor without that protocol or another `--via` program does not
  take the tag: the app then starts without it, and `kith run` says so.
- **Who may:** only who may run the node itself: a Role rule with `verbs: [exec]` on `kinds:
  [Node]` and no `namespaces` (`admin` has it). The app runs as kithd's user on the node,
  outside any container, so a right in one namespace is never enough. It is checked on the node
  you ask; the other node accepts the hop only from a cluster node, asks its own store whether
  the caller may, and writes its own audit entry with both names (it takes the first node's word
  for who asked: see SECURITY.md).
- **How:** `kith` asks its kithd for a tunnel (`POST /v1/run`); kithd runs the app under
  `waypipe server`, `kith` runs `waypipe client`, and the two are joined. Either end closing
  kills the app and what it started. The command line is in the audit log: pass no secret.
- Not yet: a node that vanishes without a word leaves an idle app running on the other; one
  `kith run` carries one connection; the app's exit status is not returned.
