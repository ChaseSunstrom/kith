# Security

## Reporting a vulnerability

Report it in private, through GitHub: the repository's **Security** tab, then
**Report a vulnerability** (GitHub's private vulnerability reporting is on for this
repository). Say what you did, what happened, and which commit or version it was. Please
do not open a public issue for something that lets one party cross one of the boundaries
below.

kith is maintained by one person, and nobody promises an answer by a certain day. A
report is read, answered in that private thread, and fixed in `main`; the fix's commit
says what it was.

Only the newest version is fixed. There are no security releases of older ones.

## Who is trusted with what

| Who | How kith knows them | What they can do |
| --- | --- | --- |
| The admin of a node | Whoever can open kithd's unix socket (mode 0600, kithd's user) | Everything in the cluster |
| A node | A certificate of the cluster's CA for `NAME.node.kith`, while its Node is in the store and names that certificate's key | A control node (what a node is unless its Node says `trust: worker`): everything in the cluster. Control nodes replicate the whole store, Secrets included, and run what they are told: **a control node is trusted as much as the admin.** A worker: what is placed on it, what every node reads to run a cluster, and to write what it says of itself (see "A node that is taken") |
| An Identity | A certificate for `NAME.user.kith` whose key is the one in its `Identity` | What its Roles say, by kind, verb and namespace |
| A workload | Nothing: it is a process on a node | What its container, machine or sandbox lets it reach (see "What is not defended") |
| Anyone who reaches a node's port | Nothing | Fetch the CA certificate, spend a join token, ask for a locked disk's key by its id |
| Whoever writes what kith fetches | Nothing by itself | What follows from it: a Source's repository is applied, a package is rendered, an image is run, an archive is restored |

## The boundaries, as they are in the code

- **A node's port (`--listen`, TLS).** Four routes take a caller with no certificate, and
  bodies of at most 4 KiB: the CA certificate, joining with a token, claiming an Identity
  with a token, and asking for a disk's key. (The web UI's pages are served to anyone
  too: they are the same files for everyone, and what they show they ask the API for.)
  A connection holds one of 64 slots until it has shown a certificate, and one that
  shows none for at most 15 seconds; one address (an IPv4 address, an IPv6 /64) holds
  at most 8 of them. The node's own loopback is not counted.
- **The API** is behind a layer that works out who calls (the socket, a node, an
  Identity) and refuses what their Roles do not allow. A token is shown once, kept only
  as a hash, good for an hour, and spent by its first use.
- **A node's certificate has no right of its own on the API**: it reads nothing and
  writes nothing there. What a node does there is pass on what someone asked it, to the
  node that has the thing: a unit's output, a Volume's files, a node's passphrase, a
  backup's restore. It names who asked (a header, `x-kith-for`), and the node that gets
  the request asks its own store what that caller may do, and writes both in its audit
  log (`alice via node a`). The header is read on those four requests and from a node
  only: sent by an Identity, or anywhere else, it changes nothing. `kith run` is passed
  to the node the app is for on the node-to-node routes, with who asked in the request,
  and checked the same way there.
  **A control node's word for who asked is taken**: one that is taken can name the local
  socket, so this narrows nothing for it. A worker's word (`spec.trust: worker` on its
  Node) is not taken: what it passes on is refused whoever it names (see "A node that
  is taken").
- **Node-to-node routes** (Raft, copies of blobs and volumes, a volume's key, running a
  command on another node) take a node's certificate only, and, like the API, only
  while that node's Node is in the store: each request is asked again.
- **What a node fetches or sends for someone who is not the admin** (a Source's
  repository, a package pushed to a registry, a `DNSBlockList`'s `url`) goes only to
  addresses that are not this node's own or on its networks, each redirect and each place a registry sends an upload
  included, and to the address that was checked, not to the name looked up again. So the
  API is not a way to reach what only the node can reach.
- **A container** runs as a user that is not root (its template's, its image's, or
  nobody), with no capabilities (on kith OS, the one to take a port below 1024) and
  `no_new_privs`, on a read-only image, behind a seccomp filter that refuses some forty
  system calls: mounting, new namespaces, loading modules, bpf, perf, io_uring, keyrings,
  another process's memory, the clock. An image that names root as its user gets nobody.
  A container whose template says `userNamespaces: true` (off unless said: a sandbox
  inside it, as Steam's runtime and Flatpak start) may make namespaces and mount in them,
  and nothing in its `/proc` is covered; it is refused to a container that is the node's
  root.
  On kith OS each container's cgroup has a device filter (a BPF program kithd loads; the
  kernel asks it at every open and `mknod` of a device node): the few nodes every
  container has, its own terminals, and the devices its claims gave it, to read and
  write. A container whose filter does not load is not started. It says nothing of what
  a device does once open, and nothing of an `exec` unit, which is a process of the host.
  Where kithd is not root there is none: the user namespace a container is in there
  makes no device nodes.
- **A pod** (a template that says `pod: true`, and so every Deployment, StatefulSet,
  DaemonSet and Job sent through the Kubernetes API) is a container with three of those
  taken off, as Kubernetes has them: it is the user its image names, root included; root
  there has the fourteen capabilities a container runtime gives by default, and no
  other; and its root file system is its own to write. It keeps `no_new_privs`, the
  seccomp filter and its namespaces, and has a network namespace of its own.
- **The Kubernetes API** (`/api`, `/apis`) is behind the same layer as `/v1`. A request
  is checked as the kith kind and namespace it comes to, by the Roles of the
  certificate's Identity; a write is asked for before anything is said of what is
  there, and a patch, which is answered with the whole object, also needs the right to
  read it. Kubernetes's own Roles, bindings and ServiceAccounts are kept as text and
  give nothing; a pod is given no token and no API to ask. `privileged`, the host's
  namespaces, `hostPath` and added capabilities have no field in kith, and an object
  that asks for one is refused by its name. Of a body in protobuf 50,000 fields are read.
- **What a resource makes for itself is asked for with it.** Whoever writes a CronJob
  must be allowed to write a Job, and whoever writes a claim that says `provision`
  (every PersistentVolumeClaim does, unless it names no storage class) a Volume.
- **An image whose template names keys** (`signedBy`) is run only if one of them signed
  its manifest's digest, which is found out before a layer is fetched; every layer is
  then fetched by the digest that manifest names. An image already on the node counts as
  signed only by keys it was checked against there.
- **Packages** are taken only with a signature over their name, version and hash, by a
  key the cluster was told to trust; there is no unsigned way in. A package's WebAssembly
  runs with limits on memory and time, and its templates with limits on size. A
  template in kith's own language (`.kith`) is evaluated inside kithd: it ends in
  500,000 steps, nested 3,000 deep and 1 MB of output or is refused, and it can read
  the package's own `templates/` and nothing else (no file of the node, no time, no
  network).
- **kith OS updates** are taken only with a signature, and never to an older version.
- **The node's own registry** (`127.0.0.1:5000`, the cluster's Images) answers that
  node's kithd and nothing else on the node, though every process and container of the
  node can connect to it. For each start kithd makes a password and, when the registry
  is first asked, a certificate, keeps both in its memory (no file, no argument, no
  container's environment) and gives them to its own pull alone: the registry speaks only TLS under that certificate and says
  nothing but 401 to a request without the password, whatever it asks for. The pull
  trusts that one certificate and sends the password only to `localhost` or `127.0.0.1`
  at the registry's own port, so neither what is pulled nor the password is read off the
  loopback (by a container that is the node's root, say; that a pull happens, and how
  large, still shows) and a process that takes the port in kithd's place learns no
  password. Its connections, shaken or not, are at most 64 at a time, and one on which no
  byte moves for 5 s after its handshake is closed; so a process of the node can still take
  the registry's slots in turn, or keep one with a byte now and then, and slow Image pulls.
  Kithd's other listeners and its open-file limit are not bounded by this. And kithd pulls
  an Image only for what runs in the Image's own namespace: an Image is a packed Volume. Reading kithd's memory is being root on
  the node outside any container, which nothing here defends against.
- **A Volume's archive** (a Backup, an Image, a replica's copy) is read through directory
  handles that are held open: nothing in the volume is reached by a path the workload
  could point elsewhere meanwhile. When one is unpacked, no entry writes outside the
  volume; a restored Backup has no setuid or setgid file (a replica's copy keeps them
  as its volume had them). A restore, a replica's first copy and each sync unpack no more
  than the Volume's `size`, where it says one: the entries are counted as they come, each
  file, directory and link at the blocks it takes (4 KiB at least, so a Volume of very many
  small files counts as more than the sum of their lengths, and one that takes more than its
  `size` this way cannot be restored from its own Backup), a GNU sparse entry at the whole
  length it says (what the next archive of the Volume reads; the tar crate gives it as its
  size and unpacks it as a hole), and the unpack stops, with the Volume empty (or a
  replica's old copy as it was) and nothing beside it, at the entry that passes it. What is
  downloaded from a bucket or a primary stops at twice the `size` and 1 MiB, before any of
  it is unpacked. An unpack keeps each directory of the archive in memory until the end
  (well under 1 KiB each): bounded by the cap at one directory per 4 KiB of the Volume's
  `size`, and by nothing for a Volume with no `size`, which is not capped at all. There is
  no quota on the directory and no count of inodes. A restore from S3 that is refused
  leaves the downloaded archive (up to twice the `size` and 1 MiB) in the node's blob
  store until blobs are next cleaned up. A sync of a Volume that is gone from the store
  (or whose spec does not parse) takes nothing and says so.
- **A Volume's files over the API** (`kith volume put` and `get`) are for whoever may
  apply a Volume and a Workload in its namespace, checked on the node that is asked; the
  node that has the Volume takes the request from that node as it takes any other node's.
  What is sent is not trusted, and neither is what the Volume holds: each entry is made
  through a handle on its directory and never through a link (one the stream made, or
  one a running container puts in the way), in a directory inside the Volume that is
  moved in only when the whole stream was good (a container that changes the Volume's
  directories while a put moves in can leave it half moved, inside the Volume). A path
  that leaves the Volume, a device, a pipe and a sparse file are refused; a link that
  points out, or that goes up after it has gone down, is not made; setuid and
  setgid are dropped; the files are the Volume's user's, never the sender's choice. A put
  stops at the Volume's `size`, where it says one, and before the node's disk has less
  than 64 MiB free. A Volume in `kith-system` (a directory of the host's) is not served.
  What a get gives was written by whatever ran in the Volume: unpacked as root it keeps
  their owners and setuid bits.
- **An encrypted disk or Volume** cannot be read by whoever takes it out of its machine:
  the key is with the other nodes.

## What is not defended

These are how kith is today. Each is a decision or a gap that is known; plan around it.

- **Whoever may apply a Workload, a NodeWorkload or a Job runs code on the cluster's
  nodes.** A container is kept small by default (see "A container" above), and its
  template is where each of those defaults is taken off: `runAsUser: 0`, `seccomp: {
  unconfined: true }`, `pod: true`, `userNamespaces: true`. That last gives a user who is
  not root the kernel's code for a namespace's root (mounting, a network of its own),
  where much of what has made a user the node's root was found; the other refused calls
  stay refused inside. On kith OS there is no user namespace, so `runAsUser: 0`
  there is the node's root with three capabilities, and root in a pod is the node's root
  with fourteen (T-0280). One of the fourteen makes device nodes; the device filter on
  the pod's cgroup is what keeps it from the node's disks. Containers that are not pods
  share the node's network, and an
  `exec` unit is a process of kithd's user. The Roles decide who may apply these, and
  nothing more is in the way. Do not give them to someone you would not give a shell on
  the node.
- **Whoever may apply a Workload or a Job in a namespace reads that namespace's Secrets
  and ConfigMaps**, without the right to `get` them: a template names one in `env`, in
  `envFrom` or as files, and its container is given what it holds. (Another
  namespace's cannot be named.) A Secret given as files is written to memory only (kithd
  asks the kernel that the directory is on no disk, and refuses otherwise). Given in
  `env` or `envFrom` it is in the container's environment, which the node's root and the
  container's own user can read, and in the container's description that the runtime
  keeps in the node's state while it runs: on that disk, encrypted only where the
  state is. A ConfigMap's files are on the state disk too.
- **Whoever may apply a Volume and a Workload in a namespace reads and writes every
  file of that namespace's Volumes**, with `kith volume get` and `put` as with a workload
  that mounts them: an encrypted Volume's too, while it is open. A put's `size` bound
  counts the stream, not what the Volume holds already, so several puts fill a Volume
  (and its disk, down to the 64 MiB a put leaves) past it. One put runs at a time on a
  node, and one that sends a little every minute keeps the others waiting; a node packs
  four gets at once.
- **`kith import compose` carries a password as the file has it.** A variable in a compose
  file's `environment` is plain text in the Workload it prints, and in the store once that
  is applied, readable by whoever may `get` Workloads in the namespace. The import says
  which variables read as a secret; it does not make a Secret of them. It refuses what
  would give a container more than kith gives (`privileged`, capabilities, devices, the
  node's network, `/`, `/proc`, `/sys`, `/dev` and a docker socket as a volume, even in
  `kith-system`), and reads no variable of the shell it runs in.
- **A host read by path trusts its own namespace, and lets every client in.** Whoever may
  write a Service with `expose.paths` sends that host's requests to any Service and port
  of the same namespace, exposed or not. kith's edge asks no client who it is: an Ingress
  whose annotations did (`auth-*`, an allow list, a snippet) is refused, not translated
  into an open host. Toward a backend the client's own `Forwarded`, `X-Forwarded-*`,
  `X-Real-IP` and any header with `_` in its name are dropped and kith's put in their
  place; a backend reached some other way than the edge (from inside the mesh) gets none
  of that, and must not trust those headers from there.
- **A block list is trusted for the names it lists, by every client of the resolver.** A
  `DNSBlockList` is the cluster's (no namespace), and its ConfigMap is read from
  `kith-system` only: whoever may write either decides which names every node answers as
  not there. The host of a `url` list sees each node's address and when it asks, and what
  it serves is taken as the list unless `sha256` pins it. A name that is only an alias (a
  CNAME) of a listed name at the other resolvers is still answered. What those resolvers
  say is kept for up to an hour and given to every client that asks the same question:
  kith checks no DNSSEC signature, so an answer forged on the way from them lasts that
  long, and answers given from what is kept do not count toward a client's limit on
  forwarded questions.
- **An app of a seat is in its session.** A workload with a claim on a seat that says
  `access: client` is given the seat's directory, where the session's Wayland and
  PipeWire sockets are, and connects as any program the session started would: it can
  put windows over others, and has what the compositor and the sound server give a
  client (the clipboard, sound in and out, a screen where the compositor shares one).
  It is given no input device and not the GPU's card (on NVIDIA's driver it has the
  driver's own nodes, all but the one that sets a screen's mode), and cannot write the
  seat's directory. kith puts nothing between an app and the session. What decides who
  gets in is the namespace: a client is placed only while a workload of its own
  namespace holds the seat, so whoever may apply a DeviceClaim and a Workload in the
  session's namespace can put a program in that session, without waiting for the seat
  as a second holder would, and nobody of another namespace can, unless the session's
  own claim says `shared`: a seat held so is held with whoever else claims it `shared`,
  of any namespace, its directory and its apps with it (the desktop packages hold theirs
  exclusively). Within the namespace the directory's owner is all there is: it is the
  session's user's alone, a template says which user its container is, and root in a pod
  on kith OS is past it.
- **A container is not a sandbox for a program you do not trust.** The filter is a list
  of what is refused: every other system call reaches the kernel, and so does a claimed
  device (a GPU's render node is a kernel driver's whole interface). There is no AppArmor
  or SELinux profile. Run such a program in a VM (`vms`).
- **An image is whoever's its registry says**, unless its template names keys
  (`signedBy`). Nothing makes a template name them: there is no rule for a cluster or a
  registry yet. A signature is checked against keys only: no certificate, no
  transparency log, so a signing key that leaks signs until it is taken out of every
  template.
- **A control node that is taken is the cluster taken, until its Node is deleted.** It has the
  whole store, every Secret in it, and a node's rights (a worker has less: below). `kith delete node/NAME` ends
  what it can ask for: each node looks a node certificate's name up in its own copy of
  the store at every request, on the API and on the node-to-node routes, and refuses
  one whose Node is gone, was only made by hand (it never joined), or names another
  key (the name joined again); the mesh drops its key in the same moment. What that
  does not undo:
  - Until its Node is deleted it can do everything: it can name the local socket as the
    one who asked on what nodes pass on to each other, and the node that leads writes to
    the store whatever a node of the cluster sends it to write, unasked.
  - **A worker that is taken reads what is placed on it and what every node needs, and
    writes only about itself.** A node whose Node
    says `spec.trust: worker` (said by whoever made its join token, `kith node token
    --worker`, or by whoever may apply a Node; the machine that joins does not say it)
    never votes on the store, is refused Raft's own messages by the other nodes (so it
    cannot lead, or send them a store; a node that is behind, or has not heard of its
    Node, still takes them, as from a deleted node, below; and one that voted when it
    was made a worker is followed until it has handed its vote over, which a taken
    one need not do: delete its Node), is refused `kith run`'s hop and what nodes pass
    on to each other whoever it names, is given no Secret that says `trust: control`
    by its own kithd, and has nothing placed on it that asks for control nodes. It was
    never handed the CA key: only the node the cluster started on has it, and that
    node is refused `trust: worker` by `kith apply`, `delete` and `rollback` (a
    courtesy against a slip: a `Release`, a `Source`, a controller or a node's own
    write is not held to it, and that the node has the key is its own word in its
    Node's status). `trust: control` on a Secret covers what a unit is given, not a
    Backup's S3 Secret, an ingress `tls-` Secret or the ACME account, which the node
    doing that work reads.

    What a worker may write is a list the control node it writes to holds it to,
    against that node's own store: what it says of the replicas the scheduler gave it
    (how many are ready is counted again; a unit's address has to be in the worker's
    own part of the mesh), `os` and `mesh` in its own Node's status (not a mesh key
    another Node says, which would cut both off), its own NodeKey once, the Devices
    and Seats whose `spec.node` is the worker (under a name that starts with the
    worker's own, with the labels discovery writes and no other, the node and the
    class among them its own), the status of an Image or a Backup of
    a Volume that is on it, a Blob it made, its own name among a Blob's holders, and
    when it synced as a Volume's replica. Everything else is refused and written to
    the audit log under the worker's name: a template, a Secret, a Role, a Node's
    spec (its own `trust` too), another node's status or Device, a report in another
    node's name. So a change asked of a worker's own API is refused as well (`ask a
    control node`). The other things nodes do among themselves
    are narrowed with it. A worker is sent a blob's bytes only where the status of an
    Image or a Backup names it and that one's Volume is on the worker, or it is an
    Image that a template placed on the worker runs; it is never one of the nodes
    that should hold a blob, and no node lets go of its copy on a worker's word. A
    Volume's whole copy is sent only to a node the store names among its replicas
    (any node, not workers alone). The key of an encrypted Volume is given to control
    nodes to keep and to no worker, and a node made a worker deletes the keys it
    kept. Of a worker's word about which nodes are there, only what it says of itself
    is taken. A worker's replica takes over a lost Volume only when no control node
    has one, whatever time it says it synced. A worker's `status.serves` (the DNS port
    it says it answers, and ingress) is its own word and nothing more: a control node
    does not probe it, and nothing outside the cluster acts on it yet. A Node's address
    on the LAN is the one the admitting control node saw at join, not the node's word.

    A worker keeps a view of the store, not the store (`docs/adr-workers.md`). A
    control node sends it, by the name in the worker's certificate: every Node,
    Namespace, Workload, NodeWorkload, Job, Service, NetworkPolicy, Volume,
    VolumeClaim, Share, Blob, Image, Device, Seat, DeviceClaim, DNSZone, DNSRecord,
    DNSBlockList, OSRelease and UpdatePlan, with its status (the proxy, the claims, the
    mesh and the resolver read every node's); the Secrets and ConfigMaps that a
    template placed on the worker names in `env`, `envFrom` or as files; the Backups
    of the Volumes on it, with the Secret each names for its bucket; the ConfigMaps
    block lists name; and its own NodeKey. Nothing else: no other Secret or ConfigMap,
    no Identity, Role or RoleBinding, no Release, Package, Repository, Source or
    CronJob, no kind someone defined, and never a Secret that says `trust: control`,
    whatever names it. The control node decides, from its own store; the worker is
    not asked what it wants. The view is in `view.json` in the worker's state
    directory (mode 0600: encrypt the state partition of a machine that can be
    carried off). When a Workload leaves the worker, the Secrets only it named are
    taken out of what kithd reads and the file is written again without them, at
    once; the blocks the old file had are the disk's to forget, and kithd's memory
    is not wiped. The worker calls one control node, by its name and the key its Node
    names, so no other node of the cluster can answer in its place (a Node that
    names no key, one from a kithd before node keys were written down, is held to
    its name alone); when that one is gone it calls another and is sent everything
    again. With no control node in
    reach it runs on from the view it has and starts nothing new: **a Secret that
    was changed meanwhile is the old one there** until it is back, and a Node that
    was deleted or made a worker meanwhile is still a control node to it. A worker
    that starts again meanwhile runs nothing until a control node answers (what
    was moved off it while it was away is not known to it), as any node that
    starts with no leader in reach. Its API
    port answers no person, reads included: it has no Identity and no Role to answer
    by (`this node is a worker and answers no one by their rights: ask a control
    node`). What a control node passes on to it for someone (a unit's output, `kith
    run`, a Volume's files, a restore) it does on that control node's word that the
    caller may; a worker's word for that is taken by nobody. Whoever is root on the
    worker reads its view at the local socket.

    A node that was sent the whole store (a control node made a worker, a worker
    from before views) asks for a view, writes the first one down, ends its part in
    Raft and erases its copy of the store (`raft/` in its state directory); its
    Node's status then says `view`, which only a control node writes, and the node
    that leads sends it no more. What it copied before, it has, and what its kithd's
    memory held is there until kithd starts again. Such a node does not become a
    control node again by a change to its Node: delete it and join it again. **A
    worker that serves ingress (`--ingress`) is still sent the whole store**, every
    Secret in it: it reads the hosts' `tls-` Secrets and the ACME account. The node
    the internet reaches holds no less as a worker, until ingress is built for
    views. Which of the two a new worker is, is its token's maker's to say, not the
    node's: `kith node token --worker` lets in only a node that runs from a view,
    and one that says it cannot is refused; `kith node token --worker --ingress`
    lets in one that is sent the store. **A worker from before views that never
    asks for a view goes on being sent the store**: `kith get node NAME -o yaml`
    shows `view: true` in the status of one that is not, and a worker without it
    that should have it is deleted and joined again. A worker told to follow only control nodes older than views says so
    (`this control node is older than workers: update it`) and, if it has the store,
    keeps it.

    What a taken worker still has: every Node's address and mesh key; the Cluster's
    and every Namespace's settings and `values` (a password written into values is
    in them); every template (image names, commands, `env` written in place); every
    Service, NetworkPolicy, Volume, Device and claim, with its status; the Secrets
    and ConfigMaps of what is placed on it, and of what was placed on it before, so
    change those Secrets; on every worker a NodeWorkload selects, that one's
    Secrets; the files of every Volume on it or that it is a replica of, and their
    backups and images. And within its list it can lie: about its own units and its
    own Node; about its Devices, so
    it can say it has a card a claim in any namespace selects and have that Workload,
    **with its Secrets**, placed on it and sent to it (a selector alone keeps nothing
    off a worker: `trust: control` on
    the Secret or in the template's placement does), and a claim whose selector
    names no node and came to one node's Devices then matches two nodes' and is
    refused until it says `kith.dev/node`; it can hold or spoil the Volumes on it,
    and name a Device as a node whose name starts with the worker's and a `-` would
    name one of its own, which then is not listed. Nothing bounds how much or how
    often it writes within its list: its reports can fill the store's log. For the round (3 seconds) in which another node still has the file
    of a Blob just deleted, a worker that knew its name can make a Blob of it and ask
    for the bytes. A worker that still votes when it is taken (it was a control node
    a moment ago) is still followed, still has the store, and what it writes as the
    node that leads is held to no list: delete its Node. It cannot read a Secret
    nothing placed on it names, or one that says `trust: control`; it is not sent a
    Volume it is no replica of, a Blob nothing on it names, or the key of an
    encrypted Volume.
  - What the node copied, it has: every Secret that was in the store, the keys of
    encrypted volumes it was handed, the CA key if it was the node the cluster started
    on (then make a new cluster). Change the Secrets.
  - A request that was already running when the Node was deleted (a `kith run` in
    progress, a copy of a blob or a volume) runs to its end. A watch is told no more.
  - A node answers by the store it has: one that is cut off from the others, or
    behind, still takes the deleted node's certificate until it has the delete.
  - A node that has not heard of a node at all takes three things from it and nothing
    else: what a leader sends to bring a store up to date (entries, a snapshot) and a
    request for its vote. It has to: the node that leads may be one that joined while
    it was away, and nobody else would send it the store. A certificate from a join
    names an index of the store by which its Node was there, so a node whose store is
    past that index knows the Node was deleted and refuses these too. One whose store
    is not that far (a node that has just joined, one that has been away since before
    the deleted node joined, one whose store was wiped while its certificate was kept)
    cannot know, and whoever
    holds a deleted node's key can send it a store of their making until it has caught
    up with the real one. Do not start a node on a wiped store: join it again.
  - A Node written by a kithd from before this check names no key and stands by its
    name, and that node's certificate names no index: once its Node is deleted, only a
    node that has not heard of itself takes those three things from it. The node the
    cluster started on writes its key at its next start; the others get both when they
    join again.
  - A refused node certificate is written to the audit log once a minute at most, not
    each time it asks, and it does not count against the connections a stranger may
    hold open.
  - A node that is still a member can write any Node's status, another's key
    included: every node is trusted as the admin is (above) until a node's rights are
    narrowed.
  - `kithd --admit-deleted-nodes` turns the check off on the node started with it, for
    a cluster that has locked itself out (a node from before this check that joined
    while another was away, and leads now); it says so at start. Leave it off. It
    brings no deleted Node back: a node deleted by mistake joins again. A deleted
    worker's certificate is taken there as a control node's (nothing says it was a
    worker any more), but for a change to the store: that is taken from no node the
    asked node has no Node for. On a worker that runs from a view and is started
    with the flag, that includes the deleted node's word for who asked: do not
    start a worker with it.
  Certificates still last ten years; nothing but the Node's deletion ends one.
- **A Release is the right to apply whatever its packages render**, with the node's
  rights and not the writer's; the same for a Source. (T-0229, T-0227.)
- **A host that no Namespace keeps goes to whoever exposes it first**, and, with
  `--acme`, has a certificate ordered for it. Keep the hosts you serve with a
  Namespace's `hosts`. Where none is kept, the "first" Service is the one whose oldest
  kept revision is oldest, so a holder can lose a host after a hundred edits or a
  delete. (T-0233.)
- **Someone on the network can still keep others from connecting** with many addresses
  at once, and eight connections from one address keep out whoever shares that address
  with them (a node behind the same NAT, or in the same IPv6 /64): the count is taken
  before a certificate is shown. A firewall in front of the port is the answer to that.
- **A Service connection the kernel passes on** (kith OS: a container on the node's own
  network connecting to a Service with a replica on the same node and no NetworkPolicy)
  is not seen by kithd: it is not counted against the node's limit of Service
  connections, not ended when it is silent, and not written anywhere. What the kernel
  passes to is made again when replicas change, so for a moment it can be behind: a
  replica that has gone is passed to until the round that the change wakes has taken it
  out, and the address of a pod that was let go may by then be the next pod's, of any
  namespace, for at most the rest of the round in progress (its probes, 3 seconds
  together, and on the node that leads its status write) and one load of the program.
  A NetworkPolicy does not come into it: a Service a policy names is never the
  kernel's. Units run with `exec` and containers on the node's network share the one
  cgroup the program is on. A kithd that is killed leaves its program where it is
  until kithd starts again, passing to what was there when it stopped; one kithd
  cannot empty is tried again each round and said.
- **Backup buckets and S3 endpoints may be on the node's own network** on purpose, and a
  restore, a replica's copy and its sync take no more than the Volume's `size` says
  (above), but a Volume with no `size` is not capped: a bucket someone else writes can
  fill a node's disk through a restore into such a Volume. The primary's copy route builds
  its archive with no cap of its own; the replica that takes it is what stops at the
  size (and a replica of a Volume with no `size` stops at nothing). (T-0230.)
- **A node started with no `--release-key` trusts the key of the first OSRelease it
  takes.** Give the key when installing. (T-0231.) What a taken admin credential can
  still do with OSRelease and UpdatePlan is restart nodes into releases their keys
  signed that are no older than the newest each node has run well (its floor,
  `os-release-floor`): not into an older one, and not onto other keys, since a
  handover must be signed by a key the node has and by one it is handed to. A node
  with no state partition keeps neither floor nor keys, and whoever holds a release
  key the nodes take still decides everything they run.
- **A Volume's directory on its node** is checked and then mounted: a path changed in
  between is not seen.
- **A stolen machine that is not locked**, started on the cluster's own network, is
  handed its disk's key. Lock it when it goes missing. The config partition and the
  system itself are not encrypted, and an update stick (`kith.update=`) is not signed:
  whoever is at the machine with a stick is its admin.
- **A node whose key is sealed to its TPM** (`kith node seal`, off unless asked for)
  opens its state with no node asked while PCRs 0, 4, 7, 9, 12 and 15 stand as they
  were sealed: other firmware, another boot file or command line, another Secure Boot
  state, or other words in its config partition (kithd measures those itself, into
  15) is refused the key and asks the cluster. The boot file is not signed for Secure
  Boot: a changed one starts, and is refused the key. Taken whole and started as it is, it
  opens by itself: no lock reaches a machine that does not hear its cluster. The key
  crosses the TPM's bus as it is (a chip's pins can be probed while the machine
  starts); after a start the TPM refused, the node seals again for whatever system
  the cluster then handed the key to; and all of it has run against a software TPM
  only.
- **The offline unlock gives up that the key is not on the machine.** A node that
  opens its encrypted state with no node in reach has its key on its own disk again:
  sealed to its TPM (above), or, with `kith node passphrase` (off unless one is given),
  wrapped under a key drawn from a passphrase by Argon2id (19 MiB, 2 passes). Whoever
  has that disk can try passphrases offline, at that cost a try and for as long as
  they like: the passphrase's strength is then all that keeps the state, where
  without one it is the cluster's lock or the recovery key's 128 random bits. A lock
  makes a node drop its passphrase only once it hears of it; a wipe erases it with
  the rest. Passphrase and seal are each a way in, not two factors. The passphrase
  goes from the node that was asked to the node it is for over the cluster's TLS and
  is kept by neither, nor by the store or the audit log; it is in kithd's memory on
  both for as long as the request takes, and that memory is not wiped after. A line taken away is written over where it lay: what a flash
  disk keeps of sectors it has replaced is not kith's to say.
- **Confidential machines (SEV-SNP, TDX) and device passthrough** have never been run on
  real hardware.

## The review before 1.0

Before 1.0 the tree was read for security, area by area: the API and who may do what,
the cluster's port and its certificates, the runtime (containers, machines, sandboxes),
packages and WebAssembly, Sources, ingress and ACME, DNS, storage (volumes, backups,
replicas, shares, encryption), kith OS updates, and the web UI. It was three passes of
reading the code. **Nothing was run against it**: no fuzzing, no scanner, no test from
outside. A finding was kept only when the path from an untrusted input to its effect was
traced in the code; where that could not be done all the way, the table says so.

Severity:

- **High**: someone crosses a boundary of the table above with no right to (reads or
  writes what is not theirs, runs code, or stops the cluster for everyone).
- **Medium**: the same, but it takes a right that was granted for something less, or a
  setup that is not the usual one.
- **Low**: a limit or a check that is missing, with no path found to more than a nuisance.

| # | Severity | What | Outcome |
| --- | --- | --- | --- |
| 1 | High | One host with no certificate could hold all 64 handshake slots of a node's port, and nobody else could connect: no join, no `kith`, no new connection between nodes. | Fixed: one address holds 8. Many addresses still can (see above). |
| 2 | High (not traced all the way: it is a race) | A workload that swaps a directory or a file of its volume for a link while the node archives the volume had the node read what the link names, as kithd, into a Backup or an Image the workload's owner can read. | Fixed: the archive is read through held directory handles and follows no link; it stops at 128 directories deep. |
| 3 | High | An exposed host went to whichever Service asked first, in any namespace; with `--acme` anyone who may write a Service had certificates ordered for names of their choosing. | Fixed in part: a Namespace keeps hosts (`hosts`), and exposes no others once it names any. Open where none is kept: T-0233. |
| 4 | Medium | An Identity allowed to push a package could have the node send it to an address only the node reaches (its loopback, its networks), by naming such a registry or one that sends the upload on to there. | Fixed: when an Identity asks, every request of the push goes only to an address that was checked, as a Source's fetch does. |
| 5 | Medium | The node's own registry answers every local process with every namespace's Images. | Fixed: the registry speaks TLS under a certificate made for each start and answers 401 without that start's password, both held in kithd's memory and given to its own pull only; kithd pulls an Image only for its own namespace. `docker pull` on a node no longer works. Not checked: who can read kithd's memory. |
| 6 | Medium | A Release (and a Source) is rendered and applied with the node's rights, not its writer's. | Open: T-0229, T-0227. Said above. |
| 7 | Low | A restore, a replica's copy and its sync have no cap on size; sparse entries in an archive may not be counted (suspected, not traced). | Fixed: each is capped by the Volume's `size` (files, directories and links counted in 4 KiB blocks, a sparse entry at its whole length; the download at twice the size and 1 MiB). Stays: a Volume with no `size` is not capped, and there is no quota on the directory. |
| 8 | Low | A node with no `--release-key` pins the first OSRelease's key; an OSRelease's image address is not vetted (what comes back is thrown away unless signed). | Open: T-0231. |
| 9 | Low | ACME answers had no size cap, redirects were followed, and a certificate's names were not compared with the host. | Fixed: an authority's answer is read to a cap (64 KiB, 256 KiB for a chain) and a larger one refused; the directory's redirects are not followed; a chain whose leaf does not name the host, or is not good now (run out, or not yet started), is refused and the stored certificate stays in use; an order has ten minutes in all. Not checked: that the URLs a directory gives are on the directory's own host (the operator names the authority, and ACME does not oblige one host). (T-0232.) |

The T- numbers are the maintainer's task numbers, the same ones commits carry.

Looked at and found to hold: which routes are open and which are behind a layer, tokens,
how far a Role reaches, paths of volumes, the refusal of a node's own addresses for
Sources, the pinning of S3 endpoints, WebAssembly's limits, how a machine's command line
is built, package signatures, template limits, how git is called, the CA being pinned by
the join token, the DNS forwarder's limits, update signatures and the refusal of older
versions, the web UI's escaping and its content security policy, and the unpacking of
archives.

The hardening of containers (their user, capabilities, the seccomp filter, signed
images) was written after this review, in answer to its first "not defended" entry. It
had one reading of its own, by a reviewer who did not write it; nothing was run against
it either, beyond its tests.

The Kubernetes API and pods were written after 1.0. They had a reading of their own
for security, by a reviewer who did not write them, with the question "is this a way
past the Roles?"; nothing was run against them beyond their tests. It found four
things, all fixed before the API was first committed: a patch answered a caller who
may write a kind but not read it with the whole object (a Secret's data too); a
CronJob was a way to run a Job without the right to write one; a write or a delete
told a caller with no right whether the object was there; and a body in protobuf made
of empty fields cost far more to read than its length. Not read then: how deep a
strategic merge patch may nest, and the YAML reader's limits for a Source's manifests.

### Not reviewed

- The mesh: WireGuard keys, who becomes a peer, what a peer may send.
- The installer and the first process (`kithd install`, `kithd` as init).
- Applying a Source against what a Package says it may write.
- How much memory a template's filters can use.
- Devices and seats.
- Dependencies: no advisory database was checked (`cargo audit` and `cargo deny` were
  not run).
- Anything that takes running it: fuzzing the YAML reader, the DNS server, the tar and
  image readers, the API's bodies. (T-0234.)
