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
| A node | A certificate of the cluster's CA for `NAME.node.kith`, while its Node is in the store and names that certificate's key | A control node (what a node is unless its Node says `trust: worker`): everything in the cluster. Control nodes replicate the whole store, Secrets included, and run what they are told: **a control node is trusted as much as the admin.** A worker: what is placed on it, what every node reads to run a cluster (an ingress worker: the exposed hosts' certificates and keys too), and to write what it says of itself (see "A node that is taken") |
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
- **An Identity's write is decided again where the log is kept.** An apply, a delete or
  a rollback by an Identity, of any kind (a Role, a RoleBinding and an Identity
  included), is asked about on the node it reaches, and then decided again on the
  leader as it is put in the log: the leader first applies every entry it holds, and
  asks its own store what the Identity may do now; a node that no longer leads sends the
  write back, to be passed to whichever does. A write that changes a Role, a
  RoleBinding, an Identity or a KindDefinition (which says whether a kind is namespaced,
  so which rule matches it), or an import, goes into the log alone: the Identities'
  writes wait for it to be applied, and it waits for those already on their way. So
  access is decided in the log's order: a RoleBinding deleted before a write is put in
  the log stops that write, even one that a node which had not heard of the deletion
  yet let through, and the refusal says so ("decided again as the write was put in the
  log"). One whose right to change access went cannot bind itself again through such a
  node either. A node passes on the Identity's name with the write (`x-kith-for`); the
  leader takes it from a control node only, and a worker's writes are held to a
  worker's list whatever it names. A write waits at most 10 seconds for what comes
  before it, and is then refused with "try again". So whoever may change a Role, a
  RoleBinding, an Identity or a KindDefinition can, by changing access over and over,
  slow the Identities' writes by up to those 10 seconds each, and past them make the
  writes fail (they are refused, to be tried again): there is no rate on it.
  What is decided once, where it arrives, and not again: an import or a restore of a
  whole store; what the controllers write for themselves (a backup made, a status); a
  blob put; a Volume's files; a package pushed; `kith run`; a seat's activity (a
  Seat's status, `/v1/seats/NAME/activity`); a node's lock, its codes and keys
  (`/v1/lock/NAME` and its lock, unlock, wipe, seal, unseal and duress,
  `/v1/lock/NAME/recovery`, `/v1/lock/NAME/passphrase` and `/v1/duress`); and a
  worker's write from its view. What it does not stop: a write put in the log before the change, which is
  the log's order and not the clock's (a deletion still on its way when the write
  reached the leader comes after it); a node of an older kith, in a cluster that is
  half updated, which passes on no name, so its writes are decided where they arrived
  (and a leader of an older kith decides nothing again); a taken control node, which
  can name anyone or write as itself; and a certificate that stops standing for its
  Identity (one made again, or the Identity deleted) while the write is on its way: the
  leader is given the name, not the key, and asks what the Roles bound to that name
  allow.
- **A node's certificate has no right of its own on the API**: it reads nothing and
  writes nothing there. What a node does there is pass on what someone asked it, to the
  node that has the thing: a unit's output, a Volume's files, a node's passphrase, a
  backup's restore. It names who asked (a header, `x-kith-for`), and the node that gets
  the request asks its own store what that caller may do, and writes both in its audit
  log (`alice via node a`). The header is read on those four requests and on a write
  passed on to the leader (above), and from a node only: sent by an Identity, or
  anywhere else, it changes nothing. `kith run` is passed
  to the node the app is for on the node-to-node routes, with who asked in the request,
  and checked the same way there.
  **A control node's word for who asked is taken**: one that is taken can name the local
  socket, so this narrows nothing for it. A worker's word (`spec.trust: worker` on its
  Node) is not taken: what it passes on is refused whoever it names (see "A node that
  is taken").
- **Node-to-node routes** (Raft, copies of blobs and volumes, a volume's key, running a
  command on another node) take a node's certificate only, and, like the API, only
  while that node's Node is in the store: each request is asked again.
- **What one node passes on to another is pinned to its name.** A passphrase, a Volume's
  key, a caller's Volume files, a restore, `kith run`, a unit's output, a Volume's copy,
  a blob copied from the node that holds it, a Raft write sent on to the leader, the
  ping of the nodes, each Raft link between voters (votes, appends and snapshots, which
  hold every Secret) and the CA probe of a node that may be made a voter go to the node
  that was named, at its address by its Node: the
  handshake is refused unless the certificate is for `NAME.node.kith` and, if the Node
  names a key (`status.certificate`), is that key. So another node of the CA that
  answers at a moved or reused address is sent nothing and what it says is not taken
  for the named node's word, and the error says who was called and who answered. A
  Node that names no key is held to its name alone.
  A Raft link goes to the voter's address in the membership. It is held to the name
  and key of the Node that has that voter's raft id; if two Nodes have it, nothing is
  sent. Where the store has no Node for the voter (a node just joined, or a voter whose
  Node was deleted and that still gets the store until it is taken out of the voters),
  it is held to a certificate whose name gives that id, which is weaker: any name of the
  CA that hashes to the id is taken for the voter. A join is refused a name whose id
  another Node or a member of the cluster has, so a joining node cannot be taken for a
  voter by choosing its name. A voter whose Node was deleted but who is still in Raft's
  membership goes on being sent the log at its address, held by its id alone, and the
  deleted node's own certificate (signed by the CA) still answers there until the
  membership change is through: seconds, longer with no leader or majority. A node's
  certificate outlives its Node, and nothing revokes it.
  **A join with a token that names its maker talks only to that node.** A token holds
  that node's name and key print beside the CA's fingerprint, and the joining node, which
  has no store, talks only to the node that made the token: it takes no other
  certificate at the `--join` address, and another node of the CA that
  answers there (a taken worker on the address) is sent nothing, not the token's secret
  and not the joiner's name, and the joiner says which node it called and which
  answered. What is left: the node that made the token, which holds the CA's key, makes
  the new node's key and sends it back (a node that holds the CA's key could sign any
  node's certificate anyway); and a token made before tokens named their maker names no
  node, so the joiner, which says so, sends it to any node of the CA that answers at the
  address, as before. A claim token (`--claim`) names no node either: it is sent by
  hand, and the README says how to check the CA it is sent to.
  Not pinned: a blob fetched by its digest (what comes is checked against the
  digest); and a locked disk's key asked at boot, before there is a store (only a key
  wrapped under the disk's own secret is sent, but the disk's id is seen by whoever
  answers).
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
  On kith OS a pod's container (a network namespace of its own) is a user namespace whose
  ids 0 to 65535 are a range of the node's ids no other container has, so its root
  (`runAsUser: 0`) is not the node's root: a root-only file of the node is not its, and
  its capabilities count only for what is its namespace's (not even the pod's network,
  which the node's root made: any port there is anyone's, as kith-mesh sets it per pod).
  Its image and its volumes are mounted id-mapped, so owners on disk are what they were.
  Not shifted, and so the node's users as before: a container on the node's network (its
  ports below 1024 would need the node's to be anyone's, and they stay root's), a
  NodeWorkload's, one given devices, and one with its image or a volume on a file system
  that takes no id-mapped mount (a volume of another node, over NFS); `hostUsers` in its
  status says which. A node mounts another node's shared Volume nosuid and nodev, so a
  set-uid file or a device node a workload on the other node wrote is not honoured on this
  node (it stays executable: containers run programs from their volumes). A `runAsUser` of 65536 or more is refused for a shifted one. Its
  `/sys` is the node's, bound in, as a user namespace may mount no other.
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
  A device node a unit was given (an exclusive Device's, most of all) is not given to another
  unit while the unit that had it still runs: a unit whose stop failed with processes left
  keeps its devices and its name, its stop is retried at a later pass and no more often than
  every 2 s, and a unit that wants those devices waits until the unit is gone (a unit of the
  same Workload has the same devices, and waits for nothing of its own). When a device
  pulled from a running unit cannot be taken out of its container, the unit is replaced, as
  the container may still hold the node, and that is done before the device is given to any
  other unit; a plug that is refused keeps the unit running and is tried again at the next
  pass. Its id is refused at create and exec while its last run still has processes (those
  of its child cgroups too), and the next start of kithd, whose cleanup kills and removes
  what it finds with errors ignored, clears it. Only a real path under /dev counts (a link
  or an alias is refused where a device is given or plugged), so one node has one path.
  What is left: kithd holds this in memory, so a restart of kithd forgets the devices held;
  kithd closes no descriptor a unit's process has open on a device that was pulled (a unit
  loses a device as it runs only once the device is gone from the node, where the kernel
  ends what was open on it; one still on the node replaces the unit); a process that moved
  out of the unit's cgroup is not counted; a cgroup whose processes cannot be read is taken
  to still run; at kithd's shutdown a failed stop is not retried, and its processes outlive
  kithd until the next start's cleanup.
- **A pod** (a template that says `pod: true`, and so every Deployment, StatefulSet,
  DaemonSet and Job sent through the Kubernetes API) is a container with three of those
  taken off, as Kubernetes has them: it is the user its image names, root included; root
  there has the fourteen capabilities a container runtime gives by default, and no
  other; and its root file system is its own to write. It keeps `no_new_privs`, the
  seccomp filter and its namespaces, and has a network namespace of its own.
- **A pod behind an Exit** (`exit:` on a Workload's template) leaves by that WireGuard
  tunnel or by nothing, and is given no capability, sysctl or device for it: kithd holds
  the tunnel (`kx` and a number) on the Exit's node. Before the pod's host link is made,
  kithd writes, and reads back, routing rules in both families for that link: IPv4 to the
  tunnel's own table (with no tunnel there, unreachable), IPv6 to the mesh's range only
  and unreachable past it. The firewall (`inet kith-pods`, chain `passed`) drops whatever
  comes from an exit's pod link (`kpx`) unless it goes to a tunnel, another pod or the
  mesh, and its chain `in` drops what comes from one to the node itself unless it
  answers what the node asked of the pod: an exit's pod reaches no service of its
  node's, its DNS and kithd's API among them, on any port. What comes in by a tunnel
  (`inet kith-exits`, made, whole, before each tunnel is) is dropped, to the node itself
  or passed on, unless it answers a connection sent out by it: the provider's end
  reaches nothing of the node's, with a pod or none. These rules are the kernel's, so
  they hold with kithd stopped or killed; a node that starts again makes `inet kith-exits`
  again before its first tunnel, and `kith-pods` before its first pod. Taken away by hand
  while pods run (`nft flush ruleset`), they are made again within a minute: until then an
  exit's pod may reach the node's services. The pod's DNS is the exit's, through the tunnel. When a tunnel is made again or goes, the connections its pods had are
  forgotten (conntrack), so none goes on by an older path. A pod names an exit only from
  a namespace the Exit lists: refused at apply, and again by the node before it starts
  one. Its replicas are placed on the Exit's node, and every other node refuses to start
  them; a build older than exits refuses such a template outright (its fields are
  checked), so it cannot run one with no tunnel. The Exit and its Secret are sent only
  to the Exit's node; the Secret is in `kith-system`, read by kithd, mounted in no
  container. Writing an Exit is cluster-wide: a Role scoped to a namespace cannot. kithd
  asks the kernel for this over netlink: routing rules (`RTM_NEWRULE`/`RTM_DELRULE`), a
  WireGuard device and its peer, and conntrack's flush by mark; kith OS's kernel has
  multiple routing tables in both families, connection marks and conntrack over netlink
  for it. Two Exits whose providers gave them one address each keep their own rules:
  taking one away leaves the other's that sends nowhere what the node sends from that
  address. About every minute kithd checks each tunnel's link, its table's route and its
  rules, and makes the tunnel again when one is gone (until then what is left sends the
  pods' packets nowhere); a change to an Exit's namespaces or DNS alone leaves the tunnel
  as it is. A pod's own rules are read back when it starts, not after: root taking one
  away by hand on a running node is not seen. A published port (`publish: true`) is kithd listening on the node's IPv4
  addresses and passing what comes to the pod's own address (the app sees that address,
  not the client's; one listening on 127.0.0.1 alone is not reached): no rule of the
  kernel's lets anything else in. No port below 1024 is published, nor kithd's own
  (5000, 7443 and 51820 are refused at apply; the ports the node was started with, its
  DNS and ingress among them, by the node, which says so in its log). A connection ends
  after 10 seconds if nothing has been sent either way yet, after 10 minutes with nothing
  sent once something has, or when its port is no longer published. Each port has 2
  connections or UDP senders of its own, and the node's ports share 64 more, taken after a
  connection is accepted: a client that fills one port and all that the node shares leaves
  each other port its 2, and a connection past that is ended at once. A new UDP sender
  past that takes the place of the one of its port heard from longest ago. A pod publishes
  8 ports at most and a node 64, so the relays hold at most 448 files; kithd does not raise
  its limit of open files (1024), and its listeners, API and ingress take of it too, so a
  node with many clients of its API or ingress besides can still run out. A port another
  namespace's Workload or Job publishes is refused at apply, and on a node the pod that
  has a port keeps it while it asks, another pod of its namespace after it, so one
  namespace's pod never takes another's; where pods of two namespaces ask for a port no
  pod has (one written through the log, by a Release or Source, is not asked at apply, and
  a node that starts again has none), none of them has it.
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
- **A Release or a Source makes only what its writer may make.** The API writes down
  who applied it (`kith.dev/written-by`, whatever the body said; through another node,
  whom that node passed on), and a rollback to an older revision (of a Release, a Source,
  a KindDefinition or a Package: each is stamped) is written down as whoever rolls back,
  not as whoever applied the old revision; a rolled-back Package that says a Repository
  fetched it is refused, like an apply of one. Each time the controller renders, every resource is asked for as
  that writer would be asked if they applied it themselves, with what it reaches (a
  Backup's Volume and Secret, a Share's Volume, a CronJob's Jobs); each one the render
  drops, for leave to delete it. One refusal and nothing of the render is applied: the
  status names the resource, the right and the writer. A Release or a Source a Source
  makes is written down as the Source's writer. Rights lost later stop the next render,
  not what is installed; a writer whose Identity is gone, or a Release or Source with no
  writer written down (one from before this check), makes nothing until it is applied
  again. The writer is its name and the print of the Identity's `publicKey`
  (`kith.dev/written-key`, SHA-256 as a node's certificate is kept), also written
  by the API; an Identity given a new certificate, or made again under the same name,
  has another key, and its Releases and Sources make nothing new and fetch nothing
  until it applies them again. The local socket's have no key.
- **A custom kind's controller acts as whoever applied its KindDefinition.** The API
  writes that one down on the KindDefinition as on a Release (name and key print,
  whatever the body said, a rollback being whoever rolls back), and at each run what
  the controller's module answered is asked for as that writer would be asked if they
  applied it, and what it no longer answers, for leave to delete it; where the writer
  may not, nothing new is made, what was made stays, and the resource's status names
  the resource, the right and the writer. The writer's rights are asked only when the
  controller runs: a right taken away from them shows at its next run (nothing new is
  made between), and a run that was refused is made again when the KindDefinition is
  applied again, which is the way to mend it. The controller does not act as whoever applied
  the custom resource it runs for, so a custom kind lets someone ask for a thing without
  the right to make its parts, as an operator does.
- **An image whose template names keys** (`signedBy`) is run only if one of them signed
  its manifest's digest, which is found out before a layer is fetched; every layer is
  then fetched by the digest that manifest names. An image already on the node counts as
  signed only by keys it was checked against there.
- **An image under a rule of the cluster's** (a `Cluster`'s `spec.images`: a registry or
  a path of one, and its keys) is run only if one of the rule's keys signed it, whether
  or not its template names keys; a template's keys narrow the rule's and never replace
  them. Each node reads the rule at every start, a worker that runs from a view too (it
  is sent every `Cluster`). Rights over the whole cluster write one, and so does whoever
  may write a Source in `kith-system` and a `Cluster` (its files are applied with its
  writer's rights): they can add a rule with a longer prefix and a key of their own. A node on a build from before
  rules reads none.
- **An image is checked when it is pulled, not again when it starts.** Its layers are
  checked against their digests as they arrive and unpacked once; a start uses the files
  on the node's disk as they are. A file that several images hold alike is one file,
  hard-linked into each (and into `shared/`, beside `images/`): a file changed there by
  root on the node changes in every image that shares it. Nothing kith runs writes
  there: a container sees its image read-only, or through an overlay that takes its
  writes. A file with any extended attribute (a file capability, a label) is never
  shared. A file in `shared/` is taken by its name (the SHA-256 it had when it was
  first unpacked) and its size, mode, owner and time: its bytes are not read again
  when a later image is linked to it, so one changed there since is what that image
  gets too.
- **An image no unit uses is removed** (`--image-grace`, a day by default; sooner under
  the state disk's reserve), as root, by kithd alone: taken out of `images/` by one
  rename while no pull holds the store, then deleted following no link; only the layers
  no image is made of any more (in the image store's `blobs/`, never the cluster's
  Blobs the node's registry serves) and the `shared/` files nothing else links go with
  it. One a unit has a slot for, or a container's bundle names, is kept; a bundle that
  cannot be read keeps every image, said once in the log. A unit that needs it again
  pulls it through the same path as the first time, so its template's `signedBy` and
  the Cluster's `spec.images` are checked again: a signature found before does not
  outlive the image, nor does the note of what its tag resolved to. Time is counted from
  the image's last use, and never from before kithd's start, so an upgrade does not take
  every old image at once and neither the time a node was down nor a clock set while it
  was counts; a wall clock set forward by more than a minute beyond the boot clock
  (which counts a suspend too) between two looks removes nothing that look and restarts
  the count; one set back only keeps images longer. A layer no image names (one a pull
  cut short fetched) goes only once as old as an image must be. Left: an image stays on
  the disk for its grace after its last use, whoever may read the node's disk can read
  it meanwhile; a cluster Image's archive (Blobs) is not removed with it; one image's
  tree is one `remove_dir_all`,
  which kithd's stop waits 2 s for and does not cut (what it leaves is out of `images/`
  and goes at the next look); while an image unpacked by a kithd from before this is on
  the node, no layer is removed (what it was made of is not known); and whoever may
  apply in one namespace can fill the state disk under its reserve, so the node drops
  other namespaces' images unused for two minutes: they are pulled and checked again
  when next needed, so it costs availability (a pull, or a start that fails while the
  registry cannot be reached), not integrity.
- **Packages** are taken only with a signature over their name, version and hash, by a
  key the cluster was told to trust; there is no unsigned way in (but a package pushed by
  hand, which a Release renders with no more than its pusher's rights, and one from a
  Repository that has no `publicKey`, which is trusted on the word of whoever answers
  at its URL). A package's WebAssembly
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
  password. The bound is on kithd's file descriptors and memory: its connections, shaken or
  not, are at most 64 at a time, and each is closed after 2 s without a handshake, after 5 s
  without a whole request head, at a 401, or after 5 s with no byte between requests. The
  head time runs from when the registry starts reading a head (the connection's start, or
  the end of the last answer). A request being answered is not cut by the 5 s, because an
  answer may wait on a copy from another node. What is left: a process on the node that
  keeps connecting can fill the 64 slots and the kernel's queue behind them again and again,
  and kithd's own pull then waits behind them or times out, for as long as that process
  keeps at it. Kithd's other listeners and its open-file limit are not bounded by this.
  Every start from one of the node's Images asks this registry for the manifest, whatever
  the pull policy, so an Image deleted, or whose namespace was deleted and made again under
  the same name, is not started from the copy kept on the node; the old bytes stay on the
  node's disk until the Image is removed. And
  kithd pulls an Image only for what runs in the Image's own namespace: an Image is a
  packed Volume. Reading kithd's memory is being root on the node outside any container,
  which nothing here defends against.
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
  it is unpacked. An unpack holds only the directories the archive is inside of, a path,
  a mode and a time each, and refuses an entry more than 128 directories down (as deep
  as a Backup packs, so what a restore takes is backed up again); an entry's headers (its name, and a long name, PAX header or sparse map the tar crate
  reads whole) are refused past 256 KiB, and an archive that ends inside an entry is
  refused: its memory does not grow with the archive. A sparse entry with a map in blocks
  after its header is refused by name before the tar crate adds the map up (it does so
  unchecked, and kith's own Backups write no sparse entry): such archives are not restored.
  An unpack that fails opens what
  it unpacked to its owner and removes it, holding open only the directories it is
  inside of, through no link, and one that finds such a leftover beside the Volume does
  the same first. Each directory is made when it comes, stays open to its owner while
  the archive is inside it, and is given its mode and time when the archive leaves it,
  through no link: one whose path leads elsewhere by then is left as it is. An archive
  in depth-first order (kith's own, GNU tar's) unpacks with every directory's mode,
  owner and time; one that is not leaves its directories' times as the unpack left
  them, and where kithd is not root, an entry that comes after the archive left a
  directory that shuts its owner out is refused. A restore unpacks into a directory
  beside the Volume, `.NAME.restoring` (a dot no Volume's name starts with), and renames
  it over the Volume's empty one: a move that fails leaves the Volume's directory as it
  was, mode and owner too. There is no quota on the directory and no count of inodes. A
  restore from S3 unpacks from its download, which is removed once the unpack is done or
  refused. A sync of a Volume that is gone from the store (or whose spec does not parse)
  takes nothing and says so.
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
  stay refused inside. On kith OS a pod's container is a user namespace of its own, so
  its root, with fourteen capabilities, is not the node's; but in one that keeps the
  node's users (one on the node's network, a NodeWorkload's, one given devices, one with
  a volume of another node) `runAsUser: 0` is the node's root with three capabilities,
  and a pod's that keeps them has fourteen.
  A user namespace is also more of the kernel to get wrong: a flaw in its code is a way
  out that a container without one did not have. The root of a container's namespace
  owns, in its id-mapped volumes, what the node's root owns there, as before. One of the
  fourteen makes device nodes (in a pod that keeps the node's users: in a namespace of its
  own the kernel makes it none); the device filter on the pod's cgroup is what keeps it
  from the node's disks. Containers that are not pods share the node's network, and an
  `exec` unit is a process of kithd's user. The Roles decide who may apply these, and
  nothing more is in the way. Do not give them to someone you would not give a shell on
  the node.

  **A node's owner can refuse them for that node, whatever the cluster says.** The
  cluster's store is what tells a node what to run, so whoever holds an admin's
  credential, a control node, or a hole in what serves the store, has every node's root
  through the list above. `kithd --node-policy` is given where a node's kithd is started
  (on kith OS among its arguments on the config partition, which the installer writes
  and no API reaches), is never read from the store, and turns off, each by its own
  word: `exec` units (`no-exec-units`); containers that would be the node's root, which
  is root in one that keeps the node's users, not root in a pod's range of its own
  (`no-root-containers`); `seccomp` unconfined or with
  refused calls allowed back (`no-unconfined`); containers on the node's own network
  (`no-node-network`); VMs (`no-vms`), a VM's kernel, firmware or disks as paths on the
  node or another hypervisor than qemu (`no-vm-paths`), PCI devices handed to a VM
  (`no-passthrough`); a Volume of `kith-system`, which is a directory anywhere on the
  node (`no-host-paths`); `POST /v1/run` (`no-run`); the cluster wiping this node or
  setting its duress codes (`no-wipe`: a wipe from the cluster then leaves its lock
  record, and it opens next with its recovery key alone); and the classes of Device a
  DeviceClaim hands out (`devices=gpu+input`). Where the classes are named, a Device is
  what the node itself finds its hardware to be: one whose class, path or further nodes
  the store says otherwise, or one written by hand, is not handed out there (the store
  could call the node's disk a GPU). `hardened` is all of them off, with a GPU the only
  Device. What a node refuses is not run there and the Workload's status says which word
  refused it; the Node's status says its policy. Every word is on where nothing is said:
  **a node with no policy is as before, and the paragraph above is all there is.** The
  scheduler places a Workload or Job only on nodes whose status says they allow what it
  asks for; that is for placing, not a defence (a node's status is its own word, and each
  node refuses by its own policy whatever it was sent). Not done yet: a VM's kernel and
  disks are paths on the node today, so `vms` without `vm-paths` runs no VM of use. Where
  `exec-units`, `vm-paths` and `run` are all off (every way for the store to start a
  process as the node's root with all its capabilities), kithd also cuts its bounding set
  at start to the fourteen a root pod keeps (`KEPT` in `crates/kithd/src/policy.rs`). The
  bounding set limits what an exec gives a child, so nothing kithd starts by an exec can
  hold a capability outside that list in the node's own user namespace, whatever its spec
  asks for and whatever bug let it ask: not `SYS_MODULE`, `SYS_RAWIO`, `SYS_PTRACE` or
  `SYS_TIME`, nor `SYS_ADMIN`, `SYS_BOOT`, `BPF` or the rest (the node's status lists what
  it kept). A pod with `userNamespaces` has a full bounding set inside its own namespace,
  over that namespace's resources only (above). **A container's bounding set is its own
  spec's on any node, cut or not** (the fourteen for a root pod, three for a root that is
  not one, one for a user): the cut is what kithd's other children inherit (a Source's
  git, dnsmasq, the storage holder, an exec unit's shim, and libcontainer's init before it
  sets the container's), so no container's `CapBnd` shows it; `ci/vm.sh --test policy`
  reads kithd's own `CapBnd` instead. **It does not limit kithd's own threads**, which keep every
  capability (`CapEff` is not cut; `ci/vm.sh --test policy` reads it): a hole inside kithd,
  or a stolen certificate that reaches a hole there, is not held back by this. That is
  the split's job (`docs/adr-privilege.md`, T-0334). Nor does it say an effect is impossible: root
  without `SYS_PTRACE` can still trace root's own processes (the same user), and root can
  write `/proc/sys` with file permissions alone; neither is covered by the cut. Untried on
  a cut node: a VM (qemu would be exec'd with the fourteen; `vm-paths` off already leaves
  no VM of use) and a passthrough device (vfio may want `IPC_LOCK` or a memlock limit,
  which the list does not have); no VM test runs either. A pod on a hardened node can still be root inside
  a user namespace of its own, with what that gives (above), and a container that keeps the node's
  users and is not root is still the node's user of its number, with whatever files on
  the node that user owns; one that would be of root's group (its image says `1001:0`,
  say) is refused as root is. The policy is no defence against whoever can write the node's config partition
  or kithd's arguments and environment where it is started (`KITH_NODE_POLICY` and the
  command line say it too), or is root on the node already.
  (T-0334, docs/adr-privilege.md.)
- **Whoever may apply a Workload or a Job in a namespace reads that namespace's Secrets
  and ConfigMaps**, without the right to `get` them: a template names one in `env`, in
  `envFrom` or as files, and its container is given what it holds. (Another
  namespace's cannot be named.) A Secret given as files is written to memory only (kithd
  asks the kernel that the directory is on no disk, and refuses otherwise). Given in
  `env` or `envFrom` it is in the container's environment, which the node's root and the
  container's own user can read, and in the container's description that the runtime
  keeps in the node's state while it runs: on that disk, encrypted only where the
  state is. A ConfigMap's files are on the state disk too.
- **An Exit keeps a pod's packets in its tunnel, not the pod's secrets from its provider.**
  The provider sees everything the pod sends, and answers its names. A published port of
  an exit's pod is open to whoever reaches the node's address: it is the pod's web UI on
  the LAN, and nothing keeps the internet from it but the node's own place on the network.
  An Exit whose Secret's file is wrong, or whose node is not root, runs none of its pods
  (they wait, and their status says why); a name in `Endpoint` is refused, not looked up.
  An exit's pod is not given the cluster's names, and a Service may not reach it. A
  Release or Source applied by an admin skips the apply-time namespace check (it writes
  through the log); the node's own check before start still refuses an unlisted namespace.
  Of the node itself, an exit's pod reaches nothing (only answers to the node's own
  questions of it go back). A running pod keeps its tunnel after its namespace is taken
  off its Exit's list, until it starts again (the node's check is at start). No NetworkPolicy's egress rules are enforced, for an exit's pod or any other (a
  policy with them says so in its status). Not tested: a tunnel's link or table taken
  away by hand on a running node (the code that makes it again is tested in a network
  namespace, not on kith OS), ICMP through or around a tunnel, kithd killed between
  starting a pod and making its rules (the rules come first; nothing shows the order
  holds under a kill), and names a pod's own resolver library cached before its exit
  changed.
- **What a replica writes outside its Volumes is held at the write where the state disk
  keeps project quotas, and counted elsewhere.** Its containers' writable roots and its
  disk scratch share the node's state disk. Where the state disk keeps project quotas (a
  kith OS state disk made since T-0598, mounted with `prjquota`, and kithd root), each pod
  is given a project of its own, its limit set to its `resources.storage` before anything
  is put in it, and its replica directory, scratch and roots in it: a write past
  `resources.storage` fails at once (EDQUOT), and its units say it reached its limit.
  kithd says at start, and in the Node's status, which way it holds limits. A pod cannot
  move its files out of its project; an unconfined pod can, and is counted every 10 s as
  before. A container that keeps the node's users can no longer change file flags or
  projects (chattr, FS_IOC_SETFLAGS/FSSETXATTR, file_setattr fail with EPERM). The x32
  system call refusal applies to every container. A state disk from before has no project
  quotas and is counted as before. A pod whose scratch held files from before projects is
  counted every 10 s until it is replaced. `resources.storage` must be at least 64Ki (what
  a pod's own directories hold). The quota holds bytes, not files: there is no limit on
  how many files a pod makes (T-0605), and each costs the disk an inode. **Stopped at the
  limit:** every write a pod's own processes make outside its Volumes: a new file or an
  append in its container's root, a file of its image copied up to be changed (refused
  whole, the image's file left as it was), its disk scratch, and a file it removed and
  holds open; in a pod with a user namespace of its own and in one with the node's users
  alike. (The root is an overlay that libcontainer's first process mounts, as the node's
  root with every capability for a pod with the node's users; the kernel leaves
  CAP_SYS_RESOURCE out of the credentials an overlay writes with, so they are held too.
  `sh ci/vm.sh --test quota` shows each.) **Only counted:** what kithd itself writes into
  a pod's project (a new container's root directories: kithd is root, whose writes the
  kernel lets past a hard limit: 64 KiB past the limit is let be, and further the pod is
  replaced at the next count, about every 10 seconds, its project's usage read, not
  walked), an unconfined pod's file moved out of its project, and a scratch from before
  projects (both walked and replaced as on a disk with no quotas, below). A project id is given again once nothing on the disk is
  left in it, its new limit set first. Elsewhere,
  with no quota, kithd counts them about every 10 seconds (each pod with a `resources.storage`
  limit, and every pod while the disk has less than twice its reserve free) and replaces
  a replica past its limit, and, while the disk is under its reserve (`--storage-reserve`,
  5% of it and at most 1 GiB unless said where kithd is root, none where it is not), the
  one that wrote the most, if that is a tenth of the reserve or more. That one goes even
  when the disk is low for a cause that is no replica's root (kithd's own store, logs and
  Images, and Volumes, count against no replica), and then the next, one a count, once
  what the last wrote is gone. A fast writer is not stopped between two counts: at the
  disk's speed it can write past its limit, or fill the disk, before a count sees it, and
  then kithd's store, logs and other replicas' writes fail until it is replaced. A count
  starts at least 10 seconds after the last ended and counts the replicas one after another, each
  in 5 seconds at most: on a slow disk 20 replicas take up to 110 seconds between a
  write and its replica's replacement. A count walks every file by directory handle, not following links, each file
  once however many names it has, and adds each removed file a process of the replica
  still holds open (or maps) on those disks. A removed file held only by a descriptor in
  flight (sent over a socket with SCM_RIGHTS, then closed) is open in no process and
  counts nothing, against the limit or the reserve: nothing in kithd stops a replica
  filling the disk so, only the blocks the filesystem keeps for root. One whose
  descriptor another replica's process holds (a socket in a shared Volume) counts against
  that replica, not its writer. A limited replica whose count does not end in 5 seconds,
  or reaches 128 directories deep, two counts in a row, is replaced (once may be a slow
  disk, slow for every replica): one with millions of small files is, though under its
  limit. One whose counts end so every other time is not replaced for that, though what
  each walked counts against its limit. An unlimited one so counted counts what was walked.
  A count or removal runs on a thread that cannot be killed: one stuck on a disk that does
  not answer is said after a minute, and until it ends no replica is limited (a count) or
  replaced for the reserve (a removal). An empty
  file costs the disk an inode and the count nothing, and a directory kithd cannot read
  (where it is not root) is passed over, as is a held-open file it cannot look at. A file
  removed from a Volume on the state disk but held open counts against the replica (more
  than it wrote outside its Volumes, never less). A process that cannot be killed keeps
  its replica's replacement waiting, and no replica is replaced for the reserve meanwhile.
  A count can count a file twice (moved between the walk and the look at open files) and
  counts a root on tmpfs, not on the disk. A count or removal under way when kithd stops
  gives up between files, and kithd waits 2 seconds for it so the state disk can be
  unmounted, and says in its log which it gave up on. A removal looks at the stop every
  1,024 steps (entries looked at). It works a level at a time, so each directory is listed
  once and the work is linear in the entries, at any depth: a directory that is not empty
  is opened through the one above (never through a link, never into another file system),
  emptied, and what directories it holds that are not empty are moved into a new
  `scratch.*` level beside the scratch, which is removed next. At most four directories are
  open, and `..` is never taken. Where the disk has no room or no file left to make a level
  of, the first directory to move becomes the level itself, by a rename. A removal ends at
  the first entry it cannot remove (a mount point, or a directory on another file system),
  with that error in the log. What a
  stop or an error leaves is the scratch and its levels, each a `scratch.*` in the replica
  directory, removed as trees of their own at the next count of its pod's roots (only a pod
  with running roots that is walked: one with a limit, or while the disk is under twice its
  reserve); two sweepers of the same scratch at once are harmless to what is outside it, and
  one may end early at what the other took, for the next count to go on with. When the pod
  is gone its replica directory is removed whole, in one call that is none of the above: a
  stop does not cut it short, and it keeps a directory open for each level it is deep in, so
  a chain of directories deeper than kithd may have files open is not removed by it.
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
- **A host a Service exposes is answered at the ingress nodes' LAN addresses, to the clients of its zone.**
  Each host a Service exposes under a zone's domain (and its Namespace keeps for it) is given the LAN
  address of every node serving ingress, unless a DNSRecord has the name. Whoever may write a Service
  or a Namespace decides which names those are, and the answer is only as private as the zone's `clients`.
  Once a house's resolver forwards the zone to a node, the client kithd sees is that resolver: `clients`
  must name it, and then no longer tells one device of the house from another. Which nodes are answered
  is each node's own word (`status.serves`, and the address it joined from): an ingress worker (its
  Node says `ingress`, below) or a worker that is sent the whole store can say it serves ingress and is
  then answered beside the others; any other worker cannot.
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
  (`signedBy`) or a rule of the cluster's has it (`spec.images`). A rule for a prefix
  holds that name only: whoever may apply a workload can name an image under no rule
  (another registry, or the same one by a name kithd does not know to be it: a
  registry's usual port and Docker Hub's own names are read as one, an address or an
  alias in DNS is not), so only a rule with no prefix makes every pulled image a signed
  one. A cluster Image is under no rule and signed by no one: whoever may apply an
  Image and write a Volume in a namespace runs what they packed. Containers already
  running when a rule is applied are not stopped. A signature is checked against keys
  only: no certificate, no transparency log, so a signing key that leaks signs until
  it is taken out of every rule and template.
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
    doing that work reads; on a host's `tls-` Secret it keeps it from ingress
    workers too, which then do not serve that host.

    What a worker may write is a list the control node it writes to holds it to,
    against that node's own store: what it says of the replicas the scheduler gave it
    (how many are ready is counted again; a unit's address has to be in the worker's
    own part of the mesh), `os`, `mesh`, `serves` and `thumbprint` in its own Node's
    status (not a mesh key another Node says, which would cut both off; a thumbprint
    in a thumbprint's shape), its own NodeKey once, the Devices
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
    does not probe it, and nothing outside the cluster acts on it yet. A worker that
    runs from a view is refused the word that it serves ingress unless its Node says
    `ingress` (an ingress worker, below); one that is sent the whole store (a worker
    from before views) may say it, and any worker may say it answers DNS. A Node's address
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
    control node again by a change to its Node: delete it and join it again.

    **An ingress worker** (`kith node token --worker --ingress`) runs from a view as
    any worker does, and its view holds what serving the cluster's hosts needs too:
    the `tls-` Secret (certificate and key) of every host a Service exposes (so whoever
    may apply a Service with `expose.host` in a namespace decides that this namespace's
    `tls-HOST` Secret is sent to every ingress worker: of that namespace only, and never
    one with `trust: control`), and the
    ConfigMap `kith-system/acme`, the ACME account's thumbprint, with which it
    answers a CA's challenges. Never the account's key (`kith-system/acme-account`),
    whatever names it: a control node started with `--acme` orders and renews every
    certificate, writes the Secrets and the thumbprint, and the worker writes none of
    them (refused: `a worker writes only what it says of itself`). It says, in its own
    Node's status, which thumbprint its view holds, and the leader asks the CA for
    nothing until each reachable ingress worker says the right one: a worker that lies
    there holds up every order and renewal, as answering the CA's challenge wrongly
    would (each ingress node is one the CA may ask), and gains nothing else. That a worker
    serves ingress is its token's maker's to say, not the node's: the control node
    that admits it writes `ingress` into its Node's spec from the token, never from
    what the joining node asks, and only a worker whose Node says it may say in its
    status that it serves ingress. A worker joined with `kith node token --worker` that
    is started with `--ingress` is refused at the join, and at a later start
    (`kith node token --worker --ingress`, the message says). **A worker that serves
    ingress from before this** (one that was sent the whole store to serve it, whose
    Node does not say `ingress`) goes on being sent the store: its kithd says so at
    every start, and each control node that sends it the store says so once, with the
    node's name and what to do: delete its Node and join it again with an ingress
    worker's token, or set `ingress: true` in its Node's spec (it then asks for a
    view and erases its copy, as above; what it copied before, it has).

    When an ingress worker is taken: delete its Node (it is then sent nothing more
    and asks for nothing), then have every certificate whose key it held replaced:
    delete each host's `tls-` Secret and the control node orders a new one, with a
    new key, within a minute (`kith get secret` lists them; it held every exposed
    host's, and those of hosts it was sent before). The old certificates stay valid at the CA until they
    expire or are revoked there (kith revokes none), so whoever has the key can
    pose as those hosts to a client whose way to them they can be on until then.

    **A worker from before views that never
    asks for a view goes on being sent the store**: `kith get node NAME -o yaml`
    shows `view: true` in the status of one that is not, and a worker without it
    that should have it is deleted and joined again. A worker told to follow only control nodes older than views says so
    (`this control node is older than workers: update it`) and, if it has the store,
    keeps it. Control nodes older than ingress workers know nothing of `ingress` in
    a Node: one that admits a node writes none (the node is then a worker that is
    sent the whole store to serve ingress, and is warned about as above), and one
    that a worker with a view follows sends it no certificate and refuses its word
    that it serves ingress. Update every control node before an ingress worker joins.

    What a taken worker still has: every Node's address and mesh key; the Cluster's
    and every Namespace's settings and `values` (a password written into values is
    in them); every template (image names, commands, `env` written in place); every
    Service, NetworkPolicy, Volume, Device and claim, with its status; the Secrets
    and ConfigMaps of what is placed on it, and of what was placed on it before, so
    change those Secrets; on every worker a NodeWorkload selects, that one's
    Secrets; the files of every Volume on it or that it is a replica of, and their
    backups and images; and an ingress worker, **the certificate and key of every
    host a Service exposes** (it can pose as each of them until the certificate is
    replaced and has expired) and the ACME account's thumbprint (it can answer a CA's
    challenge for any name, which orders nothing without the account's key). And
    within its list it can lie: about its own units and its
    own Node; about its Devices, so
    it can say it has a card a claim in any namespace selects and have that Workload,
    **with its Secrets**, placed on it and sent to it (a selector alone keeps nothing
    off a worker: `trust: control` on
    the Secret or in the template's placement does), and a claim whose selector
    names no node and came to one node's Devices then matches two nodes' and is
    refused until it says `kith.dev/node`; it can hold or spoil the Volumes on it.
    A discovered Device's or Seat's name is the node's with the longest name that
    starts it (`w-b-gpu-card0` is node `w-b`'s, not node `w`'s): a worker is refused
    another node's; a node that finds a name of its own held says so in its log and
    does not list that Device; and one made before the node with the longer name
    joined is taken away at a control node's next look (half a minute), so that node
    gets its name. A join is refused under a name that would take a discovered
    Device or Seat from a node that has it (`w-gpu` while `w` lists `w-gpu-card0`):
    whoever holds a join token chooses the new node's name, and would otherwise
    choose whose card a claim by that name comes to. Where no such Device is listed
    yet, a node named as another's name and a class (`w` and `w-gpu`) does take that
    class's names, and the other's cards are then not listed: whoever names nodes
    decides that. The same follows where a node lists a Device in the moment
    between a join's check and the new Node being written. Any worker can make
    Devices under names that start with its own, with no hardware behind them, and
    so have a join under such a name refused until that Device is deleted or
    another name is chosen. A control node's own writes
    are not held to this (it can lead: the cluster is taken with it). How much and
    how often a worker writes is held too, by each control node it asks: a write is
    at most 1 MiB (an honest report of 300 units, each with a long message and
    notes, is 131 KiB; a larger report is sent in parts of at most half that, a
    status whole in each), and a worker makes at most 10 a second, 50 at once
    after a rest, a write counting once more for each 64 KiB (so at most about
    640 KiB a second). Every write a worker sends counts: one refused for its
    list, one that is not a change, and the empty write its controller makes
    before it starts a unit (one a second at most) too. A write that says its
    size (`Content-Length`, as kithd's do) is counted for it before a byte of it
    is read: past the rate it is answered 429 with the seconds to wait, unread,
    and the worker's own kithd sends it again then; over the size it is refused
    unread. One that does not say its size is counted once, read (up to 1 MiB,
    where it is cut off), and then counted for the rest. One whose bytes do not
    all come within 15 seconds is let go. None of them reaches the log. In the
    audit log under the worker's name, a write refused for its list or as no
    change is written each time; one refused for its size, its rate or its
    slowness, a line a minute of each, which says how many were not written since
    the last. The audit log writes at most 60 refusals a minute in all, whoever
    they are of, and counts the rest with its next entry: a worker refused in a
    loop can use up that minute's, and the refusals of others then are counted,
    not written. What is left: a taken worker can still write that much, within
    its list, to each control node it reaches (each holds it to its own count:
    three control nodes, three times as much), and the log between two snapshots
    (about 1100 entries) can then hold some 1.1 GiB of it on every node, which
    takes such a worker about half an hour to write through one control node. What
    it writes over its own status is replaced, but **the Devices and Seats it makes
    under its own name are not counted**: each write can be a new one, so the store
    itself (and every snapshot, on every node) can grow by up to about 2.2 GiB an
    hour through one control node (640 KiB a second for 3600 seconds), until
    someone deletes them or its Node. Nothing bounds the store's whole size or
    what the disk has left. For the round (3 seconds) in which another node still
    has the file of a Blob just deleted, a worker that knew its name can make a Blob of it and ask
    for the bytes. A worker that still votes when it is taken (it was a control node
    a moment ago) is still followed, still has the store, and what it writes as the
    node that leads, or sends on Raft's own routes, is held to no list, no size but
    the 64 MiB any node's write may be, and no rate: delete its Node. It cannot read a Secret
    nothing placed on it names, or one that says `trust: control`; it is not sent a
    Volume it is no replica of, a Blob nothing on it names, or the key of an
    encrypted Volume.
  - What the node copied, it has: every Secret that was in the store, the keys of
    encrypted volumes it was handed, the CA key if it was the node the cluster started
    on (then make a new cluster). Change the Secrets.
  - A deleted node does not put itself back, the one the cluster started on included: that one
    makes its own Node only while the store holds no Node at all, so on a restart with its
    Node gone it writes nothing and says so. It joins again with a token. Two edges: when
    every Node of the store is deleted, the node makes its own again (no Node is left to
    tell that from a first start that ended too early); and a first start that ended before
    its Node was written, after a joiner's went in, is told "deleted, or never registered"
    at the next start and joins again. A Node of its name holding another certificate (a
    joiner's) is not written over. It waits up to 30 s for a leader and for the store to be
    caught up: with none, nothing is written in that run and the next start tries again.
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
    is not that far (one that has been away since before the sender joined) cannot know
    by itself, and asks the voters it last knew (its own store's members, itself and
    the sender not counted), each over a link held to that voter's key: it takes the
    three things once one says the sender's Node stands with that key and none says it
    does not, and refuses them otherwise (403, before Raft sees them). A voter answers
    only a node that stands in its own store, and says only yes, no, or "not yet" (it
    is behind too); "not yet", no answer in two seconds, and a build without the
    question are no word. A yes is kept until the asking node's store is past the
    sender's index, and thirty seconds at most; a no thirty seconds, no word five; each
    sender is asked once whatever it sends meanwhile, and answers for sixteen senders at
    most are kept at once (a seventeenth is refused until one lapses). What that leaves:
    - Sixteen senders of the CA it has not heard of fill those places: then the node
      that really leads is refused too, as long as they keep sending (a no is kept
      thirty seconds, no word five), and the node stays behind. That takes sixteen
      distinct names (or keys), each a certificate of the CA: sixteen deleted nodes'
      keys, or sixteen join tokens. No kind of answer has places of its own.
    - Whoever holds the key of a voter it last knew that has been deleted since can
      say yes for a deleted node, when every voter that would say no is out of reach.
      With that key they could already send it a store by themselves: the asking node
      has not heard that this one was deleted either.
    - A node that reaches none of the voters it last knew takes nothing from a node it
      has not heard of meanwhile. It asks again five seconds later, so once one that was
      down is back it catches up by itself; only when every voter it knew was replaced
      while it was away does it stay behind: join it again.
    - A node that knows of no voter at all (one that has just joined, one whose store
      was wiped while its certificate was kept) has nobody to ask and takes these from
      any node of the CA, as before: whoever holds a deleted node's key can send it a
      store of their making until it has caught up with the real one. Do not start a
      node on a wiped store: join it again.
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
- **A Release and a Source act with their writer's rights, as far as these go:**
  - Deleting one removes what it installed as the node does: leave to delete the
    Release or Source is enough, not leave to delete each thing.
  - What a Release reads to render is not asked for: a Package that is in the cluster
    already, and the `kith-values` ConfigMaps of `kith-system` and its namespace.
  - kithd fetches a Package from a Repository for a Release only when the Release's
    writer has `apply` on `Package`, the right a pull or push by hand takes; the
    Release's status says so when it has not. The right is on Packages, which are in
    no namespace, so a Role that names namespaces does not give it; and it is not on
    one Repository: whoever has it can have kithd ask any Repository there is.
  - A Source's writer is trusted for whatever its repository's authors push, up to the
    writer's own rights.
  - A Package pushed by hand is rendered with no more than its pusher's rights, besides
    its Release's writer's: the API writes the pusher down on the Package as on a Release
    (name and key print, whatever the body said), and each render is asked for as the
    pusher would be asked if they applied what it makes, and what it no longer makes, for
    leave to delete it. So one who may push Packages and nothing else cannot publish a
    version that an admin's `autoUpgrade` Release then renders with the admin's rights;
    where the pusher may not, nothing new is made, what was installed stays, and the
    Release's status names the Package, the resource, the namespace and the pusher. A
    second push of a name and version by another replaces the first, and is held to the
    second one's rights. A Package with nobody written down (one from before this check),
    or an Identity gone or made again under the name, makes nothing new until it is
    pushed again; a Source that makes a Package writes its own writer on it. A Package
    fetched from a Repository has no pusher, and the pusher check does not apply to it at
    all: with a `publicKey` the key is what it is trusted by; **with none, it is trusted
    on the word of whoever answers at the Repository's URL**. So the right to apply a
    Repository is the rights of every Release that names it, and `apply` on `Package`
    lets someone have kithd ask any Repository there is. What makes a Package "fetched"
    is `kith.dev/repository`, which only kithd's own fetcher may write: an apply that
    carries it is refused, a Source whose repository's files carry it makes nothing new
    (its status names the resource), and a Release takes it as fetched only when it
    equals the origin of the Repository the Release names (a print of that Repository's
    name, URL and key); any other Package is asked of its pusher, and refused when
    nobody is written down. A Package a Source made before this, with the annotation,
    stays until deleted.
  - A Release and a Source act as the Identity that applied them while it has the key
    it had then. An Identity made again under the same name has another key, so what
    the old one applied is not acted on as the new one: it makes nothing new, fetches no
    Package, and says to apply it again; what was installed stays. The same after a
    new certificate for the Identity (a certificate lasts ten years). A Source that
    makes a Release writes the Source's name and print on it.
  - During an upgrade, a node from before this check neither writes the writer down nor
    checks it; and each Release and Source from before it makes nothing new until it is
    applied again.
  - A custom kind's WebAssembly controller acts as whoever applied its KindDefinition,
    with what is said above of a Release's writer (name and key print written down by
    the API, a Source that makes a KindDefinition writing its own, nothing new for a
    writer gone or made again, a KindDefinition from before this check making nothing
    new until it is applied again). So the right to apply a custom kind's resources is
    the right to what its controller makes of them in that namespace, as far as the
    definition's writer may make it: whoever may apply the kind in a namespace gets
    there any ConfigMap, Workload or Secret the definition's writer could apply, and
    the answer of a module the writer set is the writer's. Admission modules still run
    on every write of their kind, whoever writes it.
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
- **A node over its limit of relayed Service connections** says no to up to 64 kept
  connections from one other node (256 in all, told apart by their mesh address) and
  hangs up on the rest at once, reading nothing from them: a client whose first bytes had
  gone with such an asking is closed, not tried at the next replica. A kept connection
  that was said no to looks for a place again at its next asking, and is passed on once
  one is free; while it keeps asking it keeps its place among the 64, so four nodes that
  keep asking hold all 256.
- **Backup buckets and S3 endpoints may be on the node's own network** on purpose, and a
  restore, a replica's copy and its sync take no more than the Volume's `size` says
  (above), but a Volume with no `size` is not capped: a bucket someone else writes can
  fill a node's disk through a restore into such a Volume. The primary's copy route builds
  its archive with no cap of its own; the replica that takes it is what stops at the
  size (and a replica of a Volume with no `size` stops at nothing). (T-0230.) An archive
  that is not in depth-first order, which kith does not make, is restored with its
  directories' times as the unpack left them, and where kithd is not root one whose
  directory shuts its owner out before all of it is unpacked is refused. A restored
  Volume's directory is the one the unpack made beside it, with kithd's mode and owner,
  not the empty one it took the place of. (T-0380.)
- **A node with no release key trusts the key of the first OSRelease it takes.** Build
  the image with one (`KITH_RELEASE_KEY`, kept in the signed root) or give it at
  install (`releaseKey`), and that first release must be signed by it. A node with
  none says so at every start and in its Node's `status.os.releaseKeys` (`none`), and
  one whose keys cannot be read says so and takes no release. An OSRelease's image is
  fetched only from an address that is not the node's own or on its networks, checked
  and then held for the connection (no proxy, no redirect); `--lan-releases` lets the
  networks' private ranges through, never the node itself, the cluster's mesh, loopback
  or link-local. With that flag, whoever may write an OSRelease has each node send one
  request to any host of those ranges, at any port and path, and sees in the plan's
  status whether it answered and with what code. Over `http://` someone on the path
  can spoil the download: nothing unsigned is written to be started, but the slot
  being written has lost its system by then, so the node has only the one it runs
  until a download goes through (as when a download breaks off): serve releases
  over `https://`.
  The image's keys are only where a fresh node starts: once it updates, its keys move
  by a signed handover or `--release-key`, not by a new image. (T-0231.) What a taken admin credential can
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
  crosses the TPM's bus encrypted, in a session salted to the TPM's storage key, whose
  name is kept in the lock record (`tpm-parent:`) and checked before any salt or secret
  is sent, so whoever only listens on the chip's pins reads no key, and a TPM that is not the
  one sealed to is refused. What the session does not stop: someone on the bus when
  the seal was made (they could answer with a key of their own, whose name is then the
  one kept; a seal of the older form, with no name kept, is opened and sealed again
  with whichever key answers), whoever can write both the bus and the lock record,
  and someone who resets the TPM on its bus and replays the measurements of an
  allowed start, then asks it for the key themselves. After a start the TPM refused,
  the node seals again for whatever system the cluster then handed the key to. A node
  taken back to a kithd older than the `tpm-parent:` line loses that line, so its next
  seal trusts the bus once again. And all of it has run against a software TPM only.
- **A node with a PIN** (`kith node pin NAME --untried-tpm`, off unless given; the line
  `tpm-pin:` of its lock record) opens its state with its TPM and a PIN of 6 to 32 digits
  typed at its console, and no longer by its TPM alone: its record holds a half of the key
  sealed to the PCRs above (no guess counted) and a half the TPM gives only for the PIN,
  counting each wrong one. Who opens what: the cluster's key still opens it, as before (a
  PIN adds a way, it closes none), and so does the recovery key; a copy of the disk on
  another machine opens by neither half. The guesses are bounded by the TPM, not by kith:
  kithd refuses a PIN unless the TPM's lockout lets through at most one in a hundred of the
  PINs of that length in a year (its M wrong ones at once, then one every I seconds). That
  bound is for a PIN of random digits: a date, or 123456, is among the first guesses, so
  choose the digits at random. Setting a PIN makes kithd take the TPM's lockout
  authorization where it is empty (32 random bytes, kept in a file of its own in the
  node's encrypted state and nowhere else), so that nobody else can forgive the count;
  where someone else holds it, or the TPM refuses the one kithd keeps (a disk moved, a
  state put back: kithd shows it to the TPM each time, and a refused one shuts the TPM's
  lockout hierarchy for its recovery time), the PIN is refused. Setting a PIN again shows
  the kept authorization to the TPM, and that forgives the wrong tries counted; it lets
  nobody try the old PIN, which the new one replaces, and only whoever may apply the
  node's NodeKey can set one. If that state is lost (a
  wipe, or a duress code, which erases the record and with it the state's key), the file
  can no longer be read, and only clearing the TPM in the firmware's settings gives the
  lockout authorization back. Each setting of a PIN tries one wrong PIN, which the TPM
  counts. The bound assumes the machine stays powered; whether a TPM counts a start after
  a power cut as a wrong try is unchecked, on swtpm and on hardware. Anyone at the console
  can type M wrong PINs and lock the PIN for a while; the console says so and when the
  next is taken. After an update that moves the PCRs, the PIN opens nothing until it is
  set again (a seal for the next system is not built: docs/adr-unlock.md, step 4); and a
  node locked, then unlocked, has no PIN until it is set again. The PIN is asked of the node it is for alone, at its
  own address over TLS or its own socket: unlike a passphrase, no node passes one on (a
  relay would see it in plain), and a relayed PIN stays refused until the owner says
  otherwise. It is kept by no node, the store or the audit log, nor shown as it is typed; kithd zeroes its own copies, not the
  ones the HTTP and JSON layers made on the way. It has run against a software TPM only:
  `--untried-tpm` is the owner saying so, until docs/adr-unlock.md's checklist has run on
  that machine. It is a word, not a lock: whoever may apply a NodeKey at that node can
  send the field.
- **A running encrypted node has its key in memory.** The encryption keeps a disk
  that is off, or away from its cluster. While the node runs, the key of its state is
  in the kernel's memory (dm-crypt's) and in kithd's, for as long as it runs: kithd
  keeps it to give the cluster its NodeKey again, to seal it to the TPM again, and to
  wrap it under a new recovery key or passphrase. So whoever is root on the node, reads
  its RAM, or finds a hole that reads kithd's memory has the key. The copies kithd
  makes on the way to the TPM are not wiped after use, because the one it keeps is
  there anyway; a kithd that does not hold the key is a design not built yet (T-0609).
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
- **An update on a node whose state is encrypted is good only once the state is open.**
  A new system is on trial for three starts, and is marked good ten seconds after kithd
  has the node's state to use: on an encrypted node, after its key came (from its TPM,
  the cluster, a recovery key or a passphrase), however long that took. So a new system
  that can never open the state is not kept. And so a node on trial that is kept from
  its key (no seal, and its cluster out of reach) and is restarted three times while it
  waits goes back to the system it ran before, which then waits for the key the same
  way. Nothing is lost by that but the update: its plan is paused, as for any release a
  node came back from, until the release is changed or another is given. (T-0572.)
- **A duress code destroys on purpose, and only what it reaches.** Typed at an encrypted
  node's waiting console (`kith node duress`, off until someone who may apply NodeKeys
  makes one), it writes zeros over the node's lock record (the disk's secret, and what
  the recovery key, a passphrase and the TPM's seal opened) and has the cluster forget
  the node's key. What it does not do: a disk copied beforehand, with its recovery key
  or a passphrase it had, still opens, and until a node of the cluster has heard the
  code such a copy started on the cluster's network is still handed its key; flash
  may keep the record's old blocks (the secret is not in a TPM); the record shows that
  a code exists, though not what it is (a public key made from 128 random bits). The
  console answers every line that opens nothing with the same words two seconds after
  it was entered, the duress code among them, by a clock a test owns; that is all that
  is the same. A write to the disk, a request to the cluster, the cluster's own log
  and audit log (which say that a duress code was typed), and the missing record are
  there for whoever watches the network or reads the disk or the cluster, and a disk
  that takes longer than those two seconds to write would answer late. A node the
  cluster would have opened by itself says after the code what a locked node says,
  and does not open; it says so when it next asks the cluster, which is not held to
  the two seconds. A code is known at a node only once that node, running, has heard
  of it (the NodeKey's status says `duress` or `duressAll`): one that was off since
  before the code was made takes it for a wrong key. The zeros are read back, and a disk that did not take them is
  written again ten times a second for as long as the node waits, with nothing said:
  **a disk that takes no write keeps its record**, and the cluster forgetting is then
  all that was done. A code typed at a console does nothing to a node that runs (its
  console takes no key then); sent to a node's port by whoever has it, it is a wipe
  of a running node as well: the node erases its record and powers off.
  **Forgotten is not gone from every disk.** The cluster stops handing the key out
  and drops it from the NodeKey, which can no longer be rolled back. The store keeps no
  earlier versions of a NodeKey, and every control node, as it applies the write that
  dropped the key, snapshots the store and drops its Raft log up to that write: the key
  is then in no control node's snapshot (`snapshot.json`) or log entry. A node that was
  off does so as it catches up; a leader drops its log once no node it sends to still
  reads that part, and asks again until then. A node stopped between the snapshot and
  the drop drops its log as it starts, and a write the cluster refused that carried a
  NodeKey (in its log as sent) is dropped the same way: whoever may apply NodeKeys can
  so make every control node snapshot as often as they write, with no limit but that
  permission. A store kept before this held earlier versions too: a control node cuts
  them as it starts on this version or takes such a store in (a snapshot sent to it, an
  import), and drops its log if that still holds a key the store does not. Each log
  dropped this way is said on kithd's standard error, with the log's index and the
  NodeKey (a cut of earlier versions alone says nothing). What stays: on a node that
  came from before the store was replicated, `store.json.imported` in its state holds
  no NodeKey (kithd cuts them, and their history, out of it as it keeps it, and at each
  start for one an earlier version kept; a file that is not a store is left as it is
  and said on standard error), but a disk that took no write, or a copy or backup of
  that file from before, has what it had; a backup or a copy of a
  control node's state taken before (kith's own backups are of Volumes and hold no
  store), a worker's `view.json` (a worker is sent its own NodeKey) until the worker
  hears of the change, and on a control node's disk the freed pages of the log file and
  the blocks of the snapshot it replaced, until something writes over them. Whoever
  reads those finds the node's key, wrapped under the secret that was on the erased
  disk, which opens nothing without a copy of that disk. A change to a NodeKey made in the
  same moment (`kith node lock`, a new code) can write the key back for the length
  of one write: it is forgotten again and the change refused, and a waiting node that
  is handed its key after a code tells the cluster again.
  **The cluster forgets for whoever has the code**, at any node's port and with no
  certificate (a waiting node cannot read its own): `POST /v1/forget` gives a number
  and takes it back signed with the code's key, within a minute, once; a copy of the
  disk without the code, a second sending and an old number are refused, all with one
  answer. So a code that leaks is a wipe for whoever reaches the port, and the
  cluster's code (`kith node duress --all`) is that for every node under it: keep a
  code as a recovery key is kept. Whoever reaches the port can also ask for numbers
  until a waiting node's own is pushed out of the 64 that are kept: the node asks
  again every few seconds, and is not told while they keep at it. Only a control
  node forgets: a worker that is asked refuses, and the waiting node asks the next.
  A node the cluster's code forgot (not the one it was typed at) keeps its own code
  and loses the cluster's; unlocked again, it has neither until they are made anew.
  One that was off when the cluster's code was used still knows that code: typed at
  it later, it erases itself, and the cluster, which had forgotten its key already,
  goes on saying forgotten and not wiped.
  **A new recovery key (`kith node recovery`) is written before it is shown**: an
  answer lost on its way leaves a key nobody saw, the old one opening no more and
  `recoverySeen` saying yes (the command says so when it fails: run it again). Where
  the node sees that whoever asked is gone, it puts the old key back; if that write
  fails, the new one stays, seen by nobody. It
  goes from the node that made it to the node that was asked over the cluster's TLS
  and is kept by neither; a control node that is taken can ask any node for one in
  an admin's name, as it can set a passphrase.
  **The cluster's code forgets; it does not erase the others.** Typed at one node, it
  erases that node, and every other node under it loses the cluster's copy of its key:
  it runs on with its state open, drops its seal and its passphrase when it hears, and
  opens from then on with its own recovery key alone until `kith node unlock`. A node
  that was off did not hear and still opens by its seal or passphrase; a node on a
  kithd from before this gives its key to the cluster again; and the cluster makes no
  such code while a node under it has a recovery key nobody was shown, where "shown"
  (`recoverySeen`: by `kith node recovery`, or typed at its console) is not "kept": a
  key shown and lost opens nothing either. It has run in VMs on disk files only.
- **Confidential machines (SEV-SNP, TDX) and device passthrough** have never been run on
  real hardware.
- **Most of kithd's and kith's memory is writable for as long as they run.** Both are
  static programs of musl's, whose start code sets the program's tables of functions
  (the vtables) and its own address table right once and leaves them writable. So the
  first thing each does, before any thread and before it reads an argument, is to make
  that part (the linker's `PT_GNU_RELRO`, about 480 kB in kithd and 77 kB in kith)
  read-only after the start: a write that goes astray in kithd, root and PID 1 on kith
  OS, can then no longer change the tables themselves. It does not protect the pointers
  to a table: those live in the heap, a stack or `.data`, and can still be pointed at a
  table someone made up. Nor does it stop someone who can already make the program call
  `mprotect`. What is not read-only after the start: the heap, the stacks of every
  thread, and the program's `.data` and `.bss`. A node where making the part read-only fails (the kernel says no)
  says so once on its error output and goes on, as a node that cannot protect itself
  still has to boot. `python3 ci/budgets.py` runs both shipped programs and fails when
  any byte of the part is still writable in `/proc/PID/maps`.

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
| 6 | Medium | A Release (and a Source) is rendered and applied with the node's rights, not its writer's. | Fixed: each render is applied only as far as the Release's or Source's writer may apply it, the writer being whoever applied it, written down by the API. Stays: what is said above under "A Release and a Source act with their writer's rights". (T-0229.) |
| 7 | Low | A restore, a replica's copy and its sync have no cap on size; sparse entries in an archive may not be counted (suspected, not traced). | Fixed: each is capped by the Volume's `size` (files, directories and links counted in 4 KiB blocks, a sparse entry at its whole length; the download at twice the size and 1 MiB). Stays: a Volume with no `size` is not capped, and there is no quota on the directory. |
| 8 | Low | A node with no `--release-key` pins the first OSRelease's key; an OSRelease's image address is not vetted (what comes back is thrown away unless signed). | Fixed: a key is given in the image (`KITH_RELEASE_KEY`) or the install's answers (`releaseKey`); the image's address is checked as a Source's and the checked address connected to; `--lan-releases` lets the private ranges of the node's networks through (any port and path there), never the node itself, the cluster's mesh, loopback or link-local. Stays: a node given no key at all pins the first release's, and says so at every start and in its status. (T-0231.) |
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
