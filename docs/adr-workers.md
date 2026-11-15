# A worker keeps no Secret that nothing placed on it names

Status: built (T-0184 step 5): the list a worker's writes are held to ("Writes"), what the
other node routes hand a worker, and the view (`crates/kithd/src/view.rs`); ingress on a
worker (T-0390, "An ingress worker"): its view holds the hosts' certificates, and a control
node orders them.
The design was reviewed three times before there was code (the first draft was found not
sound as written); what each pass found is decided below, and listed at the end. Where
the code differs from the plan is in "As built".

## The problem

Every node of a cluster keeps the whole store: every Secret of every namespace. A node
that only receives the store (a worker, `spec.trust: worker`) is sent the same log as one
that votes. And the node that leads writes whatever any node of the cluster sends to
`/v1/raft/write`. So a worker that is taken reads every Secret and can write anything:
`trust: worker` lowers what it is asked to run, and stops no one who has it. SECURITY.md
says so today.

What is wanted: a worker that is taken gives up the Secrets of what was placed on it, and
can change only what a node says about itself, each such thing checked by a control node.

What is not wanted from this step: hiding templates, Services or other nodes from a
worker. It needs most of them to do its work, and they are not where the Secrets are.

## What a complete answer has

1. A worker is no member of the store's Raft group: not a voter and not a learner. It is
   never sent the log or a snapshot.
2. A control node sends it a **view**: the store without the Secrets, ConfigMaps and other
   kinds it has no use for.
3. Its writes go to a control node, which holds each one to a list of what a node may say
   about itself, field by field.
4. It keeps the view on its own disk, so its mesh, its DNS and its Service proxy come up
   before a control node is in reach. Units wait for a fresh view, as they wait for the
   store today.
5. A cluster of 1.0 nodes and newer ones still works: nothing in the store's format or on
   the wire changes for a control node, and a worker is refused by an older control node
   in words that say why.
6. The docs say what a taken worker still has.

## Options

**A. A view, sent by a control node (chosen).** The worker's kithd keeps the `Store` type
it has and every loop that reads it. Raft on it is given nothing: a node that joined and
has not been sent the store yet is in that state already (its Raft is there, with no
members and an empty log), every loop runs on it, and the leader-only ones skip with no
leader. A client in
kithd holds one connection to a control node and applies what arrives into that store.

**B. Keep the whole store everywhere, seal the Secrets.** Each Secret's values are
encrypted in the store to the control nodes' key and to the key of each node something
that names it is placed on; the node that leads wraps them again as placement changes.
Workers stay learners. It needs no new way to send the store. It does not narrow writes
(the list is needed anyway), a 1.0 node cannot read a sealed Secret, so the store's
format breaks for the kind that matters most, and a worker that is taken keeps every
wrapped Secret it ever saw and waits for a key.

**C. No store on a worker.** A control node renders units and tells the worker to run
them. The smallest thing to trust and the largest change: the controller, claims,
volumes, the Service proxy, DNS and the mesh all read a `Store` today. It is a second
kithd.

**D. A learner whose log is filtered.** Raft's log matching does not allow a follower
whose entries differ from the leader's; openraft has no such mode. The same goes for a
log sent with its Secrets' values blanked: the entries still differ.

**E. Do less: the write list only.** Workers stay learners with the whole store, and
`/v1/raft/write` holds a worker to the list in "Writes" below. A taken worker still reads
every Secret, so "a worker holds no Secret that nothing placed on it names" is not met.
It is step 5's first half, and ships first.

## The view

A kind is sent whole, or not at all, or (two kinds) by what names it. Nothing is sent in
part: a template with pieces left out does not parse (`template` is required, and every
spec refuses a field it does not know), and the proxy, the claims and the seats each read
other Workloads' templates. **A kind not in this table is not sent**, a kind someone
defines included.

| Kind | Sent | Why |
|---|---|---|
| Cluster, Node, Namespace | whole | the mesh's peers, who is there, a namespace's hosts and values |
| Workload, NodeWorkload, Job | whole, spec and status | units to run; the proxy reads other Workloads' ports and labels, claims and seats read every template |
| Service, NetworkPolicy | whole | a connection is admitted on the node it starts at |
| Volume, VolumeClaim, Share, Blob, Image | whole | mounts, replicas, where an image's layers are |
| Device, Seat, DeviceClaim | whole | who holds a Device is worked out from all of them |
| DNSZone, DNSRecord, DNSBlockList | whole | the resolver |
| OSRelease, UpdatePlan | whole | a node updates itself from these |
| Secret | those named (in `env`, `envFrom` or files) by a template whose `status.nodes` names the worker, and the one a Backup of a Volume on it names. A Secret that says `trust: control` is never sent to a worker, whatever names it. To a worker whose Node says `ingress`, the `tls-` Secret of every host a Service exposes too. Never `kith-system/acme-account` | given to its units |
| ConfigMap | those named the same way, and those a DNSBlockList names. Not a Release's `kith-values` (the node that leads reads those) | given to its units; block lists |
| Backup | those of Volumes on the worker | it backs up its own Volumes |
| NodeKey | the worker's own | its encrypted state |
| CronJob, Package, Release, Repository, Source, KindDefinition, KubeObject | not sent | work a control node does |
| Identity, Role, RoleBinding | not sent | a worker's API answers no one by their rights (below) |

The sender decides, never the worker: the control node works the view out from its own
store and the name in the worker's certificate.

**How it is sent.** A snapshot first, then changes: an upsert or a delete, each with the
store index it is true at. The store has no log of changes, and a resource's `revision`
does not move when its status does, so there is nothing to compare cheaply: hashing every
resource for every worker on every change would be megabytes a second on a store that is
only reporting status. So the keys a command touches are noted as it is applied (each
command names them), in a short ring in memory, and a round for a worker looks only at
the keys noted since its last one, at most ten rounds a second. A command that replaces
the store, or a ring that has turned over, is answered with a whole snapshot. The same
ring is what a Kubernetes watch needs to stop reading its whole kind on every change
(T-0288): it is built once.

Which Secrets a worker is sent changes when a placement does, not only when a Secret
does: a round that sees a template's `status.nodes` or its named Secrets change works out
that worker's Secrets and ConfigMaps again.

A resource's history is not sent: what reads it today (which Service had a host first) is
worked out by a control node and read by a worker from the Service's status.

**When a Workload leaves a worker**, the Secrets only it named are deleted from the view,
and the worker's kithd drops them from its store and its disk.

**When the control node goes away**, the worker connects to another (every Node is in its
view), is sent a snapshot, and drops what is not in it.

**Reading its own write.** The answer to a write says the store index it was applied at,
and the worker waits until its view has reached it, as a node waits on Raft today.

## Writes

A node finds the leader from Raft's membership today, which a worker does not have. A
worker sends each write to the control node it is connected to. That node checks it
against its own store and submits it as its own. The check is where a node's write
arrives (`/v1/raft/write` while a worker is still sent the store, the view's own route
after), before the command is given to Raft. That route gives Raft a command as it comes
today: what a node checks before it sends one (a kind's admission, and that a new Blob
comes of putting its bytes) is not asked again there, of any node. For a worker the list
below takes the place of both. For a control node nothing changes: one that is taken is
the cluster taken. What is let through, and nothing else (a write that is refused is
logged naming it, on both nodes):

- **The barrier**: the empty write the controller makes before it starts a unit, one a
  second from each worker at most.
- **A write from a node the asked node has no Node for** is not taken, and asked again:
  what such a node may write is not known there.
- **A unit's report**, in the worker's own name, for a template whose `status.nodes` names
  it. Of the report, only the replicas that `status.nodes` gives this node are taken, only
  the fields a report has today, how many replicas there are is read from the spec by
  the control node, and `ready` is counted again by it. A
  unit's `address` is taken only inside the worker's own part of the mesh. (Today a node
  may name any replica: one replica can say it is all of them and draw the Service's
  traffic.)
- **Its own Node's status**: `os`, `mesh` (its key, its port, whom it reaches) and `serves`
  (the DNS port it answers, `ingress: true` if it answers ingress; null when it serves
  neither), the fields a node writes of itself after it has joined, and `thumbprint` (the
  ACME account's thumbprint its view holds, in a thumbprint's shape). A worker that runs from
  a view is refused `serves.ingress` unless its Node's spec says `ingress` (written by the
  control node that let it join, from the token); the address and `view` are never its to write. A mesh key another Node says is
  refused: two nodes that say one key are both left out of the mesh today, so a worker
  could cut any node off by saying its key. Not `address`, `raftId` or
  `certificate`: the node that admitted it wrote those at the join, and `certificate` is
  what says which key stands for the Node. Not `ca`, not `state`. Nothing of `spec`, so
  not `trust`.
- **Its own NodeKey.**
- **Devices and Seats** whose `spec.node` is the worker in what is sent, and in what is
  stored if there is one by that name: made, changed or deleted. A worker cannot write
  over or delete another node's Device. (Not by the name alone: a Device's name is its
  node's name, a class and an address cut at 63 characters, and node `a` is the start of
  node `a-b`'s. The name still has to start as the worker's own do, so it is not one
  another node's discovery would give.) Its labels are the ones discovery writes and no
  other, the node and the class among them its own: a claim's selector reads labels.
- **About a Volume the store says is on it**: its Image's and its Backup's status, and
  `Volume.synced` where it is a replica. Such a status may name only a Blob the worker
  made, or one that status named before.
- **A new Blob** for an image or a backup it just made, in the namespace of a Volume that
  is on it. The control node writes the worker's name on it (`kith.dev/made-on`). It is
  refused when a Blob of that name is there already in any namespace, or the control node
  still has a file of that name: the same bytes are one blob under one name everywhere,
  and a Blob for bytes a worker has only heard the name of would be a way to be sent them.
- **Deleting a Blob it made**, and no other.
- **Its own name in `Blob.nodes`**, added or removed.

Two rules for what those writes are believed for, since a taken worker can lie in them:

- A worker is never among the nodes that should hold a Blob (`holders()`), and its name
  in `Blob.nodes` never counts as a copy held elsewhere: no node deletes its copy on a
  worker's word.
- A worker's replica of a Volume is made the primary only when no control node has one,
  whatever `synced` it says.

A worker's DNS and block-list loops answer and do not write their kinds' status. (Every
node that answers DNS writes it today, with the same content; on a worker it is skipped.)

Each entry has a test that the same write in another node's name is refused, and one for
each forged field named above.

## What the other node routes hand over

A view that leaves a Secret out is worth little if the bytes can be asked for another
way. Four things nodes do among themselves answer, or believe, any node of the cluster
today:

- **A Volume's copy** (`/v1/volume-copy/NS/NAME`): the node that has a replicated Volume
  sends the whole of it to whichever node asks. It becomes: only to a node the store
  names among that Volume's replicas. For every node, not for workers alone: no node
  that is not a replica has a use for it.
- **A Blob's bytes** (`/v1/blob-copy/NAME`): a node sends any Blob it holds to a node
  that can say its name, and the Blob kind, which a worker is sent whole, says every
  name. An Image is a packed Volume, and a backup's archive is a Blob. For a worker it
  becomes: only a Blob that the status of an Image or a Backup names, where that Image's
  or Backup's Volume is on the worker, or the Image is one a template placed on the
  worker runs. Not every Blob of a namespace the worker has something in: one small
  unit on a worker would then be the backups of every Volume beside it. A worker writes
  the status of its own Volumes' Images and Backups, which is why what it may name there
  is held to what it made (under "Writes"). A node lets go of a blob's file in the round
  its last Blob went (half a minute after the file was written, at the earliest: the
  same bytes may be on their way in again); the ten minutes it waits today stay for a
  file no Blob has named yet (an upload on its way), and after kithd starts again. What is left: the node a worker writes to looks at its own
  files, so for the one round (3 seconds) in which another node still has the file of a
  Blob just deleted, a worker that knew the name can make a Blob of it and ask that node.
  A control node is answered as today: it may be a holder of any Blob.
- **A Volume's key.** Asking for one (`GET /v1/volume-key/NS/NAME`) is answered for the
  Volume's own node alone, and stays so. But the Volume's node also gives the key to
  every other node to keep, again every so often, so that the Volume outlives the nodes
  that had it first: a worker keeps the key of every encrypted Volume today, and a
  replica's and a backup's copy are not encrypted. It becomes: a key is given to control
  nodes only, a worker is asked for none, and a node made a worker erases the keys it
  kept with its copy of the store.
- **Who is there** (`/v1/ping`): a ping carries what its sender has heard of every node,
  and the newest word wins. From a worker only its word about itself is taken: it cannot
  keep a node that is gone looking alive (what was on it would not be placed elsewhere),
  or say what another node has free.

Tests: a worker asking for a Blob nothing on it names, a worker naming another's Blob in
a status, a node that is no replica asking for a Volume's copy, a worker's word about
another node in a ping; each refused or dropped, and written down with who sent it.

## What changes for the rest of kithd

- **The API.** A worker's API port answers no one by their rights: it has no Identity
  and no Role to check them against. It refuses every request of a person's certificate,
  saying which control nodes to ask: reads too, the web UI and the Kubernetes API with
  them (a list read from a view would be wrong without saying so). `kith logs` and
  `kith run` for a unit on a worker are asked of a control node, which checks the caller
  and passes the request on as nodes do today; the worker takes a control node's word
  for who asked. A worker passes nothing on itself: its word for who asked is not taken
  (step 3) and has to stay so, or a taken worker would be whoever it says. It does not
  redirect either: what was sent to a worker, a Secret in an apply among it, the worker
  has by then, and a client that follows a taken worker's redirect sends the rest where
  that worker says. `kith`, a kubeconfig and a browser are pointed at a control node; the
  README says so.
- **The local socket on a worker** is the admin of that worker's own units and of nothing
  in the cluster: `kith apply` on a worker's own shell says to ask a control node. Root on
  a worker is what this design takes to be lost.
- **Services, NetworkPolicies, claims, seats, the mesh.** Unchanged: what they read is in
  the view whole. A test has the proxy, a NetworkPolicy and `claims::resolve` decide the
  same from a worker's view as from the store.
- **Updates.** Unchanged: a worker reads its own Node, the UpdatePlan and the OSRelease,
  and writes its own Node's `os`.
- **Starting units.** The controller waits today for one write to come back before it
  starts anything, so a node never runs from a copy that is behind. A worker waits for
  its first whole view of this start and for the barrier. With no control node in reach
  it goes on running what runs and starts nothing.
- **A worker out of reach** is taken for lost after `--lost-after`, and what it ran is
  placed elsewhere while it may still run it: two copies, and two writers of a Volume
  that is not replicated. That is so for any node cut off today; it is said in the README
  for workers too.
- **Leader-only loops** never run on a worker: it is never the leader.

## Compatibility

- A control node's store, log and node routes are as in 1.0. No field is added to a kind.
- The view is kept in a file of its own (`view.json` in the state directory, mode 0600).
  The store's files and their format are not touched.
- A worker needs a control node that serves the view route. Nodes do not tell each other
  their version today: an older kithd answers 404, and the worker says "this control node
  is older than workers: update it" and tries the next. Nothing falls back to the whole
  store.
- **An existing node made a worker** asks for a view first, and erases its copy of the
  store only once a whole view is on its disk. Then its kithd leaves the Raft group (the
  leader removes a learner). With no control node in reach it stays what it was.
- Until every control node serves the view, `trust: worker` stays what it is today.

## What a taken worker still has

- Every Node's address and mesh key; the Cluster's and every Namespace's settings and
  `values` (what a package's values put there: a password written into values is in
  them); every template (image names, commands, `env` written in place); every Service,
  NetworkPolicy, Volume, Device and claim, with their status. A unit's `message` in a
  status is text its node wrote.
- The Secrets and ConfigMaps of what is placed on it, and of what was placed on it before:
  change those Secrets. A NodeWorkload's Secrets are on every worker it selects.
- **It can draw work to itself.** It reports its own Devices, so it can report a card a
  claim in any namespace selects, and have that Workload, with its Secrets, placed on it.
  `trust: control` on the Secret, or `kith.dev/trust: control` in the template's
  placement, is what keeps something off workers; a selector alone does not.
- It can lie about its own units (within the replicas it was given), about its own Node,
  and about Volumes that are on it; hold on to a Volume replica's data or spoil it.
- It can make a Device under a name another node would use for one of its own, and that
  node's Device is then not reported. Any node can today.
- The files of every Volume that is on it or that it is a replica of, the backups and
  images of those Volumes, and the Images its units run.
- **If it serves ingress** (its Node says `ingress`): the certificate and key of every host a
  Service exposes, so it can pose as each until that certificate is replaced and has expired
  (delete its Node, then each `tls-` Secret: a control node orders new keys), and the ACME
  account's thumbprint, which answers a challenge but orders nothing.
- **If it is an `edge`** (its spec says so, which the owner wrote): other nodes that
  cannot reach each other send their traffic through it, and it reads what is not
  encrypted again inside the tunnel. It can say it reaches every node and be picked
  first. A worker that is no edge is never a relay, whatever it says it reaches.
- It cannot read a Secret nothing placed on it names, or one that says `trust: control`;
  cannot be sent a Volume it is no replica of, a Blob nothing on it names, or the key of
  an encrypted Volume that is not its own;
  cannot write a template, a Secret, a Role, another node's status or Device; cannot make
  another node delete a Blob, or win a Volume from a control node's replica.

## Cost

One connection per worker on one control node, and the ring of changed keys (a key and an
index each; a few hundred entries). A round for a worker reads the resources whose keys
changed and sends those that are in its view; a placement change reads that worker's
templates again (only on a round that touches a template, a Backup, a Volume, a block list
or a Secret). Measured in step 5 with the release binaries: kithd alone with nothing to run
is 8.50 MB (the idle budget, 9.00 MB, not raised); a control node of a cluster of one is
9.78 MB, 10.82 MB with one idle worker following its view, and 10.99 MB with a second
control node instead; the worker is 10.05 MB where that second control node is 10.90 MB.
Not measured: a store whose units report ten times a second.

## Step 5, in order

1. The write list on `/v1/raft/write` for a worker that is still a learner (option E):
   the allow-list, the checks field by field, the two rules for Blobs and replicas, and
   the other routes (a Volume's copy to its replicas only, a Blob's bytes to a worker
   only where something on it names it, a Volume's key to control nodes only, a worker's
   ping taken for itself only). Tests:
   each write in another node's name, a forged replica, a Device with another node in
   `spec.node` or over another node's (a name cut at 63 characters among them), a `synced`
   larger than a control node's.
2. The view: the route, the client, `view.json`, the barrier, the API's refusal. `--ingress`
   on a worker whose Node does not say `ingress` is refused when kithd starts (T-0390).
3. A VM test with one worker: it runs a Workload with a Secret, holds no other Secret on
   its disk, loses the Secret when the Workload leaves, comes back up with no control
   node in reach, and follows a control node that goes away.
4. A cluster of one older control node and one newer: the worker says which is too old.

## As built

- **`status.view` on a Node.** "No field is added to a kind" holds for specs. A control node
  writes `view: true` into a worker's status when it sends it its first view (or lets it in
  as one that asked for a view), and the node that leads sends the store to no worker whose
  status says so. A worker cannot write it (its own Node's `os`, `mesh`, `serves` and `thumbprint` are all
  it may).
  A node whose status says it does not become a control node again by a change to its Node.
- **A worker says at the join that it can run from a view**, and is told the name and key of
  the node that let it in. Whether it is sent a view or the store is not its to choose (the
  sixth review found that it was): a worker's token lets in only a node that says it can,
  and a kithd from before views is refused unless the token was made with
  `kith node token --worker --ingress` (`/v1/tokens?trust=worker&store=whole`: the word on
  the wire is from before ingress workers ran from a view). A kithd started with `--ingress`
  is let in only by that token too, and then runs from a view.
- **One control node, by name and key.** The worker's client takes no other node's
  certificate at the address it calls: the name, and the key that node's Node names in the
  view. Another node of the cluster on the path cannot answer in its place.
- **A write goes to the control node the view comes from**, which passes it to the node that
  leads as its own once it is held to the list, and answers with the index; the worker waits
  for its view to reach that index.
- **Raft on a worker** is opened empty and ended at once: what reads who leads and who votes
  finds a node that leads nothing, with no second path. Nothing of the store is in its files.
- **`view.json` is written whole**: at once for a change to a spec, a deletion or a new whole
  view; at most every 30 seconds while only statuses change.
- **Which Secrets a worker is sent is worked out on every round**, by reading every template:
  cheap in a home's store, to be narrowed to the rounds that touch a template when a store
  is large.
- Not built: a worker that knows of a control node older than views does not skip to the
  next by version, it asks each in turn and says which answered 404.

## An ingress worker (T-0390)

The node most exposed is the one most worth making a worker. It terminates TLS, so it is
sent the `tls-` Secrets of the hosts it serves; that much is what it is for. It needs
neither the ACME account's key nor to write a certificate: the answer to an HTTP-01
challenge is the token and the account key's thumbprint, which is not secret, so a control
node orders and the worker answers. Decided and built:

- **Who says it serves ingress.** The token's maker: `kith node token --worker --ingress`.
  The control node that admits the node writes `spec.ingress: true` into its Node from the
  token, never from what the joining node asks; a node that asks to serve ingress with a
  plain worker's token is refused at the join, and a viewed worker started with `--ingress`
  whose Node does not say it is refused when kithd starts. An owner may also write
  `ingress` into a worker's Node by hand.
- **What its view adds.** The `tls-` Secret of every host a Service exposes (Service and
  Namespace changes make the round work out the names again), and the ConfigMap
  `kith-system/acme` with the account's thumbprint. Never `kith-system/acme-account`,
  whatever names it, and never a Secret that says `trust: control` (a host's `tls-` Secret
  that says so is served by control nodes only).
- **Who orders.** A control node with `--acme`: one that serves ingress orders for itself,
  and the one that leads orders for the hosts only workers serve. It writes the thumbprint
  before its first order, and asks the authority for nothing until each reachable worker
  that serves ingress from a view says, as `thumbprint` in its own Node's status, that its
  view holds it: the authority may ask any node that serves ingress, and one whose view is
  behind would answer 404 and fail the order for an hour. (No fixed pause is long enough
  for a view that lags; the leader logs whom it waits on.) A worker that says a wrong one
  holds up orders, as a wrong answer to the challenge would. The worker writes no
  certificate, no Secret, no ConfigMap and no Service's `tls` status; the write list
  refuses each.
- **A worker that served ingress before this** was sent the whole store, and its Node says
  no `ingress`. It is not moved silently: its kithd says at start what to do, and each
  control node that sends it the store says so once, by name. Writing `ingress: true`
  into its Node makes it ask for a view and erase its copy, as any worker from before views;
  so does deleting it and joining it again with an ingress worker's token.
- **A cluster half updated.** An older control node writes no `ingress` (the node is then
  a whole-store worker, warned about once a newer control node sees it) and sends a viewed
  worker no certificate, refusing its `serves.ingress`: update the control nodes first.
- Tested: `ingress_worker_is_sent_its_hosts_certificates_and_no_other_secret` in
  `crates/kithd/tests/cluster.rs` (a stand-in ACME authority on 127.0.0.1; which Secrets
  the worker's view and files hold, a TLS handshake for its host and none for another, the
  writes refused) and the VM test `sh ci/vm.sh --test worker`.

## Open

- **A Device a worker reports** could be believed only by claims that name the node. Not
  decided: it would change what a selector claim means for everyone.
- **A worker offline for long** runs a view that is old: a Secret changed meanwhile is the
  old one there until it is back.

## What the review of the first draft found

The first draft sent other Workloads "status only", left Blob, Share, Image, Cluster and
Backup out of the table with no default for a kind not listed, forgot the controller's
barrier write and the DNS loops' status writes, took a worker's word for which Devices
are its own and which replicas it runs, and let a worker's word about a Blob or a
Volume's `synced` cost another node its copy. Each is decided above. It also asked for
the tests named under "Writes", "What changes" and "Step 5". A second pass found the
rewrite sound with changes, which are in: Devices are held to `spec.node` and not to
their name, the changed keys are noted where the first rewrite hashed every resource,
the barrier is limited, and the rule for Blobs is said in the code's terms.

A third pass read what was added after it (the other node routes, the API on a worker,
a Node's status) and found: a Blob gate by namespace would hand a worker every backup
of a namespace it runs one unit of; the route a node's writes arrive by checks nothing
of what the sending node checks; a blob's file outlives its Blob by ten minutes; every
node keeps every encrypted Volume's key; a ping's word about other nodes is believed; a
mesh key said twice cuts both nodes off; and a redirect from a worker's API is followed
by no `kith` and would send a client where a taken worker says. Each is decided above.
It did not finish reading who believes a Device's, a Seat's and a Volume's status: step 5
reads those before it lets a worker write them.
