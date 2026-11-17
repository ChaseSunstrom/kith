# A cluster

## More than one node

```sh
kithd --listen 192.168.1.10:7443 --name alpha      # first start: makes the cluster's CA
kith node token                                    # on alpha: good once, for an hour
kithd --join 192.168.1.10:7443 --token TOKEN --name beta    # on the other machine
kith get node                                      # on either: alpha and beta, `ready at` their addresses
kith node status                                   # who leads the store, who votes
```

- A node that makes the cluster, or holds its CA, and listens on every address
  (`--listen 0.0.0.0:7443`, or a restart with no `--listen`) must say where
  the others reach it: `--advertise 192.168.1.10:7443`. Without it kithd refuses at
  start, before it serves anything. (A node that joins says where it is by joining; on
  kith OS, one that asked its network for an address says the one it was given.)

- Every node keeps its own copy of the store (Raft, with the log on disk in
  `<state>/raft`). A change made through any node goes to the leader, is
  written to disk by more than half of the voting nodes, and only then
  answered. What a node reads is its own copy, which can be a moment behind.
- From three nodes on, three of them vote, and the cluster goes on when one of
  those is lost: the other two pick a new leader within a few seconds. With
  two nodes (also after one of three is deleted) only one votes, because two
  voters would stop when either one did; losing it stops changes until it is
  back. A node starts to vote only once it has received the store.
- `kith delete node/NAME` takes a node out of the store's members. From the next
  request on, the other nodes refuse its certificate (`401`, on the API and between
  nodes) and drop it from the mesh, with nothing restarted. To have the machine back,
  join it again with a new token: it gets a new certificate, and the old one stays
  refused. What that node already copied it still has: see SECURITY.md.
- A node that was away while another joined takes the store from that one (it may
  lead by now) once a voter it last knew says the newcomer is a member. While it
  reaches none of them it waits, asking again every five seconds, and catches up by
  itself once one is back; only when all of them were replaced while it was away does
  it stay behind until it is joined again.
- Every node tells every other one, every two seconds, which nodes it has
  heard from (none of this goes through the store). A node nobody has heard
  from for ten seconds shows as `unreachable` in `kith get node`, and as
  `ready` again when it is back. A voter that is unreachable for a minute
  gives its vote to a node that is there, if the cluster has one to spare.

- The node that leads the store says which node runs each replica of a
  Workload: one with room for what it asks for (`resources`), that matches its
  `placement`, is not cordoned or tainted, and spread over the nodes. `kith
  get workload/NAME -o yaml` shows where each one is (`nodes`), or why one
  has no home (`unschedulable`); `kith logs` reads a replica's output from
  whichever node has it. A Job is run by one node. A node is given nothing
  new until the leader has heard from it (a few seconds after it joins).
- A `NodeWorkload` runs one copy on every node whose labels match its
  `selector` (empty: every node), except cordoned and `NoExecute`-tainted
  nodes and ones lost past `--lost-after`. Label a node by editing it:
  `kith get node/NAME -o yaml`, add `metadata.labels`, `kith apply`. A node
  that starts to match gets a copy, one that stops loses it; `nodes` in
  `kith get nodeworkload/NAME -o yaml` says which copy (number) each node
  runs, `kith get` shows ready over the number of nodes, and `kith logs
  nodeworkload/NAME --replica N` reads a copy's output. On one node (no
  cluster) it runs one copy if the selector is empty, none otherwise.
- A replica stays on its node. When the node has been unreachable for five
  minutes (`--lost-after SECONDS`), its replicas are started on other nodes,
  and stay there when it comes back; a Job it was running starts over.
  A node that restarts runs nothing until it has caught up with the store
  (it may have lost replicas while it was away), so not while the cluster has
  no leader.

- Nodes talk over TLS and both ends show a certificate from the cluster's CA:
  that proves membership, not which member (every node trusts every other).
  Without one, a caller can read the CA certificate and present a join token,
  nothing else, and is cut off after 15 s.
- A token holds its secret, the CA's fingerprint, and the name and key print
  of the node that made it: a joining node talks only to that node, and any
  other node that answers at the `--join` address is sent nothing (the joiner
  says which node it called and which answered). A token made before tokens
  named their maker still joins, and the joiner says that it names no node:
  then any node of the cluster that answers there is sent it. A kithd from
  before cannot join with a token made after (it says "not a join token"):
  update the joining node's image first.
- A node keeps its identity in `<state>/pki`; after the first start it needs
  neither `--join` nor `--token`.
- With `--mesh` (optionally `--mesh 51820`, the UDP port) a node joins the
  cluster's WireGuard mesh: kithd makes the interface `kith0`
  (`--mesh-interface NAME`) itself, with no `wg` or `ip`, which takes the
  kernel's WireGuard and CAP_NET_ADMIN (without them kithd says so and runs
  without a mesh). Every node gets a stable IPv6 address worked out from the
  cluster's CA and its own name, `kith get node/NAME -o yaml` shows it and
  the node's public key (`mesh`), and `kith node status` lists the peers and
  when each last shook hands. The private key stays in `<state>/pki`.
  Peers are reached at the address the cluster knows them by. One that has
  not answered for three minutes is reached through a node with the `edge`
  role instead, and directly again when it answers; the edge node's machine
  has to forward (`net.ipv6.conf.all.forwarding=1`, kithd warns if it does
  not and leaves the setting alone), and it sees what it passes on. kithd
  takes over a WireGuard interface of that name that is already there (its
  key and peers are replaced; one that is not WireGuard is refused) and
  removes the interface when it stops. `sh ci/mesh_rtt.sh` measures what the
  mesh adds to a round trip between two namespaces on a veth (not a LAN): +0.08 to
  +0.15 ms over the veth's 0.03 ms in five runs here, against the plan's 0.3 ms.
- A laptop is a node that comes and goes. Join it as one:

  ```sh
  kithd --join HOME:7443 --token "$(…)" --mesh --roaming
  ```

  It tells the cluster its mesh key as it joins and is told which nodes to
  call; from then on the cluster talks to it at its mesh address, through the
  tunnel the laptop opens from wherever it is, not at the address it joined
  from. A roaming node never starts to vote (it leaving must not cost the
  cluster its majority), and what it runs stays its own however long it is
  away: nothing is started elsewhere after `--lost-after`, and nothing new is
  placed on it until it is back. That is for ever: for a laptop that is gone
  for good, `kith delete node/NAME`, or take `roaming` off its Node. (`spec.roaming: true` on the Node; a node
  that joined without the flag keeps the address it joined with.)

  For this the laptop has to be able to call at least one node directly: one
  with a public address, or with UDP port 51820 forwarded to it at home. Two
  nodes that are both behind NAT only meet through an edge node (no hole
  punching yet), and an edge node sees what it passes on. If that is not
  acceptable, say so on the Node:

  ```yaml
  spec:
    roaming: true
    mesh: { relay: never }   # straight to the other node, or not at all
  ```

  Its traffic is then never passed on by an edge node, whichever end asks: a
  peer it cannot reach directly is unreachable until it can. `kith node
  status` says of each peer whether it is `direct`, `through an edge node` or
  `unreachable`. The tunnels are WireGuard between the two nodes' own keys,
  which never leave them, and what goes through them between kithds is TLS
  with the cluster's certificates as well.
- A node is a control node unless it is said to be a worker, and a worker is trusted
  with less. Join one as a worker with a token that says so, or say it on a Node that
  is there:

  ```sh
  kith node token --worker             # on alpha: the node this token lets in is a worker
  kith node token --worker --ingress   # a worker that serves ingress: it is sent the hosts' certificates too
  ```

  ```yaml
  apiVersion: kith.dev/v1
  kind: Node
  metadata: { name: gamma }
  spec: { trust: worker }         # or `control`, which is what a Node without it is
  ```

  The token's maker says it, not the machine that joins. A worker never votes on the
  store however much of it it has, and the other nodes take none of Raft's messages
  from it. A node that votes or leads and is then made a worker hands its vote to a
  control node by itself, and is followed until it has (seconds); to cut a node off
  at once, delete its Node. The nodes do not take a worker's word for who asked:
  `kith logs`, `kith volume put` and `get`, `kith node passphrase`, a backup's restore and `kith run`
  asked of a worker for something on another node are refused (`node NAME is a
  worker: its word for who asked is not taken: ask a control node`; for `kith run`,
  `only a control node sends this`). Ask a control node, or the node that has the
  thing. To keep something off workers:

  ```yaml
  apiVersion: kith.dev/v1
  kind: Workload
  metadata: { name: signer }
  spec:
    placement: { require: { kith.dev/trust: control } }   # `worker` is the other value
    template:
      containers:
        - name: signer
          image: registry.example.org/signer:1
  ---
  apiVersion: kith.dev/v1
  kind: Secret
  metadata: { name: signing-key }
  spec:
    trust: control                # given to units on control nodes only
    data: { key: the-key-as-text }
  ```

  `kith.dev/trust` is a label every node has for the scheduler, made from its
  `spec.trust` whatever its own labels say; a `NodeWorkload`'s `selector` takes it
  too. A Workload, Job or NodeWorkload that names a Secret with `trust: control` is
  placed on control nodes only (one that fits on none says `missing required
  labels`), and a worker's kithd gives such a Secret to nothing, whoever placed it
  there: `Secret/NAMESPACE/NAME is for control nodes (trust: control), and this node
  is a worker`. That covers a Secret a unit is given in `env`, `envFrom` or as files,
  and not what kithd reads for itself: a Backup's S3 Secret, an ingress host's
  `tls-` Secret and the ACME account are read by whichever node does that work.
  `kith apply`, `kith delete` and `kith rollback` refuse two changes: making the node
  that holds the CA key (the one the cluster was started on) a worker, and one that
  would leave only workers. A `Release`, a `Source` and a controller are not held to
  that, nor are two changes made at once through two nodes; if only workers come
  about, the nodes that vote go on voting, and making one a control node again puts
  it right. With fewer than three control nodes one node votes, as in a cluster of
  fewer than three nodes.

  A worker writes to the store only what it says of itself: its units' state, its
  own Node's `os`, `mesh`, `serves` and `thumbprint`, its Devices and Seats, and
  the backups and images of the Volumes that are on it. The control node it writes
  to checks each write and
  refuses the rest, in the audit log under the worker's name (`kith audit`). So run
  `kith` on a control node, and point a kubeconfig, `curl` and the web UI at one: a
  worker's port answers no person (`this node is a worker and answers no one by
  their rights: ask a control node (ADDRESS)`), and a change asked at its own
  socket is refused (`ConfigMap/default/app: it is not a worker's to apply: ask a
  control node: a worker writes only what it says of itself`). `kith logs`, `kith
  run`, `kith volume put` and a restore for something on a worker are asked of a
  control node as for any node, and passed on.

  A worker holds no blob but one it is using, is given no encrypted Volume's key to
  keep, and its copy of a replicated Volume takes over only when no control node has
  one. Not on a worker yet: ordering certificates by ACME (an ingress worker serves
  the ones a control node orders, below), and being the only node that answers DNS if you read
  `DNSRecord` or `DNSBlockList` status (a worker answers and leaves the status to
  the control nodes).

  A worker keeps no copy of the store. A control node sends it a view: what every
  node reads to run a cluster (Nodes, Namespaces, templates, Services,
  NetworkPolicies, Volumes, Devices, DNS) and, of Secrets and ConfigMaps, only those
  that something placed on it names. It keeps that in `view.json` in its state
  directory, and lets go of a Secret when the Workload that named it leaves:

  ```console
  $ kith node status                       # on the worker
  this node: beta, a worker: its view of the store is at change 41, sent by 10.0.0.1:7443
  $ kith get secret/other                  # on the worker: a Secret of what runs elsewhere
  error: Secret/default/other not found
  ```

  With no control node in reach a worker runs on from the view it has and starts
  nothing new; it follows another control node when the one it followed is gone.
  One that starts again meanwhile runs nothing until a control node answers, as
  any node that starts with no leader in reach. Tested in VMs (`sh ci/vm.sh --test
  worker`). A
  control node, or a worker from before views, that is made a worker erases its
  copy of the store once its first view is written down; to make it a control node
  again, delete its Node and join it again.

  A worker that serves ingress (the node the internet reaches) runs from a view too,
  which also holds the `tls-` Secret of every host a Service exposes and the ACME
  account's thumbprint (the ConfigMap `kith-system/acme`), never the account's key.
  It is let in only by a token that says so, and a plain worker's token refuses a
  kithd started with `--ingress`. Its certificates are ordered by a control node:
  start the control nodes with `--acme` (with or without `--ingress`); the one that
  leads orders for the workers' hosts once each ingress worker says its view holds the
  thumbprint (or after ten minutes, naming the workers that did not; a host ordered so is
  asked again in fifteen minutes, not an hour), and the worker answers the authority's
  challenges on port 80:

  ```sh
  kithd --acme ...                         # on each control node
  kith node token --worker --ingress       # on a control node
  kithd --join ADDRESS --token TOKEN --ingress --mesh   # on the edge machine
  ```

  If that worker is taken, it has every exposed host's key: delete its Node, then
  delete each `tls-` Secret (`kith get secret`) and the control node orders new ones
  with new keys. To move an ingress worker to another machine: join the new one as
  above, point the hosts' DNS at it, then delete the old one's Node. A worker that
  served ingress before this (sent the whole store to do it) goes on being sent the
  store, and its kithd and every control node that sends it the store say so, with
  what to do: delete its Node and join it again with an ingress worker's token, or
  set `ingress: true` in its Node's spec (it then asks for a view and erases its
  copy). In a cluster half updated, an older control node writes no `ingress` into a
  Node it admits (that worker is sent the whole store, as before, and is warned
  about) and sends a worker it serves no certificate: update every control node
  before an ingress worker joins. What a worker that is taken still
  has is in SECURITY.md, "A node that is taken"; the design is `docs/adr-workers.md`.
  Say `trust` only once every node runs a kithd that knows it: an older kithd
  does not read a Node or a Secret that has it, an older control node writes
  whatever a worker sends it, and a worker that finds only control nodes older than
  views says `this control node is older than workers: update it` and is sent the
  store as before.
- On the mesh a `Service` has an address of its own, the same on every node
  (`kith get service/NAME -o yaml` shows it and the number of ready replicas
  behind it), and the name `<service>.<namespace>.kith` where kithd answers
  DNS. A TCP connection from a node to that address and one of the Service's
  ports goes to a ready replica of the Workloads its selector matches, each
  in turn, on whichever node it runs: kithd passes the bytes on, over the
  mesh if the replica is elsewhere, to the replica's port on its node's
  `127.0.0.1` (or `::1`). A kithd that restarts drops the connections through
  it. A Service's connections are passed on by up to four threads of their
  own (one for each core, started with the first Service) and DNS answers on
  one more, so a busy Service holds up neither the API nor a lookup. A node
  over its limit for relaying says no to the others' asks, which try their
  next replica (past 64 such connections from one node it hangs up instead,
  and a client that had already spoken is then closed). Only TCP; a `targetPort` by name is a container port of that name.
- A `NetworkPolicy` says who may connect to the Workloads it selects through
  a Service: the first ingress rule that fits decides, and when a policy
  selects a Workload and no rule fits, the connection is refused. A peer is
  told by `node` (the node the connection comes from) or `cidr`. Peers by
  `namespace` or `selector` cannot be told apart yet (an allow rule for them
  lets nobody in, a deny rule keeps everybody out) and egress rules are not
  enforced; the policy's status says `partial` and why, `enforced` otherwise.
  A policy does not stop a connection that goes to a node's own address
  instead of the Service's.
- With `--ingress` (and `--mesh`; meant for nodes with a public address) a
  node answers HTTPS on port 443 for every Service with `expose`, by the host
  the client asks for, and passes the connection on to the Service (its first
  TCP port); port 80 sends browsers to HTTPS. Binding the two ports takes
  CAP_NET_BIND_SERVICE. A host's certificate is the Secret `tls-<host>` next
  to its Service (`tls.crt` and `tls.key`, PEM): apply your own, or start the
  node with `--acme` and kithd gets one from Let's Encrypt (`--acme URL` for
  another ACME directory; giving the flag agrees to that authority's terms)
  and another before it runs out. The host's DNS has to point at the ingress
  nodes first: the authority checks by asking port 80 there, and any node
  with `--ingress` can answer (an ingress worker's are ordered by the control
  node that leads the store, and only while it has `--acme`: give it to every
  control node that may lead, above). `kith get service/NAME -o yaml` shows how it
  went (`tls`: its `secret` names the Secret whose certificate serves the
  host, one applied by hand included); after a failure kithd tries again an
  hour later, not sooner.
  TLS ends at the ingress and the bytes go on as they are: no header is added,
  and to a NetworkPolicy the connection comes from the ingress node. With
  `expose.proxyProtocol: true` the backend is sent a PROXY protocol v1 line
  (`PROXY TCP4 <client> <ingress> <client port> <ingress port>`) with the
  client's address before the client's bytes; it is off unless asked for,
  because a backend that does not expect the line will break on it. Only the
  ingress sends it: a client inside the mesh that calls the Service gets
  none, so the backend has to take both.

  A host whose `expose` has `paths` or `headers` is read as HTTP/1.1 instead:

  ```yaml
  apiVersion: kith.dev/v1
  kind: Service
  metadata: { name: web }
  spec:
    selector: { app: web }
    ports: [{ port: 80 }]
    expose:
      host: shop.example.org
      via: edge
      paths:
        - { path: /, service: web, port: 80 }
        - { path: /api, service: api, port: 8080 }
        - { path: /healthz, exact: true, service: api, port: 9100 }
      headers: { X-Env: prod }
  ```

  Each request goes to the Service of the longest path that fits it (`/api`
  fits `/api` and `/api/x`, not `/apiary`; `exact` fits the path alone), as
  the client sent it: nothing is decoded, rewritten or matched as a pattern.
  One that fits none is answered 404. A path's Service is one of the exposing
  Service's own namespace, and is not looked for when applied: to one that is
  not there, or a port nothing listens on, the answer is 502. On its way a
  request is given `Host`, `X-Forwarded-For`, `X-Forwarded-Proto` and
  `X-Forwarded-Host` by kith and the `headers` the Service names, each in
  place of what the client sent; what a client says of where it is from
  (`Forwarded`, any other `X-Forwarded-*`, `X-Real-IP`, a header with `_` in
  its name) goes no further. A request that can be framed two ways is refused
  (400) or its connection closed; a head is 100 headers and about 64 KiB at
  most, within 30 seconds. Only a WebSocket is switched to (`Upgrade`), and
  it keeps its place among the connections. HTTP/2 is not spoken to such a
  host, and `proxyProtocol` is refused with it. Certificate keys and the ACME account key
  (`Secret/kith-system/acme-account`) are in the store like other Secrets.
  `expose.host` has to be a domain name a certificate authority issues for:
  an IP address, a label that starts or ends with `-`, or a `_` is refused
  when applied. Two Services with one host: the one made first has it, and the other's
  status says `expose: refused` and why. First is by when the store says each was
  made, which no edit changes and no trimming of its history loses; a Service that is
  deleted gives its host up, and made again it is the newer one. (A cluster that began
  on a kithd from before this was kept has it once
  [the store is in format 2](os.md#what-an-update-keeps-the-format-of-the-store).)
  Until a host is kept for a namespace,
  whoever may write a Service anywhere has it by being first: a Namespace
  with `spec: { hosts: ['*.example.org', example.org] }` (a name, or `*.` and
  a domain for every name under it; YAML wants the `*` quoted) keeps those
  for its own Services, whichever came first, and exposes no others; a
  Service that asks otherwise is refused the same way, and no certificate is
  ordered for it. Each port takes 1024 connections at
  a time, 64 of them from one source (an IPv4 address, or an IPv6 /64); more
  are hung up on. One with no byte either way for 5 minutes on 443 is closed,
  and one on 80 after 30 seconds whatever it does. Inside the mesh, a node
  passes on 4096 connections to Services at a time (1024 for any one other
  node), and one that is silent both ways for an hour is closed. Two nodes keep
  the connections between them for a while (up to 16, for 30 seconds with no
  client on them) and pass the next client's connection on one of those, so a
  new connection to a Service is seldom a new one between the nodes. Each
  client's connection is still asked for by itself, and a NetworkPolicy is
  asked about each. What a client has already said goes to the other node with
  the asking (and to no replica if the answer is no): if that node gives no
  answer in three seconds, or hangs up with none, the client's connection is
  closed, so that what it said reaches no second replica; one that had said
  nothing yet is tried at the next replica.

Where kithd is root (kith OS), a connection that a container on the node's own
network makes to a Service with a replica on that node does not pass through kithd
at all: the kernel writes the replica's address in place of the Service's as the
container connects (a program kithd puts on the containers' cgroup, and makes again
when replicas change). Replicas on other nodes keep their share of such
connections, through kithd as before. This is only for a Service whose Workloads
no NetworkPolicy is for: one a policy names goes through kithd, which asks at each
connection, and a policy applied later takes the Service off the kernel's path for
the next connection (those already made stay). A connection the kernel passes is
not one of the 4096, is not closed for being silent, and the replica sees the
client's own address. Only a replica that answers on an IPv6 address is passed to
this way. Where the kernel refuses the program, or kithd is not root, kithd says
so once and passes every connection itself.

What a cluster of three does when a node is cut off or loses power is tested
in VMs (`sh ci/vm.sh --test chaos`): three kith OS nodes, and a writer on the
host through each of them. Each node in turn has its card on the cluster's
network unplugged for a while; each node in turn is reset by the hypervisor
in the middle of writes. Every time the other two go on taking writes, and the
node that is cut off acknowledges none. Then all three are reset at the same
moment, so that no node has what another lost. At the end every write that
was acknowledged is on all three nodes, which hold the same. A reset by the
hypervisor loses what the guest had not yet handed to its disk and nothing
else: a disk that says it flushed and did not, a write torn in half, delay
and loss on the network, and real machines are not what this shows.

Not yet: nodes that do not roam still talk to each other at their plain
addresses, not over the mesh, workloads have no addresses of their own on it (a
Service has one), and two nodes that are both behind NAT only reach each other
through an edge node.
Replicas of one Workload on different nodes are all replaced at once
when it changes (on one node it is one at a time; a `NodeWorkload` is always
replaced all at once), and replicas on a node that is unreachable still count as ready until it has been
so for `--lost-after` (five minutes); a roaming node's count as ready however long it is away. A change whose answer was lost with the leader may or may not have
happened; `kith get` tells. Joining needs an empty `--state`. A joined node
that moves to another address has to be deleted and joined again.
Only the first node can admit others, tokens do not survive its restart (and
`--token` shows in the process list until then: `KITH_TOKEN` does not), a join
that dies halfway needs `kith delete node/NAME` and a new token,
certificates last ten years and cannot be renewed (a node's stops being taken when its Node is deleted,
an Identity's when the Identity is), and `kith` itself
only talks to the kithd on its own machine.

## Restarting a node on purpose

To restart or upgrade a node without losing its work, drain it first. A drain
cordons the node and puts the `kith.dev/drain` taint on it (`NoExecute`).
Replicas that can run elsewhere are started on other nodes. A replica pinned to
the node (by a Volume, a Device, or its placement) stays, and so does a running
Job: a drain never stops one. A replica no other node can take stays too, and
the plan says why, before anything is changed.

```sh
kith node drain n1 --dry-run   # says what moves and what stays, and why; changes nothing
kith node drain n1             # cordons n1 and starts the movable replicas elsewhere
# restart n1 here
kith node undrain n1           # takes the drain off; replicas that moved are not moved back
```

- The dry run and the drain print the same plan: one line per Workload,
  NodeWorkload and Job on the node, with where it moves to, or why it stays and
  what happens if the node is lost (it waits for the node, or starts over).
- Undrain removes only what the drain put on the node: a cordon its owner set
  earlier stays. A replica placed on the node after undrain may go back there.
- A drain and an undrain are applies of the Node, so they go in the audit log
  (as an apply of `Node/NAME`), and only who may apply Nodes may drain. The
  plan (`GET /v1/drain/NAME`) is read by whoever may read Nodes, and shows
  them the lines of the kinds and namespaces they may read. A worker runs from
  a view of the store and plans no drain: ask a control node.
- What a line says happens if the node is lost is worked out from what pins
  the replica there, as a hint: the scheduler decides when it happens.
- The cordon is one switch, and a drain does not own it: a drain of a node
  that was cordoned already leaves it cordoned at undrain, also when it was an
  OS update that had cordoned it (take `unschedulable` off the Node then); a cordon put on
  during a drain goes with the drain; and an update that finishes during a
  drain takes the cordon off while the drain's taint still keeps new replicas
  away.

### Checkpointing a long GPU Job

A Job runs to its end on one node, and a drain never stops it. Keep a Job's
state on a Volume, which is a directory on that node: when the Job starts, its
program reads the last checkpoint in that directory and carries on from it. If
the node is lost, the Job waits for the node (its Volume is there), and starts
again from the last checkpoint when it returns.

```yaml
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: train-state }
spec: { node: n1, path: train }
---
apiVersion: kith.dev/v1
kind: Job
metadata: { name: train }
spec:
  template:
    containers:
      - name: run
        image: example/train
        command: [sh, -c, 'exec train --checkpoint-dir /state']
        volumeMounts: [{ volume: train-state, path: /state }]
```

The GPU itself is a `DeviceClaim` on the container, as in [Hardware](hardware.md#hardware).
The checkpointing is the program's: kith keeps the directory and starts the
Job on the node that has it, not the checkpoint format. A Job of this shape is
run twice around a drain in a VM (`sh ci/vm.sh --test pods`): asked for again
while its node is drained it waits, and once the drain is off it says it went
on from the step the first one left.

## DNS

```sh
kithd --dns 192.168.1.10:53          # UDP and TCP; port 53 needs root or CAP_NET_BIND_SERVICE
kith apply -f examples/dns.yaml      # a DNSZone and two DNSRecords
dig @192.168.1.10 nas.home.example   # 192.168.1.20
kith get dnsrecord                   # each one says `served`, or why not
```

- `<node>.node.kith` is the address each node of the cluster is reached at,
  `<node>.mesh.kith` its address on the mesh (if it is on it), and
  `<service>.<namespace>.kith` a Service's address on the mesh (where the
  node asked is on it). Names under `kith` are the cluster's own: a zone
  cannot take them.
- `status.serves` on a Node says what the node answers: `dns` the port it serves
  DNS on, and `ingress: true` if it serves ingress. A node says it from its own
  `--dns` and `--ingress` flags (a `--dns` on port 0 is not said), and a restart
  without them sets it to null. That is the node's word, and a node that is
  unreachable is not counted as serving. A node's address on the LAN is the host
  of `status.address`, the address the control node that admitted it saw at
  join; a node behind NAT, or one that moved to another address, is not covered
  (delete it and join it again), and this machine's own address (`127.0.0.1`) is
  not one. A roaming node has its address on the mesh instead. `kith get node`
  shows both.
- A `DNSZone` is a domain kithd answers itself; a `DNSRecord` is a name in one:
  A, AAAA, CNAME, TXT, SRV, NS or PTR, `*.apps` for a wildcard, `@` for the
  zone itself. Names in values are full names (`nas.home.example`).
- A host a Service exposes (`expose.host`, see [More than one node](#more-than-one-node))
  under a zone's domain is answered at the LAN address of each node that serves
  ingress, for that zone's TTL and clients: one A record per node, IPv4 only
  (no AAAA for the LAN). A host under two zones is the longer zone's. A DNSRecord
  of the same name that is an A or a CNAME is answered instead; a TXT or other
  record beside it does not stop the addresses. An exposed host is answered before
  a `*.apps` wildcard DNSRecord, which answers the other names. A host its Namespace does not keep for it,
  one that is refused, and one under no zone are not answered here. Roaming,
  unreachable and LAN-less nodes are left out. The table is rebuilt when a
  Namespace's hosts or a node's `serves` or state changes.
- Split horizon: a zone with `clients: [192.168.0.0/16]` is what those clients
  get, in place of a zone for everyone with the same domain. A client inside
  two different `clients` lists gets only one of them, the list with the
  longest matching prefix (`10.1.2.0/24` beats `10.0.0.0/8`; equal prefixes
  go to the list that sorts first): give zones that belong together the same
  list.
- Every other name is passed to the resolvers in `/etc/resolv.conf`
  (`--dns-upstream 1.1.1.1,9.9.9.9` to say which), for clients on private
  networks only, so a kithd reachable from the internet is not an open
  resolver. Point your router's DHCP at a node and the whole house uses it.
  The file is read again every few seconds while kithd runs (a kith OS node
  gets its lease, and its resolvers with it, after kithd started), unless
  `--dns-upstream` names them.
  A CNAME in a zone to a name outside it is answered with the target's
  addresses from those resolvers too, so stub resolvers get one reply to use
  (the CNAME alone when they do not answer).
- A `DNSBlockList` is names answered as not there, for the clients it names
  (`clients`, as a zone has them; none: everyone). The names come from a key
  of a ConfigMap in `kith-system` (`configMap: {name, key}`) or from an
  `https://` address each node fetches itself (`url`, again every `interval`:
  24h unless it says, 5m at least). A list is a hosts file, one name a line,
  or a filter list's plain rules (`||ads.example^`); any other line is skipped
  and counted. A listed name blocks every name under it. `answer: unspecified`
  gives `0.0.0.0` and `::` in place of NXDOMAIN. The cluster's own names and
  zones are answered first, so a list cannot hide one.

  ```yaml
  apiVersion: kith.dev/v1
  kind: DNSBlockList
  metadata: { name: ads }
  spec:
    url: https://lists.example/hosts.txt
    clients: [192.168.0.0/16]
  ```

  `kith get dnsblocklist` says `loaded`, or why not; `-o yaml` has how many
  names it holds, how many lines were skipped and when it was read. Only https
  is fetched, from an address that is not this node's own or on its networks
  (a list of your own goes in the ConfigMap), no redirect is followed, and no
  more than 32 MiB is read; `sha256` names the one text that is taken. A fetch
  that fails, or a list that does not match, leaves the last good list in use
  and the status says why. A node holds 1,000,000 names in all its lists
  together, 8 bytes each (100,000 names: 0.8 MB); a list that would pass that
  is refused whole. Nothing of a list is written to disk. The host of a `url`
  list sees each node's address and when it asks. A name that is only an alias
  (a CNAME) of a listed name at the other resolvers is not blocked: lists name
  the alias too, or it gets through.
- What the other resolvers answer is kept for as long as its records say, an
  hour at most, in 4096 answers or 1 MiB, the oldest going first; memory only.
  A question that carries options of the client's own (its subnet, a cookie)
  is asked each time.
- In a cluster every node started with `--dns` answers the same names.

### Forwarding one zone

Keep the house resolver as the one clients ask, and send one domain of kith's
DNSZone to kithd: `apps.example.test` here, with kithd on a LAN address of a
DNS node (`192.0.2.10`). Run kithd with `--dns 192.0.2.10:53`, and with
`--dns-upstream` set to resolvers that are not the house resolver (`1.1.1.1,9.9.9.9`),
so a name kithd does not know goes out and does not come back to it.

The setting for each resolver, from what its documentation says the menu or file
is called. None of them was tried on a device for this guide, so each line says
"not tried" and the name is to be checked against your version:

- AdGuard Home (not tried): Settings, DNS settings, Upstream DNS servers: add the
  line `[/apps.example.test/]192.0.2.10:53` above the other upstreams.
- dnsmasq (not tried): `server=/apps.example.test/192.0.2.10#53` in the config (or
  a file in `/etc/dnsmasq.d/`), then restart dnsmasq.
- Technitium (not tried): Zones, Add Zone, type "Conditional Forwarder Zone": zone
  `apps.example.test`, forwarder `192.0.2.10`.
- UniFi (not tried): the gateway's forward domain setting (Forward Domain in
  Network's settings; where it sits depends on the version). Clients keep the
  gateway as their resolver.

Once the house resolver forwards the zone, kithd sees the house resolver's address
as the client, not each device's. The zone's `clients` must then include that
address (`clients: [192.0.2.1/32]` for a resolver at 192.0.2.1), and the zone no
longer tells one device from another.

dnsmasq with rebind protection drops answers that are private addresses, which
the LAN addresses kithd answers with are. Allow the zone with
`rebind-domain-ok=/apps.example.test/` (not tried).

Then `dig @<house resolver> www.apps.example.test` should give kithd's answer,
and `dig @<house resolver> www.example.org` the same answer as before. Only one
zone is forwarded: the others stay with the house resolver, which is what a
forwarder for one domain is for.

Not yet: DNSSEC and zone transfers.
