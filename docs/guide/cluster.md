# A cluster

## More than one node

```sh
kithd --listen 192.168.1.10:7443 --name alpha      # first start: makes the cluster's CA
kith node token                                    # on alpha: good once, for an hour
kithd --join 192.168.1.10:7443 --token TOKEN --name beta    # on the other machine
kith get node                                      # on either: alpha and beta, `ready at` their addresses
kith node status                                   # who leads the store, who votes
```

A node that holds the CA and listens on every address (`--listen 0.0.0.0:7443`, or a restart
with no `--listen`) must say where others reach it, `--advertise 192.168.1.10:7443`, or kithd
refuses to start. (A joining node says it by joining; on kith OS, one given an address by its
network says that one.) Identity is kept in `<state>/pki`, so after the first start no `--join`
or `--token` is needed.

Nodes talk TLS with certificates from the cluster's CA: that proves membership, not which
member. Without one, a caller may read the CA certificate and present a join token, nothing
else, and is cut off after 15 s. A token carries its secret, the CA's fingerprint, and the name
and key print of the node that made it: the joiner talks only to that node and names who
answered instead, if anyone else did. (A token from before makers were named still joins, with a
warning, through whichever node answers. A kithd from before cannot use a newer token, "not a
join token": update the joiner first.)

### The store, and who votes

- Every node keeps its own copy of the store (Raft, log in `<state>/raft`). A change made
  anywhere goes to the leader and is answered once more than half the voters have it on disk.
  Reads come from the node's own copy, which can be a moment behind.
- From three nodes on, three vote: lose one and the other two elect a leader within seconds.
  With two nodes (or after one of three is deleted) one votes, since two would stop when either
  did; losing it stops changes until it is back. A node votes only once it has the store.
- Every node tells every other, every two seconds, whom it has heard from. One unheard for ten
  seconds is `unreachable` in `kith get node`, `ready` again when back. A voter unreachable for
  a minute hands its vote to a node that is there, if there is a spare.
- `kith delete node/NAME` removes a member. From the next request its certificate is refused
  (`401`, on the API and between nodes) and it leaves the mesh; nothing restarts. To have it
  back, join it again with a new token (the old certificate stays refused). What it already
  copied it keeps: see SECURITY.md.
- A node that was away while another joined takes the store from the newcomer once a voter it
  knew vouches for it. Reaching none, it asks every five seconds and catches up; only if every
  voter it knew was replaced must it be joined again.
- Tested: `sh ci/vm.sh --test chaos` runs three kith OS VMs with a writer through each, unplugs
  each node's network in turn, resets each mid-write, then resets all three at once. The other
  two always keep taking writes, a cut-off node acknowledges none, and every acknowledged write
  ends up on all three. It does not show lying disks, torn writes, a lossy network or real
  hardware.

### Where work runs

- The leader places each Workload replica on a node with room (`resources`), matching its
  `placement`, not cordoned or tainted, spread out. `kith get workload/NAME -o yaml` shows
  `nodes`, or why one is `unschedulable`; `kith logs` finds a replica wherever it is. A Job runs
  on one node. A new node gets nothing until the leader has heard from it.
- A `NodeWorkload` runs one copy on each node whose labels match `selector` (empty: all), except
  cordoned, `NoExecute`-tainted and lost ones. To label a node: `kith get node/NAME -o yaml`,
  add `metadata.labels`, `kith apply`; copies follow the match. `-o yaml` says which copy number
  runs where, `kith get` shows ready over nodes, and `kith logs nodeworkload/NAME --replica N`
  reads one. With no cluster: one copy if the selector is empty, else none.
- A replica stays put. After its node is unreachable for five minutes (`--lost-after SECONDS`)
  it is started elsewhere and stays there; a Job starts over. A restarted node runs nothing
  until it has caught up with the store, so not while there is no leader.

### The mesh

`--mesh` (or `--mesh 51820`, the UDP port) joins the cluster's WireGuard mesh. kithd makes
`kith0` (`--mesh-interface NAME`) itself, with no `wg` or `ip`; it needs the kernel's WireGuard
and CAP_NET_ADMIN, and runs without a mesh, saying so, if they are missing. An existing
WireGuard interface of that name is taken over (any other kind is refused) and removed when
kithd stops. The mesh adds 0.08–0.15 ms to a veth round trip of 0.03 ms (`sh ci/mesh_rtt.sh`;
the plan allowed 0.3 ms).

- Each node gets a stable IPv6 address derived from the CA and its name; `kith get node/NAME -o
  yaml` shows it and the public key (`mesh`), `kith node status` the peers and their last
  handshakes. The private key stays in `<state>/pki`.
- A peer silent for three minutes is reached through a node with the `edge` role until it
  answers again. The edge machine must forward (`net.ipv6.conf.all.forwarding=1`; kithd warns
  but leaves it alone) and sees what it passes on.

**A laptop** is a node that comes and goes:

```sh
kithd --join HOME:7443 --token "$(…)" --mesh --roaming
```

The cluster then reaches it at its mesh address, through the tunnel it opens from wherever it is
(`spec.roaming: true` on its Node). A roaming node never votes, and what it runs stays its own
however long it is away: nothing moves after `--lost-after`, and nothing new is placed until it
is back. For one gone for good, `kith delete node/NAME`. It must reach at least one node
directly (a public address, or UDP 51820 forwarded at home). Two nodes both behind NAT call
each other where an edge node saw them, which opens a direct path through most home routers;
behind a NAT that gives a new port for each address it sends to, they meet through an edge
node instead. To forbid that:

```yaml
spec:
  roaming: true
  mesh: { relay: never }   # straight to the other node, or not at all
```

`kith node status` says of each peer `direct`, `through an edge node` or `unreachable`. Tunnels
are WireGuard between the nodes' own keys, and kithd's traffic inside them is TLS as well.

### Workers

A node is a control node unless made a worker, which is trusted with less. The token's maker
decides, not the joining machine:

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

| A worker | |
|---|---|
| votes | never, and no Raft message from it is taken. A voter made a worker hands its vote on within seconds; to cut one off at once, delete its Node. Fewer than three control nodes: one votes |
| writes | only what it says of itself: its units' state, its Node's `os`, `mesh`, `serves` and `thumbprint`, its Devices and Seats, its Volumes' backups and images. Anything else is refused and audited under its name (`kith audit`) |
| answers | no person: point `kith`, a kubeconfig, `curl` and the web UI at a control node (`this node is a worker and answers no one by their rights: ask a control node (ADDRESS)`). `kith logs`, `kith volume put`/`get`, `kith node passphrase`, a restore and `kith run` asked of a worker for another node are refused (`node NAME is a worker: its word for who asked is not taken: ask a control node`); asked of a control node they reach the worker as usual |
| holds | no copy of the store, only a view (below); no blob it is not using; no encrypted Volume's key. Its replica of a Volume takes over only when no control node has one |
| does not yet | order ACME certificates, or write `DNSRecord`/`DNSBlockList` status (it answers DNS; control nodes report) |

To keep something off workers:

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

Every node has the label `kith.dev/trust` from its `spec.trust`, for placement and
`NodeWorkload` selectors. Anything naming a `trust: control` Secret is placed on control nodes
only (`missing required labels` if none fits), and a worker hands such a Secret to nothing
(`Secret/NAMESPACE/NAME is for control nodes (trust: control), and this node is a worker`). That
covers `env`, `envFrom` and files, not what kithd reads itself (a Backup's S3 Secret, a `tls-`
Secret, the ACME account). `kith apply`, `delete` and `rollback` refuse to make the CA's node a
worker or leave only workers; a Release, a Source, a controller or two changes at once through
two nodes are not checked, and making a node control again repairs it.

**A worker's view** is what every node needs (Nodes, Namespaces, templates, Services,
NetworkPolicies, Volumes, Devices, DNS) plus only the Secrets and ConfigMaps its own units name,
kept in `view.json` and dropped when they leave (on a worker, `kith get secret/other` for a unit
elsewhere is `not found`, and `kith node status` says which change its view is at and who sent
it). With no control node in reach a worker keeps running from its view, starts nothing new, and
follows another control node when its own is gone (`sh ci/vm.sh --test worker`). A node made a
worker erases its store once its first view is written; to make it control again, delete its
Node and rejoin.

**An ingress worker** (the node the internet reaches) also gets every exposed host's `tls-`
Secret and the ACME account's thumbprint (`kith-system/acme`), never its key. It needs a
`--ingress` token. Control nodes started with `--acme` order its certificates once its view
holds the thumbprint (or after ten minutes, retrying such hosts in fifteen minutes), and it
answers the challenges on port 80:

```sh
kithd --acme ...                         # on each control node
kith node token --worker --ingress       # on a control node
kithd --join ADDRESS --token TOKEN --ingress --mesh   # on the edge machine
```

If it is taken, it has every exposed host's key: delete its Node and each `tls-` Secret, and new
keys are ordered (SECURITY.md, "A node that is taken"; design in `docs/adr-workers.md`). To move
it: join the new one, point DNS at it, delete the old Node.

**Mixed versions.** Set `trust` only once every node knows it: an older kithd cannot read a Node
or Secret with it, and an older control node writes whatever a worker sends (update every
control node before an ingress worker joins). A worker that meets only pre-view control nodes
says `this control node is older than workers: update it` and takes the whole store; one that
served ingress before views keeps getting the store, with a warning, until rejoined or given
`ingress: true`.

### Services across nodes

A `Service` has one mesh address on every node (`kith get service/NAME -o yaml` shows it and its
ready replicas) and the name `<service>.<namespace>.kith`. A TCP connection to it goes to each
ready replica in turn, wherever it runs: kithd relays it, over the mesh if needed, to the
replica's port on `127.0.0.1` (or `::1`). TCP only; a named `targetPort` is a container port of
that name. A kithd restart drops the connections through it.

- Relaying runs on up to four threads of its own and DNS on one more, so a busy Service holds up
  neither the API nor lookups.
- A node relays 4096 connections at a time (1024 per peer node) and closes one silent for an
  hour. A node at its limit refuses, and the asker tries the next replica (past 64 refusals from
  one node it hangs up, closing a client that had spoken).
- Nodes reuse up to 16 idle connections between them for 30 seconds, but each client's
  connection is still asked for and checked against NetworkPolicy. If the far node gives no
  answer in three seconds, a client that had already spoken is closed rather than replayed to a
  second replica.
- On kith OS (kithd as root), a container's connection to a Service with a replica on the same
  node skips kithd: a cgroup program rewrites the address in the kernel. Only for Services no
  NetworkPolicy covers and IPv6 replicas; such connections are outside the 4096, never
  idle-closed, and keep the client's address. If the kernel refuses the program, kithd says so
  once and relays everything.

A `NetworkPolicy` decides who may connect to the Workloads it selects through a Service: the
first ingress rule that fits wins, none means refused. Peers are a `node` or a `cidr`; peers by
`namespace` or `selector` cannot be told apart yet (allow lets nobody in, deny keeps everyone
out) and egress is not enforced; the status says `partial` and why, or `enforced`. A connection
to a node's own address bypasses it.

### Ingress: a host of its own, with a certificate

With `--ingress` (and `--mesh`; for nodes with a public address) a node serves HTTPS on 443 for
every Service with `expose`, by host, passing the connection to the Service's first TCP port;
port 80 redirects. The ports need CAP_NET_BIND_SERVICE.

- **Certificates** live in the Secret `tls-<host>` beside the Service (`tls.crt`, `tls.key`,
  PEM): apply your own, or start with `--acme` (`--acme URL` for another directory; the flag
  accepts its terms) to get and renew one from Let's Encrypt. Point the host's DNS at the
  ingress nodes first, and give `--acme` to every control node that may lead (the leader orders
  for ingress workers). `kith get service/NAME -o yaml` shows `tls`; a failure is retried an
  hour later. Keys, and the ACME account's (`Secret/kith-system/acme-account`), are Secrets in
  the store.
- **Bytes as they are:** TLS ends at the ingress and nothing is added; NetworkPolicy sees the
  ingress node. `expose.proxyProtocol: true` sends a PROXY v1 line (`PROXY TCP4 <client>
  <ingress> <client port> <ingress port>`) first; clients inside the mesh send none, so the
  backend must take both.
- **Who has a host:** `expose.host` must be a name a CA issues for (no IP, no `_`, no label
  starting or ending in `-`). Two Services with one host: the one made first has it, and the
  other says `expose: refused`. Edits and trimmed history do not change the order; a Service
  that is deleted gives its host up. (Older clusters keep this once [the store is in format
  2](os.md#what-an-update-keeps-the-format-of-the-store).) A Namespace with `spec: { hosts:
  ['*.example.org', example.org] }` (YAML wants the `*` quoted) keeps those hosts for its own
  Services and exposes no others.
- **Limits:** 1024 connections per port, 64 per source (IPv4 address or IPv6 /64). Idle 5
  minutes on 443 or 30 seconds on 80, closed.

A host whose `expose` has `paths` or `headers` is served as HTTP/1.1:

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

The longest fitting path wins (`/api` fits `/api/x`, not `/apiary`; `exact` only itself),
unmatched is 404, and an absent Service or closed port is 502; paths are not decoded or
rewritten. kith sets `Host`, `X-Forwarded-For`, `-Proto`, `-Host` and the Service's `headers`,
and drops what a client claims about its origin (`Forwarded`, other `X-Forwarded-*`,
`X-Real-IP`, headers with `_`). Ambiguous framing gets 400; a head is at most 100 headers, ~64
KiB, 30 seconds. WebSocket is the only upgrade; no HTTP/2, and no `proxyProtocol`.

### Not yet

- Non-roaming nodes talk at their plain addresses, not over the mesh; workloads have no mesh
  addresses (Services do); two nodes behind NATs that give a port per address meet only
  through an edge node.
- A changed Workload's replicas on different nodes are replaced all at once (one at a time on
  one node; a NodeWorkload always all at once). Replicas on an unreachable node count as ready
  until `--lost-after`; a roaming node's, indefinitely.
- A change whose answer was lost with the leader may or may not have happened: `kith get`.
- Joining needs an empty `--state`; a node that changes address, or a join that died halfway,
  needs `kith delete node/NAME` and a new token. Only the first node admits, and its tokens do
  not survive its restart (use `KITH_TOKEN`: `--token` shows in `ps`).
- Certificates last ten years and are not renewed (a node's is dropped with its Node, an
  Identity's with the Identity). `kith` talks only to the kithd on its own machine.

## Restarting a node on purpose

Drain a node before restarting or upgrading it. A drain cordons it and adds the `kith.dev/drain`
taint (`NoExecute`): movable replicas start elsewhere; ones pinned by a Volume, a Device or
placement stay, as does a running Job (a drain never stops one), and the plan says why, before
anything changes.

```sh
kith node drain n1 --dry-run   # says what moves and what stays, and why; changes nothing
kith node drain n1             # cordons n1 and starts the movable replicas elsewhere
# restart n1 here
kith node undrain n1           # takes the drain off; replicas that moved are not moved back
```

- The plan has one line per Workload, NodeWorkload and Job, saying where it goes or why it stays
  and what happens if the node is lost (waits, or starts over: a hint; the scheduler decides).
- A drain is an apply of `Node/NAME`: audited, and allowed to whoever may apply Nodes. The plan
  (`GET /v1/drain/NAME`) shows readers of Nodes the lines they may read. A worker plans no
  drain.
- Undrain removes only what the drain added. A cordon from before (an OS update's included: take
  `unschedulable` off the Node) stays; one added during the drain goes with it; an update
  finishing mid-drain lifts its cordon while the taint holds.

### Checkpointing a long GPU Job

A Job runs to its end on one node, and a drain never stops it. Keep its state on a Volume there:
the program reads its last checkpoint at start. If the node is lost, the Job waits for it and
resumes from that checkpoint.

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

The GPU is a `DeviceClaim` ([Hardware](hardware.md#hardware)); the checkpoint format is the
program's. `sh ci/vm.sh --test pods` runs this around a drain: the Job waits while its node is
drained, then resumes from the step it left.

## When every node was off

A power cut takes every node at once, and a cluster of [encrypted
nodes](os.md#encrypted-state) must then come back with nobody at a console. It does, when it was
set up for it:

```sh
kith node recovery n1                  # an unattended install showed nobody a recovery key: make one, keep it
kith node seal n1                      # each control node (a voter) keeps its own key in its TPM
kith node seal n2
kith get NodeKey                       # says which nodes are sealed
sh ci/vm.sh --test blackout            # three control nodes (two sealed) and a worker, killed at once, started again
```

- **The machines must start by themselves.** Set the BIOS (or the board's firmware) to
  "Restore on AC power loss: Power On" (or "Last State"), or start them over the network by
  Wake-on-LAN from another machine that stays up. A machine that waits for a button is a node that
  is off.
- **Seal every voter.** A sealed control node opens its state from its own TPM with no node asked,
  so the voters start without each other, elect a leader and a quorum forms. If one voter is not
  sealed it waits for a sealed one to answer, and while it waits it is not a voter. Seal at least
  as many as make a quorum; sealing all of them is the plain rule.
- **Unsealed nodes and workers wait for a sealed node.** A node with no seal (a worker, say) asks
  the control nodes it knows for its key every few seconds, and is handed it as soon as one of
  them is up; nothing is typed. Its workloads start again after that.
- **A node that was changed is refused by its TPM.** One that was updated, or whose firmware
  changed, since it was sealed is not given the key: it asks the cluster for it instead. So after
  every firmware or OS update, check that `kith get NodeKey` still says the node is `sealed`; if
  it does not, seal it again: `kith node seal n1 --off`, then `kith node seal n1`. When every node
  was off and one of them was changed, that one waits for the others, which open from their TPMs;
  from three control nodes on, the cluster does not need it to start (two of three voters are a
  quorum). With two control nodes there is one voter, and that node has to start.
- **The last way is a recovery key.** If no sealed node will open (every TPM was replaced, or the
  machines were moved), type one control node's [recovery
  key](os.md#encrypted-state) at its console. That node opens its state and, with the cluster's
  records in it, hands each of the others its key as they ask: only the one recovery key is
  typed. An install nobody watched (from a URL, or the network) shows the key to nobody, so run
  `kith node recovery n1` ahead of time and keep what it shows; without it there is no last way.

Writes the cluster acknowledged before the cut are there after it: the test checks every one, on
each of the three control nodes. It starts the two sealed ones first and has them elect a leader
with the third still off, then starts the third and a worker, which are handed their keys. Plan
for the quorum, not for one machine: with three control nodes, two sealed and started are enough.

## DNS

```sh
kithd --dns 192.168.1.10:53          # UDP and TCP; port 53 needs root or CAP_NET_BIND_SERVICE
kith apply -f examples/dns.yaml      # a DNSZone and two DNSRecords
dig @192.168.1.10 nas.home.example   # 192.168.1.20
kith get dnsrecord                   # each one says `served`, or why not
```

Every node started with `--dns` answers the same names.

- The cluster's own names, which no zone can take: `<node>.node.kith` (a node's address),
  `<node>.mesh.kith` (its mesh address) and `<service>.<namespace>.kith` (a Service's mesh
  address, where the asked node is on the mesh).
- A `DNSZone` is a domain kithd answers; a `DNSRecord` is a name in it: A, AAAA, CNAME, TXT,
  SRV, NS or PTR, `*.apps` for a wildcard, `@` for the apex. Values are full names.
- **Split horizon:** a zone with `clients: [192.168.0.0/16]` replaces the everyone-zone of that
  domain for those clients. A client in two lists gets the longest prefix (ties: the list that
  sorts first), so give related zones the same list.
- **Other names** go to `/etc/resolv.conf`'s resolvers (re-read every few seconds) or
  `--dns-upstream 1.1.1.1,9.9.9.9`, for private-network clients only, so kithd is never an open
  resolver. Point your router's DHCP at a node and the house uses it. A CNAME out of a zone
  comes with the target's addresses. Answers are cached by TTL, an hour at most, 4096 answers or
  1 MiB, in memory; questions with client options (subnet, cookie) are not cached.
- **Exposed hosts** (`expose.host`, see
  [Ingress](#ingress-a-host-of-its-own-with-a-certificate)) under a zone are answered with one A
  record per ingress node's LAN address (IPv4 only), at the zone's TTL and clients; the longer
  zone wins. An A or CNAME DNSRecord of that name overrides them; they beat a `*.apps` wildcard.
  Refused hosts, ones the Namespace does not keep, and roaming or unreachable nodes are left
  out.
- **Who serves:** a node's `status.serves` says its `dns` port and `ingress: true`, from its own
  flags (cleared by a restart without them). Its LAN address is the one it was admitted from
  (`status.address`); NAT, a moved node or `127.0.0.1` do not count. A roaming node has its mesh
  address. `kith get node` shows both.

**Block lists** answer names as not there, for `clients` (none: everyone):

```yaml
apiVersion: kith.dev/v1
kind: DNSBlockList
metadata: { name: ads }
spec:
  url: https://lists.example/hosts.txt
  clients: [192.168.0.0/16]
```

- Names come from a ConfigMap key in `kith-system` (`configMap: {name, key}`) or an `https://`
  `url` each node fetches every `interval` (24h default, 5m minimum): a hosts file or plain
  filter rules (`||ads.example^`); other lines are counted and skipped. A name blocks everything
  under it; `answer: unspecified` gives `0.0.0.0`/`::` instead of NXDOMAIN. The cluster's own
  names are answered first.
- `kith get dnsblocklist` says `loaded` or why not; `-o yaml` gives names, skipped lines and
  last read. A failed fetch or a `sha256` mismatch keeps the last good list.
- Fetches are https only, never to the node's own networks, no redirects, 32 MiB at most; the
  list's host sees each node ask. At most 1,000,000 names per node (8 bytes each), memory only.
  A CNAME alias of a listed name is not blocked unless listed too.

### Forwarding one zone

To keep the house resolver and send one domain (`apps.example.test`) to kithd on `192.0.2.10`:
run `kithd --dns 192.0.2.10:53 --dns-upstream 1.1.1.1,9.9.9.9` (upstreams other than the house
resolver, so nothing loops), then point the resolver at it. These come from each resolver's
documentation, not a device: check your version.

| Resolver | Setting |
|---|---|
| AdGuard Home | Settings, DNS settings, Upstream DNS servers: add `[/apps.example.test/]192.0.2.10:53` above the others |
| dnsmasq | `server=/apps.example.test/192.0.2.10#53`, and `rebind-domain-ok=/apps.example.test/` if rebind protection is on (kithd answers private addresses) |
| Technitium | Zones, Add Zone, "Conditional Forwarder Zone": `apps.example.test`, forwarder `192.0.2.10` |
| UniFi | the gateway's Forward Domain setting (where it sits varies by version) |

kithd then sees the resolver, not each device, as the client: include it in the zone's `clients`
(`[192.0.2.1/32]`). `dig @<house resolver> www.apps.example.test` should give kithd's answer,
and other names the same answer as before.

Not yet: DNSSEC and zone transfers.
