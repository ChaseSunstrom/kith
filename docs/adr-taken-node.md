# A taken control node is not the cluster taken

Status: decided, not built (T-0737). This is a design record. No code changes with it.
Layers 1 and 2 are the build that follows it. Layer 3 is its own task (captured as
T-0742). Where this record names today's code, the line was read from the code when it was
written.

## The problem

SECURITY.md says it plainly: a control node that is taken is the cluster taken. Whoever has
root on one control node holds its node certificate and key. With them they can name the
local socket to another node, lead writes, and write whatever a node of the cluster may send.

A worker is held already. It is no member of the Raft group, it is sent a view without the
Secrets, and its writes are checked field by field (docs/adr-workers.md). A control node is
held to none of that, because it must vote, keep the whole store and lead.

What is wanted: a taken control node can no longer act as a person, cannot write what is
not its own to write, and cannot get a forged entry applied on the other nodes. What it
still reads (every Secret) and what the CA node still mints stays open, and is said so below.

## What a taken control node can do today

Each door, with where it is.

1. **Name the local socket.** The local socket's API is served as `Caller::Admin`
   (crates/kithd/src/main.rs:872-873). On a hop, the sending node names its caller, and the
   name "local socket" is read back as Admin (crates/kithd/src/access.rs:48). A node
   certificate on a passed-on path takes that name as given
   (crates/kithd/src/access.rs:366-367), and Admin has every right
   (crates/kithd/src/access.rs:104). The run hop does the same with the name in its body
   (crates/kithd/src/api/run.rs:253), and lets Exec through for a node
   (crates/kithd/src/api/run.rs:258).
2. **Name any person.** The paths passed on by name are logs, volume files, a lock's
   passphrase and recovery, and a backup's restore (crates/kithd/src/access.rs:196-208). The
   node that receives one believes the `x-kith-for` header
   (crates/kithd/src/access.rs:41, crates/kithd/src/access.rs:456-459). The senders are
   crates/kithd/src/api.rs:822, crates/kithd/src/crypt.rs:1549,
   crates/kithd/src/backups.rs:958, crates/kithd/src/volume_files.rs:391 and
   crates/kithd/src/api/run.rs:165-193. Nothing the person signed comes with it.
3. **Write as a person through the leader.** The leader's `/v1/raft/write`
   (crates/kithd/src/raft.rs:465) reads the same header from a control node and writes as
   that Identity (crates/kithd/src/raft.rs:493-509). It re-decides the write with `turn`
   (crates/kithd/src/raft.rs:524), against the store, but for the name it was told.
4. **Write as itself, unchecked.** A control node that names no one "is let write as
   itself" (crates/kithd/src/raft.rs:491-492). `turn` checks nothing for a caller that is not
   an Identity, unless the write changes access (crates/kithd/src/raft.rs:680-682). An
   Admin write on a follower is forwarded with no name at all
   (crates/kithd/src/raft.rs:787-788), so the leader cannot tell it from the node's own. A
   worker's writes, by contrast, go through `checked` (crates/kithd/src/worker.rs:501).
5. **Feed the log.** Append, vote and snapshot are open to any control node
   (crates/kithd/src/raft.rs:231-259, crates/kithd/src/cluster.rs:606-607). A taken node
   that wins a vote leads, and the state machine applies every entry it is sent with no
   check (crates/kith-store/src/machine.rs:223-266), membership entries too.
6. **Be the controllers.** The leader alone runs the scheduler
   (crates/kithd/src/sched.rs:448), cron (crates/kithd/src/cron.rs:186), updates
   (crates/kithd/src/update.rs:259), Releases (crates/kithd/src/releases.rs:725), Sources
   (crates/kithd/src/sources.rs:876), the registry (crates/kithd/src/registry.rs:578), wasm
   controllers (crates/kithd/src/controllers.rs:365), ingress certificates through ACME
   (crates/kithd/src/ingress.rs:1147) and Service status (crates/kithd/src/services.rs:980).
   Each writes as the node.
7. **Mint certificates, if it is the CA node.** The CA key is loaded only where it is
   (crates/kithd/src/pki.rs:261-266). That node issues node, user and workload certificates
   (crates/kithd/src/pki.rs:125-160). `issue_user` makes the person's key and returns it
   (crates/kithd/src/pki.rs:144), so the CA node saw it.
8. **Read every Secret.** Every control node keeps the whole store.

What holds already: every request with a node certificate looks the Node up and is refused
if it was taken out (crates/kithd/src/cluster.rs:375-381). A worker is refused the Raft
routes and the hops (crates/kithd/src/cluster.rs:652-653, crates/kithd/src/access.rs:359).

## Three layers

1. **Hop callers signed.** A node that passes a caller on also passes the caller's own
   signature over the request. The node that receives it checks the signature, not the
   sending node's word. Closes doors 1 and 2.
2. **A control node's own writes held to its own list.** A write to the leader that no
   person signed is the node's own. The leader holds it to a list of what a node may say
   about itself, as it does a worker's. Closes door 4, and door 3 with layer 1.
3. **The check at apply.** Each log entry carries its signature, and every node checks it
   as it applies the entry. Narrows doors 5 and 6.

Layers 1 and 2 stop a taken node that does not lead. **They do not stop a taken node that
leads.** The leader writes the log itself: what it appends is applied on every node, signed
or not, checked or not (crates/kith-store/src/machine.rs:223-266). And a taken control node
can make itself leader through the vote route (door 5). Only layer 3 closes that, and it is
its own task (captured as T-0742), not part of this build.

## Where the admin's key lives

Today the local socket has no key: it is Admin because it is the socket
(crates/kithd/src/main.rs:872-873), and the CLI talks to nothing else
(crates/kith-cli/src/main.rs:708). Releases say so too: "the local socket has no key"
(crates/kithd/src/releases.rs:48).

Root on a taken node reads any key file on that node, and reads a passphrase as it is
typed at that node's console. So no answer keeps the admin's key safe on a node that is
taken. What an answer can do is keep the key off every node, so that taking one node does
not give it.

The options:

- **A key file.** `kith` keeps a private key in a file and signs with it. On a node, it is
  the node's to read. On a laptop or a phone, it is safe from the nodes, but is one more
  thing to lose, and a stolen laptop has it.
- **A key from a passphrase.** `kith` asks for the cluster's admin passphrase and derives
  the key from it with PBKDF2, in ring. Nothing is kept on any disk.
- **A cluster setting that phases signing in.** Not a key of its own. It says whether an
  unsigned admin is still taken, so a cluster that runs today keeps running.

**Decided: a key derived from a passphrase, never kept on any disk, phased in by a cluster
setting.** Why: it is the one option with nothing to steal from a disk, on a node or off one.
A key file on a node adds nothing over the node's own key. A key file off the nodes is safe
from them but not from the loss of the laptop, and kith has no way to turn a lost one off
short of changing the key everywhere.

How:

- Seed = PBKDF2-HMAC-SHA256(passphrase, salt = the cluster id, 600 000 rounds), 32 bytes.
  The cluster id is the SHA-256 print of the cluster's CA certificate. One passphrase gives
  each cluster its own key.
- The key is Ed25519 from that seed (ring `Ed25519KeyPair::from_seed_unchecked`). Its
  public key is kept in the Cluster resource (crates/kith-api/src/kinds.rs:190-212), as
  `spec.adminKey`.
- The admin signs from a machine that is not a node: a laptop or a phone running `kith`
  over TLS. `kith --server HOST:PORT --identity DIR` (cargo feature `remote`) talks to a node
  over TLS with a client certificate; it does not sign yet. Signing is its own slice.
- At a node's console, `kith` may still sign: it asks for the passphrase, signs that one
  command, and drops the key. **That key is exposed to that node.** If the node is taken,
  or is taken later while the passphrase is still the same, the admin key is taken. The
  docs say so beside the command.

What the console becomes: once the cluster says `required`, an unsigned call on a node's
local socket is the node itself, not Admin. It still reads what the node already holds (the
whole store, its own units and logs), and it may do what layer 2 lets the node write about
itself. A write to the cluster, a hop to another node, or a change of access needs a
signature.

What is lost in convenience: no more "sudo kith apply" at any node with no question asked.
Each cluster write at a console asks for the passphrase, and costs a fraction of a second
of PBKDF2. A session cache is allowed off the nodes only. A forgotten passphrase is a
forgotten admin: the way back is the claim at a new cluster's console
(crates/kithd/src/cluster.rs:767-799), or a Role granted to an Identity beforehand.

The setting: `spec.signing` in the Cluster resource, `open` or `required`. A cluster made
before this is `open`: unsigned "local socket" and `x-kith-for` hops are taken as today, so
nothing that works stops. A new cluster is `required`. Moving to `required` is one signed
write, and is refused until every node reports a kithd that checks signatures (see Rolling
updates). Moving back must be signed by the admin key too, so a taken node cannot.

The first `adminKey` is written while the cluster is `open`, or at the claim. That is trust
on first use, said so. Changing it later must be signed by the old key.

People who use the TLS port with curl or kubectl cannot sign a request. For them the hop
goes away: a node that would pass a person on answers 307 to the node that has the thing,
or the leader for a write. The client follows it, and the far node sees the person's own
certificate. A client that signs (`kith` over TLS, with the key of its certificate) can be
passed on with its signature.

## What a signature binds

One header, `x-kith-signed`, on the request as the signer sent it and as every hop passes it
on unchanged:

```
x-kith-signed: v1; who=<name>; target=<node or *>; expires=<seconds>; nonce=<32 hex>; sig=<base64>
```

The signature is over these bytes, UTF-8, each field ending in one `\n`:

```
kith-signed-v1
<cluster id: the 64-hex SHA-256 print of the CA certificate>
<target: the node's name, or * for a write to the log>
<method, upper case>
<path and query, exactly as sent, percent-encoding kept>
<64-hex SHA-256 of the body; of the empty string for none>
<who: "local socket", an Identity's name, or "node:<name>">
<expires: seconds since 1970, decimal>
<nonce: 32 hex, 16 random bytes>
```

- **who** is checked against `spec.adminKey` (Ed25519) for "local socket", an Identity's
  `publicKey` (P-256 ECDSA, as releases.rs:39-43 reads it) for a person, and the key of its
  node certificate for a node.
- **cluster id** stops a signature for one cluster being used on another.
- **target** stops a hop signed for one node being sent to another. A write to the log is
  signed for `*`: any node may pass it to the leader, and the leader is the target.
- **method, path, query and body** stop it being used for another request.
- **expires** is the signer's clock plus five minutes. A node refuses one past its own clock,
  or more than ten minutes ahead of it (a signer whose clock runs fast). Short, so a copied
  header is soon worth nothing.
- **nonce** stops it being used twice. Each node keeps the nonces it has taken, in memory,
  until they expire, and refuses one seen. The set is bounded by the window: at most what a
  node is sent in ten minutes.

Replay across nodes: a hop names its target, so a header taken at n2 does not pass at n3. A
write signed for `*` could be sent to two nodes, and both pass it to the leader; the leader
keeps one nonce cache, so the second is refused there. A leader that changes loses its
cache, and so does a node that starts again: until layer 3 keeps nonces in the store, a
request can be replayed once across a change of leader or a restart, inside its window, by a
node that saw it pass. Said so; layer 3 ends it.

## Layer 2: what a control node may write for itself

At `/v1/raft/write`, a write with no `x-kith-signed` is the node's own. Today it is let
through (crates/kithd/src/raft.rs:491-492). With layer 2 the leader holds it to a list.

The list is default-deny: a kind not on it is refused. It is built from the worker's
(crates/kithd/src/worker.rs:501): `Patch`, `Status` and `Report` of the node itself and of
what is placed on it, and `Apply` of the few kinds a node makes for itself, each checked
field by field as the worker's are. Then the slice lists every write a control node makes
that does not run on the leader alone (the counts of `submit` and `write` calls per file
are the starting point: crates/kithd/src/raft.rs has 11, ingress.rs 8, crypt.rs 7,
cluster.rs 7), and adds each, by kind and field, or moves it to the leader.

A test walks every kind kith knows (`kith_api::KINDS`, crates/kith-api/src/lib.rs:132) and
fails on one the list does not name, as allowed with its fields or as refused. A new kind
fails CI until someone decides what a node may write of it.

A refused write is said in the audit log with the node's name. The leader's own writes do
not go through `/v1/raft/write`, so the list does not touch the controllers (door 6): that
is layer 3's.

Built (T-0746). The list is `CLASSES` in crates/kithd/src/own_writes.rs: the 38 kinds of
`kith_api::KINDS`, each marked yes or no, and `every_kind_is_classified` fails on a kind
left out. Eleven are yes (Node, Workload, NodeWorkload, Job, Volume, Blob, Backup, Image,
Seat, Device, NodeKey); what they may hold is the worker's own check (worker.rs `patch`,
`status`, `report`, `apply`, `delete`), with the control node's own Node open to any status
field and its raft id only as its name gives it. Rollback, Import and Mark are refused
whatever they name. `held` in raft.rs makes the one call per write, and a refusal is said
on the console (`kithd: refused a control node's own write: NODE: WHY`) and audited under
the node's name.

Open in this layer: under `spec.signing: open` a taken control node can skip the list. It
sends `x-kith-for: local socket` (the admin hand-off, accepted from any node peer) or
`x-kith-worker: NAME` (a worker's write it passes on, taken for any name that is a
worker), and either header takes the write off the control node's own path. Layer 3
(T-0742) closes it, with the signature `required` already refuses both unsigned.

## Layer 3

Out of this task's build; its own task (captured as T-0742). Written down here so layers 1
and 2 are built to fit it.

A new command, `Signed { envelope, signature, command }`, next to the ones in
crates/kith-store/src/lib.rs:61-98. It is gated as `Mark` was: FORMAT goes from 2 to 3
(crates/kith-store/src/lib.rs:39), and no node writes one until every node reads it.

Every node, applying an entry, decides the same way from the entry and its own store only:

1. Checks the signature against the key in its store, as it stands at that entry.
2. Checks the signer may do the command, with the rights in that store
   (`Grants::of`, crates/kithd/src/access.rs:102-131).
3. Checks the nonce. Nonces are kept in the store, per signer, with their `expires`. A nonce
   seen is refused. An entry whose `expires` is more than five minutes before the newest
   `expires` of the same signer is refused, and nonces older than that are dropped.
4. Takes time from the envelope's `expires`. Never the clock: two nodes must decide alike.

Kept per signer, a forged far-future `expires` spoils only the forger's own key. A refused
entry is applied as nothing, on every node alike, and counted in the audit log. The stores
stay equal because every input to the decision is in the store or the entry.

The leader's controllers (door 6) write what no person signed: it is derived from what
people signed. Layer 3 signs those entries with the leader's node key and holds each to what
it is derived from:

| Writer | Writes | Checked at apply |
|---|---|---|
| Scheduler (sched.rs:448) | a placement | the Node is in the store, admitted, and fits the template's selectors |
| Releases (releases.rs:725), Sources (sources.rs:876) | what a Release or Source renders | the owner (`kith.dev/owned-by`, releases.rs:29) is in the store, and the write is within its writer's rights (`kith.dev/written-by`, releases.rs:33, with its key print, releases.rs:37), as `writer_may` decides it now (sources.rs:765) |
| Cron, updates, wasm controllers, registry | what their resource asks for | the same: the owner is in the store, and the write is within its writer's rights |
| ACME (ingress.rs:1147) | a host's certificate Secret | the host is named by an Ingress in the store |
| Service status (services.rs:980), any status | status only | a `Status` or `Report` command, no spec |

What a taken leader still can with layer 3: pick among the choices that pass. Put a Pod on
itself if it fits, render a Release wrong within its writer's rights, get a certificate for
a host already routed. Membership entries are applied by openraft, not by our state
machine, and a snapshot is the leader's word for the whole store: both stay open.

## Rolling updates

A cluster is updated one node at a time, so old and new kithd meet.

- **An older node sent a signed request** does not know the header and ignores it. It
  takes the hop as today: "local socket" or `x-kith-for` by name. Nothing breaks, and
  nothing is gained on that node until it is updated.
- **A newer node sent an unsigned request** takes it as today while the cluster is `open`.
  Under `required` it refuses it, in words that name the reason: "refused: an unsigned
  caller passed on by node n2; this cluster requires a signed one (spec.signing:
  required), so update kith on n2".
- `required` cannot be set while any node reports an older kithd: the write is refused,
  naming the nodes. So a newer node meets an unsigned hop only from a node that is taken
  or was put back to an older kithd by hand, which is what the refusal is for.
- Layer 3's `Signed` entry waits for FORMAT 3 on every node, as `Mark` did.

## Slices

Sizes are against the kithd budget of 13.00 MB (ci/budgets.py:44); kithd is about 11.4 MB.
ring is linked already (crates/kithd/Cargo.toml: `ring = "0.17"`; ECDSA in
crates/kithd/src/acme.rs:11-12), so Ed25519, PBKDF2 and SHA-256 cost only the code that
calls them.

1. **The admin key and the setting.** `kith` derives the key; `spec.adminKey` and
   `spec.signing` in the Cluster; the console's unsigned call becomes the node. Test: a CLI
   unit test that one passphrase and one cluster id give one key, and another id another;
   an access.rs test that an unsigned socket call under `required` is the node. About
   +15 KB kithd, +20 KB kith.
2. **Layer 1: hop callers signed.** The header, the bytes above, the check where it lands,
   the nonce cache, the 307 for TLS people. Test: access.rs unit tests (an unsigned "local
   socket" hop refused under `required`, a signed one taken, the same nonce twice refused,
   an expired one refused, one for another target refused, another body refused). About
   +60 KB.
3. **Layer 2: a control node's own writes held to its list (built, T-0746).** The default-deny
   list and the test over every kind. Test: raft.rs unit tests (a control node's own Secret
   write refused, its own Report taken). About +20 KB. Open under `spec.signing: open`: the
   admin hand-off and the worker header are taken on a node peer's word until layer 3.

The VM test for slices 1 to 3 extends `ci/vm.sh --test access` (three nodes, n1 leads):

- the admin applies through n2, which does not lead, signed: taken, as the access test
  writes through n2 and n3 today;
- n2 calls n3's run hop and logs with its own node certificate, naming "local socket" and
  an Identity, unsigned: both refused;
- n2 replays a signed header it was sent, to n3 and again to n1: refused;
- n2 posts a RoleBinding to n1's `/v1/raft/write` with its node certificate: refused.

4. **Layer 3: the check at apply** (captured as T-0742). `Signed`, FORMAT 3, the nonce
   store, the table above. Test: machine.rs unit tests that two stores fed one log, one
   entry forged, end equal and without it; a replayed nonce is a no-op; the decision is the
   same with the clock moved. VM: a kithd built with a test-only feature (off in a release,
   so it costs the shipped binary nothing) lets n1 append a forged entry while it leads; n2
   and n3 refuse it, and the stores agree. About +120 KB.

All four: about +215 KB, to about 11.6 MB.

### Layer 1a as built (T-0743), and where the code said otherwise

kithd checks the header (crates/kithd/src/access_sign.rs: `verify` is the pure check) on
every request a node passes on with `x-kith-for`, on `kith run`'s hop, on a write passed
to the leader for an Identity, and at the local socket; each sender passes the header it
was sent on unchanged. The CLI signer is the next slice. Where the code differs from the
text above, the safe way was taken, and each is said here:

- **A signed change is passed on as it came, or refused.** A signed apply (a Release,
  Source, KindDefinition or Package rollback is an apply as it goes back too), a delete, a
  rollback and a restore reach the leader, or the node that has the volume, with the same
  method, path (query included), body and `x-kith-signed` header, so the signature holds
  over what arrives. A signed change on a route the leader does not check the signature
  of (a drain, for one) is refused at the follower, not sent on as the node's own write:
  the leader would take it as none. A Mark is the node's own and is not refused. Unsigned,
  a restore still names the backup it chose with `at=`, and a write reaches the leader as
  a store command. Where a hop rewrites a signed request (the logs hop's `here=true`, a
  `kith run` spec, a lock's body, a volume file put), the leader refuses the mismatch
  under `required`, so it fails closed. Sign at the node that has the thing, and the
  admin's Cluster changes at the node that leads, until those hops carry as well.
- **"node:<name>" is not taken as a signer**: no node signs yet. Refused.
- **`required` is not refused while older nodes report**: kithd does not yet say its
  version on its Node. Set it once every node is updated.
- **An unsigned POST that only reads** (`/v1/diff`) is refused at the local socket under
  `required`, like a write: no handler is trusted to read alone.
- **A signed request's body is read whole**, up to 96 MiB, to be hashed.
- The first `adminKey` is written unsigned, while the cluster is `open`; after that the
  key and `spec.signing` change only by a write the admin signed.

## Why not short-lived node certificates

They were weighed and are not part of this:

- Each request looks the Node up already (crates/kithd/src/cluster.rs:375-381). Taking a
  Node out ends its certificate at once. A short life adds nothing to that.
- A copied key renews just like the node. The attacker who has the key has the node, and
  asks for the next certificate as the node would.
- A cluster that is off past the certificate's life breaks. A home cluster switched off
  over a holiday must still come back.

## What stays open

- **A taken node that leads,** until layer 3 is built (captured as T-0742).
- **The CA node mints.** Whoever takes the node with the CA key
  (crates/kithd/src/pki.rs:261-266, crates/kithd/src/pki.rs:275) can issue any certificate
  (crates/kithd/src/pki.rs:125-160). With layer 3 a new node certificate still needs a Node
  admitted by a signed write, and a new person's still needs an Identity with that key. But
  `issue_user` makes the person's key on the CA node (crates/kithd/src/pki.rs:144), so the
  CA node saw every key it made. Moving key making to the person's side is its own task.
- **Secrets are readable by any control node.** Every control node keeps the whole store.
  Nothing here changes that. adr-workers.md does it for workers only.
- **A passphrase typed at a taken node.** It is the admin key, taken. Layers 1 to 3 stop a
  taken node the admin does not sign at.
- **Snapshots and membership.** A taken leader can send a forged snapshot, and add or
  remove voters. Checking a snapshot means carrying a signed hash of the store with it.
  Not decided here.
- **Choices within the rules.** A taken leader schedules and renders within what passes.
