# People's devices into the home network: peers, levels and where a level holds

Status: design, before any code (T-0322, step 1). Nothing here is built. It builds on the
`Exit` kind, its tunnel and its kernel options as they stand on T-0321's branch (not
merged): that lands first. A security review reads this record before close; what it
finds is decided under "Review".

## The problem

The owner wants WireGuard into their home for phones and laptops that are not nodes: "into
my network but not necessarily the cluster", with "different levels, like guest, family,
admin", usable from a phone with the stock app, "super secure". A level both allows and
refuses: a guest reaches one Service, family reaches the LAN and more, admin reaches the
cluster's API. The tunnel's DNS goes through a filter the owner runs. And "multiple
different wireguard exits": a level's internet may leave by a VPN provider's tunnel.

What is not wanted: a phone on the mesh, a phone as an Identity, a port open unless a
node is told to open it, or anything kith installs on the phone.

## What a peer and a level are

Two cluster-scoped kinds, declared with the `kinds!` list (`crates/kith-api/src/lib.rs`)
and `spec!`, so unknown fields are refused (`deny_unknown_fields`, `kinds.rs`), and checked
by `Spec::check`. `Peer` and `Device` are taken, hence the names.

```yaml
apiVersion: kith.dev/v1
kind: AccessLevel
metadata: { name: family }
spec:
  networks: [10.1.0.0/24]        # ranges passed on to, IPv4 or IPv6
  services: [media/films, home/photos]   # namespace/name: each TCP port; "*": every Service
  dns: 10.1.0.53                 # the resolver its peers are given
  exit: nl-1                     # internet by this Exit only, or not at all
---
apiVersion: kith.dev/v1
kind: AccessLevel
metadata: { name: admin }
spec:
  networks: [10.1.0.0/24, 10.9.0.0/16]
  services: ["*"]
  api: true                      # the cluster's API port on the node that ends the tunnel
  dns: 10.1.0.53
  internet: true                 # by the home's own connection
---
apiVersion: kith.dev/v1
kind: AccessLevel
metadata: { name: guest }
spec: { services: [media/films], dns: 10.1.0.53, internet: true }
---
apiVersion: kith.dev/v1
kind: RemotePeer
metadata: { name: phone-1 }
spec:
  node: n1                       # the node that ends its tunnel
  level: family
  publicKey: xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
```

Every field of a level is optional; an empty level reaches nothing. The check refuses: a
range that does not parse, or a `/0` ("say `internet`"); a Service not `namespace/name` or
`*`; `dns` that is no address; `internet` and `exit` together; `internet` or `exit` without
`dns` (a phone that sends everything here needs a resolver). A peer's three fields are
required, and `publicKey` is 32 bytes in base64. The node writes a peer's status: its two
addresses, seconds since its last handshake (`Device::peers`, `netlink.rs`), and why it is
not on the device, if not. Not the phone's endpoint: that is where the phone is, and the
store keeps history on every node.

**What is stored is the public key only.** A private key kith makes is in one answer and
nowhere else ("How a configuration is shown once"). A peer may bring its own: the app
makes the key, and the owner applies the RemotePeer with its public half.

**Addresses come from the name**, as a Service's does (`kith_mesh::service_address`): one
in `100.89.0.0/16` (16 bits of the name's hash; pods have `100.88.0.0/16`, `pod.rs`) and
one in a /64 of a ULA /48 made from the cluster's CA with another seed than the mesh's
(`kith_mesh::prefix`), so `in_mesh` is false for a peer. Two names with one IPv4 address:
the second is kept off the device, its status saying "name it otherwise", as two Exits
with one number are (`exits.rs`, `wanted`). No allocator, nothing to keep.

**A peer cannot claim another's address.** Its allowed addresses on the node's device are
its own `/32` and `/128` only, and WireGuard drops a decrypted packet whose source is not
among the sending key's, before any rule sees it. `Peer.allowed` is IPv6 `/80`s today
(`lib.rs`; `netlink.rs`, `set_peers`); it becomes address-and-length pairs, so `set_peers`
serves both devices.

**Only a node its owner tells ends tunnels**, by kithd flags as `--mesh` and `--ingress`
are (`main.rs`): `--people [PORT]` (`KITH_PEOPLE`, 51821 bare; needs `--mesh` and root) and
`--people-endpoint NAME:PORT`, what a configuration names as the server. No store write
opens a port on a node. Without the flag there is no device, table or port, and what an
earlier run with it left is taken away at start. With it, the kernel's WireGuard listens on
that UDP port on every address. A peer whose `node` lacks the flag is on no device, and its
status says so. The node's key for this device is a file beside the mesh's
(`pki/people.key`, made by `mesh.rs`'s `private_key`), one per node, never in the store; its
public half, port and endpoint go in the Node's status as `people`, as `mesh` does.

**How a phone finds it**: the endpoint the owner states. The owner forwards that UDP port on
their router, or the node has a public address. kith opens no port on a router: the tree
has no UPnP, NAT-PMP or PCP code, and this adds none.

## Where a level is enforced

On the node that ends the tunnels, in the kernel, in three places of its own.

**A second WireGuard device, `kwg0`**, apart from the mesh's `kith0`, by the same writer
(`Device::make` and `set` on T-0321's branch; `set_peers`, `netlink.rs`); not `kp…` or
`kx…`, prefixes `kith-pods` matches (`pod.rs`, `nat`). It holds `100.89.0.1/16` and `::1`.

**A table of its own, `inet kith-people`**, by the nfnetlink batch pods use (`pod.rs`;
`link_name`, `verdict`, `answering`, `marked` on T-0321's branch), rebuilt whole on every
change in one all-or-nothing batch, as `nat` is. Base chains see the node's every packet, so
their policy is accept; they judge everything of `kwg0`, and each one's last rule drops it.

| Chain (hook) | Matches | Verdict |
|---|---|---|
| `pre` (prerouting) | source in `100.89.0.0/16` or the people /64, in by any link but `kwg0` | drop |
| `in` (to the node itself) | in by `kwg0`, source a peer's address | jump `<level>-in` |
| `fwd` (forward) | in by `kwg0`, source a peer's | mark the connection as the peer's; jump `<level>-out` |
| `fwd` | out by `kwg0`, destination a peer's | jump `<level>-back` |
| `out` (output) | out by `kwg0`, destination a peer's | jump `<level>-replies` |
| `in`, `fwd`, `out` | in or out by `kwg0`, whatever no rule above took | drop |
| `post` (postrouting, nat) | source in the people ranges, out by any link but `kwg0` | masquerade |

A level's chains, one set per level, each ending in drop:

- `-in`: a named Service's mesh address with one of its TCP ports (each Service, each port;
  `*` all); the API's port, with `api` (on any of the node's addresses: input is only what
  is addressed to the node); the resolver's address on 53 and 853, when it is the node's.
- `-out`: the resolver's address on UDP and TCP 53 and 853; then any other 53 or 853
  dropped; a named range; then private IPv4 (`10/8`, `172.16/12`, `192.168/16`,
  `100.64/10`, `169.254/16`) and the networks of the node's own links dropped; then the
  internet: with `internet: true`, out by any link but the mesh's, `kp*` and `kx*`; with
  `exit`, out by that Exit's `kx<number>` and no other.
- `-back`: connection state established or related, **and** the far end as `-out` would
  take it now: a source in a named range; the resolver with source port 53 or 853; for the
  internet, in by the Exit's `kx<number>` (an exit) or a public source in by none of the
  mesh, pod and exit links (home).
- `-replies`: established or related, from a named Service's address and port, the API's
  port, or the resolver; and ICMP errors, so a refused IPv6 fails at once on the phone.

A range is one masked compare each way (as `answering` writes one), a Service one rule per
port each way (`ServiceSpec`, `service_address`). One rule per peer jumps to its level's
chains, so a peer moving level changes one rule. A named range that holds the mesh /48, the
people ranges or `100.88/16` is left out, and the level's status says which. New expressions
beyond `pod.rs`'s: address compares, `nfproto`/`l4proto`, source port, jump, `!=`. No sets.

**Routing rules** by `exit.rs`'s `Rule` (T-0321), which gains the suppressed prefix length
as a field (31 for a pod as now, 0 for a peer). `exit.rs` holds priorities 9000 to 9005,
each matching an exit pod's link or a tunnel's own address, so none meets a peer's packet.

| Priority | Family | Matches | Goes to |
|---|---|---|---|
| 9010 | both | in by `kwg0` | main without its default routes (the LAN, the mesh, the node) |
| 9011 | IPv4 | in by `kwg0`, from a peer of a level with an exit | the Exit's table (`0x6b78_0000` and its number) |
| 9011 | IPv4 | in by `kwg0`, from a peer of a level with `internet: true` | main |
| 9012 | both | in by `kwg0` | unreachable |

**A narrowed level or a removed peer holds within seconds, open connections too.** The loop
wakes on every store change (as `exits.rs`'s `run`, on the generation) and every 10 s. Every
packet, both ways, is checked against the level as it is now; connection state only tells a
reply from a request, never lets one through alone. Flushed: the connections carrying the
peer's mark (`0x6b79` and 16 bits of the peer), by `exit.rs`'s `forget` with the mark as an
argument, which ends the masquerade's state too. A removed peer is first taken off the
device (`RemoveMe`), then its rules, then the flush. kithd's Service proxy holds such a
connection, passing nothing, until its idle time (an hour, `services.rs`, `IDLE`).

**Peers are kept from the mesh** (no level chain accepts out by `kith0`; the node's mesh
address is input, where only Service addresses are taken), **from each other** (none
accepts out by `kwg0`; a range holding the people ranges is left out) and **from the node's
own ports**: `-in` takes Services, the API port and the resolver; `--dns`, ingress, NFS,
netboot, the mesh's port and ports pods publish (`pods.rs`, `publish`, T-0321) are refused.

**Two changes to what is there.** `kith-pods`' guard drops everything forwarded that is not
a pod's, `nat` rebuilds it whole (`pod.rs`), and an accept in one table overrides no drop in
another: so `nat` takes the people link, as it takes the mesh's on T-0321's branch, and
passes it both ways for `kith-people` to judge. And kithd's Service listener serves only
mesh sources (`services.rs`: `accept`, and the strays in `run`); on the node that ends
tunnels it also serves the people ranges. A peer's connection then goes on as this node's,
and NetworkPolicies see this node (`reach` asks `admits` with its address).

**Between start and the rules, nothing passes.** Each step only once the last is
acknowledged: (1) `pod::node`, the guard then forwarding; (2) the table with its drops,
which match the link's name and so hold before the link exists, as `exit.rs`'s `hold` relies
on; (3) routing rules 9012 and 9010; (4) the device, made or found, its peers emptied first
(a restarted kithd finds the kernel's old device, and a peer deleted meanwhile would pass),
then key, port, addresses, up; (5) level chains, jumps and rules 9011 in one batch; (6) the
peers, from a fresh store (on a worker a fresh view, `docs/adr-workers.md`). A rule that
cannot be written leaves the device without peers, and the Node's status says why. A clean
stop takes the device away; after a crash the kernel keeps the last rules.

## DNS

A level names its resolver (`dns`): the address its peers' configuration gives (`DNS =`),
the owner's filter on the LAN or any other address. `-out` and `-in` take UDP and TCP 53
and 853 to that address only, and drop 53 and 853 anywhere else, the node's own `--dns`
included. UDP 853 is DNS over QUIC, refused with the rest.

What that does not stop, said in the README beside the kind: **DNS over HTTPS** (443, the
web's port) and over HTTP/3; a resolver on any other port; anything inside another tunnel.
A level with internet lets a peer around the filter by any of these. An app with a resolver
hard-coded on 53 is refused and sees no answer.

To LAN hosts every peer is the node (masquerade), so the filter sees one client (see Open).
`.kith` names are answered by kithd's DNS only: the filter forwards `kith.` there. kithd's
resolver forwards only for private and ULA clients (`may_forward`, `kith-dns/src/server.rs`),
where `100.64.0.0/10` is not private: by IPv4 a peer gets no name it does not hold. The people's
/64 is inside fc00::/7, so kithd refuses it by name: the forwarders are less the people's prefixes
(slice E2b, below).

## Exits

A level with `exit: nl-1` sends its internet by that Exit or not at all. As built on T-0321's
branch, an `Exit` is `node`, `secret` (a `wg0.conf` in `kith-system`, read by kithd),
`namespaces` (whose pods may name it) and `dns` (its pods' resolver); `exits.rs` holds the
tunnel on its node as `kx<number>`, with a table whose one route is the tunnel (`exit.rs`,
`ensure`). A level reuses, as built: the tunnel, table and number (`exits.rs`, `tend`);
`Rule` for 9011, which takes a `/32` source (`from`) beside `iif` (`hold`'s per-link rules
are not used: a level's peers share one link); `kith-pods`' rules taking only answers in by
`kx*`; `forget`, the mark as an argument; and the kernel options T-0321 adds
(`IP_MULTIPLE_TABLES`, `IPV6_MULTIPLE_TABLES`, `NF_CONNTRACK_MARK`, `NF_CT_NETLINK`).

One change to the kind: `namespaces` says nothing of levels, so an Exit gains `levels`, the
levels whose peers may leave by it, and its check asks for one of the two. Whoever writes the
Exit says who spends its provider's key, for levels as for pods. A level its Exit does not
list, or whose Exit is held on another node than its peers', has no internet there, and its
status says why (from `exits.rs`'s `failed`). Across nodes is not built, as for pods.

**With the exit down nothing leaves another way**, at two layers. Routing: the Exit's table
loses its route with its link, and rule 9012 answers unreachable; main's default route is
never reached, 9010 suppressing it. The table: `-out` accepts the internet only out by
`kx<number>`, whatever the routes say. Masquerade out by the tunnel takes its address
(inferred, as T-0321 infers it). IPv6 to the internet is never carried for people (the exit
carries IPv4 only): rules 9010 and 9012 and the table's IPv6 half refuse it.

With an exit and the home's filter, the names leave by the filter's upstream, not the exit.
A resolver address one of the node's own networks holds is asked there.

## How a configuration is shown once

`POST /v1/peers` (`name`, `node`, `level`) makes a key and applies the RemotePeer with its
public half, as the caller, by the same path as any apply. It answers once with:

```ini
[Interface]
PrivateKey = <shown this once>
Address = 100.89.23.7/32, fd8a:2b3c:4d5e::5e6f:7a8b:9c0d:1e2f/128
DNS = 10.1.0.53
[Peer]
PublicKey = <n1's people key, from its Node's status>
Endpoint = vpn.example.net:51821
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

`AllowedIPs` is everything for a level with internet (both families, so the phone's IPv6
does not go around the tunnel); otherwise the named ranges, the Services' /80 and the node's
people addresses. It is what the phone sends, never what it may reach.

The key is 32 bytes from `ring`'s `SystemRandom`, as `mesh.rs` makes the node's. Its public
half comes from the kernel, by a WireGuard link made for the one call, never up, then
removed, as the mesh reads its own (`mesh.rs`, `key_before_joining`); no X25519 crate is in
the tree. Asked again, a new key replaces the old one, whose configuration then stops
working. The private key is in no store, history, audit line, log or file.

**The text**: `kith peer add NAME --node N --level L` prints it, as `kith node`'s recovery
key is shown once (`crates/kith-cli/src/main.rs`): one call and a print, out of about
0.05 MB of room (2.93 of 3.00 MB, `docs/numbers.json`), measured in step 4. If it does not
fit, the web UI alone shows configurations; no raise first.

**The QR code** is drawn in the browser by a small encoder, `crates/kithd/ui/qr.js` (byte
mode, one error-correction level) in `ui.rs`'s `FILES`, on a canvas: the page's policy
(`script-src 'self'`, `img-src 'self'`) refuses a `data:` image and allows this. A few KB of
`kithd`'s 1.65 MB of room (11.35 of 13.00 MB). The UI lists both kinds from `/v1/schemas`
as any; new is "Add a peer" on the RemotePeer list: a dialog with the text, the QR and
"whoever has this picture is this peer", forgotten when closed (no browser storage).

**Who may add a peer**: an Identity whose Roles allow `apply` on `RemotePeer` with no
namespace (`access.rs`, `Grants::may`); the route joins `FOR_IDENTITIES`, and the write is
decided again where the log is kept, as every write is (SECURITY.md).

**A peer is not an Identity.** Nothing maps a tunnel address to a `Caller`. With `api: true`
a peer reaches the API's port, where TLS still asks for a client certificate; without one it
is "anyone who reaches a node's port" (SECURITY.md).

## Approaches

1. **People's devices as mesh peers, each an Identity.** `set_peers` takes off every peer
   not a node (`netlink.rs`); on `kith0` a phone sits beside nodes and Services, which trust
   mesh sources (`services.rs`, `accept`): one slip is a guest on the cluster. Refused.
2. **A proxy in kithd per level.** TCP only, cut when kithd restarts, no LAN range, no UDP
   or ICMP, and a WireGuard stack in userspace as root. Refused.
3. **Services through the TLS ingress, certificates for people, no tunnel.** No LAN range and
   nothing but HTTP, where the owner asked for the network. Part of an answer, for web apps.
4. **A device per level** (`kwg-guest`, `kwg-family`), each on a port of its own. Rules by
   link, so T-0321's `hold` would serve as built. But the owner forwards a port per level,
   and a peer that changes level needs a new configuration. Not taken.
5. **One device for people, a table of its own, rules by source (chosen).** The device and
   the table are writers that exist; each later step adds rules, not structure. Its cost:
   expressions written by hand, and a rule per peer.
6. **Allowed addresses alone, no table.** They bound what a peer sends as, not where it
   goes. Refused.

## Threats

| Threat | What holds | What does not |
|---|---|---|
| A stolen unlocked phone | What its level reaches, no more; deleting the peer holds within seconds, open connections too | Until deleted it is the peer: the app asks no unlock to turn on, and kith has no expiry |
| A guest screenshots or re-shares the QR | The copy reaches only the guest's level, and one delete ends both; two devices on one key take turns (the last handshake wins), which shows in the handshake age | kith cannot tell a copy from the phone; a photo in a cloud backup is a copy |
| A peer sets another's address | WireGuard drops it (allowed addresses per key); the table jumps by source after that; a people source in by any other link is dropped in `pre` | Nothing known |
| A peer floods | It reaches only its level; the Service proxy holds each peer to 8 of 4096 places by its own address (`services.rs`, `People`, built in slice E2b), and the API's handshakes have 16 slots for the people, 8 to a peer, apart from the mesh's 64 | No rate in the table: a peer can fill the uplink |
| The node that ends tunnels is taken | Peers' private keys are not there; the API still asks peers for certificates | Beyond what it has today (a control node is the cluster, a worker what its view holds): the people key, so it can be the server to every phone; peers' traffic in clear where not TLS; any rule. Choose a node you trust with your phones' traffic |
| Whoever may write a level widens their own | Cluster-scoped kinds: only a Role with no namespace grants them; every write is audited by Identity and decided again where the log is kept | Roles go by kind, not name: who may write one level or peer may write all, and put any peer at admin |
| An Exit provider sees traffic | Only the internet traffic of levels that name it, as the tunnel's address; not the LAN, not the phones' addresses | Destinations and whatever is not TLS. Names asked of the home's filter leave by its upstream instead |
| Replay of an old configuration after removal | The key is off the device, so no handshake completes; WireGuard refuses a replayed handshake by its timestamp | A rollback of a RemotePeer to a revision with an older key lets that key in again: delete, do not edit back |
| IPv6 past an IPv4-only rule | One `inet` table for both families with default drop; rules 9010 and 9012 for both; IPv6 to the internet never carried; `::/0` in the phone's AllowedIPs | Nothing known |
| The window at start | Table and rules before the device; the device without peers until its rules are acknowledged; peers emptied at every start | After a crash the last rules stand until kithd is back, a peer deleted meanwhile included |

## What a level does not hold

For SECURITY.md, said plainly:

- DNS over HTTPS, a resolver on another port, a tunnel inside the tunnel: a level with
  internet can go around the filter.
- Past the node a peer is the node: LAN hosts, routers and shares that trust addresses, and
  NetworkPolicies, see the node that ends its tunnel.
- No limit on bandwidth.
- A copied configuration is the peer until the peer is deleted. Nothing expires.
- No permission per level: who may write one writes all.
- The node that ends tunnels holds the people key and sees what is not TLS.
- After kithd crashes, the last rules stand until it starts again.
- kithd's proxied connection to a Service stays open, idle and passing nothing, up to an
  hour after a peer loses that Service.
- IPv6 to the internet is not carried.
- The phone decides what it sends into the tunnel; its other traffic is not the node's.
- A name is not access: the resolver may answer names a peer cannot reach.

## Older nodes and roll-back

- A kithd without these kinds refuses them ("unknown kind": `Resource::validated` in
  `lib.rs`, `Store::plan`), and refuses them too as a replicated entry
  (`crates/kith-store/src/machine.rs`, `apply`). `apply_all` is all or nothing, so an older
  node's copy then lacks **every** resource of that apply. Apply them on their own, and only
  once every control node knows them, as the README says for `trust`.
- A kithd without `--people` cannot end tunnels: given the flag it does not start (clap
  refuses it), and it ignores `KITH_PEOPLE`.
- A worker is sent the RemotePeers that name it, their levels and those levels' Exits
  (`view.rs`, `named` and `NAMES`, as Exits are on T-0321's branch); its write list gains
  `status.people` on its Node and its peers' status.
- An Exit with `levels` is refused, as an unknown field, by a node whose Exit lacks it.
- Rolling back on kith OS restarts the machine: nothing listens, phones fail closed. On
  another OS, after a crash an older kithd leaves the last rules standing and unkept until
  a restart or the link is deleted by hand. The README says so.

## Tests

No test contacts an outside host: uplinks are cut as `--test tunnel` cuts them on T-0321's
branch (`restrict=on`), and "the internet" is an address of a machine in the run.

`sh ci/vm.sh --test access` today: three nodes; writes through n2 and n3 under a RoleBinding
deleted through n1; one let through by a node cut off is refused where the log is kept. It
gains: n1 started with `--people` and holding an Exit; a LAN machine (`ci/pod.rs` serving, a
resolver that answers one name, and the Exit's provider with `ip` and `wg`, started as
`--test tunnel` starts its provider); a phone machine started the same way, whose asking runs
in network namespaces whose only link is a WireGuard link set from the text kith showed.

| Criterion | Cases |
|---|---|
| A guest reaches only what its level names | guest: its Service yes; family's Service, the LAN, the API, n1's 53, 443 and 2049, n2's mesh address, family's peer address, the internet: refused, over TCP, UDP and ICMP |
| Family nothing of admin's; no peer the mesh or another peer | family: the LAN and its Services yes; admin's Service, the API, the mesh, a peer: refused |
| Taken away or narrowed, within seconds, open connections too | a TCP stream (`pod check`) and a UDP flow open; family narrowed: no byte either way within 5 s; a peer deleted: no handshake and no byte within 5 s |
| A forged source | the guest's link sending as family's address, and the LAN machine sending from a people address: both dropped, counted |
| The resolver | its address answers; 53 over UDP and TCP and 853 to another LAN address and to n1's `--dns`: refused |
| Exits | family's internet only through the tunnel (a capture on n1's cards: no packet of the peer's but the tunnel's); provider stopped, Exit deleted: nothing leaves; IPv6 out refused |
| No new way in | admin reaches 7443 and is refused without a certificate; n2 (no flag) has no `kwg0` and no UDP 51821; n1 killed and reset while the phone sends: no packet of a peer's passes before the table |

Unit tests: `cargo test -q -p kithd access` (`POST /v1/peers` refused without `apply` on
RemotePeer; the answer's private key gives the stored public key; store, history and audit
line hold no private key; a request from a people address without a certificate refused
like any); `cargo test -p kith-api` (every field validates; an unknown field, a `/0`,
`internet` with `exit`, a key not 32 bytes refused); `KITH_E2E=1 unshare -Urn cargo test -p
kith-mesh people` (the batch taken, rules read back, a peer on the device only after its
rules); `cargo test -q -p kith-cli --test readme`; `crates/kithd/ui/test.mjs` (`qr.js`
against a reference matrix); `python3 ci/budgets.py`.

## Built: slice A

`AccessLevel` and `RemotePeer` are kinds kith-api applies and checks (`kinds!`, `Spec::check`),
and `crates/kithd/src/people.rs` gives each peer its two addresses on the leader and keeps them
in its status, with the refusals of review condition 5. Not built, as the plan says: the device,
the nftables table, `--people`, the configuration shown once, DNS and exits (slices B to D).

Where the build differs from the text above:

- An IPv6 overlap is not refused at apply: the mesh /48 and the people /64 come from the CA,
  which kith-api does not hold. kithd refuses an AccessLevel over either in its `refused` status
  instead. An IPv4 overlap with the people ranges or `100.88.0.0/16` is refused at apply.
- The pods range checked at apply is the default `100.88.0.0/16`. At start, with `--people`,
  kithd refuses a `--pod-range` that overlaps `100.89.0.0/16`, and a network of this node
  (other than `kwg0` and loopback) that overlaps it; as PID 1 the second is only said, as the
  pods' own clash is, since a refusal there restarts the machine (condition 4).
- An IPv4 address is 16 bits of the name's SHA-256 inside `100.89.0.0/16`; the IPv6 address is
  the people /64 with the name's SHA-256 bytes 8 to 16 as its interface id. Of the peers that
  share a public key, one is given its addresses: the one already holding an address of ours,
  else the smallest name. The others are refused, naming it, and keep any address they held, so
  a refusal never frees one. A refusal names no address.
- A refused peer keeps its addresses reserved in its status. Slice B, which routes or writes
  WireGuard config, uses a peer's addresses only when its `refused` is empty.

## Built: slice C

`kithd --people [PORT]` (env `KITH_PEOPLE`, default 51821; needs `--mesh`; root only) and
`--people-endpoint NAME:PORT` (env `KITH_PEOPLE_ENDPOINT`) bring the people's device up: the key
`pki/people.key` (0600, made once, kept across starts); the WireGuard device `kwg0` with no peers,
that key and the port, `100.89.0.1/16` and the people /64's `::1`, up; the `inet kith-people`
table written first, with its base chains and a masquerade for the people's IPv4 range. The node's
status says `people: {publicKey, port, endpoint}` (publicKey base64, as a peer's). Without the
flag, a start takes away `kwg0`, the table and the `people` status an earlier start left.

Not built (slice D): the level chains, the node's networks, routing rules 9010/9012, and any peer
on the device. The table is empty of those. The table is strict in production: a kernel with no
masquerade (kith OS has CONFIG_NFT_MASQ=y) says so by name, and `--people` does not start. A test
namespace on a host kernel with no masquerade (`unshare -Urn` here) makes the table without its masq
rules, as kith-mesh's `build_here` does, and says so; the masq rule is covered by kith-mesh's
expression tests.

## Built: slice D

A phone gets in: `POST /v1/peers` with `{name, node, level, replace}` (`people.rs`, `add`; the route is
in `FOR_IDENTITIES`, so the caller's own Roles decide). It makes a WireGuard key, applies a
RemotePeer holding only the public half as the caller, and answers once, with
`Cache-Control: no-store`, `{name, node, level, publicKey, addresses, config}`. The config is
`[Interface]` (the private key, the peer's addresses, the level's DNS) and `[Peer]` (the node's
people public key, the endpoint from `--people-endpoint`, the allowed ranges of the level). The
refusals: 404 for no such node or level, 409 for a node whose status has no `people` (no
`--people-endpoint`) or a level or address the plan refuses, 422 for a bad name. Asked again for
a name that already has a key, it answers 409 "RemotePeer NAME has a key: ask with replace to
give it a new one" and changes nothing; with `replace: true` (`kith peer add --replace`, or the
page's "A new key for NAME?" confirm) it makes a new key and the old configuration stops working.
A node as the caller is not told apart from an Identity.

The key is made by kithd itself, from the system's random source, not as a request to a root
part: there is no root part yet (T-0334). When there is, the key's making moves there and this
handler asks for it.

Three guards stand before the key is made. Keys are rationed by one token bucket in the
`Cluster` (5 a minute, a burst of 5), checked after the refusals that cost nothing (the asker's
right, the body, a name already taken), so those spend no token; refusals found once the key is
made (a plan that clashes, a node endpoint or level DNS that will not do) spend one, so a node
set up wrong uses the burst up. An empty bucket answers 429 with `no-store`. The bucket is per
kithd process, not shared by the cluster: a request a control node takes is limited by that
node's own bucket, so the cluster's rate is at most 5 a minute for each node asked; a restart
starts a full one. A name being added is held in a set until its answer is made: a second add of it
meanwhile answers 409 "being added", so two concurrent asks cannot both answer 200 with two
keys. The kernel's answer for the node's public key (`derive`, blocking netlink) runs under
`spawn_blocking`, so a slow netlink does not hold a runtime thread.

The node's own public key is read by `kith_mesh::public_of`, which asks the kernel for `kwg0`'s
key through netlink, as the mesh does; no key file is read for it.

The private key is held in `Zeroizing` buffers in the handler: the 32 bytes, the copy moved into
`spawn_blocking`, its base64, the configuration text and the answer's body, which the response
owns and wipes when hyper drops it. The 32 bytes are dropped before `applied(...).await`; the
configuration text lives across it until the answer is built. Copies kithd cannot wipe: the
netlink attribute and message buffers `kith_mesh::public_of` builds from the key, the stack
temporaries a dereference of the key leaves, and hyper's and the socket's buffers. The key is in the CLI's or the page's variables while they show it.
It is not in the store, the history, the audit line or kithd's log: the tests `peers_route*` and
`peers_config*` look for it in each of them, and in the applied resource.

`kith peer add NAME --node N --level L` prints the configuration and says it is shown once.

The QR code is `crates/kithd/ui/qr.js`: ISO 18004 byte mode, error correction L, versions 1 to
40, drawn on a `<canvas>` (black on white, a four-module quiet zone) as the page's policy
allows. It matches `qrencode -8 -l L -m 0` on every length from 1 to 2953 bytes, tried once
by hand; `ui/test.mjs` holds four of those outputs as fixtures. A configuration past the largest
version shows its text with "No picture: too long for a QR code".

The page: "Add a peer", on the RemotePeer list for a caller who may apply. A dialog asks the name,
the node (only those with a `people` status) and the level; the answer opens a second dialog
with the picture and the text, "Shown this once, and kept nowhere ... whoever has this picture is
this peer". Closing the dialog wipes it; nothing goes to browser storage, and the test counts
the key in each toast, question and call. `ci/ui_shots.py` takes the Peer and Qr views at 390
and 1440, light and dark, through a fetch shim, since the nodes it starts have no `kwg0` (that
needs root and a kernel WireGuard).

Sizes, `python3 ci/budgets.py` on this lane's build: `kith` 2.96 MB (budget 3.00; `docs/numbers.json`
had 2.92 before), `kith-remote` 3.59 (3.60), `kithd` 12.66 (13.00; `numbers.json` has 12). Those
are the figures slice C's text above, 2.93 and 11.35 MB, should have named; the 11.35 was an
estimate. `kithd.order` was written again (`python3 ci/order.py`), as the new handler's functions
and slice C's were not in it.

## Built: slice E1

Levels hold on the `--people` node (kithd's `levels.rs`). A pass reads the store (the node's
RemotePeers, their AccessLevels and Services) and makes what the kernel holds match it:

- The `kith-people` table is written whole, in one batch, from the people and their levels.
  There is no `ct state established` accept, so a narrowed level is cut by the rewrite alone; a
  peer taken away also has its connections' marks (`0x6b79_0000 | offset`) deleted from conntrack.
- Rules 9010 (main table, `suppress_prefixlen 0`), 9012 (unreachable) for both families, and 9011
  (the peer's /32, the full main table) for each peer of a level with `internet: true`, all `iif
  kwg0`. exit.rs's 9000-9005 are untouched; its `Rule` gained `suppress`.
- Order of a pass: the peers leaving come off kwg0 first; then the table, then the rules; then
  the peers go on; the connections of those that left are flushed last, and only once they are
  really off the device (a `set_peers` that failed leaves the pass's memory of the device as it
  was, so the next pass asks again and nothing is flushed meanwhile). Any failed step empties
  kwg0's peers (fail closed) and says why. A pass is run in `spawn_blocking`, and none runs once
  the device is being taken away (a lock shared with the teardown). A start that fails takes the
  old kwg0, its rules and its table away.
- The rules counted as held are the whole rule (action, lengths, table, suppress): one by kwg0 at
  9010 to 9012 that differs is not counted, and `people_hold` replaces it.
- The kernel is read again each pass (table present, rules), so a rule or table removed by hand
  is put back within 10 s; an unchanged pass writes nothing. `Tend` starts only after `up` has
  finished its own order (the device, the table, the 9010/9012 base).
- A peer's AllowedIPs on kwg0 are its own /32 and /128 and nothing else (condition 8 on this
  side; what the client's shown configuration holds is slice D).
- `--people-networks A,B` (env `KITH_PEOPLE_NETWORKS`; needs `--people`) names what a level's
  `networks` may hold: a level's network outside them, or overlapping the mesh /48, the people
  /64, 100.89.0.0/16, 100.88.0.0/16 or the pods' range (`--pod-range`), is left out with a note (condition 7: narrows, never widens). A Service reached only on UDP
  is left out (an empty port list means all ports). A level that names an `exit` has no internet
  in this slice ("exit X is not held yet"; slice E2a below gives it one).
- Two peers with one address or key are both left out, as is an address that is the range's first
  two or its last (condition 5). A level the store does not
  have leaves its people out. What was left out, and why, is the Node's `peopleNotes` (up to 16
  lines of 200 characters; a worker may say only its own).

Not built: a conntrack flush for a peer deleted while kithd was down; the node's own IPv6 links
in the table's link list (IPv4 only); a start failure's reason beyond stderr; exit levels (slice
E2a, below). The Service listener, the per-peer limits and the resolver's refusal are slice E2b,
below.

## Built: slice E2a

A level that names an `exit` leaves by that Exit, on the node that holds it:

- `Exit.levels` (the levels whose peers may leave by it) is in the kind, beside `namespaces`; the
  check asks for one of the two (`namespaces: []` alone is still refused), and each level is a
  name. `exits.rs` keeps them on its `Up`, and a change of levels alone keeps the tunnel.
- `levels.rs` takes a snapshot of the Exits held (`Exits::held`: number and levels when up, why
  not when failed) before it takes the store's lock. A level's `internet` is `Exit(number)` only
  while its Exit is held here and lists the level; else it has none, and the note says which:
  "does not list level X", the Exit's own failure, or "is not held on this node" (no such Exit,
  another node's, or no tunnel yet).
- `Wanted.internet` maps a peer's IPv4 to the table of rule 9011: 254 for the home's internet,
  `0x6b78_0000 | number` for an Exit's (`kith_mesh::exit::table`). `people_rules` reads the table
  of each rule, and a rule counts as held only with the table wanted. A pass takes away a rule
  9011 whose table is not the wanted one before it makes the right one (a peer never has two, and
  between them falls to 9012), and the steps say `rule 9011 + ADDRESS to table 0x6b780007`. An
  Exit that goes (or stops listing the level) loses the rule within 10 s: the peer is held, with
  no internet.
- `inet kith-pods`, with its guard (policy drop), passes what comes in by `kwg0` and what goes
  out by it, by the whole name; the people table's own chains still decide what a peer may
  reach. Without it the guard would drop a peer's packets on their way to `kx<number>`. The
  masquerade out by the tunnel is the people table's `post` chain (any link but kwg0), and its
  `-out` chain lets the internet out only by `kx<number>`: a named range never goes out an
  Exit's link (condition 3, tested for an Exit level too).

Not built: IPv6 through an Exit, the Exit of another node, the API or DNS through an Exit.

## Built: slice E2b

- **The Service listener takes the people.** A node started with `--people` accepts, on the
  Services' listeners it has, a connection from the people's ranges (100.89.0.0/16, the people /64)
  as well as the mesh's; the relay for the other nodes, and the strays the ingress hands over, stay
  mesh-only. A person is served only if its address (exact, not the /64) is a RemotePeer's whose
  level names that Service address and port (`levels::reach`, read from the store each round; a
  Service with no port listed is reached on none: fail closed, though the level never makes one):
  another level's Service, and a source in the ranges that is no peer's, are hung up on. The
  kernel's table said so first; this is the second look. What `serve` and `accept` decide by
  source is `Proxy::place` and `Proxy::takes`.
- **NetworkPolicy sees a person as the serving node.** The Workload's NetworkPolicies are asked
  with this node's mesh address as the source (`Proxy::reach`), as for every client of a Service
  on this node, not the person's: a person's address is not passed down, because a connection
  passed on to another node's replica is asked there as the caller node, so a rule on a person's
  address could not hold on both paths. A level's Services are the person's reach; a policy that
  must keep a person out of a Workload keeps the level's Service from naming it.
- **Limits of their own.** Places for the people are apart from the mesh's 4096 (`Proxy.people`):
  a peer holds 8 of 4096 by its address at 128 bits, so two IPv6 peers of one /64 are two, and the
  table of sources holds only peers, so it is no bigger than the peers (and never the room). The
  API's handshakes (`cluster::Pools`) have 16 slots for the people besides the others' 64: a full
  people pool leaves the 64 free; each peer holds 2 of the 16 (`PEOPLE_GUESTS_EACH`; the others
  hold 8 of 64), by its address, so eight peers fill it, not one. A connection is accepted first
  and then asks its own pool for a slot (none: it is hung up on), so a crowd of strangers holding
  the others' 64 does not keep a person's connection from being picked up. The API port is still
  not opened to peers by this slice.
- **The resolver does not forward for a person.** `kithd`'s forwarders are the local networks and
  the pods' range less the people's range and /64 (`dns::forwarders`, `Cidr::without`), so the deny
  wins over fc00::/7, which holds the /64; a mesh source is forwarded as before.
- Not built: bandwidth limits (the table has no rate); a person to a Service on port 443 or 80 of
  a node with the ingress (those are the ingress's: the strays are mesh-only).

## Built: slice F

`sh ci/vm.sh --test access` drives a person's tunnel end to end (`ci/vm/access.sh`, before its
"signing required" step; `ci/pod.rs` gains `pod watch`). Its three nodes all start with `--mesh`,
n1 also with `--people --people-endpoint 10.9.0.1:51821`. Two phone machines and an Exit's
provider are not nodes: each starts from memory with `ip`, `wg` and `pod` as its first process,
on the nodes' network, and a phone sets its WireGuard link from the configuration `POST /v1/peers`
answered (the CLI's `kith peer add` is not built into VM tests; the route is what it calls).
`pod watch NAME HOST PORT` holds one connection to a `pod echo` and makes a new one every third
of a second, each of which counts a byte back, and prints `held`, `fresh` and `failed`: the
test reads those from the console.

| Case | Read |
|---|---|
| phone-a on `guest` (Service `echo`) reaches echo; the Service `hidden`, in no level, is refused | `held` and `fresh` grow; `fresh` of hidden stays 0 while `failed` grows |
| phone-b on `roamer` (echo, and `exit: vpn`) leaves by the Exit | a TCP connection to the provider's `198.51.100.1`, an address only it has, answers |
| `guest` narrowed to an empty level | five seconds on, neither `held` nor `fresh` of echo grows, and the phone keeps trying |
| `guest` widened again | `held` grows again (a new connection) |
| the Exit deleted | phone-b's connections to the provider stop |
| the RemotePeer phone-a deleted | its open connection and new ones stop |

Not driven, and said: IPv6 people (the IPv6 half of a configuration is set on the phone and not
exercised), a real phone, the stock app, a real router, UDP, the forged-source, resolver and "no
new way in" cases of the table under "Tests" (those that need a second LAN machine or a capture:
the unit tests and `kith-mesh`'s namespace tests hold them). The "Tests" plan above is the
design; this is what was built.

## Open

- **People do not reach the Services on an `--ingress` node's 443 and 80 (not built).** Those
  ports are the ingress's: its listener hands the strays over to the Service listener, and that
  hand-over is mesh-only, so a person's connection to a Service on them is hung up on, though the
  kernel's table lets it in. A level that names such a Service is not served on those ports until
  the ingress takes the people's ranges too (with the same places and the level's reach).
- **Should the filter tell people apart?** Then the router routes `100.89.0.0/16` to the node
  and the node stops masquerading to the LAN; otherwise every peer is the node there.
- **A resolver hard-coded on 53: refused (here), or answered by the level's resolver** (one
  nat rule)? Refused breaks the app; redirected filters it unseen.
- **Should a peer ever reach another peer** (a laptop its phone)? Refused here.
- **Should a peer expire** (a guest for a weekend)? Not here.

Added by the review, each the owner's:

- **Who may make a peer of which level** (access rules name kinds, not names). Until decided:
  a level that holds `api` or the internet needs the right to apply Levels as well.
- **Whether a level with the internet reaches the IPv6 LAN with no range named.** Not until then.
- **What a `--people` node may be asked to forward to**: the networks given with the flag.

## Review

One security review of this record, checked against the code on main (research
T-0322-adr-review). Verdict: sound with conditions; not sound as first written in four
places. It did not read T-0321's branch: everything this record takes from `Exit` is
unverified until that branch is merged and read again. Each finding and what was decided;
the nine conditions bind whoever builds this, and where the text above says otherwise this
section holds.

| Finding | Decided |
|---|---|
| High: "the Service proxy's limits per address hold each peer" is false: one source may hold every place there is (`Limits::new(SERVING, SERVING)`), and every IPv6 peer of a /64 counts as one | People's connections get limits of their own, a peer's share far under the whole, counted by the peer's address, never its /64; the claim is taken out (condition 1) |
| Medium: the internet rule named no family and the private list only IPv4, so a guest with the internet reached the IPv6 LAN | The internet is IPv4 only; IPv6 is reached by named ranges alone, with `fc00::/7`, `fe80::/10` and `ff00::/8` dropped by name, and `0/8`, `224/4`, `240/4`, `198.18/15`, `192.0.0.0/24` added to the IPv4 list (condition 2) |
| Medium: a named range was accepted on any way out, so on a level with an Exit a LAN range behind the default gateway left through the tunnel | A named range is accepted only on a way out that is no Exit's link, no mesh link and no people link (condition 3) |
| Medium: a named range was refused only if it held the mesh, the people ranges or `100.88/16` whole, and the pods' range is a flag now | Any overlap is refused, against the mesh's /48, the people ranges and the node's own `--pod-range`; the people ranges are checked the same way against the pods' range and the node's connected networks at start (condition 4) |
| Medium: an address from 16 bits of a name's hash collides (about 7% at 100 peers), no order said, the gateway's and the ends of the range not kept out, a key on two peers not refused; the kernel gives an address to the last peer set with it, and the rules are by address | The address is kept in the RemotePeer's status once given and never drawn again; the first to hold it keeps it and a later one is refused, named; the range's first two and last addresses are never given; a public key on two RemotePeers gives its address to one (the holder, else the smallest name) and refuses the rest, naming it; kithd checks that no two peers share an address before it sets any (condition 5) |
| Medium: the mark that revocation flushes by was set only on forwarded packets, so connections to the node itself (its API, a Service) ran on | Marked on delivery to the node as well, and flushed with the rest; a request already authenticated and being answered ends with its connection, said in the docs (condition 6) |
| Medium: `--people` is the owner's flag, but which networks its peers reach was then the store's to say on that node, with no word of the node's own, and no requests of the root part for the link, the table and the rules | The networks a level may name on a node are those given with `--people` where its kithd is started (none given: Services only); the store narrows within them and never widens. `--node-policy hardened` leaves `--people` as it was given. The link, the table and the rules are a family of typed requests in docs/adr-privilege.md's terms, written into that record with this task's first code (condition 7) |
| Medium: a level without the internet left its resolver out of the peer's AllowedIPs, and the node's resolver forwards for any `fc00::/7` source (the cited `may_forward` branch is not the one kithd uses) | The level's resolver address is in AllowedIPs; the people prefixes are refused forwarding by name, both families, with a test over IPv6 (condition 8) |
| Medium: making a key by making a link is the root part's work, the private key stayed in memory and in a response that may be kept, and a second ask replaced a key | A root-part request, at most a few a minute; the key zeroed once sent; `Cache-Control: no-store`; a peer that has a key is given no other without the right to apply RemotePeers and a word that says replace (condition 9) |
| Low: whoever writes a Node's `status.people` points new configurations at another end and key | Written by the node itself only (a worker's write list names it, with its shape); the configuration shown names the node it was read from |
| Low: people's API handshakes share the 64 places every stranger has | A pool of their own, smaller |
| Low: the order of the tables' chains was not said; a more specific route of the node beats an Exit's table | The priorities are written with the first code and the VM test sends a packet each table should refuse; the rule on the way out, not the routing table, is what holds a level to its Exit, said in "Exits" |
