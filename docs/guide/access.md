# Access: who may do what, and what a node refuses

## Who may do what

On a node, whoever can open kithd's socket is the admin: `kith` there may do everything. From
anywhere else, a person or a program calls a node's TLS port (`--listen`) as an **Identity**,
with a certificate from the cluster's CA, and may do what the **Roles** bound to it allow:
nothing, to begin with. Trust, and how to report a hole: [SECURITY.md](../../SECURITY.md).

```sh
kith identity cert alice --out ~/alice    # on the node the cluster was started on
```

writes `alice.crt`, `alice.key` and `ca.crt`, and makes `Identity/alice` if it is not there.
Then say what she may do:

```yaml
apiVersion: kith.dev/v1
kind: Role
metadata: { name: web-editor }
spec:
  rules:
    - kinds: [Workload, Service, ConfigMap]   # or ['*']
      verbs: [get, list, watch, apply, delete]
      namespaces: [web]                        # left out: everywhere
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: { name: alice-web }
spec:
  role: web-editor
  subjects: [alice]        # Identities by name, or `group:ops` for spec.groups
```

```sh
curl --cacert ca.crt --cert alice.crt --key alice.key \
     --resolve kith:7443:10.0.0.7 https://kith:7443/v1/resources?kind=Workload
```

Every node's certificate is good for the name `kith`. A node nobody can log in to (kith OS has
no shell) has no socket for that: start its kithd with `--claim`, and while the cluster has no
Identity it prints a token at each start (`kith1.<secret>.<the CA's fingerprint>`). Whoever
sends it first to `/v1/claim` becomes an Identity bound to `cluster-admin`:

```sh
curl -k -d "{\"token\":\"$TOKEN\",\"name\":\"root\"}" -H 'Content-Type: application/json' \
     https://10.0.0.7:7443/v1/claim       # {"ca": …, "cert": …, "key": …}: save as ca.crt, root.crt, root.key
```

The token is good once, for an hour, for nothing else (it admits no node), and not once the
cluster has an Identity. Whoever reads the node's console or logs within the hour can claim the
cluster. `-k` means curl does not know the node yet: to rule out a man in the middle, compare
`openssl x509 -noout -fingerprint -sha256` of `https://10.0.0.7:7443/v1/ca` with the token's last
part, and claim with `--cacert`. A join token on such a cluster is asked for over TLS (`POST
/v1/tokens` with the cert and key above), only by an Identity that may apply Nodes, Roles and
RoleBindings (it could give itself every right anyway).

- Refused: 403 and why. `list` and `watch` show only what the caller may see; an apply is all or
  nothing.
- `get` covers a resource, its history and its output (`/v1/logs`); `apply` covers rollback, and
  push to or pull from a registry through kithd (which calls whatever registry is named).
- Kinds in no namespace (Node, Role, KindDefinition…) need a rule without `namespaces`.
- A template with `seccomp` unconfined or allowing calls, or a container with `userNamespaces`
  (which lets the refused calls back), also needs the right to apply `Unconfined` (in no namespace).
- The certificate stands while the Identity's `publicKey` is its key: `kith identity cert` again
  ends the old one, `kith delete identity/alice` all access.
- Grant with care: `apply` on Role, RoleBinding or Identity grants oneself anything, and whoever may apply a Workload runs programs on your nodes. A Release or a Source acts with the rights of whoever applied
  it, and makes nothing they may not apply themselves (see Packages and Sources); deleting one removes what it installed, whoever may delete it.

Every change made through a node, and every refusal (a missing certificate, or one that no longer
stands for its Identity, too), is one line in its audit log (`audit.log` in its state directory,
4 MB, and four older files `.1` to `.4`): when, who, what, how it went. `kith audit` shows the
last lines, as does `GET /v1/audit` for an Identity with `get` on `Audit` (no custom kind may take
that name). A watch ends when its Identity is deleted or given another certificate. Permission is
asked again on the leader as an apply, delete or rollback is put in the log, so a RoleBinding
deleted meanwhile stops it; a write already in the log stays.

### A Workload that calls the API

A Workload that calls the cluster (a controller, a gateway) runs as an Identity: the Identity
names the Workloads that may (a namespace, and `names` in it), the Workload says which it is:

```yaml
apiVersion: kith.dev/v1
kind: Identity
metadata: { name: gateway }
spec:
  workloads: [{ namespace: web, names: [proxy] }]
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: proxy, namespace: web }
spec:
  identity: gateway
  template:
    containers: [{ name: proxy, image: registry.example/proxy:1 }]
```

Each container of its pods finds `ca.crt`, `tls.crt`, `tls.key` and `address` (a control node's
`HOST:PORT`) in `/run/kith/identity`, in memory and readable by the container's user alone, and
calls `https://ADDRESS` as `gateway`: what that Identity's Roles allow, nothing else. The pod's
node makes the key; the certificate lasts two hours and is renewed after one, same key, no
restart. It stands only while the store says so (the Identity names the Workload, the Workload
says `identity: gateway` and is placed on that node, the node is there); otherwise it leaves the
files within a minute and is asked for again every ten minutes. Refused at apply: an Identity
that does not name the Workload, one with both `publicKey` and `workloads`, a template with exec
units or VMs (only containers get the files). A node with no directory in memory starts no such
pod. Not yet: an identity provider (OIDC), certificates for people that expire before ten years,
one audit log for the cluster.

## Use kith from a laptop

`kith` on another machine calls a node's TLS port the same way, with the identity's files
(`ca.crt`, and `alice.crt` with `alice.key` beside it, from `kith identity cert` above). Build it
with the `remote` feature; the default `kith` does not link TLS at all:

```sh
cargo build --release -p kith-cli --features remote
kith --server HOST:PORT --identity ~/alice get
kith --server HOST:PORT --identity ~/alice apply -f web.yaml
kith --server HOST:PORT --identity ~/alice logs Workload/web -f
```

`KITH_SERVER` and `KITH_IDENTITY` say the same. `get`, `apply`, `watch`, `logs -f`, and the
tunnels of `run` and `ui` all work over `--server`; `--store` still wins over it
when it is given. HOST:PORT is the node's `--listen` address, and its certificate must be
signed by the cluster's CA and name `kith`: a node of another cluster, or one whose name is
something else, is refused before anything is sent. The identity directory must hold one
`NAME.key` and its `NAME.crt`; a key that anyone but its owner can read is refused, and `kith`
says the `chmod 600` to run. The Roles of the identity decide what it may do, as above.

### Contexts: a name for a cluster

A laptop that reaches one cluster does not want the two flags on every line. A context keeps
them under a name, in `~/.config/kith/contexts.yaml` (under `$XDG_CONFIG_HOME` when that is set),
a file `kith` writes itself with mode 0600 in a 0700 directory:

```sh
kith context add lab --server HOST:PORT --identity ~/alice
kith context use lab        # the one kith takes when none is named
kith get                    # the same as kith --server HOST:PORT --identity ~/alice get
kith --context other get    # or KITH_CONTEXT=other
kith context ls             # the current one is starred
kith context rm lab
```

A second `add` of a name replaces it, and the identity directory is kept as a full path. A flag
given as well wins over the entry, each of `--server` and `--identity` on its own. The current
context is left alone when `--store`, `--socket` or `--server` is given (a context named with
`--context` is not). A name the file does not hold, or an identity directory that is gone, is an
error that names the file. The identity is held to its Roles exactly as over `--server`: what they
do not allow is refused.

Renewal and revocation of a node's own certificate is not here: it is a change to kithd's PKI,
and is T-1014.

## Let a person's phone in

A phone or a laptop that is not a node gets in over WireGuard, with the stock app and nothing
installed on it. It is not on the mesh and not an Identity: it is a **peer** of one node, and
the **level** it is given says what that node lets it reach. Nothing is open until you start a
node for it, as root, on a cluster with `--mesh`:

```sh
kithd --mesh --people --people-endpoint home.example.net:51821 ...
```

`--people` (or `--people=PORT`; 51821 bare) makes the node's second WireGuard device and
its rules; `--people-endpoint` is the address the phone is told to dial, and you forward that UDP
port on your router (kith opens none). A node without the flag has no such device and no such
port, and a peer that names it is on nothing.

A level is a file; the five things it can name are all optional, and a level that names
nothing reaches nothing:

```yaml
apiVersion: kith.dev/v1
kind: AccessLevel
metadata: { name: guest }
spec:
  services: [media/films]   # namespace/name: every TCP port of that Service
  dns: 10.1.0.53            # the resolver the phone is given
  internet: true            # out by the home's own connection (IPv4); or exit: nl-1
---
apiVersion: kith.dev/v1
kind: AccessLevel
metadata: { name: family }
spec: { networks: [10.1.0.0/24], services: ["*"], dns: 10.1.0.53, exit: nl-1 }
```

`networks` are ranges of the home (only inside what `--people-networks A,B` names on that node;
none named, none reached), `api: true` the node's API port, and `exit` an [Exit](workloads.md#a-pod-behind-a-vpn-exit)
that lists the level (`levels: [family]`), so the level's internet leaves by that VPN
provider's tunnel and by no other.

Then add the phone, from the one command or from the web UI's "Add a peer", which draws a QR
code to scan:

```sh
kith apply -f levels.yaml
kith peer add phone-1 --node n1 --level guest     # prints the configuration, once
```

kithd makes the phone's key and keeps only its public half: the private key is in that one
answer, never in the store, the history, the audit or kithd's log, so paste or scan it
before you lose it (`--replace` gives the same name a new key and ends the old
configuration). Whoever has the configuration is that peer, until you take it away:

```sh
kith delete RemotePeer phone-1
```

What bounds a peer is on the node that ends its tunnel, in the kernel's own table
(`inet kith-people`), judged on every packet both ways:

- It reaches **what its level names and nothing else**: the Services, the ranges, the
  resolver, the internet or the Exit. Not the mesh, not another peer, not the node's own ports
  (the API's only with `api`), not a Service of another level.
- Its address is its own: WireGuard drops a packet whose source is another's.
- **A level narrowed, or a peer deleted, holds within seconds**, a connection it has open
  included: no rule lets a reply through on the strength of the connection alone.
- Past the node, a peer is that node: a host or a NetworkPolicy sees the node's address.
- A peer holds 8 of the Service proxy's places and 2 of 16 API handshakes; keys kithd makes are
  rationed to 5 a minute.

Writing a level or a peer is a cluster-wide right, by kind: whoever may apply an AccessLevel
may widen any level, and put any peer on it. Give it as you would an admin's. What a level does
not hold (DNS over HTTPS around the filter, bandwidth, IPv6 to the internet, a copied
configuration until it is deleted) is in [SECURITY.md](../../SECURITY.md) ("A person's device").
`sh ci/vm.sh --test access` drives it with two phones in virtual machines: a Service reached, a
level narrowed and a peer removed with a connection open, and an Exit's level leaving by it.

## What a node refuses, whatever the cluster says

Some of what the store tells a node to run is the node's own root (an `exec` unit, a root
container, a VM from a node path), so an admin's credential reaches every node. Its owner can
turn each off, there and nowhere else:

```sh
kithd --node-policy hardened              # none of it, and a GPU the only Device handed out
                                          # (also no NodeWorkloads: add host-users to run them)
kithd --node-policy hardened,node-network # the same, but containers that are no pod
kithd --node-policy no-exec-units,no-run  # everything but exec units and `kith run`
```

The words: `exec-units`; `root-containers` (off: no container is root without an id range of its
own, as a pod's on kith OS); `unconfined` (a `seccomp` that is unconfined or allows refused
calls back, which `userNamespaces` does); `host-users` (containers with `host_users`, a
NodeWorkload's: the node's own users; off, no NodeWorkload runs); `node-network` (containers that are no pod); `vms`; `vm-paths` (a VM's kernel,
firmware or disks as node paths, or a hypervisor other than qemu; `vms` alone runs none of use); `passthrough`; `host-paths` (a Volume in `kith-system` at any path on the node);
`run` (`kith run`); `wipe` (the cluster erasing this node's key or setting duress codes);
`devices=gpu+input` (the Device classes a DeviceClaim hands out: `all`, or none after the `=`;
with classes named, only Devices the node listed itself). `no-` before a word turns it off; they
are read left to right. On kith OS they go at the end of what the config partition says (` --
--node-policy hardened`); elsewhere `KITH_NODE_POLICY` does too.

`hardened` also stops NodeWorkloads (DaemonSets): turn `host-users` back on to run them. A
container given a Device, or a mount on a file system that cannot be id-mapped, keeps the node's
users too, whatever `host-users` says.

What a node refuses is not run there, and the Workload says why. The scheduler reads each Node's
`status.policy` (`kith get node/NAME -o yaml`): a Workload or Job asking for what a node refuses
goes to nodes that allow it, and waits, saying so, when none does. A node with no policy does
everything. A word kithd does not know ends its start (kith OS runs `hardened` instead).

Where `exec-units`, `vm-paths` and `run` are all off, kithd also cuts its bounding set at start
to the fourteen a root pod keeps (`KEPT` in `crates/kithd/src/policy.rs`): nothing it starts by
an exec can hold `SYS_MODULE`, `SYS_ADMIN`, `SYS_PTRACE` or any other capability outside them. A
container's own set is its spec's. Not covered: kithd's own threads, root tracing root's
processes or writing `/proc/sys` (`docs/adr-privilege.md`). What this is and is not a defence
against: [SECURITY.md](../../SECURITY.md).
