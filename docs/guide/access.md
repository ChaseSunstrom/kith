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
- A rule with `names: [canary]` covers only the resources of those kinds called `canary` (exact
  names, no patterns: `*` is refused when the Role is applied; left out or `[]`, every name). The
  Identity may apply, get, delete (and go back, read the history or the logs of) those and no
  others, in the rule's namespaces; `list` and `watch` show it only those. A refusal is the same
  whether the name is stored or not, so it cannot be used to find what exists. A route that
  cannot say which resource it reaches (a kind-wide check) is not covered by a rule with
  `names`: it is refused, never widened. A Kubernetes-API call is checked without a name
  (`Call::allowed` in kube.rs), so a rule with `names` does not grant it: it fails closed. An older kithd
  refuses a Role with `names` (it does not ignore the field), so apply one only once every
  control node is updated. A name limits *which* resource, not what is in it: an agent that may
  apply the UpdatePlan `canary` may change its `release` and `selector`, so never give a rule
  with `names` an UpdatePlan the agent could retarget. Give it the OSRelease and keep the plan:

  ```yaml
  # A release agent for the canary ring: it may write the OSRelease called canary and nothing
  # else. The admin owns the UpdatePlan canary (release: canary, selector: the canary ring); a
  # changed OSRelease canary is a new revision, so that plan rolls again. The agent can write no
  # UpdatePlan and no other release (403).
  apiVersion: kith.dev/v1
  kind: Role
  metadata: { name: canary-roller }
  spec:
    rules:
      - { kinds: [OSRelease], verbs: [get, list, apply, delete], names: [canary] }
  ```
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

A node's own certificate is not part of a context: kithd makes it again before it ends and
refuses a deleted Node's or a replaced Identity's at the next handshake (SECURITY.md, "A node's
certificate: its life, its renewal, and its revocation").

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

`kithd --split` (or `KITH_SPLIT`, off by default) puts what needs root behind a typed request list
and a socket, and holds the part that reads the network to a confinement of its own: its state
directory alone in its mount namespace, a user that is not root, no capability, `no_new_privs` and
a system call filter. It is not complete:
until the two parts are processes the confinement is built and tested but not applied, and a node
that runs `--split` has the socket and no more. Even applied, the serving part shares the node's
network namespace (the host's loopback and abstract `AF_UNIX` sockets stay reachable).
`docs/adr-privilege.md` says what is done.

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
