# Access: who may do what, and what a node refuses

## Who may do what

On a node, whoever can open kithd's socket is the admin: `kith` there may do
everything. From anywhere else, a person or a program calls a node's TLS port
(`--listen`) as an **Identity**, with a certificate from the cluster's CA,
and may do what the **Roles** bound to it allow. Nothing, to begin with.
What each of them is trusted with, what kith does not defend against, and how
to report a hole: [SECURITY.md](../../SECURITY.md).

```sh
kith identity cert alice --out ~/alice    # on the node the cluster was started on
```

writes `alice.crt`, `alice.key` and `ca.crt`, and makes `Identity/alice` if it
is not there. Then say what she may do:

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

(Every node's certificate is good for the name `kith`. `kith` itself only
talks to the local socket so far.)

A node nobody can log in to (kith OS has no shell) has no socket to run that
on. Start its kithd with `--claim`: while the cluster has no Identity, it
prints a token at each start,

```
kithd: nobody administers this cluster from outside yet. For an hour, whoever sends this token to /v1/claim does: kith1.<secret>.<the CA's fingerprint>
```

and whoever sends it first becomes an Identity that may do everything (a Role
`cluster-admin` is bound to it):

```sh
curl -k -d "{\"token\":\"$TOKEN\",\"name\":\"root\"}" -H 'Content-Type: application/json' \
     https://10.0.0.7:7443/v1/claim       # {"ca": …, "cert": …, "key": …}: save as ca.crt, root.crt, root.key
```

Once the cluster has an Identity, however it was made, the token claims
nothing. The token is good once, for an hour, and for nothing else (it admits no node,
and a join token claims nothing). `-k` there means curl does not know the
node yet: the token's last part is the SHA-256 of the cluster's CA, so to be
sure nobody sits in between, fetch `https://10.0.0.7:7443/v1/ca` first,
compare `openssl x509 -noout -fingerprint -sha256` of it with that part, and
claim with `--cacert` instead. The token is on the node's console: who can
read that, or its logs, within the hour can claim the cluster.

Such a cluster has no socket to ask for a join token either, so its admin
asks over TLS: `curl --cacert ca.crt --cert root.crt --key root.key -X POST
https://10.0.0.7:7443/v1/tokens`. A node may do everything in its cluster, so
this is only for an Identity that may apply Nodes, Roles and RoleBindings:
one that could give itself every right anyway.

- What is not allowed is refused with 403 and the reason. `list` and `watch`
  show what the caller may see and no more. An apply is all or nothing: one
  resource it may not apply refuses the whole body.
- `get` covers a resource, its history and its output (`/v1/logs`); `apply`
  covers rollback; pushing to or pulling from a registry through kithd takes
  `apply` on `Package` (kithd then calls whatever registry is named: grant
  it to those you would let do that).
- A rule that names namespaces says nothing of kinds that are in none (Node,
  Role, KindDefinition…): those take a rule without `namespaces`.
- The certificate stands for the Identity while the Identity's `publicKey` is
  the certificate's key. `kith identity cert` again gives a new key and ends
  the old certificate's access; `kith delete identity/alice` ends it all.
- Grant with care: `apply` on Role, RoleBinding or Identity is the power to
  grant oneself anything, and whoever may apply a Workload runs programs on
  your nodes. A Release or a Source acts with the rights of whoever applied
  it, and makes nothing they may not apply themselves (see Packages and
  Sources); deleting one removes what it installed, whoever may delete it.

Every change made through a node, and every refusal, is one line in that
node's audit log (`audit.log` in its state directory, 4 MB and the four
files of 4 MB before it, `audit.log.1` to `.4`): when, who, what, and how it
went. A certificate that no longer stands for its Identity is a refusal too,
and so is no certificate at all (one line a minute of those). Refusals past
sixty a minute are counted rather than written. A watch ends when its
Identity is deleted or given another certificate. `Audit` is not a name a
custom kind may take. Permission is asked when a request arrives, and an
Identity's apply, delete or rollback is asked again on the leader as it is put
in the log: a RoleBinding deleted before then stops it, even when the node it
reached had not heard of the deletion yet. A write already in the log before
the deletion stays (SECURITY.md says what else is decided once, where it
arrives). `kith audit` shows the last of it,
as does `GET /v1/audit` for an Identity with `get` on `Audit`.

```
WHEN                  WHO           DID     WHAT                            OUTCOME
2026-11-12T10:02:11Z  local socket  apply   Role/web-editor                 ok
2026-11-12T10:03:40Z  alice         apply   Workload/web/site               ok
2026-11-12T10:03:55Z  alice         delete  Node                            alice may not delete Node: no Role bound to it allows that
```

### A Workload that calls the API

A Workload that reads or writes the cluster (a controller, a gateway) runs as
an Identity, with no key typed into a Secret. The Identity says which
Workloads may (a namespace, and the Workloads in it where `names` is given),
and the Workload says which Identity it runs as:

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

Each container of its pods finds `ca.crt`, `tls.crt`, `tls.key` and `address`
(a control node's, `HOST:PORT`) in `/run/kith/identity`, in memory and
readable by the container's user alone, and calls `https://ADDRESS` with them
as `gateway`: what that Identity's Roles allow, and nothing else. The node
that runs the pod makes the key; the certificate lasts two hours and is made
again after one, with the same key and without the container starting again.
It stands only while the store still says so: the Identity names the
Workload, the Workload says `identity: gateway` and is placed on that node,
and the node is there. An apply where the Identity does not name the
Workload is refused, and so is an Identity with both `publicKey` and
`workloads`, and a template with exec units or VMs (only containers are given
the files). Where the cluster no longer allows it, the certificate is taken out
of the files within a minute, and asked for again every ten minutes. A node
with no directory in memory does not start the pod.

Not yet: `kith` over TLS, logging in through an identity provider (OIDC),
certificates for people that expire before ten years, one audit log for the
cluster.

## What a node refuses, whatever the cluster says

A node runs what the cluster's store tells it, and some of that is the node's own root: an
`exec` unit, a container that is root, a VM from a path on the node. Whoever holds an
admin's credential has every node through them. A node's owner can turn each off for that
node, where its kithd is started and nowhere else:

```sh
kithd --node-policy hardened              # none of it, and a GPU the only Device handed out
kithd --node-policy hardened,node-network # the same, but containers that are no pod
kithd --node-policy no-exec-units,no-run  # everything but exec units and `kith run`
```

The words: `exec-units`, `root-containers` (off: no container is root unless it has a
range of ids of its own, as a pod's has on kith OS), `unconfined` (a `seccomp` that is unconfined or allows refused calls
back), `node-network` (containers that are no pod), `vms`, `vm-paths` (a VM's kernel,
firmware or disks as paths on the node, or another hypervisor than qemu), `passthrough`,
`host-paths` (a Volume in `kith-system`, whose path is anywhere on the node), `run`
(`kith run`), `wipe` (the cluster erasing this node's key, or setting its duress codes)
and `devices=gpu+input` (the classes of Device a DeviceClaim hands out; `all`, or nothing
after the `=` for none; with classes named, only Devices the node listed itself are
handed out, not ones written by hand). `no-` before a word turns it off, and they are
read left to right. On kith OS they go with kithd's other arguments at the end of what
the config partition says (` -- --node-policy hardened`); elsewhere `KITH_NODE_POLICY`
does too.

What a node refuses is not run there, and the Workload says why:

```
this node's policy refuses exec units: processes of the node's root, with all of /dev (execUnits is off: `--node-policy exec-units` where the node's kithd is started allows it)
```

Where `exec-units`, `vm-paths` and `run` are all off (nothing the cluster asks can start
a process as the node's root with every capability), kithd cuts its bounding set at
start to the fourteen a root pod keeps (`KEPT` in `crates/kithd/src/policy.rs`). That
limits what an exec gives a child: nothing kithd starts by an exec can hold `SYS_MODULE`,
`SYS_RAWIO`, `SYS_PTRACE`, `SYS_TIME`, `SYS_ADMIN`, `SYS_BOOT` or any other capability
outside the list in the node's own user namespace, whatever its spec asks for (a pod with
`userNamespaces` has a full bounding set inside its own namespace, over that namespace's
resources only). A container's own bounding set is its spec's on any node, cut or not; the
cut is what kithd's other children inherit (a Source's git, dnsmasq, the storage holder,
libcontainer's init before its capset). kithd's own threads keep every capability, so a hole inside kithd is not
held back by this (the split in `docs/adr-privilege.md` is for that), and root without
`SYS_PTRACE` can still trace root's own processes or write `/proc/sys`: not covered.
The Node's status says what it kept (`status.policy.capabilities`; `all` where it did not
cut: a kithd that is not root, or one of the three still on).

`kith get node/NAME -o yaml` shows a node's policy under `status.policy` once it has
one. A node with none does everything, as before. The scheduler reads it: a Workload or
Job that asks for what a node refuses is placed on the nodes that allow it, and waits,
saying so, when none does. (A NodeWorkload's copy, a claimed Device and a Volume belong
to one node: there the node itself says why it runs nothing.) A VM's kernel and disks are
paths on the node today, so `vms` without `vm-paths` runs no VM of use. A word kithd does
not know ends its start (on kith OS the node runs `hardened` instead, and says so on its
console). What this is and is not a defence against: [SECURITY.md](../../SECURITY.md).
