# Coming from Kubernetes, Helm, Proxmox or compose

## kubectl and Helm, as they are

kithd answers the Kubernetes API on its own port (`/api` and `/apis` beside `/v1`), so `kubectl`
and `helm` (3 and 4) work against a kith cluster with the manifests and charts you already have,
nothing rewritten or migrated. Nothing of Kubernetes runs: no API server, etcd or kubelet. kithd
holds each object as the kith resource it means, and gives it back as it was sent.

A kubeconfig is an Identity's certificate ([Who may do what](access.md#who-may-do-what)):

```sh
kith identity cert alice --out .    # alice.crt, alice.key and the cluster's ca.crt
```

```
# kubeconfig, beside those three files
apiVersion: v1
kind: Config
current-context: kith
clusters:
- name: kith
  cluster: { server: "https://NODE:7443", certificate-authority: ca.crt, tls-server-name: kith }
users:
- name: alice
  user: { client-certificate: alice.crt, client-key: alice.key }
contexts:
- name: kith
  context: { cluster: kith, user: alice }
```

```sh
export KUBECONFIG=$PWD/kubeconfig
kubectl apply -f manifests/               # a directory written for Kubernetes
kubectl rollout status deployment/shop
kubectl get pods -o wide                  # a pod each, with an address of its own
kubectl logs shop-0
helm install site ./chart --wait
```

| Kubernetes | What kith holds |
|---|---|
| Deployment, StatefulSet | a Workload whose replicas are pods (`pod: true`: [a pod](workloads.md#a-replica-as-a-pod)) |
| DaemonSet | a NodeWorkload |
| Job, CronJob | a Job, a CronJob (its Jobs are made by the clock, in UTC, a missed minute made up within `startingDeadlineSeconds`; the last three that succeeded and three that failed are kept, or `successfulJobsHistoryLimit` and `failedJobsHistoryLimit`) |
| Service, Namespace | a Service, a Namespace |
| Ingress | `expose` on the Service behind each host, its `Prefix` and `Exact` paths as `paths`; the Ingress itself is kept to be read back. Refused by name: a path that is a pattern, an annotation that rewrites or matches by pattern, and one that keeps clients out (`auth-*`, an allow or deny list, a snippet, middlewares), which kith's edge would not honour |
| ConfigMap, Secret | a ConfigMap, a Secret (Helm keeps its releases in Secrets: they are kith Secrets) |
| PersistentVolumeClaim | a VolumeClaim that says `provision: true`: a Volume is made for it on a node |
| ServiceAccount, Role, RoleBinding, ClusterRole, ClusterRoleBinding, PodDisruptionBudget, IngressClass | kept as sent (a `KubeObject`), read back, and said to give nothing |
| Pod, ReplicaSet, Node, Event | made for reading from what kith runs: `kubectl get pods`, `describe`, `logs` (a pod's name says what runs it, so a Deployment and a Job of one name make two: a Deployment's or StatefulSet's pods are `NAME-0`, a Job's `NAME-j0` and a DaemonSet's `NAME-n0`) |

What works, by the real clients in the tests (`sh ci/kube.sh`, and `sh ci/kube.sh --vm` for what
needs pods that run):

| Client | What works |
|---|---|
| kubectl | `apply` (client-side and `--server-side`), `create` (deployment, job, `job --from=cronjob/…`, cronjob, configmap, secret, namespace, serviceaccount), `get` (tables, `-o yaml\|json\|wide\|name\|jsonpath`, `-A`, `--watch`, `get all`), `describe`, `diff`, `replace`, `patch` (strategic, merge and `--type json`: the six RFC 6902 operations, a failing `test` or a path not there refuses the whole patch with a 422), `label`, `annotate`, `scale`, `expose`, `set image`, `rollout status`, `rollout restart`, `wait`, `logs` (`-f`, `--tail`, of a pod, a Deployment or a Job), `delete` (a pod restarts its owner's replica in place: the same name, a new start time, the other replicas untouched; it needs `apply` on the Workload, and a pod nothing owns is refused by name) |
| helm | `install`, `upgrade`, `rollback`, `uninstall`, `list`, `status`, `history`, `get manifest`, each with and without `--wait`, into a namespace it creates |
| Field managers | `kubectl apply --server-side` keeps who set which field (`metadata.managedFields`, up to 64 managers an object). Managers that apply one object each keep their own fields; a second manager's different value for a field the first set is a `409 Conflict` in Kubernetes's words, unless it says `--force-conflicts` (it then takes the field). A field a manager leaves out of its next apply goes, when no other manager has it. Fields are owned by their exact path, a list with no one key to merge by is owned whole, and only an apply makes a manager (a `replace` or a `patch` takes a field from whoever had it). Applying onto an object that exists, or replacing one, needs `get` as well as `apply`, as a patch does |
| AGE | `kubectl get namespaces` and `get nodes` show the time of the oldest revision the store kept: when it was made, unless the history was trimmed or the node is a worker that runs from a view and holds only what the view carried (an implicit namespace, one that only holds objects, has none) |
| Watches | `kubectl get --watch` reads what the store says changed, so one change among 2000 objects makes and compares one object, not 2000 (it shows what a list shows: the same Roles apply). It reads the kind again when it cannot know what changed: on a worker node that runs from a view, after a change to an Identity, a Role or a RoleBinding, after more than 4096 changed keys, after the store was replaced, and for Namespaces |
| port-forward | `kubectl port-forward POD LOCAL:REMOTE` (the WebSocket kubectl asks for first; the older `POST` upgrade is refused), for a pod of a Workload or a Job, as the caller who has the `exec` right on what owns the pod (`get` alone is refused, before anything is upgraded). The bytes go both ways to the pod's own address and the port asked, over the node that runs the replica; a connection that moves no byte for 5 minutes ends, a session carries 16 connections and a caller has 8 sessions at a node. TCP only, and not to a NodeWorkload's host unit |
| GitOps | a [Source](packages.md#sources-gitops) follows a repository of Kubernetes manifests as they are; a file's objects are read exactly as the API reads them |
| Every field | accounted for by one table (`crates/kith-kube/src/lib.rs`): carried into the kith resource, or taken with a `Warning:` that it changes nothing (kubectl prints it), or the object is refused with a status that names the field. Nothing is dropped in silence, and `kubectl get -o yaml` gives back what was sent |

Not answered, each refused in words:

| What | Note |
|---|---|
| A write to a resource's `/status` (a controller's, or `kubectl patch --subresource=status`) | `status is kithd's own`, written from what runs, not taken from a client. Reading works |
| `exec`, `attach`, `cp`, `kubectl run` (a pod alone), `kubectl top`; CustomResourceDefinitions (so other people's operators), admission webhooks, NetworkPolicy, HorizontalPodAutoscaler | |
| What it is not, and is not meant to become | kith is not a conformant Kubernetes (the conformance tests are not run and would not pass). It takes no CNI, CSI or device plugin (a pod's network, a volume and a device are kith's own), serves no aggregated API, and never starts, fetches or packages Kubernetes: what needs the real thing needs a real cluster |
| In a pod: `hostNetwork`, `hostPID`, `hostIPC`, `hostPath`, `privileged`, added capabilities | kith gives no Workload these, by any API |
| In a pod: a `projected` or `downwardAPI` volume, a mode for one item of a volume, an initContainer with a `restartPolicy` (a sidecar) | What a chart commonly says is carried, as [kith's own fields](workloads.md#what-a-container-is-given): volumes from a ConfigMap, a Secret or an `emptyDir`, `subPath` of any of them, `envFrom`, `fieldRef`, `initContainers`, `runAsNonRoot`, dropped capabilities, and `limits.ephemeral-storage` with a disk `emptyDir`'s `sizeLimit` as `resources.storage` (either under 64Ki raised to it) |
| A CronJob in a time zone other than UTC; `kubectl rollout undo` | use `kith rollback` |
| `--cascade=orphan`, `kubectl logs --previous`, `--since`, `--timestamps` | a unit's output is kept as it was written, not when |

What it costs: it is in the one kithd there is and added 0.38 MB to it, and the JSON patch 0.01 MB
more (the budget, then 13 MB, was not raised for it; kithd was 12.72 MB then). With pods and CronJobs kithd with nothing to do holds
7.8 MB of memory, as before (`python3 ci/budgets.py`); a node no client asks runs none of it.

Who may do what is kith's own: a request on `/api` is checked as the same request on `/v1`
would be, for the kith kind it means, by the Roles bound to the certificate's Identity (a
`kubectl patch` needs `get` as well as `apply`; a CronJob needs `apply` on Job, a
PersistentVolumeClaim on Volume). Kubernetes's Roles and ServiceAccounts give nothing. What
kith's own files made is not shown as a Kubernetes object, nor written over through this API.

## Importing from Kubernetes and Helm

`kith import k8s -f manifests.yaml` (`-f -` reads stdin; `-f` may repeat; a `List` is unwrapped)
prints the kith resources the manifests translate to. `kith import helm ./chart --name shop -n
store -f values.yaml` runs your installed `helm template` and translates what it prints (no
helm: pipe `helm template ... | kith import k8s -f -`). Review the output, then `kith apply -f`
it.

| Kubernetes | kith |
|---|---|
| Deployment, StatefulSet | Workload with `pod: true` (a StatefulSet's `volumeClaimTemplates` each become a VolumeClaim for each replica, `<template>-<name>-<ordinal>`, and its mount is `perReplica`: [each replica its own](storage.md#a-claim-for-each-replica). Scaling down keeps the claims and their data, as Kubernetes does, and scaling up again finds them) |
| DaemonSet, Service | NodeWorkload, Service |
| Ingress | `expose: {host, via: edge, paths}` on the Service behind each host (the one behind `/`, else the first named) |
| ConfigMap, Secret | ConfigMap, Secret (`data` decoded from base64: the output holds the plain text) |
| PersistentVolumeClaim | VolumeClaim, with `provision: true` unless it says `storageClassName: ""` |
| Job, CronJob | Job, CronJob (`startingDeadlineSeconds`, `successfulJobsHistoryLimit` and `failedJobsHistoryLimit` are kept to; a `timeZone` other than UTC is refused) |
| `nodeSelector`, a pod template's labels | a placement requirement; the labels are added to the workload's, since kith Services select on those |
| Not carried over | named on stderr by path, by the table [the Kubernetes API](#kubectl-and-helm-as-they-are) answers by: a field kith has nothing for (`hostNetwork`, an unknown kind, an object that would not validate), such as `not translated: Deployment/web: spec.template.spec.hostNetwork not translated`, and one taken that changes nothing (an `affinity`, most of a `securityContext`). Status, `managedFields`, `uid`, `resourceVersion` and Helm's own labels are ignored, not reported |
| Exit status | 0 everything translated, 1 something is in the report (the output is still printed), 2 the input could not be read |

### From a docker-compose file

`kith import compose docker-compose.yml --node n1 -n media` prints the stack as kith resources,
the same way: review, then `kith apply -f` it. It is a translation, once; kith does not run
compose. kith's YAML has no anchors, merge keys or variables: `docker compose config` writes them
out, and a value that still holds a `$` is refused by name.

| compose | kith |
|---|---|
| a service | a Workload with `pod: true` (a network of its own, as in compose) and one container |
| services joined by `network_mode: service:NAME` | containers of NAME's pod: they share `localhost` |
| `ports`, `expose` | a Service of the compose name, and of `container_name` and each network alias, with the container's ports (TCP) |
| a directory (`./config:/config`), a named volume | a Volume on the node `--node` names, and its mount (`:ro` carried) |
| `environment`, `command`, `entrypoint`, `working_dir`, `user` | the same fields of the container |
| `restart` | `restartPolicy` |
| `healthcheck` with `curl` or `wget` of an http address on localhost | a `readiness` probe with its interval, timeout and retries |
| refused by path and name, as `kith import k8s` does | `privileged`, `cap_add`, `sysctls`, `devices` (a [DeviceClaim](hardware.md#claiming-hardware) is how kith gives hardware), `network_mode: host`, `env_file`, `tmpfs`, a UDP port, a port published on the node's own address, a `depends_on` condition (kith waits for nothing: an app retries), two networks in one file (a namespace is one network), an absolute host path (kith takes one in `kith-system` only, and never `/`, `/proc`, `/sys`, `/dev` or a docker socket), two volumes that would make one name, and every key it does not know |
| a variable named like a secret (`PASSWORD`, `TOKEN`, `KEY`) | carried and said: it is in the output as plain text, and a Secret with `envFrom` keeps it out of the Workload |

## Coming from Proxmox or docker compose

A guest on a hypervisor is a whole system with one job. On kith the job is a Workload from the
same image the guest would have run, its data a Volume, its name a Service; the system around it
is kith OS. What each kind of guest becomes, and what is still missing:

| A guest that is | Becomes | Today |
|---|---|---|
| a web app with one port and a data directory (a password manager, a search engine, an automation tool, a package repository) | a Workload, a Volume, a Service with `expose` | works |
| an app with its database and helpers beside it (a file cloud, a Git forge) | one pod: the containers share `localhost`; a Volume each | works; a port other than HTTPS (the forge's SSH) is a published port, on the pod's node only |
| a media server with a GPU | a Workload with a `DeviceClaim` on the card | the claim works; transcoding is not tried on a real card |
| a compose stack | [`kith import compose FILE`](#from-a-docker-compose-file) prints it as Workloads, Services and Volumes, and refuses by name what it cannot carry | works for what it carries |
| a reverse proxy | kith's own ingress: a Service's `expose`, a certificate by ACME or your own | by host name and by path, with headers set; no rewriting of paths, no login in front of an app, no HTTP/2 to a host read by path |
| a DNS filter | kith's own [DNS](cluster.md#dns) with a `DNSBlockList`: hosts files and filter lists' plain rules | works; no per-client statistics or query log |
| a mail relay, or anything on a port of the LAN that is not HTTPS | a pod whose port says [`publish: true`](workloads.md#a-pod-behind-a-vpn-exit), or a Workload that shares its node's network (root, not a pod) | works; a published port is on one node, the first pod's there to ask for it |
| a VPN endpoint for people (phones, laptops) | kith's own, with levels of access | not yet |
| an app that must go out through a VPN | a Workload with an [exit](workloads.md#a-pod-behind-a-vpn-exit), its web UI a published port | WireGuard; tested against a provider in a VM, not a real one |
| a VM with no image (an appliance) | a [`vms` unit](hardware.md#virtual-machines) | outbound network only, its disk not a Volume, not on kith OS: not yet |

Moving a guest's data, one guest at a time:

1. Stop the app in the guest, so its files are whole.
2. Apply the Volume its Workload will mount (`kith apply -f app.yaml`; the Workload may wait with
   `replicas: 0`).
3. From a machine that reaches both, send the directory: `ssh GUEST tar -cf - -C /var/lib/app . |
   kith volume put app-data -` (or `kith volume put app-data ./a-copy`). It says how many files
   went in and names any link it left out; see [Files in and out of a
   volume](storage.md#files-in-and-out-of-a-volume) for what it refuses.
4. Start the Workload and look at the app. The files are its user's whatever they were in the
   guest. Keep the old guest stopped, not deleted, until the new one has run a week.

kith does not need the hypervisor gone first: a kith OS image boots as a guest (UEFI, virtio
disk and network), the way to try it beside what runs today. It is tested in QEMU, not on
Proxmox itself: see [As a guest on Proxmox VE](os.md#as-a-guest-on-proxmox-ve).
