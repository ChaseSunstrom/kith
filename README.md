<p align="center"><img src="logo-wordmark.svg" alt="kith" width="300"></p>

> **kith** *(n.)* one's close circle; the people you trust.

A tiny, immutable operating system that turns all of your machines into one
cluster, configured entirely through declarative resources. On every node one
process, `kithd`, is the API, the store, the scheduler and the container
runtime (under 13 MB, a budget the build is held to); `kith` is the command you
drive it with.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/ui-dark.png">
  <img src="docs/ui-light.png" alt="kith's web UI over a cluster of three nodes: the kinds down the left as stops on a line, the nodes and each workload's replicas drawn as a line map, the list of Workloads, and the form of the one that is open" width="100%">
</picture>

A page that shows it, with every number measured: <https://chasesunstrom.github.io/kith/>.
The design is in [PLAN.md](PLAN.md); what was read for security, and what kith
does not defend against, in [SECURITY.md](SECURITY.md).

## First run

On one Linux machine, as you: no root, an existing distribution (it needs
cgroup v2 and a systemd user session, which a current desktop or server has)
and a Rust toolchain. Most of the time it takes is the build.

1. Build the two programs and put them on your path.

   ```sh
   cargo build --release
   export PATH=$PWD/target/release:$PATH
   kith --version
   ```

   You should see `kith 1.0.0`.

2. Start the daemon.

   ```sh
   systemd-run --user --scope --quiet kithd &
   ```

   (Not plain `kithd &`: a container's cgroup goes next to kithd's own, which has to be
   your user's. From an ssh login or a system service it is root's, and kithd would take
   workloads and start none; it says so at start. `systemd-run --user --scope` runs it in
   your user's systemd.)

   You should see `kithd: serving …/kithd.sock` (a socket under `/run/user/`
   that only you can open), and after it where the state is kept.

3. Apply the smallest example: one container that says hello every five
   seconds ([examples/hello.yaml](examples/hello.yaml), 14 lines).

   ```sh
   kith apply -f examples/hello.yaml
   ```

   You should see `Workload/default/hello created (revision 1)`.

4. Look at what there is. The first time its image is pulled, which takes a
   few seconds; ask again until it is ready.

   ```sh
   kith get
   ```

   You should see `hello  1         1/1 ready`.

5. Read what it says.

   ```sh
   kith logs workload/hello
   ```

   You should see `hello from w_default_hello_0_main`, a line for every five
   seconds it has run.

6. Open the web UI: the picture above, with your one Workload in it.

   ```sh
   kith ui
   ```

   You should see `http://127.0.0.1:…/ui/`. Open that address in a browser on
   the same machine; ctrl-c ends it.

7. Take the Workload away again.

   ```sh
   kith delete workload/hello
   ```

   You should see `Workload/default/hello deleted`.

That is all of it on one machine. `kill %1` stops the daemon; what you applied
is still there when it starts again.

## What do you want to do?

| To | Read |
|---|---|
| Run containers, plain processes and jobs, and change them safely | [What kithd does today](docs/guide/workloads.md#what-kithd-does-today) |
| Make several machines one cluster | [More than one node](docs/guide/cluster.md#more-than-one-node) |
| Give what runs a name, inside and outside | [DNS](docs/guide/cluster.md#dns); a host of its own with a certificate: [More than one node](docs/guide/cluster.md#more-than-one-node) |
| Say a thing once: names, functions and imports instead of YAML repeated | [kith's own language](docs/guide/api.md#kiths-own-language) |
| Install an app with its settings, and upgrade it | [Packages](docs/guide/packages.md#packages) |
| Keep a cluster in step with a git repository | [Sources (GitOps)](docs/guide/packages.md#sources-gitops) |
| Use kubectl, Helm and the manifests you have, unchanged | [kubectl and Helm, as they are](docs/guide/kubernetes.md#kubectl-and-helm-as-they-are) |
| Turn manifests or a chart into kith's own files | [Importing from Kubernetes and Helm](docs/guide/kubernetes.md#importing-from-kubernetes-and-helm) |
| Add a kind of your own, with its controller | [Kinds of your own](docs/guide/api.md#kinds-of-your-own) |
| Let other people and programs in, each with their own rights | [Who may do what](docs/guide/access.md#who-may-do-what) |
| Hand out GPUs and seats, run virtual machines | [Hardware](docs/guide/hardware.md#hardware) |
| Keep data: volumes, shares, replicas, backups | [Storage](docs/guide/storage.md#storage) |
| Copy files into a volume or out of it, or move a guest's data in | [Files in and out of a volume](docs/guide/storage.md#files-in-and-out-of-a-volume) |
| See it and change it in a browser | [Web UI](docs/guide/ui.md#web-ui) |
| Make a machine nothing but a node, and keep it updated | [kith OS](docs/guide/os.md#kith-os-kithd-as-the-machines-first-process) |
| Know what it costs beside Kubernetes | [Beside k3s](#beside-k3s) |
| Find your way in the code and test it | [Layout](docs/guide/development.md#layout), [Development](docs/guide/development.md#development) |

## How it works

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/diagrams/architecture-dark.svg">
  <img src="docs/assets/diagrams/architecture-light.svg" alt="How kith works: the kith command and the web UI talk to kithd's resource API; what is applied goes into the store whole or not at all; from the store the scheduler places replicas, the controller starts and stops them on its node through kith's own runtime, and the mesh, Services and DNS follow; the store is replicated to the other nodes by Raft, and where the mesh is on (--mesh) each node has a WireGuard tunnel to every other" width="100%">
</picture>

You say what should exist, in files; `kith apply` sends them to a node, which
takes all of them or none. Everything else is `kithd` making its node match:
on the node that leads the store the scheduler says which node runs each
replica, and every node's controller starts and stops what is its own, with no
container daemon in between. With more than one node the store is copied to
the others by Raft; started with `--mesh`, the nodes also set up WireGuard
tunnels between themselves, over which what runs on one node reaches what
runs on another.

## Status

Every phase of the plan has been worked through, and the tree is at version
1.0.0: `kith.dev/v1` [is stable](docs/guide/api.md#kithdevv1-is-stable). No release has been
tagged. Each section below says what works and, under "Not yet", what does not
(some of it named by the plan); what was read for security,
and what kith does not defend against, is in [SECURITY.md](SECURITY.md).

`kithd` runs as a service on an existing Linux distro (agent mode), or as the
first process of [kith OS](docs/guide/os.md#kith-os-kithd-as-the-machines-first-process); on
one machine, or on several [joined into a cluster](docs/guide/cluster.md#more-than-one-node). It owns
the store and keeps the containers, processes and machines on its node matching
the resources you apply. The [first run](#first-run) is one node in agent mode;
beyond it, everything goes through the same few commands:

```sh
kith get workload/hello -o yaml  # status: each container's state, restarts and last exit code
kith get -w workload             # the table, then each row as it changes (a long-poll on GET /v1/watch)
kith logs workload/hello -f      # its output, as it arrives
kith lint -f examples/           # validate files; needs no daemon
kith diff -f examples/           # what apply would change; exits 1 if anything
kith apply -f examples/          # all or nothing
kith history workload/hello
kith rollback workload/hello --to 1
kith schema                      # the 36 built-in kinds; `kith schema workload` prints its JSON Schema
```

Mistakes are reported with the file, line and column:

```
web.yaml:7:13: invalid type: string "yes", expected u32
  |   replicas: yes
  |             ^
```

## Beside k3s

`sh ci/compare.sh` starts the same three machines twice (QEMU with KVM, 2 CPUs and
2048 MB each, on a network of their own): as three kith OS nodes, and as Alpine 3.24
with k3s v1.37.2 as it comes (a server and two agents, with the DNS, ingress, load
balancer, metrics and storage k3s starts by itself). It measures both from outside,
the same way, runs the same workloads on both, and writes the tables down
([ci/compare.txt](ci/compare.txt)):

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/diagrams/beside-k3s-dark.svg">
  <img src="docs/assets/diagrams/beside-k3s-light.svg" alt="kith beside k3s as bars, each pair on its own scale: Memory in use, idle: the first node, or the server: kith 67 MB, k3s 963 MB; Memory in use, idle: another node, or an agent: kith 65 MB, k3s 478 MB; CPU in use, idle: the first node, or the server: kith 0.7 % of a CPU, k3s 9.5 % of a CPU; From switching a machine on to a ready node: kith 2.6 s, k3s 29.4 s; From apply to a ready container: kith 0.03 s, k3s 0.49 s; One workload of 30 replicas: until all are ready: kith 0.12 s, k3s 2.66 s; A node lost: its replica ready on another, as each is set to wait: kith 300 s, k3s 354 s; Requests through a Service, connections kept (the one row where more is better): kith 29363 a second, k3s 51955 a second." width="100%">
</picture>

| | kith | k3s |
| --- | --- | --- |
| Memory in use on an idle node: the first node / the server | 66 MB (66 to 67, 3 runs) | 1030 MB (967 to 1035, 3 runs) |
| Memory in use on an idle node: another node / an agent | 65 MB (65 to 66, 3 runs) | 474 MB (472 to 479, 3 runs) |
| From apply to a ready container, its image on the node | 0.03 s (0.03 to 0.04, 3 runs) | 0.50 s (0.49 to 0.61, 3 runs) |
| A node lost: until its replica is ready on another, as each system comes | 300 s (300 to 305, 3 runs) | 350 s (344 to 364, 3 runs) |
| The same, each told to wait about 60 s | 60 s | 57 s |
| From switching a machine on to a node that is ready | 2.6 s (2.6 to 3.8, 3 runs) | 30.8 s (29.7 to 34.2, 3 runs) |
| CPU in use on an idle node: the first node / the server | 0.8 % of one CPU (0.7 to 0.9, 3 runs) | 11.2 % of one CPU (10.4 to 12.2, 3 runs) |
| CPU in use on an idle node: another node / an agent | 0.8 % of one CPU (0.7 to 0.9, 3 runs) | 5.1 % of one CPU (4.8 to 5.8, 3 runs) |
| On the first node's disk at the end | 248 MB (248 to 248, 3 runs) | 1261 MB (1261 to 1261, 3 runs) |

The same workloads, sent to each system's API in the same way (ci/compare_workloads.py):

| | kith | k3s |
| --- | --- | --- |
| One workload of 30 replicas: until all are ready | 0.17 s (0.16 to 0.22, 3 runs) | 2.72 s (2.63 to 3.57, 3 runs) |
| Memory in use that each of those replicas adds | 0.4 MB (0.4 to 0.5, 3 runs) | 11.9 MB (11.5 to 13.4, 3 runs) |
| 20 workloads at once: until all are ready | 0.16 s (0.14 to 0.17, 3 runs) | 4.29 s (4.25 to 4.32, 3 runs) |
| A change to a workload of 6 replicas: until all 6 run it | 0.14 s (0.11 to 0.17, 3 runs) | 1.33 s (1.28 to 1.47, 3 runs) |
| A container that exits: until it runs again | 0.01 s (0.01 to 0.02, 3 runs) | 0.69 s (0.41 to 0.87, 3 runs) |
| A Job that does nothing: until it has succeeded | 0.07 s (0.07 to 0.07, 3 runs) | 2.92 s (2.88 to 2.97, 3 runs) |
| Requests a second through a Service to 3 web servers, a connection each | 7367 (7236 to 7420, 3 runs) | 6988 (6698 to 7377, 3 runs) |
| Of those requests, half took under | 2 ms (2 to 2, 3 runs) | 3 ms (2 to 3, 3 runs) |
| and 99 in 100 under | 8 ms (7 to 8, 3 runs) | 9 ms (9 to 10, 3 runs) |
| Requests a second over connections that are kept | 26004 (25889 to 26682, 3 runs) | 24081 (23688 to 25074, 3 runs) |

Alpine alone, before k3s is started on it, has 233 MB (222 to 233, 3 runs) in use; kith OS has no such moment (kithd is its first process).
A kith OS machine answers on its API 2.5 s (2.5 to 3.7, 3 runs) after it is switched on (firmware included).

Of k3s's time to a ready node, 24.7 s (23.6 to 28.2, 3 runs) is Alpine starting; the rest is k3s, started by hand the moment Alpine takes a login.

- **Memory in use** is `MemTotal - MemAvailable` in a node's `/proc/meminfo`, read by
  one small container on every node three minutes after all of them run: the kernel,
  the system, and that container. For k3s that includes Alpine (the line under the
  tables); kith OS is a kernel and kithd.
- **From apply to a ready container** is from sending a workload of one replica
  (busybox, `sleep`) to the API until the API says its container is ready, which
  for both is "started", there being no probe. The image is on the node already. The
  middle of five in each run. The clock starts before the connection to the API is
  opened, and the API is asked every 0.02 s: no number can be much under that.
- **A node lost**: the machine that runs a replica is killed, as if its power went,
  and the time is until the replica is ready on another node. As they come, kith
  waits five minutes (`--lost-after`), and k3s calls the node lost 50 seconds after it
  last heard from it and then waits 300 more, by a toleration every pod is given. In
  the row after it both are told to wait about a minute: `--lost-after 60`, and a
  toleration of 10 seconds. That row is one run of each.
- **From switching a machine on to a ready node** is from the moment the script turns
  to the first machine (it makes the machine's disk from the image, then starts it)
  until the system says that node is ready. For k3s that is until Alpine takes a
  login and then from starting k3s by hand, which a machine set up to run it would
  have started by itself; the line under the tables says how much of it is Alpine.
- **CPU in use** is how busy a node was over the three minutes before the workloads
  (`/proc/stat`), as a share of one of its two CPUs. Nothing runs in them but the
  container that reads it and, at their end, the five applies of one replica above.
- **On the disk** is not measured alike, and cannot be: for kith it is how much of
  the machine's disk file has ever been written (the image with both of its slots,
  and everything since, deleted or not); for k3s it is what `df` says is in use
  inside the machine, without the archive of its images the script copies in.
- **The workloads** are sent to each system's own API by one piece of code
  ([ci/compare_workloads.py](ci/compare_workloads.py)): the same containers, the
  same counts, the same clock, and every image pulled before a clock that needs it
  starts. Ready is what each system says is ready, with no probe. The memory each
  replica adds is the memory in use on all three nodes with the 30 replicas, less
  what it was without them, over 30. The 20 workloads go to kith in one request,
  as its API takes them, and to k3s in one request each, as `kubectl apply` sends
  them. A change is rolled out as each system does it when told nothing, and is
  done for kith when every replica's output shows it, for k3s when the Deployment
  says all six are updated, ready and available. The container that exits sleeps
  three seconds first; the time is from its exit until it has started again, the
  first time that happens. The Job runs `true`, and is done when the system says it
  has succeeded. The requests are `ab` in a container on the first node, 20,000 of
  them, 20 at a time, to a Service in front of three nginx (each system puts them
  on the nodes it chooses): first a new connection for every request, which the
  two rows under it are also of, then connections that are kept.

What it does not say: anything about many nodes, or about more containers than
these. It is one shape of machine, a few runs, on a machine that was doing other
work at the time (so the times under a second move, and so do the requests). Where
the two differ in what they do, the numbers are not of the same thing:

- A kith container on kith OS shares its node's network; a pod has a network of
  its own, with an address, set up before its containers start. Much of the
  difference in starting many replicas is that.
- kith replaces all replicas of a changed workload that are on different nodes
  at once; Kubernetes goes a quarter at a time unless told otherwise.
- A kith Service is on the mesh, TCP only, and kithd itself passes every byte on
  between the two connections; k3s's is rules in the kernel. What goes from one
  kith node to another over the mesh is encrypted (WireGuard); between k3s's
  nodes, as it comes, it is not. In these runs kith serves somewhat more on
  both rows; with a new connection for each request the two ranges overlap,
  with connections that are kept they do not. (An earlier sitting of
  the same script had k3s's kept connections at 27,000 to 68,000 a second, three
  runs: a connection to a web server on the node that asks is passed by the
  kernel's rules faster than kithd passes it.) Where kith's time goes,
  from one run with one web server and connections that are kept
  ([ci/compare.where.txt](ci/compare.where.txt)): asked
  directly on its own node it answered 218,000 requests a second, through its
  Service on that node 94,000 (kithd's copying), and from another node 20,900,
  where the mesh alone gave 21,800 and the nodes' network with no mesh 30,400.
  So between nodes the encryption is the bound, not kithd, and on one node
  kithd is.
- nginx runs with a configuration of its own on both (it listens on 8080 and
  writes only under `/tmp`): as its image comes it wants to start as root and
  write into its image, which a kith container may not.
- And the two are not the same thing: k3s is Kubernetes, with its whole API and all
  that is written for it. kith answers the part of that API `kubectl` and `helm` use
  for the core kinds ([kubectl and Helm, as they are](docs/guide/kubernetes.md#kubectl-and-helm-as-they-are))
  and refuses the rest by name; the kith side of these tables is measured through
  kith's own API.
