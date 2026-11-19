# How the numbers beside k3s were taken

The tables in the README's [Beside k3s](../../README.md#beside-k3s) come from one script,
`sh ci/compare.sh`. It starts the same three machines twice (QEMU with KVM, 2 CPUs and
2048 MB each, on a network of their own): as three kith OS nodes, and as Alpine 3.24 with
k3s v1.37.2 as it comes (a server and two agents, with the DNS, ingress, load balancer,
metrics and storage k3s starts by itself). It measures both from outside, the same way,
runs the same workloads on both, and writes the tables to
[ci/compare.txt](../../ci/compare.txt).

## The numbers, drawn

The same middle runs, a pair of bars for each row that both systems have a number for, read
from [docs/numbers.json](../numbers.json) in the browser. Under the bars, the same numbers as a table.

## What each row is

| Row | How it is measured |
|---|---|
| Memory in use | `MemTotal - MemAvailable` in a node's `/proc/meminfo`, read by one small container on every node three minutes after all of them run: the kernel, the system, and that container. For k3s that includes Alpine (the line under the tables); kith OS is a kernel and kithd. |
| From apply to a ready container | From sending a workload of one replica (busybox, `sleep`) to the API until the API says its container is ready, which for both is "started", there being no probe. The image is on the node already. The middle of five in each run. The clock starts before the connection to the API is opened, and the API is asked every 0.02 s: no number can be much under that. |
| A node lost | The machine that runs a replica is killed, as if its power went, and the time is until the replica is ready on another node. As they come, kith waits five minutes (`--lost-after`), and k3s calls the node lost 50 seconds after it last heard from it and then waits 300 more, by a toleration every pod is given. In the row after it both are told to wait about a minute: `--lost-after 60`, and a toleration of 10 seconds. That row is one run of each. |
| From switching a machine on to a ready node | From the moment the script turns to the first machine (it makes the machine's disk from the image, then starts it) until the system says that node is ready. For k3s that is until Alpine takes a login and then from starting k3s by hand, which a machine set up to run it would have started by itself; the line under the tables says how much of it is Alpine. |
| CPU in use | How busy a node was over the three minutes before the workloads (`/proc/stat`), as a share of one of its two CPUs. Nothing runs in them but the container that reads it and, at their end, the five applies of one replica above. |
| On the disk | Not measured alike, and it cannot be: for kith it is how much of the machine's disk file has ever been written (the image with both of its slots, and everything since, deleted or not); for k3s it is what `df` says is in use inside the machine, without the archive of its images the script copies in. |

The workloads are sent to each system's own API by one piece of code
([ci/compare_workloads.py](../../ci/compare_workloads.py)): the same containers, the same
counts, the same clock, and every image pulled before a clock that needs it starts. Ready
is what each system says is ready, with no probe.

| Workload row | How it is measured |
|---|---|
| Memory each replica adds | The memory in use on all three nodes with the 30 replicas, less what it was without them, over 30. |
| 20 workloads at once | To kith in one request, as its API takes them; to k3s in one request each, as `kubectl apply` sends them. |
| A change to a workload | Rolled out as each system does it when told nothing. Done for kith when every replica's output shows it, for k3s when the Deployment says all six are updated, ready and available. |
| A container that exits | It sleeps three seconds first; the time is from its exit until it has started again, the first time that happens. |
| A Job that does nothing | It runs `true`, and is done when the system says it has succeeded. |
| Requests | `ab` in a container on the first node, 20,000 of them, 20 at a time, to a Service in front of three nginx (each system puts them on the nodes it chooses): first a new connection for every request, which the two rows under it are also of, then connections that are kept. |

## What it does not say

Anything about many nodes, or about more containers than these. It is one shape of
machine, a few runs, on a machine that was doing other work at the time (so the times
under a second move, and so do the requests). Where the two differ in what they do, the
numbers are not of the same thing:

- A kith container on kith OS shares its node's network; a pod has a network of its own,
  with an address, set up before its containers start. Much of the difference in
  starting many replicas is that.
- kith replaces all replicas of a changed workload that are on different nodes at once;
  Kubernetes goes a quarter at a time unless told otherwise.
- A kith Service is on the mesh, TCP only, and kithd itself passes every byte on between
  the two connections; k3s's is rules in the kernel. What goes from one kith node to
  another over the mesh is encrypted (WireGuard); between k3s's nodes, as it comes, it is
  not. In these runs kith serves somewhat more on both rows; with a new connection for
  each request the two ranges overlap, with connections that are kept they do not. (An
  earlier sitting of the same script had k3s's kept connections at 27,000 to 68,000 a
  second, three runs: a connection to a web server on the node that asks is passed by the
  kernel's rules faster than kithd passes it.)
- Where kith's time goes, from one run with one web server and connections that are kept
  ([ci/compare.where.txt](../../ci/compare.where.txt)): asked directly on its own node it
  answered 218,000 requests a second, through its Service on that node 94,000 (kithd's
  copying), and from another node 20,900, where the mesh alone gave 21,800 and the nodes'
  network with no mesh 30,400. So between nodes the encryption is the bound, not kithd,
  and on one node kithd is.
- nginx runs with a configuration of its own on both (it listens on 8080 and writes only
  under `/tmp`): as its image comes it wants to start as root and write into its image,
  which a kith container may not.
- And the two are not the same thing: k3s is Kubernetes, with its whole API and all that
  is written for it. kith answers the part of that API `kubectl` and `helm` use for the
  core kinds ([kubectl and Helm, as they are](kubernetes.md#kubectl-and-helm-as-they-are))
  and refuses the rest by name; the kith side of these tables is measured through kith's
  own API.
