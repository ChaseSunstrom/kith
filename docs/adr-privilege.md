# kithd in two parts: what reads the network holds no root

Status: design, before any code (T-0334). Nothing here is built. A security review reads
this record before the first line of the split is written; what it finds is decided at
the end ("Review"). The first cut ("Step A") ships by itself and is worth having even if
the rest is never built.

## The problem

On kith OS kithd is process 1 and root. One process terminates TLS, parses HTTP, serves
kith's API and the Kubernetes API, answers DNS, serves ingress on 443 and 80, answers
DHCP and TFTP for netboot, and proxies every Service connection. The same process mounts
disks, holds the key of the encrypted state, makes network namespaces, loads BPF, starts
containers and writes the OS's other slot. A hole in any parser of bytes from the network
is the node: its disks, its kernel, every container on it.

The only hardening kithd has of itself today is its read-only-after-start data
(`seal_relro`, T-0486). It drops no capability, sets no `no_new_privs`, has no system
call filter.

What is wanted: the part that reads the network has no uid 0, no capability, a system
call filter and a mount namespace with its own files only; a small part keeps root and
does a short list of typed things, each of which it checks again.

## What the split does not change (read this first)

**The part that reads the network still holds the store.** Every Secret of every
namespace, and on a node that holds it the cluster's CA key. A hole there is the cluster:
it can write any object as anyone. Moving the store out of that part is a non-goal here
(every API request would cross a process boundary).

**And the store may ask a node to run things as root.** SECURITY.md already says:
whoever may apply a Workload runs code on the nodes, and "do not give them to someone
you would not give a shell on the node". Three things the store can ask for are root on
the node today:

- an `exec` unit: a plain process of kithd's user (root on kith OS) with all of `/dev`
  (`crates/kith-runtime/src/container.rs`, `exec`);
- a container with `runAsUser: 0` (the node's root with three capabilities; fourteen in
  a pod, T-0280), until containers have a user namespace of their own on kith OS (T-0242);
- a container with `seccomp: { unconfined: true }` or calls allowed back by name;
- a container that is no pod: it shares the node's network;
- a device given to a container by a DeviceClaim: `/dev/input/event*` reads what is
  typed at the console (a passphrase among it), `/dev/bus/usb` is a plugged-in disk;
- a VM: its `disks[].path`, `kernel`, `initrd` and `firmware` are paths on the node,
  given to QEMU, which runs as root (`crates/kithd/src/vm.rs`); a disk path of the
  node's own disk is the node's disk. Its program is a field too;
- `POST /v1/run`: a program with the caller's arguments, as kithd's user
  (`crates/kithd/src/api/run.rs`);
- a NodeKey that says `wiped`: the node erases its lock record and powers off
  (`crates/kithd/src/crypt.rs`, `keep`). Not root, and not undone.

So a hole in the unprivileged part, which is the store, can still ask the root part for
an exec unit. With nothing else changed the split turns "a hole is root" into "a hole is
one typed, logged request away from root". That is better (the request is written to a
log the hole cannot erase, and nothing of the node's disks or keys is in its memory or
its files), and it is not the claim in this task's fifth criterion. **At the defaults
the split is defence in depth and no more.** The claim (a hole there is not the node)
holds only on a node whose **own policy** refuses every item of that list. See "The
node's own policy". This is the main finding of the study, and the review agreed.

**Keys that stay in the part that reads the network**: the node's TLS key, the
cluster's CA key on a node that holds it, the ACME account key. A hole there issues any
Identity of the cluster. Only the mesh's private key, the state's key and the lock
record move behind the root part. A request to sign in the root part would move the CA
key's bytes and not its use (the root part cannot tell which certificate should be
signed: join tokens are the store's), so it is not planned.

## What needs root today, by who asks

From two read-only passes over the code (research T-0334-study and T-0334-study-2; the
second sampled several files by search, so the list is checked again file by file as
each family moves).

| Who asks | What | How often |
|---|---|---|
| boot (`init.rs`) | mounts, the config partition, growing the state partition, the encrypted state (TPM unseal, dm-crypt), hostname, DHCP client, the OS's other slot, slot marked good | once |
| shutdown, power button | unmount, close the encrypted state, reboot | once |
| lock record loop (`crypt.rs`) | TPM seal, write the disk's lock record, the duress erase | per passphrase change |
| update loop (`update.rs`, `os.rs`) | write the root and verity partitions, mount the ESP, write its file | per update |
| mesh loop (`mesh.rs`) | WireGuard link, addresses, peers over netlink; reads the mesh's private key | on change (looked at every 10 s) |
| pods (`pods.rs`, `kith-mesh/pod.rs`) | the node's pod rules once; per pod: a network namespace, a link pair, routes | per pod |
| Service proxy (`services.rs`) | a socket made inside a pod's namespace (a thread and `setns`) | **per connection into a pod**, and per probe |
| Service proxy | the BPF connect filter on kith's cgroup | per change of the Service table |
| Service proxy, ingress, DNS, netboot, shares | binding 53, 67, 69, 80, 443, 2049, 4011 and Service ports under 1024 | once each, or per table change |
| controller (`container.rs`) | libcontainer: namespaces, mounts, overlay, cgroup, device filter (BPF), chown of files and volumes, device nodes into a running container, kill, delete | per container |
| controller | exec units and VMs (QEMU as kithd's user, `/dev/kvm`, VFIO) | per unit |
| controller, images (`image.rs`) | unpacking layers with their owners | per pull |
| volumes (`volumes.rs`, `encrypted.rs`, `share.rs`) | loop devices, dm-crypt, ext4 mounts, the NFS server's files, mounts of remote Volumes | per Volume |
| API handlers | Volume files with a caller's owner (`volume_files.rs`), restore of a backup with owners (`backups.rs`), exec into a container, `/v1/run` | per request |
| storage accounting (`controller/storage.rs`) | reading containers' roots and volumes for their sizes | periodic |

What needs nothing but its own directory: the store and its log (`kith-store`), Raft,
the API and its TLS port (7443), the unix socket, the registry door (127.0.0.1:5000),
ACME, the scheduler.

## Layouts considered

1. **Two processes over a socket pair (chosen).** Process 1 keeps root and is the *root
   part*. After boot it starts the *serving part*: the same binary run again with a
   hidden argument, as a user of its own, which is all of kithd as it is today except
   that every operation in the table above is a typed request to the root part.
2. **One process, privileges dropped per thread.** Linux capabilities and uids are per
   thread, so worker threads could run without. Not a boundary: every thread shares one
   address space, and a hole in any thread writes the memory of the thread that has
   root. Refused.
3. **Only the container runtime as the root part**, the serving part keeping
   `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE`. A shorter list of requests. But
   `CAP_NET_ADMIN` in the node's network namespace is the node's network: its firewall
   rules, its routes, every pod's traffic. And the second criterion says no capability
   in any set. Refused.
4. **Do less: one process, the capabilities it never uses dropped, a system call
   filter.** No new boundary to keep honest, no extra memory. A hole still holds
   `CAP_SYS_ADMIN` (mounts and `setns` need it), so it is still the node. And the review
   found it cannot be done as said: both are inherited by every unit kithd starts (see
   "Step A"). What is left of doing less is the node's own policy, which is Step A.
5. **The other way round: an unprivileged front that only terminates TLS and parses
   HTTP**, passing each request to a root kithd that keeps the store. The front would
   hold the node's TLS key and say who each caller is, so the boundary is the whole API:
   a hole in the front is any Identity. And DNS, ingress and the Service proxy would
   each need the same treatment. Refused.
6. **A process per function** (API server, scheduler, proxy). A non-goal of this task:
   it multiplies memory and buys no privilege boundary that layout 1 lacks.

## The two parts

**The root part** is process 1 on kith OS. It does boot as today, then listens on one
`SOCK_SEQPACKET` socket pair for requests and sends events (a unit ended, the power
button) on a second. It runs no async runtime, reads nothing from the network except
the DHCP client's own socket, and parses nothing from the serving part but the typed
requests. It writes one line for each request it takes to the console, which the serving
part cannot reach. It hosts libcontainer (which forks inside it) and is the parent and
reaper of every container, as kithd is today.

**The serving part** is started with `fork` and `exec` of `/proc/self/exe`, never `fork`
alone: its memory starts empty of the root part's (the state's key, the mesh's private
key). Before `exec` the root part gives it:

- a user and group of its own that no container is given (a container asking for that
  uid is refused), no supplementary groups;
- no capability in any set, the bounding set emptied, `no_new_privs`;
- a PID namespace and a `/proc` of its own (it sees no other process, so no container's
  `/proc/PID/root`);
- a mount namespace in which: the signed root is read-only as it is for everyone; `/dev`
  is a small tmpfs (`null`, `zero`, `urandom`); the state directory shows only the
  store, Raft, `pki/` without the mesh's private key, the view, its spool, and the
  units' logs read-only; the config partition, the ESP, volumes, containers' roots and
  images are not there;
- a system call filter that is an **allow-list**: the serving part is one fixed program
  (tokio, rustls, the store), so the calls it makes can be listed. The list is made by
  running the VM tests with the filter set to log and not refuse, then held to refuse;
  `socket` is held to `AF_UNIX`, `AF_INET` and `AF_INET6`. An off flag (`--no-filter`),
  said in SECURITY.md, for a kernel or a library upgrade the list breaks on: the rest of
  the confinement stays with it off;
- the two sockets, and nothing else open: every handle above 2 but those two is closed
  before `exec` (`close_range`), whatever the code that opened it meant, and a test
  lists the serving part's open handles at start.

Nothing in the serving part can `setns`, mount or speak netlink: `kith-mesh`'s `within`
(the thread that enters a pod's namespace) and every netlink call move into the root
part whole, behind `Pod`, `PodSockets` and `Mesh`.

The files it owns are given to its user once at start (a node that ran the single
process has them as root's).

A node kithd runs on as a user (agent mode) has no root and no split, as today. A kithd
run as root on another OS takes the split by the same flag.

## The requests

A request is one datagram: an enum in JSON (`serde`, unknown fields refused), at most
256 KiB; bytes larger than that (a Secret's files, a layer) travel as a file handle
beside it (`SCM_RIGHTS`). File handles come back the same way.

The rule for every request: **it names things, never paths or programs.** A Volume by
its name, an image by its digest, a device by its name in the root part's own inventory,
a pod by its number, a unit by an id the root part made. The root part derives every
path itself, under directories it owns, resolving beneath them only. What the root part
*cannot* check is whether the store was right to ask: who may claim a device or mount a
Volume is decided in the store, which is the serving part. A request is refused for
what it is, never for who asked.

| Family | Requests | Checked again by the root part |
|---|---|---|
| Listeners | `Bind(address, port, tcp or udp)` → a socket | not a port the root part uses itself; counted |
| Mesh | `Mesh(peers, addresses)` | every allowed address inside the cluster's mesh and pod ranges, which the root part has from the node's own configuration, and none of them this node's own; the private key never leaves it. **Not checked, and it cannot be**: that a peer's key is the node whose address it is given. A node's mesh address comes from its name (`kith-mesh`, `node_address`) and who has which key is the store's word, so a hole in the store can stand at another node's mesh address (and be that node to an NFS share, which knows clients by address). Said in SECURITY.md |
| Pods | `PodNode` (once), `Pod(number)`, `PodGone(number)`, `PodSockets(number, count)` → up to 16 sockets made inside the pod's namespace | the number in range and made by this root part; count at most 16; at most 32 unused sockets a pod and a time after which unused ones are closed |
| Services | `ServiceTable(entries)` | the root part builds the BPF program itself; every entry inside the cluster's Service range, sent to this node only |
| Images | `Unpack(manifest's layer digests, layers as file handles)`, `Drop(digest)` | the root part hashes each layer itself as it reads it and refuses one that is not the digest named (today the pulling code does, which becomes the serving part); the same containment as `unpack_layer` today (nothing outside the image's root, what it refuses today refused); the path is the root part's own for that digest. This is integrity, not authority: the asker picks the image |
| Units | `Create(unit)`, `Start(id)`, `Kill(id)`, `Delete(id)`, `Tune(id, limits)`, `Plug`/`Unplug(id, device)`, `Exec(id, argv, tty)` → handles, `Usage` → sizes of all units | the image by digest (one it unpacked), mounts by Volume name and sub-path or as file contents, devices by inventory name, the pod by number, the cgroup and log files derived from the id. A VM's disks, kernel, initrd and firmware by Volume name and a path beneath it, or a name in a fixed list in the signed root; its program from that list; its arguments built here from typed fields. Each thing of the list in "What the split does not change" only where the node's own policy allows it, a path on the node for a VM among them |
| Volumes | `Volume(name, size, key?)`, `VolumeGone(name)`, `Open(volume, path, how, owner)` → a file, `Restore(volume, archive)`, `Share`, `Unshare`, `Remote(volume, node)` | the name's form; every path beneath the volume's root; an owner that is not 0 unless policy allows |
| Node | `Update(artifact)`, `Reboot(how)`, `Lock(what the NodeKey says)` → what to write in its status, `Run(via, argv)` | `Update`: the keys kept after a handover (`os-release-keys`) and the floor no release goes below (`os-release-floor`) are files of the state directory today, read before the signed root's own keys (`update.rs`); both move to the root part's side, where the serving part cannot write them, and a handover is taken only signed by a key already held. `Lock`: the whole loop that keeps the lock record (`crypt.rs`, `keep`) runs in the root part, so the state's key and the record's secret never cross; what it is sent is the NodeKey's fields, and a wipe or a new duress key from them is taken only where policy allows (`wipe`). `Run` only where policy allows |

About thirty requests. That is more than the plan guessed (ten to fifteen), and the
study says why: API handlers reach into volumes and containers in more places than the
controller does. The list is kept honest by a test that sends every request with
arguments outside its check and expects a refusal (`root_part`), and by a rule for
review: a new request that takes a path or a program is refused in review.

Parsing that stays in the root part, and so stays reachable from outside as root: layers
of images (tar, with owners), backups being restored (tar), the DHCP client's answers,
the kernel's NFS upcalls. Each is reachable today too. Unpacking in a third, confined
process is not in this task (said as open below).

## Hot paths: what crosses, how often

| Path | Today | Split |
|---|---|---|
| An API request to the store (apply to ready) | no privileged step | none |
| A Service connection to another node, or to a replica on the node's loopback | none | none |
| A Service connection into a pod on this node | a thread started and ended, `setns`, per connection | none per connection: the serving part holds up to 16 sockets per pod made ahead by the root part and asks for 16 more when 8 are left; at most N/8 + 1 requests for N connections, and no thread per connection |
| The bytes of any connection | none | none |
| A probe into a pod | as a connection | as a connection (from the same sockets); an `exec` probe is one `Exec` per run |
| A container started | in process | at most 3 requests: `Pod` (the first container of a pod only), `Create`, `Start`; `Unpack` once per image |
| A change of the Service table | BPF attach in process | one `ServiceTable`; one `Bind` per new port under 1024 |
| The mesh every 10 s | netlink when something changed | compared in the serving part; one `Mesh` only when something changed |
| Storage accounting | reads in process | one `Usage` per period for all units |

Sockets made ahead cost kernel memory while idle: 16 unconnected TCP sockets a pod.
Measured in step 4; if it shows in the idle budget the count becomes 4 until a pod has
taken its first connection.

**The sixth criterion is corrected by this record**: it said "none for a Service
connection". With sockets made ahead it is "at most N/8 + 1 for N connections into a
pod, and none for any other". The rival that reaches zero, a rule in each pod's
namespace that sends what arrives for the pod's address from the node on to its
loopback, was not taken: the app would see the node's address as its caller where it
sees `127.0.0.1` today, IPv6 has no such rule for `::1`, and each pod would hold a
rewrite rule that a neighbour forging the node's address could aim at.

## The node's own policy

Words given to kithd where it is started, `--node-policy`: on kith OS among kithd's
arguments on the node's config partition, written at install and by whoever has the
node's disk, measured with the rest of that partition where the state's key is sealed to
the TPM, and reached by no API; elsewhere on kithd's command line or in
`KITH_NODE_POLICY`. Read by the root part only, never from the store. (As built, not a
file of YAML as first drawn: the config partition already holds kithd's arguments, and a
second file there would be a second thing to parse before anything is trusted.) The keys,
as a Node's status says them, each on where nothing is said:

```yaml
policy:
  execUnits: true        # a process of the node's root, with all of /dev
  rootContainers: true   # a container that is the node's root (no other user, no user namespace of its own)
  unconfined: true       # seccomp unconfined, or refused calls allowed back by name
  nodeNetwork: true      # containers that are no pod: the node's own network
  devices: [all]         # which classes a DeviceClaim may hand a container: gpu, input, usb, …
  vms: true
  vmPaths: true          # a VM's disk, kernel or firmware as a path on the node; another program than qemu
  passthrough: true      # PCI devices handed to a VM
  hostPaths: true        # a Volume of kith-system: a directory anywhere on the node, as its path says
  run: true              # POST /v1/run
  wipe: true             # a NodeKey of the store may erase this node, or change its duress keys
```

The words are those keys in small letters with dashes, commas between, read left to
right: `no-exec-units` turns one off, `exec-units` turns it on again,
`devices=gpu+input` names the classes handed out. A word that is no word of the policy
ends the start; on kith OS, where an ended start is a machine starting again for ever,
the node runs hardened instead and says so.

Where `devices` names classes, a Device is what the node's own look at its hardware
finds: the store says what class a Device is and what its path is, so a node that went
by the store's word would hand out its disk to whoever wrote "gpu" beside it. A Device
written by hand is then not handed out on that node.

`--node-policy hardened` is all of them off (`devices=gpu`). The list has one key for every
item of "What the split does not change"; a new way for the store to be root on a node
gets a key here in the same change, and review refuses it otherwise.

Every key defaults to on: a node does what it does today, and an upgrade changes
nothing a cluster runs. With them on, a hole in the serving part is one request from
root, and SECURITY.md says so in those words: the split is then defence in depth and no
more. With `--node-policy hardened` the fifth criterion's claim holds: a hole in the serving
part is the store and the cluster (every Secret, any Identity, another node's place on
the mesh), and not this node's disks, kernel, lock record or the state's key. Whether a
new install should be hardened by default is the owner's to say (it refuses exec units
and VMs from paths that work today); this record does not change a default.

The policy is also the answer to "what does the root part do for a hostile asker": what
the node's owner allowed the store to ask of this node, and nothing else.

## When a part dies

Either part ending ends kithd, as kithd ending does today. The serving part exits when
its socket closes (and is sent a signal when its parent dies). The root part, on the
serving part's exit or a closed socket, closes the encrypted state, unmounts and restarts
the machine, as process 1 does today on a failure. One thing differs: the wait before
that restart is counted apart. Today's count is a file on the ESP beside the kernel
images (`kith.failed`, ten seconds doubled to ten minutes), and it is about a system
that cannot start. A hole in the serving part can end it at will, so its exits are
counted in a file of the root part's own with the same growing wait, never on the ESP,
and never anything the boot loader's choice of slot reads (step 3 checks that nothing
but the wait reads `kith.failed`). On another OS the root part exits and whatever starts
kithd starts it again.

Restarting the serving part alone, with containers going on under the root part, would
be a real gain (a parser's crash would no longer restart the node). It needs the serving
part to adopt running units from the root part's list, which kithd has no code for
today. Not in this task; captured.

Nothing the root part made outlives it unheld: namespaces are held by its handles,
mounts are in its mount namespace, and it is process 1. The VM test ends each part in
turn and looks at mounts, device nodes and open handles after the restart.

## Step A, which ships by itself

The first draft of this record had Step A as a capability cut and a system call filter
on the single process. The review showed it cannot ship that way: a filter on process 1
is inherited by everything it starts, libcontainer's own setup (namespaces, `pivot_root`,
mounts, `setns`) and every unit's own `unconfined` or allowed calls with it; and a
bounding set cut on process 1 is cut for every exec unit and VM, which are root with
every capability today. With exec units as they are, there is nothing the single process
can drop that nothing it starts may be given.

So Step A is **the node's own policy, held by the single process**, as its own commits,
before any of the split:

- the policy is read at start from kithd's arguments (all on when there is none), and
  each key that is off refuses its thing where the unit is made (`controller.rs`,
  `api/run.rs`, `crypt.rs`, by `policy.rs`), in words that name the key and the word
  that turns it on; a Node's status says its policy, so the scheduler does not place on a node
  what it would refuse, and `kith get nodes` shows it;
- where `execUnits`, `vmPaths` and `run` are all off, kithd cuts its bounding set at
  start to what it and its containers use: the fourteen of a root pod
  (`container.rs`, `ROOTS`, with `SETPCAP`, `SETFCAP`, `FSETID`, `SYS_CHROOT` and
  `AUDIT_WRITE` among them) and its own (`SYS_ADMIN`, `NET_ADMIN`, `NET_RAW`,
  `SYS_BOOT`, `SYS_RESOURCE`, `BPF`); found exactly by the VM tests with a root pod, an
  unconfined unit and a nested unit, and never `SYS_MODULE`, `SYS_RAWIO`, `SYS_PTRACE`
  or `SYS_TIME`;
- no system call filter on the single process. The filter is the serving part's.

Built so far: the keys and their refusals, and the Node's status. Not yet: the scheduler
reading a Node's policy, the bounding set, the installer's question. Until they are, a
replica placed on a node that refuses it stays there and is not run, and a hardened node
holds every capability.

What Step A buys by itself: a certificate of the cluster that is stolen, or a hole in
the store, is no longer root on a node whose owner said so. A hole in a parser is still
root there until the split. SECURITY.md says both.

## Order of work after Step A

The serving part cannot give up root until the last family has moved, so the split is
one flag (`--split`) that is off until all of it passes its VM tests. To move a family
without a long-lived branch, every operation in the table goes behind one trait with two
implementations, both used: in this process (today's code, called directly) and over the
socket. Families move one commit each, in this order: listeners; mesh; pods and the
sockets made ahead (which also ends the thread per connection for the single process);
Services; images; units; volumes; node. Then the serving part's confinement, the VM
test of criterion 2, and the measurements.

## Measurements

Taken in step 4 on the commit before Step A and again after the split, three runs each
on the same VMs: apply to ready, and requests a second through a Service
(`ci/compare.sh`'s rows by those names), and idle memory of both parts together (each
part's proportional share, summed). The before runs are written here when taken. Two
processes of one binary share its text; the root part's own memory is what is added.
The 9.00 MB idle budget is not moved by this task: if the sum passes what the single
process holds today, the owner is asked.

## Open

- **Defaults of the node's policy for a new install**: the owner's to say.
- **Unpacking layers and restoring backups as root** stays in the root part. A third
  process with only the capabilities to set owners is not small enough to be a
  boundary; id-mapped containers (T-0242) may make owners unnecessary. Left.
- **The store out of the part that reads the network**: a non-goal; nothing in this
  record found it free on a hot path.
- **Volume data through the API** (`Open`) crosses once per file. If uploads of many
  small files are slow, a directory handle with `openat2` beneath it in the serving
  part is the next step; not built until measured.

## Review

One security review of the first draft, checked against the code (research
T-0334-adr-review). Verdict: sound with conditions. Each finding and what was decided;
the seven conditions bind whoever builds this.

| Finding | Decided |
|---|---|
| High: Step A's filter and capability cut on process 1 are inherited by libcontainer's setup and every unit, and the capability list missed five a root pod needs | Step A rewritten: the node's own policy held by the single process; the cut only where the policy turns off what needs the rest, with the five added and three kinds of unit in its VM test; no filter on the single process (condition 1) |
| High: a wipe or a new duress key comes from the NodeKey in the store, so "`Forget` checked against the record the root part reads" was circular | The lock loop runs whole in the root part (`Lock`); a wipe or duress change from the store is taken only where the policy's `wipe` is on, and SECURITY.md says a hole in the store can wipe a node where it is (condition 2) |
| High: a VM's disk, kernel, initrd, firmware and program are paths on the node, so "names, never paths" was false | A VM's files by Volume name or a fixed list; a path on the node only where `vmPaths` is on (condition 3). The paths as they are today are their own task, captured |
| High: with every key on the split protects no node, and the policy missed devices, the node's network and VM paths | One key for every root-when-asked thing, listed in "What the split does not change"; the defaults said for what they are; `allow: hardened`; the default for a new install left to the owner (condition 4) |
| Medium: the kept release keys and the release floor are files the serving part could write, read before the signed root's keys | Both move to the root part's side (condition 5). That kept keys win over the image's today is its own task, captured |
| Medium: `Mesh` with a hostile asker can put a peer at another node's address | The root part checks ranges and its own address; whose key is whose it cannot check, and the record and SECURITY.md say what that leaves (condition 6) |
| Medium: the node's TLS key, the CA key and the ACME account key stay in the serving part | Said in "What the split does not change"; signing in the root part refused, with why |
| Medium: `Reseal` had no shape | Replaced by `Lock`, the whole loop in the root part (condition 6) |
| Medium: `Unpack` trusted digests the pulling part checked | The root part hashes each layer itself and keeps today's containment (condition 6) |
| Low: a refuse-list lets new calls through | The serving part's filter is an allow-list, made from logged runs (condition 7) |
| Low: a hole can end the serving part at will and raise the ESP's failed count | Its exits are counted apart, never on the ESP (condition 7) |
| Low: `within` and its `setns` were not said to move | Said; unused sockets capped and timed out |
| Low: handles leaking into the serving part | Everything above 2 closed before `exec`, and a test lists what is open |

Not checked by the review, to be read as each family moves: `services.rs` and `pods.rs`
beyond the calls named here, `backups.rs` and `volumes.rs` in detail, `netboot.rs`,
`ingress.rs`, `acme.rs`, who may call the unix socket and the registry door on
127.0.0.1, what of `/sys` and `/proc` the serving part's namespace should show, and the
NFS export code.
