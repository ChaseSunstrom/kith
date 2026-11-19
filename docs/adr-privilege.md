# kithd in two parts: what reads the network holds no root

Status: design, partly built (T-0334). Built: Step A, the node's own policy
(`crates/kithd/src/policy.rs`, read and applied in `main.rs:729-734`), and the seam of the
split in `crates/kithd/src/root_part.rs`, with listeners as its first family. Not built:
the socket, the second process, every other family, the serving part's confinement. A
security review read this record before the split was written; what it found is decided
at the end ("Review"). Step A ships by itself and is worth having even if the rest is
never built.

What is built, where the code is the word where this record differs:

- **Step A** (`policy.rs`): `read` takes `KITH_NODE_POLICY` or the flag, `cut` applies it,
  `set`/`get` hold it for the process; its status is in the node's status (`main.rs:1121`).
- **`root_part.rs`**: the `Request` enum (only `Bind` so far, `deny_unknown_fields`), its
  wire (`decode`: JSON, at most `MAX_REQUEST` = 256 KiB, unknown fields and variants
  refused; nothing reads a wire yet, the tests do), `check` (a request is refused for what
  it is, never for who asks; `Bind` refuses kithd's own ports 7443, 5000, 51820 and
  multicast addresses), and the `Root` trait with its in-process `Direct`.
- **`Bind`** is used by `share.rs`'s NFS listener (`share.rs:397`).
- There is no socket and no second process yet.

The carve of the rest, one task each: T-0808 pods and Services behind `Root`, with a
counter of crossings; T-0809 mesh (done: `MeshUp`, `Mesh`, `MeshSeen` and `MeshDown`, in process, each checked and counted), then images, units, volumes and node; T-0810 the socket
pair transport, `--split` off by default; T-0811 confinement of the serving part, tied
lifetimes of the two parts, and the VM test of privilege; T-0812 the before and after
runs, the budgets, and `--split` on by default.

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
- a container with `runAsUser: 0` that keeps the node's users (the node's root with
  three capabilities): one on the node's network, with a device, with `hostUsers`, or
  with its image or a volume on a file system that takes no id-mapped mount. A pod's
  container otherwise has a range of ids of its own on kith OS (T-0242), and its root
  is not the node's;
- a container with `seccomp: { unconfined: true }` or calls allowed back by name;
- a container that is no pod: it shares the node's network;
- a device given to a container by a DeviceClaim: `/dev/input/event*` reads what is
  typed at the console (a passphrase among it), `/dev/bus/usb` is a plugged-in disk;
- a Volume in `kith-system`: its path is any directory of the node, mounted writable
  into a container (`crates/kithd/src/volumes.rs`, `host_dir`): `/etc`, or the state
  itself, to whoever runs as the files' owner (found by Step A's review);
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
| Mesh | `MeshUp(interface, address)` → the public key; `Mesh(interface, peers, addresses)`; `MeshSeen(interface)` → when each peer shook hands (a read, counted as `Seen` and not `Mesh`: the loop asks it every 10 s, for the peers' paths); `MeshDown(interface)`. In process today (T-0809), with the interface, port, key file, this node's name and the cluster's range told the root part once by the serving part (a second telling that differs is refused; the root part is to have them from its own arguments and the CA: T-0810) | the interface is the one kith made; the node's address is the first of the /80 its name gives in the cluster's /48 (`node_address`), and no other, whatever an earlier up or down said; every allowed address is another node's whole /80 in it (not a service's, not this node's own, no IPv4 or IPv4-mapped address and no other length), every address added is a service's; a peer's key is not zero and is no other peer's; an endpoint is not loopback, unspecified, inside the mesh's /48 or at port 0. One bad peer refuses the whole `Mesh` request (fail-closed: nothing of it is set). Requests of the family are one at a time, from the check to the act, and a node is up from before its up is made until a failed up (when it was not up before) or a down that worked says it is not; the private key never leaves the root part. **Not checked**: a peer's keepalive, and an endpoint that is any other address (the serving part's to say: a peer at a wrong public address is a peer that does not answer); that two peers are not allowed the same /80. **Not checked, and it cannot be**: that a peer's key is the node whose address it is given. A node's mesh address comes from its name (`kith-mesh`, `node_address`) and who has which key is the store's word, so a hole in the store can stand at another node's mesh address (and be that node to an NFS share, which knows clients by address). Said in SECURITY.md |
| People: device | `PeopleUp` → the device `kwg0` up with the people key, its port, `100.89.0.1/16` and the people /64's `::1`, and no peers | nothing from the asker: the port and the addresses come from the node's own `--people` and configuration, the key is made here once in `pki/people.key` (mode 0600) and kept, and the reply carries only the public key |
| People: table | `PeopleTable` → the `inet kith-people` table, written before the device | nothing from the asker: the rules are kith-mesh's `people::build` from the node's own settings, with default drop and the masquerade rules required, so a kernel without them refuses and `--people` does not start |
| People: peers | `set_peers` on `kwg0` → the device's peers made equal to the list, after the table and rules | nothing from the asker: kithd's `levels.rs` lists them from the store (each one's own /32 and /128 only), and empties the device when a table or rule step fails |
| People: rules | rules 9010, 9011, 9012 `iif kwg0` and a conntrack delete by mark `0x6b79xxxx` | only the priorities and the mark kith-mesh names; 9011 is each peer's /32 of a level with the internet, and the rules are taken away with the device |
| People: remove | `PeopleGone` → the device and the table removed | only the names kithd makes (`kwg0`, `kith-people`); what an earlier start left is taken away the same way when `--people` is not given |
| Pods | `PodNode` (once), `Pod(number)`, `PodGone(number)`, `PodSockets(number, count)` → up to 16 sockets made inside the pod's namespace | the number in range and made by this root part; count at most 16; at most 32 unused sockets a pod and a time after which unused ones are closed |
| Services | `ServiceTable(entries)` | the root part builds the BPF program itself; every entry inside the cluster's Service range, sent to this node only |
| Images | `Unpack(image digest, manifest text, layers as file handles)`, `Drop(image digest, before)` | the root part checks the manifest is the image digest (sha256 of its bytes), that the files are exactly the manifest's layers in order, that no file is larger than the size the manifest gives it, and hashes each layer itself as it reads it (under the decompression, and the rest of the file after the tar's end), refusing one that is not the digest the manifest names and publishing nothing (done in process: `root_part::Request::Unpack`, the pulling code still fetching and choosing the digest); the same containment as `unpack_layer` today (nothing outside the image's root, what it refuses today refused). The store is the node's own, `<state>/runtime` from the Book and canonical, never a path the asker names; the image's path is derived from its digest. A Drop refuses an image a container's bundle names whatever `before` says, and a `before` that is no time. This is integrity, not authority: the asker picks the image; a manifest over the request's 256 KiB cannot be unpacked this way |
| Units | `Create(unit)`, `Start(id)`, `Kill(id)`, `Delete(id)`, `Tune(id, limits)`, `Plug`/`Unplug(id, device)`, `Exec(id, argv, tty)` → handles, `Usage` → sizes of all units | the image by digest (one it unpacked), mounts by Volume name and sub-path or as file contents, devices by inventory name, the pod by number, the cgroup and log files derived from the id. A VM's disks, kernel, initrd and firmware by Volume name and a path beneath it, or a name in a fixed list in the signed root; its program from that list; its arguments built here from typed fields. Each thing of the list in "What the split does not change" only where the node's own policy allows it, a path on the node for a VM among them |
| Volumes | `Volume(name, size, key?)`, `VolumeGone(name)`, `Open(volume, path, how, owner)` → a file, `Restore(volume, archive)`, `Share`, `Unshare`, `Remote(volume, node)` | the name's form; every path beneath the volume's root; an owner that is not 0 unless policy allows. Built in process (`root_part::Request`): `Volume(volume)` (what mounts, backs up, replicates from or downloads a Volume: the directory, made if it is not there), `Open(volume, owner?)` (what writes into one: an upload, a replica's copy), `Restore(volume)` (a backup restored into one) and `VolumeGone(namespace, name)`; each answers with the directory, derived by `volumes::host_dir_under` from the state directory the Book has and the Volume's `spec.path`, never a path the asker gives. The namespace and the name are in the store's own form (lowercase letters, digits, `-` and `.`, at most 63, a letter or digit at both ends) before any path is made from them; the path has no empty part, `.`, `..` or NUL, nothing is followed through a link, and a directory of the node's own (`kith-system`) is only where policy has `hostPaths`. An `Open` that names an owner other than 0 is refused where policy has `hostUsers` off (none named is the owner the Volume's directory has, as an unpack's files are); `VolumeGone` removes `<state>/volumes/<namespace>/<name>` and nothing else, and never a directory of the node's own. **Not built yet**: `Volume(name, size, key?)` (the encrypted file's make, `encrypted.rs`), `Share`, `Unshare` and `Remote`, which stay as they are |
| Node | `Update(artifact)`, `Reboot(how)`, `Lock(what the NodeKey says)` → what to write in its status, `Run(via, argv)` | `Update`: the keys kept after a handover (`os-release-keys`) and the floor no release goes below (`os-release-floor`) are files of the state directory today, read before the signed root's own keys (`update.rs`); both move to the root part's side, where the serving part cannot write them, and a handover is taken only signed by a key already held. `Lock`: the whole loop that keeps the lock record (`crypt.rs`, `keep`) runs in the root part, so the state's key and the record's secret never cross; what it is sent is the NodeKey's fields, and a wipe or a new duress key from them is taken only where policy allows (`wipe`). `Run` only where policy allows: built in process (`root_part::Request::Run`, asked by `POST /v1/run` before it starts the program): refused where `run` is off, with no program, no argument list, an argument with a NUL, more than 1024 arguments or more than 64 KiB of them; the serving part still starts the program, as it holds the connection it is joined to. **Not built yet**: `Update`, `Reboot` and `Lock`, which wait on the key and floor files moving (T-0811), pid 1's keeper and the keep loop of `crypt.rs` |

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
| A container started | in process | at most 3 requests: `Pod` (the first container of a pod only), `Create`, `Start`; `Unpack` once per image; and one `Volume` for each Volume it mounts (the controller asks the directory before it makes the unit, so the three are the unit's own and the Volumes are counted apart: `crossings` tests) |
| A change of the Service table | BPF attach in process | one `ServiceTable`; one `Bind` per new port under 1024 |
| The mesh every 10 s | netlink when something changed | compared in the serving part; one `Mesh` only when something changed |
| Storage accounting | reads in process | one `Usage` per pod per period (built: T-0844) |

Sockets made ahead cost kernel memory while idle: 16 unconnected TCP sockets a pod.
Measured in step 4; if it shows in the idle budget the count becomes 4 until a pod has
taken its first connection.

As built in one process (T-0808, `kithd/src/root_part.rs`): `Direct` does `Pod`, `Sockets`
(16 a request, asked for when 8 are left, and only for a pod's address family that
connections use), and `Create` and `Start`, each after `check` or `check_create` has
looked at what is asked and never at who asks: a mount from anywhere but the places a unit's
mounts are made from, a device no claim granted, a network namespace that is no pod's of this
node, and what the node's policy has none of are refused. A `Book` counts what crosses, and the
`crossings` tests assert this table against it. `Create` and `Start` take an image and a handle
that have no wire form yet, so they are methods of `Root` and not variants of `Request` until the
root part is a process (T-0810). The bound of 32 unused sockets a pod and their time is kept by
the serving part, since a root part in this process cannot tell which are unused. A pod let go
and made again under its id while sockets are being made for it gets none of them: the serving
part notes which making of the pod it asked about, and closes the batch if it is another.

**Mounts: an allow-list of places, not Volume names, and why.** A `Create` here carries host
paths, because the controller already resolved a Volume to its directory and a wire form of
"Volume name and sub-path" would change what a container is given (a non-goal of T-0808). So
`check_mount` allows only what the controller makes a mount from, after resolving the path
(a path that does not resolve is refused, and so is a relative one): `state/volumes/<ns>/<name>`,
`state/remote/<node>/<ns>/<name>`, `state/seats/<seat>`, the unit's own pod's `replicas/<pod>/files`
(its container's own), `scratch` and, in memory, its pod's `identity` (its container's own); the
pod's `resolv.conf` and `hosts`, read-only. Never the state directory itself, `pki` (the CA, node
and people keys), the memory directory or another pod's. A host path outside these only where
`hostPaths` is on, and never given to a user. `give` (the tree is made the container's user's)
is refused for anything a unit does not own: only volumes, remote shares, seats and its own pod's
files (a rolling update's second generation, pod `<pod>b`, mounts its replica's). A user past
the 65536 ids a container's range has is refused where anything is given and the runtime
shifts ids (a unit of its own network, not the host's users, with no device).
T-0810 replaces the path forms with names (`Volume(name, sub-path)`), which makes this list
the root part's own derivation.

**For T-0810, what the two-process step must check against the root part's own configuration
and sysfs, as one process cannot:**

- *A path swapped after the check.* `check_mount` resolves a path and the container is made
  later: a symlink put in its place between the two is followed. In one process, with the serving
  part trusted, that is the same hands; across the socket it is a hole. The root part must open
  each mount source itself with `openat2` (`RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`) beneath the
  directory it derived, and pass the descriptor on (`SCM_RIGHTS`, mounted through `/proc/self/fd`
  or `open_tree`), never the path again.
- *The pod's network.* The pod's address in the mesh /80, its exit tunnel and its DNS are what
  the asker says and are not verified; the root part must derive them from its own `--pod-range`,
  tunnels and gateway.
- *Devices.* They are checked against the asker's own claim set, which is a union across every
  workload, not the claims of the workload this unit is of; the root part must hold each claim
  against the device's name in its own sysfs inventory and the unit it was granted to.
- *Exec units and VMs skip `Create`'s check* today (they have their own start path): each needs
  a check of its own at the same boundary, not none.
- *`check_create` and the fields it once ignored* (T-0915). `host_users` is held to the
  `hostUsers` key (a serving part could send it with `no_node_root`, skip `rootContainers`, and
  have the node's users with no range of its own; not `rootContainers`, since every NodeWorkload
  has it). `nested` is held to `unconfined` (it lets the refused calls back). `drop` needs no
  check: it only narrows. `project` and `dmem` are left to the Devices item above: the root
  part holds no project id or device share to bound them against.

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
  rootContainers: true   # a container that is the node's root (root, and no range of ids of its own)
  unconfined: true       # seccomp unconfined, or refused calls allowed back by name, or a nested unit
  hostUsers: true        # a container with host_users (a NodeWorkload's): the node's own users; hardened stops NodeWorkloads
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
- where `execUnits`, `vmPaths` and `run` are all off (each a way to have the node start a
  process as its root with every capability), kithd cuts its bounding set at start,
  before its runtime or any thread but the first process's console and power-button
  readers (a thread keeps the set it was made with), to the fourteen of a root pod
  (`container.rs`, `ROOTS`: `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `SETGID`,
  `SETUID`, `SETPCAP`, `NET_BIND_SERVICE`, `NET_RAW`, `SYS_CHROOT`, `MKNOD`, `AUDIT_WRITE`,
  `SETFCAP`). The list is `KEPT` in `policy.rs`; a capability joins it only for a child
  that kithd execs (a container's process, the exec shim, a helper) and fails for want of
  it, with that child named there, as `ci/vm.sh --test policy` finds (a root pod, an
  unconfined unit and a nested unit, two nodes on the mesh). None does so far: what
  kithd itself needs (`SYS_ADMIN` for mounts, namespaces, cgroups and the loop and mapper
  devices; `NET_ADMIN` for links and nftables; `SYS_BOOT` to power off; `BPF` for the
  cgroup filters) it does in its own threads, which the bounding set does not limit.
  **What this does and does not do.** The bounding set limits only what an exec gives a
  child (a root child's permitted set becomes the bounding set); `PR_CAPBSET_DROP` does
  not touch kithd's own permitted and effective sets. So nothing kithd starts by an exec
  can hold a capability outside the list in the node's own user namespace, whatever its
  spec asks and whatever bug let it ask (a pod with `userNamespaces` has a full bounding
  set inside its own namespace, over that namespace's resources only; a container's own
  bounding set is its spec's on any node, cut or not, and the cut is what kithd's other
  children inherit: a Source's git, dnsmasq, the storage holder,
  libcontainer's init before its capset): not `SYS_MODULE`, `SYS_RAWIO`, `SYS_PTRACE`, `SYS_TIME`, nor `SYS_ADMIN`, `SYS_BOOT`,
  `BPF`, `SYS_NICE`, `IPC_LOCK`, `AUDIT_CONTROL`, `MAC_*`, `SYSLOG`, `PERFMON`... But
  kithd's own threads keep every capability (the VM test reads `CapEff` and says so), so
  **a hole inside kithd is not held back by this**: that is the split's job ("Order of
  work after Step A" below, T-0334). Neither is every effect covered: root without `SYS_PTRACE` can still
  trace root's own processes, and root can write `/proc/sys` with file permissions alone.
  Untried on a cut node: a VM (qemu would be exec'd with the fourteen; `vm-paths` off
  already leaves no VM of use) and a passthrough device (vfio may want `IPC_LOCK` or a
  memlock limit, which the list does not have); no VM test runs either.
  kithd execs itself only as the exec shim, for exec units (which the policy that cuts has
  off); a container is not started through it: libcontainer forks, clones and execs it, and
  sets the container's own sets from its spec (the fourteen of a root pod, three for a root
  that is not one, one for a user) over the cut's, so no container reads the cut. No serving
  process has the bounding set for its permitted set, and what needs `SYS_PTRACE`
  (`storage::unlinked` reads `/proc/PID/fd`; `setns` into a container that is not root's)
  runs in kithd's own threads, which keep it. (`Handle::in_dev` only plugs an input device
  into a container.)
- the node's status says what it kept (`status.policy.capabilities`; `all` where it was
  not cut, which includes a kithd that is not root). A kithd that cannot cut as root
  does not start;
- no system call filter on the single process. The filter is the serving part's.

Built so far: the keys and their refusals, the Node's status, the scheduler reading
it (a label of its own making for each key a node allows, required of what asks for it)
and the bounding set. Not yet: the installer's question.

An update is taken by a node that has cut: `KITH_NODE_POLICY=no-exec-units,no-vm-paths,no-run
sh ci/vm.sh --test rollout` runs the release test with the nodes so started, which is
the smallest honest way to show it (an update inside `--test policy` would build and sign
a second image, and double its length).

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

Built so far (`root_part.rs`): the `Request` enum and its wire (`decode`: at most 256 KiB,
unknown fields and variants refused), `check` (each request's refusal), the `Root` trait
with its in-process implementation `Direct`, and the first family, listeners (`Bind`,
used by `share.rs`'s NFS listener). No socket and no second process yet.

## Measurements

Taken in step 4 on the commit before Step A and again after the split, three runs each
on the same VMs: apply to ready, and requests a second through a Service
(`ci/compare.sh`'s rows by those names), and idle memory of both parts together (each
part's proportional share, summed). The before and after runs are taken and written here
by T-0812, not before. Two
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
