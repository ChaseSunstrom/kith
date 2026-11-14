# Security

## Reporting a vulnerability

Report it in private, through GitHub: the repository's **Security** tab, then
**Report a vulnerability** (GitHub's private vulnerability reporting is on for this
repository). Say what you did, what happened, and which commit or version it was. Please
do not open a public issue for something that lets one party cross one of the boundaries
below.

kith is maintained by one person, and nobody promises an answer by a certain day. A
report is read, answered in that private thread, and fixed in `main`; the fix's commit
says what it was.

Only the newest version is fixed. There are no security releases of older ones.

## Who is trusted with what

| Who | How kith knows them | What they can do |
| --- | --- | --- |
| The admin of a node | Whoever can open kithd's unix socket (mode 0600, kithd's user) | Everything in the cluster |
| A node | A certificate of the cluster's CA for `NAME.node.kith` | Everything in the cluster: nodes replicate the whole store, Secrets included, and run what they are told. **Every node is trusted as much as the admin.** |
| An Identity | A certificate for `NAME.user.kith` whose key is the one in its `Identity` | What its Roles say, by kind, verb and namespace |
| A workload | Nothing: it is a process on a node | What its container, machine or sandbox lets it reach (see "What is not defended") |
| Anyone who reaches a node's port | Nothing | Fetch the CA certificate, spend a join token, ask for a locked disk's key by its id |
| Whoever writes what kith fetches | Nothing by itself | What follows from it: a Source's repository is applied, a package is rendered, an image is run, an archive is restored |

## The boundaries, as they are in the code

- **A node's port (`--listen`, TLS).** Four routes take a caller with no certificate, and
  bodies of at most 4 KiB: the CA certificate, joining with a token, claiming an Identity
  with a token, and asking for a disk's key. (The web UI's pages are served to anyone
  too: they are the same files for everyone, and what they show they ask the API for.)
  A connection holds one of 64 slots until it has shown a certificate, and one that
  shows none for at most 15 seconds; one address (an IPv4 address, an IPv6 /64) holds
  at most 8 of them. The node's own loopback is not counted.
- **The API** is behind a layer that works out who calls (the socket, a node, an
  Identity) and refuses what their Roles do not allow. A token is shown once, kept only
  as a hash, good for an hour, and spent by its first use.
- **Node-to-node routes** (Raft, copies of blobs and volumes, a volume's key, running a
  command on another node) take a node's certificate only.
- **What a node fetches or sends for someone who is not the admin** (a Source's
  repository, a package pushed to a registry) goes only to addresses that are not this
  node's own or on its networks, each redirect and each place a registry sends an upload
  included, and to the address that was checked, not to the name looked up again. So the
  API is not a way to reach what only the node can reach.
- **A container** runs as a user that is not root (its template's, its image's, or
  nobody), with no capabilities (on kith OS, the one to take a port below 1024) and
  `no_new_privs`, on a read-only image, behind a seccomp filter that refuses some forty
  system calls: mounting, new namespaces, loading modules, bpf, perf, io_uring, keyrings,
  another process's memory, the clock. An image that names root as its user gets nobody.
- **An image whose template names keys** (`signedBy`) is run only if one of them signed
  its manifest's digest, which is found out before a layer is fetched; every layer is
  then fetched by the digest that manifest names. An image already on the node counts as
  signed only by keys it was checked against there.
- **Packages** are taken only with a signature over their name, version and hash, by a
  key the cluster was told to trust; there is no unsigned way in. A package's WebAssembly
  runs with limits on memory and time, and its templates with limits on size. A
  template in kith's own language (`.kith`) is evaluated inside kithd: it ends in
  500,000 steps, nested 3,000 deep and 1 MB of output or is refused, and it can read
  the package's own `templates/` and nothing else (no file of the node, no time, no
  network).
- **kith OS updates** are taken only with a signature, and never to an older version.
- **A Volume's archive** (a Backup, an Image, a replica's copy) is read through directory
  handles that are held open: nothing in the volume is reached by a path the workload
  could point elsewhere meanwhile. When one is unpacked, no entry writes outside the
  volume; a restored Backup has no setuid or setgid file (a replica's copy keeps them
  as its volume had them).
- **An encrypted disk or Volume** cannot be read by whoever takes it out of its machine:
  the key is with the other nodes.

## What is not defended

These are how kith is today. Each is a decision or a gap that is known; plan around it.

- **Whoever may apply a Workload, a NodeWorkload or a Job runs code on the cluster's
  nodes.** A container is kept small by default (see "A container" above), and its
  template is where each of those defaults is taken off: `runAsUser: 0`, `seccomp: {
  unconfined: true }`. On kith OS there is no user namespace, so `runAsUser: 0` there is
  the node's root with three capabilities. Containers share the node's network, and an
  `exec` unit is a process of kithd's user. The Roles decide who may apply these, and
  nothing more is in the way. Do not give them to someone you would not give a shell on
  the node.
- **A container is not a sandbox for a program you do not trust.** The filter is a list
  of what is refused: every other system call reaches the kernel, and so does a claimed
  device (a GPU's render node is a kernel driver's whole interface). There is no AppArmor
  or SELinux profile. Run such a program in a VM (`vms`).
- **An image is whoever's its registry says**, unless its template names keys
  (`signedBy`). Nothing makes a template name them: there is no rule for a cluster or a
  registry yet. A signature is checked against keys only: no certificate, no
  transparency log, so a signing key that leaks signs until it is taken out of every
  template.
- **A node that is taken is the cluster taken.** It has the whole store. Certificates
  last ten years and cannot be revoked: deleting a node does not make its certificate
  stop working on the node-to-node routes. Take its disk, or make a new cluster.
- **A Release is the right to apply whatever its packages render**, with the node's
  rights and not the writer's; the same for a Source. (T-0229, T-0227.)
- **Every process on a node, containers included, can pull every Image of the cluster**
  from the node's own registry on `127.0.0.1:5000`, whatever its namespace. An Image is
  a packed Volume. (T-0228.)
- **A host that no Namespace keeps goes to whoever exposes it first**, and, with
  `--acme`, has a certificate ordered for it. Keep the hosts you serve with a
  Namespace's `hosts`. Where none is kept, the "first" Service is the one whose oldest
  kept revision is oldest, so a holder can lose a host after a hundred edits or a
  delete. (T-0233.)
- **Someone on the network can still keep others from connecting** with many addresses
  at once, and eight connections from one address keep out whoever shares that address
  with them (a node behind the same NAT, or in the same IPv6 /64): the count is taken
  before a certificate is shown. A firewall in front of the port is the answer to that.
- **Backup buckets and S3 endpoints may be on the node's own network** on purpose, and a
  restore, a replica's copy and its sync take as many bytes as they are sent: a bucket
  someone else writes can fill a node's disk. (T-0230.)
- **A node started with no `--release-key` trusts the key of the first OSRelease it
  takes.** Give the key when installing. (T-0231.) What a taken admin credential can
  still do with OSRelease and UpdatePlan is restart nodes into releases their keys
  signed that are no older than the newest each node has run well (its floor,
  `os-release-floor`): not into an older one, and not onto other keys, since a
  handover must be signed by a key the node has and by one it is handed to. A node
  with no state partition keeps neither floor nor keys, and whoever holds a release
  key the nodes take still decides everything they run.
- **Answers from an ACME authority** are read without a cap on size, and the
  certificate that comes back is not checked to be for the host that was asked for.
  (T-0232.)
- **A Volume's directory on its node** is checked and then mounted: a path changed in
  between is not seen.
- **A stolen machine that is not locked**, started on the cluster's own network, is
  handed its disk's key. Lock it when it goes missing. The config partition and the
  system itself are not encrypted, and an update stick (`kith.update=`) is not signed:
  whoever is at the machine with a stick is its admin.
- **Confidential machines (SEV-SNP, TDX) and device passthrough** have never been run on
  real hardware.

## The review before 1.0

Before 1.0 the tree was read for security, area by area: the API and who may do what,
the cluster's port and its certificates, the runtime (containers, machines, sandboxes),
packages and WebAssembly, Sources, ingress and ACME, DNS, storage (volumes, backups,
replicas, shares, encryption), kith OS updates, and the web UI. It was three passes of
reading the code. **Nothing was run against it**: no fuzzing, no scanner, no test from
outside. A finding was kept only when the path from an untrusted input to its effect was
traced in the code; where that could not be done all the way, the table says so.

Severity:

- **High**: someone crosses a boundary of the table above with no right to (reads or
  writes what is not theirs, runs code, or stops the cluster for everyone).
- **Medium**: the same, but it takes a right that was granted for something less, or a
  setup that is not the usual one.
- **Low**: a limit or a check that is missing, with no path found to more than a nuisance.

| # | Severity | What | Outcome |
| --- | --- | --- | --- |
| 1 | High | One host with no certificate could hold all 64 handshake slots of a node's port, and nobody else could connect: no join, no `kith`, no new connection between nodes. | Fixed: one address holds 8. Many addresses still can (see above). |
| 2 | High (not traced all the way: it is a race) | A workload that swaps a directory or a file of its volume for a link while the node archives the volume had the node read what the link names, as kithd, into a Backup or an Image the workload's owner can read. | Fixed: the archive is read through held directory handles and follows no link; it stops at 128 directories deep. |
| 3 | High | An exposed host went to whichever Service asked first, in any namespace; with `--acme` anyone who may write a Service had certificates ordered for names of their choosing. | Fixed in part: a Namespace keeps hosts (`hosts`), and exposes no others once it names any. Open where none is kept: T-0233. |
| 4 | Medium | An Identity allowed to push a package could have the node send it to an address only the node reaches (its loopback, its networks), by naming such a registry or one that sends the upload on to there. | Fixed: when an Identity asks, every request of the push goes only to an address that was checked, as a Source's fetch does. |
| 5 | Medium | The node's own registry answers every local process with every namespace's Images. | Open: T-0228. |
| 6 | Medium | A Release (and a Source) is rendered and applied with the node's rights, not its writer's. | Open: T-0229, T-0227. Said above. |
| 7 | Low | A restore, a replica's copy and its sync have no cap on size; sparse entries in an archive may not be counted (suspected, not traced). | Open: T-0230. |
| 8 | Low | A node with no `--release-key` pins the first OSRelease's key; an OSRelease's image address is not vetted (what comes back is thrown away unless signed). | Open: T-0231. |
| 9 | Low | ACME answers have no size cap, redirects are followed, and the certificate's names are not compared with the host. | Open: T-0232. |

The T- numbers are the maintainer's task numbers, the same ones commits carry.

Looked at and found to hold: which routes are open and which are behind a layer, tokens,
how far a Role reaches, paths of volumes, the refusal of a node's own addresses for
Sources, the pinning of S3 endpoints, WebAssembly's limits, how a machine's command line
is built, package signatures, template limits, how git is called, the CA being pinned by
the join token, the DNS forwarder's limits, update signatures and the refusal of older
versions, the web UI's escaping and its content security policy, and the unpacking of
archives.

The hardening of containers (their user, capabilities, the seccomp filter, signed
images) was written after this review, in answer to its first "not defended" entry. It
had one reading of its own, by a reviewer who did not write it; nothing was run against
it either, beyond its tests.

### Not reviewed

- The mesh: WireGuard keys, who becomes a peer, what a peer may send.
- The installer and the first process (`kithd install`, `kithd` as init).
- Applying a Source against what a Package says it may write.
- How much memory a template's filters can use.
- Devices and seats.
- Dependencies: no advisory database was checked (`cargo audit` and `cargo deny` were
  not run).
- Anything that takes running it: fuzzing the YAML reader, the DNS server, the tar and
  image readers, the API's bodies. (T-0234.)
