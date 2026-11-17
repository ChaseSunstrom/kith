# kith OS: kithd as the machine's first process

On a kith OS machine there is the kernel and kithd, nothing else: no systemd, no
shell.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/assets/diagrams/os-dark.svg">
  <img src="../../docs/assets/diagrams/os-light.svg" alt="kith OS from power-on: the firmware starts systemd-boot, which starts the newest kernel image that has tries left; the image names the hash of its 6 MB read-only root, of which a changed block is refused; kithd is the first process, reads the config partition and mounts the state partition, the two that no update replaces. An update, one node at a time: an OSRelease signed by the release's key (an update from a stick is not signed) is written into the other slot, the node restarts into it, and it is marked good or the node is back on the old slot after three tries" width="100%">
</picture>

When kithd finds it is process 1 it does what an init does:

- mounts `/proc`, `/sys`, `/dev`, `/run`, `/tmp` and the cgroup tree;
- names the machine: `kith.hostname=NAME` on the kernel command line, or else
  `kith-` and the last six digits of its first network card's address;
- brings the loopback and every network card up, and asks each card's network
  for an address (DHCP, renewed for as long as it runs). A machine on a network
  that gives none says `kith.ip=10.0.0.5/24,10.0.0.1` (address, then the
  gateway) and `kith.dns=9.9.9.9`;
- reads its own arguments after ` -- ` on the kernel command line:
  `console=ttyS0 kith.hostname=alpha -- --listen 0.0.0.0:7443 --advertise 10.0.0.5:7443`;
- collects the processes nobody waits for;
- stops what it runs and then restarts the machine on Ctrl-Alt-Del, or powers
  it off on SIGTERM or the power button (what a VPS panel's shutdown presses;
  a keyboard's power key counts too, and so does any input device there at
  start that sends it). A press while kithd is still starting is acted on
  once it serves. If kithd fails or panics it says why and restarts the
  machine ten seconds later: process 1 never exits.

- mounts the partition labelled `state` at `/var/lib/kith`, and says so when
  there is none (the state is then in memory);
- says what it says on every console the kernel has (a screen and a serial line).

`sh ci/vm.sh --test init` boots exactly that in QEMU (the host's kernel and an
initramfs holding one file, a static kithd) and prints how long it took to
serve: a second or two here.

### The image

```sh
sh os/build.sh --check     # target/os/kith-os.raw (281 MB) and kith-os.qcow2 (19 MB)
sh ci/vm.sh --test image   # boot a copy of it under UEFI in QEMU and check it
```

`os/build.sh` makes the whole operating system of a node, without root and
without touching a disk:

- a kernel (6.18, 13 MB) built from kernel.org's source at a pinned version and
  checksum with `os/kernel.config`: no modules and no initramfs. What a machine
  needs to find its disk, check its root and reach the network is in that one
  file: NVMe, SATA, USB and SD storage, the common wired network cards, virtio,
  WireGuard, dm-verity, dm-crypt, what containers need, KVM. The first build
  compiles it (ten minutes or so); it is kept in `~/.cache/kith-os` after that;
- a root file system of about 6 MB (squashfs, read-only): kithd as `/sbin/init`,
  `kith`, a CA bundle (curl's, pinned), empty directories. No shell, no libc,
  no package manager;
- a dm-verity hash tree for the root. The root's hash is on the kernel command
  line, which is inside the one EFI file the firmware starts (a unified kernel
  image: systemd's stub, the kernel, the command line), so a root that was
  changed is refused block by block: the test changes one and the kernel
  stops before kithd runs;
- a GPT disk: `esp` (systemd-boot and the kernel image, `kith-1-a.efi`), `root-a` and
  `verity-a`, `root-b` and `verity-b` (empty: an update goes there), and `state`
  (ext4), the only partition a running node writes.

Packed twice from the same kernel and the same kithd, the image is the same
bytes (`--twice` checks). That is not yet the whole of a reproducible build:
the kernel is compiled once and kept, kithd is compiled once per run, systemd's
EFI stub and boot loader are copied from the machine that builds, and where bc
or mtools is missing they come from nix, unpinned. So another machine, or
another checkout path, may give other bytes.

In QEMU the image serves other nodes about two seconds after the firmware
starts. The test passes kithd its arguments through the VM's SMBIOS, which the
stub adds to the command line; where a real machine's come from is the
installer's to say, which is not written yet.

### Updating a node: two slots

```sh
KITH_OS_VERSION=1.0.1 sh os/build.sh   # also writes target/os/kith-os.update (32 MB)
sh ci/vm.sh --test update              # a node updates itself in QEMU, and goes back when it must
```

A node runs from one slot (`root-a` or `root-b`) and an update is written into
the other, so the system that runs is never the one being changed:

1. kithd checks each piece of the update against the SHA-256 in its header as
   it writes it: the root, its verity tree, and last, on the ESP, the kernel
   image for that slot as `kith-N-b+3.efi`. N is one more than any other
   there, so the boot loader starts it first, and `+3` is three tries.
2. The node restarts. The boot loader counts a try down in the file's name
   each time it starts the slot (`+2-1`, `+1-2`, `+0-3`).
3. A slot that comes up, and whose kithd is still running ten seconds later,
   is marked good: the counter is dropped and the console says
   `slot b is good`. On a node whose state is encrypted the ten seconds start
   when the state is open, not while it waits for its key.
4. A slot that does not (a root its verity tree refuses, a kithd that cannot
   start) is restarted until its tries are gone. The boot loader then starts
   the slot that worked, and kithd says so on each start:
   `slot a did not come up in 3 tries: this is slot b, which ran before it`.
   Each start that fails in a row waits longer before its restart: 10 seconds,
   then 20, 40, and so on, up to ten minutes. The count is kept on the ESP
   (`kith.failed`), and a start that comes up clears it.

A damaged update, one cut short, or one too big for the slot is refused, and
then no kernel image offers the half-written slot: the node starts as before.
The state partition is not part of a slot, so the node is the same node after
an update, and after going back.

An update can reach one node from a disk: put `kith-os.update` on a stick
(`dd if=kith-os.update of=/dev/sdX`) and start the node once with
`kith.update=sdX` on its kernel command line (its name on the node, which may
differ). It writes the other slot and restarts into it, whether the release
is newer or older than what runs. An update that is what the node runs
already is skipped, and one given to a node whose own slot is not yet marked
good is refused: the slot it would replace is the only one known to start.
Nothing checks who made a file given that way: whoever can plug a disk in and
change the kernel command line has the machine anyway.

### What an update keeps: the format of the store

```sh
cargo test -p kith-store format        # this build reads a state written in format 1, and in 2
```

A node's copy of the cluster's resources is two files in its state,
`raft/log.redb` and `raft/snapshot.json`. Both say which format they are in:
1 or 2, and a file from before the number was written is 1.

Format 2 keeps when each resource was first made, apart from its history (which is
trimmed): it is what says which of two Services naming one host was there first. A
kithd that reads format 2 does not write it by being started: a format 1 state stays
format 1, readable by the kithd before, until the cluster's leader marks the store
with one entry in the log. It does that once every other node that keeps the store
(the control nodes, and a worker from before workers ran from a view) has answered it
in the last half minute saying its kithd reads format 2, which each says with every
answer to the leader's own calls; until then the leader's log names who it waits for
(`the store stays in format 1 until every member's kithd reads format 2: NAME did not
say so`), and every node orders hosts as before. A node that is down, or never
updated, holds the mark back. From that entry on the files say format 2, a kithd from
before refuses them, and the leader sends such a kithd no snapshot. So:

1. Before updating, back the store up: stop a control node's kithd, copy the `raft/`
   directory of its state, and start it again.
2. Update one node at a time. Until the last of them is updated, any can be put back
   on the kithd it had.
3. Half a minute or less after the last one answers, the leader says `the store keeps
   from now on when each resource was first made`, and there is no going back short of
   that backup. A cluster of one node has nobody to wait for: it marks its store as
   soon as the new kithd starts.

What there was at the mark is taken as made at the time of its oldest revision still
kept: a Service edited more than a hundred times before it may already count as newer
than one that names its host. Where that matters, keep the host with its Namespace's
`hosts` before updating.

- A kithd reads every format up to its own. `crates/kith-store/fixtures/format-1`
  and `format-2` are a state as each format is written, every kind of change in its
  log, and the test above has each later build open them, read every entry of the log back
  as it was written, and end with the same resources. A build that cannot does not pass; a build that changes what is written
  takes the next number, adds a fixture of its own and keeps the old ones.
- A kithd refuses a state in a format newer than its own and leaves the
  files as they were, rather than read them as if they were its own:
  `raft/log.redb is in format 2 and this kithd reads up to format 1: start
  the kithd that wrote it, or a newer one`. So going back to an older release
  is sure only while the state is in a format that release reads, and a release
  that takes a new number says so, and when the state changes to it.

Not numbered yet: what nodes say to each other (a snapshot one node sends
another is written down by the node that takes it, in its own format), and
the other files in a node's state (its keys, blobs and volumes).

One thing nodes say to each other changed after 1.0: a node that passes a request on to
the node that has the thing (`kith logs` of a replica elsewhere, `kith volume put` and
`get`, `kith node passphrase`, a backup's restore) now says who asked, and a node that
is told nothing refuses with `node NAME passed this on without saying who asked: its
kithd is older than this node's`. So while a cluster is half way through such an
update, ask the node that has the thing, or wait until both run the new kithd. Nothing
else between nodes is affected: the store, the mesh, Services and `kith run` go on.

A field a newer kithd takes is not known to an older one, which reads a resource that
has it as one it cannot read: say `trust` on a Node or a Secret (and any field newer
than the oldest kithd in the cluster) once every node runs the kithd that knows it.

### Rolling a release through the cluster

```sh
sh ci/vm.sh --test rollout             # three nodes in QEMU take a release in turn
```

Sign the update with a key of your own, put the file where every node can
fetch it (any web server), and tell the cluster:

```sh
kith package keygen release.key                  # prints the public key; keep release.key to yourself
sh os/update.sh --sign release.key kith-os.update   # prints the signature
```

```yaml
apiVersion: kith.dev/v1
kind: OSRelease
metadata:
  name: v0-0-2
spec:
  version: 1.0.1
  image: http://files.example/kith-os-1.0.1.update
  publicKey: <what keygen printed>
  signature: <what --sign printed>
---
apiVersion: kith.dev/v1
kind: UpdatePlan
metadata:
  name: everyone
spec:
  release: v0-0-2
  selector: { ring: stable }       # nodes with these labels; without it, every node
  maxUnavailable: 2                # how many at a time (1 unless said)
  windows: ["Sat,Sun 02:00-05:00"] # UTC; `23:00-04:00` is every night; none: any time
  drain: true                      # place no new workloads on a node while it updates
```

The signature is over the update's header, which names the SHA-256 of every
piece, so a node checks the signature before it writes a byte and each piece as
it writes it. A release without a key, one signed by another key, a file
changed after signing, and a file that is another version than the release
says are all refused. The address may be plain HTTP for that reason: what
comes from it is trusted for the signature alone.

A node takes releases from its own keys only, whatever key an OSRelease
names. Give them before the first release, so that nobody else's can be it:

- **in the image**: `KITH_RELEASE_KEY=KEY sh os/build.sh` (commas between
  several) writes them to `/etc/kith/release-keys`, in the signed root, so every
  node made from the image starts with them;
- **at install**: `releaseKey: KEY` in the installer's answers (commas between
  several), for one installer image that serves owners with different keys; it
  goes on kithd's line in the config partition as `--release-key`;
- **to kithd**: `--release-key KEY` (or `KITH_RELEASE_KEY`); on kith OS,
  ` -- --release-key KEY` at the end of what its config partition says.

A key given to kithd counts first, then the keys a node keeps in its state
(`os-release-keys`, written when it first updates, and by a handover below),
then the image's. A node with none of them takes the key of the first release it
updates to, whoever applied that release, and keeps it: it says so in its log at
every start, and its Node's `status.os.releaseKeys` is `none` (else `given`,
`kept` or `image`). A node with no state partition keeps nothing, so give it its
key in the image or to kithd. A release signed by any other key is refused. A
release older than what a node runs is refused too, unless the plan says
`allowDowngrade: true`. A node whose keys cannot be read takes no release, and
says that at every start too.

The image's keys are where a fresh node starts, not what it holds to: its first
update keeps them in its state, and from then on its keys change only by a
handover (below) signed by a key it has, or by `--release-key`. A new image
built with another key does not move nodes that already run: to rotate, sign a
release with the old key whose `handover` names the new one, roll it out, then
build later images with the new key alone.

The file is fetched from the address the release names and nowhere else: a
redirect is not followed, no proxy is used, and the address is looked up once,
checked and then connected to, at the port the URL names (80 for `http://` with
none, 443 for `https://`). One on the node itself or on its own networks
(loopback, private, shared, link-local, multicast) is refused. With
`--lan-releases` (`lanReleases: true` at install) the private ranges (10/8,
172.16/12, 192.168/16, 100.64/10, fc00::/7) may be, for a release server on the
LAN; the node's own addresses, the cluster's mesh (its nodes' and pods' addresses
there), loopback and link-local stay refused, and the address is still checked
and held. With the flag, whoever may write an OSRelease can have every node ask
any host on those ranges, at any port and path, and read in the plan's status
whether it answered. Even so, give OSRelease and UpdatePlan to nobody who is not
the cluster's admin: they still decide when nodes restart.

**A key hands over to others in a release.** `handover` names the keys that count
once a node runs that release (the release's own among them, if it is to go on
counting), signed by the release's key and by one of the keys named:

```sh
kith package keygen next.key                                   # prints the new public key, NEWKEY
sh os/update.sh --handover release.key kith-os.update NEWKEY   # prints handover.signature
sh os/update.sh --handover next.key kith-os.update NEWKEY      # prints handover.proof
```

```yaml
apiVersion: kith.dev/v1
kind: OSRelease
metadata:
  name: v1-0-2
spec:
  version: 1.0.2
  image: http://files.example/kith-os-1.0.2.update
  publicKey: <the key the nodes have>
  signature: <what --sign printed, with release.key>
  handover:
    keys: [c43685f967c3766aa98d5516f48db84ce1d27db7b480230f8a8e4fab95874d7e]   # 1 to 8
    signature: 63bc974e91261f724d8409a95701ef183622325d0c1d796656d33b50912a6b5a021b7a5779c68228bfa47ddcdd884d46478080a4b5110387db8ffe7a128e1c8a
    proof: 2178dab95346eac739a287cf07fdcda76983016620bd3857a0c0f48433ab9f096b880f0843c5899ef9c89460de046777a5b78faf2ba288d3bcd138ca6a508996
```

A node that takes this release puts the keys aside, and they become its keys when
it has started on 1.0.2 and marked it good (the ones it had are left beside them, in
`os-release-keys.before`): a release signed by a key that was left out is refused from
then on. Until then nothing has changed, so an update that does not come up is tried
again under the keys the node had. A handover that is not signed by both, or names
no key or more than eight, is the release refused, and the plan says why. The two
signatures are over the keys, the release's version and the update's header, so a
handover is good with that release and no other; and one in a release of the version
a node's keys came with, or of an older one, changes nothing (an old release shown
again brings no key back). Hand over in a release with a higher number than the last
handover's: two versions that differ only in a word after their numbers (`1.1-rc1`,
`1.1-rc2`) are ones a node cannot put in order, and it refuses the second handover.
Put the stanza in one release and leave it out of the ones after it. A node started
with `--release-key` takes its keys from there, and from no release.

Only a node whose kithd knows handovers takes one. A cluster from before them does
not take the stanza at all (`kith apply` says it does not know `handover`), and in
one that is half way a node still on the older release takes the update and keeps
the key it had. So the release that hands over is not the first one built from this
version: put one out without a handover first, and hand over in the next, when every
node runs the first. (A node that was missed is started with `--release-key`.)

Keep signing with the old key until every node runs a release that hands over: a
node that was off in the meantime takes that release first, and it knows the old key
only. A lost key cannot hand over, since nothing signs for it: each node is then
started with `--release-key`, as above. So hand over to two keys, and keep one of
them where the other is not.

**The floor.** A node keeps the newest version it ever ran well in its state
(`os-release-floor`, written when the slot it started from is marked good) and takes
no release under it: not when it has fallen back to its older slot, and not when a
plan says `allowDowngrade: true`. A cluster whose admin's credentials are taken is
not walked back to a release with a hole that was since mended. To go back on
purpose, release the older system again under a newer version; or remove
`os-release-floor` from the node's state, at the node (nothing in the cluster's API
does it; on kith OS that is the state partition, reached from another system
started on that machine). So `allowDowngrade` now takes back only a node with no
floor above the release: one with no state partition, or whose floor was removed. A
floor that cannot be read is not "no floor": the node takes no update until the file
says a version or is gone. The floor is for releases that come through the cluster:
an update stick (`kith.update=DEVICE`) is written whatever it says, as whoever is at
the machine with a stick is its admin already.

The node that leads the cluster picks who goes next: nodes that do not vote
on the store first, `maxUnavailable` at a time; then the voters, one at a
time, each only while every other voter is up, and itself last. A node whose
turn it is fetches the file, writes its other slot and restarts; every kith OS
node says what it runs in its Node's status (`os.version`, `os.slot`), and
the plan's status says where the rollout is:

```
status:
  phase: Progressing      # or Done, Waiting (outside its windows, no such release), Paused
  nodes: { n2: done, n3: updating }
```

`Paused`, with a `reason`, means a node did not take the release: it refused
the file, or it restarted into the new slot three times, the boot loader gave
up, and it is back on the system it had (`os.failed` in its Node's status).
Nobody else is given that release. The plan stays paused until the OSRelease
is changed (signed properly, another address) or the plan names another
release, and then starts over. `paused: true` in the plan's spec stops it by
hand, for as long as it is there; a node already told to go finishes.

With fewer than three voting nodes the store cannot be written while one of
them restarts, as with any restart of such a node. While a voting node is
away, no other is restarted, and the plan's `reason` says it is waiting.

A node told to update that says nothing for fifteen minutes counts as failed
(and as done after all if it then turns up running the release). `waitForIdleSeats` is accepted and does nothing yet (there are no seats),
`drain` stops new placements but moves nothing that already runs there, and a
download that breaks counts as a refusal: nothing was written, and the plan
is paused.

### Installing on a machine

```sh
sh os/build.sh                         # also writes target/os/kith-os-installer.raw (460 MB)
sh ci/vm.sh --test install             # the installer in QEMU, onto disks that are files
```

**The installer erases the disk it is given.** Nothing in this repository
starts it on a real machine: the test attaches files as disks to VMs. Putting
it on a machine of yours is your decision, machine by machine.

Write `kith-os-installer.raw` to a USB stick (`dd if=kith-os-installer.raw
of=/dev/sdX`, where sdX is the stick), or attach it to a VM as its first disk,
and start the machine from it (UEFI). It is kith OS started with
`kith.install`: it serves nothing, and asks on the screen and on the serial
line alike:

```
This machine's disks:
  nvme0n1 (256.1 GB, Samsung SSD 970)
  sda (2000.4 GB, WDC WD20EZRZ)
Install kith OS on which (its name)?
The node's name (empty: one made from its network card's address)?
Its address, as 10.0.0.5/24,10.0.0.1 (empty: ask the network)?
Join a cluster? The address of one of its nodes, as 10.0.0.7:7443 (empty: start a new cluster)
The join token (`kith node token` there)?
Everything on nvme0n1 (256.1 GB, Samsung SSD 970) will be erased. Type its name again to go on:
```

The disk it was started from is never in the list. A removable disk (a stick, a
card reader) is listed and is installed on when named, but `only` never means
one: a machine whose disks are all removable is asked for a name. The disk's size
is read again just before it is written, and a disk of another size writes
nothing. A name not typed the same twice writes nothing and the questions start
over. It then copies kith OS to
the disk, reads the disk back to see that it holds what was written, and
powers the machine off: take the stick out and start it.

Without anyone there, put the answers on the stick, as `kith-install.yaml` on
its first partition (FAT: any system can write it), or at a URL given on the
kernel command line (`kith.install=https://10.0.0.2/alpha.yaml`; a hypervisor
gives it as the SMBIOS string `io.systemd.stub.kernel-cmdline-extra=`). Over
plain `http` whoever sits between the machine and the URL could change the
answers (the disk, the join token, the release key), so the URL carries their
digest: `kith.install=http://10.0.2.2/alpha.yaml#sha256=HEX`, where HEX is what
`sha256sum alpha.yaml` prints (64 hex digits, either case). The installer
refuses plain `http` without that pin before it fetches anything, and refuses
answers that do not hash to it, naming both digests. `https` needs no pin.

```yaml
disk: nvme0n1        # or `only`: the one disk of a machine that has one, not removable
hostname: alpha
ip: 10.0.0.5/24,10.0.0.1      # without it the network is asked (DHCP)
dns: 10.0.0.1
join:                         # without it the node starts a new cluster
  address: 10.0.0.7:7443
  token: $TOKEN
encrypt: true                 # its state under a key the cluster holds: see "Encrypted state"
releaseKey: $KEY              # kith OS releases signed by this key only: see "Rolling a release"
lanReleases: true             # releases may come from a server on the node's private ranges
nodePolicy: hardened          # what the cluster may not have this node do: see "What a node refuses, whatever the cluster says"
```

Then nothing is asked, and nothing confirmed: a stick with answers on it
erases the disk they name in whatever machine it starts. A disk that is not there, `only` on a machine with
several, or a field it does not know stops it with the reason on the console
and nothing written.

What it was told goes into a small partition of the new disk (`config`), which
the node reads at every start as more of its kernel command line: its name,
its address, and kithd's arguments (`--listen 0.0.0.0:7443`, and `--claim` for
a new cluster or `--join` with the token). A node that starts a cluster
[offers a claim on its console](access.md#who-may-do-what); one that asked its network
for an address tells other nodes the address it was given.

The image's state partition is 32 MB, and no disk is that small: at its first
start on a disk, and at any later one if the disk was made longer since (a
cloud volume, a VM's file), a node's state partition
grows to the end of its disk and the file system in it grows with it. The node
says so on its console
(`the state partition now ends where its disk does: 228936 MB`). It only ever
does this where the state is the disk's last partition, as in the image, and
the partition table reads right; the spare table is written at the disk's new
end before the first one is touched, so a power cut in the middle leaves one of
them whole, and the next start finishes from that one. `kith.grow=off` on the
kernel command line keeps the disk as it is. A node that ran an older kith OS grows its state the first time it starts
a release with this in it. A state partition that has not grown (a VM's disk
left as long as the image, or `kith.grow=off`) has room for almost nothing: a
first pull of a large image onto it fails with `No space left`. One trial, a
Flatpak runtime in a pod, needed about 4.3 GB of state.

### Installing from the network

A node installs the machines beside it: told their network cards' addresses,
it answers those machines when they start from the network, hands each the
installer once, and the machine installs kith OS on its disk, starts from it
and joins the node's cluster. No stick, and no change to the network's own
DHCP server: the node only adds the boot file's name to what that server says.

```sh
sh os/build.sh                         # also writes kith-netboot.efi
kith node netboot --image target/os/kith-netboot.efi --mac 52:54:00:12:34:56 --mac 52:54:00:12:34:57
kith node netboot                      # is it on, and which machines have the installer
kith node netboot --off
sh ci/vm.sh --test netboot             # the same, in QEMU, on a disk that is a file
```

Then set each machine to start from the network (PXE, IPv4) once, or first in
its boot order: a machine that has the installer is not answered again and goes
on to its disk. **Everything on that disk is lost**, and nobody is asked at the
machine: name only cards of machines you mean to erase. `--disk only` (the
default) installs on a machine's one disk and refuses a machine with several;
`--disk nvme0n1` names it. Netboot turns itself off after `--minutes` (30; at
most 60), when the node restarts, or with `--off`.

The node must be the one that started the cluster (it holds the CA, which
makes the join tokens) and be run with `--listen`, as the machines join it
there. On a kith OS node, where nobody logs in, an Identity that may apply
Nodes, Roles and RoleBindings sends the same over TLS:

```sh
curl --cacert ca.pem --cert cert.pem --key key.pem --data-binary @target/os/kith-netboot.efi \
    -X PUT 'https://NODE:7443/v1/netboot?macs=52:54:00:12:34:56,52:54:00:12:34:57&minutes=30&disk=only'
```

(`GET` says where it stands, `DELETE` turns it off.)

What to know before turning it on: the boot file goes over TFTP, unencrypted
and unsigned, with the machine's join token in it. Anyone on that network
segment who claims a named card's address while netboot is on gets that token
(it lets one node join, for an hour), and anyone there who answers network
boots faster than the node can hand the machine something else: use it on a
network you trust, for as short as it takes. Machines must start by UEFI on
x86-64 and have 1 GB of memory (the image sits in memory while it is written);
the node answers on every card it has an address on. UEFI HTTP boot is not
answered yet.

### Installing on a rented machine

A machine that cannot be started from a stick, but runs some Linux you can log
in to as root, is installed from that system: `os/vps.sh` loads kith OS's
kernel with the installer and the image in a memory disk, and starts it in
place of the running kernel (kexec). **The disk named is erased, the system
that ran with it**, and the machine restarts as a kith OS node. As with the
stick, you run it, on that machine; nothing here does.

```sh
sh os/build.sh                         # also writes vmlinuz, kith-install.cpio.zst and vps.sh
scp target/os/vmlinuz target/os/kith-install.cpio.zst target/os/vps.sh root@machine:
scp answers.yaml root@machine:
ssh root@machine sh vps.sh --answers answers.yaml --erase vda
sh ci/vm.sh --test vps                 # the same, in QEMU, on a disk that is a file
```

`answers.yaml` is [the installer's](#installing-on-a-machine), with the disk
by its name (`lsblk -d` shows them). Rented machines mostly have a fixed
address and no DHCP: give `ip:` the address and gateway the machine has now
(`ip addr`, `ip route`), or it comes back with no network and no way in.
`--erase` says the disk's name a second time; without it the script asks.

**Have another way in ready** (the provider's console or rescue system) before
you run it. Once the installer's kernel starts, the old system and your login
are gone. If the installer then refuses the answers it starts the machine
again, and the old system comes back, its disk untouched; if the disk was
already being written, or the node comes up with a wrong address, the console
is all there is. The kernel has drivers for virtio, NVMe and AHCI disks and
for virtio, Intel (e1000, e1000e, igb), Realtek r8169 and Broadcom tg3 and
bnx2 network cards, and none for Xen, Hyper-V, VMware or AWS ENA devices: on
such a machine the node has no network. The installer is told the size of the
disk named and writes no disk of another size, as its kernel may name the
disks in another order.

The script refuses, with nothing done, a machine that starts by BIOS (kith OS
starts by UEFI only: `ls /sys/firmware/efi` tells), one with less than 1 GB of
memory (the image sits in memory while it is written), one without `kexec` or
`cpio`, and a disk that is not there. The test starts the kernel and memory
disk the way kexec does; the `kexec` call itself has only been read, not run.

For a cloud that takes uploaded disk images, `kith-os.raw` and
`kith-os.qcow2` are that image: such a node asks its network for an address
and names itself after its network card, as nothing has written its config.

### Encrypted state

A node's state partition (its certificates, the store, Secrets, volumes) can
be kept under dm-crypt, with the key not on the machine: the cluster holds it.
At each start the node brings its network up, asks the nodes it knows for its
key and only then opens its state. A disk taken out of its cluster, thrown
away, or sent back under warranty opens for nobody.

It is chosen when the machine is installed: `encrypt: true` in the
[installer's answers](#installing-on-a-machine) (the installer asks, at the
console), or `kith node netboot --encrypt`.

```sh
kith node lock beta                    # the cluster stops handing beta's key out: beta restarts, and waits
kith node unlock beta                  # beta is handed its key again, and starts
kith node wipe beta --erase beta       # the key is forgotten for good: beta's state is gone
kith node seal beta                    # beta's own TPM keeps the key too: it starts with no node asked
kith node seal beta --off              # taken back: beta asks the cluster again
kith node passphrase beta              # asks for one, twice, unseen: typed at beta's console, it opens beta's state away from home
kith node passphrase beta --off        # taken away
kith node pin beta --untried-tpm       # asked of beta's own kithd alone: a PIN, twice, unseen; beta's TPM then opens its state only with it typed at its console
kith node recovery beta                # beta, running, makes a new recovery key and shows it, once: the old one opens no more
kith node duress beta                  # a duress code for beta, shown once: typed at beta's waiting console, it erases beta's way in
kith node duress --all                 # one code for the whole cluster (--off takes either away)
sh ci/vm.sh --test crypt               # all of it, in QEMU, on a disk that is a file
sh ci/vm.sh --test tpm                 # the seal, with a software TPM (swtpm)
sh ci/vm.sh --test duress              # the new recovery key and the duress code, the same way
```

`lock` is for a machine that is lost or about to leave the house; a locked
node that is still running restarts within moments, and from then on says at
its console that it waits. `wipe` cannot be undone: the cluster no longer
holds the key, and the node, if it still runs, erases what it would need to
ask for it and powers off. Every control node then snapshots the store and
drops its log up to the wipe, so no earlier version or log entry keeps the
wrapped key. (It is still in copies of a node's state made before, which open
nothing without the secret on the wiped disk: SECURITY.md says what stays.)
A node whose key is still on its own disk, as no other node holds it yet,
opens whatever the cluster says.

**The recovery key.** The installer shows it once, at the console, when it is
done (32 digits in groups of four): write it down. Typed at a waiting
machine's console, it opens the state where no cluster answers: a laptop away
from home, or a cluster whose nodes were all off at once (each waits for
another to hand it its key: open one by hand, and the others follow). It
opens a locked node too, as whoever has it owns the machine; only `wipe`,
reaching a running node, or a duress code ends that. An install that nobody
watched (from a URL, or from the network) has a recovery key that nobody saw:
a cluster of such nodes that is all off at once opens for nobody. So
`kith node recovery beta` has beta, while it runs, make a new one and shows it
this once (it is kept nowhere: not in the store, not in the audit log); the key
beta had before opens it no more. Beta writes the new key before it answers:
if the command fails, run it again, since the old key may be gone and nobody
has seen the new one. While the cluster holds nodes' keys and
nobody was shown the recovery key of any of them, `kith get node` and the web
UI say so. `kith get NodeKey beta` says `recoverySeen: true` once beta's was
shown by that command, or typed at beta's console: shown, which is not the
same as written down.

**A duress code.** For whoever is made to open a node. `kith node duress beta`
makes one and shows it this once: 32 digits in groups of four, as a recovery
key looks. Typed at beta's console while beta waits for its key, it erases
beta's lock record (the disk's own secret, and with it what the recovery key
and a passphrase opened) and, when a node of the cluster answers, has the
cluster forget beta's key, as `wipe` does. The console says of it what it says
of a wrong key, two seconds after the line was entered, as it does for every
line that opens nothing; from then on nothing typed opens beta, the recovery
key included. There is no way back. Codes are made by kith, never chosen, and
none exists until someone who may apply NodeKeys makes one; `--off` takes it
away (the node drops it when it hears). A code works at a node once that node,
running, has heard of it (`kith get nodekey beta` then says `duress: true` in
its status): a node that was off when the code was made takes it for a wrong
key until it has run with the cluster in reach.

`kith node duress --all` makes one code for the whole cluster. Typed at the
waiting console of any encrypted node, it does to that node what its own code
does, and has the cluster forget the key of every other node that was under
the code when it was made. Those nodes run on. They drop their TPM's seal and
their passphrase when they hear of it, and from then on open with their own
recovery keys alone, until `kith node unlock NAME` has the cluster hold NAME's
key again. A node forgotten this way keeps its own code, which still erases
it; the cluster's code is gone from all of them, and after `kith node unlock`
a node has no code until one is made again. So the cluster makes no such code while one of its nodes has a
recovery key nobody was shown (`kith node recovery` first), and a node that
joins later is not under it: make the code again.

What a duress code does not do. A disk copied beforehand, with its recovery
key or a passphrase it had, still opens; and until a node of the cluster has
heard the code (the machine was away, or its card was pulled), such a copy
started on the cluster's network is still handed its key: `kith node wipe` it
from a node you can reach as well. Flash may keep old blocks: the record is
written over with zeros, and what a flash disk keeps of sectors it has
replaced is not kith's to say. A disk that refuses the write keeps its record:
the node tries again for as long as it waits and says nothing of it. The
cluster stops handing the key out and keeps it in no earlier version, snapshot
or log entry, but a copy of a control node's state taken before, and the freed
blocks of its disk until they are written over, still hold the wrapped key,
which opens nothing without a copy of the erased disk. The record on the disk shows that a code
exists (not what it is: it holds a public key made from the code). The answer
at the console is the same; the request to the cluster, the write to the
disk, and the record that is gone afterwards are there for whoever watches
the network or reads the disk. It works at a waiting console only: a node
that runs has its state open. And whoever has the code and can reach a node's
port can have the cluster forget without being at any console: keep a code as
you keep a recovery key.

**The machine's own TPM.** `kith node seal beta` lets beta keep its key
itself, sealed to its TPM and to the system it runs: from then on it opens
its state at start with no node asked, which is what a laptop away from home
needs. The TPM gives the key only while PCRs 0, 4, 7, 9, 12 and 15 (SHA-256)
stand as they stood when it was sealed: the firmware (0); what it started,
which is the boot loader and kith OS's boot file, with the kernel and the
command line that names the system image by its hash (4); whether Secure Boot
is on and whose keys it trusts (7); a command line or an initramfs given from
outside the boot file (9 and 12); and what the node's config partition says
(its name, its addresses, kithd's arguments), which no firmware measures and
kithd does itself before it asks for the key (15). Started with anything
else, the node is refused the key, asks the cluster as before and, once open,
seals again: an update, or new firmware, costs one start that needs the
cluster or the recovery key. (kith OS's boot file is not signed for Secure
Boot: where that is off, PCR 7 says so and no more, and a changed boot file
is refused the key by PCR 4, not kept from starting.) `kith get NodeKey beta` says whether the key is sealed, or why
not (a machine with no TPM, or one whose firmware measures nothing, goes on
asking the cluster). `--off` takes it back, and a locked or wiped node drops
its seal when it hears of it.

What the seal does not cover: a machine taken whole and started as it is
opens its state by itself, and no lock reaches it until it hears its cluster
again; what stands between whoever holds it and its state is then the running
system alone. Nor a system taken while it runs, nor a machine with no TPM.
The key crosses the TPM chip's bus encrypted, to the storage key whose name
the seal keeps, so probing the chip's pins reads nothing; but someone on the
bus when the seal was made, or who resets the TPM and replays an allowed
start's measurements, can still get it (SECURITY.md). It has run against a software TPM only, never on a real
one.

**A passphrase.** For a machine with no TPM, or whose owner will not have
the machine alone be enough: `kith node passphrase beta` asks for a
passphrase (eight characters or more, of ASCII; several unrelated words are
better)
and gives it to beta, which from then on takes it at its console where it
takes the recovery key: a start with no node in reach waits, and opens once
the passphrase is typed. What is typed at the machine's consoles is then
not shown. Run it on
any node: that node hands the passphrase to beta over the cluster's TLS and
keeps none of it; it is not in the store, and the audit log says only that
one was given, and by whom. `kith get NodeKey beta` says `passphrase: true`
while beta has one; giving another replaces it, and `--off` takes it away.

What the passphrase costs: the key is on the node's disk again, wrapped
under a key drawn from the passphrase (Argon2id, 19 MiB and 2 passes for
each try). Whoever has the disk can try passphrases for as long as they
like, on machines of their own: a short or guessable one is no protection,
and the recovery key's 128 random bits are no longer what stands between a
taken disk and its state. A locked node drops its passphrase when it hears
of the lock (and takes no new one until it is unlocked); one that was off,
or away, did not hear, and still opens for whoever types it. It is another way in, not a second lock: a node that also
has its TPM's seal opens by that, with nothing typed. And it is typed as the
keys lie when the machine starts, which is the kernel's own layout (US): a
passphrase with letters that sit elsewhere on your keyboard is typed where
they sit there.

**The TPM and a PIN.** `kith node pin beta --untried-tpm` asks for a PIN (6 to
32 digits, typed on the row above the letters), twice and unseen, and gives
it to beta's own kithd (its socket, or `POST /v1/lock/beta/pin` at beta's own
address): another node refuses it and passes it on to none, until the owner
decides otherwise. From then on beta's TPM opens its state
only with that PIN typed at its console, where it takes the recovery key, and
no longer by itself. A copy of the disk opens on no other machine, and on this
one only while its system is the one sealed to. The TPM counts each wrong PIN:
beta refuses a PIN that this TPM's lockout would let be guessed one time in a
hundred in a year (it names the shortest it takes). That holds for random
digits only: a date or 123456 is among the first guesses, so pick them at
random. Setting a PIN takes the TPM's lockout authorization where it is empty,
kept in beta's encrypted state alone, so that nobody else can forgive the
count; if that state is lost, only clearing the TPM in the firmware's settings
gives the authorization back. Setting a PIN again shows the kept authorization
to the TPM, which forgives the wrong tries counted; nobody gets to try the old
PIN by it, since the new one replaces it, and only whoever may apply beta's
NodeKey can set one. Each setting tries one wrong PIN, which the TPM
counts. After too many wrong ones the TPM refuses every PIN, the right one too,
for a while, and the console says how long; the recovery key still opens.
The cluster's key opens beta's state as before: a PIN adds a lock to the
machine alone, not to the cluster's way. `--off` takes it away. After an
update that moves the PCRs the PIN opens nothing until it is set again (a seal
for the next system is not built yet), and locking beta, then unlocking it,
drops the PIN. It has run against a software TPM only, never on a real one,
and is refused without `--untried-tpm`, the owner saying so, until the
checklist in docs/adr-unlock.md ("On hardware: the owner's checklist") has run
on the machine. That flag is a word, not a lock: whoever may apply a NodeKey at
beta can send it.

What is and is not protected:

- The cluster holds the key wrapped with a secret that only the node's disk
  has (a `NodeKey` in the store): neither the store alone, nor a backup of it,
  nor the disk alone opens the state. The disk together with a cluster that
  still hands the key out does, which is what `lock` is for.
- Until another node holds the key it stays on the node's own disk, and the
  node says so at each start: a cluster's first node, until a second has
  joined, is not protected.
- Whoever may apply NodeKeys can lock and wipe, have a node make a new
  recovery key (and is shown it), and make duress codes; a running node gives
  its NodeKey again when it is deleted or written over, and one that was off
  meanwhile needs its recovery key.
- The config partition (the node's name, address, and the join token it was
  installed with, spent since) and the system itself are not encrypted.
- Anyone who can reach a node's port can ask for a key by its id; what they
  are sent opens nothing without the disk's secret. They can ask it to forget
  one too, which it does only for a number it gave within the last minute,
  signed with the key of a duress code, once.
- A stolen machine that is not locked, started on the cluster's own network,
  is handed its key: lock it when it goes missing.

Not yet: a passphrase and the TPM both asked for (the TPM and a PIN are, above;
a passphrase and its seal are still two doors), the cluster's key and the TPM both asked for, a keyboard layout at the console, encrypting a node that was not installed that way, the disk's secret kept in
the TPM (so that erasing it would not depend on what a flash disk keeps), a duress code that opens a decoy.

### Not in kith OS yet

A CD image, starting by BIOS, a watchdog for a slot that hangs without
stopping, Secure Boot (the image is not
signed, so the firmware does not yet check the file that checks the root),
drivers for Wi-Fi, sound and graphics, a card plugged in later, IPv6 addresses from the network,
arm64.
