# kith OS: kithd as the machine's first process

On a kith OS machine there is the kernel and kithd, nothing else: no systemd, no shell.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/assets/diagrams/os-dark.svg">
  <img src="../../docs/assets/diagrams/os-light.svg" alt="kith OS from power-on: the firmware starts systemd-boot, which starts the newest kernel image that has tries left; the image names the hash of its 6 MB read-only root, of which a changed block is refused; kithd is the first process, reads the config partition and mounts the state partition, the two that no update replaces. An update, one node at a time: an OSRelease signed by the release's key (an update from a stick is not signed) is written into the other slot, the node restarts into it, and it is marked good or the node is back on the old slot after three tries" width="100%">
</picture>

As process 1, kithd:

- mounts `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, the cgroup tree, and the partition labelled
  `state` at `/var/lib/kith` (with none, the state is in memory);
- names the machine `kith.hostname=NAME` from the kernel command line, else `kith-` and the last
  six digits of its first network card's address;
- brings every card up and asks for an address (DHCP, renewed). Where there is none, say
  `kith.ip=10.0.0.5/24,10.0.0.1` (address, gateway) and `kith.dns=9.9.9.9`;
- reads its own arguments after ` -- ` on the command line: `console=ttyS0 kith.hostname=alpha
  -- --listen 0.0.0.0:7443 --advertise 10.0.0.5:7443`;
- collects orphaned processes and says what it says on every console the kernel has;
- stops what it runs, then restarts on Ctrl-Alt-Del or powers off on SIGTERM or the power
  button.

Process 1 is the same binary keeping kithd as a child of its own (`crates/kithd/src/keeper.rs`,
about 120 lines): it reaps what is left to it, writes down how each process ended, and starts
kithd again the moment it ends. What kithd started does not stop with it: pods, containers,
exec units and Jobs keep running, and the next kithd takes each back as it runs (or as it
ended, so a Job's unit is not run again). It serves again within two seconds. What a
restart drops: a container made and not yet started (made again), probes' counts, which
devices are held (SECURITY.md) and what kithd had in memory. If kithd ends ten times in a
minute, it says why and the machine restarts ten seconds later. `sh ci/vm.sh --test outlive`
kills kithd under a pod, an exec unit and a Job and checks all of it.

`sh ci/vm.sh --test init` boots exactly that in QEMU and prints the time to serve.

### The image

```sh
sh os/build.sh --check     # target/os/kith-os.raw (281 MB) and kith-os.qcow2 (19 MB)
sh ci/vm.sh --test image   # boot a copy of it under UEFI in QEMU and check it
```

`os/build.sh` makes a node's whole system without root or touching a disk:

| Part | What it is |
| --- | --- |
| kernel | 6.18, 13 MB, from kernel.org's source at a pinned version and checksum (`os/kernel.config`): no modules, no initramfs; NVMe, SATA, USB and SD storage, the common wired cards, virtio, WireGuard, dm-verity, dm-crypt, KVM. The first build takes ten minutes or so |
| root | a read-only squashfs of about 6 MB: kithd as `/sbin/init`, `kith`, curl's CA bundle. No shell, no libc, no package manager |
| verity | the root's dm-verity hash is on the command line inside the one EFI file the firmware starts (systemd's stub, the kernel, the command line), so a changed root is refused block by block |
| disk | GPT: `esp` (systemd-boot, `kith-1-a.efi`), `root-a` and `verity-a`, `root-b` and `verity-b` (empty: an update goes there), `state` (ext4), the only partition a running node writes |

The build is not yet reproducible end to end: kithd is compiled once per run, and systemd's EFI
stub and boot loader come from the building machine.

### A node that needs more: a spec

The image has no driver for graphics, sound or Wi-Fi, and no kernel modules to add one to a
running node. A node that needs one runs an image built for it, from a spec:

```yaml
# os/examples/gpu-amd.yaml
features: [gpu-amd-phoenix]
```

```sh
KITH_OS_VERSION=1.0.1+gpu-amd sh os/build.sh --spec os/examples/gpu-amd.yaml --out target/os-gpu-amd
```

| | |
| --- | --- |
| A feature | a file of its name in `os/features/` (`gpu-amd-phoenix.config`): lines of kernel config merged over `os/kernel.config`, and `# firmware:` lines, what its driver loads. Naming the feature brings both: no file names, no versions |
| Versions | None to choose: the kernel and linux-firmware (`firmware_date` in `os/build.sh`) are the ones this kith pins, as a distribution's release does |
| `firmware:` | Paths or globs in linux-firmware for what no feature knows; built into the kernel too |
| Firmware | Built in, only the files named: a driver starts before any root is mounted, and all of linux-firmware is 640 MB. So a feature is one GPU family, not every GPU of a vendor |
| Refused | A feature there is no file for (the ones there are are listed), a key other than these two, a firmware path linux-firmware does not have |
| The rest | The root, the disk and the update are as without a spec; a spec's kernel is built once and kept, beside the plain one |

The features: `gpu-amd-phoenix`, the GPU of a Ryzen 7040, 8040 or 8000G (Radeon 780M, 760M,
740M), with `/dev/kfd` for compute and the dmem cgroup, so a [GPU share](hardware.md) is a
ceiling there. It costs the kernel 4.2 MB (17.9 MB against 13.5, firmware included), so the
update is 43 MB against 34 and the ESP's two kernels 36 of its 64 MB; the root is the same.
Built and started under UEFI in QEMU, the kernel brings amdgpu up (`amdgpu: Topology: Add CPU
node`) and kithd serves; on a 780M itself it has not run yet.

A cluster runs plain and GPU nodes side by side: sign each image's update as its own
`OSRelease` and roll each with its own `UpdatePlan`, the GPU one with a `selector` on a label
those nodes carry (`gpu: amd`, put on the Node as [any label is](cluster.md#where-work-runs): kithd does not
set it from the GPU it finds yet; see [Rolling a release through the
cluster](#rolling-a-release-through-the-cluster)). A plain release given to a GPU node takes its
driver away until the next GPU one.

### Updating a node: two slots

```sh
KITH_OS_VERSION=1.0.1 sh os/build.sh   # also writes target/os/kith-os.update (32 MB)
sh ci/vm.sh --test update              # a node updates itself in QEMU, and goes back when it must
```

A node runs from one slot (`root-a` or `root-b`); an update is written into the other:

1. kithd checks each piece against the SHA-256 in the update's header as it writes it: the root,
   its verity tree, and last, on the ESP, the kernel image as `kith-N-b+3.efi`. N is one more
   than any other, so the boot loader starts it first; `+3` is three tries, counted down in the
   file's name at each start.
2. A slot whose kithd still runs ten seconds after start is marked good (`slot b is good`; with
   encrypted state the ten seconds start when it is open).
3. A slot that does not come up is restarted until its tries are gone. The boot loader then
   starts the slot that worked, and kithd says `slot a did not come up in 3 tries: this is slot
   b, which ran before it`. Each failed start in a row waits longer, up to ten minutes.

A damaged, cut-short or too-big update is refused, and no kernel image offers the half-written
slot. The state partition is in no slot: the node is the same node after an update, and after
going back. An update can also reach one node from a stick: `dd if=kith-os.update of=/dev/sdX`,
then start the node once with `kith.update=sdX` on its command line. It writes the other slot and
restarts into it, newer or older; one given while its own slot is not yet good is refused.
Nothing checks who made it: whoever can change the command line has the machine anyway.

### What an update keeps: the format of the store

```sh
cargo test -p kith-store format        # this build reads a state written in format 1, and in 2
```

A node's copy of the cluster's resources is two files in its state, `raft/log.redb` and
`raft/snapshot.json`, each saying its format, 1 or 2 (a file from before the number is 1).
Format 2 keeps when each resource was first made, apart from its history (which is trimmed): it
says which of two Services naming one host was there first. A state stays in format 1 until the
cluster's leader marks the store with one entry in the log, once every other node that keeps the
store has said, within the last half minute, that its kithd reads format 2. Until then the
leader's log names who it waits for and every node orders hosts as before; a node that is down,
or never updated, holds the mark back. From the entry on, a kithd from before refuses the
files. So:

1. Before updating, back the store up: stop a control node's kithd, copy the `raft/` directory
   of its state, and start it again.
2. Update one node at a time. Until the last is updated, any can be put back on its old kithd.
3. Half a minute or less after the last answers, the leader says `the store keeps from now on
   when each resource was first made`, and there is no going back short of that backup. A
   cluster of one node has nobody to wait for: it marks its store as soon as the new kithd
   starts.

What there was at the mark counts as made at the time of its oldest revision still kept: a
Service edited more than a hundred times before may count as newer than one that names its host.
Where that matters, keep the host with its Namespace's `hosts` before updating.

- A kithd reads every format up to its own: `crates/kith-store/fixtures/format-1` and `format-2`
  are a state as each format writes it. A build that changes what is written takes the next
  number, adds a fixture and keeps the old ones.
- A kithd refuses a newer format and leaves the files as they were. Going back to an older
  release is sure only while the state is in a format that release reads.
- Not numbered yet: what nodes say to each other, and the other files in a state. A node that
  passes a request on (`kith logs` of a replica elsewhere, `kith volume put` and `get`, `kith
  node passphrase`, a restore) now says who asked, and a node told nothing refuses it: mid-update,
  ask the node that has the thing.
- A field a newer kithd takes is unreadable to an older one: say `trust` on a Node or a Secret
  only once every node runs the kithd that knows it.

### Rolling a release through the cluster

```sh
sh ci/vm.sh --test rollout             # three nodes in QEMU take a release in turn
```

Sign the update with a key of your own, put the file where every node can fetch it (any web
server), and tell the cluster:

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

The signature is over the update's header, which names the SHA-256 of every piece, so a node
checks it before it writes a byte, and each piece as it writes it. Refused: a release without a
key, signed by another key, changed after signing, or of another version than it says. So the
address may be plain HTTP.

**Which keys a node takes.** Its own only, whatever key an OSRelease names. Give them before the
first release:

| Where | How |
| --- | --- |
| in the image | `KITH_RELEASE_KEY=KEY sh os/build.sh` (commas between several) writes `/etc/kith/release-keys` in the signed root |
| at install | `releaseKey: KEY` in the installer's answers; it goes on kithd's line as `--release-key` |
| to kithd | `--release-key KEY` (or `KITH_RELEASE_KEY`); on kith OS, ` -- --release-key KEY` at the end of the config partition's line |

A key on the config partition (the installer's `releaseKey` too) is taken only if the image holds
none or holds it: the partition is not signed, so it cannot name keys the image does not. Another
key comes by a release's handover (below) or a new image.

A key given to kithd counts first, then the keys a node keeps in its state (`os-release-keys`,
written when it first updates, and by a handover), then the image's. A node with none takes the
key of the first release it updates to and keeps it, and its Node's `status.os.releaseKeys` is
`none` (else `given`, `kept` or `image`). A node with no state partition keeps nothing: give it
its key. A release signed by any other key is refused, and so is one older than the node runs
unless the plan says `allowDowngrade: true`. A new image built with another key does not move
running nodes.

**Where the file comes from.** Only the address the release names: no redirect, no proxy. An
address on the node itself or its own networks (loopback, private, shared, link-local,
multicast) is refused. `--lan-releases` (`lanReleases: true` at install) allows the private
ranges for a release server on the LAN; then whoever may write an OSRelease can have every node
ask any host on them and read in the plan's status whether it answered. Give OSRelease and
UpdatePlan to nobody but the cluster's admin in any case: they decide when nodes restart.

**Handing over to other keys.** `handover` in a release names the keys that count once a node
runs it (its own among them, if it is to go on counting), signed by the release's key and by one
of the keys named:

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

A node that takes this release puts the keys aside, and they become its keys once it has started
on 1.0.2 and marked it good (the old ones stay in `os-release-keys.before`): a release signed by
a key left out is refused from then on, and until then an update that does not come up is tried
again under the old keys. A handover not signed by both, or naming no key or more than eight, is
the release refused, and the plan says why. The signatures cover the keys, the release's version
and the update's header, so a handover is good with that release alone. Hand over in a release
numbered higher than the last handover's, and leave the stanza out of the releases after it.

Put out a release without a handover first, and hand over in the next: only a node whose kithd
knows handovers takes one. Keep signing with the old key until every node runs a release that
hands over. A lost key cannot hand over, so hand over to two keys, and keep one where the other
is not.

**The floor.** A node keeps the newest version it ever ran well (`os-release-floor` in its
state, written when the slot is marked good) and takes no release under it, not after falling
back and not with `allowDowngrade: true`. So stolen admin credentials cannot walk a cluster back
to a release with a hole since mended. To go back on purpose, release the older system again
under a newer version, or remove `os-release-floor` at the node. A floor that cannot be read is
not "no floor": the node takes no update until the file says a version or is gone. A stick
ignores the floor.

**The order.** The node that leads picks who goes next: nodes that do not vote on the store
first, `maxUnavailable` at a time; then the voters, one at a time, each only while every other
voter is up, and itself last. A node whose turn it is fetches the file, writes its other slot
and restarts. Every node says what it runs in its Node's status (`os.version`, `os.slot`); the
plan's status says where the rollout is:

```
status:
  phase: Progressing      # or Done, Waiting (outside its windows, no such release), Paused
  nodes: { n2: done, n3: updating }
```

`Paused`, with a `reason`, means a node did not take the release: it refused the file, or the
boot loader gave up after three tries and it is back on its old system (`os.failed` in its
Node's status). Nobody else is given that release until the OSRelease is changed or the plan
names another, and then it starts over. `paused: true` stops it by hand (a node already told to
go finishes). While a voting node is away no other is restarted. A node told to update that says
nothing for fifteen minutes counts as failed. `drain` moves nothing already running;
`waitForIdleSeats` does nothing yet.

### Installing on a machine

```sh
sh os/build.sh                         # also writes target/os/kith-os-installer.raw (460 MB)
sh ci/vm.sh --test install             # the installer in QEMU, onto disks that are files
```

**The installer erases the disk it is given.** Nothing in this repository starts it on a real
machine (the test attaches files as disks to VMs): that is your decision, machine by machine.

Write `kith-os-installer.raw` to a USB stick (`dd if=kith-os-installer.raw of=/dev/sdX`), or
attach it to a VM as its first disk, and start the machine from it (UEFI). It is kith OS started
with `kith.install`: it serves nothing, and asks on the screen and the serial line alike:

```
This machine's disks:
  nvme0n1 (256.1 GB, Samsung SSD 970, serial S4EWNX0R123456)
  sda (2000.4 GB, WDC WD20EZRZ, serial WD-WCC4M1234567)
Install kith OS on which (its name, or serial:X)?
The node's name (empty: one made from its network card's address)?
Its address, as 10.0.0.5/24,10.0.0.1 (empty: ask the network)?
Join a cluster? The address of one of its nodes, as 10.0.0.7:7443 (empty: start a new cluster)
The join token (`kith node token` there)?
Everything on nvme0n1 (256.1 GB, Samsung SSD 970, serial S4EWNX0R123456) will be erased. Type its name again to go on:
```

The disk it was started from is never listed. A removable disk is installed on when named, but
`only` never means one. The disk's size is read again just before it is written, and a disk of
another size, or a disk named by serial that now gives another, writes nothing; nor does a
name not typed twice the same. It then copies kith OS to
the disk, reads it back to check, and powers off: take the stick out and start it.

On a screen with 32 bits a pixel (the console's framebuffer), each question is also drawn in the
look of the [installer's page](../install.html): the install's steps as stops on a rail, the one
being asked in blue, on paper. The answers are still typed, one line each, as above, and the text
stays on the serial line. An encrypted install's recovery key is shown on the screen too, and that
screen holds until a key is pressed, then clears; the key is written to the serial line as before,
and to no log or kernel ring.

Without anyone there, put the answers on the stick as `kith-install.yaml` on its first partition
(FAT), or at a URL on the kernel command line (`kith.install=https://10.0.0.2/alpha.yaml`; a
hypervisor gives it as the SMBIOS string `io.systemd.stub.kernel-cmdline-extra=`). Over plain
`http` whoever sits between the machine and the URL could change the answers (the disk, the join
token, the release key), so the URL carries their digest:
`kith.install=http://10.0.2.2/alpha.yaml#sha256=HEX`, where HEX is what `sha256sum alpha.yaml`
prints. The installer refuses plain `http` without that pin, and answers that do not hash to it.
`https` needs no pin.

```yaml
disk: "serial:S4EWNX0R123456"  # or nvme0n1, or `only`: the one disk of a machine that has one, not removable
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

Then nothing is asked or confirmed: a stick with answers erases the disk they name in whatever
machine it starts. A disk that is not there, `only` on a machine with several, or an unknown
field stops it with the reason on the console and nothing written. [The installer's
page](../install.html) is a form that writes this file in your browser, and checks each answer as
you type.

A kernel's name for a disk (`sda`, `nvme0n1`) can change with the order the disks are found
in; its serial does not. `serial:` names the disk by what the disk itself reports (NVMe,
virtio, SCSI and SATA disks), as listed above, here or at the console: no disk with it, or two,
stops the installer the same way. Two can: a USB case that gives every disk in it one serial, or
an NVMe drive with several namespaces, which all give their controller's. Name such a disk by
its name.

What it was told goes into a small `config` partition of the new disk, which the node reads at
every start as more of its kernel command line: name, address, and kithd's arguments (`--listen
0.0.0.0:7443`, and `--claim` for a new cluster or `--join` with the token). A node that starts a
cluster [offers a claim on its console](access.md#who-may-do-what).

The image's state partition is 32 MB. At its first start on a disk, and whenever the disk was
made longer since, it and its file system grow to the end of the disk (`the state partition now
ends where its disk does: 228936 MB`). `kith.grow=off` keeps the disk as it is, with room for
almost nothing: a large image's first pull fails with `No space left`.

### Installing from the network

A node installs the machines beside it: told their network cards' addresses, it answers those
machines when they start from the network and hands each the installer once; the machine
installs kith OS on its disk and joins the node's cluster. The network's DHCP needs no change.

```sh
sh os/build.sh                         # also writes kith-netboot.efi
kith node netboot --image target/os/kith-netboot.efi --mac 52:54:00:12:34:56 --mac 52:54:00:12:34:57
kith node netboot                      # is it on, and which machines have the installer
kith node netboot --off
sh ci/vm.sh --test netboot             # the same, in QEMU, on a disk that is a file
```

Then set each machine to start from the network (PXE, IPv4) once, or first in its boot order: a
machine that has the installer is not answered again and goes on to its disk. **Everything on
that disk is lost**, and nobody is asked at the machine: name only cards of machines you mean to
erase. `--disk only` (the default) installs on a machine's one disk and refuses a machine with
several; `--disk nvme0n1` names it. Netboot turns itself off after `--minutes` (30; at most 60),
when the node restarts, or with `--off`.

The node must be the one that started the cluster (it holds the CA, which makes the join tokens)
and run with `--listen`. An Identity that may apply Nodes, Roles and RoleBindings sends the same
over TLS (`GET` says where it stands, `DELETE` turns it off):

```sh
curl --cacert ca.pem --cert cert.pem --key key.pem --data-binary @target/os/kith-netboot.efi \
    -X PUT 'https://NODE:7443/v1/netboot?macs=52:54:00:12:34:56,52:54:00:12:34:57&minutes=30&disk=only'
```

The boot file goes over TFTP, unencrypted and unsigned, with the machine's join token in it.
Anyone on that network segment who claims a named card's address while netboot is on gets that
token (it lets one node join, for an hour), and can answer network boots faster than the node:
use it on a network you trust, for as short as it takes. Machines must start by UEFI on x86-64
and have 1 GB of memory. UEFI HTTP boot is not answered yet.

### Installing on a rented machine

A machine that cannot start from a stick but runs some Linux you can log in to as root is
installed from that system: `os/vps.sh` loads kith OS's kernel with the installer and the image
in a memory disk and starts it in place of the running kernel (kexec). **The disk named is
erased, the system that ran with it**, and the machine restarts as a kith OS node. You run it,
on that machine; nothing here does.

```sh
sh os/build.sh                         # also writes vmlinuz, kith-install.cpio.zst and vps.sh
scp target/os/vmlinuz target/os/kith-install.cpio.zst target/os/vps.sh root@machine:
scp answers.yaml root@machine:
ssh root@machine sh vps.sh --answers answers.yaml --erase vda
sh ci/vm.sh --test vps                 # the same, in QEMU, on a disk that is a file
```

`answers.yaml` is [the installer's](#installing-on-a-machine), with the disk by its name (`lsblk
-d` shows them). Rented machines mostly have a fixed address and no DHCP: give `ip:` the address
and gateway the machine has now (`ip addr`, `ip route`), or it comes back with no network and no
way in. `--erase` says the disk's name a second time; without it the script asks.

**Have another way in ready** (the provider's console or rescue system): once the installer's
kernel starts, the old system and your login are gone. If the installer refuses the answers the
old system comes back, its disk untouched; if the disk was already being written, or the node
comes up with a wrong address, the console is all there is. The kernel has drivers for virtio,
NVMe and AHCI disks and for virtio, Intel (e1000, e1000e, igb), Realtek r8169 and Broadcom tg3
and bnx2 cards, none for Xen, Hyper-V, VMware or AWS ENA: there it has no network.

The script refuses, with nothing done, a machine that starts by BIOS (`ls /sys/firmware/efi`
tells), one with under 1 GB of memory, one without `kexec` or `cpio`, and a disk that is not
there. A cloud that takes disk images takes `kith-os.raw` or `kith-os.qcow2`.

### Encrypted state

A node's state partition (its certificates, the store, Secrets, volumes) can be kept under
dm-crypt, with the key not on the machine: the cluster holds it. At each start the node brings
its network up, asks the nodes it knows for its key and only then opens its state. A disk taken
out of its cluster, thrown away, or sent back under warranty opens for nobody. It is chosen when
the machine is installed: `encrypt: true` in the [installer's
answers](#installing-on-a-machine), or `kith node netboot --encrypt`.

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

`lock` is for a machine that is lost or about to leave the house: a locked node that still runs
restarts within moments and waits. `wipe` cannot be undone: the cluster no longer holds the key,
and the node, if it still runs, erases what it would need to ask for it and powers off. Every
control node then snapshots the store and drops its log up to the wipe (SECURITY.md says what
stays).

**The recovery key.** The installer shows it once, at the console, when it is done (32 digits in
groups of four): write it down. Typed at a waiting machine's console, it opens the state where
no cluster answers: a laptop away from home, or a cluster whose nodes were all off at once. It
opens a locked node too; only `wipe` of a running node, or a duress code, ends that.

An install nobody watched (from a URL, or the network) has a recovery key nobody saw. `kith node
recovery beta` has beta, while it runs, make a new one and show it this once (kept nowhere); the
old one opens beta no more. If the command fails, run it again: the old key may be gone. While
nobody was shown a node's recovery key, `kith get node` and the web UI say so; `kith get NodeKey
beta` says `recoverySeen: true` once it was.

**A duress code.** For whoever is made to open a node. `kith node duress beta` makes one and
shows it this once, 32 digits like a recovery key. Typed at beta's console while it waits for
its key, it erases beta's lock record (the disk's own secret, and with it what the recovery key
and a passphrase opened) and, when a node answers, has the cluster forget beta's key, as `wipe`
does. From then on nothing typed opens beta, the recovery key included: there is no way back.
Codes are made by kith, never chosen; `--off` takes one away. A code works at a node once that
node, running, has heard of it (`kith get nodekey beta` says `duress: true`): one that was off
when it was made takes it for a wrong key.

`kith node duress --all` makes one code for the whole cluster. Typed at the waiting console of
any encrypted node, it does to that node what its own code does, and has the cluster forget the
key of every other node under it. Those nodes run on, drop their TPM seal and passphrase, and
open with their own recovery keys alone until `kith node unlock NAME` has the cluster hold
NAME's key again. A node that joins later is not under it, and it is not made while a node has a
recovery key nobody was shown.

A duress code does not reach a disk copied beforehand: with its recovery key or a passphrase it
had, it still opens, and until a node of the cluster has heard the code such a copy on the
cluster's network is still handed its key (`kith node wipe` it from a node you can reach as
well). Flash may keep old blocks: the record is written over with zeros, and no more is
promised. The record and the request to the cluster show that a code exists (not what it is).
Whoever has the code and can reach a node's port can have the cluster forget without being at
any console: keep a code as you keep a recovery key.

**The machine's own TPM.** `kith node seal beta` lets beta keep its key itself, sealed to its
TPM and to the system it runs: it then opens its state at start with no node asked, which is
what a laptop away from home needs. The TPM gives the key only while PCRs 0, 4, 7, 9, 12 and 15
(SHA-256) stand as they stood when it was sealed:

| PCR | Holds |
| --- | --- |
| 0 | the firmware |
| 4 | what it started: the boot loader and kith OS's boot file, with the kernel and the command line that names the system image by its hash |
| 7 | whether Secure Boot is on and whose keys it trusts |
| 9, 12 | a command line or an initramfs given from outside the boot file |
| 15 | what the node's config partition says (name, addresses, kithd's arguments), which no firmware measures and kithd does itself before it asks for the key |

Started with anything else, the node is refused the key, asks the cluster as before and, once
open, seals again: an update, or new firmware, costs one start that needs the cluster or the
recovery key. (kith OS's boot file is not signed for Secure Boot: where that is off, PCR 7 says
so and no more, and a changed boot file is refused the key by PCR 4.) `kith get NodeKey beta`
says whether the key is sealed, or why not. `--off` takes it back, and a locked or wiped node
drops its seal.

What the seal does not cover: a machine taken whole and started as it is opens its state by
itself, and no lock reaches it until it hears its cluster again. Nor a system taken while it
runs, nor a machine with no TPM. The key crosses the TPM chip's bus encrypted, so probing the
chip's pins reads nothing; but someone on the bus when the seal was made, or who resets the TPM
and replays an allowed start's measurements, can still get it (SECURITY.md). It has run against
a software TPM only, never on a real one.

**A passphrase.** For a machine with no TPM, or whose owner will not have the machine alone be
enough: `kith node passphrase beta` asks for one (eight characters or more, ASCII) and gives it
to beta over the cluster's TLS from any node, which keeps none of it. Beta then takes it at its
console where it takes the recovery key. `kith get NodeKey beta` says `passphrase: true`; giving
another replaces it, and `--off` takes it away. The key is then on the node's disk again, wrapped
under a key drawn from the passphrase (Argon2id): whoever has the disk can try passphrases on
machines of their own, so a short or guessable one is no protection, and the recovery key's 128
random bits no longer stand between a taken disk and its state. A locked node drops its
passphrase when it hears of the lock; one that was off did not. It is another way in, not a
second lock.

**The TPM and a PIN.** `kith node pin beta --untried-tpm` asks for a PIN (6 to 32 digits), twice
and unseen, and gives it to beta's own kithd (its socket, or `POST /v1/lock/beta/pin` at beta's
own address); another node refuses it. From then on beta's TPM opens its state only with that
PIN typed at its console. A copy of the disk opens on no other machine, and on this one only
while its system is the one sealed to. The TPM counts each wrong PIN: beta refuses a PIN that
this TPM's lockout would let be guessed one time in a hundred in a year (it names the shortest
it takes), for random digits only: a date or 123456 is among the first guesses. Setting a PIN
takes the TPM's lockout authorization where it is empty, kept in beta's encrypted state alone;
if that state is lost, only clearing the TPM in the firmware's settings gives it back. After too
many wrong PINs the TPM refuses every PIN for a while; the recovery key and the cluster's key
still open. `--off` takes it away, and so does an update that moves the PCRs (until it is set
again) or locking, then unlocking, beta. It has run against a software TPM only, and is refused
without `--untried-tpm` (a word, not a lock) until the checklist in docs/adr-unlock.md ("On
hardware: the owner's checklist") has run on the machine.

What is and is not protected:

- The cluster holds the key wrapped with a secret only the node's disk has (a `NodeKey` in the
  store): neither the store, nor a backup of it, nor the disk alone opens the state. The disk
  together with a cluster that still hands the key out does, which is what `lock` is for: a
  stolen machine that is not locked, started on the cluster's own network, is handed its key.
- Until another node holds the key it stays on the node's disk: a cluster's first node is not
  protected until a second has joined.
- Whoever may apply NodeKeys can lock and wipe, have a node make a new recovery key (and is
  shown it), and make duress codes.
- The config partition (name, address, the spent join token) and the system are not encrypted.

Not yet: a passphrase and the TPM both asked for, the cluster's key and the TPM both asked for,
a keyboard layout at the console, encrypting a node not installed that way, the disk's secret
kept in the TPM, a duress code that opens a decoy.

### Not in kith OS yet

A CD image, starting by BIOS, a watchdog for a slot that hangs without stopping, Secure Boot
(the image is not signed), drivers for Wi-Fi and sound, graphics but by a [spec](#a-node-that-needs-more-a-spec), a card plugged in later, IPv6
addresses from the network, arm64.
