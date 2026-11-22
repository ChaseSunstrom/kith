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
  `kith.ip=10.0.0.5/24,10.0.0.1` (address, gateway) and `kith.dns=9.9.9.9`. A card that comes
  later (plugged in, or its driver loaded after boot) is found within 5 seconds and asks the
  same way, but its lease sets only its own address and the route to its own network: the
  default route, the name servers and the time servers it names are used only if no card that
  is there gave the node one (a card unplugged takes its part with it, so the same card
  plugged in again may give it anew), so a card put on another wire cannot take them over.
  Its network must be one of a private block (10/8, 172.16/12, 192.168/16, 100.64/10,
  169.254/16) that overlaps no route the node has; a lease of another is refused and said so.
  The card that had `kith.ip`, plugged in again, gets that address, not a lease. A veth,
  bridge or tunnel that kithd makes is never asked. (The kernel has PCIe hot-plug, so a card
  put in a slot of a running machine appears; the IOMMU is off by default, so a PCIe or
  ExpressCard device plugged into a running machine can read all its memory.) IPv6 on a link is the
  kernel's (router advertisements); there is no DHCPv6;
- keeps the time: a machine has no clock battery to trust, so after the network is up kithd asks
  an SNTP server for the time at start and every hour, and sets the clock when it is more than
  two seconds off. The server is the one you name, `kith.ntp=ADDRESS[:PORT]` (the only one asked
  when set: what a network says is whatever a machine on it sent), or for every node at once the
  Cluster's `spec.ntp` (a node's own `kith.ntp` wins over it; a change is asked within a minute);
  where none is named, the one
  DHCP names (option 42), then the gateway. The cluster's leader (a worker asks its control node)
  is asked too, over the cluster's own TLS, and its time wins over a server over two seconds
  from it, as long as the operator's time server (`kith.ntp` or `spec.ntp`; a network's never)
  set the leader's own clock: its answer says so (`kith-clock: server`). A leader whose clock no
  such server set (one restarted hours off, on a network with no server) is one more source,
  held to the ten seconds below, by a node the operator's server set and by a voter most voters
  that answered agree with (each following voter asks the others at each check; three at least
  must answer); the status says why its step was not taken. With neither, it is followed as
  before (a worker follows its control node so): a closed network with no server still keeps
  one time. The server you name is followed alone, whatever the step. Before the clock was ever
  set (it reads before 2026) the first answer is enough; after that a network's word alone moves
  it by ten seconds in all (its steps together, until the leader agrees), and more needs the
  leader within a second of the same time (servers a network names do not vouch for each
  other), or it is left and the status says so; a node that runs alone for long should set
  `kith.ntp`. A node whose clock is not yet set answers its peers' time
  question with a 503. Each Node's status says its `clock`: the server, the offset and whether it
  stepped it. A step is written to the hardware clock (the RTC, in UTC) too, so a restarted node
  boots with the time it had (not the first answer of a network alone, before the clock was ever
  set: only the server you name, the leader, or a server the leader agrees with); a write that
  fails is in the status as `rtcError` and in the log, and the step still counts. A node under the `hardened` policy does not set its clock, either of them: its
  status says the offset and the refusal;
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
| kernel | 6.18, 13 MB, from kernel.org's source at a pinned version and checksum (`os/kernel.config`): no modules, no initramfs; NVMe, SATA, USB and SD storage, the common wired cards, virtio, WireGuard, dm-verity, dm-crypt, KVM, the IOMMU drivers (Intel and AMD). The first build takes ten minutes or so |
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

`gpu-nvidia-pascal`, the nouveau driver and HDMI sound (HDA with its NVIDIA codec) built in, for
an NVIDIA card before Turing (GeForce GTX 10xx, Quadro Pxxx; `os/examples/gpu-nvidia-pascal.yaml`).
Nouveau's display and HDMI sound work on any card before Turing that it knows; the firmware it
brings (`nvidia/gp102` to `gp108`) gives 3D on a desktop Pascal card, GP102 to GP108. There is no
reclocking (the card stays at its boot clock) and no video decode under nouveau, and NVIDIA's own
driver is not part of kith OS. Most of that firmware is named again in linux-firmware's `WHENCE`
(`Link:` lines): `os/firmware.sh` makes the links a glob names, as copy-firmware.sh does, with the
files they point at, and refuses a link out of the tree, a cycle or a glob that names nothing. A
spec for it with `all` is refused (nouveau as modules and built in). Its first real use is a TV
seat: [a TV or kiosk seat](hardware.md#a-tv-or-kiosk-seat).

`vfio`, to prepare the kernel for handing a PCI card (a GPU, a USB controller) to a virtual
machine: the IOMMU switched on (Intel's, with interrupt remapping) and `vfio-pci` built in
(`os/examples/vfio.yaml`). That is all it does: binding a card to `vfio-pci`, and `vms` on kith
OS (there is no qemu in the image), come later. Every kith OS kernel, spec or not, has the
IOMMU drivers pinned in `os/kernel.config` (x86's default config already had them), Intel's
off by default as before: nothing on an installed node's command line can turn it on, so the
spec does. Measured: the plain kernel is byte for byte the one it was, 13,489,152 bytes, the
update 34,288,640 and the raw image the same 282 MiB, under its 300 MB budget; the `vfio`
spec's kernel is 13,558,784 bytes (+68 KiB, 69,632 bytes), its update 34,427,904. Booted in
QEMU with a virtual Intel IOMMU (`-machine q35,kernel-irqchip=split -device
intel-iommu,intremap=on`), the plain kernel reads the IOMMU's table and leaves it off, and the
`vfio` one says `DMAR: Intel(R) Virtualization Technology for Directed I/O`, `DMAR-IR: Enabled
IRQ remapping in x2apic mode` and `VFIO - User Level meta-driver version: 0.3`. Passing a real
card through has not been tried: that is on hardware.

A node can say which features it wants itself. kithd matches its PCI cards (`lspci -n` ids) against
the `# pci:` lines of `os/features/` and lists the features that match as `wants` in its Node status.
`kith node features` prints them as a spec, which builds that node's image:

```sh
kith node features n1 > n1.yaml
sh os/build.sh --spec n1.yaml --out target/os-n1
```

A node with no card a feature matches prints `features: []`; a node that runs no kith OS has no
`wants` and the command says so. Only PCI cards are matched. A feature with no `# pci:` line (a
card the catalogue does not list yet) is chosen by hand, as above. A line may give `vendor:*`
instead of a device id, which matches any display card (PCI class 03) of that vendor and not its
audio function, and only one that no feature names by its exact id: `all` has `10de:*`, so a node
with an NVIDIA display card no feature lists wants `all` (nouveau's driver is in it), while a
Pascal card (`10de:1c03`) wants `gpu-nvidia-pascal`, not `all`. A node that also has an AMD Phoenix
or a Pascal GPU and a card of another NVIDIA family (a Turing) wants `all` alone, which build.sh
would refuse with `gpu-amd-phoenix` or `gpu-nvidia-pascal` and whose modules cover those GPUs.

#### The `all` feature: drivers as signed modules

```sh
KITH_OS_VERSION=1.0.1+all sh os/build.sh --spec os/examples/all.yaml --out target/os-all
KITH_OS_SPEC=os/examples/all.yaml sh ci/vm.sh --test image   # boot it in QEMU
sh ci/vm.sh --test modules   # the same image: drivers load at start, on a device added, and a bad signature is refused
sh ci/vm.sh --test disk      # kith node disk add on a disk file, mounted after a restart and listed, removed; a file with a signature refused, another file left alone
```

For a node whose hardware is not known when the image is built, `features: [all]` turns on
kernel modules (`os/features/all.config`): GPUs (amdgpu, i915, xe, nouveau, and NVIDIA's open modules built beside them), sound (HDA and its
codecs, USB audio, Sound Open Firmware), Wi-Fi (iwlwifi, ath9k to ath12k, mt76, rtw88, rtw89)
and the network cards the plain kernel lacks. `firmware: [all]` is all of linux-firmware; a list
of paths there (`amdgpu/*`) is those files, and in both cases the files each module names
(`modinfo -F firmware`) are there too.

- **Signed, per kernel build.** The kernel makes a key of its own at the start of each kernel build (a tree cut short and gone on from has its old key removed first), signs
  every module with it as `modules_install` writes them, and builds the public half in;
  `CONFIG_MODULE_SIG_FORCE` refuses any other module. `build.sh` then deletes the key: the build
  fails if a `signing_key` or a `.pem` is left in the kernel's tree or in the root, and a
  failed build deletes it too. It checks one module's signature against the kernel's own key.
  So the modules of one build load only into that build's kernel, and the kernel of an `all`
  image is not the same bytes from one kernel build to the next (the plain one is). The
  kernel and its modules are cached by the hash of their config, so the key is made when
  they are built, not at each image build.
- **In the root, not the ESP.** `/lib/modules/VER` (with `modules.dep`, `modules.alias`,
  `modules.builtin` and `modules.builtin.modinfo`, so a loader knows what is built in) and
  `/lib/firmware` (with the links linux-firmware lists in `WHENCE`: a driver asks for
  `iwlwifi-cc-a0-77.ucode`, the file is `intel/iwlwifi/`) are in the squashfs under dm-verity,
  block by block like the rest. The ESP stays 64 MB; the root slots grow with the root, so a
  node installed from a plain image has slots too small to be updated to this one.
- **Sizes** (the plain image is 295,715,328 bytes, as before, and its kernel the same bytes):
  kernel 13 MB; modules 109 MB (174 of them) and firmware 2,090 MB, both before compression; the
  root 1,016 MB squashfs; the raw disk image 2,794 MB (1,039 MB as qcow2); the update file
  1,051 MB. `build.sh --check` allows the `all` image 4 GB, not the plain 300 MB. The
  installer's memory disk carries the payload and not the modules.
- **NVIDIA's open modules.** `nvidia`, `nvidia-modeset`, `nvidia-uvm` and `nvidia-drm` (not
  `nvidia-peermem`) are built out of tree in the same build, against this kernel, from NVIDIA's
  `open-gpu-kernel-modules` at a version pinned in `build.sh` with its sha256 (a file that is
  not the pinned one is refused). They are signed with the same throwaway key before it is
  deleted, and installed in `/lib/modules/VER/extra`, where `modules.alias` names `nvidia` for
  NVIDIA's cards. They add about 32 MB of modules (`nvidia.ko` 24 MB, `nvidia-modeset` 4 MB,
  `nvidia-uvm` 3.5 MB, `nvidia-drm` 0.25 MB, stripped) and, as the GSP firmware the driver asks
  for (`gsp_ga10x.bin`, `gsp_tu10x.bin`, taken from NVIDIA's release file, which is not
  linux-firmware's), 98 MB in `/lib/firmware/nvidia/VERSION`. Only the kernel side is here: the
  pod brings the CUDA userspace (libraries, `nvidia-smi`) and its own driver version must be the
  same as the modules'. kithd loads `nvidia` before `nouveau` for the same card (nouveau stays
  built, with no blacklist); a card before Turing, which the open modules refuse, goes to
  nouveau. A spec naming both `all` and `gpu-amd-phoenix` is refused (the same driver, built in
  there).

A cluster runs plain and GPU nodes side by side: sign each image's update as its own
`OSRelease` and roll each with its own `UpdatePlan`, the GPU one with a `selector` on a label
those nodes carry (`gpu: amd`, put on the Node as [any label is](cluster.md#where-work-runs): kithd does not
set it from the GPU it finds yet; see [Rolling a release through the
cluster](#rolling-a-release-through-the-cluster)). A plain release given to a GPU node takes its
driver away until the next GPU one.

#### A card put in later, or swapped

The plain image has no `/lib/modules`, and kithd then loads nothing. An image that has one
(a spec's kernel built with loadable modules, `modules.alias` and `modules.dep` from
`depmod` beside them) gets its drivers from kithd, the way udev does: before it names the node and brings the
network up (the network card's driver may be one), kithd matches the `modalias` of every
device under `/sys/devices` to `modules.alias` and loads what matches, what it needs first
(`finit_module`), and then, on a thread, does the same for each kernel uevent that adds a
device. A card swapped for another of a kind
the image has a driver for needs no restart. Modules in `modules.builtin` or already in
`/proc/modules` are not loaded; each is tried once, and a failure (a bad signature, a
missing file) is one console line, never an end. Not supported: module parameters,
`modprobe.d` (blacklists, options), soft dependencies. Compressed modules (`.ko.xz`,
`.zst`) are loaded by the kernel itself, from 5.17, if it was built to.

#### Modules on the state partition: `# modules: state`

```sh
sh ci/vm.sh --test modules-state   # the image loads virtio-input from it; ten tampered disks load nothing
```

A feature whose first line is `# modules: state` (`os/features/modules-state-test.config` is the
test's) keeps its modules and the firmware they name out of the root. `build.sh` packs them into
`kith-modules.img` (squashfs, zstd) with a dm-verity tree (`kith-modules.img.verity`), and the
raw image's state partition carries both as `os/modules-a.img(.verity)`. The root, which the
UKI's verity hash covers, pins the tree's root hash, its salt and both sizes in
`/usr/share/kith/modules`, so the chain is the same as the root's: nothing on the state
partition is trusted for what it says, only for its bytes, and those are checked against a hash
the root holds. After the state mounts, kithd takes the slot's image (`kith.slot` on the command
line), opens it without following a link and with the pinned size, attaches it read-only to
loop devices, maps dm-verity with the pinned hash, mounts the squashfs at `/run/kith/modules`
(read-only, nosuid, nodev), points `firmware_class.path` at its `lib/firmware`, and runs the
loader above over its `lib/modules`. A missing, altered, longer, linked or other build's image
loads nothing: one console line (`kithd: init: modules: ...`) and the Node's status (`modules`)
say why, and the node serves as before. The disk and the network come up before the state, so
`build.sh` refuses a block or network driver as a module in such a spec, at the config and
again over the modules built, and a `.ko` in the root fails the build. Not here: the update path
(an update's slot-b image), NVIDIA's modules.
### Secure Boot: an image signed with your own key

```sh
mkdir -m 700 ~/kith-sb && openssl req -new -x509 -newkey rsa:3072 -nodes -days 3650 -subj '/CN=my kith db/' -keyout ~/kith-sb/db.key -out ~/kith-sb/db.crt
sh os/build.sh --secure-boot ~/kith-sb   # needs sbsign and sbverify (sbsigntools)
```

`--secure-boot KEYDIR` signs systemd-boot (the `BOOTX64.EFI` of both disks) and every kernel
image (slot a and b, so the update's too, and the installer's) with `KEYDIR/db.key` and
`KEYDIR/db.crt`, then checks each against the certificate before it goes into an ESP or the
update (`sh ci/secure-boot-check.sh` does this with a throwaway key, and builds twice to show the same bytes; it needs sbsign, sbverify, mcopy and openssl, and exits 3 without them). The certificate is part of the update's kernel digest, so an update that only signs, or changes the key, is a full one, not a kithd-only one. A firmware that has that certificate as a `db` entry then checks the one file that
carries the root's hash. Without sbsign the build stops with exit 3 (this machine cannot build
it), and a directory without both files is refused (exit 2). The key is only read: it is
never copied into an image, and keep it outside the repo. The signature is not part of what the
TPM measures into PCR 4 (the Authenticode hash leaves it out), so sealing to PCR 4 is as before.

Not done yet: enrolling the certificate. The installer does not write it into the firmware, so
until it does you enroll it by hand (your firmware's setup, or `sbctl`/`virt-fw-vars` on the
variable store); and the netboot image is not signed. Until then an image built with
`--secure-boot` is the same as one without on a firmware with Secure Boot off.

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
`raft/snapshot.json`, each saying its format, 1, 2 or 3 (a file from before the number is 1).
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
4. Format 3 comes the same way, once every node's kithd says it reads format 3: the leader
   says `the store keeps from now on the nonces of signed entries`. It is format 2 with a book
   of the nonces of signed writes in the log, kept so that each is run once; a kithd that
   reads format 3 refuses every such write for now, and none is written yet.

What there was at the mark counts as made at the time of its oldest revision still kept: a
Service edited more than a hundred times before may count as newer than one that names its host.
Where that matters, keep the host with its Namespace's `hosts` before updating.

- A kithd reads every format up to its own: `crates/kith-store/fixtures/format-1`, `format-2` and
  `format-3` are a state as each format writes it. A build that changes what is written takes the next
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
  drain: true                      # drain each node (`kith node drain`) before it restarts
  drainSeconds: 300                # how long to wait for what moves to run elsewhere (300 unless said; 3600 at most)
  waitForIdleSeats: true           # a node whose Seat is active or fullscreen waits (idleWaitSeconds, 3600 unless said; 86400 at most)
```

The signature is over the update's header, which names the SHA-256 of every piece, so a node
checks it before it writes a byte, and each piece as it writes it. Refused: a release without a
key, signed by another key, changed after signing, or of another version than it says. So the
address may be plain HTTP.

The header also carries a `kithd` object: the digests of kithd, of the boot file but for the root's
hash, and of the root but for kithd and its os-release. It is signed with the rest. Before it writes,
a node reads it against the header kept for the system it runs, and works out whether only kithd
differs (the kernel and the rest of the root are the same) or the update is a full one. A header
without it, or no kept header, is a full update, and the log says which part differed.

Where only kithd differs, the node does not restart. It writes the other slot as ever, mounts its
root for a moment, and copies the new kithd out of it into `/run/kith/bin`, a tmpfs of its own that
is root-only and mounted exec, nosuid and nodev (`/run` stays noexec). It stages the file only if its
SHA-256 is the signed digest. Then kithd ends with a hand-over, and the machine's first process starts
the staged kithd. Every container keeps running and the new kithd takes them back by their record, as
at any restart of kithd. A staged kithd that fails within a minute is given up for the one that was
running; that end counts toward the ten failures in a minute, a hand-over does not. The root still
says the old version (it is read-only), so the node says the new one from a note in `/run` that holds
only for the kithd it names: a reboot starts the slot that was written, which has the new release whole.
`sh ci/vm.sh --test handover` (it runs at the end of `--test update`) takes a release that differs in
kithd alone and sees the machine keep its boot id and a pod its process, then takes one with another
kernel and sees the restart into the other slot. All on disk files.

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

**Where the file comes from.** The address the release names, or where it redirects to (up to 5
redirects, as a GitHub release's download address does to its asset host): each address is
checked and held as the first is, nothing is sent but the request, https never goes back to
http, and a loop or a user and password in an address is refused. No proxy. An
address on the node itself or its own networks (loopback, private, shared, link-local,
multicast) is refused. `--lan-releases` (`lanReleases: true` at install) allows the private
ranges for a release server on the LAN; then whoever may write an OSRelease can have every node
ask any host on them and read in the plan's status whether it answered. Give OSRelease and
UpdatePlan to nobody but the cluster's admin in any case: they decide when nodes restart. A
release agent for the canary ring is the exception a Role can name: `{ kinds: [OSRelease],
verbs: [get, list, apply, delete], names: [canary] }` (see Access), with the plan `canary`
(its selector is the ring) kept by the admin: the agent cannot write any UpdatePlan or any
other release, and a changed release `canary` rolls that plan again.

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
  phase: Progressing      # or Draining, Done, Waiting (outside its windows, no such release), Paused
  nodes: { n2: done, n3: updating, n4: draining }
```

`Paused`, with a `reason`, means a node did not take the release: it refused the file, or the
boot loader gave up after three tries and it is back on its old system (`os.failed` in its
Node's status). Nobody else is given that release until the OSRelease is changed or the plan
names another, and then it starts over. `paused: true` stops it by hand (a node already told to
go finishes). While a voting node is away no other is restarted. A node told to update that says
nothing for fifteen minutes counts as failed. With `waitForIdleSeats: true` a node is picked only
while its Seats last said `idle` (a Seat that has said nothing, or has no holder, is idle, and so is a
node with no Seat); one that says `active` or `fullscreen` is passed over and the plan's `reason`
names the Seat and that it waits. A seat that stays busy lets the node go after `idleWaitSeconds`
(3600 unless said, 86400 at most), and the `reason` says so. `idleWaitSeconds` counts continuous
waiting while the plan is picking: a pause, a closed window or a node that drops out (unreachable, off
the selector, its seat idle for a moment) starts the count again. Unset or false, a Seat is not
looked at. A kithd older than this one, as leader during a mixed-version update, ignores the flag.

With `drain: true` a node picked is drained as `kith node drain` does it: it is cordoned, the
`kith.dev/drain` taint goes on, and what the drain plan says can move starts elsewhere. The plan
says `Draining` (and which node, and how many replicas it waits for) and tells the node to restart only
once each of those is running on another node, or none moves. A replica the plan says stays (pinned
to the node, one a node selector puts on every node, a Job) holds nothing. A node whose replicas
never start elsewhere is let go after `drainSeconds` (300 unless said, and at most 3600), and the
plan's `reason` says how many. The plan never names a replica (it is read by whoever may read UpdatePlans, and a
replica's name belongs to its namespace): `kith node drain NODE --dry-run` names the ones you
may read. When the node is done, or the plan is paused, changed or no longer drains, or its
OSRelease is deleted (or `release` names one that does not exist), or the node no longer matches
the `selector` (a label removed, say), the update's drain is lifted; a drain or cordon you put on
the node first is left as it was. A lift that did not take is asked for again until the node shows
no drain.

### Installing on a machine

```sh
sh os/build.sh                         # also writes target/os/kith-os-installer.raw (460 MB)
sh ci/vm.sh --test install             # the installer in QEMU, onto disks that are files
```

**The installer erases the disk it is given.** Nothing in this repository starts it on a real
machine (the test attaches files as disks to VMs): that is your decision, machine by machine.

Write `kith-os-installer.raw` to a USB stick (`dd if=kith-os-installer.raw of=/dev/sdX`), or
attach it to a VM as its first disk, and start the machine from it (UEFI). It is kith OS started
with `kith.install`: it serves nothing, and asks on the screen and the serial line alike. Its
root and verity tree are labelled `install-root` and `install-verity`, not `root-a`, so it starts
from the stick on a machine whose disk already has kith OS, and installs over it:

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

On a screen with 32 bits a pixel (the console's framebuffer), the whole install is drawn in the
look of the [installer's page](../install.html), whatever the answers' source (typed, a file on the
stick, a URL, or the network): each question, then the steps answered as stops on a rail, done one
by one with what was answered at each (never the join token), the disk's write as a bar that moves
with each percent (a sealed state's step after it), and an end screen that says the machine is
powering off (take the installer out, then start it from its disk), held a few seconds before it
does. Paper, the site's colours and font, the stop being worked at in blue. The kernel's own
messages are kept off the picture while it is drawn (the console's log level is turned down, and put
back when the picture is handed back), and a failure is written as text where it can be read. With
no such screen the install is text only, as before. The answers are still typed, one line each, as
above, and the text stays on the serial line. An encrypted install's recovery key is shown on the screen too. When the
answers were typed, that screen holds until a key is pressed, or for five minutes, then clears; an
install that was given its answers (from a file, a URL, or the network) does not stop for it. The
picture is cleared from the text console when the installer hands the screen back. The key is
written to the serial line as before, and to no log or kernel ring.

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
ntp: 10.0.0.1                 # a time server, ADDRESS or ADDRESS:PORT; the only one asked when set, and followed alone; without it DHCP's (four at most), then the gateway
join:                         # without it the node starts a new cluster
  address: 10.0.0.7:7443
  token: $TOKEN
encrypt: true                 # its state under a key the cluster holds: see "Encrypted state"
releaseKey: $KEY              # kith OS releases signed by this key only: see "Rolling a release"
lanReleases: true             # releases may come from a server on the node's private ranges
mesh: true                    # starts with its WireGuard mesh on (`--mesh`); see "The mesh" in the cluster guide
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

### As a guest on Proxmox VE

Tried in QEMU with the settings Proxmox gives a VM, not on Proxmox itself. Make a VM with:

- **BIOS: OVMF (UEFI)**, and untick **Pre-Enroll keys** on its EFI disk: the boot file is not
  signed for Secure Boot, so a firmware that enrolled Microsoft's keys refuses it.
- **Disks:** the installer image (`kith-os-installer.raw`, imported with `qm importdisk`) as
  the first disk, and a second disk for the node, 8 GB or more. The installer never lists the disk
  it started from, so the second is the one to name. Its bus can be VirtIO Block, SCSI (VirtIO
  SCSI) or SATA; the serial Proxmox gives each disk works with `serial:`. Detach the installer
  disk after it powers off.
- **CPU: `host`**, as `ci/vm.sh` runs it. A VM with the default `kvm64` has not been tried.
- **Network:** a VirtIO NIC.

The node grows its state partition to the end of the second disk at its first start, and again
after you make the disk longer in Proxmox (`qm resize`) and restart the VM.

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

The machine is installed with this node's release keys (as the node holds them when netboot is
turned on) and `--lan-releases`, if the node has them: it takes kith OS releases from the same
keys, not from the first release's. The answers hold 8 keys at most: a node with more, or with
keys it cannot read, does not turn netboot on and says which. A node started
with `--mesh` has the machine start with `mesh: true` as well. A node on the Cluster's
`spec.mesh` does not: the machine has no flag, so it follows the Cluster's switch once it has joined.

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
answers](#installing-on-a-machine), or `kith node netboot --encrypt`. A node installed plain can be
encrypted where it stands with `kith node encrypt` ([how, how long, and why an SSD keeps old plain
blocks](cluster.md#encrypting-a-node-that-was-installed-plain)); installing with `encrypt: true` is better.

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
sh ci/vm.sh --test blackout            # every node killed at once and started together: nothing typed
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
opens a locked node too; only `wipe` of a running node, or a duress code, ends that. A cluster
that must come back from a power cut with nobody there seals its control nodes instead: [When
every node was off](cluster.md#when-every-node-was-off).

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
a keyboard layout at the console, the disk's secret
kept in the TPM, a duress code that opens a decoy.

### A second disk for a node's data

A machine with a second disk can keep data on it, encrypted as a whole under a key kept in the
node's own state (so a node whose state is not encrypted adds none). Run these where kithd runs
(its own socket, as root): `NODE` is the node that kithd is.

```
kith node disk list NODE                   # the disks it has, and the ones it left alone
kith node disk add NODE SERIAL [--wipe] [--quick]
kith node disk remove NODE ID
```

- `list` shows each disk by its serial (and its id once it is a data disk). Nothing is taken
  that has not been added: a stick, a backup disk or the disk the system runs from is left alone.
- `add` names a disk by its **serial** (as `list` shows it), overwrites it through the
  encryption (a large disk takes hours; `--quick` discards its blocks instead, which is fast
  and shows which regions held data) and mounts it. The node mounts it again at every start. It
  refuses a disk that holds a partition table, a filesystem or any data unless given `--wipe`,
  and always the disk the system runs from.
- `remove` takes the disk's id: its header is zeroed and its key forgotten, so what it holds can
  no longer be read (the disk is not erased). A disk that is not in the machine any more has its
  entry and key forgotten. One in use is refused.
- Who may ask: whoever may apply (`add`), delete (`remove`) or get (`list`) a NodeKey. Each add and
  remove, done or refused, is written to the audit log with who asked and the serial; an add
  and a remove are written again when they begin, since they take long. Never a key.

The design is in [adr-second-disk.md](../adr-second-disk.md).

### Not in kith OS yet

A CD image, starting by BIOS, a watchdog for a slot that hangs without stopping, Secure Boot
(the image is not signed), drivers for Wi-Fi and sound, graphics but by a [spec](#a-node-that-needs-more-a-spec), arm64.
