# Hardware

Every node of a cluster lists its own hardware from `/sys` and keeps one `Device`
per piece of it in the store, applied when it turns up and deleted when it is
gone (a rescan every half minute, not hot-plug events: a plugged device shows
within 30 seconds). `kith get device` lists them.

- A `Device` is named `NODE-CLASS-NAME` (lower case, cut to 63 characters), and its
  `spec` has the `node`, the `class` (`gpu`, `display`, `input`, `audio`, `usb`
  or `camera`) and the device node as `path` (`/dev/dri/card0`, `/dev/input/event3`,
  `/dev/snd/controlC0`, `/dev/video0`, `/dev/bus/usb/001/004`; a `display` has none).
- GPUs are the DRM cards; a `display` is a connector with a screen on it, an `input`
  an `event` device, `audio` a sound card, `camera` a video4linux device, and `usb`
  a USB device that is not a hub.
- A card on NVIDIA's own driver also has `nodes`: the device nodes CUDA and the
  driver's OpenGL and Vulkan open beside the card's (`/dev/nvidiactl`, `/dev/nvidia-uvm`,
  `/dev/nvidia-uvm-tools`, `/dev/nvidia-modeset`, and its own `/dev/nvidiaN`, by the
  number the driver gives it in `/proc/driver/nvidia`). Only those that are there are
  listed: the driver's `nvidia-modprobe` or udev makes them, kith does not. A card the
  driver holds with no DRM card (a compute card, or the driver without modesetting) is
  a `gpu` named by its PCI address, with `/dev/nvidiaN` as its path. Every node but
  `nvidiaN` is one for all the node's cards: a container holding one card can ask the
  driver about the others. **Not tried on a real card**: this is read from the driver's
  documentation and tested against a made-up `/sys` and `/proc`, and kith OS ships no
  NVIDIA module.
- Labels: `kith.dev/node`, `class` and `kith.dev/discovered: "true"` on all; GPUs and
  USB devices also `vendor` and `model` (the hex ids, so `1002` and `73bf`), a GPU
  `driver` and, where its driver says, `vram` in bytes; inputs and sound cards `model`
  (letters, digits, `.`, `_` and `-`). A selector can name them.
- `NODE-seat0` is a `Seat` naming the node's displays, inputs, sound cards and GPUs; a
  node with none has no seat.
- Only what carries `kith.dev/discovered` and the node's name is kept in step: it
  is rewritten if you edit it and deleted when the hardware goes. A `Device` or `Seat`
  you wrote yourself is never changed or deleted. A machine without `/sys/class`
  (some containers) has no devices, and kithd says so once.
- A name belongs to the node with the longest name that starts it, so do not name a
  node as another node's name and a class (`alpha` and `alpha-gpu`): `alpha`'s GPUs
  would then go unlisted, and kithd on `alpha` says so in its log. A join under a
  name that would take a Device already listed is refused: pick another `--name`.

### Claiming hardware

A workload holds hardware by naming `DeviceClaim`s (same namespace) in its template's
`deviceClaims`. A claim names one `seat`, or one `device`, or a `selector` over
`Device` labels, and says `access: exclusive` (the default) or `shared`:

```yaml
apiVersion: kith.dev/v1
kind: DeviceClaim
metadata: { name: render }
spec:
  selector: { class: gpu, kith.dev/node: n1 }
  access: exclusive
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: renderer }
spec:
  template:
    containers: [{ name: run, image: example/renderer }]
    deviceClaims: [render]
```

- The workload runs on the node of the `Device`s its claims come to, and only there.
  Claims that come to Devices of two nodes (a selector over a whole cluster) hold
  nothing: the status says so, and `kith.dev/node` in the selector fixes it.
- One workload holds a Device at a time, however many claims reach it. A second
  exclusive holder waits, and its `unschedulable` says `waiting for DeviceClaim render,
  held by Workload/default/renderer`; it takes over when the first is gone, and the first
  never loses it to one that came later. `shared` claims on one Device may have any number
  of holders, none of them beside an exclusive one. All replicas of one workload hold what
  it holds together.
- `kith get deviceclaim render -o yaml` shows `status.node`, `status.devices` and
  `status.holders`; a claim that comes to nothing has a `status.message` instead.
- **Who may claim what.** A `Device` or `Seat` is given to namespaces by its label
  `kith.dev/namespaces`, a comma-separated list (`default, desktop`). A claim in namespace
  N reaches it only if the label lists N, or N is `kith-system`, the cluster's own. With no
  label, a `gpu` is open to every namespace, and every other `Device` (`input`, `audio`,
  `camera`, `display`, `usb`, `other`) and every `Seat` is `kith-system`'s alone. A seat
  claim, `access: client` included, is checked against the Seat's label, and against the
  label of each of its Devices that has one of its own: a labelled Device not given to N
  refuses it, and an unlabelled one follows the Seat's. A labelled `Device` or `Seat` whose
  hardware is gone is kept with its label, so it is given the same way when found again.
  The label is an admin's: `kith get seat NAME -o yaml`, add it under `metadata.labels`,
  `kith apply -f`. Discovery keeps it, and a worker cannot add, change or drop it. Taking
  it away refuses a claim at the next pass, and its `status.message` says why (`Seat X is
  not given to namespace N`). A `Device` or `Seat` made before this label had no label, so
  it is `kith-system`'s until one is set.
- **A share of a GPU's vram.** A `shared` claim may say `share: { vram: 512Mi }`: what it
  asks for of each Device it holds, counted against the Device's `vram` label (a node writes
  it from the card's total vram). A workload's shares add up; a share that does not fit
  waits, and its message gives the numbers (`has 0 of its 1073741824 vram bytes free, and
  the share asks for 536870912`). `status.share` gives each Device's `asked` and `of`, and
  `status.shareBytes` the share the claim was admitted with; a Device with no `vram` label
  it can read admits the share and says `counted: false`. A holder keeps its share when the
  label drops below what they ask, but a claim that asks for more than it held is fitted
  again. **Nothing enforces a
  share: it is cooperative.** kith counts it and does not stop an app that uses more vram
  than it asked for. No driver is held to it by kith yet. Untried options: a driver's own
  memory limit where the driver has one (the kernel's `dmem` cgroup controller), NVIDIA's
  MPS limits, and MIG partitions, which would be Devices of their own.
- A container is given the device nodes of its Devices in its own `/dev`, beside the few
  every container has (`null`, `zero`, `full`, `random`, `urandom`, `tty`). A GPU brings its render
  node (`/dev/dri/renderD*`) with its card, and a card on NVIDIA's driver its `nodes`; a
  `display` has no device node and gives nothing. A Device or claim that is missing, or a
  path that is not a device node, stops the unit from starting, and says which. An `exec`
  unit runs on the host and sees all of `/dev` as it is.
- **What holds it to those on kith OS is a device filter on its cgroup**: a program kithd
  loads into the kernel for each container, asked at every open and every `mknod` of a
  device node by a process in it. It lets through the few every container has, the
  terminals of the container's own `/dev/pts`, and each device it was given (to read and
  write, not to make a second node of); all else is refused. So a pod that is root there
  and keeps the node's users (one given devices, say), which has the capability to make
  device nodes, makes none for its node's disk and opens none; one in a user namespace of
  its own makes no device node at all, as below. (A pod that made a node for itself
  before, `/dev/net/tun` or `/dev/fuse`, is refused now: write a `Device` for the node, `class: other` with its `path`, and claim
  it.) A container whose device filter cannot be loaded is not started. Where kithd is
  your own service there is no filter and none is needed: a container there is in a user
  namespace, where the kernel lets no one make a device node, and it has the nodes in its
  `/dev` and no other.
- **An app can be a workload of its own, shown as a window in a session.** A `DeviceClaim`
  on a seat that says `access: client` takes none of the seat's devices: any number of
  workloads hold it beside the session, each on the seat's node. It is a claim of the
  session's own namespace: a client is placed only while a workload of its namespace
  holds the seat, and waits otherwise (its claim says so). Each is given the render
  nodes of the seat's GPUs (not the card: it draws, and is not the screen's master; on
  NVIDIA's driver, whose programs draw through the driver's own nodes, those but
  `nvidia-modeset`) and the seat's own directory at `/run/seat`, to read. The seat's
  holder has the same directory to write, so a session that puts its Wayland and PipeWire
  sockets there (the desktop packages set `XDG_RUNTIME_DIR=/run/seat`) is where the app
  opens its window:

```yaml
apiVersion: kith.dev/v1
kind: DeviceClaim
metadata: { name: office-apps }
spec: { seat: office-pc-seat0, access: client }
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: editor }
spec:
  template:
    deviceClaims: [office-apps]
    containers:
      - name: editor
        image: registry.example/me/editor:3
        env:
          - { name: WAYLAND_DISPLAY, value: /run/seat/wayland-0 }
          - { name: PIPEWIRE_RUNTIME_DIR, value: /run/seat }
```

- Such an app has its own image, limits, volumes (its home is a Volume it mounts) and
  rollback, and `kith get deviceclaim office-apps -o yaml` lists the seat's apps as
  `status.holders`. It has to run as the session's user: the directory is that user's
  alone (made so each time a holder of the seat starts, so two sessions sharing a seat
  are to be one user), and another user's app finds nothing in it; root in a pod on
  kith OS is held by no file's owner, and reaches it. A workload is a client of one seat
  and holds none. What a session that died left in the directory is there until the
  next one replaces it. Not here: an app on another node shown in this session, a real
  compositor tried (the test's session is a program listening on a socket), and anything
  between an app and the compositor (a client of a session is in it: see
  [SECURITY.md](../../SECURITY.md)).
- An input device plugged in or pulled (a controller, a keyboard) while a container holds
  its seat is given to that container, or taken from it, as it runs: the node appears in
  its `/dev/input` at the next scan, within half a minute, and nothing is started over. (An
  input device that is still on the node and is taken from the container, by a changed
  claim or seat, starts it over: what it has open would stay open.) That
  is so on kith OS, for a container that had an input device when it started; where kithd
  is your own service it cannot make a node in a running container, and the unit is
  started over as for any other device. kith OS runs no udev: a program that asks udev
  what an input device is (libinput does) is told nothing about it yet.
- Not yet: a NodeWorkload cannot claim (one that names a claim is refused); for anything
  but input there is no hot-plug (a changed set of device nodes starts the unit over at
  the next scan, and a Device gone even for a moment stops what claimed it until it is
  back: its holder keeps its turn). On kith OS a claimed device node is made the container's user's. Where kithd
  is your service it is the node's own file: the container opens what you may open.
- Who may claim is ordinary access control: to claim, you apply a `DeviceClaim` and a
  workload that names it, so the right to apply those is the grant, and there is no other
  permission. A Role rule with `kinds: ["*"]` covers `DeviceClaim` and `Device` like any
  other kind: give it only to someone you would let hold any hardware of the cluster.

### What a seat keeps for itself

```yaml
apiVersion: kith.dev/v1
kind: Seat
metadata: { name: desk-seat0 }
spec:
  node: desk
  devices: [desk-gpu-card0]
  reserve: { cpu: 4, memory: 8Gi }     # kept for whatever holds the seat
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: training }
spec:
  template:
    containers: [{ name: run, image: registry.example/train:1 }]
    yieldTo: { seat: desk-seat0, when: [fullscreen] }   # step back while a game is up
```

- A seat's `reserve` comes off its node for every workload that does not hold the seat,
  whether or not anything holds it just then: other workloads are placed in what is left
  (ones already placed are not moved). The holder is asked to fit only what it wants
  beyond the reserve. (Of several that share a seat, the reserve counts for one:
  the first by name, and its first replica.)
- The holder's units are guaranteed the reserve's memory (`memory.min`: it is not
  reclaimed from them) and go first for CPU and disk (`cpu.weight` and `io.weight` at the
  kernel's most, 10000; everything else has 100). The CPUs are not pinned: an idle
  session costs the others nothing. Where a cgroup file cannot be written (no `io`
  controller, say) kithd's log names it and the rest holds.
- A session says what its seat is doing:
  `POST /v1/seats/desk-seat0/activity?state=active|idle|fullscreen`, for who may apply
  `Seat`s (give the session an Identity with a Role for that); it is in the audit log and
  in `kith get seat desk-seat0 -o yaml` as `status.activity`. A seat nobody holds says
  nothing, which is idle.
- A workload with `yieldTo` runs on a twentieth of one CPU on that seat's node while the
  seat is in one of the states it names, and has its own limit back when the state
  changes (within the controller's pass, some ten seconds). It is not stopped or moved.
- Not yet (ponytail): each unit of a holder gets the whole memory guarantee; a session
  that hangs while fullscreen keeps the others held back until it goes; a GPU is not
  shared out by this, only CPU, memory and disk.

### Virtual machines

A template's `vms` are virtual machines, beside (or instead of) its `containers` and
`exec` units, in a Workload, a Job or anything else that has a template:

```yaml
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: windows }
spec:
  placement: { require: { node.labels.seat: desk } }
  template:
    deviceClaims: [card]              # a DeviceClaim for a GPU set aside for machines
    vms:
      - name: machine
        firmware: /usr/share/edk2/x64/OVMF.4m.fd
        disks: [{ path: /var/lib/machines/windows.raw }]
        cpus: 8
        memory: 16Gi
        resources: { cpu: 8, memory: 17Gi }   # what it costs the node; else its cpus and memory
```

- A machine starts from a `kernel` (with an `initrd` and a `cmdline` if it needs them: a
  microVM) or from its `disks` through `firmware`. `memory` is needed (16Mi at least),
  `cpus` is 1 unless said. Every path is a file on the node, written whole; a disk is a raw
  image, `readOnly: true` if the machine must not write it.
- kithd runs the node's hypervisor as a supervised process, as an `exec` unit is: its own
  cgroup, restarted as `restartPolicy` says, done when the machine powers off or restarts.
  The machine's serial console (`console=ttyS0`) is the unit's log: `kith logs
  Workload/windows --unit machine`. `hypervisor: qemu` (the default, with KVM) or
  `cloudHypervisor`; the node needs `qemu-system-x86_64` (`-aarch64` on arm64) or
  `cloud-hypervisor` on its PATH and `/dev/kvm`.
- **Passing a device through (VFIO).** A PCI device bound to the `vfio-pci` driver is a
  `Device` of class `pci` (`desk-pci-0000-01-00.0`; labels `driver: vfio-pci`, `vendor`,
  `model`, and `function`: `gpu`, `audio`, `usb` or `other`) whose path is its place on the
  bus. It is no part of the node's seat, and a selector for `class: gpu` never comes to it:
  claim it by name, or by `class: pci` and its `function`. A `vms` unit is given every such Device the template's
  `deviceClaims` hold; a container is never given one. Binding is the node owner's doing,
  before kithd starts (`vfio-pci.ids=10de:2684,10de:22ba` on the kernel's command line, with
  the IOMMU on); a card usually wants its sound function claimed and passed too.
- The scheduler counts a machine as its `cpus` and `memory`, or as its `resources` when it
  names them (the hypervisor needs somewhat more memory than the machine has: say so there).
- Not yet (ponytail): Firecracker (it wants a tap device and an API socket; QEMU and
  cloud-hypervisor take one command line); a network beyond QEMU's own NAT (the machine
  reaches out, nothing reaches it; none under cloud-hypervisor); a disk from a Volume; kithd
  binding a device to `vfio-pci` itself; kith OS has no hypervisor in its image and no VFIO
  in its kernel, so `vms` run on agent-mode nodes only; a machine that powers off is
  started again under `restartPolicy: always`, as one that restarted is. Tested: a Job boots a kernel under KVM and its
  console is read back with `kith logs`. Not tested: cloud-hypervisor (its command line is
  built, never run here) and a real GPU passed through, which needs a machine with a spare
  card and its owner's say.

### Switching one GPU

A desktop and a machine can take turns on one GPU of a node, with no reboot. It needs:

- an IOMMU, on, and the `vfio-pci` driver in the node's kernel (kith OS's kernel has no
  VFIO today, so this is a node of its own, in agent mode, that its owner set up);
- the desktop's driver let go of the card and `vfio-pci` bound to it, by the owner, before
  the switch. kithd never unbinds a driver or binds one.

The session and the machine each name one exclusive `DeviceClaim` for the card, and
`kith switch` says which of them holds it:

```sh
kith switch gpu windows   # the machine takes the card
kith switch gpu desktop   # the session takes it back
```

- A claim's `holder` is the workload that takes the Device ahead of the others who want
  it. That priority is for this claim's Devices only, and only if the workload lists the
  claim in its template. It takes the Device from a holder of its own namespace; a holder
  of another namespace keeps it, and the named workload waits behind it, as its claim's
  status says. The current holder is stopped, and only then is the new one started, in the
  same pass of the controller. The holder stays until another `kith switch`. A holder with
  no replicas takes nothing: the one holding the card keeps it.
- A card keeps its `pci` label (its place on the bus) under either driver, so a claim with
  `selector: { pci: "0000:01:00.0" }` names the same card as a `gpu` and as a passed-through
  Device. A `holder` is of an exclusive claim only.
- **What a switch loses.** A switch takes seconds: the session stops and the machine starts.
  The session's windows are lost, and the desktop comes back as a new session with none of
  them. An app that is its own workload (a client claim on the seat, above) is not the
  session: it waits until a session holds the seat again, and its Volumes are kept.
- Two GPUs are not built: a machine with a second card keeps it to itself. A frame relay
  that shows the machine's screen in the session is named here and not built.
- **Proven only with stand-ins.** The tests use stand-in Devices, and no real GPU, VFIO
  bind or driver unbind was tried. Until its owner runs it on such hardware, a switch is
  untried.

### Confidential machines

`confidential: true` on a template has its machines run with their memory encrypted by the
processor, out of reach of the node they run on (AMD SEV-SNP, or Intel TDX):

```yaml
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: sealed }
spec:
  placement: { require: { node.labels.cpu: epyc } }
  template:
    confidential: true
    vms:
      - name: machine
        firmware: /usr/share/edk2/x64/OVMF.amdsev.fd   # one built for SEV-SNP (or TDX)
        disks: [{ path: /var/lib/machines/sealed.raw }]
        memory: 8Gi
```

- A node runs it only if its KVM says it has one of the two
  (`/sys/module/kvm_amd/parameters/sev_snp` or `/sys/module/kvm_intel/parameters/tdx` reads
  `Y`). **A node that has neither runs none of it** and says why in the status' `notes`;
  nothing falls back to a machine with its memory in the clear.
- Only `vms` units, each with a `firmware` and under QEMU: a `containers` or `exec` unit in
  a confidential template is refused when it is applied (it would run in the clear).
- Not yet (ponytail): the scheduler does not know which nodes have such a processor (say
  where with `placement`); nobody is shown the guest's measurement (attestation), so the
  guest's owner cannot yet check what was started; containers inside such a machine (it
  takes a guest kernel and an agent of kith's in it); cloud-hypervisor. Tested: the options
  QEMU is given for each, and the refusal on a machine with neither. **Not tested: a guest
  started on SEV-SNP or TDX hardware**, which needs such a machine and its owner's say.
