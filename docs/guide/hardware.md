# Hardware

Every node lists its own hardware from `/sys` and keeps one `Device` per piece in the store,
applied when it turns up and deleted when it is gone (a rescan every half minute): `kith get
device` lists them. A `Device` is named `NODE-CLASS-NAME` (lower case, cut to 63 characters);
its `spec` has `node`, `class` and the device node as `path`. The class is `gpu` (a DRM card,
`/dev/dri/card0`), `display` (a connector with a screen; no path), `input`
(`/dev/input/event3`), `audio` (a sound card, `/dev/snd/controlC0`), `camera` (`/dev/video0`) or
`usb` (not a hub, `/dev/bus/usb/001/004`).

- **Labels** (a selector can name them). All: `kith.dev/node`, `class`, `kith.dev/discovered:
  "true"`. GPUs and USB devices also `vendor`, `model`; a GPU `driver` and, where known, `vram`
  in bytes; inputs and sound cards `model`. An input also `identity`, a hash of its name, port,
  serial and ids: another device behind the same event index is taken from its holder. A USB
  device also `bus`, its port (`1-2`), and `serial`, a hash of its serial where it says one:
  its ids are the stick's own to say, so name one stick by `serial` or `bus` with
  `kith.dev/node`; another serial (or none) in its port takes it from its holder.
- `NODE-seat0` is a `Seat` naming the node's displays, inputs, sound cards and GPUs. What
  carries `kith.dev/discovered` is kept in step (rewritten if you edit it, deleted when the
  hardware goes); a `Device` or `Seat` you wrote yourself is never touched.
- Do not name nodes `alpha` and `alpha-gpu`: a Device belongs to the node with the longest name
  that starts it. A join that would take a listed Device is refused.
- **NVIDIA's own driver.** A card on it also has `nodes`: what CUDA, OpenGL and Vulkan open
  beside the card (`/dev/nvidiactl`, `nvidia-uvm`, `nvidia-uvm-tools`, `nvidia-modeset`,
  `/dev/nvidiaN`), those that exist. **Not tried on a real card.**

### Claiming hardware

A workload names `DeviceClaim`s (same namespace) in its template's `deviceClaims`. A claim names
a `seat`, a `device` or a `selector` over `Device` labels, and `access: exclusive` (default) or
`shared`:

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

- The workload runs only on the node of the Devices its claims reach. A selector that matches
  Devices on several nodes takes those of the lowest-named node; add `kith.dev/node` to fix the
  node. Claims that reach two nodes hold nothing (the status says so).
- One workload holds a Device at a time. A second exclusive holder waits (`unschedulable`:
  `waiting for DeviceClaim render, held by Workload/default/renderer`) and takes over when the
  first is gone. `shared` claims may have any number of holders, none beside an exclusive one.
  `kith get deviceclaim render -o yaml` shows `status.node`, `devices`, `holders` or `message`.
- A container gets its Devices' nodes in its own `/dev`, beside `null`, `zero`, `full`,
  `random`, `urandom`, `tty`; a GPU brings its render node (`/dev/dri/renderD*`). A missing
  Device or claim stops the unit and says which. `/dev/mem`, `/dev/kmem`, `/dev/port` and
  `/dev/tpm*` are given to no pod, whatever a Device says.
- **On kith OS** a device filter on each container's cgroup checks every open and `mknod`: it
  lets through the usual few, the terminals of the container's own `/dev/pts` and each device it
  was given, and refuses the rest, even to a root pod. A pod that made its own node
  (`/dev/net/tun`) needs a `Device` with `class: other` and its `path`, claimed. Where kithd is
  your own service there is no filter: no one in a user namespace can make a node.
- The right to apply a `DeviceClaim` and a workload that names it is the grant: a Role rule with
  `kinds: ["*"]` covers both, so give it only to someone you trust with any hardware.

**Who may claim what.** A `Device` or `Seat` is given to namespaces by its label
`kith.dev/namespaces`, a comma-separated list (`default, desktop`). A claim in namespace N
reaches it only if the label lists N, or N is `kith-system`, the cluster's own. With no label, a
`gpu` is open to every namespace, and every other `Device` (`input`, `audio`, `camera`,
`display`, `usb`, `other`) and every `Seat` is `kith-system`'s alone. A seat claim also needs
each of the Seat's labelled Devices to be given to N. The label is an admin's
(`metadata.labels`, `kith apply -f`): discovery keeps it, and a worker cannot add, change or
drop it. Removing it refuses a claim at the next pass; its `status.message` says why. A
labelled `Device` or `Seat` whose hardware is gone is kept, so the label is there when it comes
back, and marked `kith.dev/absent: "true"` until then: a claim naming it is refused ("is
absent") and a selector passes over it.

**A share of a GPU's vram.** A `shared` claim may say `share: { vram: 512Mi }`: what it asks of
each Device it holds, counted against the Device's `vram` label. A workload's shares add up; one
that does not fit waits, and its message gives the numbers (`status.share`). **Nothing enforces
a share: it is cooperative.** Untried: `dmem` cgroups, MPS, MIG partitions.

### An app as a workload of its own, in a session's window

A `DeviceClaim` on a seat with `access: client` takes none of the seat's devices, so any number
of workloads hold it beside the session, each on the seat's node, in the session's namespace and
only while a workload of that namespace holds the seat. Each gets the render nodes of the seat's
GPUs (not the card) and the seat's directory `/run/seat`, to read. A session that puts its
Wayland and PipeWire sockets there (the desktop packages set `XDG_RUNTIME_DIR=/run/seat`) is
where the app opens its window:

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

- The app has its own image, limits, volumes and rollback, and shows as one of the claim's
  `status.holders`. It must run as the session's user: the directory is that user's alone.
- **Input hot-plug.** An input device plugged in or pulled while a container holds its seat
  appears in or leaves its `/dev/input` at the next scan, with no restart (on kith OS, for a
  container that had an input device at start); elsewhere, or when a changed claim or seat takes
  one away, the unit restarts. Not yet: an app on another node shown in this session; a
  NodeWorkload claim. A client of a session is in it: see [SECURITY.md](../../SECURITY.md).

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

- A seat's `reserve` comes off its node for every workload that does not hold the seat, held or
  not. The holder fits only what it wants beyond it; its units are guaranteed the reserve's
  memory (`memory.min`) and go first for CPU and disk (`cpu.weight` and `io.weight` at 10000;
  all else 100). CPUs are not pinned; a GPU is not shared out (not yet).
- A session says what its seat is doing with `POST
  /v1/seats/desk-seat0/activity?state=active|idle|fullscreen` (it needs an Identity whose Role
  may apply `Seat`s); it shows as `status.activity`. A seat nobody holds is idle.
- A workload with `yieldTo` runs on a twentieth of a CPU on that seat's node while the seat is
  in a state it names, and gets its limit back when the state changes (about ten seconds).

### Virtual machines

A template's `vms` are virtual machines, beside or instead of its `containers` and `exec` units,
in a Workload, a Job or anything with a template:

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

- A machine starts from a `kernel` (a microVM; `initrd`, `cmdline`) or from its `disks` through
  `firmware`. `memory` is required; `cpus` is 1 unless said. Every path is a file on the node; a
  disk is a raw image (`readOnly: true` if it must not be written).
- kithd supervises the hypervisor; the serial console (`console=ttyS0`) is the unit's log: `kith
  logs Workload/windows --unit machine`. `hypervisor: qemu` (default, with KVM) or
  `cloudHypervisor`; the node needs `qemu-system-x86_64` (`-aarch64` on arm64) or
  `cloud-hypervisor` on its PATH, and `/dev/kvm`.
- **Passing a device through (VFIO).** A PCI device bound to `vfio-pci` is a `Device` of class
  `pci` (`desk-pci-0000-01-00.0`; labels `driver: vfio-pci`, `vendor`, `model` and `function`:
  `gpu`, `audio`, `usb` or `other`). It is not in the node's seat and `class: gpu` never selects
  it: claim it by name, or by `class: pci` and its `function`. A `vms` unit gets every such
  Device its template claims; a container never does. The owner binds it before kithd starts
  (`vfio-pci.ids=10de:2684,10de:22ba`, IOMMU on).
- Not yet: Firecracker; a network beyond QEMU's own NAT (the machine reaches out, nothing
  reaches it); a disk from a Volume; kithd binding `vfio-pci`; `vms` on kith OS. Tested: a Job
  boots a kernel under KVM. Not tested: cloud-hypervisor, a real GPU passed through.

### Switching one GPU

A desktop and a machine can take turns on one GPU of a node, with no reboot. It needs an IOMMU
on, `vfio-pci` in the node's kernel (not kith OS's: use an agent-mode node) and the card bound
to `vfio-pci` by its owner (kithd never binds or unbinds a driver). The session and the machine
each name one exclusive `DeviceClaim` for it:

```sh
kith switch gpu windows   # the machine takes the card
kith switch gpu desktop   # the session takes it back
```

- A claim's `holder` (exclusive claims only) is the workload that takes the Device ahead of
  others, from a holder of its own namespace; a holder of another keeps it and the named
  workload waits. The current holder stops, then the new one starts, and stays until another
  switch. A card keeps its `pci` label under either driver: `selector: { pci: "0000:01:00.0" }`.
- **What a switch loses.** It takes seconds: the session stops, its windows are lost and the
  desktop comes back as a new session. An app that is its own workload waits for a session to
  hold the seat again; its Volumes are kept.
- Not built: two GPUs at once, a frame relay. **Proven only with stand-ins**: no real GPU, VFIO
  bind or driver unbind was tried.

### Confidential machines

`confidential: true` runs a template's machines in memory the node cannot read (SEV-SNP, TDX):

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

- A node runs it only if its KVM has SEV-SNP or TDX (`kvm_amd/parameters/sev_snp` or
  `kvm_intel/parameters/tdx` in `/sys/module` reads `Y`). **A node with neither runs none of
  it** and says why in the status' `notes`; nothing falls back to memory in the clear. Only
  `vms` units with a `firmware`, under QEMU: any other unit here is refused at apply.
- Not yet: the scheduler knows nothing of which nodes have such a processor (use `placement`);
  no attestation; containers inside such a machine; cloud-hypervisor. **Not tested: a guest on
  SEV-SNP or TDX hardware**, only QEMU's options and the refusal elsewhere.
