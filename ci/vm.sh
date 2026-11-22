#!/bin/sh
# shellcheck disable=SC1091,SC2034,SC2016,SC2089,SC2090 # (names the driver and its parts share; $reap is a script kept in a variable)
# Boot a kernel in QEMU and print what it said: by default the host's kernel with the
# static kithd as init (so, the kernel and kithd, nothing else). The image,
# installer, update and cluster tests reuse it with their own kernel, initramfs and disk image.
# The tests' bodies are in ci/vm/NAME.sh, each sourced where it runs, so no file is too long to read.
#
#   sh ci/vm.sh [--kernel FILE] [--initrd FILE] [--disk IMAGE] [--append ARGS] [--time SECONDS]
#   sh ci/vm.sh --test init     kithd as the first process: up, serving, restarts when told
#   sh ci/vm.sh --test image    kith OS's disk image (os/build.sh), booted under UEFI on a longer disk
#   sh ci/vm.sh --test update   that image updating itself, and going back when it must
#   sh ci/vm.sh --test clock    the node's clock started hours off, stepped to an SNTP server's time
#   sh ci/vm.sh --test clockleader  three nodes with no time server: one leads 8 h ahead, the others keep theirs
#   sh ci/vm.sh --test disk     disk files added, mounted and removed by the verbs, one with a GPT refused
#   sh ci/vm.sh --test encrypt  a plain node's disk file encrypted in place at its start, cut mid-pass, resumed
#   sh ci/vm.sh --test rollout  three nodes of it taking a release, one at a time
#   sh ci/vm.sh --test install  the installer, onto virtual disks, and what it installed
#   sh ci/vm.sh --test vps      the installer started from memory, as os/vps.sh starts it
#   sh ci/vm.sh --test netboot  a node installing a machine that starts from the network
#   sh ci/vm.sh --test crypt    the same machine with its state encrypted: locked, unlocked, wiped
#   sh ci/vm.sh --test tpm      the same machine with a TPM: its key sealed to the system it runs
#   sh ci/vm.sh --test duress   the same machine given a new recovery key and a duress code, which is typed
#   sh ci/vm.sh --test blackout four encrypted nodes (three control, two of them with a TPM, and a worker)
#                               losing power at once in the middle of writes and started again: nothing
#                               typed, a leader from the two sealed ones, no write lost
#   sh ci/vm.sh --test alone    two nodes, the worker set to run alone: the control node off and the worker
#                               started again, it runs its replica and holds its Job after 30 s, with the risks
#                               said; the control node back, the replica placed there is stopped on the worker
#   sh ci/vm.sh --test share    two nodes: a shared volume of one, mounted by a container on the other;
#                               an encrypted volume of one, its key kept by the other
#   sh ci/vm.sh --test pods     two nodes: pods with a network, an address and a root each to write to,
#                               found by their Service's name and reaching out from behind their node
#                               (one node's pod range is not the default: --pod-range)
#   sh ci/vm.sh --test poddns   two nodes on the mesh: a pod of a node with no --dns finds a name outside
#                               the cluster through its node's upstream, a second kithd with its own
#   sh ci/vm.sh --test services one node: every byte through a Service to a pod on the same node comes
#                               back in order, however its connection ends, passed by kithd from a pod
#                               and by the kernel from the node's own network; then on the mesh with
#                               a second node that opens no links (of before), each sends to the other's
#   sh ci/vm.sh --test mesh     two nodes started with no --mesh: the Cluster's spec.mesh turns the mesh on
#                               with no reinstall; a pod on one reaches a Service whose replica is on the other
#   sh ci/vm.sh --test compose  one node: ci/compose/stack.yml (four services of the test pod) and media.yml
#                               (eight, the media stack's shape) imported with kith import compose, applied,
#                               ready, each asked for by its compose name; KITH_E2E=1 also runs media.yml
#                               under docker compose up on an Alpine machine, timed beside kith's
#   sh ci/vm.sh --test privilege one node with --split: the confined serving process's status and mounts
#                               read, its tries at setuid, a capability, the node's disk and a mount
#                               refused; kithd killed under a pod: started again, the pod goes on
#   sh ci/vm.sh --test outlive  one node: kithd killed under a pod, an exec unit and Jobs: the machine
#                               stays up, kithd serves again and takes them back as they ran; ten
#                               kills in a minute restart the machine
#   sh ci/vm.sh --test handover one node: a kithd-only release taken with no restart (boot id and pod
#                               process kept, the new version reported); a changed kernel restarts it
#   sh ci/vm.sh --test nested   one node: a container with kith's defaults, then with each opening in
#                               turn, that starts a second runtime (bubblewrap) and kithd in agent mode and
#                               says what refused each and the guest kernel's settings; the rows go to
#                               $KITH_NESTED_OUT (ci/stress.sh --nested keeps them in ci/stress.txt)
#   sh ci/vm.sh --test nofile   one node: a container's open-file limit is soft 1024 and hard 524288
#                               (a Job of the test pod; KITH_E2E=1 also a busybox Job's ulimit -Sn, -Hn)
#   sh ci/vm.sh --test quota    one node whose state disk keeps project quotas: a pod's storage limit
#                               holds at the write, in its root and its scratch, however it tries past it
#   sh ci/vm.sh --test kube     two nodes: the real kubectl and helm against them, with manifests written
#                               for Kubernetes; what they make runs, rolls out, keeps its data and is waited for
#   sh ci/vm.sh --test worker   two nodes, one a worker: it runs what is placed on it with its Secret, its
#                               disk never has another's, and what it does with no control node in reach
#   sh ci/vm.sh --test chaos    three nodes taking writes: each in turn cut off from the others, each
#                               in turn losing power, then all at once; what was acknowledged is on all three
#   sh ci/vm.sh --test home     three voters and a roaming fourth, with a house address in the Cluster: one MAC answers for it, and DNS, TCP 443 and WireGuard answer from it
#                               and DNS answers from it; the holder reset, and the next stopped: another
#                               announces it within 10 s and two are never heard at once
#   sh ci/vm.sh --test access   three nodes: a write let through by a node that had not heard its
#                               RoleBinding was deleted is refused where the log is kept; and
#                               three entries a forging leader appends (bare, a changed body,
#                               a replayed nonce) are refused at apply by every node
#   sh ci/vm.sh --test fido2    the client of kithd against a software security key (the fido2-test
#                               build) through the kernel's uhid and hidraw: the hmac-secret each seed
#                               says it must be, another seed another secret, a withheld touch timing out
#   sh ci/vm.sh --test policy   two nodes whose policy turns off exec units, VM paths and /v1/run: kithd
#                               cut its bounding set, and a pod that is root, a container with no filter
#                               and a sandbox inside a container still run
#   sh ci/vm.sh --test tunnel   one node and a WireGuard provider: a pod behind an Exit reaches out
#                               only through its tunnel, never with it down, and is reached on its node
#
# Nothing needs root, and the VM never writes to a disk image: it runs `-snapshot`
# (writes go to a temporary file), and a path under /dev is refused. Where there is no
# QEMU, no KVM or no readable kernel it prints "skipped: ..." and exits 0.
set -eu

usage() {
    cat <<'EOF'
usage: sh ci/vm.sh [--kernel FILE] [--initrd FILE] [--disk IMAGE] [--append ARGS] [--time SECONDS]

Boots a kernel in QEMU (KVM), prints the serial console, and exits 0 once the guest
has said something of kithd's (a line containing "kithd"), 1 if it did not.

  --kernel FILE    any kernel image (default: the host's /boot/vmlinuz-*)
  --initrd FILE    any initramfs, plain or compressed cpio
                   (default: one made here, whose /init is the static kithd)
  --disk IMAGE     any raw disk image, attached as a virtio disk (/dev/vda); the VM
                   runs with -snapshot, so IMAGE is never written; /dev paths are refused
  --append ARGS    the kernel command line (default: console=ttyS0 panic=-1)
  --time SECONDS   stop the VM after this long (default: 60)
  --test init      instead: wait for kithd, as the machine's first process, to serve its
                   API, print how long that took (it fails past 10 s), press Ctrl-Alt-Del,
                   and expect kithd to stop and restart the machine; then the same
                   with the power button, and expect it to power off; needs socat
  --test image     instead: build kith OS's image (os/build.sh), boot a copy of it under
                   UEFI with a network card, and expect: the root mounted through
                   dm-verity, the state partition mounted, an address by DHCP, TLS
                   answered on the node's port, the same node after a restart, and a
                   root with one block changed refused; needs OVMF, socat, openssl
  --test update    instead: on a copy of the image, give the node a damaged update
                   (refused), a good one (it restarts into its other slot, marks it
                   good, and is the same node), then one whose root is broken (three
                   tries, and it is back on the slot that worked); same needs
  --test clock     instead: the node's clock starts six hours off (QEMU -rtc base=), an SNTP
                   server on the host's loopback answers (ci/vm/sntp_standin.py), and the
                   node, told of it by kith.ntp=10.0.2.2:PORT, steps its clock to its time;
                   same needs as image, and python3
  --test clockleader instead: three nodes as for rollout, no time server for any; all lose
                   power, one starts again eight hours ahead and leads, the others start
                   after it: each keeps the host's time within 5 s and says why it did not
                   take the leader's (2 of 3 voters agree with it); same needs as rollout
  --test modules   instead: the 'all' image (its drivers are modules, signed with the key of its
                   build): kithd loads the driver of an HDA controller at start, and of a USB
                   audio device the monitor adds later, in the same boot; the same spec built
                   with one byte of snd-usb-audio changed is refused on one console line; same
                   needs as image, and the image is built twice
  --test encrypt  instead: a plain node's disk file given a lock record and a marker, and its
                   state encrypted in place at the next start (docs/adr-encrypt-in-place.md); the
                   first such start is cut mid-pass (the monitor's quit) and the next resumes it.
                   Expected: the same node, a state the host cannot read, the marker gone, and no
                   pass at a third start; same needs as image, and od
  --test disk      instead: one node the installer made, its state encrypted, claimed over TLS,
                   with three more disks that are files: one of 16 GiB (sparse) the add verb
                   makes a data disk, one with a GPT on it (refused), one nobody names.
                   Expected: the first added, mounted, listed and audited, mounted again at
                   the next start from its header and key, then removed (its header zero,
                   nobody's again); the other two unchanged byte for byte; needs what
                   install needs (curl, python3, cpio, mtools, socat)
  --test rollout   instead: three nodes on a network of their own, claimed and joined
                   over TLS, their image built with a release key; a first release by
                   another key (refused), one with another file's signature (refused), a signed
                   one (each node takes it in turn, one cluster throughout), then one
                   that cannot start (one node tries, comes back, the plan is paused);
                   also needs curl, python3, xxd
  --test install   instead: the installer image started in VMs whose disks are files
                   made here: with no disk (nothing installed); with answers on the
                   stick, from a URL, and typed at the console (after a slip that
                   writes nothing); each installed disk then starts as a node, one
                   keeps its state, one joins the first's cluster; also needs curl,
                   python3, mcopy
  --test vps       instead: os/vps.sh packs the installer's memory disk with answers
                   (and wants the disk named twice); kernel and memory disk started
                   as kexec starts them, over a disk that held something else; the
                   disk then starts as the node; also needs cpio
  --test netboot   instead: a node, on a network with a DHCP server of its own, is told
                   to install a machine by its card's address; that machine, with an
                   empty disk, starts from the network (PXE), installs, starts from
                   its disk and joins the node's cluster
  --test crypt     instead: the same, the machine installed with its state encrypted:
                   the node holds its key; it is locked, unlocked, opened with its
                   recovery key and wiped; and opened away from its cluster with a passphrase
  --test tpm       instead: the same machine with a software TPM (swtpm): told to
                   (`kith node seal`), it seals its key to the system it runs and
                   starts with no node asked; started with another command line, or
                   a changed boot file, it is refused the key, asks the cluster and
                   seals anew; locked, it drops the seal and waits; needs swtpm
  --test duress    instead: the same encrypted machine: the cluster warns that nobody
                   saw its recovery key until it shows a new one (the old one opens
                   no more); its key forgotten as the cluster's duress code does, it
                   runs on until unlocked; its own duress code, typed at its waiting
                   console, is answered as a wrong key is, its lock record is erased,
                   the cluster forgets its key, and nothing opens it after
  --test blackout  instead: four nodes the installer made, each with its state
                   encrypted: three control nodes (two sealed by their TPMs, swtpm, the
                   third not) and a worker, with writes going in and a Workload on the
                   worker and on a control node; all four lose power at the same moment,
                   a write in flight, and start again with nothing typed at any console:
                   the two sealed nodes open from their TPMs and elect a leader with the
                   third still off, which then, and the worker, are handed their keys;
                   every acknowledged write is on all three control nodes and both
                   Workloads are started again; needs swtpm
  --test alone    instead: two nodes the installer made, each with its state not
                   encrypted: a control node and a worker set to `alone: run`, with a
                   one-replica Workload and a Job on the worker; the control node is
                   stopped and the worker started again: after about 30 s it says so,
                   with the risks, runs the replica and holds the Job; the control node
                   back, the worker says since when it ran alone and until when, and
                   the replica placed on the control node is stopped on the worker
  --test share    instead: two nodes on the mesh, each with kith as a container image
                   already there: a file a container makes in a shared volume on the
                   node that does not hold it is there on the node that does, and the
                   other way round; no NFS is answered from outside the mesh until a
                   Share names this machine, which then makes a directory in the
                   Share's volume and cannot write a read-only one; an encrypted
                   volume is made on one node with its key kept by the other, shows
                   no file system on the node's disk, and is opened again with what
                   was written in it after the node restarts
  --test pods      instead: two nodes on the mesh with ci/pod.rs as a container image
                   already there: three pods of one Workload (so two on one node) each
                   listen on port 80 as root, write to their root and have an address
                   of their own (the second node's from --pod-range 10.77.0.0/20, the
                   first's from the default 100.88.0.0/16, each told by its pods which);
                   a pod of a user who is not root finds their Service
                   by its short name and its Kubernetes one, hears all three through
                   it, reaches this machine from behind its node's address, and
                   writes to /dev/stdout by name; a NetworkPolicy's egress rule holds
                   the pods of one app to this machine's address and one port (and
                   port 80 of no other address): another port, or a pod's address on
                   port 80, is silent, while an unfenced pod on the same node is
                   answered by that pod and refused by the port nothing listens on;
                   a pod that is root is kept from a
                   device it was not given (its node's disk); a container that asks for user
                   namespaces starts a sandbox in it (this machine's bwrap), one that
                   does not is refused, one that is root is not started; a USB keyboard
                   plugged in is given to the container holding the seat as it runs;
                   an app that is a client of the seat reaches the socket its session
                   listens on and cannot write beside it, and another user's cannot;
                   the image of a Workload deleted goes once unused for --image-grace
                   (two minutes here) and that of a running one stays;
                   needs rustc for x86_64-unknown-linux-musl, bwrap and socat. With
                   KITH_E2E=1 also three pods of
                   nginx as it is shipped, pulled from mirror.gcr.io
  --test poddns    instead: two nodes on the mesh, the first started without --dns but with
                   --dns-upstream the second, which serves DNS too and forwards what it does
                   not know to an outside resolver (ci/outside-dns.py, on this machine); a pod
                   on the first finds outside.example.test through both. KITH_POD_NOUPSTREAM=1
                   starts neither with an upstream: the control, where the name is not found
  --test privilege instead: one node on the mesh with --split, the image of a kithd built with the
                   cargo feature confine-probe (target/os-probe, never shipped): `kithd confine-probe`
                   (as an exec unit) confines itself as the serving part does and says its status,
                   its mounts and what it tried and was refused, with the filter and with
                   --no-filter (and holding a directory open: refused); then kithd
                   killed under a pod: started again, the pod the same process
  --test nested    instead: one node with an image that holds bash, bubblewrap and kithd; a Job in it for
                   kith's defaults, then five variants: unconfined seccomp, userNamespaces, both, runAsUser 0;
                   each starts a user namespace, bubblewrap and kithd in agent mode, and
                   says what refused it, the guest kernel's settings and the smallest opening
                   that let it run. It changes no default (KITH_NESTED_OUT: where the rows go)
  --test nofile    instead: one node on the mesh with ci/pod.rs as a container image: a Job
                   there reads its open-file limits (/proc/self/limits). Expected: soft
                   1024 and hard 524288, so an app can raise its own, as under containerd.
                   KITH_E2E=1 also a Job of busybox, whose ulimit -Sn and -Hn say the same
  --test outlive   instead: one node on the mesh with ci/pod.rs as an image and on its
                   disk: kithd killed (SIGKILL) under a pod of two containers, an exec
                   unit and a Job; the machine stays up, kithd serves again within
                   2 s and takes each back as it ran; killed ten times in a minute,
                   the machine restarts
  --test handover  instead: one node on the mesh with ci/pod.rs as an image: a release that
                   differs from the running slot in kithd alone is handed over to with no
                   restart (same boot id, same pod process, the new version reported), and
                   a release with another kernel restarts into the other slot (the test
                   `update` runs it too, after its own)
  --test services  instead: one node with no --mesh (as kith OS starts) with ci/pod.rs as a container image
                   already there: a pod that sends back every byte it is sent, its
                   Service, and a Job on the same node sending through that Service
                   over 680 connections (one after another and side by side, from
                   nothing to more than a megabyte, half closed at once when all is
                   sent, reset by either end on the way) and one of 5000 small turns:
                   every byte comes back in order. The Job runs twice: in a pod,
                   kithd passes its bytes; on the node's own network, the kernel
                   sends its connections straight to the pod. Then the node starts again
                   with --mesh and a second joins it with KITH_NO_LINK set (kithd says
                   no `link` and opens none, as a node of before): a pod on each sends
                   through the Service of a pod on the other, both ways. Needs rustc for
                   x86_64-unknown-linux-musl
  --test mesh      instead: two nodes on disk files started with no --mesh (as kith OS starts),
                   the second joined to the first: neither brings a mesh up. The Cluster then
                   says spec.mesh {enabled: true} and both do, with no restart: kith0 up, an
                   address in the cluster's /48 on each Node, and a Job in a pod on the first
                   sends through a Service whose only replica is on the second, every byte
                   back, reaching kithd at the Service's mesh address. The switch set to
                   false takes each node's mesh status back. Needs rustc for
                   x86_64-unknown-linux-musl
  --test compose  instead: one node on the mesh, and on this machine `kith import
                   compose` of ci/compose/stack.yml (four services of the test pod,
                   nothing in it left out) and of ci/compose/media.yml (the eight services
                   of the media stack, on the test pod) applied to it. Expected: each
                   Workload ready, each Service given its backend, and a Job in a pod
                   asking each service by its compose name (and the alias a container_name
                   gives) is answered by that service's pod; the seconds from the apply to
                   all ready are printed (kith's side of T-0320's comparison with docker
                   compose). With KITH_E2E=1 also docker compose up of media.yml on an
                   Alpine machine of its own (docker from Alpine's packages; three runs,
                   the median printed beside kith's)
  --test quota     instead: one node on the mesh, its state disk made with project
                   quotas (as os/build.sh makes it). Expected: kithd says it holds
                   pods' storage limits at the write; a pod of 64Ki removed and the
                   node started again, the pod given its id after it is held to its
                   own limit, not that one's; a pod of 64 MiB writing 200 MiB
                   is stopped at its limit by the kernel, in its root, its scratch
                   and a file it removed and holds open, and is not replaced, while
                   one beside it loses no write; a pod of 64 MiB making empty files
                   is stopped at the files its limit lets it (its share of the
                   disk's, 4096 at least) and says so, while one beside it makes
                   all of its own; a pod with the node's users is
                   stopped in its root too, and in both kinds a file of the image
                   copied up near the limit is refused whole, the file unchanged;
                   a pod cannot move its files out of
                   its project (in a user namespace the kernel refuses, as the node's
                   root its filter does; unconfined it can, and is counted and
                   replaced); what it changes of its image is charged to it. Needs
                   rustc for x86_64-unknown-linux-musl, and socat
  --test kube      instead: two nodes as for pods, and kubectl (KITH_KUBECTL, or the
                   one on PATH) and helm (KITH_HELM, several with colons between, or
                   the one on PATH) asking the first as the cluster's admin: the
                   manifests of ci/kube applied, rolled out and running, a
                   StatefulSet's claim given a volume that outlives its
                   pod, a StatefulSet of three with a claim and a volume for each
                   replica across the nodes, a Job and a CronJob's Job reading all of it through their
                   Services, kubectl create, expose, scale, set image, rollout
                   restart, wait and logs, helm install, upgrade and uninstall
                   with --wait, and nothing left when all is deleted. Skipped
                   without kubectl. With KITH_E2E=1 also nginx as it is shipped,
                   pulled from mirror.gcr.io
  --test worker    instead: two nodes on the mesh, the second let in as a worker
                   (it is sent a view of the store). Expected: its Node says `view`;
                   a Workload placed on it runs with its Secret; the worker's disk
                   has that Secret and never the Secret of what runs on the control
                   node; its API answers no person; with the control node paused it
                   runs on, started again it runs nothing until the control node is
                   back, and then what it ran; a Workload that is deleted leaves it
  --test chaos     instead: three nodes as for rollout, and three writers on this
                   machine, one through each node. Each node in turn has its card on
                   the cluster's network unplugged, then plugged back; each node in
                   turn is reset by the hypervisor in the middle of writes, and then
                   all three at the same moment. Expected: the other two go on taking
                   writes each time, a cut-off node acknowledges none, every write
                   that was acknowledged is on all three nodes at the end, and the
                   three hold the same; needs what --test rollout needs
  --test home      instead: three voters as for rollout and a fourth that roams (a learner,
                   reset by the hypervisor; its Node says spec.roaming), a house address (10.9.0.100/24)
                   in the Cluster, and a machine on their network (ci/lan_probe.py)
                   that asks who has it four times a second. Expected: one card
                   answers and announces it, the Cluster's status.home says whose
                   it is (and the next holder's after a reset), DNS and TCP 443 asked of it answer
                   from it, a WireGuard handshake sent to it is answered from it (a reset roaming
                   node dials it), with
                   the holder reset by the hypervisor and then (after it is back)
                   the next one stopped, another announces it within 10 s (the
                   seconds are printed), and two cards are never heard answering at
                   once, not when the stopped one goes on again; needs socat and
                   python3 as --test chaos does
  --test fido2     instead: the image of a kithd built with the cargo feature fido2-test
                   (and a kernel with /dev/uhid), one machine: it makes three software
                   security keys on uhid in turn and runs the client against each through
                   hidraw (makeCredential, getAssertion, a known salt). Expected: each
                   hmac-secret is what its seed says (computed again here in Python), seeds 1
                   and 2 differ, seed 3's withheld touch is given up on and its given touch
                   answered; a disk file only, no real key; needs OVMF, socat, python3
  --test access    instead: three nodes as for rollout, and the cluster's admin
                   writing through n2 and n3 by a RoleBinding that is deleted through
                   n1, once while n2 is cut off from the others. Expected: no write
                   begun after the deletion was acknowledged is acknowledged or
                   kept, and the one n2 let through while it was cut off is refused
                   when it reaches the leader, which decided again. Then, on an
                   image of a kithd built with the cargo feature forge (a leader
                   that can append an entry it was not asked for), under
                   signing: required, four such entries: a bare RoleBinding, a
                   signed entry whose body was changed, one with a replayed
                   nonce and one with a command its signed body does not make;
                   every node refuses each at apply (and audits it), and the
                   three nodes' lists agree; needs what --test rollout needs.
                   The first run per checkout does a cold forge release build
                   (kithd and kith, into a target folder of its own) and an
                   image of it in target/os-forge: far longer than a warm one
  --test policy    instead: two nodes on the mesh started with --node-policy
                   no-exec-units,no-vm-paths,no-run. Expected: each says what it
                   kept of the bounding set (never SYS_MODULE, SYS_RAWIO,
                   SYS_PTRACE or SYS_TIME), kithd's own CapBnd (and a later
                   thread's) is that and its CapEff is not cut, the pod that is
                   root has that CapBnd, and a pod
                   that is root, a container with no system call filter and a
                   sandbox inside a container (bubblewrap) all run, and so do
                   a volume of each node written and read back, a shared volume
                   of the first written from the second, a pod of a user who is
                   not root, and three pods behind a Service; needs what
                   --test pods needs, less socat
  --test tunnel    instead: one node on the mesh, its uplink cut off from everything
                   (the hypervisor's restrict=on), and a second machine on its LAN as
                   a WireGuard provider, with keys made for the run by wg. A pod of a
                   namespace an Exit lists runs behind it, and each second fetches a
                   page and asks names outside, tries IPv6 and sends packets out.
                   Expected: all of it through the tunnel while the provider answers,
                   none of it while the provider is stopped, its Secret changes, the
                   Exit is deleted or the node is reset; the pod's web and UDP ports
                   published on the node answer from this machine throughout; a pod
                   of a namespace the Exit does not list is refused; and in what
                   the node's two cards carried, no packet of the pod's but the
                   tunnel's own. Needs what --test pods needs, and ip and wg
  --selftest-said  instead: said() matches a line that a kernel stack-depth record landed in the
                   middle of, and does not match the line when it is absent; reads fixture logs only
  --selftest-kill  instead: start this script with a stand-in for QEMU, kill its shell from
                   outside (SIGKILL, then SIGTERM) and expect no QEMU left and the VM lock
                   free; needs no QEMU, KVM or kernel
  --selftest-sweep instead: a run takes the VM lock and deletes the work folders of killed runs (the
                   kith-vm-work-UID.* folders under TMPDIR), but no other folder and not the lock file;
                   needs sh and mktemp, no QEMU, KVM or kernel
  --selftest-web   instead: web_up serves a directory on a port and returns once it answers; with
                   another process holding the port, it returns 1 with that server's own error;
                   needs python3 and curl, no QEMU, KVM or kernel
  --help           this text

Without --initrd it builds kithd for x86_64-unknown-linux-musl (with zig as the C
compiler when there is no musl-gcc: ci/musl.sh) and needs cpio and zstd.
EOF
}

kernel='' initrd='' disk='' time=60 test='' selftest=''
append="console=ttyS0 panic=-1"
while [ $# -gt 0 ]; do
    case $1 in
    --help | -h) usage; exit 0 ;;
    --selftest-kill) selftest='kill'; shift ;;
    --selftest-said) selftest='said'; shift ;;
    --selftest-web) selftest='web'; shift ;;
    --selftest-sweep) selftest='sweep'; shift ;;
    --kernel | --initrd | --disk | --append | --time | --test)
        [ $# -ge 2 ] || { echo "vm.sh: $1 needs a value" >&2; exit 2; }
        case $1 in
        --kernel) kernel=$2 ;; --initrd) initrd=$2 ;; --disk) disk=$2 ;;
        --append) append=$2 ;; --time) time=$2 ;; --test) test=$2 ;;
        esac
        shift 2 ;;
    *) echo "vm.sh: unknown option $1 (try --help)" >&2; exit 2 ;;
    esac
done
case $test in '' | init | image | update | modules | rollout | install | vps | netboot | crypt | tpm | duress | blackout | share | pods | poddns | services | mesh | compose | quota | kube | worker | chaos | home | access | policy | tunnel | outlive | handover | privilege | nested | nofile | alone | disk | clock | clockleader | encrypt | fido2) ;; *) echo "vm.sh: --test knows: init, image, update, modules, clock, clockleader, disk, encrypt, rollout, install, vps, netboot, crypt, tpm, duress, blackout, alone, share, pods, poddns, services, mesh, compose, quota, kube, worker, chaos, home, access, policy, tunnel, outlive, handover, privilege, nested, nofile, fido2" >&2; exit 2 ;; esac
# (From here on the TPM test is the encrypted one, with its own end.)
sealing='' duress=''
[ "$test" != tpm ] || test=crypt sealing=1
[ "$test" != duress ] || test=crypt duress=1
[ "$test" != blackout ] || sealing=1
case $time in '' | *[!0-9]*) echo "vm.sh: --time wants whole seconds" >&2; exit 2 ;; esac
if [ -n "$disk" ]; then
    case $(realpath -m "$disk") in
    /dev | /dev/*) echo "vm.sh: refusing $disk: a device is not a disk image" >&2; exit 2 ;;
    esac
    [ -f "$disk" ] || { echo "vm.sh: no such disk image: $disk" >&2; exit 2; }
fi

skip() { echo "skipped: $1"; exit 0; }

# said_in FILE TEXT: the console FILE says TEXT (a grep pattern). A kernel stack-depth record (what a
# task prints when it exits: "[ts] comm (pid) used greatest stack depth: N bytes left") can land in the
# middle of a line the guest is writing, which then reads as two lines. TEXT is looked for as written;
# failing that, with that one record taken out (and its newline) and nothing else. (The serial console
# ends a line with CR LF, the kernel's and the guest's alike, so the newline may follow a CR.)
said_in() {
    grep -aq "$2" "$1" 2>/dev/null && return 0
    sed -z -E 's/\[ *[0-9]+\.[0-9]+\] [^ ()]+ \([0-9]+\) used greatest stack depth: [0-9]+ bytes left\r?\n//g' "$1" | grep -aq "$2"
}

# --selftest-said: said_in on fixture logs. A kernel stack-depth record can land in the middle of a
# line the guest writes; the line then reads as two. The match must hold for that, and must fail when
# the line is absent. Needs sh, grep, sed and mktemp.
if [ "$selftest" = said ]; then
    st=$(mktemp -d)
    rec='[    3.141592] cryptomgr_probe (83) used greatest stack depth: 15568 bytes left'
    printf 'reboot: Restarting %s\nsystem\n' "$rec" >"$st/split"
    printf 'reboot: Restarting system\n' >"$st/whole"
    printf '%s\nreboot: Restarting system\n' "$rec" >"$st/beside"
    printf 'reboot: Restarting %s\nkithd: serving\n' "$rec" >"$st/absent"
    printf 'kithd: init: restarting\n' >"$st/other"
    printf 'kithd: init: the state'"'"'s file system grown to 40[    2.926586] kithd (90) used greatest stack depth: 13224 bytes left\n709 MB\n' >"$st/grown"
    printf 'kithd: init: sta[    1.208476] kithd (90) used greatest stack depth: 13224 bytes left\r\nte on /dev/vda7\r\n' >"$st/crlf"
    bad=0
    said_in "$st/grown" 'grown to 40709 MB' || { echo "vm.sh: selftest: FAIL: a line split by a record does not match" >&2; bad=1; }
    said_in "$st/crlf" 'kithd: init: state on /dev/vda7' || { echo "vm.sh: selftest: FAIL: a line split by a record on a CR LF console does not match" >&2; bad=1; }
    said_in "$st/split" 'reboot: Restarting system' || { echo "vm.sh: selftest: FAIL: an interleaved line does not match" >&2; bad=1; }
    said_in "$st/whole" 'reboot: Restarting system' || { echo "vm.sh: selftest: FAIL: a whole line does not match" >&2; bad=1; }
    said_in "$st/beside" 'reboot: Restarting system' || { echo "vm.sh: selftest: FAIL: a line beside a record does not match" >&2; bad=1; }
    ! said_in "$st/absent" 'reboot: Restarting system' || { echo "vm.sh: selftest: FAIL: a split line matches with its second half absent" >&2; bad=1; }
    ! said_in "$st/other" 'reboot: Restarting system' || { echo "vm.sh: selftest: FAIL: an absent line matches" >&2; bad=1; }
    rm -rf "$st"
    [ "$bad" = 0 ] || exit 1
    echo "vm.sh: selftest ok: said matches a line a kernel record was interleaved into, and not an absent one"
    exit 0
fi

# --selftest-kill: this script, with a stand-in for QEMU (a sleep that writes its pid), killed from
# outside by SIGKILL (no trap runs) and by SIGTERM: nothing of it may be left, and its lock must be
# free. Needs no QEMU, no KVM and no kernel. Stops only the pid the stand-in wrote, if it survives.
if [ "$selftest" = kill ]; then
    st=$(mktemp -d)
    mkdir "$st/bin"
    printf '#!/bin/sh\necho $$ >"%s/pid"\nexec sleep 300\n' "$st" >"$st/bin/qemu-system-x86_64"
    chmod +x "$st/bin/qemu-system-x86_64"
    : >"$st/kernel"; : >"$st/initrd"
    bad=0 alive=''
    for sig in KILL TERM; do
        rm -f "$st/pid"
        KITH_VM_STUB=1 KITH_VM_LOCK="$st/lock" TMPDIR="$st" PATH="$st/bin:$PATH" \
            sh "$0" --kernel "$st/kernel" --initrd "$st/initrd" --time 300 >/dev/null 2>&1 8>&- &
        shell=$!
        n=0
        until [ -s "$st/pid" ]; do
            n=$((n + 1)); [ "$n" -lt 100 ] || { echo "vm.sh: selftest: the stand-in never started" >&2; kill -9 "$shell"; exit 1; }
            sleep 0.1
        done
        qemu=$(cat "$st/pid")
        kill -"$sig" "$shell"
        n=0
        while kill -0 "$qemu" 2>/dev/null && [ "$n" -lt 50 ]; do n=$((n + 1)); sleep 0.1; done
        if kill -0 "$qemu" 2>/dev/null; then
            echo "vm.sh: selftest: FAIL: after SIG$sig to the shell its QEMU ($qemu) still runs" >&2
            bad=1 alive=1
        fi
        # (up to 5 s for the lock: the shell's own exit frees it; a QEMU that kept the descriptor never does)
        if command -v flock >/dev/null 2>&1 && ! flock -w 5 "$st/lock" true; then
            echo "vm.sh: selftest: FAIL: after SIG$sig to the shell its lock is still held" >&2
            bad=1
        fi
        kill -9 "$shell" 2>/dev/null || true # (only if it ignored the signal; reaped here)
        wait "$shell" 2>/dev/null || true
        [ -z "$alive" ] || kill -9 "$qemu" 2>/dev/null || true # (its own pid, as it survived)
        alive=''
    done
    rm -rf "$st"
    [ "$bad" = 0 ] || exit 1
    echo "vm.sh: selftest ok: killed from outside (SIGKILL, SIGTERM), no QEMU left and the lock free"
    exit 0
fi

# --selftest-sweep: the run takes the VM lock, then deletes the work folders a killed run left (SIGKILL runs
# no EXIT trap): kith-vm-work-UID.* under TMPDIR. A folder under another name, and the lock file, stay. TMPDIR
# is a folder of the selftest's own, so no real folder is touched. Needs sh and mktemp; no QEMU, KVM or kernel.
if [ "$selftest" = sweep ]; then
    st=$(mktemp -d)
    uid=$(id -u)
    mkdir "$st/bin" "$st/kith-vm-work-$uid.stale" "$st/kith-vm-work-${uid}0.keep"
    : >"$st/kith-vm-work-$uid.stale/disk.raw"
    printf '#!/bin/sh\nexit 0\n' >"$st/bin/qemu-system-x86_64"
    chmod +x "$st/bin/qemu-system-x86_64"
    : >"$st/kernel"; : >"$st/initrd"
    # (The run ends with "nothing of kithd's": only what it left matters here.)
    KITH_VM_STUB=1 KITH_VM_LOCK="$st/lock" TMPDIR="$st" PATH="$st/bin:$PATH" \
        sh "$0" --kernel "$st/kernel" --initrd "$st/initrd" --time 5 >/dev/null 2>&1 8>&- || true
    bad=0
    [ ! -e "$st/kith-vm-work-$uid.stale" ] || { echo "vm.sh: selftest: FAIL: a work folder a killed run left was not swept" >&2; bad=1; }
    [ -d "$st/kith-vm-work-${uid}0.keep" ] || { echo "vm.sh: selftest: FAIL: the sweep took a folder that is not under the prefix" >&2; bad=1; }
    [ -f "$st/lock" ] || { echo "vm.sh: selftest: FAIL: the lock file was removed" >&2; bad=1; }
    [ -z "$(ls -d "$st/kith-vm-work-$uid".* 2>/dev/null)" ] || { echo "vm.sh: selftest: FAIL: the run's own work folder was left behind" >&2; bad=1; }
    rm -rf "$st"
    [ "$bad" = 0 ] || exit 1
    echo "vm.sh: selftest ok: a run swept the work folder a killed run left, under the lock, and nothing else"
    exit 0
fi

# web_up DIR PORT: a web server of DIR on 127.0.0.1 PORT, waited for until its log says it is serving
# and it answers; sets web to its pid and returns 0, or returns 1 with the server's own error. Its
# stderr goes to a file, never /dev/null: a port another process holds kills the server at the bind,
# and only that error says why the guests hear nothing. Bounded by time tries of a second; the log
# line guards against another process answering on the port (only our server prints it, after bind).
web_up() {
    (cd "$1" && exec python3 -u -m http.server --bind 127.0.0.1 "$2") >"$work/web-$2.log" 2>"$work/web-$2.err" &
    web=$!
    web_tries=0
    until grep -aq 'Serving HTTP' "$work/web-$2.log" && curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$2/"; do
        kill -0 "$web" 2>/dev/null || { echo "vm.sh: the web server on port $2 is not running: $(cat "$work/web-$2.err")" >&2; return 1; }
        web_tries=$((web_tries + 1))
        [ "$web_tries" -lt "$time" ] || { echo "vm.sh: the web server on port $2 did not answer: $(cat "$work/web-$2.err")" >&2; return 1; }
        sleep 1
    done
}

# --selftest-web: web_up serves a directory and returns once it answers. With another process holding
# the port, its own server dies at the bind: web_up must return 1 and say that server's error, not
# call the port served by the other process. Needs python3 and curl; no QEMU, KVM or kernel.
if [ "$selftest" = web ]; then
    st=$(mktemp -d)
    work=$st time=20
    mkdir "$st/www"
    : >"$st/www/index.html"
    free=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    bad=0
    if web_up "$st/www" "$free"; then
        curl -sf --max-time 5 -o /dev/null "http://127.0.0.1:$free/index.html" || { echo "vm.sh: selftest: FAIL: the server web_up started does not serve its directory" >&2; bad=1; }
    else
        echo "vm.sh: selftest: FAIL: web_up did not start a server on a free port" >&2; bad=1
    fi
    kill "$web" 2>/dev/null || true
    wait "$web" 2>/dev/null || true
    (cd "$st/www" && exec python3 -m http.server --bind 127.0.0.1 "$free") >"$st/holder.log" 2>"$st/holder.err" &
    holder=$!
    n=0
    until curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$free/"; do
        n=$((n + 1)); [ "$n" -lt 100 ] || { echo "vm.sh: selftest: FAIL: the holder of the port never answered" >&2; kill "$holder"; exit 1; }
        sleep 0.1
    done
    if web_up "$st/www" "$free" 2>"$st/held.err"; then
        echo "vm.sh: selftest: FAIL: web_up called a port another process holds served" >&2; bad=1
        kill "$web" 2>/dev/null || true
    else
        grep -aq 'Errno' "$st/held.err" || { echo "vm.sh: selftest: FAIL: the server's own error is not said: $(cat "$st/held.err")" >&2; bad=1; }
    fi
    kill "$holder" 2>/dev/null || true
    wait "$holder" 2>/dev/null || true
    rm -rf "$st"
    [ "$bad" = 0 ] || exit 1
    echo "vm.sh: selftest ok: web_up serves a port it is given, and says the server's own error when another process holds it"
    exit 0
fi

# (KITH_VM_STUB is for that selftest: a stand-in QEMU on PATH, no KVM needed.)
command -v qemu-system-x86_64 >/dev/null 2>&1 || skip "no qemu-system-x86_64"
if [ -z "${KITH_VM_STUB:-}" ] && { ! [ -r /dev/kvm ] || ! [ -w /dev/kvm ]; }; then skip "no usable /dev/kvm"; fi

# One VM test at a time for a user on a machine: two at once starve each other into waits
# that run out, which reads as a failure. KITH_VM_LOCK names another file; empty, no wait.
lock=${KITH_VM_LOCK-/tmp/kith-vm-$(id -u).lock}
if [ -n "$lock" ] && command -v flock >/dev/null 2>&1; then
    exec 8>>"$lock"
    flock -w 7200 8 || { echo "vm.sh: another VM test has held $lock for two hours" >&2; exit 1; }
    # (Holding the lock, no other run is using a work folder: the folders under this prefix are those of
    # runs killed with SIGKILL, which ran no EXIT trap, 2-3 GB of disk copies each. The lock file is not one.)
    for old in "${TMPDIR:-/tmp}"/kith-vm-work-"$(id -u)".*; do
        [ ! -d "$old" ] || rm -rf "$old" || true
    done
fi

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/kith-vm-work-$(id -u).XXXXXX")
vms='' web='' found=''
# (What a test left running goes with it; its consoles' logs are kept where KITH_VM_LOGS
# names a directory, for a failure that does not come again. Stopped, it ends there: a trap on
# TERM alone would clean up and then go on running the test.)
# A write a control node makes as itself that the leader refused (raft.rs `write`, own_writes.rs)
# is a call site no suite expects: the run fails whatever the suite said, and names the lines.
refusals() { grep -ahs "refused a control node.s own write" "$work"/log "$work"/*.log | head -n 3; }
# Everything this run starts carries KITH_VM_RUN in its environment, and $reap ends what carries it
# (TERM, then KILL for what is left a second later): the QEMU itself, which a `kill` of its `timeout`
# wrapper does not reach when the shell is gone, and no process by name. The EXIT trap runs it; so does a
# watcher of its own (own session, no lock descriptor) for the shell killed with SIGKILL, which runs no trap.
KITH_VM_RUN=$$.$(date +%s%N); export KITH_VM_RUN
reap='for sig in TERM KILL; do pids=; for f in $(grep -lzx "KITH_VM_RUN=$1" /proc/[0-9]*/environ 2>/dev/null); do p=${f#/proc/}; pids="$pids ${p%/environ}"; done; [ -z "$pids" ] || { kill -$sig $pids 2>/dev/null; sleep 1; }; done; true'
setsid=''; ! command -v setsid >/dev/null 2>&1 || setsid=setsid
env -u KITH_VM_RUN $setsid sh -c 'while kill -0 "$1" 2>/dev/null; do sleep 1; done; exec sh -c "$2" sh "$3"' sh $$ "$reap" "$KITH_VM_RUN" </dev/null >/dev/null 2>&1 8>&- &
trap 'st=$?; kill $vms $web 2>/dev/null || true; env -u KITH_VM_RUN sh -c "$reap" sh "$KITH_VM_RUN"; [ -z "${KITH_VM_LOGS:-}" ] || cp "$work"/*.log "$work"/log "$work"/wg "$work"/wg.err "$work"/arp "$work"/arp.err "$KITH_VM_LOGS"/ 2>/dev/null || true; if [ "$st" -ne 0 ] && [ -n "${KITH_VM_LOGS:-}" ] && [ ! -e "$KITH_VM_LOGS/fail" ]; then echo "vm.sh: FAIL: exit $st without a fail file: a failure that did not go through fail(), see the log" >"$KITH_VM_LOGS/fail" 2>/dev/null || true; fi; found=$(refusals); rm -rf "$work"; [ -z "$found" ] || { echo "vm.sh: FAIL: a write a control node made as itself was refused, which no suite expects:" >&2; echo "$found" >&2; exit 1; }' EXIT
trap 'exit 1' INT TERM
said() { said_in "$work/log" "$1"; }
fail() { cat "$work/log"; echo "vm.sh: FAIL: $1" >&2; [ -z "${KITH_VM_LOGS:-}" ] || echo "vm.sh: FAIL: $1" >"$KITH_VM_LOGS/fail" 2>/dev/null || true; exit 1; }

if [ -n "$test" ] && [ "$test" != init ]; then
    . "$root/ci/vm/tests.sh"
fi

if [ -z "$kernel" ]; then
    for k in "/boot/vmlinuz-$(uname -r)" "/lib/modules/$(uname -r)/vmlinuz" /boot/vmlinuz-* /boot/vmlinuz; do
        [ -r "$k" ] && { kernel=$k; break; }
    done
    # (A machine with no kernel of its own, as a cluster Job's is, starts the image's: built here if need be.)
    if [ -z "$kernel" ]; then
        [ -r "$root/target/os/vmlinuz" ] || sh "$root/os/build.sh" --out "$root/target/os" >&2 || { [ $? -ne 3 ] || skip "no readable kernel in /boot (pass --kernel), and this machine cannot build the image's"; exit 1; }
        kernel=$root/target/os/vmlinuz
    fi
fi
[ -r "$kernel" ] || skip "kernel $kernel is not readable"

if [ -z "$initrd" ]; then
    command -v cpio >/dev/null 2>&1 || skip "no cpio to make an initramfs"
    command -v zstd >/dev/null 2>&1 || skip "no zstd to make an initramfs"
    kithd=$(sh "$root/ci/musl.sh")/kithd
    mkdir "$work/fs"
    cp "$kithd" "$work/fs/init"
    (cd "$work/fs" && echo init | cpio -o -H newc --quiet | zstd -q -19 >"$work/initrd.zst")
    initrd=$work/initrd.zst
fi
[ -r "$initrd" ] || { echo "vm.sh: cannot read initramfs $initrd" >&2; exit 2; }

set -- -enable-kvm -cpu host -m 512 -smp 2 -display none -serial stdio -monitor none \
    -no-reboot -kernel "$kernel" -initrd "$initrd" -append "$append"
[ -z "$disk" ] || set -- "$@" -snapshot -drive "file=$disk,format=raw,if=virtio"

if [ "$test" = init ]; then
    command -v socat >/dev/null 2>&1 || skip "no socat to press keys with"
    began=$(date +%s%N)
    shift 13 # (up to -monitor none: here the console goes to a file, and keys come in)
    # Started, told to stop with what $1 says to QEMU, and the console then to say $2.
    started() {
        told=$1 last=$2
        shift 2
        rm -f "$work/log" "$work/keys"
        timeout --foreground "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -display none \
            -serial "file:$work/log" -monitor "unix:$work/keys,server,nowait" "$@" </dev/null >/dev/null 2>&1 8>&- &
        vm=$!
        until said 'kithd: serving '; do
            kill -0 "$vm" 2>/dev/null || fail "the VM ended before kithd served"
            sleep 0.05
        done
        [ -n "${took:-}" ] || took=$((($(date +%s%N) - began) / 1000000))
        echo "$told" | socat - "unix-connect:$work/keys" >/dev/null
        wait "$vm" || fail "the VM did not end within ${time} s of starting (told: $told)"
        cat "$work/log"
        # Each boot's console kept: started() removes log on the next boot; the exit trap copies *.log.
        boots=$((${boots:-0} + 1))
        cp "$work/log" "$work/boot$boots.log" 2>/dev/null || true
        said 'kithd: init: .* is up' || fail "kithd did not say it was the first process"
        said "$last" || fail "after $told the console never said: $last"
        ! said 'Kernel panic' || fail "the kernel panicked: its first process ended"
    }
    started 'sendkey ctrl-alt-delete' 'reboot: Restarting system' "$@"
    # The power button (a VPS panel's shutdown): kithd stops what it runs and powers off.
    started system_powerdown 'reboot: Power down' "$@"
    resident=$(grep -ao 'told to stop: [0-9]* kB resident, [0-9]* kB of it files' "$work/log" | tail -n 1)
    [ -n "$resident" ] || fail "kithd did not say what it held in memory when told to stop"
    echo "vm.sh: kithd as the first process, from a memory disk, ${resident#told to stop: }"
    echo "vm.sh: kithd served ${took} ms after QEMU started (the firmware and kernel included)"
    # The 10 s is scaled as ci/budgets.py's timings are: the host's 1-minute load over its CPUs, at least 1
    # (the VM waits for a CPU too: 10041 ms under load once).
    read -r load _ </proc/loadavg 2>/dev/null || load=0
    cpus=$(nproc 2>/dev/null || echo 1)
    budget=$(awk -v l="${load:-0}" -v c="$cpus" 'BEGIN { f = l / c; if (f < 1) f = 1; printf "%d", 10000 * f }')
    echo "vm.sh: boot budget ${budget} ms (10000 x load ${load:-0} over ${cpus} CPUs, at least 1)"
    [ "$took" -lt "$budget" ] || { echo "vm.sh: FAIL: ${took} ms is over the budget of ${budget} ms" >&2; exit 1; }
    echo "vm.sh: ok: kithd is the first process, serves, restarts the machine when told, and powers it off at the power button"
    exit 0
fi

# panic=-1 reboots at once, -no-reboot turns that into QEMU exiting: a kithd that
# stops (as init, it must not) ends the run; the timeout ends one that does not.
# (In the background and waited for: a signal's trap waits for a command in the foreground.)
# (--foreground, here and at every QEMU start in ci/vm/: QEMU stays in this run's process group, so a SIGKILL to the group ends it too; a plain timeout moves it to a group of its own.)
timeout --foreground "$time" qemu-system-x86_64 "$@" </dev/null >"$work/log" 2>&1 8>&- &
vms=$!
wait "$vms" || true
cat "$work/log"
if grep -qi kithd "$work/log"; then
    echo "vm.sh: ok: kithd spoke"
else
    echo "vm.sh: FAIL: nothing of kithd's in the console output" >&2
    exit 1
fi
