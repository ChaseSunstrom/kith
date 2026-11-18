#!/bin/sh
# shellcheck disable=SC1091,SC2034 # (names the driver and its parts share)
# Boot a kernel in QEMU and print what it said: by default the host's kernel with the
# static kithd as init (so, the kernel and kithd, nothing else). The image,
# installer, update and cluster tests reuse it with their own kernel, initramfs and disk image.
# The tests' bodies are in ci/vm/NAME.sh, each sourced where it runs, so no file is too long to read.
#
#   sh ci/vm.sh [--kernel FILE] [--initrd FILE] [--disk IMAGE] [--append ARGS] [--time SECONDS]
#   sh ci/vm.sh --test init     kithd as the first process: up, serving, restarts when told
#   sh ci/vm.sh --test image    kith OS's disk image (os/build.sh), booted under UEFI on a longer disk
#   sh ci/vm.sh --test update   that image updating itself, and going back when it must
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
#   sh ci/vm.sh --test share    two nodes: a shared volume of one, mounted by a container on the other;
#                               an encrypted volume of one, its key kept by the other
#   sh ci/vm.sh --test pods     two nodes: pods with a network, an address and a root each to write to,
#                               found by their Service's name and reaching out from behind their node
#                               (one node's pod range is not the default: --pod-range)
#   sh ci/vm.sh --test poddns   two nodes on the mesh: a pod of a node with no --dns finds a name outside
#                               the cluster through its node's upstream, a second kithd with its own
#   sh ci/vm.sh --test services one node: every byte through a Service to a pod on the same node comes
#                               back in order, however its connection ends, passed by kithd from a pod
#                               and by the kernel from the node's own network
#   sh ci/vm.sh --test compose  one node: ci/compose/stack.yml (four services of the test pod) imported with
#                               kith import compose, applied, ready, each asked for by its compose name
#   sh ci/vm.sh --test outlive  one node: kithd killed under a pod, an exec unit and Jobs: the machine
#                               stays up, kithd serves again and takes them back as they ran; ten
#                               kills in a minute restart the machine
#   sh ci/vm.sh --test quota    one node whose state disk keeps project quotas: a pod's storage limit
#                               holds at the write, in its root and its scratch, however it tries past it
#   sh ci/vm.sh --test kube     two nodes: the real kubectl and helm against them, with manifests written
#                               for Kubernetes; what they make runs, rolls out, keeps its data and is waited for
#   sh ci/vm.sh --test worker   two nodes, one a worker: it runs what is placed on it with its Secret, its
#                               disk never has another's, and what it does with no control node in reach
#   sh ci/vm.sh --test chaos    three nodes taking writes: each in turn cut off from the others, each
#                               in turn losing power, then all at once; what was acknowledged is on all three
#   sh ci/vm.sh --test home     three nodes with a house address in the Cluster: one MAC answers for it
#                               and DNS answers from it; the holder reset, and the next stopped: another
#                               announces it within 10 s and two are never heard at once
#   sh ci/vm.sh --test access   three nodes: a write let through by a node that had not heard its
#                               RoleBinding was deleted is refused where the log is kept
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
  --test modules   instead: the 'all' image (its drivers are modules, signed with the key of its
                   build): kithd loads the driver of an HDA controller at start, and of a USB
                   audio device the monitor adds later, in the same boot; the same spec built
                   with one byte of snd-usb-audio changed is refused on one console line; same
                   needs as image, and the image is built twice
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
                   writes to /dev/stdout by name; a pod that is root is kept from a
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
  --test outlive   instead: one node on the mesh with ci/pod.rs as an image and on its
                   disk: kithd killed (SIGKILL) under a pod of two containers, an exec
                   unit and a Job; the machine stays up, kithd serves again within
                   2 s and takes each back as it ran; killed ten times in a minute,
                   the machine restarts
  --test services  instead: one node with no --mesh (as kith OS starts) with ci/pod.rs as a container image
                   already there: a pod that sends back every byte it is sent, its
                   Service, and a Job on the same node sending through that Service
                   over 680 connections (one after another and side by side, from
                   nothing to more than a megabyte, half closed at once when all is
                   sent, reset by either end on the way) and one of 5000 small turns:
                   every byte comes back in order. The Job runs twice: in a pod,
                   kithd passes its bytes; on the node's own network, the kernel
                   sends its connections straight to the pod. Needs rustc for
                   x86_64-unknown-linux-musl
  --test compose   instead: one node on the mesh, and on this machine `kith import
                   compose` of ci/compose/stack.yml (four services of the test pod,
                   nothing in it left out) applied to it. Expected: each Workload ready,
                   each Service given its backend, and a Job in a pod asking each service
                   by its compose name (and the alias a container_name gives) is answered
                   by that service's pod; the seconds from the apply to all four ready are
                   printed (kith's side of T-0320's comparison with docker compose)
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
  --test home      instead: three nodes as for rollout, a house address (10.9.0.100/24)
                   in the Cluster, and a machine on their network (ci/lan_probe.py)
                   that asks who has it four times a second. Expected: one card
                   answers and announces it, DNS asked of it answers from it, with
                   the holder reset by the hypervisor and then (after it is back)
                   the next one stopped, another announces it within 10 s (the
                   seconds are printed), and two cards are never heard answering at
                   once, not when the stopped one goes on again; needs socat and
                   python3 as --test chaos does
  --test access    instead: three nodes as for rollout, and the cluster's admin
                   writing through n2 and n3 by a RoleBinding that is deleted through
                   n1, once while n2 is cut off from the others. Expected: no write
                   begun after the deletion was acknowledged is acknowledged or
                   kept, and the one n2 let through while it was cut off is refused
                   when it reaches the leader, which decided again; needs what
                   --test rollout needs
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
  --help           this text

Without --initrd it builds kithd for x86_64-unknown-linux-musl (with zig as the C
compiler when there is no musl-gcc: ci/musl.sh) and needs cpio and zstd.
EOF
}

kernel='' initrd='' disk='' time=60 test=''
append="console=ttyS0 panic=-1"
while [ $# -gt 0 ]; do
    case $1 in
    --help | -h) usage; exit 0 ;;
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
case $test in '' | init | image | update | modules | rollout | install | vps | netboot | crypt | tpm | duress | blackout | share | pods | poddns | services | compose | quota | kube | worker | chaos | home | access | policy | tunnel | outlive) ;; *) echo "vm.sh: --test knows: init, image, update, modules, rollout, install, vps, netboot, crypt, tpm, duress, blackout, share, pods, poddns, services, compose, quota, kube, worker, chaos, home, access, policy, tunnel, outlive" >&2; exit 2 ;; esac
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
command -v qemu-system-x86_64 >/dev/null 2>&1 || skip "no qemu-system-x86_64"
if ! [ -r /dev/kvm ] || ! [ -w /dev/kvm ]; then skip "no usable /dev/kvm"; fi

# One VM test at a time for a user on a machine: two at once starve each other into waits
# that run out, which reads as a failure. KITH_VM_LOCK names another file; empty, no wait.
lock=${KITH_VM_LOCK-/tmp/kith-vm-$(id -u).lock}
if [ -n "$lock" ] && command -v flock >/dev/null 2>&1; then
    exec 8>>"$lock"
    flock -w 7200 8 || { echo "vm.sh: another VM test has held $lock for two hours" >&2; exit 1; }
fi

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
vms='' web='' found=''
# (What a test left running goes with it; its consoles' logs are kept where KITH_VM_LOGS
# names a directory, for a failure that does not come again. Stopped, it ends there: a trap on
# TERM alone would clean up and then go on running the test.)
# A write a control node makes as itself that the leader refused (raft.rs `write`, own_writes.rs)
# is a call site no suite expects: the run fails whatever the suite said, and names the lines.
refusals() { grep -ahs "refused a control node.s own write" "$work"/log "$work"/*.log | head -n 3; }
trap 'kill $vms $web 2>/dev/null || true; [ -z "${KITH_VM_LOGS:-}" ] || cp "$work"/*.log "$work"/log "$KITH_VM_LOGS"/ 2>/dev/null || true; found=$(refusals); rm -rf "$work"; [ -z "$found" ] || { echo "vm.sh: FAIL: a write a control node made as itself was refused, which no suite expects:" >&2; echo "$found" >&2; exit 1; }' EXIT
trap 'exit 1' INT TERM
said() { grep -aq "$1" "$work/log" 2>/dev/null; }
fail() { cat "$work/log"; echo "vm.sh: FAIL: $1" >&2; exit 1; }

if [ -n "$test" ] && [ "$test" != init ]; then
    . "$root/ci/vm/tests.sh"
fi

if [ -z "$kernel" ]; then
    for k in "/boot/vmlinuz-$(uname -r)" "/lib/modules/$(uname -r)/vmlinuz" /boot/vmlinuz-* /boot/vmlinuz; do
        [ -r "$k" ] && { kernel=$k; break; }
    done
    [ -n "$kernel" ] || skip "no readable kernel in /boot (pass --kernel)"
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
        timeout "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -display none \
            -serial "file:$work/log" -monitor "unix:$work/keys,server,nowait" "$@" </dev/null >/dev/null 2>&1 &
        vm=$!
        until said 'kithd: serving '; do
            kill -0 "$vm" 2>/dev/null || fail "the VM ended before kithd served"
            sleep 0.05
        done
        [ -n "${took:-}" ] || took=$((($(date +%s%N) - began) / 1000000))
        echo "$told" | socat - "unix-connect:$work/keys" >/dev/null
        wait "$vm" || fail "the VM did not end within ${time} s of starting (told: $told)"
        cat "$work/log"
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
    [ "$took" -lt 10000 ] || { echo "vm.sh: FAIL: over 10 s" >&2; exit 1; }
    echo "vm.sh: ok: kithd is the first process, serves, restarts the machine when told, and powers it off at the power button"
    exit 0
fi

# panic=-1 reboots at once, -no-reboot turns that into QEMU exiting: a kithd that
# stops (as init, it must not) ends the run; the timeout ends one that does not.
timeout "$time" qemu-system-x86_64 "$@" </dev/null >"$work/log" 2>&1 || true
cat "$work/log"
if grep -qi kithd "$work/log"; then
    echo "vm.sh: ok: kithd spoke"
else
    echo "vm.sh: FAIL: nothing of kithd's in the console output" >&2
    exit 1
fi
