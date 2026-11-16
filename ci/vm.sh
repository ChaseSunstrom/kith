#!/bin/sh
# Boot a kernel in QEMU and print what it said: by default the host's kernel with the
# static kithd as init (so, the kernel and kithd, nothing else). The image,
# installer, update and cluster tests reuse it with their own kernel, initramfs and disk image.
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
#   sh ci/vm.sh --test quota    one node whose state disk keeps project quotas: a pod's storage limit
#                               holds at the write, in its root and its scratch, however it tries past it
#   sh ci/vm.sh --test kube     two nodes: the real kubectl and helm against them, with manifests written
#                               for Kubernetes; what they make runs, rolls out, keeps its data and is waited for
#   sh ci/vm.sh --test worker   two nodes, one a worker: it runs what is placed on it with its Secret, its
#                               disk never has another's, and what it does with no control node in reach
#   sh ci/vm.sh --test chaos    three nodes taking writes: each in turn cut off from the others, each
#                               in turn losing power, then all at once; what was acknowledged is on all three
#   sh ci/vm.sh --test access   three nodes: a write let through by a node that had not heard its
#                               RoleBinding was deleted is refused where the log is kept
#   sh ci/vm.sh --test policy   two nodes whose policy turns off exec units, VM paths and /v1/run: kithd
#                               cut its bounding set, and a pod that is root, a container with no filter
#                               and a sandbox inside a container still run
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
  --test services  instead: one node on the mesh with ci/pod.rs as a container image
                   already there: a pod that sends back every byte it is sent, its
                   Service, and a Job on the same node sending through that Service
                   over 680 connections (one after another and side by side, from
                   nothing to more than a megabyte, half closed at once when all is
                   sent, reset by either end on the way) and one of 5000 small turns:
                   every byte comes back in order. The Job runs twice: in a pod,
                   kithd passes its bytes; on the node's own network, the kernel
                   sends its connections straight to the pod. Needs rustc for
                   x86_64-unknown-linux-musl
  --test quota     instead: one node as for services, its state disk made with project
                   quotas (as os/build.sh makes it). Expected: kithd says it holds
                   pods' storage limits at the write; a pod of 64Ki removed and the
                   node started again, the pod given its id after it is held to its
                   own limit, not that one's; a pod of 64 MiB writing 200 MiB
                   is stopped at its limit by the kernel, in its root, its scratch
                   and a file it removed and holds open, and is not replaced, while
                   one beside it loses no write; a pod with the node's users is
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
                   pod, a Job and a CronJob's Job reading all of it through their
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
  --help          this text

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
case $test in '' | init | image | update | rollout | install | vps | netboot | crypt | tpm | duress | share | pods | poddns | services | quota | kube | worker | chaos | access | policy) ;; *) echo "vm.sh: --test knows: init, image, update, rollout, install, vps, netboot, crypt, tpm, duress, share, pods, poddns, services, quota, kube, worker, chaos, access, policy" >&2; exit 2 ;; esac
# (From here on the TPM test is the encrypted one, with its own end.)
sealing='' duress=''
[ "$test" != tpm ] || test=crypt sealing=1
[ "$test" != duress ] || test=crypt duress=1
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

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
vms='' web=''
# (What a test left running goes with it; its consoles' logs are kept where KITH_VM_LOGS
# names a directory, for a failure that does not come again.)
trap 'kill $vms $web 2>/dev/null || true; [ -z "${KITH_VM_LOGS:-}" ] || cp "$work"/*.log "$work"/log "$KITH_VM_LOGS"/ 2>/dev/null || true; rm -rf "$work"' EXIT INT TERM
said() { grep -aq "$1" "$work/log" 2>/dev/null; }
fail() { cat "$work/log"; echo "vm.sh: FAIL: $1" >&2; exit 1; }

if [ -n "$test" ] && [ "$test" != init ]; then
    command -v socat >/dev/null 2>&1 || skip "no socat to press keys with"
    command -v openssl >/dev/null 2>&1 || skip "no openssl to call the node with"
    firmware=''
    for f in /usr/share/edk2-ovmf/x64/OVMF.4m.fd /usr/share/edk2/x64/OVMF.4m.fd /usr/share/OVMF/OVMF.fd /usr/share/ovmf/OVMF.fd; do
        [ -r "$f" ] && { firmware=$f; break; }
    done
    [ -n "$firmware" ] || skip "no UEFI firmware (OVMF)"
    command -v sfdisk >/dev/null 2>&1 || skip "no sfdisk to find the root partition with"
    sh "$root/os/build.sh" --check >&2 || { [ $? -ne 3 ] || skip "this machine cannot build the image"; exit 1; }
    if [ "$test" = rollout ] || [ "$test" = share ] || [ "$test" = pods ] || [ "$test" = poddns ] || [ "$test" = services ] || [ "$test" = quota ] || [ "$test" = kube ] || [ "$test" = worker ] || [ "$test" = chaos ] || [ "$test" = access ] || [ "$test" = policy ]; then
        for tool in curl python3 xxd; do
            command -v "$tool" >/dev/null 2>&1 || skip "no $tool"
        done
        kubectl=${KITH_KUBECTL:-$(command -v kubectl || true)}
        helms=$(printf '%s' "${KITH_HELM:-$(command -v helm || true)}" | tr ':' ' ')
        [ "$test" != kube ] || [ -x "$kubectl" ] || skip "no kubectl (KITH_KUBECTL names one; sh ci/kube.sh --vm fetches one)"
        [ "$test" != quota ] || command -v socat >/dev/null 2>&1 || skip "no socat to restart a node with"
        if [ "$test" = pods ]; then
            command -v socat >/dev/null 2>&1 || skip "no socat to plug a keyboard in with"
        fi
        if [ "$test" = pods ] || [ "$test" = policy ]; then
            bwrap=$(command -v bwrap) || skip "no bwrap (bubblewrap) to start a sandbox inside a container with"
        fi
        [ "$time" -gt 60 ] || time=900
        [ "$test" != kube ] || time=$((time * 2))
        port=$((20000 + $$ % 20000))
        fail() { tail -n 30 "$work"/n?.log; echo "vm.sh: FAIL: $1" >&2; exit 1; }
        cargo build -q --manifest-path "$root/Cargo.toml" -p kith-cli >&2
        # (rollout, chaos and access: three nodes and nothing more said to kithd; share, pods, kube and
        # worker: two, on the mesh; services and quota: one, on the mesh.)
        others='2 3' more='' inside=2049 lan='' base=$root/target/os https=''
        seed() { :; }
      if [ "$test" = share ] || [ "$test" = pods ] || [ "$test" = poddns ] || [ "$test" = services ] || [ "$test" = quota ] || [ "$test" = kube ] || [ "$test" = worker ] || [ "$test" = policy ]; then
        others=2 more=--mesh project=''
        [ "$test" != services ] || others=''
        # (quota: a state disk with project quotas, as os/build.sh makes it; the others' have none,
        # as a node's state from before had none: kithd counts what their pods write.)
        [ "$test" != quota ] || others='' project='-I 256 -O quota,project'
        # (pods: a state disk of 32 MB keeps 8 MiB free, so a pod filling it is seen in time.)
        # (And an image no unit has used for two minutes goes: README, --image-grace.)
        [ "$test" != pods ] || more='--mesh --storage-reserve 8388608 --image-grace 120'
        # (worker: this machine asks what listens on port 80 of a node's own network.)
        [ "$test" != worker ] || inside=80
        # (policy: no way left to be root with all of the kernel's capabilities, so kithd gives up the rest.
        # QEMU reads a comma in -smbios as the end of a value, so each one here is doubled.)
        [ "$test" != policy ] || more='--mesh --node-policy no-exec-units,,no-vm-paths,,no-run'
        # A container image the nodes have without asking anybody (they reach no registry
        # here): kith itself, put where a node keeps an image it has pulled, in a state
        # partition made again with that in it.
        seed() { # DISK
            if ! [ -f "$work/state.img" ]; then
                digest=$(printf kith | sha256sum | cut -d ' ' -f 1)
                image=$work/seed/runtime/images/$digest
                mkdir -p "$work/seed/runtime/refs" "$image/rootfs/bin"
                cp "$(sh "$root/ci/musl.sh")/kith" "$image/rootfs/bin/kith"
                echo '{}' >"$image/config.json"
                printf '{"digest":"sha256:%s","entrypoint":[],"cmd":[],"env":[],"user":null}' "$digest" >"$work/seed/runtime/refs/kith.test%2fkith:1"
                # And what those tests' pods run (ci/pod.rs), as an image that names no user,
                # as one that names a user who is not root, and as two that say what to start
                # (an image nothing more is said of, as a chart has one). (share: what a
                # container's ids are, and what it sees of files.)
                rustc --edition 2024 -O -C panic=abort --target x86_64-unknown-linux-musl -o "$work/pod" "$root/ci/pod.rs" >&2
                digest=$(printf pod | sha256sum | cut -d ' ' -f 1)
                image=$work/seed/runtime/images/$digest
                mkdir -p "$image/rootfs/bin"
                cp "$work/pod" "$image/rootfs/bin/pod"
                echo '{}' >"$image/config.json"
                printf '{"digest":"sha256:%s","entrypoint":[],"cmd":[],"env":[],"user":null}' "$digest" >"$work/seed/runtime/refs/kith.test%2fpod:1"
                printf '{"digest":"sha256:%s","entrypoint":[],"cmd":[],"env":[],"user":"1000"}' "$digest" >"$work/seed/runtime/refs/kith.test%2fpod:user"
                for tag in serve again; do
                    printf '{"digest":"sha256:%s","entrypoint":["/bin/pod","serve"],"cmd":[],"env":[],"user":null}' "$digest" >"$work/seed/runtime/refs/kith.test%2fpod:$tag"
                done
                if [ "$test" = quota ]; then
                    # (quota: files of the image that a pod's root is made of, for it to change:
                    # one larger than its limit, others to rename over and to link. Not zeros,
                    # which mkfs keeps no blocks for.)
                    mkdir -p "$image/rootfs/data" "$image/rootfs/tree"
                    head -c 12582912 /dev/urandom >"$image/rootfs/big"
                    head -c 1048576 /dev/urandom >"$image/rootfs/data/small"
                    head -c 1048576 /dev/urandom >"$image/rootfs/data/other"
                    echo leaf >"$image/rootfs/tree/leaf"
                fi
                if [ "$test" = pods ] || [ "$test" = policy ]; then
                    # And bubblewrap as this machine has it, with what it is linked to, beside
                    # pod, for a user who is not root: a sandbox started inside a container.
                    digest=$(printf sandbox | sha256sum | cut -d ' ' -f 1)
                    image=$work/seed/runtime/images/$digest
                    mkdir -p "$image/rootfs/bin"
                    cp "$work/pod" "$image/rootfs/bin/pod"
                    cp -L "$bwrap" "$image/rootfs/bin/bwrap"
                    ldd "$bwrap" | awk '$2 == "=>" && $3 ~ /^\// { print ($1 ~ /^\// ? $1 : $3), $3 } $1 ~ /^\// && $2 != "=>" { print $1, $1 }' >"$work/linked"
                    while read -r to from; do
                        mkdir -p "$image/rootfs${to%/*}"
                        cp -L "$from" "$image/rootfs$to"
                    done <"$work/linked"
                    echo '{}' >"$image/config.json"
                    printf '{"digest":"sha256:%s","entrypoint":[],"cmd":[],"env":[],"user":"1000"}' "$digest" >"$work/seed/runtime/refs/kith.test%2fsandbox:1"
                    # And pod again under another name, for a Workload that is deleted: its
                    # image goes once unused for --image-grace. (Each image here is marked
                    # used a day ahead, so none goes before a unit has used it: no registry
                    # would give it back. Its pod is the other's, linked: a copy would put
                    # the state disk under its reserve, and every unused image would go.)
                    digest=$(printf gone | sha256sum | cut -d ' ' -f 1)
                    image=$work/seed/runtime/images/$digest
                    mkdir -p "$image/rootfs/bin"
                    ln "$work/seed/runtime/images/$(printf pod | sha256sum | cut -d ' ' -f 1)/rootfs/bin/pod" "$image/rootfs/bin/pod"
                    echo '{}' >"$image/config.json"
                    printf '{"digest":"sha256:%s","entrypoint":[],"cmd":[],"env":[],"user":null}' "$digest" >"$work/seed/runtime/refs/kith.test%2fgone:1"
                    touch -d '+1 day' "$work"/seed/runtime/images/*/config.json
                fi
                sfdisk -l -o Start,Sectors,Name "$1" | awk '$3 == "state" { print $1, $2 }' >"$work/state.at"
                read -r state_start state_sectors <"$work/state.at"
                mkfs.ext4 -q -d "$work/seed" -E root_owner=0:0 $project "$work/state.img" "$((state_sectors / 2))k" >&2
            fi
            read -r state_start state_sectors <"$work/state.at"
            dd if="$work/state.img" of="$1" bs=512 seek="$state_start" conv=notrunc status=none
            # (Room for an image that is pulled: the state grows to the disk's end at the first start.)
            # (quota: room for what its pods write.)
            case $test${KITH_E2E:-} in pods1 | kube1 | quota*) truncate -s 2G "$1" ;; esac
        }
      elif [ "$test" = rollout ]; then
        # The nodes run an image built with the release key: the first release they take
        # is one it signed, whoever applies one. (They fetch from this machine, on the
        # network QEMU gives them: their own, so --lan-releases.)
        public=$("$root/target/debug/kith" package keygen "$work/key")
        KITH_RELEASE_KEY=$public sh "$root/os/build.sh" --out "$work/base" >&2
        base=$work/base lan=--lan-releases
        # (KITH_NODE_POLICY: the nodes' policy, so that an update is taken by nodes that have
        # cut their bounding set: no-exec-units,no-vm-paths,no-run.)
        [ -z "${KITH_NODE_POLICY:-}" ] || lan="$lan --node-policy $(printf '%s' "$KITH_NODE_POLICY" | sed 's/,/,,/g')"
        # Two releases, both signed: one that runs, and one whose root is not the one its
        # verity tree was made for. The nodes fetch them from this machine.
        KITH_OS_VERSION=9.0.0-next sh "$root/os/build.sh" --out "$work/next" >&2
        mkdir "$work/www"
        cp "$work/next/kith-os.update" "$work/www/next.update"
        cp "$work/next/root.squashfs" "$work/broken.root"
        dd if=/dev/urandom of="$work/broken.root" bs=4096 count=8 conv=notrunc status=none
        sh "$root/os/update.sh" 9.0.0-broken "$(sha256sum "$work/broken.root" | cut -d ' ' -f 1)" "$work/broken.root" \
            "$work/next/root.verity" "$work/next/kith-a.efi" "$work/next/kith-b.efi" >"$work/www/broken.update"
        sign() { sh "$root/os/update.sh" --sign "$work/${2:-key}" "$work/www/$1.update"; }
        # A second key, which the first hands over to in the release every node takes.
        public2=$("$root/target/debug/kith" package keygen "$work/key2")
        handed() { sh "$root/os/update.sh" --handover "$work/$1" "$work/www/next.update" "$public2"; } # KEYFILE
        by=$public more='' allow=''
        (cd "$work/www" && exec python3 -m http.server --bind 127.0.0.1 $((port + 9))) >/dev/null 2>&1 &
        web=$!
      fi

        # Each node: a card on a network the three share (QEMU passes it over multicast on
        # this machine's loopback), with a fixed address, and one out to this machine (which
        # reaches the node's API through it, and tries its NFS port, or port $inside).
        node() { # N [kithd's further arguments]
            [ -f "$work/n$1.raw" ] || { cp "$base/kith-os.raw" "$work/n$1.raw" && seed "$work/n$1.raw"; }
            timeout "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -display none \
                -machine q35 -bios "$firmware" -drive "file=$work/n$1.raw,format=raw,if=virtio" -device qemu-xhci,id=usb \
                -netdev "socket,id=lan,mcast=230.0.0.1:$((port + 8)),localaddr=127.0.0.1" -device "virtio-net-pci,netdev=lan,mac=52:54:00:00:09:0$1" \
                -netdev "user,id=out,hostfwd=tcp:127.0.0.1:$((port + $1))-:7443,hostfwd=tcp:127.0.0.1:$((port + 4 + $1))-:$inside${https:+,hostfwd=tcp:127.0.0.1:$((port + 10 + $1))-:443}" -device "virtio-net-pci,netdev=out,mac=52:54:00:00:0a:0$1" \
                -smbios "type=11,value=io.systemd.stub.kernel-cmdline-extra=kith.hostname=n$1 kith.ip=10.9.0.$1/24 -- --listen 0.0.0.0:7443 --advertise 10.9.0.$1:7443 $more $lan ${2:-}" \
                -serial "file:$work/n$1.log" -monitor "unix:$work/keys$1,server,nowait" </dev/null >/dev/null 2>&1 &
            vms="$vms $!"
        }
        field() { python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]], end="")' "$1"; }
        api() { # N METHOD PATH [FILE to send]: as the cluster's admin, to node N
            set -- "$@" ''
            curl -sf --max-time "${patience:-10}" --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
                --resolve "kith:$((port + $1)):127.0.0.1" -X "$2" -H 'Content-Type: application/json' ${4:+-d "@$4"} "https://kith:$((port + $1))$3"
        }
        any() { api 1 "$@" || api 2 "$@" || api 3 "$@"; }
        # What the cluster says, from whichever node answers:
        # "PHASE HOW-MANY-UPDATING VERSION,VERSION,VERSION REASON"; nothing while nobody does.
        see() {
            any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
nodes = sorted((r for r in found if r["kind"] == "Node"), key=lambda r: r["metadata"]["name"])
versions = ",".join(((n.get("status") or {}).get("os") or {}).get("version", "?") for n in nodes)
status = next(((r.get("status") or {}) for r in found if r["kind"] == "UpdatePlan"), {})
updating = sum(1 for state in (status.get("nodes") or {}).values() if state == "updating")
print(status.get("phase", "-"), updating, versions or "-", status.get("reason", ""))
'
        }
        until_says() { # WHAT, a pattern for see's line: wait for it; never two nodes updating at once
            waited=0
            until line=$(see) && printf '%s\n' "$line" | grep -Eq "$2"; do
                case $line in '' | *' 0 '* | *' 1 '*) ;; *) fail "more than one node updating at once: $line" ;; esac
                waited=$((waited + 1))
                [ "$waited" -lt $((time / 2)) ] || fail "waited for $1; the cluster says: $line"
                sleep 1
            done
            echo "vm.sh: $1: $line" >&2
        }
        # NAME VERSION SIGNATURE [FILE]: that release, and a plan that gives it to every node.
        # (Signed by the key $by; $more is more of the release's spec and $allow of the
        # plan's, for this one release.)
        release() {
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"OSRelease","metadata":{"name":"$1"},
  "spec":{"version":"$2","image":"http://10.0.2.2:$((port + 9))/${4:-$1}.update","publicKey":"$by","signature":"$3"$more}},
 {"apiVersion":"kith.dev/v1","kind":"UpdatePlan","metadata":{"name":"all"},"spec":{"release":"$1"$allow}}]
EOF
            more='' allow=''
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the release $1 was not applied"
        }
        starts() { grep -ac "Kernel command line:.*kith.slot=$2" "$work/n$1.log"; }

        # Nobody can log in to these nodes: the first says a token on its console, and
        # who sends it back is the cluster's admin; the others join with tokens it asks for.
        # (poddns: the first node asks the second for names it does not know, and the second asks an
        # outside resolver on this machine; KITH_POD_NOUPSTREAM=1 gives both an upstream that answers
        # nothing, the control. Neither asks the network out there.)
        first='' joined=''
        if [ "$test" = poddns ]; then
            first='--dns-upstream 10.9.0.2:5353'
            joined="--dns 0.0.0.0:5353 --dns-upstream 10.0.2.2:$((port + 9))"
            [ "${KITH_POD_NOUPSTREAM:-}" != 1 ] || { first='--dns-upstream 10.9.0.9:5353'; joined='--dns 0.0.0.0:5353 --dns-upstream 10.9.0.9:5353'; }
        fi
        node 1 "--claim ${first:-}"
        tries=0
        until token=$(grep -ao 'sends this token to /v1/claim does: kith1\.[0-9a-f.]*' "$work/n1.log" 2>/dev/null) && [ -n "$token" ] \
            && [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 -H 'Content-Type: application/json' -d '{"token":"x","name":"root"}' "https://127.0.0.1:$((port + 1))/v1/claim")" = 403 ]; do
            tries=$((tries + 1))
            [ "$tries" -lt 300 ] || fail "the first node offered no claim, or did not answer"
            sleep 0.2
        done
        claimed=$(curl -sk --max-time 10 -H 'Content-Type: application/json' -d "{\"token\":\"${token##* }\",\"name\":\"root\"}" "https://127.0.0.1:$((port + 1))/v1/claim")
        for part in ca cert key; do
            printf '%s' "$claimed" | (umask 077 && field "$part" >"$work/$part.pem") || fail "the claim was refused: $claimed"
        done
        for n in $others; do
            # (worker: the node it lets in is one, and is sent a view of the store, never the store.)
            asks=/v1/tokens
            [ "$test" != worker ] || asks='/v1/tokens?trust=worker'
            join=$(api 1 POST "$asks" | field token) || fail "no join token over TLS"
            # (pods: the second node takes its pods' addresses from another range than the first's.)
            range=''
            [ "$test$n" != pods2 ] || range='--pod-range 10.77.0.0/20'
            node "$n" "--join 10.9.0.1:7443 --token $join $range ${joined:-}"
        done
        # What a resource's units say: "HOW-MANY-ARE-READY STATE ADDRESS ADDRESS ... and
        # what it says" (`none` for a unit with no address of its own).
        units() { # KIND NAME
            any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    if r["kind"] == sys.argv[1] and r["metadata"]["name"] == sys.argv[2]:
        status = r.get("status") or {}
        units = status.get("containers") or []
        ready = sum(1 for u in units if u.get("ready"))
        said = [status.get("message", "")] + [u.get("message", "") for u in units]
        print(ready, status.get("state", "-"), *sorted(u.get("address", "none") for u in units), *said)
' "$1" "$2"
        }
        if [ "$test" = poddns ]; then
            # The outside resolver is this machine's (ci/outside-dns.py): what the second node asks
            # for a name no node knows. The first node's pods ask the second, which has no such name.
            # (A SERVFAIL, when an upstream did not answer in time, is "Try again" to the pod, and musl
            # does not retry it: so the Job may run again (`retries`), up to the deadline below.)
            python3 "$root/ci/outside-dns.py" $((port + 9)) >/dev/null 2>"$work/outside-dns.log" &
            vms="$vms $!"
            sleep 1
            # The second node's DNS is up once it says so: until then node 1 asks a port nothing
            # listens on and the pod gets SERVFAIL ("Try again"), so the Job waits for that line.
            waited=0
            until grep -aq 'serving DNS on 0.0.0.0:5353' "$work/n2.log" 2>/dev/null; do
                waited=$((waited + 1))
                [ "$waited" -lt 180 ] || fail "the second node did not serve DNS: $(tail -n 3 "$work/n2.log" 2>/dev/null)"
                sleep 1
            done
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"lookup"},"spec":{"retries":4,"template":{"pod":true,"containers":[
  {"name":"ask","image":"kith.test/pod:user","command":["/bin/pod","lookup","outside.example.test"]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job lookup was not applied"
            waited=0
            until line=$(units Job lookup) && case $line in *' succeeded'* | *' failed'*) true ;; *) false ;; esac; do
                waited=$((waited + 1))
                [ "$waited" -lt 240 ] || fail "waited for the Job lookup; it says: $line"
                sleep 1
            done
            any GET "/v1/logs/Job/default/lookup" >"$work/lookup.out" || fail "what the Job lookup wrote could not be read"
            echo "vm.sh: the Job lookup: $line; its pod wrote: $(cat "$work/lookup.out")" >&2
            if [ "${KITH_POD_NOUPSTREAM:-}" = 1 ]; then
                grep -q 'outside.example.test: failed' "$work/lookup.out" || fail "the control found a name with no upstream: $(cat "$work/lookup.out")"
                echo "vm.sh: ok: control: with an upstream that answers nothing, a pod did not find outside.example.test" >&2
                exit 0
            fi
            # (What the Job wrote comes back as JSON, so the quotes around the address are \" in it.)
            grep -Fq 'outside.example.test: [\"198.51.100.7\"]' "$work/lookup.out" || fail "the pod did not find outside.example.test through its node's upstream: $(cat "$work/lookup.out") (the outside resolver's stderr: $(cat "$work/outside-dns.log"))"
            echo "vm.sh: ok: a pod of a node started without --dns found outside.example.test (198.51.100.7) through its node's upstream, a second kithd, which asked an outside resolver" >&2
            exit 0
        fi
        if [ "$test" = worker ]; then
            monitor() { echo "$2" | socat - "unix-connect:$work/keys$1" >/dev/null; } # N COMMAND
            # What listens on port 80 of node N's own network says (the word of the Secret it
            # was given): this machine asks it through the node's card out, and no node's API.
            hears() { curl -s --max-time 5 "http://127.0.0.1:$((port + 4 + $1))/"; } # N
            until_hears() { # N WORD WHAT
                waited=0
                until hears "$1" | grep -q "$2"; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 180 ] || fail "waited for this: $3; n$1 answers on port 80: '$(hears "$1" | head -c 200)'; the Workloads say: mine: $(units Workload mine); other: $(units Workload other)"
                    sleep 1
                done
                echo "vm.sh: $3" >&2
            }
            console_says() { # N PATTERN HOW-OFTEN WHAT: node N's console has said it that often
                waited=0
                until [ "$(grep -ac "$2" "$work/n$1.log")" -ge "$3" ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for n$1 to say: $4"
                    sleep 1
                done
            }
            mine=the-word-of-what-runs-on-the-worker other=the-word-of-what-runs-elsewhere
            # The worker's Node says worker (its token's maker said so) and that it is sent a
            # view (the control node wrote that when it let it in).
            waited=0
            until api 1 GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
node = next(r for r in found if r["kind"] == "Node" and r["metadata"]["name"] == "n2")
status = node.get("status") or {}
sys.exit(0 if node["spec"].get("trust") == "worker" and status.get("view") is True and status.get("address") else 1)
' 2>/dev/null; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "the Node n2 did not come to say that it is a worker sent a view"
                sleep 1
            done
            # A Secret and a Workload that reads it for each kind of node: on the node's own
            # network, answering on port 80 with the word it was given.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Secret","metadata":{"name":"mine"},"spec":{"data":{"word":"$mine"}}},
 {"apiVersion":"kith.dev/v1","kind":"Secret","metadata":{"name":"other"},"spec":{"data":{"word":"$other"}}},
 {"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"mine"},"spec":{"placement":{"require":{"kith.dev/trust":"worker"}},"template":{"containers":[
  {"name":"web","image":"kith.test/pod:1","command":["/bin/pod","say"],"env":[{"name":"PASSWORD","secret":{"name":"mine","key":"word"}}]}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"other"},"spec":{"placement":{"require":{"kith.dev/trust":"control"}},"template":{"containers":[
  {"name":"web","image":"kith.test/pod:1","command":["/bin/pod","say"],"env":[{"name":"PASSWORD","secret":{"name":"other","key":"word"}}]}]}}}]
EOF
            api 1 POST /v1/apply "$work/apply.json" >/dev/null || fail "the two Secrets and their Workloads were not applied"
            until_hears 2 "$mine" "the worker runs what is placed on it, with its Secret"
            until_hears 1 "$other" "the control node runs the other, with its Secret"
            # A person is answered by a control node: the worker has no Identity to know one by.
            code=$(curl -s -o "$work/refused" -w '%{http_code}' --max-time 10 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
                --resolve "kith:$((port + 2)):127.0.0.1" "https://kith:$((port + 2))/v1/resources") || true
            { [ "$code" = 403 ] && grep -q 'answers no one by their rights' "$work/refused"; } || fail "the worker answered the cluster's admin: $code $(cat "$work/refused")"
            # Each node's disk, as this machine has it in a file: the control node's has both
            # words (so looking finds what is on a disk), the worker's has its own, and the
            # word of what runs elsewhere was never written to it.
            waited=0
            until grep -aqF "$other" "$work/n1.raw" && grep -aqF "$mine" "$work/n1.raw" && grep -aqF "$mine" "$work/n2.raw"; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "a Secret is not on the disk of a node that keeps it: looking at the disks finds nothing"
                sleep 1
            done
            ! grep -aqF "$other" "$work/n2.raw" || fail "the Secret of what runs on the control node is on the worker's disk"

            # The control node is paused (nobody answers for it): the worker says so, and goes
            # on running what it runs.
            monitor 1 stop
            console_says 2 'sends no view' 1 "that its control node sends no view"
            hears 2 | grep -q "$mine" || fail "the worker stopped what it ran when its control node went silent"
            echo "vm.sh: the control node paused: the worker says it is sent no view, and runs on" >&2
            # The worker loses power meanwhile: started again from the view it kept, it runs
            # nothing until a control node answers (what was moved off it while it was away
            # is not known to it), as any node that starts with no leader in reach.
            monitor 2 system_reset
            console_says 2 'Kernel command line' 2 "that it starts again"
            console_says 2 'workloads start once this node has' 1 "that it waits for a control node before it runs anything"
            sleep 10
            ! hears 2 | grep -q . || fail "the worker, started with no control node in reach, runs what it ran: $(hears 2)"
            echo "vm.sh: the worker started again with the control node paused: it waits, and runs nothing" >&2
            monitor 1 cont
            until_hears 2 "$mine" "the control node back: the worker follows it again and runs what is placed on it, with its Secret"
            ! grep -aqF "$other" "$work/n2.raw" || fail "the Secret of what runs on the control node is on the worker's disk after it started again"
            # What is deleted leaves the worker.
            api 1 DELETE /v1/resources/Workload/default/mine >/dev/null || fail "the Workload mine was not deleted"
            waited=0
            while hears 2 | grep -q .; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the Workload that was deleted still answers on the worker"
                sleep 1
            done
            # The worker is made an ingress worker: its owner says so in its Node (what the
            # control node that admits a node writes there from a token of `kith node token
            # --worker --ingress`), and it starts again with --ingress, port 443 reached from
            # this machine. A host is exposed with a certificate applied by hand (no ACME
            # authority is reached from here: tests/cluster.rs orders one from a stand-in).
            unplaced=the-word-of-a-secret-nothing-places
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=shop.example.test \
                -addext subjectAltName=DNS:shop.example.test -keyout "$work/shop.key" -out "$work/shop.crt" 2>/dev/null \
                || fail "openssl made no certificate"
            api 1 GET /v1/resources | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
node = next(r for r in found if r["kind"] == "Node" and r["metadata"]["name"] == "n2")
crt, key = (open(path).read() for path in sys.argv[1:3])
def secret(name, data):
    return {"apiVersion": "kith.dev/v1", "kind": "Secret", "metadata": {"name": name}, "spec": {"data": data}}
json.dump([
    {"apiVersion": "kith.dev/v1", "kind": "Node", "metadata": {"name": "n2"}, "spec": {**node["spec"], "ingress": True}},
    secret("tls-shop.example.test", {"tls.crt": crt, "tls.key": key}),
    secret("unplaced", {"word": sys.argv[3]}),
    {"apiVersion": "kith.dev/v1", "kind": "Service", "metadata": {"name": "shop"}, "spec": {
        "selector": {"app": "shop"}, "ports": [{"port": 80}], "expose": {"host": "shop.example.test", "via": "edge"}}},
], open(sys.argv[4], "w"))
' "$work/shop.crt" "$work/shop.key" "$unplaced" "$work/apply.json" || fail "the worker's Node was not read"
            api 1 POST /v1/apply "$work/apply.json" >/dev/null || fail "the worker's Node, the certificate and the Service were not applied"
            # Its view now holds the host's key (its Node says ingress, so the control node sends
            # it): its disk has it, and the Secret nothing places is on the control node's alone.
            line=$(sed -n 2p "$work/shop.key")
            waited=0
            until grep -aqF "$line" "$work/n2.raw" && grep -aqF "$unplaced" "$work/n1.raw"; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the host's key is not on the ingress worker's disk, or the Secret nothing places is on no disk"
                sleep 1
            done
            sleep 2
            monitor 2 quit
            sleep 2
            https=1
            node 2 --ingress
            # It answers the host over TLS with that certificate, and no other host. (s_client
            # says "Verify return code: 0 (ok)" after a handshake that failed too: a certificate
            # sent, and one that verified, is what says it answered.)
            handshake() { # HOST
                openssl s_client -connect "127.0.0.1:$((port + 12))" -servername "$1" -CAfile "$work/shop.crt" \
                    -verify_hostname "$1" -verify_return_error </dev/null 2>/dev/null
            }
            answers() { handshake "$1" | grep -q 'BEGIN CERTIFICATE' && handshake "$1" | grep -q 'Verify return code: 0 (ok)'; } # HOST
            waited=0
            until answers shop.example.test; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "the ingress worker did not answer shop.example.test over TLS: $(handshake shop.example.test | tail -n 5)"
                sleep 1
            done
            # (Unverified: a host nothing exposes is sent no certificate at all, not one that fails.)
            ! openssl s_client -connect "127.0.0.1:$((port + 12))" -servername other.example.test </dev/null 2>/dev/null \
                | grep -q 'BEGIN CERTIFICATE' || fail "the ingress worker sent a certificate for a host nothing exposes"
            echo "vm.sh: the ingress worker answers its host over TLS with the certificate it was sent" >&2
            # Its disk has no Secret that is neither a tls- one nor placed on it.
            ! grep -aqF "$unplaced" "$work/n2.raw" || fail "a Secret nothing places is on the ingress worker's disk"
            ! grep -aqF "$other" "$work/n2.raw" || fail "the Secret of what runs on the control node is on the ingress worker's disk"
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: two nodes, one let in as a worker: its Node says it is sent a view; a Workload placed on it ran with its Secret; its disk has that Secret and never had the Secret of what runs on the control node; its API answered no person; with the control node paused it said so and ran on; started again meanwhile it ran nothing until the control node was back, then what it ran; a deleted Workload left it; made an ingress worker it answered its host over TLS, with the host's key on its disk and no Secret nothing places on it"
            exit 0
        fi
        if [ "$test" = services ]; then
            # A pod that sends back what it is sent, and its Service.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"echo","labels":{"app":"echo"}},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"echo","image":"kith.test/pod:1","command":["/bin/pod","echo"],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}}}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Service","metadata":{"name":"echo"},"spec":{"selector":{"app":"echo"},"ports":[{"port":80}]}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the echo pod was not applied"
            waited=0
            until line=$(units Workload echo) && [ "${line%% *}" = 1 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "waited for the echo pod to be ready; the Workload says: $line"
                sleep 1
            done
            # The Service's address, once it has its replica.
            waited=0
            until address=$(any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    status = r.get("status") or {}
    if r["kind"] == "Service" and r["metadata"]["name"] == "echo" and status.get("address") and status.get("backends"):
        print(status["address"])
        sys.exit(0)
sys.exit(1)
'); do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the Service echo was given no address with its replica"
                sleep 1
            done
            # A Job on the same node sending to it through the Service, twice: in a pod of its
            # own (kithd passes its bytes), and on the node's own network (the kernel sends
            # its connections straight to the replica's IPv6 address, never a v4 one an
            # IPv6-only socket could not reach). What each says is in $work/JOB.out.
            checked=''
            for job in check near; do
                if [ "$job" = check ]; then pod='"pod":true,' to=echo; else pod='' to=$address; fi
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$job"},"spec":{"retries":0,"template":{$pod"containers":[
  {"name":"check","image":"kith.test/pod:1","command":["/bin/pod","check","$to","80"]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $job was not applied"
                waited=0
                until line=$(units Job "$job") && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 600 ] || fail "waited for the Job $job; it says: $line"
                    sleep 1
                done
                any GET "/v1/logs/Job/default/$job" >"$work/$job.out" 2>/dev/null || true
                any GET "/v1/logs/Job/default/$job?stderr=true" >"$work/$job.err" 2>/dev/null || true
                any GET '/v1/logs/Workload/default/echo?replica=0' >"$work/echo.out" 2>/dev/null || true
                printf '%s\n' "$line" | grep -q succeeded || fail "bytes through the Service from the Job $job did not all come back in order: $line: $(cat "$work/$job.out" "$work/$job.err")"
                ! grep -q 'echo: bad' "$work/echo.out" || fail "the echo pod heard bytes out of order: $(cat "$work/echo.out")"
                # (The log comes as JSON: its lines are inside a string.)
                said=$(grep -o 'check: [0-9][^"\\]*' "$work/$job.out") || fail "the Job $job said nothing of how it went: $(cat "$work/$job.out" "$work/$job.err")"
                reached=$(grep -o 'check: reached [^"\\]*' "$work/$job.out") || fail "the Job $job did not say what it reached: $(cat "$work/$job.out" "$work/$job.err")"
                reached=${reached#check: reached }
                if [ "$job" = check ]; then
                    [ "$reached" = "[$address]:80" ] || fail "a pod's connection to the Service reached $reached, not kithd at [$address]:80"
                else
                    case $reached in "[$address]:80" | "[::ffff:"* | [![]*) fail "a connection on the node's own network to the Service reached $reached, not the replica: the kernel did not send it there" ;; esac
                fi
                checked="$checked${checked:+; }$job: ${said#check: }, reached $reached"
            done
            # (Its state disk has no project quotas, as a node's from before: kithd says it counts.)
            grep -aq "kithd: pods' storage limits are held by a count every 10 s of what each pod wrote" "$work/n1.log" \
                || fail "kithd did not say it counts what pods write on a state disk with no project quotas: $(grep -a 'storage limits' "$work/n1.log")"
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node, a pod that sent back what it was sent and its Service; Jobs on the same node, one in a pod (passed by kithd) and one on the node's own network (passed by the kernel straight to the replica), sent through the Service on connections closed at once, half closed, reset by either end with bytes on their way, side by side and kept for small turns, and every byte came back in order ($checked)"
            exit 0
        fi
        if [ "$test" = quota ]; then
            # Each case that held says `quota: ok: CASE`; at the end every one must have.
            : >"$work/oks"
            ok() { echo "quota: ok: $1"; echo "$1" >>"$work/oks"; }
            # KIND NAME MORE STEP ...: a pod that runs `pod quota STEP ...` (ci/pod.rs), MORE more
            # of its container; what it said is in $work/NAME.out once it is done.
            quota() {
                kind=$1 name=$2 extra=$3
                shift 3
                steps=$(printf '"%s",' "$@")
                spec='"replicas":1,'
                [ "$kind" = Workload ] || spec='"selector":{},'
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"$kind","metadata":{"name":"$name"},"spec":{$spec"template":{"pod":true,"containers":[
  {"name":"quota","image":"kith.test/pod:1","command":["/bin/pod","quota",${steps%,}]$extra}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the $kind $name was not applied"
            }
            done_() { # KIND NAME: wait for it to have said all it does
                waited=0
                until grep -q 'quota: done' "$work/$2.out" 2>/dev/null; do
                    for replica in 0 1 2 3; do
                        any GET "/v1/logs/$1/default/$2?replica=$replica" >"$work/$2.out" 2>/dev/null && grep -q 'quota: done' "$work/$2.out" && break
                    done
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for the $1 $2 to be done; it says: $(units "$1" "$2"): $(cat "$work/$2.out" 2>/dev/null)"
                    sleep 1
                done
            }
            gone() { api 1 DELETE "/v1/resources/$1/default/$2" >/dev/null || fail "the $1 $2 was not deleted"; }
            # What NAME said of STEP (its log comes as JSON: the lines are in its strings).
            result() {
                python3 -c '
import json, sys
def strings(v):
    if isinstance(v, str):
        yield v
    for x in (v.values() if isinstance(v, dict) else v if isinstance(v, list) else []):
        yield from strings(x)
try:
    log = json.load(open(sys.argv[1]))
except ValueError:
    sys.exit(1)
said = [l[len(sys.argv[2]) + 1:] for s in strings(log) for l in s.splitlines() if l.startswith(sys.argv[2] + " ")]
print(said[-1] if said else "nothing", end="")
' "$work/$1.out" "quota: $2"
            }
            expect() { # NAME STEP PATTERN (grep -E, all of what it said) WHAT-IT-SHOWS
                got=$(result "$1" "$2")
                printf '%s\n' "$got" | grep -Eqx "$3" || fail "$1: $2 said \"$got\": $4"
            }
            stopped() { # NAME STEP LIMIT: the write failed at the kernel's quota, at most LIMIT in
                got=$(result "$1" "$2")
                wrote=$(printf '%s\n' "$got" | sed -n 's/^failed after \([0-9]*\): .* (os error 122)$/\1/p')
                [ -n "$wrote" ] && [ "$wrote" -le "$3" ] || fail "$1: $2 said \"$got\": not stopped at the write at its limit of $3 bytes"
            }
            used() { # NAME STEP LIMIT: statfs of its project's directory says its limit, and no more used
                got=$(result "$1" "$2")
                case $got in "size $3 used "*) ;; *) fail "$1: $2 said \"$got\": its project's limit is not $3" ;; esac
                got=${got#size $3 used }
                [ "${got%% *}" -le "$3" ] || fail "$1: $2 holds ${got%% *} bytes, past its limit of $3"
            }
            free() { # NAME: what the state disk has free, as a pod with a Volume there sees it
                quota Workload "$1" ',"volumeMounts":[{"volume":"free","path":"/free"}]' '#/free'
                done_ Workload "$1"
                gone Workload "$1"
                got=$(result "$1" '#/free')
                printf '%s\n' "${got##* }" | grep -Eqx '[0-9]+' || fail "$1: #/free said \"$got\""
                echo "${got##* }"
            }

            # kithd says once how it holds pods' limits, and the Node says it too.
            grep -aq "kithd: pods' storage limits are held at the write, by the state disk's project quota" "$work/n1.log" \
                || fail "kithd did not say it holds pods' storage limits at the write: $(grep -a 'storage limits' "$work/n1.log")"
            waited=0
            until storage=$(any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    if r["kind"] == "Node" and r["metadata"]["name"] == "n1":
        print(((r.get("status") or {}).get("os") or {}).get("storage", ""), end="")
') && [ -n "$storage" ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the Node n1 did not say how it holds pods' storage limits"
                sleep 1
            done
            [ "$storage" = "at the write, by the state disk's project quota" ] || fail "the Node n1 says its pods' limits are held $storage"
            ok said

            # An id given again: a pod of 64Ki (the first given a project, so the lowest id) runs
            # and is removed; kithd starts again, and gives the next pod the lowest id with nothing
            # in it, the same. That pod, whose image and scratch it changes are past 64Ki, starts
            # and is held to its own limit, not the one before.
            # What this does not show: that the stale limit is cleared. kithd sets a project's
            # limit before anything is put in it, but kithd is root with CAP_SYS_RESOURCE, and
            # the kernel lets such a writer past a hard limit (dquot.c, ignore_hardlimit): with
            # the 64Ki left on the id, the pod's start passes all the same. (Run against a kithd
            # that left it, this case held too.) It shows an id given again, and its new limit.
            quota Workload tiny ',"resources":{"storage":"64Ki"}' '?/' '+/fill:131072'
            done_ Workload tiny
            stopped tiny '+/fill:131072' 65536
            was=$(result tiny '?/')
            printf '%s\n' "$was" | grep -Eqx 'project [1-9][0-9]*' || fail "tiny: its root is in no project of its own: $was"
            gone Workload tiny
            # (Its replica directory goes at kithd's next pass once its unit has; a kithd that
            # starts with it there gives ids past it.)
            waited=0
            while [ -n "$(units Workload tiny)" ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the Workload tiny was not removed: $(units Workload tiny)"
                sleep 1
            done
            sleep 10
            # Started again as a machine is when its power button is pressed: kithd stops, and
            # the node comes back up from its disk.
            echo 'sendkey ctrl-alt-delete' | socat - "unix-connect:$work/keys1" >/dev/null || fail "QEMU's monitor of n1 did not answer"
            waited=0
            until [ "$(grep -ac "kithd: pods' storage limits are held at the write" "$work/n1.log")" -ge 2 ] && any GET /v1/resources >/dev/null 2>&1; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "n1 did not start again holding pods' limits at the write: $(grep -a 'storage limits\|reboot:' "$work/n1.log")"
                sleep 1
            done
            grep -aq 'reboot: Restarting system' "$work/n1.log" || fail "n1 did not restart: its console says no 'reboot: Restarting system'"
            quota Workload again ',"resources":{"storage":"64Mi"},"volumeMounts":[{"scratch":"work","path":"/work"}]' '?/' '^/big' '+/work/fill:1048576' '+/fill:209715200' '#/'
            done_ Workload again
            expect again '?/' "$was" "the pod after kithd started again was not given the removed pod's id, so no id was given again"
            expect again '^/big' ok "a file of its image past the last limit of its id was not copied up"
            expect again '+/work/fill:1048576' 'wrote 1048576' "its scratch was held to the last limit of its id"
            stopped again '+/fill:209715200' 67108864
            used again '#/' 67108864
            waited=0
            until line=$(units Workload again) && [ "${line%% *}" = 1 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "the Workload again is not ready: $line"
                sleep 1
            done
            gone Workload again
            echo "vm.sh: again: $was given again after kithd started again; held to 64 MiB, not 64Ki" >&2
            ok again

            # A pod of 64 MiB writing 200 MiB, in its root and then its scratch, beside one writing
            # 32 MiB: the first is stopped at the write, the second loses none, and the disk loses
            # no more than both their limits let them (and 4 MiB of kithd's own). It is in a user
            # namespace of its own (a Workload's pod, with a network of its own), so its root's
            # overlay was mounted by that namespace's root; its scratch it writes itself.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"free"},"spec":{"node":"n1","path":"free"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Volume free was not applied"
            limit=67108864 storage=',"resources":{"storage":"64Mi"}'
            for case in write scratch; do
                to=/fill more=$storage
                [ "$case" = write ] || { to=/work/fill more="$storage,\"volumeMounts\":[{\"scratch\":\"work\",\"path\":\"/work\"}]"; }
                before=$(free "before-$case")
                quota Workload "big-$case" "$more" '@' "+$to:209715200" "#${to%/fill}/"
                quota Workload "small-$case" "$more" "+$to:33554432"
                done_ Workload "big-$case"
                done_ Workload "small-$case"
                after=$(free "after-$case")
                expect "big-$case" '@' '0 [1-9][0-9]* [0-9]+' "a Workload's pod with a network of its own has the node's users"
                stopped "big-$case" "+$to:209715200" "$limit"
                used "big-$case" "#${to%/fill}/" "$limit"
                expect "small-$case" "+$to:33554432" 'wrote 33554432' "a pod beside one at its limit lost a write"
                [ $((before - after)) -le $((limit + 33554432 + 4194304)) ] || fail "$case: the state disk lost $((before - after)) bytes to two pods of 64 MiB, one writing 32 MiB"
                # Its status says it holds all it may, and it is not replaced for it.
                waited=0
                until line=$(units Workload "big-$case") && printf '%s\n' "$line" | grep -q 'reached its storage limit'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 60 ] || fail "big-$case's status does not say it reached its storage limit: $line"
                    sleep 1
                done
                sleep 12
                any GET "/v1/logs/Workload/default/big-$case?replica=0" >"$work/big-$case.out" 2>/dev/null || true
                [ "$(grep -o 'quota: done' "$work/big-$case.out" | wc -l)" = 1 ] || fail "big-$case was started again: $(cat "$work/big-$case.out")"
                ! grep -aq 'replaced: its pod wrote' "$work/n1.log" || fail "a pod held to its limit was replaced: $(grep -a 'replaced: its pod wrote' "$work/n1.log")"
                gone Workload "big-$case"
                gone Workload "small-$case"
                echo "vm.sh: $case: stopped at $wrote bytes of 200 MiB; the disk lost $((before - after)) bytes; $line" >&2
                ok "$case"
            done

            # A file it removed and holds open, with no name to find: charged all the same.
            quota Workload unlinked "$storage" "~/fill:209715200"
            done_ Workload unlinked
            stopped unlinked "~/fill:209715200" "$limit"
            gone Workload unlinked
            ok unlinked

            # The root of a pod with the node's users (a NodeWorkload's): its overlay was mounted
            # by the node's root with every capability, CAP_SYS_RESOURCE too, which lets a writer
            # past a project's hard limit. The kernel leaves that one out of the credentials an
            # overlay writes its upper layer with (fs/overlayfs/super.c, "Never override disk
            # quota limits"), so it is held all the same: a new file past its limit, and, in both
            # kinds of pod, a file of its image copied up near its limit (12 MiB with 8 of 16
            # written), refused whole and left as the image has it.
            quota NodeWorkload nodewrite "$storage" '@' '+/fill:209715200' '#/'
            copy=',"resources":{"storage":"16Mi"}'
            quota Workload copyup "$copy" '+/pad:8388608' '^/big' '=/big' '+/fill:16777216' '#/'
            quota NodeWorkload nodecopyup "$copy" '@' '+/pad:8388608' '^/big' '=/big' '+/fill:16777216' '#/'
            done_ NodeWorkload nodewrite
            expect nodewrite '@' '0 0 4294967295' "a NodeWorkload's pod does not have the node's users"
            stopped nodewrite '+/fill:209715200' "$limit"
            used nodewrite '#/' "$limit"
            echo "vm.sh: nodewrite: the node's root stopped at $wrote bytes of 200 MiB in its root" >&2
            gone NodeWorkload nodewrite
            ok nodewrite
            for name in copyup nodecopyup; do
                kind=Workload
                [ "$name" = copyup ] || kind=NodeWorkload
                done_ "$kind" "$name"
                [ "$kind" = Workload ] || expect "$name" '@' '0 0 4294967295' "a NodeWorkload's pod does not have the node's users"
                expect "$name" '+/pad:8388608' 'wrote 8388608' "a pod of 16 MiB could not write 8 MiB"
                expect "$name" '^/big' '.* \(os error 122\)' "a file of its image of 12 MiB was copied up with 8 MiB of 16 written"
                expect "$name" '=/big' 'size 12582912' "a copy-up refused at its limit changed the file of its image"
                stopped "$name" '+/fill:16777216' 16777216
                used "$name" '#/' 16777216
                echo "vm.sh: $name: the copy-up of 12 MiB failed: $(result "$name" '^/big'); /big $(result "$name" '=/big'); then stopped at $wrote" >&2
                gone "$kind" "$name"
                ok "$name"
            done

            # Moving its files out of its project: in a user namespace the kernel refuses; as the
            # node's root (a NodeWorkload's pod) its filter does; unconfined nothing does, and
            # what it then writes is counted, and it is replaced for it.
            quota Workload userns '' '+/esc:1' '0/esc' '!/esc' '?/esc'
            quota NodeWorkload noderoot '' '+/esc:1' '0/esc' '!/esc' '?/esc'
            done_ Workload userns
            done_ NodeWorkload noderoot
            for step in 0/esc '!/esc'; do
                expect userns "$step" '.* \(os error 22\)' "a pod in a user namespace moved its file out of its project"
                expect noderoot "$step" '.* \(os error 1\)' "a pod as the node's root moved its file out of its project"
            done
            expect userns '?/esc' 'project [1-9][0-9]*' "its file is not in its pod's project"
            expect noderoot '?/esc' 'project [1-9][0-9]*' "its file is not in its pod's project"
            gone Workload userns
            gone NodeWorkload noderoot
            ok userns
            ok noderoot
            quota NodeWorkload unconfined "$storage,\"seccomp\":{\"unconfined\":true}" '+/esc:1' '0/esc' '?/esc' '+/esc:104857600'
            done_ NodeWorkload unconfined
            expect unconfined 0/esc ok "an unconfined pod as the node's root could not move its file out of its project"
            expect unconfined '?/esc' 'project 0' "an unconfined pod's file stayed in its project"
            expect unconfined '+/esc:104857600' 'wrote 104857600' "a file out of its project took less than it wrote"
            waited=0
            until grep -aq 'replaced: its pod wrote [0-9]* bytes outside its volumes, over its limit of 67108864' "$work/n1.log"; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "an unconfined pod that wrote past its limit out of its project was not replaced"
                sleep 1
            done
            gone NodeWorkload unconfined
            ok unconfined

            # Its file linked and renamed to elsewhere: another file system (its Volume; another
            # pod's root is not in its).
            quota Workload elsewhere ',"volumeMounts":[{"volume":"free","path":"/free"}]' '+/mine:1' '&/mine:/free/linked' '>/mine:/free/moved'
            done_ Workload elsewhere
            expect elsewhere '&/mine:/free/linked' '.* \(os error 18\)' "a pod linked a file of its root into a Volume"
            expect elsewhere '>/mine:/free/moved' '.* \(os error 18\)' "a pod moved a file of its root into a Volume"
            gone Workload elsewhere
            ok elsewhere

            # What it changes of its image is charged to it: a file of its image larger than its
            # limit, appended to; a directory renamed; a file renamed over one; one linked; one
            # removed; then it fills the rest.
            quota Workload image ',"resources":{"storage":"8Mi"}' '?/' '^/big' '>/tree:/moved' '+/new:1048576' '>/new:/data/small' '?/data/small' '&/data/other:/linked' '?/linked' '-/big' '+/fill:16777216' '#/'
            done_ Workload image
            its=$(result image '?/')
            expect image '?/' 'project [1-9][0-9]*' "its root is in no project of its own"
            expect image '^/big' '.* \(os error 122\)' "a file of its image larger than its limit was copied up whole"
            expect image '>/tree:/moved' 'ok|.* \(os error 18\)' "a directory of its image renamed"
            expect image '>/new:/data/small' ok "a file renamed over one of its image"
            expect image '?/data/small' "$its" "a file renamed over one of its image left its project"
            expect image '&/data/other:/linked' ok "a file of its image linked"
            expect image '?/linked' "$its" "a file of its image linked is not charged to it"
            expect image '-/big' ok "a file of its image removed"
            stopped image '+/fill:16777216' 8388608
            used image '#/' 8388608
            gone Workload image
            ok image

            for case in said again write scratch unlinked nodewrite copyup nodecopyup userns noderoot unconfined elsewhere image; do
                grep -qx "$case" "$work/oks" || fail "the case $case was not shown"
            done
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node whose state disk keeps project quotas: kithd said it holds pods' storage limits at the write; a project id given again after kithd started again held its new pod to its own limit, not the last one's; a pod of 64 MiB writing 200 MiB was stopped by the kernel at its limit, in its root, in its scratch and in a file it removed and held open, and not replaced, while one beside it lost no write; a pod with the node's users was stopped in its root too, and in both kinds a file of the image copied up near the limit was refused whole and left unchanged; its files stayed in its project in a user namespace (the kernel) and as the node's root (its filter), and unconfined it moved one out and was counted and replaced; linked or renamed out of its root they were refused; what it changed of its image was charged to it"
            exit 0
        fi
        if [ "$test" = pods ]; then
            # This machine, as something outside the cluster a pod asks: the nodes reach it
            # at 10.0.2.2, and only from an address their card out has (a pod's own is not
            # one the network out there knows).
            mkdir "$work/www"
            (cd "$work/www" && exec python3 -m http.server --bind 127.0.0.1 $((port + 9))) >/dev/null 2>&1 &
            web=$!
            # NAME and the rest of its one container: three pods of it on the two nodes, so
            # two of them on one, each listening on port 80, and a Service of that name.
            three() {
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"$1","labels":{"app":"$1"}},"spec":{"replicas":3,"template":{"pod":true,"containers":[
  {"name":"web",$2,"ports":[{"port":80}],"readiness":{"tcp":{"port":80}}}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Service","metadata":{"name":"$1"},"spec":{"selector":{"app":"$1"},"ports":[{"port":80}]}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the pods of $1 were not applied"
                waited=0
                until line=$(units Workload "$1") && [ "${line%% *}" = 3 ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for three pods of $1 to be ready; the Workload says: $line"
                    sleep 1
                done
                echo "vm.sh: three pods of $1 ready: $line" >&2
                [ "$(printf '%s\n' $line | grep : | sort -u | grep -c :)" = 3 ] || fail "the three pods of $1 do not have an address each on the mesh: $line"
            }
            # NAME and whom to ask (HOST PORT ...): a pod of a user who is not root asks
            # each, and writes what it heard to /dev/stdout by name; that is in $work/NAME.out.
            asks() {
                name=$1
                shift
                # ($pinned: a Volume that puts the Job on its node.)
                mounts=''
                [ -z "${pinned:-}" ] || mounts=",\"volumeMounts\":[{\"volume\":\"$pinned\",\"path\":\"/state\"}]"
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$name"},"spec":{"retries":0,"template":{"pod":true,"containers":[
  {"name":"ask","image":"kith.test/pod:user","command":["/bin/pod","ask"$(printf ',"%s"' "$@")]$mounts}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $name was not applied"
                waited=0
                until line=$(units Job "$name") && case $line in *' succeeded '* | *' succeeded') true ;; *) false ;; esac; do
                    waited=$((waited + 1))
                    any GET "/v1/logs/Job/default/$name?stderr=true" >"$work/$name.err" 2>/dev/null || true
                    case $line in *' failed '* | *' failed') fail "the Job $name failed: $line: $(cat "$work/$name.err")" ;; esac
                    [ "$waited" -lt 240 ] || fail "waited for the Job $name; it says: $line: $(cat "$work/$name.err")"
                    sleep 1
                done
                any GET "/v1/logs/Job/default/$name" >"$work/$name.out" || fail "what the Job $name wrote could not be read"
                ! grep -q 'failed: ' "$work/$name.out" || fail "the pod that asked was not always answered: $(cat "$work/$name.out")"
            }
            # Each makes a file in its root, as root, before it listens.
            three web '"image":"kith.test/pod:1","command":["/bin/pod","serve"]'
            # Their Service by its short name and by its whole one, and this machine.
            asks ask web 80 web.default.svc.cluster.local 80 10.0.2.2 $((port + 9))
            for heard in web-0 web-1 web-2 'HTTP/1.0 200 OK'; do
                grep -q "$heard" "$work/ask.out" || fail "the pod that asked did not hear $heard: $(cat "$work/ask.out")"
            done
            # A pod on each node (a Volume of its node puts it there) says where it asks for
            # names and from which address: the first node's in 100.88.0.0/16 (the default),
            # the second's in the range that node was told (--pod-range).
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on-n1"},"spec":{"node":"n1","path":"pod"}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on-n2"},"spec":{"node":"n2","path":"pod"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the volumes that put a pod on each node were not applied"
            for side in n1 n2; do
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"at-$side"},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"web","image":"kith.test/pod:1","command":["/bin/pod","serve"],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}},
   "volumeMounts":[{"volume":"on-$side","path":"/state"}]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the pod at-$side was not applied"
                waited=0
                until line=$(units Workload "at-$side") && [ "${line%% *}" = 1 ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for the pod at-$side to be ready; the Workload says: $line"
                    sleep 1
                done
                any GET "/v1/logs/Workload/default/at-$side?replica=0" >"$work/at-$side.out" || fail "what the pod at-$side wrote could not be read"
            done
            grep -qE 'where: nameserver 100\.88\.0\.1 from 100\.88\.[0-9]+\.[0-9]+' "$work/at-n1.out" || fail "the pod on n1 is not in the default range: $(cat "$work/at-n1.out")"
            grep -qE 'where: nameserver 10\.77\.0\.1 from 10\.77\.[0-9]+\.[0-9]+' "$work/at-n2.out" || fail "the pod on n2 is not in the range of --pod-range: $(cat "$work/at-n2.out")"
            # And one pod on n2 asks this machine, from behind its node's address: the node
            # sends it as its own only if the masquerade rule matches the range it was told.
            pinned='on-n2'
            asks egress 10.0.2.2 $((port + 9))
            pinned=''
            grep -q 'HTTP/1.0 200 OK' "$work/egress.out" || fail "the pod on n2 (range of --pod-range) did not reach this machine from behind its node: $(cat "$work/egress.out")"
            # A Workload of an image nothing else uses, deleted once it runs: its image is
            # looked for again at the end.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"gone"},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"web","image":"kith.test/gone:1","command":["/bin/pod","serve"],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}}}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Workload gone was not applied"
            waited=0
            until line=$(units Workload gone) && [ "${line%% *}" = 1 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "waited for the pod of gone to be ready; the Workload says: $line"
                sleep 1
            done
            api 1 DELETE /v1/resources/Workload/default/gone >/dev/null || fail "the Workload gone was not deleted"
            stock='no stock image was tried (KITH_E2E=1 pulls one)'
            if [ "${KITH_E2E:-}" = 1 ]; then
                # An image as its makers ship it, with nothing said but its name: nginx starts
                # as root, writes its configuration and its pid in its root, opens /dev/stdout
                # by name for what it is asked, and listens on port 80.
                three stock '"image":"mirror.gcr.io/library/nginx:1.27-alpine"'
                asks ask-stock stock 80
                grep -q 'HTTP/1.1 200 OK' "$work/ask-stock.out" || fail "nginx did not answer through its Service: $(cat "$work/ask-stock.out")"
                for replica in 0 1 2; do
                    any GET "/v1/logs/Workload/default/stock?replica=$replica" >"$work/stock.out" || fail "what nginx $replica wrote could not be read"
                    grep -q 'GET / HTTP/1.0' "$work/stock.out" || fail "the Service did not pass a request to nginx $replica, or it could not say so on /dev/stdout: $(cat "$work/stock.out")"
                done
                stock='three pods of nginx as it is shipped (mirror.gcr.io/library/nginx:1.27-alpine) started the same way, and each said on /dev/stdout that it was asked through their Service'
            fi

            # A Job of one container: NAME, more of its template, its container, and what the
            # Job comes to say. What it wrote is in $work/NAME.out and .err.
            job() {
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{$2"containers":[
  {"name":"box",$3}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
                waited=0
                until line=$(units Job "$1") && printf '%s\n' "$line" | grep -Eq "$4|^[0-9]+ (succeeded|failed)( |\$)"; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 120 ] || fail "waited for the Job $1; it says: $line"
                    sleep 1
                done
                any GET "/v1/logs/Job/default/$1" >"$work/$1.out" 2>/dev/null || true
                any GET "/v1/logs/Job/default/$1?stderr=true" >"$work/$1.err" 2>/dev/null || true
                printf '%s\n' "$line" | grep -Eq "$4" || fail "the Job $1 says: $line: $(cat "$work/$1.out" "$work/$1.err")"
            }
            # What holds a container to its devices: a pod that is root is root of a user
            # namespace of its own on kith OS, where the kernel makes no device node, not even
            # /dev/null again; its node's own disk it may neither make nor read. (NAME, block
            # or character, and where /sys has the device's numbers.)
            makes() { job "$1" '"pod":true,' "\"image\":\"kith.test/pod:1\",\"command\":[\"/bin/pod\",\"node\",\"$2\",\"$3\",\"/dev/made\"]" '^[0-9]+ succeeded'; }
            makes null c /sys/class/mem/null/dev
            grep -q 'node: made -1, read Err' "$work/null.out" || fail "a pod that is root made a device node in a user namespace of its own: $(cat "$work/null.out" "$work/null.err")"
            makes disk b /sys/class/block/vda/dev
            grep -q 'node: made -1, read Err' "$work/disk.out" || fail "a pod that is root was not kept from its node's disk: $(cat "$work/disk.out" "$work/disk.err")"

            # A sandbox inside a container (bubblewrap as this machine has it; Steam's runtime
            # and Flatpak start theirs so): a user namespace of its own, with a /proc and a
            # /dev made in it. NAME, more of its container, and what its Job comes to say.
            sandbox() { job "$1" '' "\"image\":\"kith.test/sandbox:1\"$2,\"command\":[\"/bin/bwrap\",\"--unshare-user\",\"--uid\",\"0\",\"--gid\",\"0\",\"--unshare-pid\",\"--ro-bind\",\"/\",\"/\",\"--proc\",\"/proc\",\"--dev\",\"/dev\",\"/bin/pod\",\"self\"]" "$3"; }
            # Only a container that asks may, and never one that is the node's root.
            sandbox boxed ',"userNamespaces":true' '^[0-9]+ succeeded'
            grep -q 'nested: pid 2, uid 0' "$work/boxed.out" || fail "the sandbox did not say where it found itself: $(cat "$work/boxed.out" "$work/boxed.err")"
            sandbox unboxed '' '^[0-9]+ failed'
            # (bubblewrap gives up there before it asks for a namespace, over the capability a
            # container keeps on kith OS; that the call itself is refused is the runtime's test.)
            ! grep -q nested "$work/unboxed.out" || fail "a container that did not ask started a sandbox: $(cat "$work/unboxed.out")"
            sandbox rooted ',"runAsUser":0,"userNamespaces":true' 'userNamespaces: this container is the node.s root'
            ! grep -q nested "$work/rooted.out" || fail "the node's root was let make a user namespace: $(cat "$work/rooted.out")"

            # A session's input: a keyboard plugged in while a container holds the seat is
            # one more node in its /dev that it can open, and nothing is started again for it.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"DeviceClaim","metadata":{"name":"seat"},"spec":{"seat":"n1-seat0"}},
 {"apiVersion":"kith.dev/v1","kind":"DeviceClaim","metadata":{"name":"apps"},"spec":{"seat":"n1-seat0","access":"client"}},
 {"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"session"},"spec":{"template":{"deviceClaims":["seat"],"containers":[
  {"name":"sees","image":"kith.test/pod:1","command":["/bin/pod","seen","/dev/input","/run/seat/wayland-0"]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the session and its claim on the seat were not applied"
            # How many nodes it can open, by the last it said.
            opens() { any GET /v1/logs/Workload/default/session 2>/dev/null | field data | grep '^seen:' | tail -n 1 | tr ' ' '\n' | grep -c '+$'; }
            comes_to() { # WHAT, and a test of how many it opens now against $had
                waited=0
                until now=$(opens) && test "$now" "$2" "$had"; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 120 ] || fail "waited for $1; it opens $now, and says: $(any GET /v1/logs/Workload/default/session 2>&1 | tail -n 3); the Workload: $(units Workload session)"
                    sleep 1
                done
            }
            plug() { echo "$1" | socat - "unix-connect:$work/keys1" >/dev/null; } # what the first node's machine is told
            had=0
            comes_to "the session to open the seat's input devices" -gt
            had=$now
            plug 'device_add usb-kbd,id=pad,bus=usb.0'
            comes_to "the session to open the keyboard plugged in" -gt
            grep -aq 'its input devices changed, and it has them as it runs' "$work/n1.log" || fail "the first node did not say it gave the session the keyboard as it ran"
            plug 'device_del pad'
            # An app as a workload of its own: a client of the seat is beside the session, and
            # finds the socket the session listens on in the seat's directory, which it may
            # not write; one that is another user finds nothing there. (The session's socket
            # stands in for a compositor's.)
            app() { job "$1" '"deviceClaims":["apps"],' "\"image\":\"kith.test/pod:1\"$2,\"command\":[\"/bin/pod\",\"call\",\"/run/seat/wayland-0\"]" '^[0-9]+ succeeded'; }
            app window ''
            grep -q 'called: a window, wrote Err(ReadOnlyFilesystem)' "$work/window.out" || fail "an app of the seat did not reach its session's socket, or could write the seat's directory: $(cat "$work/window.out" "$work/window.err")"
            app stranger ',"runAsUser":1000'
            grep -q 'called: failed: PermissionDenied' "$work/stranger.out" || fail "another user's app was not kept from the session's socket: $(cat "$work/stranger.out" "$work/stranger.err")"

            comes_to "the session to lose the keyboard pulled" -eq
            any GET /v1/resources >"$work/found.json" || fail "the cluster's resources could not be read"
            again=$(python3 -c '
import json, sys
found = json.load(open(sys.argv[1]))
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
units = [u for r in found if r["kind"] == "Workload" and r["metadata"]["name"] == "session" for u in (r.get("status") or {}).get("containers") or []]
print(len(units), sum(u.get("restarts", 0) for u in units))' "$work/found.json")
            [ "$again" = '1 0' ] || fail "the session was started again for its keyboard (units, restarts): $again"

            # A long Job keeps its place on a Volume of the node it runs on (README, "Restarting
            # a node on purpose"). The node is drained: the plan is answered, and the Job asked
            # for again is not started there. The drain taken off, it runs and goes on from
            # the step the first one left.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"train-state"},"spec":{"node":"n2","path":"train"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Volume of the Job's state was not applied"
            train='"image":"kith.test/pod:1","command":["/bin/pod","count","/state"],"volumeMounts":[{"volume":"train-state","path":"/state"}]'
            job train '' "$train" '^[0-9]+ succeeded'
            grep -q 'began: step 1' "$work/train.out" || fail "the Job that keeps its step did not begin at the first: $(cat "$work/train.out" "$work/train.err")"
            api 1 GET /v1/drain/n2 >"$work/plan.json" || fail "the plan of a drain of n2 was not answered"
            python3 -c 'import json, sys; assert isinstance(json.load(open(sys.argv[1])), list)' "$work/plan.json" || fail "the plan of a drain is not a list: $(cat "$work/plan.json")"
            api 1 POST '/v1/drain/n2?do=drain' >/dev/null || fail "n2 was not drained"
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"train-again"},"spec":{"retries":0,"template":{"containers":[{"name":"box",$train}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job train-again was not applied"
            sleep 15
            line=$(units Job train-again)
            ! printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)' || fail "a Job was started on a drained node: $line"
            echo "vm.sh: n2 drained: a Job whose Volume is there waits ($line)" >&2
            api 1 POST '/v1/drain/n2?do=undrain' >/dev/null || fail "the drain was not taken off n2"
            job train-again '' "$train" '^[0-9]+ succeeded'
            grep -q 'went on from step 1: step 2' "$work/train-again.out" || fail "the Job run again after the drain did not go on from the first's step: $(cat "$work/train-again.out" "$work/train-again.err")"
            echo "vm.sh: the drain off: the Job ran and went on from the step the first left on its Volume" >&2

            # What a pod writes outside its Volumes is counted (README, resources.storage). NAME,
            # more of its container, how many bytes it writes to /fill, and what its replacement
            # says: it is replaced, says why, and starts again from an empty root.
            fills() {
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"$1"},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"fill","image":"kith.test/pod:1","command":["/bin/pod","fill","/fill","$3"]$2}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Workload $1 was not applied"
                waited=0
                until line=$(units Workload "$1") && printf '%s\n' "$line" | grep -q "$4" \
                    && any GET "/v1/logs/Workload/default/$1?replica=0" >"$work/$1.out" 2>/dev/null \
                    && [ "$(grep -o 'fill: an empty root' "$work/$1.out" | wc -l)" -ge 2 ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for $1 to be replaced and start again; it says: $line: $(cat "$work/$1.out")"
                    sleep 1
                done
                ! grep -q 'fill: /fill was there' "$work/$1.out" || fail "$1 started again with what it wrote in its root: $(cat "$work/$1.out")"
                ! grep -q 'fill: a write failed' "$work/$1.out" || fail "$1 filled its node's state disk before it was replaced: $(cat "$work/$1.out")"
                grep -aq "kithd: .*$4" "$work"/n?.log || fail "no node said on its console why $1 was replaced"
                api 1 DELETE "/v1/resources/Workload/default/$1" >/dev/null || fail "the Workload $1 was not deleted"
                echo "vm.sh: $1 replaced and started again from an empty root: $line" >&2
            }
            # Past its limit of 1 MiB at about 128 KiB a second.
            fills over ',"resources":{"storage":"1Mi"}' 2097152 'replaced: its pod wrote [0-9]* bytes outside its volumes, over its limit of 1048576'
            # With no limit, writing until its node's disk is full: it is replaced once the disk
            # has less free than its reserve, and its write never fails.
            fills full '' 1073741824 'replaced: the node.s state disk has [0-9]* bytes free, under its reserve of 8388608'
            # Past its limit with a file it removed and holds open: no name to walk to, still counted.
            fills unlinked ',"resources":{"storage":"1Mi"}' '2097152","unlinked' 'replaced: its pod wrote [0-9]* bytes outside its volumes, over its limit of 1048576'

            # The deleted Workload's image went, from the node it ran on, once unused for its
            # grace (looked at once a minute; the state disks here are under their reserve,
            # where an image goes once unused for two minutes, as long as the grace here). That
            # of web, running on the first node all along (it is never drained), stayed there,
            # and web still answers.
            gone=$(printf gone | sha256sum | cut -d ' ' -f 1)
            waited=0
            until grep -aq "kithd: removed image sha256:$gone, unused for [0-9]* s (past its grace)" "$work"/n?.log; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "the image of the deleted Workload gone was not removed past its grace: $(grep -ah 'kithd: .*image' "$work"/n?.log)"
                sleep 1
            done
            pod=$(printf pod | sha256sum | cut -d ' ' -f 1)
            ! grep -aq "kithd: removed image sha256:$pod" "$work/n1.log" || fail "the image of web was removed from the node it runs on: $(grep -a 'kithd: remov' "$work/n1.log")"
            asks ask-after web 80
            grep -q 'web-' "$work/ask-after.out" || fail "web did not answer after an image was removed: $(cat "$work/ask-after.out")"
            grep -ah 'kithd: .*image' "$work"/n?.log | tr -d '\r' | sed 's/^/vm.sh: /' >&2

            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: two nodes on the mesh and three pods of one Workload on them, each with an address of its own on the mesh and its IPv4 one from its node's range (the second node's from --pod-range, the first's the default; a pod on each said which at its node's DNS), each listening on port 80 as root and writing to its root; a pod of a user who is not root found their Service by its short name and by its Kubernetes one at the node's DNS, was answered by all three through it, reached this machine from behind its node's address, and wrote what it heard to /dev/stdout by name; $stock; a pod that is root made /dev/null again and read it, and could neither make nor read its node's disk; a container that asked for user namespaces started a sandbox of its own in it (bubblewrap: a user namespace, with a /proc and a /dev made in it), one that did not ask started none, and one that is the node's root was not started; a keyboard plugged in while a container held the seat was one more node it could open, and gone from it when pulled, with nothing started again; an app that was a client of the seat was answered on the socket the seat's session listened on in the seat's directory and could make no file there, and one of another user was not let in; a pod past its limit on what it writes, one past it with a file it removed and held open, and one filling its node's state disk past the reserve, were replaced, said why and started again from an empty root; the image of a Workload deleted went from its node once unused for its grace, and that of a running one stayed and its pods answered"
            exit 0
        fi
        if [ "$test" = policy ]; then
            # Two nodes whose policy turns off exec units, VM paths and /v1/run: nothing the
            # store can ask starts a process as the node's root with every capability, so kithd
            # cut its bounding set at start (README, SECURITY.md). All else is allowed, and
            # what is allowed still runs: a pod that is root, a container with no filter on its
            # system calls, and a sandbox inside a container.
            held() { # each node: "NAME CAPABILITY CAPABILITY ..." as its own status says
                any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    if r["kind"] == "Node":
        print(r["metadata"]["name"], *((r.get("status") or {}).get("policy") or {}).get("capabilities", ["-"]))
'
            }
            waited=0
            until [ "$(held | grep -c '^n[0-9] [^-]')" = 2 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the two nodes did not both say what they hold: $(held)"
                sleep 1
            done
            held >"$work/held"
            echo "vm.sh: what the nodes hold: $(tr '\n' ';' <"$work/held")" >&2
            for n in n1 n2; do
                line=$(grep "^$n " "$work/held") || fail "the node $n did not say what it holds: $(cat "$work/held")"
                case " $line " in *' all '*) fail "the node $n was not cut: $line" ;; esac
                for forbidden in SYS_MODULE SYS_RAWIO SYS_PTRACE SYS_TIME; do
                    case " $line " in *" $forbidden "*) fail "the node $n kept $forbidden: $line" ;; esac
                done
                # (And what the kernel says of kithd, read by it from /proc/PID/status and from a
                # thread it made after the cut, once on its console: the bounding set is exactly
                # what is kept, a later thread's too; the effective set is not cut, so it holds
                # what the bounding set does not, and a later thread's is the same.)
                said=$(grep -ao 'kithd: capability bounding set cut: CapBnd [0-9a-f]* CapEff [0-9a-f]*; a later thread: CapBnd [0-9a-f]* CapEff [0-9a-f]*' "$work/${n}.log" | tail -n 1) || fail "the node $n did not say its bounding set was cut"
                echo "vm.sh: kithd on $n: ${said#kithd: capability bounding set cut: }" >&2
                # shellcheck disable=SC2046
                python3 -c '
import sys
bnd, eff, lbnd, leff = (int(w, 16) for w in sys.argv[1:5])
kept = 0xA80425FB  # CHOWN DAC_OVERRIDE FOWNER FSETID KILL SETGID SETUID SETPCAP NET_BIND_SERVICE NET_RAW SYS_CHROOT MKNOD AUDIT_WRITE SETFCAP
sys.exit(bnd != kept or lbnd != kept or eff & ~bnd == 0 or leff != eff)
' $(printf '%s\n' "$said" | grep -o '[0-9a-f]\{16\}') || fail "kithd on $n: its bounding set is not what it kept, or its effective set was cut: $said"
            done

            # A Job of one container, on a node by a Volume of that node: NAME, the node, the container.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on-n1"},"spec":{"node":"n1","path":"pod"}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on-n2"},"spec":{"node":"n2","path":"pod"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the volumes that put a pod on each node were not applied"
            podded=true # (false: a container that is not a pod)
            job() {
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{"pod":$podded,"containers":[
  {"name":"box","volumeMounts":[{"volume":"on-$2","path":"/state"}],$3}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
                waited=0
                until line=$(units Job "$1") && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 180 ] || fail "waited for the Job $1; it says: $line"
                    sleep 1
                done
                any GET "/v1/logs/Job/default/$1" >"$work/$1.out" 2>/dev/null || true
                any GET "/v1/logs/Job/default/$1?stderr=true" >"$work/$1.err" 2>/dev/null || true
                printf '%s\n' "$line" | grep -Eq '^[0-9]+ succeeded' || fail "the Job $1 says: $line: $(cat "$work/$1.out" "$work/$1.err")"
            }
            # A pod that is root, on the joined node.
            job rooted n2 '"image":"kith.test/pod:1","command":["/bin/pod","tell"]'
            grep -q 'tell: started uid 0 ' "$work/rooted.out" || fail "the pod that is root did not start as root: $(cat "$work/rooted.out" "$work/rooted.err")"
            # (A pod's own bounding set is what its spec says, the fourteen of a root pod
            # whatever kithd's is: that it is what the node kept shows the spec and the cut
            # agree, not the cut, which only kithd's own CapBnd above shows. The same of a
            # container that is not a pod and is root: its spec says three.)
            grep -m1 'tell: started uid 0 ' "$work/rooted.out" | sed 's/^/vm.sh: the pod that is root: /' >&2
            [ "$(grep -m1 'tell: started uid 0 ' "$work/rooted.out" | sed 's/.* bnd //; s/[^0-9a-f].*//' | python3 -c 'import sys; print(int(sys.stdin.read().strip() or "0", 16))')" = $((0xA80425FB)) ] || fail "the bounding set of the pod that is root is not what the node kept: $(cat "$work/rooted.out")"
            # A container that is root and not a pod, naming no capability: what it holds is its
            # spec's three (the runtime's default), on a cut node as on any, so it reads the same
            # as it would uncut; the cut itself is only in kithd's own CapBnd, above.
            podded=false
            job plain n1 '"image":"kith.test/pod:1","command":["/bin/pod","tell"]'
            podded=true
            grep -q 'tell: started uid 0 ' "$work/plain.out" || fail "the container that is root and not a pod did not start as root: $(cat "$work/plain.out" "$work/plain.err")"
            grep -m1 'tell: started uid 0 ' "$work/plain.out" | sed 's/^/vm.sh: the container that is root and not a pod: /' >&2
            [ "$(grep -m1 'tell: started uid 0 ' "$work/plain.out" | sed 's/.* bnd //; s/[^0-9a-f].*//' | python3 -c 'import sys; print(int(sys.stdin.read().strip() or "0", 16))')" = $((0x20000420)) ] || fail "the container that is root and not a pod does not hold its spec's three (AUDIT_WRITE, KILL, NET_BIND_SERVICE): $(cat "$work/plain.out")"
            # A container with no filter on its system calls.
            job open n1 '"image":"kith.test/pod:1","seccomp":{"unconfined":true},"command":["/bin/pod","tell"]'
            grep -q 'tell: started uid 0 ' "$work/open.out" || fail "the container with no filter did not start: $(cat "$work/open.out" "$work/open.err")"
            # A sandbox inside a container (bubblewrap, in a user namespace of its own).
            job boxed n1 '"image":"kith.test/sandbox:1","userNamespaces":true,"command":["/bin/bwrap","--unshare-user","--uid","0","--gid","0","--unshare-pid","--ro-bind","/","/","--proc","/proc","--dev","/dev","/bin/pod","self"]'
            grep -q 'nested: pid 2, uid 0' "$work/boxed.out" || fail "the sandbox did not say where it found itself: $(cat "$work/boxed.out" "$work/boxed.err")"

            # What the node is for still runs on the cut node. A container is forked, cloned
            # and exec'd by libcontainer from kithd, which has the cut set when it does (its
            # volumes, its network, its user); the shim is only for exec units, which are off.
            # (a) A volume of the node's own, on each node: one pod writes it, the next reads it.
            for node in n1 n2; do
                job "keep-a-$node" "$node" '"image":"kith.test/pod:1","command":["/bin/pod","count","/state"]'
                job "keep-b-$node" "$node" '"image":"kith.test/pod:1","command":["/bin/pod","count","/state"]'
                grep -q 'began: step 1' "$work/keep-a-$node.out" || fail "the pod on $node wrote nothing to its node's volume: $(cat "$work/keep-a-$node.out" "$work/keep-a-$node.err")"
                grep -q 'went on from step 1: step 2' "$work/keep-b-$node.out" || fail "the next pod on $node did not read what the first wrote to the volume: $(cat "$work/keep-b-$node.out" "$work/keep-b-$node.err")"
                echo "vm.sh: a volume of node $node: $(cat "$work/keep-a-$node.out"); then: $(cat "$work/keep-b-$node.out")" >&2
            done
            # (b) A volume of the first node, shared, mounted by a container on the second (what
            # --test share does of it): written there, seen on the first.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"data"},"spec":{"node":"n1","path":"all","shared":true}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on1"},"spec":{"node":"n1","path":"own"}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on2"},"spec":{"node":"n2","path":"own"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the shared volume was not applied"
            keygen() { # NAME NODE FILE: a Job that makes FILE in the shared volume (kith's own keygen, which refuses one that is there), on NODE
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{"containers":[
  {"name":"run","image":"kith.test/kith:1","command":["/bin/kith","package","keygen","/data/$3"],
   "volumeMounts":[{"volume":"data","path":"/data"},{"volume":"on${2#n}","path":"/here"}]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
                waited=0
                until line=$(units Job "$1") && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 180 ] || fail "waited for the Job $1; it says: $line"
                    sleep 1
                done
                any GET "/v1/logs/Job/default/$1?stderr=true" >"$work/$1.err" 2>/dev/null || true
            }
            # (The first mount asks the other node for 2 seconds only; on a loaded machine the
            # first packet over the mesh may take longer, so a Job that was refused for that is
            # made again, a few times, and each refusal is said.)
            for attempt in 1 2 3 4 5; do
                keygen "shared-write-$attempt" n2 from-n2
                case $line in *'does not serve it'*) echo "vm.sh: attempt $attempt: $line" >&2 ;; *) break ;; esac
                sleep 10
            done
            printf '%s\n' "$line" | grep -Eq '^[0-9]+ succeeded' || fail "the container on n2 made nothing in the first node's shared volume: $line: $(cat "$work/shared-write-$attempt.err")"
            grep -aq 'kithd: mounted volume default/data from node n1' "$work/n2.log" || fail "the second node did not say it mounted the first node's volume"
            grep -aq 'kithd: serving [0-9]* shared volume' "$work/n1.log" || fail "the first node did not say it serves the volume"
            keygen shared-again n1 from-n2
            printf '%s\n' "$line" | grep -Eq '^[0-9]+ failed' || fail "the container on n1 made a file that the one on n2 made: $line"
            grep -q '/data/from-n2: File exists' "$work/shared-again.err" || fail "the container on n1 did not find what the one on n2 wrote: $(cat "$work/shared-again.err")"
            echo "vm.sh: a shared volume of n1, written from n2 and seen on n1: $(grep -a 'File exists' "$work/shared-again.err" | head -n 1)" >&2
            # (c) A pod whose container is not root. (kith has no command that runs in a
            # running pod, and the probe that would, `exec`, is not run yet: what kithd does in
            # a pod's namespaces for itself is the network a pod joins as it starts, which each
            # pod here did, and the /proc/PID/root of a pod that is given an input device as
            # it is plugged, which no VM here has.)
            job lowly n2 '"image":"kith.test/pod:user","command":["/bin/pod","tell"]'
            grep -q 'tell: started uid 1000 ' "$work/lowly.out" || fail "the pod of a user who is not root did not start as that user: $(cat "$work/lowly.out" "$work/lowly.err")"
            grep -m1 'tell: started uid 1000 ' "$work/lowly.out" | sed 's/^/vm.sh: the pod that is not root: /' >&2
            # (d) Three pods of one Workload on the two nodes, each listening on port 80 at an
            # address of its own on the mesh, and a Service: a pod on the second node asks the
            # Service's name and is answered by each.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"web","labels":{"app":"web"}},"spec":{"replicas":3,"template":{"pod":true,"containers":[
  {"name":"web","image":"kith.test/pod:1","command":["/bin/pod","serve"],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}}}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Service","metadata":{"name":"web"},"spec":{"selector":{"app":"web"},"ports":[{"port":80}]}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the pods of web were not applied"
            waited=0
            until line=$(units Workload web) && [ "${line%% *}" = 3 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "waited for three pods of web to be ready; the Workload says: $line"
                sleep 1
            done
            [ "$(printf '%s\n' $line | grep : | sort -u | grep -c :)" = 3 ] || fail "the three pods of web do not have an address each on the mesh: $line"
            webs=$line
            job asker n2 '"image":"kith.test/pod:user","command":["/bin/pod","ask","web.default.svc.cluster.local","80"]'
            for heard in web-0 web-1 web-2; do
                grep -q "$heard" "$work/asker.out" || fail "the pod that asked the Service did not hear $heard: $(cat "$work/asker.out" "$work/asker.err")"
            done
            ! grep -q 'failed: ' "$work/asker.out" || fail "the pod that asked was not always answered: $(cat "$work/asker.out")"
            echo "vm.sh: three pods of web ready ($webs); a pod on n2 asked the Service and heard: $(tr '\n' ' ' <"$work/asker.out")" >&2

            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: two nodes on the mesh whose policy turns off exec units, VM paths and /v1/run cut their bounding set (kithd's own CapBnd, and a later thread's, was the fourteen a root pod keeps and its CapEff was not cut; each node's status named what was kept) and ran a pod that is root (on the joined node, holding its spec's fourteen), a container that is root and not a pod (holding its spec's three), a container with no filter on its system calls and a sandbox inside a container; a volume of each node's own was written by one pod and read by the next, a shared volume of the first node was written from the second and seen on the first, a pod of a user who is not root started, and three pods of a Workload on both nodes were answered through their Service by a pod on the second"
            exit 0
        fi
        if [ "$test" = kube ]; then
            # kubectl and helm as they are shipped, on this machine, asking the first node as
            # the cluster's admin: what they are given has nothing of kith in it but an
            # image's name. (What they keep for themselves stays in the test's directory.)
            cat >"$work/kubeconfig" <<EOF
apiVersion: v1
kind: Config
current-context: kith
clusters:
- name: kith
  cluster: { server: "https://127.0.0.1:$((port + 1))", certificate-authority: ca.pem, tls-server-name: kith }
users:
- name: root
  user: { client-certificate: cert.pem, client-key: key.pem }
contexts:
- name: kith
  context: { cluster: kith, user: root }
EOF
            mkdir "$work/home"
            k() { HOME="$work/home" KUBECONFIG="$work/kubeconfig" "$kubectl" "$@"; }
            must() { # WHAT IT IS, and a command that has to succeed (what it said: $work/said)
                what=$1
                shift
                "$@" >"$work/said" 2>&1 || fail "$what: $(cat "$work/said"): $(k get pods,jobs,pvc -o wide 2>&1)"
            }
            # NAME and what must be in it: wait for that Job to complete, and read what its
            # pod heard (kubectl logs), which is in $work/NAME.out.
            heard() {
                job=$1
                shift
                must "the Job $job did not complete" k wait --for=condition=complete "job/$job" --timeout=240s
                k logs "job/$job" >"$work/$job.out" 2>"$work/said" || fail "kubectl logs job/$job: $(cat "$work/said")"
                ! grep -q 'failed: ' "$work/$job.out" || fail "the Job $job was not always answered: $(cat "$work/$job.out")"
                for line in "$@"; do
                    grep -q "$line" "$work/$job.out" || fail "the Job $job did not hear \"$line\": $(cat "$work/$job.out")"
                done
            }

            # The manifests: a Deployment told things by a ConfigMap and a Secret, behind a
            # Service with an Ingress, and a StatefulSet with a claim nobody made a volume for.
            waited=0
            until k get node n2 >/dev/null 2>&1; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "kubectl sees no second node: $(k get nodes 2>&1)"
                sleep 1
            done
            must 'the two nodes are not both ready' k wait --for=condition=Ready node/n1 node/n2 --timeout=120s
            must 'kubectl apply of the shop and the db' k apply -f "$root/ci/kube/shop.yaml" -f "$root/ci/kube/db.yaml"
            must 'the Deployment did not roll out' k rollout status deployment/shop --timeout=240s
            must 'the StatefulSet did not roll out' k rollout status statefulset/db --timeout=240s
            k get pods -o wide >"$work/pods" 2>&1 || fail "kubectl get pods: $(cat "$work/pods")"
            [ "$(grep -c ' Running ' "$work/pods")" = 4 ] || fail "not four pods running: $(cat "$work/pods")"
            [ "$(k get pvc data-db-0 -o 'jsonpath={.status.phase}')" = Bound ] || fail "the StatefulSet's claim is not bound: $(k get pvc 2>&1)"
            k get ingress shop 2>&1 | grep -q shop.example.com || fail "the Ingress does not say its host: $(k get ingress 2>&1)"
            must 'kubectl logs of a running pod' k logs shop-0
            must 'kubectl describe of a running pod' k describe pod shop-0
            # The ways into a running pod are not here, and say so.
            if timeout 60 env HOME="$work/home" KUBECONFIG="$work/kubeconfig" "$kubectl" port-forward shop-0 "$((port + 10)):80" >"$work/said" 2>&1; then
                fail "kubectl port-forward was answered"
            fi
            grep -q 'not answered here' "$work/said" || fail "kubectl port-forward was not refused in words: $(cat "$work/said")"

            # A Job, and a CronJob's Job made by the clock: each hears the three of the shop,
            # what they were told, and the db, which has started once.
            must 'kubectl apply of the Job and the CronJob' k apply -f "$root/ci/kube/jobs.yaml"
            heard ask 'shop-0 hello hunter2' 'shop-1 hello hunter2' 'shop-2 hello hunter2' 'db-0 started 1'
            waited=0
            until tick=$(k get jobs -o name 2>/dev/null | grep -m 1 '^job.batch/tick-'); do
                waited=$((waited + 1))
                [ "$waited" -lt 100 ] || fail "the CronJob made no Job in a minute and a half: $(k get cronjobs,jobs 2>&1)"
                sleep 1
            done
            heard "${tick#job.batch/}" 'shop-0 hello hunter2' 'db-0 started 1'
            # Restarted, the db is a new pod with the file the old one wrote: a Job made
            # from the CronJob by hand hears that it has started twice.
            must 'kubectl rollout restart' k rollout restart statefulset/db
            must 'the StatefulSet did not roll out again' k rollout status statefulset/db --timeout=240s
            must 'kubectl create job --from' k create job again --from=cronjob/tick
            heard again 'db-0 started 2'

            # What a stock chart says of a pod beyond its image (ci/kube/files.yaml): a
            # ConfigMap and a Secret as files, directories of its own, what it is told from
            # maps and from itself, a user who is not root with no capability, and a
            # container that runs first. The pod says what it finds (ci/pod.rs, tell).
            must 'kubectl apply of the pod with files' k apply -f "$root/ci/kube/files.yaml"
            must 'the Deployment with files did not roll out' k rollout status deployment/files --timeout=240s
            waited=0
            until k logs files-0 -c tell >"$work/files.out" 2>"$work/said" && grep -q '^tell: watching' "$work/files.out"; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "the pod with files has not said what it found: $(cat "$work/said" "$work/files.out")"
                sleep 1
            done
            # (What it found when it started: before it watched for what changes.)
            sed '/^tell: watching/q' "$work/files.out" >"$work/files.first"
            for line in \
                '^tell: started uid 1000 caps eff 0000000000000000 bnd 0000000000000000$' \
                '^tell: env COLOUR=green$' '^tell: env S_token=sesame$' \
                '^tell: env POD_NAME=files-0$' '^tell: env POD_NAMESPACE=default$' '^tell: env NODE_NAME=n[12]$' \
                "^tell: env POD_IP=$(k get pod files-0 -o 'jsonpath={.status.podIP}' | sed 's/\./\\./g')\$" \
                '^tell: mount /etc/conf [^ ]+ /[^ ]+ ro write Err' \
                '^tell: mount /etc/one.conf [^ ]+ /[^ ]+ ro write Err' \
                '^tell: mount /etc/secret tmpfs /kith/replicas/[^ ]+ ro write Err' \
                '^tell: mount /work [^ ]+ /[^ ]+ rw write Ok' \
                '^tell: mount /fast tmpfs /kith/replicas/[^ ]+ rw write Ok' \
                '^tell: file /etc/conf/motd [0-7]+ one$' '^tell: file /etc/conf/site.conf [0-7]+ listen 80$' \
                '^tell: file /etc/one.conf [0-7]+ listen 80$' \
                '^tell: file /etc/secret/creds/token 400 sesame$' \
                '^tell: file /work/first [0-7]+ ran first$'; do
                grep -Eq "$line" "$work/files.first" || fail "the pod with files did not say \"$line\" when it started: $(cat "$work/files.out")"
            done
            [ "$(grep -c '^tell: file /etc/secret/' "$work/files.first")" = 1 ] || fail "the Secret's files are not the one its items name: $(cat "$work/files.out")"
            must 'kubectl logs of the container that ran first' k logs files-0 -c first
            grep -q '^put: /work/first' "$work/said" || fail "the container that ran first did not say so: $(cat "$work/said")"
            said=$(k get pod files-0 -o 'jsonpath={.status.initContainerStatuses[0].state.terminated.reason} {.status.containerStatuses[*].name}' 2>&1)
            [ "$said" = 'Completed tell' ] || fail "the pod with files says of its containers: $said"
            # The ConfigMap changed, its files are the new ones in the pod that was running.
            sed -n '/^kind: ConfigMap/,/^---/p' "$root/ci/kube/files.yaml" | sed -e '/^---/,$d' -e 's/motd: one/motd: two/' >"$work/files-config.yaml"
            { echo 'apiVersion: v1'; cat "$work/files-config.yaml"; } >"$work/files-changed.yaml"
            grep -q 'motd: two' "$work/files-changed.yaml" || fail "the test's changed ConfigMap is not one: $(cat "$work/files-changed.yaml")"
            must 'kubectl apply of the changed ConfigMap' k apply -f "$work/files-changed.yaml"
            waited=0
            until k logs files-0 -c tell 2>&1 | grep -Eq '^tell: file /etc/conf/motd [0-7]+ two$'; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "the changed ConfigMap's file did not change in the pod: $(k logs files-0 -c tell 2>&1)"
                sleep 1
            done
            said=$(k logs files-0 -c tell 2>&1 | grep -c '^tell: started') restarts=$(k get pod files-0 -o 'jsonpath={.status.containerStatuses[0].restartCount}')
            [ "$said $restarts" = '1 0' ] || fail "the pod was started again for a changed file (started $said times, $restarts restarts)"
            # Root without two capabilities has the others, and not those two (13 and 27; CHOWN is 0).
            heard caps '^tell: started uid 0 '
            bnd=$(sed -n 's/^tell: started uid 0 caps eff \([0-9a-f]*\) bnd \1$/\1/p' "$work/caps.out")
            [ -n "$bnd" ] && [ "$((0x$bnd >> 13 & 1))$((0x$bnd >> 27 & 1))$((0x$bnd & 1))" = 001 ] || fail "root without NET_RAW and MKNOD has: $(cat "$work/caps.out")"
            # Told not to be root, an image that names no user does not start, and says why.
            waited=0
            until k get pod rooted-0 -o 'jsonpath={.status.containerStatuses[0].state.waiting.message}' 2>&1 | grep -q runAsNonRoot; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "a pod that would be root under runAsNonRoot does not say so: $(k get pod rooted-0 -o yaml 2>&1)"
                sleep 1
            done
            [ "$(k get pod rooted-0 -o 'jsonpath={.status.phase}')" = Pending ] || fail "a pod that would be root under runAsNonRoot is not pending: $(k get pods 2>&1)"

            # Without a file: made, shown to others, grown and given another image by hand.
            must 'kubectl create deployment' k create deployment made --image=kith.test/pod:serve --replicas=2 --port=80
            must 'kubectl expose' k expose deployment made --port=80
            must 'the Deployment made by hand did not roll out' k rollout status deployment/made --timeout=240s
            must 'kubectl scale' k scale deployment/made --replicas=3
            must 'kubectl set image' k set image deployment/made pod=kith.test/pod:again
            must 'the Deployment made by hand did not roll out again' k rollout status deployment/made --timeout=240s
            said=$(k get deployment made -o 'jsonpath={.status.readyReplicas} {.spec.template.spec.containers[0].image}' 2>&1)
            [ "$said" = '3 kith.test/pod:again' ] || fail "the Deployment made by hand says: $said"
            must 'kubectl create job' k create job ask-made --image=kith.test/pod:1 -- /bin/pod ask made 80
            heard ask-made made-0 made-1 made-2

            # Helm, 3 and 4: the chart it starts every chart from, waited for until it is ready.
            n=0
            for helm in $helms; do
                n=$((n + 1))
                h() { HOME="$work/home" KUBECONFIG="$work/kubeconfig" "$helm" "$@"; }
                must "helm create ($n)" h create "$work/site$n"
                must "helm install --wait ($n)" h install "site$n" "$work/site$n" --set image.repository=kith.test/pod --set image.tag=serve --wait --timeout 240s
                must "helm upgrade --wait ($n)" h upgrade "site$n" "$work/site$n" --reuse-values --set replicaCount=2 --wait --timeout 240s
                [ "$(k get deployment "site$n" -o 'jsonpath={.status.readyReplicas}')" = 2 ] || fail "helm upgrade --wait ($n) came back before two were ready: $(k get deployments 2>&1)"
                h list 2>&1 | grep -q "site$n.*deployed" || fail "helm list ($n) does not say deployed: $(h list 2>&1)"
                must "helm uninstall --wait ($n)" h uninstall "site$n" --wait --timeout 120s
            done

            stock='no stock image was tried (KITH_E2E=1 pulls one)'
            if [ "${KITH_E2E:-}" = 1 ]; then
                # nginx as it is shipped, by hand and as Helm's chart with nothing changed
                # but where the image comes from.
                must 'kubectl create deployment of nginx' k create deployment stock --image=mirror.gcr.io/library/nginx:1.27-alpine --replicas=2 --port=80
                must 'kubectl expose of nginx' k expose deployment stock --port=80
                must 'nginx did not roll out' k rollout status deployment/stock --timeout=480s
                must 'kubectl create job, to ask nginx' k create job ask-stock --image=kith.test/pod:1 -- /bin/pod ask stock 80
                heard ask-stock 'HTTP/1.1 200 OK'
                if [ -n "$helms" ]; then
                    helm=${helms%% *}
                    must 'helm install --wait of nginx' h install stock-site "$work/site1" --set image.repository=mirror.gcr.io/library/nginx --set image.tag=1.27-alpine --wait --timeout 480s
                    must 'helm uninstall of nginx' h uninstall stock-site --wait --timeout 120s
                fi
                must 'kubectl delete of nginx' k delete deployment,service stock
                must 'kubectl delete of the Job that asked nginx' k delete job ask-stock
                stock='nginx as it is shipped (mirror.gcr.io/library/nginx:1.27-alpine) rolled out by kubectl create deployment and by helm install --wait, and answered through its Service'
            fi

            # Deleted, nothing of it is left: not the volume made for the claim either.
            must 'kubectl delete of the manifests' k delete -f "$root/ci/kube"
            must 'kubectl delete of what was made by hand' k delete deployment,service made
            must 'kubectl delete of the Jobs made by hand' k delete job again ask-made
            must 'kubectl delete of the claim' k delete pvc data-db-0
            left() {
                k get all,pvc,configmaps,secrets,ingress -o name 2>&1
                any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
ours = ("Workload", "Job", "CronJob", "Service", "Volume", "VolumeClaim", "ConfigMap", "Secret", "KubeObject")
for r in found:
    if r["kind"] in ours and r["metadata"].get("namespace") != "kith-system":
        print(r["kind"], r["metadata"]["name"])
'
            }
            waited=0
            until [ -z "$(left)" ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "deleted, this is left: $(left)"
                sleep 1
            done

            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: two nodes, and kubectl and helm as they are shipped asking the first: manifests written for Kubernetes applied (a Deployment of three told things by a ConfigMap and a Secret, its Service and Ingress, a StatefulSet whose claim got a volume made for it), rolled out and running; a Job and a CronJob's Job, made by the clock, heard all of them through their Services (kubectl wait, kubectl logs); after kubectl rollout restart the StatefulSet's new pod had the file the old one wrote; a pod as a chart writes one had a ConfigMap's files (changed in it when the ConfigMap was, with no restart) and one of them alone (subPath), a Secret's file from memory with the mode it asked, two directories of its own (one in memory), what it was told by envFrom and by its own fields, no capability as a user who is not root, and found what its initContainer left; root without two capabilities had the others; told runAsNonRoot an image that names no user did not start and said why; a Deployment made, exposed, scaled and given another image by hand rolled out each time; port-forward was refused in words; helm install, upgrade and uninstall with --wait came back when the chart was ready ($n of helm); deleted, nothing was left; $stock" >&2
            exit 0
        fi
        if [ "$test" = share ]; then
            # What a Job says of itself and of its unit: "STATE and what it says"; nothing
            # while there is no such Job.
            job() {
                any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    if r["kind"] == "Job" and r["metadata"]["name"] == sys.argv[1]:
        status = r.get("status") or {}
        units = status.get("containers") or [{}]
        print(status.get("state", "-"), status.get("message", ""), units[0].get("message", ""), status.get("notes", ""))
' "$1"
            }
            until_job() { # NAME STATE: wait for the Job to end that way
                waited=0
                until line=$(job "$1") && [ "${line%% *}" = "$2" ]; do
                    case ${line%% *} in succeeded | failed) fail "the Job $1 $line; expected: $2" ;; esac
                    waited=$((waited + 1))
                    [ "$waited" -lt $((time / 2)) ] || fail "waited for the Job $1 to have $2; it says: $line"
                    sleep 1
                done
                echo "vm.sh: the Job $1 $2" >&2
            }
            # A Job whose container makes a new file in the shared volume (kith's own keygen:
            # it refuses a file that is there). The volume of one node it also mounts is what
            # puts it on that node.
            run() { # NAME THAT-NODE'S-VOLUME FILE
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{"containers":[
  {"name":"run","image":"kith.test/kith:1","command":["/bin/kith","package","keygen","/data/$3"],
   "volumeMounts":[{"volume":"data","path":"/data"},{"volume":"$2","path":"/here"}]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
            }
            refused() { # NAME FILE: the Job failed because FILE was there already
                any GET "/v1/logs/Job/default/$1?stderr=true" >"$work/$1.err" 2>/dev/null || true
                grep -q "/data/$2: File exists" "$work/$1.err" || fail "the Job $1 did not fail for /data/$2 being there: $(cat "$work/$1.err"); it says: $(job "$1")"
            }
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"data"},"spec":{"node":"n1","path":"all","shared":true}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"roots"},"spec":{"node":"n1","path":"all","shared":true}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on1"},"spec":{"node":"n1","path":"own"}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on2"},"spec":{"node":"n2","path":"own"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the volumes were not applied"

            # Written on the second node, through the first node's volume; there on the first.
            run write on2 from-n2
            until_job write succeeded
            grep -aq 'kithd: mounted volume default/data from node n1' "$work/n2.log" || fail "the second node did not say it mounted the volume"
            grep -aq 'kithd: serving [0-9]* shared volume' "$work/n1.log" || fail "the first node did not say it serves the volume"
            run again on1 from-n2
            until_job again failed
            refused again from-n2
            # And the other way: written on the first node, there on the second.
            run here on1 from-n1
            until_job here succeeded
            run across on2 from-n1
            until_job across failed
            refused across from-n1

            # Those containers were not root: /dev is root's, and a key cannot be made there
            # but by a container whose template says it is root.
            user() { # NAME [USER]
                as=''
                [ -z "${2:-}" ] || as=",\"runAsUser\":$2"
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{"containers":[
  {"name":"run","image":"kith.test/kith:1","command":["/bin/kith","package","keygen","/dev/key"]$as}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
            }
            user nobody
            until_job nobody failed
            any GET "/v1/logs/Job/default/nobody?stderr=true" >"$work/nobody.err" 2>/dev/null || true
            grep -q 'Permission denied' "$work/nobody.err" || fail "a container that names no user was not kept out of /dev as one that is not root is: $(cat "$work/nobody.err")"
            user root 0
            until_job root succeeded

            # A container on the node's network keeps the node's users (a port it serves is
            # under 1024 as often as not, and no capability of a user namespace reaches that
            # network), and the node's ports under 1024 stay its root's.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"node-ids"},"spec":{"retries":0,"template":{"containers":[
  {"name":"run","image":"kith.test/pod:1","command":["/bin/pod","ids","=/proc/sys/net/ipv4/ip_unprivileged_port_start"],"runAsUser":0,
   "volumeMounts":[{"volume":"on1","path":"/here"}]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job node-ids was not applied"
            until_job node-ids succeeded
            said=$(any GET /v1/logs/Job/default/node-ids | field data) || fail "what the Job node-ids said could not be read"
            printf '%s\n' "$said" | grep -q '^ids: map 0 0 4294967295$' || fail "a container on the node's network did not keep the node's users: $said"
            printf '%s\n' "$said" | grep -q '^ids: =/proc/sys/net/ipv4/ip_unprivileged_port_start holds Ok("1024")$' || fail "the node's ports under 1024 are not its root's alone: $said"

            # A pod's root is not the node's: its ids are a range of the node's of its own (two
            # running at once never share one), the node's own files (its /sys) are nobody's
            # to it, a file there only the node's root opens does not open, and port 80 of its
            # own network is still its to bind. Its
            # volume's files are owned on disk as before: read on the second node through NFS
            # (which takes no id-mapped mount: that container keeps the node's users, and says
            # so), what containers on the first made is root's, or nobody's, as they were. (Root
            # writes a volume of its own: the Jobs made data nobody's, and a Workload's root has
            # no capability to write what is another's.)
            sees() { # NAME REPLICA UNTIL: what a replica of the Workload said, once it said UNTIL
                waited=0
                until said=$(any GET "/v1/logs/Workload/default/$1?replica=$2" 2>/dev/null | field data) && printf '%s\n' "$said" | grep -q "$3"; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 120 ] || fail "replica $2 of the Workload $1 did not say what it sees: $said"
                    sleep 1
                done
                printf '%s\n' "$said"
            }
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"ids"},"spec":{"replicas":2,"template":{"pod":true,"containers":[
  {"name":"run","image":"kith.test/pod:1","command":["/bin/pod","stays",":80","/sys","root-only","+/roots/by-root"],"runAsUser":0,
   "volumeMounts":[{"volume":"data","path":"/data"},{"volume":"roots","path":"/roots"},{"volume":"on1","path":"/here"}]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Workload ids was not applied"
            range() { # REPLICA: the first id of its range
                said=$(sees ids "$1" '^ids: +/roots/by-root /') || exit 1
                printf '%s\n' "$said" | grep -q '^ids: :80 binds Ok(())$' || fail "a pod's root did not bind port 80 of its own network: $said"
                printf '%s\n' "$said" | grep -q '^ids: /sys /sys owner 65534 opens Ok' || fail "the node's /sys is not nobody's to a container: $said"
                printf '%s\n' "$said" | grep -q '^ids: root-only /sys/.* owner 65534 opens Err(PermissionDenied)' || fail "a container's root opened a file only the node's root does: $said"
                printf '%s\n' "$said" | grep -q '^ids: +/roots/by-root /roots/by-root owner 0 opens Ok' || fail "a container's root did not make a file of its own in its volume: $said"
                printf '%s\n' "$said" | sed -n 's/^ids: map 0 \([0-9]*\) 65536$/\1/p' | grep -E '^[1-9][0-9]{4,}$' || fail "replica $1 of the Workload ids has no range of its own: $said"
            }
            first=$(range 0) || exit 1
            second=$(range 1) || exit 1
            [ "$first" -ge 65536 ] && [ "$second" -ge 65536 ] && [ "$first" != "$second" ] || fail "two containers have the ranges $first and $second"
            echo "vm.sh: two containers' ids start at $first and $second of the node's" >&2
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"owners"},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"run","image":"kith.test/pod:1","command":["/bin/pod","stays","/roots/by-root","/data/from-n1","/data/from-n2"],
   "volumeMounts":[{"volume":"data","path":"/data"},{"volume":"roots","path":"/roots","readOnly":true},{"volume":"on2","path":"/here"}]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Workload owners was not applied"
            said=$(sees owners 0 '^ids: /data/from-n2 ') || exit 1
            for made in roots/by-root:0 data/from-n1:65534 data/from-n2:65534; do
                printf '%s\n' "$said" | grep -q "^ids: /${made%:*} /${made%:*} owner ${made#*:} opens Ok" || fail "/${made%:*} is not ${made#*:}'s on disk: $said"
            done
            printf '%s\n' "$said" | grep -q '^ids: map 0 0 4294967295$' || fail "a container with a volume through NFS did not keep the node's users: $said"
            any GET /v1/resources >"$work/all.json" || fail "the resources could not be read"
            python3 - "$work/all.json" <<'EOF' || fail "the units do not say whose users they have: $(cat "$work/all.json")"
import json, sys

found = json.load(open(sys.argv[1]))
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
said = {r["metadata"]["name"]: [c.get("hostUsers") for c in (r.get("status") or {}).get("containers", [])] for r in found if r["kind"] == "Workload"}
sys.exit(0 if said.get("ids") == [False, False] and said.get("owners") == [True] else 1)
EOF
            for made in ids owners; do
                any DELETE "/v1/resources/Workload/default/$made" >/dev/null || fail "the Workload $made was not deleted"
            done

            # From outside the mesh (this machine, through the node's other card) there is no
            # NFS server to talk to: it listens on the mesh address alone.
            python3 - "$((port + 5))" <<'EOF' || fail "the first node's NFS port answered an address outside the mesh"
import socket, sys

# An RPC call of NFS 4's procedure 0, which a server that hears it answers.
call = bytes.fromhex("80000028" "00000001" "00000000" "00000002" "000186a3" "00000004" + "00000000" * 5)
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5) as s:
        s.sendall(call)
        sys.exit(1 if s.recv(4) else 0)
except OSError:
    sys.exit(0)
EOF

            # A Share names this machine (10.0.2.2 to the node, through its other card): it
            # is no node and not on the mesh, and speaks NFS 4.2 to the first node itself.
            probe() { python3 "$root/ci/nfs_probe.py" 127.0.0.1 "$@" | tr '\n' ' '; }
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Share","metadata":{"name":"mine"},"spec":{"volume":"on1","nfs":{"clients":["10.0.2.2"]}}},
 {"apiVersion":"kith.dev/v1","kind":"Share","metadata":{"name":"look"},"spec":{"volume":"data","readOnly":true,"nfs":{"clients":["10.0.2.0/24"]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Shares were not applied"
            waited=0
            until grep -aq 'kithd: serving [0-9]* shared volume.*; 2 Share(s) to the addresses they name' "$work/n1.log"; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "the first node did not say it serves the Shares"
                sleep 1
            done
            said=$(probe "$((port + 5))" /default/on1/own mkdir from-lan) || fail "the first node did not speak NFS to a machine its Share names"
            [ "$said" = '0 0 ' ] || fail "a machine the Share names did not make a directory in its volume: NFS said $said"
            # The directory is in the volume, for a container on that node: a key goes in it.
            # (The Share's user and the container's are the same one: nobody, as neither says.)
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"lan"},"spec":{"retries":0,"template":{"containers":[
  {"name":"run","image":"kith.test/kith:1","command":["/bin/kith","package","keygen","/here/from-lan/key"],
   "volumeMounts":[{"volume":"on1","path":"/here"}]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job lan was not applied"
            until_job lan succeeded
            said=$(probe "$((port + 5))" /default/data/all mkdir nope) || fail "the first node stopped speaking NFS"
            [ "$said" = '0 30 ' ] || fail "a read-only Share was not read-only (30): NFS said $said"
            said=$(probe "$((port + 5))" /default/on2) || fail "the first node stopped speaking NFS"
            [ "$said" = '2 ' ] || fail "a Share's client saw something that is no Share's (2 is no such thing): NFS said $said"
            # The second node has no Share: it still answers nothing outside the mesh.
            ! python3 "$root/ci/nfs_probe.py" 127.0.0.1 "$((port + 6))" / >/dev/null 2>&1 || fail "the second node, with no Share, spoke NFS outside the mesh"
            any GET /v1/resources >"$work/all.json" || fail "the resources could not be read"
            python3 - "$work/all.json" <<'EOF' || fail "the Share mine does not say where it is"
import json, sys

found = json.load(open(sys.argv[1]))
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
status = next(r.get("status") for r in found if r["kind"] == "Share" and r["metadata"]["name"] == "mine")
sys.exit(0 if status == {"node": "n1", "path": "/default/on1/own"} else 1)
EOF

            # An encrypted volume on the second node. Its key is made there and kept by the
            # first node; its file, read from outside on the node's disk, shows nothing of
            # the file system in it (the one it starts as has a label to look for); told to
            # restart, the node closes it, comes up, is handed the key again, and what a
            # container wrote in it is still there.
            grep -aq kith-volume "$root/target/os/root/usr/share/kith/volume.ext4" || fail "the file system an encrypted volume starts as has no label to look for"
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"vault"},"spec":{"node":"n2","path":"in","size":"12Mi","encrypted":true}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the encrypted volume was not applied"
            sealed() { # NAME: a Job whose container makes the file `key` in the encrypted volume
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{"containers":[
  {"name":"run","image":"kith.test/kith:1","command":["/bin/kith","package","keygen","/vault/key"],
   "volumeMounts":[{"volume":"vault","path":"/vault"}]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
            }
            hears() { # N WHAT: wait for node N's console to have said it
                waited=0
                until grep -aq "$2" "$work/n$1.log"; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 120 ] || fail "the node n$1 did not say: $2"
                    sleep 1
                done
            }
            hears 2 'kithd: made the encrypted volume default/vault'
            sealed seal
            until_job seal succeeded
            echo sendkey ctrl-alt-delete | socat - "unix-connect:$work/keys2" >/dev/null
            hears 2 'reboot: Restarting system'
            hears 2 'kithd: opened the encrypted volume default/vault'
            grep -aq 'kithd: handed n2 the key of its volume default/vault' "$work/n1.log" || fail "the first node did not say it handed the volume's key over"
            sealed sealed-again
            until_job sealed-again failed
            any GET "/v1/logs/Job/default/sealed-again?stderr=true" >"$work/sealed.err" 2>/dev/null || true
            grep -q '/vault/key: File exists' "$work/sealed.err" || fail "what was written in the encrypted volume was not there after the restart: $(cat "$work/sealed.err")"
            read -r state_start state_sectors <"$work/state.at"
            ! dd if="$work/n2.raw" bs=512 skip="$state_start" count="$state_sectors" status=none | grep -aq kith-volume || fail "the encrypted volume's file system is in the clear on its node's disk"

            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: two nodes on the mesh; a file made in a shared volume by a container on the node that does not hold it was there for one on the node that does, and the other way round; nothing answered NFS from outside the mesh until a Share named this machine, which then made a directory in the Share's volume, could not write a read-only Share, and saw nothing else; an encrypted volume was made on the second node with its key kept by the first, its file system not to be seen on the node's disk, closed when the node was told to restart and opened again with the key the first node handed back, what was written in it still there; a pod's root was not the node's (two at once had ranges of ids of their own, the node's /sys was nobody's to them, a file only the node's root opens did not open, and each bound port 80 of its own network) while a container on the node's network kept the node's users and the node's ports under 1024 stayed its root's, and what containers made in a volume was owned on disk as before"
            exit 0
        fi
        until_says "three nodes, each saying what it runs" "^- 0 [^,? ]+,[^,? ]+,[^,? ]+ "
        was=${line#- 0 } was=${was%% *}
        if [ "$test" = access ]; then
            # The cluster's admin is an Identity like any other: its Role becomes one that may
            # read and delete everything and apply only Roles and RoleBindings, and a RoleBinding
            # of its own (maps-root) lets it apply ConfigMaps, until that is deleted.
            printf '%s' '[{"apiVersion":"kith.dev/v1","kind":"Role","metadata":{"name":"cluster-admin"},"spec":{"rules":[{"kinds":["*"],"verbs":["get","list","watch","delete","exec"]},{"kinds":["Role","RoleBinding"],"verbs":["apply"]}]}},
{"apiVersion":"kith.dev/v1","kind":"Role","metadata":{"name":"maps"},"spec":{"rules":[{"kinds":["ConfigMap"],"verbs":["apply"]}]}},
{"apiVersion":"kith.dev/v1","kind":"RoleBinding","metadata":{"name":"maps-root"},"spec":{"role":"maps","subjects":["root"]}}]' >"$work/grant.json"
            api 1 POST /v1/apply "$work/grant.json" >/dev/null || fail "the admin's Roles were not applied"
            # Two writers, through n2 and through n3: numbered ConfigMaps, and a note of every
            # attempt, as for chaos: NAME NODE BEGUN ANSWERED ok|no.
            writer() { # N
                i=0 patience=5
                while ! [ -e "$work/stop" ]; do
                    i=$((i + 1))
                    printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"a%s-%s"},"spec":{"data":{"n":"a%s-%s"}}}]' "$1" "$i" "$1" "$i" >"$work/a$1.json"
                    begun=$(date +%s.%N) said=no
                    ! api "$1" POST /v1/apply "$work/a$1.json" >/dev/null 2>&1 || said=ok
                    echo "a$1-$i $1 $begun $(date +%s.%N) $said" >>"$work/writes$1"
                    sleep 0.1
                done
            }
            acked() { cat "$work"/writes? 2>/dev/null | awk -v n="$1" '$5 == "ok" && $2 == n' | wc -l; }
            monitor() { echo "$2" | socat - "unix-connect:$work/keys$1" >/dev/null; } # N COMMAND
            writers=''
            for n in 2 3; do
                writer "$n" &
                vms="$vms $!" writers="$writers $!"
            done
            waited=0
            until [ "$(acked 2)" -ge 10 ] && [ "$(acked 3)" -ge 10 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the admin's writes through n2 and n3 were not acknowledged: $(acked 2) and $(acked 3)"
                sleep 1
            done
            echo "vm.sh: the admin writing through n2 and n3" >&2

            # n2 is cut off from the others (its card on the cluster's network unplugged), so
            # it does not hear of the deletion; the RoleBinding is deleted through n1, whichever
            # of n1 and n3 leads then. (Had n2 led, it leads no more once it is plugged back:
            # its write is then passed on to the one that does, and refused there all the same.)
            monitor 2 'set_link lan off'
            sleep 2
            begun=$(date +%s.%N)
            (patience=30 && api 1 DELETE /v1/resources/RoleBinding/maps-root) >/dev/null || fail "the RoleBinding maps-root was not deleted"
            echo "$begun $(date +%s.%N)" >"$work/deleted"
            # A write through n2, which still holds the RoleBinding and lets it through; it
            # waits for the leader until the card is plugged back, and is refused there.
            printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"late"},"spec":{"data":{"n":"late"}}}]' >"$work/late.json"
            curl -s -o "$work/late" -w '%{http_code}' --max-time 40 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
                --resolve "kith:$((port + 2)):127.0.0.1" -H 'Content-Type: application/json' --data-binary "@$work/late.json" \
                "https://kith:$((port + 2))/v1/apply" >"$work/late.code" &
            late=$!
            sleep 3
            monitor 2 'set_link lan on'
            wait "$late" || true
            sleep 5
            : >"$work/stop"
            # shellcheck disable=SC2086 # (a list of process numbers)
            wait $writers

            # Each node's own list, until the three say the same; then against the notes.
            cat "$work"/writes? >"$work/writes"
            lists() { for n in 1 2 3; do api "$n" GET '/v1/resources?kind=ConfigMap' >"$work/list$n.json" 2>/dev/null || { echo "n$n did not answer" >"$work/wrong"; return 1; }; done; }
            tries=0
            until lists && said=$(python3 -c '
import json, sys
work = sys.argv[1]
def held(n):
    found = json.load(open(f"{work}/list{n}.json"))
    found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
    return {r["metadata"]["name"] for r in found if r["kind"] == "ConfigMap"}
lists = [held(n) for n in (1, 2, 3)]
writes = {name: (float(begun), float(answered), said) for name, node, begun, answered, said in (line.split() for line in open(f"{work}/writes"))}
begun, deleted = (float(at) for at in open(f"{work}/deleted").read().split())
code, late = open(f"{work}/late.code").read().strip(), open(f"{work}/late").read()
wrong = []
if not lists[0] == lists[1] == lists[2]:
    wrong.append("the nodes hold different writes: " + ", ".join(str(len(held)) for held in lists))
acked = {name for name, (at, answered, said) in writes.items() if said == "ok"}
lost = sorted(acked - lists[0])
if lost:
    wrong.append(f"{len(lost)} acknowledged writes are not held: {lost[:5]}")
after = [name for name, (at, answered, said) in writes.items() if at > deleted]
taken = sorted(name for name in after if writes[name][2] == "ok")
if taken:
    wrong.append(f"{len(taken)} writes begun after the deletion was acknowledged were acknowledged: {taken[:5]}")
kept = sorted(name for name in lists[0] if name == "late" or (name in writes and writes[name][0] > deleted))
if kept:
    wrong.append(f"{len(kept)} writes begun after the deletion was acknowledged are held: {kept[:5]}")
if not after:
    wrong.append("no write was begun after the deletion: the test showed nothing")
if code != "422" or "decided again" not in late:
    wrong.append(f"the write n2 let through while it was cut off was not refused where the log is kept: {code} {late[:300]}"
                 + (" (it waited on a log no majority held: n2 may have led when it was cut off, and kept leading past the 10 s it waits; run again)" if code == "500" and "no leader" in late else ""))
if wrong:
    sys.exit("; ".join(wrong))
print(f"{len(acked)} writes acknowledged of {len(writes)} tried, each held by all three nodes; none of the {len(after)} begun after the deletion was acknowledged or kept, and the one n2 let through while cut off was refused by the leader")
' "$work" 2>"$work/wrong"); do
                tries=$((tries + 1))
                [ "$tries" -lt 60 ] || fail "after the deletion: $(cat "$work/wrong")"
                sleep 1
            done
            ! grep -al 'Kernel panic\|panicked at' "$work"/n?.log || fail "a node panicked"
            echo "vm.sh: ok: three nodes; the admin writing through n2 and n3 by a RoleBinding deleted through n1 while n2 was cut off: $said"
            exit 0
        fi

        if [ "$test" = chaos ]; then
            # Three writers on this machine, one through each node: numbered ConfigMaps, and
            # a note of every attempt: NAME NODE BEGUN ANSWERED ok|no. (Each node has two
            # cards: the writers come in by the one that is never unplugged.)
            writer() { # N
                # (Not long with each: a cut-off node is tried more than once while it is.
                # One that is given up on and then lands is a write nobody was told of.)
                i=0 patience=3
                while ! [ -e "$work/stop" ]; do
                    i=$((i + 1))
                    printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"w%s-%s"},"spec":{"data":{"n":"w%s-%s"}}}]' "$1" "$i" "$1" "$i" >"$work/w$1.json"
                    begun=$(date +%s.%N) said=no
                    ! api "$1" POST /v1/apply "$work/w$1.json" >/dev/null 2>&1 || said=ok
                    echo "w$1-$i $1 $begun $(date +%s.%N) $said" >>"$work/writes$1"
                    sleep 0.2
                done
            }
            # How many writes were acknowledged: through node N, or (-N) through the others.
            acked() { cat "$work"/writes? 2>/dev/null | awk -v n="${1:-0}" '$5 == "ok" && (n == 0 || (n > 0 && $2 == n) || (n < 0 && $2 != -n))' | wc -l; }
            goes_on() { # WHOSE WHAT: ten more writes acknowledged (through WHOSE, as for acked)
                had=$(acked "$1") waited=0
                until [ "$(acked "$1")" -ge $((had + 10)) ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt $((time / 4)) ] || fail "$2: $(($(acked "$1") - had)) writes acknowledged in $waited s"
                    sleep 1
                done
                echo "vm.sh: $2" >&2
            }
            monitor() { echo "$2" | socat - "unix-connect:$work/keys$1" >/dev/null; } # N COMMAND
            fault() { echo "$1 $2 $(date +%s.%N)" >>"$work/faults"; }                # WHAT N
            writers=''
            for n in 1 2 3; do
                writer "$n" &
                vms="$vms $!" writers="$writers $!"
            done
            goes_on 0 "three nodes, taking writes through each"
            for n in 1 2 3; do goes_on "$n" "writes through n$n"; done

            # Each node in turn (so the leader's turn comes, whichever it is) is cut off from
            # the other two: its card on the cluster's network is unplugged. It still
            # answers this machine, and acknowledges nothing; the other two go on.
            for n in 1 2 3; do
                # (KITH_CHAOS_CUT='info status' cuts nothing, and the test must then fail:
                # that is how it was shown to see a node that goes on acknowledging.)
                monitor "$n" "${KITH_CHAOS_CUT:-set_link lan off}"
                sleep 2
                fault cut "$n"
                goes_on "-$n" "n$n cut off: the other two went on taking writes"
                sleep 15 # (long enough for it to give up on its leader, or on leading)
                # (The writers wait 3 s for an answer and a node 10 s for its leader: one
                # write through the cut-off node is waited for longer than both.)
                printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"cut-%s"},"spec":{"data":{"n":"cut-%s"}}}]' "$n" "$n" >"$work/cut.json"
                ! (patience=20 && api "$n" POST /v1/apply "$work/cut.json") >/dev/null 2>&1 || fail "n$n, cut off from the others, acknowledged a write"
                goes_on "-$n" "n$n still cut off: the other two still taking writes"
                curl -sk -o /dev/null --max-time 5 "https://127.0.0.1:$((port + n))/v1/ca" || fail "n$n, cut off from the others, did not answer this machine either: the test cut the wrong card"
                fault heal "$n"
                monitor "$n" 'set_link lan on'
                goes_on "$n" "n$n back with the others: writes through it again"
            done

            # Each node in turn loses power: reset by the hypervisor in the middle of
            # writes, with nothing flushed that was not flushed already. The other two go
            # on; it starts again and is one of the three again.
            # (What a guest had flushed is in its disk's file whatever happens to the guest:
            # a disk that lies about a flush, or tears a write, is not what this shows.)
            for n in 1 2 3; do
                monitor "$n" system_reset
                fault reset "$n"
                goes_on "-$n" "n$n lost power: the other two went on taking writes"
                goes_on "$n" "n$n started again: writes through it again"
            done

            # All three lose power at the same moment, in the middle of writes: now no
            # node has what another lost, and what was acknowledged is there only if a
            # majority had it on disk before it was.
            for n in 1 2 3; do monitor "$n" system_reset; done
            fault dark 0
            for n in 1 2 3; do goes_on "$n" "all three lost power at once: n$n started again, writes through it"; done
            : >"$work/stop"
            # shellcheck disable=SC2086 # (a list of process numbers)
            wait $writers

            # Each node's own list, until the three say the same; then against the notes.
            cat "$work"/writes? >"$work/writes"
            lists() { for n in 1 2 3; do api "$n" GET '/v1/resources?kind=ConfigMap' >"$work/list$n.json" 2>/dev/null || { echo "n$n did not answer" >"$work/wrong"; return 1; }; done; }
            tries=0
            until lists && said=$(python3 -c '
import json, sys
work = sys.argv[1]
def held(n):
    found = json.load(open(f"{work}/list{n}.json"))
    found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
    return {r["metadata"]["name"]: r["spec"]["data"]["n"] for r in found if r["kind"] == "ConfigMap"}
lists = [held(n) for n in (1, 2, 3)]
writes = [line.split() for line in open(f"{work}/writes")]
acked = {name for name, node, begun, answered, said in writes if said == "ok"}
wrong = []
if not lists[0] == lists[1] == lists[2]:
    wrong.append("the nodes hold different writes: " + ", ".join(str(len(held)) for held in lists))
for n, has in enumerate(lists, 1):
    lost = sorted(acked - set(has))
    if lost:
        wrong.append(f"n{n} lacks {len(lost)} acknowledged writes: {lost[:5]}")
    if any(name != value for name, value in has.items()):
        wrong.append(f"n{n} holds a write with another one in it")
faults = [line.split() for line in open(f"{work}/faults")]
cuts = {node: float(at) for what, node, at in faults if what == "cut"}
refused = 0
for what, node, healed in faults:
    if what == "heal":
        # (Begun while it was cut off; acknowledged while it still was, which it cannot be.
        # One that hangs until the card is back and is acknowledged then is as it should be.)
        tried = [(name, said, float(answered)) for name, at, begun, answered, said in writes
                 if at == node and cuts[node] < float(begun) < float(healed)]
        inside = [name for name, said, answered in tried if said == "ok" and answered < float(healed)]
        refused += sum(1 for name, said, answered in tried if said == "no")
        if inside:
            wrong.append(f"n{node} acknowledged {len(inside)} writes while it was cut off: {inside[:5]}")
        if not tried:
            wrong.append(f"nothing was tried through n{node} while it was cut off: the test showed nothing")
if wrong:
    sys.exit("; ".join(wrong))
print(f"{len(acked)} writes acknowledged of {len(writes)} tried, each of them held by all three nodes; {refused} tried through a cut-off node, none acknowledged")
' "$work" 2>"$work/wrong"); do
                tries=$((tries + 1))
                [ "$tries" -lt 60 ] || fail "after the faults: $(cat "$work/wrong")"
                sleep 1
            done
            ! grep -al 'Kernel panic\|EXT4-fs error\|panicked at' "$work"/n?.log || fail "a node panicked, or its file system was found broken"
            [ "$(starts 1 a)$(starts 2 a)$(starts 3 a)" = 333 ] || fail "not every node started exactly three times: the resets did not happen as meant"
            echo "vm.sh: ok: three nodes; each in turn cut off from the other two, which went on taking writes while it acknowledged none, each in turn reset in the middle of writes and back as one of the three, and all three reset at the same moment: $said"
            exit 0
        fi

        # Before any release, each node says it takes releases from its image's keys (each
        # says it in its first round: waited for).
        waited=0
        until whose=$(any GET /v1/resources | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
nodes = (r for r in found if r["kind"] == "Node")
print(",".join(sorted(((n.get("status") or {}).get("os") or {}).get("releaseKeys", "?") for n in nodes)))
') && [ "$whose" = image,image,image ]; do
            waited=$((waited + 1))
            [ "$waited" -lt 60 ] || fail "the nodes do not take releases from the image's keys alone: $whose"
            sleep 1
        done
        # The first release applied, signed by a key the image was not built with: refused,
        # where a node with no key would have taken that key for its own.
        by=$public2
        release stranger 9.0.0-stranger "$(sign next key2)" next
        until_says "a first release by a key the image was not built with refused" "^Paused 0 $was .*not signed by a key this node takes releases from"
        [ "$(starts 1 a)$(starts 2 a)$(starts 3 a)" = 111 ] || fail "a node restarted for a release it refused"
        by=$public

        # A release whose signature is another file's: the first node asked refuses it,
        # writes nothing, and the plan stops there.
        release forged 9.0.0-next "$(sign broken)" next
        until_says "a release signed for another file refused" "^Paused 0 $was .*signature is not the release's key's"
        [ "$(starts 1 a)$(starts 2 a)$(starts 3 a)" = 111 ] || fail "a node restarted for a release it refused"

        # The release, signed: every node takes it, one at a time, and it is one cluster still.
        # It hands its key over to a second one, which signs with the first that it is held.
        more=",\"handover\":{\"keys\":[\"$public2\"],\"signature\":\"$(handed key)\",\"proof\":\"$(handed key2)\"}"
        release next 9.0.0-next "$(sign next)"
        until_says "all three on the release" "^Done 0 9.0.0-next,9.0.0-next,9.0.0-next "
        [ "$(starts 1 b)$(starts 2 b)$(starts 3 b)" = 111 ] || fail "not every node started its other slot once"
        ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
        # (Each takes the keys handed over once it has called the release's slot good.)
        tries=0
        until [ "$(grep -al 'handed over its release keys' "$work"/n?.log | wc -l)" = 3 ]; do
            tries=$((tries + 1))
            [ "$tries" -lt 60 ] || fail "not every node took the keys the release handed over"
            sleep 1
        done
        on=9.0.0-next,9.0.0-next,9.0.0-next

        # A release under what every node has now run well, in a plan that allows going
        # back and signed by the key they now take: refused, with nothing fetched.
        by=$public2 allow=',"allowDowngrade":true'
        release under 0.0.1 "$(sign next key2)" next
        until_says "a release under the floor refused, though its plan allows going back" "^Paused 0 $on .*the newest this node has run well"
        # One signed by the key that was left out: refused too.
        by=$public
        release left-out 9.0.1 "$(sign next)" next
        until_says "a release signed by the key that handed over refused" "^Paused 0 $on .*not signed by a key this node takes releases from"
        [ "$(starts 1 b)$(starts 2 b)$(starts 3 b)" = 111 ] || fail "a node restarted for a release it refused"
        by=$public2

        # A release that cannot start: the first node tries it three times and is back on
        # what it ran; the plan is paused, and no other node is given it.
        release broken 9.0.0-broken "$(sign broken key2)"
        until_says "a release that cannot start stopped at the first node" "^Paused 0 9.0.0-next,9.0.0-next,9.0.0-next .* did not take 9.0.0-broken: it did not come up"
        # (It says so once it has called its own slot good, ten seconds after it started.)
        tries=0
        until [ "$(grep -al 'slot a did not come up in 3 tries: this is slot b' "$work"/n?.log | wc -l)" = 1 ]; do
            tries=$((tries + 1))
            [ "$tries" -lt 30 ] || fail "not exactly one node tried the broken release"
            sleep 1
        done
        [ "$(($(starts 1 a) + $(starts 2 a) + $(starts 3 a)))" = 6 ] || fail "expected three tries of the broken release on one node"
        echo "vm.sh: ok: three nodes, claimed and joined over TLS; a first release by a key their image was not built with refused; a forged release refused; a signed one taken by all three, one at a time, as one cluster, and with it the key it handed over to; a release under their floor and one by the key left out refused; one that cannot start, signed by the new key, tried by one node, which came back, and the plan paused: $line"
        exit 0
    fi
    if [ "$test" = install ] || [ "$test" = vps ] || [ "$test" = netboot ] || [ "$test" = crypt ]; then
        for tool in curl python3 cpio ${sealing:+swtpm}; do
            command -v "$tool" >/dev/null 2>&1 || skip "no $tool"
        done
        # (mcopy puts the answers on the stick; where it is missing nix has it, as for os/build.sh.)
        if ! command -v mcopy >/dev/null 2>&1; then
            command -v nix >/dev/null 2>&1 || skip "no mcopy (mtools)"
            mcopy() { nix shell nixpkgs#mtools -c mcopy "$@"; }
        fi
        [ "$time" -gt 60 ] || time=300
        port=$((20000 + $$ % 20000))
        fail() {
            for log in "$work"/*.log; do echo "== $log"; tail -n 25 "$log"; done
            echo "vm.sh: FAIL: $1" >&2
            exit 1
        }
        installer=$root/target/os/kith-os-installer.raw
        # (Where its ESP starts: the first partition in its table.)
        esp=$(python3 -c 'import struct, sys; f = open(sys.argv[1], "rb"); f.seek(512 + 72); f.seek(struct.unpack("<Q", f.read(8))[0] * 512 + 32); print(struct.unpack("<Q", f.read(8))[0] * 512)' "$installer")
        # Every disk here is a file in this test's own directory: the installer is only
        # ever started in a VM, with those attached.
        stick() { # NAME [ANSWERS]: a copy of the installer, with answers on its ESP
            cp "$installer" "$work/$1.stick"
            [ -z "${2:-}" ] || mcopy -i "$work/$1.stick@@$esp" "$2" ::kith-install.yaml
        }
        blank() { truncate -s 2G "$work/$1.disk"; }
        drive() { echo "-drive file=$work/$1,format=raw,if=virtio"; }
        lan() { # N: a card on the network the nodes share, and one out to this machine
            echo "-netdev socket,id=lan,mcast=230.0.0.1:$((port + 8)),localaddr=127.0.0.1 -device virtio-net-pci,netdev=lan,mac=52:54:00:00:09:0$1" \
                "-netdev user,id=out,hostfwd=tcp:127.0.0.1:$((port + $1))-:7443 -device virtio-net-pci,netdev=out,mac=52:54:00:00:0a:0$1"
        }
        vm() { # NAME [QEMU's arguments]: a machine whose serial console is logged and can be typed at
            name=$1
            shift
            timeout "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -display none -no-reboot \
                -machine q35 -bios "$firmware" "$@" \
                -chardev "socket,id=tty,path=$work/$name.tty,server=on,wait=off,logfile=$work/$name.log" -serial chardev:tty \
                -monitor none </dev/null >/dev/null 2>&1 &
            vm=$!
            vms="$vms $vm"
        }
        hears() { # NAME TEXT
            waited=0
            until grep -aqF -- "$2" "$work/$1.log" 2>/dev/null; do
                waited=$((waited + 1))
                [ "$waited" -lt $((time * 5)) ] || fail "$1 never said: $2"
                sleep 0.2
            done
        }
        installed() { # NAME DISK: the installer said so and powered the machine off
            wait "$vm" || fail "$1 did not end by itself"
            grep -aqF "kithd: install: kith OS is on $2" "$work/$1.log" || fail "$1 did not install on $2"
            grep -aqF 'kithd: init: powering off' "$work/$1.log" || fail "$1 did not power off"
        }
        print() { # PORT: who answers TLS there, into $who
            tries=0
            until openssl s_client -connect "127.0.0.1:$1" </dev/null 2>/dev/null >"$work/hello" \
                && who=$(openssl x509 -noout -fingerprint -sha256 <"$work/hello" 2>/dev/null); do
                tries=$((tries + 1))
                [ "$tries" -lt 100 ] || fail "nobody answered TLS on port $1"
                sleep 0.2
            done
        }

        if [ "$test" = vps ]; then
            # A rented machine: os/vps.sh there loads the kernel and a memory disk and starts
            # them in place of the system that runs. Here the script packs the memory disk
            # (--dry-run: nothing of this machine is looked at or started) and QEMU starts
            # kernel and memory disk as kexec would, over a disk that held something else.
            out=$root/target/os
            printf 'disk: vda   # the only one\nhostname: delta\n' >"$work/delta.yaml"
            sh "$out/vps.sh" --answers "$work/delta.yaml" --erase vdb --dry-run "$work/no" >/dev/null 2>"$work/refused" \
                && fail "vps.sh went on with another disk named than the answers'"
            grep -qF 'nothing was done' "$work/refused" || fail "vps.sh did not say that nothing was done"
            [ ! -e "$work/no" ] || fail "vps.sh wrote something before the disk was named twice"
            printf 'vdb\n' | sh "$out/vps.sh" --answers "$work/delta.yaml" --dry-run "$work/no" >/dev/null 2>&1 \
                && fail "vps.sh went on with another disk typed than the answers'"
            sh "$out/vps.sh" --answers "$work/delta.yaml" --erase vda --dry-run "$work/vps" >/dev/null || fail "vps.sh --dry-run failed"
            blank delta
            head -c $((8 << 20)) /dev/urandom >"$work/held"
            dd if="$work/held" of="$work/delta.disk" conv=notrunc status=none
            # Answers the installer refuses (a disk of another size than the one meant):
            # nothing is written, and the machine starts again, into what it held.
            printf 'disk: vda\nsize: 5\n' >"$work/other.yaml"
            sh "$out/vps.sh" --answers "$work/other.yaml" --erase vda --dry-run "$work/other" >/dev/null || fail "vps.sh --dry-run failed"
            # shellcheck disable=SC2046
            vm refused -m 1024 -kernel "$out/vmlinuz" -initrd "$work/other/initrd" -append 'console=ttyS0 kith.install' $(drive delta.disk)
            wait "$vm" || fail "the installer that refused its answers did not start the machine again"
            grep -aqF 'is not the disk that was named' "$work/refused.log" || fail "a disk of another size than the one named was not refused"
            grep -aqF 'kithd: init: restarting' "$work/refused.log" || fail "the installer that refused its answers did not start the machine again"
            cmp -s -n $((8 << 20)) "$work/held" "$work/delta.disk" || fail "the installer that refused its answers wrote to the disk"
            # shellcheck disable=SC2046
            vm install-delta -m 1024 -kernel "$out/vmlinuz" -initrd "$work/vps/initrd" -append 'console=ttyS0 kith.install' $(drive delta.disk)
            wait "$vm" || fail "install-delta did not end by itself"
            grep -aqF 'kithd: install: kith OS is on vda' "$work/install-delta.log" || fail "the installer in memory did not install on vda"
            grep -aqF 'kithd: init: restarting' "$work/install-delta.log" || fail "the installer in memory did not restart the machine"
            # shellcheck disable=SC2046
            vm delta $(drive delta.disk) -netdev "user,id=out,hostfwd=tcp:127.0.0.1:$((port + 5))-:7443" -device virtio-net-pci,netdev=out
            hears delta 'kithd: init: delta is up'
            hears delta 'kithd: node delta serving other nodes on 0.0.0.0:7443'
            print $((port + 5))
            echo "vm.sh: ok: os/vps.sh wants the disk named twice; the kernel and memory disk it packs, started as kexec starts them over a disk that held something else, installed kith OS there and restarted; the disk then started as node delta ($who)"
            exit 0
        fi

        if [ "$test" = netboot ] || [ "$test" = crypt ]; then
            # A network as in a house: one with a DHCP server of its own (ci/dhcpd.py), on a
            # hub with a node's card and a socket that a second machine's card connects to.
            # The node is told to install that machine; the machine, with an empty disk, is
            # set to start from the network. The node's second card is this script's way in.
            out=$root/target/os
            [ "$time" -gt 300 ] || time=600
            mac=52:54:00:00:09:02 more=''
            # (Six starts of the machine: the node has to outlast them all.)
            [ "$test" = netboot ] || more='&encrypt=true' time=$((time * 2))
            [ -z "$sealing" ] || time=$((time * 3 / 2))
            python3 "$root/ci/dhcpd.py" "$((port + 9))" 52:54:00:00:09:01=10.9.0.1 "$mac=10.9.0.2" &
            vms="$vms $!"
            sleep 0.5
            cp "$out/kith-os.raw" "$work/alpha.disk"
            # shellcheck disable=SC2046
            vm alpha $(drive alpha.disk) \
                -netdev "socket,id=d,connect=127.0.0.1:$((port + 9))" -netdev hubport,id=h0,hubid=0,netdev=d \
                -netdev "socket,id=s,listen=127.0.0.1:$((port + 8))" -netdev hubport,id=h1,hubid=0,netdev=s \
                -netdev hubport,id=h2,hubid=0 -device virtio-net-pci,netdev=h2,mac=52:54:00:00:09:01 \
                -netdev "user,id=u,restrict=on,hostfwd=tcp:127.0.0.1:$((port + 1))-10.0.2.15:7443" -device virtio-net-pci,netdev=u \
                -smbios 'type=11,value=io.systemd.stub.kernel-cmdline-extra=kith.hostname=alpha -- --listen 0.0.0.0:7443 --advertise 10.9.0.1:7443 --claim'
            hears alpha 'kithd: node alpha serving other nodes on 0.0.0.0:7443'
            hears alpha 'sends this token to /v1/claim does: kith1.'
            token=$(grep -ao 'sends this token to /v1/claim does: kith1\.[0-9a-f.]*' "$work/alpha.log")
            tries=0
            until claimed=$(curl -sfk --max-time 10 -H 'Content-Type: application/json' -d "{\"token\":\"${token##* }\",\"name\":\"root\"}" "https://127.0.0.1:$((port + 1))/v1/claim"); do
                tries=$((tries + 1))
                [ "$tries" -lt 50 ] || fail "the node's cluster could not be claimed"
                sleep 0.2
            done
            field() { python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]], end="")' "$1"; }
            for part in ca cert key; do
                printf '%s' "$claimed" | (umask 077 && field "$part" >"$work/$part.pem") || fail "the claim was refused: $claimed"
            done
            api() { # METHOD PATH [curl's further arguments]: as the cluster's admin, to alpha
                method=$1 path=$2
                shift 2
                curl -s --max-time 60 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
                    --resolve "kith:$((port + 1)):127.0.0.1" -X "$method" "$@" "https://kith:$((port + 1))$path"
            }
            # Off until told; not turned on by a file that is not the boot file, nor for no machine.
            now=$(api GET /v1/netboot)
            [ "$(printf '%s' "$now" | field on)" = False ] || fail "netboot is on before anyone turned it on: $now"
            api PUT "/v1/netboot?macs=$mac" --data-binary "@$out/vmlinuz" | grep -qF "not kith's network boot file" || fail "netboot took a file that is not the boot file"
            api PUT '/v1/netboot?minutes=10' --data-binary "@$out/kith-netboot.efi" | grep -qF "a machine's card address" || fail "netboot went on for no machine"
            [ "$(api GET /v1/netboot | field on)" = False ] || fail "netboot is on after two refusals"
            [ "$(api PUT "/v1/netboot?macs=$mac&minutes=10$more" --data-binary "@$out/kith-netboot.efi" | field on)" = True ] || fail "netboot did not go on"
            # (Again while on: the second takes the ports the first held.)
            [ "$(api PUT "/v1/netboot?macs=$mac&minutes=10$more" --data-binary "@$out/kith-netboot.efi" | field on)" = True ] || fail "netboot, on, could not be turned on anew"
            hears alpha 'kithd: netboot: on for 10 minutes'

            beta() { # LOG [disk]: the machine: an empty disk at first, and its card, which it starts from (or: from its disk)
                vm "$1" -m 1024 -drive "file=$work/beta.disk,format=raw,if=none,id=d" -device "virtio-blk-pci,drive=d${2+,bootindex=0}" \
                    -netdev "socket,id=n,connect=127.0.0.1:$((port + 8))" -device "virtio-net-pci,netdev=n,mac=$mac${2-,bootindex=1}"
            }
            blank beta
            beta install-beta
            wait "$vm" || fail "the machine started from the network did not install and start again"
            grep -aqF 'kithd: install: kith OS is on vda' "$work/install-beta.log" || fail "the machine started from the network did not install"
            hears alpha "kithd: netboot: $mac has the installer"
            api GET /v1/netboot | grep -q '"served": *true' || fail "the node does not say the machine was served"
            # Started again, still from the network first: it is not answered a second time,
            # goes on to its disk, and joins the node's cluster with the token it was given.
            beta beta
            hears beta 'kithd: init: kith-000902 is up'
            tries=0
            until api GET /v1/resources/Node/kith-000902 -f >/dev/null; do
                tries=$((tries + 1))
                [ "$tries" -lt 300 ] || fail "the machine installed from the network is not in the node's cluster"
                sleep 0.2
            done
            ! grep -aqF 'kithd: install:' "$work/beta.log" || fail "the machine was installed a second time"
            [ "$(api DELETE /v1/netboot | field on)" = False ] || fail "netboot did not go off"
            hears alpha 'kithd: netboot: off'
            if [ "$test" = crypt ]; then
                # What a disk file says from outside: whether its state partition shows a file
                # system (ext4's mark) and what its lock record holds.
                says() {
                    python3 -c '
import struct, sys
disk, at = open(sys.argv[1], "rb"), {}
disk.seek(512 + 72)
entries = struct.unpack("<Q", disk.read(8))[0] * 512
for index in range(128):
    disk.seek(entries + index * 128)
    entry = disk.read(128)
    at[entry[56:].decode("utf-16-le").rstrip("\0")] = struct.unpack("<Q", entry[32:40])[0] * 512
disk.seek(at["state"] + 1080)
state = "plain" if disk.read(2) == b"\x53\xef" else "sealed"
disk.seek(at["config"] + (512 << 10))
record = disk.read(4096)
print(state, "none" if not record.startswith(b"kith-lock v1\n") else "key" if b"\nkey: " in record else "held", *["tpm"] * (b"\ntpm: " in record), *["tpm-parent"] * (b"\ntpm-parent: " in record), *["tpm-pin"] * (b"\ntpm-pin: " in record), *["passphrase"] * (b"\npassphrase: " in record), *["seen"] * (b"\nseen: yes\n" in record), *["duress"] * (b"\nduress: " in record))' "$1"
                }
                lock() { api POST "/v1/lock/kith-000902?do=$1"; }
                up() { # LOG: the machine's state is open and it serves
                    hears "$1" 'kithd: init: state on /dev/dm-'
                    hears "$1" 'kithd: node kith-000902 serving other nodes'
                }
                recovery=$(grep -ao 'shown this once: [0-9a-f-]*' "$work/install-beta.log") || fail "the installer showed no recovery key"
                [ "$(says "$out/kith-os.raw")" = 'plain none' ] || fail "the image's state is not a plain file system: $(says "$out/kith-os.raw")"
                # First start: the key is beside the lock until the other node holds it.
                hears beta 'still on its disk: no other node holds it yet'
                up beta
                hears beta "10.9.0.1:7443 holds the key of this node's state"
                if [ -n "$sealing" ]; then
                    tpm=''
                    mkdir "$work/tpm"
                    own() { # LOG [away] [more of QEMU's arguments]: the machine from its disk, with its TPM (the same at every start: its state is kept); away: without its card, so no node is in reach
                        machine=$1 card=1
                        shift
                        [ "${1:-}" != away ] || { card='' && shift; }
                        [ -z "$tpm" ] || kill "$tpm" 2>/dev/null || true
                        rm -f "$work/tpm.sock"
                        swtpm socket --tpm2 --tpmstate "dir=$work/tpm" --ctrl "type=unixio,path=$work/tpm.sock" >/dev/null 2>&1 &
                        tpm=$!
                        vms="$vms $tpm"
                        tries=0
                        until [ -S "$work/tpm.sock" ]; do
                            tries=$((tries + 1))
                            [ "$tries" -lt 50 ] || fail "swtpm did not start"
                            sleep 0.1
                        done
                        [ -n "$card" ] || set -- -nic none "$@"
                        [ -z "$card" ] || set -- -netdev "socket,id=n,connect=127.0.0.1:$((port + 8))" -device "virtio-net-pci,netdev=n,mac=$mac" "$@"
                        vm "$machine" -m 1024 -drive "file=$work/beta.disk,format=raw,if=none,id=d" -device virtio-blk-pci,drive=d,bootindex=0 \
                            -chardev "socket,id=tpmc,path=$work/tpm.sock" -tpmdev emulator,id=tpm0,chardev=tpmc -device tpm-tis,tpmdev=tpm0 "$@"
                    }
                    off() { # the machine's power cut
                        kill "$vm"
                        wait "$vm" 2>/dev/null || true
                    }
                    told() { # WHAT: the cluster's NodeKey of the machine comes to say it
                        tries=0
                        until api GET /v1/resources/NodeKey/kith-000902 | grep -q "$1"; do
                            tries=$((tries + 1))
                            [ "$tries" -lt 150 ] || fail "the machine's NodeKey never said $1: $(api GET /v1/resources/NodeKey/kith-000902)"
                            sleep 0.2
                        done
                    }
                    # Told to seal, a machine with no TPM says why not, and runs on as it was.
                    lock seal | grep -q '"seal": *true' || fail "the machine could not be told to seal its key"
                    hears beta 'is not sealed: this machine has no TPM'
                    told 'no TPM'
                    off
                    [ "$(says "$work/beta.disk")" = 'sealed held' ] || fail "the machine's disk, read from outside: $(says "$work/beta.disk")"
                    # With its TPM: it asks the node this once, and seals its key to what it runs.
                    own beta2
                    hears beta2 'asking the cluster for its key'
                    up beta2
                    hears beta2 "this machine's TPM holds the key of its state"
                    told '"sealed": *true'
                    off
                    [ "$(says "$work/beta.disk")" = 'sealed held tpm tpm-parent' ] || fail "the sealed machine's disk, read from outside: $(says "$work/beta.disk")"
                    # Started again: its own TPM gives the key, and no node is asked.
                    own beta3
                    hears beta3 'TPM gave the key of its state: no node was asked'
                    up beta3
                    ! grep -aqF 'asking the cluster' "$work/beta3.log" || fail "a machine whose TPM holds its key asked the cluster for it"
                    off
                    # A word of its config partition changed (a space after the last): the TPM
                    # refuses, the node is asked, and the key is sealed to what runs now.
                    python3 -c '
import struct, sys
with open(sys.argv[1], "r+b") as disk:
    disk.seek(512 + 72)
    entries = struct.unpack("<Q", disk.read(8))[0] * 512
    for index in range(128):
        disk.seek(entries + index * 128)
        entry = disk.read(128)
        if entry[56:].decode("utf-16-le").rstrip("\0") == "config":
            at = struct.unpack("<Q", entry[32:40])[0] * 512
            disk.seek(at)
            disk.seek(at + disk.read(64 << 10).index(b"\0"))
            disk.write(b" ")
            sys.exit(0)
    sys.exit(1)' "$work/beta.disk" || fail "the machine's disk has no config partition to change"
                    refused() { # LOG: the TPM gave no key, the node did, and the key is sealed anew
                        hears "$1" 'this is not the system it was sealed for'
                        hears "$1" 'asking the cluster for its key'
                        up "$1"
                        hears "$1" "this machine's TPM holds the key of its state"
                        off
                    }
                    own beta4
                    refused beta4
                    # The boot file changed (a letter of the command line in it): the same.
                    python3 -c '
import mmap, sys
with open(sys.argv[1], "r+b") as disk:
    disk, found = mmap.mmap(disk.fileno(), 0), 0
    at = disk.find(b"console=tty0 dm-mod.create")
    while at >= 0:
        disk[at : at + 12], found = b"console=tty1", found + 1
        at = disk.find(b"console=tty0 dm-mod.create", at)
    sys.exit(found == 0)' "$work/beta.disk" || fail "the machine's disk has no boot file with the command line this test changes"
                    own beta5
                    refused beta5
                    # A command line beside the boot file's: the same. And with that one again,
                    # its own TPM gives the key, and no node is asked.
                    beside='type=11,value=io.systemd.stub.kernel-cmdline-extra=loglevel=7'
                    own beta6 -smbios "$beside"
                    refused beta6
                    own beta7 -smbios "$beside"
                    hears beta7 'TPM gave the key of its state: no node was asked'
                    up beta7
                    ! grep -aqF 'asking the cluster' "$work/beta7.log" || fail "the machine, sealed anew, asked the cluster for its key"
                    # Locked: it drops the seal, restarts and waits; unlocked, it seals again.
                    lock lock | grep -q '"locked": *true' || fail "the sealed machine could not be locked"
                    hears beta7 "this machine's TPM no longer holds the key of its state"
                    hears beta7 'kithd: the cluster has locked this node'
                    wait "$vm" || true
                    [ "$(says "$work/beta.disk")" = 'sealed held' ] || fail "the locked machine's disk, read from outside: $(says "$work/beta.disk")"
                    own beta8
                    hears beta8 'still locked: 10.9.0.1:7443 does not hand this node'
                    ! grep -aqF 'state on' "$work/beta8.log" || fail "a locked machine opened its state"
                    lock unlock | grep -q '"locked": *false' || fail "the machine could not be unlocked"
                    up beta8
                    hears beta8 "this machine's TPM holds the key of its state"
                    # Taken back: the seal is dropped, and the NodeKey says so.
                    lock unseal | grep -q '"seal": *false' || fail "the seal could not be taken back"
                    hears beta8 "this machine's TPM no longer holds the key of its state"
                    told '"sealed": *false'
                    off
                    [ "$(says "$work/beta.disk")" = 'sealed held' ] || fail "the machine's disk, read from outside, once its seal was taken back: $(says "$work/beta.disk")"
                    # A PIN, asked of the machine itself at its own address (no node passes one
                    # on): refused unless the owner says this TPM is untried (swtpm's is: 3
                    # wrong PINs, then one more every 1000 seconds, which 8 digits are enough
                    # for). (Its second card has no ROM, so the firmware starts as before.)
                    own beta9 -netdev "user,id=u,restrict=on,hostfwd=tcp:127.0.0.1:$((port + 2))-10.0.2.15:7443" -device virtio-net-pci,netdev=u,romfile=
                    up beta9
                    pin=40917253
                    api POST /v1/lock/kith-000902/pin -H 'Content-Type: application/json' -d "{\"pin\":\"$pin\",\"untried\":true}" | grep -qF 'ask node kith-000902 itself' || fail "a PIN was passed on by the other node"
                    given() { # JSON: to the machine itself
                        curl -s --max-time 60 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" --resolve "kith:$((port + 2)):127.0.0.1" \
                            -X POST -H 'Content-Type: application/json' -d "$1" "https://kith:$((port + 2))/v1/lock/kith-000902/pin"
                    }
                    tries=0
                    until said=$(given "{\"pin\":\"$pin\"}") && [ -n "$said" ]; do
                        tries=$((tries + 1))
                        [ "$tries" -lt 150 ] || fail "the machine does not answer at its own address"
                        sleep 0.2
                    done
                    printf '%s' "$said" | grep -qF 'On hardware' || fail "a PIN was taken without the owner saying the TPM is untried: $said"
                    given '{"pin":"4091","untried":true}' | grep -qF 'a PIN is 6 to 32 digits' || fail "a PIN of 4 digits was not refused"
                    said=$(given "{\"pin\":\"$pin\",\"untried\":true}")
                    printf '%s' "$said" | grep -q '"pin": *true' || fail "the machine took no PIN: $said"
                    hears beta9 "this machine's TPM and its PIN open its state; its TPM alone no longer does"
                    ! api GET /v1/resources | grep -qF "$pin" || fail "the PIN is in the store"
                    off
                    [ "$(says "$work/beta.disk")" = 'sealed held tpm-parent tpm-pin' ] || fail "the disk of the machine with a PIN, read from outside: $(says "$work/beta.disk")"
                    ! grep -aqF "$pin" "$work/beta.disk" "$work/alpha.log" "$work/beta9.log" || fail "the PIN is on the machine's disk or was said by a node"
                    # Away from its cluster it asks at its console: its PIN opens it.
                    own pin1 away
                    hears pin1 'Or type its PIN, or the recovery key, here: neither is shown'
                    hears pin1 'still locked'
                    ! grep -aqF 'state on' "$work/pin1.log" || fail "a machine away from its cluster opened its state before its PIN was typed"
                    types() { printf '%s\n' "$2" | socat - "unix-connect:$work/$1.tty" >/dev/null; }
                    types pin1 "$pin"
                    hears pin1 'kithd: init: opened with its PIN'
                    hears pin1 'kithd: init: state on /dev/dm-'
                    off
                    # Started again: a wrong PIN opens nothing and is counted, until the TPM
                    # refuses every PIN, the right one too, and says for how long. (Setting
                    # the PIN tried a wrong one; a TPM cut off after a PIN was used counts
                    # one more: how many are left here is not known beforehand.)
                    answered() { grep -acF -e "kithd: init: that does not open this node's state" -e 'kithd: init: the TPM refuses every PIN for now' "$work/$1.log" || true; }
                    after() { # LOG N: the console answered more than N lines
                        tries=0
                        until [ "$(answered "$1")" -gt "$2" ]; do
                            tries=$((tries + 1))
                            [ "$tries" -lt 150 ] || fail "the console answered no more than $2 lines"
                            sleep 0.2
                        done
                    }
                    own pin2 away
                    hears pin2 'Or type its PIN, or the recovery key, here: neither is shown'
                    hears pin2 'still locked'
                    wrong=0
                    until grep -aqF 'the TPM refuses every PIN for now' "$work/pin2.log"; do
                        [ "$wrong" -lt 4 ] || fail "the TPM refused no PIN after $wrong wrong ones"
                        types pin2 40917250
                        after pin2 "$wrong"
                        wrong=$((wrong + 1))
                    done
                    types pin2 "$pin"
                    after pin2 "$wrong"
                    [ "$(grep -acF 'the TPM refuses every PIN for now' "$work/pin2.log")" -ge 2 ] || fail "the right PIN, typed while the TPM refused every PIN, was not refused"
                    grep -aqF 'the next is taken within 1000 seconds' "$work/pin2.log" || fail "the console did not say when the TPM takes a PIN again"
                    ! grep -aqF 'state on' "$work/pin2.log" || fail "a PIN opened the state while the TPM refused every PIN"
                    # The recovery key opens it all the same, and no console showed a PIN.
                    types pin2 "${recovery##* }"
                    hears pin2 'kithd: init: opened with the recovery key'
                    hears pin2 'kithd: init: state on /dev/dm-'
                    ! grep -aqF -e "$pin" -e 40917250 "$work/pin1.log" "$work/pin2.log" || fail "the machine's console showed a PIN as it was typed"
                    off
                    echo "vm.sh: ok: a machine with its state encrypted, told to seal its key, said why not without a TPM; with one (swtpm) it sealed the key, and started again with no node asked; started with a word of its config partition changed, then with its boot file changed, then with a command line beside the boot file's, the TPM refused the key each time, the node was asked and the key sealed anew; locked, it dropped the seal, restarted and waited until unlocked, then sealed again; the seal taken back, its disk holds none; a PIN not passed on by the other node, given at its own address (once the owner said the TPM is untried), away from its cluster it opened with that PIN, then refused $wrong wrong ones until its TPM refused every PIN, the right one too, and the recovery key opened it all the same"
                    exit 0
                fi
                api GET /v1/resources/NodeKey/kith-000902 | grep -q '"wrapped"' || fail "the cluster holds no key for the machine"
                if [ -n "$duress" ]; then
                    key() { api GET /v1/resources/NodeKey/kith-000902; }
                    comes() { # WHAT WHY: the machine's NodeKey comes to hold WHAT
                        tries=0
                        until key | grep -q "$1"; do
                            tries=$((tries + 1))
                            [ "$tries" -lt 150 ] || fail "$2: $(key)"
                            sleep 0.2
                        done
                    }
                    wrong() { # LOG TIMES: the console said so often that what was typed opens nothing
                        tries=0
                        until [ "$(grep -acF "kithd: init: that does not open this node's state" "$work/$1.log")" -ge "$2" ]; do
                            tries=$((tries + 1))
                            [ "$tries" -lt 150 ] || fail "the console answered what was typed at it fewer than $2 times"
                            sleep 0.2
                        done
                    }
                    types() { printf '%s\n' "$2" | socat - "unix-connect:$work/$1.tty" >/dev/null; }
                    # Nobody watched the install: the cluster says so, and makes no code for
                    # all of its nodes while one of them could then be opened by nobody.
                    api GET /v1/lock | grep -qF 'nobody was shown the recovery key of any node' || fail "the cluster does not warn of a recovery key nobody saw: $(api GET /v1/lock)"
                    api POST /v1/duress | grep -qF 'nobody was shown the recovery key of kith-000902' || fail "a duress code for the whole cluster was made while the machine's recovery key was never shown"
                    # A new recovery key, through the other node (which keeps none of it): the
                    # machine's record says it was shown, and the cluster warns no more.
                    new=$(api POST /v1/lock/kith-000902/recovery | field recovery) || fail "the machine made no new recovery key"
                    [ "${#new}" = 39 ] && [ "$new" != "${recovery##* }" ] || fail "what the machine answered is no new recovery key: $new"
                    comes '"recoverySeen": *true' "the cluster does not say the machine's recovery key was shown"
                    [ "$(api GET /v1/lock | field warning)" = None ] || fail "the cluster still warns once a recovery key was shown: $(api GET /v1/lock)"
                    ! api GET /v1/resources | grep -qF "$new" || fail "the new recovery key is in the store"
                    ! grep -aqF "$new" "$work/alpha.log" "$work/beta.log" || fail "a node said the new recovery key"
                    kill "$vm"
                    wait "$vm" 2>/dev/null || true
                    [ "$(says "$work/beta.disk")" = 'sealed held seen' ] || fail "the machine's disk, read from outside: $(says "$work/beta.disk")"
                    beta beta2 ''
                    up beta2
                    # Now there is a code for all. What it does to a node it was not typed at:
                    # the cluster forgets the key (written here as the forget writes it), the
                    # machine runs on, gives no key again and takes no other word but unlock.
                    all=$(api POST /v1/duress | field code) || fail "no duress code for the whole cluster was made"
                    comes '"duressAll": *true' "the machine did not take the cluster's duress code to its record"
                    id=$(key | python3 -c 'import json, sys; print(json.load(sys.stdin)["spec"]["id"], end="")')
                    printf '[{"apiVersion":"kith.dev/v1","kind":"NodeKey","metadata":{"name":"kith-000902"},"spec":{"id":"%s","forgotten":true}}]' "$id" >"$work/forgotten.json"
                    api POST /v1/apply -H 'Content-Type: application/json' --data-binary "@$work/forgotten.json" >/dev/null
                    hears beta2 'kithd: the cluster has forgotten the key of this node'
                    sleep 5
                    ! key | grep -q '"wrapped"' || fail "the machine gave the cluster the key it had forgotten"
                    ! grep -aqF 'restarting' "$work/beta2.log" || fail "a machine whose key was forgotten did not run on"
                    lock lock | grep -qF 'has forgotten' || fail "a machine whose key was forgotten could be locked"
                    lock unlock | grep -q '"locked": *false' || fail "the cluster could not be told to hold the machine's key again"
                    comes '"wrapped"' "the machine did not give its key again once it was unlocked"
                    ! api GET /v1/resources | grep -qF "$all" || fail "the cluster's duress code is in the store"
                    # A code of its own; then locked, so that it waits at its console with the
                    # cluster in reach.
                    code=$(lock duress | field code) || fail "no duress code was made for the machine"
                    [ "${#code}" = 39 ] || fail "what was made is no duress code: $code"
                    comes '"duress": *true' "the machine did not take its duress code to its record"
                    ! api GET /v1/resources | grep -qF "$code" || fail "the duress code is in the store"
                    ! grep -aqF "$code" "$work/alpha.log" "$work/beta2.log" || fail "a node said the duress code"
                    lock lock | grep -q '"locked": *true' || fail "the machine could not be locked"
                    hears beta2 'kithd: the cluster has locked this node'
                    wait "$vm" || true
                    [ "$(says "$work/beta.disk")" = 'sealed held seen duress' ] || fail "the disk of the machine with a duress code, read from outside: $(says "$work/beta.disk")"
                    beta beta3 ''
                    hears beta3 'still locked: 10.9.0.1:7443 does not hand this node'
                    # A key that is none, and the key the installer showed (it opens no more).
                    types beta3 0000-0000-0000-0000-0000-0000-0000-0000
                    wrong beta3 1
                    types beta3 "${recovery##* }"
                    wrong beta3 2
                    # The duress code: answered as those were, and nothing else is said of it
                    # on the machine; the other node forgets its key, and says so.
                    types beta3 "$code"
                    wrong beta3 3
                    hears alpha 'kithd: a duress code was typed: forgetting NodeKey/kith-000902'
                    comes '"wiped": *true' "the cluster did not forget the key of the machine a duress code was typed at"
                    ! key | grep -q '"wrapped"' || fail "the cluster still has the key of the machine a duress code was typed at"
                    # Its recovery key, which opened it a moment ago, opens nothing now.
                    types beta3 "$new"
                    wrong beta3 4
                    sleep 3
                    ! grep -aqF 'state on' "$work/beta3.log" || fail "the machine opened its state after its duress code was typed"
                    [ "$(grep -acF "kithd: init: that does not open this node's state" "$work/beta3.log")" = 4 ] || fail "the console said something else of one of the four lines typed at it"
                    ! grep -aiE 'kithd: .*(duress|eras|forg)' "$work/beta3.log" || fail "the machine's console says a duress code was typed"
                    lock unlock | grep -qF 'was wiped' || fail "a machine whose duress code was typed could be unlocked"
                    # Nor does an earlier version of its NodeKey, which has the key, come back.
                    api POST '/v1/rollback/NodeKey/kith-000902?to=1' | grep -qF 'a NodeKey is not rolled back' || fail "a forgotten NodeKey could be rolled back"
                    ! key | grep -q '"wrapped"' || fail "the cluster has the key again of the machine a duress code was typed at"
                    kill "$vm"
                    wait "$vm" 2>/dev/null || true
                    [ "$(says "$work/beta.disk")" = 'sealed none' ] || fail "the disk of the machine its duress code was typed at, read from outside: $(says "$work/beta.disk")"
                    beta beta4 ''
                    hears beta4 'the state partition is damaged'
                    echo "vm.sh: ok: a machine installed with its state encrypted and nobody watching: the cluster warned that nobody saw a recovery key and made no duress code for all; the machine made a new recovery key, shown once, and the warning went; its key forgotten as the cluster's code forgets it, it ran on, gave no key and was held again once unlocked; given a duress code of its own and locked, it waited: a wrong key, the installer's old recovery key and the duress code were each answered with the same line; the code erased its lock record and had the other node forget its key, the new recovery key opened nothing after, and its disk opens for nobody"
                    exit 0
                fi
                kill "$vm"
                wait "$vm" 2>/dev/null || true
                [ "$(says "$work/beta.disk")" = 'sealed held' ] || fail "the machine's disk, read from outside: $(says "$work/beta.disk")"
                # Started again, it asks the node for its key. Locked, it restarts and waits.
                beta beta2 ''
                hears beta2 'asking the cluster for its key'
                up beta2
                lock lock | grep -q '"locked": *true' || fail "the machine could not be locked"
                hears beta2 'kithd: the cluster has locked this node'
                wait "$vm" || true
                beta beta3 ''
                hears beta3 'still locked: 10.9.0.1:7443 does not hand this node'
                ! grep -aqF 'state on' "$work/beta3.log" || fail "a locked machine opened its state"
                lock unlock | grep -q '"locked": *false' || fail "the machine could not be unlocked"
                up beta3
                # Its key deleted from the store: the running machine gives it again, and has not restarted.
                api DELETE /v1/resources/NodeKey/kith-000902 >/dev/null
                tries=0
                until api GET /v1/resources/NodeKey/kith-000902 | grep -q '"wrapped"'; do
                    tries=$((tries + 1))
                    [ "$tries" -lt 150 ] || fail "the machine did not give its key again once it was deleted"
                    sleep 0.2
                done
                echo "vm.sh: the machine gave its key again after $tries tries of 0.2 s"
                ! grep -aqF 'has locked this node' "$work/beta3.log" || fail "the unlocked machine restarted as if locked"
                # A passphrase, given through the other node (which keeps none of it): too short
                # a one is refused; taken away, the disk has no line of it; given again, it has.
                pass() { api POST /v1/lock/kith-000902/passphrase -H 'Content-Type: application/json' -d "$1"; }
                passes() { # WHETHER: the NodeKey's status comes to say so
                    tries=0
                    until [ "$(api GET /v1/resources/NodeKey/kith-000902 | grep -c '"passphrase": *true')" = "$1" ]; do
                        tries=$((tries + 1))
                        [ "$tries" -lt 100 ] || fail "the cluster does not say whether the machine has a passphrase (expected $1)"
                        sleep 0.2
                    done
                }
                pass '{"passphrase":"short"}' | grep -qF 'characters or more' || fail "a passphrase of five characters was taken"
                pass '{"passphrase":"pässwörter und mehr"}' | grep -qF 'signs of ASCII' || fail "a passphrase the console of a starting machine cannot type was taken"
                pass '{"passphrase":"correct horse battery"}' | grep -q '"passphrase": *true' || fail "the machine was given no passphrase"
                passes 1
                pass '{}' | grep -q '"passphrase": *false' || fail "the machine's passphrase was not taken away"
                passes 0
                pass '{"passphrase":"correct horse battery"}' | grep -q '"passphrase": *true' || fail "the machine was given no passphrase a second time"
                passes 1
                ! api GET /v1/resources | grep -qF 'correct horse' || fail "the passphrase is in the store"
                ! grep -aqF 'correct horse' "$work/alpha.log" "$work/beta3.log" || fail "a node said the passphrase"
                kill "$vm"
                wait "$vm" 2>/dev/null || true
                [ "$(says "$work/beta.disk")" = 'sealed held passphrase' ] || fail "the disk of the machine with a passphrase, read from outside: $(says "$work/beta.disk")"
                ! grep -aqF 'correct horse' "$work/beta.disk" || fail "the passphrase is on the machine's disk as it was typed"
                # Away from its cluster (started without its card): no node answers, and it opens
                # its state once the passphrase is typed at it, not before and not for another.
                vm away -m 1024 -drive "file=$work/beta.disk,format=raw,if=none,id=d" -device virtio-blk-pci,drive=d,bootindex=0
                hears away 'Or type its passphrase, or the recovery key'
                hears away 'still locked'
                printf 'correct horse batterz\n' | socat - "unix-connect:$work/away.tty" >/dev/null
                hears away "kithd: init: that does not open this node's state"
                ! grep -aqF 'state on' "$work/away.log" || fail "a machine away from its cluster opened its state without its passphrase"
                printf 'correct horse battery\n' | socat - "unix-connect:$work/away.tty" >/dev/null
                hears away 'kithd: init: opened with its passphrase'
                hears away 'kithd: init: state on /dev/dm-'
                ! grep -aqF 'correct horse' "$work/away.log" || fail "the machine's console showed the passphrase as it was typed"
                kill "$vm"
                wait "$vm" 2>/dev/null || true
                beta home ''
                up home
                # Locked again: it drops its passphrase, and the recovery key, typed at the
                # machine, opens it all the same.
                lock lock >/dev/null
                hears home 'its passphrase no longer opens its state'
                hears home 'kithd: the cluster has locked this node: restarting'
                wait "$vm" || true
                beta beta4 ''
                hears beta4 'Or type the recovery key here'
                hears beta4 'still locked'
                printf 'correct horse battery\n' | socat - "unix-connect:$work/beta4.tty" >/dev/null
                hears beta4 "kithd: init: that does not open this node's state"
                ! grep -aqF 'state on' "$work/beta4.log" || fail "a locked machine opened its state with the passphrase it had"
                printf '%s\n' "${recovery##* }" | socat - "unix-connect:$work/beta4.tty" >/dev/null
                hears beta4 'kithd: init: opened with the recovery key'
                up beta4
                pass '{"passphrase":"correct horse battery"}' | grep -qF 'unlock it first' || fail "a locked machine was given a passphrase"
                pass '{}' | grep -q '"passphrase": *false' || fail "a locked machine could not have its passphrase taken away"
                # Wiped: the cluster forgets the key, the machine erases its record and ends;
                # what is left on its disk opens for nobody.
                lock wipe | grep -q '"wiped": *true' || fail "the machine could not be wiped"
                hears beta4 'kithd: the cluster has wiped this node'
                wait "$vm" || true
                [ "$(says "$work/beta.disk")" = 'sealed none' ] || fail "the wiped machine's disk, read from outside: $(says "$work/beta.disk")"
                lock unlock | grep -qF 'was wiped' || fail "a wiped machine could be unlocked"
                beta beta5 ''
                hears beta5 'the state partition is damaged'
                echo "vm.sh: ok: a machine installed with its state encrypted joined, and the node took its key to hold: the disk read from outside shows no file system and no key; started again it asked the node for its key; locked, it restarted and waited until unlocked; given a passphrase (through the node, which kept none of it) and started without its card, it opened its state once the passphrase was typed at it, and not for another; locked again, it dropped the passphrase, and the recovery key typed at it opened it; wiped, it erased its record and its disk opens for nobody"
                exit 0
            fi
            echo "vm.sh: ok: a node told to install the machine with card $mac answered its network boot (beside the network's own DHCP server), served it the installer once over TFTP; the machine installed on its only disk, started from it and joined the node's cluster; netboot off again"
            exit 0
        fi

        # A machine with no disk but the installer's own: nothing to install on, and said.
        printf 'disk: only\nhostname: alpha\nip: 10.9.0.1/24\n' >"$work/alpha.yaml"
        stick alpha "$work/alpha.yaml"
        # shellcheck disable=SC2046
        vm nodisk $(drive alpha.stick)
        hears nodisk 'kithd: install: nothing was installed: this machine has no disk to install on'
        kill "$vm"

        # Answers on the stick: the only disk, a name, a fixed address, a new cluster.
        blank alpha
        # shellcheck disable=SC2046
        vm install-alpha $(drive alpha.stick) $(drive alpha.disk)
        installed install-alpha vdb
        # shellcheck disable=SC2046
        vm alpha $(drive alpha.disk) $(lan 1)
        hears alpha 'kithd: init: alpha is up'
        hears alpha 'has 10.9.0.1/24'
        hears alpha 'kithd: node alpha serving other nodes on 0.0.0.0:7443'
        hears alpha 'sends this token to /v1/claim does: kith1.'
        token=$(grep -ao 'sends this token to /v1/claim does: kith1\.[0-9a-f.]*' "$work/alpha.log")
        tries=0
        until claimed=$(curl -sfk --max-time 10 -H 'Content-Type: application/json' -d "{\"token\":\"${token##* }\",\"name\":\"root\"}" "https://127.0.0.1:$((port + 1))/v1/claim"); do
            tries=$((tries + 1))
            [ "$tries" -lt 50 ] || fail "the installed node's cluster could not be claimed"
            sleep 0.2
        done
        field() { python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]], end="")' "$1"; }
        for part in ca cert key; do
            printf '%s' "$claimed" | (umask 077 && field "$part" >"$work/$part.pem") || fail "the claim was refused: $claimed"
        done
        api() { # METHOD PATH: as the cluster's admin, to alpha
            curl -sf --max-time 10 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
                --resolve "kith:$((port + 1)):127.0.0.1" -X "$1" "https://kith:$((port + 1))$2"
        }
        join=$(api POST /v1/tokens | field token) || fail "no join token over TLS"

        # Answers from a URL: the disk by name where there are two, and the network asked
        # for an address. The other disk is not touched.
        mkdir "$work/www"
        printf 'disk: vdc\nhostname: beta\n' >"$work/www/beta.yaml"
        (cd "$work/www" && exec python3 -m http.server --bind 127.0.0.1 $((port + 9))) >/dev/null 2>&1 &
        web=$!
        stick beta
        blank beta
        blank spare
        # shellcheck disable=SC2046
        vm install-beta $(drive beta.stick) $(drive spare.disk) $(drive beta.disk) -netdev user,id=out -device virtio-net-pci,netdev=out \
            -smbios "type=11,value=io.systemd.stub.kernel-cmdline-extra=kith.install=http://10.0.2.2:$((port + 9))/beta.yaml"
        installed install-beta vdc
        cmp -s -n $((64 << 20)) "$work/spare.disk" /dev/zero || fail "the disk that was not chosen was written to"
        beta() { # LOG: the installed disk, started
            # shellcheck disable=SC2046
            vm "$1" $(drive beta.disk) -netdev "user,id=out,hostfwd=tcp:127.0.0.1:$((port + 5))-:7443" -device virtio-net-pci,netdev=out
            hears "$1" 'kithd: init: beta is up'
            hears "$1" 'kithd: node beta serving other nodes on 0.0.0.0:7443'
            print $((port + 5))
        }
        beta beta
        first=$who
        kill "$vm"
        wait "$vm" 2>/dev/null || true
        beta beta-again
        [ "$first" = "$who" ] || fail "the installed node is another node after a restart: its state was not kept"
        kill "$vm"

        # Answers typed at the console: a slip first (the disk's name not typed the same
        # twice, so nothing is written), then a node that joins alpha's cluster by token.
        stick gamma
        blank gamma
        # shellcheck disable=SC2046
        vm install-gamma $(drive gamma.stick) $(drive gamma.disk)
        typed() { # WAIT-FOR LINE
            hears install-gamma "$1"
            printf '%s\n' "$2" | socat - "unix-connect:$work/install-gamma.tty" >/dev/null
        }
        typed 'Install kith OS on which' vdb
        typed "The node's name" gamma
        typed 'Its address, as' ''
        typed 'Join a cluster?' ''
        typed 'Keep its state encrypted' ''
        typed 'will be erased. Type its name again' vda
        hears install-gamma 'kithd: install: `vda` is not `vdb`: nothing was written'
        cmp -s -n $((64 << 20)) "$work/gamma.disk" /dev/zero || fail "a disk was written to before its name was typed twice"
        hears install-gamma 'kithd: install: once more.'
        for line in vdb gamma 10.9.0.3/24 10.9.0.1:7443 "$join" '' vdb; do
            printf '%s\n' "$line" | socat - "unix-connect:$work/install-gamma.tty" >/dev/null
            sleep 0.3
        done
        installed install-gamma vdb
        # shellcheck disable=SC2046
        vm gamma $(drive gamma.disk) $(lan 3)
        hears gamma 'kithd: init: gamma is up'
        tries=0
        until api GET /v1/resources/Node/gamma >/dev/null; do
            tries=$((tries + 1))
            [ "$tries" -lt 150 ] || fail "the node installed with a join token is not in alpha's cluster"
            sleep 0.2
        done
        echo "vm.sh: ok: no disk, nothing installed; from answers on the stick, a node (alpha) that starts a cluster at its fixed address; from a URL, onto the disk named of two, a node (beta, $first) that asks its network and keeps its state; from the console, after a slip that wrote nothing, a node (gamma) that joined alpha's cluster by token"
        exit 0
    fi
    # A copy: the node writes its state to the disk, and this test damages its root.
    cp "$root/target/os/kith-os.raw" "$work/disk.raw"
    port=$((20000 + $$ % 20000))
    # (The stub adds $more to the command line of the image: here, kithd's own arguments.)
    serve='-- --listen 0.0.0.0:7443 --advertise 10.0.2.15:7443'
    more=$serve once=1
    boot() { # [more of QEMU's arguments]: $once empty lets the guest restart itself
        : >"$work/log"
        timeout "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -display none ${once:+-no-reboot} \
            -machine q35 -bios "$firmware" -drive "file=$work/disk.raw,format=raw,if=virtio" \
            -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$port-:7443" -device virtio-net-pci,netdev=n0 \
            -smbios "type=11,value=io.systemd.stub.kernel-cmdline-extra=$more" "$@" \
            -serial "file:$work/log" -monitor "unix:$work/keys,server,nowait" </dev/null >/dev/null 2>&1 &
        vm=$!
    }
    heard() { # TEXT: wait for the guest to say it
        until said "$1"; do
            kill -0 "$vm" 2>/dev/null || fail "the VM ended before it said: $1"
            sleep 0.05
        done
    }
    up() { heard 'serving other nodes on '; }
    # Who answers on the node's port, through the VM's network card: its certificate,
    # into $who.
    who() {
        tries=0
        until openssl s_client -connect "127.0.0.1:$port" </dev/null 2>/dev/null >"$work/hello" \
            && who=$(openssl x509 -noout -fingerprint -sha256 <"$work/hello" 2>/dev/null); do
            tries=$((tries + 1))
            [ "$tries" -lt 100 ] || fail "nobody answered TLS on the node's port"
            sleep 0.2
        done
    }
    restart() {
        echo sendkey ctrl-alt-delete | socat - "unix-connect:$work/keys" >/dev/null
        wait "$vm" || fail "the VM did not end within ${time} s of starting"
        said 'reboot: Restarting system' || fail "kithd did not restart the machine when told"
        ! said 'Kernel panic' || fail "the kernel panicked"
        resident=$(grep -ao 'told to stop: [0-9]* kB resident, [0-9]* kB of it files' "$work/log" | tail -n 1)
    }

    if [ "$test" = update ]; then
        [ "$time" -gt 60 ] || time=180
        # Three updates: a release, the same with its end damaged on the way, and a
        # release whose root is not the one its verity tree was made for.
        # (The release is an older version than the image's: the node must start it all
        # the same, since the newest written is what was asked for.)
        KITH_OS_VERSION=0.0.0-test sh "$root/os/build.sh" --out "$work/next" >&2
        cp "$work/next/kith-os.update" "$work/good.update"
        cp "$work/good.update" "$work/damaged.update"
        printf 'kith-test-damage' | dd of="$work/damaged.update" bs=1 seek=$(($(stat -c %s "$work/good.update") - 16)) conv=notrunc status=none
        cp "$work/next/root.squashfs" "$work/broken.root"
        dd if=/dev/urandom of="$work/broken.root" bs=4096 count=8 conv=notrunc status=none
        sh "$root/os/update.sh" 0.0.0-broken "$(sha256sum "$work/broken.root" | cut -d ' ' -f 1)" "$work/broken.root" \
            "$work/next/root.verity" "$work/next/kith-a.efi" "$work/next/kith-b.efi" >"$work/broken.update"
        # (A disk is whole sectors; kithd reads as much as the header says.)
        truncate -s %1M "$work/good.update" "$work/damaged.update" "$work/broken.update"
        given() { boot -drive "file=$work/$1.update,format=raw,if=virtio,readonly=on"; }
        slot() { [ "$(grep -ac "Kernel command line:.*kith.slot=$1" "$work/log")" = "$2" ] || fail "expected $2 start(s) of slot $1"; }

        more="kith.update=vdb $serve"
        given damaged
        up
        said 'kithd: init: no update from vdb: the update is damaged' || fail "a damaged update was not refused"
        slot a 1
        who
        first=$who
        restart

        given good
        wait "$vm" || fail "the VM did not end within ${time} s of starting"
        said 'kithd: init: kith OS 0.0.0-test from vdb is in the other slot' || fail "the update was not written"
        cat "$work/log"

        more=$serve
        boot
        up
        slot b 1
        who
        [ "$first" = "$who" ] || fail "the updated node is another node: its state did not survive ($first, then $who)"
        heard 'kithd: init: slot b is good'
        restart
        cat "$work/log"

        # A release that cannot start: slot a is tried three times, then b again.
        more="kith.update=vdb $serve"
        given broken
        wait "$vm" || fail "the VM did not end within ${time} s of starting"
        said 'kithd: init: kith OS 0.0.0-broken from vdb is in the other slot' || fail "the broken release was not written"
        more=$serve once=''
        boot
        heard 'kithd: init: slot a did not come up in 3 tries: this is slot b'
        cat "$work/log"
        slot a 3
        slot b 1
        who
        [ "$first" = "$who" ] || fail "after going back the node is another node ($first, then $who)"
        kill "$vm"
        echo "vm.sh: ok: a damaged update refused; an update written into slot b, started, marked good, the same node ($first); a release that cannot start tried three times, then slot b again"
        exit 0
    fi

    # (The disk is longer than the image written to it, as a real one is: 40 GB, of which
    # the file holds what is written. Past 32 GB an ext4 as small as the image's has used
    # up the room it kept for growing and the kernel has to lay its groups out anew.)
    truncate -s 40G "$work/disk.raw"
    began=$(date +%s%N)
    boot
    up
    took=$((($(date +%s%N) - began) / 1000000))
    said 'Mounted root (squashfs filesystem) readonly on device 25[0-9]:0' || fail "the root is not the verity device"
    said 'kithd: init: state on /dev/vda7' || fail "the state partition was not mounted"
    # The state partition is the image's 32 MB no longer: it ends where the disk does, the
    # file system fills it, and a tool that reads partition tables finds nothing to say.
    said 'kithd: init: the state partition now ends where its disk does: 407[0-9][0-9] MB' || fail "the state partition was not made to end where its disk does"
    said "kithd: init: the state's file system grown to 407[0-9][0-9] MB" || fail "the state's file system was not grown to its partition"
    who
    first=$who
    said 'by DHCP' || fail "the network card got no address by DHCP"
    restart
    cp "$work/log" "$work/log.first"
    table=$(sfdisk -l "$work/disk.raw" 2>&1)
    case $table in *mismatch* | *corrupt* | *'not on the end'* | *rror*) fail "the partition table kith OS wrote is not right: $table" ;; esac
    [ "$(sfdisk -l -o Name,Sectors "$work/disk.raw" | awk '$1 == "state" { print int($2 / 2048 / 100) }')" = 407 ] || fail "the table does not say the state partition is longer: $table"

    boot
    up
    said 'kithd: init: state on /dev/vda7' || fail "the state partition was not mounted the second time"
    ! said 'now ends where its disk does' || fail "the state partition was changed again at the second start"
    ! said 'file system grown' || fail "the state's file system was grown again at the second start"
    who
    second=$who
    restart
    [ "$first" = "$second" ] || fail "the node came back as another: its state did not survive ($first, then $second)"

    # One block of the root changed: the kernel must refuse it, and kithd never run.
    start=$(sfdisk -l -o Start,Name "$work/disk.raw" | awk '$2 == "root-a" { print $1 }')
    dd if=/dev/urandom of="$work/disk.raw" bs=512 seek="$start" count=8 conv=notrunc status=none
    boot
    wait "$vm" || true
    cat "$work/log.first"
    ! said 'kithd: ' || fail "kithd ran from a root that was tampered with"
    said 'device-mapper: verity: .* is corrupted' || fail "the kernel did not say the root was corrupted"
    echo "vm.sh: the image served other nodes ${took} ms after QEMU started (firmware, boot loader and kernel included)"
    # (Of the second start, from the image's own root: read from the disk, as a node's is.)
    [ -n "$resident" ] || fail "kithd did not say what it held in memory when told to stop"
    echo "vm.sh: kithd as the first process of kith OS, ${resident#told to stop: }"
    [ "$took" -lt 10000 ] || { echo "vm.sh: FAIL: over 10 s" >&2; exit 1; }
    echo "vm.sh: ok: UEFI boot from the image, a verity root, DHCP, TLS answered ($first), on a disk longer than the image a state partition that ends where the disk does from the first start and is left alone at the second, state kept across a restart, a tampered root refused"
    exit 0
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
