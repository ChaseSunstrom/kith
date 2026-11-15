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
#   sh ci/vm.sh --test share    two nodes: a shared volume of one, mounted by a container on the other;
#                               an encrypted volume of one, its key kept by the other
#   sh ci/vm.sh --test pods     two nodes: pods with a network, an address and a root each to write to,
#                               found by their Service's name and reaching out from behind their node
#   sh ci/vm.sh --test services one node: every byte through a Service to a pod on the same node comes
#                               back in order, however its connection ends, passed by kithd from a pod
#                               and by the kernel from the node's own network
#   sh ci/vm.sh --test kube     two nodes: the real kubectl and helm against them, with manifests written
#                               for Kubernetes; what they make runs, rolls out, keeps its data and is waited for
#   sh ci/vm.sh --test worker   two nodes, one a worker: it runs what is placed on it with its Secret, its
#                               disk never has another's, and what it does with no control node in reach
#   sh ci/vm.sh --test chaos    three nodes taking writes: each in turn cut off from the others, each
#                               in turn losing power, then all at once; what was acknowledged is on all three
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
                   over TLS; a release with another file's signature (refused), a signed
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
                   of their own; a pod of a user who is not root finds their Service
                   by its short name and its Kubernetes one, hears all three through
                   it, reaches this machine from behind its node's address, and
                   writes to /dev/stdout by name; a pod that is root is kept from a
                   device it was not given (its node's disk); a container that asks for user
                   namespaces starts a sandbox in it (this machine's bwrap), one that
                   does not is refused, one that is root is not started; a USB keyboard
                   plugged in is given to the container holding the seat as it runs;
                   an app that is a client of the seat reaches the socket its session
                   listens on and cannot write beside it, and another user's cannot;
                   needs rustc for x86_64-unknown-linux-musl, bwrap and socat. With
                   KITH_E2E=1 also three pods of
                   nginx as it is shipped, pulled from mirror.gcr.io
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
  --help           this text

Without --initrd it builds kithd for x86_64-unknown-linux-musl (with zig as the C
compiler when there is no musl-gcc, as ci/budgets.py does) and needs cpio and zstd.
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
case $test in '' | init | image | update | rollout | install | vps | netboot | crypt | tpm | share | pods | services | kube | worker | chaos) ;; *) echo "vm.sh: --test knows: init, image, update, rollout, install, vps, netboot, crypt, tpm, share, pods, services, kube, worker, chaos" >&2; exit 2 ;; esac
# (From here on the TPM test is the encrypted one, with its own end.)
sealing=''
[ "$test" != tpm ] || test=crypt sealing=1
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
# (What a test left running goes with it.)
trap 'kill $vms $web 2>/dev/null || true; rm -rf "$work"' EXIT INT TERM
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
    if [ "$test" = rollout ] || [ "$test" = share ] || [ "$test" = pods ] || [ "$test" = services ] || [ "$test" = kube ] || [ "$test" = worker ] || [ "$test" = chaos ]; then
        for tool in curl python3 xxd; do
            command -v "$tool" >/dev/null 2>&1 || skip "no $tool"
        done
        kubectl=${KITH_KUBECTL:-$(command -v kubectl || true)}
        helms=$(printf '%s' "${KITH_HELM:-$(command -v helm || true)}" | tr ':' ' ')
        [ "$test" != kube ] || [ -x "$kubectl" ] || skip "no kubectl (KITH_KUBECTL names one; sh ci/kube.sh --vm fetches one)"
        if [ "$test" = pods ]; then
            command -v socat >/dev/null 2>&1 || skip "no socat to plug a keyboard in with"
            bwrap=$(command -v bwrap) || skip "no bwrap (bubblewrap) to start a sandbox inside a container with"
        fi
        [ "$time" -gt 60 ] || time=900
        [ "$test" != kube ] || time=$((time * 2))
        port=$((20000 + $$ % 20000))
        fail() { tail -n 30 "$work"/n?.log; echo "vm.sh: FAIL: $1" >&2; exit 1; }
        cargo build -q --manifest-path "$root/Cargo.toml" -p kith-cli >&2
        # (rollout and chaos: three nodes and nothing more said to kithd; share, pods, kube and
        # worker: two, on the mesh; services: one, on the mesh.)
        others='2 3' more='' inside=2049
        seed() { :; }
      if [ "$test" = share ] || [ "$test" = pods ] || [ "$test" = services ] || [ "$test" = kube ] || [ "$test" = worker ]; then
        others=2 more=--mesh
        [ "$test" != services ] || others=''
        # (worker: this machine asks what listens on port 80 of a node's own network.)
        [ "$test" != worker ] || inside=80
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
                if [ "$test" != share ]; then
                    # And what those tests' pods run (ci/pod.rs), as an image that names no
                    # user, as one that names a user who is not root, and as two that say
                    # what to start (an image nothing more is said of, as a chart has one).
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
                fi
                if [ "$test" = pods ]; then
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
                fi
                sfdisk -l -o Start,Sectors,Name "$1" | awk '$3 == "state" { print $1, $2 }' >"$work/state.at"
                read -r state_start state_sectors <"$work/state.at"
                mkfs.ext4 -q -d "$work/seed" -E root_owner=0:0 "$work/state.img" "$((state_sectors / 2))k" >&2
            fi
            read -r state_start state_sectors <"$work/state.at"
            dd if="$work/state.img" of="$1" bs=512 seek="$state_start" conv=notrunc status=none
            # (Room for an image that is pulled: the state grows to the disk's end at the first start.)
            case $test${KITH_E2E:-} in pods1 | kube1) truncate -s 2G "$1" ;; esac
        }
      elif [ "$test" = rollout ]; then
        # Two releases, both signed: one that runs, and one whose root is not the one its
        # verity tree was made for. The nodes fetch them from this machine.
        KITH_OS_VERSION=9.0.0-next sh "$root/os/build.sh" --out "$work/next" >&2
        mkdir "$work/www"
        cp "$work/next/kith-os.update" "$work/www/next.update"
        cp "$work/next/root.squashfs" "$work/broken.root"
        dd if=/dev/urandom of="$work/broken.root" bs=4096 count=8 conv=notrunc status=none
        sh "$root/os/update.sh" 9.0.0-broken "$(sha256sum "$work/broken.root" | cut -d ' ' -f 1)" "$work/broken.root" \
            "$work/next/root.verity" "$work/next/kith-a.efi" "$work/next/kith-b.efi" >"$work/www/broken.update"
        public=$("$root/target/debug/kith" package keygen "$work/key")
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
            [ -f "$work/n$1.raw" ] || { cp "$root/target/os/kith-os.raw" "$work/n$1.raw" && seed "$work/n$1.raw"; }
            timeout "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -display none \
                -machine q35 -bios "$firmware" -drive "file=$work/n$1.raw,format=raw,if=virtio" -device qemu-xhci,id=usb \
                -netdev "socket,id=lan,mcast=230.0.0.1:$((port + 8)),localaddr=127.0.0.1" -device "virtio-net-pci,netdev=lan,mac=52:54:00:00:09:0$1" \
                -netdev "user,id=out,hostfwd=tcp:127.0.0.1:$((port + $1))-:7443,hostfwd=tcp:127.0.0.1:$((port + 4 + $1))-:$inside" -device "virtio-net-pci,netdev=out,mac=52:54:00:00:0a:0$1" \
                -smbios "type=11,value=io.systemd.stub.kernel-cmdline-extra=kith.hostname=n$1 kith.ip=10.9.0.$1/24 -- --listen 0.0.0.0:7443 --advertise 10.9.0.$1:7443 $more ${2:-}" \
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
        node 1 --claim
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
            node "$n" "--join 10.9.0.1:7443 --token $join"
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
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: two nodes, one let in as a worker: its Node says it is sent a view; a Workload placed on it ran with its Secret; its disk has that Secret and never had the Secret of what runs on the control node; its API answered no person; with the control node paused it said so and ran on; started again meanwhile it ran nothing until the control node was back, then what it ran; a deleted Workload left it"
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
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node, a pod that sent back what it was sent and its Service; Jobs on the same node, one in a pod (passed by kithd) and one on the node's own network (passed by the kernel straight to the replica), sent through the Service on connections closed at once, half closed, reset by either end with bytes on their way, side by side and kept for small turns, and every byte came back in order ($checked)"
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
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$name"},"spec":{"retries":0,"template":{"pod":true,"containers":[
  {"name":"ask","image":"kith.test/pod:user","command":["/bin/pod","ask"$(printf ',"%s"' "$@")]}]}}}]
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
            # What holds a container to its devices: a pod that is root may make device nodes,
            # and makes /dev/null again and reads it; its node's own disk it may neither make
            # nor read. (NAME, block or character, and where /sys has the device's numbers.)
            makes() { job "$1" '"pod":true,' "\"image\":\"kith.test/pod:1\",\"command\":[\"/bin/pod\",\"node\",\"$2\",\"$3\",\"/dev/made\"]" '^[0-9]+ succeeded'; }
            makes null c /sys/class/mem/null/dev
            grep -q 'node: made 0, read Ok(0)' "$work/null.out" || fail "a pod that is root could not make /dev/null again and read it: $(cat "$work/null.out" "$work/null.err")"
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

            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: two nodes on the mesh and three pods of one Workload on them, each with an address of its own on the mesh, each listening on port 80 as root and writing to its root; a pod of a user who is not root found their Service by its short name and by its Kubernetes one at the node's DNS, was answered by all three through it, reached this machine from behind its node's address, and wrote what it heard to /dev/stdout by name; $stock; a pod that is root made /dev/null again and read it, and could neither make nor read its node's disk; a container that asked for user namespaces started a sandbox of its own in it (bubblewrap: a user namespace, with a /proc and a /dev made in it), one that did not ask started none, and one that is the node's root was not started; a keyboard plugged in while a container held the seat was one more node it could open, and gone from it when pulled, with nothing started again; an app that was a client of the seat was answered on the socket the seat's session listened on in the seat's directory and could make no file there, and one of another user was not let in"
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
                grep -q "/data/$2: File exists" "$work/$1.err" || fail "the Job $1 did not fail for /data/$2 being there: $(cat "$work/$1.err")"
            }
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"data"},"spec":{"node":"n1","path":"all","shared":true}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on1"},"spec":{"node":"n1","path":"own"}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on2"},"spec":{"node":"n2","path":"own"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the volumes were not applied"

            # Written on the second node, through the first node's volume; there on the first.
            run write on2 from-n2
            until_job write succeeded
            grep -aq 'kithd: mounted volume default/data from node n1' "$work/n2.log" || fail "the second node did not say it mounted the volume"
            grep -aq 'kithd: serving 1 shared volume' "$work/n1.log" || fail "the first node did not say it serves the volume"
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
            until grep -aq 'kithd: serving 1 shared volume.*; 2 Share(s) to the addresses they name' "$work/n1.log"; do
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
            echo "vm.sh: ok: two nodes on the mesh; a file made in a shared volume by a container on the node that does not hold it was there for one on the node that does, and the other way round; nothing answered NFS from outside the mesh until a Share named this machine, which then made a directory in the Share's volume, could not write a read-only Share, and saw nothing else; an encrypted volume was made on the second node with its key kept by the first, its file system not to be seen on the node's disk, closed when the node was told to restart and opened again with the key the first node handed back, what was written in it still there"
            exit 0
        fi
        until_says "three nodes, each saying what it runs" "^- 0 [^,? ]+,[^,? ]+,[^,? ]+ "
        was=${line#- 0 } was=${was%% *}
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
        echo "vm.sh: ok: three nodes, claimed and joined over TLS; a forged release refused; a signed one taken by all three, one at a time, as one cluster, and with it the key it handed over to; a release under their floor and one by the key left out refused; one that cannot start, signed by the new key, tried by one node, which came back, and the plan paused: $line"
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
print(state, "none" if not record.startswith(b"kith-lock v1\n") else "key" if b"\nkey: " in record else "held", *["tpm"] * (b"\ntpm: " in record), *["passphrase"] * (b"\npassphrase: " in record))' "$1"
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
                    own() { # LOG [more of QEMU's arguments]: the machine from its disk, with its TPM (the same at every start: its state is kept)
                        machine=$1
                        shift
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
                        vm "$machine" -m 1024 -drive "file=$work/beta.disk,format=raw,if=none,id=d" -device virtio-blk-pci,drive=d,bootindex=0 \
                            -netdev "socket,id=n,connect=127.0.0.1:$((port + 8))" -device "virtio-net-pci,netdev=n,mac=$mac" \
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
                    [ "$(says "$work/beta.disk")" = 'sealed held tpm' ] || fail "the sealed machine's disk, read from outside: $(says "$work/beta.disk")"
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
                    echo "vm.sh: ok: a machine with its state encrypted, told to seal its key, said why not without a TPM; with one (swtpm) it sealed the key, and started again with no node asked; started with a word of its config partition changed, then with its boot file changed, then with a command line beside the boot file's, the TPM refused the key each time, the node was asked and the key sealed anew; locked, it dropped the seal, restarted and waited until unlocked, then sealed again; the seal taken back, its disk holds none"
                    exit 0
                fi
                api GET /v1/resources/NodeKey/kith-000902 | grep -q '"wrapped"' || fail "the cluster holds no key for the machine"
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
                sleep 5
                api GET /v1/resources/NodeKey/kith-000902 | grep -q '"wrapped"' || fail "the machine did not give its key again once it was deleted"
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
                hears away "that is not this node's recovery key, nor its passphrase"
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
                hears beta4 "that is not this node's recovery key"
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
