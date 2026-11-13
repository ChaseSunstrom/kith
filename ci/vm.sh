#!/bin/sh
# Boot a kernel in QEMU and print what it said: by default the host's kernel with the
# static kithd as init (so, the kernel and kithd, nothing else). Phase 5's image,
# installer and update tests reuse it with their own kernel, initramfs and disk image.
#
#   sh ci/vm.sh [--kernel FILE] [--initrd FILE] [--disk IMAGE] [--append ARGS] [--time SECONDS]
#   sh ci/vm.sh --test init     kithd as the first process: up, serving, restarts when told
#   sh ci/vm.sh --test image    kith OS's disk image (os/build.sh), booted under UEFI
#   sh ci/vm.sh --test update   that image updating itself, and going back when it must
#   sh ci/vm.sh --test rollout  three nodes of it taking a release, one at a time
#   sh ci/vm.sh --test install  the installer, onto virtual disks, and what it installed
#   sh ci/vm.sh --test vps      the installer started from memory, as os/vps.sh starts it
#   sh ci/vm.sh --test netboot  a node installing a machine that starts from the network
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
                   and expect kithd to stop and restart the machine; needs socat
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
case $test in '' | init | image | update | rollout | install | vps | netboot) ;; *) echo "vm.sh: --test knows: init, image, update, rollout, install, vps, netboot" >&2; exit 2 ;; esac
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
    if [ "$test" = rollout ]; then
        for tool in curl python3 xxd; do
            command -v "$tool" >/dev/null 2>&1 || skip "no $tool"
        done
        [ "$time" -gt 60 ] || time=900
        port=$((20000 + $$ % 20000))
        fail() { tail -n 30 "$work"/n?.log; echo "vm.sh: FAIL: $1" >&2; exit 1; }
        cargo build -q --manifest-path "$root/Cargo.toml" -p kith-cli >&2
        # Two releases, both signed: one that runs, and one whose root is not the one its
        # verity tree was made for. The nodes fetch them from this machine.
        KITH_OS_VERSION=0.0.0-next sh "$root/os/build.sh" --out "$work/next" >&2
        mkdir "$work/www"
        cp "$work/next/kith-os.update" "$work/www/next.update"
        cp "$work/next/root.squashfs" "$work/broken.root"
        dd if=/dev/urandom of="$work/broken.root" bs=4096 count=8 conv=notrunc status=none
        sh "$root/os/update.sh" 0.0.0-broken "$(sha256sum "$work/broken.root" | cut -d ' ' -f 1)" "$work/broken.root" \
            "$work/next/root.verity" "$work/next/kith-a.efi" "$work/next/kith-b.efi" >"$work/www/broken.update"
        public=$("$root/target/debug/kith" package keygen "$work/key")
        sign() { sh "$root/os/update.sh" --sign "$work/key" "$work/www/$1.update"; }
        (cd "$work/www" && exec python3 -m http.server --bind 127.0.0.1 $((port + 9))) >/dev/null 2>&1 &
        web=$!

        # Each node: a card on a network the three share (QEMU passes it over multicast on
        # this machine's loopback), with a fixed address, and one out to this machine.
        node() { # N [kithd's further arguments]
            [ -f "$work/n$1.raw" ] || cp "$root/target/os/kith-os.raw" "$work/n$1.raw"
            timeout "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -display none \
                -machine q35 -bios "$firmware" -drive "file=$work/n$1.raw,format=raw,if=virtio" \
                -netdev "socket,id=lan,mcast=230.0.0.1:$((port + 8)),localaddr=127.0.0.1" -device "virtio-net-pci,netdev=lan,mac=52:54:00:00:09:0$1" \
                -netdev "user,id=out,hostfwd=tcp:127.0.0.1:$((port + $1))-:7443" -device "virtio-net-pci,netdev=out,mac=52:54:00:00:0a:0$1" \
                -smbios "type=11,value=io.systemd.stub.kernel-cmdline-extra=kith.hostname=n$1 kith.ip=10.9.0.$1/24 -- --listen 0.0.0.0:7443 --advertise 10.9.0.$1:7443 ${2:-}" \
                -serial "file:$work/n$1.log" -monitor none </dev/null >/dev/null 2>&1 &
            vms="$vms $!"
        }
        field() { python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]], end="")' "$1"; }
        api() { # N METHOD PATH [FILE to send]: as the cluster's admin, to node N
            set -- "$@" ''
            curl -sf --max-time 10 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
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
        release() { # NAME VERSION SIGNATURE: that release, and a plan that gives it to every node
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"OSRelease","metadata":{"name":"$1"},
  "spec":{"version":"$2","image":"http://10.0.2.2:$((port + 9))/${4:-$1}.update","publicKey":"$public","signature":"$3"}},
 {"apiVersion":"kith.dev/v1","kind":"UpdatePlan","metadata":{"name":"all"},"spec":{"release":"$1"}}]
EOF
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
        for n in 2 3; do
            join=$(api 1 POST /v1/tokens | field token) || fail "no join token over TLS"
            node "$n" "--join 10.9.0.1:7443 --token $join"
        done
        until_says "three nodes, each saying what it runs" "^- 0 [^,? ]+,[^,? ]+,[^,? ]+ "
        was=${line#- 0 } was=${was%% *}

        # A release whose signature is another file's: the first node asked refuses it,
        # writes nothing, and the plan stops there.
        release forged 0.0.0-next "$(sign broken)" next
        until_says "a release signed for another file refused" "^Paused 0 $was .*signature is not the release's key's"
        [ "$(starts 1 a)$(starts 2 a)$(starts 3 a)" = 111 ] || fail "a node restarted for a release it refused"

        # The release, signed: every node takes it, one at a time, and it is one cluster still.
        release next 0.0.0-next "$(sign next)"
        until_says "all three on the release" "^Done 0 0.0.0-next,0.0.0-next,0.0.0-next "
        [ "$(starts 1 b)$(starts 2 b)$(starts 3 b)" = 111 ] || fail "not every node started its other slot once"
        ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"

        # A release that cannot start: the first node tries it three times and is back on
        # what it ran; the plan is paused, and no other node is given it.
        release broken 0.0.0-broken "$(sign broken)"
        until_says "a release that cannot start stopped at the first node" "^Paused 0 0.0.0-next,0.0.0-next,0.0.0-next .* did not take 0.0.0-broken: it did not come up"
        # (It says so once it has called its own slot good, ten seconds after it started.)
        tries=0
        until [ "$(grep -al 'slot a did not come up in 3 tries: this is slot b' "$work"/n?.log | wc -l)" = 1 ]; do
            tries=$((tries + 1))
            [ "$tries" -lt 30 ] || fail "not exactly one node tried the broken release"
            sleep 1
        done
        [ "$(($(starts 1 a) + $(starts 2 a) + $(starts 3 a)))" = 6 ] || fail "expected three tries of the broken release on one node"
        echo "vm.sh: ok: three nodes, claimed and joined over TLS; a forged release refused; a signed one taken by all three, one at a time, as one cluster; one that cannot start tried by one node, which came back, and the plan paused: $line"
        exit 0
    fi
    if [ "$test" = install ] || [ "$test" = vps ] || [ "$test" = netboot ]; then
        for tool in curl python3 cpio; do
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

        if [ "$test" = netboot ]; then
            # A network as in a house: one with a DHCP server of its own (ci/dhcpd.py), on a
            # hub with a node's card and a socket that a second machine's card connects to.
            # The node is told to install that machine; the machine, with an empty disk, is
            # set to start from the network. The node's second card is this script's way in.
            out=$root/target/os
            [ "$time" -gt 300 ] || time=600
            mac=52:54:00:00:09:02
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
            [ "$(api PUT "/v1/netboot?macs=$mac&minutes=10" --data-binary "@$out/kith-netboot.efi" | field on)" = True ] || fail "netboot did not go on"
            # (Again while on: the second takes the ports the first held.)
            [ "$(api PUT "/v1/netboot?macs=$mac&minutes=10" --data-binary "@$out/kith-netboot.efi" | field on)" = True ] || fail "netboot, on, could not be turned on anew"
            hears alpha 'kithd: netboot: on for 10 minutes'

            beta() { # LOG: the machine: an empty disk at first, and its card, which it starts from
                # shellcheck disable=SC2046
                vm "$1" -m 1024 $(drive beta.disk) -netdev "socket,id=n,connect=127.0.0.1:$((port + 8))" \
                    -device "virtio-net-pci,netdev=n,mac=$mac,bootindex=1"
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
        typed 'will be erased. Type its name again' vda
        hears install-gamma 'kithd: install: `vda` is not `vdb`: nothing was written'
        cmp -s -n $((64 << 20)) "$work/gamma.disk" /dev/zero || fail "a disk was written to before its name was typed twice"
        hears install-gamma 'kithd: install: once more.'
        for line in vdb gamma 10.9.0.3/24 10.9.0.1:7443 "$join" vdb; do
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

    began=$(date +%s%N)
    boot
    up
    took=$((($(date +%s%N) - began) / 1000000))
    said 'Mounted root (squashfs filesystem) readonly on device 25[0-9]:0' || fail "the root is not the verity device"
    said 'kithd: init: state on /dev/vda6' || fail "the state partition was not mounted"
    who
    first=$who
    said 'by DHCP' || fail "the network card got no address by DHCP"
    restart
    cp "$work/log" "$work/log.first"

    boot
    up
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
    echo "vm.sh: ok: UEFI boot from the image, a verity root, DHCP, TLS answered ($first), state kept across a restart, a tampered root refused"
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
    timeout "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -display none \
        -serial "file:$work/log" -monitor "unix:$work/keys,server,nowait" "$@" </dev/null >/dev/null 2>&1 &
    vm=$!
    until said 'kithd: serving '; do
        kill -0 "$vm" 2>/dev/null || fail "the VM ended before kithd served"
        sleep 0.05
    done
    took=$((($(date +%s%N) - began) / 1000000))
    echo sendkey ctrl-alt-delete | socat - "unix-connect:$work/keys" >/dev/null
    wait "$vm" || fail "the VM did not end within ${time} s of starting"
    cat "$work/log"
    said 'kithd: init: .* is up' || fail "kithd did not say it was the first process"
    said 'reboot: Restarting system' || fail "kithd did not restart the machine when told"
    ! said 'Kernel panic' || fail "the kernel panicked: its first process ended"
    echo "vm.sh: kithd served ${took} ms after QEMU started (the firmware and kernel included)"
    [ "$took" -lt 10000 ] || { echo "vm.sh: FAIL: over 10 s" >&2; exit 1; }
    echo "vm.sh: ok: kithd is the first process, serves, and restarts the machine when told"
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
