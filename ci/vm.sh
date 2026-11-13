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
case $test in '' | init | image | update | rollout) ;; *) echo "vm.sh: --test knows: init, image, update, rollout" >&2; exit 2 ;; esac
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
trap 'kill $vms $web 2>/dev/null; rm -rf "$work"' EXIT INT TERM
said() { grep -aq "$1" "$work/log" 2>/dev/null; }
fail() { cat "$work/log"; echo "vm.sh: FAIL: $1" >&2; exit 1; }

if [ "$test" = image ] || [ "$test" = update ] || [ "$test" = rollout ]; then
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
