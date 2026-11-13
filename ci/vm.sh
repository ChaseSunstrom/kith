#!/bin/sh
# Boot a kernel in QEMU and print what it said: by default the host's kernel with the
# static kithd as init (so, the kernel and kithd, nothing else). Phase 5's image,
# installer and update tests reuse it with their own kernel, initramfs and disk image.
#
#   sh ci/vm.sh [--kernel FILE] [--initrd FILE] [--disk IMAGE] [--append ARGS] [--time SECONDS]
#   sh ci/vm.sh --test init     kithd as the first process: up, serving, restarts when told
#   sh ci/vm.sh --test image    kith OS's disk image (os/build.sh), booted under UEFI
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
case $test in '' | init | image) ;; *) echo "vm.sh: --test knows: init, image" >&2; exit 2 ;; esac
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
trap 'rm -rf "$work"' EXIT INT TERM
said() { grep -aq "$1" "$work/log" 2>/dev/null; }
fail() { cat "$work/log"; echo "vm.sh: FAIL: $1" >&2; exit 1; }

if [ "$test" = image ]; then
    command -v socat >/dev/null 2>&1 || skip "no socat to press keys with"
    command -v openssl >/dev/null 2>&1 || skip "no openssl to call the node with"
    firmware=''
    for f in /usr/share/edk2-ovmf/x64/OVMF.4m.fd /usr/share/edk2/x64/OVMF.4m.fd /usr/share/OVMF/OVMF.fd /usr/share/ovmf/OVMF.fd; do
        [ -r "$f" ] && { firmware=$f; break; }
    done
    [ -n "$firmware" ] || skip "no UEFI firmware (OVMF)"
    command -v sfdisk >/dev/null 2>&1 || skip "no sfdisk to find the root partition with"
    sh "$root/os/build.sh" --check >&2 || { [ $? -ne 3 ] || skip "this machine cannot build the image"; exit 1; }
    # A copy: the node writes its state to the disk, and this test damages its root.
    cp "$root/target/os/kith-os.raw" "$work/disk.raw"
    port=$((20000 + $$ % 20000))
    # (The stub adds this to the command line of the image: kithd's own arguments.)
    more='io.systemd.stub.kernel-cmdline-extra=-- --listen 0.0.0.0:7443 --advertise 10.0.2.15:7443'
    boot() {
        : >"$work/log"
        timeout "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -display none -no-reboot \
            -machine q35 -bios "$firmware" -drive "file=$work/disk.raw,format=raw,if=virtio" \
            -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$port-:7443" -device virtio-net-pci,netdev=n0 \
            -smbios "type=11,value=$more" \
            -serial "file:$work/log" -monitor "unix:$work/keys,server,nowait" </dev/null >/dev/null 2>&1 &
        vm=$!
    }
    up() {
        until said 'serving other nodes on '; do
            kill -0 "$vm" 2>/dev/null || fail "the VM ended before kithd served other nodes"
            sleep 0.05
        done
    }
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
        said 'kithd: init: restarting' || fail "kithd did not restart the machine when told"
        ! said 'Kernel panic' || fail "the kernel panicked"
    }

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
    said 'kithd: init: restarting' || fail "kithd did not restart the machine when told"
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
