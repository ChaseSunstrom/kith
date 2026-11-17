# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test vps: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
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
