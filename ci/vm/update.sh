# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test update: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
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
        # The updates of kithd alone, and of another kernel, on a node with a pod running: a test of its own
        # (the lock this run holds is inherited, so the child waits for none).
        KITH_VM_LOCK='' sh "$root/ci/vm.sh" --test handover || fail "the kithd-only hand-over test failed"
        echo "vm.sh: ok: a damaged update refused; an update written into slot b, started, marked good, the same node ($first); a release that cannot start tried three times, then slot b again; a kithd-only release handed over to with no restart"
        exit 0
