# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test disk (through tests.sh): it runs inside the driver's shell,
# with its variables and functions; not a script to run alone.
#
# The second disk, as docs/adr-second-disk.md has it: the image of a kithd built with the cargo
# feature disk-test (never shipped) makes the disk whose serial the kernel command line names
# (kith.disk-add=SERIAL) a data disk at start: the real mapping (aes-xts, the key in the state),
# the seed ext4 made for it and grown to the disk, and the mount after the state is open. A second
# disk the machine does not know is given with it, and must come out as it went in. Both are FILES
# on this machine, never a device (the add verb itself is T-0958's second half: no test of it here).
    [ "$time" -gt 120 ] || time=240
    known=kithknown0001 unknown=kithother0001
    # (Sparse: 16 GiB of a file that holds what is written. The unknown disk has bytes in it that
    # are not zeros, at its start and its end, and a checksum taken now.)
    truncate -s 16G "$work/known.raw"
    truncate -s 256M "$work/other.raw"
    dd if=/dev/urandom of="$work/other.raw" bs=1M count=4 conv=notrunc status=none
    dd if=/dev/urandom of="$work/other.raw" bs=1M count=4 seek=252 conv=notrunc status=none
    before=$(sha256sum <"$work/other.raw")
    # (A serial is a property of the device, not of the drive: -device virtio-blk-pci.)
    drives="-drive file=$work/known.raw,format=raw,if=none,id=known,discard=unmap -device virtio-blk-pci,drive=known,serial=$known"
    drives="$drives -drive file=$work/other.raw,format=raw,if=none,id=other -device virtio-blk-pci,drive=other,serial=$unknown"

    cp "$osdir/kith-os.raw" "$work/disk.raw"
    more="kith.disk-add=$known $serve" once=1
    # shellcheck disable=SC2086
    boot $drives
    up
    said 'kithd: built with disk-test: adding the disk with serial '"$known" || fail "the disk-test build did not add the disk it was told to"
    heard 'kithd: data disks: '
    said "kithd: disk-test: added " || fail "the disk was not added: the mapping, the seed or the header failed"
    said "kithd: data disks: known: [^;]*serial ${known}[^;]*mounted" || fail "the disk added at start was not mounted by the scan after the state opened"
    said "unknown: [^;]*serial ${unknown}[^;]* left alone" || fail "the disk nobody added is not listed as left alone"
    ! said 'kithd: the data disk .* is not closed' || fail "a data disk was not closed"
    restart
    ! said 'kithd: the data disk .* is not closed' || fail "a data disk was not closed at the restart"
    [ "$(sha256sum <"$work/other.raw")" = "$before" ] || fail "the disk nobody added was written to"
    cp "$work/log" "$work/log.first"

    # Started again: the disk is known now (its header and its key), so the scan mounts it without
    # the command line asking; the unknown one is still left alone.
    more=$serve
    # shellcheck disable=SC2086
    boot $drives
    up
    heard 'kithd: data disks: '
    said "kithd: data disks: known: [^;]*serial ${known}[^;]*mounted" || fail "the known disk was not mounted at the second start, from its header and key"
    ! said 'kithd: built with disk-test' || fail "the second start was told to add the disk again"
    said "unknown: [^;]*serial ${unknown}[^;]* left alone" || fail "the unknown disk is not left alone at the second start"
    restart
    ! said 'kithd: the data disk .* is not closed' || fail "a data disk was not closed at the second restart"
    [ "$(sha256sum <"$work/other.raw")" = "$before" ] || fail "the disk nobody added was written to at the second start"
    echo "vm.sh: ok: a disk file added at start was mounted after the state opened, mounted again from its key at the next start, and the unlabelled disk file was listed as left alone and kept byte for byte"
    exit 0
