# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test encrypt (through tests.sh): it runs inside the driver's shell,
# with its variables and functions; not a script to run alone.
#
# In-place encryption at boot (docs/adr-encrypt-in-place.md, T-1106 slice a2): a plain node, its disk a
# FILE here, is given on the host what the verb will give it (slice b): a lock record holding the key
# and a marker on the config partition. At its start init runs the pass over the state partition (the
# partition under a dm-crypt mapping, sector by sector, a journal on the config partition) before the
# state is mounted, and opens the node as an encrypted one. The first start of that is cut mid-pass
# (the monitor's `quit`: the VM is gone as a power cut leaves it), and the next resumes where the
# journal says. Expected: the node is the one it was (its identity is in the state), the state's file
# system is no longer readable from the host, and the marker is gone; a third start does no pass.
    [ "$time" -gt 120 ] || time=240
    for tool in od sfdisk socat debugfs python3; do
        command -v "$tool" >/dev/null 2>&1 || skip "no $tool to read and cut the disk with"
    done
    cp "$osdir/kith-os.raw" "$work/disk.raw"
    # (A disk a gigabyte longer than the image: the state partition is made to end where it does at
    # the first start, and the pass runs over all of it: a few thousand chunks, a cut has room.)
    truncate -s "$(($(stat -c %s "$work/disk.raw") + 1073741824))" "$work/disk.raw"
    # (Where a partition starts, in 512-byte sectors.)
    start_of() { sfdisk -l -o Start,Name "$work/disk.raw" 2>/dev/null | awk -v name="$1" '$2 == name { print $1 }'; }
    # (Whether the state's file system can be read from the host: the magic of an ext4 is at byte 1080.)
    ext4_magic() { dd if="$work/disk.raw" bs=1 skip=$((state_at * 512 + 1080)) count=2 status=none | od -An -tx1 | tr -d ' \n'; }

    # A plain node first: it makes its identity at its first start, and that is what must survive.
    more=$serve once=1
    boot
    up
    who
    first=$who
    ! said 'encrypting the state in place' || fail "a node with no marker was encrypted"
    restart
    state_at=$(start_of state)
    config_at=$(start_of config)
    [ -n "$state_at" ] || fail "no state partition in the image's table"
    [ -n "$config_at" ] || fail "no config partition in the image's table"
    [ "$(ext4_magic)" = 53ef ] || fail "the plain node's state is not an ext4 before the pass: $(ext4_magic)"

    # What the verb will do: the lock record (the key of the state on the disk, as a node with no TPM
    # and no other node holds it) twice, as the node writes it, and the marker.
    hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
    key=$(hex 64)
    printf 'kith-lock v1\nsecret: %s\nrecovery: %s\nkey: %s\n' "$(hex 32)" "$(hex 16)" "$key" >"$work/lock"
    truncate -s 4096 "$work/lock"
    printf 'kith-inplace pending v1\n' >"$work/marker"
    truncate -s 4096 "$work/marker"
    # A file of known bytes in the state, big enough to span where the cut falls (the pass is cut a few
    # dozen chunks in, a chunk is 256 KiB): after the pass the host decrypts it from the disk and
    # compares, so a chunk lost or doubled at the resume shows. Where its blocks are is read while the
    # state is still plain (the ext4 is not readable after).
    head -c 67108864 /dev/urandom >"$work/blob"
    debugfs -w -R "write $work/blob blob" "$work/disk.raw?offset=$((state_at * 512))" >/dev/null 2>&1 || fail "debugfs could not write the blob into the plain state"
    debugfs -R 'ex blob' "$work/disk.raw?offset=$((state_at * 512))" 2>/dev/null | awk 'NF >= 11 && $6 == "-" && $9 == "-" { print $5, $8, $11 }' >"$work/extents"
    [ -s "$work/extents" ] || fail "debugfs gave no extents for the blob"
    dd if="$work/lock" of="$work/disk.raw" bs=512 seek=$((config_at + 1024)) conv=notrunc status=none
    dd if="$work/lock" of="$work/disk.raw" bs=512 seek=$((config_at + 1032)) conv=notrunc status=none
    dd if="$work/marker" of="$work/disk.raw" bs=512 seek=$((config_at + 128)) conv=notrunc status=none

    # The power goes a little way into the pass.
    boot
    heard 'kithd: init: encrypting the state in place: [0-9]* chunks of 256 KiB'
    heard 'kithd: init: encrypting the state in place: 32 of '
    echo quit | socat - "unix-connect:$work/keys" >/dev/null 2>&1 || :
    wait "$vm" || :
    ! said 'the state is encrypted in place' || fail "the pass ended before it was cut: the disk is too short for the test"
    ! said 'Kernel panic' || fail "the kernel panicked"
    cp "$work/log" "$work/log.cut"
    [ "$(dd if="$work/disk.raw" bs=1 skip=$((config_at * 512 + 65536)) count=24 status=none)" = 'kith-inplace pending v1' ] || fail "the marker is gone from a pass that was cut"

    # The next start resumes, finishes, and opens the node under the key the record holds.
    boot
    heard 'kithd: init: encrypting the state in place, resumed at chunk '
    up
    cp "$work/log" "$work/log.resumed"
    said 'kithd: init: the state is encrypted in place' || fail "the pass did not end at the resumed start"
    said "kithd: init: the key of this node's encrypted state is still on its disk" || fail "the node was not opened as an encrypted one"
    ! said 'the state is not opened' || fail "init refused the resumed pass"
    ! said 'Kernel panic' || fail "the kernel panicked"
    who
    second=$who
    restart
    [ "$first" = "$second" ] || fail "the node came back as another: its data did not survive the pass ($first, then $second)"
    [ "$(ext4_magic)" != 53ef ] || fail "the state's file system can still be read from the host: it was not encrypted"
    resumed=$(grep -o 'resumed at chunk [0-9]*' "$work/log.resumed" | tail -n 1 | tr -dc 0-9)
    [ -n "$resumed" ] || fail "the log of the resumed start does not say at which chunk"
    python3 -I "$root/ci/vm/xts_check.py" "$work/disk.raw" "$state_at" "$key" "$work/extents" "$work/blob" $((resumed * 512)) || fail "the blob in the state is not what was written: the resume lost or doubled a chunk"
    [ "$(dd if="$work/disk.raw" bs=1 skip=$((config_at * 512 + 65536)) count=24 status=none | tr -d '\0')" != 'kith-inplace pending v1' ] || fail "the marker is still on the config partition after the pass"

    # A third start: no marker, no journal to resume, the same node.
    boot
    up
    ! said 'encrypting the state in place' || fail "the third start ran a pass again"
    who
    third=$who
    restart
    [ "$first" = "$third" ] || fail "the node came back as another at the third start ($first, then $third)"
    echo "vm.sh: ok: a plain node's disk file with a marker was encrypted in place at its start, cut mid-pass and resumed at the next, came up as the same node on an encrypted state the host cannot read, and the third start ran no pass"
    exit 0
