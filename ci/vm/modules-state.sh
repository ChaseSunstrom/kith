# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test modules-state (through tests.sh): it runs inside the driver's
# shell, with its variables and functions; not a script to run alone.
#
# The image of os/examples/modules-state-test.yaml has one driver as a module, virtio-input, and
# it is not in the root: the state partition carries it as os/modules-a.img (a squashfs) and
# os/modules-a.img.verity, and the root pins the tree's hash and the sizes
# (/usr/share/kith/modules). First the build's own claims (no .ko in the root; a block or network
# driver as a module refused), then the boot: the module loaded from the image, and the same
# disk with the image altered, its tree altered, another build's, longer, missing and a link,
# each refused on one console line while the node stays up.
    [ "$time" -gt 90 ] || time=90
    rng='-device virtio-keyboard-pci'

    # --- the root, read from the disk: the pin is in it, and no module is.
    disk=$osdir/kith-os.raw
    off() { sfdisk -l -o Start,Name "$disk" | awk -v n="$1" '$2 == n { print $1 * 512 }'; }
    rootoff=$(off root-a)
    stateoff=$(off state)
    [ -n "$rootoff" ] && [ -n "$stateoff" ] || fail "no root-a or state partition in the image's table"
    unsquashfs -o "$rootoff" -l "$disk" >"$work/root.list" 2>"$work/root.err" || fail "the root's file list: $(cat "$work/root.err")"
    grep -q '/usr/share/kith/modules$' "$work/root.list" || fail "the root has no /usr/share/kith/modules, the pin of the modules image"
    ! grep -Eq '\.ko(\.|$)' "$work/root.list" || fail "a kernel module is in the root: $(grep -E '\.ko(\.|$)' "$work/root.list" | head -n 3)"
    ! grep -q '/lib/modules' "$work/root.list" || fail "the root has a lib/modules: the modules are on the state partition"
    echo "vm.sh: ok: the root pins its modules image (/usr/share/kith/modules) and holds no .ko"

    # --- build.sh refuses a driver of the network or the disk as a module, with modules on state.
    # (At the config, before any kernel is built: a feature of its own, made here and gone.)
    bad=$root/os/features/modules-state-bad.config
    echo '# modules: state
CONFIG_MODULES=y
CONFIG_VIRTIO_NET=m' >"$bad"
    printf 'features: [modules-state-bad]\n' >"$work/bad.yaml"
    status=0
    sh "$root/os/build.sh" --check --spec "$work/bad.yaml" --out "$work/os-bad" >"$work/bad.out" 2>&1 || status=$?
    rm -f "$bad"
    [ "$status" -ne 0 ] || fail "build.sh built an image with a network driver as a module on the state partition"
    grep -q "block or network driver as a module (CONFIG_VIRTIO_NET=m)" "$work/bad.out" || fail "build.sh refused it, but not for the driver: $(tail -n 3 "$work/bad.out")"
    echo "vm.sh: ok: build.sh refused CONFIG_VIRTIO_NET=m with modules on state, before any kernel"

    # --- the disk, as the tests below change it: a copy of the image's, the state edited in place
    # (debugfs reaches into a file system at an offset of a file).
    fs() { debugfs -w -R "$1" "$work/disk.raw?offset=$stateoff" >"$work/fs.out" 2>&1; }
    fresh() { cp --sparse=always "$disk" "$work/disk.raw"; }
    fresh
    fs 'stats'
    bs=$(awk -F: '/^Block size/ { gsub(/ /, "", $2); print $2 }' "$work/fs.out")
    [ -n "$bs" ] || fail "debugfs cannot read the state's file system: $(head -n 3 "$work/fs.out")"
    # The byte of block $2 of the state's file $1, one added to it, on the disk.
    flip() {
        fs "bmap /os/$1 $2"
        blk=$(tail -n 1 "$work/fs.out")
        case $blk in *[!0-9]* | '') fail "no block $2 in os/$1: $(cat "$work/fs.out")" ;; esac
        at=$((stateoff + blk * bs + 100))
        old=$(od -An -tu1 -j"$at" -N1 "$work/disk.raw" | tr -d ' ')
        printf "\\$(printf %o $(((old + 1) % 256)))" | dd of="$work/disk.raw" bs=1 seek="$at" count=1 conv=notrunc status=none
    }
    # The files of the state's os/ out, to change as files: $work/m.img and $work/m.verity.
    take() {
        rm -f "$work/m.img" "$work/m.verity"
        fs "dump /os/modules-a.img $work/m.img"
        fs "dump /os/modules-a.img.verity $work/m.verity"
        [ -s "$work/m.img" ] && [ -s "$work/m.verity" ] || fail "the state has no os/modules-a.img to take"
    }
    # ...and back in place of the two.
    put() {
        fs 'rm /os/modules-a.img'
        fs 'rm /os/modules-a.img.verity'
        fs "write $work/m.img /os/modules-a.img"
        fs "write $work/m.verity /os/modules-a.img.verity"
    }
    # Boot $work/disk.raw: with the virtio keyboard, kithd up, the module not loaded; the
    # console line says $1.
    refused() {
        boot $rng
        up
        heard "kithd: init: modules: .*$1.*no module of the state's image is loaded"
        ! said 'kithd: init: module virtio_input loaded' || fail "kithd loaded a module from an image it should have refused ($2)"
        [ "$(grep -ac 'kithd: init: modules: ' "$work/log")" -eq 1 ] || fail "the refusal ($2) is not one console line"
        kill "$vm" 2>/dev/null || true
        wait "$vm" 2>/dev/null || true
        echo "vm.sh: ok: $2: refused on one console line, the node up"
    }

    # --- the image as built: loaded from.
    began=$(date +%s%N)
    boot $rng
    up
    heard 'kithd: init: module virtio_input loaded'
    took=$((($(date +%s%N) - began) / 1000000))
    ! said 'kithd: init: modules: ' || fail "kithd refused the image as built: $(grep -a 'kithd: init: modules: ' "$work/log")"
    kill "$vm" 2>/dev/null || true
    wait "$vm" 2>/dev/null || true
    echo "vm.sh: ok: kithd mapped os/modules-a.img through dm-verity and loaded virtio_input from it, ${took} ms after QEMU started"

    # --- the tamper matrix: each from the image's own disk.
    fresh
    flip modules-a.img 0
    refused 'blocks do not match the hash' "a block of the image altered"
    said 'device-mapper: verity: ' || fail "the kernel did not name dm-verity for the altered block"

    fresh
    flip modules-a.img.verity 1
    refused 'blocks do not match the hash' "a block of the hash tree altered"

    # Another build's: the same size, a tree of its own made from changed blocks.
    fresh
    take
    old=$(od -An -tu1 -j5000 -N1 "$work/m.img" | tr -d ' ')
    printf "\\$(printf %o $(((old + 1) % 256)))" | dd of="$work/m.img" bs=1 seek=5000 count=1 conv=notrunc status=none
    rm -f "$work/m.verity"
    veritysetup format "$work/m.img" "$work/m.verity" >/dev/null || fail "veritysetup cannot make another build's tree"
    put
    refused 'blocks do not match the hash' "another build's image, of the same size, with a tree that is its own"

    # A longer one: a block more, as an image of another build is.
    fresh
    take
    dd if=/dev/zero bs=4096 count=1 status=none >>"$work/m.img"
    put
    refused 'is [0-9]* bytes, and this system pinned' "an image of another size"

    # A shorter one: a block less.
    fresh
    take
    truncate -s -4096 "$work/m.img"
    put
    refused 'is [0-9]* bytes, and this system pinned' "an image of another size, shorter"

    # Another build's tree alone: the image of this build, the tree made from a changed copy.
    fresh
    take
    cp "$work/m.img" "$work/other.img"
    old=$(od -An -tu1 -j5000 -N1 "$work/other.img" | tr -d ' ')
    printf "\\$(printf %o $(((old + 1) % 256)))" | dd of="$work/other.img" bs=1 seek=5000 count=1 conv=notrunc status=none
    rm -f "$work/m.verity"
    veritysetup format "$work/other.img" "$work/m.verity" >/dev/null || fail "veritysetup cannot make another build's tree"
    put
    refused 'blocks do not match the hash' "another build's .verity alone"

    fresh
    fs 'rm /os/modules-a.img'
    refused 'No such file' "the image missing"

    fresh
    fs 'rm /os/modules-a.img.verity'
    refused 'os/modules-a.img.verity' "the tree missing"

    fresh
    fs 'rm /os/modules-a.img'
    fs 'symlink /os/modules-a.img /os/modules-a.img.verity'
    refused 'os/modules-a.img: ' "the image a link"

    echo "vm.sh: ok: modules on the state partition: pinned by the root, mapped through dm-verity, loaded; an altered, another build's, longer, missing and linked image loads nothing and says why"
    exit 0
