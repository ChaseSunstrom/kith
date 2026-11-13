#!/bin/sh
# Build kith OS's disk image: the whole operating system of a node.
#
#   sh os/build.sh [--out DIR] [--check] [--twice]
#
# What is in it:
#   - a kernel built from kernel.org's source at a pinned version and checksum with
#     os/kernel.config: no modules, no initramfs;
#   - a root file system (squashfs, read-only) holding kithd as /sbin/init, kith, a CA
#     bundle and empty directories, with a dm-verity hash tree beside it;
#   - a unified kernel image (systemd's stub, the kernel, and the command line that
#     names the root's hash), started by systemd-boot from the ESP;
#   - a GPT disk: esp, root-a, root-b, verity-a, verity-b, state (ext4).
#
# Nothing needs root, nothing outside --out and the cache is written, and no disk is
# touched: the result is two files, kith-os.raw and kith-os.qcow2.
set -eu

kernel_version=6.18.63
kernel_sha256=81764a545072d160748beff4d9de2e7d95aa9f16e8261110288f067a2cc61d71
kernel_url=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$kernel_version.tar.xz
ca_date=2026-11-05
ca_sha256=427c064216761a1e72a8b30f0d954d08cb6e4435a82091fb865afd20c8497285
ca_url=https://curl.se/ca/cacert-$ca_date.pem
# Every time and identifier in the image comes from these, so the same inputs give the
# same bytes.
export SOURCE_DATE_EPOCH=1700000000
seed=6b697468-0000-4000-8000-00006f730001
salt=6b697468206f732076657269747920736c743a206e6f74206120736563726574
limit=$((300 * 1024 * 1024))

usage() {
    cat <<'EOF'
usage: sh os/build.sh [--out DIR] [--check] [--twice]

Builds DIR/kith-os.raw and DIR/kith-os.qcow2 (default DIR: target/os).
Beside them, DIR/kith-os.update: what a running node is given to become this version
(it writes it into its other slot). KITH_OS_VERSION names the version built (default:
the workspace's).

  --out DIR   where the image and the pieces it is made of go: a directory this
              made before, or an empty one (it is emptied first)
  --check     fail unless the raw image is under 300 MB
  --twice     build the root and the image a second time and fail unless both are
              byte for byte the same (the kernel comes from the cache both times)
  --help      this text

The first build compiles the kernel (ten minutes or so) and keeps it in
$KITH_OS_CACHE (default ~/.cache/kith-os), keyed by its version, its config and the
compiler; later builds take seconds. Needs: gcc, make, flex, bison, bc, cargo, a musl C
compiler or zig, mksquashfs, veritysetup, objcopy, systemd-repart with systemd's EFI
stub and systemd-boot, mkfs.vfat, mcopy (mtools), mkfs.ext4, qemu-img, curl. Where bc
or mcopy is missing and nix is there, they come from nix.
EOF
}

out='' check='' twice=''
while [ $# -gt 0 ]; do
    case $1 in
    --help | -h) usage; exit 0 ;;
    --check) check=1; shift ;;
    --twice) twice=1; shift ;;
    --out)
        [ $# -ge 2 ] || { echo "build.sh: --out needs a directory" >&2; exit 2; }
        out=$2; shift 2 ;;
    *) echo "build.sh: unknown option $1 (try --help)" >&2; exit 2 ;;
    esac
done

here=$(dirname "$0")
root=$(cd "$here/.." && pwd)
[ -n "$out" ] || out=$root/target/os
cache=${KITH_OS_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/kith-os}
efi=/usr/lib/systemd/boot/efi
die() { echo "build.sh: $1" >&2; exit 1; }
# (3: this machine cannot build it, which is not the image being wrong; ci/vm.sh skips.)
lacks() { echo "build.sh: needs $1" >&2; exit 3; }

# bc (the kernel's build) and mcopy (files into the ESP) are the two tools a machine
# with the rest often lacks.
if ! command -v bc >/dev/null 2>&1 || ! command -v mcopy >/dev/null 2>&1; then
    if [ -z "${KITH_OS_IN_NIX:-}" ] && command -v nix >/dev/null 2>&1; then
        export KITH_OS_IN_NIX=1
        [ -z "$check" ] || set -- "$@" --check
        [ -z "$twice" ] || set -- "$@" --twice
        exec nix shell nixpkgs#bc nixpkgs#mtools -c sh "$0" --out "$out" "$@"
    fi
    lacks "bc and mcopy (mtools)"
fi
for tool in gcc make flex bison cargo flock objdump sfdisk mksquashfs veritysetup objcopy systemd-repart mkfs.vfat mkfs.ext4 qemu-img curl; do
    command -v "$tool" >/dev/null 2>&1 || lacks "$tool"
done
if ! [ -r "$efi/linuxx64.efi.stub" ] || ! [ -r "$efi/systemd-bootx64.efi" ]; then lacks "systemd's EFI stub and systemd-boot in $efi"; fi

mkdir -p "$out" "$cache"

# A file from the network is only ever used if it is the one pinned here.
fetch() { # URL SHA256 FILE
    if ! [ -r "$3" ] || ! echo "$2  $3" | sha256sum -c --quiet - 2>/dev/null; then
        curl -fsSL --retry 3 -o "$3.part" "$1"
        echo "$2  $3.part" | sha256sum -c --quiet - || die "$1 is not the file pinned here"
        mv "$3.part" "$3"
    fi
}

# The kernel: built once per (version, config, compiler).
compiler=$(gcc --version | head -n 1)
key=$({ echo "$kernel_version $kernel_sha256 $compiler"; cat "$root/os/kernel.config"; } | sha256sum | cut -c 1-16)
kernel=$cache/kernel-$key/vmlinuz
# (One build at a time: checkouts share the cache, and two would write one tree.)
exec 9>"$cache/lock"
flock 9
if ! [ -r "$kernel" ]; then
    echo "build.sh: building the kernel ($kernel_version): this takes a while, once" >&2
    fetch "$kernel_url" "$kernel_sha256" "$cache/linux-$kernel_version.tar.xz"
    tree=$cache/kernel-$key/src
    mkdir -p "$tree"
    tar -xJf "$cache/linux-$kernel_version.tar.xz" -C "$tree" --strip-components=1
    (
        cd "$tree"
        export KBUILD_BUILD_TIMESTAMP='Thu Jan  1 00:00:00 UTC 1970' KBUILD_BUILD_USER=kith KBUILD_BUILD_HOST=kith
        make -s x86_64_defconfig
        scripts/kconfig/merge_config.sh -m .config "$root/os/kernel.config" >/dev/null
        make -s olddefconfig
        # What the config asks for and the kernel does not have would be dropped in silence.
        grep '^CONFIG_' "$root/os/kernel.config" | while read -r wanted; do
            grep -qxF "$wanted" .config || { echo "build.sh: the kernel did not take $wanted" >&2; exit 1; }
        done
        nice -n 10 make -s -j"${KITH_OS_JOBS:-$(nproc)}" bzImage
        cp arch/x86/boot/bzImage ../vmlinuz.part
        cp .config ../config
    ) >&2
    # (The tree is 2.6 GB; the kernel is what is kept.)
    find "$tree" -delete
    mv "$cache/kernel-$key/vmlinuz.part" "$kernel"
fi
fetch "$ca_url" "$ca_sha256" "$cache/cacert-$ca_date.pem"
exec 9>&-
bin=$(sh "$root/ci/musl.sh")
# (KITH_OS_VERSION: the name of what is built, where it is not the workspace's version.)
version=${KITH_OS_VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -n 1)}
case $version in '' | *[!0-9A-Za-z.+-]*) die "a version is letters, digits, dots, + and -: not '$version'" ;; esac

# One slot's worth of system, and the disk around it, into DIR.
assemble() { # DIR
    w=$1
    mkdir -p "$w"
    # Emptied first, so only a directory that is this script's, or an empty one.
    if [ -n "$(ls -A "$w")" ] && ! [ -e "$w/.kith-os" ]; then die "$w has other things in it: not emptying it"; fi
    find "$w" -mindepth 1 -delete
    : >"$w/.kith-os"

    # The root: what a node runs, and the places things are mounted.
    r=$w/root
    mkdir -p "$r/sbin" "$r/bin" "$r/etc/ssl/certs" "$r/proc" "$r/sys" "$r/dev" "$r/run" "$r/tmp" "$r/var/lib/kith"
    cp "$bin/kithd" "$r/sbin/init"
    cp "$bin/kith" "$r/bin/kith"
    cp "$cache/cacert-$ca_date.pem" "$r/etc/ssl/certs/ca-certificates.crt"
    ln -s /run/resolv.conf "$r/etc/resolv.conf"
    printf 'NAME="kith OS"\nID=kith\nVERSION_ID=%s\nPRETTY_NAME="kith OS %s"\n' "$version" "$version" >"$r/etc/os-release"
    chmod -R u=rwX,go=rX "$r"
    mksquashfs "$r" "$w/root.squashfs" -comp zstd -Xcompression-level 19 -all-root -noappend -no-xattrs -quiet -no-progress
    veritysetup format "$w/root.squashfs" "$w/root.verity" --salt="$salt" --uuid="$seed" >"$w/verity.txt"
    hash=$(awk '/^Root hash/ { print $3 }' "$w/verity.txt")
    blocks=$(($(stat -c %s "$w/root.squashfs") / 4096))

    # The kernel is told its root's hash on its command line, which is inside the one
    # file the firmware starts: change the root and it is refused, block by block. One
    # such file per slot, since the command line names the slot's partitions.
    #
    # The sections go above the stub's own, at the addresses systemd's ukify uses for
    # this stub: a stub laid out otherwise is refused here, not at boot.
    objdump -h "$efi/linuxx64.efi.stub" | awk '$1 ~ /^[0-9]+$/ { print $3, $4 }' | while read -r size at; do
        [ $((0x$at + 0x$size)) -le $((0x14dfc0000)) ] || die "systemd's EFI stub here is laid out otherwise than this script knows"
    done
    # (No version in the kernel image's own os-release: the boot loader would order the
    # slots by it, and a node told to go to an older release would never start it. The
    # order is the N in the file's name, which the node gives it: crates/kithd/src/os.rs.)
    printf 'NAME="kith OS"\nID=kith\nPRETTY_NAME="kith OS"\n' >"$w/osrel"
    for slot in a b; do
        table="root,,,ro,0 $((blocks * 8)) verity 1 PARTLABEL=root-$slot PARTLABEL=verity-$slot 4096 4096 $blocks 1 sha256 $hash $salt"
        printf '%s' "console=ttyS0 console=tty0 dm-mod.create=\"$table\" dm-mod.waitfor=PARTLABEL=root-$slot,PARTLABEL=verity-$slot root=/dev/dm-0 ro rootwait kith.slot=$slot" >"$w/cmdline-$slot"
        objcopy \
            --add-section .osrel="$w/osrel" --change-section-vma .osrel=0x14dfc0000 \
            --add-section .cmdline="$w/cmdline-$slot" --change-section-vma .cmdline=0x14dfd0000 \
            --add-section .linux="$kernel" --change-section-vma .linux=0x14e000000 \
            "$efi/linuxx64.efi.stub" "$w/kith-$slot.efi"
        touch -d "@$SOURCE_DATE_EPOCH" "$w/kith-$slot.efi"
    done
    # What a node of an older version is given to become this one (os/update.sh).
    sh "$root/os/update.sh" "$version" "$hash" "$w/root.squashfs" "$w/root.verity" "$w/kith-a.efi" "$w/kith-b.efi" >"$w/kith-os.update"

    # The ESP, made here and not by repart: FAT16 at 64 MB, where repart insists on 260.
    truncate -s 64M "$w/esp.img"
    mkfs.vfat --invariant -i 6B697468 -n KITH-ESP "$w/esp.img" >/dev/null
    printf 'timeout 0\n' >"$w/loader.conf"
    touch -d "@$SOURCE_DATE_EPOCH" "$w/loader.conf"
    cp -p "$efi/systemd-bootx64.efi" "$w/boot.efi"
    touch -d "@$SOURCE_DATE_EPOCH" "$w/boot.efi"
    mmd -i "$w/esp.img" ::EFI ::EFI/BOOT ::EFI/Linux ::loader
    mcopy -m -i "$w/esp.img" "$w/boot.efi" ::EFI/BOOT/BOOTX64.EFI
    # (kith-N-SLOT: the boot loader starts the highest N that has tries left; an update
    # is added as N+1 with three tries, see crates/kithd/src/os.rs.)
    mcopy -m -i "$w/esp.img" "$w/kith-a.efi" ::EFI/Linux/kith-1-a.efi
    mcopy -m -i "$w/esp.img" "$w/loader.conf" ::loader/loader.conf

    # The disk. root-b and verity-b are empty: an update fills them (and has room to
    # be bigger than this one).
    d=$w/repart.d
    mkdir "$d"
    part() { # FILE TYPE LABEL SIZE [more lines]
        f=$d/$1.conf
        printf '[Partition]\nType=%s\nLabel=%s\nSizeMinBytes=%s\nSizeMaxBytes=%s\n' "$2" "$3" "$4" "$4" >"$f"
        shift 4
        for line; do echo "$line" >>"$f"; done
    }
    part 10-esp esp esp 64M "CopyBlocks=$w/esp.img"
    part 20-root-a root-x86-64 root-a 88M "CopyBlocks=$w/root.squashfs"
    part 21-root-b root-x86-64 root-b 88M
    part 30-verity-a root-x86-64-verity verity-a 4M "CopyBlocks=$w/root.verity"
    part 31-verity-b root-x86-64-verity verity-b 4M
    part 40-state linux-generic state 32M "Format=ext4"
    systemd-repart --empty=create --size=auto --dry-run=no --seed="$seed" --definitions="$d" "$w/kith-os.raw" >"$w/repart.log" 2>&1 \
        || { cat "$w/repart.log" >&2; die "systemd-repart failed"; }
    qemu-img convert -f raw -O qcow2 "$w/kith-os.raw" "$w/kith-os.qcow2"
}

assemble "$out"
size=$(stat -c %s "$out/kith-os.raw")
echo "build.sh: $out/kith-os.raw: $((size / 1024 / 1024)) MB ($(($(stat -c %s "$out/kith-os.qcow2") / 1024 / 1024)) MB as qcow2); kernel $kernel_version, $(($(stat -c %s "$kernel") / 1024 / 1024)) MB; root $(($(stat -c %s "$out/root.squashfs") / 1024 / 1024)) MB"
if [ -n "$check" ]; then
    [ "$size" -lt "$limit" ] || die "the image is $size bytes: over 300 MB"
    qemu-img compare -q -f raw -F qcow2 "$out/kith-os.raw" "$out/kith-os.qcow2" || die "the qcow2 image is not the raw one"
fi
if [ -n "$twice" ]; then
    assemble "$out/again"
    for piece in root.squashfs root.verity kith-a.efi kith-b.efi kith-os.update esp.img kith-os.raw; do
        cmp "$out/$piece" "$out/again/$piece" || die "$piece differs between two builds"
    done
    find "$out/again" -delete
    echo "build.sh: two builds, the same bytes"
fi
