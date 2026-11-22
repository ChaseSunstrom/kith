#!/bin/sh
# Build kith OS's disk image: the whole operating system of a node.
#
#   sh os/build.sh [--out DIR] [--spec FILE] [--secure-boot KEYDIR] [--check] [--twice]
#
# What is in it:
#   - a kernel built from kernel.org's source at a pinned version and checksum with
#     os/kernel.config: no modules, no initramfs (but for a spec with the `all` feature:
#     signed modules, NVIDIA's open ones among them, and their firmware in the root, see --spec);
#   - a root file system (squashfs, read-only) holding kithd as /sbin/init, kith, a CA
#     bundle and empty directories, with a dm-verity hash tree beside it;
#   - a unified kernel image (systemd's stub, the kernel, and the command line that
#     names the root's hash), started by systemd-boot from the ESP;
#   - a GPT disk: esp, root-a, root-b, verity-a, verity-b, config, state (ext4);
#   - the installer: a second disk image that starts kith OS with `kith.install` and
#     carries the first one whole, to copy to a machine's disk.
#
# Nothing needs root, nothing outside --out and the cache is written, and no disk is
# touched: the result is files, kith-os.raw, kith-os.qcow2 and kith-os-installer.raw.
set -eu

kernel_version=6.18.63
kernel_sha256=81764a545072d160748beff4d9de2e7d95aa9f16e8261110288f067a2cc61d71
kernel_url=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$kernel_version.tar.xz
firmware_date=20261019
firmware_sha256=a10d1ab5baf2c74ba92e8c7cf313e691696c26bddfa6df00db795e48d70cd4ca
firmware_url=https://cdn.kernel.org/pub/linux/kernel/firmware/linux-firmware-$firmware_date.tar.xz
# NVIDIA's open GPU kernel modules, for the `all` image only: the source (built out of tree
# against that kernel's tree and signed with its key) and the release's own .run file, which is
# only read for the GSP firmware the modules load (nvidia/VERSION/gsp_*.bin: linux-firmware
# has another layout, for nouveau). Both are the files of this version, by their hashes.
nvidia_version=595.112.07
nvidia_sha256=6bf8f19b9d7fa6ca0029100fe09f8a72d413df67e08ad4428b1b358ec10d28c0
nvidia_url=https://github.com/NVIDIA/open-gpu-kernel-modules/archive/refs/tags/$nvidia_version.tar.gz
nvidia_run_sha256=1a38ecd538a2da6232a7330184063af59e9fc946c908cca555bd07909848b9f0
nvidia_run_url=https://download.nvidia.com/XFree86/Linux-x86_64/$nvidia_version/NVIDIA-Linux-x86_64-$nvidia_version.run
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
usage: sh os/build.sh [--out DIR] [--spec FILE] [--secure-boot KEYDIR] [--check] [--twice]

Builds DIR/kith-os.raw, DIR/kith-os.qcow2 and the installer, DIR/kith-os-installer.raw
(default DIR: target/os).
For a machine that is only reached through the system it runs: DIR/vmlinuz,
DIR/kith-install.cpio.zst and DIR/vps.sh (see os/vps.sh). For machines started from
the network by a node (`kith node netboot`): DIR/kith-netboot.efi.
Beside them, DIR/kith-os.update: what a running node is given to become this version
(it writes it into its other slot). KITH_OS_VERSION names the version built (default:
the workspace's). KITH_RELEASE_KEY (hex keys, commas between) are the keys its nodes take
releases from (/etc/kith/release-keys); without, a node takes the first release's key.
KITH_OS_BIN is a folder with the kithd and kith to put in it (default: what ci/musl.sh builds).

  --out DIR   where the image and the pieces it is made of go: a directory this
              made before, or an empty one (it is emptied first)
  --spec FILE what goes into the kernel beyond os/kernel.config: a YAML file with
              `features:` (each os/features/NAME.config) and `firmware:` (paths or
              globs in linux-firmware, built in), for a node that needs a driver
              others do not (os/examples/gpu-amd.yaml). A feature that turns on
              CONFIG_MODULES (all: os/examples/all.yaml) makes the kernel sign its
              modules with a key made for this build and deleted after, and puts the
              modules and the firmware they name (`firmware: [all]`: all of
              linux-firmware) in the root's /lib/modules and /lib/firmware
  --secure-boot KEYDIR
              sign systemd-boot and every kernel image (both slots', the update's and
              the installer's) with KEYDIR/db.key and KEYDIR/db.crt, the owner's own
              key, which is only read here and never goes into an image; an owner who
              enrolls that certificate as db has the firmware check the file that
              carries the root's hash. Enrolling it is not done by kith yet (docs/guide/os.md).
              Needs sbsign and sbverify (sbsigntools)
  --check     fail unless the raw image is under 300 MB (4 GB with modules)
  --twice     build the root and the image a second time and fail unless both are
              byte for byte the same (the kernel comes from the cache both times)
  --help      this text

The first build compiles the kernel (ten minutes or so) and keeps it in
$KITH_OS_CACHE (default ~/.cache/kith-os), keyed by its version, its config and the
compiler; later builds take seconds. Needs: gcc, make, flex, bison, bc, cargo, a musl C
compiler or zig, mksquashfs, veritysetup, objcopy, systemd-repart with systemd's EFI
stub and systemd-boot, mkfs.vfat, mcopy (mtools), mkfs.ext4, qemu-img, curl, cpio, zstd. Where bc
or mcopy is missing and nix is there, they come from nix.
EOF
}

out='' check='' twice='' spec='' sbdir=''
while [ $# -gt 0 ]; do
    case $1 in
    --help | -h) usage; exit 0 ;;
    --check) check=1; shift ;;
    --twice) twice=1; shift ;;
    --spec)
        # shellcheck disable=SC2015 # (C only reports and exits)
        [ $# -ge 2 ] && [ -f "$2" ] && [ -r "$2" ] || { echo "build.sh: --spec needs a file it can read" >&2; exit 2; }
        spec=$(realpath "$2"); shift 2 ;;
    --secure-boot)
        # shellcheck disable=SC2015 # (C only reports and exits)
        [ $# -ge 2 ] && [ -f "$2/db.key" ] && [ -r "$2/db.key" ] && [ -f "$2/db.crt" ] && [ -r "$2/db.crt" ] \
            || { echo "build.sh: --secure-boot needs a directory with a db.key and db.crt it can read" >&2; exit 2; }
        sbdir=$(realpath "$2"); shift 2 ;;
    --out)
        [ $# -ge 2 ] || { echo "build.sh: --out needs a directory" >&2; exit 2; }
        out=$2; shift 2 ;;
    *) echo "build.sh: unknown option $1 (try --help)" >&2; exit 2 ;;
    esac
done

here=$(dirname "$0")
root=$(cd "$here/.." && pwd)
[ -n "$out" ] || out=$root/target/os
# (Absolute: systemd-repart ignores a relative CopyBlocks= path and leaves the partition empty.)
mkdir -p "$out"
out=$(cd "$out" && pwd)
# KITHD_FEATURES (ci/musl.sh) builds a kithd with test-only code: only into the folder
# ci/vm.sh gives that image, so one left in the environment never makes an image that ships.
# (forge: a route a leader appends an unchecked entry by; fido2-test: a software security key
# on /dev/uhid, docs/adr-fido2.md section 2; disk-test: a data disk made at boot from the
# command line, until the add verb is, docs/adr-second-disk.md.)
case "${KITHD_FEATURES:-}" in
    '') ;;
    forge) want=$root/target/os-forge ;;
    fido2-test) want=$root/target/os-fido2 ;;
    disk-test) want=$root/target/os-disk ;;
    *) echo "build.sh: KITHD_FEATURES is set ('$KITHD_FEATURES'): it knows forge, fido2-test and disk-test (unset it)" >&2; exit 2 ;;
esac
if [ -n "${KITHD_FEATURES:-}" ] && [ "$out" != "$want" ]; then
    echo "build.sh: KITHD_FEATURES is set ('$KITHD_FEATURES'): only for --out ${want#"$root"/}, not $out (unset it)" >&2
    exit 2
fi
cache=${KITH_OS_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/kith-os}
efi=/usr/lib/systemd/boot/efi
die() { echo "build.sh: $1" >&2; exit 1; }
# (3: this machine cannot build it, which is not the image being wrong; ci/vm.sh skips.)
lacks() { echo "build.sh: needs $1" >&2; exit 3; }
# (KITH_RELEASE_KEY: the keys a node of this image takes releases from, in its signed
# root. Without, a node takes the key of the first release it is given.)
keys=''
set -f
for k in $(printf '%s' "${KITH_RELEASE_KEY:-}" | tr ',' ' '); do
    case $k in *[!0-9a-fA-F]*) die "KITH_RELEASE_KEY: '$k' is not a key (64 hex digits)" ;; esac
    [ ${#k} -eq 64 ] || die "KITH_RELEASE_KEY: '$k' is not a key (64 hex digits)"
    keys="$keys$k
"
done
set +f

# bc (the kernel's build) and mcopy (files into the ESP) are the two tools a machine
# with the rest often lacks.
if ! command -v bc >/dev/null 2>&1 || ! command -v mcopy >/dev/null 2>&1; then
    if [ -z "${KITH_OS_IN_NIX:-}" ] && command -v nix >/dev/null 2>&1; then
        export KITH_OS_IN_NIX=1
        [ -z "$check" ] || set -- "$@" --check
        [ -z "$twice" ] || set -- "$@" --twice
        [ -z "$spec" ] || set -- "$@" --spec "$spec"
        [ -z "$sbdir" ] || set -- "$@" --secure-boot "$sbdir"
        exec nix shell nixpkgs#bc nixpkgs#mtools -c sh "$0" --out "$out" "$@"
    fi
    lacks "bc and mcopy (mtools)"
fi
for tool in gcc make flex bison cargo flock objdump sfdisk mksquashfs veritysetup objcopy systemd-repart mkfs.vfat mkfs.ext4 qemu-img curl cpio zstd; do
    command -v "$tool" >/dev/null 2>&1 || lacks "$tool"
done
if [ -n "$sbdir" ]; then
    for tool in sbsign sbverify; do
        command -v "$tool" >/dev/null 2>&1 || lacks "$tool (sbsigntools: --secure-boot signs the boot loader and the kernel images)"
    done
fi
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

# (One build at a time: checkouts share the cache, and two would write one tree.)
exec 9>"$cache/lock"
flock 9

# The spec: `features:` and `firmware:`, each a list, `[a, b]` or one `- a` a line. Any
# other line is refused, so a misspelt key is not a feature left out in silence.
spec_list() { # KEY
    awk -v key="$1" '
        { sub(/(^|[ \t]+)#.*/, ""); gsub(/["\047]/, "") }
        /^[ \t]*$/ { next }
        /^[a-z]+:/ {
            k = $0; sub(/:.*/, "", k); v = $0; sub(/^[a-z]+:[ \t]*/, "", v)
            if (k != "features" && k != "firmware") { print "?" $0; next }
            inside = k == key; open = 0
            if (v ~ /^\[.*\]$/) { if (inside) { gsub(/[][ \t]/, "", v); n = split(v, a, ","); for (i = 1; i <= n; i++) if (a[i] != "") print a[i] } }
            else if (v != "") print "?" $0
            else open = 1
            next
        }
        # (An item under no `key:` of its own is refused, not dropped.)
        /^[ \t]+-[ \t]+[^ \t]+[ \t]*$/ { if (!open) print "?" $0; else if (inside) { sub(/^[ \t]+-[ \t]+/, ""); sub(/[ \t]+$/, ""); print }; next }
        { print "?" $0 }
    ' "$spec"
}
kconfig=$cache/kernel.config.$$
# (The key a kernel with modules signs them with is made in its build tree: gone from it on
# any way out of this script the trap sees (not SIGKILL: a tree that is gone on from has its
# key removed before make). Made anew, if the build is run again.)
tree=''
trap 'rm -f "$kconfig"; [ -z "$tree" ] || rm -f "$tree/certs/signing_key.pem"' EXIT
trap 'exit 1' HUP INT TERM
cp "$root/os/kernel.config" "$kconfig"
fwdir=$cache/firmware-$firmware_date
firmware='' modules='' fwextra=''
if [ -n "$spec" ]; then
    bad=$(spec_list features | grep '^?' | head -n 1) || true
    [ -z "$bad" ] || die "--spec: not a feature, a firmware or a list item: '${bad#?}'"
    # (Globs are words here, not this directory's files.)
    set -f
    # A feature is a piece of kernel config; its `# firmware:` lines are what its driver
    # loads, so a spec that names the feature need not name them.
    globs=$(spec_list firmware)
    for f in $(spec_list features); do
        case $f in *[!a-z0-9-]*) die "--spec: '$f' is not a feature's name" ;; esac
        # shellcheck disable=SC2012 # (ls of a fixed directory, for a message)
        [ -r "$root/os/features/$f.config" ] ||
            die "--spec: no feature '$f' (os/features has: $(cd "$root/os/features" && ls | sed 's/\.config$//' | tr '\n' ' '))"
        # (uhid-test puts /dev/uhid in the kernel: only for the image of the fido2 test, which
        # has the software key that opens it, and which ships nowhere.)
        [ "$f" != uhid-test ] || [ "$out" = "$root/target/os-fido2" ] ||
            die "--spec: the feature uhid-test (CONFIG_UHID) is for --out target/os-fido2 only, not $out"
        { echo "# --spec: $f"; cat "$root/os/features/$f.config"; } >>"$kconfig"
        globs="$globs
$(sed -n 's/^# firmware:[ \t]*//p' "$root/os/features/$f.config")"
    done
    # (all.config has modules, gpu-amd-phoenix builds the same driver in: merged, the one
    # would be =y and =m by the order of the lines.)
    ! spec_list features | grep -qx all || ! spec_list features | grep -qx gpu-amd-phoenix ||
        die "--spec: 'all' and 'gpu-amd-phoenix' do not go together (the same driver, as modules and built in)"
    ! spec_list features | grep -qx all || ! spec_list features | grep -qx gpu-nvidia-pascal ||
        die "--spec: 'all' and 'gpu-nvidia-pascal' do not go together (nouveau, as modules and built in)"
    # shellcheck disable=SC2086 # (a list of globs, split on purpose; globbing is off)
    globs=$(printf '%s\n' $globs | LC_ALL=C sort -u)
    for g in $globs; do
        case $g in /* | *..* | *[!A-Za-z0-9_./*+-]*) die "--spec: '$g' is not a path in linux-firmware" ;; esac
    done
    # With modules (the last word on CONFIG_MODULES in the config is =y), the firmware is
    # not built in: the drivers load it from the root when they start, so the root has
    # the files the modules name (modinfo -F firmware), and the whole of linux-firmware
    # for `all`.
    [ "$(grep -E '^(CONFIG_MODULES=y|# CONFIG_MODULES is not set)$' "$kconfig" | tail -n 1)" != CONFIG_MODULES=y ] || modules=1
    if [ -n "$modules" ]; then
        for tool in modinfo depmod openssl; do
            command -v "$tool" >/dev/null 2>&1 || lacks "$tool (kmod, openssl: modules are signed and indexed)"
        done
        fwextra=$globs
        limit=$((4096 * 1024 * 1024))
    elif [ -n "$globs" ]; then
        # shellcheck disable=SC2116,SC2086 # (the echo joins the lines of a list; globbing is off)
        case " $(echo $globs) " in *" all "*) die "--spec: firmware: [all] is for a kernel with modules (os/examples/all.yaml)" ;; esac
        # (The tarball is 640 MB, read once per new list of files: what it gave is kept.)
        if [ "$(cat "$fwdir/.kith-globs" 2>/dev/null)" != "$globs" ]; then
            # shellcheck disable=SC2116,SC2086 # (as above: the echo joins the list)
            echo "build.sh: firmware from linux-firmware $firmware_date: $(echo $globs)" >&2
            fetch "$firmware_url" "$firmware_sha256" "$cache/linux-firmware-$firmware_date.tar.xz"
            [ ! -d "$fwdir" ] || find "$fwdir" -delete
            mkdir -p "$fwdir"
            # The files the globs name, and the links of linux-firmware's WHENCE that they name
            # (most of nvidia/gp106 is links) with what those point at: os/firmware.sh, which
            # dies, naming why, for a glob that names nothing, a link out of the tree or a cycle.
            # shellcheck disable=SC2086 # (one argument for each glob; globbing is off)
            sh "$root/os/firmware.sh" "$cache/linux-firmware-$firmware_date.tar.xz" "$fwdir" $globs ||
                die "--spec: os/firmware.sh's line above says what linux-firmware $firmware_date lacks or why a link is refused"
            echo "$globs" >"$fwdir/.kith-globs"
        fi
        # (Files and links, as the kernel's firmware list: a link is a name a driver asks for.)
        firmware=$(cd "$fwdir" && find . \( -type f -o -type l \) ! -name '.*' | sed 's|^\./||' | LC_ALL=C sort | tr '\n' ' ')
        firmware=${firmware% }
        # Built in: no modules and no initramfs, so a driver finds its firmware in the
        # kernel when it starts, before any root is mounted. (A path relative to the
        # kernel's tree, so the builder's home is not in /proc/config.gz.)
        printf '# --spec: firmware, linux-firmware %s\nCONFIG_EXTRA_FIRMWARE="%s"\nCONFIG_EXTRA_FIRMWARE_DIR="kith-firmware"\n' \
            "$firmware_date" "$firmware" >>"$kconfig"
    fi
    set +f
fi

# The kernel: built once per (version, settings, firmware, compiler). The key reads the
# config's settings, '# CONFIG_X is not set' among them, not its other comments or blank lines
# (a comment edit must not rebuild a kernel: 2.6 GB of tree and an hour). The firmware is
# in it by its hash and its CONFIG_EXTRA_FIRMWARE line.
compiler=$(gcc --version | head -n 1)
key=$({ echo "$kernel_version $kernel_sha256 $compiler"; [ -z "$firmware" ] || echo "$firmware_sha256"; [ -z "$modules" ] || echo "nvidia $nvidia_sha256 no-peermem"; sed -e '/^# CONFIG_.* is not set$/b' -e '/^[[:space:]]*\(#\|$\)/d' "$kconfig"; } | sha256sum | cut -c 1-16)
kernel=$cache/kernel-$key/vmlinuz
mods=$cache/kernel-$key/mods
if ! [ -r "$kernel" ]; then
    echo "build.sh: building the kernel ($kernel_version): this takes a while, once" >&2
    fetch "$kernel_url" "$kernel_sha256" "$cache/linux-$kernel_version.tar.xz"
    [ -z "$modules" ] || fetch "$nvidia_url" "$nvidia_sha256" "$cache/nvidia-open-$nvidia_version.tar.gz"
    tree=$cache/kernel-$key/src
    # (A build that was cut short goes on from its tree, which has the mark of a config
    # made; a tree without it is begun again. The modules of an earlier key are not kept.)
    fresh=''
    if ! [ -e "$tree/.kith-config" ]; then
        [ ! -d "$tree" ] || find "$tree" -delete
        mkdir -p "$tree"
        tar -xJf "$cache/linux-$kernel_version.tar.xz" -C "$tree" --strip-components=1
        fresh=1
    fi
    [ ! -d "$mods" ] || find "$mods" -delete
    [ ! -d "$mods.part" ] || find "$mods.part" -delete
    (
        cd "$tree"
        export KBUILD_BUILD_TIMESTAMP='Thu Jan  1 00:00:00 UTC 1970' KBUILD_BUILD_USER=kith KBUILD_BUILD_HOST=kith
        if [ -n "$fresh" ]; then
            make -s x86_64_defconfig
            [ -z "$firmware" ] || cp -r "$fwdir" kith-firmware
            scripts/kconfig/merge_config.sh -m .config "$kconfig" >/dev/null
            make -s olddefconfig
            # What the config asks for and the kernel does not have would be dropped in silence.
            grep '^CONFIG_' "$kconfig" | while read -r wanted; do
                grep -qxF "$wanted" .config || { echo "build.sh: the kernel did not take $wanted" >&2; exit 1; }
            done
            : >.kith-config
        fi
        # A tree that was cut short may still hold the key of that run (a SIGKILL or a power
        # cut gives the trap no turn): gone, the kernel makes a fresh one and builds its
        # public half in, and the modules are signed with that.
        [ ! -d certs ] || find certs -name 'signing_key*' -delete
        nice -n 10 make -s -j"${KITH_OS_JOBS:-$(nproc)}" bzImage ${modules:+modules}
        cp arch/x86/boot/bzImage ../vmlinuz.part
        cp .config ../config
        if [ -n "$modules" ]; then
            # Signed as they are installed, with the key this build made (certs/signing_key.pem),
            # whose public half is in the kernel (certs/signing_key.x509). Stripped, so that
            # what goes into the root is the code; /lib/modules/VER/{build,source} would
            # name this tree, which goes.
            make -s modules_install INSTALL_MOD_PATH="$mods.part" INSTALL_MOD_STRIP=1
            rel=$(make -s kernelrelease)
            m=$mods.part/lib/modules/$rel
            rm -f "$m/build" "$m/source"
            # NVIDIA's open modules, out of tree against this tree (nvidia, nvidia-modeset,
            # nvidia-uvm, nvidia-drm; peermem is not built), installed the same way: signed with
            # the same key, stripped, into extra/, and depmod runs again so modules.alias and
            # modules.dep have them. The source is the pinned tarball, in a folder of its own.
            nv=$cache/kernel-$key/nvidia
            [ ! -d "$nv" ] || find "$nv" -delete
            mkdir -p "$nv"
            tar -xzf "$cache/nvidia-open-$nvidia_version.tar.gz" -C "$nv" --strip-components=1
            nice -n 10 make -s -C "$nv" SYSSRC="$tree" SYSOUT="$tree" -j"${KITH_OS_JOBS:-$(nproc)}" modules
            make -s -C "$nv" SYSSRC="$tree" SYSOUT="$tree" modules_install INSTALL_MOD_PATH="$mods.part" INSTALL_MOD_STRIP=1 INSTALL_MOD_DIR=extra
            find "$nv" -delete
            # (nvidia-peermem is built where the kernel has InfiniBand: not wanted, and no card's
            # alias loads it. Gone, and the index made again without it.)
            rm -f "$m/extra/nvidia-peermem.ko"
            depmod -b "$mods.part" -a "$rel"
            for f in nvidia nvidia-modeset nvidia-uvm nvidia-drm; do
                [ -s "$m/extra/$f.ko" ] || { echo "build.sh: NVIDIA's $f.ko is not in lib/modules/$rel/extra" >&2; exit 1; }
            done
            ! grep -q peermem "$m/modules.dep" || { echo "build.sh: modules.dep still names nvidia-peermem" >&2; exit 1; }
            grep -q '^alias pci:v000010DE.* nvidia$' "$m/modules.alias" || { echo "build.sh: modules.alias has no alias of an NVIDIA card for nvidia" >&2; exit 1; }
            for f in modules.dep modules.alias modules.symbols modules.builtin modules.builtin.modinfo modules.order; do
                [ -s "$m/$f" ] || { echo "build.sh: modules_install left no $f in lib/modules/$rel" >&2; exit 1; }
            done
            # Every module carries a signature, and the signer is the key built into the kernel.
            find "$m" -name '*.ko' | while read -r f; do
                tail -c 28 "$f" | grep -aq '^~Module signature appended~$' || { echo "build.sh: $f is not signed" >&2; exit 1; }
            done
            n=$(find "$m" -name '*.ko' | wc -l)
            [ "$n" -gt 100 ] || { echo "build.sh: only $n modules built: the config did not give the drivers" >&2; exit 1; }
            sample=$(find "$m" -name 'amdgpu.ko' | head -n 1)
            [ -n "$sample" ] || { echo "build.sh: no amdgpu.ko among the modules" >&2; exit 1; }
            # (kmod shows the signer's serial or its key id, by version: either names the cert.)
            hexid() { tr -d ': \n' | tr 'a-f' 'A-F' | sed 's/^0*//'; }
            have=$(modinfo -F sig_key "$sample" | hexid)
            serial=$(openssl x509 -inform DER -in certs/signing_key.x509 -noout -serial | sed 's/^serial=//' | hexid)
            ski=$(openssl x509 -inform DER -in certs/signing_key.x509 -noout -ext subjectKeyIdentifier | sed -n 2p | hexid)
            # shellcheck disable=SC2015 # (C only reports and exits)
            [ -n "$have" ] && [ -n "$(modinfo -F signer "$sample")" ] || { echo "build.sh: amdgpu.ko has no signer: $(modinfo "$sample" | tail -n 5)" >&2; exit 1; }
            [ "$have" = "$serial" ] || [ "$have" = "$ski" ] ||
                { echo "build.sh: amdgpu.ko is signed by $have, which is not the kernel's key (serial $serial, id $ski)" >&2; exit 1; }
            for f in nvidia nvidia-modeset nvidia-uvm nvidia-drm; do
                [ "$(modinfo -F sig_key "$m/extra/$f.ko" | hexid)" = "$have" ] ||
                    { echo "build.sh: $f.ko is not signed by the key amdgpu.ko is" >&2; exit 1; }
            done
            echo "build.sh: $n modules, signed by $(modinfo -F signer "$sample") ($have)"
            # The key is not kept: not in the tree, not in what is installed.
            rm -f certs/signing_key.pem
            [ -z "$(find . -name 'signing_key*' ! -name 'signing_key.x509' ! -name 'signing_key.x509.d')$(find certs "$mods.part" -name '*.pem')" ] ||
                { echo "build.sh: a private key is left in the build" >&2; exit 1; }
            ! grep -rlaE -e '-----BEGIN [A-Z ]*PRIVATE KEY' "$mods.part" || { echo "build.sh: a private key is in the modules" >&2; exit 1; }
        fi
    ) >&2
    [ -z "$modules" ] || mv "$mods.part" "$mods"
    # (The tree is 2.6 GB; the kernel is what is kept.)
    find "$tree" -delete
    mv "$cache/kernel-$key/vmlinuz.part" "$kernel"
fi
# What the kernel was built with, not what was asked of it: the merge fragments never show an
# option that is off, and a defconfig may give one on of its own. A key and an HID device
# node for it in every build; /dev/uhid (which lets root make an input device out of nothing)
# in none that ships: that build must say '# CONFIG_UHID is not set', so a missing line (an
# option the tree does not know) fails too. Only the uhid-test spec has CONFIG_UHID=y.
built=$cache/kernel-$key/config
[ -r "$built" ] || die "no .config kept for the kernel ($built)"
for want_on in CONFIG_HIDRAW=y CONFIG_USB_HID=y; do
    grep -qxF "$want_on" "$built" || die "the kernel's .config has no $want_on"
done
if [ -n "$spec" ] && spec_list features | grep -qx uhid-test; then
    grep -qxF 'CONFIG_UHID=y' "$built" || die "the uhid-test kernel's .config has no CONFIG_UHID=y"
else
    grep -qxF '# CONFIG_UHID is not set' "$built" ||
        die "a shipped kernel's .config must say '# CONFIG_UHID is not set' (only --spec with the feature uhid-test has /dev/uhid): $(grep 'CONFIG_UHID' "$built" || echo 'no CONFIG_UHID line')"
fi
if [ -n "$modules" ]; then
    # What the modules ask for, from linux-firmware: the whole of it for `all`, and the files
    # named in the spec. The list is kept; the tarball (640 MB) is read once, into a tree.
    fwall=$cache/firmware-$firmware_date-all
    if ! [ -e "$fwall/.kith-done" ]; then
        echo "build.sh: linux-firmware $firmware_date, all of it" >&2
        fetch "$firmware_url" "$firmware_sha256" "$cache/linux-firmware-$firmware_date.tar.xz"
        [ ! -d "$fwall" ] || find "$fwall" -delete
        mkdir -p "$fwall"
        tar -xJf "$cache/linux-firmware-$firmware_date.tar.xz" -C "$fwall" --strip-components=1
        : >"$fwall/.kith-done"
    fi
    # The links linux-firmware's WHENCE lists (a driver asks for iwlwifi-cc-a0-77.ucode, the
    # file is intel/iwlwifi/iwlwifi-cc-a0-77.ucode): made as its own copy-firmware.sh does.
    if ! [ -e "$fwall/.kith-links" ]; then
        sed -n 's/^Link: \([^ ]*\) *-> \([^ ]*\)$/\1 \2/p' "$fwall/WHENCE" | while read -r name target; do
            # (The tarball is checked against its hash; still, no link out of the tree.)
            case $name in /* | *..*) continue ;; esac
            case $target in /*) continue ;; esac
            # (Nor a `..` that climbs past the top, however deep the link sits.)
            case $(realpath -ms --relative-to="$fwall" "$fwall/$(dirname "$name")/$target") in .. | ../* | /*) continue ;; esac
            [ -e "$fwall/$name" ] || [ -h "$fwall/$name" ] || { mkdir -p "$fwall/$(dirname "$name")" && ln -s "$target" "$fwall/$name"; }
        done
        : >"$fwall/.kith-links"
    fi
    # NVIDIA's GSP firmware, the two files the modules load as nvidia/VERSION/gsp_*.bin: from the
    # release's .run (423 MB, a shell header and a zstd tar behind it, the line it starts at in
    # `skip=`), of which only they are kept. The .run is the file pinned above.
    nvfw=$cache/nvidia-firmware-$nvidia_version
    if ! [ -e "$nvfw/.kith-done" ]; then
        echo "build.sh: NVIDIA $nvidia_version's GSP firmware" >&2
        fetch "$nvidia_run_url" "$nvidia_run_sha256" "$cache/nvidia-$nvidia_version.run"
        skip=$(sed -n '2,20s/^skip=\([0-9][0-9]*\)$/\1/p' "$cache/nvidia-$nvidia_version.run")
        [ -n "$skip" ] || die "the .run of NVIDIA $nvidia_version has no skip= line"
        [ ! -d "$nvfw" ] || find "$nvfw" -delete
        mkdir -p "$nvfw"
        # (A pipe: a failed zstd leaves tar a short stream, which it fails on; and the files are checked.)
        tail -n "+$skip" "$cache/nvidia-$nvidia_version.run" | zstd -dcq | tar -x -C "$nvfw" --wildcards 'firmware/gsp_*.bin'
        for f in gsp_ga10x gsp_tu10x; do
            [ -s "$nvfw/firmware/$f.bin" ] || die "the .run of NVIDIA $nvidia_version has no firmware/$f.bin"
        done
        # (The .run is 423 MB and is not read again.)
        find "$cache/nvidia-$nvidia_version.run" -delete
        : >"$nvfw/.kith-done"
    fi
    # (The tag is the layout of the list: a list made before the links was another.)
    fwlist=$cache/kernel-$key/firmware-$(printf 'links2\n%s\n%s\n' "$firmware_sha256" "$fwextra" | sha256sum | cut -c 1-16).list
    if ! [ -s "$fwlist" ]; then
        set -f
        # shellcheck disable=SC2116,SC2086 # (the echo joins the lines of a list; globbing is off)
        case " $(echo $fwextra) " in
        # (Every file and every link, a link to a directory too: not what is under one.)
        *" all "*) (cd "$fwall" && find . \( -type f -o -type l \) ! -name '.kith-*' | sed 's|^\./||' | LC_ALL=C sort) >"$fwlist.part" ;;
        *)
            # (A module names the files it may load; the ones linux-firmware has are kept.)
            { find "$mods/lib/modules" -name '*.ko' -exec modinfo -F firmware {} + ; echo "$fwextra"; } |
                tr ' ' '\n' | LC_ALL=C sort -u >"$fwlist.named"
            (
                cd "$fwall"
                set +f
                while read -r name; do
                    case $name in '' | /* | *..*) continue ;; esac
                    # shellcheck disable=SC2086 # (a list of names, split on purpose; globbing is off)
                    # (A link is kept with the file it points to.)
                    for f in $name; do
                        [ -f "$f" ] || continue
                        echo "$f"
                        [ -h "$f" ] || continue
                        # (A link that leaves the tree stops the build, as the one made above is not made.)
                        r=$(realpath --relative-to=. "$f")
                        case $r in .. | ../* | /*) die "a link out of linux-firmware's tree: $f -> $r" ;; esac
                        echo "$r"
                    done
                done <"$fwlist.named" >"$fwlist.kept"
                LC_ALL=C sort -u "$fwlist.kept"
                find "$fwlist.kept" -delete
            ) >"$fwlist.part"
            echo "build.sh: the $(wc -l <"$fwlist.named") names the modules ask for are $(wc -l <"$fwlist.part") files and links in linux-firmware" >&2
            find "$fwlist.named" -delete
            ;;
        esac
        set +f
        [ -s "$fwlist.part" ] || die "no firmware for the modules"
        mv "$fwlist.part" "$fwlist"
    fi
fi
fetch "$ca_url" "$ca_sha256" "$cache/cacert-$ca_date.pem"
exec 9>&-
# (KITH_OS_BIN: a folder with kithd and kith to build from, where they are not ci/musl.sh's:
# ci/vm/handover.sh makes a release whose kithd alone differs.)
bin=${KITH_OS_BIN:-$(sh "$root/ci/musl.sh")}
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
    if [ -n "$keys" ]; then
        mkdir -p "$r/etc/kith"
        printf '%s' "$keys" >"$r/etc/kith/release-keys"
    fi
    # The file system an encrypted Volume starts as: a node has no mkfs, so kithd writes
    # this one under the volume's key and grows it (crates/kithd/src/encrypted.rs). 4 KiB
    # blocks and an inode for 32 KiB once it has grown; the same bytes at every build.
    mkdir -p "$r/usr/share/kith"
    truncate -s 8M "$r/usr/share/kith/volume.ext4"
    E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH mkfs.ext4 -q -b 4096 -N 4096 -L kith-volume -U "$seed" \
        -E "hash_seed=$seed,root_owner=0:0,lazy_itable_init=0,lazy_journal_init=0" "$r/usr/share/kith/volume.ext4" >&2
    # The same for a second disk's data (docs/adr-second-disk.md, section 4), with room kept for
    # the descriptor blocks of a disk of 2^30 blocks (4 TiB): an ext4 grows online only as far
    # as it reserved, and one made this small reserves little. The grow is one transaction that
    # holds every reserved descriptor block (512 here), and a journal allows a transaction a
    # quarter of itself: the default one of a file system this small (4 MiB) is too small for it
    # (ENOSPC at the grow, seen in a VM), so -J size=16 (4096 blocks). crates/kithd/src/data_disk/seed.rs
    # pins these parameters (resize= is its CEILING); zeros squash to nothing in the root.
    truncate -s 64M "$r/usr/share/kith/data.ext4"
    E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH mkfs.ext4 -q -b 4096 -N 4096 -J size=16 -L kith-data -U "$seed" \
        -E "hash_seed=$seed,root_owner=0:0,lazy_itable_init=0,lazy_journal_init=0,resize=1073741824" "$r/usr/share/kith/data.ext4" >&2
    msize=0 fsize=0
    if [ -n "$modules" ]; then
        # The modules (signed, with depmod's index and the list of what is built in, so the
        # loader skips those) and the firmware they name, in the root: it is checked block
        # by block, and the 64 MB ESP stays as it is.
        [ -r "$mods/lib/modules/$(ls "$mods/lib/modules")/modules.alias" ] || die "$mods has no modules: the kernel in the cache is not this build's"
        mkdir -p "$r/lib/firmware"
        cp -a "$mods/lib/modules" "$r/lib/modules"
        # (Links stay links, as in linux-firmware: a file once, under both its names.)
        (cd "$fwall" && cpio -pd --quiet "$r/lib/firmware") <"$fwlist"
        # (A link whose file the list lacks is not kept.)
        find "$r/lib/firmware" -xtype l -delete
        # NVIDIA's GSP firmware, where the modules ask for it: nvidia/VERSION/ (VERSION is the
        # modules' own, which they are built from the source of).
        mkdir -p "$r/lib/firmware/nvidia/$nvidia_version"
        cp "$nvfw"/firmware/gsp_*.bin "$r/lib/firmware/nvidia/$nvidia_version/"
        for f in gsp_ga10x gsp_tu10x; do
            [ -s "$r/lib/firmware/nvidia/$nvidia_version/$f.bin" ] || die "no NVIDIA $f.bin in the root's /lib/firmware"
        done
        find "$r/lib" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
        # Not a key anywhere in the root (its CA bundle is a .crt).
        [ -z "$(find "$r" \( -name '*.pem' -o -name 'signing_key*' \))" ] || die "a key is in the root"
        ! grep -rlaE -e '-----BEGIN [A-Z ]*PRIVATE KEY' "$r/lib/modules" || die "a private key is in the modules"
        # The firmware a module names (modinfo -F firmware) is in the root, by that name: shown
        # for the two drivers everyone asks about, and there must be some.
        for m in amdgpu iwlwifi; do
            ko=$(find "$r/lib/modules" -name "$m.ko")
            [ -n "$ko" ] || continue
            named=$(modinfo -F firmware "$ko" | wc -l)
            have=$(modinfo -F firmware "$ko" | while read -r f; do [ ! -e "$r/lib/firmware/$f" ] || echo "$f"; done | wc -l)
            echo "build.sh: $m.ko names $named firmware files, $have of them in /lib/firmware" >&2
            [ "$have" -gt 0 ] || die "$m.ko: none of the firmware it names is in the root's /lib/firmware"
        done
        msize=$(du -sb "$r/lib/modules" | cut -f 1)
        fsize=$(du -sb "$r/lib/firmware" | cut -f 1)
    fi
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
    # With --secure-boot: the owner's db key signs the file and the owner's certificate must
    # verify it, so a file the firmware would refuse is never put in an ESP or an update.
    # (The signature is added after the sections are, so the hashes above do not change.)
    sign() { # FILE
        [ -z "$sbdir" ] || {
            sbsign --key "$sbdir/db.key" --cert "$sbdir/db.crt" --output "$1.signed" "$1" >/dev/null || die "sbsign could not sign $1"
            mv "$1.signed" "$1"
            sbverify --cert "$sbdir/db.crt" "$1" >/dev/null || die "$1 does not verify against $sbdir/db.crt"
        }
    }
    cmdline() { # SLOT BLOCKS HASH
        table="root,,,ro,0 $(($2 * 8)) verity 1 PARTLABEL=root-$1 PARTLABEL=verity-$1 4096 4096 $2 1 sha256 $3 $salt"
        printf '%s' "console=ttyS0 console=tty0 dm-mod.create=\"$table\" dm-mod.waitfor=PARTLABEL=root-$1,PARTLABEL=verity-$1 root=/dev/dm-0 ro rootwait kith.slot=$1"
    }
    for slot in a b; do
        cmdline "$slot" "$blocks" "$hash" >"$w/cmdline-$slot"
        objcopy \
            --add-section .osrel="$w/osrel" --change-section-vma .osrel=0x14dfc0000 \
            --add-section .cmdline="$w/cmdline-$slot" --change-section-vma .cmdline=0x14dfd0000 \
            --add-section .linux="$kernel" --change-section-vma .linux=0x14e000000 \
            "$efi/linuxx64.efi.stub" "$w/kith-$slot.efi"
        sign "$w/kith-$slot.efi"
        touch -d "@$SOURCE_DATE_EPOCH" "$w/kith-$slot.efi"
    done
    # The installer's: slot a's, told to install and not to serve (crates/kithd/src/install.rs),
    # with its root and verity tree under labels of their own. The kernel takes the first
    # partition with a label, and a disk that already has kith OS has a root-a: the stick's
    # hash on that disk's root is a panic (T-1064).
    sed 's/PARTLABEL=root-a/PARTLABEL=install-root/g; s/PARTLABEL=verity-a/PARTLABEL=install-verity/g' \
        "$w/cmdline-a" | tr -d '\n' >"$w/cmdline-install"
    printf ' kith.install' >>"$w/cmdline-install"
    grep -q 'PARTLABEL=install-root PARTLABEL=install-verity' "$w/cmdline-install" || die "the installer's command line names the disk's root"
    objcopy \
        --add-section .osrel="$w/osrel" --change-section-vma .osrel=0x14dfc0000 \
        --add-section .cmdline="$w/cmdline-install" --change-section-vma .cmdline=0x14dfd0000 \
        --add-section .linux="$kernel" --change-section-vma .linux=0x14e000000 \
        "$efi/linuxx64.efi.stub" "$w/kith-install.efi"
    sign "$w/kith-install.efi"
    touch -d "@$SOURCE_DATE_EPOCH" "$w/kith-install.efi"
    # What tells a node a kithd-only update from a full one (the header's `kithd` object,
    # crates/kithd/src/os.rs): the digests of kithd; of the boot file but for the root's own
    # hash (the kernel, the stub, its os-release and the command line with no hash or size
    # in it); and of the root but for kithd (/sbin/init) and its os-release, which names the
    # version (sorted, owner and time fixed, as the squashfs is).
    kithd_sum=$(sha256sum "$bin/kithd" | cut -d ' ' -f 1)
    # (--secure-boot: the certificate is in the digest, so an update that only signs, or changes the
    # key, is not taken for a kithd-only one; without it the digest is what it was.)
    kernel_sum=$({ cmdline a 0 0; cat "$kernel" "$efi/linuxx64.efi.stub" "$w/osrel"; [ -z "$sbdir" ] || cat "$sbdir/db.crt"; } | sha256sum | cut -d ' ' -f 1)
    rest_sum=$(tar -C "$r" --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
        --exclude=./sbin/init --exclude=./etc/os-release -cf - . | sha256sum | cut -d ' ' -f 1)
    # What a node of an older version is given to become this one (os/update.sh).
    sh "$root/os/update.sh" "$version" "$hash" "$w/root.squashfs" "$w/root.verity" "$w/kith-a.efi" "$w/kith-b.efi" "$kithd_sum" "$kernel_sum" "$rest_sum" >"$w/kith-os.update"

    # The ESP, made here and not by repart: FAT16 at 64 MB, where repart insists on 260.
    # The installer's is the same with its own kernel image.
    truncate -s 64M "$w/esp.img" "$w/esp-install.img"
    mkfs.vfat --invariant -i 6B697468 -n KITH-ESP "$w/esp.img" >/dev/null
    mkfs.vfat --invariant -i 6B697469 -n KITH-INST "$w/esp-install.img" >/dev/null
    printf 'timeout 0\neditor no\n' >"$w/loader.conf"
    touch -d "@$SOURCE_DATE_EPOCH" "$w/loader.conf"
    cp -p "$efi/systemd-bootx64.efi" "$w/boot.efi"
    sign "$w/boot.efi"
    touch -d "@$SOURCE_DATE_EPOCH" "$w/boot.efi"
    mmd -i "$w/esp.img" ::EFI ::EFI/BOOT ::EFI/Linux ::loader
    mcopy -m -i "$w/esp.img" "$w/boot.efi" ::EFI/BOOT/BOOTX64.EFI
    # (kith-N-SLOT: the boot loader starts the highest N that has tries left; an update
    # is added as N+1 with three tries, see crates/kithd/src/os.rs.)
    mcopy -m -i "$w/esp.img" "$w/kith-a.efi" ::EFI/Linux/kith-1-a.efi
    mcopy -m -i "$w/esp.img" "$w/loader.conf" ::loader/loader.conf
    mmd -i "$w/esp-install.img" ::EFI ::EFI/BOOT ::EFI/Linux ::loader
    mcopy -m -i "$w/esp-install.img" "$w/boot.efi" ::EFI/BOOT/BOOTX64.EFI
    mcopy -m -i "$w/esp-install.img" "$w/kith-install.efi" ::EFI/Linux/kith-install.efi
    mcopy -m -i "$w/esp-install.img" "$w/loader.conf" ::loader/loader.conf

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
    # (88 MB and 4 MB; with modules, the root's size and a quarter more and 64 MB, and its
    # tree's size and 4 MB, for the next version to be bigger.)
    rootsz=88M veritysz=4M
    if [ -n "$modules" ]; then
        s=$(stat -c %s "$w/root.squashfs")
        # shellcheck disable=SC2017 # (whole MB: the 5/4 is room, not precision)
        rootsz=$((s / 1048576 * 5 / 4 + 64))M
        # shellcheck disable=SC2017 # (as above)
        veritysz=$(($(stat -c %s "$w/root.verity") / 1048576 * 5 / 4 + 4))M
    fi
    part 10-esp esp esp 64M "CopyBlocks=$w/esp.img"
    part 20-root-a root-x86-64 root-a "$rootsz" "CopyBlocks=$w/root.squashfs"
    part 21-root-b root-x86-64 root-b "$rootsz"
    part 30-verity-a root-x86-64-verity verity-a "$veritysz" "CopyBlocks=$w/root.verity"
    part 31-verity-b root-x86-64-verity verity-b "$veritysz"
    # (config: what the installer was told of this node, read at each start as more of
    # the kernel command line. Empty here.)
    part 35-config linux-generic config 1M
    # (state: 32 MB here, and as long as the rest of the disk it is written to from the
    # node's first start there (crates/kithd/src/gpt.rs). Its file system grows with it,
    # 128 MB at a time, each with as many inodes as this first part has: 8192, one for
    # every 16 KiB, which is what the images of containers need.)
    part 40-state linux-generic state 32M "Format=ext4"
    # (project: each pod's writable files are a project of their own, and quota keeps
    # the count and the limit of each: T-0470.)
    SYSTEMD_REPART_MKFS_OPTIONS_EXT4='-N 8192 -O quota,project' systemd-repart --empty=create --size=auto --dry-run=no --seed="$seed" --definitions="$d" "$w/kith-os.raw" >"$w/repart.log" 2>&1 \
        || { cat "$w/repart.log" >&2; die "systemd-repart failed"; }
    ! grep -q "ignoring" "$w/repart.log" || { grep "ignoring" "$w/repart.log" >&2; die "systemd-repart left something out"; }
    qemu-img convert -f raw -O qcow2 "$w/kith-os.raw" "$w/kith-os.qcow2"

    # The installer: enough of kith OS to start (its ESP, a root and its verity tree), and
    # the image above, whole, in a partition: installing is copying that to a disk.
    d=$w/repart-install.d
    mkdir "$d"
    part 10-esp esp esp 64M "CopyBlocks=$w/esp-install.img"
    part 20-root-a root-x86-64 install-root "$rootsz" "CopyBlocks=$w/root.squashfs"
    part 30-verity-a root-x86-64-verity install-verity "$veritysz" "CopyBlocks=$w/root.verity"
    part 50-payload linux-generic payload "$(($(stat -c %s "$w/kith-os.raw") / 1048576 + 1))M" "CopyBlocks=$w/kith-os.raw"
    systemd-repart --empty=create --size=auto --dry-run=no --seed="$seed" --definitions="$d" "$w/kith-os-installer.raw" >"$w/repart-install.log" 2>&1 \
        || { cat "$w/repart-install.log" >&2; die "systemd-repart failed (the installer)"; }
    ! grep -q "ignoring" "$w/repart-install.log" || { grep "ignoring" "$w/repart-install.log" >&2; die "systemd-repart left something out"; }

    # The installer for a machine that can only be reached through the system it runs
    # (os/vps.sh): the kernel, and a memory disk with the same root and the image as a
    # file. The kernel unpacks it and starts /init: no disk is needed to get there.
    i=$w/initramfs
    mkdir "$i"
    if [ -n "$modules" ]; then
        # (Not the modules and the firmware: it installs the image it carries, it runs nothing.)
        for e in "$r"/*; do [ "$e" = "$r/lib" ] || cp -a "$e" "$i/"; done
    else
        cp -a "$r/." "$i/"
    fi
    ln -s sbin/init "$i/init"
    cp "$w/kith-os.raw" "$i/payload"
    find "$i" -exec touch -h -d @0 {} +
    # (To a file first: in a pipe, a cpio that failed would leave half an archive unnoticed.)
    (cd "$i" && find . | LC_ALL=C sort | cpio -o -H newc --reproducible --owner=0:0 --quiet) >"$w/kith-install.cpio"
    zstd -19 -T1 -q --rm "$w/kith-install.cpio"
    find "$i" -delete
    cp "$kernel" "$w/vmlinuz"
    cp "$root/os/vps.sh" "$w/vps.sh"

    # For a machine started from the network (crates/kithd/src/netboot.rs): one file its
    # firmware fetches and starts. The kernel, and as its memory disk the installer's
    # with, before it and not compressed, an answers file of 4096 bytes that says
    # nothing: the node that serves the file writes each machine's answers over it.
    a=$w/answers
    mkdir "$a"
    { printf '#kith-netboot-answers#\n'; head -c 4072 /dev/zero | tr '\0' '#'; printf '\n'; } >"$a/kith-install.yaml"
    touch -h -d @0 "$a" "$a/kith-install.yaml"
    (cd "$a" && echo kith-install.yaml | cpio -o -H newc --reproducible --owner=0:0 --quiet) >"$w/answers.cpio"
    cat "$w/answers.cpio" "$w/kith-install.cpio.zst" >"$w/netboot.initrd"
    find "$a" -delete
    # (The memory disk goes on the next 16 MB after the kernel: a spec's kernel is bigger.)
    initrd_at=$(printf '0x%x' $((0x14e000000 + ($(stat -c %s "$kernel") / 0x1000000 + 1) * 0x1000000)))
    printf 'console=ttyS0 console=tty0 kith.install' >"$w/cmdline-netboot"
    objcopy \
        --add-section .osrel="$w/osrel" --change-section-vma .osrel=0x14dfc0000 \
        --add-section .cmdline="$w/cmdline-netboot" --change-section-vma .cmdline=0x14dfd0000 \
        --add-section .linux="$kernel" --change-section-vma .linux=0x14e000000 \
        --add-section .initrd="$w/netboot.initrd" --change-section-vma .initrd="$initrd_at" \
        "$efi/linuxx64.efi.stub" "$w/kith-netboot.efi"
    touch -d "@$SOURCE_DATE_EPOCH" "$w/kith-netboot.efi"
    # (With the firmware the root dir is a GB the image has: kept only where it is small.)
    [ -z "$modules" ] || find "$r" -delete
}

assemble "$out"
size=$(stat -c %s "$out/kith-os.raw")
sizes="kernel $kernel_version, $(($(stat -c %s "$kernel") / 1024 / 1024)) MB; root $(($(stat -c %s "$out/root.squashfs") / 1024 / 1024)) MB"
[ -z "$modules" ] || sizes="$sizes (modules $((msize / 1024 / 1024)) MB and firmware $((fsize / 1024 / 1024)) MB, before compression)"
echo "build.sh: $out/kith-os.raw: $((size / 1024 / 1024)) MB ($(($(stat -c %s "$out/kith-os.qcow2") / 1024 / 1024)) MB as qcow2); $sizes"
if [ -n "$check" ]; then
    [ "$size" -lt "$limit" ] || die "the image is $size bytes: over $((limit / 1024 / 1024)) MB"
    qemu-img compare -q -f raw -F qcow2 "$out/kith-os.raw" "$out/kith-os.qcow2" || die "the qcow2 image is not the raw one"
fi
if [ -n "$twice" ]; then
    assemble "$out/again"
    for piece in root.squashfs root.verity kith-a.efi kith-b.efi kith-install.efi kith-os.update esp.img kith-os.raw kith-os-installer.raw kith-install.cpio.zst kith-netboot.efi; do
        cmp "$out/$piece" "$out/again/$piece" || die "$piece differs between two builds"
    done
    find "$out/again" -delete
    echo "build.sh: two builds, the same bytes"
fi
