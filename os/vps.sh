#!/bin/sh
# Put kith OS on the machine this runs on, in place of the system it runs: for a rented
# machine that cannot be started from a stick.
#
# EVERYTHING ON THE DISK NAMED IS LOST, this system included. Nothing in this repository
# runs this against a machine: its owner does, on that machine, as root.
#
# It loads kith OS's kernel with the installer and the image in a memory disk (the
# files os/build.sh leaves beside this script) and starts that kernel in place of the
# running one (kexec). The installer (crates/kithd/src/install.rs) writes the disk,
# and the machine restarts as the node the answers describe.
#
#   scp target/os/vmlinuz target/os/kith-install.cpio.zst target/os/vps.sh root@machine:
#   ssh root@machine sh vps.sh --answers answers.yaml --erase vda
#
# ponytail: the image sits whole in memory, so the machine needs 1 GB; a compressed image
# read by the installer would halve that. UEFI machines only, as kith OS is.
set -eu

usage() {
    cat <<'EOF'
usage: sh vps.sh --answers FILE --erase DISK [--dry-run DIR]

Erases DISK of this machine and installs kith OS on it, then restarts into it.

  --answers FILE   what the installer is told (kith-install.yaml: see the README). Its
                   `disk:` is a name, as lsblk shows it; a rented machine mostly needs
                   `ip:` too, with the address and gateway it has now
  --erase DISK     the same disk's name again: without it, it is asked for
  --dry-run DIR    check nothing of this machine and start nothing: write the memory
                   disk to DIR/initrd and say what would be run
  --help           this text
EOF
}
die() { echo "vps.sh: $1" >&2; exit 1; }

answers='' erase='' dry=''
while [ $# -gt 0 ]; do
    case $1 in
    --answers | --erase | --dry-run)
        [ $# -ge 2 ] || { usage >&2; exit 2; }
        case $1 in --answers) answers=$2 ;; --erase) erase=$2 ;; --dry-run) dry=$2 ;; esac
        shift 2
        ;;
    --help | -h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
    esac
done
[ -n "$answers" ] || { usage >&2; exit 2; }
[ -r "$answers" ] || die "cannot read $answers"
here=$(cd "$(dirname "$0")" && pwd)
for piece in vmlinuz kith-install.cpio.zst; do
    [ -r "$here/$piece" ] || die "$piece is not beside this script: os/build.sh makes both"
done
command -v cpio >/dev/null 2>&1 || die "needs cpio"

# The disk, said twice: in the answers, and to this script.
disk=$(sed -n 's/^disk:[[:space:]]*\([^[:space:]#]*\).*/\1/p' "$answers" | head -n 1)
disk=${disk#/dev/}
# (What the installer would refuse is refused here, while there is still a way in.)
! grep -q '^ip:[^/]*$' "$answers" || die "ip: in $answers has no /LENGTH (as 10.0.0.5/24,10.0.0.1)"
case $disk in
'') die "$answers names no disk (disk: NAME)" ;;
*[!A-Za-z0-9]*) die "\`$disk\` in $answers is not a disk's name (as lsblk -d shows it, unquoted)" ;;
only) die "name the disk in $answers: \`only\` is for a stick, not for a machine that runs" ;;
esac
if [ -z "$erase" ]; then
    printf 'Everything on %s will be erased, this system with it. Type its name again to go on: ' "$disk" >&2
    read -r erase || erase=''
fi
[ "${erase#/dev/}" = "$disk" ] || die "\`$erase\` is not \`$disk\`: nothing was done"

if [ -z "$dry" ]; then
    [ "$(id -u)" = 0 ] || die "needs root"
    command -v kexec >/dev/null 2>&1 || die "needs kexec (the package is kexec-tools)"
    [ -d /sys/firmware/efi ] || die "this machine starts by BIOS, and kith OS starts by UEFI only: nothing was done"
    [ -e "/sys/block/$disk" ] || die "this machine has no disk $disk (lsblk -d lists them)"
    kb=$(sed -n 's/^MemTotal:[[:space:]]*\([0-9]*\).*/\1/p' /proc/meminfo)
    [ "$kb" -ge 900000 ] || die "this machine has $((kb / 1024)) MB of memory: the installer needs 1 GB"
    dir=$(mktemp -d)
    # (The answers may hold a join token: not left behind if this stops here.)
    trap 'rm -rf "$dir"' EXIT
else
    dir=$dry
    mkdir -p "$dir"
fi

# The memory disk: the answers, then the installer's (the kernel unpacks one after the
# other, and a plain one has to come before a compressed one).
mkdir -p "$dir/answers"
cp "$answers" "$dir/answers/kith-install.yaml"
# The installer's kernel may name the disks otherwise than this one: it is told how much
# the disk meant holds, and writes none of another size.
if [ -z "$dry" ] && ! grep -q '^size:' "$answers"; then
    printf '\nsize: %s\n' "$(($(cat "/sys/block/$disk/size") * 512))" >>"$dir/answers/kith-install.yaml"
fi
(cd "$dir/answers" && echo kith-install.yaml | cpio -o -H newc --quiet) >"$dir/answers.cpio"
cat "$dir/answers.cpio" "$here/kith-install.cpio.zst" >"$dir/initrd"
line='console=ttyS0 console=tty0 kith.install'

if [ -n "$dry" ]; then
    echo "vps.sh: would run: kexec -l $here/vmlinuz --initrd=$dir/initrd --command-line=\"$line\" && kexec -e"
    exit 0
fi
kexec -l "$here/vmlinuz" --initrd="$dir/initrd" --command-line="$line" || die "kexec did not take the kernel: nothing was done"
echo "vps.sh: starting the installer: this connection ends here. $disk is erased next; the machine then restarts as a kith OS node." >&2
sync
# (Through the service manager where there is one: it stops what runs first.)
systemctl kexec 2>/dev/null || kexec -e
