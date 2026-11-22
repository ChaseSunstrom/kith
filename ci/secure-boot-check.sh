#!/bin/sh
# Builds kith OS with a throwaway Secure Boot key and checks what os/build.sh --secure-boot promises:
# the build is the same twice, the boot loader and the kernel images verify against the key's
# certificate, and signing changes the update's kernel digest (so an update that only signs is
# not taken for a kithd-only one). Exit 3: this machine lacks a tool (a skip, as ci/vm.sh counts it).
#
#   sh ci/secure-boot-check.sh
set -eu
here=$(dirname "$0")
root=$(cd "$here/.." && pwd)
for tool in sbsign sbverify mcopy openssl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "secure-boot-check: needs $tool" >&2; exit 3; }
done
w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT INT TERM
mkdir "$w/keys"
openssl req -new -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=kith secure-boot-check/' \
    -keyout "$w/keys/db.key" -out "$w/keys/db.crt" 2>/dev/null
# (build.sh exits 3 itself for a tool of its own that is missing: that passes through.)
sh "$root/os/build.sh" --secure-boot "$w/keys" --twice --out "$w/signed"
sh "$root/os/build.sh" --out "$w/plain"
for f in kith-a.efi kith-b.efi kith-install.efi; do
    sbverify --cert "$w/keys/db.crt" "$w/signed/$f" >/dev/null || { echo "secure-boot-check: $f does not verify" >&2; exit 1; }
    ! sbverify --list "$w/plain/$f" 2>&1 | grep -q 'signature 1' || { echo "secure-boot-check: the unsigned build's $f is signed" >&2; exit 1; }
done
# (The update's header, the first 4096 bytes, names the digest of the boot file but for the root's hash.)
digest() { head -c 4096 "$1" | tr -d ' \n\0' | sed -n 's/.*"kernel":"\([0-9a-f]*\)".*/\1/p'; }
a=$(digest "$w/signed/kith-os.update")
b=$(digest "$w/plain/kith-os.update")
{ [ -n "$a" ] && [ -n "$b" ] && [ "$a" != "$b" ]; } || { echo "secure-boot-check: the update's kernel digest is '$a' signed and '$b' unsigned: it must differ" >&2; exit 1; }
echo "secure-boot-check: kith-a.efi, kith-b.efi and kith-install.efi verify; the build is the same twice; the kernel digest differs from the unsigned build's"
