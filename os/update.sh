#!/bin/sh
# Pack a kith OS update, the one file a node writes into the slot it does not run from
# (crates/kithd/src/os.rs): a header of 4096 bytes (a line of JSON, padded with spaces)
# and then the pieces it names, in order. Written to standard output.
#
#   sh os/update.sh VERSION ROOTHASH ROOT VERITY UKI-A UKI-B >kith-os.update
#
#   sh os/update.sh --sign KEYFILE kith-os.update
#
# ROOTHASH is the root's verity hash, as on the command line inside both kernel images.
# os/build.sh calls the first form. The second prints the signature an OSRelease carries
# (`signature`): KEYFILE's key (from `kith package keygen KEYFILE`, which prints the public
# key that goes in `publicKey`) over the header, which names every piece's SHA-256.
set -eu
if [ "${1:-}" = --sign ]; then
    [ $# -eq 3 ] || { echo "usage: sh os/update.sh --sign KEYFILE UPDATE" >&2; exit 2; }
    for tool in openssl xxd; do
        command -v "$tool" >/dev/null 2>&1 || { echo "update.sh: needs $tool" >&2; exit 3; }
    done
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    # (The key file is PKCS#8 in hex; Ed25519 signs the header as it is, not a hash of it.)
    (umask 077 && xxd -r -p <"$2" >"$work/key")
    head -c 4096 "$3" >"$work/header"
    openssl pkeyutl -sign -rawin -keyform DER -inkey "$work/key" -in "$work/header" | xxd -p -c 64
    exit 0
fi
[ $# -eq 6 ] || { echo "usage: sh os/update.sh VERSION ROOTHASH ROOT VERITY UKI-A UKI-B >FILE, or --sign KEYFILE UPDATE" >&2; exit 2; }
version=$1 hash=$2
# (Both go into JSON as they are.)
case $version$hash in '' | *[!0-9A-Za-z.+-]*) echo "update.sh: a version is letters, digits, dots, + and -" >&2; exit 2 ;; esac
shift 2
piece() { printf '{"name":"%s","size":%s,"sha256":"%s"}' "$1" "$(stat -c %s "$2")" "$(sha256sum "$2" | cut -d ' ' -f 1)"; }
header=$(printf '{"format":1,"version":"%s","hash":"%s","pieces":[%s,%s,%s,%s]}' "$version" "$hash" \
    "$(piece root "$1")" "$(piece verity "$2")" "$(piece a "$3")" "$(piece b "$4")")
[ ${#header} -lt 4096 ] || { echo "update.sh: the header is over 4096 bytes" >&2; exit 1; }
printf '%-4095s\n' "$header"
cat "$1" "$2" "$3" "$4"
