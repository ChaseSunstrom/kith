#!/bin/sh
# Pack a kith OS update, the one file a node writes into the slot it does not run from
# (crates/kithd/src/os.rs): a header of 4096 bytes (a line of JSON, padded with spaces)
# and then the pieces it names, in order. Written to standard output.
#
#   sh os/update.sh VERSION ROOTHASH ROOT VERITY UKI-A UKI-B >kith-os.update
#
# ROOTHASH is the root's verity hash, as on the command line inside both kernel images.
# os/build.sh calls this; nothing is signed here.
set -eu
[ $# -eq 6 ] || { echo "usage: sh os/update.sh VERSION ROOTHASH ROOT VERITY UKI-A UKI-B >FILE" >&2; exit 2; }
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
