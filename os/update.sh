#!/bin/sh
# Pack a kith OS update, the one file a node writes into the slot it does not run from
# (crates/kithd/src/os.rs): a header of 4096 bytes (a line of JSON, padded with spaces)
# and then the pieces it names, in order. Written to standard output.
#
#   sh os/update.sh VERSION ROOTHASH ROOT VERITY UKI-A UKI-B [KITHD KERNEL REST] >kith-os.update
#
# The three digests at the end (64 hex digits each: kithd, what the boot file is but for
# the root's hash, and the root but for kithd and its os-release; os/build.sh makes them)
# go into the header as its `kithd` object, which is signed with the rest of it: a node
# that runs a system with such a header can tell a kithd-only update from a full one
# (crates/kithd/src/os.rs, `way`). Without them an update is always full.
#
#   sh os/update.sh --check
#     packs an update of small files and says whether its header, with the digests, is
#     under 4096 bytes and holds them.
#
#   sh os/update.sh --sign KEYFILE kith-os.update
#
#   sh os/update.sh --handover KEYFILE kith-os.update NEWKEY...
#
# ROOTHASH is the root's verity hash, as on the command line inside both kernel images.
# os/build.sh calls the first form. The second prints the signature an OSRelease carries
# (`signature`): KEYFILE's key (from `kith package keygen KEYFILE`, which prints the public
# key that goes in `publicKey`) over the header, which names every piece's SHA-256.
# The third prints KEYFILE's signature of a handover to the public keys NEWKEY... with
# this update: run with the release's key file it is the OSRelease's `handover.signature`,
# and with the key file of one of NEWKEY... its `handover.proof`.
set -eu
if [ "${1:-}" = --sign ] || [ "${1:-}" = --handover ]; then
    case $1$# in --sign3) ;; --sign* | --handover[0-3]) echo "usage: sh os/update.sh --sign KEYFILE UPDATE, or --handover KEYFILE UPDATE NEWKEY..." >&2; exit 2 ;; esac
    for tool in openssl xxd; do
        command -v "$tool" >/dev/null 2>&1 || { echo "update.sh: needs $tool" >&2; exit 3; }
    done
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    # (The key file is PKCS#8 in hex; Ed25519 signs the header as it is, not a hash of it.)
    (umask 077 && xxd -r -p <"$2" >"$work/key")
    head -c 4096 "$3" >"$work/header"
    signed=$work/header
    if [ "$1" = --handover ]; then
        # (As crates/kithd/src/update.rs handover_text: the keys, for this release alone.)
        shift 3
        for key; do
            case ${#key}:$key in 64:*[!0-9A-Fa-f]*) false ;; 64:*) ;; *) false ;; esac ||
                { echo "update.sh: $key is not a public key (64 hex digits, as kith package keygen prints)" >&2; exit 2; }
        done
        version=$(sed -n 's/^{"format":[0-9]*,"version":"\([^"]*\)".*/\1/p' "$work/header")
        [ -n "$version" ] || { echo "update.sh: that file's header names no version: is it a kith OS update?" >&2; exit 1; }
        signed=$work/text
        {
            printf 'kith os-release keys v1\n%s\n%s\n' "$version" "$(sha256sum "$work/header" | cut -d ' ' -f 1)"
            printf '%s\n' "$@" | tr A-F a-f | LC_ALL=C sort
        } >"$signed"
    fi
    openssl pkeyutl -sign -rawin -keyform DER -inkey "$work/key" -in "$signed" | xxd -p -c 64
    exit 0
fi
if [ "${1:-}" = --check ]; then
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    for f in root verity a b; do printf '%s' "$f" >"$work/$f"; done
    one=$(printf '%064d' 1) two=$(printf '%064d' 2) three=$(printf '%064d' 3)
    sh "$0" 0.0.0-check "$one" "$work/root" "$work/verity" "$work/a" "$work/b" "$one" "$two" "$three" >"$work/with"
    sh "$0" 0.0.0-check "$one" "$work/root" "$work/verity" "$work/a" "$work/b" >"$work/without"
    head -c 4096 "$work/with" >"$work/header"
    [ "$(stat -c %s "$work/with")" -eq $((4096 + 12)) ] || { echo "update.sh: --check: the update is not a header and its four pieces" >&2; exit 1; }
    grep -q "\"kithd\":{\"sha256\":\"$one\",\"kernel\":\"$two\",\"rest\":\"$three\"}" "$work/header" || { echo "update.sh: --check: the header does not hold the kithd digests" >&2; exit 1; }
    ! head -c 4096 "$work/without" | grep -q kithd || { echo "update.sh: --check: a header made without the digests holds them" >&2; exit 1; }
    # (The same refusals, for what is not a digest.)
    ! sh "$0" 0.0.0-check "$one" "$work/root" "$work/verity" "$work/a" "$work/b" "$one" "$two" xyz >/dev/null 2>&1 || { echo "update.sh: --check: a digest that is not 64 hex digits is taken" >&2; exit 1; }
    echo "update.sh: --check: the header is $(head -c 4096 "$work/with" | tr -d ' \n' | wc -c) bytes of 4096, with the kithd digests"
    exit 0
fi
{ [ $# -eq 6 ] || [ $# -eq 9 ]; } || { echo "usage: sh os/update.sh VERSION ROOTHASH ROOT VERITY UKI-A UKI-B [KITHD KERNEL REST] >FILE, or --sign KEYFILE UPDATE, or --check" >&2; exit 2; }
version=$1 hash=$2
# (Both go into JSON as they are.)
case $version$hash in '' | *[!0-9A-Za-z.+-]*) echo "update.sh: a version is letters, digits, dots, + and -" >&2; exit 2 ;; esac
shift 2
kithd=
if [ $# -eq 7 ]; then
    for digest in "$5" "$6" "$7"; do
        case ${#digest}:$digest in 64:*[!0-9A-Fa-f]*) false ;; 64:*) ;; *) false ;; esac ||
            { echo "update.sh: $digest is not a digest (64 hex digits)" >&2; exit 2; }
    done
    kithd=$(printf ',"kithd":{"sha256":"%s","kernel":"%s","rest":"%s"}' "$5" "$6" "$7")
fi
piece() { printf '{"name":"%s","size":%s,"sha256":"%s"}' "$1" "$(stat -c %s "$2")" "$(sha256sum "$2" | cut -d ' ' -f 1)"; }
header=$(printf '{"format":1,"version":"%s","hash":"%s","pieces":[%s,%s,%s,%s]%s}' "$version" "$hash" \
    "$(piece root "$1")" "$(piece verity "$2")" "$(piece a "$3")" "$(piece b "$4")" "$kithd")
[ ${#header} -lt 4096 ] || { echo "update.sh: the header is over 4096 bytes" >&2; exit 1; }
printf '%-4095s\n' "$header"
cat "$1" "$2" "$3" "$4"
