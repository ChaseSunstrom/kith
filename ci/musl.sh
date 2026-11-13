#!/bin/sh
# Build kithd and kith as static binaries (x86_64, musl) and print the directory they
# are in (the one line this writes to its standard output).
#
# kithd's TLS (ring) has C in it, so linking it for musl needs a musl C compiler:
# musl-gcc, or CC_x86_64_unknown_linux_musl, or else zig (as ci/budgets.py does).
set -eu
here=$(dirname "$0")
root=$(cd "$here/.." && pwd)
target=x86_64-unknown-linux-musl
if [ -z "${CC_x86_64_unknown_linux_musl:-}" ] && ! command -v musl-gcc >/dev/null 2>&1 \
    && ! command -v x86_64-linux-musl-gcc >/dev/null 2>&1 && command -v zig >/dev/null 2>&1; then
    export CC_x86_64_unknown_linux_musl="$root/ci/musl-cc.sh"
fi
cd "$root"
cargo build --release --quiet --target "$target" -p kithd -p kith-cli >&2
echo "${CARGO_TARGET_DIR:-$root/target}/$target/release"
