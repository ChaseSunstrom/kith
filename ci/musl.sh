#!/bin/sh
# Build kithd and kith as static binaries (x86_64, musl) and print the directory they
# are in (the one line this writes to its standard output).
#
# kithd's TLS (ring) has C in it, so linking it for musl needs a musl C compiler:
# musl-gcc, or CC_x86_64_unknown_linux_musl, or else zig. ci/budgets.py weighs what this builds.
set -eu
here=$(dirname "$0")
root=$(cd "$here/.." && pwd)
target=x86_64-unknown-linux-musl
if [ -z "${CC_x86_64_unknown_linux_musl:-}" ] && ! command -v musl-gcc >/dev/null 2>&1 \
    && ! command -v x86_64-linux-musl-gcc >/dev/null 2>&1 && command -v zig >/dev/null 2>&1; then
    export CC_x86_64_unknown_linux_musl="$root/ci/musl-cc.sh"
fi
cd "$root"
if [ "${1:-}" = --tests ]; then
    # (Or with --tests: kithd's unit tests, built the same way, and the path of that one file.
    # In a target directory of their own: their link writes kithd.map too, and in kithd's
    # it would leave ci/order.py the test binary's map for kithd.)
    built=$(CARGO_TARGET_DIR="$(cd "${CARGO_TARGET_DIR:-target}" && pwd)/tests" cargo test --release --quiet --target "$target" -p kithd --bin kithd --no-run --message-format=json)
    printf '%s\n' "$built" | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n 1
    exit 0
fi
out="$(cd "${CARGO_TARGET_DIR:-target}" && pwd)/$target/release"
# kith with TLS to a node (cargo feature remote) is built first and kept as kith-remote, beside
# the default kith, which the size budget weighs; the default build after it leaves kith as it was.
# Only when KITH_MUSL_REMOTE=1, which the budgets script sets: the other callers want kith alone.
if [ "${KITH_MUSL_REMOTE:-}" = 1 ]; then
    cargo build --release --quiet --target "$target" -p kith-cli --features remote >&2
    cp "$out/kith" "$out/kith-remote"
fi
cargo build --release --quiet --target "$target" -p kithd -p kith-cli >&2
# cargo reads a relative CARGO_TARGET_DIR from here; the line printed is absolute (order.py
# matches it against /proc's maps).
echo "$out"
