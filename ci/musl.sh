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
# Where cargo puts what it builds, as cargo says (absolute): CARGO_TARGET_DIR, a
# .cargo/config.toml's build.target-dir (a Sampo lane has one), or target.
dir=$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
[ -n "$dir" ] || { echo "musl.sh: cargo metadata names no target directory" >&2; exit 1; }
if [ "${1:-}" = --tests ]; then
    # (Or with --tests: kithd's unit tests, built the same way, and the path of that one file.
    # In a target directory of their own: their link writes kithd.map too, and in kithd's
    # it would leave ci/order.py the test binary's map for kithd.)
    built=$(CARGO_TARGET_DIR="$dir/tests" cargo test --release --quiet --target "$target" -p kithd --bin kithd --no-run --message-format=json)
    printf '%s\n' "$built" | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n 1
    exit 0
fi
# KITHD_FEATURES=forge: the test build whose leader can append an entry it was not asked for
# (crates/kithd/src/forge.rs, ci/vm/access.sh). In a target directory of its own, and only
# that: the release build below, the one budgets.py weighs and os/build.sh ships, never
# has the feature, and a build for one does not rebuild the other.
case "${KITHD_FEATURES:-}" in
    '') ;;
    forge)
        CARGO_TARGET_DIR="$dir/forge" cargo build --release --quiet --target "$target" -p kithd -p kith-cli --features kithd/forge >&2
        echo "$dir/forge/$target/release"
        exit 0
        ;;
    # fido2-test: the one with a software security key on /dev/uhid (crates/kithd/src/fido2_test.rs,
    # docs/adr-fido2.md section 2), for the fido2 VM test alone; its folder is its own too.
    fido2-test)
        CARGO_TARGET_DIR="$dir/fido2-test" cargo build --release --quiet --target "$target" -p kithd -p kith-cli --features kithd/fido2-test >&2
        echo "$dir/fido2-test/$target/release"
        exit 0
        ;;
    # confine-probe: the one with `kithd confine-probe DIR` (crates/kithd/src/confine.rs, docs/adr-privilege.md),
    # for the privilege VM test alone; its folder is its own too.
    confine-probe)
        CARGO_TARGET_DIR="$dir/confine-probe" cargo build --release --quiet --target "$target" -p kithd -p kith-cli --features kithd/confine-probe >&2
        echo "$dir/confine-probe/$target/release"
        exit 0
        ;;
    *) echo "musl.sh: KITHD_FEATURES knows: forge, fido2-test, confine-probe" >&2; exit 1 ;;
esac
out="$dir/$target/release"
# kith with TLS to a node (cargo feature remote) is built first and kept as kith-remote, beside
# the default kith, which the size budget weighs; the default build after it leaves kith as it was.
# Only when KITH_MUSL_REMOTE=1, which the budgets script sets: the other callers want kith alone.
if [ "${KITH_MUSL_REMOTE:-}" = 1 ]; then
    # (docker: `kith docker serve`, the Docker Engine API front, T-1205: here and not in the default kith.)
    cargo build --release --quiet --target "$target" -p kith-cli --features remote,docker >&2
    cp "$out/kith" "$out/kith-remote"
fi
cargo build --release --quiet --target "$target" -p kithd -p kith-cli >&2
# Whatever the environment held, this kithd is the one that ships: it has no forge route. (Not
# "/v1/forge" alone: it is the start of "/v1/forget", which kithd has; the startup line of a
# forge build is the other thing only that build has.)
[ -f "$out/kithd" ] || { echo "musl.sh: no $out/kithd to check" >&2; exit 1; }
if grep -aqE '/v1/forge([^t]|$)|built with forge: ' "$out/kithd"; then
    echo "musl.sh: $out/kithd has the forge route in it: a build that ships has none" >&2
    exit 1
fi
# And no software security key: the startup line of a fido2-test build, the start of each line
# its VM run prints and the touch file it reads are in nothing else (fido2_test.rs).
if grep -aqE 'built with fido2-test: |kithd: fido2-test: |/run/fido2-touch' "$out/kithd"; then
    echo "musl.sh: $out/kithd has the fido2-test authenticator in it: a build that ships has none" >&2
    exit 1
fi
# And no confinement probe, which makes a directory as root: the name of its subcommand, in the
# message it ends with, is in nothing else (confine.rs).
if grep -aq 'kithd: confine-probe: ' "$out/kithd"; then
    echo "musl.sh: $out/kithd has the confine-probe in it: a build that ships has none" >&2
    exit 1
fi
# cargo reads a relative CARGO_TARGET_DIR from here; the line printed is absolute (order.py
# matches it against /proc's maps).
echo "$out"
