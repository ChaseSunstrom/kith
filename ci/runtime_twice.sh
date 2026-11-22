#!/bin/sh
# Two kith-runtime test processes at once, 15 rounds (T-1186, after T-1185): the unit tests of one
# process used to share their containers' `kith-ID` cgroups with another's and kill them, which no
# check saw because the gates ran alone. One test that starts a container is run as two processes
# at the same moment; any round where either fails, or does not run it, is a failure.
#
#   sh ci/runtime_twice.sh
#
# Skips (exit 0, says so) where there is no delegated cgroup, as the tests themselves do.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
test=container::tests::container_starts_with_no_signal_blocked
rounds=15

# The same question as kith_runtime::has_delegated_cgroup: root has /kith; a user needs its own
# cgroup to be below the root's direct children.
own=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null | head -n 1)
parent=${own%/*}
if [ "$(id -u)" != 0 ] && [ -z "$parent" ]; then
    echo "runtime_twice: skipped: no delegated cgroup here"
    exit 0
fi

cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# The test binary is the one cargo says it built (no fixed target folder).
cargo test -p kith-runtime --lib --no-run --message-format=json >"$work/build.json"
bin=$(python3 -I -c '
import json, sys
for line in open(sys.argv[1]):
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "kith_runtime" and m["profile"]["test"]:
        print(m["executable"])
' "$work/build.json")
[ -n "$bin" ] && [ -x "$bin" ] || { echo "runtime_twice: no kith-runtime test binary in cargo's output" >&2; exit 1; }

round=1
while [ "$round" -le "$rounds" ]; do
    "$bin" --exact "$test" >"$work/a.out" 2>&1 & a=$!
    "$bin" --exact "$test" >"$work/b.out" 2>&1 & b=$!
    ok=1
    wait "$a" || ok=0
    wait "$b" || ok=0
    # (A filter that matches nothing, or a skip, exits 0: one test has to have passed in each.)
    for f in a b; do
        grep -q '^test result: ok. 1 passed' "$work/$f.out" || ok=0
        grep -q 'skipped' "$work/$f.out" && ok=0
    done
    if [ "$ok" = 0 ]; then
        echo "runtime_twice: round $round failed" >&2
        cat "$work/a.out" "$work/b.out" >&2
        exit 1
    fi
    round=$((round + 1))
done
echo "runtime_twice: $rounds rounds of two at once passed"
