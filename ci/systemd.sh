#!/bin/sh
# Run dist/kithd.service under systemd, as a transient user unit with the file's own
# [Service] lines (ExecStart aside: this tree's kithd, on a state and socket of its own):
#
#   sh ci/systemd.sh [KITHD]    KITHD: target/debug/kithd unless named; kith is beside it
#
# Needs a user manager (systemctl --user), systemd 254 or newer and cgroup v2, as the unit
# does. It checks what the unit's lines promise: kithd answers from the unit's `supervisor`
# cgroup (Delegate, DelegateSubgroup), runs an exec Workload in a cgroup beside it, and on
# `systemctl --user stop` (KillMode=mixed: SIGTERM to kithd alone) stops it and exits within
# TimeoutStopSec. Nothing is installed; the unit is gone when the script ends.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
kithd=$(realpath "${1:-$root/target/debug/kithd}")
kith=$(dirname "$kithd")/kith
file=$root/dist/kithd.service
unit=kith-trial-$$
work=$(mktemp -d)
trap 'systemctl --user stop "$unit" 2>/dev/null || :; systemctl --user reset-failed "$unit" 2>/dev/null || :; rm -rf "$work"' EXIT
fail() { echo "systemd: $*" >&2; exit 1; }
export KITH_SOCKET="$work/kithd.sock"

# The [Service] lines, each a property of the transient unit.
set --
for line in $(sed -n '/^\[Service\]/,/^\[/p' "$file" | grep -E '^[A-Za-z]+=' | grep -v '^ExecStart='); do
    set -- "$@" -p "$line"
done
echo "systemd: $unit with $*"
systemd-run --user --quiet --unit "$unit" "$@" -- \
    "$kithd" --state "$work/state" --socket "$KITH_SOCKET" --registry-port 0

i=0
until "$kith" get workload >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || { journalctl --user -u "$unit" --no-pager | tail -20 >&2; fail "kithd did not answer in 30 s"; }
    sleep 0.5
done
pid=$(systemctl --user show -p MainPID --value "$unit")
group=$(systemctl --user show -p ControlGroup --value "$unit")
grep -qx "0::$group/supervisor" "/proc/$pid/cgroup" || fail "kithd is in $(cat "/proc/$pid/cgroup"), not $group/supervisor"
echo "systemd: kithd ($pid) answers from $group/supervisor"

"$kith" apply -f - <<'EOF'
apiVersion: kith.dev/v1
kind: Workload
metadata:
  name: trial
spec:
  template:
    exec:
      - name: run
        command: [sleep, "300"]
EOF
i=0
procs=
until [ -n "$procs" ]; do
    procs=$(cat /sys/fs/cgroup"$group"/kith-*/cgroup.procs 2>/dev/null || :)
    i=$((i + 1))
    [ "$i" -lt 60 ] || { "$kith" get workload/trial -o yaml >&2 || :; fail "the Workload has no process beside kithd in 30 s"; }
    sleep 0.5
done
echo "systemd: the Workload runs beside kithd: $(echo "$procs" | tr '\n' ' ')"

limit=$(sed -n 's/^TimeoutStopSec=//p' "$file")
start=$(date +%s)
systemctl --user stop "$unit"
took=$(($(date +%s) - start))
[ "$took" -lt "$limit" ] || fail "stopping took $took s, TimeoutStopSec is $limit"
for p in $procs; do
    [ ! -e "/proc/$p" ] || fail "the Workload's process $p outlived the unit"
done
journalctl --user -u "$unit" --no-pager | grep -q 'SIGKILL' && fail "systemd had to SIGKILL what kithd left"
echo "systemd: stopped in $took s (TimeoutStopSec $limit), the Workload's processes gone with it"
