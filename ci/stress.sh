#!/bin/sh
# kith under load: where it gives. Kith OS nodes in local QEMU machines, loaded with N
# containers, one row of ci/stress.txt for each N.
#
#   sh ci/stress.sh [--system kith|k3s] [--sizes 100,300,1000,3000] [--memory MB] [--nodes 1|3] [--out FILE]
#
# --system  kith (default) or k3s: the same workloads on the same machines, on k3s instead of kith.
#           A k3s row ends in `k3s max_pods=N`, the pods each node was let run: k3s's 110 up to
#           100 containers, then ceil(N/nodes)+110 above that (k3s then also gets a /22 pod range).
# --sizes   the numbers of containers, tried in turn (default 100); the run ends at the first
#           size that fails. --memory is each machine's RAM (default 2048), written in every
#           row. --nodes 3 spreads the containers over three nodes; --nodes 1 runs every one of
#           them on the first node (the other two are up and idle). --out is where the rows go
#           (default ci/stress.txt), after a header line, one row to a size.
#
# Each size is a run of ci/compare.sh (three machines, KVM, 2 CPUs, a timeout of 3000 s on
# each, disks that are sparse files in a folder of their own that goes with the run) with
# ci/stress_workloads.py in place of its workloads. The row has: how long until all N
# containers are ready, the memory and CPU of each, kithd's own memory, the churn (half of
# them away and back, a change rolled through all, a replica that crashes), how long N/10
# Services of three replicas each take to have their backends and how many of those span
# nodes, whether the nodes still answer, and whether the first node, stopped as its power
# button stops it and started again, has its store back and the replicas running.
# A size that fails has the word limit in the fourth place, in place of ready_s, and then what
# was read from the nodes: free memory, tasks, open files and cgroups on each, how many times
# the kernel killed for memory, and kithd's last lines. A size that fails before any reading
# says `no readings: STEP`, the step being what compare.sh's fail named. The exit status is then 1.
# Exit 77: this machine cannot run it (no KVM, no QEMU, ...).
set -eu

sizes=100 memory=2048 nodes=3 out='' system=kith
while [ $# -gt 0 ]; do
    case $1 in
    --sizes | --memory | --nodes | --out | --system)
        [ $# -ge 2 ] || { echo "stress.sh: $1 needs a value" >&2; exit 2; }
        case $1 in --sizes) sizes=$2 ;; --memory) memory=$2 ;; --nodes) nodes=$2 ;; --out) out=$2 ;; --system) system=$2 ;; esac
        shift 2
        ;;
    --help | -h) sed -n '2,27p' "$0"; exit 0 ;;
    *) sed -n '2,3p' "$0" >&2; exit 2 ;;
    esac
done
case $sizes in '' | *[!0-9,]* | ,* | *, | *,,*) echo "stress.sh: --sizes takes numbers with commas, like 100,300" >&2; exit 2 ;; esac
case $memory in '' | 0* | *[!0-9]*) echo "stress.sh: --memory takes MB, a number" >&2; exit 2 ;; esac
case $nodes in 1 | 3) ;; *) echo "stress.sh: --nodes takes 1 or 3" >&2; exit 2 ;; esac
case $system in kith | k3s) ;; *) echo "stress.sh: --system takes kith or k3s" >&2; exit 2 ;; esac

root=$(cd "$(dirname "$0")/.." && pwd)
adapter=$root/ci/stress_workloads.py
out=${out:-$root/ci/stress.txt}
mkdir -p "$(dirname "$out")"
work=$(mktemp -d)
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'rm -rf "$work"' EXIT

[ -s "$out" ] || python3 "$adapter" header >"$out"

KITH_COMPARE_MEM=$memory KITH_COMPARE_SETTLE=0 KITH_COMPARE_ONLY=stress KITH_COMPARE_RAW=$work/raw
KITH_COMPARE_WORKLOADS=$adapter KITH_COMPARE_RESTART=1 STRESS_NODES=$nodes
export KITH_COMPARE_MEM KITH_COMPARE_SETTLE KITH_COMPARE_ONLY KITH_COMPARE_RAW KITH_COMPARE_WORKLOADS KITH_COMPARE_RESTART STRESS_NODES

for size in $(echo "$sizes" | tr , ' '); do
    # (k3s is let run more pods than its 110 above 100 containers: its share of them on each
    # node, and room for the rest. The row says so; kith's rows have no such mark.)
    maxpods=110
    [ "$size" -le 100 ] || maxpods=$(((size + nodes - 1) / nodes + 110))
    mark=''
    [ "$system" != k3s ] || mark=" k3s max_pods=$maxpods"
    echo "stress.sh: $size containers on $nodes node(s), $memory MB each machine, $system" >&2
    : >"$work/raw"
    status=0
    KITH_COMPARE_MAX_PODS=$maxpods STRESS_SIZE=$size sh "$root/ci/compare.sh" --only "$system" --runs 1 2>"$work/err" || status=$?
    [ "$status" -ne 77 ] || { cat "$work/err" >&2; exit 77; }
    failed=''
    if [ "$status" -eq 0 ] && json=$(grep "^$system tried " "$work/raw" | tail -n 1) && [ -n "$json" ]; then
        # (A row that does not parse is a limit too: the parser's last line is its cause.)
        row=$(printf '%s' "${json#"$system tried "}" | python3 "$adapter" row 2>"$work/parse") || row="$size $nodes $memory limit the adapter's row did not parse: $(tail -n 1 "$work/parse" | cut -c1-300)$mark"
    else
        # (The machines did not come up or did not answer, before any reading: compare.sh's fail names the step, and its consoles are the rest.)
        step=$(grep '^compare.sh: FAIL: ' "$work/err" | tail -n 1 | cut -c1-300)
        step=${step#compare.sh: FAIL: }
        said=$(tr -cd '[:print:]\n' <"$work/err" | grep -v '^==>' | grep -v '^$' | grep -v '^compare.sh: FAIL: ' | tail -n 4 | paste -sd';' | cut -c1-500)
        row="$size $nodes $memory limit no readings: ${step:-the machines did not run it} | $said$mark"
    fi
    case $row in "$size $nodes $memory limit "*) failed=1 ;; esac
    echo "$row" >>"$out"
    echo "$row"
    [ -z "$failed" ] || { tail -n 8 "$work/err" >&2; exit 1; }
done
