#!/bin/sh
# Phase 2 exit check (PLAN): the mesh adds at most 0.3 ms to the round trip.
#
#     sh ci/mesh_rtt.sh [MAX_MS]        # default 0.3; PINGS=200 pings per leg
#
# Two network namespaces joined by a veth, in a user namespace of their own (no root, nothing
# changed on the machine). The WireGuard mesh is brought up between them with the kith-mesh e2e
# test program (the same tool e2e.sh uses), then the median round trip over the veth is taken
# against the median over the mesh, and the script fails if the mesh is more than MAX_MS slower.
# A veth is not a LAN, so this is the mesh's own cost (crypto, the extra hop through the
# interface), not a wire's. Prints "skipped: ..." and exits 0 where namespaces or WireGuard are missing.
#
# Names here are fixed words with no spaces, and the tool's arguments are split on purpose.
# shellcheck disable=SC2086,SC2046
set -eu
max=${1:-0.3}
pings=${PINGS:-200}
seed=rtt-cluster

if [ -z "${MESH_RTT_INNER:-}" ]; then
    # Outside: check what is needed, build the tool, run this script again in new namespaces.
    unshare -Urnm true 2> /dev/null || { echo "skipped: no unprivileged user namespaces here (unshare -Urnm)"; exit 0; }
    for need in ip ping cargo; do
        command -v $need > /dev/null || { echo "skipped: no $need"; exit 0; }
    done
    root=$(dirname "$0")/..
    tool=$(cd "$root" && cargo test -q -p kith-mesh --test e2e --no-run --message-format=json 2> /dev/null |
        sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n 1)
    [ -x "$tool" ] || { echo "could not build the kith-mesh test program" >&2; exit 1; }
    MESH_RTT_INNER=$tool exec unshare -Urnm sh "$0" "$max"
fi

tool=$MESH_RTT_INNER
mount -t tmpfs none /run
for node in a b; do ip netns add $node; ip -n $node link set lo up; done
ip link add toa netns b type veth peer name tob netns a
ip -n a addr add 10.1.0.1/24 dev tob; ip -n a link set tob up
ip -n b addr add 10.1.0.2/24 dev toa; ip -n b link set toa up
in_() { node=$1; shift; ip netns exec $node "$@"; }

if ! in_ a ip link add probe0 type wireguard 2> /dev/null; then
    echo "skipped: the kernel has no WireGuard here"
    exit 0
fi
in_ a ip link del probe0

private() { printf "%064d" $(($(printf %d "'$1") - 96)); } # a: 00…01, b: 00…02
key_a=$(in_ a $tool up $seed a $(private a))
key_b=$(in_ b $tool up $seed b $(private b))
addr_b=$($tool address $seed b)
members="a,$key_a,10.1.0.1:51820,0,1 b,$key_b,10.1.0.2:51820,0,1"
in_ a $tool peers $seed a $(private a) $members
in_ b $tool peers $seed b $(private b) $members

# Warm up: the first packets wait for the keys to be agreed (and the caches to fill).
in_ a ping -6 -q -c 5 -i 0.3 -W 2 $addr_b > /dev/null || { echo "the mesh does not carry a ping" >&2; exit 1; }
in_ a ping -q -c 20 -i 0.01 10.1.0.2 > /dev/null

median() { # median ADDRESS...: the median of the round trips in ms
    in_ a ping -c $pings -i 0.01 -W 1 "$@" | sed -n 's/.*time=\([0-9.]*\) ms/\1/p' | sort -n |
        awk '{ t[NR] = $1 } END { if (NR < 0.9 * '"$pings"') exit 1; print (NR % 2 ? t[(NR + 1) / 2] : (t[NR / 2] + t[NR / 2 + 1]) / 2) }'
}
base=$(median 10.1.0.2) || { echo "the veth lost too many pings" >&2; exit 1; }
mesh=$(median -6 $addr_b) || { echo "the mesh lost too many pings" >&2; exit 1; }
awk -v base="$base" -v mesh="$mesh" -v max="$max" -v n="$pings" 'BEGIN {
    d = mesh - base
    printf "median of %d pings: veth %.3f ms, mesh %.3f ms, difference %+.3f ms (limit %s ms)\n", n, base, mesh, d, max
    if (d > max) { print "FAIL: the mesh costs more than the plan allows"; exit 1 }
    print "ok"
}'
