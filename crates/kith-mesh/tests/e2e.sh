#!/bin/sh
# Names here are fixed words with no spaces, lists are split on purpose, and key_NODE and
# addr_NODE are set through eval.
# shellcheck disable=SC2086,SC2046,SC2154
# Run by e2e.rs inside a new user, network and mount namespace, with the test program
# (the tool) as $1. Three namespaces on a line, a - b - c: b is the edge node.
set -eu
tool=$1
seed=e2e-cluster
# A place for `ip netns` to keep its namespaces, seen by nobody else.
mount -t tmpfs none /run
for node in a b c; do ip netns add $node; ip -n $node link set lo up; done
wire() { # wire NODE OTHER NET: a cable between the two, NET.1 on NODE and NET.2 on OTHER
    ip link add to$2 netns $1 type veth peer name to$1 netns $2
    ip -n $1 addr add $3.1/24 dev to$2; ip -n $1 link set to$2 up
    ip -n $2 addr add $3.2/24 dev to$1; ip -n $2 link set to$1 up
}
wire a b 10.1.0
wire b c 10.2.0
in_() { node=$1; shift; ip netns exec $node "$@"; }
in_ b sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'

private() { printf "%064d" $(($(printf %d "'$1") - 96)); } # a: 00…01, b: 00…02
for node in a b c; do
    eval "key_$node=\$(in_ $node $tool up $seed $node $(private $node))"
    eval "addr_$node=\$($tool address $seed $node)"
done
# Where each node says it is: a and c have never heard of a way to each other.
members() { # members A_REACHES_C: the member list, with whether a and c reach each other
    echo "a,$key_a,10.1.0.1:51820,0,$1 b,$key_b,$2:51820,1,1 c,$key_c,10.2.0.2:51820,0,$1"
}
mesh() { # mesh A_REACHES_C
    in_ a $tool peers $seed a $(private a) $(members $1 10.1.0.2)
    in_ b $tool peers $seed b $(private b) $(members 1 10.1.0.2)
    in_ c $tool peers $seed c $(private c) $(members $1 10.2.0.1)
}
# (Three tries: the first packet also has to wait for the keys to be agreed.)
reaches() { in_ $1 ping -6 -q -c 3 -i 0.3 -W 1 $2 > /dev/null; }

mesh 1
reaches a $addr_b
reaches c $addr_b
reaches b $addr_a
if reaches a $addr_c; then echo "a reached c with no path between them"; exit 1; fi
# b has agreed on keys with a, and a's interface says so.
in_ a $tool show $seed a $(private a) | grep "^$key_b " | grep -q "Some(.*) Some("

# a and c give up on each other: through b it goes, both ways.
mesh 0
reaches a $addr_c
reaches c $addr_a
# And back to direct (still no path): b is not left passing on what is not asked of it.
mesh 1
if reaches a $addr_c; then echo "a still reaches c"; exit 1; fi
reaches a $addr_b

# Setting the same again changes nothing; down takes the interface away, and only it.
in_ a $tool down $seed a $(private a)
if in_ a ip link show kith0 2> /dev/null; then echo "kith0 is still there"; exit 1; fi
in_ a ip link show tob > /dev/null
# An interface of that name that is something else is refused, and left.
in_ a ip link add kith0 type veth peer name other
if in_ a $tool up $seed a $(private a) 2> /dev/null; then echo "took over a veth"; exit 1; fi
in_ a ip link show kith0 | grep -q kith0
