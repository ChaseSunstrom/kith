# shellcheck shell=sh
# shellcheck disable=SC2034,SC2046,SC2086,SC2154 # (names the driver and its parts share; lists of words)
# Sourced by ci/vm.sh for --test alone: it runs inside the driver's shell, with its variables and
# functions (machines.sh's: stick, blank, drive, lan, vm, hears, installed, fail); not a script to
# run alone.
#
# Two machines the installer made, with their state unencrypted (a node runs alone only from
# state it can open by itself): n1 is a control node, n2 a worker with `alone: run`. A Workload of
# one replica (mover) and a Job (held) are both placed on n2. Both machines are stopped, and only
# n2 is started again while n1 is still off: the setting is read when kithd starts, so the worker
# runs alone from its own copy of the store after about 30 s. Then the replica runs there, and the
# Job is held. n1 is started again: the worker catches up, and the replica, placed on n1 meanwhile,
# is stopped on n2.
# (The scenario's own budget: at least 1800 s for its VMs, whatever --time says; its waits stop it sooner.)
[ "$time" -gt 1800 ] || time=1800

# The cluster's admin, through node N: N METHOD PATH [FILE with JSON to send].
api() {
    curl -sf --max-time "${patience:-10}" --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
        --resolve "kith:$((port + $1)):127.0.0.1" -X "$2" ${4:+-H 'Content-Type: application/json' --data-binary "@$4"} \
        "https://kith:$((port + $1))$3"
}
field() { python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]], end="")' "$1"; }
until_ok() { # WHAT COMMAND...: tried each second until it holds
    what=$1
    shift
    waited=0
    until "$@" >/dev/null 2>&1; do
        waited=$((waited + 1))
        [ "$waited" -lt "${limit:-$time}" ] || fail "waited $waited s for: $what"
        sleep 1
    done
}
now() { date +%s.%N; }
since() { python3 -c 'import sys; print(round(float(sys.argv[1]) - float(sys.argv[2]), 1))' "$1" "$2"; } # seconds from $2 to $1

# Node N's machine from its disk, on the cluster's network, with no TPM: its state is plain.
start() { # N LOG
    vm "$2" -m 1024 -pidfile "$work/$2.pid" $(drive "n$1.disk") $(lan "$1")
    eval "boot$1=\$vm"
}
# Processes that ended (and were waited for) are taken out of $vms: the EXIT trap signals
# what is left there, and a number that is free by then may be another process's.
forget() { # PID...
    kept=''
    for p in $vms; do
        case " $* " in *" $p "*) ;; *) kept="$kept $p" ;; esac
    done
    vms=$kept
}
install_plain() { # N [TOKEN]: the installer on a blank disk, with its state not encrypted (join the cluster at n1 by TOKEN)
    {
        printf 'disk: only\nhostname: n%s\nip: 10.9.0.%s/24\n' "$1" "$1"
        [ -z "${2:-}" ] || printf 'join:\n  address: 10.9.0.1:7443\n  token: %s\n' "$2"
    } >"$work/n$1.yaml"
    stick "n$1" "$work/n$1.yaml"
    blank "n$1"
    vm "install-n$1" $(drive "n$1.stick") $(drive "n$1.disk")
    installed "install-n$1" vdb
}
known() { api 1 GET "/v1/resources/Node/$1"; }
# Node N's view of the cluster is sent (its Node says so) and it is told to run alone.
viewed() { api 1 GET /v1/resources/Node/n2 | python3 -c 'import json, sys; sys.exit(0 if (json.load(sys.stdin).get("status") or {}).get("view") is True else 1)'; }
# The header lines on n2's disk: each start of a unit on the worker adds one (`kith get node -w`
# prints its table once under a header), once written to the disk. The control node is down when
# this is read, so the worker's own disk is what is looked at.
headers() { grep -ao 'KIND  *NAMESPACE' "$work/n2.disk" | wc -l; }
# On a failed wait: both nodes' logs are copied into the lane's .fm-scratch, to read after the run.
keep() { mkdir -p "$root/.fm-scratch" && for n in n1b n2b; do cp "$work/$n.log" "$root/.fm-scratch/alone-$n.log"; done; }
# PATH NODE: a unit of the resource is ready on NODE (the replica runs there).
on() { api 1 GET "$1" | python3 -c '
import json, sys
r = json.load(sys.stdin)
units = (r.get("status") or {}).get("containers") or []
sys.exit(0 if any(u.get("node") == sys.argv[1] and u.get("ready") for u in units) else 1)' "$2"; }
# PATH NODE: no unit of the resource is on NODE.
off() { api 1 GET "$1" | python3 -c '
import json, sys
r = json.load(sys.stdin)
units = (r.get("status") or {}).get("containers") or []
sys.exit(0 if not any(u.get("node") == sys.argv[1] and u.get("ready") for u in units) else 1)' "$2"; }
# The Node's `alone` status: since when the node ran alone, and until when a leader answered.
recorded() { api 1 GET /v1/resources/Node/n2 | python3 -c '
import json, sys
alone = (json.load(sys.stdin).get("status") or {}).get("alone") or {}
sys.exit(0 if alone.get("since") and alone.get("until") else 1)'; }

# The first node starts the cluster; n2 joins as a worker.
install_plain 1
start 1 n1
hears n1 'sends this token to /v1/claim does: kith1.'
token=$(grep -ao 'sends this token to /v1/claim does: kith1\.[0-9a-f.]*' "$work/n1.log")
tries=0
until claimed=$(curl -sfk --max-time 10 -H 'Content-Type: application/json' -d "{\"token\":\"${token##* }\",\"name\":\"root\"}" "https://127.0.0.1:$((port + 1))/v1/claim"); do
    tries=$((tries + 1))
    [ "$tries" -lt 150 ] || fail "n1's cluster could not be claimed"
    sleep 0.2
done
for part in ca cert key; do
    printf '%s' "$claimed" | (umask 077 && field "$part" >"$work/$part.pem") || fail "the claim was refused: $claimed"
done
workers=$(api 1 POST '/v1/tokens?trust=worker' | field token) || fail "no join token for a worker"
install_plain 2 "$workers"
start 2 n2
until_ok "n2 in the cluster" known n2
until_ok "n2 is sent a view" viewed
echo "vm.sh: two nodes installed with their state unencrypted: n1 a control node, n2 a worker" >&2

# n2 is told to run alone when no leader answers. Its Node keeps the rest of its spec.
api 1 GET /v1/resources/Node/n2 | python3 -c '
import json, sys
node = json.load(sys.stdin)
json.dump([{"apiVersion": "kith.dev/v1", "kind": "Node", "metadata": {"name": "n2"}, "spec": {**node["spec"], "alone": "run"}}], open(sys.argv[1], "w"))
' "$work/alone.json" || fail "n2's Node was not read"
api 1 POST /v1/apply "$work/alone.json" >/dev/null || fail "n2 was not told to run alone"

# A replica (mover) and a Job (held), both placed on the worker. Their units print one header
# each time they start.
printf '%s\n' '[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"mover"},"spec":{"replicas":1,"placement":{"require":{"kith.dev/trust":"worker"}},"template":{"exec":[{"name":"watch","command":["/bin/kith","get","node","-w"]}]}}},{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"held"},"spec":{"retries":0,"placement":{"require":{"kith.dev/trust":"worker"}},"template":{"exec":[{"name":"watch","command":["/bin/kith","get","node","-w"]}]}}}]' >"$work/apply.json"
api 1 POST /v1/apply "$work/apply.json" >/dev/null || fail "the Workload and the Job were not applied"
until_ok "the replica runs on n2" on /v1/resources/Workload/default/mover n2
echo "vm.sh: the replica runs on the worker, with the control node up" >&2

# (The worker's disk takes its logs within about 40 s: the count of headers there is what the
# power cut leaves, one for the replica's start and one for the Job's.)
sleep 40
before=$(headers)
[ "$before" -ge 2 ] || fail "the replica and the Job did not both start on the worker's disk: $before header(s)"

# The power is cut on both, as if unplugged, and only the worker is started again: its setting
# is read at its start, with no control node in reach.
kill -9 "$(cat "$work/n1.pid")" "$(cat "$work/n2.pid")"
wait "$boot1" "$boot2" 2>/dev/null || true
forget "$boot1" "$boot2"
sleep 3
for n in 1 2; do
    ! kill -0 "$(cat "$work/n$n.pid")" 2>/dev/null || fail "n$n still runs after the power was cut"
done
start 2 n2b
echo "vm.sh: the worker started again with its control node off" >&2

# Not before its 30 s are up, and then it says so, with the risks, and runs alone.
sleep 20
! grep -aqF 'running alone from this node' "$work/n2b.log" || fail "the worker ran alone before its 30 s were up"
hears n2b 'running alone from this node'
hears n2b 'A replica moved off this node meanwhile runs twice'
hears n2b 'a Job is not started alone'
echo "vm.sh: the worker says it runs alone, with its risks, and no leader in reach" >&2

# The replica is started from the worker's copy (one more header on its disk); the Job is held
# (no header for it), and that holds for as long as the worker runs alone.
waited=0
until [ "$(headers)" -gt "$before" ]; do
    waited=$((waited + 1))
    [ "$waited" -lt 300 ] || { keep; fail "waited $waited s for: the replica is started again on the worker, alone"; }
    sleep 1
done
sleep 45
after=$(headers)
[ "$after" -eq $((before + 1)) ] || fail "the Job ran alone, or the replica started more than once: $before header(s) before the power cut, $after now"
echo "vm.sh: alone, the replica starts on the worker and the Job is held" >&2

# The control node is back: a leader answers, the worker catches up, and says since when it ran
# alone and until when. (The status records that; it is not cleared.)
start 1 n1b
hears n1b 'kithd: node n1 serving other nodes'
waited=0
until grep -aqF 'a leader answers: this node ran alone since' "$work/n2b.log"; do
    waited=$((waited + 1))
    [ "$waited" -lt 300 ] || { keep; fail "waited $waited s for: the worker's alone status is written by a leader"; }
    sleep 1
done
until_ok "n2's status says since when it ran alone, and until when" recorded
echo "vm.sh: the leader answered: n2's status: $(api 1 GET /v1/resources/Node/n2 | python3 -c 'import json, sys; print(json.dumps((json.load(sys.stdin).get("status") or {}).get("alone")))')" >&2

# The replica is placed on the control node instead: the worker stops the copy it has.
printf '%s\n' '[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"mover"},"spec":{"replicas":1,"placement":{"require":{"kith.dev/trust":"control"}},"template":{"exec":[{"name":"watch","command":["/bin/kith","get","node","-w"]}]}}}]' >"$work/move.json"
api 1 POST /v1/apply "$work/move.json" >/dev/null || fail "the replica was not placed on the control node"
until_ok "the replica runs on n1" on /v1/resources/Workload/default/mover n1
until_ok "the replica the leader does not place on n2 is stopped there" off /v1/resources/Workload/default/mover n2
echo "vm.sh: the replica runs on n1 and is stopped on n2" >&2

! grep -al 'Kernel panic' "$work"/*.log || fail "a kernel panicked"
echo "vm.sh: ok: two nodes, the worker set to run alone; with the control node off and the worker started again, it said so after 30 s with its risks, started the replica from its copy and held the Job; the control node back, it said since when it ran alone and until when, and the replica the leader placed on the control node was stopped on the worker"
exit 0
