# shellcheck shell=sh
# shellcheck disable=SC2034,SC2046,SC2086,SC2154 # (names the driver and its parts share; lists of words)
# Sourced by ci/vm.sh for --test blackout: it runs inside the driver's shell, with its
# variables and functions (machines.sh's: stick, blank, drive, lan, vm, hears, installed);
# not a script to run alone.
#
# A cluster of four machines made by the installer, each with its state encrypted: n1, n2
# and n3 are control nodes (three voters, so two make a majority), n4 is a worker. n1 and n2
# each have a TPM (swtpm) that holds its key; n3 and n4 have none. The power is cut on all
# four at once, in the middle of writes, and comes back: nobody types anything. n1 and n2
# open their state by their TPMs and elect a leader between them, with n3 still dark; then
# n3 is powered, and it and the worker n4 are handed their keys by the cluster. Every write
# that was acknowledged must be there on all three voters, and what ran on the worker and on
# a control node must run again.
[ "$time" -gt 1800 ] || time=1800
mkdir "$work/tpm1" "$work/tpm2"

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
        [ "$waited" -lt "${limit:-$time}" ] || { ${dump:-:}; fail "waited $waited s for: $what"; }
        sleep 1
    done
}
now() { date +%s.%N; }
since() { python3 -c 'import sys; print(round(float(sys.argv[1]) - float(sys.argv[2]), 1))' "$1" "$2"; } # seconds from $2 to $1

# Node N's machine from its disk, on the cluster's network. n1 and n2 have a TPM, started
# anew each time with the state it had (a TPM keeps its state through a power cut). The
# numbers of what it started are kept in boot$N (the machine's) and tpm$N.
power() { # N LOG
    n=$1 log=$2
    if [ "$n" -lt 3 ]; then
        rm -f "$work/tpm$n.sock"
        swtpm socket --tpm2 --tpmstate "dir=$work/tpm$n" --ctrl "type=unixio,path=$work/tpm$n.sock" >/dev/null 2>&1 &
        tpmpid=$!
        vms="$vms $tpmpid"
        eval "tpm$n=\$tpmpid"
        tries=0
        until [ -S "$work/tpm$n.sock" ]; do
            tries=$((tries + 1))
            [ "$tries" -lt 50 ] || fail "swtpm $n did not start"
            sleep 0.1
        done
        vm "$log" -m 1024 -pidfile "$work/$log.pid" $(drive "n$n.disk") $(lan "$n") \
            -chardev "socket,id=tpmc,path=$work/tpm$n.sock" -tpmdev emulator,id=tpm0,chardev=tpmc -device tpm-tis,tpmdev=tpm0
    else
        vm "$log" -m 1024 -pidfile "$work/$log.pid" $(drive "n$n.disk") $(lan "$n")
    fi
    eval "boot$n=\$vm"
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
install() { # N [TOKEN]: the installer, with its answers on a stick, on a blank disk (join the cluster at n1 by TOKEN)
    {
        printf 'disk: only\nhostname: n%s\nip: 10.9.0.%s/24\nencrypt: true\n' "$1" "$1"
        [ -z "${2:-}" ] || printf 'join:\n  address: 10.9.0.1:7443\n  token: %s\n' "$2"
    } >"$work/n$1.yaml"
    stick "n$1" "$work/n$1.yaml"
    blank "n$1"
    vm "install-n$1" -m 1024 $(drive "n$1.stick") $(drive "n$1.disk")
    installed "install-n$1" vdb
    grep -aqF 'shown this once:' "$work/install-n$1.log" || fail "the installer showed no recovery key for n$1"
}
key() { api "$1" GET "/v1/resources/NodeKey/$2"; } # THROUGH NODE: what the cluster holds of its key
sealed() { key 1 "$1" | grep -q '"sealed": *true'; }
held() { key 1 "$1" | grep -q '"wrapped"'; }
known() { api 1 GET "/v1/resources/Node/$1"; }

# The first node starts the cluster; n2 and n3 join as control nodes, n4 as a worker.
install 1
power 1 n1
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
for n in 2 3; do
    join=$(api 1 POST /v1/tokens | field token) || fail "no join token for a control node"
    install "$n" "$join"
    power "$n" "n$n"
    until_ok "n$n in the cluster" known "n$n"
done
workers=$(api 1 POST '/v1/tokens?trust=worker' | field token) || fail "no join token for a worker"
install 4 "$workers"
power 4 n4
until_ok "n4 in the cluster" known n4
echo "vm.sh: four nodes installed with their state encrypted: n1, n2 and n3 control, n4 a worker" >&2

# Each node's key is held by the others now (and off its own disk); n1 and n2 seal theirs to
# their TPMs, n3 and n4 have none and go on asking.
for n in 1 2 3 4; do until_ok "the cluster holds n$n's key" held "n$n"; done
for n in 1 2; do
    [ "$(api $((3 - n)) POST "/v1/lock/n$n?do=seal" | field seal)" = True ] || fail "n$n could not be told to seal its key"
    hears "n$n" "this machine's TPM holds the key of its state"
    until_ok "n$n's NodeKey says it is sealed" sealed "n$n"
done
for n in 3 4; do ! sealed "n$n" || fail "n$n, which has no TPM, says its key is sealed"; done

# Something runs on the worker, and something on a control node (kith's own client: it
# lists the cluster's nodes and goes on listening for changes).
cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"on-worker"},"spec":{"replicas":1,"placement":{"require":{"kith.dev/trust":"worker"}},"template":{"exec":[
  {"name":"watch","command":["/bin/kith","get","node","-w"]}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"on-control"},"spec":{"replicas":1,"placement":{"require":{"kith.dev/trust":"control"}},"template":{"exec":[
  {"name":"watch","command":["/bin/kith","get","node","-w"]}]}}}]
EOF
api 1 POST /v1/apply "$work/apply.json" >/dev/null || fail "the two Workloads were not applied"
# NAME: ready.
running() { api 1 GET /v1/resources | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    if r["kind"] == "Workload" and r["metadata"]["name"] == sys.argv[1]:
        units = (r.get("status") or {}).get("containers") or []
        sys.exit(0 if units and all(u.get("ready") for u in units) else 1)
sys.exit(1)' "$1"; }
# NAME: how many times its unit has been started. Each start of `kith get node -w` prints the
# table of nodes once, under a header, and later only what changes; a unit's log is a file
# on its node's state that each run appends to, so what the power cut did not take stays,
# and a run after it adds one header.
starts() { api 1 GET "/v1/logs/Workload/default/$1?unit=watch&tail=2000" | grep -o 'KIND  *NAMESPACE' | wc -l; }
started() { [ "$(starts "$1")" -ge 1 ]; }
for name in on-worker on-control; do
    until_ok "$name runs" running "$name"
    until_ok "$name has listed the nodes" started "$name"
done
echo "vm.sh: a Workload runs on the worker and one on a control node" >&2

# Two writers, through n1 and n2 (the worker takes no person's writes): numbered ConfigMaps,
# and a note of every attempt: NAME NODE BEGUN ANSWERED ok|no. (inflightN holds the time a
# write began until it is answered: a write in flight is seen by it.)
writer() { # N
    i=0 patience=3
    while ! [ -e "$work/stop" ]; do
        i=$((i + 1))
        printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"w%s-%s"},"spec":{"data":{"n":"w%s-%s"}}}]' "$1" "$i" "$1" "$i" >"$work/w$1.json"
        begun=$(now) said=no
        echo "$begun" >"$work/inflight$1"
        ! api "$1" POST /v1/apply "$work/w$1.json" >/dev/null 2>&1 || said=ok
        echo "w$1-$i $1 $begun $(now) $said" >>"$work/writes$1"
        : >"$work/inflight$1"
        sleep 0.2
    done
}
# How many writes were acknowledged through node N (0: any), since time S (seconds, 0: ever).
acked() { cat "$work"/writes? 2>/dev/null | awk -v n="${1:-0}" -v s="${2:-0}" '$5 == "ok" && (n == 0 || $2 == n) && $3 > s' | wc -l; }
writers=''
for n in 1 2; do
    writer "$n" &
    vms="$vms $!" writers="$writers $!"
done
waited=0
until [ "$(acked 1)" -ge 20 ] && [ "$(acked 2)" -ge 20 ]; do
    waited=$((waited + 1))
    [ "$waited" -lt 120 ] || fail "writes through n1 and n2: $(acked 1) and $(acked 2) acknowledged in $waited s"
    sleep 1
done
echo "vm.sh: writes taken through n1 and n2" >&2

# The power cut: every machine ends at once, as if unplugged (SIGKILL, nothing flushed that
# was not), then each TPM, which a power cut ends too; at a moment when a write is in flight.
# (The writers go on. The logs of the two Workloads are written to the disks first, 40 s
# ahead: a log that was only in memory when the power went would be short, and a run after
# it could not be told from none. Each one's starts are counted then.)
sleep 40
for name in on-worker on-control; do
    starts "$name" >"$work/starts-$name"
    [ "$(cat "$work/starts-$name")" -ge 1 ] || fail "$name's log cannot be read before the power is cut"
done
pids=''
for n in 1 2 3 4; do pids="$pids $(cat "$work/n$n.pid")"; done
tries=0
until [ -s "$work/inflight1" ] || [ -s "$work/inflight2" ]; do
    tries=$((tries + 1))
    [ "$tries" -lt 3000 ] || fail "no write was in flight in 15 s to cut the power at"
    sleep 0.005
done
cut=$(now)
kill -9 $pids "$tpm1" "$tpm2"
wait "$boot1" "$boot2" "$boot3" "$boot4" "$tpm1" "$tpm2" 2>/dev/null || true
forget "$boot1" "$boot2" "$boot3" "$boot4" "$tpm1" "$tpm2"
sleep 3
for n in 1 2 3 4; do
    ! kill -0 "$(cat "$work/n$n.pid")" 2>/dev/null || fail "n$n still runs after the power was cut"
done
# (Writes tried while it is dark are noted, and fail.) One that began before the cut and was
# answered after it was in flight: the case the test claims.
flying=$(cat "$work"/writes? | awk -v c="$cut" '$3 < c && $4 > c' | wc -l)
[ "$flying" -ge 1 ] || fail "no write was in flight when the power was cut"
echo "vm.sh: the power cut with $flying write(s) in flight" >&2
sleep 2

# And back, all at once but n3: n1, n2 and the worker. Nobody types anything: no console is
# ever written to.
back=$(now)
power 1 n1b
power 2 n2b
power 4 n4b

# n1 and n2 open from their TPMs; n4, with none, asks the cluster and is handed its key.
for n in 1 2; do
    hears "n${n}b" 'this machine'"'"'s TPM gave the key of its state: no node was asked'
    hears "n${n}b" "kithd: node n$n serving other nodes"
    ! grep -aqF 'asking the cluster' "$work/n${n}b.log" || fail "n$n, whose TPM holds its key, asked the cluster for it"
done

# A leader, between two of the three voters: a write is acknowledged (the store takes none
# without one, and a majority), through each of them, with n3 off.
waited=0
until [ "$(acked 1 "$back")" -ge 10 ] && [ "$(acked 2 "$back")" -ge 10 ]; do
    waited=$((waited + 1))
    [ "$waited" -lt $((time / 2)) ] || fail "after the power came back: $(acked 1 "$back") writes acknowledged through n1, $(acked 2 "$back") through n2, in $waited s"
    sleep 1
done
cat "$work"/writes? | sort -k4 -n >"$work/writes.sorted"
leader=$(awk -v s="$back" '$5 == "ok" && $3 > s { print $4; exit }' "$work/writes.sorted")
[ -n "$leader" ] || fail "no write was acknowledged after the power came back"
to_leader=$(since "$leader" "$back")
echo "vm.sh: a leader, $to_leader s after the power came back, with n3 still off: writes acknowledged through both n1 and n2" >&2

# Now n3, the third voter, which has no TPM: it asks the cluster and is handed its key.
power 3 n3b
for n in 3 4; do
    hears "n${n}b" 'asking the cluster for its key'
    hears "n${n}b" 'kithd: init: state on /dev/dm-'
done
hears n3b "kithd: node n3 serving other nodes"
! grep -aqF 'opened with' "$work/n1b.log" "$work/n2b.log" "$work/n3b.log" "$work/n4b.log" || fail "a node was opened with something typed at its console"

# The worker has its key and is in the cluster again; both Workloads run, as new processes
# (their logs hold one more start than before the cut).
# (What the cluster says of them, and of their logs, if they do not.)
dumped() {
    for name in on-worker on-control; do
        echo "== $name: $(cat "$work/starts-$name") starts before the cut, $(starts "$name" 2>&1) now" >&2
        api 1 GET /v1/resources 2>&1 | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    if r["kind"] == "Workload" and r["metadata"]["name"] == sys.argv[1]:
        print(json.dumps(r.get("status")))' "$name" >&2
    done
    grep -aiE 'workload|replica|container|unit|pod|taken|kithd: [a-z-]*-[a-z0-9]*:' "$work"/n?b.log | tail -n 30 >&2
}
restarted() { [ "$(starts "$1")" -ge $(($(cat "$work/starts-$1") + 1)) ]; }
dump=dumped
for name in on-worker on-control; do
    until_ok "$name runs again" running "$name"
    until_ok "$name was started again and listed the nodes" restarted "$name"
done
unset dump
to_ready=$(since "$(now)" "$back")
echo "vm.sh: both Workloads run again, $to_ready s after the power came back" >&2

# Every acknowledged write is there, on each of the three voters, and they hold the same.
: >"$work/stop"
wait $writers
cat "$work"/writes? >"$work/writes"
lists() { for n in 1 2 3; do api "$n" GET '/v1/resources?kind=ConfigMap' >"$work/list$n.json" 2>/dev/null || return 1; done; }
tries=0
until lists && said=$(python3 -c '
import json, sys
work = sys.argv[1]
def held(n):
    found = json.load(open(f"{work}/list{n}.json"))
    found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
    return {r["metadata"]["name"]: r["spec"]["data"]["n"] for r in found if r["kind"] == "ConfigMap"}
lists = [held(n) for n in (1, 2, 3)]
writes = [line.split() for line in open(f"{work}/writes")]
acked = {name for name, node, begun, answered, said in writes if said == "ok"}
wrong = []
if not lists[0] == lists[1] == lists[2]:
    wrong.append("the nodes hold different writes: " + ", ".join(str(len(has)) for has in lists))
for n, has in enumerate(lists, 1):
    lost = sorted(acked - set(has))
    if lost:
        wrong.append(f"n{n} lacks {len(lost)} acknowledged writes: {lost[:5]}")
    if any(name != value for name, value in has.items()):
        wrong.append(f"n{n} holds a write with another one in it")
if wrong:
    sys.exit("; ".join(wrong))
print(f"{len(acked)} writes acknowledged of {len(writes)} tried, each of them held by all three control nodes")
' "$work" 2>"$work/wrong"); do
    tries=$((tries + 1))
    [ "$tries" -lt 90 ] || fail "after the power cut: $(cat "$work/wrong")"
    sleep 1
done
! grep -al 'Kernel panic\|EXT4-fs error\|panicked at' "$work"/n?b.log || fail "a node panicked, or its file system was found broken after the power cut"
echo "vm.sh: ok: four machines with their state encrypted (three control nodes, two with a TPM that holds its key and one without, and a worker without), all with their power cut at once in the middle of writes (with $flying in flight) and started again with nothing typed at any console: n1 and n2 opened from their TPMs and elected a leader $to_leader s after the power came back, with n3 still off; n3 and the worker n4 were handed their keys by the cluster; $said; both Workloads (one on the worker, one on a control node) were started again $to_ready s after the power came back"
exit 0
