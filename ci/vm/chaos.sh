# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test chaos: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # Three writers on this machine, one through each node: numbered ConfigMaps, and
            # a note of every attempt: NAME NODE BEGUN ANSWERED ok|no. (Each node has two
            # cards: the writers come in by the one that is never unplugged.)
            writer() { # N
                # (Not long with each: a cut-off node is tried more than once while it is.
                # One that is given up on and then lands is a write nobody was told of.)
                i=0 patience=3
                while ! [ -e "$work/stop" ]; do
                    i=$((i + 1))
                    printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"w%s-%s"},"spec":{"data":{"n":"w%s-%s"}}}]' "$1" "$i" "$1" "$i" >"$work/w$1.json"
                    begun=$(date +%s.%N) said=no
                    ! api "$1" POST /v1/apply "$work/w$1.json" >/dev/null 2>&1 || said=ok
                    echo "w$1-$i $1 $begun $(date +%s.%N) $said" >>"$work/writes$1"
                    sleep 0.2
                done
            }
            # How many writes were acknowledged: through node N, or (-N) through the others.
            acked() { cat "$work"/writes? 2>/dev/null | awk -v n="${1:-0}" '$5 == "ok" && (n == 0 || (n > 0 && $2 == n) || (n < 0 && $2 != -n))' | wc -l; }
            goes_on() { # WHOSE WHAT: ten more writes acknowledged (through WHOSE, as for acked)
                had=$(acked "$1") waited=0
                until [ "$(acked "$1")" -ge $((had + 10)) ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt $((time / 4)) ] || fail "$2: $(($(acked "$1") - had)) writes acknowledged in $waited s"
                    sleep 1
                done
                echo "vm.sh: $2" >&2
            }
            monitor() { echo "$2" | socat - "unix-connect:$work/keys$1" >/dev/null; } # N COMMAND
            fault() { echo "$1 $2 $(date +%s.%N)" >>"$work/faults"; }                # WHAT N
            writers=''
            for n in 1 2 3; do
                writer "$n" &
                vms="$vms $!" writers="$writers $!"
            done
            goes_on 0 "three nodes, taking writes through each"
            for n in 1 2 3; do goes_on "$n" "writes through n$n"; done

            # Each node in turn (so the leader's turn comes, whichever it is) is cut off from
            # the other two: its card on the cluster's network is unplugged. It still
            # answers this machine, and acknowledges nothing; the other two go on.
            for n in 1 2 3; do
                # (KITH_CHAOS_CUT='info status' cuts nothing, and the test must then fail:
                # that is how it was shown to see a node that goes on acknowledging.)
                monitor "$n" "${KITH_CHAOS_CUT:-set_link lan off}"
                sleep 2
                fault cut "$n"
                goes_on "-$n" "n$n cut off: the other two went on taking writes"
                sleep 15 # (long enough for it to give up on its leader, or on leading)
                # (The writers wait 3 s for an answer and a node 10 s for its leader: one
                # write through the cut-off node is waited for longer than both.)
                printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"cut-%s"},"spec":{"data":{"n":"cut-%s"}}}]' "$n" "$n" >"$work/cut.json"
                ! (patience=20 && api "$n" POST /v1/apply "$work/cut.json") >/dev/null 2>&1 || fail "n$n, cut off from the others, acknowledged a write"
                goes_on "-$n" "n$n still cut off: the other two still taking writes"
                curl -sk -o /dev/null --max-time 5 "https://127.0.0.1:$((port + n))/v1/ca" || fail "n$n, cut off from the others, did not answer this machine either: the test cut the wrong card"
                fault heal "$n"
                monitor "$n" 'set_link lan on'
                goes_on "$n" "n$n back with the others: writes through it again"
            done

            # Each node in turn loses power: reset by the hypervisor in the middle of
            # writes, with nothing flushed that was not flushed already. The other two go
            # on; it starts again and is one of the three again.
            # (What a guest had flushed is in its disk's file whatever happens to the guest:
            # a disk that lies about a flush, or tears a write, is not what this shows.)
            for n in 1 2 3; do
                monitor "$n" system_reset
                fault reset "$n"
                goes_on "-$n" "n$n lost power: the other two went on taking writes"
                goes_on "$n" "n$n started again: writes through it again"
            done

            # All three lose power at the same moment, in the middle of writes: now no
            # node has what another lost, and what was acknowledged is there only if a
            # majority had it on disk before it was.
            for n in 1 2 3; do monitor "$n" system_reset; done
            fault dark 0
            for n in 1 2 3; do goes_on "$n" "all three lost power at once: n$n started again, writes through it"; done
            : >"$work/stop"
            # shellcheck disable=SC2086 # (a list of process numbers)
            wait $writers

            # Each node's own list, until the three say the same; then against the notes.
            cat "$work"/writes? >"$work/writes"
            lists() { for n in 1 2 3; do api "$n" GET '/v1/resources?kind=ConfigMap' >"$work/list$n.json" 2>/dev/null || { echo "n$n did not answer" >"$work/wrong"; return 1; }; done; }
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
    wrong.append("the nodes hold different writes: " + ", ".join(str(len(held)) for held in lists))
for n, has in enumerate(lists, 1):
    lost = sorted(acked - set(has))
    if lost:
        wrong.append(f"n{n} lacks {len(lost)} acknowledged writes: {lost[:5]}")
    if any(name != value for name, value in has.items()):
        wrong.append(f"n{n} holds a write with another one in it")
faults = [line.split() for line in open(f"{work}/faults")]
cuts = {node: float(at) for what, node, at in faults if what == "cut"}
refused = 0
for what, node, healed in faults:
    if what == "heal":
        # (Begun while it was cut off; acknowledged while it still was, which it cannot be.
        # One that hangs until the card is back and is acknowledged then is as it should be.)
        tried = [(name, said, float(answered)) for name, at, begun, answered, said in writes
                 if at == node and cuts[node] < float(begun) < float(healed)]
        inside = [name for name, said, answered in tried if said == "ok" and answered < float(healed)]
        refused += sum(1 for name, said, answered in tried if said == "no")
        if inside:
            wrong.append(f"n{node} acknowledged {len(inside)} writes while it was cut off: {inside[:5]}")
        if not tried:
            wrong.append(f"nothing was tried through n{node} while it was cut off: the test showed nothing")
if wrong:
    sys.exit("; ".join(wrong))
print(f"{len(acked)} writes acknowledged of {len(writes)} tried, each of them held by all three nodes; {refused} tried through a cut-off node, none acknowledged")
' "$work" 2>"$work/wrong"); do
                tries=$((tries + 1))
                [ "$tries" -lt 60 ] || fail "after the faults: $(cat "$work/wrong")"
                sleep 1
            done
            ! grep -al 'Kernel panic\|EXT4-fs error\|panicked at' "$work"/n?.log || fail "a node panicked, or its file system was found broken"
            [ "$(starts 1 a)$(starts 2 a)$(starts 3 a)" = 333 ] || fail "not every node started exactly three times: the resets did not happen as meant"
            echo "vm.sh: ok: three nodes; each in turn cut off from the other two, which went on taking writes while it acknowledged none, each in turn reset in the middle of writes and back as one of the three, and all three reset at the same moment: $said"
            exit 0
