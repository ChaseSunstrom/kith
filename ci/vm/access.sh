# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test access: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # The cluster's admin is an Identity like any other: its Role becomes one that may
            # read and delete everything and apply only Roles and RoleBindings, and a RoleBinding
            # of its own (maps-root) lets it apply ConfigMaps, until that is deleted.
            printf '%s' '[{"apiVersion":"kith.dev/v1","kind":"Role","metadata":{"name":"cluster-admin"},"spec":{"rules":[{"kinds":["*"],"verbs":["get","list","watch","delete","exec"]},{"kinds":["Role","RoleBinding"],"verbs":["apply"]}]}},
{"apiVersion":"kith.dev/v1","kind":"Role","metadata":{"name":"maps"},"spec":{"rules":[{"kinds":["ConfigMap"],"verbs":["apply"]}]}},
{"apiVersion":"kith.dev/v1","kind":"RoleBinding","metadata":{"name":"maps-root"},"spec":{"role":"maps","subjects":["root"]}}]' >"$work/grant.json"
            api 1 POST /v1/apply "$work/grant.json" >/dev/null || fail "the admin's Roles were not applied"
            # Two writers, through n2 and through n3: numbered ConfigMaps, and a note of every
            # attempt, as for chaos: NAME NODE BEGUN ANSWERED ok|no.
            writer() { # N
                i=0 patience=5
                while ! [ -e "$work/stop" ]; do
                    i=$((i + 1))
                    printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"a%s-%s"},"spec":{"data":{"n":"a%s-%s"}}}]' "$1" "$i" "$1" "$i" >"$work/a$1.json"
                    begun=$(date +%s.%N) said=no
                    ! api "$1" POST /v1/apply "$work/a$1.json" >/dev/null 2>&1 || said=ok
                    echo "a$1-$i $1 $begun $(date +%s.%N) $said" >>"$work/writes$1"
                    sleep 0.1
                done
            }
            acked() { cat "$work"/writes? 2>/dev/null | awk -v n="$1" '$5 == "ok" && $2 == n' | wc -l; }
            monitor() { echo "$2" | socat - "unix-connect:$work/keys$1" >/dev/null; } # N COMMAND
            writers=''
            for n in 2 3; do
                writer "$n" &
                vms="$vms $!" writers="$writers $!"
            done
            waited=0
            until [ "$(acked 2)" -ge 10 ] && [ "$(acked 3)" -ge 10 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the admin's writes through n2 and n3 were not acknowledged: $(acked 2) and $(acked 3)"
                sleep 1
            done
            echo "vm.sh: the admin writing through n2 and n3" >&2

            # n2 is cut off from the others (its card on the cluster's network unplugged), so
            # it does not hear of the deletion; the RoleBinding is deleted through n1, whichever
            # of n1 and n3 leads then. (Had n2 led, it leads no more once it is plugged back:
            # its write is then passed on to the one that does, and refused there all the same.)
            monitor 2 'set_link lan off'
            sleep 2
            begun=$(date +%s.%N)
            (patience=30 && api 1 DELETE /v1/resources/RoleBinding/maps-root) >/dev/null || fail "the RoleBinding maps-root was not deleted"
            echo "$begun $(date +%s.%N)" >"$work/deleted"
            # A write through n2, which still holds the RoleBinding and lets it through; it
            # waits for the leader until the card is plugged back, and is refused there.
            printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"late"},"spec":{"data":{"n":"late"}}}]' >"$work/late.json"
            curl -s -o "$work/late" -w '%{http_code}' --max-time 40 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
                --resolve "kith:$((port + 2)):127.0.0.1" -H 'Content-Type: application/json' --data-binary "@$work/late.json" \
                "https://kith:$((port + 2))/v1/apply" >"$work/late.code" &
            late=$!
            sleep 3
            monitor 2 'set_link lan on'
            wait "$late" || true
            sleep 5
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
    return {r["metadata"]["name"] for r in found if r["kind"] == "ConfigMap"}
lists = [held(n) for n in (1, 2, 3)]
writes = {name: (float(begun), float(answered), said) for name, node, begun, answered, said in (line.split() for line in open(f"{work}/writes"))}
begun, deleted = (float(at) for at in open(f"{work}/deleted").read().split())
code, late = open(f"{work}/late.code").read().strip(), open(f"{work}/late").read()
wrong = []
if not lists[0] == lists[1] == lists[2]:
    wrong.append("the nodes hold different writes: " + ", ".join(str(len(held)) for held in lists))
acked = {name for name, (at, answered, said) in writes.items() if said == "ok"}
lost = sorted(acked - lists[0])
if lost:
    wrong.append(f"{len(lost)} acknowledged writes are not held: {lost[:5]}")
after = [name for name, (at, answered, said) in writes.items() if at > deleted]
taken = sorted(name for name in after if writes[name][2] == "ok")
if taken:
    wrong.append(f"{len(taken)} writes begun after the deletion was acknowledged were acknowledged: {taken[:5]}")
kept = sorted(name for name in lists[0] if name == "late" or (name in writes and writes[name][0] > deleted))
if kept:
    wrong.append(f"{len(kept)} writes begun after the deletion was acknowledged are held: {kept[:5]}")
if not after:
    wrong.append("no write was begun after the deletion: the test showed nothing")
if code != "422" or "decided again" not in late:
    wrong.append(f"the write n2 let through while it was cut off was not refused where the log is kept: {code} {late[:300]}"
                 + (" (it waited on a log no majority held: n2 may have led when it was cut off, and kept leading past the 10 s it waits; run again)" if code == "500" and "no leader" in late else ""))
if wrong:
    sys.exit("; ".join(wrong))
print(f"{len(acked)} writes acknowledged of {len(writes)} tried, each held by all three nodes; none of the {len(after)} begun after the deletion was acknowledged or kept, and the one n2 let through while cut off was refused by the leader")
' "$work" 2>"$work/wrong"); do
                tries=$((tries + 1))
                [ "$tries" -lt 60 ] || fail "after the deletion: $(cat "$work/wrong")"
                sleep 1
            done
            ! grep -al 'Kernel panic\|panicked at' "$work"/n?.log || fail "a node panicked"
            echo "vm.sh: ok: three nodes; the admin writing through n2 and n3 by a RoleBinding deleted through n1 while n2 was cut off: $said"
            exit 0
