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
            echo "vm.sh: $said" >&2

            # What a taken leader could append, and no more (T-0848): these nodes run the image of a kithd
            # built with the feature forge, whose POST /v1/forge puts one entry in the log as it is, with
            # none of the checks a request gets before it is written. Only what every node does with an
            # entry when it applies it is between it and the stores: three entries it was not asked for,
            # once the cluster says signing is required and the admin's key is in it.
            # The nodes check signed entries once the store is in format 4, which the leader moves it to
            # when every member reads it.
            # Each says on its console that it is a forge build, which a build that ships never does.
            for log in "$work"/n?.log; do
                grep -aq 'kithd: built with forge: POST /v1/forge appends unchecked entries; never ship this' "$log" || fail "$log has no line saying kithd is built with forge"
            done
            tries=0
            until grep -aq 'every node checking them' "$work"/n?.log; do
                tries=$((tries + 1))
                [ "$tries" -lt 300 ] || fail "the store was not moved to format 4, where every node checks signed entries"
                sleep 1
            done
            # The admin's key (Ed25519), made here; the cluster's id is the print of its CA.
            adminseed=$(head -c 32 /dev/urandom | xxd -p -c 64)
            printf '302e020100300506032b657004220420%s' "$adminseed" | xxd -r -p >"$work/admin.der"
            adminkey=$(openssl pkey -inform DER -in "$work/admin.der" -pubout -outform DER | tail -c 32 | xxd -p -c 64)
            clusterid=$(openssl x509 -in "$work/ca.pem" -outform DER | sha256sum | cut -d ' ' -f 1)
            [ -n "$adminkey" ] || fail "no admin key to sign with"
            [ -n "$clusterid" ] || fail "no cluster id to sign with"
            # A body of resources, in $work/BODY.json.
            configmap() { # NAME VALUE
                printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"%s"},"spec":{"data":{"n":"%s"}}}]' "$1" "$2"
            }
            # An entry the admin signed (or not), in $work/NAME.entry; its nonce is the number, in 32 hex digits.
            expires=$(($(date +%s) + 300))
            entry() { # NAME NONCE EXPIRES-PLUS SIGNED-BODY [CARRIED-BODY [COMMAND-BODY]]
                python3 "$root/ci/vm/forge_entry.py" "$work/admin.der" "$clusterid" "$((expires + $3))" "$(printf '%032x' "$2")" "$work/$4.json" ${5:+"$work/$5.json"} ${6:+"$work/$6.json"} \
                    >"$work/$1.entry" || fail "the entry $1 was not made"
            }
            # The entry appended by whichever node leads (a follower says it does not): its answer, in $work/forged.json.
            forge() { # NAME
                for n in 1 2 3; do
                    api "$n" POST /v1/forge "$work/$1.entry" >"$work/forged.json" 2>/dev/null && return 0
                done
                fail "no node appended the entry $1"
            }
            applied() { forge "$1"; grep -q '"applied":true' "$work/forged.json" || fail "the entry $1 was not applied: $(cat "$work/forged.json")"; }
            # Each node's resources of a kind as KIND/NAME=SPEC, until the three say the same.
            held() { # KIND: in $work/held, one line a resource; fails unless the three nodes agree
                for n in 1 2 3; do
                    api "$n" GET "/v1/resources?kind=$1" 2>/dev/null | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in sorted(found, key=lambda r: r["metadata"]["name"]):
    print(r["kind"] + "/" + r["metadata"]["name"] + "=" + json.dumps(r["spec"], sort_keys=True))
' >"$work/held$n" || return 1
                done
                cmp -s "$work/held1" "$work/held2" && cmp -s "$work/held1" "$work/held3" && cp "$work/held1" "$work/held"
            }
            agreed() { # KIND [REGEX]: the three nodes hold the same of KIND, and REGEX is in it
                tries=0
                until held "$1" && { [ -z "${2:-}" ] || grep -q -- "$2" "$work/held"; }; do
                    tries=$((tries + 1))
                    [ "$tries" -lt 60 ] || fail "the nodes do not agree on $1 holding $2: $(head -c 300 "$work/held1") | $(head -c 300 "$work/held2") | $(head -c 300 "$work/held3")"
                    sleep 1
                done
            }
            # Where the cluster's Role may apply a Cluster, then the Cluster of the admin's key (open, the first
            # key is written unsigned), then the entry the admin signs to turn signing on: required.
            printf '%s' '[{"apiVersion":"kith.dev/v1","kind":"Role","metadata":{"name":"cluster-admin"},"spec":{"rules":[{"kinds":["*"],"verbs":["get","list","watch","delete","exec"]},{"kinds":["Role","RoleBinding","Cluster"],"verbs":["apply"]}]}}]' >"$work/regrant.json"
            api 1 POST /v1/apply "$work/regrant.json" >/dev/null || fail "the admin was not allowed to apply a Cluster"
            printf '[{"apiVersion":"kith.dev/v1","kind":"Cluster","metadata":{"name":"home"},"spec":{"adminKey":"%s"}}]' "$adminkey" >"$work/open.json"
            api 1 POST /v1/apply "$work/open.json" >/dev/null || fail "the Cluster with the admin's key was not applied"
            printf '[{"apiVersion":"kith.dev/v1","kind":"Cluster","metadata":{"name":"home"},"spec":{"adminKey":"%s","signing":"required"}}]' "$adminkey" >"$work/required.json"
            entry required 1 0 required
            applied required
            agreed Cluster '"signing": "required"'
            echo "vm.sh: signing required, by an entry the admin signed" >&2
            # Two entries the admin signed, written by the leader, and applied on all three nodes.
            configmap genuine 1 >"$work/first.json"
            configmap genuine 2 >"$work/second.json"
            entry first 2 1 first
            entry second 3 2 second
            applied first
            applied second
            agreed ConfigMap 'ConfigMap/genuine=.*"n": "2"'
            # The audit log's refusals are held to a number a minute: begin a minute of our own.
            sleep $((61 - $(date +%s) % 60))
            # (1) a bare RoleBinding, which no one signed.
            printf '{"Apply":{"resources":[{"apiVersion":"kith.dev/v1","kind":"RoleBinding","metadata":{"name":"forged-bare"},"spec":{"role":"cluster-admin","subjects":["mallory"]}}],"at":0}}' >"$work/bare.entry"
            forge bare
            grep -q '"applied":false' "$work/forged.json" || fail "a bare RoleBinding was applied: $(cat "$work/forged.json")"
            # (2) a Signed entry whose body was changed: what the admin signed is a ConfigMap, what it carries a RoleBinding.
            configmap harmless 1 >"$work/harmless.json"
            printf '[{"apiVersion":"kith.dev/v1","kind":"RoleBinding","metadata":{"name":"forged-changed"},"spec":{"role":"cluster-admin","subjects":["mallory"]}}]' >"$work/changed.json"
            entry changed 4 3 harmless changed
            forge changed
            grep -q '"applied":false' "$work/forged.json" || fail "a signed entry with its body changed was applied: $(cat "$work/forged.json")"
            # (3) a Signed entry with a replayed nonce: the first of the two ConfigMaps, which the second has since replaced.
            cp "$work/first.entry" "$work/replayed.entry"
            forge replayed
            grep -q '"applied":false' "$work/forged.json" || fail "a signed entry with a nonce taken was applied: $(cat "$work/forged.json")"
            # (4) the signature kept whole, and the body it signed, but a command that is not what they make:
            # the check of the signature passes, and what refuses it is the one that derives the command from the request.
            entry swapped 5 4 harmless harmless changed
            forge swapped
            grep -q '"applied":false' "$work/forged.json" || fail "a signed entry with another command than its body makes was applied: $(cat "$work/forged.json")"
            # (5) a bare Patch of a Node's certificate (a taken leader would make a key its own): what a node
            # says of itself is signed by its key (`own_writes`), so a bare one is refused at apply.
            printf '{"Patch":{"statuses":[["Node/n2",{"certificate":"00"}]]}}' >"$work/node.entry"
            forge node
            grep -q '"applied":false' "$work/forged.json" || fail "a bare Patch of a Node's certificate was applied: $(cat "$work/forged.json")"
            # Each node refused all five at apply, and wrote it in its audit log.
            audited() { # N WHO WHAT WHY
                api "$1" GET '/v1/audit?tail=200' 2>/dev/null | python3 -c '
import json, sys
who, what, why = sys.argv[1:4]
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("entries", [])
sys.exit(0 if any(e["verb"] == "signed" and not e["ok"] and e["who"] == who and any(what in w for w in e["what"]) and why in e.get("error", "") for e in found) else 1)
' "$2" "$3" "$4"
            }
            for n in 1 2 3; do
                tries=0
                until audited "$n" unsigned forged-bare 'a bare write that writes a spec is refused' \
                    && audited "$n" 'local socket' /v1/apply 'over this request' \
                    && audited "$n" 'local socket' /v1/apply "$(printf '%032x' 2) of local socket was seen already" \
                    && audited "$n" 'local socket' /v1/apply 'is not what its method, path and body make' \
                    && api "$n" GET '/v1/audit?tail=200' 2>/dev/null | grep -q "sets a Node's certificate or raft id"; do
                    tries=$((tries + 1))
                    [ "$tries" -lt 60 ] || fail "n$n did not write all five refusals in its audit log: $(api "$n" GET '/v1/audit?tail=6' 2>&1 | head -c 1500)"
                    sleep 1
                done
            done
            # And the three hold what the admin signed, and none of what was forged.
            agreed ConfigMap 'ConfigMap/genuine=.*"n": "2"'
            ! grep -q 'forged\|harmless' "$work/held" || fail "a forged resource is held: $(cat "$work/held")"
            agreed RoleBinding
            ! grep -q 'forged\|mallory' "$work/held" || fail "a forged RoleBinding is held: $(cat "$work/held")"
            # Every bare spec write is refused under required, whatever it writes (T-0850; open kept them: the
            # writers above and the Cluster of the admin's key were bare): a ConfigMap by curl, which the API
            # refuses unsigned, and a ConfigMap Apply and a Delete of the genuine one a taken leader appends, which
            # every node refuses at apply.
            configmap curled 1 >"$work/curled.json"
            ! api 1 POST /v1/apply "$work/curled.json" >/dev/null 2>&1 || fail "a bare curl write of a ConfigMap was taken under required"
            printf '{"Apply":{"resources":[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"forged-map"},"spec":{"data":{"n":"x"}}}],"at":0}}' >"$work/barecm.entry"
            forge barecm
            grep -q '"applied":false' "$work/forged.json" || fail "a bare ConfigMap was applied under required: $(cat "$work/forged.json")"
            printf '{"Delete":{"key":"ConfigMap/genuine"}}' >"$work/baredel.entry"
            forge baredel
            grep -q '"applied":false' "$work/forged.json" || fail "a bare Delete of a ConfigMap was applied under required: $(cat "$work/forged.json")"
            agreed ConfigMap 'ConfigMap/genuine=.*"n": "2"'
            ! grep -q 'forged-map\|curled' "$work/held" || fail "a bare ConfigMap is held under required: $(cat "$work/held")"
            echo "vm.sh: a bare ConfigMap by curl, a bare ConfigMap Apply and a bare Delete, each refused under required" >&2
            # A node's own write, signed by its key (`own_writes`): the scheduler's Volume for a claim the
            # admin signed, applied on all three nodes while signing is required (a bare one is refused).
            printf '[{"apiVersion":"kith.dev/v1","kind":"VolumeClaim","metadata":{"name":"own"},"spec":{"size":"1Gi","provision":true}}]' >"$work/claim.json"
            entry claim 6 5 claim
            applied claim
            agreed Volume '"path": "data"'
            echo "vm.sh: a Volume the scheduler made for a claim, signed by its node's key, held by all three nodes under required" >&2
            echo "vm.sh: five entries the leader was not asked for, a bare RoleBinding, a signed one with its body changed, one with a replayed nonce, one with a command its signed body does not make and a bare Patch of a Node's certificate, each refused by all three nodes at apply" >&2
            ! grep -al 'Kernel panic\|panicked at' "$work"/n?.log || fail "a node panicked"
            echo "vm.sh: ok: three nodes; the admin writing through n2 and n3 by a RoleBinding deleted through n1 while n2 was cut off: $said; and a leader that appended a bare RoleBinding, a signed entry with its body changed, one with a replayed nonce, one with a command its signed body does not make and a bare Patch of a Node's certificate: all three nodes refused each at apply, and hold the same"
            exit 0
