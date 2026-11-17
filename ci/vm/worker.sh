# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test worker: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            monitor() { echo "$2" | socat - "unix-connect:$work/keys$1" >/dev/null; } # N COMMAND
            # What listens on port 80 of node N's own network says (the word of the Secret it
            # was given): this machine asks it through the node's card out, and no node's API.
            hears() { curl -s --max-time 5 "http://127.0.0.1:$((port + 4 + $1))/"; } # N
            until_hears() { # N WORD WHAT
                waited=0
                until hears "$1" | grep -q "$2"; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 180 ] || fail "waited for this: $3; n$1 answers on port 80: '$(hears "$1" | head -c 200)'; the Workloads say: mine: $(units Workload mine); other: $(units Workload other)"
                    sleep 1
                done
                echo "vm.sh: $3" >&2
            }
            console_says() { # N PATTERN HOW-OFTEN WHAT: node N's console has said it that often
                waited=0
                until [ "$(grep -ac "$2" "$work/n$1.log")" -ge "$3" ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for n$1 to say: $4"
                    sleep 1
                done
            }
            mine=the-word-of-what-runs-on-the-worker other=the-word-of-what-runs-elsewhere
            # The worker's Node says worker (its token's maker said so) and that it is sent a
            # view (the control node wrote that when it let it in).
            waited=0
            until api 1 GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
node = next(r for r in found if r["kind"] == "Node" and r["metadata"]["name"] == "n2")
status = node.get("status") or {}
sys.exit(0 if node["spec"].get("trust") == "worker" and status.get("view") is True and status.get("address") else 1)
' 2>/dev/null; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "the Node n2 did not come to say that it is a worker sent a view"
                sleep 1
            done
            # A Secret and a Workload that reads it for each kind of node: on the node's own
            # network, answering on port 80 with the word it was given.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Secret","metadata":{"name":"mine"},"spec":{"data":{"word":"$mine"}}},
 {"apiVersion":"kith.dev/v1","kind":"Secret","metadata":{"name":"other"},"spec":{"data":{"word":"$other"}}},
 {"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"mine"},"spec":{"placement":{"require":{"kith.dev/trust":"worker"}},"template":{"containers":[
  {"name":"web","image":"kith.test/pod:1","command":["/bin/pod","say"],"env":[{"name":"PASSWORD","secret":{"name":"mine","key":"word"}}]}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"other"},"spec":{"placement":{"require":{"kith.dev/trust":"control"}},"template":{"containers":[
  {"name":"web","image":"kith.test/pod:1","command":["/bin/pod","say"],"env":[{"name":"PASSWORD","secret":{"name":"other","key":"word"}}]}]}}}]
EOF
            api 1 POST /v1/apply "$work/apply.json" >/dev/null || fail "the two Secrets and their Workloads were not applied"
            until_hears 2 "$mine" "the worker runs what is placed on it, with its Secret"
            until_hears 1 "$other" "the control node runs the other, with its Secret"
            # A person is answered by a control node: the worker has no Identity to know one by.
            code=$(curl -s -o "$work/refused" -w '%{http_code}' --max-time 10 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
                --resolve "kith:$((port + 2)):127.0.0.1" "https://kith:$((port + 2))/v1/resources") || true
            { [ "$code" = 403 ] && grep -q 'answers no one by their rights' "$work/refused"; } || fail "the worker answered the cluster's admin: $code $(cat "$work/refused")"
            # Each node's disk, as this machine has it in a file: the control node's has both
            # words (so looking finds what is on a disk), the worker's has its own, and the
            # word of what runs elsewhere was never written to it.
            waited=0
            until grep -aqF "$other" "$work/n1.raw" && grep -aqF "$mine" "$work/n1.raw" && grep -aqF "$mine" "$work/n2.raw"; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "a Secret is not on the disk of a node that keeps it: looking at the disks finds nothing"
                sleep 1
            done
            ! grep -aqF "$other" "$work/n2.raw" || fail "the Secret of what runs on the control node is on the worker's disk"

            # The control node is paused (nobody answers for it): the worker says so, and goes
            # on running what it runs.
            monitor 1 stop
            console_says 2 'sends no view' 1 "that its control node sends no view"
            hears 2 | grep -q "$mine" || fail "the worker stopped what it ran when its control node went silent"
            echo "vm.sh: the control node paused: the worker says it is sent no view, and runs on" >&2
            # The worker loses power meanwhile: started again from the view it kept, it runs
            # nothing until a control node answers (what was moved off it while it was away
            # is not known to it), as any node that starts with no leader in reach.
            monitor 2 system_reset
            console_says 2 'Kernel command line' 2 "that it starts again"
            console_says 2 'workloads start once this node has' 1 "that it waits for a control node before it runs anything"
            sleep 10
            ! hears 2 | grep -q . || fail "the worker, started with no control node in reach, runs what it ran: $(hears 2)"
            echo "vm.sh: the worker started again with the control node paused: it waits, and runs nothing" >&2
            monitor 1 cont
            until_hears 2 "$mine" "the control node back: the worker follows it again and runs what is placed on it, with its Secret"
            ! grep -aqF "$other" "$work/n2.raw" || fail "the Secret of what runs on the control node is on the worker's disk after it started again"
            # What is deleted leaves the worker.
            api 1 DELETE /v1/resources/Workload/default/mine >/dev/null || fail "the Workload mine was not deleted"
            waited=0
            while hears 2 | grep -q .; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the Workload that was deleted still answers on the worker"
                sleep 1
            done
            # The worker is made an ingress worker: its owner says so in its Node (what the
            # control node that admits a node writes there from a token of `kith node token
            # --worker --ingress`), and it starts again with --ingress, port 443 reached from
            # this machine. A host is exposed with a certificate applied by hand (no ACME
            # authority is reached from here: tests/cluster.rs orders one from a stand-in).
            unplaced=the-word-of-a-secret-nothing-places
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=shop.example.test \
                -addext subjectAltName=DNS:shop.example.test -keyout "$work/shop.key" -out "$work/shop.crt" 2>/dev/null \
                || fail "openssl made no certificate"
            api 1 GET /v1/resources | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
node = next(r for r in found if r["kind"] == "Node" and r["metadata"]["name"] == "n2")
crt, key = (open(path).read() for path in sys.argv[1:3])
def secret(name, data):
    return {"apiVersion": "kith.dev/v1", "kind": "Secret", "metadata": {"name": name}, "spec": {"data": data}}
json.dump([
    {"apiVersion": "kith.dev/v1", "kind": "Node", "metadata": {"name": "n2"}, "spec": {**node["spec"], "ingress": True}},
    secret("tls-shop.example.test", {"tls.crt": crt, "tls.key": key}),
    secret("unplaced", {"word": sys.argv[3]}),
    {"apiVersion": "kith.dev/v1", "kind": "Service", "metadata": {"name": "shop"}, "spec": {
        "selector": {"app": "shop"}, "ports": [{"port": 80}], "expose": {"host": "shop.example.test", "via": "edge"}}},
], open(sys.argv[4], "w"))
' "$work/shop.crt" "$work/shop.key" "$unplaced" "$work/apply.json" || fail "the worker's Node was not read"
            api 1 POST /v1/apply "$work/apply.json" >/dev/null || fail "the worker's Node, the certificate and the Service were not applied"
            # Its view now holds the host's key (its Node says ingress, so the control node sends
            # it): its disk has it, and the Secret nothing places is on the control node's alone.
            line=$(sed -n 2p "$work/shop.key")
            waited=0
            until grep -aqF "$line" "$work/n2.raw" && grep -aqF "$unplaced" "$work/n1.raw"; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the host's key is not on the ingress worker's disk, or the Secret nothing places is on no disk"
                sleep 1
            done
            sleep 2
            monitor 2 quit
            sleep 2
            https=1
            node 2 --ingress
            # It answers the host over TLS with that certificate, and no other host. (s_client
            # says "Verify return code: 0 (ok)" after a handshake that failed too: a certificate
            # sent, and one that verified, is what says it answered.)
            handshake() { # HOST
                openssl s_client -connect "127.0.0.1:$((port + 12))" -servername "$1" -CAfile "$work/shop.crt" \
                    -verify_hostname "$1" -verify_return_error </dev/null 2>/dev/null
            }
            answers() { handshake "$1" | grep -q 'BEGIN CERTIFICATE' && handshake "$1" | grep -q 'Verify return code: 0 (ok)'; } # HOST
            waited=0
            until answers shop.example.test; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "the ingress worker did not answer shop.example.test over TLS: $(handshake shop.example.test | tail -n 5)"
                sleep 1
            done
            # (Unverified: a host nothing exposes is sent no certificate at all, not one that fails.)
            ! openssl s_client -connect "127.0.0.1:$((port + 12))" -servername other.example.test </dev/null 2>/dev/null \
                | grep -q 'BEGIN CERTIFICATE' || fail "the ingress worker sent a certificate for a host nothing exposes"
            echo "vm.sh: the ingress worker answers its host over TLS with the certificate it was sent" >&2
            # Its disk has no Secret that is neither a tls- one nor placed on it.
            ! grep -aqF "$unplaced" "$work/n2.raw" || fail "a Secret nothing places is on the ingress worker's disk"
            ! grep -aqF "$other" "$work/n2.raw" || fail "the Secret of what runs on the control node is on the ingress worker's disk"
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: two nodes, one let in as a worker: its Node says it is sent a view; a Workload placed on it ran with its Secret; its disk has that Secret and never had the Secret of what runs on the control node; its API answered no person; with the control node paused it said so and ran on; started again meanwhile it ran nothing until the control node was back, then what it ran; a deleted Workload left it; made an ingress worker it answered its host over TLS, with the host's key on its disk and no Secret nothing places on it"
            exit 0
