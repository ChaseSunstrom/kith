# shellcheck shell=sh
# shellcheck disable=SC2154,SC2034 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test mesh: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # Two kith OS nodes on disk files, both started with no --mesh (as kith OS starts), the second
            # joined to the first. The cluster turns its mesh on afterwards with spec.mesh (T-1076): no
            # reinstall, no restart. A pod on one then reaches a Service whose only replica is on the other.
            # What each Node says of its mesh, "n1 ADDRESS n2 ADDRESS" (a "-" for none).
            meshes() {
                any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in sorted((r for r in found if r["kind"] == "Node"), key=lambda r: r["metadata"]["name"]):
    print(r["metadata"]["name"], ((r.get("status") or {}).get("mesh") or {}).get("address") or "-", end=" ")
'
            }
            waited=0
            until said=$(meshes) && [ "$said" = "n1 - n2 - " ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the nodes started with no --mesh and no switch: they say '$said', not 'n1 - n2 - '"
                sleep 1
            done
            ! grep -aq 'kithd: mesh address' "$work/n1.log" "$work/n2.log" || fail "a node brought the mesh up with the switch off: $(grep -a 'kithd: mesh' "$work"/n?.log)"
            # A pod on each node, and a Service whose only replica is on n2.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on-n1"},"spec":{"node":"n1","path":"pod"}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on-n2"},"spec":{"node":"n2","path":"pod"}},
 {"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"echo","labels":{"app":"echo"}},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"echo","image":"kith.test/pod:1","command":["/bin/pod","echo"],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}},
   "volumeMounts":[{"volume":"on-n2","path":"/state"}]}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Service","metadata":{"name":"echo"},"spec":{"selector":{"app":"echo"},"ports":[{"port":80}]}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the echo pod on n2 and its Service were not applied"
            waited=0
            until line=$(units Workload echo) && [ "${line%% *}" = 1 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "waited for the echo pod on n2 to be ready; the Workload says: $line"
                sleep 1
            done
            # The switch: one Cluster, mesh on. Every node acts on it, the one that is a member already too.
            printf '[{"apiVersion":"kith.dev/v1","kind":"Cluster","metadata":{"name":"home"},"spec":{"mesh":{"enabled":true}}}]' >"$work/switch.json"
            any POST /v1/apply "$work/switch.json" >/dev/null || fail "the Cluster with spec.mesh was not applied"
            waited=0
            until said=$(meshes) && case $said in *' - '* | '') false ;; *) true ;; esac; do
                waited=$((waited + 1))
                [ "$waited" -lt 240 ] || fail "the nodes did not bring the mesh up on the Cluster's switch: they say '$said'; $(grep -a 'kithd: .*mesh' "$work"/n?.log)"
                sleep 1
            done
            for n in 1 2; do
                grep -aq 'kithd: mesh address .* on kith0' "$work/n$n.log" || fail "n$n did not say its mesh address on kith0: $(grep -a 'mesh' "$work/n$n.log")"
            done
            # The Service has its address in the mesh's /48, as the nodes do.
            waited=0
            until address=$(any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    status = r.get("status") or {}
    if r["kind"] == "Service" and r["metadata"]["name"] == "echo" and status.get("address") and status.get("backends"):
        print(status["address"])
        sys.exit(0)
sys.exit(1)
'); do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the Service echo was given no address with its replica"
                sleep 1
            done
            python3 -c '
import ipaddress, sys
service, node = (ipaddress.IPv6Address(a) for a in sys.argv[1:])
sys.exit(0 if int(service) >> 80 == int(node) >> 80 else 1)
' "$address" "$(printf '%s\n' "$said" | cut -d ' ' -f 2)" || fail "the Service address $address is not in the mesh's /48 (the nodes say: $said)"
            # A Job in a pod on n1 sends through the Service to the replica on n2, which no node reaches but over kith0.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"across"},"spec":{"retries":0,"template":{"pod":true,"containers":[
  {"name":"check","image":"kith.test/pod:1","command":["/bin/pod","check","echo","80"],"volumeMounts":[{"volume":"on-n1","path":"/state"}]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job across was not applied"
            waited=0
            until line=$(units Job across) && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                waited=$((waited + 1))
                [ "$waited" -lt 600 ] || fail "waited for the Job across; it says: $line"
                sleep 1
            done
            any GET "/v1/logs/Job/default/across" >"$work/across.out" 2>/dev/null || true
            any GET "/v1/logs/Job/default/across?stderr=true" >"$work/across.err" 2>/dev/null || true
            printf '%s\n' "$line" | grep -q succeeded || fail "bytes from a pod on n1 through the Service to the replica on n2 did not all come back: $line: $(cat "$work/across.out" "$work/across.err")"
            reached=$(grep -o 'check: reached [^"\\]*' "$work/across.out") || fail "the Job across did not say what it reached: $(cat "$work/across.out")"
            [ "${reached#check: reached }" = "[$address]:80" ] || fail "the pod's connection reached ${reached#check: reached }, not kithd at the Service's mesh address [$address]:80"
            # (n2 had the replica: kithd on n2 heard the connection over its mesh address, as it has no other way to be reached from n1's Service address.)
            # And off again: the switch removed, each node takes its mesh status back, nothing restarts.
            printf '[{"apiVersion":"kith.dev/v1","kind":"Cluster","metadata":{"name":"home"},"spec":{"mesh":{"enabled":false}}}]' >"$work/switch.json"
            any POST /v1/apply "$work/switch.json" >/dev/null || fail "the Cluster with spec.mesh off was not applied"
            waited=0
            until said=$(meshes) && [ "$said" = "n1 - n2 - " ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 240 ] || fail "the nodes did not take the mesh down on the Cluster's switch: they say '$said'"
                sleep 1
            done
            [ "$(grep -ac 'Kernel command line' "$work/n1.log")" = 1 ] || fail "n1 restarted"
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: two kith OS nodes started with no --mesh, no mesh; the Cluster's spec.mesh turned it on (kith0, an address in the cluster's /48 on each Node) with no reinstall and no restart; a pod on n1 sent through the Service of a pod on n2 over it (reached [$address]:80, every byte back); the switch off took each node's mesh status back"
            exit 0
