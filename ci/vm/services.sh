# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test services: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # A pod that sends back what it is sent, and its Service.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"echo","labels":{"app":"echo"}},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"echo","image":"kith.test/pod:1","command":["/bin/pod","echo"],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}}}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Service","metadata":{"name":"echo"},"spec":{"selector":{"app":"echo"},"ports":[{"port":80}]}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the echo pod was not applied"
            waited=0
            until line=$(units Workload echo) && [ "${line%% *}" = 1 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "waited for the echo pod to be ready; the Workload says: $line"
                sleep 1
            done
            # The Service's address, once it has its replica.
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
            # A Job on the same node sending to it through the Service, twice: in a pod of its
            # own (kithd passes its bytes), and on the node's own network (the kernel sends
            # its connections straight to the replica's IPv6 address, never a v4 one an
            # IPv6-only socket could not reach). What each says is in $work/JOB.out.
            checked=''
            for job in check near; do
                if [ "$job" = check ]; then pod='"pod":true,' to=echo; else pod='' to=$address; fi
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$job"},"spec":{"retries":0,"template":{$pod"containers":[
  {"name":"check","image":"kith.test/pod:1","command":["/bin/pod","check","$to","80"]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $job was not applied"
                waited=0
                until line=$(units Job "$job") && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 600 ] || fail "waited for the Job $job; it says: $line"
                    sleep 1
                done
                any GET "/v1/logs/Job/default/$job" >"$work/$job.out" 2>/dev/null || true
                any GET "/v1/logs/Job/default/$job?stderr=true" >"$work/$job.err" 2>/dev/null || true
                any GET '/v1/logs/Workload/default/echo?replica=0' >"$work/echo.out" 2>/dev/null || true
                printf '%s\n' "$line" | grep -q succeeded || fail "bytes through the Service from the Job $job did not all come back in order: $line: $(cat "$work/$job.out" "$work/$job.err")"
                ! grep -q 'echo: bad' "$work/echo.out" || fail "the echo pod heard bytes out of order: $(cat "$work/echo.out")"
                # (The log comes as JSON: its lines are inside a string.)
                said=$(grep -o 'check: [0-9][^"\\]*' "$work/$job.out") || fail "the Job $job said nothing of how it went: $(cat "$work/$job.out" "$work/$job.err")"
                reached=$(grep -o 'check: reached [^"\\]*' "$work/$job.out") || fail "the Job $job did not say what it reached: $(cat "$work/$job.out" "$work/$job.err")"
                reached=${reached#check: reached }
                if [ "$job" = check ]; then
                    [ "$reached" = "[$address]:80" ] || fail "a pod's connection to the Service reached $reached, not kithd at [$address]:80"
                else
                    case $reached in "[$address]:80" | "[::ffff:"* | [![]*) fail "a connection on the node's own network to the Service reached $reached, not the replica: the kernel did not send it there" ;; esac
                fi
                checked="$checked${checked:+; }$job: ${said#check: }, reached $reached"
            done
            # A rolling update of a one-replica Workload behind a Service (T-0020): the new pod
            # starts beside the old and the old stops once it is ready, so a Job asking the
            # Service ten times a second all through the update is answered every time, and
            # hears the new answer before it ends.
            web() {
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"web","labels":{"app":"web"}},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"web","image":"kith.test/pod:1","command":["/bin/pod","say"],"env":[{"name":"PASSWORD","value":"$1"}],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}}}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Service","metadata":{"name":"web"},"spec":{"selector":{"app":"web"},"ports":[{"port":80}]}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the web Workload ($1) was not applied"
            }
            web one
            waited=0
            until line=$(units Workload web) && [ "${line%% *}" = 1 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "waited for the web pod to be ready; the Workload says: $line"
                sleep 1
            done
            waited=0
            until any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
sys.exit(0 if any(r["kind"] == "Service" and r["metadata"]["name"] == "web" and (r.get("status") or {}).get("backends") for r in found) else 1)
'; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the Service web was given no replica"
                sleep 1
            done
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"hammer"},"spec":{"retries":0,"template":{"pod":true,"containers":[
  {"name":"hammer","image":"kith.test/pod:1","command":["/bin/pod","hammer","web","80","60"]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job hammer was not applied"
            sleep 8
            web two
            waited=0
            until line=$(units Job hammer) && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                waited=$((waited + 1))
                [ "$waited" -lt 600 ] || fail "waited for the Job hammer; it says: $line"
                sleep 1
            done
            any GET /v1/logs/Job/default/hammer >"$work/hammer.out" 2>/dev/null || true
            rolled=$(grep -o 'hammer: [0-9].*' "$work/hammer.out" | head -1) || fail "the Job hammer said nothing of how it went: $(cat "$work/hammer.out")"
            printf '%s\n' "$line" | grep -q succeeded || fail "the Job hammer did not end well: $line: $rolled"
            case $rolled in *" 0 failed"*) ;; *) fail "the Service web did not answer every request through a rolling update: $rolled" ;; esac
            case $rolled in *one*two* | *two*one*) ;; *) fail "the update did not finish while the Job asked (it should hear both answers): $rolled" ;; esac
            # (Its state disk has no project quotas, as a node's from before: kithd says it counts.)
            grep -aq "kithd: pods' storage limits are held by a count every 10 s of what each pod wrote" "$work/n1.log" \
                || fail "kithd did not say it counts what pods write on a state disk with no project quotas: $(grep -a 'storage limits' "$work/n1.log")"
            # A node of before beside one with links (T-0326): n1 starts again, now on the mesh, and a
            # second node joins it with KITH_NO_LINK in its environment (kithd says no `link` and
            # opens none, as the kithd of before does: one binary stands for both). A pod of a Job
            # on each, sent to a Service of the other's, on connections closed at once, half closed
            # and reset, as above.
            alone=${vms# }
            kill "$alone"
            wait "$alone" 2>/dev/null || true
            more=--mesh
            node 1
            waited=0
            until api 1 GET /v1/resources >/dev/null 2>&1; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "the first node did not answer again, on the mesh: $(tail -n 3 "$work/n1.log")"
                sleep 1
            done
            join=$(api 1 POST /v1/tokens | field token) || fail "no join token on the mesh"
            nolink=1
            node 2 "--join 10.9.0.1:7443 --token $join --pod-range 10.77.0.0/20"
            nolink=''
            # What each node says of itself: n1 takes links, n2 (as a node of before) does not.
            waited=0
            until said=$(any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in sorted((r for r in found if r["kind"] == "Node"), key=lambda r: r["metadata"]["name"]):
    mesh = (r.get("status") or {}).get("mesh") or {}
    print(r["metadata"]["name"], "link" if mesh.get("link") else "-", "kept" if mesh.get("kept") else "-", end=" ")
') && [ "$said" = "n1 link kept n2 - kept " ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "the nodes do not say 'n1 link kept n2 - kept' (a node with links and one of before); they say: $said"
                sleep 1
            done
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on-n1"},"spec":{"node":"n1","path":"pod"}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on-n2"},"spec":{"node":"n2","path":"pod"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the volumes that put a pod on each node were not applied"
            for side in n1 n2; do
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"echo-$side","labels":{"app":"echo-$side"}},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"echo","image":"kith.test/pod:1","command":["/bin/pod","echo"],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}},
   "volumeMounts":[{"volume":"on-$side","path":"/state"}]}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Service","metadata":{"name":"echo-$side"},"spec":{"selector":{"app":"echo-$side"},"ports":[{"port":80}]}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the pod echo-$side was not applied"
                waited=0
                until line=$(units Workload "echo-$side") && [ "${line%% *}" = 1 ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for the pod echo-$side to be ready; the Workload says: $line"
                    sleep 1
                done
            done
            for pair in 'n1 n2' 'n2 n1'; do
                from=${pair% *} to=${pair#* }
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"mix-$from-$to"},"spec":{"retries":0,"template":{"pod":true,"containers":[
  {"name":"check","image":"kith.test/pod:1","command":["/bin/pod","check","echo-$to","80"],"volumeMounts":[{"volume":"on-$from","path":"/state"}]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job mix-$from-$to was not applied"
                waited=0
                until line=$(units Job "mix-$from-$to") && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 600 ] || fail "waited for the Job mix-$from-$to; it says: $line"
                    sleep 1
                done
                any GET "/v1/logs/Job/default/mix-$from-$to" >"$work/mix.out" 2>/dev/null || true
                any GET "/v1/logs/Job/default/mix-$from-$to?stderr=true" >"$work/mix.err" 2>/dev/null || true
                printf '%s\n' "$line" | grep -q succeeded || fail "bytes from a pod on $from through the Service echo-$to did not all come back in order: $line: $(cat "$work/mix.out" "$work/mix.err")"
                any GET "/v1/logs/Workload/default/echo-$to?replica=0" >"$work/echo-$to.out" 2>/dev/null || true
                ! grep -q 'echo: bad' "$work/echo-$to.out" || fail "the echo pod on $to heard bytes out of order: $(cat "$work/echo-$to.out")"
                grep -q 'check: [0-9]' "$work/mix.out" || fail "the Job mix-$from-$to said nothing of how it went: $(cat "$work/mix.out" "$work/mix.err")"
            done
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node, a pod that sent back what it was sent and its Service; Jobs on the same node, one in a pod (passed by kithd) and one on the node's own network (passed by the kernel straight to the replica), sent through the Service on connections closed at once, half closed, reset by either end with bytes on their way, side by side and kept for small turns, and every byte came back in order ($checked); a one-replica Workload behind a Service rolled to a new spec answered every request ($rolled); then on the mesh with a second node that says no link (as a node of before), a pod on each sent through the Service of a pod on the other, both ways"
            exit 0
