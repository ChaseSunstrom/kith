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
            said=$(grep -o 'hammer: [0-9].*' "$work/hammer.out" | head -1) || fail "the Job hammer said nothing of how it went: $(cat "$work/hammer.out")"
            printf '%s\n' "$line" | grep -q succeeded || fail "the Job hammer did not end well: $line: $said"
            case $said in *" 0 failed"*) ;; *) fail "the Service web did not answer every request through a rolling update: $said" ;; esac
            case $said in *one*two* | *two*one*) ;; *) fail "the update did not finish while the Job asked (it should hear both answers): $said" ;; esac
            # (Its state disk has no project quotas, as a node's from before: kithd says it counts.)
            grep -aq "kithd: pods' storage limits are held by a count every 10 s of what each pod wrote" "$work/n1.log" \
                || fail "kithd did not say it counts what pods write on a state disk with no project quotas: $(grep -a 'storage limits' "$work/n1.log")"
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node, a pod that sent back what it was sent and its Service; Jobs on the same node, one in a pod (passed by kithd) and one on the node's own network (passed by the kernel straight to the replica), sent through the Service on connections closed at once, half closed, reset by either end with bytes on their way, side by side and kept for small turns, and every byte came back in order ($checked); a one-replica Workload behind a Service rolled to a new spec answered every request ($said)"
            exit 0
