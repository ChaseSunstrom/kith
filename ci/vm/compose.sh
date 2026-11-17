# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# shellcheck disable=SC2015 # (as the script had them before it was cut)
# Sourced by ci/vm.sh for --test compose: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # A compose file of the test pod's, as kith resources: made on this machine by the
            # kith that is built here (exit 0 is all of it translated; 1 says what was left out).
            kith=$(sh "$root/ci/musl.sh")/kith
            "$kith" import compose "$root/ci/compose/stack.yml" >"$work/stack.yml" || fail "kith import compose left something of ci/compose/stack.yml out"
            # The resources as JSON for the API: a store file of this machine's takes them (what
            # `kith import` prints is YAML), and says each as JSON without its revision.
            KITH_STORE="$work/stack-store.json" "$kith" apply --file "$work/stack.yml" >&2 || fail "the imported stack did not lint as resources"
            KITH_STORE="$work/stack-store.json" "$kith" get --output json | python3 -c '
import json, sys
found = json.load(sys.stdin)
for r in found:
    r["metadata"].pop("revision", None)
json.dump(found, sys.stdout)
' >"$work/apply.json" || fail "the imported stack could not be read back as JSON"
            names='api db cache web'
            # The clock starts at the apply and stops when each Workload has said one container ready.
            started=$(date +%s%N)
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the imported stack was not applied"
            waited=0
            while :; do
                every=y
                for name in $names; do
                    line=$(units Workload "$name") && [ "${line%% *}" = 1 ] || { every=''; unready="$name: $line"; }
                done
                [ -z "$every" ] || break
                waited=$((waited + 1))
                [ "$waited" -lt 1500 ] || fail "waited for the four services to be ready; one says $unready"
                sleep 0.2
            done
            elapsed=$((($(date +%s%N) - started) / 1000000))
            seconds=$(printf '%d.%03d' $((elapsed / 1000)) $((elapsed % 1000)))
            echo "vm.sh: compose: apply to all four ready: $seconds s" >&2
            # Each name, then, as a Job in a pod of its own asks for it (40 times: pod ask,
            # ci/pod.rs): its Service has an address and its pod answers with its own name.
            for ask in api db cache web frontend; do
                waited=0
                until any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    status = r.get("status") or {}
    if r["kind"] == "Service" and r["metadata"]["name"] == sys.argv[1] and status.get("address") and status.get("backends"):
        sys.exit(0)
sys.exit(1)
' "$ask"; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 120 ] || fail "the Service $ask was given no address with its pod"
                    sleep 1
                done
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"ask-$ask"},"spec":{"retries":0,"template":{"pod":true,"containers":[
  {"name":"ask","image":"kith.test/pod:1","command":["/bin/pod","ask","$ask","80"]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job ask-$ask was not applied"
                waited=0
                until line=$(units Job "ask-$ask") && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for the Job ask-$ask; it says: $line"
                    sleep 1
                done
                any GET "/v1/logs/Job/default/ask-$ask" >"$work/ask-$ask.out" 2>/dev/null || true
                printf '%s\n' "$line" | grep -q succeeded || fail "the Job ask-$ask did not succeed: $line: $(cat "$work/ask-$ask.out")"
                ! grep -q 'failed: ' "$work/ask-$ask.out" || fail "the Job asking for $ask was not always answered: $(cat "$work/ask-$ask.out")"
                # (A pod is named for its Workload: web's alias, frontend, is answered by web-0.)
                want=$ask
                [ "$ask" != frontend ] || want=web
                grep -q 'HTTP/1.0 200 OK' "$work/ask-$ask.out" && grep -q "$want-0" "$work/ask-$ask.out" || fail "the name $ask was not answered by $want-0: $(cat "$work/ask-$ask.out")"
            done
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node, kith import compose of ci/compose/stack.yml (four services of the test pod, nothing left out) applied: all four ready $seconds s after the apply, and each of api, db, cache, web and frontend (web's container_name) asked for by that name from a Job in a pod, and answered by its own pod"
            exit 0
