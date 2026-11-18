# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test outlive: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # One node, and what runs on it: a pod of two containers (one probed for readiness),
            # an exec unit, and a Job in a pod, each saying once which process it is and when it
            # started, then a tick a second. (ci/pod.rs is on the node's disk too, at
            # /var/lib/kith/tools/pod, for the exec units: cluster.sh.)
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"ticker"},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"echo","image":"kith.test/pod:1","command":["/bin/pod","echo"],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}}},
  {"name":"tick","image":"kith.test/pod:1","command":["/bin/pod","tick"]}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"host"},"spec":{"replicas":1,"template":{"exec":[
  {"name":"tick","command":["/var/lib/kith/tools/pod","tick"]}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"long"},"spec":{"retries":0,"template":{"pod":true,"containers":[
  {"name":"tick","image":"kith.test/pod:1","command":["/bin/pod","tick","60"]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "what outlives kithd was not applied"
            # KIND NAME [UNIT]: what it wrote (as JSON: its lines inside a string).
            said() { any GET "/v1/logs/$1/default/$2${3:+?unit=$3}" 2>/dev/null; }
            # KIND NAME [UNIT]: the last tick it said, and which process it said it was.
            ticked() { said "$@" | grep -o 'tick [0-9]*' | tail -n 1 | cut -d ' ' -f 2; }
            process() { said "$@" | grep -o 'tick: process [0-9]* started at [0-9]*'; }
            # NAME: each unit's restarts and readiness, "unit:restarts:ready ...".
            kept() {
                any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    if r["metadata"]["name"] == sys.argv[1] and r["kind"] in ("Workload", "Job"):
        print(*sorted("%s:%s:%s" % (u.get("name"), u.get("restarts", 0), u.get("ready")) for u in (r.get("status") or {}).get("containers") or []))
' "$1"
            }
            units_of='Workload ticker tick|Workload host tick|Job long'
            waited=0
            until line=$(units Workload ticker) && [ "${line%% *}" -ge 1 ] && [ "$(ticked Workload ticker tick)" -ge 3 ] 2>/dev/null \
                && [ "$(ticked Workload host tick)" -ge 3 ] 2>/dev/null && [ "$(ticked Job long)" -ge 3 ] 2>/dev/null; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "waited for the units to tick: ticker $line, $(said Workload host tick) $(said Job long)"
                sleep 1
            done
            before=$(IFS='|'; for unit in $units_of; do IFS=' '; set -- $unit; process "$@"; done)
            [ "$(printf '%s\n' "$before" | grep -c 'tick: process')" = 3 ] || fail "each unit did not say once which process it is: $before"
            ticks=$(ticked Workload ticker tick)
            # kithd killed (SIGKILL) by an exec unit of a Job: the first process starts it again.
            booted=$(grep -ac 'Kernel command line' "$work/n1.log")
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"strike"},"spec":{"retries":0,"template":{"exec":[
  {"name":"kill","command":["/var/lib/kith/tools/pod","kill","1","0"]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job that kills kithd was not applied"
            waited=0
            until grep -aq 'kithd: init: kithd ended' "$work/n1.log"; do
                waited=$((waited + 1))
                [ "$waited" -lt 1200 ] || fail "kithd was not killed: $(grep -a 'kill' "$work/n1.log" | tail -n 3)"
                sleep 0.1
            done
            ended=$(date +%s%N)
            until patience=1 api 1 GET /v1/resources >/dev/null 2>&1; do
                [ $(($(date +%s%N) - ended)) -lt 30000000000 ] || fail "kithd did not serve again within 30 s of its end"
                sleep 0.05
            done
            back=$((($(date +%s%N) - ended) / 1000000))
            echo "vm.sh: kithd killed; the API answered again $back ms after the first process said so" >&2
            # Served within a second (2 s here: this machine's own load).
            [ "$back" -le 2000 ] || fail "kithd served again only after $back ms"
            sleep 6
            [ "$(grep -ac 'Kernel command line' "$work/n1.log")" = "$booted" ] || fail "the machine restarted when kithd was killed"
            [ "$(grep -ac 'kithd: init: kithd ended' "$work/n1.log")" = 1 ] || fail "kithd ended more than once: $(grep -a 'kithd: init:' "$work/n1.log" | tail -n 5)"
            taken=$(grep -ac 'taken back, as it ran' "$work/n1.log")
            [ "$taken" -ge 4 ] || fail "kithd took back $taken units, not the four that ran: $(grep -a 'kithd: ' "$work/n1.log" | tail -n 20)"
            after=$(IFS='|'; for unit in $units_of; do IFS=' '; set -- $unit; process "$@"; done)
            [ "$after" = "$before" ] || fail "a unit was started again: before, $before; after, $after"
            [ "$(ticked Workload ticker tick)" -gt $((ticks + 4)) ] || fail "the pod's log stopped at tick $(ticked Workload ticker tick) (it was at $ticks)"
            for name in ticker host; do
                line=$(kept $name)
                [ -n "$line" ] || fail "$name says nothing of its units"
                for unit in $line; do
                    case $unit in *:0:True) ;; *) fail "$name was restarted or is not ready: $line" ;; esac
                done
            done
            waited=0
            until line=$(units Job strike) && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "waited for the Job strike; it says: $line"
                sleep 1
            done
            printf '%s\n' "$line" | grep -q succeeded || fail "the Job strike, which ended while kithd was gone, did not succeed: $line"
            waited=0
            until line=$(units Job long) && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "waited for the Job long; it says: $line"
                sleep 1
            done
            printf '%s\n' "$line" | grep -q succeeded || fail "the Job long, taken back, did not succeed: $line"
            [ "$(ticked Job long)" = 60 ] || fail "the Job long ended at tick $(ticked Job long), not 60"
            # What the two processes hold resident, said (both are one file, mapped once).
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"memory"},"spec":{"retries":0,"template":{"exec":[
  {"name":"read","command":["/var/lib/kith/tools/pod","memory"]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job that reads the memory was not applied"
            waited=0
            until memory=$(said Job memory | grep -o 'memory: [0-9]* [a-z]* [0-9]* [0-9]*') && [ "$(printf '%s\n' "$memory" | wc -l)" = 2 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "the memory of process 1 and kithd was not read: $(said Job memory)"
                sleep 1
            done
            memory=$(printf '%s\n' "$memory" | awk '{printf "%s%s %d kB resident (%d kB its own)", sep, ($2 == 1 ? "process 1" : "kithd"), $4, $5; sep = ", "}')
            echo "vm.sh: memory: $memory" >&2
            # Killed again and again, ten times in a minute: the machine restarts, as it did
            # when kithd was the first process.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"strikes"},"spec":{"retries":0,"template":{"exec":[
  {"name":"kill","command":["/var/lib/kith/tools/pod","kill","14","2"]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job that kills kithd again and again was not applied"
            waited=0
            until [ "$(grep -ac 'Kernel command line' "$work/n1.log")" -gt "$booted" ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 180 ] || fail "the machine did not restart when kithd was killed again and again: $(grep -a 'kithd: init:' "$work/n1.log" | tail -n 5)"
                sleep 1
            done
            grep -aq 'kithd: init: kithd failed 10 times in a minute' "$work/n1.log" || fail "the machine restarted, but not after ten failures: $(grep -a 'kithd: init:' "$work/n1.log" | tail -n 5)"
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node: kithd killed (SIGKILL) under a pod of two containers, an exec unit and a Job; the machine did not restart, kithd served again in $back ms and took back all $taken units as they ran (each the same process, its log going on, nothing restarted, readiness kept), the Job that ended while it was gone and the one that ended after both succeeded ($memory); killed ten times in a minute, the machine restarted"
            exit 0
