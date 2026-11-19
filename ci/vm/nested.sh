# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test nested: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # One node, and a container in it that holds a second runtime (bubblewrap) and kithd in agent mode,
            # with kith's defaults and then with each opening in turn (cluster.sh makes the image from this
            # machine's bash, bwrap and unshare; ci/vm/nested-probe.sh is what runs in it). Nothing here
            # changes a default: it asks what refuses what, and what the guest kernel says. Each variant's
            # row, from the probe's last line, goes to $KITH_NESTED_OUT (ci/stress.sh --nested keeps it).
            rows=${KITH_NESTED_OUT:-/dev/null}
            : >"$work/nested.rows"
            # NAME and the container's further fields: one Job, run to its end; its log in $work/NAME.out.
            variant() {
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"v-$1"},"spec":{"node":"n1","path":"nested-$1"}},
 {"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{"containers":[
  {"name":"probe","image":"kith.test/nested:1","command":["/bin/bash","/probe.sh"],"volumeMounts":[{"volume":"v-$1","path":"/state"}]$2}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
                waited=0
                until line=$(units Job "$1") && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 600 ] || fail "waited for the Job $1; it says: $line"
                    sleep 1
                done
                # (The log comes as {"data": TEXT, ...}.)
                any GET "/v1/logs/Job/default/$1" 2>/dev/null | python3 -c 'import json, sys; t = json.load(sys.stdin); print(t.get("data", "") if isinstance(t, dict) else t)' >"$work/$1.out" || true
                any GET "/v1/logs/Job/default/$1?stderr=true" 2>/dev/null | python3 -c 'import json, sys; t = json.load(sys.stdin); print(t.get("data", "") if isinstance(t, dict) else t)' >"$work/$1.err" || true
                echo "vm.sh: nested $1: the Job says: $line" >&2
                sed 's/^/vm.sh: nested '"$1"': /' "$work/$1.out" "$work/$1.err" >&2
                if grep -q '^row: ' "$work/$1.out"; then
                    printf 'nested %s | %s\n' "$1" "$(grep '^row: ' "$work/$1.out" | tail -n 1 | cut -c6-)" >>"$work/nested.rows"
                else
                    # (The probe itself did not run to its end: the Job's own words are the row.)
                    printf 'nested %s | the probe did not finish: %s | %s\n' "$1" "$line" "$(tr '\n' ' ' <"$work/$1.err" | cut -c1-400)" >>"$work/nested.rows"
                fi
            }
            # kith's defaults first; then each opening that the one before it showed to be needed.
            variant defaults ''
            variant unconfined ',"seccomp":{"unconfined":true}'
            variant userns ',"userNamespaces":true'
            variant userns-unconfined ',"userNamespaces":true,"seccomp":{"unconfined":true}'
            variant root ',"runAsUser":0'
            cat "$work/nested.rows" >>"$rows"
            # The smallest opening: the first variant whose container (kithd's) ran.
            first=$(grep -m1 'its container: ran' "$work/nested.rows" | cut -d ' ' -f 2 || true)
            printf 'nested smallest opening: %s\n' "${first:-none of those tried}" | tee -a "$rows" >&2
            echo "vm.sh: ok: kithd in agent mode and bubblewrap started inside a container, with kith's defaults and with each opening in turn: what refused each is in the rows above (a Job that did not finish is a row too)" >&2
            exit 0
