# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test nofile: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # A container's open-file limit: soft 1024 and hard 524288 (kithd, as the machine's
            # first process, raised its own hard one; the container gets it, as under containerd),
            # so an app can raise its soft one. A Job of one container: NAME, then its container's
            # fields; what it wrote is in $work/NAME.out (as JSON: its lines inside a string).
            job() {
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{"pod":true,"containers":[
  {"name":"box",$2}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
                waited=0
                until line=$(units Job "$1") && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for the Job $1; it says: $line"
                    sleep 1
                done
                any GET "/v1/logs/Job/default/$1" >"$work/$1.out" 2>/dev/null || true
                any GET "/v1/logs/Job/default/$1?stderr=true" >"$work/$1.err" 2>/dev/null || true
                printf '%s\n' "$line" | grep -q succeeded || fail "the Job $1 says: $line: $(cat "$work/$1.out" "$work/$1.err")"
            }
            job limits '"image":"kith.test/pod:1","command":["/bin/pod","nofile"]'
            got=$(grep -o 'nofile: [0-9]* [0-9]*' "$work/limits.out" | head -n 1)
            [ "$got" = 'nofile: 1024 524288' ] || fail "the test pod's open-file limits are \"$got\", not soft 1024 and hard 524288: $(cat "$work/limits.out" "$work/limits.err")"
            stock='no stock image was tried (KITH_E2E=1 pulls busybox)'
            if [ "${KITH_E2E:-}" = 1 ]; then
                # busybox as it is shipped: its shell says the limits it was started with.
                job box '"image":"mirror.gcr.io/library/busybox:1.36","command":["sh","-c","echo ulimit $(ulimit -Sn) $(ulimit -Hn)"]'
                got=$(grep -o 'ulimit [0-9]* [0-9]*' "$work/box.out" | head -n 1)
                [ "$got" = 'ulimit 1024 524288' ] || fail "busybox's ulimit -Sn and -Hn are \"$got\", not 1024 and 524288: $(cat "$work/box.out" "$work/box.err")"
                stock='busybox (mirror.gcr.io/library/busybox:1.36) said the same from ulimit -Sn and -Hn'
            fi
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node, a container whose open-file limit is soft 1024 and hard 524288 (the test pod read /proc/self/limits; $stock)"
            exit 0
