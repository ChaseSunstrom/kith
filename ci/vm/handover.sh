# shellcheck shell=sh
# shellcheck disable=SC2154,SC2034,SC2015 # (names the driver and its parts share; A && B || fail is a check)
# Sourced by ci/vm.sh for --test handover: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone. The releases are built in cluster.sh.
            # One node, claimed, on disk files only. A pod ticks on it (ci/pod.rs, a container image the
            # node has), and a Job says the machine's boot id (the kernel's, new at every boot).
            more='' # (the nodes' arguments are given: from here $more is what a release's spec adds)
            said() { any GET "/v1/logs/$1/default/$2${3:+?unit=$3}" 2>/dev/null; } # KIND NAME [UNIT]
            ticked() { said "$@" | grep -o 'tick [0-9]*' | tail -n 1 | cut -d ' ' -f 2; }
            process() { said "$@" | grep -o 'tick: process [0-9]* started at [0-9]*' | tail -n 1; }
            # NAME: a Job in a pod says the boot id; into $bootid.
            boot() {
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{"pod":true,"containers":[
  {"name":"boot","image":"kith.test/pod:1","command":["/bin/pod","bootid"]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
                waited=0
                until bootid=$(said Job "$1" | grep -o 'bootid: [0-9a-f-]*') && [ ${#bootid} = 44 ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 120 ] || fail "the Job $1 did not say the boot id: $(said Job "$1")"
                    sleep 1
                done
                bootid=${bootid#bootid: }
            }
            # N: wait until the pod has ticked N times.
            ticking() {
                waited=0
                until [ "$(ticked Workload ticker tick)" -ge "$1" ] 2>/dev/null; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "the pod did not tick $1 times: $(said Workload ticker tick)"
                    sleep 1
                done
            }
            booted() { grep -ac 'Kernel command line' "$work/n1.log"; }
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"ticker"},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"tick","image":"kith.test/pod:1","command":["/bin/pod","tick"]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the pod was not applied"
            ticking 3
            # (A restart starts the pod again: its log then says another process, as the old one's may be there still.)
            again() { # PROCESS: wait until the pod is a process other than that one, ticking
                waited=0
                until [ -n "$(process Workload ticker tick)" ] && [ "$(process Workload ticker tick)" != "$1" ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "the pod did not start again after the restart: $(said Workload ticker tick)"
                    sleep 1
                done
                ticking 3
            }
            process_was=$(process Workload ticker tick)
            boot boot0
            first_boot=$bootid
            [ "$(booted)" = 1 ] || fail "the node started $(booted) times before any update"

            # A full update first: the image has no header kept for what it runs, so nothing says a
            # kithd-only update is one. The node restarts into slot b, and keeps release a's header there.
            release a 9.0.0 "$(sign a)" a
            until_says "release a taken" "^Done 0 9.0.0 "
            grep -aq 'kithd: update: 9.0.0 is a full update (a restart): ' "$work/n1.log" || fail "release a was not said to be a full update"
            [ "$(booted)" = 2 ] && [ "$(starts 1 b)" = 1 ] || fail "the node did not restart once, into slot b: $(booted) starts, $(starts 1 b) in slot b"
            again "$process_was"
            boot boot1
            [ "$bootid" != "$first_boot" ] || fail "the boot id did not change over a restart ($bootid): it says nothing"
            boot_id=$bootid

            # The kithd-only release: no restart, so the machine keeps its boot id, the container its
            # process (the pid it says and when it started), and the node says the new version.
            process_was=$(process Workload ticker tick)
            [ -n "$process_was" ] || fail "the pod says no process: $(said Workload ticker tick)"
            ticks=$(ticked Workload ticker tick)
            taken=$(grep -ac 'of an earlier run still run, or ended while no kithd did' "$work/n1.log" || true) # (kithd's line for the units it takes back)
            release b 9.0.1 "$(sign b)" b
            until_says "release b (kithd alone) taken" "^Done 0 9.0.1 "
            grep -aq 'kithd: update: 9.0.1 differs from this system in kithd alone' "$work/n1.log" || fail "release b was not found to differ in kithd alone: $(grep -a 'kithd: update:' "$work/n1.log" | tail -n 3)"
            grep -aq 'kithd: kith OS 9.0.1 differs in kithd alone: handing over to the kithd staged' "$work/n1.log" || fail "kithd did not hand over: $(grep -a 'kithd: ' "$work/n1.log" | tail -n 5)"
            ! grep -aq 'kithd: kith OS 9.0.1 is in the other slot: restarting into it' "$work/n1.log" || fail "release b restarted the node"
            ! grep -aq 'the staged kithd failed within a minute' "$work/n1.log" || fail "the staged kithd failed"
            [ "$(booted)" = 2 ] && [ "$(starts 1 b)" = 1 ] || fail "the machine restarted for a kithd-only release: $(booted) starts"
            [ "$(grep -ac 'of an earlier run still run, or ended while no kithd did' "$work/n1.log")" -gt "$taken" ] || fail "the new kithd took no unit back"
            boot boot2
            [ "$bootid" = "$boot_id" ] || fail "the boot id changed over the hand-over: $boot_id, then $bootid"
            [ "$(process Workload ticker tick)" = "$process_was" ] || fail "the pod's process is not the one it was: $process_was, then $(process Workload ticker tick)"
            ticking $((ticks + 4))
            [ "$(process Workload ticker tick)" = "$process_was" ] || fail "the pod's process changed while it ticked on"
            echo "vm.sh: handed over to 9.0.1 with the boot id $boot_id and the pod's process ($process_was) kept, $(( $(ticked Workload ticker tick) - ticks )) ticks on" >&2

            # A release with another kernel is no hand-over: the node restarts into the other slot, a.
            release c 9.0.2 "$(sign c)" c
            until_says "release c (another kernel) taken" "^Done 0 9.0.2 "
            grep -aq 'kithd: update: 9.0.2 is a full update (a restart): the kernel image differs' "$work/n1.log" || fail "release c was not said to be a full update for its kernel: $(grep -a 'kithd: update:' "$work/n1.log" | tail -n 3)"
            grep -aq 'kithd: kith OS 9.0.2 is in the other slot: restarting into it' "$work/n1.log" || fail "the node did not restart into the other slot for release c"
            [ "$(booted)" = 3 ] && [ "$(starts 1 a)" = 2 ] && [ "$(starts 1 b)" = 1 ] || fail "the node did not restart once into slot a: $(booted) starts, $(starts 1 a) in a, $(starts 1 b) in b"
            again "$process_was"
            boot boot3
            [ "$bootid" != "$boot_id" ] || fail "the boot id did not change over the restart into slot a"
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node on disk files: a full release restarted it into slot b; a release that differs in kithd alone was handed over to with the boot id and the pod's process kept (it says 9.0.1, as the node does, with no restart); a release with another kernel restarted it into slot a"
            exit 0
