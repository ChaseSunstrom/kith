# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test privilege: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # One node started with --split (docs/adr-privilege.md). The serving part's confinement,
            # held to what it says: `kithd confine-probe DIR` (an exec unit, so as root) opens a
            # listener and a file in DIR, confines itself as the serving part does, then reads its own
            # status and mountinfo and tries what it must not do. With the filter, and with
            # --no-filter (which leaves the filter alone and nothing else). Then kithd is killed
            # with a pod running: it is started again, and the pod's process is the same.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"confined"},"spec":{"retries":0,"template":{"exec":[
  {"name":"probe","command":["/proc/1/exe","confine-probe","/var/lib/kith/confined"]}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"unfiltered"},"spec":{"retries":0,"template":{"exec":[
  {"name":"probe","command":["/proc/1/exe","confine-probe","/var/lib/kith/unfiltered","--no-filter"]}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"holding"},"spec":{"retries":0,"template":{"exec":[
  {"name":"probe","command":["/proc/1/exe","confine-probe","/var/lib/kith/holding","--hold-dir"]}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"ticker"},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"tick","image":"kith.test/pod:1","command":["/bin/pod","tick"]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the probes and the pod were not applied"
            # JOB: what its probe said, one line each, with the tabs of the kernel's text spaces.
            probed() { any GET "/v1/logs/Job/default/$1" 2>/dev/null | sed 's/\\n/\n/g; s/\\t/ /g'; }
            for job in confined unfiltered; do
                waited=0
                until probed "$job" | grep -q 'confine: filter'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 120 ] || fail "the probe $job did not finish: $(probed "$job" | head -n 20) $(units Job "$job")"
                    sleep 1
                done
                probed "$job" >"$work/$job.said"
                # (What it is, from the kernel: a user and a group that are not 0 and no other group, no
                # capability in any set, no_new_privs, and the filter, in "$job" it asked for.)
                for id in Uid Gid; do
                    [ "$(grep -o "confine: status $id: [0-9 ]*" "$work/$job.said" | tr -s ' ' | sed 's/ *$//')" = "confine: status $id: 4100 4100 4100 4100" ] || fail "$job: $id is not the serving part's alone: $(grep "status $id" "$work/$job.said")"
                done
                ! grep 'confine: status Groups:' "$work/$job.said" | grep -q '[0-9]' || fail "$job: it kept a group: $(grep 'status Groups' "$work/$job.said")"
                for set in CapInh CapPrm CapEff CapBnd CapAmb; do
                    [ "$(grep -o "confine: status $set: [0-9a-f]*" "$work/$job.said" | cut -d ' ' -f 4)" = 0000000000000000 ] || fail "$job: $set is not empty: $(grep "status $set" "$work/$job.said")"
                done
                [ "$(grep -o 'confine: status NoNewPrivs: [0-9]' "$work/$job.said" | cut -d ' ' -f 4)" = 1 ] || fail "$job: no_new_privs is not set"
                # (Its mounts: its root, its state directory and /proc, and no other.)
                mounts=$(grep -o 'confine: mountinfo .*' "$work/$job.said" | awk '{print $7}' | sort | tr '\n' ' ')
                [ "$mounts" = "/ /proc /var/lib/kith/$job " ] || fail "$job: its mounts are not its own state directory's alone: $mounts"
                # (Its state directory's mount: nosuid, nodev, noexec.)
                grep "confine: mountinfo .* /var/lib/kith/$job " "$work/$job.said" | awk '{print $8}' | grep -q 'noexec' || fail "$job: its state directory is mounted with exec: $(grep "mountinfo .* /var/lib/kith/$job " "$work/$job.said")"
                for held in 'serves ok' 'setuid refused' 'capability refused' 'disk refused' 'mount refused' 'procs refused \[\]' 'proc-global refused'; do
                    grep -q "confine: $held" "$work/$job.said" || fail "$job: not '$held': $(grep -a 'confine: ' "$work/$job.said" | grep -v 'mountinfo\|status')"
                done
            done
            # (A directory of the node open when it confines: refused, before anything is changed.)
            waited=0
            until probed holding | grep -q 'confine: hold'; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the probe holding did not finish: $(probed holding | head -n 20) $(units Job holding)"
                sleep 1
            done
            probed holding | grep -q 'confine: hold refused' || fail "holding: a directory held open was not refused: $(probed holding | head -n 20)"
            [ "$(grep -o 'confine: status Seccomp: [0-9]' "$work/confined.said" | cut -d ' ' -f 4)" = 2 ] || fail "confined: the filter is not on"
            grep -q 'confine: filter refused' "$work/confined.said" || fail "confined: a call outside the filter was not refused"
            # (The calls it lets through in part: a clone that makes a namespace of each kind, clone3, TIOCSTI.)
            for held in 'clone refused' 'clone3 refused' 'ioctl refused' 'socket refused'; do
                grep -q "confine: $held" "$work/confined.said" || fail "confined: not '$held': $(grep -a 'confine: ' "$work/confined.said" | grep 'clone\|ioctl\|socket')"
            done
            # (Without the filter the same clones are made, each with a user namespace: so the filter
            # is what refused them above, not a kernel that refuses a process with no capability.)
            grep -q 'confine: clone made' "$work/unfiltered.said" || fail "unfiltered: the namespaces were not made without the filter, so the refusal above shows nothing: $(grep -a 'confine: clone' "$work/unfiltered.said")"
            [ "$(grep -o 'confine: status Seccomp: [0-9]' "$work/unfiltered.said" | cut -d ' ' -f 4)" = 0 ] || fail "unfiltered: a filter is on with --no-filter"
            grep -q 'confine: filter off' "$work/unfiltered.said" || fail "unfiltered: it did not say the filter is off"
            echo "vm.sh: the confined process: $(grep -o 'confine: \(setuid\|capability\|disk\|mount\|filter\|clone3\|clone\|ioctl\|socket\|procs\|proc-global\) [a-z]*' "$work/confined.said" | cut -d ' ' -f 2- | tr '\n' ';')" >&2
            # kithd ended under a pod (--split): it is started again, and the pod goes on as the same process.
            said() { any GET "/v1/logs/$1/default/$2${3:+?unit=$3}" 2>/dev/null; }
            waited=0
            until [ "$(said Workload ticker tick | grep -o 'tick [0-9]*' | wc -l)" -ge 3 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "the pod did not tick: $(said Workload ticker tick)"
                sleep 1
            done
            before=$(said Workload ticker tick | grep -o 'tick: process [0-9]* started at [0-9]*')
            [ "$(printf '%s\n' "$before" | wc -l)" = 1 ] || fail "the pod did not say once which process it is: $before"
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
            [ "$(grep -ac 'Kernel command line' "$work/n1.log")" = "$booted" ] || fail "the machine restarted when kithd was killed"
            waited=0
            until [ "$(said Workload ticker tick | grep -o 'tick [0-9]*' | tail -n 1 | cut -d ' ' -f 2)" -gt 3 ] 2>/dev/null; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "the pod did not tick on after kithd was killed"
                sleep 1
            done
            [ "$(said Workload ticker tick | grep -o 'tick: process [0-9]* started at [0-9]*')" = "$before" ] || fail "the pod's process was not the same after kithd was killed"
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node with --split: the confined process holds uid and gid 4100, no capability in any set, no_new_privs, a filter, its own state directory's mount alone; setuid, a capability, the node's disk, a mount, a namespace made by clone, clone3 and TIOCSTI refused; kithd killed under a pod: started again, the pod the same process" >&2
            exit 0
