# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# shellcheck disable=SC2086 # (as the script had them before it was cut)
# Sourced by ci/vm.sh for --test policy: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # Two nodes whose policy turns off exec units, VM paths and /v1/run: nothing the
            # store can ask starts a process as the node's root with every capability, so kithd
            # cut its bounding set at start (README, SECURITY.md). All else is allowed, and
            # what is allowed still runs: a pod that is root, a container with no filter on its
            # system calls, and a sandbox inside a container.
            held() { # each node: "NAME CAPABILITY CAPABILITY ..." as its own status says
                any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    if r["kind"] == "Node":
        print(r["metadata"]["name"], *((r.get("status") or {}).get("policy") or {}).get("capabilities", ["-"]))
'
            }
            waited=0
            until [ "$(held | grep -c '^n[0-9] [^-]')" = 2 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the two nodes did not both say what they hold: $(held)"
                sleep 1
            done
            held >"$work/held"
            echo "vm.sh: what the nodes hold: $(tr '\n' ';' <"$work/held")" >&2
            for n in n1 n2; do
                line=$(grep "^$n " "$work/held") || fail "the node $n did not say what it holds: $(cat "$work/held")"
                case " $line " in *' all '*) fail "the node $n was not cut: $line" ;; esac
                for forbidden in SYS_MODULE SYS_RAWIO SYS_PTRACE SYS_TIME; do
                    case " $line " in *" $forbidden "*) fail "the node $n kept $forbidden: $line" ;; esac
                done
                # (And what the kernel says of kithd, read by it from /proc/PID/status and from a
                # thread it made after the cut, once on its console: the bounding set is exactly
                # what is kept, a later thread's too; the effective set is not cut, so it holds
                # what the bounding set does not, and a later thread's is the same.)
                # (A node's console reaches its log a little after kithd writes it: asked for up to
                # 30 s, not once.)
                said=''
                for _ in $(seq 30); do
                    said=$(grep -ao 'kithd: capability bounding set cut: CapBnd [0-9a-f]* CapEff [0-9a-f]*; a later thread: CapBnd [0-9a-f]* CapEff [0-9a-f]*' "$work/${n}.log" | tail -n 1)
                    [ -n "$said" ] && break
                    sleep 1
                done
                [ -n "$said" ] || fail "the node $n did not say its bounding set was cut: $(grep -a 'kithd:' "$work/${n}.log" | head -n 5)"
                echo "vm.sh: kithd on $n: ${said#kithd: capability bounding set cut: }" >&2
                # shellcheck disable=SC2046
                python3 -c '
import sys
bnd, eff, lbnd, leff = (int(w, 16) for w in sys.argv[1:5])
kept = 0xA80425FB  # CHOWN DAC_OVERRIDE FOWNER FSETID KILL SETGID SETUID SETPCAP NET_BIND_SERVICE NET_RAW SYS_CHROOT MKNOD AUDIT_WRITE SETFCAP
sys.exit(bnd != kept or lbnd != kept or eff & ~bnd == 0 or leff != eff)
' $(printf '%s\n' "$said" | grep -o '[0-9a-f]\{16\}') || fail "kithd on $n: its bounding set is not what it kept, or its effective set was cut: $said"
            done

            # A Job of one container, on a node by a Volume of that node: NAME, the node, the container.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on-n1"},"spec":{"node":"n1","path":"pod"}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on-n2"},"spec":{"node":"n2","path":"pod"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the volumes that put a pod on each node were not applied"
            podded=true # (false: a container that is not a pod)
            job() {
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{"pod":$podded,"containers":[
  {"name":"box","volumeMounts":[{"volume":"on-$2","path":"/state"}],$3}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
                waited=0
                until line=$(units Job "$1") && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 180 ] || fail "waited for the Job $1; it says: $line"
                    sleep 1
                done
                any GET "/v1/logs/Job/default/$1" >"$work/$1.out" 2>/dev/null || true
                any GET "/v1/logs/Job/default/$1?stderr=true" >"$work/$1.err" 2>/dev/null || true
                printf '%s\n' "$line" | grep -Eq '^[0-9]+ succeeded' || fail "the Job $1 says: $line: $(cat "$work/$1.out" "$work/$1.err")"
            }
            # A pod that is root, on the joined node.
            job rooted n2 '"image":"kith.test/pod:1","command":["/bin/pod","tell"]'
            grep -q 'tell: started uid 0 ' "$work/rooted.out" || fail "the pod that is root did not start as root: $(cat "$work/rooted.out" "$work/rooted.err")"
            # (A pod's own bounding set is what its spec says, the fourteen of a root pod
            # whatever kithd's is: that it is what the node kept shows the spec and the cut
            # agree, not the cut, which only kithd's own CapBnd above shows. The same of a
            # container that is not a pod and is root: its spec says three.)
            grep -m1 'tell: started uid 0 ' "$work/rooted.out" | sed 's/^/vm.sh: the pod that is root: /' >&2
            [ "$(grep -m1 'tell: started uid 0 ' "$work/rooted.out" | sed 's/.* bnd //; s/[^0-9a-f].*//' | python3 -c 'import sys; print(int(sys.stdin.read().strip() or "0", 16))')" = $((0xA80425FB)) ] || fail "the bounding set of the pod that is root is not what the node kept: $(cat "$work/rooted.out")"
            # A container that is root and not a pod, naming no capability: what it holds is its
            # spec's three (the runtime's default), on a cut node as on any, so it reads the same
            # as it would uncut; the cut itself is only in kithd's own CapBnd, above.
            podded=false
            job plain n1 '"image":"kith.test/pod:1","runAsUser":0,"command":["/bin/pod","tell"]'
            podded=true
            grep -q 'tell: started uid 0 ' "$work/plain.out" || fail "the container that is root and not a pod did not start as root: $(cat "$work/plain.out" "$work/plain.err")"
            grep -m1 'tell: started uid 0 ' "$work/plain.out" | sed 's/^/vm.sh: the container that is root and not a pod: /' >&2
            [ "$(grep -m1 'tell: started uid 0 ' "$work/plain.out" | sed 's/.* bnd //; s/[^0-9a-f].*//' | python3 -c 'import sys; print(int(sys.stdin.read().strip() or "0", 16))')" = $((0x20000420)) ] || fail "the container that is root and not a pod does not hold its spec's three (AUDIT_WRITE, KILL, NET_BIND_SERVICE): $(cat "$work/plain.out")"
            # A container with no filter on its system calls.
            job open n1 '"image":"kith.test/pod:1","seccomp":{"unconfined":true},"command":["/bin/pod","tell"]'
            grep -q 'tell: started uid 0 ' "$work/open.out" || fail "the container with no filter did not start: $(cat "$work/open.out" "$work/open.err")"
            # A sandbox inside a container (bubblewrap, in a user namespace of its own).
            job boxed n1 '"image":"kith.test/sandbox:1","userNamespaces":true,"command":["/bin/bwrap","--unshare-user","--uid","0","--gid","0","--unshare-pid","--ro-bind","/","/","--proc","/proc","--dev","/dev","/bin/pod","self"]'
            grep -q 'nested: pid 2, uid 0' "$work/boxed.out" || fail "the sandbox did not say where it found itself: $(cat "$work/boxed.out" "$work/boxed.err")"

            # What the node is for still runs on the cut node. A container is forked, cloned
            # and exec'd by libcontainer from kithd, which has the cut set when it does (its
            # volumes, its network, its user); the shim is only for exec units, which are off.
            # (a) A volume of the node's own, on each node: one pod writes it, the next reads it.
            for node in n1 n2; do
                job "keep-a-$node" "$node" '"image":"kith.test/pod:1","command":["/bin/pod","count","/state"]'
                job "keep-b-$node" "$node" '"image":"kith.test/pod:1","command":["/bin/pod","count","/state"]'
                grep -q 'began: step 1' "$work/keep-a-$node.out" || fail "the pod on $node wrote nothing to its node's volume: $(cat "$work/keep-a-$node.out" "$work/keep-a-$node.err")"
                grep -q 'went on from step 1: step 2' "$work/keep-b-$node.out" || fail "the next pod on $node did not read what the first wrote to the volume: $(cat "$work/keep-b-$node.out" "$work/keep-b-$node.err")"
                echo "vm.sh: a volume of node $node: $(cat "$work/keep-a-$node.out"); then: $(cat "$work/keep-b-$node.out")" >&2
            done
            # (b) A volume of the first node, shared, mounted by a container on the second (what
            # --test share does of it): written there, seen on the first.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"data"},"spec":{"node":"n1","path":"all","shared":true}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on1"},"spec":{"node":"n1","path":"own"}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on2"},"spec":{"node":"n2","path":"own"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the shared volume was not applied"
            keygen() { # NAME NODE FILE: a Job that makes FILE in the shared volume (kith's own keygen, which refuses one that is there), on NODE
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{"containers":[
  {"name":"run","image":"kith.test/kith:1","command":["/bin/kith","package","keygen","/data/$3"],
   "volumeMounts":[{"volume":"data","path":"/data"},{"volume":"on${2#n}","path":"/here"}]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
                waited=0
                until line=$(units Job "$1") && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 180 ] || fail "waited for the Job $1; it says: $line"
                    sleep 1
                done
                any GET "/v1/logs/Job/default/$1?stderr=true" >"$work/$1.err" 2>/dev/null || true
            }
            # (The first mount asks the other node for 2 seconds only; on a loaded machine the
            # first packet over the mesh may take longer, so a Job that was refused for that is
            # made again, a few times, and each refusal is said.)
            for attempt in 1 2 3 4 5; do
                keygen "shared-write-$attempt" n2 from-n2
                case $line in *'does not serve it'*) echo "vm.sh: attempt $attempt: $line" >&2 ;; *) break ;; esac
                sleep 10
            done
            printf '%s\n' "$line" | grep -Eq '^[0-9]+ succeeded' || fail "the container on n2 made nothing in the first node's shared volume: $line: $(cat "$work/shared-write-$attempt.err")"
            grep -aq 'kithd: mounted volume default/data from node n1' "$work/n2.log" || fail "the second node did not say it mounted the first node's volume"
            grep -aq 'kithd: serving [0-9]* shared volume' "$work/n1.log" || fail "the first node did not say it serves the volume"
            keygen shared-again n1 from-n2
            printf '%s\n' "$line" | grep -Eq '^[0-9]+ failed' || fail "the container on n1 made a file that the one on n2 made: $line"
            grep -q '/data/from-n2: File exists' "$work/shared-again.err" || fail "the container on n1 did not find what the one on n2 wrote: $(cat "$work/shared-again.err")"
            echo "vm.sh: a shared volume of n1, written from n2 and seen on n1: $(grep -a 'File exists' "$work/shared-again.err" | head -n 1)" >&2
            # (c) A pod whose container is not root. (This test runs no command in a running
            # pod, and no exec probe: what kithd does in a pod's namespaces for itself is the
            # network a pod joins as it starts, which each
            # pod here did, and the /proc/PID/root of a pod that is given an input device as
            # it is plugged, which no VM here has.)
            job lowly n2 '"image":"kith.test/pod:user","command":["/bin/pod","tell"]'
            grep -q 'tell: started uid 1000 ' "$work/lowly.out" || fail "the pod of a user who is not root did not start as that user: $(cat "$work/lowly.out" "$work/lowly.err")"
            grep -m1 'tell: started uid 1000 ' "$work/lowly.out" | sed 's/^/vm.sh: the pod that is not root: /' >&2
            # (d) Three pods of one Workload on the two nodes, each listening on port 80 at an
            # address of its own on the mesh, and a Service: a pod on the second node asks the
            # Service's name and is answered by each.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"web","labels":{"app":"web"}},"spec":{"replicas":3,"template":{"pod":true,"containers":[
  {"name":"web","image":"kith.test/pod:1","command":["/bin/pod","serve"],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}}}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Service","metadata":{"name":"web"},"spec":{"selector":{"app":"web"},"ports":[{"port":80}]}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the pods of web were not applied"
            waited=0
            until line=$(units Workload web) && [ "${line%% *}" = 3 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "waited for three pods of web to be ready; the Workload says: $line"
                sleep 1
            done
            [ "$(printf '%s\n' $line | grep : | sort -u | grep -c :)" = 3 ] || fail "the three pods of web do not have an address each on the mesh: $line"
            webs=$line
            job asker n2 '"image":"kith.test/pod:user","command":["/bin/pod","ask","web.default.svc.cluster.local","80"]'
            for heard in web-0 web-1 web-2; do
                grep -q "$heard" "$work/asker.out" || fail "the pod that asked the Service did not hear $heard: $(cat "$work/asker.out" "$work/asker.err")"
            done
            ! grep -q 'failed: ' "$work/asker.out" || fail "the pod that asked was not always answered: $(cat "$work/asker.out")"
            echo "vm.sh: three pods of web ready ($webs); a pod on n2 asked the Service and heard: $(tr '\n' ' ' <"$work/asker.out")" >&2

            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: two nodes on the mesh whose policy turns off exec units, VM paths and /v1/run cut their bounding set (kithd's own CapBnd, and a later thread's, was the fourteen a root pod keeps and its CapEff was not cut; each node's status named what was kept) and ran a pod that is root (on the joined node, holding its spec's fourteen), a container that is root and not a pod (holding its spec's three), a container with no filter on its system calls and a sandbox inside a container; a volume of each node's own was written by one pod and read by the next, a shared volume of the first node was written from the second and seen on the first, a pod of a user who is not root started, and three pods of a Workload on both nodes were answered through their Service by a pod on the second"
            exit 0
