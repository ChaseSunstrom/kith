# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# shellcheck disable=SC2086 # (as the script had them before it was cut)
# Sourced by ci/vm.sh for --test pods: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # This machine, as something outside the cluster a pod asks: the nodes reach it
            # at 10.0.2.2, and only from an address their card out has (a pod's own is not
            # one the network out there knows).
            mkdir "$work/www"
            (cd "$work/www" && exec python3 -m http.server --bind 127.0.0.1 $((port + 9))) >/dev/null 2>&1 &
            web=$!
            # NAME and the rest of its one container: three pods of it on the two nodes, so
            # two of them on one, each listening on port 80, and a Service of that name.
            three() {
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"$1","labels":{"app":"$1"}},"spec":{"replicas":3,"template":{"pod":true,"containers":[
  {"name":"web",$2,"ports":[{"port":80}],"readiness":{"tcp":{"port":80}}}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Service","metadata":{"name":"$1"},"spec":{"selector":{"app":"$1"},"ports":[{"port":80}]}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the pods of $1 were not applied"
                waited=0
                until line=$(units Workload "$1") && [ "${line%% *}" = 3 ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for three pods of $1 to be ready; the Workload says: $line"
                    sleep 1
                done
                echo "vm.sh: three pods of $1 ready: $line" >&2
                [ "$(printf '%s\n' $line | grep : | sort -u | grep -c :)" = 3 ] || fail "the three pods of $1 do not have an address each on the mesh: $line"
            }
            # NAME and whom to ask (HOST PORT ...): a pod of a user who is not root asks
            # each, and writes what it heard to /dev/stdout by name; that is in $work/NAME.out.
            asks() {
                name=$1
                shift
                # ($pinned: a Volume that puts the Job on its node.)
                mounts=''
                [ -z "${pinned:-}" ] || mounts=",\"volumeMounts\":[{\"volume\":\"$pinned\",\"path\":\"/state\"}]"
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$name"},"spec":{"retries":0,"template":{"pod":true,"containers":[
  {"name":"ask","image":"kith.test/pod:user","command":["/bin/pod","ask"$(printf ',"%s"' "$@")]$mounts}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $name was not applied"
                waited=0
                until line=$(units Job "$name") && case $line in *' succeeded '* | *' succeeded') true ;; *) false ;; esac; do
                    waited=$((waited + 1))
                    any GET "/v1/logs/Job/default/$name?stderr=true" >"$work/$name.err" 2>/dev/null || true
                    case $line in *' failed '* | *' failed') fail "the Job $name failed: $line: $(cat "$work/$name.err")" ;; esac
                    [ "$waited" -lt 240 ] || fail "waited for the Job $name; it says: $line: $(cat "$work/$name.err")"
                    sleep 1
                done
                any GET "/v1/logs/Job/default/$name" >"$work/$name.out" || fail "what the Job $name wrote could not be read"
                ! grep -q 'failed: ' "$work/$name.out" || fail "the pod that asked was not always answered: $(cat "$work/$name.out")"
            }
            # Each makes a file in its root, as root, before it listens.
            three web '"image":"kith.test/pod:1","command":["/bin/pod","serve"]'
            # Their Service by its short name and by its whole one, and this machine.
            asks ask web 80 web.default.svc.cluster.local 80 10.0.2.2 $((port + 9))
            for heard in web-0 web-1 web-2 'HTTP/1.0 200 OK'; do
                grep -q "$heard" "$work/ask.out" || fail "the pod that asked did not hear $heard: $(cat "$work/ask.out")"
            done
            # A pod on each node (a Volume of its node puts it there) says where it asks for
            # names and from which address: the first node's in 100.88.0.0/16 (the default),
            # the second's in the range that node was told (--pod-range).
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on-n1"},"spec":{"node":"n1","path":"pod"}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on-n2"},"spec":{"node":"n2","path":"pod"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the volumes that put a pod on each node were not applied"
            for side in n1 n2; do
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"at-$side"},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"web","image":"kith.test/pod:1","command":["/bin/pod","serve"],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}},
   "volumeMounts":[{"volume":"on-$side","path":"/state"}]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the pod at-$side was not applied"
                waited=0
                until line=$(units Workload "at-$side") && [ "${line%% *}" = 1 ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for the pod at-$side to be ready; the Workload says: $line"
                    sleep 1
                done
                any GET "/v1/logs/Workload/default/at-$side?replica=0" >"$work/at-$side.out" || fail "what the pod at-$side wrote could not be read"
            done
            grep -qE 'where: nameserver 100\.88\.0\.1 from 100\.88\.[0-9]+\.[0-9]+' "$work/at-n1.out" || fail "the pod on n1 is not in the default range: $(cat "$work/at-n1.out")"
            grep -qE 'where: nameserver 10\.77\.0\.1 from 10\.77\.[0-9]+\.[0-9]+' "$work/at-n2.out" || fail "the pod on n2 is not in the range of --pod-range: $(cat "$work/at-n2.out")"
            # And one pod on n2 asks this machine, from behind its node's address: the node
            # sends it as its own only if the masquerade rule matches the range it was told.
            pinned='on-n2'
            asks egress 10.0.2.2 $((port + 9))
            pinned=''
            grep -q 'HTTP/1.0 200 OK' "$work/egress.out" || fail "the pod on n2 (range of --pod-range) did not reach this machine from behind its node: $(cat "$work/egress.out")"
            # A Workload of an image nothing else uses, deleted once it runs: its image is
            # looked for again at the end.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"gone"},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"web","image":"kith.test/gone:1","command":["/bin/pod","serve"],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}}}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Workload gone was not applied"
            waited=0
            until line=$(units Workload gone) && [ "${line%% *}" = 1 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "waited for the pod of gone to be ready; the Workload says: $line"
                sleep 1
            done
            api 1 DELETE /v1/resources/Workload/default/gone >/dev/null || fail "the Workload gone was not deleted"
            stock='no stock image was tried (KITH_E2E=1 pulls one)'
            if [ "${KITH_E2E:-}" = 1 ]; then
                # An image as its makers ship it, with nothing said but its name: nginx starts
                # as root, writes its configuration and its pid in its root, opens /dev/stdout
                # by name for what it is asked, and listens on port 80.
                three stock '"image":"mirror.gcr.io/library/nginx:1.27-alpine"'
                asks ask-stock stock 80
                grep -q 'HTTP/1.1 200 OK' "$work/ask-stock.out" || fail "nginx did not answer through its Service: $(cat "$work/ask-stock.out")"
                for replica in 0 1 2; do
                    any GET "/v1/logs/Workload/default/stock?replica=$replica" >"$work/stock.out" || fail "what nginx $replica wrote could not be read"
                    grep -q 'GET / HTTP/1.0' "$work/stock.out" || fail "the Service did not pass a request to nginx $replica, or it could not say so on /dev/stdout: $(cat "$work/stock.out")"
                done
                stock='three pods of nginx as it is shipped (mirror.gcr.io/library/nginx:1.27-alpine) started the same way, and each said on /dev/stdout that it was asked through their Service'
            fi

            # A Job of one container: NAME, more of its template, its container, and what the
            # Job comes to say. What it wrote is in $work/NAME.out and .err.
            job() {
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{$2"containers":[
  {"name":"box",$3}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
                waited=0
                until line=$(units Job "$1") && printf '%s\n' "$line" | grep -Eq "$4|^[0-9]+ (succeeded|failed)( |\$)"; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 120 ] || fail "waited for the Job $1; it says: $line"
                    sleep 1
                done
                any GET "/v1/logs/Job/default/$1" >"$work/$1.out" 2>/dev/null || true
                any GET "/v1/logs/Job/default/$1?stderr=true" >"$work/$1.err" 2>/dev/null || true
                printf '%s\n' "$line" | grep -Eq "$4" || fail "the Job $1 says: $line: $(cat "$work/$1.out" "$work/$1.err")"
            }
            # What node SIDE's state disk has free, as a pod there sees it (a Volume of the
            # node's is on that disk), asked by a Job NAME: the bytes are in $left.
            reserve=8388608
            spare() {
                job "$2" '"pod":true,' "\"image\":\"kith.test/pod:1\",\"command\":[\"/bin/pod\",\"free\",\"/state\"],\"volumeMounts\":[{\"volume\":\"on-$1\",\"path\":\"/state\"}]" '^[0-9]+ succeeded'
                left=$(grep -o 'free: /state [0-9]*' "$work/$2.out" | cut -d ' ' -f 3)
                [ -n "$left" ] || fail "the Job $2 did not say what $1 has free: $(cat "$work/$2.out" "$work/$2.err")"
            }
            # Each node starts with more free than its reserve: the full pod below crosses it.
            for side in n1 n2; do
                spare $side "free-$side"
                [ "$left" -gt $reserve ] || fail "$side's state disk has $left bytes free at the start, under its reserve of $reserve"
            done
            echo "vm.sh: each node's state disk above its reserve of $reserve at the start (n2: $left bytes free)" >&2
            # What holds a container to its devices: a pod that is root is root of a user
            # namespace of its own on kith OS, where the kernel makes no device node, not even
            # /dev/null again; its node's own disk it may neither make nor read. (NAME, block
            # or character, and where /sys has the device's numbers.)
            makes() { job "$1" '"pod":true,' "\"image\":\"kith.test/pod:1\",\"command\":[\"/bin/pod\",\"node\",\"$2\",\"$3\",\"/dev/made\"]" '^[0-9]+ succeeded'; }
            makes null c /sys/class/mem/null/dev
            grep -q 'node: made -1, read Err' "$work/null.out" || fail "a pod that is root made a device node in a user namespace of its own: $(cat "$work/null.out" "$work/null.err")"
            makes disk b /sys/class/block/vda/dev
            grep -q 'node: made -1, read Err' "$work/disk.out" || fail "a pod that is root was not kept from its node's disk: $(cat "$work/disk.out" "$work/disk.err")"

            # A sandbox inside a container (bubblewrap as this machine has it; Steam's runtime
            # and Flatpak start theirs so): a user namespace of its own, with a /proc and a
            # /dev made in it. NAME, more of its container, and what its Job comes to say.
            sandbox() { job "$1" '' "\"image\":\"kith.test/sandbox:1\"$2,\"command\":[\"/bin/bwrap\",\"--unshare-user\",\"--uid\",\"0\",\"--gid\",\"0\",\"--unshare-pid\",\"--ro-bind\",\"/\",\"/\",\"--proc\",\"/proc\",\"--dev\",\"/dev\",\"/bin/pod\",\"self\"]" "$3"; }
            # Only a container that asks may, and never one that is the node's root.
            sandbox boxed ',"userNamespaces":true' '^[0-9]+ succeeded'
            grep -q 'nested: pid 2, uid 0' "$work/boxed.out" || fail "the sandbox did not say where it found itself: $(cat "$work/boxed.out" "$work/boxed.err")"
            sandbox unboxed '' '^[0-9]+ failed'
            # (bubblewrap gives up there before it asks for a namespace, over the capability a
            # container keeps on kith OS; that the call itself is refused is the runtime's test.)
            ! grep -q nested "$work/unboxed.out" || fail "a container that did not ask started a sandbox: $(cat "$work/unboxed.out")"
            sandbox rooted ',"runAsUser":0,"userNamespaces":true' 'userNamespaces: this container is the node.s root'
            ! grep -q nested "$work/rooted.out" || fail "the node's root was let make a user namespace: $(cat "$work/rooted.out")"

            # A part of a Volume alone (subPath): made where it is not there, and opened beneath
            # the Volume with no link followed (the kubelet's CVE-2017-1002101). A pod leaves a
            # link to / in the Volume: a pod that mounts that link as its part does not start,
            # and one that mounts a plain part sees what another wrote there. (NAME, the
            # command's words, more of its mount, and what its Job comes to say.)
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"parts"},"spec":{"node":"n2","path":"parts"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Volume parts was not applied"
            part() { job "$1" '"pod":true,' "\"image\":\"kith.test/pod:1\",\"command\":[\"/bin/pod\",$2],\"volumeMounts\":[{\"volume\":\"parts\",\"path\":\"/v\"$3}]" "$4"; }
            part plant '"link","/","/v/escape"' '' '^[0-9]+ succeeded'
            grep -q 'link: /v/escape -> /: Ok' "$work/plant.out" || fail "the pod that plants a link did not make it: $(cat "$work/plant.out" "$work/plant.err")"
            part escape '"ids","/v/sbin/init"' ',"subPath":"escape"' 'subPath .escape.'
            ! grep -q 'opens Ok' "$work/escape.out" || fail "a pod reached its node's root through a link in its Volume: $(cat "$work/escape.out")"
            api 1 DELETE /v1/resources/Job/default/escape >/dev/null || fail "the Job escape was not deleted"
            part writer '"ids","+/v/note"' ',"subPath":"shared/deep"' '^[0-9]+ succeeded'
            part reader '"ids","=/v/note"' ',"subPath":"shared/deep"' '^[0-9]+ succeeded'
            grep -q 'ids: =/v/note holds Ok("made")' "$work/reader.out" || fail "a pod did not see in its part what another wrote there: $(cat "$work/writer.out" "$work/reader.out" "$work/reader.err")"
            echo "vm.sh: ok: a subPath through a link to / was refused at its start; a plain one, made, was shared" >&2

            # A tun device (a VPN's): the one way a pod has it is a Device of class other with its
            # path, given to the namespace and claimed (docs/guide/hardware.md). Without the claim
            # a root pod has no /dev/net/tun to open; with it, it opens.
            tun() { job "$1" "\"pod\":true,$2" "\"image\":\"kith.test/pod:1\",\"command\":[\"/bin/pod\",\"ids\",\"/dev/net/tun\"]" '^[0-9]+ succeeded'; }
            tun notun ''
            ! grep -q 'opens Ok' "$work/notun.out" || fail "a pod with no claim opened /dev/net/tun: $(cat "$work/notun.out")"
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Device","metadata":{"name":"n2-tun","labels":{"kith.dev/namespaces":"default"}},"spec":{"node":"n2","class":"other","path":"/dev/net/tun"}},
 {"apiVersion":"kith.dev/v1","kind":"DeviceClaim","metadata":{"name":"tun"},"spec":{"device":"n2-tun"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Device n2-tun and its claim were not applied"
            tun withtun '"deviceClaims":["tun"],'
            grep -q 'ids: /dev/net/tun /dev/net/tun owner [0-9]* opens Ok' "$work/withtun.out" || fail "a pod whose claim names the tun Device did not open /dev/net/tun: $(cat "$work/withtun.out" "$work/withtun.err")"
            echo "vm.sh: ok: /dev/net/tun opens only in a pod that claims a Device of it" >&2

            # The seat is kith-system's until its label names the namespace that claims it: the
            # node's discovered Seat is given to default here, as an admin would label it.
            any GET /v1/resources >"$work/seat.json" || fail "the resources could not be read"
            python3 -c '
import json, sys
found = [r for r in json.load(open(sys.argv[1])) if r.get("kind") == "Seat" and r["metadata"]["name"] == "n1-seat0"]
assert len(found) == 1, "no Seat n1-seat0"
found[0]["metadata"].pop("revision", None)
found[0]["metadata"].setdefault("labels", {})["kith.dev/namespaces"] = "default"
json.dump(found, open(sys.argv[2], "w"))
' "$work/seat.json" "$work/seat-label.json" || fail "the seat n1-seat0 was not found to label: $(cat "$work/seat.json")"
            any POST /v1/apply "$work/seat-label.json" >/dev/null || fail "the seat n1-seat0 was not given to the namespace default"
            # A session's input: a keyboard plugged in while a container holds the seat is
            # one more node in its /dev that it can open, and nothing is started again for it.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"DeviceClaim","metadata":{"name":"seat"},"spec":{"seat":"n1-seat0"}},
 {"apiVersion":"kith.dev/v1","kind":"DeviceClaim","metadata":{"name":"apps"},"spec":{"seat":"n1-seat0","access":"client"}},
 {"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"session"},"spec":{"template":{"deviceClaims":["seat"],"containers":[
  {"name":"sees","image":"kith.test/pod:1","command":["/bin/pod","seen","/dev/input","/run/seat/wayland-0"]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the session and its claim on the seat were not applied"
            # How many nodes it can open, by the last it said.
            opens() { any GET /v1/logs/Workload/default/session 2>/dev/null | field data | grep '^seen:' | tail -n 1 | tr ' ' '\n' | grep -c '+$'; }
            comes_to() { # WHAT, and a test of how many it opens now against $had
                waited=0
                until now=$(opens) && test "$now" "$2" "$had"; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 120 ] || fail "waited for $1; it opens $now, and says: $(any GET /v1/logs/Workload/default/session 2>&1 | tail -n 3); the Workload: $(units Workload session)"
                    sleep 1
                done
            }
            plug() { echo "$1" | socat - "unix-connect:$work/keys1" >/dev/null; } # what the first node's machine is told
            had=0
            comes_to "the session to open the seat's input devices" -gt
            had=$now
            plug 'device_add usb-kbd,id=pad,bus=usb.0'
            comes_to "the session to open the keyboard plugged in" -gt
            grep -aq 'its input devices changed, and it has them as it runs' "$work/n1.log" || fail "the first node did not say it gave the session the keyboard as it ran"
            plug 'device_del pad'
            # An app as a workload of its own: a client of the seat is beside the session, and
            # finds the socket the session listens on in the seat's directory, which it may
            # not write; one that is another user finds nothing there. (The session's socket
            # stands in for a compositor's.)
            app() { job "$1" '"deviceClaims":["apps"],' "\"image\":\"kith.test/pod:1\"$2,\"command\":[\"/bin/pod\",\"call\",\"/run/seat/wayland-0\"]" '^[0-9]+ succeeded'; }
            app window ''
            grep -q 'called: a window, wrote Err(ReadOnlyFilesystem)' "$work/window.out" || fail "an app of the seat did not reach its session's socket, or could write the seat's directory: $(cat "$work/window.out" "$work/window.err")"
            app stranger ',"runAsUser":1000'
            grep -q 'called: failed: PermissionDenied' "$work/stranger.out" || fail "another user's app was not kept from the session's socket: $(cat "$work/stranger.out" "$work/stranger.err")"

            comes_to "the session to lose the keyboard pulled" -eq
            any GET /v1/resources >"$work/found.json" || fail "the cluster's resources could not be read"
            again=$(python3 -c '
import json, sys
found = json.load(open(sys.argv[1]))
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
units = [u for r in found if r["kind"] == "Workload" and r["metadata"]["name"] == "session" for u in (r.get("status") or {}).get("containers") or []]
print(len(units), sum(u.get("restarts", 0) for u in units))' "$work/found.json")
            [ "$again" = '1 0' ] || fail "the session was started again for its keyboard (units, restarts): $again"

            # A long Job keeps its place on a Volume of the node it runs on (README, "Restarting
            # a node on purpose"). The node is drained: the plan is answered, and the Job asked
            # for again is not started there. The drain taken off, it runs and goes on from
            # the step the first one left.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"train-state"},"spec":{"node":"n2","path":"train"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Volume of the Job's state was not applied"
            train='"image":"kith.test/pod:1","command":["/bin/pod","count","/state"],"volumeMounts":[{"volume":"train-state","path":"/state"}]'
            job train '' "$train" '^[0-9]+ succeeded'
            grep -q 'began: step 1' "$work/train.out" || fail "the Job that keeps its step did not begin at the first: $(cat "$work/train.out" "$work/train.err")"
            api 1 GET /v1/drain/n2 >"$work/plan.json" || fail "the plan of a drain of n2 was not answered"
            python3 -c 'import json, sys; assert isinstance(json.load(open(sys.argv[1])), list)' "$work/plan.json" || fail "the plan of a drain is not a list: $(cat "$work/plan.json")"
            api 1 POST '/v1/drain/n2?do=drain' >/dev/null || fail "n2 was not drained"
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"train-again"},"spec":{"retries":0,"template":{"containers":[{"name":"box",$train}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job train-again was not applied"
            sleep 15
            line=$(units Job train-again)
            ! printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)' || fail "a Job was started on a drained node: $line"
            echo "vm.sh: n2 drained: a Job whose Volume is there waits ($line)" >&2
            api 1 POST '/v1/drain/n2?do=undrain' >/dev/null || fail "the drain was not taken off n2"
            job train-again '' "$train" '^[0-9]+ succeeded'
            grep -q 'went on from step 1: step 2' "$work/train-again.out" || fail "the Job run again after the drain did not go on from the first's step: $(cat "$work/train-again.out" "$work/train-again.err")"
            echo "vm.sh: the drain off: the Job ran and went on from the step the first left on its Volume" >&2

            # What a pod writes outside its Volumes is counted (README, resources.storage). NAME,
            # more of its container, how many bytes it writes to /fill, and what its replacement
            # says: it is replaced, says why, and starts again from an empty root.
            fills() {
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"$1"},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"fill","image":"kith.test/pod:1","command":["/bin/pod","fill","/fill","$3"]$2}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Workload $1 was not applied"
                waited=0
                until line=$(units Workload "$1") && printf '%s\n' "$line" | grep -q "$4" \
                    && any GET "/v1/logs/Workload/default/$1?replica=0" >"$work/$1.out" 2>/dev/null \
                    && [ "$(grep -o 'fill: an empty root' "$work/$1.out" | wc -l)" -ge 2 ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for $1 to be replaced and start again; it says: $line: $(cat "$work/$1.out")"
                    sleep 1
                done
                ! grep -q 'fill: /fill was there' "$work/$1.out" || fail "$1 started again with what it wrote in its root: $(cat "$work/$1.out")"
                ! grep -q 'fill: a write failed' "$work/$1.out" || fail "$1 filled its node's state disk before it was replaced: $(cat "$work/$1.out")"
                grep -aq "kithd: .*$4" "$work"/n?.log || fail "no node said on its console why $1 was replaced"
                api 1 DELETE "/v1/resources/Workload/default/$1" >/dev/null || fail "the Workload $1 was not deleted"
                echo "vm.sh: $1 replaced and started again from an empty root: $line" >&2
            }
            # Past its limit of 1 MiB at about 128 KiB a second.
            fills over ',"resources":{"storage":"1Mi"}' 2097152 'replaced: its pod wrote [0-9]* bytes outside its volumes, over its limit of 1048576'
            # With no limit, writing until its node's disk is full: it is replaced once the disk
            # has less free than its reserve, and its write never fails. First a ballast brings
            # n2's disk to 16 MiB above its reserve, fast: a named file in a Volume (not the pod's
            # own, so not counted and not what is replaced; one held with no name would be). Then
            # full, on n2 too, crosses the reserve at its own pace: above it, it runs; under it,
            # replaced. Then the ballast is emptied, so n2 has its room back.
            spare n2 free-ballast
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"ballast"},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"fill","image":"kith.test/pod:1","command":["/bin/pod","fill","/state/ballast","$((left - reserve - 16777216))","fast"],
   "volumeMounts":[{"volume":"on-n2","path":"/state"}]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Workload ballast was not applied"
            waited=0
            until any GET "/v1/logs/Workload/default/ballast?replica=0" >"$work/ballast.out" 2>/dev/null && grep -q 'fill: wrote' "$work/ballast.out"; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "the ballast did not end its writes: $(units Workload ballast): $(cat "$work/ballast.out" 2>/dev/null)"
                sleep 1
            done
            ! grep -q 'fill: a write failed' "$work/ballast.out" || fail "the ballast filled n2's disk: $(cat "$work/ballast.out")"
            spare n2 free-full
            if [ "$left" -le $reserve ] || [ "$left" -gt $((reserve + 16777216 + 4194304)) ]; then
                fail "the ballast left n2 $left bytes free, not just above its reserve of $reserve"
            fi
            echo "vm.sh: the ballast left n2 $left bytes free, above its reserve" >&2
            fills full ',"volumeMounts":[{"volume":"on-n2","path":"/state"}]' 1073741824 'replaced: the node.s state disk has [0-9]* bytes free, under its reserve of 8388608'
            api 1 DELETE "/v1/resources/Workload/default/ballast" >/dev/null || fail "the Workload ballast was not deleted"
            # Emptied by a pod of its own: fill opens it with truncation and writes nothing.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"unballast"},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"fill","image":"kith.test/pod:1","command":["/bin/pod","fill","/state/ballast","0","fast"],
   "volumeMounts":[{"volume":"on-n2","path":"/state"}]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Workload unballast was not applied"
            waited=0
            until any GET "/v1/logs/Workload/default/unballast?replica=0" >"$work/unballast.out" 2>/dev/null && grep -q 'fill: wrote 0 bytes' "$work/unballast.out"; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the ballast was not emptied: $(units Workload unballast): $(cat "$work/unballast.out" 2>/dev/null)"
                sleep 1
            done
            api 1 DELETE "/v1/resources/Workload/default/unballast" >/dev/null || fail "the Workload unballast was not deleted"
            # Past its limit with a file it removed and holds open: no name to walk to, still counted.
            fills unlinked ',"resources":{"storage":"1Mi"}' '2097152","unlinked' 'replaced: its pod wrote [0-9]* bytes outside its volumes, over its limit of 1048576'

            # The deleted Workload's image went, from the node it ran on, once unused for its
            # grace (looked at once a minute; the state disks are above their reserve again,
            # checked first, so it goes for its grace and not for want of room). That
            # of web, running on the first node all along (it is never drained), stayed there,
            # and web still answers.
            for side in n1 n2; do
                waited=0
                until spare $side "free-again-$side-$waited" && [ "$left" -gt $reserve ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 10 ] || fail "$side's state disk has $left bytes free after the fills, under its reserve of $reserve"
                    sleep 3
                done
            done
            gone=$(printf gone | sha256sum | cut -d ' ' -f 1)
            waited=0
            until grep -aq "kithd: removed image sha256:$gone, unused for [0-9]* s (past its grace)" "$work"/n?.log; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "the image of the deleted Workload gone was not removed past its grace: $(grep -ah 'kithd: .*image' "$work"/n?.log)"
                sleep 1
            done
            pod=$(printf pod | sha256sum | cut -d ' ' -f 1)
            ! grep -aq "kithd: removed image sha256:$pod" "$work/n1.log" || fail "the image of web was removed from the node it runs on: $(grep -a 'kithd: remov' "$work/n1.log")"
            asks ask-after web 80
            grep -q 'web-' "$work/ask-after.out" || fail "web did not answer after an image was removed: $(cat "$work/ask-after.out")"
            grep -ah 'kithd: .*image' "$work"/n?.log | tr -d '\r' | sed 's/^/vm.sh: /' >&2

            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: two nodes on the mesh and three pods of one Workload on them, each with an address of its own on the mesh and its IPv4 one from its node's range (the second node's from --pod-range, the first's the default; a pod on each said which at its node's DNS), each listening on port 80 as root and writing to its root; a pod of a user who is not root found their Service by its short name and by its Kubernetes one at the node's DNS, was answered by all three through it, reached this machine from behind its node's address, and wrote what it heard to /dev/stdout by name; $stock; a pod that is root made /dev/null again and read it, and could neither make nor read its node's disk; a container that asked for user namespaces started a sandbox of its own in it (bubblewrap: a user namespace, with a /proc and a /dev made in it), one that did not ask started none, and one that is the node's root was not started; a keyboard plugged in while a container held the seat was one more node it could open, and gone from it when pulled, with nothing started again; an app that was a client of the seat was answered on the socket the seat's session listened on in the seat's directory and could make no file there, and one of another user was not let in; a pod past its limit on what it writes, one past it with a file it removed and held open, and one filling its node's state disk past the reserve, were replaced, said why and started again from an empty root; the image of a Workload deleted went from its node once unused for its grace, and that of a running one stayed and its pods answered"
            exit 0
