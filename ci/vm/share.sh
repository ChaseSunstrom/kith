# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# shellcheck disable=SC2015 # (as the script had them before it was cut)
# Sourced by ci/vm.sh for --test share: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # What a Job says of itself and of its unit: "STATE and what it says"; nothing
            # while there is no such Job.
            job() {
                any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    if r["kind"] == "Job" and r["metadata"]["name"] == sys.argv[1]:
        status = r.get("status") or {}
        units = status.get("containers") or [{}]
        print(status.get("state", "-"), status.get("message", ""), units[0].get("message", ""), status.get("notes", ""))
' "$1"
            }
            until_job() { # NAME STATE: wait for the Job to end that way
                waited=0
                until line=$(job "$1") && [ "${line%% *}" = "$2" ]; do
                    case ${line%% *} in succeeded | failed) fail "the Job $1 $line; expected: $2" ;; esac
                    waited=$((waited + 1))
                    [ "$waited" -lt $((time / 2)) ] || fail "waited for the Job $1 to have $2; it says: $line"
                    sleep 1
                done
                echo "vm.sh: the Job $1 $2" >&2
            }
            # A Job whose container makes a new file in the shared volume (kith's own keygen:
            # it refuses a file that is there). The volume of one node it also mounts is what
            # puts it on that node.
            run() { # NAME THAT-NODE'S-VOLUME FILE
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{"containers":[
  {"name":"run","image":"kith.test/kith:1","command":["/bin/kith","package","keygen","/data/$3"],
   "volumeMounts":[{"volume":"data","path":"/data"},{"volume":"$2","path":"/here"}]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
            }
            refused() { # NAME FILE: the Job failed because FILE was there already
                any GET "/v1/logs/Job/default/$1?stderr=true" >"$work/$1.err" 2>/dev/null || true
                grep -q "/data/$2: File exists" "$work/$1.err" || fail "the Job $1 did not fail for /data/$2 being there: $(cat "$work/$1.err"); it says: $(job "$1")"
            }
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"data"},"spec":{"node":"n1","path":"all","shared":true}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"roots"},"spec":{"node":"n1","path":"all","shared":true}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on1"},"spec":{"node":"n1","path":"own"}},
 {"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"on2"},"spec":{"node":"n2","path":"own"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the volumes were not applied"

            # Written on the second node, through the first node's volume; there on the first.
            run write on2 from-n2
            until_job write succeeded
            grep -aq 'kithd: mounted volume default/data from node n1' "$work/n2.log" || fail "the second node did not say it mounted the volume"
            grep -aq 'kithd: serving [0-9]* shared volume' "$work/n1.log" || fail "the first node did not say it serves the volume"
            run again on1 from-n2
            until_job again failed
            refused again from-n2
            # And the other way: written on the first node, there on the second.
            run here on1 from-n1
            until_job here succeeded
            run across on2 from-n1
            until_job across failed
            refused across from-n1

            # Those containers were not root: /dev is root's, and a key cannot be made there
            # but by a container whose template says it is root.
            user() { # NAME [USER]
                as=''
                [ -z "${2:-}" ] || as=",\"runAsUser\":$2"
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{"containers":[
  {"name":"run","image":"kith.test/kith:1","command":["/bin/kith","package","keygen","/dev/key"]$as}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
            }
            user nobody
            until_job nobody failed
            any GET "/v1/logs/Job/default/nobody?stderr=true" >"$work/nobody.err" 2>/dev/null || true
            grep -q 'Permission denied' "$work/nobody.err" || fail "a container that names no user was not kept out of /dev as one that is not root is: $(cat "$work/nobody.err")"
            user root 0
            until_job root succeeded

            # A container on the node's network keeps the node's users (a port it serves is
            # under 1024 as often as not, and no capability of a user namespace reaches that
            # network), and the node's ports under 1024 stay its root's.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"node-ids"},"spec":{"retries":0,"template":{"containers":[
  {"name":"run","image":"kith.test/pod:1","command":["/bin/pod","ids","=/proc/sys/net/ipv4/ip_unprivileged_port_start"],"runAsUser":0,
   "volumeMounts":[{"volume":"on1","path":"/here"}]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job node-ids was not applied"
            until_job node-ids succeeded
            said=$(any GET /v1/logs/Job/default/node-ids | field data) || fail "what the Job node-ids said could not be read"
            printf '%s\n' "$said" | grep -q '^ids: map 0 0 4294967295$' || fail "a container on the node's network did not keep the node's users: $said"
            printf '%s\n' "$said" | grep -q '^ids: =/proc/sys/net/ipv4/ip_unprivileged_port_start holds Ok("1024")$' || fail "the node's ports under 1024 are not its root's alone: $said"

            # A pod's root is not the node's: its ids are a range of the node's of its own (two
            # running at once never share one), the node's own files (its /sys) are nobody's
            # to it, a file there only the node's root opens does not open, and port 80 of its
            # own network is still its to bind. Its
            # volume's files are owned on disk as before: read on the second node through NFS
            # (which takes no id-mapped mount: that container keeps the node's users, and says
            # so), what containers on the first made is root's, or nobody's, as they were. (Root
            # writes a volume of its own: the Jobs made data nobody's, and a Workload's root has
            # no capability to write what is another's.)
            sees() { # NAME REPLICA UNTIL: what a replica of the Workload said, once it said UNTIL
                waited=0
                until said=$(any GET "/v1/logs/Workload/default/$1?replica=$2" 2>/dev/null | field data) && printf '%s\n' "$said" | grep -q "$3"; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 120 ] || fail "replica $2 of the Workload $1 did not say what it sees: $said"
                    sleep 1
                done
                printf '%s\n' "$said"
            }
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"ids"},"spec":{"replicas":2,"template":{"pod":true,"containers":[
  {"name":"run","image":"kith.test/pod:1","command":["/bin/pod","stays",":80","/sys","root-only","+/roots/by-root"],"runAsUser":0,
   "volumeMounts":[{"volume":"data","path":"/data"},{"volume":"roots","path":"/roots"},{"volume":"on1","path":"/here"}]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Workload ids was not applied"
            range() { # REPLICA: the first id of its range
                said=$(sees ids "$1" '^ids: +/roots/by-root /') || exit 1
                printf '%s\n' "$said" | grep -q '^ids: :80 binds Ok(())$' || fail "a pod's root did not bind port 80 of its own network: $said"
                printf '%s\n' "$said" | grep -q '^ids: /sys /sys owner 65534 opens Ok' || fail "the node's /sys is not nobody's to a container: $said"
                printf '%s\n' "$said" | grep -q '^ids: root-only /sys/.* owner 65534 opens Err(PermissionDenied)' || fail "a container's root opened a file only the node's root does: $said"
                printf '%s\n' "$said" | grep -q '^ids: +/roots/by-root /roots/by-root owner 0 opens Ok' || fail "a container's root did not make a file of its own in its volume: $said"
                printf '%s\n' "$said" | sed -n 's/^ids: map 0 \([0-9]*\) 65536$/\1/p' | grep -E '^[1-9][0-9]{4,}$' || fail "replica $1 of the Workload ids has no range of its own: $said"
            }
            first=$(range 0) || exit 1
            second=$(range 1) || exit 1
            [ "$first" -ge 65536 ] && [ "$second" -ge 65536 ] && [ "$first" != "$second" ] || fail "two containers have the ranges $first and $second"
            echo "vm.sh: two containers' ids start at $first and $second of the node's" >&2
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"owners"},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"run","image":"kith.test/pod:1","command":["/bin/pod","stays","/roots/by-root","/data/from-n1","/data/from-n2"],
   "volumeMounts":[{"volume":"data","path":"/data"},{"volume":"roots","path":"/roots","readOnly":true},{"volume":"on2","path":"/here"}]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Workload owners was not applied"
            said=$(sees owners 0 '^ids: /data/from-n2 ') || exit 1
            for made in roots/by-root:0 data/from-n1:65534 data/from-n2:65534; do
                printf '%s\n' "$said" | grep -q "^ids: /${made%:*} /${made%:*} owner ${made#*:} opens Ok" || fail "/${made%:*} is not ${made#*:}'s on disk: $said"
            done
            printf '%s\n' "$said" | grep -q '^ids: map 0 0 4294967295$' || fail "a container with a volume through NFS did not keep the node's users: $said"
            any GET /v1/resources >"$work/all.json" || fail "the resources could not be read"
            python3 - "$work/all.json" <<'EOF' || fail "the units do not say whose users they have: $(cat "$work/all.json")"
import json, sys

found = json.load(open(sys.argv[1]))
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
said = {r["metadata"]["name"]: [c.get("hostUsers") for c in (r.get("status") or {}).get("containers", [])] for r in found if r["kind"] == "Workload"}
sys.exit(0 if said.get("ids") == [False, False] and said.get("owners") == [True] else 1)
EOF
            for made in ids owners; do
                any DELETE "/v1/resources/Workload/default/$made" >/dev/null || fail "the Workload $made was not deleted"
            done

            # From outside the mesh (this machine, through the node's other card) there is no
            # NFS server to talk to: it listens on the mesh address alone.
            python3 - "$((port + 5))" <<'EOF' || fail "the first node's NFS port answered an address outside the mesh"
import socket, sys

# An RPC call of NFS 4's procedure 0, which a server that hears it answers.
call = bytes.fromhex("80000028" "00000001" "00000000" "00000002" "000186a3" "00000004" + "00000000" * 5)
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5) as s:
        s.sendall(call)
        sys.exit(1 if s.recv(4) else 0)
except OSError:
    sys.exit(0)
EOF

            # A Share names this machine (10.0.2.2 to the node, through its other card): it
            # is no node and not on the mesh, and speaks NFS 4.2 to the first node itself.
            probe() { python3 "$root/ci/nfs_probe.py" 127.0.0.1 "$@" | tr '\n' ' '; }
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Share","metadata":{"name":"mine"},"spec":{"volume":"on1","nfs":{"clients":["10.0.2.2"]}}},
 {"apiVersion":"kith.dev/v1","kind":"Share","metadata":{"name":"look"},"spec":{"volume":"data","readOnly":true,"nfs":{"clients":["10.0.2.0/24"]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Shares were not applied"
            waited=0
            until grep -aq 'kithd: serving [0-9]* shared volume.*; 2 Share(s) to the addresses they name' "$work/n1.log"; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "the first node did not say it serves the Shares"
                sleep 1
            done
            said=$(probe "$((port + 5))" /default/on1/own mkdir from-lan) || fail "the first node did not speak NFS to a machine its Share names"
            [ "$said" = '0 0 ' ] || fail "a machine the Share names did not make a directory in its volume: NFS said $said"
            # The directory is in the volume, for a container on that node: a key goes in it.
            # (The Share's user and the container's are the same one: nobody, as neither says.)
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"lan"},"spec":{"retries":0,"template":{"containers":[
  {"name":"run","image":"kith.test/kith:1","command":["/bin/kith","package","keygen","/here/from-lan/key"],
   "volumeMounts":[{"volume":"on1","path":"/here"}]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job lan was not applied"
            until_job lan succeeded
            said=$(probe "$((port + 5))" /default/data/all mkdir nope) || fail "the first node stopped speaking NFS"
            [ "$said" = '0 30 ' ] || fail "a read-only Share was not read-only (30): NFS said $said"
            said=$(probe "$((port + 5))" /default/on2) || fail "the first node stopped speaking NFS"
            [ "$said" = '2 ' ] || fail "a Share's client saw something that is no Share's (2 is no such thing): NFS said $said"
            # The second node has no Share: it still answers nothing outside the mesh.
            ! python3 "$root/ci/nfs_probe.py" 127.0.0.1 "$((port + 6))" / >/dev/null 2>&1 || fail "the second node, with no Share, spoke NFS outside the mesh"
            any GET /v1/resources >"$work/all.json" || fail "the resources could not be read"
            python3 - "$work/all.json" <<'EOF' || fail "the Share mine does not say where it is"
import json, sys

found = json.load(open(sys.argv[1]))
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
status = next(r.get("status") for r in found if r["kind"] == "Share" and r["metadata"]["name"] == "mine")
# (`served` is the node's own word of whether it serves the Share yet: a bool that may still be false here.)
sys.exit(0 if isinstance(status.get("served"), bool) and {k: v for k, v in status.items() if k != "served"} == {"node": "n1", "path": "/default/on1/own"} else 1)
EOF

            # An encrypted volume on the second node. Its key is made there and kept by the
            # first node; its file, read from outside on the node's disk, shows nothing of
            # the file system in it (the one it starts as has a label to look for); told to
            # restart, the node closes it, comes up, is handed the key again, and what a
            # container wrote in it is still there.
            grep -aq kith-volume "$root/target/os/root/usr/share/kith/volume.ext4" || fail "the file system an encrypted volume starts as has no label to look for"
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"vault"},"spec":{"node":"n2","path":"in","size":"12Mi","encrypted":true}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the encrypted volume was not applied"
            sealed() { # NAME: a Job whose container makes the file `key` in the encrypted volume
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$1"},"spec":{"retries":0,"template":{"containers":[
  {"name":"run","image":"kith.test/kith:1","command":["/bin/kith","package","keygen","/vault/key"],
   "volumeMounts":[{"volume":"vault","path":"/vault"}]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job $1 was not applied"
            }
            hears() { # N WHAT: wait for node N's console to have said it
                waited=0
                until grep -aq "$2" "$work/n$1.log"; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 120 ] || fail "the node n$1 did not say: $2"
                    sleep 1
                done
            }
            hears 2 'kithd: made the encrypted volume default/vault'
            sealed seal
            until_job seal succeeded
            echo sendkey ctrl-alt-delete | socat - "unix-connect:$work/keys2" >/dev/null
            hears 2 'reboot: Restarting system'
            hears 2 'kithd: opened the encrypted volume default/vault'
            grep -aq 'kithd: handed n2 the key of its volume default/vault' "$work/n1.log" || fail "the first node did not say it handed the volume's key over"
            sealed sealed-again
            until_job sealed-again failed
            any GET "/v1/logs/Job/default/sealed-again?stderr=true" >"$work/sealed.err" 2>/dev/null || true
            grep -q '/vault/key: File exists' "$work/sealed.err" || fail "what was written in the encrypted volume was not there after the restart: $(cat "$work/sealed.err")"
            read -r state_start state_sectors <"$work/state.at"
            ! dd if="$work/n2.raw" bs=512 skip="$state_start" count="$state_sectors" status=none | grep -aq kith-volume || fail "the encrypted volume's file system is in the clear on its node's disk"

            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: two nodes on the mesh; a file made in a shared volume by a container on the node that does not hold it was there for one on the node that does, and the other way round; nothing answered NFS from outside the mesh until a Share named this machine, which then made a directory in the Share's volume, could not write a read-only Share, and saw nothing else; an encrypted volume was made on the second node with its key kept by the first, its file system not to be seen on the node's disk, closed when the node was told to restart and opened again with the key the first node handed back, what was written in it still there; a pod's root was not the node's (two at once had ranges of ids of their own, the node's /sys was nobody's to them, a file only the node's root opens did not open, and each bound port 80 of its own network) while a container on the node's network kept the node's users and the node's ports under 1024 stayed its root's, and what containers made in a volume was owned on disk as before"
            exit 0
