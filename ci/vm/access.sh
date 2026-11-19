# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test access: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # The cluster's admin is an Identity like any other: its Role becomes one that may
            # read and delete everything and apply only Roles and RoleBindings, and a RoleBinding
            # of its own (maps-root) lets it apply ConfigMaps, until that is deleted.
            printf '%s' '[{"apiVersion":"kith.dev/v1","kind":"Role","metadata":{"name":"cluster-admin"},"spec":{"rules":[{"kinds":["*"],"verbs":["get","list","watch","delete","exec"]},{"kinds":["Role","RoleBinding"],"verbs":["apply"]}]}},
{"apiVersion":"kith.dev/v1","kind":"Role","metadata":{"name":"maps"},"spec":{"rules":[{"kinds":["ConfigMap"],"verbs":["apply"]}]}},
{"apiVersion":"kith.dev/v1","kind":"RoleBinding","metadata":{"name":"maps-root"},"spec":{"role":"maps","subjects":["root"]}}]' >"$work/grant.json"
            api 1 POST /v1/apply "$work/grant.json" >/dev/null || fail "the admin's Roles were not applied"
            # Two writers, through n2 and through n3: numbered ConfigMaps, and a note of every
            # attempt, as for chaos: NAME NODE BEGUN ANSWERED ok|no.
            writer() { # N
                i=0 patience=5
                while ! [ -e "$work/stop" ]; do
                    i=$((i + 1))
                    printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"a%s-%s"},"spec":{"data":{"n":"a%s-%s"}}}]' "$1" "$i" "$1" "$i" >"$work/a$1.json"
                    begun=$(date +%s.%N) said=no
                    ! api "$1" POST /v1/apply "$work/a$1.json" >/dev/null 2>&1 || said=ok
                    echo "a$1-$i $1 $begun $(date +%s.%N) $said" >>"$work/writes$1"
                    sleep 0.1
                done
            }
            acked() { cat "$work"/writes? 2>/dev/null | awk -v n="$1" '$5 == "ok" && $2 == n' | wc -l; }
            monitor() { echo "$2" | socat - "unix-connect:$work/keys$1" >/dev/null; } # N COMMAND
            writers=''
            for n in 2 3; do
                writer "$n" &
                vms="$vms $!" writers="$writers $!"
            done
            waited=0
            until [ "$(acked 2)" -ge 10 ] && [ "$(acked 3)" -ge 10 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the admin's writes through n2 and n3 were not acknowledged: $(acked 2) and $(acked 3)"
                sleep 1
            done
            echo "vm.sh: the admin writing through n2 and n3" >&2

            # n2 is cut off from the others (its card on the cluster's network unplugged), so
            # it does not hear of the deletion; the RoleBinding is deleted through n1, whichever
            # of n1 and n3 leads then. (Had n2 led, it leads no more once it is plugged back:
            # its write is then passed on to the one that does, and refused there all the same.)
            monitor 2 'set_link lan off'
            sleep 2
            begun=$(date +%s.%N)
            (patience=30 && api 1 DELETE /v1/resources/RoleBinding/maps-root) >/dev/null || fail "the RoleBinding maps-root was not deleted"
            echo "$begun $(date +%s.%N)" >"$work/deleted"
            # A write through n2, which still holds the RoleBinding and lets it through; it
            # waits for the leader until the card is plugged back, and is refused there.
            printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"late"},"spec":{"data":{"n":"late"}}}]' >"$work/late.json"
            curl -s -o "$work/late" -w '%{http_code}' --max-time 40 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
                --resolve "kith:$((port + 2)):127.0.0.1" -H 'Content-Type: application/json' --data-binary "@$work/late.json" \
                "https://kith:$((port + 2))/v1/apply" >"$work/late.code" &
            late=$!
            sleep 3
            monitor 2 'set_link lan on'
            wait "$late" || true
            sleep 5
            : >"$work/stop"
            # shellcheck disable=SC2086 # (a list of process numbers)
            wait $writers

            # Each node's own list, until the three say the same; then against the notes.
            cat "$work"/writes? >"$work/writes"
            lists() { for n in 1 2 3; do api "$n" GET '/v1/resources?kind=ConfigMap' >"$work/list$n.json" 2>/dev/null || { echo "n$n did not answer" >"$work/wrong"; return 1; }; done; }
            tries=0
            until lists && said=$(python3 -c '
import json, sys
work = sys.argv[1]
def held(n):
    found = json.load(open(f"{work}/list{n}.json"))
    found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
    return {r["metadata"]["name"] for r in found if r["kind"] == "ConfigMap"}
lists = [held(n) for n in (1, 2, 3)]
writes = {name: (float(begun), float(answered), said) for name, node, begun, answered, said in (line.split() for line in open(f"{work}/writes"))}
begun, deleted = (float(at) for at in open(f"{work}/deleted").read().split())
code, late = open(f"{work}/late.code").read().strip(), open(f"{work}/late").read()
wrong = []
if not lists[0] == lists[1] == lists[2]:
    wrong.append("the nodes hold different writes: " + ", ".join(str(len(held)) for held in lists))
acked = {name for name, (at, answered, said) in writes.items() if said == "ok"}
lost = sorted(acked - lists[0])
if lost:
    wrong.append(f"{len(lost)} acknowledged writes are not held: {lost[:5]}")
after = [name for name, (at, answered, said) in writes.items() if at > deleted]
taken = sorted(name for name in after if writes[name][2] == "ok")
if taken:
    wrong.append(f"{len(taken)} writes begun after the deletion was acknowledged were acknowledged: {taken[:5]}")
kept = sorted(name for name in lists[0] if name == "late" or (name in writes and writes[name][0] > deleted))
if kept:
    wrong.append(f"{len(kept)} writes begun after the deletion was acknowledged are held: {kept[:5]}")
if not after:
    wrong.append("no write was begun after the deletion: the test showed nothing")
if code != "422" or "decided again" not in late:
    wrong.append(f"the write n2 let through while it was cut off was not refused where the log is kept: {code} {late[:300]}"
                 + (" (it waited on a log no majority held: n2 may have led when it was cut off, and kept leading past the 10 s it waits; run again)" if code == "500" and "no leader" in late else ""))
if wrong:
    sys.exit("; ".join(wrong))
print(f"{len(acked)} writes acknowledged of {len(writes)} tried, each held by all three nodes; none of the {len(after)} begun after the deletion was acknowledged or kept, and the one n2 let through while cut off was refused by the leader")
' "$work" 2>"$work/wrong"); do
                tries=$((tries + 1))
                [ "$tries" -lt 60 ] || fail "after the deletion: $(cat "$work/wrong")"
                sleep 1
            done
            echo "vm.sh: $said" >&2

            # People (docs/adr-people.md, slice F): n1 ends the people's tunnels (--people, with
            # --people-endpoint its address on this network). Two phones are two machines on
            # that network, each started from memory with this machine's ip and wg and ci/pod.rs
            # as its first process, whose only way to a Service is a WireGuard link set from the
            # configuration `POST /v1/peers` (what `kith peer add` calls) answered once; a third
            # is the Exit's provider (as --test tunnel has it). `pod watch` on a phone keeps one
            # connection to a Service and tries a new one every third of a second, and says how
            # many bytes came back: that, in the machine's console, is what these cases read.
            # phone-a is on level guest (the Service echo, and not the Service hidden); phone-b on
            # level roamer (echo, and the internet by the Exit vpn: "outside", 198.51.100.1, is
            # the provider's, which no other way here reaches).
            # (The admin's Role may apply what these need, until the next Role below.)
            printf '%s' '[{"apiVersion":"kith.dev/v1","kind":"Role","metadata":{"name":"cluster-admin"},"spec":{"rules":[{"kinds":["*"],"verbs":["get","list","watch","delete","exec"]},{"kinds":["Role","RoleBinding","Workload","Service","AccessLevel","RemotePeer","Exit","Secret"],"verbs":["apply"]}]}}]' >"$work/people-role.json"
            api 1 POST /v1/apply "$work/people-role.json" >/dev/null || fail "the admin was not allowed to apply the people's kinds"
            cat >"$work/people.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"echo","labels":{"app":"echo"}},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"echo","image":"kith.test/pod:1","command":["/bin/pod","echo"],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}}}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Service","metadata":{"name":"echo"},"spec":{"selector":{"app":"echo"},"ports":[{"port":80}]}},
 {"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"hidden","labels":{"app":"hidden"}},"spec":{"replicas":1,"template":{"pod":true,"containers":[
  {"name":"hidden","image":"kith.test/pod:1","command":["/bin/pod","say"],"env":[{"name":"PASSWORD","value":"hidden"}],"ports":[{"port":80}],"readiness":{"tcp":{"port":80}}}]}}},
 {"apiVersion":"kith.dev/v1","kind":"Service","metadata":{"name":"hidden"},"spec":{"selector":{"app":"hidden"},"ports":[{"port":80}]}}]
EOF
            api 1 POST /v1/apply "$work/people.json" >/dev/null || fail "the Services echo and hidden were not applied"
            service_at() { # NAME: the Service's address, once it has a replica
                any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    status = r.get("status") or {}
    if r["kind"] == "Service" and r["metadata"]["name"] == sys.argv[1] and status.get("address") and status.get("backends"):
        print(status["address"])
        sys.exit(0)
sys.exit(1)
' "$1"
            }
            tries=0
            until echo_at=$(service_at echo) && hidden_at=$(service_at hidden); do
                tries=$((tries + 1))
                [ "$tries" -lt 300 ] || fail "the Services echo and hidden were given no address with a replica: $(units Workload echo); $(units Workload hidden)"
                sleep 1
            done
            level() { # NAME SPEC: an AccessLevel
                printf '[{"apiVersion":"kith.dev/v1","kind":"AccessLevel","metadata":{"name":"%s"},"spec":%s}]' "$1" "$2" >"$work/level-$1.json"
                api 1 POST /v1/apply "$work/level-$1.json" >/dev/null || fail "the AccessLevel $1 was not applied"
            }
            level guest '{"services":["default/echo"]}'
            level roamer '{"services":["default/echo"],"exit":"vpn","dns":"10.9.0.9"}'
            # The machines' root: pod, ip and wg with what they are linked to; each machine
            # takes a copy with its own script (and the key a phone's link is made with).
            mkdir -p "$work/vmroot/bin"
            cp "$work/pod" "$work/vmroot/bin/pod"
            : >"$work/vmlinked"
            for tool in ip wg; do
                cp -L "$(command -v "$tool")" "$work/vmroot/bin/$tool"
                ldd "$(command -v "$tool")" | awk '$2 == "=>" && $3 ~ /^\// { print ($1 ~ /^\// ? $1 : $3), $3 } $1 ~ /^\// && $2 != "=>" { print $1, $1 }' >>"$work/vmlinked"
            done
            while read -r to from; do
                mkdir -p "$work/vmroot${to%/*}"
                cp -L "$from" "$work/vmroot$to"
            done <"$work/vmlinked"
            lanbox() { # N NAME: start the machine NAME at 10.9.0.N on the cluster's network from $work/NAME, and wait for its script to end
                (cd "$work/$2" && find . | LC_ALL=C sort | cpio -o -H newc --owner=0:0 --quiet) >"$work/$2.cpio"
                timeout "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 256 -smp 1 -display none -no-reboot \
                    -kernel "$base/vmlinuz" -initrd "$work/$2.cpio" -append "console=ttyS0 panic=-1 rdinit=/bin/pod -- init /script" \
                    -netdev "socket,id=lan,mcast=230.0.0.1:$((port + 8)),localaddr=127.0.0.1" -device "virtio-net-pci,netdev=lan,mac=52:54:00:00:0$1:0$1" \
                    -serial "file:$work/n$1.log" -monitor "unix:$work/keys$1,server,nowait" </dev/null >/dev/null 2>&1 8>&- &
                vms="$vms $!"
                tries=0
                until grep -aq 'init: ready' "$work/n$1.log" 2>/dev/null; do
                    tries=$((tries + 1))
                    [ "$tries" -lt 120 ] || fail "the machine $2 did not start"
                    sleep 1
                done
                ! grep -a 'init: failed' "$work/n$1.log" || fail "the machine $2 did not run its script"
            }
            # The provider: the node's end of the Exit's tunnel at 10.9.0.9 and, beyond it,
            # "outside": 198.51.100.1, which answers on port 80 with "outside".
            (umask 077 && wg genkey >"$work/node.key" && wg genkey >"$work/provider.key")
            provider_public=$(wg pubkey <"$work/provider.key")
            cp -a "$work/vmroot" "$work/provider"
            cp "$work/provider.key" "$work/provider/provider.key"
            cat >"$work/provider/script" <<EOF
/bin/ip link set lo up
/bin/ip address add 198.51.100.1/32 dev lo
/bin/ip link set eth0 up
/bin/ip address add 10.9.0.9/24 dev eth0
/bin/ip link add wg0 type wireguard
/bin/wg set wg0 private-key /provider.key listen-port 51820 peer $(wg pubkey <"$work/node.key") allowed-ips 10.2.0.2/32
/bin/ip address add 10.2.0.1/24 dev wg0
/bin/ip link set wg0 up
& PASSWORD=outside /bin/pod say
EOF
            lanbox 9 provider
            printf '[Interface]\nPrivateKey = %s\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = 10.9.0.9:51820\nPersistentKeepalive = 5\n' \
                "$(cat "$work/node.key")" "$provider_public" | python3 -c '
import json, sys
print(json.dumps([{"apiVersion": "kith.dev/v1", "kind": "Secret", "metadata": {"name": "vpn", "namespace": "kith-system"}, "spec": {"data": {"wg0.conf": sys.stdin.read()}}},
                  {"apiVersion": "kith.dev/v1", "kind": "Exit", "metadata": {"name": "vpn"}, "spec": {"node": "n1", "secret": "vpn", "levels": ["roamer"]}}]))
' >"$work/exit.json"
            api 1 POST /v1/apply "$work/exit.json" >/dev/null || fail "the Exit vpn, held for the level roamer, was not applied"
            tries=0
            until grep -aq 'kithd: exit vpn: tunnel kx[0-9]* up' "$work/n1.log"; do
                tries=$((tries + 1))
                [ "$tries" -lt 120 ] || fail "the Exit's tunnel did not come up: $(grep -a 'kithd: exit' "$work/n1.log")"
                sleep 1
            done
            # The peers, made as `kith peer add` makes them: once n1 has said its people's key,
            # `POST /v1/peers` answers each one's configuration, the only copy of its private key.
            tries=0
            until any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
sys.exit(0 if any(r["kind"] == "Node" and r["metadata"]["name"] == "n1" and ((r.get("status") or {}).get("people") or {}).get("publicKey") for r in found) else 1)
'; do
                tries=$((tries + 1))
                [ "$tries" -lt 120 ] || fail "n1 never said its people's key: $(grep -a 'people' "$work/n1.log" | tail -n 5)"
                sleep 1
            done
            umask 077
            for peer in phone-a:guest phone-b:roamer; do
                printf '{"name":"%s","node":"n1","level":"%s"}' "${peer%%:*}" "${peer##*:}" >"$work/${peer%%:*}.json"
                api 1 POST /v1/peers "$work/${peer%%:*}.json" | field config >"$work/${peer%%:*}.conf" || fail "kithd made no configuration for ${peer%%:*}"
                grep -q '^PrivateKey = ' "$work/${peer%%:*}.conf" || fail "the configuration of ${peer%%:*} holds no private key"
            done
            umask 022
            # A phone: its LAN address (N), then its link as its configuration makes it (what
            # the WireGuard app does), then what it watches: NAME HOST PORT each.
            phone() { # N NAME PEER WATCH...
                n=$1 name=$2 peer=$3
                shift 3
                cp -a "$work/vmroot" "$work/$name"
                python3 -I - "$work/$peer.conf" "$work/$name" "$n" "$@" <<'PY'
import sys
conf, out, n = sys.argv[1:4]
have = {}
for line in open(conf):
    if "=" in line and not line.startswith("["):
        key, value = line.split("=", 1)
        have[key.strip()] = value.strip()
split = lambda text: [item.strip() for item in text.split(",")]
inet = lambda item: ["-6"] if ":" in item else []
open(out + "/phone.key", "w").write(have["PrivateKey"] + "\n")
lines = ["/bin/ip link set lo up", "/bin/ip link set eth0 up", "/bin/ip address add 10.9.0." + n + "/24 dev eth0",
         "/bin/ip link add wg0 type wireguard",
         "/bin/wg set wg0 private-key /phone.key peer " + have["PublicKey"] + " endpoint " + have["Endpoint"] + " allowed-ips " + ",".join(split(have["AllowedIPs"])) + " persistent-keepalive 25"]
lines += ["/bin/ip " + " ".join(inet(a) + ["address", "add", a, "dev", "wg0", "nodad"] if ":" in a else ["address", "add", a, "dev", "wg0"]) for a in split(have["Address"])]
lines += ["/bin/ip link set wg0 up"]
lines += ["/bin/ip " + " ".join(inet(a) + ["route", "add", a, "dev", "wg0"]) for a in split(have["AllowedIPs"])]
lines += ["& /bin/pod watch " + watch for watch in sys.argv[4:]]
open(out + "/script", "w").write("\n".join(lines) + "\n")
PY
                lanbox "$n" "$name"
            }
            phone 8 phone-a-box phone-a "a-echo $echo_at 80" "a-hidden $hidden_at 80"
            phone 7 phone-b-box phone-b "b-echo $echo_at 80" "b-out 198.51.100.1 80"
            # What a phone's last complete line says of one of its counts (the line it is
            # writing now may be cut): KIND is held (bytes the kept connection had back), fresh
            # (new connections answered) or failed.
            count() { # N NAME KIND
                grep -a "$2: held=" "$work/n$1.log" | tail -n 2 | head -n 1 | grep -ao "$3=[0-9]*" | cut -d = -f 2
            }
            grew() { # N NAME KIND AT-LEAST WHAT
                tries=0
                until [ "$(count "$1" "$2" "$3")" -ge "$4" ] 2>/dev/null; do
                    tries=$((tries + 1))
                    [ "$tries" -lt 120 ] || fail "$5: $2 never got $4 of $3: $(grep -a "$2: held=" "$work/n$1.log" | tail -n 1)"
                    sleep 1
                done
            }
            counts() { # N NAME KIND...
                set -- "$@" ''
                for kind in "$@"; do
                    [ "$kind" != '' ] && [ "$kind" != "$1" ] && [ "$kind" != "$2" ] && printf '%s ' "$(count "$1" "$2" "$kind")"
                done
                :
            }
            stopped() { # N NAME WHAT KIND...: five seconds on, no more of KIND comes though the phone tries on
                sn=$1 sname=$2 swhat=$3
                shift 3
                sleep 5
                sbefore=$(counts "$sn" "$sname" "$@") stried=$(count "$sn" "$sname" failed)
                sleep 4
                safter=$(counts "$sn" "$sname" "$@")
                [ "$safter" = "$sbefore" ] || fail "$swhat: $sname still had $* of $sbefore a few seconds after five: $safter"
                [ "$(count "$sn" "$sname" failed)" -gt "$stried" ] || fail "$swhat: $sname made no new tries, so it says nothing"
            }
            # (1) Each phone reaches what its level names: a kept connection and new ones, to
            # the Service echo; phone-b also "outside", by the Exit. Neither reaches hidden.
            grew 8 a-echo held 20 "phone-a (guest) reaching the Service echo"
            grew 8 a-echo fresh 3 "phone-a (guest) reaching the Service echo"
            grew 7 b-echo held 20 "phone-b (roamer) reaching the Service echo"
            grew 7 b-out fresh 3 "phone-b (roamer) leaving by the Exit vpn"
            grew 8 a-hidden failed 5 "phone-a (guest) trying the Service hidden"
            [ "$(count 8 a-hidden fresh)" = 0 ] || fail "phone-a (guest) reached the Service hidden, which its level does not name"
            echo "vm.sh: people: phone-a reaches the Service echo and not hidden; phone-b reaches echo and outside by the Exit" >&2
            # (2) A level narrowed (to nothing): no byte either way within five seconds, the
            # kept connection and new ones. Widened again: it is let through again.
            level guest '{}'
            stopped 8 a-echo "the level guest narrowed" held fresh
            level guest '{"services":["default/echo"]}'
            sbefore=$(count 8 a-echo held)
            grew 8 a-echo held $((sbefore + 20)) "the level guest widened again"
            # (3) The Exit deleted: nothing of phone-b's leaves.
            api 1 DELETE /v1/resources/Exit/vpn >/dev/null || fail "the Exit vpn was not deleted"
            stopped 7 b-out "the Exit vpn deleted" fresh
            # (4) A peer removed: the connection it has open is ended and no byte comes either way.
            api 1 DELETE /v1/resources/RemotePeer/phone-a >/dev/null || fail "the RemotePeer phone-a was not deleted"
            stopped 8 a-echo "the peer phone-a removed" held fresh
            [ "$(count 8 a-hidden fresh)" = 0 ] || fail "phone-a (guest) reached the Service hidden, which its level does not name"
            ! grep -aq 'panicked at' "$work/n7.log" "$work/n8.log" "$work/n9.log" || fail "a phone or the provider panicked"
            echo "vm.sh: people: the level guest narrowed, the Exit deleted and the peer phone-a removed each cut what was open and new tries within five seconds" >&2

            # What a taken leader could append, and no more (T-0848): these nodes run the image of a kithd
            # built with the feature forge, whose POST /v1/forge puts one entry in the log as it is, with
            # none of the checks a request gets before it is written. Only what every node does with an
            # entry when it applies it is between it and the stores: three entries it was not asked for,
            # once the cluster says signing is required and the admin's key is in it.
            # The nodes check signed entries once the store is in format 4, which the leader moves it to
            # when every member reads it.
            # Each says on its console that it is a forge build, which a build that ships never does.
            for log in "$work"/n[123].log; do
                grep -aq 'kithd: built with forge: POST /v1/forge appends unchecked entries; never ship this' "$log" || fail "$log has no line saying kithd is built with forge"
            done
            tries=0
            until grep -aq 'every node checking them' "$work"/n?.log; do
                tries=$((tries + 1))
                [ "$tries" -lt 300 ] || fail "the store was not moved to format 4, where every node checks signed entries"
                sleep 1
            done
            # The admin's key (Ed25519), made here; the cluster's id is the print of its CA.
            adminseed=$(head -c 32 /dev/urandom | xxd -p -c 64)
            printf '302e020100300506032b657004220420%s' "$adminseed" | xxd -r -p >"$work/admin.der"
            adminkey=$(openssl pkey -inform DER -in "$work/admin.der" -pubout -outform DER | tail -c 32 | xxd -p -c 64)
            clusterid=$(openssl x509 -in "$work/ca.pem" -outform DER | sha256sum | cut -d ' ' -f 1)
            [ -n "$adminkey" ] || fail "no admin key to sign with"
            [ -n "$clusterid" ] || fail "no cluster id to sign with"
            # A body of resources, in $work/BODY.json.
            configmap() { # NAME VALUE
                printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"%s"},"spec":{"data":{"n":"%s"}}}]' "$1" "$2"
            }
            # An entry the admin signed (or not), in $work/NAME.entry; its nonce is the number, in 32 hex digits.
            expires=$(($(date +%s) + 300))
            entry() { # NAME NONCE EXPIRES-PLUS SIGNED-BODY [CARRIED-BODY [COMMAND-BODY]]
                python3 "$root/ci/vm/forge_entry.py" "$work/admin.der" "$clusterid" "$((expires + $3))" "$(printf '%032x' "$2")" "$work/$4.json" ${5:+"$work/$5.json"} ${6:+"$work/$6.json"} \
                    >"$work/$1.entry" || fail "the entry $1 was not made"
            }
            # The entry appended by whichever node leads (a follower says it does not): its answer, in $work/forged.json.
            forge() { # NAME
                for n in 1 2 3; do
                    api "$n" POST /v1/forge "$work/$1.entry" >"$work/forged.json" 2>/dev/null && return 0
                done
                fail "no node appended the entry $1"
            }
            applied() { forge "$1"; grep -q '"applied":true' "$work/forged.json" || fail "the entry $1 was not applied: $(cat "$work/forged.json")"; }
            # Each node's resources of a kind as KIND/NAME=SPEC, until the three say the same.
            held() { # KIND: in $work/held, one line a resource; fails unless the three nodes agree
                for n in 1 2 3; do
                    api "$n" GET "/v1/resources?kind=$1" 2>/dev/null | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in sorted(found, key=lambda r: r["metadata"]["name"]):
    print(r["kind"] + "/" + r["metadata"]["name"] + "=" + json.dumps(r["spec"], sort_keys=True))
' >"$work/held$n" || return 1
                done
                cmp -s "$work/held1" "$work/held2" && cmp -s "$work/held1" "$work/held3" && cp "$work/held1" "$work/held"
            }
            agreed() { # KIND [REGEX]: the three nodes hold the same of KIND, and REGEX is in it
                tries=0
                until held "$1" && { [ -z "${2:-}" ] || grep -q -- "$2" "$work/held"; }; do
                    tries=$((tries + 1))
                    [ "$tries" -lt 60 ] || fail "the nodes do not agree on $1 holding $2: $(head -c 300 "$work/held1") | $(head -c 300 "$work/held2") | $(head -c 300 "$work/held3")"
                    sleep 1
                done
            }
            # Where the cluster's Role may apply a Cluster, then the Cluster of the admin's key (open, the first
            # key is written unsigned), then the entry the admin signs to turn signing on: required.
            printf '%s' '[{"apiVersion":"kith.dev/v1","kind":"Role","metadata":{"name":"cluster-admin"},"spec":{"rules":[{"kinds":["*"],"verbs":["get","list","watch","delete","exec"]},{"kinds":["Role","RoleBinding","Cluster"],"verbs":["apply"]}]}}]' >"$work/regrant.json"
            api 1 POST /v1/apply "$work/regrant.json" >/dev/null || fail "the admin was not allowed to apply a Cluster"
            printf '[{"apiVersion":"kith.dev/v1","kind":"Cluster","metadata":{"name":"home"},"spec":{"adminKey":"%s"}}]' "$adminkey" >"$work/open.json"
            api 1 POST /v1/apply "$work/open.json" >/dev/null || fail "the Cluster with the admin's key was not applied"
            printf '[{"apiVersion":"kith.dev/v1","kind":"Cluster","metadata":{"name":"home"},"spec":{"adminKey":"%s","signing":"required"}}]' "$adminkey" >"$work/required.json"
            entry required 1 0 required
            applied required
            agreed Cluster '"signing": "required"'
            echo "vm.sh: signing required, by an entry the admin signed" >&2
            # Two entries the admin signed, written by the leader, and applied on all three nodes.
            configmap genuine 1 >"$work/first.json"
            configmap genuine 2 >"$work/second.json"
            entry first 2 1 first
            entry second 3 2 second
            applied first
            applied second
            agreed ConfigMap 'ConfigMap/genuine=.*"n": "2"'
            # The audit log's refusals are held to a number a minute: begin a minute of our own.
            sleep $((61 - $(date +%s) % 60))
            # (1) a bare RoleBinding, which no one signed.
            printf '{"Apply":{"resources":[{"apiVersion":"kith.dev/v1","kind":"RoleBinding","metadata":{"name":"forged-bare"},"spec":{"role":"cluster-admin","subjects":["mallory"]}}],"at":0}}' >"$work/bare.entry"
            forge bare
            grep -q '"applied":false' "$work/forged.json" || fail "a bare RoleBinding was applied: $(cat "$work/forged.json")"
            # (2) a Signed entry whose body was changed: what the admin signed is a ConfigMap, what it carries a RoleBinding.
            configmap harmless 1 >"$work/harmless.json"
            printf '[{"apiVersion":"kith.dev/v1","kind":"RoleBinding","metadata":{"name":"forged-changed"},"spec":{"role":"cluster-admin","subjects":["mallory"]}}]' >"$work/changed.json"
            entry changed 4 3 harmless changed
            forge changed
            grep -q '"applied":false' "$work/forged.json" || fail "a signed entry with its body changed was applied: $(cat "$work/forged.json")"
            # (3) a Signed entry with a replayed nonce: the first of the two ConfigMaps, which the second has since replaced.
            cp "$work/first.entry" "$work/replayed.entry"
            forge replayed
            grep -q '"applied":false' "$work/forged.json" || fail "a signed entry with a nonce taken was applied: $(cat "$work/forged.json")"
            # (4) the signature kept whole, and the body it signed, but a command that is not what they make:
            # the check of the signature passes, and what refuses it is the one that derives the command from the request.
            entry swapped 5 4 harmless harmless changed
            forge swapped
            grep -q '"applied":false' "$work/forged.json" || fail "a signed entry with another command than its body makes was applied: $(cat "$work/forged.json")"
            # Each node refused all four at apply, and wrote it in its audit log.
            audited() { # N WHO WHAT WHY
                api "$1" GET '/v1/audit?tail=200' 2>/dev/null | python3 -c '
import json, sys
who, what, why = sys.argv[1:4]
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("entries", [])
sys.exit(0 if any(e["verb"] == "signed" and not e["ok"] and e["who"] == who and any(what in w for w in e["what"]) and why in e.get("error", "") for e in found) else 1)
' "$2" "$3" "$4"
            }
            for n in 1 2 3; do
                tries=0
                until audited "$n" unsigned forged-bare 'a bare write that changes access is refused' \
                    && audited "$n" 'local socket' /v1/apply 'over this request' \
                    && audited "$n" 'local socket' /v1/apply "$(printf '%032x' 2) of local socket was seen already" \
                    && audited "$n" 'local socket' /v1/apply 'is not what its method, path and body make'; do
                    tries=$((tries + 1))
                    [ "$tries" -lt 60 ] || fail "n$n did not write all four refusals in its audit log: $(api "$n" GET '/v1/audit?tail=6' 2>&1 | head -c 1500)"
                    sleep 1
                done
            done
            # And the three hold what the admin signed, and none of what was forged.
            agreed ConfigMap 'ConfigMap/genuine=.*"n": "2"'
            ! grep -q 'forged\|harmless' "$work/held" || fail "a forged resource is held: $(cat "$work/held")"
            agreed RoleBinding
            ! grep -q 'forged\|mallory' "$work/held" || fail "a forged RoleBinding is held: $(cat "$work/held")"
            echo "vm.sh: four entries the leader was not asked for, a bare RoleBinding, a signed one with its body changed, one with a replayed nonce and one with a command its signed body does not make, each refused by all three nodes at apply" >&2
            ! grep -al 'Kernel panic\|panicked at' "$work"/n?.log || fail "a node panicked"
            echo "vm.sh: ok: three nodes; the admin writing through n2 and n3 by a RoleBinding deleted through n1 while n2 was cut off: $said; and a leader that appended a bare RoleBinding, a signed entry with its body changed, one with a replayed nonce and one with a command its signed body does not make: all three nodes refused each at apply, and hold the same; and a phone added by POST /v1/peers whose tunnel reached its level's Service, was cut when the level narrowed, lost its open connection when the peer was removed, and left an exit level by its Exit"
            exit 0
