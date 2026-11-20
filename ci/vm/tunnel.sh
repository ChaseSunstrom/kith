# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test tunnel: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            monitor() { echo "$2" | socat - "unix-connect:$work/keys$1" >/dev/null; } # N COMMAND
            # The provider: a second machine on the node's LAN, started from memory with this
            # machine's ip and wg (and what they are linked to) and ci/pod.rs as its first
            # process. It holds the tunnel's other end at 10.9.0.9, and behind it "outside":
            # 198.51.100.1 answers on port 80 and, on port 53, every name with itself.
            (umask 077 && wg genkey >"$work/node.key" && wg genkey >"$work/provider.key")
            provider_public=$(wg pubkey <"$work/provider.key")
            mkdir -p "$work/provider/bin"
            cp "$work/pod" "$work/provider/bin/pod"
            cp "$work/provider.key" "$work/provider/provider.key"
            for tool in ip wg; do
                cp -L "$(command -v "$tool")" "$work/provider/bin/$tool"
                ldd "$(command -v "$tool")" | awk '$2 == "=>" && $3 ~ /^\// { print ($1 ~ /^\// ? $1 : $3), $3 } $1 ~ /^\// && $2 != "=>" { print $1, $1 }' >>"$work/linked"
            done
            while read -r to from; do
                mkdir -p "$work/provider${to%/*}"
                cp -L "$from" "$work/provider$to"
            done <"$work/linked"
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
& /bin/pod dns 198.51.100.1
& /bin/pod knock 10.2.0.2:7443
EOF
            (cd "$work/provider" && find . | LC_ALL=C sort | cpio -o -H newc --owner=0:0 --quiet) >"$work/provider.cpio"
            timeout --foreground "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 256 -smp 1 -display none -no-reboot \
                -kernel "$base/vmlinuz" -initrd "$work/provider.cpio" -append "console=ttyS0 panic=-1 rdinit=/bin/pod -- init /script" \
                -netdev "socket,id=lan,mcast=230.0.0.1:$((port + 8)),localaddr=127.0.0.1" -device "virtio-net-pci,netdev=lan,mac=52:54:00:00:09:09" \
                -serial "file:$work/n9.log" -monitor "unix:$work/keys9,server,nowait" </dev/null >/dev/null 2>&1 8>&- &
            vms="$vms $!"
            waited=0
            until grep -aq 'init: ready' "$work/n9.log" 2>/dev/null; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the WireGuard provider did not start"
                sleep 1
            done
            ! grep -a 'init: failed' "$work/n9.log" || fail "the WireGuard provider did not make its end of the tunnel"
            # The provider's file for its customer (the node), in a Secret of kith-system; the
            # Exit that holds it on n1 for the namespace media; and a pod of media behind it
            # whose web (TCP) and UDP ports are published on n1.
            secret() { # KEEPALIVE: the Secret, in $work/apply.json
                printf '[Interface]\nPrivateKey = %s\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = 10.9.0.9:51820\nPersistentKeepalive = %s\n' \
                    "$(cat "$work/node.key")" "$provider_public" "$1" | python3 -c '
import json, sys
print(json.dumps([{"apiVersion": "kith.dev/v1", "kind": "Secret", "metadata": {"name": "vpn", "namespace": "kith-system"}, "spec": {"data": {"wg0.conf": sys.stdin.read()}}}]))
' >"$work/apply.json"
            }
            secret 5
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the provider's Secret was not applied"
            cat >"$work/exit.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Exit","metadata":{"name":"vpn"},"spec":{"node":"n1","secret":"vpn","namespaces":["media"]}}]
EOF
            any POST /v1/apply "$work/exit.json" >/dev/null || fail "the Exit was not applied"
            # The tunnel up and no pod yet: the provider, knocking on kithd's API at the node's
            # end of the tunnel all along, is never answered.
            waited=0
            until grep -aq 'kithd: exit vpn: tunnel kx[0-9]* up' "$work/n1.log"; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the Exit's tunnel did not come up: $(grep -a 'kithd: exit' "$work/n1.log")"
                sleep 1
            done
            sleep 10
            grep -aq 'knock: 10.2.0.2:7443' "$work/n9.log" || fail "the provider never knocked on the node's end of the tunnel"
            ! grep -a 'knock: 10.2.0.2:7443 answered' "$work/n9.log" || fail "the node answered its VPN provider on kithd's API, before any pod"
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"probe","namespace":"media"},"spec":{"template":{"pod":true,"exit":"vpn","containers":[
  {"name":"probe","image":"kith.test/pod:1","command":["/bin/pod","probe"],"ports":[{"port":8080,"publish":true},{"port":8080,"protocol":"udp","publish":true}]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the pod behind the Exit was not applied"
            # What the pod says each round, and its web and UDP ports as this machine reaches
            # them on the node (UDP as a machine on the node's LAN).
            rounds() { any GET '/v1/logs/Workload/media/probe?replica=0&tail=20' 2>/dev/null | grep -o 'probe [0-9]*: [^"\\]*'; }
            web() { curl -s --max-time 5 "http://127.0.0.1:$((port + 5))/"; }
            echoed() { python3 -I "$root/ci/lan_probe.py" "$((port + 8))" 52:54:00:00:09:01 10.9.0.1 8080 'a datagram for the pod' 2>/dev/null; }
            up='web ok dns ok tcp-dns ok node-dns silent node-api silent ipv6 [A-Z]'
            down='web failed dns failed tcp-dns silent node-dns silent node-api silent ipv6 [A-Z]'
            probes() { # PATTERN WHAT: three rounds of the pod's, all after the last one before, each say PATTERN
                before=$(rounds | tail -n 1)
                waited=0
                until rounds | tail -n 3 >"$work/rounds" && [ "$(grep -c "$1" "$work/rounds")" = 3 ] && ! grep -qxF "$before" "$work/rounds"; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for this: $2; the pod last said: $(cat "$work/rounds"); its Workload says: $(units Workload probe)"
                    sleep 1
                done
                echo "vm.sh: $2: $(tail -n 1 "$work/rounds")" >&2
            }
            published() { # WHAT
                waited=0
                until web | grep -q 'the web of a pod behind an exit' && echoed | grep -q 'a datagram for the pod'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 120 ] || fail "$1: the pod's ports published on its node do not answer: web: '$(web)'; UDP: '$(echoed)'"
                    sleep 1
                done
            }
            probes "$up" "the tunnel up: the pod reaches outside and its names through it, IPv6 nowhere and its node's DNS not at all"
            published "the tunnel up"
            # Its names were asked of the provider, over UDP and over TCP, and never of its node.
            grep -aq 'dns: udp kithleak-[0-9]' "$work/n9.log" || fail "the provider was never asked the pod's names over UDP"
            grep -aq 'dns: tcp kithleak-tcp-' "$work/n9.log" || fail "the provider was never asked the pod's names over TCP"
            ! grep -aq 'kithleak-node' "$work/n9.log" || fail "a name the pod asked of its node reached the provider"

            # The provider stops answering: nothing of the pod's reaches anywhere, and its
            # published web goes on answering; then back.
            monitor 9 stop
            probes "$down" "the provider stopped: the pod reaches nothing"
            published "the provider stopped"
            monitor 9 cont
            probes "$up" "the provider back"

            # The Secret changes: the tunnel is made again, and the pod goes on through it.
            secret 6
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the provider's changed Secret was not applied"
            waited=0
            until [ "$(grep -ac 'kithd: exit vpn: tunnel kx[0-9]* up' "$work/n1.log")" -ge 2 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the Secret changed, and the tunnel was not made again: $(grep -a 'kithd: exit' "$work/n1.log")"
                sleep 1
            done
            probes "$up" "the Secret changed: the tunnel made again"

            # The Exit is deleted while its pod runs: the pod reaches nothing (it is stopped, as
            # it starts only with its tunnel up); applied again, it runs as before.
            any DELETE /v1/resources/Exit/vpn >/dev/null || fail "the Exit was not deleted"
            waited=0
            until ! web | grep -q 'behind an exit' || [ "$(rounds | tail -n 3 | grep -c "$down")" = 3 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "the Exit deleted, its pod still runs and reaches out: $(rounds | tail -n 3)"
                sleep 1
            done
            echo "vm.sh: the Exit deleted: its pod reaches nothing; its Workload says: $(units Workload probe)" >&2
            any POST /v1/apply "$work/exit.json" >/dev/null || fail "the Exit was not applied again"
            probes "$up" "the Exit applied again"
            published "the Exit applied again"

            # The node loses power (kithd is its first process: this is kithd killed): started
            # again, the pod runs behind its tunnel as before.
            monitor 1 system_reset
            waited=0
            until [ "$(grep -ac 'Kernel command line' "$work/n1.log")" -ge 2 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the node did not start again"
                sleep 1
            done
            probes "$up" "the node started again"
            published "the node started again"

            # A pod of a namespace the Exit does not list is refused, and says why.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"probe","namespace":"other"},"spec":{"template":{"pod":true,"exit":"vpn","containers":[
  {"name":"probe","image":"kith.test/pod:1","command":["/bin/pod","probe"]}]}}}]
EOF
            code=$(curl -s -o "$work/refused" -w '%{http_code}' --max-time 10 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
                --resolve "kith:$((port + 1)):127.0.0.1" -X POST -H 'Content-Type: application/json' -d "@$work/apply.json" "https://kith:$((port + 1))/v1/apply") || true
            case $code in 4??) ;; *) fail "a pod of a namespace the Exit does not list was not refused: $code $(cat "$work/refused")" ;; esac
            grep -q 'does not list namespace other' "$work/refused" || fail "a pod of a namespace the Exit does not list was refused without saying why: $(cat "$work/refused")"

            # And a pod behind no exit, whose packets out are seen on the node's card out: what
            # finds no packet of the pod's there would find one.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"control"},"spec":{"retries":0,"template":{"pod":true,"containers":[
  {"name":"control","image":"kith.test/pod:1","command":["/bin/pod","shout","203.0.113.7:9","kithcontrol"]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job control was not applied"
            waited=0
            until line=$(units Job control) && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "waited for the Job control; it says: $line"
                sleep 1
            done

            # What the node's two cards carried, all along: no packet to or from the pod's
            # outside, its DNS or its tunnel address, none to IPv6's documentation addresses, and
            # none with `kithleak` in it, but for the tunnel's own (to the provider's port).
            python3 -c '
import ipaddress, struct, sys
def frames(path):
    data = open(path, "rb").read()
    order = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    at = 24
    while at + 16 <= len(data):
        caught = struct.unpack(order + "I", data[at + 8:at + 12])[0]
        yield data[at + 16:at + 16 + caught]
        at += 16 + caught
outside = [ipaddress.ip_network(n) for n in ("198.51.100.0/24", "203.0.113.0/24", "10.2.0.0/24", "100.88.0.0/16")]
documentation = ipaddress.ip_network("2001:db8::/32")
leaks, tunnel, control = [], 0, 0
for path in sys.argv[1:]:
    for frame in frames(path):
        kind, rest = frame[12:14], frame[14:]
        while kind == b"\x81\x00":
            kind, rest = rest[2:4], rest[4:]
        if b"kithcontrol" in frame:
            control += 1
            continue
        said = None
        if kind == b"\x08\x00" and len(rest) >= 20:
            source, to = ipaddress.ip_address(rest[12:16]), ipaddress.ip_address(rest[16:20])
            header = (rest[0] & 15) * 4
            if rest[9] == 17 and str(to) == "10.9.0.9" and rest[header + 2:header + 4] == (51820).to_bytes(2, "big"):
                tunnel += 1
                continue
            if any(source in net or to in net for net in outside):
                said = f"{source} > {to}"
        elif kind == b"\x86\xdd" and len(rest) >= 40:
            source, to = ipaddress.ip_address(rest[8:24]), ipaddress.ip_address(rest[24:40])
            if source in documentation or to in documentation:
                said = f"{source} > {to}"
        if said is None and b"kithleak" in frame:
            said = "a frame with kithleak in it"
        if said:
            leaks.append(path.rsplit("/", 1)[-1] + ": " + said)
print(len(leaks), tunnel, control, "; ".join(leaks[:10]))
' "$work/lan.pcap" "$work/out.pcap" >"$work/counted" || fail "the node's cards' packets could not be read"
            read -r leaked tunnelled controls rest <"$work/counted"
            [ "$leaked" = 0 ] || fail "$leaked packets of the pod's left the node outside its tunnel: $rest"
            [ "$tunnelled" -gt 0 ] || fail "no packet went to the provider through the tunnel"
            [ "$controls" -gt 0 ] || fail "the pod behind no exit sent nothing that was seen: the count of the node's packets sees nothing; the Job says: $line: $(any GET '/v1/logs/Job/default/control?stderr=true' 2>&1)"
            ! grep -a 'knock: 10.2.0.2:7443 answered' "$work/n9.log" || fail "the node answered its VPN provider on kithd's API"
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node and a WireGuard provider: the provider was never answered on kithd's API through the tunnel; a pod behind an Exit reached outside and asked its names (UDP and TCP) only through the tunnel, never IPv6, never its node's DNS nor kithd's API; with the provider stopped, its Secret changed, its Exit deleted and its node reset it reached nothing, and then through the tunnel again; its web and UDP ports published on the node answered; a pod of a namespace the Exit does not list was refused; and of $tunnelled packets to the provider and $controls of a pod behind no exit seen on the node's cards, none of the pod's left outside the tunnel"
            exit 0
