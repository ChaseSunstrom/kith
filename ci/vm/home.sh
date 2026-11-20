# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test home: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            monitor() { echo "$2" | socat - "unix-connect:$work/keys$1" >/dev/null; } # N COMMAND
            now() { date +%s.%N; }
            house=10.9.0.100
            # (The endpoint is where a roaming node calls the holder from outside: the router's forward
            # of UDP 51820 to the house address, which is the LAN here.)
            printf '[{"apiVersion":"kith.dev/v1","kind":"Cluster","metadata":{"name":"home"},"spec":{"home":{"address":"%s/24","endpoint":"%s:51820"}}}]' "$house" "$house" >"$work/home.json"
            any POST /v1/apply "$work/home.json" >/dev/null || fail "the Cluster with a house address was not applied"

            # A machine on the LAN asks who has the house address four times a second, and
            # notes who answers: "SECONDS MAC[,MAC]" (or "-"), and "SECONDS announce MAC".
            # SECONDS count from $began.
            began=$(now)
            python3 -I "$root/ci/lan_probe.py" "$((port + 8))" arp "$house" 900 >"$work/arp" 2>"$work/arp.err" &
            vms="$vms $!"
            # Every WireGuard handshake answer to n4's address (10.9.0.4), from whatever address
            # it came from: "EPOCH SRC DST" (EPOCH from date, as $(now) is; SRC is the reply's source).
            python3 -I "$root/ci/lan_probe.py" "$((port + 8))" handshakes 10.9.0.4 900 >"$work/wg" 2>"$work/wg.err" &
            vms="$vms $!"
            # The one MAC that has answered for the last three seconds, once one has.
            steady() { # SECONDS to wait, WHAT
                waited=0
                until holder=$(awk 'NF == 2 { l[++n] = $2 } END { if (n < 12) exit 1; for (i = n - 11; i <= n; i++) if (l[i] != l[n] || l[n] == "-" || l[n] ~ /,/) exit 1; print l[n] }' "$work/arp"); do
                    waited=$((waited + 1))
                    [ "$waited" -lt "$1" ] || fail "waited for one card to answer for $house: $2: $(tail -n 4 "$work/arp") $(cat "$work/arp.err")"
                    sleep 1
                done
            }
            # Never two cards at once.
            alone() { # WHAT
                ! grep -q '^[0-9.]* [0-9a-f:]*,' "$work/arp" || fail "$1: two cards answered for $house at once: $(grep -m 3 '^[0-9.]* [0-9a-f:]*,' "$work/arp")"
            }
            # The node whose card has that MAC.
            node_of() { n=${1##*:} n=${n#0}; }
            # DNS at the house address, asked of the card that holds it: n1.node.kith, which the
            # reply must answer from the house address itself (the probe takes only that).
            query=123401000001000000000000026e31046e6f6465046b6974680000010001
            asked() { python3 -I "$root/ci/lan_probe.py" "$((port + 8))" "$1" "$house" 5353 "hex:$query" 2>/dev/null; }
            # TCP 443 at the house address answers a SYN sent to it at the card MAC that holds it: a
            # SYN-ACK from the house address itself.
            synack() { [ "$(python3 -I "$root/ci/lan_probe.py" "$((port + 8))" "$1" "$house" 443 syn 2>/dev/null)" = syn-ack ]; } # MAC of the holder's card
            # The first WireGuard handshake answer since SINCE (a $(now)) from the house address to
            # node NODE's address, or nothing yet.
            answered() { # SINCE NODE
                awk -v since="$1" -v house="$house" -v to="10.9.0.$2" '$1 > since && $2 == house && $3 == to && $4 == 2 { print; exit }' "$work/wg"
            }
            # The roaming node is n4 (a learner: it never votes). The store must say so, in its
            # Node's spec.roaming, and not only the flag passed.
            roams() {
                any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    found = []
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
print(any(r["kind"] == "Node" and r["metadata"]["name"] == "n4" and (r.get("spec") or {}).get("roaming") is True for r in found))
'
            }
            # n4 is reset, and its WireGuard device is new: it dials the house address once the
            # Cluster names the holder. The house address must answer that handshake, from itself.
            reset_roamer() {
                waited=0
                until [ "$(roams)" = True ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 60 ] || fail "the store does not say n4 roams: $(any GET /v1/resources 2>&1 | head -c 600)"
                    sleep 1
                done
                # (n4 reaches none of the voters' own addresses while it is reset, as a roaming node off the
                # LAN does not: ci/lan_bridge.py drops them; it may call only the house address.)
                : >"$work/cut"
                reset=$(now)
                monitor 4 system_reset
                waited=0
                until reply=$(answered "$reset" 4) && [ -n "$reply" ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 240 ] || fail "n4 was reset and no WireGuard handshake from $house answered it: (reset at $reset, holder n$had, then n${now_holder:-?}) $(awk -v since="$reset" '$1 > since' "$work/wg" | tail -n 30) $(cat "$work/wg.err") $(grep -aih 'house\|mesh' "$work/n4.log" | tail -n 6)"
                    sleep 1
                done
                rm -f "$work/cut"
                echo "vm.sh: n4 was reset, cut off from the voters' own addresses: its WireGuard handshake to $house was answered from $house ($reply)" >&2
            }

            steady 120 "the cluster did not take up the house address"
            alone "the house address taken up"
            first_holder=$holder
            node_of "$holder"
            had=$n
            grep -q "announce $holder" "$work/arp" || fail "n$had holds $house and did not announce it"
            reply=$(asked "$holder") || fail "nothing answered DNS from $house (n$had holds it)"
            case $reply in
                1234[89ab]??000010001*) ;;
                *) fail "DNS from $house (n$had) did not answer n1.node.kith: $reply" ;;
            esac
            echo "vm.sh: n$had holds $house ($holder), announced it, and answers DNS from it" >&2
            # The holder says so in the Cluster (status.home.holder), and the next one replaces it.
            says_holder() { # N: waits for the Cluster to say node nN holds the house address
                waited=0
                until [ "$(any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
print(next((((r.get("status") or {}).get("home") or {}).get("holder", "") for r in found if r["kind"] == "Cluster"), ""))
')" = "n$1" ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 30 ] || fail "$2: the Cluster does not say n$1 holds $house: $(any GET /v1/resources 2>&1 | head -c 600)"
                    sleep 1
                done
            }
            says_holder "$had" "the first holder"
            # (The nodes have no ip to show the address's valid_lft with: kithd says the time it
            # gives it, and a node that stopped renewing is shown below to lose it.)
            grep -aq "kithd: the house address $house is held on [a-z0-9]*, for up to 3 s at a time" "$work/n$had.log" || fail "n$had holds $house and did not say it holds it for up to 3 s at a time: $(grep -a 'house address' "$work/n$had.log" | tail -n 3)"
            for other in 1 2 3 4; do
                [ "$other" = "$had" ] || ! grep -aq "house address $house is held" "$work/n$other.log" || fail "n$other says it holds $house beside n$had"
            done

            # The holder answers TCP 443 at the house address, and answers a WireGuard handshake
            # to it from there (a reset roaming node dials it).
            synack "$holder" || fail "nothing answered TCP 443 at $house (n$had holds it)"
            echo "vm.sh: n$had holds $house and answers TCP 443 at it" >&2
            reset_roamer

            # The holder loses power. Another takes the address, announces it, and the two are
            # never heard at once.
            # (Only once all three vote: two of three can elect a new leader.)
            waited=0
            until grep -aq 'cluster members: ReplaceAllVoters({[0-9]*, [0-9]*, [0-9]*})' "$work"/n?.log; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the three nodes did not all become voters: $(grep -ah 'cluster members' "$work"/n?.log | tail -n 3)"
                sleep 1
            done
            lost=$(now)
            # (Reset, and then kept stopped: a machine that boots again in five seconds is back
            # before the others have waited out their leader, and no one else need lead.)
            monitor "$had" system_reset
            monitor "$had" stop
            waited=0
            until moved=$(awk -v began="$began" -v lost="$lost" -v old="$holder" '$2 == "announce" && $3 != old && began + $1 > lost { printf "%.1f", began + $1 - lost; exit }' "$work/arp") && [ -n "$moved" ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || { grep -a 'house address\|leader\|elect\|cluster members' "$work"/n?.log >&2 || true; fail "n$had was reset and nobody else announced $house: $(tail -n 4 "$work/arp")"; }
                sleep 1
            done
            echo "vm.sh: n$had was reset: $house was announced again after $moved s" >&2
            monitor "$had" cont
            awk -v moved="$moved" 'BEGIN { exit !(moved <= 12) }' || fail "the address took $moved s to move after n$had was reset (12 s allowed)"
            steady 30 "after n$had was reset"
            alone "after n$had was reset"
            [ "$holder" != "$first_holder" ] || fail "$house is held by the card that was reset"
            node_of "$holder"
            now_holder=$n
            asked "$holder" >/dev/null || fail "nothing answered DNS from $house after n$had was reset (n$now_holder holds it)"
            says_holder "$now_holder" "after n$had was reset"

            # The node that was reset is back, one of the three again (a write goes through it).
            printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"back"},"spec":{"data":{"n":"back"}}}]' >"$work/back.json"
            waited=0
            until (patience=5 && api "$had" POST /v1/apply "$work/back.json") >/dev/null 2>&1; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "n$had did not come back after it was reset"
                sleep 1
            done

            # After the holder moved: the new one answers TCP 443 at the house address, and a
            # WireGuard handshake from a reset roaming node is answered from there.
            synack "$holder" || fail "nothing answered TCP 443 at $house after n$had was reset (n$now_holder holds it)"
            echo "vm.sh: n$now_holder holds $house after n$had was reset and answers TCP 443 at it" >&2
            reset_roamer

            # The holder hangs: the hypervisor stops its processor, with its card plugged in
            # and its address on it. Another takes the address, and when the first goes on
            # again it is not heard answering beside the new holder.
            stopped=$(now)
            monitor "$now_holder" stop
            waited=0
            until moved=$(awk -v began="$began" -v stopped="$stopped" -v old="$holder" '$2 == "announce" && $3 != old && began + $1 > stopped { printf "%.1f", began + $1 - stopped; exit }' "$work/arp") && [ -n "$moved" ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "n$now_holder was stopped and nobody else announced $house: $(tail -n 4 "$work/arp")"
                sleep 1
            done
            echo "vm.sh: n$now_holder was stopped: $house was announced again after $moved s" >&2
            awk -v moved="$moved" 'BEGIN { exit !(moved <= 12) }' || fail "the address took $moved s to move after n$now_holder was stopped (12 s allowed)"
            alone "while n$now_holder was stopped"
            sleep 3
            alone "while n$now_holder was stopped"
            resumed=$(now)
            monitor "$now_holder" cont
            sleep 10
            steady 30 "after n$now_holder went on again"
            # (A stopped guest's clock stood still, so its kernel still has the address when it
            # goes on again, until its kithd takes it off: the lifetime, 3 s, bounds that. Two
            # cards heard later than that fail.)
            twice=$(awk -v began="$began" -v resumed="$resumed" 'NF == 2 && $2 ~ /,/ && began + $1 > resumed + 4 { print; exit }' "$work/arp")
            [ -z "$twice" ] || fail "two cards answered for $house more than 4 s after n$now_holder went on again: $twice"
            [ "$holder" != "$(printf '52:54:00:00:09:0%s' "$now_holder")" ] || fail "n$now_holder went on again and holds $house"
            asked "$holder" >/dev/null || fail "nothing answered DNS from $house after n$now_holder went on again"
            synack "$holder" || fail "nothing answered TCP 443 at $house after n$now_holder went on again"
            ! grep -a 'panicked at\|Kernel panic' "$work"/n?.log || fail "a node panicked"
            echo "vm.sh: ok: three nodes; one MAC answered for $house and announced it, DNS and TCP 443 answered from it, and a WireGuard handshake to it was answered from it while the holder was up and after it was reset (TCP 443 too after the next was stopped); after the holder was reset, and after the next was stopped, another announced it within 12 s ($moved s the last time) and two cards were never heard at once while a holder was stopped, nor for more than 4 s after it went on again"
            exit 0
