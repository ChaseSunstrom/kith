# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test home: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            monitor() { echo "$2" | socat - "unix-connect:$work/keys$1" >/dev/null; } # N COMMAND
            now() { date +%s.%N; }
            house=10.9.0.100
            printf '[{"apiVersion":"kith.dev/v1","kind":"Cluster","metadata":{"name":"home"},"spec":{"home":{"address":"%s/24"}}}]' "$house" >"$work/home.json"
            any POST /v1/apply "$work/home.json" >/dev/null || fail "the Cluster with a house address was not applied"

            # A machine on the LAN asks who has the house address four times a second, and
            # notes who answers: "SECONDS MAC[,MAC]" (or "-"), and "SECONDS announce MAC".
            # SECONDS count from $began.
            began=$(now)
            python3 -I "$root/ci/lan_probe.py" "$((port + 8))" arp "$house" 400 >"$work/arp" 2>"$work/arp.err" &
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
            # (The nodes have no ip to show the address's valid_lft with: kithd says the time it
            # gives it, and a node that stopped renewing is shown below to lose it.)
            grep -aq "kithd: the house address $house is held on [a-z0-9]*, for up to 3 s at a time" "$work/n$had.log" || fail "n$had holds $house and did not say it holds it for up to 3 s at a time: $(grep -a 'house address' "$work/n$had.log" | tail -n 3)"
            for other in 1 2 3; do
                [ "$other" = "$had" ] || ! grep -aq "house address $house is held" "$work/n$other.log" || fail "n$other says it holds $house beside n$had"
            done

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
            awk -v moved="$moved" 'BEGIN { exit !(moved <= 10) }' || fail "the address took $moved s to move after n$had was reset (10 s allowed)"
            steady 30 "after n$had was reset"
            alone "after n$had was reset"
            [ "$holder" != "$first_holder" ] || fail "$house is held by the card that was reset"
            node_of "$holder"
            now_holder=$n
            asked "$holder" >/dev/null || fail "nothing answered DNS from $house after n$had was reset (n$now_holder holds it)"

            # The node that was reset is back, one of the three again (a write goes through it).
            printf '[{"apiVersion":"kith.dev/v1","kind":"ConfigMap","metadata":{"name":"back"},"spec":{"data":{"n":"back"}}}]' >"$work/back.json"
            waited=0
            until (patience=5 && api "$had" POST /v1/apply "$work/back.json") >/dev/null 2>&1; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "n$had did not come back after it was reset"
                sleep 1
            done

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
            awk -v moved="$moved" 'BEGIN { exit !(moved <= 10) }' || fail "the address took $moved s to move after n$now_holder was stopped (10 s allowed)"
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
            ! grep -a 'panicked at\|Kernel panic' "$work"/n?.log || fail "a node panicked"
            echo "vm.sh: ok: three nodes; one MAC answered for $house and announced it, DNS answered from it; after the holder was reset, and after the next was stopped, another announced it within 10 s ($moved s the last time) and two cards were never heard at once while a holder was stopped, nor for more than 4 s after it went on again"
            exit 0
