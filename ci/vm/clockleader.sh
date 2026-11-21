# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm/cluster.sh for --test clockleader: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
#
# A leader whose clock no time server set does not move the others' by hours (T-1228). No node
# reaches a time server (their cards out are restricted: nothing answers SNTP), so no clock is
# vouched for. All three lose power; n1 starts again with its RTC eight hours ahead (QEMU -rtc
# base=, and no-kvmclock so that its kernel reads it), campaigns alone, and the other two start
# together after it and elect it. Each of them asks the other voter too: two of three agree,
# against the leader's word, so the leader is one source and its step is not taken.
            # (Once all three vote: the majority counted is of the voters.)
            waited=0
            until grep -aq 'cluster members: ReplaceAllVoters({[0-9]*, [0-9]*, [0-9]*})' "$work"/n?.log; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the three nodes did not all become voters: $(grep -ah 'cluster members' "$work"/n?.log | tail -n 3)"
                sleep 1
            done
            # A node's clock less this machine's, in seconds, by the Date of its answer (hyper's,
            # read from the guest's clock; whole seconds). Any answer has one: a refusal too.
            skew() { # N
                date=$(curl -sk -o /dev/null -D - --max-time 5 "https://127.0.0.1:$((port + $1))/v1/clock" | tr -d '\r' | sed -n 's/^[Dd]ate: //p')
                [ -n "$date" ] || return 1
                echo $(($(date -u -d "$date" +%s) - $(date +%s)))
            }
            near() { [ "$1" -ge -5 ] && [ "$1" -le 5 ]; } # SECONDS: within 5 s of this machine's
            # One start of all three, from power lost: 0 when n1 leads, 1 when another was elected
            # (n1's clock then follows its leader's, and the start is tried again).
            started() {
                for pid in $vms; do kill "$pid" 2>/dev/null || true; done
                for pid in $vms; do wait "$pid" 2>/dev/null || true; done
                dumps="-rtc base=$(date -u -d '8 hours' +%Y-%m-%dT%H:%M:%S)" gateway=' no-kvmclock'
                node 1
                dumps='' gateway=''
                waited=0
                until ahead=$(skew 1) && [ "$ahead" -gt 28000 ]; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 180 ] || fail "n1 did not start eight hours ahead: it says ${ahead:-nothing} s ($(tail -n 3 "$work/n1.log"))"
                    sleep 1
                done
                echo "vm.sh: n1 started $ahead s ahead, alone" >&2
                # (A while alone: its term passes theirs, and it asks them first when they are up.)
                sleep 10
                node 2
                node 3
                # Both followers up and answering (this machine asks as n2 and n3 ask each other).
                # A check of one before the other answered has two voters answering, no majority,
                # and follows the leader as it should: that start proves nothing and is tried again.
                # Once both answer, a follower moved fails the test.
                waited=0
                until s2=$(skew 2) && s3=$(skew 3); do
                    waited=$((waited + 1))
                    [ "$waited" -lt 240 ] || fail "n2 and n3 did not both answer: $(tail -n 3 "$work/n2.log" "$work/n3.log")"
                    sleep 1
                done
                if ! near "$s2" || ! near "$s3"; then
                    echo "vm.sh: a follower checked before the other answered (n2 $s2 s, n3 $s3 s): all three start again" >&2
                    return 1
                fi
                waited=0
                until grep -aq 'no time server set its clock' "$work/n2.log" && grep -aq 'no time server set its clock' "$work/n3.log"; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 240 ] || fail "n2 and n3 did not both say the leader's step was not taken: $(grep -ah 'kithd: clock' "$work"/n?.log | tail -n 6)"
                    for n in 2 3; do
                        if said=$(skew "$n") && ! near "$said"; then
                            fail "n$n was moved to $said s from this machine's time: $(grep -a 'kithd: clock' "$work/n$n.log" | tail -n 3)"
                        fi
                    done
                    if [ $((waited % 10)) = 0 ] && ahead=$(skew 1) && near "$ahead"; then
                        echo "vm.sh: n1 was not elected: its clock followed the leader's ($ahead s); all three start again" >&2
                        return 1
                    fi
                    sleep 1
                done
            }
            tries=1
            until started; do
                tries=$((tries + 1))
                [ "$tries" -le 4 ] || fail "no start of four had n1 elected with both followers answering"
            done
            for n in 2 3; do
                grep -aq 'no time server set its clock: 2 of 3 voters that answered agree' "$work/n$n.log" \
                    || fail "n$n did not say two of three voters agree: $(grep -a 'kithd: clock' "$work/n$n.log" | tail -n 3)"
            done
            # And they keep it, past the next check (a minute: their first found no leader).
            sleep 70
            for n in 2 3; do
                said=$(skew "$n") || fail "n$n did not answer"
                near "$said" || fail "n$n is $said s from this machine's time: $(grep -a 'kithd: clock' "$work/n$n.log" | tail -n 3)"
            done
            ahead=$(skew 1) || fail "n1 did not answer"
            [ "$ahead" -gt 28000 ] || fail "n1, the leader, was moved to $ahead s from this machine's time"
            said=$(grep -ah 'no time server set its clock' "$work/n2.log" | tail -n 1)
            echo "vm.sh: ok: three nodes with no time server; all lost power, n1 started again $ahead s ahead and was elected (start $tries); n2 and n3 kept this machine's time within 5 s, and said why: ${said#*kithd: }" >&2
            exit 0
