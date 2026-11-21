# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test clock (through tests.sh): it runs inside the driver's shell,
# with its variables and functions; not a script to run alone.
#
# The guest's clock starts hours off (QEMU's -rtc base= is eight hours before the host's time, and
# the kernel is told no-kvmclock so that it reads it). An SNTP server
# on the host's loopback (sntp_standin.py) answers with the host's time, and the node is told
# of it by `kith.ntp=10.0.2.2:PORT` (10.0.2.2 is the host, to a guest on QEMU's user-mode
# network; the default restrict=on of these tests would cut that off, so it is left out here).
# The node says on the console that it stepped its clock to that server's time, by about as
# much as it was off, and the server counted a request. The guest is then restarted (inside the
# same QEMU, whose RTC keeps what the node set it to): the step went to the hardware clock too, so
# the restarted node's first check finds its clock within 2 s and has nothing to step. (A step by
# the cluster's leader takes the same path in kithd: clock.rs's `ask` sets both.)
    [ "$time" -gt 120 ] || time=240
    net_restrict=''
    sntp=$((port + 100))
    : >"$work/sntp-count"
    python3 "$root/ci/vm/sntp_standin.py" "$sntp" "$work/sntp-count" 8>&- &
    sleep 1
    kill -0 $! 2>/dev/null || fail "the SNTP stand-in did not start on 127.0.0.1:$sntp"

    cp "$osdir/kith-os.raw" "$work/disk.raw"
    # (no-kvmclock: under KVM the guest's kernel takes the time of day from the host's through
    # kvmclock and never reads the RTC, so -rtc base= would change nothing.)
    # (once empty: the guest restarts inside the same QEMU, whose RTC then keeps what the node wrote
    # to it; -no-reboot would end QEMU, and the next one start the RTC from -rtc base= again.)
    more="no-kvmclock kith.ntp=10.0.2.2:$sntp $serve" once=
    boot -rtc "base=$(date -u -d '8 hours ago' +%Y-%m-%dT%H:%M:%S)"
    up
    heard 'kithd: clock: stepped '
    line=$(grep -ao 'kithd: clock: stepped [-+][0-9.]* s to the time of [0-9.:]*' "$work/log" | head -n 1)
    echo "vm.sh: $line"
    # Restarted, with the hardware clock where the node's step put it: its first check of the new
    # boot finds the clock right (a clock that was not written would be eight hours off again,
    # and the first check a step).
    mark=$(wc -c <"$work/log")
    echo sendkey ctrl-alt-delete | socat - "unix-connect:$work/keys" >/dev/null
    heard 'reboot: Restarting system'
    until second=$(tail -c +"$((mark + 1))" "$work/log" | grep -ao 'kithd: clock: [^ ].*' | head -n 1 | tr -d '\r') && [ -n "$second" ]; do
        kill -0 "$vm" 2>/dev/null || fail "the VM ended before the restarted node said what it found of its clock"
        sleep 0.2
    done
    kill "$vm" 2>/dev/null || true
    wait "$vm" 2>/dev/null || true
    echo "vm.sh: after the restart: $second"
    case $second in
    "kithd: clock: "[-+][01].[0-9]*" s from the time of 10.0.2.2:$sntp: kept") ;;
    *) fail "the restarted node's first check did not find its clock within 2 s (the hardware clock kept the step): $second" ;;
    esac
    # (A step of over 10000 s: 28800 s, the RTC's eight hours.)
    case $line in
    "kithd: clock: stepped +"[0-9][0-9][0-9][0-9][0-9]*) ;;
    *) fail "the node did not step its clock forward by hours: $line" ;;
    esac
    case $line in
    *"the time of 10.0.2.2:$sntp") ;;
    *) fail "the node took the time from another server than the one it was told of: $line" ;;
    esac
    [ "$(cat "$work/sntp-count")" -ge 1 ] || fail "the stand-in answered no request"
    echo "vm.sh: ok: a node whose clock started hours off stepped it to the time of an SNTP server on the host, and after a restart found its clock right (the step went to the hardware clock)"
    exit 0
