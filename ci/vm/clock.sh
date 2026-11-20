# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test clock (through tests.sh): it runs inside the driver's shell,
# with its variables and functions; not a script to run alone.
#
# The guest's clock starts hours off (QEMU's -rtc base= is six hours before the host's time, and
# the kernel is told no-kvmclock so that it reads it). An SNTP server
# on the host's loopback (sntp_standin.py) answers with the host's time, and the node is told
# of it by `kith.ntp=10.0.2.2:PORT` (10.0.2.2 is the host, to a guest on QEMU's user-mode
# network; the default restrict=on of these tests would cut that off, so it is left out here).
# The node says on the console that it stepped its clock to that server's time, by about as
# much as it was off, and the server counted a request.
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
    more="no-kvmclock kith.ntp=10.0.2.2:$sntp $serve" once=1
    boot -rtc "base=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%S)"
    up
    heard 'kithd: clock: stepped '
    kill "$vm" 2>/dev/null || true
    wait "$vm" 2>/dev/null || true
    line=$(grep -ao 'kithd: clock: stepped [-+][0-9.]* s to the time of [0-9.:]*' "$work/log" | head -n 1)
    echo "vm.sh: $line"
    # (A step of over 10000 s: 21600 s, the RTC's six hours.)
    case $line in
    "kithd: clock: stepped +"[0-9][0-9][0-9][0-9][0-9]*) ;;
    *) fail "the node did not step its clock forward by hours: $line" ;;
    esac
    case $line in
    *"the time of 10.0.2.2:$sntp") ;;
    *) fail "the node took the time from another server than the one it was told of: $line" ;;
    esac
    [ "$(cat "$work/sntp-count")" -ge 1 ] || fail "the stand-in answered no request"
    echo "vm.sh: ok: a node whose clock started hours off stepped it to the time of an SNTP server on the host"
    exit 0
