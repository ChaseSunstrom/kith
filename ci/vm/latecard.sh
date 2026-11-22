# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test latecard: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # One node with two cards at boot (eth0: the LAN, a kith.ip address; eth1: QEMU's user
            # network, which gives a DHCP lease and a router advertisement), and a PCIe root port
            # free. A third card is plugged in after the boot, through the monitor: kithd must
            # find it within its 5 s scan, bring it up, and ask its network for an address.
            kept=$(grep -ac 'kithd: init: eth[0-9]* has .* by DHCP' "$work/n1.log")
            [ "$kept" = 1 ] || fail "before the plug, $kept cards had a lease, not the one: $(grep -a 'kithd: init:' "$work/n1.log" | tail -n 5)"
            ! grep -aq 'came after boot' "$work/n1.log" || fail "a card came after boot before any was plugged: $(grep -a 'came after boot' "$work/n1.log")"
            # NAME: a monitor command, to the node.
            monitor() { printf '%s\n' "$1" | socat - "unix-connect:$work/keys1" >/dev/null; }
            plugged=$(date +%s%N)
            monitor 'netdev_add user,id=late,restrict=on'
            monitor 'device_add virtio-net-pci,netdev=late,id=latenic,bus=rp1,mac=52:54:00:00:0b:01'
            until grep -aq 'kithd: init: eth[0-9]* came after boot' "$work/n1.log" \
                && grep -aq 'kithd: init: eth[0-9]* has .* by DHCP' "$work/n1.log" \
                && [ "$(grep -ac 'kithd: init: eth[0-9]* has .* by DHCP' "$work/n1.log")" -gt "$kept" ]; do
                [ $(($(date +%s%N) - plugged)) -lt 10000000000 ] || fail "10 s after the plug the new card had no lease: $(grep -a 'kithd: init:' "$work/n1.log" | tail -n 5)"
                sleep 0.1
            done
            took=$((($(date +%s%N) - plugged) / 1000000))
            late=$(grep -ao 'kithd: init: eth[0-9]* came after boot' "$work/n1.log" | head -n 1 | cut -d ' ' -f 3)
            [ "$(grep -ac 'came after boot' "$work/n1.log")" = 1 ] || fail "more than one card came after boot: $(grep -a 'came after boot' "$work/n1.log")"
            grep -aq "kithd: init: $late has .* by DHCP" "$work/n1.log" || fail "the late card $late took no lease: $(grep -a 'by DHCP' "$work/n1.log")"
            echo "vm.sh: $late, plugged in after the boot, had a DHCP lease $took ms later" >&2
            # What the host's network is, read by an exec unit: a global address from QEMU's router
            # advertisement (the kernel's SLAAC, kithd asked nothing) on the card that is up since boot,
            # and /run/resolv.conf with the DHCP server of the user network (10.0.2.3) alone: kith.ip's
            # line (empty: no --dns) was written first and the lease replaced it.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"net"},"spec":{"retries":0,"template":{"exec":[
  {"name":"read","command":["/var/lib/kith/tools/pod","net"]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job that reads the network was not applied"
            said() { any GET "/v1/logs/$1/default/$2${3:+?unit=$3}" 2>/dev/null; }
            waited=0
            until line=$(units Job net) && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "waited for the Job net; it says: $line"
                sleep 1
            done
            printf '%s\n' "$line" | grep -q succeeded || fail "the Job net did not succeed: $line"
            net=$(said Job net)
            printf '%s\n' "$net" | grep -Eq 'inet6: eth1 fec0:' || fail "eth1 has no SLAAC address from QEMU's router advertisement: $net"
            [ "$(printf '%s\n' "$net" | grep -o 'resolv: [0-9.]*' | sort -u)" = 'resolv: 10.0.2.3' ] || fail "/run/resolv.conf does not list the DHCP server alone: $net"
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node: a card plugged in after the boot ($late) was brought up and took a DHCP lease in $took ms; eth1 had a SLAAC address with nothing asked; /run/resolv.conf listed the DHCP-given server"
            exit 0
