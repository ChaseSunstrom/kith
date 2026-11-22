# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test latecard: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # One node with two cards at boot (eth0: the LAN, a kith.ip address; eth1: QEMU's user
            # network, which gives a DHCP lease and a router advertisement), and a PCIe root port
            # free. A third card is plugged in after the boot, through the monitor: kithd must
            # find it within its 5 s scan, bring it up, and ask its network for an address.
            # (Waited for: the lease of the card of the boot may come a moment after the node is up.)
            waited=0
            until [ "$(grep -ac 'kithd: init: eth[0-9]* has .* by DHCP' "$work/n1.log")" -ge 1 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "no card of the boot had a DHCP lease in 30 s: $(grep -a 'kithd: init:' "$work/n1.log" | tail -n 5)"
                sleep 0.5
            done
            kept=$(grep -ac 'kithd: init: eth[0-9]* has .* by DHCP' "$work/n1.log")
            [ "$kept" = 1 ] || fail "before the plug, $kept cards had a lease, not the one: $(grep -a 'kithd: init:' "$work/n1.log" | tail -n 5)"
            ! grep -aq 'came after boot' "$work/n1.log" || fail "a card came after boot before any was plugged: $(grep -a 'came after boot' "$work/n1.log")"
            # NAME: a monitor command, to the node.
            # (-t 1: it waits a second for the monitor's answer, which it keeps in $said_by_monitor.)
            monitor() { said_by_monitor=$(printf '%s\n' "$1" | socat -t 1 - "unix-connect:$work/keys1" 2>&1 | tr -d '\r'); }
            # What the host's network is, by an exec unit running `pod net`: its answer in $net (or what went wrong).
            # (Named $1: each reading is a Job of its own, and a Job applied again is not run again.)
            read_net() {
                job=$1
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"$job"},"spec":{"retries":0,"template":{"exec":[
  {"name":"read","command":["/var/lib/kith/tools/pod","net"]}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || { net='the Job that reads the network was not applied'; return 1; }
                waited=0
                until line=$(units Job "$job") && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 60 ] || { net="waited for the Job $job; it says: $line"; return 1; }
                    sleep 1
                done
                printf '%s\n' "$line" | grep -q succeeded || { net="the Job $job did not succeed: $line"; return 1; }
                net=$(any GET "/v1/logs/Job/default/$job" 2>/dev/null)
            }
            # What the node's default routes are before the plug (the late card's network, its own
            # slirp on 10.0.3.0/24, gives a router and a name server of its own: neither may be taken).
            read_net netbefore || fail "$net"
            # ($net is the log as JSON, its lines joined by \n: the words are picked out.)
            routes_before=$(printf '%s\n' "$net" | grep -o 'default: [a-z0-9]* [0-9A-F]*' | sort || true)
            [ -n "$routes_before" ] || fail "the node has no default route before the plug: $net"
            # (A different network from the boot card's, whose slirp is on 10.0.2.0/24, and a lease
            # with a router and a name server: restrict=on would give neither.)
            monitor 'netdev_add user,id=late,net=10.0.3.0/24'
            netdev_said=$said_by_monitor
            monitor 'device_add virtio-net-pci,netdev=late,id=latenic,bus=rp1,mac=52:54:00:00:0b:01'
            device_said=$said_by_monitor
            plugged=$(date +%s%N)
            until grep -aq 'kithd: init: eth[0-9]* came after boot' "$work/n1.log" \
                && grep -aq 'kithd: init: eth[0-9]* has .* by DHCP' "$work/n1.log" \
                && [ "$(grep -ac 'kithd: init: eth[0-9]* has .* by DHCP' "$work/n1.log")" -gt "$kept" ]; do
                [ $(($(date +%s%N) - plugged)) -lt 10000000000 ] || { monitor 'info network'; read_net netfail || true; fail "10 s after the plug the new card had no lease: $(grep -a 'kithd: init:' "$work/n1.log" | tail -n 5); the monitor said to netdev_add: $netdev_said; to device_add: $device_said; of the network: $said_by_monitor; what the node's cards are: $net; what the kernel said of PCI: $(grep -aiE '_OSC|hotplug|pciehp|pcieport|acpiphp|pci 0000:01|virtio_net' "$work/n1.log" | tail -n 16); the log's end: $(tail -n 12 "$work/n1.log")"; }
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
            read_net netafter || fail "$net"
            printf '%s\n' "$net" | grep -Eq 'inet6: eth1 fec0' || fail "eth1 has no SLAAC address from QEMU's router advertisement: $net"
            # The late card's lease named a router (10.0.3.2) and a name server (10.0.3.3): the node
            # has both from the boot card, so the late card's are not used (the resolv.conf below
            # lists 10.0.2.3 alone), and the default routes are what they were.
            [ "$(printf '%s\n' "$net" | grep -o 'default: [a-z0-9]* [0-9A-F]*' | sort || true)" = "$routes_before" ] || fail "the late card changed the default routes: before: $routes_before; after: $net"
            grep -aq "kithd: init: $late has 10.0.3.[0-9]*/24 by DHCP" "$work/n1.log" || fail "the late card $late did not take a lease of the 10.0.3.0/24 network: $(grep -a 'by DHCP' "$work/n1.log")"
            [ "$(printf '%s\n' "$net" | grep -o 'resolv: [0-9.]*' | sort -u)" = 'resolv: 10.0.2.3' ] || fail "/run/resolv.conf does not list the DHCP server alone: $net; kithd said: $(grep -a 'kithd: init:' "$work/n1.log")"
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node: a card plugged in after the boot ($late) was brought up and took a DHCP lease in $took ms; eth1 had a SLAAC address with nothing asked; /run/resolv.conf listed the DHCP-given server"
            exit 0
