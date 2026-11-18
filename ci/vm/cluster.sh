# shellcheck shell=sh
# shellcheck disable=SC1091,SC2034,SC2154 # (names the driver and its parts share)
# shellcheck disable=SC2086 # (as the script had them before it was cut)
# Sourced by ci/vm.sh for --test rollout and the tests on a cluster of nodes: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
        for tool in curl python3 xxd; do
            command -v "$tool" >/dev/null 2>&1 || skip "no $tool"
        done
        kubectl=${KITH_KUBECTL:-$(command -v kubectl || true)}
        helms=$(printf '%s' "${KITH_HELM:-$(command -v helm || true)}" | tr ':' ' ')
        [ "$test" != kube ] || [ -x "$kubectl" ] || skip "no kubectl (KITH_KUBECTL names one; sh ci/kube.sh --vm fetches one)"
        [ "$test" != quota ] || command -v socat >/dev/null 2>&1 || skip "no socat to restart a node with"
        [ "$test" != home ] || command -v socat >/dev/null 2>&1 || skip "no socat to reset and stop a node with"
        if [ "$test" = pods ]; then
            command -v socat >/dev/null 2>&1 || skip "no socat to plug a keyboard in with"
        fi
        if [ "$test" = pods ] || [ "$test" = policy ]; then
            bwrap=$(command -v bwrap) || skip "no bwrap (bubblewrap) to start a sandbox inside a container with"
        fi
        if [ "$test" = tunnel ]; then
            # (The provider's: this machine's ip and wg, run there; and keys made by wg here.)
            for tool in ip wg cpio ldd socat; do
                command -v "$tool" >/dev/null 2>&1 || skip "no $tool for the WireGuard provider"
            done
        fi
        [ "$time" -gt 60 ] || time=900
        [ "$test" != kube ] || time=$((time * 2))
        [ "$test" != tunnel ] || time=$((time * 2))
        port=$((20000 + $$ % 20000))
        fail() { tail -n 30 "$work"/n?.log || true; echo "vm.sh: FAIL: $1" >&2; exit 1; }
        cargo build -q --manifest-path "$root/Cargo.toml" -p kith-cli >&2
        # (rollout, chaos and access: three nodes and nothing more said to kithd; share, pods, kube and
        # worker: two, on the mesh; quota: one, on the mesh; services: one, with no mesh.)
        others='2 3' more='' inside=2049 lan='' base=$root/target/os dumps='' gateway='' https='' guest=''
        seed() { :; }
      if [ "$test" = share ] || [ "$test" = pods ] || [ "$test" = poddns ] || [ "$test" = services ] || [ "$test" = compose ] || [ "$test" = quota ] || [ "$test" = kube ] || [ "$test" = worker ] || [ "$test" = policy ] || [ "$test" = tunnel ] || [ "$test" = outlive ]; then
        others=2 more=--mesh project=''
        [ "$test" != services ] && [ "$test" != compose ] && [ "$test" != outlive ] || others=''
        # (quota: a state disk with project quotas, as os/build.sh makes it; the others' have none,
        # as a node's state from before had none: kithd counts what their pods write.)
        [ "$test" != quota ] || others='' project='-I 256 -O quota,project'
        # (tunnel: one node, whose card out reaches nothing but this machine's forwards, to
        # its API and to its pod's web port published on it; and what both its cards carry,
        # kept. The UDP port published is asked from the node's LAN by ci/lan_probe.py: QEMU's
        # restricted user network drops every UDP answer of its guest's, and gives by DHCP no
        # way out: the node's is over its LAN, by the provider's machine, which is "outside"
        # too. So what a pod sends past its tunnel has somewhere to go, and is seen.)
        if [ "$test" = tunnel ]; then
            # (The comma doubled: QEMU's options take one as the next option's start.)
            others='' inside=8080 net_restrict=",restrict=on" gateway=,,10.9.0.9
            dumps="-object filter-dump,id=lan-dump,netdev=lan,file=$work/lan.pcap -object filter-dump,id=out-dump,netdev=out,file=$work/out.pcap"
        fi
        # (pods: a state disk keeps 8 MiB free, so a pod filling it is seen in time.)
        # (And an image no unit has used for two minutes goes: README, --image-grace.)
        [ "$test" != pods ] || more='--mesh --storage-reserve 8388608 --image-grace 120'
        # (worker: this machine asks what listens on port 80 of a node's own network.)
        [ "$test" != worker ] || inside=80
        # (services: no --mesh, as kith OS starts a node: its Services answer there too, T-0723.)
        [ "$test" != services ] || more=''
        # (policy: no way left to be root with all of the kernel's capabilities, so kithd gives up the rest.
        # QEMU reads a comma in -smbios as the end of a value, so each one here is doubled.)
        [ "$test" != policy ] || more='--mesh --node-policy no-exec-units,,no-vm-paths,,no-run'
        # A container image the nodes have without asking anybody (they reach no registry
        # here): kith itself, put where a node keeps an image it has pulled, in a state
        # partition made again with that in it.
        seed() { # DISK
            if ! [ -f "$work/state.img" ]; then
                digest=$(printf kith | sha256sum | cut -d ' ' -f 1)
                image=$work/seed/runtime/images/$digest
                mkdir -p "$work/seed/runtime/refs" "$image/rootfs/bin"
                cp "$(sh "$root/ci/musl.sh")/kith" "$image/rootfs/bin/kith"
                echo '{}' >"$image/config.json"
                printf '{"digest":"sha256:%s","entrypoint":[],"cmd":[],"env":[],"user":null}' "$digest" >"$work/seed/runtime/refs/kith.test%2fkith:1"
                # And what those tests' pods run (ci/pod.rs), as an image that names no user,
                # as one that names a user who is not root, and as two that say what to start
                # (an image nothing more is said of, as a chart has one). (share: what a
                # container's ids are, and what it sees of files.)
                rustc --edition 2024 -O -C panic=abort --target x86_64-unknown-linux-musl -o "$work/pod" "$root/ci/pod.rs" >&2
                digest=$(printf pod | sha256sum | cut -d ' ' -f 1)
                image=$work/seed/runtime/images/$digest
                mkdir -p "$image/rootfs/bin"
                cp "$work/pod" "$image/rootfs/bin/pod"
                echo '{}' >"$image/config.json"
                # (outlive: pod on the node's own disk as well, for its exec units.)
                [ "$test" != outlive ] || { mkdir -p "$work/seed/tools" && cp "$work/pod" "$work/seed/tools/pod"; }
                printf '{"digest":"sha256:%s","entrypoint":[],"cmd":[],"env":[],"user":null}' "$digest" >"$work/seed/runtime/refs/kith.test%2fpod:1"
                printf '{"digest":"sha256:%s","entrypoint":[],"cmd":[],"env":[],"user":"1000"}' "$digest" >"$work/seed/runtime/refs/kith.test%2fpod:user"
                for tag in serve again; do
                    printf '{"digest":"sha256:%s","entrypoint":["/bin/pod","serve"],"cmd":[],"env":[],"user":null}' "$digest" >"$work/seed/runtime/refs/kith.test%2fpod:$tag"
                done
                if [ "$test" = quota ]; then
                    # (quota: files of the image that a pod's root is made of, for it to change:
                    # one larger than its limit, others to rename over and to link. Not zeros,
                    # which mkfs keeps no blocks for.)
                    mkdir -p "$image/rootfs/data" "$image/rootfs/tree"
                    head -c 12582912 /dev/urandom >"$image/rootfs/big"
                    head -c 1048576 /dev/urandom >"$image/rootfs/data/small"
                    head -c 1048576 /dev/urandom >"$image/rootfs/data/other"
                    echo leaf >"$image/rootfs/tree/leaf"
                fi
                if [ "$test" = pods ] || [ "$test" = policy ]; then
                    # And bubblewrap as this machine has it, with what it is linked to, beside
                    # pod, for a user who is not root: a sandbox started inside a container.
                    digest=$(printf sandbox | sha256sum | cut -d ' ' -f 1)
                    image=$work/seed/runtime/images/$digest
                    mkdir -p "$image/rootfs/bin"
                    cp "$work/pod" "$image/rootfs/bin/pod"
                    cp -L "$bwrap" "$image/rootfs/bin/bwrap"
                    ldd "$bwrap" | awk '$2 == "=>" && $3 ~ /^\// { print ($1 ~ /^\// ? $1 : $3), $3 } $1 ~ /^\// && $2 != "=>" { print $1, $1 }' >"$work/linked"
                    while read -r to from; do
                        mkdir -p "$image/rootfs${to%/*}"
                        cp -L "$from" "$image/rootfs$to"
                    done <"$work/linked"
                    echo '{}' >"$image/config.json"
                    printf '{"digest":"sha256:%s","entrypoint":[],"cmd":[],"env":[],"user":"1000"}' "$digest" >"$work/seed/runtime/refs/kith.test%2fsandbox:1"
                    # And pod again under another name, for a Workload that is deleted: its
                    # image goes once unused for --image-grace. (Each image here is marked
                    # used a day ahead, so none goes before a unit has used it: no registry
                    # would give it back. Its pod is the other's, linked: a copy would put
                    # the state disk under its reserve, and every unused image would go.)
                    digest=$(printf gone | sha256sum | cut -d ' ' -f 1)
                    image=$work/seed/runtime/images/$digest
                    mkdir -p "$image/rootfs/bin"
                    ln "$work/seed/runtime/images/$(printf pod | sha256sum | cut -d ' ' -f 1)/rootfs/bin/pod" "$image/rootfs/bin/pod"
                    echo '{}' >"$image/config.json"
                    printf '{"digest":"sha256:%s","entrypoint":[],"cmd":[],"env":[],"user":null}' "$digest" >"$work/seed/runtime/refs/kith.test%2fgone:1"
                    touch -d '+1 day' "$work"/seed/runtime/images/*/config.json
                fi
                sfdisk -l -o Start,Sectors,Name "$1" | awk '$3 == "state" { print $1, $2 }' >"$work/state.at"
                read -r state_start state_sectors <"$work/state.at"
                mkfs.ext4 -q -d "$work/seed" -E root_owner=0:0 $project "$work/state.img" "$((state_sectors / 2))k" >&2
            fi
            read -r state_start state_sectors <"$work/state.at"
            dd if="$work/state.img" of="$1" bs=512 seek="$state_start" conv=notrunc status=none
            # (Room for an image that is pulled: the state grows to the disk's end at the first start.)
            # (quota: room for what its pods write. pods: room above its reserve, which its
            # full pod crosses on purpose.)
            case $test${KITH_E2E:-} in
                pods1 | kube1 | quota*) truncate -s 2G "$1" ;;
                pods) truncate -s 512M "$1" ;;
            esac
        }
      elif [ "$test" = rollout ]; then
        # The nodes run an image built with the release key: the first release they take
        # is one it signed, whoever applies one. (They fetch from this machine, on the
        # network QEMU gives them: their own, so --lan-releases.)
        public=$("$root/target/debug/kith" package keygen "$work/key")
        KITH_RELEASE_KEY=$public sh "$root/os/build.sh" --out "$work/base" >&2
        base=$work/base lan=--lan-releases
        # (KITH_NODE_POLICY: the nodes' policy, so that an update is taken by nodes that have
        # cut their bounding set: no-exec-units,no-vm-paths,no-run.)
        [ -z "${KITH_NODE_POLICY:-}" ] || lan="$lan --node-policy $(printf '%s' "$KITH_NODE_POLICY" | sed 's/,/,,/g')"
        # Two releases, both signed: one that runs, and one whose root is not the one its
        # verity tree was made for. The nodes fetch them from this machine.
        KITH_OS_VERSION=9.0.0-next sh "$root/os/build.sh" --out "$work/next" >&2
        mkdir "$work/www"
        cp "$work/next/kith-os.update" "$work/www/next.update"
        cp "$work/next/root.squashfs" "$work/broken.root"
        dd if=/dev/urandom of="$work/broken.root" bs=4096 count=8 conv=notrunc status=none
        sh "$root/os/update.sh" 9.0.0-broken "$(sha256sum "$work/broken.root" | cut -d ' ' -f 1)" "$work/broken.root" \
            "$work/next/root.verity" "$work/next/kith-a.efi" "$work/next/kith-b.efi" >"$work/www/broken.update"
        sign() { sh "$root/os/update.sh" --sign "$work/${2:-key}" "$work/www/$1.update"; }
        # A second key, which the first hands over to in the release every node takes.
        public2=$("$root/target/debug/kith" package keygen "$work/key2")
        handed() { sh "$root/os/update.sh" --handover "$work/$1" "$work/www/next.update" "$public2"; } # KEYFILE
        by=$public more='' allow=''
        (cd "$work/www" && exec python3 -m http.server --bind 127.0.0.1 $((port + 9))) >/dev/null 2>&1 &
        web=$!
        # (The nodes' port 80 is this server: only where it runs, as a guest with no listener there cannot start.)
        # (cmd: each guest connection gets its own socat to that port.)
        guest=",guestfwd=tcp:10.0.2.100:80-cmd:socat - TCP:127.0.0.1:$((port + 9))"
      fi

        # Each node: a card on a network the three share (QEMU passes it over multicast on
        # this machine's loopback), with a fixed address, and one out to this machine (which
        # reaches the node's API through it, and tries its NFS port, or port $inside).
        node() { # N [kithd's further arguments]
            [ -f "$work/n$1.raw" ] || { cp "$base/kith-os.raw" "$work/n$1.raw" && seed "$work/n$1.raw"; }
            timeout "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -display none \
                -machine q35 -bios "$firmware" -drive "file=$work/n$1.raw,format=raw,if=virtio" -device qemu-xhci,id=usb \
                -netdev "socket,id=lan,mcast=230.0.0.1:$((port + 8)),localaddr=127.0.0.1" -device "virtio-net-pci,netdev=lan,mac=52:54:00:00:09:0$1" \
                -netdev "user,id=out,hostfwd=tcp:127.0.0.1:$((port + $1))-:7443,hostfwd=tcp:127.0.0.1:$((port + 4 + $1))-:$inside${https:+,hostfwd=tcp:127.0.0.1:$((port + 10 + $1))-:443}$guest${net_restrict-,restrict=on}" -device "virtio-net-pci,netdev=out,mac=52:54:00:00:0a:0$1" $dumps \
                -smbios "type=11,value=io.systemd.stub.kernel-cmdline-extra=kith.hostname=n$1 kith.ip=10.9.0.$1/24$gateway -- --listen 0.0.0.0:7443 --advertise 10.9.0.$1:7443 $more $lan ${2:-}" \
                -serial "file:$work/n$1.log" -monitor "unix:$work/keys$1,server,nowait" </dev/null >/dev/null 2>&1 &
            vms="$vms $!"
        }
        field() { python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]], end="")' "$1"; }
        api() { # N METHOD PATH [FILE to send]: as the cluster's admin, to node N
            set -- "$@" ''
            curl -sf --max-time "${patience:-10}" --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
                --resolve "kith:$((port + $1)):127.0.0.1" -X "$2" -H 'Content-Type: application/json' ${4:+-d "@$4"} "https://kith:$((port + $1))$3"
        }
        any() { api 1 "$@" || api 2 "$@" || api 3 "$@"; }
        # What the cluster says, from whichever node answers:
        # "PHASE HOW-MANY-UPDATING VERSION,VERSION,VERSION REASON"; nothing while nobody does.
        see() {
            any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
nodes = sorted((r for r in found if r["kind"] == "Node"), key=lambda r: r["metadata"]["name"])
versions = ",".join(((n.get("status") or {}).get("os") or {}).get("version", "?") for n in nodes)
status = next(((r.get("status") or {}) for r in found if r["kind"] == "UpdatePlan"), {})
updating = sum(1 for state in (status.get("nodes") or {}).values() if state == "updating")
print(status.get("phase", "-"), updating, versions or "-", status.get("reason", ""))
'
        }
        until_says() { # WHAT, a pattern for see's line: wait for it; never two nodes updating at once
            waited=0
            until line=$(see) && printf '%s\n' "$line" | grep -Eq "$2"; do
                case $line in '' | *' 0 '* | *' 1 '*) ;; *) fail "more than one node updating at once: $line" ;; esac
                waited=$((waited + 1))
                [ "$waited" -lt $((time / 2)) ] || fail "waited for $1; the cluster says: $line"
                sleep 1
            done
            echo "vm.sh: $1: $line" >&2
        }
        # NAME VERSION SIGNATURE [FILE]: that release, and a plan that gives it to every node.
        # (Signed by the key $by; $more is more of the release's spec and $allow of the
        # plan's, for this one release.)
        release() {
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"OSRelease","metadata":{"name":"$1"},
  "spec":{"version":"$2","image":"http://10.0.2.100/${4:-$1}.update","publicKey":"$by","signature":"$3"$more}},
 {"apiVersion":"kith.dev/v1","kind":"UpdatePlan","metadata":{"name":"all"},"spec":{"release":"$1"$allow}}]
EOF
            more='' allow=''
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the release $1 was not applied"
        }
        starts() { grep -ac "Kernel command line:.*kith.slot=$2" "$work/n$1.log"; }

        # Nobody can log in to these nodes: the first says a token on its console, and
        # who sends it back is the cluster's admin; the others join with tokens it asks for.
        # (poddns: the first node asks the second for names it does not know, and the second asks an
        # outside resolver on this machine; KITH_POD_NOUPSTREAM=1 gives both an upstream that answers
        # nothing, the control. Neither asks the network out there.)
        first='' joined=''
        if [ "$test" = poddns ]; then
            first='--dns-upstream 10.9.0.2:5353'
            joined="--dns 0.0.0.0:5353 --dns-upstream 10.0.2.2:$((port + 9))" # unrestricted: the joined nodes ask this machine's resolver over UDP, which restrict=on drops
            [ "${KITH_POD_NOUPSTREAM:-}" != 1 ] || { first='--dns-upstream 10.9.0.9:5353'; joined='--dns 0.0.0.0:5353 --dns-upstream 10.9.0.9:5353'; }
        fi
        # (pods: a pod's egress may not reach the node's own subnet (kith's guard refuses it), so
        # the server its pods ask sits behind the gateway, 10.0.2.2, which restrict=on blocks.
        # unrestricted: this test's nodes keep their card out open; the value is put back after.)
        keep=${net_restrict-,restrict=on}
        [ "$test" != pods ] || net_restrict=''
        # (home: every node serves DNS on all its addresses, the house address too once it holds it.)
        [ "$test" != home ] || { first='--dns 0.0.0.0:5353'; joined='--dns 0.0.0.0:5353'; }
        node 1 "--claim ${first:-}"
        net_restrict=$keep
        tries=0
        until token=$(grep -ao 'sends this token to /v1/claim does: kith1\.[0-9a-f.]*' "$work/n1.log" 2>/dev/null) && [ -n "$token" ] \
            && [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 -H 'Content-Type: application/json' -d '{"token":"x","name":"root"}' "https://127.0.0.1:$((port + 1))/v1/claim")" = 403 ]; do
            tries=$((tries + 1))
            [ "$tries" -lt 300 ] || fail "the first node offered no claim, or did not answer"
            sleep 0.2
        done
        claimed=$(curl -sk --max-time 10 -H 'Content-Type: application/json' -d "{\"token\":\"${token##* }\",\"name\":\"root\"}" "https://127.0.0.1:$((port + 1))/v1/claim")
        for part in ca cert key; do
            printf '%s' "$claimed" | (umask 077 && field "$part" >"$work/$part.pem") || fail "the claim was refused: $claimed"
        done
        for n in $others; do
            # (worker: the node it lets in is one, and is sent a view of the store, never the store.)
            asks=/v1/tokens
            [ "$test" != worker ] || asks='/v1/tokens?trust=worker'
            join=$(api 1 POST "$asks" | field token) || fail "no join token over TLS"
            # (pods: the second node takes its pods' addresses from another range than the first's.)
            range=''
            [ "$test$n" != pods2 ] || range='--pod-range 10.77.0.0/20'
            # (poddns: a joined node asks this machine's resolver over UDP, which restrict=on
            # drops. unrestricted: only that test's joined nodes keep their card out open; the
            # value is put back after each, so no other node of it is opened.)
            case $test in poddns | pods) net_restrict='' ;; esac
            node "$n" "--join 10.9.0.1:7443 --token $join $range ${joined:-}"
            net_restrict=$keep
        done
        # What a resource's units say: "HOW-MANY-ARE-READY STATE ADDRESS ADDRESS ... and
        # what it says" (`none` for a unit with no address of its own).
        units() { # KIND NAME
            any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    if r["kind"] == sys.argv[1] and r["metadata"]["name"] == sys.argv[2]:
        status = r.get("status") or {}
        units = status.get("containers") or []
        ready = sum(1 for u in units if u.get("ready"))
        said = [status.get("message", "")] + [u.get("message", "") for u in units]
        print(ready, status.get("state", "-"), *sorted(u.get("address", "none") for u in units), *said)
' "$1" "$2"
        }
        if [ "$test" = poddns ]; then
            # The outside resolver is this machine's (ci/outside-dns.py): what the second node asks
            # for a name no node knows. The first node's pods ask the second, which has no such name.
            # (A SERVFAIL, when an upstream did not answer in time, is "Try again" to the pod, and musl
            # does not retry it: so the Job may run again (`retries`), up to the deadline below.)
            python3 "$root/ci/outside-dns.py" $((port + 9)) >/dev/null 2>"$work/outside-dns.log" &
            vms="$vms $!"
            sleep 1
            # The second node's DNS is up once it says so: until then node 1 asks a port nothing
            # listens on and the pod gets SERVFAIL ("Try again"), so the Job waits for that line.
            waited=0
            until grep -aq 'serving DNS on 0.0.0.0:5353' "$work/n2.log" 2>/dev/null; do
                waited=$((waited + 1))
                [ "$waited" -lt 180 ] || fail "the second node did not serve DNS: $(tail -n 3 "$work/n2.log" 2>/dev/null)"
                sleep 1
            done
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"lookup"},"spec":{"retries":4,"template":{"pod":true,"containers":[
  {"name":"ask","image":"kith.test/pod:user","command":["/bin/pod","lookup","outside.example.test"]}]}}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job lookup was not applied"
            waited=0
            until line=$(units Job lookup) && case $line in *' succeeded'* | *' failed'*) true ;; *) false ;; esac; do
                waited=$((waited + 1))
                [ "$waited" -lt 240 ] || fail "waited for the Job lookup; it says: $line"
                sleep 1
            done
            any GET "/v1/logs/Job/default/lookup" >"$work/lookup.out" || fail "what the Job lookup wrote could not be read"
            echo "vm.sh: the Job lookup: $line; its pod wrote: $(cat "$work/lookup.out")" >&2
            if [ "${KITH_POD_NOUPSTREAM:-}" = 1 ]; then
                grep -q 'outside.example.test: failed' "$work/lookup.out" || fail "the control found a name with no upstream: $(cat "$work/lookup.out")"
                echo "vm.sh: ok: control: with an upstream that answers nothing, a pod did not find outside.example.test" >&2
                exit 0
            fi
            # (What the Job wrote comes back as JSON, so the quotes around the address are \" in it.)
            grep -Fq 'outside.example.test: [\"198.51.100.7\"]' "$work/lookup.out" || fail "the pod did not find outside.example.test through its node's upstream: $(cat "$work/lookup.out") (the outside resolver's stderr: $(cat "$work/outside-dns.log"))"
            echo "vm.sh: ok: a pod of a node started without --dns found outside.example.test (198.51.100.7) through its node's upstream, a second kithd, which asked an outside resolver" >&2
            exit 0
        fi
        if [ "$test" = worker ]; then
            . "$root/ci/vm/worker.sh"
        fi
        if [ "$test" = tunnel ]; then
            . "$root/ci/vm/tunnel.sh"
        fi
        if [ "$test" = services ]; then
            . "$root/ci/vm/services.sh"
        fi
        if [ "$test" = outlive ]; then
            . "$root/ci/vm/outlive.sh"
        fi
        if [ "$test" = compose ]; then
            . "$root/ci/vm/compose.sh"
        fi
        if [ "$test" = quota ]; then
            . "$root/ci/vm/quota.sh"
        fi
        if [ "$test" = pods ]; then
            . "$root/ci/vm/pods.sh"
        fi
        if [ "$test" = policy ]; then
            . "$root/ci/vm/policy.sh"
        fi
        if [ "$test" = kube ]; then
            . "$root/ci/vm/kube.sh"
        fi
        if [ "$test" = share ]; then
            . "$root/ci/vm/share.sh"
        fi
        until_says "three nodes, each saying what it runs" "^- 0 [^,? ]+,[^,? ]+,[^,? ]+ "
        was=${line#- 0 } was=${was%% *}
        if [ "$test" = access ]; then
            . "$root/ci/vm/access.sh"
        fi

        if [ "$test" = chaos ]; then
            . "$root/ci/vm/chaos.sh"
        fi
        if [ "$test" = home ]; then
            . "$root/ci/vm/home.sh"
        fi

        # Before any release, each node says it takes releases from its image's keys (each
        # says it in its first round: waited for).
        waited=0
        until whose=$(any GET /v1/resources | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
nodes = (r for r in found if r["kind"] == "Node")
print(",".join(sorted(((n.get("status") or {}).get("os") or {}).get("releaseKeys", "?") for n in nodes)))
') && [ "$whose" = image,image,image ]; do
            waited=$((waited + 1))
            [ "$waited" -lt 60 ] || fail "the nodes do not take releases from the image's keys alone: $whose"
            sleep 1
        done
        # The first release applied, signed by a key the image was not built with: refused,
        # where a node with no key would have taken that key for its own.
        by=$public2
        release stranger 9.0.0-stranger "$(sign next key2)" next
        until_says "a first release by a key the image was not built with refused" "^Paused 0 $was .*not signed by a key this node takes releases from"
        [ "$(starts 1 a)$(starts 2 a)$(starts 3 a)" = 111 ] || fail "a node restarted for a release it refused"
        by=$public

        # A release whose signature is another file's: the first node asked refuses it,
        # writes nothing, and the plan stops there.
        release forged 9.0.0-next "$(sign broken)" next
        until_says "a release signed for another file refused" "^Paused 0 $was .*signature is not the release's key's"
        [ "$(starts 1 a)$(starts 2 a)$(starts 3 a)" = 111 ] || fail "a node restarted for a release it refused"

        # The release, signed: every node takes it, one at a time, and it is one cluster still.
        # It hands its key over to a second one, which signs with the first that it is held.
        more=",\"handover\":{\"keys\":[\"$public2\"],\"signature\":\"$(handed key)\",\"proof\":\"$(handed key2)\"}"
        release next 9.0.0-next "$(sign next)"
        until_says "all three on the release" "^Done 0 9.0.0-next,9.0.0-next,9.0.0-next "
        [ "$(starts 1 b)$(starts 2 b)$(starts 3 b)" = 111 ] || fail "not every node started its other slot once"
        ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
        # (Each takes the keys handed over once it has called the release's slot good.)
        tries=0
        until [ "$(grep -al 'handed over its release keys' "$work"/n?.log | wc -l)" = 3 ]; do
            tries=$((tries + 1))
            [ "$tries" -lt 60 ] || fail "not every node took the keys the release handed over"
            sleep 1
        done
        on=9.0.0-next,9.0.0-next,9.0.0-next

        # A release under what every node has now run well, in a plan that allows going
        # back and signed by the key they now take: refused, with nothing fetched.
        by=$public2 allow=',"allowDowngrade":true'
        release under 0.0.1 "$(sign next key2)" next
        until_says "a release under the floor refused, though its plan allows going back" "^Paused 0 $on .*the newest this node has run well"
        # One signed by the key that was left out: refused too.
        by=$public
        release left-out 9.0.1 "$(sign next)" next
        until_says "a release signed by the key that handed over refused" "^Paused 0 $on .*not signed by a key this node takes releases from"
        [ "$(starts 1 b)$(starts 2 b)$(starts 3 b)" = 111 ] || fail "a node restarted for a release it refused"
        by=$public2

        # A release that cannot start: the first node tries it three times and is back on
        # what it ran; the plan is paused, and no other node is given it.
        release broken 9.0.0-broken "$(sign broken key2)"
        until_says "a release that cannot start stopped at the first node" "^Paused 0 9.0.0-next,9.0.0-next,9.0.0-next .* did not take 9.0.0-broken: it did not come up"
        # (It says so once it has called its own slot good, ten seconds after it started.)
        tries=0
        until [ "$(grep -al 'slot a did not come up in 3 tries: this is slot b' "$work"/n?.log | wc -l)" = 1 ]; do
            tries=$((tries + 1))
            [ "$tries" -lt 30 ] || fail "not exactly one node tried the broken release"
            sleep 1
        done
        [ "$(($(starts 1 a) + $(starts 2 a) + $(starts 3 a)))" = 6 ] || fail "expected three tries of the broken release on one node"
        echo "vm.sh: ok: three nodes, claimed and joined over TLS; a first release by a key their image was not built with refused; a forged release refused; a signed one taken by all three, one at a time, as one cluster, and with it the key it handed over to; a release under their floor and one by the key left out refused; one that cannot start, signed by the new key, tried by one node, which came back, and the plan paused: $line"
        exit 0
