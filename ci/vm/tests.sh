# shellcheck shell=sh
# shellcheck disable=SC1091,SC2119,SC2120,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test every test but init (the image's own, and the groups below): it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
    command -v socat >/dev/null 2>&1 || skip "no socat to press keys with"
    command -v openssl >/dev/null 2>&1 || skip "no openssl to call the node with"
    # (fido2 computes the secrets it expects with python3: asked before the image is built, so it can't skip after.)
    [ "$test" != fido2 ] || command -v python3 >/dev/null 2>&1 || skip "no python3 to compute the secrets with"
    firmware=''
    for f in /usr/share/edk2-ovmf/x64/OVMF.4m.fd /usr/share/edk2/x64/OVMF.4m.fd /usr/share/OVMF/OVMF.fd /usr/share/ovmf/OVMF.fd; do
        [ -r "$f" ] && { firmware=$f; break; }
    done
    [ -n "$firmware" ] || skip "no UEFI firmware (OVMF)"
    # (The guests reach nothing outside their forwards, unless KITH_E2E=1 asks for image pulls: then net_restrict is set empty.)
    [ "${KITH_E2E:-}" != 1 ] || net_restrict=''
    command -v sfdisk >/dev/null 2>&1 || skip "no sfdisk to find the root partition with"
    # (KITH_OS_SPEC=os/examples/all.yaml tries the image of a spec instead of the plain one.)
    # (modules: the 'all' image, whose drivers are modules.)
    [ "$test" != modules ] || KITH_OS_SPEC=os/examples/all.yaml
    osdir=$root/target/os
    [ -z "${KITH_OS_SPEC:-}" ] || osdir=$root/target/os-spec
    # (access: the image of a kithd built with the feature forge, whose leader can append an entry it
    # was not asked for (ci/vm/access.sh); in a folder of its own, so the plain image stays plain.)
    [ "$test" != access ] || { KITHD_FEATURES=forge osdir=$root/target/os-forge; export KITHD_FEATURES; }
    # (fido2: the image of a kithd built with the cargo feature fido2-test, which answers as a security
    # key on /dev/uhid (docs/adr-fido2.md section 2), and of a kernel with that device (the uhid-test
    # spec); in a folder of its own, so the plain image stays plain, and no other test has either.)
    [ "$test" != fido2 ] || { KITHD_FEATURES=fido2-test KITH_OS_SPEC=os/examples/fido2-test.yaml osdir=$root/target/os-fido2; export KITHD_FEATURES; }
    # (disk: the image of a kithd built with the cargo feature disk-test, which makes the disk named on
    # the kernel command line a data disk at start (kith.disk-add=SERIAL), so the real mapping and the
    # mount are seen without the verbs; in a folder of its own, so the plain image stays plain.)
    [ "$test" != disk ] || { KITHD_FEATURES=disk-test osdir=$root/target/os-disk; export KITHD_FEATURES; }
    sh "$root/os/build.sh" --check ${KITH_OS_SPEC:+--spec "$root/$KITH_OS_SPEC"} --out "$osdir" >&2 || { [ $? -ne 3 ] || skip "this machine cannot build the image"; exit 1; }
    if [ "$test" = rollout ] || [ "$test" = share ] || [ "$test" = pods ] || [ "$test" = poddns ] || [ "$test" = services ] || [ "$test" = compose ] || [ "$test" = quota ] || [ "$test" = kube ] || [ "$test" = worker ] || [ "$test" = chaos ] || [ "$test" = home ] || [ "$test" = access ] || [ "$test" = policy ] || [ "$test" = tunnel ] || [ "$test" = outlive ] || [ "$test" = nested ] || [ "$test" = nofile ] || [ "$test" = handover ]; then
        . "$root/ci/vm/cluster.sh"
    fi
    if [ "$test" = install ] || [ "$test" = vps ] || [ "$test" = netboot ] || [ "$test" = crypt ] || [ "$test" = blackout ] || [ "$test" = alone ]; then
        . "$root/ci/vm/machines.sh"
    fi
    # A copy: the node writes its state to the disk, and this test damages its root.
    cp "$osdir/kith-os.raw" "$work/disk.raw"
    port=$((20000 + $$ % 20000))
    # (The stub adds $more to the command line of the image: here, kithd's own arguments.)
    serve='-- --listen 0.0.0.0:7443 --advertise 10.0.2.15:7443'
    more=$serve once=1
    boot() { # [more of QEMU's arguments]: $once empty lets the guest restart itself
        : >"$work/log"
        timeout --foreground "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -display none ${once:+-no-reboot} \
            -machine q35 -bios "$firmware" -drive "file=$work/disk.raw,format=raw,if=virtio" \
            -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$port-:7443${net_restrict-,restrict=on}" -device virtio-net-pci,netdev=n0 \
            -smbios "type=11,value=io.systemd.stub.kernel-cmdline-extra=$more" "$@" \
            -serial "file:$work/log" -monitor "unix:$work/keys,server,nowait" </dev/null >/dev/null 2>&1 8>&- &
        vm=$!
    }
    heard() { # TEXT: wait for the guest to say it
        until said "$1"; do
            kill -0 "$vm" 2>/dev/null || fail "the VM ended before it said: $1"
            sleep 0.05
        done
    }
    up() { heard 'serving other nodes on '; }
    # Who answers on the node's port, through the VM's network card: its certificate,
    # into $who.
    who() {
        tries=0
        until timeout 10 openssl s_client -connect "127.0.0.1:$port" </dev/null 2>/dev/null >"$work/hello" \
            && who=$(openssl x509 -noout -fingerprint -sha256 <"$work/hello" 2>/dev/null); do
            tries=$((tries + 1))
            [ "$tries" -lt 100 ] || fail "nobody answered TLS on the node's port"
            sleep 0.2
        done
    }
    restart() {
        echo sendkey ctrl-alt-delete | socat - "unix-connect:$work/keys" >/dev/null
        wait "$vm" || fail "the VM did not end within ${time} s of starting"
        said 'reboot: Restarting system' || fail "kithd did not restart the machine when told"
        ! said 'Kernel panic' || fail "the kernel panicked"
        resident=$(grep -ao 'told to stop: [0-9]* kB resident, [0-9]* kB of it files' "$work/log" | tail -n 1)
    }

    if [ "$test" = update ]; then
        . "$root/ci/vm/update.sh"
    fi
    if [ "$test" = modules ]; then
        . "$root/ci/vm/modules.sh"
    fi
    if [ "$test" = clock ]; then
        . "$root/ci/vm/clock.sh"
    fi
    if [ "$test" = disk ]; then
        . "$root/ci/vm/disk.sh"
    fi
    if [ "$test" = fido2 ]; then
        . "$root/ci/vm/fido2.sh"
    fi

    # (The disk is longer than the image written to it, as a real one is: 40 GB, of which
    # the file holds what is written. Past 32 GB an ext4 as small as the image's has used
    # up the room it kept for growing and the kernel has to lay its groups out anew.)
    truncate -s 40G "$work/disk.raw"
    # (The state partition ends at the disk's end, less the last MiB the GPT's backup and
    # the alignment take: 40959 MB less where it starts, which is the size of the rest of
    # the image; $want is its size in hundreds of MB, 407 for the plain image.)
    want=$(sfdisk -l -o Start,Name "$work/disk.raw" 2>/dev/null | awk '$2 == "state" { print int((40959 - $1 / 2048) / 100) }')
    [ -n "$want" ] || fail "no state partition in the image's table"
    began=$(date +%s%N)
    boot
    up
    took=$((($(date +%s%N) - began) / 1000000))
    said 'Mounted root (squashfs filesystem) readonly on device 25[0-9]:0' || fail "the root is not the verity device"
    said 'kithd: init: state on /dev/vda7' || fail "the state partition was not mounted"
    # The state partition is the image's 32 MB no longer: it ends where the disk does, the
    # file system fills it, and a tool that reads partition tables finds nothing to say.
    said 'kithd: init: the state partition now ends where its disk does: '"$want"'[0-9][0-9] MB' || fail "the state partition was not made to end where its disk does"
    said "kithd: init: the state's file system grown to ${want}[0-9][0-9] MB" || fail "the state's file system was not grown to its partition"
    who
    first=$who
    said 'by DHCP' || fail "the network card got no address by DHCP"
    restart
    cp "$work/log" "$work/log.first"
    table=$(sfdisk -l "$work/disk.raw" 2>&1)
    case $table in *mismatch* | *corrupt* | *'not on the end'* | *rror*) fail "the partition table kith OS wrote is not right: $table" ;; esac
    [ "$(sfdisk -l -o Name,Sectors "$work/disk.raw" | awk '$1 == "state" { print int($2 / 2048 / 100) }')" = "$want" ] || fail "the table does not say the state partition is longer: $table"

    boot
    up
    said 'kithd: init: state on /dev/vda7' || fail "the state partition was not mounted the second time"
    ! said 'now ends where its disk does' || fail "the state partition was changed again at the second start"
    ! said 'file system grown' || fail "the state's file system was grown again at the second start"
    who
    second=$who
    restart
    [ "$first" = "$second" ] || fail "the node came back as another: its state did not survive ($first, then $second)"

    # One block of the root changed: the kernel must refuse it, and kithd never run.
    start=$(sfdisk -l -o Start,Name "$work/disk.raw" | awk '$2 == "root-a" { print $1 }')
    dd if=/dev/urandom of="$work/disk.raw" bs=512 seek="$start" count=8 conv=notrunc status=none
    boot
    wait "$vm" || true
    cat "$work/log.first"
    ! said 'kithd: ' || fail "kithd ran from a root that was tampered with"
    said 'device-mapper: verity: .* is corrupted' || fail "the kernel did not say the root was corrupted"
    echo "vm.sh: the image served other nodes ${took} ms after QEMU started (firmware, boot loader and kernel included)"
    # (Of the second start, from the image's own root: read from the disk, as a node's is.)
    [ -n "$resident" ] || fail "kithd did not say what it held in memory when told to stop"
    echo "vm.sh: kithd as the first process of kith OS, ${resident#told to stop: }"
    [ "$took" -lt 10000 ] || { echo "vm.sh: FAIL: over 10 s" >&2; exit 1; }
    echo "vm.sh: ok: UEFI boot from the image, a verity root, DHCP, TLS answered ($first), on a disk longer than the image a state partition that ends where the disk does from the first start and is left alone at the second, state kept across a restart, a tampered root refused"
    exit 0
