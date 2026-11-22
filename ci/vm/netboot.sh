# shellcheck shell=sh
# shellcheck disable=SC2154,SC2034 # (names the driver and its parts share)
# shellcheck disable=SC2015 # (as the script had them before it was cut)
# Sourced by ci/vm.sh for --test netboot and crypt: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # A network as in a house: one with a DHCP server of its own (ci/dhcpd.py), on a
            # hub with a node's card and a socket that a second machine's card connects to.
            # The node is told to install that machine; the machine, with an empty disk, is
            # set to start from the network. The node's second card is this script's way in.
            out=$root/target/os
            [ "$time" -gt 300 ] || time=600
            mac=52:54:00:00:09:02 more=''
            # (Six starts of the machine: the node has to outlast them all.)
            [ "$test" = netboot ] || more='&encrypt=true' time=$((time * 2))
            [ -z "$sealing" ] || time=$((time * 3 / 2))
            # --test tpm, the update leg (docs/adr-unlock.md, Tests): three releases signed by a key
            # this run makes, and a second key the node does not take releases from. Alpha is started
            # with the first key and --lan-releases: the installer carries both on to the machine it
            # installs, which takes releases from that key alone (so none is taken on trust) and
            # fetches them from this machine (served below). Each root names that key and a junk
            # one of its own (64 hex digits, no one's): a system's own keys are what a command
            # line's key must be one of, and a root that differs makes the update a full one, a
            # restart: three releases that only said another version would be hand-overs of
            # kithd, with no restart at all.
            #
            # What this run does not do end to end (T-1180): a slot on trial is killed 15 s
            # after it starts, not left to wait its 300 s (TRIAL_WAIT) and restart by itself, so
            # that restart (init::end(true)) and the 300 s retry of a seal-again that began before
            # its slot was good (UNSEALED_RETRY) are not run here; the boot loader's count of
            # tries is what the legs read (ondisk b N). And an update from a stick cannot seal
            # ahead by design: init takes it before the state is opened, when kithd holds no key
            # to seal, so that leg checks what it can (the stick's slot has no seal and the old
            # slot comes back), and the control that sealing ahead works is the signed leg above it.
            releasing=''
            if [ -n "$sealing" ]; then
                command -v xxd >/dev/null 2>&1 || skip "no xxd to make a release key with"
                command -v openssl >/dev/null 2>&1 || skip "no openssl to make a release key with"
                keygen() { # NAME: a key file in $work (PKCS#8 in hex, as os/update.sh --sign reads it); its public key said
                    (umask 077 && openssl genpkey -algorithm ed25519 -outform DER | xxd -p -c 256 >"$work/$1")
                    xxd -r -p <"$work/$1" | openssl pkey -inform DER -pubout -outform DER | tail -c 32 | xxd -p -c 64
                }
                key1=$(keygen key1)
                key2=$(keygen key2)
                releasing="--release-key $key1 --lan-releases"
                mkdir "$work/www"
                for n in 1 2 3; do
                    KITH_RELEASE_KEY="$key1,$(printf '%064d' "$n")" KITH_OS_VERSION=9.$n.0 sh "$root/os/build.sh" --out "$work/r$n" >&2
                    cp "$work/r$n/kith-os.update" "$work/www/r$n.update"
                    rm -rf "$work/r$n"
                done
                web_up "$work/www" $((port + 7)) || fail "the web server on port $((port + 7)) did not start"
                # (The machine's second card: its port 80 is that server. cmd: each connection gets its own socat.)
                guest="user,id=w,restrict=on,guestfwd=tcp:10.0.2.100:80-cmd:socat - TCP:127.0.0.1:$((port + 7))"
            fi
            # Alpha and the DHCP server of its hub, started again where a test takes alpha off:
            # the server ends when the hub's connection to it does, so it goes with alpha.
            start_alpha() {
                python3 "$root/ci/dhcpd.py" "$((port + 9))" 52:54:00:00:09:01=10.9.0.1 "$mac=10.9.0.2" &
                dhcp=$!
                vms="$vms $dhcp"
                sleep 0.5
                # shellcheck disable=SC2046
                vm alpha $(drive alpha.disk) \
                    -netdev "socket,id=d,connect=127.0.0.1:$((port + 9))" -netdev hubport,id=h0,hubid=0,netdev=d \
                    -netdev "socket,id=s,listen=127.0.0.1:$((port + 8))" -netdev hubport,id=h1,hubid=0,netdev=s \
                    -netdev hubport,id=h2,hubid=0 -device virtio-net-pci,netdev=h2,mac=52:54:00:00:09:01 \
                    -netdev "user,id=u,restrict=on,hostfwd=tcp:127.0.0.1:$((port + 1))-10.0.2.15:7443" -device virtio-net-pci,netdev=u \
                    -smbios 'type=11,value=io.systemd.stub.kernel-cmdline-extra=kith.hostname=alpha -- --listen 0.0.0.0:7443 --advertise 10.9.0.1:7443 --claim '"$releasing"
                alpha=$vm
            }
            cp "$out/kith-os.raw" "$work/alpha.disk"
            start_alpha
            hears alpha 'kithd: node alpha serving other nodes on 0.0.0.0:7443'
            hears alpha 'sends this token to /v1/claim does: kith1.'
            token=$(grep -ao 'sends this token to /v1/claim does: kith1\.[0-9a-f.]*' "$work/alpha.log")
            tries=0
            until claimed=$(curl -sfk --max-time 10 -H 'Content-Type: application/json' -d "{\"token\":\"${token##* }\",\"name\":\"root\"}" "https://127.0.0.1:$((port + 1))/v1/claim"); do
                tries=$((tries + 1))
                [ "$tries" -lt 50 ] || fail "the node's cluster could not be claimed"
                sleep 0.2
            done
            field() { python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]], end="")' "$1"; }
            for part in ca cert key; do
                printf '%s' "$claimed" | (umask 077 && field "$part" >"$work/$part.pem") || fail "the claim was refused: $claimed"
            done
            api() { # METHOD PATH [curl's further arguments]: as the cluster's admin, to alpha
                method=$1 path=$2
                shift 2
                curl -s --max-time 60 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
                    --resolve "kith:$((port + 1)):127.0.0.1" -X "$method" "$@" "https://kith:$((port + 1))$path"
            }
            # Off until told; not turned on by a file that is not the boot file, nor for no machine.
            now=$(api GET /v1/netboot)
            [ "$(printf '%s' "$now" | field on)" = False ] || fail "netboot is on before anyone turned it on: $now"
            api PUT "/v1/netboot?macs=$mac" --data-binary "@$out/vmlinuz" | grep -qF "not kith's network boot file" || fail "netboot took a file that is not the boot file"
            api PUT '/v1/netboot?minutes=10' --data-binary "@$out/kith-netboot.efi" | grep -qF "a machine's card address" || fail "netboot went on for no machine"
            [ "$(api GET /v1/netboot | field on)" = False ] || fail "netboot is on after two refusals"
            [ "$(api PUT "/v1/netboot?macs=$mac&minutes=10$more" --data-binary "@$out/kith-netboot.efi" | field on)" = True ] || fail "netboot did not go on"
            # (Again while on: the second takes the ports the first held.)
            [ "$(api PUT "/v1/netboot?macs=$mac&minutes=10$more" --data-binary "@$out/kith-netboot.efi" | field on)" = True ] || fail "netboot, on, could not be turned on anew"
            hears alpha 'kithd: netboot: on for 10 minutes'

            beta() { # LOG [disk]: the machine: an empty disk at first, and its card, which it starts from (or: from its disk)
                vm "$1" -m 1024 -drive "file=$work/beta.disk,format=raw,if=none,id=d" -device "virtio-blk-pci,drive=d${2+,bootindex=0}${2-,bootindex=2}" \
                    -netdev "socket,id=n,connect=127.0.0.1:$((port + 8))" -device "virtio-net-pci,netdev=n,mac=$mac${2-,bootindex=1}"
            }
            blank beta
            # (Its answers are the node's: no one is asked, and the install is drawn all the same:
            # shown part-way and done, with no kernel text, as from a stick.)
            [ "$test" != netboot ] || monitor=unix:$work/install-beta.mon,server=on,wait=off
            beta install-beta
            monitor=
            if [ "$test" = netboot ]; then
                shot install-beta mid 'kithd: install: kith OS is on'
                shot install-beta end 'kithd: init: restarting'
            fi
            wait "$vm" || fail "the machine started from the network did not install and start again"
            grep -aqF 'kithd: install: kith OS is on vda' "$work/install-beta.log" || fail "the machine started from the network did not install"
            hears alpha "kithd: netboot: $mac has the installer"
            api GET /v1/netboot | grep -q '"served": *true' || fail "the node does not say the machine was served"
            # Started again, still from the network first: it is not answered a second time,
            # goes on to its disk, and joins the node's cluster with the token it was given.
            beta beta
            hears beta 'kithd: init: kith-000902 is up'
            tries=0
            until api GET /v1/resources/Node/kith-000902 -f >/dev/null; do
                tries=$((tries + 1))
                [ "$tries" -lt 300 ] || fail "the machine installed from the network is not in the node's cluster"
                sleep 0.2
            done
            ! grep -aqF 'kithd: install:' "$work/beta.log" || fail "the machine was installed a second time"
            [ "$(api DELETE /v1/netboot | field on)" = False ] || fail "netboot did not go off"
            hears alpha 'kithd: netboot: off'
            if [ "$test" = crypt ]; then
                # What a disk file says from outside: whether its state partition shows a file
                # system (ext4's mark) and what its lock record holds.
                says() {
                    python3 -c '
import struct, sys
disk, at = open(sys.argv[1], "rb"), {}
disk.seek(512 + 72)
entries = struct.unpack("<Q", disk.read(8))[0] * 512
for index in range(128):
    disk.seek(entries + index * 128)
    entry = disk.read(128)
    at[entry[56:].decode("utf-16-le").rstrip("\0")] = struct.unpack("<Q", entry[32:40])[0] * 512
disk.seek(at["state"] + 1080)
state = "plain" if disk.read(2) == b"\x53\xef" else "sealed"
disk.seek(at["config"] + (512 << 10))
record = disk.read(4096)
print(state, "none" if not record.startswith(b"kith-lock v1\n") else "key" if b"\nkey: " in record else "held", *["tpm"] * (b"\ntpm: " in record), *["tpm-parent"] * (b"\ntpm-parent: " in record), *["tpm-next"] * (b"\ntpm-next: " in record), *["tpm-pin"] * (b"\ntpm-pin: " in record), *["passphrase"] * (b"\npassphrase: " in record), *["seen"] * (b"\nseen: yes\n" in record), *["duress"] * (b"\nduress: " in record))' "$1"
                }
                lock() { api POST "/v1/lock/kith-000902?do=$1"; }
                up() { # LOG: the machine's state is open and it serves
                    hears "$1" 'kithd: init: state on /dev/dm-'
                    hears "$1" 'kithd: node kith-000902 serving other nodes'
                }
                command -v mdir >/dev/null 2>&1 || mdir() { nix shell nixpkgs#mtools -c mdir "$@"; }
                espat() { # NAME: where the partition NAME of beta's disk starts
                    python3 -c '
import struct, sys
disk = open(sys.argv[1], "rb")
disk.seek(512 + 72)
entries = struct.unpack("<Q", disk.read(8))[0] * 512
for index in range(128):
    disk.seek(entries + index * 128)
    entry = disk.read(128)
    if entry[56:].decode("utf-16-le").rstrip("\0") == sys.argv[2]:
        print(struct.unpack("<Q", entry[32:40])[0] * 512, end="")
        sys.exit(0)
sys.exit(1)' "$work/beta.disk" "$1"
                }
                ondisk() { # SLOT TRIES: beta's ESP holds exactly one boot file for SLOT, with TRIES tries left (kith-N-SLOT+TRIES.efi, or +TRIES-DONE once tried; TRIES good: the slot is marked good, kith-N-SLOT.efi)
                    names=$(mdir -b -i "$work/beta.disk@@$(espat esp)" ::EFI/Linux) || fail "beta's ESP could not be read"
                    [ "$(printf '%s\n' "$names" | grep -cE "/kith-[0-9]*-$1[+.]")" = 1 ] || fail "beta's ESP does not have exactly one boot file for slot $1: $names"
                    [ "$2" = good ] && pattern="/kith-[0-9]*-$1\.efi$" || pattern="/kith-[0-9]*-$1\+$2(-[0-9]+)?\.efi$"
                    [ "$(printf '%s\n' "$names" | grep -cE "$pattern")" = 1 ] || fail "beta's ESP does not have slot $1 with $2 tries left: $names"
                }
                recovery=$(grep -ao 'shown this once: [0-9a-f-]*' "$work/install-beta.log") || fail "the installer showed no recovery key"
                [ "$(says "$out/kith-os.raw")" = 'plain none' ] || fail "the image's state is not a plain file system: $(says "$out/kith-os.raw")"
                # First start: the key is beside the lock until the other node holds it.
                hears beta 'still on its disk: no other node holds it yet'
                up beta
                hears beta "10.9.0.1:7443 holds the key of this node's state"
                if [ -n "$sealing" ]; then
                    tpm=''
                    mkdir "$work/tpm"
                    own() { # LOG [away] [web] [more of QEMU's arguments]: the machine from its disk, with its TPM (the same at every start: its state is kept); away: without its card, so no node is in reach; web: with a card to the web server of the releases
                        machine=$1 card=1
                        shift
                        [ "${1:-}" != away ] || { card='' && shift; }
                        [ "${1:-}" != web ] || { shift && set -- -netdev "$guest" -device virtio-net-pci,netdev=w,romfile= "$@"; }
                        [ -z "$tpm" ] || kill "$tpm" 2>/dev/null || true
                        rm -f "$work/tpm.sock"
                        swtpm socket --tpm2 --tpmstate "dir=$work/tpm" --ctrl "type=unixio,path=$work/tpm.sock" >/dev/null 2>&1 &
                        tpm=$!
                        vms="$vms $tpm"
                        tries=0
                        until [ -S "$work/tpm.sock" ]; do
                            tries=$((tries + 1))
                            [ "$tries" -lt 50 ] || fail "swtpm did not start"
                            sleep 0.1
                        done
                        [ -n "$card" ] || set -- -nic none "$@"
                        [ -z "$card" ] || set -- -netdev "socket,id=n,connect=127.0.0.1:$((port + 8))" -device "virtio-net-pci,netdev=n,mac=$mac" "$@"
                        vm "$machine" -m 1024 -drive "file=$work/beta.disk,format=raw,if=none,id=d" -device virtio-blk-pci,drive=d,bootindex=0 \
                            -chardev "socket,id=tpmc,path=$work/tpm.sock" -tpmdev emulator,id=tpm0,chardev=tpmc -device tpm-tis,tpmdev=tpm0 "$@"
                    }
                    off() { # the machine's power cut
                        kill "$vm"
                        wait "$vm" 2>/dev/null || true
                    }
                    restarts() { # WHAT: the machine restarts itself (its qemu ends) within 5 minutes
                        tries=0
                        while kill -0 "$vm" 2>/dev/null; do
                            tries=$((tries + 1))
                            [ "$tries" -lt 1500 ] || fail "the machine did not restart after $1"
                            sleep 0.2
                        done
                        wait "$vm" || true
                    }
                    told() { # WHAT: the cluster's NodeKey of the machine comes to say it
                        tries=0
                        until api GET /v1/resources/NodeKey/kith-000902 | grep -q "$1"; do
                            tries=$((tries + 1))
                            [ "$tries" -lt 150 ] || fail "the machine's NodeKey never said $1: $(api GET /v1/resources/NodeKey/kith-000902)"
                            sleep 0.2
                        done
                    }
                    types() { printf '%s\n' "$2" | socat - "unix-connect:$work/$1.tty" >/dev/null; }
                    labelled() { # the machine's Node resource, labelled ring=canary: the update plan below names that ring (alpha has no label, so it is no part of any rollout)
                        api GET /v1/resources/Node/kith-000902 -f >"$work/node.json" || fail "the machine's Node could not be read"
                        python3 -c '
import json, sys
found = json.load(open(sys.argv[1]))
found = found if isinstance(found, list) else [found]
for node in found:
    node["metadata"].pop("revision", None)
    node["metadata"].setdefault("labels", {})["ring"] = "canary"
json.dump(found, open(sys.argv[2], "w"))' "$work/node.json" "$work/node-label.json" || fail "the machine's Node could not be labelled: $(cat "$work/node.json")"
                        api POST /v1/apply -f -H 'Content-Type: application/json' --data-binary "@$work/node-label.json" >/dev/null || fail "the machine's Node label was refused"
                    }
                    release() { # NAME VERSION KEYFILE PUBLIC FILE: that release (FILE.update, in the web server's folder), signed by KEYFILE, and a plan that gives it to the ring
                        signature=$(sh "$root/os/update.sh" --sign "$work/$3" "$work/www/$5.update") || fail "the release $1 could not be signed"
                        cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"OSRelease","metadata":{"name":"$1"},
  "spec":{"version":"$2","image":"http://10.0.2.100/$5.update","publicKey":"$4","signature":"$signature"}},
 {"apiVersion":"kith.dev/v1","kind":"UpdatePlan","metadata":{"name":"all"},"spec":{"release":"$1","selector":{"ring":"canary"}}}]
EOF
                        api POST /v1/apply -f -H 'Content-Type: application/json' --data-binary "@$work/apply.json" >/dev/null || fail "the release $1 was not applied"
                    }
                    good() { # SLOT: beta's boot loader marks SLOT good (its boot file loses its tries) once the state has been open a while
                        tries=0
                        until mdir -b -i "$work/beta.disk@@$(espat esp)" ::EFI/Linux | grep -qE "/kith-[0-9]*-$1\.efi$"; do
                            tries=$((tries + 1))
                            [ "$tries" -lt 150 ] || fail "slot $1 was not marked good"
                            sleep 0.5
                        done
                    }
                    opens() { hears "$1" 'kithd: init: state on /dev/dm-'; }
                    recovered() { # LOG: the end of each leg: away from the cluster, the TPM refused (a command line beside the boot file's), the recovery key typed at the console opens the disk
                        own "$1" away -smbios 'type=11,value=io.systemd.stub.kernel-cmdline-extra=loglevel=6'
                        hears "$1" 'Or type the recovery key here'
                        hears "$1" 'still locked'
                        ! grep -aqF 'state on' "$work/$1.log" || fail "a machine away from its cluster opened its state before the recovery key was typed"
                        types "$1" "${recovery##* }"
                        hears "$1" 'kithd: init: opened with the recovery key'
                        hears "$1" 'kithd: init: state on /dev/dm-'
                        off
                    }
                    trial() { # LOG TRIES: a start of the slot on trial with no node in reach, and no key for it: it waits (kithd restarts it after 300 s: killed before, the boot loader has counted the try), and has TRIES tries left
                        own "$1" away
                        hears "$1" 'asking the cluster for its key'
                        hears "$1" 'still locked: 10.9.0.1:7443 cannot be reached'
                        sleep 15
                        ! grep -aqF 'slot b is good' "$work/$1.log" || fail "the slot on trial was called good with its key not opened"
                        ondisk b "$2"
                        off
                    }
                    # Told to seal, a machine with no TPM says why not, and runs on as it was.
                    lock seal | grep -q '"seal": *true' || fail "the machine could not be told to seal its key"
                    hears beta 'is not sealed: reading /sys/kernel/security/tpm0/binary_bios_measurements'
                    told 'binary_bios_measurements'
                    off
                    [ "$(says "$work/beta.disk")" = 'sealed held' ] || fail "the machine's disk, read from outside: $(says "$work/beta.disk")"
                    # With its TPM, but on the image the installer wrote (no release signed it: no
                    # header of one is kept): it is not sealed for, the node's key is all it has.
                    own beta1 web
                    hears beta1 'asking the cluster for its key'
                    up beta1
                    hears beta1 'is not sealed: no release header is kept for slot a'
                    told 'no release header is kept for slot a'
                    # The first signed release is taken: a full update (a restart). Slot b is
                    # the first system a release signed, and the one that is sealed for.
                    labelled
                    release r1 9.1.0 key1 "$key1" r1
                    hears beta1 '9.1.0 is a full update (a restart)'
                    hears beta1 'kith OS 9.1.0 is in the other slot: restarting into it'
                    restarts 'the first release'
                    [ "$(says "$work/beta.disk")" = 'sealed held' ] || fail "the disk of the machine that took its first release, read from outside: $(says "$work/beta.disk")"
                    # With its TPM: it asks the node this once, and seals its key to what it runs.
                    own beta2 web
                    hears beta2 'asking the cluster for its key'
                    up beta2
                    hears beta2 "this machine's TPM holds the key of its state, for this system"
                    told '"sealed": *true'
                    # A release the cluster's key did not sign (a second key, which the node does
                    # not take releases from) is refused before its image is fetched: the other
                    # slot is not written, and no key is sealed for what it holds.
                    release rx 9.5.0 key2 "$key2" r3
                    hears beta2 'the release is not signed by a key this node takes releases from'
                    hears beta2 'no update to kith OS 9.5.0'
                    ! grep -aqF -e 'kith OS 9.5.0 is in the other slot' -e 'sealed ahead for 9.5.0' "$work/beta2.log" || fail "a release the cluster's key did not sign was taken"
                    good b
                    off
                    [ "$(says "$work/beta.disk")" = 'sealed held tpm tpm-parent' ] || fail "the sealed machine's disk, read from outside: $(says "$work/beta.disk")"
                    ondisk b good
                    # Started again: its own TPM gives the key, and no node is asked.
                    own beta3
                    hears beta3 'TPM gave the key of its state: no node was asked'
                    up beta3
                    ! grep -aqF 'asking the cluster' "$work/beta3.log" || fail "a machine whose TPM holds its key asked the cluster for it"
                    off
                    # A word of its config partition changed (a space after the last): the TPM
                    # refuses, the node is asked, and the key is sealed to what runs now.
                    python3 -c '
import struct, sys
with open(sys.argv[1], "r+b") as disk:
    disk.seek(512 + 72)
    entries = struct.unpack("<Q", disk.read(8))[0] * 512
    for index in range(128):
        disk.seek(entries + index * 128)
        entry = disk.read(128)
        if entry[56:].decode("utf-16-le").rstrip("\0") == "config":
            at = struct.unpack("<Q", entry[32:40])[0] * 512
            disk.seek(at)
            disk.seek(at + disk.read(64 << 10).index(b"\0"))
            disk.write(b" ")
            sys.exit(0)
    sys.exit(1)' "$work/beta.disk" || fail "the machine's disk has no config partition to change"
                    refused() { # LOG: the TPM gave no key, the node did, and the key is sealed anew
                        hears "$1" 'this is not the system it was sealed for'
                        hears "$1" 'asking the cluster for its key'
                        up "$1"
                        hears "$1" "this machine's TPM holds the key of its state"
                        off
                    }
                    own beta4
                    refused beta4
                    # The boot file changed (a letter of the command line in it): the same.
                    python3 -c '
import mmap, sys
with open(sys.argv[1], "r+b") as disk:
    disk, found = mmap.mmap(disk.fileno(), 0), 0
    at = disk.find(b"console=tty0 dm-mod.create")
    while at >= 0:
        disk[at : at + 12], found = b"console=tty1", found + 1
        at = disk.find(b"console=tty0 dm-mod.create", at)
    sys.exit(found == 0)' "$work/beta.disk" || fail "the machine's disk has no boot file with the command line this test changes"
                    # (The boot file is no longer the piece the release names for this slot: the
                    # TPM refuses, the node is asked, and the key is not sealed for it: that is a
                    # system the cluster's key did not sign.)
                    own beta5 web
                    hears beta5 'this is not the system it was sealed for'
                    hears beta5 'asking the cluster for its key'
                    up beta5
                    hears beta5 'is not sealed: the image that runs is not the piece the release names for slot b'
                    told 'the image that runs is not the piece the release names for slot b'
                    off
                    python3 -c '
import mmap, sys
with open(sys.argv[1], "r+b") as disk:
    disk, found = mmap.mmap(disk.fileno(), 0), 0
    at = disk.find(b"console=tty1 dm-mod.create")
    while at >= 0:
        disk[at : at + 12], found = b"console=tty0", found + 1
        at = disk.find(b"console=tty1 dm-mod.create", at)
    sys.exit(found == 0)' "$work/beta.disk" || fail "the machine's disk has no changed boot file to put back"
                    # Put back, the TPM's seal for it opens again, with no node asked.
                    own beta5b
                    hears beta5b 'TPM gave the key of its state: no node was asked'
                    up beta5b
                    ! grep -aqF 'asking the cluster' "$work/beta5b.log" || fail "a machine whose TPM holds its key asked the cluster for it, once its boot file was put back"
                    off
                    # A command line beside the boot file's: the same for the TPM (it gives no key, the
                    # node is asked), but the key is not sealed again for it: PCR 9 holds a command
                    # line that is not the boot file's in any form kithd can explain (docs/adr-unlock.md,
                    # step 5), so what it would predict is not to be trusted. The old seal stays: the
                    # machine started as it was, its own TPM gives the key, and no node is asked.
                    beside='type=11,value=io.systemd.stub.kernel-cmdline-extra=loglevel=7'
                    own beta6 -smbios "$beside"
                    hears beta6 'this is not the system it was sealed for'
                    hears beta6 'asking the cluster for its key'
                    up beta6
                    hears beta6 'is not sealed: the event log has no event in PCR 9 that is the running boot file'
                    off
                    own beta7
                    hears beta7 'TPM gave the key of its state: no node was asked'
                    up beta7
                    ! grep -aqF 'asking the cluster' "$work/beta7.log" || fail "the machine, started as it was, asked the cluster for its key"
                    # Locked: it drops the seal, restarts and waits; unlocked, it seals again.
                    lock lock | grep -q '"locked": *true' || fail "the sealed machine could not be locked"
                    hears beta7 "this machine's TPM no longer holds the key of its state"
                    hears beta7 'kithd: the cluster has locked this node'
                    restarts 'the cluster locked it'
                    [ "$(says "$work/beta.disk")" = 'sealed held' ] || fail "the locked machine's disk, read from outside: $(says "$work/beta.disk")"
                    own beta8
                    hears beta8 'still locked: 10.9.0.1:7443 does not hand this node'
                    ! grep -aqF 'state on' "$work/beta8.log" || fail "a locked machine opened its state"
                    lock unlock | grep -q '"locked": *false' || fail "the machine could not be unlocked"
                    up beta8
                    hears beta8 "this machine's TPM holds the key of its state"
                    # Taken back: the seal is dropped, and the NodeKey says so.
                    lock unseal | grep -q '"seal": *false' || fail "the seal could not be taken back"
                    hears beta8 "this machine's TPM no longer holds the key of its state"
                    told '"sealed": *false'
                    off
                    [ "$(says "$work/beta.disk")" = 'sealed held' ] || fail "the machine's disk, read from outside, once its seal was taken back: $(says "$work/beta.disk")"
                    # The update leg (docs/adr-unlock.md, Tests). The machine runs slot b (the first
                    # release), and is told to seal again. A second release, signed by the cluster's
                    # key, is taken: the key is sealed ahead (tpm-next:) for the system in the other
                    # slot, and the machine restarts into it with its peers off (no card), and opens
                    # by tpm-next with no node asked. (The plan names a label that only this machine
                    # has: alpha is no part of the rollout.)
                    own up1 web
                    hears up1 'asking the cluster for its key'
                    up up1
                    lock seal | grep -q '"seal": *true' || fail "the machine could not be told to seal its key again"
                    hears up1 "this machine's TPM holds the key of its state, for this system"
                    release r2 9.2.0 key1 "$key1" r2
                    hears up1 '9.2.0 is a full update (a restart)'
                    hears up1 "the key of this node's state is sealed ahead for 9.2.0"
                    hears up1 'kith OS 9.2.0 is in the other slot: restarting into it'
                    restarts 'the second release'
                    [ "$(says "$work/beta.disk")" = 'sealed held tpm tpm-parent tpm-next' ] || fail "the disk of the machine that sealed ahead, read from outside: $(says "$work/beta.disk")"
                    ondisk a 3
                    own up2 away
                    hears up2 'TPM gave the key of its state (the seal made ahead for this system, tpm-next:): no node was asked'
                    opens up2
                    ! grep -aqF 'asking the cluster' "$work/up2.log" || fail "a machine whose TPM holds the key ahead asked the cluster for it"
                    # Once the slot is good the seal made ahead is the seal of this system.
                    hears up2 'the old seal is dropped'
                    good a
                    off
                    [ "$(says "$work/beta.disk")" = 'sealed held tpm tpm-parent' ] || fail "the disk of the machine that took its update, read from outside: $(says "$work/beta.disk")"
                    ondisk a good
                    recovered rec1
                    # An update from a stick is taken on the word of whoever holds it (no release
                    # signed it), and never sealed for. By design it cannot be: init takes it before
                    # the state is opened, so kithd holds no key to seal ahead with (and its boot
                    # carries a command line of its own, which the TPM refuses anyway). So this
                    # checks what is observable, and the signed leg above is its control (the same
                    # kind of update, sealed ahead, opens its slot by tpm-next): the disk says no
                    # tpm-next after it, and the slot it wrote is tried three times and asks the
                    # cluster each time, never opened by its TPM, before the old slot starts again.
                    # It is the third release here, which no key signed so far.
                    cp "$work/www/r3.update" "$work/stick.update"
                    truncate -s %1M "$work/stick.update"
                    own stick away -drive "file=$work/stick.update,format=raw,if=virtio,readonly=on" -smbios 'type=11,value=io.systemd.stub.kernel-cmdline-extra=kith.update=vdb'
                    hears stick 'kithd: init: kith OS 9.3.0 from vdb is in the other slot'
                    restarts 'the update from a stick'
                    # (From here the record says "seen": the recovery key was typed at the console.)
                    [ "$(says "$work/beta.disk")" = 'sealed held tpm tpm-parent seen' ] || fail "the disk of the machine that took an update from a stick, read from outside: $(says "$work/beta.disk")"
                    ondisk b 3
                    trial stick1 2
                    trial stick2 1
                    trial stick3 0
                    ! grep -aqF 'TPM gave the key' "$work/stick1.log" "$work/stick2.log" "$work/stick3.log" || fail "the slot an update from a stick wrote was opened by the TPM: something was sealed for it"
                    own stick4 away
                    hears stick4 'slot b did not come up in 3 tries: this is slot a'
                    hears stick4 'TPM gave the key of its state: no node was asked'
                    opens stick4
                    off
                    recovered rec2
                    # The third release, signed, with its tpm-next: damaged by a byte of the file on
                    # the disk: the slot it was sealed for fails three times (the TPM refuses the
                    # seal), the old slot starts, and its state opens with nothing typed.
                    own dm2 web
                    hears dm2 'TPM gave the key of its state: no node was asked'
                    up dm2
                    release r3 9.3.0 key1 "$key1" r3
                    hears dm2 "the key of this node's state is sealed ahead for 9.3.0"
                    hears dm2 'kith OS 9.3.0 is in the other slot: restarting into it'
                    restarts 'the third release'
                    [ "$(says "$work/beta.disk")" = 'sealed held tpm tpm-parent tpm-next seen' ] || fail "the disk of the machine that sealed ahead again, read from outside: $(says "$work/beta.disk")"
                    ondisk b 3
                    python3 -c '
import hashlib, re, struct, sys
# (The format of the lock record is in crates/kithd/src/crypt.rs, Record::read and Record::write: it sits
# at 512 KiB of the "config" partition and a copy follows 4096 bytes on, written first; its text is
# "kith-lock v1", a "sum:" line that is the SHA-256 of the rest, then the lines. One byte changed
# and the sum kept would be a damaged record kithd refuses, not a seal the TPM refuses; so the
# byte is changed in both copies and the sum made again.
# The byte is hex digit 40 of tpm-next:, byte 20 of the sealed blob: inside the integrity HMAC
# of the TPM2B_PRIVATE (bytes 4 to 36), so what reads the record whole and parses the blob (sizes
# untouched) is TPM2_Load of the TPM, and that is what refuses. The log cannot say so: a seal that
# does not open is said as the refusal of tpm:, the system that runs now. The control is the signed
# leg above, whose undamaged tpm-next opens its slot; here the old slot "TPM gave the key" line
# and the three tries are what is read.)
with open(sys.argv[1], "r+b") as disk:
    disk.seek(512 + 72)
    entries = struct.unpack("<Q", disk.read(8))[0] * 512
    for index in range(128):
        disk.seek(entries + index * 128)
        entry = disk.read(128)
        if entry[56:].decode("utf-16-le").rstrip("\0") == "config":
            at = struct.unpack("<Q", entry[32:40])[0] * 512 + (512 << 10)
            disk.seek(at)
            record = disk.read(4096).split(b"\0")[0]
            first, _, rest = record.split(b"\n", 2)
            found = re.search(rb"\ntpm-next: ([0-9a-f]+)\n", rest)
            assert found, "no tpm-next: in the lock record"
            place = found.start(1) + 40
            rest = rest[:place] + (b"0" if rest[place : place + 1] != b"0" else b"1") + rest[place + 1 :]
            made = first + b"\nsum: " + hashlib.sha256(rest).hexdigest().encode() + b"\n" + rest
            for to in (0, 4096):
                disk.seek(at + to)
                disk.write(made.ljust(4096, b"\0"))
            sys.exit(0)
    sys.exit(1)' "$work/beta.disk" || fail "the machine's lock record has no tpm-next: to damage"
                    trial dmg1 2
                    trial dmg2 1
                    trial dmg3 0
                    ! grep -aqF 'TPM gave the key' "$work/dmg1.log" "$work/dmg2.log" "$work/dmg3.log" || fail "the TPM gave the key from the seal that was damaged"
                    own dmg4 away
                    hears dmg4 'slot b did not come up in 3 tries: this is slot a'
                    hears dmg4 'TPM gave the key of its state: no node was asked'
                    opens dmg4
                    off
                    recovered rec3
                    # (The damaged seal is no use to anyone: taken back, with the rest, for what follows.)
                    own dmg5 web
                    up dmg5
                    lock unseal | grep -q '"seal": *false' || fail "the seal could not be taken back after the damaged leg"
                    hears dmg5 "this machine's TPM no longer holds the key of its state"
                    told '"sealed": *false'
                    off
                    [ "$(says "$work/beta.disk")" = 'sealed held seen' ] || fail "the machine's disk, read from outside, once its seal was taken back again: $(says "$work/beta.disk")"
                    # A PIN, asked of the machine itself at its own address (no node passes one
                    # on): refused unless the owner says this TPM is untried (swtpm's is: 3
                    # wrong PINs, then one more every 1000 seconds, which 8 digits are enough
                    # for). (Its second card has no ROM, so the firmware starts as before.)
                    own beta9 -netdev "user,id=u,restrict=on,hostfwd=tcp:127.0.0.1:$((port + 2))-10.0.2.15:7443" -device virtio-net-pci,netdev=u,romfile=
                    up beta9
                    pin=40917253
                    api POST /v1/lock/kith-000902/pin -H 'Content-Type: application/json' -d "{\"pin\":\"$pin\",\"untried\":true}" | grep -qF 'ask node kith-000902 itself' || fail "a PIN was passed on by the other node"
                    given() { # JSON: to the machine itself
                        curl -s --max-time 60 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" --resolve "kith:$((port + 2)):127.0.0.1" \
                            -X POST -H 'Content-Type: application/json' -d "$1" "https://kith:$((port + 2))/v1/lock/kith-000902/pin"
                    }
                    tries=0
                    until said=$(given "{\"pin\":\"$pin\"}") && [ -n "$said" ]; do
                        tries=$((tries + 1))
                        [ "$tries" -lt 150 ] || fail "the machine does not answer at its own address"
                        sleep 0.2
                    done
                    printf '%s' "$said" | grep -qF 'On hardware' || fail "a PIN was taken without the owner saying the TPM is untried: $said"
                    given '{"pin":"4091","untried":true}' | grep -qF 'a PIN is 6 to 32 digits' || fail "a PIN of 4 digits was not refused"
                    said=$(given "{\"pin\":\"$pin\",\"untried\":true}")
                    printf '%s' "$said" | grep -q '"pin": *true' || fail "the machine took no PIN: $said"
                    hears beta9 "this machine's TPM and its PIN open its state; its TPM alone no longer does"
                    ! api GET /v1/resources | grep -qF "$pin" || fail "the PIN is in the store"
                    off
                    [ "$(says "$work/beta.disk")" = 'sealed held tpm-parent tpm-pin seen' ] || fail "the disk of the machine with a PIN, read from outside: $(says "$work/beta.disk")"
                    ! grep -aqF "$pin" "$work/beta.disk" "$work/alpha.log" "$work/beta9.log" || fail "the PIN is on the machine's disk or was said by a node"
                    # Away from its cluster it asks at its console: its PIN opens it.
                    own pin1 away
                    hears pin1 'Or type its PIN, or the recovery key, here: neither is shown'
                    hears pin1 'still locked'
                    ! grep -aqF 'state on' "$work/pin1.log" || fail "a machine away from its cluster opened its state before its PIN was typed"
                    types pin1 "$pin"
                    hears pin1 'kithd: init: opened with its PIN'
                    hears pin1 'kithd: init: state on /dev/dm-'
                    off
                    # Started again: a wrong PIN opens nothing and is counted, until the TPM
                    # refuses every PIN, the right one too, and says for how long. (Setting
                    # the PIN tried a wrong one; a TPM cut off after a PIN was used counts
                    # one more: how many are left here is not known beforehand.)
                    answered() { grep -acF -e "kithd: init: that does not open this node's state" -e 'kithd: init: the TPM refuses every PIN for now' "$work/$1.log" || true; }
                    after() { # LOG N: the console answered more than N lines
                        tries=0
                        until [ "$(answered "$1")" -gt "$2" ]; do
                            tries=$((tries + 1))
                            [ "$tries" -lt 150 ] || fail "the console answered no more than $2 lines"
                            sleep 0.2
                        done
                    }
                    own pin2 away
                    hears pin2 'Or type its PIN, or the recovery key, here: neither is shown'
                    hears pin2 'still locked'
                    wrong=0
                    until grep -aqF 'the TPM refuses every PIN for now' "$work/pin2.log"; do
                        [ "$wrong" -lt 4 ] || fail "the TPM refused no PIN after $wrong wrong ones"
                        types pin2 40917250
                        after pin2 "$wrong"
                        wrong=$((wrong + 1))
                    done
                    types pin2 "$pin"
                    after pin2 "$wrong"
                    [ "$(grep -acF 'the TPM refuses every PIN for now' "$work/pin2.log")" -ge 2 ] || fail "the right PIN, typed while the TPM refused every PIN, was not refused"
                    grep -aqF 'the next is taken within 1000 seconds' "$work/pin2.log" || fail "the console did not say when the TPM takes a PIN again"
                    ! grep -aqF 'state on' "$work/pin2.log" || fail "a PIN opened the state while the TPM refused every PIN"
                    # The recovery key opens it all the same, and no console showed a PIN.
                    types pin2 "${recovery##* }"
                    hears pin2 'kithd: init: opened with the recovery key'
                    hears pin2 'kithd: init: state on /dev/dm-'
                    ! grep -aqF -e "$pin" -e 40917250 "$work/pin1.log" "$work/pin2.log" || fail "the machine's console showed a PIN as it was typed"
                    off
                    echo "vm.sh: ok: a machine with its state encrypted, told to seal its key, said why not without a TPM; with one (swtpm) it sealed the key, and started again with no node asked; started with a word of its config partition changed, then with its boot file changed, then with a command line beside the boot file's, the TPM refused the key each time, the node was asked and the key sealed anew; locked, it dropped the seal, restarted and waited until unlocked, then sealed again; the seal taken back, its disk holds none; a boot file that is not the piece the cluster's key signed was never sealed for, and a release another key signed was refused before its image was fetched; a second signed release sealed the key ahead (tpm-next:), and the machine, with no node in reach, opened by it in the new slot and made it its seal once the slot was good; an update from a stick sealed nothing ahead; a third release with its tpm-next: damaged by a byte failed three times, the old slot started and opened with nothing typed; each leg ended with the recovery key opening the disk; a PIN not passed on by the other node, given at its own address (once the owner said the TPM is untried), away from its cluster it opened with that PIN, then refused $wrong wrong ones until its TPM refused every PIN, the right one too, and the recovery key opened it all the same"
                    exit 0
                fi
                api GET /v1/resources/NodeKey/kith-000902 | grep -q '"wrapped"' || fail "the cluster holds no key for the machine"
                if [ -n "$duress" ]; then
                    key() { api GET /v1/resources/NodeKey/kith-000902; }
                    comes() { # WHAT WHY: the machine's NodeKey comes to hold WHAT
                        tries=0
                        until key | grep -q "$1"; do
                            tries=$((tries + 1))
                            [ "$tries" -lt 150 ] || fail "$2: $(key)"
                            sleep 0.2
                        done
                    }
                    wrong() { # LOG TIMES: the console said so often that what was typed opens nothing
                        tries=0
                        until [ "$(grep -acF "kithd: init: that does not open this node's state" "$work/$1.log")" -ge "$2" ]; do
                            tries=$((tries + 1))
                            [ "$tries" -lt 150 ] || fail "the console answered what was typed at it fewer than $2 times"
                            sleep 0.2
                        done
                    }
                    types() { printf '%s\n' "$2" | socat - "unix-connect:$work/$1.tty" >/dev/null; }
                    # Nobody watched the install: the cluster says so, and makes no code for
                    # all of its nodes while one of them could then be opened by nobody.
                    api GET /v1/lock | grep -qF 'nobody was shown the recovery key of any node' || fail "the cluster does not warn of a recovery key nobody saw: $(api GET /v1/lock)"
                    api POST /v1/duress | grep -qF 'nobody was shown the recovery key of kith-000902' || fail "a duress code for the whole cluster was made while the machine's recovery key was never shown"
                    # A new recovery key, through the other node (which keeps none of it): the
                    # machine's record says it was shown, and the cluster warns no more.
                    new=$(api POST /v1/lock/kith-000902/recovery | field recovery) || fail "the machine made no new recovery key"
                    [ "${#new}" = 39 ] && [ "$new" != "${recovery##* }" ] || fail "what the machine answered is no new recovery key: $new"
                    comes '"recoverySeen": *true' "the cluster does not say the machine's recovery key was shown"
                    [ "$(api GET /v1/lock | field warning)" = None ] || fail "the cluster still warns once a recovery key was shown: $(api GET /v1/lock)"
                    ! api GET /v1/resources | grep -qF "$new" || fail "the new recovery key is in the store"
                    ! grep -aqF "$new" "$work/alpha.log" "$work/beta.log" || fail "a node said the new recovery key"
                    kill "$vm"
                    wait "$vm" 2>/dev/null || true
                    [ "$(says "$work/beta.disk")" = 'sealed held seen' ] || fail "the machine's disk, read from outside: $(says "$work/beta.disk")"
                    beta beta2 ''
                    up beta2
                    # Now there is a code for all. What it does to a node it was not typed at:
                    # the cluster forgets the key (written here as the forget writes it), the
                    # machine runs on, gives no key again and takes no other word but unlock.
                    all=$(api POST /v1/duress | field code) || fail "no duress code for the whole cluster was made"
                    comes '"duressAll": *true' "the machine did not take the cluster's duress code to its record"
                    id=$(key | python3 -c 'import json, sys; print(json.load(sys.stdin)["spec"]["id"], end="")')
                    printf '[{"apiVersion":"kith.dev/v1","kind":"NodeKey","metadata":{"name":"kith-000902"},"spec":{"id":"%s","forgotten":true}}]' "$id" >"$work/forgotten.json"
                    api POST /v1/apply -H 'Content-Type: application/json' --data-binary "@$work/forgotten.json" >/dev/null
                    hears beta2 'kithd: the cluster has forgotten the key of this node'
                    sleep 5
                    ! key | grep -q '"wrapped"' || fail "the machine gave the cluster the key it had forgotten"
                    ! grep -aqF 'restarting' "$work/beta2.log" || fail "a machine whose key was forgotten did not run on"
                    lock lock | grep -qF 'has forgotten' || fail "a machine whose key was forgotten could be locked"
                    lock unlock | grep -q '"locked": *false' || fail "the cluster could not be told to hold the machine's key again"
                    comes '"wrapped"' "the machine did not give its key again once it was unlocked"
                    ! api GET /v1/resources | grep -qF "$all" || fail "the cluster's duress code is in the store"
                    # A code of its own; then locked, so that it waits at its console with the
                    # cluster in reach.
                    code=$(lock duress | field code) || fail "no duress code was made for the machine"
                    [ "${#code}" = 39 ] || fail "what was made is no duress code: $code"
                    comes '"duress": *true' "the machine did not take its duress code to its record"
                    ! api GET /v1/resources | grep -qF "$code" || fail "the duress code is in the store"
                    ! grep -aqF "$code" "$work/alpha.log" "$work/beta2.log" || fail "a node said the duress code"
                    lock lock | grep -q '"locked": *true' || fail "the machine could not be locked"
                    hears beta2 'kithd: the cluster has locked this node'
                    wait "$vm" || true
                    [ "$(says "$work/beta.disk")" = 'sealed held seen duress' ] || fail "the disk of the machine with a duress code, read from outside: $(says "$work/beta.disk")"
                    beta beta3 ''
                    hears beta3 'still locked: 10.9.0.1:7443 does not hand this node'
                    # A key that is none, and the key the installer showed (it opens no more).
                    types beta3 0000-0000-0000-0000-0000-0000-0000-0000
                    wrong beta3 1
                    types beta3 "${recovery##* }"
                    wrong beta3 2
                    # The duress code: answered as those were, and nothing else is said of it
                    # on the machine; the other node forgets its key, and says so.
                    types beta3 "$code"
                    wrong beta3 3
                    hears alpha 'kithd: a duress code was typed: forgetting NodeKey/kith-000902'
                    comes '"wiped": *true' "the cluster did not forget the key of the machine a duress code was typed at"
                    ! key | grep -q '"wrapped"' || fail "the cluster still has the key of the machine a duress code was typed at"
                    # Its recovery key, which opened it a moment ago, opens nothing now.
                    types beta3 "$new"
                    wrong beta3 4
                    sleep 3
                    ! grep -aqF 'state on' "$work/beta3.log" || fail "the machine opened its state after its duress code was typed"
                    [ "$(grep -acF "kithd: init: that does not open this node's state" "$work/beta3.log")" = 4 ] || fail "the console said something else of one of the four lines typed at it"
                    ! grep -aiE 'kithd: .*(duress|eras|forg)' "$work/beta3.log" || fail "the machine's console says a duress code was typed"
                    lock unlock | grep -qF 'was wiped' || fail "a machine whose duress code was typed could be unlocked"
                    # Nor does an earlier version of its NodeKey, which has the key, come back.
                    api POST '/v1/rollback/NodeKey/kith-000902?to=1' | grep -qF 'a NodeKey is not rolled back' || fail "a forgotten NodeKey could be rolled back"
                    ! key | grep -q '"wrapped"' || fail "the cluster has the key again of the machine a duress code was typed at"
                    kill "$vm"
                    wait "$vm" 2>/dev/null || true
                    [ "$(says "$work/beta.disk")" = 'sealed none' ] || fail "the disk of the machine its duress code was typed at, read from outside: $(says "$work/beta.disk")"
                    beta beta4 ''
                    hears beta4 "kithd: init: this node's lock record was erased"
                    echo "vm.sh: ok: a machine installed with its state encrypted and nobody watching: the cluster warned that nobody saw a recovery key and made no duress code for all; the machine made a new recovery key, shown once, and the warning went; its key forgotten as the cluster's code forgets it, it ran on, gave no key and was held again once unlocked; given a duress code of its own and locked, it waited: a wrong key, the installer's old recovery key and the duress code were each answered with the same line; the code erased its lock record and had the other node forget its key, the new recovery key opened nothing after, and its disk opens for nobody"
                    exit 0
                fi
                kill "$vm"
                wait "$vm" 2>/dev/null || true
                [ "$(says "$work/beta.disk")" = 'sealed held' ] || fail "the machine's disk, read from outside: $(says "$work/beta.disk")"
                # Started again, it asks the node for its key. Locked, it restarts and waits.
                beta beta2 ''
                hears beta2 'asking the cluster for its key'
                up beta2
                lock lock | grep -q '"locked": *true' || fail "the machine could not be locked"
                hears beta2 'kithd: the cluster has locked this node'
                wait "$vm" || true
                beta beta3 ''
                hears beta3 'still locked: 10.9.0.1:7443 does not hand this node'
                ! grep -aqF 'state on' "$work/beta3.log" || fail "a locked machine opened its state"
                lock unlock | grep -q '"locked": *false' || fail "the machine could not be unlocked"
                up beta3
                # Its key deleted from the store: the running machine gives it again, and has not restarted.
                api DELETE /v1/resources/NodeKey/kith-000902 >/dev/null
                tries=0
                until api GET /v1/resources/NodeKey/kith-000902 | grep -q '"wrapped"'; do
                    tries=$((tries + 1))
                    [ "$tries" -lt 150 ] || fail "the machine did not give its key again once it was deleted"
                    sleep 0.2
                done
                echo "vm.sh: the machine gave its key again after $tries tries of 0.2 s"
                ! grep -aqF 'has locked this node' "$work/beta3.log" || fail "the unlocked machine restarted as if locked"
                # An update given to a node whose key holder is off: it is written to slot b and started
                # there with no key, so slot b stays on trial (not marked good), and after three starts
                # without its key the boot loader is back on slot a. Read from beta's ESP, where the counter is.
                # The update comes by kith.update from a stick (vdb), not from the cluster: update.rs's path
                # from the OS release is not exercised here.
                kill "$vm"
                wait "$vm" 2>/dev/null || true
                kill "$alpha"
                wait "$alpha" 2>/dev/null || true
                # The server usually ends once alpha's connection does; killed if it has not, so the next one can take its port.
                kill "$dhcp" 2>/dev/null || true
                wait "$dhcp" 2>/dev/null || true
                KITH_OS_VERSION=0.0.0-test sh "$root/os/build.sh" --out "$work/next" >&2
                cp "$work/next/kith-os.update" "$work/good.update"
                truncate -s %1M "$work/good.update"
                vm slotb -m 1024 -drive "file=$work/beta.disk,format=raw,if=none,id=d" -device virtio-blk-pci,drive=d,bootindex=0 \
                    -drive "file=$work/good.update,format=raw,if=virtio,readonly=on" -nic none \
                    -smbios 'type=11,value=io.systemd.stub.kernel-cmdline-extra=kith.update=vdb'
                hears slotb 'kithd: init: kith OS 0.0.0-test from vdb is in the other slot'
                wait "$vm" || fail "the update was not written to slot b while the key holder was off"
                ondisk b 3
                # Started from its disk with no way to alpha: each start waits for its key, and is still on
                # trial 15 s on, one try fewer each time; the third leaves none, so the next start is slot a.
                # The real "not marked good" check is ondisk b N: a slot marked good is renamed to
                # kith-N-b.efi (settle), which ondisk does not match. The grep is a second look at the log.
                trial() { # LOG TRIES: a start of beta's disk with no network card at all
                    vm "$1" -m 1024 -drive "file=$work/beta.disk,format=raw,if=none,id=d" -device virtio-blk-pci,drive=d,bootindex=0 \
                        -nic none
                    hears "$1" 'asking the cluster for its key'
                    hears "$1" 'still locked: 10.9.0.1:7443 cannot be reached'
                    sleep 15
                    ! grep -aqF 'slot b is good' "$work/$1.log" || fail "slot b was marked good without its key ($1)"
                    ondisk b "$2"
                    kill "$vm"
                    wait "$vm" 2>/dev/null || true
                }
                trial trial1 2
                trial trial2 1
                trial trial3 0
                # Alpha back, its DHCP server with it: the fourth start is slot a, which opens its state.
                start_alpha
                hears alpha 'kithd: node alpha serving other nodes on 0.0.0.0:7443'
                beta slota ''
                up slota
                grep -aq 'Kernel command line:.*kith.slot=a' "$work/slota.log" || fail "the node did not start slot a after three tries on slot b"
                hears slota 'slot b did not come up in 3 tries: this is slot a'
                ondisk b 0
                # A passphrase, given through the other node (which keeps none of it): too short
                # a one is refused; taken away, the disk has no line of it; given again, it has.
                pass() { api POST /v1/lock/kith-000902/passphrase -H 'Content-Type: application/json' -d "$1"; }
                passes() { # WHETHER: the NodeKey's status comes to say so
                    tries=0
                    until [ "$(api GET /v1/resources/NodeKey/kith-000902 | grep -c '"passphrase": *true')" = "$1" ]; do
                        tries=$((tries + 1))
                        [ "$tries" -lt 100 ] || fail "the cluster does not say whether the machine has a passphrase (expected $1)"
                        sleep 0.2
                    done
                }
                pass '{"passphrase":"short"}' | grep -qF 'characters or more' || fail "a passphrase of five characters was taken"
                pass '{"passphrase":"pässwörter und mehr"}' | grep -qF 'signs of ASCII' || fail "a passphrase the console of a starting machine cannot type was taken"
                pass '{"passphrase":"correct horse battery"}' | grep -q '"passphrase": *true' || fail "the machine was given no passphrase"
                passes 1
                pass '{}' | grep -q '"passphrase": *false' || fail "the machine's passphrase was not taken away"
                passes 0
                pass '{"passphrase":"correct horse battery"}' | grep -q '"passphrase": *true' || fail "the machine was given no passphrase a second time"
                passes 1
                ! api GET /v1/resources | grep -qF 'correct horse' || fail "the passphrase is in the store"
                ! grep -aqF 'correct horse' "$work/alpha.log" "$work/beta3.log" "$work/slota.log" || fail "a node said the passphrase"
                kill "$vm"
                wait "$vm" 2>/dev/null || true
                [ "$(says "$work/beta.disk")" = 'sealed held passphrase' ] || fail "the disk of the machine with a passphrase, read from outside: $(says "$work/beta.disk")"
                ! grep -aqF 'correct horse' "$work/beta.disk" || fail "the passphrase is on the machine's disk as it was typed"
                # Away from its cluster (started without its card): no node answers, and it opens
                # its state once the passphrase is typed at it, not before and not for another.
                vm away -m 1024 -drive "file=$work/beta.disk,format=raw,if=none,id=d" -device virtio-blk-pci,drive=d,bootindex=0
                hears away 'Or type its passphrase, or the recovery key'
                hears away 'still locked'
                printf 'correct horse batterz\n' | socat - "unix-connect:$work/away.tty" >/dev/null
                hears away "kithd: init: that does not open this node's state"
                ! grep -aqF 'state on' "$work/away.log" || fail "a machine away from its cluster opened its state without its passphrase"
                printf 'correct horse battery\n' | socat - "unix-connect:$work/away.tty" >/dev/null
                hears away 'kithd: init: opened with its passphrase'
                hears away 'kithd: init: state on /dev/dm-'
                ! grep -aqF 'correct horse' "$work/away.log" || fail "the machine's console showed the passphrase as it was typed"
                kill "$vm"
                wait "$vm" 2>/dev/null || true
                beta home ''
                up home
                # Locked again: it drops its passphrase, and the recovery key, typed at the
                # machine, opens it all the same.
                lock lock >/dev/null
                hears home 'its passphrase no longer opens its state'
                hears home 'kithd: the cluster has locked this node: restarting'
                wait "$vm" || true
                beta beta4 ''
                hears beta4 'Or type the recovery key here'
                hears beta4 'still locked'
                printf 'correct horse battery\n' | socat - "unix-connect:$work/beta4.tty" >/dev/null
                hears beta4 "kithd: init: that does not open this node's state"
                ! grep -aqF 'state on' "$work/beta4.log" || fail "a locked machine opened its state with the passphrase it had"
                printf '%s\n' "${recovery##* }" | socat - "unix-connect:$work/beta4.tty" >/dev/null
                hears beta4 'kithd: init: opened with the recovery key'
                up beta4
                pass '{"passphrase":"correct horse battery"}' | grep -qF 'unlock it first' || fail "a locked machine was given a passphrase"
                pass '{}' | grep -q '"passphrase": *false' || fail "a locked machine could not have its passphrase taken away"
                # Wiped: the cluster forgets the key, the machine erases its record and ends;
                # what is left on its disk opens for nobody.
                lock wipe | grep -q '"wiped": *true' || fail "the machine could not be wiped"
                hears beta4 'kithd: the cluster has wiped this node'
                wait "$vm" || true
                [ "$(says "$work/beta.disk")" = 'sealed none' ] || fail "the wiped machine's disk, read from outside: $(says "$work/beta.disk")"
                lock unlock | grep -qF 'was wiped' || fail "a wiped machine could be unlocked"
                beta beta5 ''
                hears beta5 "kithd: init: this node's lock record was erased"
                echo "vm.sh: ok: a machine installed with its state encrypted joined, and the node took its key to hold: the disk read from outside shows no file system and no key; started again it asked the node for its key; locked, it restarted and waited until unlocked; given a passphrase (through the node, which kept none of it) and started without its card, it opened its state once the passphrase was typed at it, and not for another; locked again, it dropped the passphrase, and the recovery key typed at it opened it; wiped, it erased its record and its disk opens for nobody; given an update while its key holder was off, it wrote it to slot b and tried slot b three times without its key, none of them marked good, and once its key holder was back it opened on slot a: slot b did not come up in 3 tries"
                exit 0
            fi
            echo "vm.sh: ok: a node told to install the machine with card $mac answered its network boot (beside the network's own DHCP server), served it the installer once over TFTP; the machine installed on its only disk, started from it and joined the node's cluster; netboot off again"
            exit 0
