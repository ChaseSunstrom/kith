# shellcheck shell=sh
# shellcheck disable=SC2034,SC2046,SC2086,SC2154 # (names the driver and its parts share; lists of words)
# Sourced by machines.sh for --test disk (which ci/vm/tests.sh sets up): it runs inside the
# driver's shell, with its variables and functions (machines.sh's: stick, blank, drive, lan, vm,
# hears, installed, fail); not a script to run alone.
#
# The second disk, as docs/adr-second-disk.md has it, through the verbs: one node made by the
# installer with its state encrypted (a data disk's key is kept in that state), a cluster of it
# claimed, and then, over TLS as the claimed Identity (what `kith node disk add`, `list` and
# `remove` send): a disk with a GPT on it is refused and left as it was, a disk file of 16 GiB
# (sparse) is added, mounted (its file system grown to the disk), listed, and mounted again at the
# next start from its header and the key in the state; removed, its header is zero and it is
# listed as nobody's. Another disk file, never named, is byte for byte what it was at the end.
# Every disk here is a file in this test's own directory, and the node is only a VM.
[ "$time" -gt 1800 ] || time=1800
known=kithknown0001 signed=kithsigned0001 unknown=kithother0001

# (Sparse: 16 GiB of a file that holds what is written. The unknown disk has bytes in it that
# are not zeros, at its start and its end; the signed one has the mark of a GPT at byte 512.)
truncate -s 16G "$work/known.raw"
truncate -s 256M "$work/other.raw"
dd if=/dev/urandom of="$work/other.raw" bs=1M count=4 conv=notrunc status=none
dd if=/dev/urandom of="$work/other.raw" bs=1M count=4 seek=252 conv=notrunc status=none
truncate -s 64M "$work/signed.raw"
printf 'EFI PART' | dd of="$work/signed.raw" bs=1 seek=512 conv=notrunc status=none
other_sum=$(sha256sum <"$work/other.raw")
signed_sum=$(sha256sum <"$work/signed.raw")
# (A serial is a property of the device, not of the drive: -device virtio-blk-pci.)
drives="-drive file=$work/known.raw,format=raw,if=none,id=known,discard=unmap -device virtio-blk-pci,drive=known,serial=$known"
drives="$drives -drive file=$work/signed.raw,format=raw,if=none,id=signed -device virtio-blk-pci,drive=signed,serial=$signed"
drives="$drives -drive file=$work/other.raw,format=raw,if=none,id=other -device virtio-blk-pci,drive=other,serial=$unknown"

field() { python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]], end="")' "$1"; }
forget() { # PID...: ended and waited for, taken out of $vms (the EXIT trap signals what is left)
    kept=''
    for p in $vms; do
        case " $* " in *" $p "*) ;; *) kept="$kept $p" ;; esac
    done
    vms=$kept
}
# The cluster's admin, to n1: METHOD PATH [FILE with JSON to send]. The status is in $code and the
# answer in $work/answer, whatever it is (a refusal is an answer; nothing at all fails the call).
call() {
    code=$(curl -s -o "$work/answer" -w '%{http_code}' --max-time 900 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
        --resolve "kith:$((port + 1)):127.0.0.1" -X "$1" ${3:+-H 'Content-Type: application/json' --data-binary "@$3"} \
        "https://kith:$((port + 1))$2")
}
# The disks listed (GET) and what is said of the one with serial $1: "known|unknown STATE [ID]".
listed() {
    call GET /v1/disks/n1 || fail "the disks could not be listed: no answer"
    [ "$code" = 200 ] || fail "the disks could not be listed ($code: $(cat "$work/answer"))"
}
of() {
    python3 -c '
import json, sys
found = json.load(open(sys.argv[1]))
for group in ("known", "unknown"):
    for d in found[group]:
        if "serial " + sys.argv[2] + ")" in d.get("disk", ""):
            print(group, d["state"], d.get("id", ""))
' "$work/answer" "$1"
}
# Node n1 from its disk, on the network the nodes share, with the disk files $drives (no TPM:
# its state is encrypted, and its key is on its disk beside the lock until another node holds it).
node() { # LOG
    monitor=unix:$work/$1.mon,server=on,wait=off
    vm "$1" -m 1024 $(drive n1.disk) $(lan 1) $drives
    monitor=
    n1=$vm
}
# The node asked to restart from its keyboard, as the machine's own tests do: it stops its
# services, closes what it opened, and the VM ends (-no-reboot).
stop_node() { # LOG
    echo sendkey ctrl-alt-delete | socat - "unix-connect:$work/$1.mon" >/dev/null
    wait "$n1" || fail "$1 did not end within ${time} s of being told to restart"
    forget "$n1"
    grep -aqF 'reboot: Restarting system' "$work/$1.log" || fail "kithd did not restart the machine ($1) when told"
    ! grep -aqE 'Kernel panic|EXT4-fs error|panicked at' "$work/$1.log" || fail "$1 panicked, or its file system was found broken"
    ! grep -aq 'kithd: the data disk .* is not closed' "$work/$1.log" || fail "a data disk was not closed when $1 restarted"
}

# The installer, on a blank disk, with the state encrypted; and no data disk yet, so none to choose.
printf 'disk: only\nhostname: n1\nip: 10.9.0.1/24\nencrypt: true\n' >"$work/n1.yaml"
stick n1 "$work/n1.yaml"
blank n1
vm install-n1 -m 1024 $(drive n1.stick) $(drive n1.disk)
installed install-n1 vdb
grep -aqF 'shown this once:' "$work/install-n1.log" || fail "the installer showed no recovery key for n1"

# The node, with the three disk files beside its own; its cluster claimed by the token it prints.
node n1
hears n1 'sends this token to /v1/claim does: kith1.'
token=$(grep -ao 'sends this token to /v1/claim does: kith1\.[0-9a-f.]*' "$work/n1.log")
end=$(($(date +%s) + time))
until claimed=$(curl -sfk --max-time 10 -H 'Content-Type: application/json' -d "{\"token\":\"${token##* }\",\"name\":\"root\"}" "https://127.0.0.1:$((port + 1))/v1/claim"); do
    [ "$(date +%s)" -lt "$end" ] || fail "n1's cluster could not be claimed"
    sleep 0.2
done
for part in ca cert key; do
    printf '%s' "$claimed" | (umask 077 && field "$part" >"$work/$part.pem") || fail "the claim was refused: $claimed"
done
hears n1 'kithd: data disks: known: none; unknown: '
said_line=$(grep -ao 'kithd: data disks: .*' "$work/n1.log" | tail -n 1)
for serial in $known $signed $unknown; do
    case $said_line in *"serial $serial"*) ;; *) fail "the start did not list the disk file with serial $serial: $said_line" ;; esac
done
case $said_line in *mounted*) fail "a disk nobody added was mounted at the start: $said_line" ;; esac

# Listed, then asked for what is wrong: a disk with a GPT (refused, left as it was, and the answer
# says what it holds and the way past it), a serial no disk has, and another node's name.
listed
[ "$(of "$known")" = "unknown not ours " ] || fail "the disk file to be added is not listed as nobody's: $(of "$known")"
[ "$(of "$signed")" = "unknown not ours " ] || fail "the disk file with a GPT is not listed as nobody's: $(of "$signed")"
printf '{"serial":"%s","quick":true}' "$signed" >"$work/add-signed.json"
call POST /v1/disks/n1 "$work/add-signed.json" || fail "no answer to adding the disk with a GPT"
[ "$code" = 409 ] || fail "the disk with a GPT was not refused ($code: $(cat "$work/answer"))"
grep -aqF 'a GPT' "$work/answer" || fail "the refusal does not say what the disk holds: $(cat "$work/answer")"
grep -aqF -- '--wipe' "$work/answer" || fail "the refusal does not say how to go past it: $(cat "$work/answer")"
[ "$(sha256sum <"$work/signed.raw")" = "$signed_sum" ] || fail "the refused disk was written to"
printf '{"serial":"nobody","quick":true}' >"$work/add-nobody.json"
call POST /v1/disks/n1 "$work/add-nobody.json" || fail "no answer to adding a disk no one has"
[ "$code" = 409 ] || fail "a serial no disk has was not refused ($code: $(cat "$work/answer"))"
call POST /v1/disks/n2 "$work/add-nobody.json" || fail "no answer to adding to another node"
[ "$code" = 409 ] || fail "a node that is not this one was not refused ($code: $(cat "$work/answer"))"
[ "$(sha256sum <"$work/other.raw")" = "$other_sum" ] || fail "the disk nobody named was written to"

# The add: the file's 16 GiB are the disk's, its header is on it, it is mounted, and it holds
# what it was given (sparse still: the quick add writes the header and the file system's start).
printf '{"serial":"%s","quick":true}' "$known" >"$work/add-known.json"
call POST /v1/disks/n1 "$work/add-known.json" || fail "no answer to adding the disk"
[ "$code" = 200 ] || fail "the disk was not added ($code: $(cat "$work/answer"))"
id=$(field id <"$work/answer")
[ "${#id}" = 32 ] || fail "the add gave no id: $(cat "$work/answer")"
grep -aqE '"mounted": *true' "$work/answer" || fail "the disk added was not mounted: $(cat "$work/answer")"
[ "$(head -c 12 "$work/known.raw")" = 'kith-disk v1' ] || fail "the disk has no kith-disk header after the add"
[ "$(stat -c %s "$work/known.raw")" = $((16 << 30)) ] || fail "the disk file is not 16 GiB any more"
[ $(($(stat -c %b "$work/known.raw") * 512)) -lt $((2 << 30)) ] || fail "the quick add wrote over 2 GiB of a 16 GiB disk"
listed
[ "$(of "$known")" = "known mounted $id" ] || fail "the added disk is not listed as mounted: $(of "$known")"
call POST /v1/disks/n1 "$work/add-known.json" || fail "no answer to adding the disk twice"
[ "$code" = 409 ] || fail "the disk was added a second time ($code: $(cat "$work/answer"))"
# Each verb left its entry in the audit log (who, what, and whether it was done).
call GET '/v1/audit?tail=100' || fail "the audit log could not be read"
[ "$code" = 200 ] || fail "the audit log could not be read ($code)"
grep -aqF 'disk add --quick' "$work/answer" || fail "the add left no entry in the audit log: $(cat "$work/answer")"
grep -aqF "Disk/$id" "$work/answer" || fail "the audit log does not name the disk added"

# Restarted: nobody asks again; the scan at start finds the header and the key and mounts it.
stop_node n1
node n1b
hears n1b 'kithd: init: state on /dev/dm-'
hears n1b 'kithd: data disks: '
said_line=$(grep -ao 'kithd: data disks: .*' "$work/n1b.log" | tail -n 1)
case $said_line in *"serial $known"*mounted*) ;; *) fail "the added disk was not mounted at the next start: $said_line" ;; esac
case $said_line in *"serial $unknown"*"left alone"*) ;; *) fail "the disk nobody added is not left alone at the next start: $said_line" ;; esac
end=$(($(date +%s) + time))
until call GET /v1/disks/n1 && [ "$code" = 200 ]; do
    [ "$(date +%s)" -lt "$end" ] || fail "n1 did not answer after the restart"
    sleep 1
done
[ "$(of "$known")" = "known mounted $id" ] || fail "the disk is not listed as mounted after the restart: $(of "$known")"

# The remove: unmounted, its mapping gone, its header zero, its key forgotten; nobody's again.
call DELETE "/v1/disks/n1/$id" || fail "no answer to removing the disk"
[ "$code" = 200 ] || fail "the disk was not removed ($code: $(cat "$work/answer"))"
cmp -s -n 4096 "$work/known.raw" /dev/zero || fail "the removed disk's header is not zero"
listed
[ "$(of "$known")" = "unknown not ours " ] || fail "the removed disk is not listed as nobody's: $(of "$known")"
call DELETE "/v1/disks/n1/$id" || fail "no answer to removing the disk twice"
[ "$code" = 409 ] || fail "a disk removed was removed a second time ($code: $(cat "$work/answer"))"
call GET '/v1/audit?tail=100' || fail "the audit log could not be read"
grep -aqF 'disk remove' "$work/answer" || fail "the remove left no entry in the audit log"
stop_node n1b
node n1c
hears n1c 'kithd: data disks: known: none; unknown: '
stop_node n1c
[ "$(sha256sum <"$work/other.raw")" = "$other_sum" ] || fail "the disk nobody named was written to"
[ "$(sha256sum <"$work/signed.raw")" = "$signed_sum" ] || fail "the disk with a GPT was written to"
echo "vm.sh: ok: a node with its state encrypted: a disk file with a GPT refused and left alone, one of 16 GiB (sparse) added by the verb, mounted, listed and audited, mounted again at the next start from its header and key, removed with its header zero and nobody's again, and the disk file nobody named kept byte for byte"
exit 0
