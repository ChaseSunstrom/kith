# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test fido2 (through tests.sh): it runs inside the driver's shell,
# with its variables and functions; not a script to run alone.
#
# The client of kithd against the software security key (docs/adr-fido2.md section 2, T-0973),
# through the kernel's real HID layer: uhid, then hidraw. The image is the fido2-test one (a
# kithd built with the cargo feature fido2-test, a kernel with CONFIG_UHID; tests.sh builds it
# into target/os-fido2 and no other test has either). Booted with the bare word `fido2-test`, that
# kithd makes three stand-in keys on /dev/uhid in turn, runs makeCredential and getAssertion
# on each with a known salt (bytes 0 to 31) and prints the credential id and the hmac-secret.
# This script computes the secret again outside Rust, from the seed alone:
#   hmac-secret = HMAC-SHA256(HMAC-SHA256(seed byte x 32, credential id), salt)
# and checks: seed 1's and seed 2's secrets are what their seeds say and are not each other's;
# seed 3 has its touch withheld first (the client gives up, no credential is made) and then given
# (its secret is what its seed says). Seed 1's key lists PIN/UV auth protocol 1 only, seed 2's
# protocol 2 only, seed 3's both (the client takes 2): both protocols run. A disk file only: the machine's disk is a copy of the image.
# It never touches a real key or disk.
    [ "$time" -gt 180 ] || time=180
    cp "$osdir/kith-os.raw" "$work/disk.raw"
    more='fido2-test' once=1
    boot
    wait "$vm" || fail "the VM did not power off within ${time} s of starting"
    # The kernel prints on the same serial line as kithd, and a kernel message can land in the middle of
    # one of kithd's lines (a key's hidraw node appears while the line of the one before is written):
    # clean has no kernel message, its text cut out with its newline, so kithd's line is whole again.
    python3 -I -c '
import re, sys
text = open(sys.argv[1], "rb").read().decode("latin-1").replace("\r", "")
open(sys.argv[2], "w").write(re.sub(r"\[ *[0-9]+\.[0-9]{6}\][^\n]*\n", "", text))' "$work/log" "$work/clean"
    said_clean() { grep -aq -- "$1" "$work/clean"; }
    said 'built with fido2-test: ' || fail "the fido2-test kithd did not say, at its start, that it is one"
    ! said_clean 'kithd: fido2-test: FAIL' || fail "the client or the stand-in failed in the VM"
    ! said_clean 'kithd: init: started again' || fail "kithd was started again (it died and the keeper restarted it)"
    said_clean 'kithd: fido2-test: done' || fail "the fido2-test run did not reach its end"
    said_clean 'kithd: init: powering off' || fail "kithd did not power the machine off when it was done"
    ! said 'Kernel panic' || fail "the kernel panicked"

    # What the log says of seed N: "credential ID secret S", the last one when there are two.
    said_of() { # N FIELD (credential or secret)
        grep -a "kithd: fido2-test: key $1: credential " "$work/clean" | tail -n 1 \
            | sed -E "s/.* $2 ([0-9a-f]+).*/\\1/"
    }
    # The same by the seed, with no Rust: the cipher of the stand-in is not the check.
    expect() { # SEED CREDENTIAL
        python3 -I -c '
import hashlib, hmac, sys
random = hmac.new(bytes([int(sys.argv[1])]) * 32, bytes.fromhex(sys.argv[2]), hashlib.sha256).digest()
print(hmac.new(random, bytes(range(32)), hashlib.sha256).hexdigest())' "$1" "$2"
    }
    for seed in 1 2 3; do
        cred=$(said_of "$seed" credential)
        got=$(said_of "$seed" secret)
        [ "${#cred}" -eq 64 ] || fail "key $seed: no credential id of 32 bytes in the log: '$cred'"
        [ "${#got}" -eq 64 ] || fail "key $seed: no hmac-secret of 32 bytes in the log: '$got'"
        [ "$got" = "$(expect "$seed" "$cred")" ] || fail "key $seed: the hmac-secret the client got is not what the seed says: $got"
        eval "secret$seed=\$got"
    done
    [ "$secret1" != "$secret2" ] || fail "two keys with two seeds gave the same hmac-secret"
    # Both PIN/UV auth protocols: the stand-in refuses one it does not list, so these secrets are proof.
    said_clean 'kithd: fido2-test: key 1 lists pinUvAuthProtocols \[1\]$' || fail "key 1 did not list protocol 1 alone"
    said_clean 'kithd: fido2-test: key 2 lists pinUvAuthProtocols \[2\]$' || fail "key 2 did not list protocol 2 alone"
    said_clean 'kithd: fido2-test: key 3 lists pinUvAuthProtocols \[1, 2\]$' || fail "key 3 did not list both protocols"
    # Seed 3: the withheld touch was given up on, before the credential that came with the touch.
    log=$(cat "$work/clean")
    gave=$(printf '%s\n' "$log" | grep -an 'kithd: fido2-test: key 3: touch withheld: gave up' | head -n 1 | cut -d: -f1)
    made=$(printf '%s\n' "$log" | grep -an 'kithd: fido2-test: key 3: credential ' | head -n 1 | cut -d: -f1)
    # The key must have been alive and waiting (UPNEEDED) before the client gave up: a dead key times out too.
    told=$(printf '%s\n' "$log" | grep -an 'kithd: fido2-test: the key sends UPNEEDED' | head -n 1 | cut -d: -f1)
    [ -n "$gave" ] || fail "key 3: its touch was withheld and the client did not give up"
    [ -n "$told" ] || fail "key 3: the key never sent UPNEEDED"
    [ "$told" -lt "$gave" ] || fail "key 3: the client gave up with no UPNEEDED from the key before (a dead key, not a waiting one)"
    [ -n "$made" ] || fail "key 3: no credential was made once the touch was given"
    [ "$gave" -lt "$made" ] || fail "key 3: a credential was made before the touch (line $made, gave up at $gave)"
    echo "vm.sh: ok: the client, through uhid and hidraw, got the hmac-secret each seed says it must be (key 1 ${secret1%"${secret1#????????}"}..., key 2 ${secret2%"${secret2#????????}"}...), the two differ, and a withheld touch timed out where a given one was answered"
    exit 0
