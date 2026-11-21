# shellcheck shell=sh
# shellcheck disable=SC1091,SC2034,SC2154 # (names the driver and its parts share)
# shellcheck disable=SC2016 # (as the script had them before it was cut)
# Sourced by ci/vm.sh for --test install, vps, netboot, crypt, blackout and alone: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
        for tool in curl python3 cpio ${sealing:+swtpm}; do
            command -v "$tool" >/dev/null 2>&1 || skip "no $tool"
        done
        # (mcopy puts the answers on the stick; where it is missing nix has it, as for os/build.sh.)
        if ! command -v mcopy >/dev/null 2>&1; then
            command -v nix >/dev/null 2>&1 || skip "no mcopy (mtools)"
            mcopy() { nix shell nixpkgs#mtools -c mcopy "$@"; }
        fi
        [ "$time" -gt 60 ] || time=300
        port=$((20000 + $$ % 20000))
        fail() {
            for log in "$work"/*.log; do echo "== $log"; tail -n 25 "$log"; done
            echo "vm.sh: FAIL: $1" >&2
            exit 1
        }
        installer=$root/target/os/kith-os-installer.raw
        # (Where its ESP starts: the first partition in its table.)
        esp=$(python3 -c 'import struct, sys; f = open(sys.argv[1], "rb"); f.seek(512 + 72); f.seek(struct.unpack("<Q", f.read(8))[0] * 512 + 32); print(struct.unpack("<Q", f.read(8))[0] * 512)' "$installer")
        # Every disk here is a file in this test's own directory: the installer is only
        # ever started in a VM, with those attached.
        stick() { # NAME [ANSWERS]: a copy of the installer, with answers on its ESP
            cp "$installer" "$work/$1.stick"
            [ -z "${2:-}" ] || mcopy -i "$work/$1.stick@@$esp" "$2" ::kith-install.yaml
        }
        blank() { truncate -s 2G "$work/$1.disk"; }
        drive() { echo "-drive file=$work/$1,format=raw,if=virtio"; }
        lan() { # N: a card on the network the nodes share, and one out to this machine
            echo "-netdev socket,id=lan,mcast=230.0.0.1:$((port + 8)),localaddr=127.0.0.1 -device virtio-net-pci,netdev=lan,mac=52:54:00:00:09:0$1" \
                "-netdev user,id=out,hostfwd=tcp:127.0.0.1:$((port + $1))-:7443${net_restrict-,restrict=on} -device virtio-net-pci,netdev=out,mac=52:54:00:00:0a:0$1"
        }
        vm() { # NAME [QEMU's arguments]: a machine whose serial console is logged and can be typed at
            name=$1
            shift
            timeout --foreground "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -display none -no-reboot \
                -machine q35 -bios "$firmware" "$@" \
                -chardev "socket,id=tty,path=$work/$name.tty,server=on,wait=off,logfile=$work/$name.log" -serial chardev:tty \
                -monitor "${monitor:-none}" </dev/null >/dev/null 2>&1 8>&- &
            vm=$!
            vms="$vms $vm"
        }
        hears() { # NAME TEXT
            waited=0
            until grep -aqF -- "$2" "$work/$1.log" 2>/dev/null; do
                waited=$((waited + 1))
                [ "$waited" -lt $((time * 5)) ] || fail "$1 never said: $2"
                sleep 0.2
            done
        }
        installed() { # NAME DISK: the installer said so and powered the machine off
            wait "$vm" || fail "$1 did not end by itself"
            grep -aqF "kithd: install: kith OS is on $2" "$work/$1.log" || fail "$1 did not install on $2"
            grep -aqF 'kithd: init: powering off' "$work/$1.log" || fail "$1 did not power off"
        }
        print() { # PORT: who answers TLS there, into $who
            tries=0
            until openssl s_client -connect "127.0.0.1:$1" </dev/null 2>/dev/null >"$work/hello" \
                && who=$(openssl x509 -noout -fingerprint -sha256 <"$work/hello" 2>/dev/null); do
                tries=$((tries + 1))
                [ "$tries" -lt 100 ] || fail "nobody answered TLS on port $1"
                sleep 0.2
            done
        }

        # A screendump of machine NAME's framebuffer (its monitor socket is $work/NAME.mon), asked
        # for until it is WHAT, and held to be the install as drawn (T-1083): "mid", the disk
        # written part of the way (the bar has some of its length filled and some not), or "end",
        # the install done (nothing in the accent: no stop or bar under way), "ask", a question
        # asked (T-0734), or "key", the recovery key's screen (T-1172). Whichever, every
        # pixel is a colour of docs/site.css's tokens: no kernel text (white or grey on black)
        # is on the picture. It stops asking when the machine's log says GIVE-UP.
        shot() { # NAME WHAT GIVE-UP
            python3 -I -c '
import collections, re, socket, sys, time
mon, ppm, css, what, log, giveup, limit = sys.argv[1:8]
block = open(css).read()
block = block[block.index(":root {"):]
block = block[: block.index("}")]
tokens = {n: bytes(int(h[i : i + 2], 16) for i in (0, 2, 4)) for n, h in re.findall(r"--([\w-]+):\s*#([0-9a-fA-F]{6})", block)}
paper, text, hair, accent = (tokens[n] for n in ("bg", "text", "hair", "accent"))
end = time.time() + int(limit)
conn = None
def said():
    try:
        return giveup.encode() in open(log, "rb").read()
    except OSError:
        return False
def ioerr():
    raise OSError("monitor closed")
def ask():
    global conn
    if conn is None:
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(5)
        conn.connect(mon)
        seen = b""
        while seen.count(b"(qemu)") < 1:
            seen += conn.recv(4096) or ioerr()
    conn.sendall(("screendump " + ppm + "\n").encode())
    seen = b""
    while seen.count(b"(qemu)") < 1:
        seen += conn.recv(4096) or ioerr()
def shape():
    head = open(ppm, "rb").read().split(b"\n", 3)
    if head[0] != b"P6":
        return None
    width, height = map(int, head[1].split())
    pixels = head[3]
    colours = collections.Counter(zip(pixels[0::3], pixels[1::3], pixels[2::3]))
    rows = [pixels[y * width * 3 : (y + 1) * width * 3] for y in range(height)]
    return colours, rows
while time.time() < end:
    try:
        ask()
        got = shape()
    except (OSError, ValueError):
        conn = None
        got = None
    if got:
        colours, rows = got
        if what == "mid":
            now = any(r.count(accent) >= 64 and r.count(hair) >= 64 for r in rows)
        elif what in ("ask", "key"):
            # (A question or the key on the framebuffer: mostly paper, the accent on the current
            # stop (a few hundred pixels). The key is told from a bar by no row of the accent.)
            now = colours.most_common(1)[0][0] == tuple(paper) and colours[tuple(accent)] >= 100
            now = now and (what == "ask" or not any(r.count(accent) >= 64 for r in rows))
        else:
            now = colours[tuple(accent)] == 0 and colours[tuple(text)] >= 200 and colours.most_common(1)[0][0] == tuple(paper)
        if now:
            known = {tuple(v) for v in tokens.values()}
            odd = {c: n for c, n in colours.items() if c not in known}
            if odd:
                print("the picture has colours the site has no token for (kernel text?):", sorted(odd.items(), key=lambda c: -c[1])[:5])
                sys.exit(2)
            sys.exit(0)
    if said():
        break
    time.sleep(0.05)
print("never saw the", what, "picture")
sys.exit(1)
' "$work/$1.mon" "$work/$1-$2.ppm" "$root/docs/site.css" "$2" "$work/$1.log" "$3" "$time" || fail "$1's screen is not the install as drawn ($2)"
            [ -z "${KITH_VM_LOGS:-}" ] || cp "$work/$1-$2.ppm" "$KITH_VM_LOGS/" 2>/dev/null || true
        }

        if [ "$test" = vps ]; then
            . "$root/ci/vm/vps.sh"
        fi

        if [ "$test" = blackout ]; then
            . "$root/ci/vm/blackout.sh"
        fi

        if [ "$test" = alone ]; then
            . "$root/ci/vm/alone.sh"
        fi

        if [ "$test" = netboot ] || [ "$test" = crypt ]; then
            . "$root/ci/vm/netboot.sh"
        fi

        # A machine with no disk but the installer's own: nothing to install on, and said.
        printf 'disk: only\nhostname: alpha\nip: 10.9.0.1/24\n' >"$work/alpha.yaml"
        stick alpha "$work/alpha.yaml"
        # shellcheck disable=SC2046
        vm nodisk $(drive alpha.stick)
        hears nodisk 'kithd: install: nothing was installed: this machine has no disk to install on'
        kill "$vm"

        # Answers on the stick: the only disk, a name, a fixed address, a new cluster.
        blank alpha
        # (The picture is drawn whatever the answers' source: the disk written part of the way,
        # then the end screen, both as the site draws them, with no kernel text on them.)
        monitor=unix:$work/install-alpha.mon,server=on,wait=off
        # shellcheck disable=SC2046
        vm install-alpha $(drive alpha.stick) $(drive alpha.disk)
        monitor=
        shot install-alpha mid 'kithd: install: kith OS is on'
        shot install-alpha end 'kithd: init: powering off'
        installed install-alpha vdb
        # A machine whose disk already has kith OS, that disk before the stick (vda), the firmware
        # told to start the stick: the kernel takes the first partition with a label, so the
        # installer's root has its own (install-root), not the disk's root-a; it starts from the
        # stick and installs on that disk (T-1064).
        cp "$work/alpha.disk" "$work/old.disk"
        vm reinstall -drive "file=$work/old.disk,format=raw,if=none,id=old" -device virtio-blk-pci,drive=old,bootindex=1 \
            -drive "file=$work/alpha.stick,format=raw,if=none,id=stick" -device virtio-blk-pci,drive=stick,bootindex=0
        installed reinstall vda
        rm -f "$work/old.disk"
        # shellcheck disable=SC2046
        vm alpha $(drive alpha.disk) $(lan 1)
        hears alpha 'kithd: init: alpha is up'
        hears alpha 'has 10.9.0.1/24'
        hears alpha 'kithd: node alpha serving other nodes on 0.0.0.0:7443'
        hears alpha 'sends this token to /v1/claim does: kith1.'
        token=$(grep -ao 'sends this token to /v1/claim does: kith1\.[0-9a-f.]*' "$work/alpha.log")
        # (Its first listen is as slow as the host is loaded, so the claim waits for as long as the
        # test's time, as hears() does; a count of tries would give about ten seconds on a busy host.)
        end=$(($(date +%s) + time))
        until claimed=$(curl -sfk --max-time 10 -H 'Content-Type: application/json' -d "{\"token\":\"${token##* }\",\"name\":\"root\"}" "https://127.0.0.1:$((port + 1))/v1/claim"); do
            [ "$(date +%s)" -lt "$end" ] || fail "the installed node's cluster could not be claimed"
            sleep 0.2
        done
        field() { python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]], end="")' "$1"; }
        for part in ca cert key; do
            printf '%s' "$claimed" | (umask 077 && field "$part" >"$work/$part.pem") || fail "the claim was refused: $claimed"
        done
        api() { # METHOD PATH: as the cluster's admin, to alpha
            curl -sf --max-time 10 --cacert "$work/ca.pem" --cert "$work/cert.pem" --key "$work/key.pem" \
                --resolve "kith:$((port + 1)):127.0.0.1" -X "$1" "https://kith:$((port + 1))$2"
        }
        join=$(api POST /v1/tokens | field token) || fail "no join token over TLS"

        # Answers from a URL: the disk by its serial where there are two (on a SCSI
        # controller, where the kernel's names are in the order the disks answer), and the
        # network asked for an address. The other disk is not touched.
        mkdir "$work/www"
        printf 'disk: serial:kith-beta\nhostname: beta\n' >"$work/www/beta.yaml"
        # (Over plain http the answers are taken only with their hash pinned in the URL.)
        pin=$(sha256sum "$work/www/beta.yaml" | cut -d' ' -f1)
        web_up "$work/www" $((port + 9)) || fail "the web server on port $((port + 9)) did not start"
        stick beta
        blank beta
        blank spare
        # shellcheck disable=SC2046
        vm install-beta $(drive beta.stick) -device virtio-scsi-pci,id=scsi \
            -drive "file=$work/spare.disk,format=raw,if=none,id=spare" -device scsi-hd,drive=spare,serial=kith-spare \
            -drive "file=$work/beta.disk,format=raw,if=none,id=beta" -device scsi-hd,drive=beta,serial=kith-beta \
            -netdev "user,id=out,guestfwd=tcp:10.0.2.100:80-cmd:socat - TCP:127.0.0.1:$((port + 9))${net_restrict-,restrict=on}" -device virtio-net-pci,netdev=out \
            -smbios "type=11,value=io.systemd.stub.kernel-cmdline-extra=kith.install=http://10.0.2.100/beta.yaml#sha256=$pin"
        installed install-beta sd
        grep -aq 'kith OS is on sd[a-z] (.*serial kith-beta)' "$work/install-beta.log" || fail "install-beta did not install on the disk with serial kith-beta"
        cmp -s -n $((64 << 20)) "$work/spare.disk" /dev/zero || fail "the disk that was not chosen was written to"
        beta() { # LOG: the installed disk, started
            # shellcheck disable=SC2046
            vm "$1" $(drive beta.disk) -netdev "user,id=out,hostfwd=tcp:127.0.0.1:$((port + 5))-:7443${net_restrict-,restrict=on}" -device virtio-net-pci,netdev=out
            hears "$1" 'kithd: init: beta is up'
            hears "$1" 'kithd: node beta serving other nodes on 0.0.0.0:7443'
            print $((port + 5))
        }
        beta beta
        first=$who
        kill "$vm"
        wait "$vm" 2>/dev/null || true
        beta beta-again
        [ "$first" = "$who" ] || fail "the installed node is another node after a restart: its state was not kept"
        kill "$vm"

        # Answers typed at the console: a slip first (the disk's name not typed the same
        # twice, so nothing is written), then a node that joins alpha's cluster by token.
        stick gamma
        blank gamma
        # (A monitor socket, for the screendump below; the other machines have none.)
        monitor=unix:$work/install-gamma.mon,server=on,wait=off
        # shellcheck disable=SC2046
        vm install-gamma $(drive gamma.stick) $(drive gamma.disk)
        monitor=
        typed() { # WAIT-FOR LINE
            hears install-gamma "$1"
            printf '%s\n' "$2" | socat - "unix-connect:$work/install-gamma.tty" >/dev/null
        }
        # The picture while the disk question is asked: the console's framebuffer (kithd draws
        # the question on it) is mostly paper, with the accent on the current stop. Retried, as
        # the picture is drawn just after the question's text is on the serial console.
        hears install-gamma 'Install kith OS on which'
        shot install-gamma ask "The node's name"
        typed 'Install kith OS on which' vdb
        typed "The node's name" gamma
        typed 'Its address, as' ''
        typed 'Join a cluster?' ''
        typed 'Keep its state encrypted' ''
        typed 'will be erased. Type its name again' vda
        hears install-gamma 'kithd: install: `vda` is not `vdb`: nothing was written'
        cmp -s -n $((64 << 20)) "$work/gamma.disk" /dev/zero || fail "a disk was written to before its name was typed twice"
        hears install-gamma 'kithd: install: once more.'
        for line in vdb gamma 10.9.0.3/24 10.9.0.1:7443 "$join" '' vdb; do
            printf '%s\n' "$line" | socat - "unix-connect:$work/install-gamma.tty" >/dev/null
            sleep 0.3
        done
        installed install-gamma vdb
        # shellcheck disable=SC2046
        vm gamma $(drive gamma.disk) $(lan 3)
        hears gamma 'kithd: init: gamma is up'
        tries=0
        until api GET /v1/resources/Node/gamma >/dev/null; do
            tries=$((tries + 1))
            [ "$tries" -lt 150 ] || fail "the node installed with a join token is not in alpha's cluster"
            sleep 0.2
        done
        # Answers typed at the console, the state asked to be encrypted (T-1172): the recovery key
        # is on the screen as well as the log, held (still there after a few seconds) until a key
        # is pressed, and gone then (the end screen, with nothing of the accent, takes its place).
        stick delta
        blank delta
        monitor=unix:$work/install-delta.mon,server=on,wait=off
        # shellcheck disable=SC2046
        vm install-delta $(drive delta.stick) $(drive delta.disk)
        monitor=
        hears install-delta 'Install kith OS on which'
        for line in vdb delta '' '' yes vdb; do
            printf '%s\n' "$line" | socat - "unix-connect:$work/install-delta.tty" >/dev/null
            sleep 0.3
        done
        hears install-delta 'kithd: install: the node'"'"'s state is encrypted'
        shot install-delta key 'kithd: install: kith OS is on'
        sleep 3
        shot install-delta key 'kithd: install: kith OS is on'
        ! grep -aqF 'kithd: install: kith OS is on' "$work/install-delta.log" || fail "the installer went on before a key was pressed"
        printf '\n' | socat - "unix-connect:$work/install-delta.tty" >/dev/null
        shot install-delta end 'kithd: init: powering off'
        installed install-delta vdb
        echo "vm.sh: ok: no disk, nothing installed; from answers on the stick, a node (alpha) that starts a cluster at its fixed address; from a URL, onto the one of two disks its serial names, a node (beta, $first) that asks its network and keeps its state; from the console, after a slip that wrote nothing, a node (gamma) that joined alpha's cluster by token, and one (delta) with its state encrypted whose recovery key's screen was held until a key and gone after it"
        exit 0
