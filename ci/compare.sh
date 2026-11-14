#!/bin/sh
# kith beside k3s: the same machines, started as one and then as the other, and measured
# the same way from this machine.
#
#   sh ci/compare.sh                    both, three runs each, and one run each with the wait
#                                       for a lost node set to about a minute; writes
#                                       ci/compare.txt (the table README.md carries)
#   sh ci/compare.sh --only kith        one system (kith or k3s); rows are added to what
#     [--runs N] [--lost SECONDS]       was measured before (target/compare.raw)
#   sh ci/compare.sh --table            ci/compare.txt again, from the rows there are
#
# A run is three QEMU machines (KVM, 2 CPUs, 2048 MB, a network of their own): three kith OS
# nodes, or Alpine with k3s as it comes (a server and two agents). On each it measures:
#
#   memory   MemTotal - MemAvailable of a node, read from /proc/meminfo by one small
#            container on every node (a NodeWorkload, a DaemonSet), three minutes after
#            all of them run: on the node that was first (kith) or the server (k3s), and
#            the mean of the other two
#   apply    from sending a one-replica workload until the system says its container
#            is ready, the image being on the node already; the middle of five
#   lost     a machine that runs a replica is killed (as if its power went): until the
#            replica is ready on another node
#   boot     kith only: from starting the first machine until kithd answers on its port
#
# k3s and Alpine's image are fetched once into ~/.cache/kith-compare and checked against
# the hashes below; the nodes pull one image (busybox) from mirror.gcr.io. Exit 77: this
# machine cannot run it (no KVM, no QEMU, ...).
#
# ponytail: one machine shape, one workload, three runs: enough to say which is bigger
# and by about how much, not a benchmark. Throughput and scale when someone needs them.
set -eu

k3s_version=v1.37.2+k3s1
k3s_sha256=265b3ee6a3198ef14033c63ef46cbb32370d83795199fb6d1b01f21575eddbda
k3s_images_sha256=35a5af1e69b57b8b627a4f6b1c29ea104209b661067b8c97fd40dc3f860bfcd2
alpine=generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2
alpine_sha512=8d756f6fc7653daa4fb4e2e213d8a66007bcb1e5a846e28891af62c47b90685c694486c2746099ad99e9e8f5278db76b69d11dfe1e9361aa4c8406df16929a9c
image=mirror.gcr.io/library/busybox:1.36

runs=3 only='' lost='' table=''
mem=${KITH_COMPARE_MEM:-2048} settle=${KITH_COMPARE_SETTLE:-180} time=3000
while [ $# -gt 0 ]; do
    case $1 in
    --runs | --only | --lost)
        [ $# -ge 2 ] || { echo "compare.sh: $1 needs a value" >&2; exit 2; }
        case $1 in --runs) runs=$2 ;; --only) only=$2 ;; --lost) lost=$2 ;; esac
        shift 2
        ;;
    --table) table=1; shift ;;
    *) sed -n '2,11p' "$0" >&2; exit 2 ;;
    esac
done
case $only in '' | kith | k3s) ;; *) echo "compare.sh: --only kith or --only k3s" >&2; exit 2 ;; esac
case $runs in '' | 0* | *[!0-9]*) echo "compare.sh: --runs takes a number, 1 or more" >&2; exit 2 ;; esac
# (Under 51 s there is nothing left for k3s's pods to tolerate: it waits 50 by itself.)
case $lost in '') ;; *[!0-9]*) echo "compare.sh: --lost takes seconds" >&2; exit 2 ;; *) [ "$lost" -ge 51 ] || { echo "compare.sh: --lost takes 51 s or more" >&2; exit 2; } ;; esac

root=$(cd "$(dirname "$0")/.." && pwd)
raw=$root/target/compare.raw
cache=${XDG_CACHE_HOME:-$HOME/.cache}/kith-compare
skip() { echo "compare.sh: skipped: $1" >&2; exit 77; }

# The table: for each system the middle run of each number, and how far the runs lay apart.
table() {
    python3 - "$raw" "$k3s_version" "${alpine%-r0.qcow2}" "$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -n 1)" "$mem" "$image" <<'EOF'
import statistics, sys
raw, k3s, alpine, kith, mem, image = sys.argv[1:]
rows = {}
for line in open(raw):
    system, setting, *numbers = line.split()
    rows.setdefault((system, setting), []).append(dict(n.split("=") for n in numbers))
def cell(system, setting, what, unit, digits):
    found = [float(r[what]) for r in rows.get((system, setting), []) if r.get(what, "-") != "-"]
    if not found:
        return "not measured"
    said = lambda n: f"{n:.{digits}f}"
    middle = f"{said(statistics.median(found))} {unit}"
    return middle if len(found) == 1 else f"{middle} ({said(min(found))} to {said(max(found))}, {len(found)} runs)"
tuned = sorted({setting for _, setting in rows if setting != "default"})
lines = [
    ("Memory in use on an idle node: the first node / the server", "default", "control", "MB", 0),
    ("Memory in use on an idle node: another node / an agent", "default", "worker", "MB", 0),
    ("From apply to a ready container, its image on the node", "default", "apply", "s", 2),
    ("A node lost: until its replica is ready on another, as each system comes", "default", "lost", "s", 0),
] + [(f"The same, each told to wait about {setting} s", setting, "lost", "s", 0) for setting in tuned]
print(f"kith {kith} beside k3s {k3s} (on Alpine: {alpine}): three QEMU machines each (KVM, 2 CPUs, {mem} MB),")
print(f"one workload ({image}), measured by ci/compare.sh. The middle run, and the lowest and highest.")
print()
print("| | kith | k3s |")
print("| --- | --- | --- |")
for name, setting, what, unit, digits in lines:
    print(f"| {name} | {cell('kith', setting, what, unit, digits)} | {cell('k3s', setting, what, unit, digits)} |")
before = cell("k3s", "default", "before", "MB", 0)
print()
print(f"Alpine alone, before k3s is started on it, has {before} in use; kith OS has no such moment (kithd is its first process).")
print(f"A kith OS machine answers on its API {cell('kith', 'default', 'boot', 's', 1)} after it is switched on (firmware included).")
print()
print("The runs (system, the wait for a lost node, then what was measured: MB, MB, s, s):")
print()
for line in open(raw):
    print("    " + line.strip())
EOF
}
if [ -n "$table" ]; then
    [ -s "$raw" ] || { echo "compare.sh: nothing measured yet ($raw)" >&2; exit 1; }
    table >"$root/ci/compare.txt"
    cat "$root/ci/compare.txt"
    exit 0
fi

for tool in qemu-system-x86_64 qemu-img curl python3 ssh ssh-keygen scp xorriso sha256sum sha512sum; do
    command -v "$tool" >/dev/null 2>&1 || skip "no $tool"
done
if ! [ -r /dev/kvm ] || ! [ -w /dev/kvm ]; then skip "no usable /dev/kvm"; fi
firmware=''
for f in /usr/share/edk2-ovmf/x64/OVMF.4m.fd /usr/share/edk2/x64/OVMF.4m.fd /usr/share/OVMF/OVMF.fd /usr/share/ovmf/OVMF.fd; do
    [ -r "$f" ] && { firmware=$f; break; }
done
[ -n "$firmware" ] || skip "no UEFI firmware (OVMF)"

work=$(mktemp -d)
vms=''
# (A signal ends the script, and ending it is what puts the machines and the files away.)
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'kill $vms 2>/dev/null || true; rm -rf "$work"' EXIT
port=$((20000 + $$ % 20000))
fail() { tail -n 20 "$work"/n?.log "$work"/n?.err 2>/dev/null; echo "compare.sh: FAIL: $1" >&2; exit 1; }
note() { echo "compare.sh: $1" >&2; }

# What is fetched, once, and what it must be.
fetched() { # FILE URL sha256sum|sha512sum HASH
    if ! [ -f "$cache/$1" ]; then
        mkdir -p "$cache"
        curl -fsSL --max-time 900 -o "$cache/$1.part" "$2" || skip "could not fetch $2"
        mv "$cache/$1.part" "$cache/$1"
    fi
    [ "$("$3" "$cache/$1" | cut -d ' ' -f 1)" = "$4" ] || fail "$cache/$1 is not the file this script names (remove it to fetch it again)"
}

# One request after another to a system's API as its admin, over one connection:
#   call METHOD PATH [FILE [CONTENT-TYPE]]   prints the answer
#   wait SECONDS PATH EXPRESSION             until EXPRESSION holds of the answer (`j`); prints how long it took
#   timed SECONDS PATH EXPRESSION METHOD PATH FILE   the same, counted from just before that request
cat >"$work/api.py" <<'EOF'
import http.client, json, os, socket, ssl, sys, time
port, name = int(os.environ["API_PORT"]), os.environ["API_NAME"]
context = ssl.create_default_context(cafile=os.environ["API_CA"])
context.load_cert_chain(os.environ["API_CERT"], os.environ["API_KEY"])
connection = None
def call(method, path, file=None, kind="application/json"):
    global connection
    try:
        if connection is None:
            connection = http.client.HTTPSConnection(name, port, timeout=10)
            plain = socket.create_connection(("127.0.0.1", port), 10)
            connection.sock = context.wrap_socket(plain, server_hostname=name)
        body = open(file, "rb").read() if file else None
        connection.request(method, path, body, {"Content-Type": kind} if file else {})
        answer = connection.getresponse()
        return answer.status, answer.read()
    except (OSError, http.client.HTTPException) as e:
        connection = None
        return 0, str(e).encode()
def wait(seconds, path, expression, begun):
    every = float(os.environ.get("API_EVERY", "0.02"))
    while time.monotonic() - begun < float(seconds):
        status, body = call("GET", path)
        try:
            # (The expressions are this script's own, a few lines below: nobody else's text is run.)
            if status == 200 and eval(expression, {"j": json.loads(body), "os": os}):
                print(f"{time.monotonic() - begun:.3f}")
                return
        except (ValueError, KeyError, TypeError, AttributeError):
            pass
        time.sleep(every)
    sys.exit(f"waited {seconds} s for {path}: {expression}; it says {status}: {body[:600]!r}")
what, rest = sys.argv[1], sys.argv[2:]
if what == "call":
    status, body = call(*rest)
    sys.stdout.write(body.decode(errors="replace"))
    sys.exit(0 if 200 <= status < 300 else f"{rest[0]} {rest[1]}: {status}")
begun = time.monotonic()
if what == "timed":
    status, body = call(*rest[3:])
    if not 200 <= status < 300:
        sys.exit(f"{rest[3]} {rest[4]}: {status}: {body[:600]!r}")
wait(rest[0], rest[1], rest[2], begun)
EOF
api() { python3 "$work/api.py" "$@"; }

# The machine both systems get; what differs is its disk and its firmware.
machine() { # N and the rest of QEMU's line
    it=$1
    shift
    timeout "$time" qemu-system-x86_64 -enable-kvm -cpu host -m "$mem" -smp 2 -display none -machine q35 "$@" \
        -serial "file:$work/n$it.log" -monitor none -pidfile "$work/n$it.pid" </dev/null >"$work/n$it.err" 2>&1 &
    vms="$vms $!"
}
# A machine's power goes: QEMU itself is killed (the pid above is of the timeout that minds it).
lose() { kill -9 "$(cat "$work/n$1.pid")" || fail "machine $1 could not be killed"; }
lan() { echo "-netdev socket,id=lan,mcast=230.0.0.1:$((port + 8)),localaddr=127.0.0.1 -device virtio-net-pci,netdev=lan,mac=52:54:00:00:09:0$1"; }
used() { awk '{ printf "%d", ($2 - $5) / 1024 }'; } # of "MemTotal: N kB MemAvailable: N kB"
loop='while :; do echo $(grep -E "^(MemTotal|MemAvailable):" /proc/meminfo); sleep 10; done'
middle() { sort -n >"$work/sorted" && sed -n "$((($(wc -l <"$work/sorted") + 1) / 2))p" "$work/sorted"; } # of the lines it is given
mean() { echo $((($1 + $2) / 2)); }

# ---- kith: three kith OS nodes -------------------------------------------------------
kith() { # the wait for a lost node, or nothing
    # (The image there is, unless a source is newer than it: what is measured is this tree.)
    os=$root/target/os/kith-os.raw
    if ! [ -f "$os" ] || [ -n "$(find "$root/crates" "$root/os" "$root/Cargo.lock" -type f -newer "$os" | head -n 1)" ]; then
        sh "$root/os/build.sh" >&2 || skip "this machine cannot build kith OS's image"
    fi
    more=${1:+--lost-after $1}
    node() { # N [kithd's further arguments]
        cp "$root/target/os/kith-os.raw" "$work/n$1.raw"
        # shellcheck disable=SC2046
        machine "$1" -bios "$firmware" -drive "file=$work/n$1.raw,format=raw,if=virtio" $(lan "$1") \
            -netdev "user,id=out,hostfwd=tcp:127.0.0.1:$((port + $1))-:7443" -device "virtio-net-pci,netdev=out,mac=52:54:00:00:0a:0$1" \
            -smbios "type=11,value=io.systemd.stub.kernel-cmdline-extra=kith.hostname=n$1 kith.ip=10.9.0.$1/24 -- --listen 0.0.0.0:7443 --advertise 10.9.0.$1:7443 $more ${2:-}"
    }
    field() { python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]], end="")' "$1"; }
    begun=$(date +%s.%N)
    node 1 --claim
    tries=0
    until token=$(grep -ao 'sends this token to /v1/claim does: kith1\.[0-9a-f.]*' "$work/n1.log" 2>/dev/null) && [ -n "$token" ] \
        && [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 -H 'Content-Type: application/json' -d '{"token":"x","name":"root"}' "https://127.0.0.1:$((port + 1))/v1/claim")" = 403 ]; do
        tries=$((tries + 1))
        [ "$tries" -lt 600 ] || fail "the first kith node offered no claim, or did not answer"
        sleep 0.2
    done
    # (From the machine's start, firmware included, until kithd answers on its port.)
    boot=$(echo "$(date +%s.%N) $begun" | awk '{ printf "%.1f", $1 - $2 }')
    claimed=$(curl -sk --max-time 10 -H 'Content-Type: application/json' -d "{\"token\":\"${token##* }\",\"name\":\"root\"}" "https://127.0.0.1:$((port + 1))/v1/claim")
    for part in ca cert key; do
        printf '%s' "$claimed" | (umask 077 && field "$part" >"$work/$part.pem") || fail "the claim was refused: $claimed"
    done
    export API_PORT=$((port + 1)) API_NAME=kith API_CA="$work/ca.pem" API_CERT="$work/cert.pem" API_KEY="$work/key.pem"
    for n in 2 3; do
        join=$(api call POST /v1/tokens | field token) || fail "no join token"
        node "$n" "--join 10.9.0.1:7443 --token $join"
    done
    ready='sum(1 for r in (j if isinstance(j, list) else j.get("resources", j.get("items", []))) if r["kind"] == "Node" and (r.get("status") or {}).get("state") == "ready") == 3'
    API_EVERY=1 api wait 600 /v1/resources "$ready" >/dev/null || fail "three kith nodes did not become ready"
    note "kith: three nodes"

    # The two that joined are where the workload that loses its node may run.
    for n in 2 3; do
        api call GET "/v1/resources/Node/n$n" | python3 -c '
import json, sys
node = json.load(sys.stdin)
node.pop("status", None)
node["metadata"].setdefault("labels", {})["role"] = "worker"
json.dump([node], sys.stdout)' >"$work/apply.json"
        api call POST /v1/apply "$work/apply.json" >/dev/null || fail "n$n was not labelled"
    done
    apply() { cat >"$work/apply.json" && api call POST /v1/apply "$work/apply.json" >/dev/null; }
    apply <<EOF || fail "the NodeWorkload was not applied"
[{"apiVersion":"kith.dev/v1","kind":"NodeWorkload","metadata":{"name":"mem"},"spec":{"template":{"containers":[
  {"name":"mem","image":"$image","command":["sh","-c","$(printf '%s' "$loop" | sed 's/"/\\"/g')"]}]}}}]
EOF
    API_EVERY=1 api wait 600 /v1/resources/NodeWorkload/default/mem '(j.get("status") or {}).get("ready") == 3' >/dev/null || fail "the memory readers did not all run"
    note "kith: a container on every node; idle for $settle s"
    sleep "$settle"
    api call GET /v1/resources/NodeWorkload/default/mem >"$work/mem.json"
    reads() { # NODE: what its container read last, in MB
        replica=$(python3 -c '
import json, sys
nodes = json.load(open(sys.argv[1]))["status"]["nodes"]
print(next(k if v == sys.argv[2] else v for k, v in nodes.items() if sys.argv[2] in (k, v)))' "$work/mem.json" "$1")
        api call GET "/v1/logs/NodeWorkload/default/mem?replica=$replica&tail=1" | field data | used
    }
    control=$(reads n1) worker=$(mean "$(reads n2)" "$(reads n3)")
    [ "$control" -gt 0 ] && [ "$worker" -gt 0 ] || fail "no memory was read: $control, $worker"

    : >"$work/applies"
    for i in 1 2 3 4 5; do
        cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"a$i"},"spec":{"template":{"containers":[
  {"name":"run","image":"$image","command":["sleep","3600"]}]}}}]
EOF
        api timed 300 "/v1/resources/Workload/default/a$i" '(j.get("status") or {}).get("ready") == 1' POST /v1/apply "$work/apply.json" >>"$work/applies" || fail "the workload a$i did not run"
        api call DELETE "/v1/resources/Workload/default/a$i" >/dev/null || fail "a$i was not deleted"
    done
    applied=$(middle <"$work/applies")

    apply <<EOF || fail "the workload to move was not applied"
[{"apiVersion":"kith.dev/v1","kind":"Workload","metadata":{"name":"move"},"spec":{"placement":{"require":{"node.labels.role":"worker"}},
  "template":{"containers":[{"name":"run","image":"$image","command":["sleep","36000"]}]}}}]
EOF
    api wait 300 /v1/resources/Workload/default/move '(j.get("status") or {}).get("ready") == 1' >/dev/null || fail "the workload to move did not run"
    on=$(api call GET /v1/resources/Workload/default/move | python3 -c 'import json, sys; print(*json.load(sys.stdin)["status"]["nodes"].values())')
    case $on in n2 | n3) ;; *) fail "the workload to move runs on '$on', not on one of the two it may" ;; esac
    lose "${on#n}"
    gone=$(LOST=$on API_EVERY=0.5 api wait 1200 /v1/resources/Workload/default/move \
        '(j["status"].get("ready") == 1) and os.environ["LOST"] not in j["status"]["nodes"].values()') || fail "the replica of the lost node $on ran nowhere else"
    echo "kith ${1:-default} control=$control worker=$worker apply=$applied lost=$gone boot=$boot" >>"$raw"
    note "kith: $(tail -n 1 "$raw")"
}

# ---- k3s: Alpine, a server and two agents ---------------------------------------------
k3s() { # the wait for a lost node, or nothing
    fetched k3s "https://github.com/k3s-io/k3s/releases/download/$(printf '%s' "$k3s_version" | sed 's/+/%2B/')/k3s" sha256sum "$k3s_sha256"
    fetched k3s-airgap-images-amd64.tar.zst "https://github.com/k3s-io/k3s/releases/download/$(printf '%s' "$k3s_version" | sed 's/+/%2B/')/k3s-airgap-images-amd64.tar.zst" sha256sum "$k3s_images_sha256"
    fetched "$alpine" "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud/$alpine" sha512sum "$alpine_sha512"
    ssh-keygen -q -t ed25519 -N '' -f "$work/id"
    on() { # N COMMAND: in that machine, as its user (who may `doas`)
        it=$1
        shift
        ssh -q -i "$work/id" -p "$((port + 10 + it))" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 alpine@127.0.0.1 "$@"
    }
    node() { # N: its disk, what cloud-init is told (a name, an address on the shared network, who may log in), and the machine
        mkdir "$work/seed$1"
        printf 'instance-id: k%s\nlocal-hostname: k%s\n' "$1" "$1" >"$work/seed$1/meta-data"
        printf 'version: 2\nethernets:\n  eth0: { dhcp4: true }\n  eth1: { addresses: [10.9.0.%s/24] }\n' "$1" >"$work/seed$1/network-config"
        printf '#cloud-config\nssh_authorized_keys:\n  - %s\n' "$(cat "$work/id.pub")" >"$work/seed$1/user-data"
        xorriso -as mkisofs -quiet -V cidata -J -r -o "$work/seed$1.iso" "$work/seed$1" 2>/dev/null
        qemu-img create -q -f qcow2 -b "$cache/$alpine" -F qcow2 "$work/n$1.qcow2" 8G
        # shellcheck disable=SC2046
        machine "$1" -drive "file=$work/n$1.qcow2,format=qcow2,if=virtio" -drive "file=$work/seed$1.iso,format=raw,if=virtio,readonly=on" \
            -netdev "user,id=out,hostfwd=tcp:127.0.0.1:$((port + 10 + $1))-:22,hostfwd=tcp:127.0.0.1:$((port + $1))-:6443" -device "virtio-net-pci,netdev=out,mac=52:54:00:00:0a:0$1" $(lan "$1")
    }
    for n in 1 2 3; do node "$n"; done
    for n in 1 2 3; do
        tries=0
        until on "$n" true 2>/dev/null; do
            tries=$((tries + 1))
            [ "$tries" -lt 150 ] || fail "the Alpine machine $n did not take a login"
            sleep 2
        done
    done
    before=$(on 1 "echo \$(grep -E '^(MemTotal|MemAvailable):' /proc/meminfo)" | used)
    # k3s as its release is: the binary, and its own images beside it so that it asks no
    # registry for them. The iptables it brings is pointed at its nft build before it
    # first runs: as unpacked it is the legacy one, which Alpine's kernel has no module for.
    start() { # N and k3s's arguments
        to=$1
        shift
        scp -q -i "$work/id" -P "$((port + 10 + to))" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$cache/k3s" "$cache/k3s-airgap-images-amd64.tar.zst" alpine@127.0.0.1:/tmp/ || fail "k3s was not copied to machine $to"
        on "$to" "doas rc-service -q cgroups start && doas install -m 755 /tmp/k3s /usr/local/bin/k3s && doas mkdir -p /var/lib/rancher/k3s/agent/images \
            && doas mv /tmp/k3s-airgap-images-amd64.tar.zst /var/lib/rancher/k3s/agent/images/ && rm /tmp/k3s \
            && { doas k3s kubectl version --client >/dev/null 2>&1 || true; } && cd /var/lib/rancher/k3s/data/current/bin/aux \
            && for tool in iptables iptables-save iptables-restore ip6tables ip6tables-save ip6tables-restore; do doas ln -sf xtables-nft-multi \$tool || exit 1; done \
            && doas sh -c 'setsid nohup k3s $* >/var/log/k3s.log 2>&1 </dev/null &'" || fail "k3s was not started on machine $to"
    }
    start 1 server --node-ip 10.9.0.1 --flannel-iface eth1 --token compare --tls-san 127.0.0.1 --write-kubeconfig-mode 644
    tries=0
    until on 1 'cat /etc/rancher/k3s/k3s.yaml' >"$work/kubeconfig" 2>/dev/null && [ -s "$work/kubeconfig" ]; do
        tries=$((tries + 1))
        [ "$tries" -lt 150 ] || fail "the k3s server wrote no kubeconfig: $(on 1 'tail -n 5 /var/log/k3s.log' 2>&1)"
        sleep 2
    done
    python3 - "$work" <<'EOF'
import base64, os, re, sys
text = open(f"{sys.argv[1]}/kubeconfig").read()
for field, file in (("certificate-authority-data", "ca.pem"), ("client-certificate-data", "cert.pem"), ("client-key-data", "key.pem")):
    with open(os.open(f"{sys.argv[1]}/{file}", os.O_WRONLY | os.O_CREAT, 0o600), "wb") as out:
        out.write(base64.b64decode(re.search(field + r":\s*(\S+)", text).group(1)))
EOF
    export API_PORT=$((port + 1)) API_NAME=127.0.0.1 API_CA="$work/ca.pem" API_CERT="$work/cert.pem" API_KEY="$work/key.pem"
    for n in 2 3; do start "$n" agent --server https://10.9.0.1:6443 --token compare --node-ip "10.9.0.$n" --flannel-iface eth1; done
    is_ready='any(c["type"] == "Ready" and c["status"] == "True" for c in (x["status"].get("conditions") or []))'
    API_EVERY=1 api wait 900 /api/v1/nodes "sum(1 for x in j[\"items\"] if $is_ready) == 3" >/dev/null || fail "three k3s nodes did not become ready"
    # (What k3s starts by itself: its DNS, its ingress and load balancer, its metrics and storage.)
    API_EVERY=1 api wait 900 /api/v1/namespaces/kube-system/pods \
        'len(j["items"]) >= 7 and all(x["status"]["phase"] == "Succeeded" or all(c.get("ready") for c in x["status"].get("containerStatuses") or [{}]) for x in j["items"])' >/dev/null || fail "k3s's own pods did not all run"
    note "k3s: a server and two agents"

    for n in 2 3; do
        echo '{"metadata":{"labels":{"role":"worker"}}}' >"$work/apply.json"
        api call PATCH "/api/v1/nodes/k$n" "$work/apply.json" application/merge-patch+json >/dev/null || fail "k$n was not labelled"
    done
    deployment() { # NAME SECONDS [more of the pod's spec]
        cat >"$work/apply.json" <<EOF
{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"$1"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"$1"}},
 "template":{"metadata":{"labels":{"app":"$1"}},"spec":{"terminationGracePeriodSeconds":0${3:-},"containers":[{"name":"run","image":"$image","command":["sleep","$2"]}]}}}}
EOF
    }
    cat >"$work/apply.json" <<EOF
{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"mem"},"spec":{"selector":{"matchLabels":{"app":"mem"}},
 "template":{"metadata":{"labels":{"app":"mem"}},"spec":{"terminationGracePeriodSeconds":0,"tolerations":[{"operator":"Exists"}],
  "containers":[{"name":"mem","image":"$image","command":["sh","-c","$(printf '%s' "$loop" | sed 's/"/\\"/g')"]}]}}}}
EOF
    api call POST /apis/apps/v1/namespaces/default/daemonsets "$work/apply.json" >/dev/null || fail "the DaemonSet was not applied"
    API_EVERY=1 api wait 600 /apis/apps/v1/namespaces/default/daemonsets/mem '(j.get("status") or {}).get("numberReady") == 3' >/dev/null || fail "the memory readers did not all run"
    note "k3s: a container on every node; idle for $settle s"
    sleep "$settle"
    api call GET '/api/v1/namespaces/default/pods?labelSelector=app%3Dmem' >"$work/mem.json"
    reads() { # NODE: what its container read last, in MB
        pod=$(python3 -c '
import json, sys
print(next(x["metadata"]["name"] for x in json.load(open(sys.argv[1]))["items"] if x["spec"]["nodeName"] == sys.argv[2]))' "$work/mem.json" "$1")
        api call GET "/api/v1/namespaces/default/pods/$pod/log?tailLines=1" | used
    }
    control=$(reads k1) worker=$(mean "$(reads k2)" "$(reads k3)")
    [ "$control" -gt 0 ] && [ "$worker" -gt 0 ] || fail "no memory was read: $control, $worker"

    : >"$work/applies"
    for i in 1 2 3 4 5; do
        deployment "a$i" 3600
        api timed 300 "/apis/apps/v1/namespaces/default/deployments/a$i" '(j.get("status") or {}).get("readyReplicas") == 1' \
            POST /apis/apps/v1/namespaces/default/deployments "$work/apply.json" >>"$work/applies" || fail "the deployment a$i did not run"
        api call DELETE "/apis/apps/v1/namespaces/default/deployments/a$i" >/dev/null || fail "a$i was not deleted"
    done
    applied=$(middle <"$work/applies")

    # (k3s calls a node lost 50 s after it last heard from it (node-monitor-grace-period as it
    # comes) and then, by each pod's own toleration, waits 300 s more: a run told to wait
    # about N has the pod tolerate the lost node for N - 50.)
    tolerate=''
    if [ -n "${1:-}" ]; then
        for taint in unreachable not-ready; do
            tolerate="$tolerate${tolerate:+,}{\"key\":\"node.kubernetes.io/$taint\",\"operator\":\"Exists\",\"effect\":\"NoExecute\",\"tolerationSeconds\":$(($1 - 50))}"
        done
        tolerate=",\"tolerations\":[$tolerate]"
    fi
    deployment move 36000 ",\"nodeSelector\":{\"role\":\"worker\"}$tolerate"
    api call POST /apis/apps/v1/namespaces/default/deployments "$work/apply.json" >/dev/null || fail "the deployment to move was not applied"
    api wait 300 /apis/apps/v1/namespaces/default/deployments/move '(j.get("status") or {}).get("readyReplicas") == 1' >/dev/null || fail "the deployment to move did not run"
    where=$(api call GET '/api/v1/namespaces/default/pods?labelSelector=app%3Dmove' | python3 -c 'import json, sys; print(*[x["spec"]["nodeName"] for x in json.load(sys.stdin)["items"]])')
    case $where in k2 | k3) ;; *) fail "the deployment to move runs on '$where', not on one of the two it may" ;; esac
    lose "${where#k}"
    gone=$(LOST=$where API_EVERY=0.5 api wait 1200 '/api/v1/namespaces/default/pods?labelSelector=app%3Dmove' \
        "any(x[\"spec\"].get(\"nodeName\") not in (None, os.environ[\"LOST\"]) and $is_ready for x in j[\"items\"])") || fail "the replica of the lost node $where ran nowhere else"
    echo "k3s ${1:-default} control=$control worker=$worker apply=$applied lost=$gone before=$before" >>"$raw"
    note "k3s: $(tail -n 1 "$raw")"
}

mkdir -p "$root/target"
[ -n "$only" ] || : >"$raw" # (a whole comparison starts over)
if [ -z "$only" ] || [ "$runs" != 1 ]; then
    # Each run is this script again: its machines and its files go when it ends.
    for system in ${only:-kith k3s}; do
        for _ in $(seq "$runs"); do sh "$0" --only "$system" --runs 1 ${lost:+--lost "$lost"} || exit $?; done
        [ -n "$only" ] || sh "$0" --only "$system" --runs 1 --lost 60 || exit $?
    done
    [ -n "$only" ] || { table >"$root/ci/compare.txt" && cat "$root/ci/compare.txt"; }
    exit 0
fi
note "$only${lost:+, told to wait $lost s for a lost node}"
"$only" $lost
