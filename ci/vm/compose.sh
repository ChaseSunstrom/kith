# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# shellcheck disable=SC2015 # (as the script had them before it was cut)
# Sourced by ci/vm.sh for --test compose: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
# (The tools the docker half needs are checked before the kith half runs, as ci/compare.sh checks its own.)
if [ "${KITH_E2E:-}" = 1 ]; then
    for tool in xorriso ssh-keygen scp qemu-img curl sha512sum; do
        command -v "$tool" >/dev/null 2>&1 || fail "$tool is needed for KITH_E2E=1 (the docker machine)"
    done
fi
kith=$(sh "$root/ci/musl.sh")/kith
# stack TAG FILE NAMES ASKS: a compose file of the test pod's, as kith resources: made on this machine by
# the kith that is built here (exit 0 is all of it translated; 1 says what was left out), applied to
# the node. Then each of NAMES (NAME:COUNT) has COUNT containers ready in its Workload, and each of ASKS (NAME, or
# NAME:WANT when NAME is answered by WANT's pod) is asked for by that name from a Job in a pod of its own.
stack() {
    tag=$1 file=$2 names=$3 asks=$4
    # (--node n1: the volumes are made on the node, which is the one this test has.)
    "$kith" import compose "$file" --node n1 >"$work/$tag.yml" || fail "kith import compose left something of $file out"
    # The resources as JSON for the API: a store file of this machine's takes them (what
    # `kith import` prints is YAML), and says each as JSON without its revision.
    KITH_STORE="$work/$tag-store.json" "$kith" apply --file "$work/$tag.yml" >&2 || fail "the imported $tag did not lint as resources"
    KITH_STORE="$work/$tag-store.json" "$kith" get --output json | python3 -c '
import json, sys
found = json.load(sys.stdin)
for r in found:
    r["metadata"].pop("revision", None)
json.dump(found, sys.stdout)
' >"$work/$tag-apply.json" || fail "the imported $tag could not be read back as JSON"
    # The clock starts at the apply and stops when each Workload has said one container ready.
    started=$(date +%s%N)
    any POST /v1/apply "$work/$tag-apply.json" >/dev/null || fail "the imported $tag was not applied"
    waited=0
    while :; do
        every=y
        for pair in $names; do
            name=${pair%%:*} count=${pair#*:}
            line=$(units Workload "$name") && [ "${line%% *}" = "$count" ] || { every=''; unready="$name: $line"; }
        done
        [ -z "$every" ] || break
        waited=$((waited + 1))
        [ "$waited" -lt 1500 ] || fail "waited for the $tag services to be ready; one says $unready"
        sleep 0.2
    done
    elapsed=$((($(date +%s%N) - started) / 1000000))
    seconds=$(printf '%d.%03d' $((elapsed / 1000)) $((elapsed % 1000)))
    echo "vm.sh: compose: $tag apply to all ready: $seconds s (one run, ready includes HTTP probes, 512 MB node)" >&2
    # Each name, then, as a Job in a pod of its own asks for it (40 times: pod ask,
    # ci/pod.rs): its Service has an address and its pod answers with its own name.
    for pair in $asks; do
        ask=${pair%%:*}
        want=${pair#*:}
        waited=0
        until any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    status = r.get("status") or {}
    if r["kind"] == "Service" and r["metadata"]["name"] == sys.argv[1] and status.get("address") and status.get("backends"):
        sys.exit(0)
sys.exit(1)
' "$ask"; do
            waited=$((waited + 1))
            [ "$waited" -lt 120 ] || fail "the Service $ask was given no address with its pod"
            sleep 1
        done
        cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Job","metadata":{"name":"ask-$ask"},"spec":{"retries":0,"template":{"pod":true,"containers":[
  {"name":"ask","image":"kith.test/pod:1","command":["/bin/pod","ask","$ask","80"]}]}}}]
EOF
        any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Job ask-$ask was not applied"
        waited=0
        until line=$(units Job "ask-$ask") && printf '%s\n' "$line" | grep -Eq '^[0-9]+ (succeeded|failed)( |$)'; do
            waited=$((waited + 1))
            [ "$waited" -lt 300 ] || fail "waited for the Job ask-$ask; it says: $line"
            sleep 1
        done
        any GET "/v1/logs/Job/default/ask-$ask" >"$work/$tag-ask-$ask.out" 2>/dev/null || true
        printf '%s\n' "$line" | grep -q succeeded || fail "the Job ask-$ask did not succeed: $line: $(cat "$work/$tag-ask-$ask.out")"
        ! grep -q 'failed: ' "$work/$tag-ask-$ask.out" || fail "the Job asking for $ask was not always answered: $(cat "$work/$tag-ask-$ask.out")"
        grep -q 'HTTP/1.0 200 OK' "$work/$tag-ask-$ask.out" && grep -q "$want-0" "$work/$tag-ask-$ask.out" || fail "the name $ask was not answered by $want-0: $(cat "$work/$tag-ask-$ask.out")"
    done
}
# docker compose up of the same media file, on an Alpine machine of its own (KITH_E2E=1): docker as
# Alpine packages it, the test pod's image made here and imported into it, the file's directories made
# by hand. Timed from `docker compose up -d` until its eight containers run, three runs (each after a
# `down -v`), the median printed beside kith's. (Health checks are not waited for: the test pod has no curl.)
dock() {
    # (The Alpine image ci/compare.sh uses, fetched and checked the same way.)
    cache=${XDG_CACHE_HOME:-$HOME/.cache}/kith-compare
    img=$cache/generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2
    if ! [ -f "$img" ]; then
        mkdir -p "$cache"
        curl -fsSL --max-time 900 -o "$img.part" https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud/generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2 || fail "could not fetch the Alpine image"
        mv "$img.part" "$img"
    fi
    [ "$(sha512sum "$img" | cut -d ' ' -f 1)" = '8d756f6fc7653daa4fb4e2e213d8a66007bcb1e5a846e28891af62c47b90685c694486c2746099ad99e9e8f5278db76b69d11dfe1e9361aa4c8406df16929a9c' ] || fail "$img is not the Alpine image ci/compare.sh names (remove it to fetch it again)"
    # The test pod as an image docker can import: its binary at /bin/pod, as the compose file runs it.
    mkdir -p "$work/dock/bin" && cp "$work/pod" "$work/dock/bin/pod" && tar -C "$work/dock" -cf "$work/dock.tar" bin || fail "the test pod was not put in a tar"
    ssh-keygen -q -t ed25519 -N '' -f "$work/dock-id" || fail "ssh-keygen could not make the docker machine's key"
    mkdir "$work/dock-seed"
    printf 'instance-id: dock\nlocal-hostname: dock\n' >"$work/dock-seed/meta-data"
    printf 'version: 2\nethernets:\n  eth0: { dhcp4: true }\n' >"$work/dock-seed/network-config"
    printf '#cloud-config\nssh_authorized_keys:\n  - %s\n' "$(cat "$work/dock-id.pub")" >"$work/dock-seed/user-data"
    xorriso -as mkisofs -quiet -V cidata -J -r -o "$work/dock-seed.iso" "$work/dock-seed" 2>/dev/null || fail "xorriso could not make the docker machine's seed"
    qemu-img create -q -f qcow2 -b "$img" -F qcow2 "$work/dock.qcow2" 8G || fail "qemu-img could not make the docker machine's disk"
    # (The kith node goes first: this machine is the only one running while docker is timed.)
    kill $vms 2>/dev/null || true
    wait $vms 2>/dev/null || true
    vms=''
    # (Installing and three runs take longer than the kith machines' time.)
    time=1800
    dock_net="user,id=out,hostfwd=tcp:127.0.0.1:$((port + 20))-:22" # unrestricted: KITH_E2E=1 only; the machine installs docker from Alpine's mirrors
    timeout "$time" qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 -display none -machine q35 \
        -drive "file=$work/dock.qcow2,format=qcow2,if=virtio" -drive "file=$work/dock-seed.iso,format=raw,if=virtio,readonly=on" \
        -netdev "$dock_net" -device "virtio-net-pci,netdev=out,mac=52:54:00:00:0a:04" \
        -serial "file:$work/n4.log" -monitor none </dev/null >"$work/n4.err" 2>&1 &
    vms="$vms $!"
    ssh_dock() { ssh -q -i "$work/dock-id" -p "$((port + 20))" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 alpine@127.0.0.1 "$@"; }
    tries=0
    until ssh_dock true 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -lt 600 ] || fail "the Alpine machine for docker took no login"
        sleep 0.5
    done
    # (coreutils: busybox's date has no %N, so the runs would be timed in whole seconds, 0 ms.)
    ssh_dock 'doas apk add -q --no-cache docker docker-cli-compose coreutils && doas rc-service -q cgroups start && doas rc-service -q docker start && mkdir -p stack/config/vpn stack/config/films' || fail "docker was not installed on the Alpine machine"
    scp -q -i "$work/dock-id" -P "$((port + 20))" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$work/dock.tar" alpine@127.0.0.1: || fail "the test pod's tar was not copied"
    scp -q -i "$work/dock-id" -P "$((port + 20))" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$root/ci/compose/media.yml" alpine@127.0.0.1:stack/compose.yml || fail "media.yml was not copied"
    # (What the machine does: the daemon up, the image imported, and three timed runs; "run N MS" each.)
    cat >"$work/dock-run.sh" <<'EOF'
#!/bin/sh
set -eu
tries=0
until doas docker info >/dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -lt 300 ] || { echo "docker's daemon did not start" >&2; exit 1; }
    sleep 1
done
echo "docker $(doas docker version --format '{{.Server.Version}}')"
doas docker import "$HOME/dock.tar" kith.test/pod:1 >/dev/null
cd "$HOME/stack"
for run in 1 2 3; do
    doas docker compose down -v >/dev/null 2>&1 || true
    start=$(date +%s%N)
    doas docker compose up -d >/dev/null
    waited=0
    until [ "$(doas docker ps -q --filter label=com.docker.compose.project=stack --filter status=running | wc -l)" -ge 8 ]; do
        waited=$((waited + 1))
        [ "$waited" -lt 1500 ] || { echo "the eight containers did not all run" >&2; exit 1; }
        sleep 0.2
    done
    echo "run $run $(( ($(date +%s%N) - start) / 1000000 ))"
done
EOF
    scp -q -i "$work/dock-id" -P "$((port + 20))" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$work/dock-run.sh" alpine@127.0.0.1: || fail "the run script was not copied"
    ssh_dock 'sh dock-run.sh' >"$work/dock.out" 2>"$work/dock.err" || fail "docker compose did not bring the stack up: $(cat "$work/dock.err")"
    ms=$(awk '$1 == "run" { print $3 }' "$work/dock.out" | sort -n)
    [ "$(printf '%s\n' "$ms" | wc -l)" -eq 3 ] || fail "docker's three runs were not all timed: $(cat "$work/dock.out")"
    [ "$(printf '%s\n' "$ms" | sed -n 1p)" -gt 0 ] || fail "docker's fastest run took 0 ms, so the clock is wrong: $(cat "$work/dock.out")"
    seconds() { printf '%d.%03d' $(($1 / 1000)) $(($1 % 1000)); }
    docker_seconds=$(seconds "$(printf '%s\n' "$ms" | sed -n 2p)")
    docker_version=$(awk '$1 == "docker" { print $2 }' "$work/dock.out")
    [ -n "$docker_version" ] || fail "docker's version was not read: $(cat "$work/dock.out")"
    echo "vm.sh: compose: docker compose up of the same file to all eight running: $docker_seconds s (median of three, running only, no health wait, 2048 MB VM, docker $docker_version)" >&2
}
# (A pod is named for its Workload: web's alias, frontend, is answered by web-0.)
stack stack "$root/ci/compose/stack.yml" 'api:1 db:1 cache:1 web:1' 'api db cache web frontend:web'
# (The eight services of the media stack: downloader shares vpn's pod (network_mode), so it has no
# Service of its own; its container is ready with vpn's (two of vpn's pod's containers).)
stack media "$root/ci/compose/media.yml" 'vpn:2 indexer:1 shows:1 films:1 requests:1 media:1 subtitles:1' 'vpn indexer shows films requests media mediaserver:media subtitles'
media_seconds=$seconds
! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
# (With KITH_E2E=1 the same media file under docker, after the kith node is stopped.)
docker_note=''
if [ "${KITH_E2E:-}" = 1 ]; then
    dock
    docker_note="; docker compose up of the same file to all eight running $docker_seconds s (median of three, running only, no health wait, 2048 MB VM, docker $docker_version)"
fi
echo "vm.sh: ok: one node, kith import compose of ci/compose/stack.yml (four services of the test pod) and of ci/compose/media.yml (eight services, the media stack's shape on the test pod), nothing left out: each applied and all ready, and each name asked for from a Job in a pod, and answered by its own pod; media apply to all ready $media_seconds s (one run, ready includes HTTP probes, 512 MB node)$docker_note"
exit 0
