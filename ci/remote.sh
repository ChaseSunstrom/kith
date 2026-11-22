#!/bin/sh
# Run the workspace's tests spread over every node of a kith cluster, from a commit that need not
# be pushed, so this machine does not.
#
#   KITH_REMOTE=ADDR[:PORT] KITH_REMOTE_CREDS=DIR sh ci/remote.sh [--fan] [COMMIT [CARGO TEST ARGS]]
#   KITH_REMOTE=ADDR[:PORT] KITH_REMOTE_CREDS=DIR sh ci/remote.sh --vm TEST[,TEST...] [COMMIT]
#   sh ci/remote.sh --self-test
#
# DIR holds ca.crt, root.crt and root.key: the cluster's CA and a client allowed to apply Volumes
# and Jobs and to put files into a Volume. COMMIT is HEAD unless named. Only what GitHub lacks is
# sent: a git bundle of origin/main..COMMIT, put into the node's Volume ci-NODE, which also keeps
# the node's cargo registry and target folder, so a second run is warm. Each node lists the
# workspace's tests, keeps those whose name hashes to its place among the nodes and runs them
# (cargo test --no-fail-fast ARGS -- --exact NAMES), as a user who is not root, in a pod.
# One merged result is printed, naming the node and test of each failure. Exits 0 when every
# test passed, else as cargo test did (101), or 2 when a node's Job did not run to its end.
# With KITH_REMOTE unset, or no node answering, it runs `cargo test ARGS` here instead and exits
# as it does (ARGS is `--workspace` unless given; COMMIT is then the working tree, not named).
# KITH_REMOTE_REPO (the GitHub clone URL), KITH_REMOTE_TIMEOUT (a Job's seconds, 3600) and
# KITH_REMOTE_CACHE_MB (the size at which a node's target folder is dropped, 30000) are settable.
# --vm runs each named test of ci/vm.sh (sh ci/vm.sh --test TEST) in a Job of its own, one at a
# time on each node, with the node's /dev/kvm: a Device ci-kvm-NODE of it, granted to namespace ci
# alone, and a shared DeviceClaim ci-kvm-NODE, named by the Job (the claim is applied each run, the
# Device only where it is not there, or is wrong (another node's or path, or granted past ci: it is applied over).
# Everything else this applies (Volumes, Jobs, claims) is in namespace ci: a Volume ci-NODE that an
# earlier version made in namespace default stays until it is deleted by hand (DELETE
# /v1/resources/Volume/default/ci-NODE). A Job that is
# still pending after KITH_REMOTE_PENDING seconds (600; --vm Jobs only) is given up on, with its claim's own message
# as the log, so a node with no /dev/kvm to give ends the run at once, not at the hour. The tools the tests need are
# installed by apt into a copy of the image's root in the node's Volume, once; there too stay the
# OS build's cache and cargo's. A test that ci/vm.sh skips (no KVM, a tool missing) counts as
# failed. One merged result names the node and test of each failure; it exits 0 when all passed.
set -eu
repo=${KITH_REMOTE_REPO:-https://github.com/ChaseSunstrom/kith}
timeout=${KITH_REMOTE_TIMEOUT:-3600}
cache_mb=${KITH_REMOTE_CACHE_MB:-30000}
# (How long a Job may stay pending before the run gives up on it, seconds.)
pending=${KITH_REMOTE_PENDING:-600}
# (Both are used in arithmetic and in a Job's env: digits, or the run is refused.)
case $cache_mb$pending in '' | *[!0-9]*) echo "remote.sh: KITH_REMOTE_CACHE_MB and KITH_REMOTE_PENDING are whole numbers" >&2; exit 64 ;; esac
# (0 would give up on every --vm Job before its first poll.)
[ "$pending" -ge 1 ] || { echo "remote.sh: KITH_REMOTE_PENDING is at least 1" >&2; exit 64; }
# (CI's namespace: its Volumes, Jobs and claims, and the one /dev/kvm is granted to.)
ns=ci

# The partition: a test goes to the node whose index is its name's hash mod N. The same awk runs
# here (the self-test) and on each node, so they agree. Hashing by name keeps a test's place
# when others come and go, and balances the big binaries by count.
# shellcheck disable=SC2016 # (awk's, not the shell's)
part='BEGIN { for (i = 1; i < 256; i++) o[sprintf("%c", i)] = i }
NF { h = 0; n = length($0); for (i = 1; i <= n; i++) h = (h * 31 + o[substr($0, i, 1)]) % 2147483647; if (h % N == I) print }'

# What a node runs, as its Job's command. It takes CACHE (the node's Volume) and WORK (scratch),
# REPO, COMMIT, BASES (what GitHub has that the bundle builds on, or COMMIT itself), ARGS, IDX, N,
# PART, CAP_MB. Its last line is SUMMARY, then the failures as FAILED lines are above it.
# shellcheck disable=SC2016 # (expanded by the Job's shell, on the node)
job_script='cache=${CACHE:-/cache} work=${WORK:-/work}
mkdir -p "$cache" "$work" && exec 9>"$cache/lock" && flock 9 || exit 1
cd "$cache" && mkdir -p cargo in src
warm=cold; [ ! -d target ] || warm=warm
find in -type f -mtime +1 -delete
mb=$(du -sm target 2>/dev/null | cut -f1); [ "${mb:-0}" -lt "$CAP_MB" ] || { rm -rf target; warm=cold; }
export CARGO_HOME=$cache/cargo CARGO_TARGET_DIR=$cache/target HOME=$work
t0=$(date +%s)
cd src && { [ -d .git ] || git init -q; }
git fetch -q --depth 1 "$REPO" $BASES || { echo "SUMMARY exit=2 why=fetch"; exit 2; }
[ ! -f "../in/$COMMIT.bundle" ] || git bundle unbundle "../in/$COMMIT.bundle" >/dev/null || { echo "SUMMARY exit=2 why=bundle"; exit 2; }
git checkout -q -f --detach "$COMMIT" && git clean -fdxq || { echo "SUMMARY exit=2 why=checkout"; exit 2; }
if ! cargo test $ARGS -- --list --format terse >"$work/raw.txt" 2>"$work/err.txt"; then
    tail -40 "$work/err.txt"; echo "SUMMARY exit=101 why=listing"; exit 101
fi
sed -n "s/: test\$//p" "$work/raw.txt" | LC_ALL=C sort -u >"$work/all.txt"
awk -v N="$N" -v I="$IDX" "$PART" "$work/all.txt" >"$work/mine.txt"
xargs -r -d "\n" cargo test --no-fail-fast $ARGS -- --exact <"$work/mine.txt" >"$work/out.txt" 2>&1
code=$?; [ "$code" = 0 ] || code=101
sed -n "s/^test \(.*\) \.\.\. FAILED\$/FAILED \1/p" "$work/out.txt"
grep -E -A2 "panicked at|^error" "$work/out.txt" | head -150
echo "SUMMARY exit=$code host=$(hostname) cache=$warm cpus=$(nproc) of=$(wc -l <"$work/all.txt") share=$(wc -l <"$work/mine.txt") $(awk "/^test result:/ { p += \$4; f += \$6; i += \$8 } END { print \"passed=\" p + 0, \"failed=\" f + 0, \"ignored=\" i + 0 }" "$work/out.txt") secs=$(($(date +%s) - t0))"
exit $code'

api() {
    path=$1
    shift
    curl -sS -m 30 --cacert "$creds/ca.crt" --cert "$creds/root.crt" --key "$creds/root.key" \
        --resolve "kith:$port:$addr" "$@" "https://kith:$port/v1/$path"
}

# job_json NAME NODE IDX N COMMIT BASES ARGS: the Job of one node. (The node's certificate is for
# the name `kith`, whatever its address; a Job with a Volume is placed where the Volume is.)
job_json() {
    jq -n --arg name "$1" --arg vol "ci-$2" --arg idx "$3" --arg n "$4" --arg commit "$5" --arg bases "$6" \
        --arg args "$7" --arg script "$job_script" --arg repo "$repo" --arg part "$part" \
        --arg cap "$cache_mb" --argjson timeout "$timeout" --arg ns "$ns" '[{
  apiVersion: "kith.dev/v1", kind: "Job", metadata: {name: $name, namespace: $ns},
  spec: {retries: 0, timeoutSeconds: $timeout, template: {pod: true, containers: [{
    name: "test", image: "docker.io/library/rust:1.99.1", runAsUser: 1000, userNamespaces: true,
    env: [{name: "RUSTUP_TOOLCHAIN", value: "1.99.1"}, {name: "ARGS", value: $args}, {name: "REPO", value: $repo},
          {name: "COMMIT", value: $commit}, {name: "BASES", value: $bases}, {name: "IDX", value: $idx},
          {name: "N", value: $n}, {name: "PART", value: $part}, {name: "CAP_MB", value: $cap}],
    volumeMounts: [{volume: $vol, path: "/cache"}, {scratch: "work", path: "/work"}],
    command: ["sh", "-c", $script]}]}}}]'
}

volume_json() {
    jq -n --arg vol "ci-$1" --arg node "$1" --arg ns "$ns" \
        '[{apiVersion: "kith.dev/v1", kind: "Volume", metadata: {name: $vol, namespace: $ns}, spec: {node: $node, path: "ci-cache"}}]'
}

# --vm: what the VM tests need that the image lacks; apt puts it into a copy of the image's root.
pkgs='qemu-system-x86 qemu-utils ovmf socat openssl curl python3 cpio zstd xz-utils flex bison bc libelf-dev libssl-dev mtools dosfstools fdisk e2fsprogs squashfs-tools cryptsetup-bin systemd-repart systemd-boot-efi musl-tools swtpm bubblewrap kmod xxd iproute2 wireguard-tools'

# What a node runs for one VM test, as its Job's command (ci/remote/vm-job.sh says what it takes).
here=$(dirname "$0")
vm_script=$(cat "$here/remote/vm-job.sh")

# dev_json NODE: the Device of NODE's /dev/kvm, which namespace ci alone may claim, and its shared claim.
dev_json() {
    jq -n --arg name "ci-kvm-$1" --arg node "$1" --arg ns "$ns" '[
  {apiVersion: "kith.dev/v1", kind: "Device", metadata: {name: $name, labels: {"kith.dev/node": $node, class: "other", "kith.dev/namespaces": $ns}},
   spec: {node: $node, class: "other", path: "/dev/kvm"}},
  {apiVersion: "kith.dev/v1", kind: "DeviceClaim", metadata: {name: $name, namespace: $ns}, spec: {device: $name, access: "shared"}}]'
}

# vm_job_json NAME NODE TEST COMMIT BASES: the Job of one VM test on NODE, with its claim of /dev/kvm.
vm_job_json() {
    jq -n --arg name "$1" --arg node "$2" --arg test "$3" --arg commit "$4" --arg bases "$5" --arg script "$vm_script" \
        --arg repo "$repo" --arg pkgs "$pkgs" --arg cap "$cache_mb" --argjson timeout "$timeout" --arg ns "$ns" '[{
  apiVersion: "kith.dev/v1", kind: "Job", metadata: {name: $name, namespace: $ns},
  spec: {retries: 0, timeoutSeconds: $timeout, template: {pod: true, deviceClaims: [("ci-kvm-" + $node)], containers: [{
    name: "test", image: "docker.io/library/rust:1.99.1", runAsUser: 1000, userNamespaces: true,
    env: [{name: "RUSTUP_TOOLCHAIN", value: "1.99.1"}, {name: "REPO", value: $repo}, {name: "COMMIT", value: $commit},
          {name: "BASES", value: $bases}, {name: "TEST", value: $test}, {name: "PKGS", value: $pkgs}, {name: "CAP_MB", value: $cap},
          {name: "SCRIPT", value: $script}],
    volumeMounts: [{volume: ("ci-" + $node), path: "/cache"}, {scratch: "work", path: "/work"}],
    command: ["sh", "-c", $script]}]}}}]'
}

# bundle COMMIT DIR: DIR/in/COMMIT.bundle holds what GitHub lacks (origin/main..COMMIT), unless
# nothing; prints BASES, the commits of GitHub it builds on (or COMMIT, when there is no bundle).
bundle() {
    ref=refs/ci-remote/$$
    git update-ref "$ref" "$1"
    if [ "$(git rev-list --count "origin/main..$1")" = 0 ]; then
        git update-ref -d "$ref"
        echo "$1"
        return
    fi
    mkdir -p "$2/in"
    git bundle create -q "$2/in/$1.bundle" "$ref" "^origin/main" || { git update-ref -d "$ref"; return 1; }
    git update-ref -d "$ref"
    # (Every commit just outside the range: a shallow clone of each lets the bundle unpack.)
    git rev-list --boundary "origin/main..$1" | sed -n 's/^-//p' | paste -sd' ' -
}

# report DIR N: print each node's log and the merged result of DIR/I.node, I.state and I.log;
# returns what the run exits with.
report() {
    rc=0
    i=0
    while [ "$i" -lt "$2" ]; do
        node=$(cat "$1/$i.node")
        echo "=== $node ($(cat "$1/$i.state"))"
        tr -cd '[:print:]\n\t' <"$1/$i.log" | grep -v '^FAILED ' || true
        sum=$(grep '^SUMMARY ' "$1/$i.log" | tail -1 || true)
        code=${sum#SUMMARY exit=}
        code=${code%% *}
        if [ -z "$sum" ]; then
            rc=2
        elif [ "$code" != 0 ] && [ "$rc" = 0 ]; then
            rc=$code
        fi
        sed -n 's/^FAILED \(.*\)$/FAILED: '"$node"': \1/p' "$1/$i.log" | tr -cd '[:print:]\n\t' >>"$1/failures.txt"
        i=$((i + 1))
    done
    echo "=== merged: $2 Jobs"
    i=0
    while [ "$i" -lt "$2" ]; do
        echo "$(cat "$1/$i.node"): $(grep '^SUMMARY ' "$1/$i.log" | tail -1 | cut -c9- | tr -cd '[:print:]\n\t' || true)"
        i=$((i + 1))
    done
    if [ -s "$1/failures.txt" ]; then
        echo "$(wc -l <"$1/failures.txt") tests failed:"
        cat "$1/failures.txt"
    fi
    [ "$rc" != 0 ] && echo "result: exit $rc" || echo "result: all passed"
    return "$rc"
}

# one NODE I N COMMIT BASES ARGS DIR [TEST]: ships the bundle, runs the Job (of VM test TEST, with
# the node's Device and claim, when named), waits, saves its log. (A subshell: its names, n and
# node among them, are not its caller's.)
one() (
    node=$1 i=$2 n=$3 commit=$4 bases=$5 args=$6 dir=$7 vmtest=${8-}
    echo "$node" >"$dir/$i.node"
    echo "no answer" >"$dir/$i.state"
    : >"$dir/$i.log"
    name=ci-$(printf %.20s "$node")-$(printf %.8s "$commit")-${vmtest:+$vmtest-}$(date +%s)
    # (The API answers a refusal with {"error": …} and a status curl does not fail on.)
    answer="$dir/$i.answer"
    volume_json "$node" | api apply -H 'content-type: application/json' --data-binary @- >"$answer" 2>&1
    if grep -qE '"error"|^curl:' "$answer"; then cp "$answer" "$dir/$i.log"; echo "Volume refused" >"$dir/$i.state"; return 0; fi
    if [ -n "$vmtest" ]; then
        # (The Device only where it is not there or is wrong (not this node's /dev/kvm, or granted past ci), applied over; the claim each time.)
        if api "resources/Device/ci-kvm-$node" | jq -e --arg node "$node" --arg ns "$ns" \
            '.kind == "Device" and .spec.node == $node and .spec.path == "/dev/kvm" and .metadata.labels["kith.dev/namespaces"] == $ns' >/dev/null 2>&1; then dev_json "$node" | jq '[.[1]]'; else dev_json "$node"; fi |
            api apply -H 'content-type: application/json' --data-binary @- >"$answer" 2>&1
        if grep -qE '"error"|^curl:' "$answer"; then cp "$answer" "$dir/$i.log"; echo "Device refused" >"$dir/$i.state"; return 0; fi
    fi
    if [ -d "$dir/in" ]; then
        tries=0
        # (A Volume just made takes a moment to be there.)
        until tar -cf - -C "$dir" in | api "volumes/$ns/ci-$node/files" -m 900 -X PUT \
            -H 'content-type: application/x-tar' --data-binary @- >"$answer" 2>&1 && ! grep -qE '"error"|^curl:' "$answer"; do
            tries=$((tries + 1))
            [ "$tries" -lt 10 ] || { cp "$answer" "$dir/$i.log"; echo "bundle put refused" >"$dir/$i.state"; return 0; }
            sleep 3
        done
    fi
    echo "$name" >>"$dir/jobs"
    if [ -n "$vmtest" ]; then vm_job_json "$name" "$node" "$vmtest" "$commit" "$bases"; else job_json "$name" "$node" "$i" "$n" "$commit" "$bases" "$args"; fi |
        api apply -H 'content-type: application/json' --data-binary @- >"$answer" 2>&1
    if grep -qE '"error"|^curl:' "$answer"; then cp "$answer" "$dir/$i.log"; echo "Job refused" >"$dir/$i.state"; return 0; fi
    echo "remote.sh: $node: Job $name" >&2
    state=pending waited=0 gave=''
    while [ "$state" != succeeded ] && [ "$state" != failed ]; do
        [ "$waited" -lt $((timeout + 600)) ] || { gave="no end after $waited s"; break; }
        # (Still pending after PENDING s: nothing placed it, as when the node has no /dev/kvm to give. Its claim says why.)
        # (Only a --vm Job: a fan Job waits its node's turn behind another run's, as long as the timeout.)
        if [ -n "$vmtest" ] && [ "$state" = pending ] && [ "$waited" -ge "$pending" ]; then
            why=$(api "resources/DeviceClaim/$ns/ci-kvm-$node" | jq -r '.status.message // empty' 2>/dev/null) || why=''
            gave="Job still pending after $waited s${why:+: $why}"
            break
        fi
        sleep 15
        waited=$((waited + 15))
        state=$(api "resources/Job/$ns/$name" | jq -r '.status.state // "pending"') || state=pending
        echo "$state" >"$dir/$i.state"
    done
    if [ -n "$gave" ]; then echo "$gave" >"$dir/$i.log"; else api "logs/Job/$ns/$name" | jq -r .data >"$dir/$i.log" || true; fi
    api "resources/Job/$ns/$name" -X DELETE >/dev/null || true
)

# find_nodes: sets creds, addr and port for api, and nodes: the cluster's ready, schedulable
# nodes, one a line (none when it does not answer).
find_nodes() {
    creds=${KITH_REMOTE_CREDS:?names the directory with ca.crt, root.crt and root.key}
    addr=${KITH_REMOTE%:*} port=7443
    [ "$addr" = "$KITH_REMOTE" ] || port=${KITH_REMOTE##*:}
    nodes=$(api resources -m 15 | jq -r '.[] | select(.kind == "Node" and .status.state == "ready" and (.spec.unschedulable | not)) | .metadata.name' 2>/dev/null | grep -E '^[a-z0-9][a-z0-9-]*$' | sort) || nodes=''
}

# start COMMIT: the run's folder (its Jobs deleted and it removed at the end) and the bundle.
start() {
    dir=$(mktemp -d)
    trap 'for j in $(cat "$dir/jobs" 2>/dev/null); do api "resources/Job/$ns/$j" -X DELETE >/dev/null 2>&1 || true; done; rm -rf "$dir"' EXIT
    trap 'exit 130' INT TERM
    : >"$dir/failures.txt"
    bases=$(bundle "$1" "$dir")
}

fan() {
    commit=$(git rev-parse --verify "$1^{commit}")
    shift
    args=${*:---workspace}
    case " $args " in *" -- "*) echo "remote.sh: ARGS are cargo's, without a -- (libtest's are the Job's)" >&2; exit 64 ;; esac
    find_nodes
    if [ -z "$nodes" ]; then
        echo "remote.sh: no node answered at $KITH_REMOTE: cargo test $args here, on the working tree" >&2
        # shellcheck disable=SC2086 # (ARGS is words)
        exec cargo test $args
    fi
    n=$(echo "$nodes" | wc -l)
    start "$commit"
    echo "remote.sh: cargo test $args of $commit on $n nodes ($(du -sk "$dir/in" 2>/dev/null | cut -f1) kB bundle)" >&2
    i=0
    for node in $nodes; do
        one "$node" "$i" "$n" "$commit" "$bases" "$args" "$dir" &
        i=$((i + 1))
    done
    wait
    report "$dir" "$n"
}

# vm TEST[,TEST...] COMMIT: each VM test in a Job of its own; the Kth on node K mod N, after that
# node's one before it, so a node runs one at a time (its /dev/kvm, CPUs and Volume are the test's).
vm() {
    set -f # (a name is checked as it is typed: a `*` must not become the files of this folder)
    tests=$(echo "$1" | tr , ' ')
    for x in $tests; do
        case $x in *[!a-z0-9]*) echo "remote.sh: --vm: '$x' is not a test of ci/vm.sh" >&2; exit 64 ;; esac
    done
    [ -n "$tests" ] || { echo "remote.sh: --vm names no test" >&2; exit 64; }
    commit=$(git rev-parse --verify "$2^{commit}")
    find_nodes
    [ -n "$nodes" ] || { echo "remote.sh: no node answered at $KITH_REMOTE (--vm runs nothing here: sh ci/vm.sh --test TEST does)" >&2; exit 2; }
    n=$(echo "$nodes" | wc -l)
    total=$(echo "$tests" | wc -w)
    start "$commit"
    echo "remote.sh: ci/vm.sh --test $1 of $commit on $n nodes ($(du -sk "$dir/in" 2>/dev/null | cut -f1) kB bundle)" >&2
    j=0
    for node in $nodes; do
        (
            k=0
            for x in $tests; do
                [ $((k % n)) != "$j" ] || one "$node" "$k" "$total" "$commit" "$bases" "" "$dir" "$x"
                k=$((k + 1))
            done
        ) &
        j=$((j + 1))
    done
    wait
    report "$dir" "$total"
}

case "${1-}" in
-h | --help) sed -n '2,/^set /{/^#/p}' "$0" | cut -c3-; exit 0 ;;
--self-test)
    # shellcheck disable=SC2034 # (the self-test's: it runs this script again)
    self=$0
    # shellcheck source=/dev/null # (shellcheck checks ci/remote/self-test.sh on its own)
    . "$here/remote/self-test.sh"
    self_test
    exit 0
    ;;
--vm)
    [ $# -ge 2 ] || { echo "usage: sh ci/remote.sh --vm TEST[,TEST...] [COMMIT]" >&2; exit 64; }
    [ -n "${KITH_REMOTE-}" ] || { echo "remote.sh: --vm needs KITH_REMOTE (here, sh ci/vm.sh --test TEST)" >&2; exit 2; }
    # (set -e: a failure exits with report's status)
    vm "$2" "${3:-HEAD}"
    exit
    ;;
esac
[ "${1-}" != --fan ] || shift
if [ -z "${KITH_REMOTE-}" ]; then
    [ $# -lt 1 ] || shift
    echo "remote.sh: KITH_REMOTE is not set: cargo test here, on the working tree" >&2
    [ $# -gt 0 ] || set -- --workspace
    exec cargo test "$@"
fi
commit=${1:-HEAD}
[ $# -lt 1 ] || shift
fan "$commit" "$@"
