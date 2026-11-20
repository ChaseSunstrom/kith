#!/bin/sh
# Run the workspace's tests spread over every node of a kith cluster, from a commit that need not
# be pushed, so this machine does not.
#
#   KITH_REMOTE=ADDR[:PORT] KITH_REMOTE_CREDS=DIR sh ci/remote.sh [--fan] [COMMIT [CARGO TEST ARGS]]
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
set -eu
repo=${KITH_REMOTE_REPO:-https://github.com/ChaseSunstrom/kith}
timeout=${KITH_REMOTE_TIMEOUT:-3600}
cache_mb=${KITH_REMOTE_CACHE_MB:-30000}

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
        --arg cap "$cache_mb" --argjson timeout "$timeout" '[{
  apiVersion: "kith.dev/v1", kind: "Job", metadata: {name: $name},
  spec: {retries: 0, timeoutSeconds: $timeout, template: {pod: true, containers: [{
    name: "test", image: "docker.io/library/rust:1.99.1", runAsUser: 1000, userNamespaces: true,
    env: [{name: "RUSTUP_TOOLCHAIN", value: "1.99.1"}, {name: "ARGS", value: $args}, {name: "REPO", value: $repo},
          {name: "COMMIT", value: $commit}, {name: "BASES", value: $bases}, {name: "IDX", value: $idx},
          {name: "N", value: $n}, {name: "PART", value: $part}, {name: "CAP_MB", value: $cap}],
    volumeMounts: [{volume: $vol, path: "/cache"}, {scratch: "work", path: "/work"}],
    command: ["sh", "-c", $script]}]}}}]'
}

volume_json() {
    jq -n --arg vol "ci-$1" --arg node "$1" \
        '[{apiVersion: "kith.dev/v1", kind: "Volume", metadata: {name: $vol}, spec: {node: $node, path: "ci-cache"}}]'
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
    echo "=== merged: $2 nodes"
    i=0
    while [ "$i" -lt "$2" ]; do
        echo "$(cat "$1/$i.node"): $(grep '^SUMMARY ' "$1/$i.log" | tail -1 | cut -c9- || true)"
        i=$((i + 1))
    done
    if [ -s "$1/failures.txt" ]; then
        echo "$(wc -l <"$1/failures.txt") tests failed:"
        cat "$1/failures.txt"
    fi
    [ "$rc" != 0 ] && echo "result: exit $rc" || echo "result: all passed"
    return "$rc"
}

# one NODE I N COMMIT BASES ARGS DIR: ships the bundle, runs the Job, waits, saves its log.
one() {
    node=$1 i=$2 n=$3 commit=$4 bases=$5 args=$6 dir=$7
    echo "$node" >"$dir/$i.node"
    echo "no answer" >"$dir/$i.state"
    : >"$dir/$i.log"
    name=ci-$(printf %.20s "$node")-$(printf %.8s "$commit")-$(date +%s)
    # (The API answers a refusal with {"error": …} and a status curl does not fail on.)
    answer="$dir/$i.answer"
    volume_json "$node" | api apply -H 'content-type: application/json' --data-binary @- >"$answer" 2>&1
    if grep -qE '"error"|^curl:' "$answer"; then cp "$answer" "$dir/$i.log"; echo "Volume refused" >"$dir/$i.state"; return 0; fi
    if [ -d "$dir/in" ]; then
        tries=0
        # (A Volume just made takes a moment to be there.)
        until tar -cf - -C "$dir" in | api "volumes/default/ci-$node/files" -m 900 -X PUT \
            -H 'content-type: application/x-tar' --data-binary @- >"$answer" 2>&1 && ! grep -qE '"error"|^curl:' "$answer"; do
            tries=$((tries + 1))
            [ "$tries" -lt 10 ] || { cp "$answer" "$dir/$i.log"; echo "bundle put refused" >"$dir/$i.state"; return 0; }
            sleep 3
        done
    fi
    echo "$name" >>"$dir/jobs"
    job_json "$name" "$node" "$i" "$n" "$commit" "$bases" "$args" |
        api apply -H 'content-type: application/json' --data-binary @- >"$answer" 2>&1
    if grep -qE '"error"|^curl:' "$answer"; then cp "$answer" "$dir/$i.log"; echo "Job refused" >"$dir/$i.state"; return 0; fi
    echo "remote.sh: $node: Job $name" >&2
    state=pending waited=0
    while [ "$state" != succeeded ] && [ "$state" != failed ]; do
        [ "$waited" -lt $((timeout + 600)) ] || { echo "no end after $waited s" >"$dir/$i.log"; break; }
        sleep 15
        waited=$((waited + 15))
        state=$(api "resources/Job/default/$name" | jq -r '.status.state // "pending"') || state=pending
        echo "$state" >"$dir/$i.state"
    done
    api "logs/Job/default/$name" | jq -r .data >"$dir/$i.log" || true
    api "resources/Job/default/$name" -X DELETE >/dev/null || true
}

fan() {
    commit=$(git rev-parse --verify "$1^{commit}")
    shift
    args=${*:---workspace}
    case " $args " in *" -- "*) echo "remote.sh: ARGS are cargo's, without a -- (libtest's are the Job's)" >&2; exit 64 ;; esac
    creds=${KITH_REMOTE_CREDS:?names the directory with ca.crt, root.crt and root.key}
    addr=${KITH_REMOTE%:*} port=7443
    [ "$addr" = "$KITH_REMOTE" ] || port=${KITH_REMOTE##*:}
    nodes=$(api resources -m 15 | jq -r '.[] | select(.kind == "Node" and .status.state == "ready" and (.spec.unschedulable | not)) | .metadata.name' 2>/dev/null | grep -E '^[a-z0-9][a-z0-9-]*$' | sort) || nodes=''
    if [ -z "$nodes" ]; then
        echo "remote.sh: no node answered at $KITH_REMOTE: cargo test $args here, on the working tree" >&2
        # shellcheck disable=SC2086 # (ARGS is words)
        exec cargo test $args
    fi
    n=$(echo "$nodes" | wc -l)
    dir=$(mktemp -d)
    trap 'for j in $(cat "$dir/jobs" 2>/dev/null); do api "resources/Job/default/$j" -X DELETE >/dev/null 2>&1 || true; done; rm -rf "$dir"' EXIT
    trap 'exit 130' INT TERM
    : >"$dir/failures.txt"
    bases=$(bundle "$commit" "$dir")
    echo "remote.sh: cargo test $args of $commit on $n nodes ($(du -sk "$dir/in" 2>/dev/null | cut -f1) kB bundle)" >&2
    i=0
    for node in $nodes; do
        one "$node" "$i" "$n" "$commit" "$bases" "$args" "$dir" &
        i=$((i + 1))
    done
    wait
    report "$dir" "$n"
}

# --self-test: the bundle, the partition, the Jobs and the merged report, offline, with a
# GitHub made of a folder and a cargo that only lists and prints.
self_test() {
    t=$(mktemp -d)
    trap 'rm -rf "$t"' EXIT
    ok() { echo "ok: $1"; }
    die() { echo "FAIL: $1" >&2; exit 1; }
    # a commit GitHub lacks, on top of two it has (the second the tip of main, one off the first)
    git init -q --bare "$t/gh.git"
    git -C "$t/gh.git" config uploadpack.allowAnySHA1InWant true
    git init -q -b main "$t/w"
    git -C "$t/w" config user.email t@t && git -C "$t/w" config user.name t
    echo one >"$t/w/f" && git -C "$t/w" add f && git -C "$t/w" commit -qm one
    echo two >"$t/w/f" && git -C "$t/w" commit -qam two
    git -C "$t/w" remote add origin "file://$t/gh.git" && git -C "$t/w" push -q origin main
    git -C "$t/w" fetch -q origin
    echo three >"$t/w/f" && echo x >"$t/w/g" && git -C "$t/w" add g && git -C "$t/w" commit -qam three
    c=$(git -C "$t/w" rev-parse HEAD)
    git -C "$t/gh.git" cat-file -e "$c" 2>/dev/null && die "the test's commit is on GitHub"
    mkdir "$t/send"
    bases=$(cd "$t/w" && bundle "$c" "$t/send")
    [ -f "$t/send/in/$c.bundle" ] || die "no bundle for a commit GitHub lacks"
    [ "$(git -C "$t/w" rev-parse origin/main)" = "$bases" ] || die "bases are not origin/main: $bases"
    [ "$(du -k "$t/send/in/$c.bundle" | cut -f1)" -lt 16 ] || die "the bundle carries more than origin/main..COMMIT"
    ok "a bundle of the one commit GitHub lacks, on $bases"
    # the commit that GitHub has needs no bundle
    : >"$t/none.txt"
    mkdir "$t/send2"
    b2=$(cd "$t/w" && bundle "$(git -C "$t/w" rev-parse origin/main)" "$t/send2")
    [ ! -d "$t/send2/in" ] || die "a pushed commit made a bundle"
    [ "$b2" = "$(git -C "$t/w" rev-parse origin/main)" ] || die "a pushed commit's base is not itself"
    ok "a pushed commit: no bundle, it is fetched"
    # a fake cargo: --list prints $FAKE_LIST as terse libtest does; a run prints a line a name
    mkdir "$t/bin"
    cat >"$t/bin/cargo" <<'EOF'
#!/bin/sh
case "$*" in *--list*) sed 's/$/: test/' "$FAKE_LIST"; echo; echo "$(wc -l <"$FAKE_LIST") tests, 0 benchmarks"; exit 0 ;; esac
while [ "$1" != --exact ]; do shift; done; shift; f=0
for x in "$@"; do
    echo "$x" >>"$FAKE_RAN"
    if [ "$x" = "$FAKE_FAIL" ]; then f=1; echo "test $x ... FAILED"; echo "thread panicked at src/x.rs:1:1:"; else echo "test $x ... ok"; fi
done
echo "test result: $([ $f = 0 ] && echo ok || echo FAILED). $(($# - f)) passed; $f failed; 0 ignored; 0 measured; 0 filtered out"
exit $f
EOF
    chmod +x "$t/bin/cargo"
    # names with spaces, brackets, a repeat (as two test binaries can have) and a doctest
    printf '%s\n' a::b c::d 'src/lib.rs - f (line 3)' e::[x] a::b mod::case_1 mod::case_2 z::long_name_here q r s t u v >"$t/list"
    sort -u "$t/list" >"$t/uniq"
    for n in 1 2 3 5; do
        : >"$t/joined"
        i=0
        while [ "$i" -lt "$n" ]; do
            awk -v N="$n" -v I="$i" "$part" "$t/uniq" >>"$t/joined"
            i=$((i + 1))
        done
        [ "$(sort "$t/joined")" = "$(cat "$t/uniq")" ] || die "N=$n: the shares do not cover each test once"
    done
    ok "shares of 1, 2, 3 and 5 nodes cover each listed test exactly once"
    # the Job of each of three nodes, run here against the folder: each runs its share only
    mkdir "$t/dir" && cp -R "$t/send/in" "$t/dir/in"
    : >"$t/ran"
    i=0
    for node in n1 n2 n3; do
        echo "$node" >"$t/dir/$i.node"
        j=$(job_json "j$i" "$node" "$i" 3 "$c" "$bases" "--workspace")
        echo "$j" | jq -e --arg v "ci-$node" '.[0] | .kind == "Job" and (.spec.template.containers[0].volumeMounts | map(.volume) | index($v)) != null' >/dev/null || die "Job $i names no Volume ci-$node"
        echo "$j" | jq -e --arg i "$i" '.[0].spec.template.containers[0].env | (map(select(.name == "IDX" and .value == $i)) | length == 1) and (map(select(.name == "N" and .value == "3")) | length == 1)' >/dev/null || die "Job $i has no share"
        script=$(echo "$j" | jq -r '.[0].spec.template.containers[0].command[2]')
        # shellcheck disable=SC2030 # (the PATH is the subshell's: the node's)
        out=$(
            export CACHE="$t/cache$i" WORK="$t/work$i" REPO="file://$t/gh.git" COMMIT="$c" BASES="$bases" ARGS="--workspace" \
                IDX="$i" N=3 PART="$part" CAP_MB=100 PATH="$t/bin:$PATH" FAKE_LIST="$t/list" FAKE_RAN="$t/ran" FAKE_FAIL=mod::case_2
            mkdir -p "$CACHE/in" && cp "$t/dir/in/"* "$CACHE/in/"
            sh -c "$script" 2>&1
        ) || true
        echo "$out" >"$t/dir/$i.log"
        echo failed >"$t/dir/$i.state"
        [ "$(cat "$t/cache$i/src/g")" = x ] || die "node $i did not check out the unpushed commit"
        i=$((i + 1))
    done
    [ "$(sort "$t/ran")" = "$(cat "$t/uniq")" ] || die "the three nodes did not run each test once: $(sort "$t/ran" | tr '\n' ' ')"
    ok "a Job on each of 3 nodes checked out the unpushed commit and ran its share: each test once"
    : >"$t/dir/failures.txt"
    rep=$(report "$t/dir" 3) && die "a failing test gave exit 0"
    echo "$rep" | grep -qE '^FAILED: n[123]: mod::case_2$' || die "the report does not name node and test: $rep"
    [ "$(echo "$rep" | grep -c '^FAILED: ')" = 1 ] || die "the report names more than the one failure"
    ok "one merged report names the node and test of the failure, and fails"
    # the local fallback: no KITH_REMOTE, or a cluster that does not answer, runs cargo test with the same args and exit
    cat >"$t/bin/cargo" <<'EOF'
#!/bin/sh
echo "$@" >"$FAKE_RAN"
exit 7
EOF
    # shellcheck disable=SC2031 # (the PATH of the subshell above is not wanted here)
    for env in "env -u KITH_REMOTE" "env KITH_REMOTE=127.0.0.1:1 KITH_REMOTE_CREDS=$t"; do
        : >"$t/ran"
        code=0
        $env PATH="$t/bin:$PATH" FAKE_RAN="$t/ran" sh "$self" HEAD -p kithd -q 2>/dev/null || code=$?
        [ "$code" = 7 ] || die "no fallback ($env): exit $code"
        [ "$(cat "$t/ran")" = "test -p kithd -q" ] || die "fallback args ($env): $(cat "$t/ran")"
    done
    ok "with no cluster, cargo test runs here with the same args and exit status"
    echo "self-test passed"
}

self=$0
case "${1-}" in
-h | --help) sed -n '2,20p' "$0" | cut -c3-; exit 0 ;;
--self-test) self_test; exit 0 ;;
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
