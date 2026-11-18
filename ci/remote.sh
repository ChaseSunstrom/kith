#!/bin/sh
# Run the workspace's tests on another kith node, as a Job there, so this machine does not.
#
#   KITH_REMOTE=ADDR[:PORT] KITH_REMOTE_CREDS=DIR sh ci/remote.sh [COMMIT [CARGO TEST ARGS]]
#
# DIR holds ca.crt, root.crt and root.key: the cluster's CA and a client allowed to apply Jobs.
# COMMIT is one the repository has on GitHub (KITH_REMOTE_REPO; origin/main by default): the
# node clones it, it is not sent from here. It runs as a user who is not root, as tests do here.
# Exits as `cargo test` did (`--workspace` unless ARGS say), after printing what failed.
set -eu
case "${1-}" in -h | --help) sed -n '2,9p' "$0" | cut -c3-; exit 0 ;; esac
: "${KITH_REMOTE:?names the node: ADDR[:PORT]}"
creds=${KITH_REMOTE_CREDS:?names the directory with ca.crt, root.crt and root.key}
repo=${KITH_REMOTE_REPO:-https://github.com/ChaseSunstrom/kith}
commit=$(git rev-parse "${1:-origin/main}")
[ $# -lt 1 ] || shift
args=${*:---workspace}
addr=${KITH_REMOTE%:*} port=7443
[ "$addr" = "$KITH_REMOTE" ] || port=${KITH_REMOTE##*:}
# (The node's certificate is for the name `kith`, whatever its address.)
api() {
    path=$1
    shift
    curl -sS -m 30 --cacert "$creds/ca.crt" --cert "$creds/root.crt" --key "$creds/root.key" \
        --resolve "kith:$port:$addr" "$@" "https://kith:$port/v1/$path"
}
name=test-$(printf %.12s "$commit")-$(date +%s)
# ponytail: a fresh clone, crates and build each run (a few minutes); a Volume for the cargo
# cache and target if runs get frequent. The working tree is not sent: push it first.
# shellcheck disable=SC2016 # (expanded by the Job's shell, on the node)
script='cd /work && git init -q k && cd k && git fetch -q --depth 1 "$REPO" "$COMMIT" && git checkout -q FETCH_HEAD || exit 1
t0=$(date +%s); cargo test -q --no-fail-fast $ARGS >/work/out.txt 2>&1; code=$?
grep -E -A2 "panicked at|^error" /work/out.txt | head -150
echo "cargo test: exit $code, $(grep -c "^test result: ok" /work/out.txt) test binaries ok, $(($(date +%s) - t0)) s on $(nproc) CPUs"
exit $code'
# (A pod with namespaces of its own inside: a few tests make user namespaces. The toolchain is
# the image's, named so rustup adds nothing as a user who cannot.)
jq -n --arg name "$name" --arg args "$args" --arg script "$script" --arg repo "$repo" --arg commit "$commit" '[{
  apiVersion: "kith.dev/v1", kind: "Job", metadata: {name: $name},
  spec: {retries: 0, template: {pod: true, containers: [{
    name: "test", image: "docker.io/library/rust:1.99.1", runAsUser: 1000, userNamespaces: true,
    env: [{name: "HOME", value: "/work"}, {name: "RUSTUP_TOOLCHAIN", value: "1.99.1"}, {name: "ARGS", value: $args}, {name: "REPO", value: $repo}, {name: "COMMIT", value: $commit}],
    volumeMounts: [{scratch: "work", path: "/work"}],
    command: ["sh", "-c", $script]}]}}}]' |
    api apply -H 'content-type: application/json' --data-binary @- >/dev/null
echo "remote.sh: Job $name: cargo test $args of $commit" >&2
state=running waited=0
while [ "$state" != succeeded ] && [ "$state" != failed ]; do
    [ "$waited" -lt 5400 ] || { echo "remote.sh: Job $name still $state after $waited s" >&2; exit 2; }
    sleep 15
    waited=$((waited + 15))
    state=$(api "resources/Job/default/$name" | jq -r '.status.state // "pending"')
done
api "logs/Job/default/$name" | jq -r .data
api "resources/Job/default/$name" -X DELETE >/dev/null || true
[ "$state" = succeeded ]
