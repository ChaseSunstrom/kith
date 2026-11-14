#!/bin/sh
# The real kubectl and helm against kithd on 127.0.0.1 (crates/kithd/tests/kube.rs): the
# clients are fetched once, as their makers release them, checked against the hashes
# written here, and the tests that use them are run. Nothing of Kubernetes is started:
# kubectl and helm are clients. (helm twice: 3 patches what it changes, 4 applies on the
# server and watches what it waits for.)
#
#   sh ci/kube.sh            # every test of crates/kithd/tests/kube.rs
#   sh ci/kube.sh NAME       # the ones whose name has NAME in it
#   sh ci/kube.sh --vm       # instead: sh ci/vm.sh --test kube with those clients (a pod
#                            # needs a node to run on: what must run, runs there)
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cache=${XDG_CACHE_HOME:-$HOME/.cache}/kith-kube
kubectl_version=v1.37.2
kubectl_sha256=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4
helm3_version=v3.22.1
helm3_sha256=896cf63684a42a723d61c980369d6e588330927deb13676ca0d85006dd6da0ea
helm4_version=v4.3.1
helm4_sha256=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b

skip() { echo "kube.sh: skipped: $1" >&2; exit 0; }
fail() { echo "kube.sh: FAIL: $1" >&2; exit 1; }

[ "$(uname -sm)" = "Linux x86_64" ] || skip "the clients are fetched for Linux on x86_64 only"

# What is fetched, once, and what it must be.
fetched() { # FILE URL SHA256
    if ! [ -f "$cache/$1" ]; then
        mkdir -p "$cache"
        curl -fsSL --max-time 900 -o "$cache/$1.part" "$2" || skip "could not fetch $2"
        mv "$cache/$1.part" "$cache/$1"
    fi
    [ "$(sha256sum "$cache/$1" | cut -d ' ' -f 1)" = "$3" ] || fail "$cache/$1 is not the file this script names (remove it to fetch it again)"
    chmod +x "$cache/$1"
}

# helm comes packed: the one program is taken out of what was checked, and nothing else.
helm() { # VERSION SHA256
    fetched "helm-$1.tar.gz" "https://get.helm.sh/helm-$1-linux-amd64.tar.gz" "$2"
    [ -x "$cache/helm-$1/linux-amd64/helm" ] || { mkdir -p "$cache/helm-$1" && tar -xzf "$cache/helm-$1.tar.gz" -C "$cache/helm-$1" linux-amd64/helm; }
}

fetched "kubectl-$kubectl_version" "https://dl.k8s.io/release/$kubectl_version/bin/linux/amd64/kubectl" "$kubectl_sha256"
helm "$helm3_version" "$helm3_sha256"
helm "$helm4_version" "$helm4_sha256"

cd "$root"
export KITH_KUBECTL="$cache/kubectl-$kubectl_version" KITH_HELM="$cache/helm-$helm3_version/linux-amd64/helm:$cache/helm-$helm4_version/linux-amd64/helm"
[ "${1:-}" != --vm ] || exec sh ci/vm.sh --test kube
# What kubectl and helm send as protobuf is read by a table: it must be the one
# Kubernetes's own types give (they are fetched once, by hash, like the clients).
python3 ci/kube_proto.py --check || fail "crates/kithd/src/kubeproto.txt is not what ci/kube_proto.py writes"
cargo test -q -p kithd --test kube "$@"
