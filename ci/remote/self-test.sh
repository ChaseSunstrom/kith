# shellcheck shell=sh disable=SC2154 # (part, vm_script and self are ci/remote.sh's)
# `sh ci/remote.sh --self-test`, sourced by it: the bundle, the partition, the Jobs and the merged
# report, offline, with a GitHub made of a folder and a cargo that only lists and prints; and
# --vm's Device, claim, Job, schedule and script.
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
    # (its ci/vm.sh passes alone, if tar would leave a file's owner be, skips skipme as ci/vm.sh
    # skips, and fails the rest)
    mkdir "$t/w/ci"
    # shellcheck disable=SC2016 # (the stub's)
    printf '%s\n' '[ "$1" = --test ] || exit 9' 'case $2 in alone) [ "${TAR_OPTIONS-}" = --no-same-owner ] || { echo "vm.sh: FAIL: tar keeps owners"; exit 1; }; echo "vm.sh: ok: alone" ;; skipme) echo "skipped: no KVM"; exit 0 ;; *) echo "vm.sh: FAIL: $2"; exit 1 ;; esac' >"$t/w/ci/vm.sh"
    # shellcheck disable=SC2016 # (the stub's)
    printf '%s\n' 'echo "kube.sh $*" >>"$FAKE_RAN"' 'echo "kube.sh: skipped: could not fetch kubectl" >&2' >"$t/w/ci/kube.sh"
    echo three >"$t/w/f" && echo x >"$t/w/g" && git -C "$t/w" add g ci && git -C "$t/w" commit -qam three
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
    # --vm: a Device of the node's /dev/kvm that namespace ci alone may claim, a shared claim of it,
    # and a Job that names the claim and runs as 1000 with no field of the Job's security beyond fan's
    d=$(dev_json n1)
    echo "$d" | jq -e '.[0] | .kind == "Device" and .metadata.name == "ci-kvm-n1" and .spec == {node: "n1", class: "other", path: "/dev/kvm"} and .metadata.labels["kith.dev/node"] == "n1" and .metadata.labels["kith.dev/namespaces"] == "ci"' >/dev/null || die "no Device of n1's /dev/kvm for ci alone: $d"
    echo "$d" | jq -e '.[1] | .kind == "DeviceClaim" and .metadata.name == "ci-kvm-n1" and .spec == {device: "ci-kvm-n1", access: "shared"}' >/dev/null || die "no shared claim of it: $d"
    j=$(vm_job_json j n1 alone "$c" "$bases")
    echo "$j" | jq -e '.[0].spec.template | .deviceClaims == ["ci-kvm-n1"] and (.containers[0] | .runAsUser == 1000 and (keys - ["name", "image", "runAsUser", "userNamespaces", "env", "volumeMounts", "command"]) == [] and (.volumeMounts | map(.volume) | index("ci-n1")) != null and (.env | map(select(.name == "TEST" and .value == "alone")) | length == 1))' >/dev/null || die "the Job does not claim ci-kvm-n1 as 1000: $j"
    ok "--vm: a Device of each node's /dev/kvm, a shared claim, and a Job that names it, as 1000"
    # all that a run applies and asks for, fan's and --vm's, is in namespace ci: the API stubbed
    : >"$t/applied" && : >"$t/paths" && mkdir "$t/ns"
    # shellcheck disable=SC2030,SC2034,SC2317 # (the stubs are the subshell's)
    (
        api() {
            echo "$1" >>"$t/paths"
            case $1 in
            apply) cat >>"$t/applied" ;;
            volumes/*) cat >/dev/null ;;
            resources/*) echo '{"status": {"state": "succeeded"}}' ;;
            logs/*) echo '{"data": "SUMMARY exit=0"}' ;;
            esac
        }
        sleep() { :; }
        timeout=1
        mkdir "$t/ns/in" && : >"$t/ns/in/x.bundle"
        one n1 0 2 "$c" "$bases" --workspace "$t/ns"
        one n2 1 2 "$c" "$bases" "" "$t/ns" alone
    ) || die "one, its API stubbed, failed"
    jq -s -e 'add | length == 6 and all(if .kind == "Device" then .metadata.labels["kith.dev/namespaces"] == "ci" and .metadata.namespace == null else .metadata.namespace == "ci" end)' "$t/applied" >/dev/null || die "an object applied outside namespace ci: $(cat "$t/applied")"
    ! grep -vE '^(apply|(resources/Job|logs/Job|volumes)/ci/.)' "$t/paths" || die "an API path outside namespace ci"
    ok "every object a run applies (Volume, Job, claim) is in namespace ci; the Device is granted to ci alone"
    # one test per node at a time, each test once: the cluster's answers stubbed, one as it is (a
    # Job named ci-NODE-COMMIT-TEST-TIME starts at its apply and ends at its log)
    : >"$t/sched"
    # shellcheck disable=SC2030,SC2034,SC2317 # (the stubs and names are the subshell's)
    rep=$(
        cd "$t/w" || exit 1
        api() {
            case $1 in
            resources) echo '[{"kind": "Node", "metadata": {"name": "n2"}, "status": {"state": "ready"}}, {"kind": "Node", "metadata": {"name": "n1"}, "status": {"state": "ready"}}]' ;;
            apply) jq -r '.[] | select(.kind == "Job") | .metadata.name | split("-") | "start \(.[1]) \(.[3])"' >>"$t/sched" ;;
            volumes/*) cat >/dev/null ;;
            resources/*) echo '{"status": {"state": "succeeded"}}' ;;
            logs/*)
                echo "${1##*/}" | awk -F- '{print "end", $2, $4}' >>"$t/sched"
                echo "${1##*/}" | awk -F- '{print "{\"data\": \"SUMMARY exit=0 test=" $4 "\"}"}'
                ;;
            esac
        }
        sleep() { :; }
        timeout=1
        KITH_REMOTE=a:1 KITH_REMOTE_CREDS=$t
        vm a,b,c,d,e HEAD
    ) || die "--vm, every test passing, failed: $rep"
    [ "$(sed -n 's/^start //p' "$t/sched" | sort)" = "$(printf '%s\n' 'n1 a' 'n1 c' 'n1 e' 'n2 b' 'n2 d')" ] || die "the tests were not spread one each over n1, n2: $(cat "$t/sched")"
    for node in n1 n2; do
        [ "$(grep " $node " "$t/sched" | cut -d' ' -f1 | uniq -c | awk '$1 != 1' | wc -l)" = 0 ] || die "$node ran two tests at once: $(cat "$t/sched")"
    done
    echo "$rep" | grep -q '^result: all passed$' || die "no merged result: $rep"
    ok "--vm: tests spread over the nodes, one at a time on each, every one once, one merged result"
    # the Job's script, run here: the root and mounts of a user namespace stubbed, a ci/vm.sh in the
    # commit that passes alone, skips skipme and fails broken: a skip fails the run as a failure does
    cat >"$t/bin/unshare" <<'EOF'
#!/bin/sh
while case $1 in -*) true ;; *) false ;; esac; do shift; done
exec "$@"
EOF
    printf '#!/bin/sh\nshift\nexec "$@"\n' >"$t/bin/chroot"
    printf '#!/bin/sh\nexit 0\n' >"$t/bin/mount"
    for x in apt-get rustup; do
        # shellcheck disable=SC2016 # (the stub's)
        printf '#!/bin/sh\necho "%s $*" >>"$FAKE_RAN"\n' "$x" >"$t/bin/$x"
    done
    chmod +x "$t/bin/unshare" "$t/bin/chroot" "$t/bin/mount" "$t/bin/apt-get" "$t/bin/rustup"
    mkdir -p "$t/from/etc" "$t/from/usr" "$t/vm"
    : >"$t/ran" && : >"$t/vm/failures.txt"
    i=0
    for x in alone skipme broken; do
        echo "n$((i + 1))" >"$t/vm/$i.node" && echo succeeded >"$t/vm/$i.state"
        code=0
        # shellcheck disable=SC2030,SC2031 # (the PATH is the subshell's: the node's)
        (
            export CACHE="$t/vc" WORK="$t/vw$i" REPO="file://$t/gh.git" COMMIT="$c" BASES="$bases" TEST="$x" PKGS="qemu socat" \
                FROM="$t/from" SCRIPT="$vm_script" PATH="$t/bin:$PATH" FAKE_RAN="$t/ran"
            mkdir -p "$CACHE/in" && cp "$t/dir/in/"* "$CACHE/in/"
            sh -c "$SCRIPT"
        ) >"$t/vm/$i.log" 2>&1 || code=$?
        case $x in alone) [ "$code" = 0 ] ;; *) [ "$code" != 0 ] ;; esac || die "--vm $x: exit $code: $(cat "$t/vm/$i.log")"
        i=$((i + 1))
    done
    grep -q '^SUMMARY exit=3 test=skipme .*why=skipped: no KVM$' "$t/vm/1.log" || die "a skip is not exit 3 with its reason: $(cat "$t/vm/1.log")"
    [ "$(grep -c '^apt-get .* install .*qemu socat' "$t/ran")" = 1 ] || die "the tools were not installed once, then kept: $(cat "$t/ran")"
    rep=$(report "$t/vm" 3) && die "a skipped test gave exit 0: $rep"
    for x in 'n2: skipme' 'n3: broken'; do
        echo "$rep" | grep -qx "FAILED: $x" || die "the report does not name $x: $rep"
    done
    ! echo "$rep" | grep -q '^FAILED: n1' || die "the test that passed is named failed: $rep"
    ok "--vm: a skipped test fails the run as a failed one does, named with its node; the tools installed once and kept; tar leaves owners be"
    # rollout and kube: what a machine of one's own has, the Job makes first
    # shellcheck disable=SC2016 # (the stub's)
    printf '#!/bin/sh\necho "cargo $*" >>"$FAKE_RAN"\n' >"$t/bin/cargo" && chmod +x "$t/bin/cargo"
    for x in rollout kube; do
        # shellcheck disable=SC2030,SC2031 # (as above)
        (
            export CACHE="$t/vc" WORK="$t/vw$x" REPO="file://$t/gh.git" COMMIT="$c" BASES="$bases" TEST="$x" PKGS="qemu socat" \
                FROM="$t/from" SCRIPT="$vm_script" PATH="$t/bin:$PATH" FAKE_RAN="$t/ran"
            sh -c "$SCRIPT"
        ) >"$t/vm/$x.log" 2>&1 || true
    done
    grep -qx 'cargo build -q -p kith-cli --bin kith --target-dir target' "$t/ran" || die "rollout's kith was not built where its test runs it: $(cat "$t/ran")"
    grep -qx 'kube.sh --vm' "$t/ran" || die "kube did not go by ci/kube.sh --vm (which fetches kubectl and helm): $(cat "$t/ran")"
    grep -q '^SUMMARY exit=3 test=kube .*why=kube.sh: skipped: could not fetch kubectl$' "$t/vm/kube.log" || die "ci/kube.sh's skip is not a failure: $(cat "$t/vm/kube.log")"
    ok "--vm: rollout has the checkout's kith built in its target folder; kube goes by ci/kube.sh --vm, whose skip fails too"
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
