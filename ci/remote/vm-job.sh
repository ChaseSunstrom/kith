#!/bin/sh
# What a node runs for one VM test (TEST) of `sh ci/remote.sh --vm`: its Job's command, and SCRIPT
# (this text), which it runs again as root of a user namespace of its own (`mounts`: that root is
# the Job's user, 1000) chrooted into CACHE/vmroot: a copy of the image's root (FROM) with PKGS,
# owned by 1000, so apt can install into it (`tools`) and the test runs in it (`run`). It takes
# CACHE (the node's Volume), WORK (scratch), REPO, COMMIT, BASES, PKGS and CAP_MB (the size in MB
# at which the cache's target folder is dropped, 30000 unless given). The checkout is as
# ci/remote.sh's Jobs make it; KITH_OS_CACHE, cargo's registry and target folder stay in the
# Volume, so a second run is warm. A test that ci/vm.sh skips exits 3 with why=skipped: ..., as a
# failure. Its last line is SUMMARY.
# shellcheck disable=SC2086 # (PKGS and BASES are words)
cache=${CACHE:-/cache} work=${WORK:-/work}
root=$cache/vmroot
case ${1-} in
mounts)
    for d in /proc /dev /sys /tmp "$cache" "$work"; do mkdir -p "$root$d" && mount --rbind "$d" "$root$d" || exit 1; done
    mkdir -p "$root/run" && mount -t tmpfs run "$root/run" || exit 1
    [ ! -f /etc/resolv.conf ] || cp /etc/resolv.conf "$root/etc/resolv.conf"
    exec chroot "$root" sh -c "$SCRIPT" vm "$2" ;;
tools)
    export DEBIAN_FRONTEND=noninteractive
    set -- -q -o APT::Sandbox::User=root -o "Dir::Cache::archives=$cache/apt/archives" -o "Dir::State::Lists=$cache/apt/lists"
    # (A node whose clock is behind refuses the newest lists as not yet signed; the rest still serve.)
    apt-get "$@" update || true
    apt-get "$@" -y install --no-install-recommends $PKGS && rustup target add x86_64-unknown-linux-musl
    exit ;;
run)
    # kith's pod seccomp answers EPERM to FS_IOC_SETFLAGS, and systemd-repart (--empty=create sets
    # NOCOW) gives up on any error but "not supported": this shim says that, as tmpfs would.
    shim=$cache/ci-nocow.so
    # (Built to a name of its own and moved: a build cut short must not leave half a file there to be kept.)
    [ -f "$shim" ] || { gcc -shared -fPIC -x c -o "$shim.$$" - <<'EOF' && mv "$shim.$$" "$shim"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <linux/fs.h>
int ioctl(int fd, unsigned long req, ...) {
    static int (*real)(int, unsigned long, ...);
    va_list ap;
    va_start(ap, req);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    if (req == FS_IOC_SETFLAGS) { errno = EOPNOTSUPP; return -1; }
    if (!real) real = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT, "ioctl");
    return real(fd, req, arg);
}
EOF
    } || { rm -f "$shim.$$"; exit 1; }
    cd "$cache/src" || exit 1
    # (Root here is the Job's user, the one uid this namespace maps: tar, as root, would give a file
    # its owner in the archive, a uid not mapped, and fail on it. TAR_OPTIONS keeps the files ours.)
    export LD_PRELOAD="$shim" TAR_OPTIONS=--no-same-owner HOME="$work" TMPDIR=/tmp CARGO_HOME="$cache/cargo" \
        CARGO_TARGET_DIR="$cache/target" KITH_OS_CACHE="$cache/os" XDG_CACHE_HOME="$cache/xdg"
    # (What a machine of one's own has: rollout signs with the checkout's kith from target/debug;
    # kube wants kubectl and helm, which ci/kube.sh --vm fetches, checked by their hashes.)
    case $TEST in
    rollout) cargo build -q -p kith-cli --bin kith --target-dir target || exit 1 ;;
    kube) exec sh ci/kube.sh --vm ;;
    esac
    exec sh ci/vm.sh --test "$TEST" ;;
esac
mkdir -p "$cache" "$work" && exec 9>"$cache/lock" && flock 9 || exit 1
t0=$(date +%s)
end() { [ "$1" = 0 ] || echo "FAILED $TEST"; echo "SUMMARY exit=$1 test=$TEST host=$(hostname) secs=$(($(date +%s) - t0)) $2"; exit "$1"; }
cd "$cache" && mkdir -p in src cargo os apt/archives/partial apt/lists/partial
find in -type f -mtime +1 -delete
# (The cargo target folder only grows: dropped at CAP_MB, as ci/remote.sh's own Jobs drop theirs.)
mb=$(du -sm target 2>/dev/null | cut -f1); [ "${mb:-0}" -lt "${CAP_MB:-30000}" ] || rm -rf target
cd src && { [ -d .git ] || git init -q; }
git fetch -q --depth 1 "$REPO" $BASES || end 2 why=fetch
[ ! -f "../in/$COMMIT.bundle" ] || git bundle unbundle "../in/$COMMIT.bundle" >/dev/null || end 2 why=bundle
{ git checkout -q -f --detach "$COMMIT" && git clean -fdq; } || end 2 why=checkout
want="$(cat /etc/debian_version 2>/dev/null) $(rustc --version 2>/dev/null) $PKGS"
if [ "$(cat "$root.stamp" 2>/dev/null)" != "$want" ]; then
    chmod -R u+w "$root" 2>/dev/null; rm -rf "$root" "$root.stamp"; mkdir -p "$root"
    for d in bin etc lib lib64 sbin usr var opt; do [ ! -e "${FROM-}/$d" ] || cp -a --one-file-system "${FROM-}/$d" "$root/" 2>/dev/null; done
    unshare -r -m sh -c "$SCRIPT" vm mounts tools >"$work/tools.txt" 2>&1 || { tail -40 "$work/tools.txt"; end 2 why=tools; }
    echo "$want" >"$root.stamp"
fi
code=0
unshare -r -m sh -c "$SCRIPT" vm mounts run >"$work/out.txt" 2>&1 || code=$?
tail -200 "$work/out.txt"
why=$(grep -m1 -E "^(kube\.sh: )?skipped: " "$work/out.txt" || true)
[ -z "$why" ] || code=3
end "$code" "${why:+why=$why}"
