#!/bin/bash
# Run INSIDE a kith container by ci/vm.sh --test nested (the image it is in has bash, bwrap, unshare,
# kithd and kith, copied from the machine that builds it): what a second runtime and kithd in agent
# mode meet there. Each step says what it found, and the last line ("row: ...") is the one ci/stress.sh
# --nested keeps in ci/stress.txt. Nothing here changes a default; it only asks.
export PATH=/bin
one() { local v=unreadable; [ -r "$1" ] && IFS= read -r v <"$1"; echo "$v"; } # the first line of a file
status() { local l; while IFS= read -r l; do case $l in "$1:"*) l=${l#*:}; echo "${l//[[:space:]]/}"; return ;; esac; done </proc/self/status; echo "?"; }
squeeze() { local s=${1//$'\n'/ }; s=${s//|/;}; echo "${s:0:${2:-200}}"; } # one line, no bar, cut

# (1) What this container is, and what the guest kernel says of namespaces and cgroups.
uid=$UID
outer="uid=$uid seccomp=$(status Seccomp) no_new_privs=$(status NoNewPrivs) cap_bnd=$(status CapBnd) uid_map=$(squeeze "$(one /proc/self/uid_map)" 40)"
if { : >/probe-write; } 2>/dev/null; then outer="$outer image=writable"; else outer="$outer image=read-only"; fi
kernel="kernel=$(one /proc/sys/kernel/osrelease) max_user_namespaces=$(one /proc/sys/user/max_user_namespaces)"
kernel="$kernel unprivileged_userns_clone=$(one /proc/sys/kernel/unprivileged_userns_clone) apparmor_restrict_unprivileged_userns=$(one /proc/sys/kernel/apparmor_restrict_unprivileged_userns)"
cg="cgroup=$(squeeze "$(one /proc/self/cgroup)" 60) controllers=$(squeeze "$(one /sys/fs/cgroup/cgroup.controllers)" 60)"
cgmount=none
# shellcheck disable=SC2086 # (the mount's fields)
while IFS= read -r l; do case $l in *" /sys/fs/cgroup cgroup2 "*) set -- $l; cgmount=$4 ;; esac; done </proc/self/mounts
cg="$cg mount=$(squeeze "$cgmount" 40)"
if said=$(mkdir /sys/fs/cgroup/probe 2>&1); then cg="$cg subgroup=made"; rmdir /sys/fs/cgroup/probe; else cg="$cg subgroup=refused ($(squeeze "${said##*: }" 50))"; fi
if [ -w /sys/fs/cgroup/cgroup.subtree_control ]; then cg="$cg subtree_control=writable"; else cg="$cg subtree_control=read-only"; fi
echo "outer: $outer"; echo "guest: $kernel $cg"

# (2) A user namespace of its own, the least a second runtime asks.
# shellcheck disable=SC2016 # (the inner shell expands $(id -u))
if said=$(unshare --user --map-root-user /bin/sh -c 'echo uid $(id -u)' 2>&1); then userns="ok ($said)"; else userns="refused: $(squeeze "$said" 120)"; fi
echo "userns: $userns"

# (3) A second runtime: bubblewrap, a sandbox of its own (a user namespace, a pid namespace, /proc and /dev made new).
if said=$(timeout 60 bwrap --unshare-user --uid 0 --gid 0 --unshare-pid --ro-bind / / --proc /proc --dev /dev /bin/pod self 2>&1); then second="ran ($(squeeze "$said" 80))"; else second="refused: $(squeeze "$said" 300)"; fi
echo "bwrap: $second"

# (4) kithd in agent mode, and a container of its own.
k=/state/k
mkdir -p $k/runtime && cp -r /seed/runtime/. $k/runtime/
timeout 120 kithd --state $k --socket $k/kithd.sock >$k/kithd.log 2>&1 &
for _ in $(seq 1 30); do [ -S $k/kithd.sock ] && break; sleep 1; done
if [ -S $k/kithd.sock ]; then
    sleep 3
    daemon="serving"
    if kith --socket $k/kithd.sock apply -f /inner-job.json >$k/apply.out 2>&1; then
        for _ in $(seq 1 60); do
            got=$(kith --socket $k/kithd.sock logs Job/inner 2>&1)
            case $got in *'nested:'*) break ;; esac
            sleep 1
        done
        case $got in *'nested:'*) inner="ran ($(squeeze "$got" 60))" ;; *) inner="did not run: $(squeeze "$(grep -h 'will not run' $k/kithd.log)" 120); its status: $(squeeze "$(kith --socket $k/kithd.sock get Job/inner -o json 2>&1 | tr -d '\n' | grep -o '"status":.*')" 500)" ;; esac
    else inner="not applied: $(squeeze "$(<$k/apply.out)" 200)"; fi
else
    daemon="did not serve"
    inner="no daemon"
fi
echo "kithd log: $(squeeze "$(tail -n 12 $k/kithd.log)" 1500)"
echo "kithd: $daemon; its container: $inner"
echo "row: $outer | guest: $kernel $cg | user namespace: $userns | bwrap: $second | kithd: $daemon; its container: $inner"
