# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# shellcheck disable=SC2015,SC2295 # (as the script had them before it was cut)
# Sourced by ci/vm.sh for --test quota: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # Each case that held says `quota: ok: CASE`; at the end every one must have.
            : >"$work/oks"
            ok() { echo "quota: ok: $1"; echo "$1" >>"$work/oks"; }
            # KIND NAME MORE STEP ...: a pod that runs `pod quota STEP ...` (ci/pod.rs), MORE more
            # of its container; what it said is in $work/NAME.out once it is done.
            quota() {
                kind=$1 name=$2 extra=$3
                shift 3
                steps=$(printf '"%s",' "$@")
                spec='"replicas":1,'
                [ "$kind" = Workload ] || spec='"selector":{},'
                cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"$kind","metadata":{"name":"$name"},"spec":{$spec"template":{"pod":true,"containers":[
  {"name":"quota","image":"kith.test/pod:1","command":["/bin/pod","quota",${steps%,}]$extra}]}}}]
EOF
                any POST /v1/apply "$work/apply.json" >/dev/null || fail "the $kind $name was not applied"
            }
            done_() { # KIND NAME: wait for it to have said all it does
                waited=0
                until grep -q 'quota: done' "$work/$2.out" 2>/dev/null; do
                    for replica in 0 1 2 3; do
                        any GET "/v1/logs/$1/default/$2?replica=$replica" >"$work/$2.out" 2>/dev/null && grep -q 'quota: done' "$work/$2.out" && break
                    done
                    waited=$((waited + 1))
                    [ "$waited" -lt 300 ] || fail "waited for the $1 $2 to be done; it says: $(units "$1" "$2"): $(cat "$work/$2.out" 2>/dev/null)"
                    sleep 1
                done
            }
            gone() { api 1 DELETE "/v1/resources/$1/default/$2" >/dev/null || fail "the $1 $2 was not deleted"; }
            # What NAME said of STEP (its log comes as JSON: the lines are in its strings).
            result() {
                python3 -c '
import json, sys
def strings(v):
    if isinstance(v, str):
        yield v
    for x in (v.values() if isinstance(v, dict) else v if isinstance(v, list) else []):
        yield from strings(x)
try:
    log = json.load(open(sys.argv[1]))
except ValueError:
    sys.exit(1)
said = [l[len(sys.argv[2]) + 1:] for s in strings(log) for l in s.splitlines() if l.startswith(sys.argv[2] + " ")]
print(said[-1] if said else "nothing", end="")
' "$work/$1.out" "quota: $2"
            }
            expect() { # NAME STEP PATTERN (grep -E, all of what it said) WHAT-IT-SHOWS
                got=$(result "$1" "$2")
                printf '%s\n' "$got" | grep -Eqx "$3" || fail "$1: $2 said \"$got\": $4"
            }
            stopped() { # NAME STEP LIMIT: the write failed at the kernel's quota, at most LIMIT in
                got=$(result "$1" "$2")
                wrote=$(printf '%s\n' "$got" | sed -n 's/^failed after \([0-9]*\): .* (os error 122)$/\1/p')
                [ -n "$wrote" ] && [ "$wrote" -le "$3" ] || fail "$1: $2 said \"$got\": not stopped at the write at its limit of $3 bytes"
            }
            used() { # NAME STEP LIMIT: statfs of its project's directory says its limit, and no more used
                got=$(result "$1" "$2")
                case $got in "size $3 used "*) ;; *) fail "$1: $2 said \"$got\": its project's limit is not $3" ;; esac
                got=${got#size $3 used }
                [ "${got%% *}" -le "$3" ] || fail "$1: $2 holds ${got%% *} bytes, past its limit of $3"
            }
            free() { # NAME: what the state disk has free, as a pod with a Volume there sees it
                quota Workload "$1" ',"volumeMounts":[{"volume":"free","path":"/free"}]' '#/free'
                done_ Workload "$1"
                gone Workload "$1"
                got=$(result "$1" '#/free')
                printf '%s\n' "${got##* }" | grep -Eqx '[0-9]+' || fail "$1: #/free said \"$got\""
                echo "${got##* }"
            }

            # kithd says once how it holds pods' limits, and the Node says it too.
            grep -aq "kithd: pods' storage limits are held at the write, by the state disk's project quota" "$work/n1.log" \
                || fail "kithd did not say it holds pods' storage limits at the write: $(grep -a 'storage limits' "$work/n1.log")"
            waited=0
            until storage=$(any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
try:
    found = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
for r in found:
    if r["kind"] == "Node" and r["metadata"]["name"] == "n1":
        print(((r.get("status") or {}).get("os") or {}).get("storage", ""), end="")
') && [ -n "$storage" ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the Node n1 did not say how it holds pods' storage limits"
                sleep 1
            done
            [ "$storage" = "at the write, by the state disk's project quota" ] || fail "the Node n1 says its pods' limits are held $storage"
            ok said

            # An id given again: a pod of 64Ki (the first given a project, so the lowest id) runs
            # and is removed; kithd starts again, and gives the next pod the lowest id with nothing
            # in it, the same. That pod, whose image and scratch it changes are past 64Ki, starts
            # and is held to its own limit, not the one before.
            # What this does not show: that the stale limit is cleared. kithd sets a project's
            # limit before anything is put in it, but kithd is root with CAP_SYS_RESOURCE, and
            # the kernel lets such a writer past a hard limit (dquot.c, ignore_hardlimit): with
            # the 64Ki left on the id, the pod's start passes all the same. (Run against a kithd
            # that left it, this case held too.) It shows an id given again, and its new limit.
            quota Workload tiny ',"resources":{"storage":"64Ki"}' '?/' '+/fill:131072'
            done_ Workload tiny
            stopped tiny '+/fill:131072' 65536
            was=$(result tiny '?/')
            printf '%s\n' "$was" | grep -Eqx 'project [1-9][0-9]*' || fail "tiny: its root is in no project of its own: $was"
            gone Workload tiny
            # (Its replica directory goes at kithd's next pass once its unit has; a kithd that
            # starts with it there gives ids past it.)
            waited=0
            while [ -n "$(units Workload tiny)" ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "the Workload tiny was not removed: $(units Workload tiny)"
                sleep 1
            done
            sleep 10
            # Started again as a machine is when its power button is pressed: kithd stops, and
            # the node comes back up from its disk.
            echo 'sendkey ctrl-alt-delete' | socat - "unix-connect:$work/keys1" >/dev/null || fail "QEMU's monitor of n1 did not answer"
            waited=0
            until [ "$(grep -ac "kithd: pods' storage limits are held at the write" "$work/n1.log")" -ge 2 ] && any GET /v1/resources >/dev/null 2>&1; do
                waited=$((waited + 1))
                [ "$waited" -lt 300 ] || fail "n1 did not start again holding pods' limits at the write: $(grep -a 'storage limits\|reboot:' "$work/n1.log")"
                sleep 1
            done
            grep -aq 'reboot: Restarting system' "$work/n1.log" || fail "n1 did not restart: its console says no 'reboot: Restarting system'"
            quota Workload again ',"resources":{"storage":"64Mi"},"volumeMounts":[{"scratch":"work","path":"/work"}]' '?/' '^/big' '+/work/fill:1048576' '+/fill:209715200' '#/'
            done_ Workload again
            expect again '?/' "$was" "the pod after kithd started again was not given the removed pod's id, so no id was given again"
            expect again '^/big' ok "a file of its image past the last limit of its id was not copied up"
            expect again '+/work/fill:1048576' 'wrote 1048576' "its scratch was held to the last limit of its id"
            stopped again '+/fill:209715200' 67108864
            used again '#/' 67108864
            waited=0
            until line=$(units Workload again) && [ "${line%% *}" = 1 ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "the Workload again is not ready: $line"
                sleep 1
            done
            gone Workload again
            echo "vm.sh: again: $was given again after kithd started again; held to 64 MiB, not 64Ki" >&2
            ok again

            # A pod of 64 MiB writing 200 MiB, in its root and then its scratch, beside one writing
            # 32 MiB: the first is stopped at the write, the second loses none, and the disk loses
            # no more than both their limits let them (and 4 MiB of kithd's own). It is in a user
            # namespace of its own (a Workload's pod, with a network of its own), so its root's
            # overlay was mounted by that namespace's root; its scratch it writes itself.
            cat >"$work/apply.json" <<EOF
[{"apiVersion":"kith.dev/v1","kind":"Volume","metadata":{"name":"free"},"spec":{"node":"n1","path":"free"}}]
EOF
            any POST /v1/apply "$work/apply.json" >/dev/null || fail "the Volume free was not applied"
            limit=67108864 storage=',"resources":{"storage":"64Mi"}'
            for case in write scratch; do
                to=/fill more=$storage
                [ "$case" = write ] || { to=/work/fill more="$storage,\"volumeMounts\":[{\"scratch\":\"work\",\"path\":\"/work\"}]"; }
                before=$(free "before-$case")
                quota Workload "big-$case" "$more" '@' "+$to:209715200" "#${to%/fill}/"
                quota Workload "small-$case" "$more" "+$to:33554432"
                done_ Workload "big-$case"
                done_ Workload "small-$case"
                after=$(free "after-$case")
                expect "big-$case" '@' '0 [1-9][0-9]* [0-9]+' "a Workload's pod with a network of its own has the node's users"
                stopped "big-$case" "+$to:209715200" "$limit"
                used "big-$case" "#${to%/fill}/" "$limit"
                expect "small-$case" "+$to:33554432" 'wrote 33554432' "a pod beside one at its limit lost a write"
                [ $((before - after)) -le $((limit + 33554432 + 4194304)) ] || fail "$case: the state disk lost $((before - after)) bytes to two pods of 64 MiB, one writing 32 MiB"
                # Its status says it holds all it may, and it is not replaced for it.
                waited=0
                until line=$(units Workload "big-$case") && printf '%s\n' "$line" | grep -q 'reached its storage limit'; do
                    waited=$((waited + 1))
                    [ "$waited" -lt 60 ] || fail "big-$case's status does not say it reached its storage limit: $line"
                    sleep 1
                done
                sleep 12
                any GET "/v1/logs/Workload/default/big-$case?replica=0" >"$work/big-$case.out" 2>/dev/null || true
                [ "$(grep -o 'quota: done' "$work/big-$case.out" | wc -l)" = 1 ] || fail "big-$case was started again: $(cat "$work/big-$case.out")"
                ! grep -aq 'replaced: its pod wrote' "$work/n1.log" || fail "a pod held to its limit was replaced: $(grep -a 'replaced: its pod wrote' "$work/n1.log")"
                gone Workload "big-$case"
                gone Workload "small-$case"
                echo "vm.sh: $case: stopped at $wrote bytes of 200 MiB; the disk lost $((before - after)) bytes; $line" >&2
                ok "$case"
            done

            # A file it removed and holds open, with no name to find: charged all the same.
            # ("~" is ci/pod.rs's word for a file written, then removed: no home folder.)
            # shellcheck disable=SC2088
            held="~/fill:209715200"
            quota Workload unlinked "$storage" "$held"
            done_ Workload unlinked
            stopped unlinked "$held" "$limit"
            gone Workload unlinked
            ok unlinked

            # A pod of 64 MiB making empty files, beside one making 100: the first is stopped at
            # the files its limit lets it on this disk (its share of the disk's files, 4096 at
            # least), as statfs of its root says them; the one beside it makes all of its own;
            # and the first's status says it holds them all, in files.
            quota Workload many "$storage" '*/many:1000000' '%/'
            quota Workload few "$storage" '*/few:100'
            done_ Workload many
            done_ Workload few
            got=$(result many '*/many:1000000')
            made=$(printf '%s\n' "$got" | sed -n 's/^made \([0-9]*\), then: .* (os error 122)$/\1/p')
            [ -n "$made" ] && [ "$made" -ge 1 ] || fail "many: making files said \"$got\": not stopped at the kernel's quota"
            got=$(result many '%/')
            most=$(printf '%s\n' "$got" | sed -n 's/^files \([0-9]*\) held [0-9]*$/\1/p')
            [ -n "$most" ] && [ "$most" -ge 4096 ] && [ "$made" -le "$most" ] && [ "$got" = "files $most held $most" ] \
                || fail "many: it made $made files, and statfs of its root said \"$got\": not held at a file limit of 4096 or more"
            expect few '*/few:100' 'made 100' "a pod beside one at its file limit made no file"
            waited=0
            until line=$(units Workload many) && printf '%s\n' "$line" | grep -Eq 'reached its storage limit: its pod holds [0-9]+ files outside its volumes'; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "many's status does not say it holds all its files: $line"
                sleep 1
            done
            gone Workload many
            gone Workload few
            echo "vm.sh: files: stopped after $made files made, at the $most its 64 MiB let it; $line" >&2
            ok files

            # The root of a pod with the node's users (a NodeWorkload's): its overlay was mounted
            # by the node's root with every capability, CAP_SYS_RESOURCE too, which lets a writer
            # past a project's hard limit. The kernel leaves that one out of the credentials an
            # overlay writes its upper layer with (fs/overlayfs/super.c, "Never override disk
            # quota limits"), so it is held all the same: a new file past its limit, and, in both
            # kinds of pod, a file of its image copied up near its limit (12 MiB with 8 of 16
            # written), refused whole and left as the image has it.
            quota NodeWorkload nodewrite "$storage" '@' '+/fill:209715200' '#/'
            copy=',"resources":{"storage":"16Mi"}'
            quota Workload copyup "$copy" '+/pad:8388608' '^/big' '=/big' '+/fill:16777216' '#/'
            quota NodeWorkload nodecopyup "$copy" '@' '+/pad:8388608' '^/big' '=/big' '+/fill:16777216' '#/'
            done_ NodeWorkload nodewrite
            expect nodewrite '@' '0 0 4294967295' "a NodeWorkload's pod does not have the node's users"
            stopped nodewrite '+/fill:209715200' "$limit"
            used nodewrite '#/' "$limit"
            echo "vm.sh: nodewrite: the node's root stopped at $wrote bytes of 200 MiB in its root" >&2
            gone NodeWorkload nodewrite
            ok nodewrite
            for name in copyup nodecopyup; do
                kind=Workload
                [ "$name" = copyup ] || kind=NodeWorkload
                done_ "$kind" "$name"
                [ "$kind" = Workload ] || expect "$name" '@' '0 0 4294967295' "a NodeWorkload's pod does not have the node's users"
                expect "$name" '+/pad:8388608' 'wrote 8388608' "a pod of 16 MiB could not write 8 MiB"
                expect "$name" '^/big' '.* \(os error 122\)' "a file of its image of 12 MiB was copied up with 8 MiB of 16 written"
                expect "$name" '=/big' 'size 12582912' "a copy-up refused at its limit changed the file of its image"
                stopped "$name" '+/fill:16777216' 16777216
                used "$name" '#/' 16777216
                echo "vm.sh: $name: the copy-up of 12 MiB failed: $(result "$name" '^/big'); /big $(result "$name" '=/big'); then stopped at $wrote" >&2
                gone "$kind" "$name"
                ok "$name"
            done

            # Moving its files out of its project: in a user namespace the kernel refuses; as the
            # node's root (a NodeWorkload's pod) its filter does; unconfined nothing does, and
            # what it then writes is counted, and it is replaced for it.
            quota Workload userns '' '+/esc:1' '0/esc' '!/esc' '?/esc'
            quota NodeWorkload noderoot '' '+/esc:1' '0/esc' '!/esc' '?/esc'
            done_ Workload userns
            done_ NodeWorkload noderoot
            for step in 0/esc '!/esc'; do
                expect userns "$step" '.* \(os error 22\)' "a pod in a user namespace moved its file out of its project"
                expect noderoot "$step" '.* \(os error 1\)' "a pod as the node's root moved its file out of its project"
            done
            expect userns '?/esc' 'project [1-9][0-9]*' "its file is not in its pod's project"
            expect noderoot '?/esc' 'project [1-9][0-9]*' "its file is not in its pod's project"
            gone Workload userns
            gone NodeWorkload noderoot
            ok userns
            ok noderoot
            quota NodeWorkload unconfined "$storage,\"seccomp\":{\"unconfined\":true}" '+/esc:1' '0/esc' '?/esc' '+/esc:104857600'
            done_ NodeWorkload unconfined
            expect unconfined 0/esc ok "an unconfined pod as the node's root could not move its file out of its project"
            expect unconfined '?/esc' 'project 0' "an unconfined pod's file stayed in its project"
            expect unconfined '+/esc:104857600' 'wrote 104857600' "a file out of its project took less than it wrote"
            waited=0
            until grep -aq 'replaced: its pod wrote [0-9]* bytes outside its volumes, over its limit of 67108864' "$work/n1.log"; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "an unconfined pod that wrote past its limit out of its project was not replaced"
                sleep 1
            done
            gone NodeWorkload unconfined
            ok unconfined

            # Its file linked and renamed to elsewhere: another file system (its Volume; another
            # pod's root is not in its).
            quota Workload elsewhere ',"volumeMounts":[{"volume":"free","path":"/free"}]' '+/mine:1' '&/mine:/free/linked' '>/mine:/free/moved'
            done_ Workload elsewhere
            expect elsewhere '&/mine:/free/linked' '.* \(os error 18\)' "a pod linked a file of its root into a Volume"
            expect elsewhere '>/mine:/free/moved' '.* \(os error 18\)' "a pod moved a file of its root into a Volume"
            gone Workload elsewhere
            ok elsewhere

            # What it changes of its image is charged to it: a file of its image larger than its
            # limit, appended to; a directory renamed; a file renamed over one; one linked; one
            # removed; then it fills the rest.
            quota Workload image ',"resources":{"storage":"8Mi"}' '?/' '^/big' '>/tree:/moved' '+/new:1048576' '>/new:/data/small' '?/data/small' '&/data/other:/linked' '?/linked' '-/big' '+/fill:16777216' '#/'
            done_ Workload image
            its=$(result image '?/')
            expect image '?/' 'project [1-9][0-9]*' "its root is in no project of its own"
            expect image '^/big' '.* \(os error 122\)' "a file of its image larger than its limit was copied up whole"
            expect image '>/tree:/moved' 'ok|.* \(os error 18\)' "a directory of its image renamed"
            expect image '>/new:/data/small' ok "a file renamed over one of its image"
            expect image '?/data/small' "$its" "a file renamed over one of its image left its project"
            expect image '&/data/other:/linked' ok "a file of its image linked"
            expect image '?/linked' "$its" "a file of its image linked is not charged to it"
            expect image '-/big' ok "a file of its image removed"
            stopped image '+/fill:16777216' 8388608
            used image '#/' 8388608
            gone Workload image
            ok image

            # kithd's own tests of the project-quota path (crates/kithd/src/controller/storage.rs),
            # which skip where the disk keeps no projects. They set a project's limit, which takes
            # CAP_SYS_ADMIN, and no pod has it: so with n1 off, as the first process of a machine
            # of their own, root with every capability. Kith OS's kernel and a memory disk of
            # ci/pod.rs (its `tests`: it mounts n1's state partition as kithd does and runs them
            # there) and the tests; every one run and none skipped.
            echo quit | socat - "unix-connect:$work/keys1" >/dev/null 2>&1 || :
            sleep 2
            mkdir -p "$work/unitrd"
            cp "$work/pod" "$work/unitrd/init"
            cp "$(sh "$root/ci/musl.sh" --tests)" "$work/unitrd/kithd-tests"
            (cd "$work/unitrd" && find . | cpio -o -H newc --quiet) >"$work/unit.cpio"
            number=$(sfdisk -d "$work/n1.raw" | sed -n 's/^[^ ]*[^0-9]\([0-9][0-9]*\) :.*name="state".*/\1/p')
            timeout --foreground 600 qemu-system-x86_64 -enable-kvm -cpu host -m 1024 -smp 2 -display none -no-reboot -machine q35 \
                -kernel "$base/vmlinuz" -initrd "$work/unit.cpio" -append "console=ttyS0 panic=-1 -- tests /dev/vda$number" \
                -drive "file=$work/n1.raw,format=raw,if=virtio" -serial "file:$work/unit.log" -monitor none </dev/null >/dev/null 2>&1 8>&- &
            vms="$vms $!"
            wait "$!" \
                || fail "the machine of kithd's unit tests did not power off: $(tail -n 20 "$work/unit.log")"
            want=$(grep -c 'fn storage_projects_' "$root/crates/kithd/src/controller/storage.rs")
            grep -aq "test result: ok. $want passed" "$work/unit.log" || fail "kithd's storage_projects_ tests, not $want passed: $(grep -a -e 'test result' -e panicked -e 'tests:' "$work/unit.log")"
            ! grep -aq 'storage_projects_[a-z_]*: skipped' "$work/unit.log" || fail "a storage_projects_ test skipped on a disk that keeps projects: $(grep -ao 'storage_projects_[a-z_]*: skipped' "$work/unit.log")"
            ok unit

            for case in said again write scratch unlinked files nodewrite copyup nodecopyup userns noderoot unconfined elsewhere image unit; do
                grep -qx "$case" "$work/oks" || fail "the case $case was not shown"
            done
            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: one node whose state disk keeps project quotas: kithd said it holds pods' storage limits at the write; a project id given again after kithd started again held its new pod to its own limit, not the last one's; a pod of 64 MiB writing 200 MiB was stopped by the kernel at its limit, in its root, in its scratch and in a file it removed and held open, and not replaced, while one beside it lost no write; a pod with the node's users was stopped in its root too, and in both kinds a file of the image copied up near the limit was refused whole and left unchanged; its files stayed in its project in a user namespace (the kernel) and as the node's root (its filter), and unconfined it moved one out and was counted and replaced; linked or renamed out of its root they were refused; what it changed of its image was charged to it; kithd's storage_projects_ unit tests passed on it, none skipped"
            exit 0
