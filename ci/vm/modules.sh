# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154 # (names the driver and its parts share)
# Sourced by ci/vm.sh for --test modules (through tests.sh): it runs inside the driver's shell,
# with its variables and functions; not a script to run alone.
#
# The 'all' image has its drivers as modules, signed with the key its build made. Two boots of
# it: kithd loads the driver of a QEMU Intel HDA controller at start (snd-hda-intel), and a
# USB audio device the QEMU monitor adds later gets its driver (snd-usb-audio) in the same
# boot. Then the same spec built again, from a cache whose snd-usb-audio has one byte changed:
# the signature no longer matches, the kernel refuses the module (MODULE_SIG_FORCE), and kithd
# says so on one console line.
    [ "$time" -gt 120 ] || time=240
    # (Audio with no sound card behind it: QEMU's own no-backend driver.)
    audio='-audiodev none,id=snd0'

    cp "$osdir/kith-os.raw" "$work/disk.raw"
    more=$serve once=1
    boot -device intel-hda $audio -device qemu-xhci,id=xhci
    up
    said 'kithd: init: module snd_hda_intel loaded' || fail "kithd did not load the driver of the HDA controller at start"
    echo 'device_add usb-audio,id=audio0,bus=xhci.0,audiodev=snd0' | socat - "unix-connect:$work/keys" >/dev/null
    heard 'kithd: init: module snd_usb_audio loaded'
    kill "$vm" 2>/dev/null || true
    wait "$vm" 2>/dev/null || true
    echo "vm.sh: ok: kithd loaded snd_hda_intel at start and snd_usb_audio for a device added after, in the same boot"

    # NVIDIA's open modules, built out of tree in the same build: each is signed (the tail
    # of a signed module is the mark), the alias of an NVIDIA card (vendor 10DE) names nvidia,
    # and no key is left in the modules or in their /lib/modules index.
    real=${KITH_OS_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/kith-os}
    for n in nvidia nvidia-modeset nvidia-uvm nvidia-drm; do
        found=$(find "$real" -path '*/mods/*' -name "$n.ko")
        [ -n "$found" ] || fail "no $n.ko in the kernel's modules: the NVIDIA modules were not built"
        for m in $found; do
            tail -c 28 "$m" | grep -aq '^~Module signature appended~$' || fail "$m is not signed"
        done
    done
    for d in "$real"/kernel-*/mods/lib/modules/*; do
        [ -d "$d" ] || continue
        grep -q '^alias pci:v000010DE.* nvidia$' "$d/modules.alias" || fail "$d/modules.alias has no alias of an NVIDIA card for nvidia"
        ! grep -rlaE -e '-----BEGIN [A-Z ]*PRIVATE KEY' "$d" || fail "a private key is in $d"
    done
    echo "vm.sh: ok: nvidia, nvidia-modeset, nvidia-uvm and nvidia-drm signed, nvidia aliased to NVIDIA's cards, no key left"

    # The same spec, built from a cache of its own: the kernel and its modules copied (the
    # real cache is read only through its links), one byte of snd-usb-audio changed after it
    # was signed.
    cache=$work/cache
    mkdir -p "$cache"
    for f in "$real"/*; do
        case $f in
        */kernel-* | */kernel.config.*) ;;
        *) ln -s "$f" "$cache/" ;;
        esac
    done
    for d in "$real"/kernel-*; do
        [ -d "$d/mods" ] && cp -a "$d" "$cache/"
    done
    targets=$(find "$cache" -path '*/mods/*' -name 'snd-usb-audio.ko')
    [ -n "$targets" ] || fail "no snd-usb-audio.ko in the kernel's modules to change"
    for m in $targets; do
        old=$(od -An -tu1 -j1024 -N1 "$m" | tr -d ' ')
        printf "\\$(printf %o $(((old + 1) % 256)))" | dd of="$m" bs=1 seek=1024 count=1 conv=notrunc status=none
    done
    # The build is 14 GB: it goes on disk under target/ (the work folder is a tmpfs), its output
    # to a log whose tail a failure prints, and the first boot's disk is gone before it starts.
    # (One VM test runs at a time, so a folder a killed run left is stale.)
    rm -rf "$root"/target/vm-modules-*
    out=$root/target/vm-modules-$$
    mkdir -p "$out"
    rm -f "$work/disk.raw"
    KITH_OS_CACHE=$cache sh "$root/os/build.sh" --check --spec "$root/$KITH_OS_SPEC" --out "$out/os-bad" >"$out/os-bad.log" 2>&1 \
        || { tail -n 40 "$out/os-bad.log" >&2; rm -rf "$out"; fail "the image with a changed module did not build"; }
    cp "$out/os-bad/kith-os.raw" "$work/disk.raw"
    rm -rf "$out"
    boot $audio -device qemu-xhci,id=xhci
    up
    echo 'device_add usb-audio,id=audio0,bus=xhci.0,audiodev=snd0' | socat - "unix-connect:$work/keys" >/dev/null
    heard 'kithd: init: module snd_usb_audio: '
    said 'kithd: init: module snd_usb_audio loaded' && fail "kithd loaded a module whose signature is wrong"
    [ "$(grep -ac 'kithd: init: module snd_usb_audio' "$work/log")" -eq 1 ] || fail "the refusal is not one console line"
    kill "$vm" 2>/dev/null || true
    wait "$vm" 2>/dev/null || true
    echo "vm.sh: ok: a module whose signature is wrong refused on one console line, the node still up"
    exit 0
