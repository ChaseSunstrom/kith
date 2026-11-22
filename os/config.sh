#!/bin/sh
# Write a node's config (its name, address and kithd's arguments) into a built kith OS
# image, so a cloud image starts as the node meant. Run it on the build host, on a raw
# image you may change (a copy of target/os/kith-os.raw); convert it after, if the cloud
# wants qcow2: qemu-img convert -O qcow2 kith-os.raw kith-os.qcow2
#
# The words are made by the installer's own code (kithd config-image), from the same
# answers file, so they are the ones the installer would have written. KITHD is the
# kithd to run (default: the one ci/musl.sh builds).
set -eu

usage() {
    cat <<'EOF'
usage: sh os/config.sh IMAGE ANSWERS

Writes into IMAGE (kith-os.raw, changed in place) the config the installer would write
for ANSWERS (kith-install.yaml: see docs/guide/os.md). Nothing else in IMAGE changes, and
a second call replaces the first. `disk:` is needed and not used. `encrypt: true` and
`size:` mean a machine: they are refused. The image is made readable by you alone first:
it holds the join token in plain text.

  KITHD   the kithd binary to run (default: built by ci/musl.sh)
EOF
}

case "${1:-}" in
    -h | --help)
        usage
        exit 0
        ;;
esac
[ "$#" = 2 ] || {
    usage >&2
    exit 2
}
if [ -z "${KITHD:-}" ]; then
    KITHD=$(sh "$(dirname "$0")/../ci/musl.sh")/kithd
fi
# (The image will hold the join token in plain text: nobody else reads it.)
chmod go-rwx "$1"
exec "$KITHD" config-image "$1" "$2"
