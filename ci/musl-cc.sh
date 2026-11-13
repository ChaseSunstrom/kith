#!/bin/sh
# zig as the C compiler for x86_64 musl, for cc-rs (ci/musl.sh points it here): cc-rs
# passes rustc's name for the target, which zig spells differently.
for a; do
    shift
    case "$a" in --target=*) ;; *) set -- "$@" "$a" ;; esac
done
exec zig cc -target x86_64-linux-musl "$@"
