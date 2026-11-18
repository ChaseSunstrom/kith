#!/bin/sh
# The holder's start: a session bus at the seat's directory, then the Wayland compositor on
# the seat's socket. kithd gives this container the seat's devices and its directory
# (XDG_RUNTIME_DIR); with LIBSEAT_BACKEND=noop the compositor opens them without logind.
set -eu
export LIBSEAT_BACKEND=noop
dbus-daemon --session --fork --address=unix:path=/run/seat/bus
exec weston --backend=drm-backend.so --renderer=pixman --socket=wayland-0
