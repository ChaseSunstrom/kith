#!/bin/sh
# Takes the firmware that globs name out of a linux-firmware tarball into DIR, as
# copy-firmware.sh would lay it out, without extracting the tarball's 640 MB:
#
#     sh os/firmware.sh TARBALL DIR GLOB...
#
# linux-firmware keeps a file once and names it again in its WHENCE file's `Link: NAME -> TARGET`
# lines (most of nvidia/gp106 is links to gp102 and gm200). Each file a glob names is taken, and
# each link a glob names is made (a relative symlink, as written) with what it points at taken
# too, links in turn. A glob is a path where `*` stands for part of one name, never a `/` (as
# tar's does here): `intel/*` makes no link named intel/a/b. build.sh calls this for a spec's
# built-in firmware (T-1235); os/firmware.sh is tested by kithd's os.rs (`built_in_firmware`).
#
# It dies, with a message, for a glob that names neither a file nor a link, for a link that
# leaves the tree (an absolute target, or a `..` past the top, however deep it goes first), for
# one that points at what linux-firmware lacks, and for links that follow each other for more
# than 50 rounds (a cycle). Only DIR is written; what it had is added to.
set -eu
die() {
    echo "firmware.sh: $*" >&2
    exit 1
}
[ $# -ge 3 ] || die "usage: sh firmware.sh TARBALL DIR GLOB..."
tarball=$1 dir=$2
shift 2
# (Globs and names are words here, not this directory's files.)
set -f
for g in "$@"; do
    case $g in /* | *..* | *[!A-Za-z0-9_./*+-]*) die "'$g' is not a path in linux-firmware" ;; esac
done
mkdir -p "$dir"
trap 'rm -f "$dir/.whence" "$dir/.plan" "$dir/.tar-err"' EXIT
export LC_ALL=C

# WHENCE first, alone (it is early in the tarball: tar stops at it).
tar -xJf "$tarball" -C "$dir" --strip-components=1 --wildcards --no-wildcards-match-slash \
    --occurrence=1 '*/WHENCE' || die "no WHENCE in $tarball"
mv "$dir/WHENCE" "$dir/.whence"

# What the globs ask of the links, from WHENCE alone: `L NAME TARGET` for a link to make, `F PATH`
# for a file it comes to, `M GLOB` for a glob that names a link, `E TEXT` for the way out.
awk -v globs="$*" -v max=50 '
function norm(base, t,    n, p, i, c, s, out) { # a link in directory BASE to T: the path it is, "" if out
    if (t ~ /^\// || t == "") return ""
    n = split(base "/" t, p, "/")
    c = 0
    for (i = 1; i <= n; i++) {
        if (p[i] == "" || p[i] == ".") continue
        if (p[i] == "..") { if (c == 0) return ""; c--; continue }
        s[++c] = p[i]
    }
    out = s[1]
    for (i = 2; i <= c; i++) out = out "/" s[i]
    return out
}
# (Exit 0: an E line is how a refusal is said; a status that is not 0 is awk itself failing.)
function bad(text) { print "E " text; exit 0 }
function linked(p,    n, a, i, s) { # does a directory on the way to P (not P) hold a link of WHENCE
    n = split(p, a, "/")
    s = a[1]
    for (i = 2; i <= n; i++) {
        if (s in target) return 1
        s = s "/" a[i]
    }
    return 0
}
BEGIN {
    n = split(globs, g, " ")
    for (i = 1; i <= n; i++) {
        r = g[i]
        gsub(/[.]/, "[.]", r)
        gsub(/[+]/, "[+]", r)
        gsub(/[*]/, "[^/]*", r)
        re[i] = "^" r "$"
    }
}
$1 == "Link:" && NF == 4 && $3 == "->" { target[$2] = $4 }
END {
    for (name in target)
        for (i = 1; i <= n; i++)
            if (name ~ re[i]) { todo[name] = 1; seen[g[i]] = 1 }
    for (i = 1; i <= n; i++) if (seen[g[i]]) print "M " g[i]
    for (round = 1; ; round++) {
        more = 0
        for (w in todo) more = 1
        if (!more) break
        if (round > max) bad("links that follow each other for more than " max " rounds, a cycle, at " w)
        split("", next_)
        for (w in todo) {
            t = target[w]
            d = w
            if (sub(/\/[^\/]*$/, "", d) == 0) d = "."
            r = norm(d, t)
            if (w ~ /^\// || w ~ /(^|\/)[.][.](\/|$)/ || r == "")
                bad("a link out of the linux-firmware tree: " w " -> " t)
            if (w !~ /^[A-Za-z0-9_.\/+-]+$/ || r !~ /^[A-Za-z0-9_.\/+-]+$/)
                bad("a link that is not a path in linux-firmware: " w " -> " t)
            # (A path through the directory of a link lands elsewhere than the walk above says.)
            if (linked(w) || linked(r))
                bad("a link in or to a directory that is a link: " w " -> " t)
            print "L " w " " t
            if (r in target) next_[r] = 1; else print "F " r
        }
        split("", todo)
        for (w in next_) todo[w] = 1
    }
    print "Z"
}' "$dir/.whence" >"$dir/.plan" || die "awk failed reading WHENCE"
err=$(sed -n 's/^E //p' "$dir/.plan" | head -n 1)
[ -z "$err" ] || die "$err"
# (The plan ends with Z: a plan that stops short is an awk that did, and no links.)
[ "$(tail -n 1 "$dir/.plan")" = Z ] || die "awk's plan of the links is incomplete"
files=$(sed -n 's/^F //p' "$dir/.plan" | sort -u)

# The files: what the globs name and what the links come to, in one read of the tarball. A glob
# that names only links is "not found" to tar; one that names nothing at all is an error here.
args=''
for p in "$@" $files; do args="$args */$p"; done
# shellcheck disable=SC2086
tar -xJf "$tarball" -C "$dir" --strip-components=1 --wildcards --no-wildcards-match-slash --no-recursion $args 2>"$dir/.tar-err" || true
other=$(grep -v -e 'Not found in archive' -e 'Exiting with failure status' "$dir/.tar-err" || true)
[ -z "$other" ] || die "tar: $other"
for g in "$@"; do
    grep -qxF "M $g" "$dir/.plan" || ! grep -qF -e "*/$g: Not found in archive" "$dir/.tar-err" ||
        die "'$g' names no file and no link in linux-firmware"
done
for f in $files; do
    [ -e "$dir/$f" ] || [ -L "$dir/$f" ] || die "a link points at what linux-firmware lacks: $f"
done
# tar does not recurse here, so a glob that matches a directory takes the directory, empty: a glob
# that names no file and no link, and a directory, is a mistake (write `DIR/*` for its files).
for g in "$@"; do
    ! grep -qxF "M $g" "$dir/.plan" || continue
    # (Globs are words here, `set +f` lets this one stand for the paths it names.)
    if (set +f; for p in "$dir"/$g; do [ -f "$p" ] && exit 1; done; for p in "$dir"/$g; do [ -d "$p" ] && exit 0; done; exit 1); then
        die "'$g' names only directories in linux-firmware (tar takes no files in them): write '$g/*' for their files"
    fi
done

# The links, made as WHENCE writes them; one that leads nowhere is the tarball's fault.
sed -n 's/^L //p' "$dir/.plan" | sort -u | while read -r name target; do
    mkdir -p "$dir/$(dirname "$name")"
    ln -sfn "$target" "$dir/$name"
done
sed -n 's/^L //p' "$dir/.plan" | sort -u | while read -r name target; do
    [ -e "$dir/$name" ] || die "a link points at what linux-firmware lacks: $name -> $target"
done
