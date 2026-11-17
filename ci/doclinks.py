#!/usr/bin/env python3
"""Every relative link and #anchor in README.md and docs/guide/*.md goes somewhere.

    python3 ci/doclinks.py            exit 1 naming each link that does not resolve
    python3 ci/doclinks.py --lines    and the README with the guides is at most three
                                      quarters of the one README they came from
    python3 ci/doclinks.py --self-test

An anchor is a heading's GitHub slug: lower case, punctuation dropped, spaces as hyphens,
a repeated one given -1, -2.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# README.md's length before it was split into a front page and docs/guide/ (T-0682).
BEFORE = 4336
LINK = re.compile(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)|(?:href|src|srcset)=\"([^\"]+)\"")


def docs():
    return [ROOT / "README.md", *sorted((ROOT / "docs" / "guide").glob("*.md"))]


def prose(text):
    """The lines outside fenced code blocks, with their numbers."""
    fenced = False
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            yield number, line


def slug(heading):
    heading = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def anchors(text):
    seen, out = {}, set()
    for _, line in prose(text):
        m = re.match(r"#{1,6}\s+(.*?)\s*#*\s*$", line)
        if m:
            s = slug(m.group(1))
            n = seen.get(s, 0)
            seen[s] = n + 1
            out.add(s if n == 0 else f"{s}-{n}")
        for a in re.findall(r"<a (?:name|id)=\"([^\"]+)\"", line):
            out.add(a)
    return out


def broken(files):
    known = {}
    wrong = []
    for path in files:
        for number, line in prose(path.read_text()):
            for a, b in LINK.findall(line):
                target = a or b.split()[0]
                if re.match(r"[a-z]+:", target) or target.startswith("//"):
                    continue
                file, _, anchor = target.partition("#")
                dest = (path.parent / file).resolve() if file else path
                where = f"{path.relative_to(ROOT)}:{number}: {target}"
                if not dest.exists():
                    wrong.append(f"{where}: no such file")
                    continue
                if anchor and dest.suffix == ".md":
                    if dest not in known:
                        known[dest] = anchors(dest.read_text())
                    if anchor not in known[dest]:
                        wrong.append(f"{where}: no such heading")
    return wrong


def self_test():
    assert slug("kith OS: kithd as the machine's first process") == "kith-os-kithd-as-the-machines-first-process"
    assert slug("`kith.dev/v1` is stable") == "kithdevv1-is-stable"
    assert slug("Sources (GitOps)") == "sources-gitops"
    assert anchors("# A\n## A\n```\n# B\n```\n") == {"a", "a-1"}
    print("doclinks: self-test ok")


def main(args):
    if "--self-test" in args:
        self_test()
        return 0
    files = docs()
    wrong = broken(files)
    for w in wrong:
        print(w)
    lines = sum(len(p.read_text().splitlines()) for p in files)
    print(f"doclinks: {len(files)} files, {lines} lines, {len(wrong)} links that go nowhere")
    if "--lines" in args and lines > BEFORE * 3 // 4:
        print(f"doclinks: {lines} lines is more than three quarters of the {BEFORE} the README had")
        return 1
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
