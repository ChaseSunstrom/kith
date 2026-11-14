#!/usr/bin/env python3
"""The numbers the website shows (docs/index.html): measured here, not typed in.

    python3 ci/site_numbers.py           measure, write docs/numbers.json, put them in the page
    python3 ci/site_numbers.py --check   fail if the page shows a number the file lacks, or another

Where each comes from:
    kith.size, kithd.size, kithd.idle, apply.peak   ci/budgets.py (the static binaries, run here)
    os.update, os.image, os.root                    target/os/ (sh os/build.sh), in MB
    kinds                                           README.md's count, which a test holds to the code
    tests, vm_tests, crates, rust_lines, refused,   counted in the sources\n    refused.names, by_crate
    cmp.*                                           ci/compare.txt (sh ci/compare.sh): the middle run
The comparison is drawn too, for README.md: docs/assets/diagrams/beside-k3s-light.svg and
-dark.svg, from the same cmp.* numbers (--check fails on a drawing of other numbers).
What cannot be measured now (no image built, no comparison run) keeps the value it had.

In the page, `<b data-n="KEY">` is given the number as its text, and the block
`<script id="measured">` the whole file, which the charts are drawn from.
"""
import datetime
import json
import pathlib
import re
import statistics
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FILE, PAGE = ROOT / "docs/numbers.json", ROOT / "docs/index.html"
MB = 1024 * 1024


def measured(old):
    n = dict(old)
    said = subprocess.run([sys.executable, ROOT / "ci/budgets.py"], capture_output=True, text=True, check=True).stdout
    names = {("kith", "binary size"): "kith.size", ("kithd", "binary size"): "kithd.size", ("kithd", "idle RSS"): "kithd.idle", ("kith apply", "peak RSS"): "apply.peak"}
    for name, what, actual, budget in re.findall(r"^ok\s+(.+?): (.+?) ([\d.]+) MB \(budget ([\d.]+) MB\)", said, re.M):
        n[names[name, what]], n[names[name, what] + ".budget"] = float(actual), float(budget)
    for key, file in (("os.update", "kith-os.update"), ("os.image", "kith-os.raw"), ("os.root", "root.squashfs")):
        if (ROOT / "target/os" / file).exists():
            n[key] = round((ROOT / "target/os" / file).stat().st_size / MB, 1)
    sources = [p for p in (ROOT / "crates").rglob("*.rs") if "target" not in p.relative_to(ROOT).parts]
    text = {p: p.read_text() for p in sources}
    n["kinds"] = int(re.search(r"the (\d+) built-in kinds", (ROOT / "README.md").read_text()).group(1))
    n["tests"] = sum(len(re.findall(r"#\[(?:tokio::)?test\b", t)) for t in text.values())
    n["vm_tests"] = len(set(re.findall(r"^#\s+sh ci/vm\.sh --test (\w+)", (ROOT / "ci/vm.sh").read_text(), re.M)))
    n["crates"] = sum(1 for p in (ROOT / "crates").iterdir() if p.is_dir())
    n["rust_lines"] = sum(t.count("\n") for t in text.values())
    n["refused.names"] = re.findall(r'^\s+\("(\w+)", libc::SYS_', (ROOT / "crates/kith-runtime/src/seccomp.rs").read_text(), re.M)
    n["refused"] = len(n["refused.names"])
    n["by_crate"] = {}  # crate: [lines, tests]
    for path, t in text.items():
        lines, tests = n["by_crate"].setdefault(path.relative_to(ROOT / "crates").parts[0], [0, 0])
        n["by_crate"][path.relative_to(ROOT / "crates").parts[0]] = [lines + t.count("\n"), tests + len(re.findall(r"#\[(?:tokio::)?test\b", t))]
    n["version"] = re.search(r'^version = "(.*)"', (ROOT / "Cargo.toml").read_text(), re.M).group(1)
    n.update(compared())
    n["measured"] = datetime.date.today().isoformat()
    return {k: int(v) if isinstance(v, float) and v == int(v) else v for k, v in sorted(n.items())}


# How many places after the point a measured number keeps (none where not named).
PLACES = {"apply": 2, "scale": 2, "burst": 2, "roll": 2, "crash": 2, "job": 2, "boot": 1, "ready": 1, "login": 1, "cpu": 1, "cpu2": 1, "each": 1}


def compared():
    """cmp.*: the middle run of each number ci/compare.sh wrote down beside k3s."""
    n, compared = {}, ROOT / "ci/compare.txt"
    if compared.exists():
        runs = {}
        for system, setting, rest in re.findall(r"^\s+(kith|k3s) (default|\d+) (.*)$", compared.read_text(), re.M):
            for what, value in (pair.split("=") for pair in rest.split()):
                runs.setdefault((system, setting, what), []).append(float(value))
        for (system, setting, what), values in runs.items():
            if setting == "default" or what == "lost":
                key = f"cmp.{system}.{what}" + ("" if setting == "default" else setting)
                n[key] = round(statistics.median(values), PLACES.get(what, 0))
        n["cmp.runs"] = len(runs.get(("kith", "default", "control"), []))
        n["cmp.k3s.version"] = re.search(r"k3s (v[\d.]+)", compared.read_text()).group(1)
    return {k: int(v) if isinstance(v, float) and v == int(v) else v for k, v in n.items()}


# The drawing's colours: surface, text, quiet text, then kith and k3s. (The two series were
# checked as a pair on each surface, for every kind of colour sight: they differ by 29 or
# more where 8 is the floor. Each bar is named and numbered beside it all the same.)
SCHEMES = {"light": ("#f6f5f1", "#16181d", "#575c69", "#2f5fe0", "#8f5f00"), "dark": ("#16181d", "#f6f5f1", "#a9aebb", "#5b8cff", "#b98426")}
ROWS = [  # each its own scale: they are not one measure
    ("control", "MB", "Memory in use, idle: the first node, or the server"),
    ("worker", "MB", "Memory in use, idle: another node, or an agent"),
    ("cpu", "% of a CPU", "CPU in use, idle: the first node, or the server"),
    ("ready", "s", "From switching a machine on to a ready node"),
    ("apply", "s", "From apply to a ready container"),
    ("scale", "s", "One workload of 30 replicas: until all are ready"),
    ("lost", "s", "A node lost: its replica ready on another, as each is set to wait"),
    ("kept", "a second", "Requests through a Service, connections kept (the one row where more is better)"),
]


def chart(n, scheme):
    """ci/compare.txt's middle runs as bars, a pair for each thing measured."""
    surface, text, quiet, *colours = SCHEMES[scheme]
    rows = [(label, unit, [n[f"cmp.{system}.{key}"] for system in ("kith", "k3s")]) for key, unit, label in ROWS if all(f"cmp.{system}.{key}" in n for system in ("kith", "k3s"))]
    left, full, top, tall = 24, 560, 92, 62
    said = "; ".join(f"{label}: kith {a} {unit}, k3s {b} {unit}" for label, unit, (a, b) in rows)
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 880 {top + tall * len(rows) + 8}" role="img" font-family="ui-sans-serif, system-ui, sans-serif">',
        f"<title>kith beside k3s, measured</title><desc>{said}.</desc>",
        f'<rect width="100%" height="100%" rx="10" fill="{surface}"/>',
        f'<text x="{left}" y="36" font-size="17" font-weight="700" fill="{text}">kith beside k3s {n["cmp.k3s.version"]}, measured</text>',
        f'<text x="{left}" y="58" font-size="12.5" fill="{quiet}">Three QEMU machines each, the middle of {n["cmp.runs"]} runs (ci/compare.sh). Each pair has its own scale.</text>',
    ]
    for at, (name, colour) in enumerate(zip(("kith", "k3s"), colours)):
        out.append(f'<rect x="{720 + at * 70}" y="26" width="12" height="12" rx="2" fill="{colour}"/><text x="{738 + at * 70}" y="36.5" font-size="13" fill="{text}">{name}</text>')
    for row, (label, unit, values) in enumerate(rows):
        y = top + row * tall
        out.append(f'<text x="{left}" y="{y}" font-size="13.5" fill="{text}">{label}</text>')
        for at, (value, colour, name) in enumerate(zip(values, colours, ("kith", "k3s"))):
            wide, by = max(6, round(full * value / (max(values) or 1))), y + 10 + at * 16
            # (Flat where it starts, round where it ends.)
            out.append(f'<path d="M{left} {by}h{wide - 4}a4 4 0 0 1 4 4v6a4 4 0 0 1 -4 4h-{wide - 4}z" fill="{colour}"/>')
            out.append(f'<text x="{left + wide + 8}" y="{by + 11}" font-size="12.5" fill="{text}"><tspan font-weight="700">{value} {unit}</tspan><tspan dx="6" fill="{quiet}">{name}</tspan></text>')
    return "\n".join(out) + "\n</svg>\n"


def charts(n):
    return {ROOT / f"docs/assets/diagrams/beside-k3s-{scheme}.svg": chart(n, scheme) for scheme in SCHEMES}


def filled(page, n):
    """The page with every number in its place; and the keys it asks for that there are none of."""
    missing = []

    def number(found):
        opening, key, closing = found.group(1), found.group(3), found.group(4)
        if key not in n:
            missing.append(key)
            return found.group(0)
        return f"{opening}{n[key]}{closing}"

    page = re.sub(r'(<(\w+)\b[^>]*\bdata-n="([^"]+)"[^>]*>)[^<]*(</\2>)', number, page)
    block = re.compile(r'(<script id="measured" type="application/json">).*?(</script>)', re.S)
    # A bar's value and its budget are keys too; the numbers' own block has to be there;
    # and the kinds the page names are as many as it counts.
    missing += [key for key in re.findall(r'\bdata-(?:v|of)="([^"]+)"', page) if key not in n]
    if not block.search(page):
        missing.append("(the #measured block)")
    kinds = re.search(r'<section[^>]*id="kinds".*?</section>', page, re.S)
    named = len(re.findall(r"<span>\w+</span>", kinds.group(0))) if kinds else 0
    if named != n.get("kinds"):
        missing.append(f"(kinds: {named} named, {n.get('kinds')} counted)")
    return block.sub(lambda f: f.group(1) + json.dumps(n) + f.group(2), page), missing


def main():
    check = sys.argv[1:] == ["--check"]
    old = json.loads(FILE.read_text()) if FILE.exists() else {}
    n = old if check else measured(old)
    page, missing = filled(PAGE.read_text(), n)
    if missing:
        sys.exit(f"docs/index.html shows numbers docs/numbers.json lacks: {', '.join(sorted(set(missing)))}")
    if check:
        if {k: v for k, v in n.items() if k.startswith("cmp.")} != compared():
            sys.exit("docs/numbers.json has other numbers beside k3s than ci/compare.txt: python3 ci/site_numbers.py takes them")
        if page != PAGE.read_text():
            sys.exit("docs/index.html shows other numbers than docs/numbers.json: python3 ci/site_numbers.py puts them in")
        for file, drawn in charts(n).items():
            if not file.exists() or file.read_text() != drawn:
                sys.exit(f"{file.relative_to(ROOT)} draws other numbers than docs/numbers.json: python3 ci/site_numbers.py draws it again")
        print(f"ok: {len(re.findall('data-n=', page))} numbers in the page, all from docs/numbers.json")
        return
    FILE.write_text(json.dumps(n, indent=1) + "\n")
    PAGE.write_text(page)
    for file, drawn in charts(n).items():
        file.write_text(drawn)
    print(json.dumps(n, indent=1))


if __name__ == "__main__":
    main()
