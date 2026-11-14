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
    compared = ROOT / "ci/compare.txt"
    if compared.exists():
        runs = {}
        for system, setting, rest in re.findall(r"^\s+(kith|k3s) (default|\d+) (.*)$", compared.read_text(), re.M):
            for what, value in (pair.split("=") for pair in rest.split()):
                runs.setdefault((system, setting, what), []).append(float(value))
        for (system, setting, what), values in runs.items():
            if setting == "default" or what == "lost":
                key = f"cmp.{system}.{what}" + ("" if setting == "default" else setting)
                n[key] = round(statistics.median(values), 2 if what == "apply" else 1 if what == "boot" else 0)
        n["cmp.runs"] = len(runs.get(("kith", "default", "control"), []))
        n["cmp.k3s.version"] = re.search(r"k3s (v[\d.]+)", compared.read_text()).group(1)
    n["measured"] = datetime.date.today().isoformat()
    return {k: int(v) if isinstance(v, float) and v == int(v) else v for k, v in sorted(n.items())}


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
        if page != PAGE.read_text():
            sys.exit("docs/index.html shows other numbers than docs/numbers.json: python3 ci/site_numbers.py puts them in")
        print(f"ok: {len(re.findall('data-n=', page))} numbers in the page, all from docs/numbers.json")
        return
    FILE.write_text(json.dumps(n, indent=1) + "\n")
    PAGE.write_text(page)
    print(json.dumps(n, indent=1))


if __name__ == "__main__":
    main()
