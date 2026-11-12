#!/usr/bin/env python3
"""Size and memory budgets (PLAN.md §3.2, §8). CI fails when one is exceeded.

Budgets are deliberately tight: raise one only in a commit that says why.
kithd joins the table when it exists (idle RSS <= 40 MB on a 3-node cluster).
"""
import os
import subprocess
import sys
import tempfile

TARGET = "x86_64-unknown-linux-musl"  # static, as shipped
MB = 1024 * 1024

# binary -> max size in bytes
SIZE_BUDGETS = {"kith": int(2.5 * MB)}
# name -> (argv after the binary, max peak RSS in bytes)
RSS_BUDGETS = {"kith apply": (["apply", "-f", "examples"], 4 * MB)}


def peak_rss(argv, env):
    """Peak resident set size of one run of argv, in bytes, as kith reports it.

    Not getrusage(RUSAGE_CHILDREN): that high-water mark carries over exec, so
    it would mostly measure this Python process.
    """
    env = {**env, "KITH_PRINT_PEAK_RSS": "1"}
    out = subprocess.run(argv, env=env, check=True, capture_output=True, text=True)
    line = next(l for l in out.stderr.splitlines() if l.startswith("VmHWM:"))
    return int(line.split()[1]) * 1024  # reported in kB


def check(name, what, actual, limit):
    ok = actual <= limit
    print(f"{'ok  ' if ok else 'FAIL'} {name}: {what} {actual / MB:.2f} MB (budget {limit / MB:.2f} MB)")
    return ok


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root)
    self_test = "--self-test" in sys.argv
    # Only the budgeted binaries: kith-runtime's TLS (ring) needs a musl C compiler,
    # which CI gets with kithd, the first binary that links it.
    for binary in SIZE_BUDGETS:
        package = "kith-cli" if binary == "kith" else binary
        subprocess.run(["cargo", "build", "--release", "--quiet", "--target", TARGET, "-p", package], check=True)
    bin_dir = os.path.join(os.environ.get("CARGO_TARGET_DIR", "target"), TARGET, "release")
    results = []
    for binary, limit in SIZE_BUDGETS.items():
        size = os.path.getsize(os.path.join(bin_dir, binary))
        results.append(check(binary, "binary size", size, 1 if self_test else limit))
    with tempfile.TemporaryDirectory() as tmp:
        env = {**os.environ, "KITH_STORE": os.path.join(tmp, "store.json")}
        for name, (args, limit) in RSS_BUDGETS.items():
            rss = peak_rss([os.path.join(bin_dir, "kith"), *args], env)
            results.append(check(name, "peak RSS", rss, 1 if self_test else limit))
    if self_test:
        # With 1-byte budgets every check must fail; otherwise the checks check nothing.
        if any(results):
            sys.exit("self-test failed: a check passed against a 1-byte budget")
        print("self-test ok: every check fails against a 1-byte budget")
    elif not all(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
