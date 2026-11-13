#!/usr/bin/env python3
"""Size and memory budgets (PLAN.md §3.2, §8). CI fails when one is exceeded.

Budgets are deliberately tight: raise one only in a commit that says why.
The plan's ceiling for kithd is 40 MB idle on a 3-node cluster; one idle node
in agent mode sits far below that, and its budget is set near what it measures
so that creep shows up long before the ceiling does.
"""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

TARGET = "x86_64-unknown-linux-musl"  # static, as shipped
MB = 1024 * 1024

# Measured 6.5 MB and 4.0 MB when kithd first ran workloads (API server, store,
# controller, container runtime, registry client with TLS); 8.2 MB and 5.7 MB with
# the replicated store (openraft and redb, Phase 2b), which raised the size budget from 8;
# 10.0 MB with mesh, ingress, ACME, packages and Sources (Phases 2-3), which raised it
# from 10 for Phase 4 (access control, WASM, the web UI). The plan's own ceilings are
# on memory (30 MB for kithd), which the idle RSS budget below stays far under.
# Idle RSS measured 7.80 MB before device claims and 8.00 MB with them (Phase 6): nearly
# all of the rise is pages of the binary itself, not heap, which raised its budget from 8.
KITHD_SIZE = 12
KITHD_IDLE_RSS = 9 * MB
# binary -> max size in bytes. kith measured 2.0 MB before it rendered packages and
# 2.7 MB with the template engine (minijinja, Phase 3a), which raised its budget from 2.5.
SIZE_BUDGETS = {"kith": 3 * MB, "kithd": KITHD_SIZE * MB}
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


def idle_rss(kithd, tmp):
    """Resident set size of a kithd that serves its socket and has nothing to run."""
    socket = os.path.join(tmp, "kithd.sock")
    daemon = subprocess.Popen([kithd, "--state", os.path.join(tmp, "state"), "--socket", socket], stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 10
        while not os.path.exists(socket):
            if daemon.poll() is not None or time.time() > deadline:
                sys.exit("kithd did not start serving")
            time.sleep(0.05)
        time.sleep(0.5)  # past startup: the first reconcile pass has run
        with open(f"/proc/{daemon.pid}/status") as status:
            line = next(l for l in status if l.startswith("VmRSS:"))
        return int(line.split()[1]) * 1024
    finally:
        daemon.send_signal(signal.SIGTERM)
        daemon.wait()


def musl_cc(env):
    """kithd's TLS (ring) has C in it, so a static build needs a musl C compiler.

    CI installs musl-tools. Where there is none but zig is installed, zig is one.
    """
    var = "CC_" + TARGET.replace("-", "_")
    if var in env or shutil.which("musl-gcc") or shutil.which("x86_64-linux-musl-gcc") or not shutil.which("zig"):
        return env
    wrapper = os.path.join(os.path.dirname(os.path.abspath(__file__)), "musl-cc.sh")
    return {**env, var: wrapper}


def check(name, what, actual, limit):
    ok = actual <= limit
    print(f"{'ok  ' if ok else 'FAIL'} {name}: {what} {actual / MB:.2f} MB (budget {limit / MB:.2f} MB)")
    return ok


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root)
    self_test = "--self-test" in sys.argv
    with tempfile.TemporaryDirectory() as tmp:
        build_env = musl_cc(os.environ.copy())
        for binary in SIZE_BUDGETS:
            package = "kith-cli" if binary == "kith" else binary
            build = ["cargo", "build", "--release", "--quiet", "--target", TARGET, "-p", package]
            subprocess.run(build, check=True, env=build_env)
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
        rss = idle_rss(os.path.join(bin_dir, "kithd"), tmp)
        results.append(check("kithd", "idle RSS", rss, 1 if self_test else KITHD_IDLE_RSS))
    if self_test:
        # With 1-byte budgets every check must fail; otherwise the checks check nothing.
        if any(results):
            sys.exit("self-test failed: a check passed against a 1-byte budget")
        print("self-test ok: every check fails against a 1-byte budget")
    elif not all(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
