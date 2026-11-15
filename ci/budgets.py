#!/usr/bin/env python3
"""Size, memory and time budgets (PLAN.md §3.2, §8). CI fails when one is exceeded.

Budgets are deliberately tight: raise one only in a commit that says why.
The plan's ceiling for kithd is 40 MB idle on a 3-node cluster; one idle node
in agent mode sits far below that, and its budget is set near what it measures
so that creep shows up long before the ceiling does.

Time budgets are ceilings for a regression, not claims of speed. They are measured
on the CI runner and set at twice the slowest of three of its runs on main; a path
with no budget (None) would be printed and not fail.

    python3 ci/budgets.py            # sizes, RSS and times, each with its budget
    python3 ci/budgets.py --times    # the times only: medians of five runs each
    python3 ci/budgets.py --self-test
"""
import json
import os
import re
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time

TARGET = "x86_64-unknown-linux-musl"  # static, as shipped
MB = 1024 * 1024
RUNS = 5  # each time is the median of this many runs

# Measured 6.5 MB and 4.0 MB when kithd first ran workloads (API server, store,
# controller, container runtime, registry client with TLS); 8.2 MB and 5.7 MB with
# the replicated store (openraft and redb, Phase 2b), which raised the size budget from 8;
# 10.0 MB with mesh, ingress, ACME, packages and Sources (Phases 2-3), which raised it
# from 10 for Phase 4 (access control, WASM, the web UI). The plan's own ceilings are
# on memory (30 MB for kithd), which the idle RSS budget below stays far under.
# Idle RSS measured 7.80 MB before device claims and 8.00 MB with them (Phase 6): nearly
# all of the rise is pages of the binary itself, not heap, which raised its budget from 8.
# 12.10 MB with storage (Phase 7: the NFS server's driver, the blob store with BLAKE3,
# backups with tar and S3), which raised the size budget from 12 for the rest of that phase.
KITHD_SIZE = 13
KITHD_IDLE_RSS = 9 * MB
# binary -> max size in bytes. kith measured 2.0 MB before it rendered packages and
# 2.7 MB with the template engine (minijinja, Phase 3a), which raised its budget from 2.5.
SIZE_BUDGETS = {"kith": 3 * MB, "kithd": KITHD_SIZE * MB}
# name -> (argv after the binary, max peak RSS in bytes)
RSS_BUDGETS = {"kith apply": (["apply", "-f", "examples"], 4 * MB)}

# Seconds, one per timed path: twice the slowest of three runs (each a median of RUNS) on main on the CI runner
# (apply 85.3, 88.1, 78.3 ms; status 4.7, 4.8, 4.8 ms; DNS 2.9, 3.1, 3.5 ms), rounded up.
# A ceiling for a regression, not a claim of speed. None would mean no budget (printed only).
TIME_BUDGETS = {
    "apply to a running container": 0.180,
    "a status change reaching a second kithd": 0.010,
    "one DNS answer from kithd": 0.007,
}
# A local image (no registry): a rootfs holding the static kithd, which runs until stopped.
IMAGE = "local.test/timing:1"
WORKLOAD = {"apiVersion": "kith.dev/v1", "kind": "Workload", "metadata": {"name": "timing"},
            "spec": {"replicas": 1, "template": {"containers": [{"name": "main", "image": IMAGE, "command": ["/kithd", "--state", "/s", "--socket", "/s.sock"]}]}}}


def over(seconds, budget):
    """True when a timed run exceeds its budget. No budget yet: nothing is exceeded."""
    return budget is not None and seconds > budget


def wait_until(ok, what, limit=60.0):
    deadline = time.monotonic() + limit
    while not ok():
        if time.monotonic() > deadline:
            sys.exit(f"{what}: not within {limit:.0f} s")
        time.sleep(0.005)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class NotHere(Exception):
    """A timed path that this machine cannot run (no container starts on it), and what kithd said."""


class Daemon:
    """A kithd of its own: state and socket under dir, its log beside them."""

    def __init__(self, bins, dir, *args):
        os.makedirs(dir, exist_ok=True)
        self.bins = bins
        self.socket = os.path.join(dir, "kithd.sock")
        self.log = open(os.path.join(dir, "kithd.log"), "w")
        argv = [os.path.join(bins, "kithd"), "--state", os.path.join(dir, "state"), "--socket", self.socket, *args]
        self.proc = subprocess.Popen(argv, stdout=self.log, stderr=subprocess.STDOUT)
        wait_until(lambda: os.path.exists(self.socket) or self.proc.poll() is not None, "kithd to serve")
        if self.proc.poll() is not None:
            sys.exit(f"kithd did not start: see {self.log.name}")

    def kith(self, *args):
        argv = [os.path.join(self.bins, "kith"), "--socket", self.socket, *args]
        return subprocess.run(argv, check=True, capture_output=True, text=True).stdout

    def apply(self, name, doc):
        """`kith apply` of doc, written to a file beside the node's state."""
        path = os.path.join(os.path.dirname(self.socket), name + ".json")
        with open(path, "w") as f:
            json.dump(doc, f)
        return self.kith("apply", "-f", path)

    def said(self):
        """The last lines of its log and what it says of its Workloads and itself, on one line."""
        with open(self.log.name) as log:
            lines = log.read().splitlines()[-6:]
        for kind in ("Workload", "Node"):
            status = [w.get("status") for w in json.loads(self.kith("get", kind, "-o", "json"))]
            lines.append(f"{kind}: {json.dumps(status)[:700]}")
        return " | ".join(lines)

    def stop(self):
        self.proc.send_signal(signal.SIGTERM)
        self.proc.wait()
        self.log.close()


def local_image(state, bins):
    """Makes IMAGE in the state directory of a node that is not yet started."""
    digest = f"{1:064x}"
    images = os.path.join(state, "runtime", "images", digest)
    os.makedirs(os.path.join(images, "rootfs"))
    shutil.copy(os.path.join(bins, "kithd"), os.path.join(images, "rootfs", "kithd"))
    with open(os.path.join(images, "config.json"), "w") as f:
        f.write("{}")
    os.makedirs(os.path.join(state, "runtime", "refs"))
    said = {"digest": f"sha256:{digest}", "entrypoint": [], "cmd": [], "env": [], "user": None}
    with open(os.path.join(state, "runtime", "refs", IMAGE.replace("/", "%2f")), "w") as f:
        json.dump(said, f)


def apply_to_running(bins, dir):
    """Seconds from `kith apply` of a one-replica Workload to its replica running."""
    local_image(os.path.join(dir, "state"), bins)
    node = Daemon(bins, dir)
    try:
        began = time.monotonic()
        node.apply("workload", WORKLOAD)
        deadline = began + 20
        while running(node, "timing") != 1:
            if time.monotonic() > deadline:
                raise NotHere(node.said())
            time.sleep(0.005)
        return time.monotonic() - began
    finally:
        node.stop()


def running(node, name):
    listing = json.loads(node.kith("get", "Workload", "-o", "json"))
    return sum(w.get("status", {}).get("ready", 0) for w in listing if w["metadata"]["name"] == name)


def crossing(bins, dir):
    """Seconds from a change written on one kithd until another kithd, joined to it, has it."""
    address = f"127.0.0.1:{free_port()}"
    first = Daemon(bins, os.path.join(dir, "a"), "--name", "a", "--listen", address)
    try:
        token = first.kith("node", "token").strip()
        second = Daemon(bins, os.path.join(dir, "b"), "--name", "b", "--join", address, "--token", token)
        try:
            def config(value):
                return {"apiVersion": "kith.dev/v1", "kind": "ConfigMap", "metadata": {"name": "crossing"}, "spec": {"data": {"k": value}}}

            def seen(value):
                return f'"{value}"' in second.kith("get", "ConfigMap", "-o", "json")

            first.apply("before", config("before"))
            wait_until(lambda: seen("before"), "the second node to have the ConfigMap")
            began = time.monotonic()
            first.apply("after", config("after"))
            wait_until(lambda: seen("after"), "the change to reach the second node")
            return time.monotonic() - began
        finally:
            second.stop()
    finally:
        first.stop()


def dns_query(name):
    """A DNS query for the A record of name, as bytes."""
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return struct.pack(">HHHHHH", 0x5151, 0x0100, 1, 0, 0, 0) + labels + b"\0" + struct.pack(">HH", 1, 1)


def dns_answer(bins, dir):
    """Seconds from `kith apply` of a DNSRecord to kithd's answer carrying its address."""
    port = free_port()
    node = Daemon(bins, dir, "--dns", f"127.0.0.1:{port}")
    try:
        node.apply("zone", {"apiVersion": "kith.dev/v1", "kind": "DNSZone", "metadata": {"name": "home"}, "spec": {"domain": "home.example"}})
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(0.05)

            def reply(name):
                udp.sendto(dns_query(name), ("127.0.0.1", port))
                try:
                    return udp.recv(512)
                except TimeoutError:
                    return b""

            wait_until(lambda: reply("warm.home.example") != b"", "kithd to answer")
            address = socket.inet_aton("192.0.2.20")
            record = {"apiVersion": "kith.dev/v1", "kind": "DNSRecord", "metadata": {"name": "nas"},
                      "spec": {"zone": "home", "name": "nas", "type": "A", "values": ["192.0.2.20"]}}
            began = time.monotonic()
            node.apply("record", record)
            wait_until(lambda: address in reply("nas.home.example"), "the answer to carry the record", limit=30)
            return time.monotonic() - began
    finally:
        node.stop()


TIMED = {
    "apply to a running container": apply_to_running,
    "a status change reaching a second kithd": crossing,
    "one DNS answer from kithd": dns_answer,
}


def medians(bins, tmp, runs):
    """name -> (median seconds, every run in seconds) for the three timed paths."""
    found = {}
    for name, measure in TIMED.items():
        times = []
        try:
            for i in range(runs):
                dir = os.path.join(tmp, f"{name.split()[0]}-{i}")
                times.append(measure(bins, dir))
        except NotHere as said:
            print(f"skip {name}: it cannot be run here: {said}")
            continue
        found[name] = (statistics.median(times), times)
    return found


def check(name, what, actual, limit):
    ok = actual <= limit
    print(f"{'ok  ' if ok else 'FAIL'} {name}: {what} {actual / MB:.2f} MB (budget {limit / MB:.2f} MB)")
    return ok


def check_time(name, seconds, budget):
    if budget is None:
        print(f"time {name}: {seconds * 1000:.1f} ms (no budget yet: printed, not enforced)")
        return True
    ok = not over(seconds, budget)
    print(f"{'ok  ' if ok else 'FAIL'} {name}: {seconds * 1000:.1f} ms (budget {budget * 1000:.1f} ms)")
    return ok


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


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root)
    self_test = "--self-test" in sys.argv
    bin_dir = os.path.join(os.environ.get("CARGO_TARGET_DIR", "target"), TARGET, "release")
    with tempfile.TemporaryDirectory() as tmp:
        build_env = musl_cc(os.environ.copy())
        for binary in SIZE_BUDGETS:
            package = "kith-cli" if binary == "kith" else binary
            build = ["cargo", "build", "--release", "--quiet", "--target", TARGET, "-p", package]
            subprocess.run(build, check=True, env=build_env)
        if "--times" in sys.argv:
            # The same three paths, unjudged: the numbers the budgets are set from.
            print(f"load {os.getloadavg()[0]:.1f} on {os.cpu_count()} CPUs")
            for name, (median, times) in medians(bin_dir, tmp, RUNS).items():
                runs = ", ".join(f"{t * 1000:.1f}" for t in times)
                print(f"{name}: median {median * 1000:.1f} ms of {RUNS} runs ({runs} ms)")
            return
        results = []
        for binary, limit in SIZE_BUDGETS.items():
            size = os.path.getsize(os.path.join(bin_dir, binary))
            results.append(check(binary, "binary size", size, 1 if self_test else limit))
        env = {**os.environ, "KITH_STORE": os.path.join(tmp, "store.json")}
        for name, (args, limit) in RSS_BUDGETS.items():
            rss = peak_rss([os.path.join(bin_dir, "kith"), *args], env)
            results.append(check(name, "peak RSS", rss, 1 if self_test else limit))
        rss = idle_rss(os.path.join(bin_dir, "kithd"), tmp)
        results.append(check("kithd", "idle RSS", rss, 1 if self_test else KITHD_IDLE_RSS))
        timed = medians(bin_dir, tmp, 1 if self_test else RUNS)
        for name in TIMED:
            budget = 0.001 if self_test else TIME_BUDGETS[name]
            if name in timed:
                results.append(check_time(name, timed[name][0], budget))
            elif not self_test and budget is not None:
                # (A path with a budget is held to it: where it cannot be run, that is a failure.)
                print(f"FAIL {name}: it has a budget and could not be run here")
                results.append(False)
    if self_test:
        # With 1-byte and 1 ms budgets every check must fail; otherwise the checks check nothing.
        if any(results):
            sys.exit("self-test failed: a check passed against a 1-byte or 1 ms budget")
        print("self-test ok: every check fails against a 1-byte or 1 ms budget")
    elif not all(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
