#!/usr/bin/env python3
"""Phase 1 acceptance numbers (PLAN.md §7), measured through kithd and the CLI:

  - a container whose image is cached starts in under 150 ms (apply -> first output);
  - 20 containers run, and kithd stays under 30 MB RSS with them;
  - kithd (one thread) answers the API within 100 ms while it starts 20 containers.

Opt-in, like the e2e tests: it pulls an image and needs a delegated cgroup.

    python3 ci/budgets.py && python3 ci/bench.py     # budgets.py builds the static binaries

`--dry-run` alone measures what a dry run costs (time, peak RSS) with 1 000 and 10 000
resources in the store; it needs no image and no cgroup.
"""
import glob
import http.client
import json
import os
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time

IMAGE = os.environ.get("KITH_E2E_IMAGE", "mirror.gcr.io/library/busybox:1.36")
START_BUDGET = 0.150  # seconds
RSS_BUDGET = 30 * 1024 * 1024
API_BUDGET = 0.100  # seconds
WORKLOAD = """apiVersion: kith.dev/v1
kind: Workload
metadata: {{ name: {name} }}
spec:
  replicas: {replicas}
  template:
    containers:
      - name: main
        image: {image}
        command: [sh, -c, "echo up; sleep 600"]
        resources: {{ memory: 16Mi }}
"""


class Unix(http.client.HTTPConnection):
    """HTTP over kithd's unix socket."""

    def __init__(self, path):
        super().__init__("kithd")
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(self.path)


def dry_run(bins, tmp):
    """What one dry run (`POST /v1/apply?dryRun=true`, which /v1/diff is too) costs kithd
    with 1 000 and with 10 000 resources in its store: time (median of 20) and peak RSS."""
    path = os.path.join(tmp, "kithd.sock")
    daemon = subprocess.Popen([os.path.join(bins, "kithd"), "--state", os.path.join(tmp, "state"), "--socket", path])

    def post(url, body):
        conn = Unix(path)
        conn.request("POST", url, json.dumps(body), {"Content-Type": "application/json"})
        reply = conn.getresponse()
        text = reply.read()
        conn.close()
        if reply.status != 200:
            sys.exit(f"{url}: {reply.status} {text[:200]!r}")

    def config(i, value="x"):
        return {"apiVersion": "kith.dev/v1", "kind": "ConfigMap", "metadata": {"name": f"c{i}"}, "spec": {"data": {"k": value}}}

    try:
        while not os.path.exists(path):
            if daemon.poll() is not None:
                sys.exit("kithd did not start")
            time.sleep(0.01)
        time.sleep(0.5)
        filled = 0
        for size in (1000, 10000):
            for start in range(filled, size, 500):
                post("/v1/apply", [config(i) for i in range(start, min(start + 500, size))])
            filled = size
            times = []
            for _ in range(20):
                began = time.monotonic()
                post("/v1/apply?dryRun=true", [config(0, "changed")])
                times.append(time.monotonic() - began)
            with open(f"/proc/{daemon.pid}/status") as status:
                rss = int(next(l for l in status if l.startswith("VmHWM:")).split()[1]) * 1024
            print(f"dry run with {size} resources: {statistics.median(times) * 1000:.1f} ms (median of 20), kithd peak RSS {rss / 2**20:.1f} MB")
    finally:
        daemon.send_signal(signal.SIGTERM)
        daemon.wait()


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # The binaries ci/budgets.py just built.
    target = os.path.join(root, os.environ.get("CARGO_TARGET_DIR", "target"))
    bins = os.path.join(target, "x86_64-unknown-linux-musl", "release")
    os.makedirs(os.path.join(root, "target", "tmp"), exist_ok=True)
    if "--dry-run" in sys.argv:
        with tempfile.TemporaryDirectory(dir=os.path.join(root, "target", "tmp")) as tmp:
            return dry_run(bins, tmp)
    # Under target/: a unix socket path has to stay short.
    with tempfile.TemporaryDirectory(dir=os.path.join(root, "target", "tmp")) as tmp:
        socket = os.path.join(tmp, "kithd.sock")
        daemon = subprocess.Popen([os.path.join(bins, "kithd"), "--state", os.path.join(tmp, "state"), "--socket", socket])
        try:
            while not os.path.exists(socket):
                if daemon.poll() is not None:
                    sys.exit("kithd did not start")
                time.sleep(0.01)

            def start(name, replicas):
                """Seconds from `kith apply` to the last replica's first output."""
                path = os.path.join(tmp, name + ".yaml")
                with open(path, "w") as f:
                    f.write(WORKLOAD.format(name=name, replicas=replicas, image=IMAGE))
                began = time.monotonic()
                kith = [os.path.join(bins, "kith"), "--socket", socket]
                subprocess.run([*kith, "apply", "-f", path], check=True, stdout=subprocess.DEVNULL)
                while True:
                    logs = glob.glob(os.path.join(tmp, "state", "logs", f"w_default_{name}_*_main.out"))
                    if len(logs) == replicas and all(os.path.getsize(log) for log in logs):
                        return time.monotonic() - began
                    if time.monotonic() - began > 120:
                        sys.exit(f"{name}: not up after 120 s")
                    time.sleep(0.001)

            print(f"first start, with the pull: {start('cold', 1) * 1000:.0f} ms")
            cached = statistics.median(start(f"cached{i}", 1) for i in range(5))
            twenty = start("twenty", 20)

            # kithd is one thread: how long does the API go quiet while it starts 20 more?
            with open(os.path.join(tmp, "burst.yaml"), "w") as f:
                f.write(WORKLOAD.format(name="burst", replicas=20, image=IMAGE))
            kith = [os.path.join(bins, "kith"), "--socket", socket]
            subprocess.run([*kith, "apply", "-f", os.path.join(tmp, "burst.yaml")], check=True, stdout=subprocess.DEVNULL)
            stall, during = 0, 0

            def burst_up():
                logs = glob.glob(os.path.join(tmp, "state", "logs", "w_default_burst_*_main.out"))
                return len(logs) == 20 and all(os.path.getsize(log) for log in logs)

            # Only calls made before the burst is up count: later ones measure an idle kithd.
            deadline = time.monotonic() + 120
            while not burst_up():
                if time.monotonic() > deadline:
                    sys.exit("burst: not up after 120 s")
                began = time.monotonic()
                subprocess.run([*kith, "get", "ConfigMap"], check=True, stdout=subprocess.DEVNULL)
                stall = max(stall, time.monotonic() - began)
                during += 1
            time.sleep(1)
            # Peak, not current: a spike while 20 start at once counts too.
            with open(f"/proc/{daemon.pid}/status") as status:
                rss = int(next(l for l in status if l.startswith("VmHWM:")).split()[1]) * 1024
            listing = subprocess.run([os.path.join(bins, "kith"), "--socket", socket, "get", "-o", "json"], check=True, capture_output=True)
            running = sum(w["status"]["ready"] for w in json.loads(listing.stdout))
            total = sum(w["spec"].get("replicas", 1) for w in json.loads(listing.stdout))
        finally:
            daemon.send_signal(signal.SIGTERM)
            daemon.wait()

    results = [
        ("cached start (median of 5)", cached <= START_BUDGET, f"{cached * 1000:.0f} ms (budget {START_BUDGET * 1000:.0f} ms)"),
        ("containers still running", running == total == 46, f"{running} of {total}"),
        (
            "slowest API call while 20 containers start",
            during >= 3 and stall <= API_BUDGET,
            f"{stall * 1000:.0f} ms over {during} calls during the burst (budget {API_BUDGET * 1000:.0f} ms, at least 3 calls)",
        ),
        (f"kithd peak RSS with {total} containers", rss <= RSS_BUDGET, f"{rss / 2**20:.1f} MB (budget {RSS_BUDGET / 2**20:.0f} MB)"),
    ]
    print(f"20 replicas up: {twenty * 1000:.0f} ms")
    for name, ok, detail in results:
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {detail}")
    if not all(ok for _, ok, _ in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
