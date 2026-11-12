#!/usr/bin/env python3
"""Phase 1 acceptance numbers (PLAN.md §7), measured through kithd and the CLI:

  - a container whose image is cached starts in under 150 ms (apply -> first output);
  - 20 containers run, and kithd stays under 30 MB RSS with them.

Opt-in, like the e2e tests: it pulls an image and needs a delegated cgroup.

    python3 ci/budgets.py && python3 ci/bench.py     # budgets.py builds the static binaries
"""
import glob
import json
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import time

IMAGE = os.environ.get("KITH_E2E_IMAGE", "mirror.gcr.io/library/busybox:1.36")
START_BUDGET = 0.150  # seconds
RSS_BUDGET = 30 * 1024 * 1024
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


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # The binaries ci/budgets.py just built.
    target = os.path.join(root, os.environ.get("CARGO_TARGET_DIR", "target"))
    bins = os.path.join(target, "x86_64-unknown-linux-musl", "release")
    os.makedirs(os.path.join(root, "target", "tmp"), exist_ok=True)
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
                    logs = glob.glob(os.path.join(tmp, "state", "logs", f"default_{name}_*_main.out"))
                    if len(logs) == replicas and all(os.path.getsize(log) for log in logs):
                        return time.monotonic() - began
                    if time.monotonic() - began > 120:
                        sys.exit(f"{name}: not up after 120 s")
                    time.sleep(0.001)

            print(f"first start, with the pull: {start('cold', 1) * 1000:.0f} ms")
            cached = statistics.median(start(f"cached{i}", 1) for i in range(5))
            twenty = start("twenty", 20)
            time.sleep(1)
            # Peak, not current: a spike while 20 start at once counts too.
            with open(f"/proc/{daemon.pid}/status") as status:
                rss = int(next(l for l in status if l.startswith("VmHWM:")).split()[1]) * 1024
            listing = subprocess.run([os.path.join(bins, "kith"), "--socket", socket, "get", "-o", "json"], check=True, capture_output=True)
            running = sum(w["status"]["ready"] for w in json.loads(listing.stdout))
        finally:
            daemon.send_signal(signal.SIGTERM)
            daemon.wait()

    results = [
        ("cached start (median of 5)", cached <= START_BUDGET, f"{cached * 1000:.0f} ms (budget {START_BUDGET * 1000:.0f} ms)"),
        ("containers still running", running == 26, f"{running} of 26"),
        ("kithd peak RSS with 26 containers", rss <= RSS_BUDGET, f"{rss / 2**20:.1f} MB (budget {RSS_BUDGET / 2**20:.0f} MB)"),
    ]
    print(f"20 replicas up: {twenty * 1000:.0f} ms")
    for name, ok, detail in results:
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {detail}")
    if not all(ok for _, ok, _ in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
