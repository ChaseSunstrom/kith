#!/usr/bin/env python3
"""What ci/stress.sh asks of kith, run in place of ci/compare_workloads.py inside ci/compare.sh.

    stress_workloads.py kith          load: STRESS_SIZE replicas, churn, Services; prints JSON
    stress_workloads.py stop JSON     the first node is stopped as its power button stops it
    stress_workloads.py after JSON    the first node is back: is the store as it was
    stress_workloads.py header|row    the lines of ci/stress.txt (a row is read from stdin)

STRESS_NODES=1 puts every replica on the first node (ci/compare.sh labels it role=first); the
other two machines are up and empty. A wait that makes no progress for two minutes, or takes
longer than a cap that grows with the size, is the size's limit: what it was waiting for, and
what the nodes say of themselves (a reader on every node: free memory, tasks, open files,
cgroups; kithd's last lines from the console), so that a full machine is not taken for a
limit of kith's. Everything it makes is kept for the restart; the machines go with the script.
"""

import json
import os
import re
import socket
import sys
import time

from compare_workloads import BUSYBOX, NGINX, SERVE, Kith, reading

SIZE = int(os.environ.get("STRESS_SIZE", "100"))
NODES = int(os.environ.get("STRESS_NODES", "3"))
MEMORY = os.environ.get("KITH_COMPARE_MEM", "2048")
WORK = os.environ.get("COMPARE_WORK", "")
ON = "first" if NODES == 1 else None
# What a node says of itself every 5 s, from its own /proc: free memory, running/all tasks,
# open files, cgroups (the pids controller's count), and what the first process holds.
LIMITS = 'while :; do echo $(grep -E "^MemAvailable:" /proc/meminfo) $(cut -d" " -f4 /proc/loadavg) $(cut -f1 /proc/sys/fs/file-nr) $(awk "\\$1==\\"pids\\"{print \\$3}" /proc/cgroups); sleep 5; done'
COLUMNS = "size nodes mem_mb ready_s mem_each_mb cpu_each_pct kithd_mb down_s up_s roll_s crash_s services svc_s spread answers store back_s".split()
KINDS = ("Workload", "Service", "NodeWorkload")


class Limit(Exception):
    pass


def wait(what, count, target, stall=120, every=0.25):
    """Seconds until count() reaches target; a Limit when it stops rising for `stall` s or takes too long."""
    begun = moved = time.monotonic()
    best, cap = -1, 240 + 3 * SIZE
    while True:
        now, have = time.monotonic(), count()
        if have >= target:
            return now - begun
        if have > best:
            best, moved = have, now
        if now - moved > stall or now - begun > cap:
            raise Limit(f"{what}: {have} of {target} after {now - begun:.0f} s")
        time.sleep(every)


def listed(api):
    found = api.get("/v1/resources") or []
    return found if isinstance(found, list) else found.get("resources", found.get("items", []))


def workload(api, name, replicas, **more):
    return api.workload(name, replicas, on=ON, **more)


def cpu(api):
    """% of one CPU, over the reader's last 30 s on every node."""
    total = 0
    for node in api.nodes:
        lines = api.read(node, 4)
        if len(lines) < 4:
            raise Limit(f"{node}'s reader has said {len(lines)} lines")
        (_, busy, all_), (_, busy0, all0) = reading(lines[-1]), reading(lines[0])
        total += 100 * int(os.environ.get("NODE_CPUS", "2")) * (busy - busy0) / (all_ - all0)
    return total


def used(api):
    return sum(reading(api.read(node, 1)[-1])[0] for node in api.nodes)


def say(api, node):
    """What the node's own reader (`limits`) last said, as words, or what is wrong."""
    nodes = api.status("NodeWorkload", "limits").get("nodes") or {}
    replica = next((k if v == node else v for k, v in nodes.items() if node in (k, v)), None)
    log = api.get(f"/v1/logs/NodeWorkload/default/limits?replica={replica}&tail=1") if replica else None
    found = re.search(r"MemAvailable:\s+(\d+) kB (\d+)/(\d+) (\d+) (\d+)", (log or {}).get("data") or "")
    if not found:
        return f"{node}: no answer"
    free, running, tasks, files, cgroups = map(int, found.groups())
    return f"{node}: free={free // 1024}MB tasks={tasks} (running {running}) files={files} cgroups={cgroups}"


def console(n, lines):
    try:
        with open(f"{WORK}/n{n}.log", "rb") as log:
            log.seek(0, 2)
            log.seek(max(0, log.tell() - 20000))
            text = log.read().decode(errors="replace")
    except OSError:
        return []
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]|[^\x20-\x7e\n]", "", text)
    noise = re.compile(r"used greatest stack depth|lists only v1 controllers")
    return [line.strip()[:160] for line in text.splitlines() if line.strip() and not noise.search(line)][-lines:]


def look(api):
    """What the nodes say of themselves, now."""
    code, why = api.call("GET", "/v1/resources/Node/n1")
    said = [f"api: {code if code else why.decode(errors='replace')[:80]}"] + [say(api, node) for node in api.nodes]
    ooms = sum(len(re.findall(r"Out of memory|oom-kill|Killed process", " ".join(console(n, 400)))) for n in (1, 2, 3))
    return " | ".join(said + [f"oom_kills={ooms}", "kithd: " + " / ".join(console(1, 3))])


def load(api, out):
    api.apply([api.unit("NodeWorkload", "limits", BUSYBOX, ["sh", "-c", LIMITS])])
    wait("the readers", lambda: api.status("NodeWorkload", "limits").get("ready") or 0, 3)
    for node in api.nodes:  # (compare.sh's reader prints every 10 s: 30 s of it is four lines)
        wait(f"{node}'s reader", lambda: len(api.read(node, 4)), 4)
    mem0, cpu0 = used(api), cpu(api)

    out["ready_s"] = f"{timed(api, 'many', [workload(api, 'many', SIZE)], lambda: api.ready('many'), SIZE):.2f}"
    time.sleep(40)
    out["mem_each_mb"] = f"{(used(api) - mem0) / SIZE:.2f}"
    out["cpu_each_pct"] = f"{(cpu(api) - cpu0) / SIZE:.3f}"

    # Churn: half of them away and all of them back, a change rolled through all, and one that fails.
    half = SIZE // 2
    out["down_s"] = f"{timed(api, 'scaled down', [workload(api, 'many', half)], lambda: SIZE - api.ready('many'), SIZE - half):.2f}"
    out["up_s"] = f"{timed(api, 'scaled up', [workload(api, 'many', SIZE)], lambda: api.ready('many'), SIZE):.2f}"
    # (Each look at the rolled change is a request for every replica's log: not one in a quarter second.)
    out["roll_s"] = f"{timed(api, 'rolled', [workload(api, 'many', SIZE, says='two')], lambda: sum(s == 'two' for s in api.says('many')), SIZE, every=1):.2f}"
    api.apply([workload(api, "crash", 1, command=["sh", "-c", "cut -d ' ' -f 1 /proc/uptime; sleep 3; exit 1"])])
    said = []

    def again():
        said[:] = api.starts("crash")
        return len(set(said))

    wait("the container that exits to start again", again, 2)
    first, second = map(float, said)
    out["crash_s"] = f"{second - first - 3:.2f}"
    api.delete("Workload", "crash")

    # Many Services, each of three replicas that are not told where to run.
    count = max(1, SIZE // 10)
    names = [f"web{i}" for i in range(count)]
    begun = time.monotonic()
    api.apply([d for name in names for d in (workload(api, name, 3, image=NGINX, command=SERVE, port=8080), api.service(name))])

    def served():
        found = listed(api)
        by = {(r["kind"], r["metadata"]["name"]): r.get("status") or {} for r in found}
        return sum(by.get(("Service", n), {}).get("backends") == 3 and by.get(("Workload", n), {}).get("ready") == 3 for n in names)

    try:
        wait("the Services to have their three backends", served, count, every=1)
    except Limit as e:  # (say how the first one that was not served stands)
        stuck = next((n for n in names if api.backends(n) != 3 or api.ready(n) != 3), names[0])
        log = (api.get(f"/v1/logs/Workload/default/{stuck}?replica=0&tail=3") or {}).get("data") or ""
        raise Limit(f"{e}; {stuck} has {api.ready(stuck)} of 3 replicas ready and {api.backends(stuck)} backends; its first replica says {log.strip()!r}") from None
    out["services"] = count
    out["svc_s"] = f"{time.monotonic() - begun:.2f}"
    spread = sum(len(set((api.status("Workload", n).get("nodes") or {}).values())) > 1 for n in names)
    out["spread"] = f"{spread}/{count}"

    # Still answering, and what the store holds, to be read back after the restart.
    answered = time.monotonic()
    nodes = [r for r in listed(api) if r["kind"] == "Node" and (r.get("status") or {}).get("state") == "ready"]
    out["answers"] = f"{'yes' if len(nodes) == 3 and time.monotonic() - answered < 10 else 'no'}"
    out["stored"] = len([r for r in listed(api) if r["kind"] in KINDS])


def timed(api, what, documents, count, target, every=0.25):
    begun = time.monotonic()
    api.apply(documents)
    wait(what, count, target, every=every)
    return time.monotonic() - begun


def stop(out):
    """The first node's power button, over QMP; its console then says what kithd held."""
    pid = int(open(f"{WORK}/n1.pid").read())
    alive = lambda: os.path.exists(f"/proc/{pid}")
    try:
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(10)
            s.connect(f"{WORK}/n1.qmp")
            f = s.makefile("rw")
            f.readline()
            for command in ("qmp_capabilities", "system_powerdown"):
                f.write(json.dumps({"execute": command}) + "\n")
                f.flush()
                f.readline()
    except OSError as e:
        out["stopped"] = f"no power button: {e}"
    for _ in range(240):
        if not alive():
            break
        time.sleep(1)
    if alive():  # (the recorded pid of this run's machine, and no other)
        os.kill(pid, 9)
        out["stopped"] = "killed"
        time.sleep(2)
    held = re.findall(r"told to stop: (\d+) kB resident", "\n".join(console(1, 200)))
    if held:
        out["kithd_mb"] = f"{int(held[-1]) / 1024:.1f}"


def after(api, out):
    begun = time.monotonic()
    try:
        found = [r for r in listed(api) if r["kind"] in KINDS]
        many = api.get("/v1/resources/Workload/default/many") or {}
        replicas = ((many.get("spec") or {}).get("replicas"))
        out["store"] = "ok" if len(found) == out["stored"] and replicas == SIZE else f"{len(found)} of {out['stored']} resources, many has {replicas}"
        wait("the replicas to run again", lambda: api.ready("many"), SIZE)
        out["back_s"] = f"{time.monotonic() - begun:.2f}"
    except Limit as e:
        out["limit"] = f"after the restart {e}"
        out["where"] = look(api)


def row(out):
    mem = out.get("mem_mb", MEMORY)
    if "limit" in out:
        done = " ".join(f"{k}={out[k]}" for k in COLUMNS[3:] if k in out)
        return f"{out['size']} {out['nodes']} {mem} limit {out['limit']} | {out.get('where', 'nodes not read')}" + (f" | measured: {done}" if done else "")
    return " ".join(str(out.get(k, "-")) for k in COLUMNS)


def main():
    what = sys.argv[1]
    if what == "header":
        print("# " + " ".join(COLUMNS))
        print("# a size that fails has SIZE NODES MEM_MB, then the word in place of ready_s and what it waited for in vain | each node's free memory, tasks, open files, cgroups | oom kills | kithd's last console lines")
        return
    out = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    if what == "row":
        print(row(json.load(sys.stdin)))
        return
    api = Kith()
    out.update(size=SIZE, nodes=NODES, mem_mb=MEMORY)
    try:
        if what == "kith":
            load(api, out)
        elif what == "stop":
            stop(out)
        elif what == "after":
            after(api, out)
    except Limit as e:
        out["limit"] = str(e)
        out["where"] = look(api)
    except SystemExit as e:  # (a request the node refused: api.must)
        out["limit"] = f"the node refused: {e.code}"
        out["where"] = look(api)
    print(json.dumps(out))


if __name__ == "__main__":
    main()
