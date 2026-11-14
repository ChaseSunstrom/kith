#!/usr/bin/env python3
"""The workloads ci/compare.sh runs on kith and on Kubernetes alike, and what it measures of them.

    python3 ci/compare_workloads.py kith|k3s     (from compare.sh, which says where the API is)

Each measurement below is one piece of code for both systems; what differs is how each is
asked (`Kith`, `Kube`): the same containers, the same counts, the same clock. It prints
one line of `name=number`, which compare.sh puts in the run's row:

    cpu, cpu2     % of one CPU a node was busy over the three idle minutes: the first node
                  (the server), and the mean of the other two
    scale         s from applying one workload of 30 replicas until all are ready
    each          MB of memory in use, over the three nodes, that each of those replicas added
    burst         s from applying 20 workloads of one replica until all are ready
    roll          s from changing a workload of 6 replicas until all 6 run the change
    crash         s from a container's exit (code 1) until it runs again
    job           s from applying a Job until it has succeeded
    rps, p50, p99 requests a second, and the ms half and 99% of them took, through a Service
                  to three web servers, a new connection for each (ab, 20 at a time)
    kept          requests a second over connections that are kept open

The images are on the nodes before anything is timed.
"""

import http.client
import json
import os
import re
import socket
import ssl
import sys
import time

BUSYBOX = "mirror.gcr.io/library/busybox:1.36"
NGINX = "mirror.gcr.io/library/nginx:1.27-alpine"
# nginx told to keep what it writes in /tmp, to say what goes wrong on the output it was
# started with, and to answer on 8080: as its image comes it wants to be root and to write
# into its image, which a kith container is not and may not (Kubernetes lets it). The same
# on both systems, and no line written for a request.
WEB = """pid /tmp/nginx.pid; error_log stderr; events {} http { access_log off;
client_body_temp_path /tmp/a; proxy_temp_path /tmp/b; fastcgi_temp_path /tmp/c; uwsgi_temp_path /tmp/d; scgi_temp_path /tmp/e;
server { listen 8080; location / { return 200 'kith or not, the same page\n'; } } }"""
SERVE = ["sh", "-c", f'echo "{WEB}" >/tmp/web.conf && exec nginx -e stderr -c /tmp/web.conf -g "daemon off;"']
HTTPD = "mirror.gcr.io/library/httpd:2.4-alpine"
# What a container that only has to be there runs: it goes at once when told to.
STAY = ["sh", "-c", 'echo "$SAYS"; trap "exit 0" TERM; sleep 36000 & wait']


class Api:
    """Requests to a system's API as its admin, over one connection that is kept."""

    def __init__(self):
        self.port, self.name = int(os.environ["API_PORT"]), os.environ["API_NAME"]
        self.tls = ssl.create_default_context(cafile=os.environ["API_CA"])
        self.tls.load_cert_chain(os.environ["API_CERT"], os.environ["API_KEY"])
        self.connection = None

    def call(self, method, path, body=None, kind="application/json"):
        """The answer's status and what it says; 0 when there was no answer."""
        try:
            if self.connection is None:
                self.connection = http.client.HTTPSConnection(self.name, self.port, timeout=10)
                plain = socket.create_connection(("127.0.0.1", self.port), 10)
                self.connection.sock = self.tls.wrap_socket(plain, server_hostname=self.name)
            data = None if body is None else json.dumps(body).encode()
            self.connection.request(method, path, data, {"Content-Type": kind} if data else {})
            answer = self.connection.getresponse()
            return answer.status, answer.read()
        except (OSError, http.client.HTTPException) as e:
            self.connection = None
            return 0, str(e).encode()

    def get(self, path):
        status, body = self.call("GET", path)
        try:
            return json.loads(body) if status == 200 else None
        except ValueError:
            return None

    def must(self, method, path, body=None, kind="application/json"):
        status, said = self.call(method, path, body, kind)
        if not 200 <= status < 300:
            sys.exit(f"{method} {path}: {status}: {said[:600]!r}")
        return said


class Kith(Api):
    nodes = ["n1", "n2", "n3"]

    def unit(self, kind, name, image, command, replicas=None, says="", port=None, on=None):
        container = {"name": "run", "image": image, "command": command, "env": [{"name": "SAYS", "value": says}]}
        if port:
            container["ports"] = [{"name": "http", "port": port}]
        spec = {"template": {"containers": [container]}}
        if replicas is not None:
            spec["replicas"] = replicas
        if on:
            spec["placement"] = {"require": {"node.labels.role": on}}
        return {"apiVersion": "kith.dev/v1", "kind": kind, "metadata": {"name": name, "labels": {"app": name}}, "spec": spec}

    def workload(self, name, replicas, image=BUSYBOX, command=STAY, **more):
        return self.unit("Workload", name, image, command, replicas, **more)

    def job(self, name, image, command, **more):
        return self.unit("Job", name, image, command, **more)

    def service(self, name):
        spec = {"selector": {"app": name}, "ports": [{"port": 80, "targetPort": "http"}]}
        return {"apiVersion": "kith.dev/v1", "kind": "Service", "metadata": {"name": name}, "spec": spec}

    def apply(self, documents):
        self.must("POST", "/v1/apply", documents)

    def delete(self, kind, name):
        self.must("DELETE", f"/v1/resources/{kind}/default/{name}")

    def status(self, kind, name):
        return (self.get(f"/v1/resources/{kind}/default/{name}") or {}).get("status") or {}

    def ready(self, name):
        return self.status("Workload", name).get("ready") or 0

    def all_ready(self, names):
        found = self.get("/v1/resources") or []
        found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
        ready = {r["metadata"]["name"] for r in found if r["kind"] == "Workload" and (r.get("status") or {}).get("ready") == 1}
        return ready >= set(names)

    def gone(self, name):
        return self.call("GET", f"/v1/resources/Workload/default/{name}")[0] == 404

    def says(self, name, lines=1):
        """The last line (or lines) of each replica's container."""
        said = []
        for replica in self.status("Workload", name).get("nodes") or {}:
            log = self.get(f"/v1/logs/Workload/default/{name}?replica={replica}&tail={lines}")
            said.append(((log or {}).get("data") or "").strip())
        return said

    def starts(self, name):
        """What a one-replica workload's container said when it last started, and the time before
        (a replica's log goes on through its restarts)."""
        return "".join(self.says(name, 2)).split()

    def rolled(self, name, replicas, says):
        return self.ready(name) == replicas and self.says(name) == [says] * replicas

    def done(self, name):
        status = self.status("Job", name)
        if status.get("state") == "failed":
            sys.exit(f"the Job {name} failed: {status}")
        return status.get("state") == "succeeded"

    def output(self, name):
        return (self.get(f"/v1/logs/Job/default/{name}?tail=200") or {}).get("data") or ""

    def address(self, name):
        address = self.status("Service", name).get("address")
        return address and f"[{address}]"

    def backends(self, name):
        return self.status("Service", name).get("backends") or 0

    def read(self, node, lines):
        """The last lines of the reader (compare.sh's `mem`) on a node."""
        nodes = self.status("NodeWorkload", "mem").get("nodes") or {}
        replica = next((k if v == node else v for k, v in nodes.items() if node in (k, v)), None)
        log = self.get(f"/v1/logs/NodeWorkload/default/mem?replica={replica}&tail={lines}")
        return ((log or {}).get("data") or "").splitlines()


class Kube(Api):
    nodes = ["k1", "k2", "k3"]
    paths = {"Deployment": "/apis/apps/v1", "Job": "/apis/batch/v1", "Service": "/api/v1"}

    def path(self, kind, name=""):
        return f"{self.paths[kind]}/namespaces/default/{kind.lower()}s" + (f"/{name}" if name else "")

    def pod(self, name, image, command, says="", port=None, on=None, **more):
        container = {"name": "run", "image": image, "command": command, "env": [{"name": "SAYS", "value": says}]}
        if port:
            container["ports"] = [{"name": "http", "containerPort": port}]
        spec = {"terminationGracePeriodSeconds": 0, "containers": [container], **more}
        if on:
            spec["nodeSelector"] = {"role": on}
        return {"metadata": {"labels": {"app": name}}, "spec": spec}

    def workload(self, name, replicas, image=BUSYBOX, command=STAY, **more):
        spec = {"replicas": replicas, "selector": {"matchLabels": {"app": name}}, "template": self.pod(name, image, command, **more)}
        return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name}, "spec": spec}

    def job(self, name, image, command, **more):
        spec = {"backoffLimit": 0, "template": self.pod(name, image, command, restartPolicy="Never", **more)}
        return {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name}, "spec": spec}

    def service(self, name):
        spec = {"selector": {"app": name}, "ports": [{"port": 80, "targetPort": "http"}]}
        return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name}, "spec": spec}

    def apply(self, documents):
        # (What `kubectl apply --server-side` sends: one request for each, new or changed.)
        for document in documents:
            path = self.path(document["kind"], document["metadata"]["name"]) + "?fieldManager=compare&force=true"
            self.must("PATCH", path, document, "application/apply-patch+yaml")

    def delete(self, kind, name):
        kind = {"Workload": "Deployment"}.get(kind, kind)
        self.must("DELETE", self.path(kind, name), {"propagationPolicy": "Background"})

    def status(self, kind, name):
        return (self.get(self.path(kind, name)) or {}).get("status") or {}

    def ready(self, name):
        return self.status("Deployment", name).get("readyReplicas") or 0

    def all_ready(self, names):
        found = (self.get(self.path("Deployment")) or {}).get("items") or []
        ready = {d["metadata"]["name"] for d in found if (d.get("status") or {}).get("readyReplicas") == 1}
        return ready >= set(names)

    def pods(self, name):
        return (self.get(f"/api/v1/namespaces/default/pods?labelSelector=app%3D{name}") or {}).get("items") or []

    def gone(self, name):
        return self.call("GET", self.path("Deployment", name))[0] == 404 and not self.pods(name)

    def rolled(self, name, replicas, says):
        now = self.get(self.path("Deployment", name)) or {}
        status = now.get("status") or {}
        counts = [status.get(count) for count in ("replicas", "updatedReplicas", "readyReplicas", "availableReplicas")]
        return status.get("observedGeneration") == now.get("metadata", {}).get("generation") and counts == [replicas] * 4

    def says(self, name, more=""):
        lines = []
        for pod in self.pods(name):
            status, body = self.call("GET", f"/api/v1/namespaces/default/pods/{pod['metadata']['name']}/log?tailLines=1{more}")
            lines.append(body.decode(errors="replace").strip() if status == 200 else "")
        return lines

    def starts(self, name):
        # (Each container of a pod has a log of its own: the one before, and this one.)
        return "".join(self.says(name, "&previous=true")).split() + "".join(self.says(name)).split()

    def done(self, name):
        status = self.status("Job", name)
        if status.get("failed"):
            sys.exit(f"the Job {name} failed: {status}")
        return status.get("succeeded") == 1

    def output(self, name):
        pods = self.pods(name)
        status, body = self.call("GET", f"/api/v1/namespaces/default/pods/{pods[0]['metadata']['name']}/log?tailLines=200") if pods else (0, b"")
        return body.decode(errors="replace") if status == 200 else ""

    def address(self, name):
        return ((self.get(self.path("Service", name)) or {}).get("spec") or {}).get("clusterIP")

    def backends(self, name):
        found = self.get(f"/api/v1/namespaces/default/endpoints/{name}") or {}
        return sum(len(subset.get("addresses") or []) for subset in found.get("subsets") or [])

    def read(self, node, lines):
        pod = next((p["metadata"]["name"] for p in self.pods("mem") if p["spec"].get("nodeName") == node), None)
        status, body = self.call("GET", f"/api/v1/namespaces/default/pods/{pod}/log?tailLines={lines}")
        return body.decode(errors="replace").splitlines() if status == 200 else []


def until(what, holds, seconds=600, every=0.02, begun=None):
    """How long it took until `holds()`, from now or from `begun`."""
    begun = begun or time.monotonic()
    while time.monotonic() - begun < seconds:
        if holds():
            return time.monotonic() - begun
        time.sleep(every)
    sys.exit(f"waited {seconds} s for {what}")


def timed(api, what, documents, holds, seconds=600):
    begun = time.monotonic()
    api.apply(documents)
    return until(what, holds, seconds, begun=begun)


def reading(line):
    """Of a reader's line: MB in use, and the node's CPU time so far: (busy, all), in ticks."""
    words = line.split()
    ticks = [int(word) for word in words[words.index("cpu") + 1 :]]
    # user nice system idle iowait irq softirq steal: idle and iowait are not work.
    return (int(words[1]) - int(words[4])) / 1024, sum(ticks[:8]) - ticks[3] - ticks[4], sum(ticks[:8])


def in_use(api):
    return sum(reading(api.read(node, 1)[-1])[0] for node in api.nodes)


def idle_cpu(api, node, cpus, minutes=3):
    lines = api.read(node, minutes * 6 + 1)
    (_, busy, total), (_, busy_then, total_then) = reading(lines[-1]), reading(lines[0])
    # (Of one CPU: a node that kept one of its two busy says 100.)
    return 100 * cpus * (busy - busy_then) / (total - total_then)


def main():
    api = {"kith": Kith, "k3s": Kube}[sys.argv[1]]()
    cpus = int(os.environ.get("NODE_CPUS", "2"))
    out = {}

    # Idle first: what the nodes did in the minutes before any of this ran.
    out["cpu"] = f"{idle_cpu(api, api.nodes[0], cpus):.1f}"
    out["cpu2"] = f"{(idle_cpu(api, api.nodes[1], cpus) + idle_cpu(api, api.nodes[2], cpus)) / 2:.1f}"

    # One workload, many replicas; and what each of them costs in memory.
    many, before = 30, in_use(api)
    out["scale"] = f"{timed(api, 'thirty replicas', [api.workload('many', many)], lambda: api.ready('many') == many):.2f}"
    time.sleep(25)
    out["each"] = f"{(in_use(api) - before) / many:.1f}"
    api.delete("Workload", "many")
    until("the thirty to go", lambda: api.gone("many"))

    # Many workloads at once.
    names = [f"b{n}" for n in range(1, 21)]
    out["burst"] = f"{timed(api, 'twenty workloads', [api.workload(name, 1) for name in names], lambda: api.all_ready(names)):.2f}"
    for name in names:
        api.delete("Workload", name)
    until("the twenty to go", lambda: all(api.gone(name) for name in names))

    # A change, rolled through six replicas: done when every one of them says the new word.
    api.apply([api.workload("roll", 6, says="one")])
    until("six replicas", lambda: api.rolled("roll", 6, "one"))
    out["roll"] = f"{timed(api, 'the change in all six', [api.workload('roll', 6, says='two')], lambda: api.rolled('roll', 6, 'two')):.2f}"
    api.delete("Workload", "roll")

    # A container that fails: each start says the node's uptime, so the two are on one clock.
    api.apply([api.workload("crash", 1, command=["sh", "-c", "cut -d ' ' -f 1 /proc/uptime; sleep 3; exit 1"])])
    said = []

    def again():
        said[:] = api.starts("crash")
        return len(set(said)) == 2

    until("the container to start again", again, every=0.2)
    first, second = map(float, said)
    out["crash"] = f"{second - first - 3:.2f}"
    api.delete("Workload", "crash")

    # A task that runs once.
    out["job"] = f"{timed(api, 'a Job', [api.job('once', BUSYBOX, ['true'])], lambda: api.done('once')):.2f}"
    api.delete("Job", "once")

    # Requests through a Service: three web servers, and ab on the first node.
    api.apply([api.workload("web", 3, NGINX, SERVE, port=8080), api.service("web")])
    until("three web servers behind the Service", lambda: api.ready("web") == 3 and api.backends("web") == 3)
    address = api.address("web")
    for name, keep in (("rps", ""), ("kept", "-k ")):
        load = f"ab -q {keep}-n 20000 -c 20 http://{address}/"
        api.apply([api.job(name, HTTPD, ["sh", "-c", load], on="first")])
        until(f"ab ({name})", lambda: api.done(name), every=0.5)
        said = api.output(name)
        found = re.search(r"Requests per second:\s+([\d.]+)", said)
        failed = re.search(r"Failed requests:\s+(\d+)", said)
        if not found or not failed or failed.group(1) != "0" or "Non-2xx" in said:
            sys.exit(f"ab ({name}) did not answer for every request:\n{said}")
        out[name] = f"{float(found.group(1)):.0f}"
        if not keep:
            out["p50"], out["p99"] = (re.search(rf"^\s*{part}%\s+(\d+)", said, re.M).group(1) for part in (50, 99))
        api.delete("Job", name)
    api.delete("Workload", "web")
    api.delete("Service", "web")

    print(" ".join(f"{name}={value}" for name, value in out.items()))


if __name__ == "__main__":
    main()
