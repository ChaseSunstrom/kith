"""The stress adapter's exits, as a fake api answers them: python3 ci/test_stress_workloads.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stress_workloads as sw  # noqa: E402

LINES = tuple(f"MemAvailable: 1000 kB cpu {10 * i} 0 20 {30 + 5 * i} 0 0 0 0" for i in range(4))  # (the ticks go up)
SAID = "MemAvailable: 2097152 kB 2/120 80 10"


class Fake:
    nodes = ["k1", "k2", "k3"]

    def __init__(self, lines=LINES, fail=None):
        self.lines, self.fail = list(lines), fail

    def reader(self, name, command):
        pass

    def readers_ready(self, name):
        return 3

    def read(self, node, lines):
        return self.lines[-lines:] if self.lines else []

    def workload(self, name, replicas, **more):
        return {}

    def apply(self, documents):
        if self.fail:
            raise self.fail

    def reader_said(self, node, name):
        return SAID

    def probe(self):
        return 0, b"refused"

    def running(self, node):
        return None


class Pods(Fake):
    def running(self, node):
        return 3, 2


def test_an_empty_reader_is_a_limit():
    try:
        sw.used(Fake(lines=[]))
    except sw.Limit as e:
        assert "k1" in str(e), e
        return
    raise AssertionError("an empty reader did not raise a Limit")


def test_an_error_is_the_rows_cause():
    out = sw.run(Fake(fail=ValueError("boom")), "k3s", {})
    assert out["limit"] == "the adapter failed: ValueError: boom", out
    assert out["where"].startswith("api: "), out


def test_a_limit_keeps_its_nodes_when_they_cannot_be_read():
    class Broken(Fake):
        def probe(self):
            raise RuntimeError("no answer")

    out = sw.run(Broken(fail=sw.Limit("the test")), "k3s", {})
    assert out["limit"] == "the test", out
    assert out["where"].startswith("nodes not read: RuntimeError"), out


def test_a_refusal_is_still_a_limit():
    out = sw.run(Fake(fail=SystemExit("HTTP 422")), "k3s", {})
    assert out["limit"] == "the node refused: HTTP 422", out


def test_a_node_says_its_pods():
    assert "pods=3 (running 2)" in sw.say(Pods(), "k1"), sw.say(Pods(), "k1")


class Silent(Fake):
    def reader_said(self, node, name):
        return "log HTTP 0"


def test_a_silent_reader_says_why():
    assert "no answer (log HTTP 0)" in sw.say(Silent(), "k1"), sw.say(Silent(), "k1")


def test_a_row_is_one_line():
    line = sw.row({"size": 100, "nodes": 1, "mem_mb": "2048", "limit": "x\ny", "where": "a\nb", "system": "k3s", "max_pods": "110"})
    assert "\n" not in line and line.endswith("k3s max_pods=110"), line


if __name__ == "__main__":
    for name, test in list(globals().items()):
        if name.startswith("test_"):
            test()
            print(f"ok {name}")
