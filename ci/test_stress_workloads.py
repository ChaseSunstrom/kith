"""The stress adapter's exits, as a fake api answers them: python3 ci/test_stress_workloads.py"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
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


def test_the_raw_line_is_written_with_printf():
    compare = open(os.path.join(HERE, "compare.sh")).read()
    assert 'echo "k3s tried' not in compare and 'echo "kith tried' not in compare, "dash's echo turns the JSON's \\n into a newline"


def test_a_newline_in_the_limit_is_one_raw_line():
    out = sw.run(Fake(fail=ValueError("a\nb")), "k3s", {})
    got = subprocess.run(["sh", "-c", 'printf "%s\\n" "k3s tried $1"', "sh", json.dumps(out)], capture_output=True, text=True).stdout
    assert got.count("\n") == 1 and json.loads(got[len("k3s tried "):]) == out, got


def test_a_pipe_in_the_limit_is_not_a_section():
    line = sw.row({"size": 100, "nodes": 1, "mem_mb": "2048", "limit": "x | y", "where": "a", "system": "k3s", "max_pods": "110"})
    assert line.count(" | ") == 1 and "x / y" in line, line


def stress_sh(compare, tmp):
    """Runs a copy of ci/stress.sh whose compare.sh is `compare`; returns its exit status and the row it wrote."""
    ci = os.path.join(tmp, "ci")
    os.mkdir(ci)
    for name in ("stress.sh", "stress_workloads.py", "compare_workloads.py"):
        shutil.copy(os.path.join(HERE, name), ci)
    with open(os.path.join(ci, "compare.sh"), "w") as f:
        f.write(compare)
    out = os.path.join(tmp, "out.txt")
    run = subprocess.run(["sh", os.path.join(ci, "stress.sh"), "--system", "k3s", "--sizes", "100", "--nodes", "1", "--out", out],
                         capture_output=True, text=True)
    with open(out) as f:
        return run.returncode, f.read().splitlines()[-1]


def test_a_failure_before_the_adapter_names_its_step():
    compare = 'echo "Welcome to Alpine Linux" >&2\necho "compare.sh: FAIL: the memory readers did not all run" >&2\nexit 1\n'
    with tempfile.TemporaryDirectory() as tmp:
        status, row = stress_sh(compare, tmp)
    assert status == 1 and row.startswith("100 1 2048 limit no readings: the memory readers did not all run | "), row


def test_a_row_that_does_not_parse_is_a_limit_row():
    compare = r'''printf '%s\n' 'k3s tried {"limit": "cut' >>"$KITH_COMPARE_RAW"
'''
    with tempfile.TemporaryDirectory() as tmp:
        status, row = stress_sh(compare, tmp)
    assert status == 1 and row.startswith("100 1 2048 limit the adapter's row did not parse: "), row


if __name__ == "__main__":
    for name, test in list(globals().items()):
        if name.startswith("test_"):
            test()
            print(f"ok {name}")
