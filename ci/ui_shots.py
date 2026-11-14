#!/usr/bin/env python3
"""Screenshots of the web UI (crates/kithd/ui) over a real cluster: three kithds on this machine.

    python3 ci/ui_shots.py OUT            the board with a Workload open, at 1440 and 390 px, light
                                          and dark, as OUT/ui-WIDTH-SCHEME.png; and its other tabs
                                          the review of a change and a kind with nothing in it,
                                          as OUT/ui-SCENE-SCHEME.png
    python3 ci/ui_shots.py OUT --serve    the same cluster left up at the printed address, to look
                                          at by hand; Enter ends it

The page's files are read from crates/kithd/ui as they are on disk, so a change shows without a
build, and are sent with the policy crates/kithd/src/ui.rs gives them; every other request goes
to the first node's socket, the way `kith ui` passes it on. What runs is `exec` units (sleep),
so nothing is pulled. Needs target/debug/kithd and kith (cargo build) and a Chromium
(playwright's headless shell in ~/.cache/ms-playwright, or CHROME=path).
"""
import glob
import http.server
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent
UI = ROOT / "crates/kithd/ui"
HOLD = 5  # seconds the page is given to connect and draw before it is photographed
KINDS = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".woff2": "font/woff2"}
POLICY = re.sub(r"\\\n\s*", "", re.search(r'const POLICY: &str = "(.*?)";', (ROOT / "crates/kithd/src/ui.rs").read_text(), re.S).group(1))
# What the photographed page is given besides its own files: a hand, for the scenes that need a click.
DRIVE = """
const scene = new URLSearchParams(location.search).get('scene');
const tab = (name) => [...document.querySelectorAll('#tabs button')].find((button) => button.textContent === name).click();
// (A step that cannot be taken is told to the script, which then fails: no photograph of the wrong scene.)
const step = (ms, act) => setTimeout(() => { try { act(); } catch (error) { fetch(`failed?${encodeURIComponent(`${scene}: ${error}`)}`); } }, ms);
step(1500, () => {
  if (scene !== 'Review') return scene && scene !== 'Empty' && tab(scene);
  const replicas = [...document.querySelectorAll('.field')].find((field) => field.querySelector('label')?.textContent.startsWith('replicas')).querySelector('input');
  replicas.value = '5';
  replicas.dispatchEvent(new Event('input', { bubbles: true }));
  step(700, () => document.getElementById('review').click());
});
"""
# And a still hand: what waits blinks, and a photograph would catch it at any point of that.
STILL = b".wait, .wait::before { animation: none !important; }"
SCENE = """\
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: web }
spec:
  replicas: 3
  template:
    exec: [{ name: run, command: [sh, -c, 'echo serving; exec sleep 3600'] }]
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: queue }
spec:
  replicas: 2
  template:
    exec: [{ name: run, command: [sh, -c, 'echo waiting for work; exec sleep 3600'] }]
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: mail }
spec:
  replicas: 2
  template:
    exec: [{ name: run, command: [sh, -c, 'echo no relay configured >&2; exit 1'] }]
---
apiVersion: kith.dev/v1
kind: ConfigMap
metadata: { name: site }
spec:
  data: { title: kith }
"""


def free():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def until(what, ok, seconds=90):
    end = time.time() + seconds
    while time.time() < end:
        if ok():
            return
        time.sleep(0.5)
    sys.exit(f"gave up waiting for {what}")


def main():
    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    # (In /tmp whatever TMPDIR says: a socket's path has 108 bytes to fit in.)
    work = pathlib.Path(tempfile.mkdtemp(prefix="kith-ui-", dir="/tmp"))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit("ended"))  # so the nodes are put away then too
    nodes = []
    failed = []

    def kith(*args):
        env = {k: v for k, v in os.environ.items() if k != "KITH_STORE"} | {"KITH_SOCKET": str(work / "alpha/kithd.sock")}
        return subprocess.run([ROOT / "target/debug/kith", *args], env=env, capture_output=True, text=True)

    def node(name, *more):
        (work / name).mkdir()
        log = open(work / name / "log", "w")
        args = ["--state", "state", "--socket", "kithd.sock", "--name", name, "--registry-port", "0", "--listen", f"127.0.0.1:{free()}", *more]
        nodes.append(subprocess.Popen([ROOT / "target/debug/kithd", *args], cwd=work / name, stdin=subprocess.DEVNULL, stdout=log, stderr=log))
        return args[9]

    try:
        alpha = node("alpha")
        until("alpha", lambda: kith("get", "node").returncode == 0)
        for name in ("beta", "gamma"):
            node(name, "--join", alpha, "--token", kith("node", "token").stdout.strip())
        until("three ready nodes", lambda: kith("get", "node").stdout.count("ready at") == 3)
        (work / "scene.yaml").write_text(SCENE)
        applied = kith("apply", "-f", str(work / "scene.yaml"))
        if applied.returncode:
            sys.exit(applied.stderr)
        until("web's three replicas", lambda: "3/3" in kith("get", "workload/web").stdout)

        class Page(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *said):
                pass

            def do_GET(self):
                file = UI / (self.path.split("?")[0][len("/ui/"):] or "index.html") if self.path.startswith("/ui/") else None
                if self.path.startswith("/ui/failed?"):
                    failed.append(urllib.parse.unquote(self.path.split("?", 1)[1]))
                    return self.send_error(404)
                if self.path == "/ui/hold":
                    time.sleep(HOLD)
                    return self.send_error(404)
                if self.path in ("/ui/drive.js", "/ui/still.css"):
                    self.send_response(200)
                    self.send_header("content-type", KINDS[self.path[-3:] if self.path.endswith(".js") else ".css"])
                    self.end_headers()
                    return self.wfile.write(DRIVE.encode() if self.path.endswith(".js") else STILL)
                if file and file.name == "overpass.woff2":
                    file = ROOT / "docs/fonts/overpass.woff2"  # (kithd carries the website's own copy)
                if file and file.is_file() and file.parent in (UI, ROOT / "docs/fonts") and file.suffix in KINDS:
                    self.send_response(200)
                    self.send_header("content-type", KINDS[file.suffix])
                    self.send_header("content-security-policy", POLICY)
                    self.end_headers()
                    # ponytail: Chromium photographs at the load event, which is before the watch has
                    # brought anything; an image that is slow to not be there holds that event back.
                    # A devtools client could wait for the board instead.
                    held = b'<img src="hold" alt="" hidden><link rel="stylesheet" href="still.css"><script type="module" src="drive.js"></script>' if file.name == "index.html" and "--serve" not in sys.argv else b""
                    return self.wfile.write(file.read_bytes() + held)
                # Not the page's: to kithd, word for word, and back until kithd is done (a watch never is).
                body = self.rfile.read(int(self.headers.get("content-length") or 0))
                head = "".join(f"{k}: {v}\r\n" for k, v in self.headers.items() if k.lower() != "connection")
                with socket.socket(socket.AF_UNIX) as up:
                    up.connect(str(work / "alpha/kithd.sock"))
                    up.sendall(f"{self.command} {self.path} HTTP/1.1\r\n{head}connection: close\r\n\r\n".encode() + body)
                    try:
                        while chunk := up.recv(65536):
                            self.wfile.write(chunk)
                            self.wfile.flush()
                    except OSError:
                        pass

            do_POST = do_PUT = do_DELETE = do_GET

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Page)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        address = f"http://127.0.0.1:{server.server_address[1]}/ui/?scene=#/Workload/default/web"
        if "--serve" in sys.argv:
            print(address, flush=True)
            sys.stdin.readline()
            return
        found = sorted(glob.glob(os.path.expanduser("~/.cache/ms-playwright/chromium_headless_shell-*/*/chrome-headless-shell")))
        chrome = os.environ.get("CHROME") or (found[-1] if found else sys.exit("no Chromium: set CHROME"))
        views = [(1440, 900, scheme, "") for scheme in ("light", "dark")] + [(390, 2200, scheme, "") for scheme in ("light", "dark")]
        views += [(1440, 900, scheme, scene) for scene in ("YAML", "Status", "History", "Logs", "Review", "Empty") for scheme in ("light", "dark")]
        for width, height, scheme, scene in views:
            shot = out / f"ui-{scene.lower() or width}-{scheme}.png"
            flags = ["--no-sandbox", "--disable-gpu", "--hide-scrollbars", f"--window-size={width},{height}", f"--screenshot={shot}"]
            if scheme == "dark":
                flags.append("--blink-settings=preferredColorScheme=0")
            # (Empty: a kind the scene has none of, open with nothing in it.)
            url = address.replace("scene=", f"scene={scene}").replace("#/Workload/default/web" if scene == "Empty" else "#/none", "#/Secret")
            subprocess.run([chrome, *flags, url], check=True, capture_output=True, timeout=120)
            print(shot)
        if failed:
            sys.exit("the hand that drives the page failed: " + "; ".join(failed))
    finally:
        for process in nodes:
            process.terminate()
        for process in nodes:
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
