#!/usr/bin/env python3
"""Screenshots of the web UI (crates/kithd/ui) over a real cluster: three kithds on this machine.

    python3 ci/ui_shots.py OUT            the overview (the dashboard), at 1440, 768 and 360 px, light
                                          and dark, as OUT/ui-dash-WIDTH-SCHEME.png, its figures
                                          crates/kithd/ui/fixture.mjs's (see SHIM); the board with a
                                          Workload open, at 1440 and 390 px, light
                                          and dark, as OUT/ui-WIDTH-SCHEME.png; and its other tabs
                                          the review of a change and a kind with nothing in it,
                                          as OUT/ui-SCENE-SCHEME.png; the Install part and a join
                                          token shown once, as OUT/ui-install-WIDTH-SCHEME.png
                                          and OUT/ui-token-WIDTH-SCHEME.png; Add a peer, its question
                                          and the QR code it shows once, as OUT/ui-peer-WIDTH-SCHEME.png
                                          and OUT/ui-qr-WIDTH-SCHEME.png
    python3 ci/ui_shots.py OUT --serve    the same cluster left up at the printed address, to look
                                          at by hand; Enter ends it

The page's files are read from crates/kithd/ui as they are on disk, so a change shows without a
build, and are sent with the policy crates/kithd/src/ui.rs gives them; every other request goes
to the first node's socket, the way `kith ui` passes it on. What runs is `exec` units (sleep),
so nothing is pulled. Builds target/debug/kithd and kith first (cargo build), and needs a Chromium
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
TARGET = pathlib.Path(os.environ.get("CARGO_TARGET_DIR") or ROOT / "target")  # (a lane builds in a folder of its own)
HOLD = 5  # seconds the page is given to connect and draw before it is photographed
KINDS = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8", ".woff2": "font/woff2"}
POLICY = re.sub(r"\\\n\s*", "", re.search(r'const POLICY: &str = "(.*?)";', (ROOT / "crates/kithd/src/ui.rs").read_text(), re.S).group(1))
# What the photographed page is given besides its own files: a hand, for the scenes that need a click.
DRIVE = """
const scene = new URLSearchParams(location.search).get('scene');
const tab = (name) => [...document.querySelectorAll('#tabs button')].find((button) => button.textContent === name).click();
// (A step that cannot be taken is told to the script, which then fails: no photograph of the wrong scene.)
const step = (ms, act) => setTimeout(() => { try { act(); } catch (error) { fetch(`failed?${encodeURIComponent(`${scene}: ${error}`)}`); } }, ms);
const press = (id) => document.getElementById(id).click();
if (scene === 'Install' || scene === 'Token') {
  // The Install part: no sideways scroll, and for Token the dialog that shows a join token once.
  if (scene === 'Token') step(1500, () => { document.getElementById('token-at').selectedIndex = 1; press('token-make'); step(500, () => press('dialog-yes')); });
  step(3500, () => {
    if (document.documentElement.scrollWidth > innerWidth) throw new Error(`sideways overflow: ${document.documentElement.scrollWidth} > ${innerWidth}`);
    if (document.getElementById('install').hidden) throw new Error('the Install part is not in view');
  });
}
if (scene === 'Peer' || scene === 'Qr') {
  // Add a peer: Peer is its question, filled in; Qr the configuration it shows once (see SHIM).
  step(1800, () => {
    press('peer-add');
    step(400, () => {
      for (const [id, value] of [['peer-name', 'phone'], ['peer-node', 'alpha'], ['peer-level', 'family']]) document.getElementById(id).value = value;
      if (scene === 'Qr') step(300, () => press('dialog-yes'));
    });
  });
  step(3500, () => {
    if (!document.getElementById('dialog').open) throw new Error('the dialog is not open');
    if (document.documentElement.scrollWidth > innerWidth) throw new Error(`sideways overflow: ${document.documentElement.scrollWidth} > ${innerWidth}`);
    if (scene === 'Qr' && !document.querySelector('canvas.qr')) throw new Error('no QR code is drawn');
  });
}
if (scene === 'Dash') {
  // The overview: every chart drawn, a line per node, and no sideways scroll at any width; and the
  // first load, which SHIM fails part way, drawn on its retry (not left waiting for a change).
  step(3500, () => {
    if (document.querySelectorAll('#kinds li').length === 0) throw new Error('the kinds were not drawn after a first load that failed');
    if (document.getElementById('link').textContent !== 'live') throw new Error(`the link says ${document.getElementById('link').textContent}`);
    if (!/^updated \\d\\d:\\d\\d:\\d\\d$/.test(document.getElementById('updated').textContent)) throw new Error('no updated time');
    if (document.getElementById('dash').hidden) throw new Error('the overview is not in view');
    if (document.querySelectorAll('#charts .chart-panel').length < 6) throw new Error('not every chart is there');
    if (!document.querySelector('#charts .series')) throw new Error('no chart has a line');
    if (document.documentElement.scrollWidth > innerWidth) throw new Error(`sideways overflow: ${document.documentElement.scrollWidth} > ${innerWidth}`);
  });
}
step(1500, () => {
  if (['Install', 'Token', 'Peer', 'Qr', 'Dash'].includes(scene)) return;
  if (scene !== 'Review') return scene && scene !== 'Empty' && tab(scene);
  const replicas = [...document.querySelectorAll('.field')].find((field) => field.querySelector('label')?.textContent.startsWith('replicas')).querySelector('input');
  replicas.value = '5';
  replicas.dispatchEvent(new Event('input', { bubbles: true }));
  step(700, () => document.getElementById('review').click());
});
"""
# The Peer and Qr scenes: these nodes have no people device (that takes root, and a kernel's WireGuard), so
# what the page asks of kithd is answered here: alpha says it has one, and a peer is made with
# the documentation's own sample key. Nothing else is touched, and it is for photographs only.
# The Dash scene: nodes this young have kept no history, so /v1/metrics is answered from the
# fixture the tests use (crates/kithd/ui/fixture.mjs), ending now; its nodes are this cluster's.
SHIM = """\
const scene = new URLSearchParams(location.search).get('scene');
if (scene === 'Dash') {
  const real = window.fetch;
  let failed = false;
  window.fetch = async (url, init = {}) => {
    const asked = new URL(String(url), location.href);
    // (The first load fails part way, after the watch answered: the page must draw on its retry.)
    if (asked.pathname.endsWith('/v1/schemas') && !failed) {
      failed = true;
      throw new TypeError('Failed to fetch');
    }
    if (!asked.pathname.endsWith('/v1/metrics')) return real(url, init);
    const { fixture } = await import('./fixture.mjs');
    const body = fixture(asked.searchParams.get('range') ?? '1h', Math.floor(Date.now() / 1000));
    return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
  };
}
if (scene === 'Peer' || scene === 'Qr') {
  const real = window.fetch;
  const config = ['[Interface]', 'PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=', 'Address = 100.89.2.3/32, fd8a:1c3f:5b9d:2::3/128',
    'DNS = 10.1.0.53', '', '[Peer]', 'PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=', 'Endpoint = vpn.example.org:51821',
    'AllowedIPs = 192.168.0.0/16, fd12::/16, 100.89.0.1/32, fd8a:1c3f:5b9d::1/128, 10.1.0.53/32', 'PersistentKeepalive = 25', ''].join('\\n');
  window.fetch = async (url, init = {}) => {
    const text = String(url);
    if (init.method === 'POST' && text.endsWith('/v1/peers')) {
      return new Response(JSON.stringify({ ...JSON.parse(init.body), config }), { headers: { 'content-type': 'application/json' } });
    }
    const got = await real(url, init);
    if (!/\\/v1\\/(watch|resources)/.test(text)) return got;
    const json = await got.json();
    for (const one of Array.isArray(json) ? json : json.resources) {
      if (one.kind === 'Node' && one.metadata.name === 'alpha') one.status = { ...one.status, people: { endpoint: 'vpn.example.org:51821' } };
    }
    return new Response(JSON.stringify(json), { status: got.status, headers: got.headers });
  };
}
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
---
apiVersion: kith.dev/v1
kind: AccessLevel
metadata: { name: family }
spec:
  networks: [10.1.0.0/24]
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
    # (A lane's own target folder starts empty: what is already built, cargo leaves.)
    subprocess.run(["cargo", "build", "-q", "-p", "kithd", "-p", "kith-cli"], cwd=ROOT, check=True)
    # (In /tmp whatever TMPDIR says: a socket's path has 108 bytes to fit in.)
    work = pathlib.Path(tempfile.mkdtemp(prefix="kith-ui-", dir="/tmp"))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit("ended"))  # so the nodes are put away then too
    nodes = []
    failed = []

    def kith(*args):
        env = {k: v for k, v in os.environ.items() if k != "KITH_STORE"} | {"KITH_SOCKET": str(work / "alpha/kithd.sock")}
        return subprocess.run([TARGET / "debug/kith", *args], env=env, capture_output=True, text=True)

    def node(name, *more):
        (work / name).mkdir()
        log = open(work / name / "log", "w")
        args = ["--state", "state", "--socket", "kithd.sock", "--name", name, "--registry-port", "0", "--listen", f"127.0.0.1:{free()}", *more]
        nodes.append(subprocess.Popen([TARGET / "debug/kithd", *args], cwd=work / name, stdin=subprocess.DEVNULL, stdout=log, stderr=log))
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
                if self.path in ("/ui/drive.js", "/ui/shim.js", "/ui/still.css"):
                    self.send_response(200)
                    self.send_header("content-type", KINDS[self.path[-3:] if self.path.endswith(".js") else ".css"])
                    self.end_headers()
                    return self.wfile.write({"/ui/drive.js": DRIVE.encode(), "/ui/shim.js": SHIM.encode(), "/ui/still.css": STILL}[self.path])
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
                    held = b'<img src="hold" alt="" hidden><link rel="stylesheet" href="still.css"><script src="shim.js"></script><script type="module" src="drive.js"></script>' if file.name == "index.html" and "--serve" not in sys.argv else b""
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
        views += [(width, height, scheme, "Dash") for width, height in ((1440, 1400), (768, 2300), (360, 3300)) for scheme in ("light", "dark")]
        views += [(1440, 900, scheme, scene) for scene in ("YAML", "Status", "History", "Logs", "Review", "Empty") for scheme in ("light", "dark")]
        # (The Install part, and a join token shown once, at both widths.)
        views += [(width, height, scheme, scene) for scene in ("Install", "Token") for width, height in ((1440, 1500), (390, 2400)) for scheme in ("light", "dark")]
        # (Add a peer: its question, and the configuration it shows once, at both widths.)
        views += [(width, height, scheme, scene) for scene in ("Peer", "Qr") for width, height in ((1440, 900), (390, 1500)) for scheme in ("light", "dark")]
        for width, height, scheme, scene in views:
            shot = out / (f"ui-{scene.lower()}-{width}-{scheme}.png" if scene in ("Install", "Token", "Peer", "Qr", "Dash") else f"ui-{scene.lower() or width}-{scheme}.png")
            flags = ["--no-sandbox", "--disable-gpu", "--hide-scrollbars", f"--window-size={width},{height}", f"--screenshot={shot}"]
            if scheme == "dark":
                flags.append("--blink-settings=preferredColorScheme=0")
            # (Empty: a kind the scene has none of, open with nothing in it.)
            opened = {"Dash": "#/", "Empty": "#/Secret", "Install": "#/install", "Token": "#/install", "Peer": "#/RemotePeer", "Qr": "#/RemotePeer"}.get(scene)
            url = address.replace("scene=", f"scene={scene}")
            if opened:
                url = url.replace("#/Workload/default/web", opened)
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
