#!/usr/bin/env python3
"""Screenshots of the website (docs/index.html), to look at before it is published.

    python3 ci/site_shots.py [OUT]   the whole page at 360, 768 and 1440 px, light and dark,
                                     as OUT/site-WIDTH-SCHEME.png (OUT is docs/shots), with
                                     reduced motion (so every part is drawn), each cut into
                                     pieces to read, and the first screen of each in OUT/top/
                                     (docs/shots keeps those); and fails when anything sticks
                                     out past the screen's width, at each of the three

Needs a Chromium (playwright's headless shell in ~/.cache/ms-playwright, or CHROME=path).
"""
import functools
import glob
import http.server
import os
import pathlib
import re
import subprocess
import sys
import threading

from PIL import Image

ROOT = pathlib.Path(__file__).resolve().parent.parent
PIECE = 2000  # px of page in one piece


# The page in a frame of the width asked, and what sticks out of it: anything whose right edge is
# past the frame and that no scrolling box of its own (a <pre>) holds. body hides sideways overflow,
# so a screenshot cannot show it: this is how "no horizontal scroll" is held.
PROBE = """<!doctype html><iframe id=f src="index.html" style="width:%dpx;height:900px;border:0"></iframe>
<script>f.onload = () => setTimeout(() => {
  const d = f.contentDocument, w = d.documentElement.clientWidth, out = [];
  const held = el => { for (let p = el.parentElement; p && p !== d.body; p = p.parentElement) if (/auto|scroll|hidden/.test(f.contentWindow.getComputedStyle(p).overflowX)) return true; return false; };
  for (const el of d.body.querySelectorAll("*")) { const r = el.getBoundingClientRect(); if (r.width && r.right > w + 1 && !held(el)) out.push(el.tagName + "." + (el.getAttribute("class") || "") + ":" + Math.round(r.right)); }
  document.body.textContent = "WIDE " + w + " " + d.documentElement.scrollHeight + " " + JSON.stringify(out.slice(0, 8));
}, 600);</script>"""


def main():
    out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs/shots"
    (out / "top").mkdir(parents=True, exist_ok=True)
    found = glob.glob(os.path.expanduser("~/.cache/ms-playwright/chromium_headless_shell-*/*/chrome-headless-shell"))
    chrome = os.environ.get("CHROME") or (found[-1] if found else sys.exit("no Chromium: set CHROME"))
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *said):
            pass

        def do_GET(self):
            if self.path.startswith("/probe-"):
                try:
                    body = (PROBE % int(self.path[len("/probe-"):].split(".")[0])).encode()
                except ValueError:
                    return self.send_error(404)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                super().do_GET()

    serve = functools.partial(Quiet, directory=ROOT / "docs")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), serve)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    address = f"http://127.0.0.1:{server.server_address[1]}/index.html"
    failed = False
    for width in (360, 768, 1440):
        # first what sticks out and how tall the page is: the window below is made that tall
        said = subprocess.run([chrome, "--no-sandbox", "--disable-gpu", "--force-prefers-reduced-motion", "--virtual-time-budget=4000", "--dump-dom", address.replace("index.html", f"probe-{width}.html")], check=True, capture_output=True, text=True, timeout=120).stdout
        wide = re.search(r"WIDE \d+ (\d+) (\[.*?\])", said)
        print(f"{width} px: {'no sideways overflow' if wide and wide.group(2) == '[]' else 'STICKS OUT ' + (wide.group(2) if wide else said[:200])}")
        failed |= not (wide and wide.group(2) == "[]")
        tall = int(wide.group(1)) + 200 if wide else 16000
        for scheme in ("light", "dark"):
            shot = out / f"site-{width}-{scheme}.png"
            # ponytail: a window taller than the page, cut back to it after; a real page height takes the devtools protocol
            flags = ["--no-sandbox", "--disable-gpu", "--hide-scrollbars", "--force-prefers-reduced-motion", f"--window-size={width},{tall}", "--virtual-time-budget=4000", f"--screenshot={shot}"]
            if scheme == "dark":
                flags.append("--blink-settings=preferredColorScheme=0")
            subprocess.run([chrome, *flags, address], check=True, capture_output=True, timeout=120)
            page = Image.open(shot).convert("RGB")
            ground = page.getpixel((2, page.height - 1))
            end = next((y for y in range(page.height - 1, 0, -1) if any(page.getpixel((x, y)) != ground for x in range(0, width, 7))), page.height - 1)
            page = page.crop((0, 0, width, min(page.height, end + 24)))
            page.save(shot)
            page.crop((0, 0, width, 780 if width < 768 else 900)).save(out / "top" / shot.name)
            for i, top in enumerate(range(0, page.height, PIECE)):
                page.crop((0, top, width, min(page.height, top + PIECE))).save(out / f"site-{width}-{scheme}.{i}.png")
            print(shot, page.size)
        # and the first screen as it moves, five seconds in (no reduced motion: the map is running)
        live = out / "top" / f"live-{width}.png"
        subprocess.run([chrome, "--no-sandbox", "--disable-gpu", "--hide-scrollbars", f"--window-size={width},{780 if width < 768 else 900}", "--virtual-time-budget=5000", f"--screenshot={live}", address], check=True, capture_output=True, timeout=120)
    if failed:
        sys.exit("something is wider than the screen: see above")


if __name__ == "__main__":
    main()
