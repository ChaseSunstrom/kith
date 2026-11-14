#!/usr/bin/env python3
"""Screenshots of the website (docs/index.html), to look at before it is published.

    python3 ci/site_shots.py OUT     the whole page at 360, 768 and 1440 px, light and dark,
                                     as OUT/site-WIDTH-SCHEME.png, with reduced motion (so
                                     every part is drawn), each cut into pieces to read, and
                                     the first screen of each in OUT/top/ (docs/shots keeps those)

Needs a Chromium (playwright's headless shell in ~/.cache/ms-playwright, or CHROME=path).
"""
import functools
import glob
import http.server
import os
import pathlib
import subprocess
import sys
import threading

from PIL import Image

ROOT = pathlib.Path(__file__).resolve().parent.parent
PIECE = 2000  # px of page in one piece


def main():
    out = pathlib.Path(sys.argv[1])
    (out / "top").mkdir(parents=True, exist_ok=True)
    found = glob.glob(os.path.expanduser("~/.cache/ms-playwright/chromium_headless_shell-*/*/chrome-headless-shell"))
    chrome = os.environ.get("CHROME") or (found[-1] if found else sys.exit("no Chromium: set CHROME"))
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *said):
            pass

    serve = functools.partial(Quiet, directory=ROOT / "docs")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), serve)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    address = f"http://127.0.0.1:{server.server_address[1]}/index.html"
    for width in (360, 768, 1440):
        for scheme in ("light", "dark"):
            shot = out / f"site-{width}-{scheme}.png"
            # ponytail: a window taller than the page, cut back to it after; a real page height takes the devtools protocol
            flags = ["--no-sandbox", "--disable-gpu", "--hide-scrollbars", "--force-prefers-reduced-motion", f"--window-size={width},16000", "--virtual-time-budget=4000", f"--screenshot={shot}"]
            if scheme == "dark":
                flags.append("--blink-settings=preferredColorScheme=0")
            subprocess.run([chrome, *flags, address], check=True, capture_output=True, timeout=120)
            page = Image.open(shot).convert("RGB")
            ground = page.getpixel((2, page.height - 1))
            end = next(y for y in range(page.height - 1, 0, -1) if any(page.getpixel((x, y)) != ground for x in range(0, width, 7)))
            page = page.crop((0, 0, width, min(page.height, end + 24)))
            page.save(shot)
            page.crop((0, 0, width, 780 if width < 768 else 900)).save(out / "top" / shot.name)
            for i, top in enumerate(range(0, page.height, PIECE)):
                page.crop((0, top, width, min(page.height, top + PIECE))).save(out / f"site-{width}-{scheme}.{i}.png")
            print(shot, page.size)


if __name__ == "__main__":
    main()
