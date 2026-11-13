"""An OCI registry for the tests: as much of the distribution API as pushing, pulling
and listing tags takes, kept in memory.

usage: fake_registry.py PORT READY    listens on 127.0.0.1:PORT, then creates READY
"""

import hashlib, http.server, json, re, sys

blobs, manifests, uploads = {}, {}, {}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, code, body=b"", headers=()):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def body(self):
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def route(self):
        path, _, query = self.path.partition("?")
        if path == "/v2/":
            return self.reply(200, b"{}")
        found = re.fullmatch(r"/v2/(.+)/(blobs/uploads|blobs|manifests|tags)/?(.*)", path)
        if not found:
            return self.reply(404)
        name, what, rest = found.groups()
        verb = self.command
        if what == "tags":
            tags = sorted(tag for (of, tag) in manifests if of == name and not tag.startswith("sha256:"))
            return self.reply(200, json.dumps({"name": name, "tags": tags}).encode())
        if what == "blobs" and verb in ("GET", "HEAD"):
            if rest not in blobs:
                return self.reply(404)
            return self.reply(200, blobs[rest], [("Docker-Content-Digest", rest)])
        if what == "blobs/uploads" and verb == "POST":
            uploads[str(len(uploads))] = b""
            where = f"/v2/{name}/blobs/uploads/{len(uploads) - 1}"
            return self.reply(202, headers=[("Location", where), ("Range", "0-0")])
        if what == "blobs/uploads" and verb == "PATCH":
            uploads[rest] += self.body()
            end = max(len(uploads[rest]) - 1, 0)
            return self.reply(202, headers=[("Location", f"/v2/{name}/blobs/uploads/{rest}"), ("Range", f"0-{end}")])
        if what == "blobs/uploads" and verb == "PUT":
            data = uploads.pop(rest) + self.body()
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
            if f"digest={digest}".replace(":", "%3A") not in query and f"digest={digest}" not in query:
                return self.reply(400, b"the digest is not the blob's")
            blobs[digest] = data
            return self.reply(201, headers=[("Location", f"/v2/{name}/blobs/{digest}"), ("Docker-Content-Digest", digest)])
        if what == "manifests" and verb == "PUT":
            data = self.body()
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
            kind = self.headers.get("Content-Type")
            manifests[(name, rest)] = manifests[(name, digest)] = (kind, data, digest)
            return self.reply(201, headers=[("Location", f"/v2/{name}/manifests/{digest}"), ("Docker-Content-Digest", digest)])
        if what == "manifests" and verb in ("GET", "HEAD"):
            if (name, rest) not in manifests:
                return self.reply(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}')
            kind, data, digest = manifests[(name, rest)]
            return self.reply(200, data, [("Content-Type", kind), ("Docker-Content-Digest", digest)])
        self.reply(405)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = route


server = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
open(sys.argv[2], "w").close()
server.serve_forever()
