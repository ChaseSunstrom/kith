"""A certificate authority for the tests: as much of ACME (RFC 8555) as kithd uses, and
checked the way a real one checks it (signatures, nonces, the challenge's answer).

usage: fake_acme.py ADDRESS PORT DIR    every host "resolves" to ADDRESS; listens on
                                        ADDRESS:PORT; its CA is DIR/ca.pem
"""

import base64, hashlib, http.server, json, subprocess, sys, urllib.request

EDGE, PORT, DIR = sys.argv[1], int(sys.argv[2]), sys.argv[3]
BASE = f"http://{EDGE}:{PORT}"
# What a challenge asks the host to say back (a made-up word, the same for every order).
CHALLENGE = "word_for-the-host"
P256 = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
state = {"nonces": set(), "count": 0, "jwk": None, "orders": 0, "host": None, "authz": "pending",
         "why": None, "order": "pending", "stale_once": True}


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def openssl(*args):
    return subprocess.run(["openssl", *args], capture_output=True)


def verified(jwk, signed, signature):
    def integer(raw):
        raw = raw.lstrip(b"\0") or b"\0"
        raw = b"\0" + raw if raw[0] & 0x80 else raw
        return b"\x02" + bytes([len(raw)]) + raw

    both = integer(signature[:32]) + integer(signature[32:])
    for name, data in [("pub.der", P256 + b"\x04" + unb64(jwk["x"]) + unb64(jwk["y"])),
                       ("sig.der", b"\x30" + bytes([len(both)]) + both), ("signed", signed)]:
        open(f"{DIR}/{name}", "wb").write(data)
    check = openssl("dgst", "-sha256", "-verify", f"{DIR}/pub.der", "-keyform", "DER",
                    "-signature", f"{DIR}/sig.der", f"{DIR}/signed")
    return len(signature) == 64 and check.returncode == 0


def thumbprint(jwk):
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, sort_keys=True, separators=(",", ":"))
    return b64(hashlib.sha256(canonical.encode()).digest())


class Problem(Exception):
    def __init__(self, kind, detail):
        self.kind, self.detail = kind, detail


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, body, headers=()):
        body = body if isinstance(body, bytes) else json.dumps(body).encode()
        state["count"] += 1
        nonce = f"nonce-{state['count']}"
        state["nonces"].add(nonce)
        self.send_response(code)
        self.send_header("Replay-Nonce", nonce)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.reply(200, b"")

    def do_GET(self):
        if self.path == "/orders":
            return self.reply(200, str(state["orders"]).encode())
        self.reply(200, {"newNonce": f"{BASE}/nonce", "newAccount": f"{BASE}/account", "newOrder": f"{BASE}/order"})

    def do_POST(self):
        try:
            self.reply(*self.post())
        except Problem as problem:
            body = {"type": f"urn:ietf:params:acme:error:{problem.kind}", "detail": problem.detail}
            self.reply(400, body)

    def post(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.headers["Content-Type"] != "application/jose+json":
            raise Problem("malformed", "not application/jose+json")
        protected = json.loads(unb64(body["protected"]))
        # (The first nonce anyone uses has gone stale, as happens: they must try again.)
        if protected["nonce"] not in state["nonces"] or state.pop("stale_once", False):
            raise Problem("badNonce", "a nonce we did not give, or gave before")
        state["nonces"].discard(protected["nonce"])
        if protected["alg"] != "ES256" or protected["url"] != BASE + self.path:
            raise Problem("malformed", f"alg or url: {protected}")
        if self.path == "/account":
            state["jwk"] = protected["jwk"]
        elif protected.get("kid") != f"{BASE}/account/1" or "jwk" in protected:
            raise Problem("accountDoesNotExist", "not the account's URL")
        signed = f"{body['protected']}.{body['payload']}".encode()
        if not verified(state["jwk"], signed, unb64(body["signature"])):
            raise Problem("malformed", "the signature does not check")
        payload = json.loads(unb64(body["payload"])) if body["payload"] else None

        if self.path == "/account":
            if not payload.get("termsOfServiceAgreed"):
                raise Problem("userActionRequired", "the terms are not agreed to")
            return 201, {"status": "valid"}, [("Location", f"{BASE}/account/1")]
        if self.path == "/order":
            [identifier] = payload["identifiers"]
            state.update(orders=state["orders"] + 1, host=identifier["value"], authz="pending", order="pending")
            return 201, self.order(), [("Location", f"{BASE}/order/1")]
        if self.path == "/order/1" and payload is None:
            return 200, self.order()
        if self.path == "/authz/1" and payload is None:
            challenge = {"type": "http-01", "url": f"{BASE}/challenge/1", "token": CHALLENGE, "status": state["authz"]}
            if state["why"]:
                challenge["error"] = {"detail": state["why"]}
            other = {"type": "dns-01", "url": f"{BASE}/nothing", "token": CHALLENGE}
            return 200, {"status": state["authz"], "challenges": [other, challenge]}
        if self.path == "/challenge/1" and payload == {}:
            wanted = CHALLENGE + "." + thumbprint(state["jwk"])
            ask = urllib.request.Request(f"http://{EDGE}:80/.well-known/acme-challenge/{CHALLENGE}", headers={"Host": state["host"]})
            try:
                got = urllib.request.urlopen(ask, timeout=5).read().decode()
            except OSError as e:
                got = f"({e})"
            state["authz"] = "valid" if got == wanted else "invalid"
            state["why"] = None if got == wanted else f"the host said {got!r}, not {wanted!r}"
            return 200, {"status": "processing"}
        if self.path == "/finalize/1" and state["authz"] == "valid":
            open(f"{DIR}/csr.der", "wb").write(unb64(payload["csr"]))
            asked = openssl("req", "-inform", "DER", "-in", f"{DIR}/csr.der", "-noout", "-text", "-verify")
            if asked.returncode != 0 or f"DNS:{state['host']}" not in asked.stdout.decode():
                raise Problem("badCSR", "the request is not for the order's name")
            made = openssl("x509", "-req", "-inform", "DER", "-in", f"{DIR}/csr.der", "-CA", f"{DIR}/ca.pem",
                           "-CAkey", f"{DIR}/ca.key", "-CAcreateserial", "-days", "90", "-copy_extensions", "copy",
                           "-out", f"{DIR}/cert.pem")
            if made.returncode != 0:
                raise Problem("serverInternal", made.stderr.decode())
            state["order"] = "valid"
            return 200, self.order()
        if self.path == "/cert/1" and payload is None and state["order"] == "valid":
            return 200, open(f"{DIR}/cert.pem", "rb").read(), [("Content-Type", "application/pem-certificate-chain")]
        raise Problem("malformed", f"nothing to do for {self.path}")

    def order(self):
        order = {"status": state["order"], "authorizations": [f"{BASE}/authz/1"], "finalize": f"{BASE}/finalize/1"}
        if state["order"] == "valid":
            order["certificate"] = f"{BASE}/cert/1"
        return order


made = openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout",
               f"{DIR}/ca.key", "-out", f"{DIR}/ca.pem.new", "-subj", "/CN=fake authority", "-days", "2")
assert made.returncode == 0, made.stderr.decode()
server = http.server.HTTPServer((EDGE, PORT), Handler)
# (Listening: say so by putting the CA where the test looks for it.)
import os
os.rename(f"{DIR}/ca.pem.new", f"{DIR}/ca.pem")
server.serve_forever()
