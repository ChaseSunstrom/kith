#!/usr/bin/env python3
"""A signed log entry for ci/vm/access.sh, as the leader's own writes make one (kith-store's
Command::Signed), for POST /v1/forge: the admin's signature (Ed25519, "local socket") over a
POST /v1/apply of SIGNED_BODY, around the command CARRIED_BODY makes. They are one file for an
entry that is what was signed; two for one whose body was changed after.

usage: forge_entry.py KEY.der CLUSTER_ID EXPIRES NONCE SIGNED_BODY [CARRIED_BODY [COMMAND_BODY]]  (the entry, on stdout)

CARRIED_BODY is the body the entry holds beside the signature (the signature fails if it is not
SIGNED_BODY); COMMAND_BODY the resources of the command it holds (it is not what the body makes
if it is not CARRIED_BODY): each is the one before it when left out.

KEY.der is the PKCS8 of the admin's Ed25519 key; CLUSTER_ID the SHA-256 print of the cluster's CA
certificate. The bytes signed are access_sign::bytes's: the fields each ending in one newline.
"""
import base64
import hashlib
import json
import subprocess
import sys
import tempfile

key, cluster, expires, nonce, signed_file = sys.argv[1:6]
carried_file = sys.argv[6] if len(sys.argv) > 6 else signed_file
command_file = sys.argv[7] if len(sys.argv) > 7 else carried_file
signed, carried = open(signed_file, "rb").read(), open(carried_file, "rb").read()
command = open(command_file, "rb").read()
message = f"kith-signed-v1\n{cluster}\n*\nPOST\n/v1/apply\n{hashlib.sha256(signed).hexdigest()}\nlocal socket\n{expires}\n{nonce}\n"
with tempfile.NamedTemporaryFile() as file:
    file.write(message.encode())
    file.flush()
    sig = subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", key, "-in", file.name],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
header = f"v1; who=local socket; target=*; expires={expires}; nonce={nonce}; sig={base64.b64encode(sig).decode()}"
entry = {
    "Signed": {
        "header": header,
        "method": "POST",
        "path": "/v1/apply",
        "body": base64.b64encode(carried).decode(),
        "command": {"Apply": {"resources": json.loads(command), "at": 0}},
    }
}
print(json.dumps(entry))
