"""A machine that is not a node, speaking NFS 4.2 to a kith Share (no mount, no root).

  nfs_probe.py HOST PORT PATH [mkdir NAME]

Walks PATH from the server's root; with `mkdir NAME`, makes a directory there. Prints the
NFS status of the walk (and of the mkdir): 0 is done, 2 no such thing, 13 not allowed,
30 read-only, 10016 wrong security (nobody to this server). Exit 0 whatever it prints,
1 when the server did not speak NFS at all.
"""

import os
import socket
import struct
import sys


def u32(n):
    return struct.pack(">I", n)


def opaque(data):
    return u32(len(data)) + data + b"\0" * (-len(data) % 4)


def call(sock, xid, ops):
    """One COMPOUND of `ops` (already packed); the reply's body after the RPC header."""
    cred = u32(0) + opaque(b"probe") + u32(0) + u32(0) + u32(0)  # AUTH_SYS: root, who is squashed
    head = u32(xid) + u32(0) + u32(2) + u32(100003) + u32(4) + u32(1) + u32(1) + opaque(cred) + u32(0) + u32(0)
    body = head + opaque(b"") + u32(2) + u32(len(ops)) + b"".join(ops)
    sock.sendall(u32(0x80000000 | len(body)) + body)
    reply = b""
    while True:
        (mark,) = struct.unpack(">I", read(sock, 4))
        reply += read(sock, mark & 0x7FFFFFFF)
        if mark & 0x80000000:
            break
    # xid, REPLY, accepted, verifier (flavor, length 0), success
    if struct.unpack(">6I", reply[:24]) != (xid, 1, 0, 0, 0, 0):
        raise OSError(f"not an accepted RPC reply: {reply[:24].hex()}")
    return reply[24:]


def read(sock, n):
    data = b""
    while len(data) < n:
        more = sock.recv(n - len(data))
        if not more:
            raise OSError("the server hung up")
        data += more
    return data


def results(body):
    """(status of the whole, the bytes after the tag and the count of results)."""
    status, tag = struct.unpack(">II", body[:8])
    return status, body[8 + tag + (-tag % 4) + 4 :]


def main():
    host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    make = sys.argv[5] if len(sys.argv) > 5 and sys.argv[4] == "mkdir" else None
    with socket.create_connection((host, port), timeout=10) as sock:
        owner = os.urandom(8)
        # EXCHANGE_ID: who we are; no state protection; no implementation id.
        status, rest = results(call(sock, 1, [u32(42) + owner + opaque(b"kith-probe-" + owner.hex().encode()) + u32(0) + u32(0) + u32(0)]))
        if status:
            print(status)
            return
        client, sequence = rest[8:16], rest[16:20]
        # CREATE_SESSION: one slot each way, no callbacks.
        channel = u32(0) + u32(65536) + u32(65536) + u32(4096) + u32(16) + u32(1) + u32(0)
        status, rest = results(call(sock, 2, [u32(43) + client + sequence + u32(0) + channel + channel + u32(0) + u32(1) + u32(0)]))
        if status:
            print(status)
            return
        session = rest[8:24]
        count = [0]

        def seq():
            count[0] += 1
            return u32(53) + session + u32(count[0]) + u32(0) + u32(0) + u32(0)

        walk = [u32(24)] + [u32(15) + opaque(part.encode()) for part in path.split("/") if part]
        status, _ = results(call(sock, 3, [seq()] + walk))
        print(status)
        if make is not None and status == 0:
            # CREATE a directory, mode 0755.
            create = u32(6) + u32(2) + opaque(make.encode()) + u32(2) + u32(0) + u32(2) + opaque(u32(0o755))
            status, _ = results(call(sock, 4, [seq()] + walk + [create]))
            print(status)


try:
    main()
except OSError as e:
    print(f"nfs_probe: {e}", file=sys.stderr)
    sys.exit(1)
