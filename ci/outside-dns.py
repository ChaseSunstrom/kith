"""The outside resolver of `sh ci/vm.sh --test poddns`: one name, outside.example.test, has
an address (198.51.100.7); every other name is NXDOMAIN. It answers UDP on 127.0.0.1 at the
port it is given, which is only the test's own VMs reach (through their 10.0.2.2)."""

import socket
import struct
import sys

NAME = "outside.example.test"
ADDRESS = bytes([198, 51, 100, 7])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", int(sys.argv[1])))
print(f"listening on 127.0.0.1:{sys.argv[1]}", file=sys.stderr, flush=True)
while True:
    query, peer = sock.recvfrom(512)
    print(f"received {len(query)} bytes from {peer[0]}:{peer[1]}", file=sys.stderr, flush=True)
    try:
        at, labels = 12, []
        while at < len(query) and query[at]:
            labels.append(query[at + 1 : at + 1 + query[at]].decode("ascii", "replace").lower())
            at += query[at] + 1
        question = query[12 : at + 5]
        qtype = struct.unpack(">H", query[at + 1 : at + 3])[0]
        name = ".".join(labels)
        answer = b""
        if name == NAME and qtype == 1:
            answer = struct.pack(">HHHLH", 0xC00C, 1, 1, 60, 4) + ADDRESS
        flags = 0x8180 | (0 if name == NAME else 3)
        head = query[:2] + struct.pack(">HHHHH", flags, 1, 1 if answer else 0, 0, 0)
        sock.sendto(head + question + answer, peer)
        print(f"asked {name} type {qtype} from {peer[0]}:{peer[1]}: answered {flags & 0xF}", file=sys.stderr, flush=True)
    except (struct.error, IndexError, UnicodeError):
        continue
