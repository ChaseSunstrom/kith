#!/usr/bin/env python3
"""An SNTP server for ci/vm/clock.sh: answers each request with this machine's clock (stratum 2).

usage: sntp_standin.py PORT COUNT_FILE  (binds 127.0.0.1:PORT, which a QEMU user-mode guest reaches
as 10.0.2.2:PORT; COUNT_FILE holds the number of requests answered so far)
"""
import socket
import struct
import sys
import time

NTP_UNIX = 2208988800  # seconds from 1900 to 1970


def stamp(t):
    return struct.pack(">II", int(t) + NTP_UNIX, int((t % 1) * (1 << 32)))


port, count_file = int(sys.argv[1]), sys.argv[2]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", port))
answered = 0
while True:
    request, peer = sock.recvfrom(512)
    if len(request) < 48:
        continue
    now = stamp(time.time())
    # LI 0, version 4, mode 4; stratum 2; poll 4; precision -20; delay, dispersion, reference id;
    # then four stamps: reference, originate (the request's transmit stamp), receive, transmit.
    answer = struct.pack(">BBBb", 0x24, 2, 4, -20) + bytes(12) + now + request[40:48] + now + now
    sock.sendto(answer, peer)
    answered += 1
    with open(count_file, "w") as f:
        f.write(f"{answered}\n")
