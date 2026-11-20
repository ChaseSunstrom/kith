"""Joins two of the tests' LANs (QEMU socket netdevs: Ethernet frames as datagrams to
230.0.0.1:PORT on 127.0.0.1) into one, as a switch would: what --test home puts its roaming node
on, so the node can be cut off from the voters' own addresses and still reach the house address.

  lan_bridge.py PORT_A PORT_B CUTFILE

Every frame heard on one LAN is sent on the other. While the file CUTFILE exists, a frame that
carries one of the voters' own addresses (10.9.0.1 to 10.9.0.3) as an IPv4 source or destination,
or as an ARP sender or target, is dropped instead: whatever else is on the LAN (the house
address, the machines asking about it) still passes.
"""

import collections
import os
import select
import socket
import sys

ports = (int(sys.argv[1]), int(sys.argv[2]))
cut = sys.argv[3]
voters = {socket.inet_aton(f"10.9.0.{n}") for n in (1, 2, 3)}
here = socket.inet_aton("127.0.0.1")


def join(port):
    lan = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    lan.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lan.bind(("230.0.0.1", port))
    lan.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton("230.0.0.1") + here)
    lan.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, here)
    lan.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    return lan


def voters_own(frame):
    kind, rest = frame[12:14], frame[14:]
    if kind == b"\x08\x00" and len(rest) >= 20:
        return rest[12:16] in voters or rest[16:20] in voters
    if kind == b"\x08\x06" and len(rest) >= 28:
        return rest[14:18] in voters or rest[24:28] in voters
    return False


lans = [join(ports[0]), join(ports[1])]
# (What was sent on a LAN comes back to this socket, as multicast loops: it is not sent on again.)
sent = [collections.Counter(), collections.Counter()]
while True:
    for lan in select.select(lans, [], [])[0]:
        i = lans.index(lan)
        frame = lan.recv(65536)
        if sent[i][frame]:
            sent[i][frame] -= 1
            if not sent[i][frame]:
                del sent[i][frame]
            continue
        if os.path.exists(cut) and voters_own(frame):
            continue
        sent[1 - i][frame] += 1
        lans[1 - i].sendto(frame, ("230.0.0.1", ports[1 - i]))
