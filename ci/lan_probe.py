"""A machine on a node's LAN that is not a VM: sends one UDP datagram to the node and says
what comes back (what `vm.sh --test tunnel` asks a pod's published UDP port).

  lan_probe.py GROUP_PORT MAC ADDRESS PORT TEXT

The test's LAN is QEMU's socket netdev: Ethernet frames as datagrams to 230.0.0.1:GROUP_PORT
on 127.0.0.1. This joins it as 10.9.0.77, sends TEXT to ADDRESS:PORT (the card MAC), answers
the node's ARP for itself, and prints what ADDRESS:PORT sends back. Exit 1 when nothing came
in five seconds. (QEMU's restricted user network drops every UDP answer of its guest's: the
test's card out, which reaches nothing else, can carry no UDP answer back to this machine.)
"""

import socket
import struct
import sys
import time

group_port, mac, to, to_port, text = sys.argv[1:6]
group = ("230.0.0.1", int(group_port))
node_mac, node = bytes.fromhex(mac.replace(":", "")), socket.inet_aton(to)
me_mac, me = bytes.fromhex("525400000977"), socket.inet_aton("10.9.0.77")
my_port = 40977


def checksum(header):
    total = sum(struct.unpack(f">{len(header) // 2}H", header))
    total = (total >> 16) + (total & 0xFFFF)
    return ~(total + (total >> 16)) & 0xFFFF


def datagram():
    udp = struct.pack(">HHHH", my_port, int(to_port), 8 + len(text), 0) + text.encode()
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0, me, node)
    ip = ip[:10] + struct.pack(">H", checksum(ip)) + ip[12:]
    return node_mac + me_mac + b"\x08\x00" + ip + udp


lan = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
lan.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lan.bind(group)
here = socket.inet_aton("127.0.0.1")
lan.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(group[0]) + here)
lan.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, here)
lan.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
end, sent = time.monotonic() + 5, 0.0
while time.monotonic() < end:
    # (Sent again each second: the first may go while the node asks who this is.)
    if time.monotonic() - sent >= 1:
        lan.sendto(datagram(), group)
        sent = time.monotonic()
    lan.settimeout(max(0.01, min(1.0, end - time.monotonic())))
    try:
        frame = lan.recv(65536)
    except TimeoutError:
        continue
    kind, rest = frame[12:14], frame[14:]
    if kind == b"\x08\x06" and len(rest) >= 28 and rest[6:8] == b"\x00\x01" and rest[24:28] == me:
        asker_mac, asker = rest[8:14], rest[14:18]
        arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 2) + me_mac + me + asker_mac + asker
        lan.sendto(asker_mac + me_mac + b"\x08\x06" + arp, group)
    elif kind == b"\x08\x00" and len(rest) >= 28 and rest[9] == 17 and rest[12:16] == node and rest[16:20] == me:
        header = (rest[0] & 15) * 4
        source_port, port, length = struct.unpack(">HHH", rest[header:header + 6])
        if source_port == int(to_port) and port == my_port:
            print(rest[header + 8:header + length].decode(errors="replace"))
            sys.exit(0)
sys.exit(1)
