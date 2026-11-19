"""A machine on a node's LAN that is not a VM: sends one UDP datagram to the node and says
what comes back (what `vm.sh --test tunnel` asks a pod's published UDP port), or watches who
answers for an address (what `vm.sh --test home` asks of the house address).

  lan_probe.py GROUP_PORT MAC ADDRESS PORT TEXT
  lan_probe.py GROUP_PORT arp ADDRESS SECONDS
  lan_probe.py GROUP_PORT handshakes ADDRESS SECONDS
  lan_probe.py GROUP_PORT MAC ADDRESS PORT syn

The test's LAN is QEMU's socket netdev: Ethernet frames as datagrams to 230.0.0.1:GROUP_PORT
on 127.0.0.1. This joins it as 10.9.0.77, sends TEXT to ADDRESS:PORT (the card MAC), answers
the node's ARP for itself, and prints what ADDRESS:PORT sends back. Exit 1 when nothing came
in five seconds. (QEMU's restricted user network drops every UDP answer of its guest's: the
test's card out, which reaches nothing else, can carry no UDP answer back to this machine.)
A TEXT that starts with `hex:` is sent as those bytes, and what comes back is printed as hex.

`arp`: asks who has ADDRESS four times a second for SECONDS, and prints a line each time:
"SECONDS-SINCE-START MAC[,MAC...]" (the cards that answered, or "-" when none did), and
"SECONDS-SINCE-START announce MAC" for each announcement of ADDRESS that goes by.

`handshakes`: sends nothing. It prints "EPOCH SRC DST TYPE" for each WireGuard handshake packet
(a UDP datagram from port 51820 to port 51820 whose body is type 1, an initiation, or type 2, an
answer) that ADDRESS sends (type 1: DST is where it dials) or is sent (type 2: SRC is the address
the answer came from, which need not be one of the node's own) for SECONDS: the LAN carries every
frame to this machine too. EPOCH is time.time().

`syn` (in place of TEXT): sends a SYN from 10.9.0.77 to ADDRESS:PORT at MAC, once a second for
five seconds. Prints "syn-ack" and exits 0 when ADDRESS:PORT answers it; exit 1 otherwise.
(Not to a broadcast MAC: a TCP stack takes only frames sent to its own card.)
"""

import socket
import struct
import sys
import time

group_port, mac, to, to_port, text = (sys.argv[1:6] + [""] * 5)[:5]
arp_mode = mac == "arp"
handshakes_mode = mac == "handshakes"
syn_mode = text == "syn"
group = ("230.0.0.1", int(group_port))
if arp_mode or handshakes_mode:
    node_mac = b""
else:
    node_mac = bytes.fromhex(mac.replace(":", ""))
node = socket.inet_aton(to)
me_mac, me = bytes.fromhex("525400000977"), socket.inet_aton("10.9.0.77")
my_port = 40977
as_hex = text.startswith("hex:")
payload = bytes.fromhex(text[4:]) if as_hex else text.encode()


def checksum(header):
    total = sum(struct.unpack(f">{len(header) // 2}H", header))
    total = (total >> 16) + (total & 0xFFFF)
    return ~(total + (total >> 16)) & 0xFFFF


def ipv4(proto, body):
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 1, 0x4000, 64, proto, 0, me, node)
    return ip[:10] + struct.pack(">H", checksum(ip)) + ip[12:] + body


def datagram():
    udp = struct.pack(">HHHH", my_port, int(to_port), 8 + len(payload), 0) + payload
    return node_mac + me_mac + b"\x08\x00" + ipv4(17, udp)


def syn():
    head = struct.pack(">HHIIBBHHH", my_port, int(to_port), 1000, 0, 0x50, 0x02, 65535, 0, 0)
    pseudo = me + node + struct.pack(">BBH", 0, 6, len(head))
    head = head[:16] + struct.pack(">H", checksum(pseudo + head)) + head[18:]
    return node_mac + me_mac + b"\x08\x00" + ipv4(6, head)


def who_has():
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + me_mac + me + b"\0" * 6 + node
    return b"\xff" * 6 + me_mac + b"\x08\x06" + arp


def answer_arp(rest):
    asker_mac, asker = rest[8:14], rest[14:18]
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 2) + me_mac + me + asker_mac + asker
    lan.sendto(asker_mac + me_mac + b"\x08\x06" + arp, group)


lan = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
lan.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lan.bind(group)
here = socket.inet_aton("127.0.0.1")
lan.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(group[0]) + here)
lan.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, here)
lan.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)


def watch(seconds):
    start = time.monotonic()
    end = start + seconds
    while time.monotonic() < end:
        asked, answered = time.monotonic(), set()
        lan.sendto(who_has(), group)
        while time.monotonic() - asked < 0.25:
            lan.settimeout(max(0.01, 0.25 - (time.monotonic() - asked)))
            try:
                frame = lan.recv(65536)
            except TimeoutError:
                continue
            kind, rest = frame[12:14], frame[14:]
            if kind != b"\x08\x06" or len(rest) < 28 or rest[2:4] != b"\x08\x00":
                continue
            opcode, sender_mac, sender, target = struct.unpack(">H", rest[6:8])[0], rest[8:14], rest[14:18], rest[24:28]
            if sender != node:
                continue
            if opcode == 2 and target == me:
                answered.add(sender_mac.hex(":"))
            elif opcode == 1 and target == node:
                print(f"{time.monotonic() - start:.2f} announce {sender_mac.hex(':')}", flush=True)
        print(f"{asked - start:.2f} {','.join(sorted(answered)) or '-'}", flush=True)


def handshakes(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        lan.settimeout(max(0.01, min(1.0, end - time.monotonic())))
        try:
            frame = lan.recv(65536)
        except TimeoutError:
            continue
        kind, rest = frame[12:14], frame[14:]
        if kind != b"\x08\x00" or len(rest) < 20 or rest[9] != 17:
            continue
        header = (rest[0] & 15) * 4
        if len(rest) < header + 9:
            continue
        source_port, port = struct.unpack(">HH", rest[header:header + 4])
        wanted = (1, rest[12:16]) if rest[12:16] == node else (2, rest[16:20])
        if source_port == 51820 and port == 51820 and rest[header + 8] == wanted[0] and wanted[1] == node:
            print(f"{time.time():.2f} {socket.inet_ntoa(rest[12:16])} {socket.inet_ntoa(rest[16:20])} {rest[header + 8]}", flush=True)


if arp_mode:
    watch(float(to_port))
    sys.exit(0)
if handshakes_mode:
    handshakes(float(to_port))
    sys.exit(0)

send = syn if syn_mode else datagram
end, sent = time.monotonic() + 5, 0.0
while time.monotonic() < end:
    # (Sent again each second: the first may go while the node asks who this is.)
    if time.monotonic() - sent >= 1:
        lan.sendto(send(), group)
        sent = time.monotonic()
    lan.settimeout(max(0.01, min(1.0, end - time.monotonic())))
    try:
        frame = lan.recv(65536)
    except TimeoutError:
        continue
    kind, rest = frame[12:14], frame[14:]
    if kind == b"\x08\x06" and len(rest) >= 28 and rest[6:8] == b"\x00\x01" and rest[24:28] == me:
        answer_arp(rest)
    elif kind == b"\x08\x00" and len(rest) >= 28 and rest[9] == 17 and rest[12:16] == node and rest[16:20] == me:
        header = (rest[0] & 15) * 4
        source_port, port, length = struct.unpack(">HHH", rest[header:header + 6])
        if source_port == int(to_port) and port == my_port:
            body = rest[header + 8:header + length]
            print(body.hex() if as_hex else body.decode(errors="replace"))
            sys.exit(0)
    elif syn_mode and kind == b"\x08\x00" and len(rest) >= 40 and rest[9] == 6 and rest[12:16] == node and rest[16:20] == me:
        header = (rest[0] & 15) * 4
        source_port, port = struct.unpack(">HH", rest[header:header + 4])
        ack, flags = struct.unpack(">I", rest[header + 8:header + 12])[0], rest[header + 13]
        if source_port == int(to_port) and port == my_port and (flags & 0x12) == 0x12 and ack == 1001:
            print("syn-ack", flush=True)
            sys.exit(0)
sys.exit(1)
