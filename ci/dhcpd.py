"""A test network's DHCP server: python3 ci/dhcpd.py PORT MAC=ADDRESS...

QEMU connects `-netdev socket,connect=127.0.0.1:PORT` to it and passes Ethernet frames,
each after its length. The cards named are given their address (in a /24, with no
router and no name server); nothing else on the network is answered. QEMU's own user
network cannot stand in for it between two machines: it takes every packet it sees for
one to send on, and resets their connections to each other.
"""

import socket
import struct
import sys

US, CARD, COOKIE = bytes([10, 9, 0, 254]), bytes.fromhex("5254000009fe"), bytes([99, 130, 83, 99])


def checksum(header):
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    total = (total & 0xFFFF) + (total >> 16)
    return ~(total + (total >> 16)) & 0xFFFF


def answer(frame, leases):
    """The frame that answers `frame`, if that is a DISCOVER or REQUEST from a card in `leases`."""
    if len(frame) < 14 + 20 + 8 + 240 or frame[12:14] != b"\x08\x00" or frame[23] != 17:
        return None
    udp = 14 + (frame[14] & 15) * 4
    asked = frame[udp + 8 :]
    if frame[udp + 2 : udp + 4] != b"\x00\x43" or len(asked) < 240 or asked[0] != 1 or asked[236:240] != COOKIE:
        return None
    kind, at = None, 240
    while at + 1 < len(asked) and asked[at] != 255:
        if asked[at] == 0:
            at += 1
            continue
        if asked[at] == 53 and at + 2 < len(asked):
            kind = asked[at + 2]
        at += 2 + asked[at + 1]
    yours, kind = leases.get(asked[28:34]), {1: 2, 3: 5}.get(kind)
    if not yours or not kind:
        return None
    options = bytes([53, 1, kind, 54, 4]) + US + bytes([51, 4, 0, 0, 14, 16, 1, 4, 255, 255, 255, 0, 255])
    said = bytes([2, 1, 6, 0]) + asked[4:8] + bytes(2) + asked[10:12] + bytes(4) + yours + bytes(8)
    said += asked[28:44] + bytes(192) + COOKIE + options
    said += bytes(max(0, 300 - len(said)))
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 28 + len(said), 0, 0, 64, 17, 0) + US + bytes([255] * 4)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    # (No UDP checksum: IPv4 lets it be left out.)
    return bytes([255] * 6) + CARD + b"\x08\x00" + ip + struct.pack("!HHHH", 67, 68, 8 + len(said), 0) + said


def main():
    leases = {bytes.fromhex(mac.replace(":", "")): socket.inet_aton(address) for mac, address in (arg.split("=") for arg in sys.argv[2:])}
    with socket.create_server(("127.0.0.1", int(sys.argv[1]))) as listening:
        wire = listening.accept()[0]
    frames = wire.makefile("rb")
    while len(head := frames.read(4)) == 4:
        reply = answer(frames.read(struct.unpack("!I", head)[0]), leases)
        if reply:
            wire.sendall(struct.pack("!I", len(reply)) + reply)


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        card = bytes.fromhex("525400000902")
        asked = bytes([1, 1, 6, 0, 1, 2, 3, 4, 0, 0, 0x80, 0]) + bytes(16) + card + bytes(202) + COOKIE + bytes([53, 1, 1, 255])
        frame = bytes(12) + b"\x08\x00\x45" + bytes(8) + b"\x11" + bytes(10) + struct.pack("!HHHH", 68, 67, 0, 0) + asked
        said = answer(frame, {card: bytes([10, 9, 0, 2])})
        assert said[42 + 16 : 42 + 20] == bytes([10, 9, 0, 2]) and said[42 + 240 : 42 + 243] == bytes([53, 1, 2])
        assert checksum(said[14:34]) == 0 and said[46:50] == bytes([1, 2, 3, 4])
        assert answer(frame, {}) is None and answer(frame[:-2] + bytes([8, 255]), {card: US}) is None
    else:
        main()
