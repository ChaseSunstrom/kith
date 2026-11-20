"""Reads a file back from an encrypted state partition on the host, for ci/vm/encrypt.sh.

    xts_check.py DISK STATE_START_SECTOR KEY_HEX EXTENTS BLOB BOUNDARY_SECTOR

The state is under dm-crypt (aes-xts-plain64: the IV is the sector's number in the partition). The host
has no root to map it, and `openssl enc` has no XTS, so this calls libcrypto itself. EXTENTS is a file
of `logical_block physical_block length` lines (4096-byte blocks of the state's ext4, read with debugfs
before the pass: the ext4 is not readable after it). Every sector of BLOB is decrypted from DISK and
compared, and BOUNDARY_SECTOR (where the pass was cut and resumed) must have blob sectors on both sides.
"""

import ctypes
import ctypes.util
import struct
import sys

disk, start, key_hex, extents, blob, boundary = sys.argv[1:7]
start, boundary = int(start), int(boundary)
key = bytes.fromhex(key_hex)
assert len(key) == 64

lib = ctypes.CDLL(ctypes.util.find_library("crypto") or "libcrypto.so.3")
lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
lib.EVP_aes_256_xts.restype = ctypes.c_void_p
for name in ("EVP_CIPHER_CTX_reset", "EVP_CIPHER_CTX_set_padding", "EVP_CipherInit_ex", "EVP_CipherUpdate"):
    getattr(lib, name).argtypes = None
ctx = ctypes.c_void_p(lib.EVP_CIPHER_CTX_new())
xts = ctypes.c_void_p(lib.EVP_aes_256_xts())


def decrypt(sector, data):
    iv = struct.pack("<Q", sector) + bytes(8)
    lib.EVP_CIPHER_CTX_reset(ctx)
    ok = lib.EVP_CipherInit_ex(ctx, xts, None, key, iv, 0)
    lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
    out, n = ctypes.create_string_buffer(len(data)), ctypes.c_int(0)
    ok = ok and lib.EVP_CipherUpdate(ctx, out, ctypes.byref(n), data, len(data))
    if not ok or n.value != len(data):
        sys.exit("xts_check: libcrypto refused sector %d" % sector)
    return out.raw


wanted = open(blob, "rb").read()
assert len(wanted) % 4096 == 0
checked = before = after = 0
with open(disk, "rb") as d:
    for line in open(extents):
        logical, physical, length = map(int, line.split())
        for block in range(length):
            first = (physical + block) * 8  # a block of 4096 bytes is 8 sectors of 512
            d.seek((start + first) * 512)
            raw = d.read(4096)
            for i in range(8):
                at = (logical + block) * 4096 + i * 512
                if decrypt(first + i, raw[i * 512 : (i + 1) * 512]) != wanted[at : at + 512]:
                    sys.exit("xts_check: sector %d of the state (byte %d of the blob) is not what was written" % (first + i, at))
                checked += 1
                before += first + i < boundary
                after += first + i >= boundary
print("xts_check: %d sectors of the blob read back, %d before sector %d and %d after" % (checked, before, boundary, after))
if checked * 512 != len(wanted) or not before or not after:
    sys.exit("xts_check: the blob is not all in the extents, or the cut (sector %d) is not inside it" % boundary)
