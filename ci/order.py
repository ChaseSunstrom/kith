#!/usr/bin/env python3
"""crates/kithd/kithd.order: the functions kithd runs from its start until it has idled a
while, in the order it first runs each. kithd's build links them next to each other in
that order (crates/kithd/build.rs says why).

    python3 ci/order.py           build kithd (ci/musl.sh), run it, write the file
    python3 ci/order.py --check   how many of the file's names the built kithd still has, and
                                  has together where its code starts: exit 1 under four fifths

How: a breakpoint on the first byte of every function (the linker's map says where each
is: the binary is stripped), taken off the first time it is hit. Each function stops kithd
once, so it runs at nearly its own speed, and every one that runs is seen, the ones that
run once at start too (a sampling profiler misses most of those). x86_64 Linux only.

Run it again when idle memory (ci/budgets.py) has crept up: code written since is not in
the file, and lands wherever the compiler put it. A name that is gone names no section, so
an old file is never wrong, only less use.
"""
import ctypes
import glob
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORDER = os.path.join(ROOT, "crates/kithd/kithd.order")
# After it serves: long enough for what it does every second, every 5 and every 10.
IDLE = 12
TRACEME, CONT, GETREGS, SETREGS, SETOPTIONS = 0, 7, 12, 13, 0x4200
TRACECLONE, EXITKILL, WALL = 0x8, 0x100000, 0x40000000
REGISTERS = "r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs"


class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in REGISTERS.split()]


def built():
    """The kithd ci/musl.sh builds, and the linker's map of it."""
    made = subprocess.run(["sh", os.path.join(ROOT, "ci/musl.sh")], check=True, stdout=subprocess.PIPE, text=True)
    release = made.stdout.strip()
    maps = glob.glob(os.path.join(release, "build/kithd-*/out/kithd.map"))
    if not maps:
        sys.exit("no kithd.map: this toolchain has no lld, so kithd is linked in the compiler's order")
    return os.path.join(release, "kithd"), max(maps, key=os.path.getmtime)


def functions(map_file):
    """Address -> the names there, for every symbol the map puts in .text."""
    line = re.compile(r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+[0-9a-f]+\s+\d+ ( *)(.*)$")
    found, section = {}, ""
    with open(map_file) as rows:
        for row in rows:
            row = line.match(row)
            if not row:
                continue
            address, indent, name = int(row[1], 16), len(row[2]), row[3]
            if indent == 0:
                section = name
            elif indent >= 16 and section == ".text":
                found.setdefault(address, []).append(name)
    return found


def loose(name):
    """A Rust name without what is written before each crate's name: it changes with the
    crate's dependencies and the compiler, and the build takes any letters there."""
    return re.sub(r"Cs[0-9A-Za-z]+_", "Cs_", name) if name.startswith("_R") else name


def traced(kithd, functions):
    """Run kithd until it has idled; the names of the functions it ran, first run first."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long
    with socket.socket() as free:
        free.bind(("127.0.0.1", 0))
        port = str(free.getsockname()[1])
    with tempfile.TemporaryDirectory() as tmp:
        serving = os.path.join(tmp, "kithd.sock")
        # (Its own registry port: on the usual one, taken by another kithd, it would run
        # the code that says so, not the code that serves.)
        arguments = [kithd, "--state", os.path.join(tmp, "state"), "--socket", serving, "--registry-port", port]
        pid = os.fork()
        if pid == 0:
            try:
                libc.ptrace(TRACEME, 0, None, None)
                os.dup2(os.open(os.devnull, os.O_WRONLY), 2)
                # (With no KITH_ variable of the shell this runs in: each is an argument of kithd's.)
                os.execve(kithd, arguments, {name: value for name, value in os.environ.items() if not name.startswith("KITH_")})
            finally:
                os._exit(127)
        os.waitpid(pid, 0)  # (Stopped at its first instruction.)
        libc.ptrace(SETOPTIONS, pid, None, TRACECLONE | EXITKILL)
        with open(f"/proc/{pid}/maps") as maps:
            base = int(next(row for row in maps if row.rstrip().endswith(kithd)).split("-")[0], 16)
        memory = os.open(f"/proc/{pid}/mem", os.O_RDWR)
        planted = {base + address: os.pread(memory, 1, base + address) for address in functions}
        for address in planted:
            os.pwrite(memory, b"\xcc", address)
        order, seen, until, started = [], set(), None, time.time()
        libc.ptrace(CONT, pid, None, None)
        while True:
            who, status = os.waitpid(-1, os.WNOHANG | WALL)
            if who == 0:
                if until is None and os.path.exists(serving):
                    until = time.time() + IDLE
                if until and time.time() > until:
                    break
                if until is None and time.time() > started + 120:
                    sys.exit("kithd did not serve in 120 s")  # (It is killed as this ends.)
                time.sleep(0.001)
                continue
            if not os.WIFSTOPPED(status):
                if who == pid:
                    sys.exit("kithd ended while it was traced")
                continue
            stopped, deliver = os.WSTOPSIG(status), 0
            if stopped == signal.SIGTRAP and status >> 16 == 0:
                registers = Registers()
                libc.ptrace(GETREGS, who, None, ctypes.byref(registers))
                at = registers.rip - 1
                if at in planted:
                    if at not in seen:
                        seen.add(at)
                        order += functions[at - base]
                        os.pwrite(memory, planted[at], at)
                    # (Hit by two threads at once, the second finds it already taken off.)
                    registers.rip = at
                    libc.ptrace(SETREGS, who, None, ctypes.byref(registers))
            elif stopped not in (signal.SIGTRAP, signal.SIGSTOP):  # (Those: a new thread's first stop.)
                deliver = stopped
            libc.ptrace(CONT, who, None, deliver)
        os.kill(pid, signal.SIGKILL)
        try:
            while True:  # (Every thread of it: the first is not gone before the others are.)
                os.waitpid(-1, WALL)
        except ChildProcessError:
            pass
        os.close(memory)
    return order


def main():
    kithd, map_file = built()
    known = functions(map_file)
    if "--check" in sys.argv:
        with open(ORDER) as file:
            names = file.read().split()
        where = {loose(name): address for address, names in known.items() for name in names}
        found = [where[loose(name)] for name in names if loose(name) in where]
        # Together: in the first quarter of its code (in the compiler's order a quarter would be).
        quarter = min(known) + (max(known) - min(known)) // 4
        together = sum(address < quarter for address in found)
        print(f"{len(found)} of {len(names)} names in kithd.order are in the built kithd, {together} of them together where its code starts")
        # (An empty file orders nothing; one mostly of names that are gone, little; and a
        # link that did not take the order leaves them all over.)
        sys.exit(0 if names and len(found) >= 0.8 * len(names) and together >= 0.8 * len(found) else 1)
    # (A name is written into the linker's script as it is: only what a name is made of.)
    order = [name for name in traced(kithd, known) if re.fullmatch(r"[\w.$]+", name)]
    with open(ORDER, "w") as file:
        file.write("".join(name + "\n" for name in order))
    print(f"{len(order)} of {sum(map(len, known.values()))} functions ran; build again (sh ci/musl.sh) to link them in this order")


if __name__ == "__main__":
    main()
